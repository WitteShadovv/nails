# A switch that hangs until soft-reboot.target's job timeout powers the machine
# off instead of being forced through.
#
# systemd ends a switch that hangs for 30 minutes by force
# (JobTimeoutAction=soft-reboot-force): PID 1 switches without
# systemd-soft-reboot.service, so without the session's transition step. The
# session installs a runtime drop-in for soft-reboot.target next to its other
# drop-ins that makes that timeout power off by force (poweroff-force), and the
# way back removes it.
#
# Two pieces of the node exist only for this test: a unit that holds up the
# next switch once it is started, as long as its instance says
# (hold-switch@infinity.service: its stop never ends; shutdown.target waits
# for its stop, and the transition's service waits for shutdown.target), and a
# drop-in that shortens soft-reboot.target's job timeout to a minute. NixOS
# writes that one as soft-reboot.target.d/overrides.conf. It sets only the
# timeout and the session's drop-in only the action, so both hold. Nothing in
# the product knows about either.
#
#   1. A session loads the drop-in in the hidden PID 1, which keeps the
#      test's timeout, and the way back leaves the decoy's own unit.
#   2. The positive control, on the decoy after that session: a plain
#      soft-reboot held up by the unit is forced through at the timeout, and
#      the machine comes back up.
#   3. The positive control for the session's own switch: once the test has
#      removed the drop-in in the hidden session, a way back held up by the
#      unit is forced through at the timeout into the decoy, which comes up
#      with the session's files still in /run (its runtime directory and the
#      transition's drop-in), as the way back's last step never ran. A cold
#      boot clears them. The way in has no such control: the entry refuses
#      unless PID 1 reports the drop-in's action.
#   4. Why the drop-in powers off by force: with a test-only runtime drop-in
#      that sets a plain poweroff for the timeout, PID 1 skips that action
#      while the switch's shutdown runs, and a switch held up for 90 seconds
#      goes on only when the hold ends.
#   5. A way back held up by the unit powers the machine off at the timeout,
#      with no userspace coming up first, and the next cold boot is the plain
#      decoy.
#   6. An entry held up the same way powers off too, without the hidden
#      session ever coming up; the next cold boot is the plain decoy, the
#      record still says active, and `recover` resets it.
#
# PID 1 says on the console what its job timeout does ("Forcibly powering off:
# job timed out"). The test VMs name the serial port first and the screen last,
# so the node swaps them, and turns PID 1's status lines on, which the test VMs
# turn off: those lines then reach the serial log the driver reads.
{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
in
{
  name = "session-switch-timeout";
  meta.tags = [
    "security"
    "session"
  ];
  # 439 s on a hosted runner: five waits for the one-minute timeout (one in a
  # 90-second hold), two power-offs and a crash with their cold boots and
  # seven soft-reboots, which a slower runner stretches.
  globalTimeout = 1200;

  nodes.machine =
    { pkgs, lib, ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [ self.packages.${pkgs.stdenv.hostPlatform.system}.nails ];
      virtualisation.qemu.consoles = [
        "tty0"
        "ttyS0,115200n8"
      ];
      systemd = {
        settings.Manager.ShowStatus = lib.mkForce true;
        # Test only: the switch's job timeout, a minute instead of 30.
        targets.soft-reboot.unitConfig.JobTimeoutSec = "60s";
        # Test only: started, it holds up the next switch for as long as its
        # instance says, in seconds or `infinity`.
        services."hold-switch@" = {
          description = "Hold up the next switch (%i)";
          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = true;
            ExecStart = "${pkgs.coreutils}/bin/true";
            ExecStop = "${pkgs.coreutils}/bin/sleep %i";
            TimeoutStopSec = "infinity";
          };
        };
      };
    };

  testScript = _: ''
    from nails_e2e import session

    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.readStatusJsonFn}
    ${testHelpers.canonicalActivateFn}
    ${testHelpers.canonicalDeactivateFn}

    CONFIG = "/mnt/data/config/nails.toml"
    UNIT = "soft-reboot.target"
    GUARD = "/run/systemd/system/soft-reboot.target.d/zz-overlay-runtime.conf"
    #: What PID 1 says when the switch's job timeout powers off, and when it
    #: forces the switch through.
    POWERING_OFF = "Forcibly powering off: job timed out"
    FORCED = "Forcibly soft-rebooting: job timed out"
    #: Test only: a plain poweroff for the switch's job timeout.
    PLAIN = "/run/systemd/system/soft-reboot.target.d/90-plain-poweroff.conf"
    #: The session's plan in its runtime directory, and the transition's
    #: drop-in: the way back's last step removes both.
    PLAN = "/run/overlay-runtime/plan.json"
    TRANSITION = "/run/systemd/system/systemd-soft-reboot.service.d/50-overlay-runtime.conf"
    #: What PID 1 logs when the switch's job times out, and when it skips a
    #: plain poweroff because a shutdown is under way.
    TIMED_OUT = "Job soft-reboot.target/start timed out."
    SKIPPED = "Skipping emergency action request poweroff."
    #: How long a follow may take: the timeout, the switch or the power-off,
    #: and room for a slow runner.
    DEADLINE_S = 60 + 240


    def unit(prop):
        return machine.succeed(f"systemctl show -P {prop} {UNIT}").strip()


    def assert_guard(where):
        """PID 1 has the session's drop-in loaded, on top of the test's own:
        the switch's job timeout powers off, and the timeout is the test's."""
        dropins = unit("DropInPaths").split()
        assert GUARD in dropins, f"{where}: {dropins}"
        assert unit("JobTimeoutAction") == "poweroff-force", where
        assert unit("JobTimeoutUSec") == "1min", f"{where}: {unit('JobTimeoutUSec')}"
        machine.log(f"{where}: {UNIT} from {unit('FragmentPath')} with {dropins}")


    def assert_no_guard(where):
        """The decoy's own unit: its job timeout forces the switch through."""
        machine.fail(f"test -e {GUARD}")
        dropins = unit("DropInPaths")
        assert "/run/" not in dropins, f"{where}: {dropins}"
        assert unit("JobTimeoutAction") == "soft-reboot-force", where


    def hold_switch(seconds="infinity"):
        machine.succeed(f"systemctl start hold-switch@{seconds}.service")
        machine.succeed(f"systemctl is-active hold-switch@{seconds}.service")


    def pid1_lines(text):
        """How many lines PID 1 logged with `text` in this boot, before a
        soft-reboot too: the volatile journal and the boot ID outlive one."""
        out = machine.succeed("journalctl -b _PID=1 -o cat --no-pager")
        return sum(text in line for line in out.splitlines())


    def said(since, text):
        return any(text in line for line in machine.full_console_log[since:])


    def assert_powered_off_at_the_timeout(since, where):
        assert said(since, POWERING_OFF), f"{where}: PID 1 never said {POWERING_OFF!r}"
        assert not said(since, FORCED), f"{where}: the switch was forced through"


    def assert_cold_decoy(where):
        machine.start()
        machine.wait_for_unit("multi-user.target")
        session.assert_decoy_root(machine)
        machine.fail("test -e /dev/mapper/data")
        assert_no_guard(where)
        machine.log(f"{where}: the plain decoy")


    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    machine.succeed("nails init /mnt/data")
    write_headless_config(CONFIG)
    assert_no_guard("the decoy before any session")

    with subtest("the hidden PID 1 has the drop-in, and the way back removes it"):
        canonical_activate(CONFIG, "--overlay-only", "activate-plain")
        assert_guard("the hidden session")
        canonical_deactivate(CONFIG, "deactivate-plain")
        assert_no_guard("the decoy after the way back")

    with subtest("without the drop-in the same hold forces a soft-reboot through"):
        hold_switch()
        since = len(machine.full_console_log)
        session.follow_soft_reboot(
            machine, "systemctl soft-reboot", "forced", deadline_s=DEADLINE_S
        )
        assert said(since, FORCED), f"PID 1 never said {FORCED!r}"
        assert not said(since, POWERING_OFF), "the decoy powered off"
        machine.fail("systemctl is-active hold-switch@infinity.service")
        session.assert_decoy_root(machine)

    with subtest("without the drop-in a held way back is forced through without its last step"):
        machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
        canonical_activate(CONFIG, "--overlay-only", "activate-forced-back")
        assert_guard("the session whose drop-in the test removes")
        # Test only: the hidden PID 1 forgets the session's drop-in, so the
        # unit's own action holds for the way back.
        machine.succeed(f"rm {GUARD} && systemctl daemon-reload")
        assert unit("JobTimeoutAction") == "soft-reboot-force", unit("JobTimeoutAction")
        hold_switch()
        since = len(machine.full_console_log)
        session.follow_soft_reboot(
            machine,
            f"nails --config {CONFIG} deactivate -y > {session.SERIAL_CONSOLE} 2>&1",
            "forced-back",
            deadline_s=DEADLINE_S,
        )
        assert said(since, FORCED), f"PID 1 never said {FORCED!r}"
        assert not said(since, POWERING_OFF), "the way back powered off"
        # The decoy's root, with the session's files still in /run.
        fstype = session.root_fstype(machine)
        assert fstype != "overlay", f"/ is {fstype}: the switch stayed in the session"
        machine.succeed(f"test -e {PLAN}")
        machine.succeed(f"test -e {TRANSITION}")
        machine.log(
            "the forced way back left: "
            + machine.succeed(f"ls -A /run/overlay-runtime $(dirname {TRANSITION})")
        )
        machine.crash()
        assert_cold_decoy("after the forced way back")

    with subtest("a plain poweroff at the timeout does nothing during a switch"):
        machine.succeed(
            f"mkdir -p $(dirname {PLAIN}) && "
            f"printf '[Unit]\\nJobTimeoutAction=poweroff\\n' > {PLAIN} && "
            "systemctl daemon-reload"
        )
        assert unit("JobTimeoutAction") == "poweroff", unit("JobTimeoutAction")
        timeouts = pid1_lines(TIMED_OUT)
        hold_switch("90")
        since = len(machine.full_console_log)
        timings = session.follow_soft_reboot(
            machine, "systemctl soft-reboot", "plain", deadline_s=DEADLINE_S
        )
        assert pid1_lines(TIMED_OUT) == timeouts + 1, "the switch's job never timed out"
        assert pid1_lines(SKIPPED) == 1, "PID 1 did not skip the plain poweroff"
        assert not said(since, FORCED), "the switch was forced through"
        # Not at the timeout: once the hold ended, as an ordinary switch.
        assert timings["trigger_to_backdoor"] > 90, timings
        machine.succeed(f"rm -r $(dirname {PLAIN}) && systemctl daemon-reload")
        assert_no_guard("the decoy after the plain poweroff's control")

    with subtest("a way back held up until the timeout powers off"):
        machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
        canonical_activate(CONFIG, "--overlay-only", "activate-hold-back")
        assert_guard("the session whose way back hangs")
        hold_switch()
        since = len(machine.full_console_log)
        session.follow_power_off(
            machine,
            f"nails --config {CONFIG} deactivate -y > {session.SERIAL_CONSOLE} 2>&1",
            "hold-back",
            deadline_s=DEADLINE_S,
        )
        assert_powered_off_at_the_timeout(since, "the way back")
        assert_cold_decoy("after the way back's power-off")

    with subtest("an entry held up until the timeout powers off"):
        machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
        hold_switch()
        since = len(machine.full_console_log)
        session.follow_power_off(
            machine,
            "set -o pipefail; "
            f"nails --config {CONFIG} activate -y --overlay-only 2>&1 "
            f"| tee /mnt/data/activate-hold-in.log > {session.SERIAL_CONSOLE}",
            "hold-in",
            deadline_s=DEADLINE_S,
        )
        assert_powered_off_at_the_timeout(since, "the entry")
        assert_cold_decoy("after the entry's power-off")
        # The entry recorded the session before the switch began.
        machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
        print(machine.succeed("cat /mnt/data/activate-hold-in.log"))
        rc, data = read_status_json_with_rc(CONFIG)
        machine.log(f"status after the entry's power-off: {rc} {data}")
        assert data["place"] == "decoy", data
        assert data["attention"] == "ended_abnormally", data
        machine.succeed(f"nails --config {CONFIG} recover")
        data = read_status_json(CONFIG)
        assert data["place"] == "decoy", data
        assert data["attention"] is None, data
  '';
}
