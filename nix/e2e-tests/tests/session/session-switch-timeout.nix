# A switch that hangs until soft-reboot.target's job timeout powers the machine
# off instead of being forced through.
#
# systemd ends a switch that hangs for 30 minutes by force
# (JobTimeoutAction=soft-reboot-force): PID 1 switches without
# systemd-soft-reboot.service, so without the session's transition step. The
# session installs a runtime drop-in for soft-reboot.target next to its other
# drop-ins that makes that timeout power off by force (poweroff-force). The
# drop-in stays for the whole session: a hidden session never goes back to the
# decoy, and every ending (deactivate, emergency) is a power-off that asks
# about no guard.
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
#      test's timeout, and keeps it through a reload of PID 1; deactivate
#      powers off, and the next cold boot has the decoy's own unit.
#   2. The positive control, on the decoy: a plain soft-reboot held up by the
#      unit is forced through at the timeout, and the machine comes back up.
#   3. Activation refuses where the timeout would do nothing, with a
#      test-only runtime drop-in that turns the timeout off, and nothing of the
#      entry is left.
#   4. A `systemctl service-watchdogs no` on the decoy does not refuse the
#      next activation: every reload of PID 1, the activation's own included,
#      sets service watchdogs back to what the kernel command line says, and
#      the hidden PID 1 then has them on. In that session deactivate asks
#      about no guard: with the timeout off, the drop-in gone and service
#      watchdogs off it powers the machine off at once, with no job running
#      into a timeout, and the next cold boot is the plain decoy with the
#      record inactive.
#   5. Why the drop-in powers off by force: with a test-only runtime drop-in
#      that sets a plain poweroff for the timeout, PID 1 skips that action
#      while the switch's shutdown runs, and a switch held up for 90 seconds
#      goes on only when the hold ends.
#   6. A plain soft-reboot in the hidden session held up by the unit powers
#      the machine off at the timeout, with no userspace coming up first, and
#      the next cold boot is the plain decoy; the record still says active,
#      and `recover` resets it.
#   7. An entry held up the same way powers off too, without the hidden
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
  # Four waits for the one-minute timeout (one in a 90-second hold), four
  # power-offs with their cold boots, six soft-reboots and the refused
  # activation, which a slower runner stretches.
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
    #: Test only: a plain poweroff for the switch's job timeout, and no
    #: timeout at all.
    PLAIN = "/run/systemd/system/soft-reboot.target.d/90-plain-poweroff.conf"
    NO_TIMEOUT = "/run/systemd/system/soft-reboot.target.d/zzz-no-timeout.conf"
    #: What PID 1 logs when the switch's job times out, and when it skips a
    #: plain poweroff because a shutdown is under way.
    TIMED_OUT = "Job soft-reboot.target/start timed out."
    SKIPPED = "Skipping emergency action request poweroff."
    #: How long a follow may take: the timeout, the switch or the power-off,
    #: and room for a slow runner.
    DEADLINE_S = 60 + 240


    def unit(prop):
        return machine.succeed(f"systemctl show -P {prop} {UNIT}").strip()


    def manager(prop):
        """`prop` of PID 1 itself."""
        return machine.succeed(f"systemctl show -P {prop}").strip()


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


    def assert_refused(command, code, *lines, absent=()):
        """`command` refuses with exit `code`, saying each of `lines` and
        none of `absent`."""
        rc, out = machine.execute(f"{command} 2>&1")
        machine.log(out)
        assert rc == code, f"{command}: exit {rc}\n{out}"
        for line in lines:
            assert line in out, f"{command}: no {line!r} in\n{out}"
        for line in absent:
            assert line not in out, f"{command}: {line!r} in\n{out}"


    def without_timeout():
        machine.succeed(
            f"mkdir -p $(dirname {NO_TIMEOUT}) && "
            f"printf '[Unit]\\nJobTimeoutSec=infinity\\n' > {NO_TIMEOUT} && "
            "systemctl daemon-reload"
        )
        assert unit("JobTimeoutUSec") == "infinity", unit("JobTimeoutUSec")


    def with_timeout_again():
        machine.succeed(f"rm {NO_TIMEOUT} && systemctl daemon-reload")


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

    with subtest("the hidden PID 1 keeps the drop-in, and deactivate powers off"):
        canonical_activate(CONFIG, "--overlay-only", "activate-plain")
        assert_guard("the hidden session")
        machine.succeed("systemctl daemon-reload")
        assert_guard("the hidden session after a reload")
        canonical_deactivate(CONFIG, "deactivate-plain")
        assert_no_guard("the decoy's cold boot after deactivate")

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

    with subtest("activation refuses where the timeout would do nothing"):
        machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
        activate = f"nails --config {CONFIG} activate -y --overlay-only"
        without_timeout()
        # The fix names the test's drop-in, the last that sets the timeout.
        assert_refused(
            activate,
            4,
            "JobTimeoutUSec=infinity",
            f"Remove the JobTimeoutSec= that turns the timeout off from {NO_TIMEOUT}",
        )
        with_timeout_again()
        assert_no_guard("after the refusal without a timeout")
        session.assert_decoy_root(machine)
        machine.fail("test -e /run/overlay-runtime")

    with subtest("deactivate asks about no guard: it powers off at once"):
        # The activation's reload undoes this, so it goes on, and the hidden
        # PID 1 has service watchdogs on.
        machine.succeed("systemctl service-watchdogs no")
        assert manager("ServiceWatchdogs") == "no"
        canonical_activate(CONFIG, "--overlay-only", "activate-unguarded")
        assert manager("ServiceWatchdogs") == "yes", "the entry's reload left them off"
        assert_guard("the session the test unguards")
        # Test only: no timeout, the session's drop-in forgotten and service
        # watchdogs off. None of it is the power-off's business.
        without_timeout()
        machine.succeed(f"rm {GUARD} && systemctl daemon-reload")
        assert unit("JobTimeoutAction") == "soft-reboot-force", unit("JobTimeoutAction")
        machine.succeed("systemctl service-watchdogs no")
        since = len(machine.full_console_log)
        canonical_deactivate(CONFIG, "deactivate-unguarded", boot=False)
        # An ordinary power-off: no job of it ran into its timeout.
        assert not said(since, "job timed out"), "the power-off waited for a job timeout"
        assert_cold_decoy("after deactivate without the guard")
        # Deactivate recorded the session's end before the power-off.
        machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
        data = read_status_json(CONFIG)
        assert data["place"] == "decoy", data
        assert data["attention"] is None, data

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

    with subtest("a soft-reboot in the session held up until the timeout powers off"):
        machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
        canonical_activate(CONFIG, "--overlay-only", "activate-hold-session")
        assert_guard("the session whose soft-reboot hangs")
        hold_switch()
        since = len(machine.full_console_log)
        session.follow_power_off(
            machine, "systemctl soft-reboot", "hold-session", deadline_s=DEADLINE_S
        )
        assert_powered_off_at_the_timeout(since, "the session's soft-reboot")
        assert_cold_decoy("after the session's power-off at the timeout")
        # Nothing ended the session on the record.
        machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
        rc, data = read_status_json_with_rc(CONFIG)
        machine.log(f"status after the session's power-off: {rc} {data}")
        assert data["place"] == "decoy", data
        assert data["attention"] == "ended_abnormally", data
        machine.succeed(f"nails --config {CONFIG} recover")
        data = read_status_json(CONFIG)
        assert data["attention"] is None, data
        machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")

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
