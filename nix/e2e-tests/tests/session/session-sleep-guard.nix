# The sleep guard in each `sleep_policy.mode`, against a closed lid.
#
# A virtual lid switch (a uinput device with SW_LID, which udev tags
# `power-switch` and logind watches like a laptop's ACPI lid) is closed in the
# hidden session, so the lid takes the same path through logind as a real one.
# logind is configured to suspend on a closed lid in every case it tells apart
# (battery, external power, docked) and to act at once (no holdoff). The
# suspend itself is replaced by a stub that leaves a marker in /run and a line
# on the console, so the VM keeps running and a suspend shows.
#
#   1. `warn`: `check` warns, no guard runs and no inhibitor is held; a closed
#      lid suspends the session. So does it with a plain `sleep:idle` block
#      inhibitor held, which is all `block` took before: logind ignores sleep
#      inhibitors for the lid switch (LidSwitchIgnoreInhibited=yes).
#   2. `block`: `check` says what the guard does; the guard holds a
#      `sleep:idle` and a `handle-lid-switch` block inhibitor under neutral
#      names, and a closed lid does not suspend. Stopping the guard, as the way
#      back does, releases both, after which a closed lid suspends again.
#   3. `teardown`: the guard holds a sleep delay inhibitor; a closed lid powers
#      the machine off and the stubbed suspend never runs; the next cold boot
#      is the plain decoy with the backend closed.
{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;

  # A lid switch on /dev/uinput: SIGUSR1 closes it, SIGUSR2 opens it, SIGTERM
  # removes the device.
  lidSwitch = pkgs.writeScriptBin "lid-switch" ''
    #!${pkgs.python3}/bin/python3
    import fcntl
    import os
    import signal
    import struct
    import sys

    UI_SET_EVBIT = 0x40045564
    UI_SET_SWBIT = 0x4004556D
    UI_DEV_SETUP = 0x405C5503
    UI_DEV_CREATE = 0x5501
    EV_SYN, EV_SW, SW_LID, BUS_VIRTUAL = 0, 5, 0, 6

    fd = os.open("/dev/uinput", os.O_WRONLY | os.O_NONBLOCK)
    fcntl.ioctl(fd, UI_SET_EVBIT, EV_SW)
    fcntl.ioctl(fd, UI_SET_SWBIT, SW_LID)
    fcntl.ioctl(
        fd, UI_DEV_SETUP, struct.pack("<HHHH80sI", BUS_VIRTUAL, 1, 1, 1, b"Lid Switch", 0)
    )
    fcntl.ioctl(fd, UI_DEV_CREATE)


    def emit(value):
        # struct input_event: a zero timeval (the kernel stamps it), type,
        # code, value; then the SYN_REPORT that delivers it.
        for kind, code, val in ((EV_SW, SW_LID, value), (EV_SYN, 0, 0)):
            os.write(fd, struct.pack("<qqHHi", 0, 0, kind, code, val))


    signal.signal(signal.SIGUSR1, lambda *_: emit(1))
    signal.signal(signal.SIGUSR2, lambda *_: emit(0))
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    print("lid switch ready", flush=True)
    while True:
        signal.pause()
  '';
in
{
  name = "session-sleep-guard";
  meta.tags = [
    "security"
    "session"
  ];
  # Five soft-reboots at about 15 s each, a power-off and a cold boot, plus
  # the waits for a suspend that must not come.
  globalTimeout = 1500;

  nodes.machine =
    { lib, ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [
        self.packages.${pkgs.stdenv.hostPlatform.system}.nails
        lidSwitch
      ];
      boot.kernelModules = [ "uinput" ];
      services.logind.settings.Login = {
        HandleLidSwitch = "suspend";
        HandleLidSwitchExternalPower = "suspend";
        HandleLidSwitchDocked = "suspend";
        HoldoffTimeoutSec = "0";
      };
      # The suspend logind starts, stubbed: the VM stays up and the marker
      # and the console line show that the lid suspended the session.
      systemd.services.systemd-suspend.serviceConfig.ExecStart = lib.mkForce [
        ""
        "${pkgs.bash}/bin/sh -c 'echo suspend-stub-ran > /dev/console; touch /run/suspend-stub-ran'"
      ];
    };

  testScript = _: ''
    import json

    from nails_e2e import session

    ${testHelpers.canonicalActivateFn}
    ${testHelpers.canonicalDeactivateFn}

    CONFIG = "/mnt/data/config/nails.toml"
    GUARD = "overlay-runtime-power.service"
    MARKER = "/run/suspend-stub-ran"
    STUB_LINE = "suspend-stub-ran"


    def write_config(mode):
        machine.succeed(
            f"cat > {CONFIG} <<'EOF'\n"
            "hidden_volume_root = \"/mnt/data\"\n"
            "minimum_space_mb = 100\n"
            "[sleep_policy]\n"
            f"mode = \"{mode}\"\n"
            "EOF"
        )


    def sleep_policy_line():
        rc, out = machine.execute(f"nails --config {CONFIG} check --overlay-only 2>&1")
        machine.log(out)
        assert rc == 0, f"check refused a ready host (rc={rc})"
        lines = [line for line in out.splitlines() if "sleep-policy" in line]
        assert len(lines) == 1, out
        assert "[WARN]" in lines[0], lines[0]
        return lines[0]


    def inhibitors():
        """logind's inhibitors as (what, who, why, mode) tuples."""
        out = machine.succeed(
            "busctl --json=short call org.freedesktop.login1 /org/freedesktop/login1 "
            "org.freedesktop.login1.Manager ListInhibitors"
        )
        return sorted(tuple(entry[:4]) for entry in json.loads(out)["data"][0])


    def guard_inhibitors():
        return [entry for entry in inhibitors() if entry[1] == "power-management"]


    def start_lid():
        """Create the lid switch and wait until logind watches it."""
        since = machine.succeed("date +%s").strip()
        machine.succeed("systemctl reset-failed lid-switch.service 2>/dev/null || true")
        machine.succeed("systemd-run --unit lid-switch --property=Type=exec lid-switch")
        machine.wait_until_succeeds(
            f"journalctl -u systemd-logind --since @{since} --no-pager "
            "| grep -q 'Watching system buttons.*(Lid Switch)'",
            timeout=60,
        )


    def lid(closed):
        machine.succeed(f"systemctl kill -s {'USR1' if closed else 'USR2'} lid-switch.service")
        machine.wait_until_succeeds(
            "busctl get-property org.freedesktop.login1 /org/freedesktop/login1 "
            f"org.freedesktop.login1.Manager LidClosed | grep -qx 'b {str(closed).lower()}'",
            timeout=30,
        )


    def suspend_settled():
        """Wait until logind has no sleep in flight. A lid held closed makes
        logind suspend again after each (stubbed) resume, so one more suspend
        can still be under way when the lid opens."""
        machine.wait_until_succeeds(
            "busctl get-property org.freedesktop.login1 /org/freedesktop/login1 "
            "org.freedesktop.login1.Manager PreparingForSleep | grep -qx 'b false' && "
            "! systemctl list-jobs --no-legend | grep -qE 'suspend|sleep'",
            timeout=60,
        )


    def close_lid_expect_suspend():
        machine.succeed(f"rm -f {MARKER}")
        lid(True)
        machine.wait_until_succeeds(f"test -e {MARKER}", timeout=60)
        lid(False)
        suspend_settled()


    def close_lid_expect_no_suspend():
        machine.succeed(f"rm -f {MARKER}")
        lid(True)
        # logind acts on the closing edge at once (no holdoff) and checks a
        # lid that stays closed again after 5 s; give it three times that.
        # sync-lint: allow sleep -- a suspend that must not come has nothing to wait on; the marker check below is the finding
        machine.sleep(15)
        machine.fail(f"test -e {MARKER}")
        lid(False)


    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    machine.succeed("nails init /mnt/data")

    with subtest("warn: no guard, and a closed lid suspends the session"):
        write_config("warn")
        line = sleep_policy_line()
        assert "HandleLidSwitch=suspend" in line, line
        assert 'sleep_policy.mode = "block" or "teardown"' in line, line
        canonical_activate(CONFIG, "--overlay-only", "activate-warn")
        machine.fail(f"systemctl is-active {GUARD}")
        assert guard_inhibitors() == [], inhibitors()
        start_lid()
        close_lid_expect_suspend()

    with subtest("warn: a sleep:idle block inhibitor alone does not stop the lid"):
        machine.succeed(
            "systemd-run --unit sleep-idle-only --property=Type=exec "
            "systemd-inhibit --what=sleep:idle --mode=block /run/current-system/sw/bin/sleep infinity"
        )
        machine.wait_until_succeeds(
            "systemd-inhibit --list --no-pager | grep -q 'sleep:idle'", timeout=30
        )
        close_lid_expect_suspend()
        machine.succeed("systemctl stop sleep-idle-only.service lid-switch.service")
        canonical_deactivate(CONFIG, "deactivate-warn")

    with subtest("block: the guard holds sleep, idle and lid-switch inhibitors"):
        machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
        write_config("block")
        line = sleep_policy_line()
        assert "takes the lid switch from logind" in line, line
        canonical_activate(CONFIG, "--overlay-only", "activate-block")
        machine.wait_for_unit(GUARD)
        machine.wait_until_succeeds(
            "busctl --json=short call org.freedesktop.login1 /org/freedesktop/login1 "
            "org.freedesktop.login1.Manager ListInhibitors | grep -q handle-lid-switch",
            timeout=60,
        )
        held = guard_inhibitors()
        why = "A background task is in progress"
        assert held == [
            ("handle-lid-switch", "power-management", why, "block"),
            ("sleep:idle", "power-management", why, "block"),
        ], inhibitors()
        for text in (str(inhibitors()), GUARD):
            assert "nails" not in text.lower() and "hidden" not in text.lower(), text

    with subtest("block: a closed lid does not suspend the session"):
        start_lid()
        close_lid_expect_no_suspend()
        machine.succeed(f"systemctl is-active {GUARD}")
        session.assert_hidden_root(machine)

    with subtest("block: stopping the guard releases both inhibitors"):
        machine.succeed(f"systemctl stop {GUARD}")
        machine.wait_until_succeeds(
            "! busctl --json=short call org.freedesktop.login1 /org/freedesktop/login1 "
            "org.freedesktop.login1.Manager ListInhibitors | grep -q power-management",
            timeout=30,
        )
        close_lid_expect_suspend()
        machine.succeed("systemctl stop lid-switch.service")
        canonical_deactivate(CONFIG, "deactivate-block")

    with subtest("teardown: a closed lid powers the machine off instead"):
        machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
        write_config("teardown")
        canonical_activate(CONFIG, "--overlay-only", "activate-teardown")
        machine.wait_for_unit(GUARD)
        machine.wait_until_succeeds(
            "busctl --json=short call org.freedesktop.login1 /org/freedesktop/login1 "
            "org.freedesktop.login1.Manager ListInhibitors | grep -q power-management",
            timeout=60,
        )
        assert guard_inhibitors() == [
            ("sleep", "power-management", "Finishing a background task before sleep", "delay"),
        ], inhibitors()
        start_lid()
        stubs_before = machine.get_console_log().count(STUB_LINE)
        machine.succeed("systemctl kill -s USR1 lid-switch.service")
        session.wait_for_power_off(machine, 300)
        console = machine.get_console_log()
        assert console.count(STUB_LINE) == stubs_before, "the suspend ran before the power-off"

    with subtest("teardown: the next cold boot is the plain decoy with the backend closed"):
        machine.start()
        machine.wait_for_unit("multi-user.target")
        session.assert_decoy_root(machine)
        machine.fail("test -e /dev/mapper/data")
  '';
}
