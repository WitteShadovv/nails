# The way back powering off instead of returning when it cannot put the
# decoy's network state back.
#
# A network change the way back cannot undo lives only in the kernel: a
# power-off erases it, a return would hand it to the decoy. The test makes one
# the way back cannot undo, the IPIP fallback device `tunl0`: loading the
# `ipip` module makes it, it is a virtual link the decoy did not have, and the
# kernel keeps it when asked to delete it (`ip link delete` returns success
# and the link stays), so the way back sees it still there.
#
#   1. A session that makes a dummy link, which the way back deletes, returns
#      to the decoy with `deactivate` as before, without the link: a way back
#      that undoes everything never powers off.
#   2. A session that loads `ipip`: `deactivate` powers the machine off, with
#      nothing on the console that says why, and the next cold boot is the
#      plain decoy without it.
#   3. The same with a plain `emergency`, which returns through the same way
#      back: it powers off too, as quietly.
#
# A line written to `/dev/console`, the kernel's last `console=`, shows on the
# screen, where it would tell anyone watching that a hidden session had just
# ended. The test VMs name the serial port first and the screen last, so the
# node swaps them: `/dev/console` is then the serial log the driver reads, and
# the test finds no line there that names the way back or the decoy.
{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
in
{
  name = "session-wayback-poweroff";
  meta.tags = [
    "security"
    "session"
  ];

  nodes.machine =
    { pkgs, ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [ self.packages.${pkgs.stdenv.hostPlatform.system}.nails ];
      virtualisation.qemu.consoles = [
        "tty0"
        "ttyS0,115200n8"
      ];
    };

  testScript = _: ''
    import re

    from nails_e2e import session

    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.canonicalActivateFn}
    ${testHelpers.canonicalDeactivateFn}

    CONFIG = "/mnt/data/config/nails.toml"
    #: What a line that says why the machine powers off would name.
    WHY = re.compile(r"way back|decoy", re.IGNORECASE)


    def assert_cold_decoy(where):
        machine.start()
        machine.wait_for_unit("multi-user.target")
        session.assert_decoy_root(machine)
        machine.fail("test -e /dev/mapper/data")
        machine.fail("test -e /sys/class/net/tunl0")
        machine.log(f"{where}: the plain decoy, without tunl0")


    def enter_with_tunl0(label):
        machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
        canonical_activate(CONFIG, "--overlay-only", label)
        machine.succeed("modprobe ipip")
        machine.succeed("test -e /sys/class/net/tunl0")
        # The kernel keeps its fallback device: the way back cannot delete it.
        machine.execute("ip link delete tunl0")
        machine.succeed("test -e /sys/class/net/tunl0")


    def leave_detached(command):
        machine.execute(
            f"({command}) </dev/null >/dev/null 2>&1 &",
            check_return=False,
            check_output=False,
        )


    def assert_nothing_says_why(since):
        """No console line since index `since` of the console log says why the
        machine powered off."""
        why = [line for line in machine.full_console_log[since:] if WHY.search(line)]
        assert not why, f"the console says why the machine powered off: {why}"


    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.fail("test -e /sys/class/net/tunl0")
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    machine.succeed("nails init /mnt/data")
    write_headless_config(CONFIG)

    with subtest("a way back that undoes everything returns to the decoy"):
        canonical_activate(CONFIG, "--overlay-only", "activate-control")
        machine.succeed("ip link add probe0 type dummy && ip link set probe0 up")
        canonical_deactivate(CONFIG, "deactivate-control")
        machine.fail("test -e /sys/class/net/probe0")

    with subtest("deactivate powers off when the way back cannot delete a link"):
        enter_with_tunl0("activate-deactivate")
        since = len(machine.full_console_log)
        leave_detached(f"nails --config {CONFIG} deactivate -y")
        session.wait_for_power_off(machine, 300)
        assert_nothing_says_why(since)
        assert_cold_decoy("after deactivate")

    with subtest("a plain emergency powers off when the way back cannot delete a link"):
        enter_with_tunl0("activate-emergency")
        since = len(machine.full_console_log)
        leave_detached(f"nails --config {CONFIG} emergency")
        session.wait_for_power_off(machine, 300)
        assert_nothing_says_why(since)
        assert_cold_decoy("after emergency")
  '';
}
