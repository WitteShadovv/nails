# Session: the window's emergency, through the engine's helper and through
# the operator's own power-off
#
# The window's Emergency control does not ask the person anything and does
# not go through the window's worker: it writes the engine's emergency onto
# the helper's pipe itself, as the request
#
#   {"v":1,"id":0,"op":{"emergency":{"poweroff":true,"reboot":false}}}
#
# (the window's `emergency::request_line`, which a unit test of the window
# pins to these bytes). Here the static engine with the `gui` cargo feature
# serves that request in a hidden NixOS session: a shell client speaks the
# window's half of the protocol to `nails helper --stdio`, run as root as the
# launcher and pkexec run it, the hello the helper names and then that line.
# Where no helper takes the request in time, the window asks logind for the
# power-off itself, as the operator: `systemctl poweroff --no-ask-password`
# from its fixed path, with no terminal (the window's streams are
# /dev/null) and, here, no environment at all. The second session runs that
# command line from the operator's login on tty1, in a scope of the user's
# service manager, where a desktop or a terminal runs the window. The test
# shows:
#
#   - the helper takes the request, and the engine's emergency powers the
#     machine off;
#   - polkit and logind let the operator's power-off through without a
#     password, and the machine powers off;
#   - each cold boot after is the plain decoy, with the hidden volume closed.
#
# Each power-off is proved, not taken from QEMU's exit: the driver starts the
# machine with -no-reboot, so a reboot or a kernel panic ends QEMU too. Only
# the kernel's own "reboot: Power down" on the console, with no reboot or
# panic before it, passes (`session.wait_for_real_power_off`).
{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  packages = self.packages.x86_64-linux;
  # The release binary with the window's helper built in: the `gui` cargo
  # feature, which no release enables yet.
  windowEngine = packages.nails.overrideAttrs (old: {
    pname = "nails-window";
    cargoBuildFlags = old.cargoBuildFlags ++ [
      "--features"
      "gui"
    ];
  });
  # The window's half of the protocol up to its emergency. The helper reads
  # requests from a pipe of its own; its hello is echoed back as the
  # window's, which names the same release and protocol.
  client = pkgs.writeShellScript "window-emergency-client" ''
    set -eu
    coproc HELPER { exec /mnt/data/nails --config /mnt/data/config/nails.toml helper --stdio 2>/dev/null; }
    IFS= read -r -t 60 hello <&"''${HELPER[0]}"
    theirs=''${hello#'{"hello":'}
    theirs=''${theirs%'}'}
    printf '{"v":1,"id":1,"op":{"hello":%s}}\n' "$theirs" >&"''${HELPER[1]}"
    IFS= read -r -t 60 answer <&"''${HELPER[0]}"
    case "$answer" in
      *'"id":1'*'"ok":true'*) ;;
      *) echo "the helper did not take the hello: $answer" >&2; exit 1 ;;
    esac
    printf '%s\n' '{"v":1,"id":0,"op":{"emergency":{"poweroff":true,"reboot":false}}}' >&"''${HELPER[1]}"
    # The engine's emergency powers off: nothing here returns.
    sleep 600
  '';
in
{
  name = "session-window-emergency";
  meta.tags = [ "session" ];

  # Two soft-reboots, two power-offs and two cold boots.
  globalTimeout = 1500;

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      # What decides the operator's own power-off, as on every desktop.
      security.polkit.enable = true;
      system.extraDependencies = [
        windowEngine
        client
      ];
    };

  testScript = _: ''
    from nails_e2e import session

    CONFIG = "/mnt/data/config/nails.toml"
    UPPER = "/mnt/data/root/upper"

    machine.start()
    machine.wait_for_unit("multi-user.target")

    with subtest("a build with the window's helper on the hidden volume"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed("install -m 0755 ${windowEngine}/bin/nails /mnt/data/nails")
        machine.succeed(
            "mkdir -p /mnt/data/config && "
            f"cat > {CONFIG} <<'EOF'\n"
            "hidden_volume_root = \"/mnt/data\"\n"
            "minimum_space_mb = 100\n"
            "EOF"
        )

    with subtest("activate through sudo as the operator"):
        session.follow_soft_reboot(
            machine,
            f"su testuser -c 'sudo /mnt/data/nails --config {CONFIG} activate -y --overlay-only' "
            "> /mnt/data/activate.log 2>&1",
            "activate",
        )
        session.assert_hidden_root(machine, UPPER)

    with subtest("the window's emergency request through the helper powers off"):
        # The helper answers the hello before anything else: a client that
        # fails on it ends at once, and the machine stays on.
        machine.execute(
            "(${client}) </dev/null >/dev/null 2>/mnt/data/client.err &",
            check_return=False,
            check_output=False,
        )
        session.wait_for_real_power_off(machine, 300)

    with subtest("the next cold boot is the plain decoy with the hidden volume closed"):
        machine.start()
        machine.wait_for_unit("multi-user.target")
        session.assert_decoy_root(machine)
        machine.fail("test -e /dev/mapper/data")

    with subtest("activate again, and log the operator in on tty1"):
        machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
        session.follow_soft_reboot(
            machine,
            f"su testuser -c 'sudo /mnt/data/nails --config {CONFIG} activate -y --overlay-only' "
            "> /mnt/data/activate-again.log 2>&1",
            "activate again",
        )
        session.assert_hidden_root(machine, UPPER)
        machine.wait_for_unit("getty@tty1.service")
        # Clear tty1 first, so an earlier prompt cannot match; wait for the
        # password prompt before typing (login flushes typeahead).
        machine.succeed("printf '\\033[H\\033[2J' > /dev/tty1")
        machine.send_chars("testuser\n")
        machine.wait_until_tty_matches("1", "Password: ", timeout=60)
        machine.send_chars("test\n")
        machine.wait_until_succeeds(
            "loginctl list-sessions --no-legend | grep -q testuser", timeout=60
        )
        uid = machine.succeed("id -u testuser").strip()
        machine.wait_until_succeeds(f"systemctl is-active user@{uid}.service", timeout=60)

    with subtest("the operator's own power-off, as the window asks for it, powers off"):
        # The window's fallback command line (`Fallback::system` on NixOS,
        # which a unit test of the window pins), in a scope of the user's
        # manager, with no terminal and an empty environment.
        machine.send_chars(
            "setsid -f systemd-run --user --scope --quiet -- env -i "
            "/run/current-system/sw/bin/systemctl poweroff --no-ask-password "
            "</dev/null >/dev/null 2>&1\n"
        )
        session.wait_for_real_power_off(machine, 300)

    with subtest("the cold boot after it is the plain decoy too"):
        machine.start()
        machine.wait_for_unit("multi-user.target")
        session.assert_decoy_root(machine)
        machine.fail("test -e /dev/mapper/data")
  '';
}
