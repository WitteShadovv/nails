# Session: the window's emergency through the engine's helper
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
# The test shows:
#
#   - the helper takes it, and the engine's emergency powers the machine off;
#   - the next cold boot is the plain decoy, with the hidden volume closed.
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

  # One soft-reboot, the power-off and a cold boot.
  globalTimeout = 1200;

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
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
        session.wait_for_power_off(machine, 300)

    with subtest("the next cold boot is the plain decoy with the hidden volume closed"):
        machine.start()
        machine.wait_for_unit("multi-user.target")
        session.assert_decoy_root(machine)
        machine.fail("test -e /dev/mapper/data")
  '';
}
