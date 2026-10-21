# Test 13: Quick start, run exactly as the README documents it
#
# The README tells the operator to copy the verified binary onto the mounted
# hidden root and then invoke it by its full path, under `sudo`, with no
# `--config`: the hidden-volume root is derived from the binary's own location.
# Every other smoke test puts `nails` on PATH and passes `--config`, so none of
# them exercises that documented path. This one does: it copies the binary onto
# the hidden root, runs `init`, `activate` (a soft-reboot into the whole-root
# overlay, whose upper lands on that hidden root) and `emergency` (a soft-reboot
# back to the plain decoy, closing the backend) as an unprivileged operator
# through `su - testuser -c 'sudo /mnt/data/nails ...'`, and never passes
# `--config`.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
in
{
  name = "quickstart-zero-config";
  meta.tags = [
    "smoke"
    "init"
    "lifecycle"
  ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      # The binary is copied onto the hidden root and run by its full path, so it
      # is deliberately NOT placed on PATH. sudo must still hand NAILS a PATH that
      # includes the system profile for the tools it shells out to.
      security.sudo.extraConfig = ''
        Defaults secure_path="/run/wrappers/bin:/run/current-system/sw/bin:/usr/bin:/bin"
      '';
    };

  testScript = _: ''
    import json

    from nails_e2e import session


    def hidden_status():
        # Read `status --json` through the hidden-root binary with no --config, so
        # the state is resolved purely from the binary location.
        # The redirection is the root driver shell's: testuser cannot create
        # files in /run.
        machine.succeed(
            "su - testuser -c 'sudo /mnt/data/nails status --json' "
            + "> /run/nails-status.json 2>/run/nails-status.err"
        )
        payload = json.loads(machine.succeed("cat /run/nails-status.json"))
        return payload.get("data", payload)


    machine.start()
    machine.wait_for_unit("multi-user.target")

    hidden_nails = "/mnt/data/nails"

    with subtest("mount the backend and install the verified binary onto it"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        # Stand in for "download and verify elsewhere, then copy onto the hidden
        # root": place the built binary directly on the mounted backend.
        machine.succeed(
            f"install -m 0755 ${self.packages.x86_64-linux.nails}/bin/nails {hidden_nails}"
        )
        machine.succeed(f"test -x {hidden_nails}")

    with subtest("init bootstraps the layout with no --config, run by full path under sudo"):
        init_output = machine.succeed(
            "su - testuser -c "
            + f"'sudo {hidden_nails} init /mnt/data --no-hardware-config'"
        )
        assert "Next steps:" in init_output, init_output
        machine.succeed("test -f /mnt/data/config/nails.toml")
        # The generated config leaves the root commented out, so it is derived
        # from the binary location rather than pinned to this mount point.
        machine.succeed("grep -q '# hidden_volume_root' /mnt/data/config/nails.toml")

    with subtest("status before activation is the plain decoy, resolved from the binary location"):
        status = hidden_status()
        assert status["place"] == "decoy", f"expected the plain decoy, got {status}"

    with subtest("activate with no --config enters the hidden root, run by full path under sudo"):
        session.follow_soft_reboot(
            machine,
            "su - testuser -c "
            + f"'sudo {hidden_nails} activate --overlay-only -y' "
            + "> /mnt/data/quickstart-activate.log 2>&1",
            "quickstart-activate",
        )
        print(machine.succeed("cat /mnt/data/quickstart-activate.log || true"))
        # The root overlay's upper is on the hidden root the binary sits on.
        session.assert_hidden_root(machine, "/mnt/data/root/upper")
        status = hidden_status()
        assert status["place"] == "hidden", f"expected the hidden session, got {status}"

    with subtest("the pre-activation residue report lands on the hidden root"):
        report = (
            machine.succeed("ls /mnt/data/reports/activation-residue-*.json")
            .splitlines()[0]
            .strip()
        )
        machine.succeed(f"grep -q 'schema_version' {report}")

    with subtest("emergency by full path returns to the plain decoy and closes the backend"):
        session.follow_soft_reboot(
            machine,
            "su - testuser -c " + f"'sudo {hidden_nails} emergency'",
            "quickstart-emergency",
        )
        session.assert_decoy_root(machine)
        # The hidden backend closed itself: no master key left in RAM.
        machine.wait_until_succeeds("test ! -e /dev/mapper/data", timeout=60)
  '';
}
