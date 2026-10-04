# Test 13: Quick start, run exactly as the README documents it
#
# The README tells the operator to copy the verified binary onto the mounted
# hidden root and then invoke it by its full path, under `sudo`, with no
# `--config`: the hidden-volume root is derived from the binary's own location.
# Every other smoke test puts `nails` on PATH and passes `--config`, so none of
# them exercises that documented path. This one does: it copies the binary onto
# the hidden root, runs `init` and then `activate` as an unprivileged operator
# through `su - testuser -c 'sudo /mnt/data/nails ...'`, and never passes
# `--config`.
#
# NOTE (evaluate under nix): the default (auto) overlay set covers /nix, which
# drives the NixOS-specific nix-store handling, so this can only be confirmed by
# `nix build .#checks.x86_64-linux.quickstart-zero-config` on a Nix host.

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


    def hidden_status():
        # Read `status --json` through the hidden-root binary with no --config, so
        # the state is resolved purely from the binary location.
        machine.succeed(
            "su - testuser -c "
            + "'sudo /mnt/data/nails status --json "
            + "> /tmp/nails-status.json 2>/tmp/nails-status.err'"
        )
        payload = json.loads(machine.succeed("cat /tmp/nails-status.json"))
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

    with subtest("status before activation is Inactive, resolved from the binary location"):
        status = hidden_status()
        assert status["state"]["kind"] == "inactive", f"expected inactive, got {status}"

    with subtest("activate with no --config overlays the default set, run by full path under sudo"):
        machine.succeed(
            "su - testuser -c "
            + f"'sudo {hidden_nails} activate --overlay-only --session keep -y'"
        )

        home_mount = machine.succeed("mount | grep 'overlay on /home' || true")
        etc_mount = machine.succeed("mount | grep 'overlay on /etc' || true")
        assert "overlay" in home_mount, "no overlay mounted on /home"
        assert "overlay" in etc_mount, "no overlay mounted on /etc"
        assert "/mnt/data/home" in home_mount, "the /home overlay upperdir is not on the hidden root"
        assert "/mnt/data/etc" in etc_mount, "the /etc overlay upperdir is not on the hidden root"

        status = hidden_status()
        assert status["state"]["kind"] == "active", f"expected active, got {status}"
        active_paths = {overlay["mount_point"] for overlay in status["overlays"]}
        assert {"/etc", "/home"}.issubset(active_paths), status

    with subtest("the pre-activation residue report lands on the hidden root"):
        report = (
            machine.succeed("ls /mnt/data/reports/activation-residue-*.json")
            .splitlines()[0]
            .strip()
        )
        machine.succeed(f"grep -q 'schema_version' {report}")

    with subtest("emergency teardown returns the host to Inactive with no overlays"):
        machine.succeed("su - testuser -c " + f"'sudo {hidden_nails} emergency'")
        machine.fail("mount | grep 'overlay on /home'")
        machine.fail("mount | grep 'overlay on /etc'")
        status = hidden_status()
        assert status["state"]["kind"] == "inactive", f"expected inactive after teardown, got {status}"

    with subtest("the hidden backend closes cleanly, leaving no master key in RAM"):
        machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")
  '';
}
