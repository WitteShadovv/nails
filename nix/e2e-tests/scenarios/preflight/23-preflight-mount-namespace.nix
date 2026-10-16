# Scenario `preflight-mount-namespace` of the `preflight-hidden-root` batch:
#   tests/preflight/13-preflight-hidden-root.nix
# Formerly the stand-alone test
#   tests/preflight/23-preflight-mount-namespace.nix
# It now shares one VM boot with the batch's other scenarios (lib/batch.nix).
#
# Test 23: Preflight Mount Namespace
# PID 1 must see /run/nextroot, so activation from a private mount namespace
# (`unshare -m`) is refused by the mount-namespace check before any next root
# is prepared.

_:
let
  preflightHelpers = import ./../../lib/preflight-helpers.nix;
in
{
  name = "preflight-mount-namespace";
  tags = [
    "preflight"
    "smoke"
  ];

  helpers = [
    preflightHelpers.writeTextFileFn
    preflightHelpers.runCommandCaptureFn
    preflightHelpers.commandAssertionsFn
  ];

  script = ''
    def scenario_preflight_mount_namespace() -> None:
        def write_hidden_config(path):
            write_text_file(path, """
    hidden_volume_root = "/mnt/data"
    minimum_space_mb = 10
    """.strip() + "\n")

        machine.wait_for_unit("multi-user.target")

        with subtest("activation in a private mount namespace is refused before mounting"):
            # A real ext4 hidden volume so the namespace check is the decisive
            # failure rather than an unrelated storage check. Its image lives on
            # the /run tmpfs: an image file on the decoy's own disk is refused by
            # the attach gate before any check runs.
            machine.succeed(
                    "bash -lc 'truncate -s 128M /run/hidden.img && mkfs.ext4 -q /run/hidden.img && mkdir -p /mnt/data && mount -o loop /run/hidden.img /mnt/data'"
                )
            write_hidden_config("/tmp/preflight-mount-namespace.toml")

            result = run_command_capture(
                "preflight-mount-namespace",
                "unshare -m nails --config /tmp/preflight-mount-namespace.toml activate --overlay-only -y",
            )
            assert_command_failed(result)
            assert_result_contains(
                result,
                ["private mount namespace", "unshare -m"],
                stream="stderr",
            )

            # Pre-flight failed, so no next root was prepared (in any namespace:
            # the refused activation's own namespace is gone with it).
            from nails_e2e import session

            session.assert_decoy_root(machine)
            machine.succeed("test -z \"$(ls -A /run/nextroot 2>/dev/null)\"")

            machine.succeed("umount /mnt/data")
  '';
}
