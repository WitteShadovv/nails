# Scenario `preflight-symlink-support` of the `preflight-vfat-targets` batch:
#   tests/preflight/17-preflight-vfat-targets.nix
# Formerly the stand-alone test
#   tests/preflight/18-preflight-symlink-support.nix
# It now shares one VM boot with the batch's other scenarios (lib/batch.nix).
#
# Test 18: Preflight Symlink Support
# A FAT hidden volume cannot hold symlinks or the root overlay's upper:
# activation refuses it with a message naming the problem, before any next
# root is prepared.

_:
let
  preflightHelpers = import ./../../lib/preflight-helpers.nix;
in
{
  name = "preflight-symlink-support";
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
    def scenario_preflight_symlink_support() -> None:
        def write_fat_hidden_config(path):
            write_text_file(path, """
    hidden_volume_root = "/mnt/fat-hidden"
    minimum_space_mb = 10
    """.strip() + "\n")

        machine.wait_for_unit("multi-user.target")

        with subtest("fat hidden volume is rejected before staging config symlinks"):
            # The image lives on the /run tmpfs: an image file on the decoy's own
            # disk is refused by the attach gate before the symlink check runs.
            machine.succeed(
                    "bash -lc 'truncate -s 96M /run/fat-hidden.img && mkfs.vfat /run/fat-hidden.img && mkdir -p /mnt/fat-hidden && mount -o loop /run/fat-hidden.img /mnt/fat-hidden'"
                )
            write_fat_hidden_config("/tmp/preflight-symlink-support.toml")
            result = run_command_capture(
                "preflight-symlink-support",
                "nails --config /tmp/preflight-symlink-support.toml activate --overlay-only -y",
            )
            assert_command_failed(result)
            assert_result_contains(
                result,
                ["does not support symbolic links", "Linux filesystem", "FAT32 and exFAT"],
                stream="stderr",
            )
            machine.succeed("umount /mnt/fat-hidden")
  '';
}
