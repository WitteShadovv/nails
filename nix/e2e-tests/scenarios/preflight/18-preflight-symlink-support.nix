# Scenario `preflight-symlink-support` of the `preflight-vfat-targets` batch:
#   tests/preflight/17-preflight-vfat-targets.nix
# Formerly the stand-alone test
#   tests/preflight/18-preflight-symlink-support.nix
# It now shares one VM boot with the batch's other scenarios (lib/batch.nix);
# its subtests and assertions are unchanged.
#
# Test 18: Preflight Symlink Support

_:
let
  preflightHelpers = import ./../../lib/preflight-helpers.nix;
  baseOs = import ./../../lib/base-os-overlays.nix;
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
    overlay_mode = "explicit"

    ${baseOs.tomlFor "/mnt/fat-hidden"}
    [[overlays]]
    name = "home"
    lower = "/home"
    upper = "/mnt/fat-hidden/home"
    work = "/mnt/fat-hidden/.work/home"
    target = "/home"
    """.strip() + "\n")

        machine.wait_for_unit("multi-user.target")

        with subtest("fat hidden volume is rejected before staging config symlinks"):
            machine.succeed(
                    "bash -lc 'truncate -s 96M /tmp/fat-hidden.img && mkfs.vfat /tmp/fat-hidden.img && mkdir -p /mnt/fat-hidden && mount -o loop /tmp/fat-hidden.img /mnt/fat-hidden'"
                )
            write_fat_hidden_config("/tmp/preflight-symlink-support.toml")
            result = run_command_capture(
                "preflight-symlink-support",
                "nails --config /tmp/preflight-symlink-support.toml activate --overlay-only --session keep -y",
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
