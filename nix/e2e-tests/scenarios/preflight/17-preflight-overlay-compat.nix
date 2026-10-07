# Scenario `preflight-overlay-compat` of the `preflight-vfat-targets` batch:
#   tests/preflight/17-preflight-vfat-targets.nix
# Formerly the stand-alone test
#   tests/preflight/17-preflight-overlay-compat.nix
# It now shares one VM boot with the batch's other scenarios (lib/batch.nix);
# its subtests and assertions are unchanged.
#
# Test 17: Preflight Overlay Compatibility

_:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  preflightHelpers = import ./../../lib/preflight-helpers.nix;
  baseOs = import ./../../lib/base-os-overlays.nix;
in
{
  name = "preflight-overlay-compat";
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
    def scenario_preflight_overlay_compat() -> None:
        def write_overlay_compat_config(path):
            write_text_file(path, """
    hidden_volume_root = "/mnt/data"
    overlay_mode = "explicit"

    ${baseOs.toml}
    [[overlays]]
    name = "vfat-target"
    lower = "/mnt/vfat-target"
    upper = "/mnt/data/vfat-target"
    work = "/mnt/data/.work/vfat-target"
    target = "/mnt/vfat-target"
    """.strip() + "\n")

        machine.wait_for_unit("multi-user.target")
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

        with subtest("small vfat overlay target is surfaced as snapshot-pivot warning"):
            machine.succeed(
                    "bash -lc 'truncate -s 64M /tmp/vfat.img && mkfs.vfat /tmp/vfat.img && mkdir -p /mnt/vfat-target && mount -o loop /tmp/vfat.img /mnt/vfat-target && touch /mnt/vfat-target/compat-proof'"
                )
            write_overlay_compat_config("/tmp/preflight-overlay-compat.toml")
            result = run_command_capture(
                "preflight-overlay-compat",
                "nails --config /tmp/preflight-overlay-compat.toml activate --dry-run --overlay-only --session keep --ascii",
            )
            assert_command_succeeded(result)
            assert_result_contains(result, ["overlay-compatibility", "vfat", "snapshot pivot"], stream="stdout")
            machine.succeed("umount /mnt/vfat-target")

        machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")
  '';
}
