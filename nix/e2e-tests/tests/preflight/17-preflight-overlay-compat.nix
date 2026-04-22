# Test 17: Preflight Overlay Compatibility

{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  preflightHelpers = import ./../../lib/preflight-helpers.nix;
in
{
  name = "preflight-overlay-compat";
  meta.tags = [
    "preflight"
    "smoke"
  ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [
        self.packages.x86_64-linux.nails
        pkgs.dosfstools
      ];
    };

  testScript = _: ''
    ${preflightHelpers.writeTextFileFn}
    ${preflightHelpers.runCommandCaptureFn}
    ${preflightHelpers.commandAssertionsFn}

    def write_overlay_compat_config(path):
        write_text_file(path, """
    hidden_volume_root: /mnt/hidden-volume
    overlay_mode: explicit
    overlays:
      - name: vfat-target
        lower: /mnt/vfat-target
        upper: /mnt/hidden-volume/vfat-target
        work: /mnt/hidden-volume/.work/vfat-target
        target: /mnt/vfat-target
    """.strip() + "\n")

    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("small vfat overlay target is surfaced as snapshot-pivot warning"):
        machine.succeed(
                "bash -lc 'truncate -s 64M /tmp/vfat.img && mkfs.vfat /tmp/vfat.img && mkdir -p /mnt/vfat-target && mount -o loop /tmp/vfat.img /mnt/vfat-target && touch /mnt/vfat-target/compat-proof'"
            )
        write_overlay_compat_config("/tmp/preflight-overlay-compat.yaml")
        result = run_command_capture(
            "preflight-overlay-compat",
            "nails --config /tmp/preflight-overlay-compat.yaml activate --dry-run --overlay-only --no-kill-session --plain",
        )
        assert_command_succeeded(result)
        assert_result_contains(result, ["overlay-compatibility", "vfat", "snapshot pivot"], stream="stdout")
        machine.succeed("umount /mnt/vfat-target")

    machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")
  '';
}
