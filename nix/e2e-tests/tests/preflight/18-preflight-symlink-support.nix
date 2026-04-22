# Test 18: Preflight Symlink Support

{ self, pkgs, ... }:
let
  preflightHelpers = import ./../../lib/preflight-helpers.nix;
in
{
  name = "preflight-symlink-support";
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

    def write_fat_hidden_config(path):
        write_text_file(path, """
    hidden_volume_root: /mnt/fat-hidden
    overlay_mode: explicit
    overlays:
      - name: home
        lower: /home
        upper: /mnt/fat-hidden/home
        work: /mnt/fat-hidden/.work/home
        target: /home
    """.strip() + "\n")

    machine.start()
    machine.wait_for_unit("multi-user.target")

    with subtest("fat hidden volume is rejected before staging config symlinks"):
        machine.succeed(
                "bash -lc 'truncate -s 96M /tmp/fat-hidden.img && mkfs.vfat /tmp/fat-hidden.img && mkdir -p /mnt/fat-hidden && mount -o loop /tmp/fat-hidden.img /mnt/fat-hidden'"
            )
        write_fat_hidden_config("/tmp/preflight-symlink-support.yaml")
        result = run_command_capture(
            "preflight-symlink-support",
            "nails --config /tmp/preflight-symlink-support.yaml activate --overlay-only --no-kill-session -y",
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
