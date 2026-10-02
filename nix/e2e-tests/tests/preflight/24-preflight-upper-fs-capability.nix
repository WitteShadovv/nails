# Test 24: Preflight Upper-Filesystem Capability
#
# A FAT upper cannot back an overlayfs upper layer (no trusted xattrs), so the
# upper-fs-capability check must refuse activation before anything is mounted,
# naming the backend, and must leave no probe scratch directory behind.

{ self, pkgs, ... }:
let
  preflightHelpers = import ./../../lib/preflight-helpers.nix;
in
{
  name = "preflight-upper-fs-capability";
  meta.tags = [
    "preflight"
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
    hidden_volume_root = "/mnt/fat-hidden"
    overlay_mode = "explicit"

    [[overlays]]
    name = "home"
    lower = "/home"
    upper = "/mnt/fat-hidden/home"
    work = "/mnt/fat-hidden/.work/home"
    target = "/home"
    """.strip() + "\n")

    machine.start()
    machine.wait_for_unit("multi-user.target")

    with subtest("fat upper is refused with a backend-specific capability message"):
        machine.succeed(
                "bash -lc 'truncate -s 96M /tmp/fat-hidden.img && mkfs.vfat /tmp/fat-hidden.img && mkdir -p /mnt/fat-hidden && mount -o loop /tmp/fat-hidden.img /mnt/fat-hidden'"
            )
        write_fat_hidden_config("/tmp/preflight-upper-fs-capability.toml")
        result = run_command_capture(
            "preflight-upper-fs-capability",
            "nails --config /tmp/preflight-upper-fs-capability.toml activate --overlay-only --session keep -y",
        )
        assert_command_failed(result)
        assert_result_contains(
            result,
            ["cannot host an overlayfs upper layer", "vfat", "ext4"],
            stream="stderr",
        )

    with subtest("refusal mounts no overlay and leaves no probe scratch dir"):
        # Preflight runs before any mount, so no overlay backed by the hidden
        # root may exist (neither an activation overlay nor a leftover probe
        # mount). Matching on the upperdir avoids a false positive if the VM's
        # own root happens to be an overlay.
        machine.fail("grep -q 'upperdir=/mnt/fat-hidden' /proc/mounts")
        # The probe removes its .probe-<unique> scratch dir on every path.
        machine.fail("bash -lc 'ls -d /mnt/fat-hidden/.probe-* 2>/dev/null'")
        machine.succeed("umount /mnt/fat-hidden")
  '';
}
