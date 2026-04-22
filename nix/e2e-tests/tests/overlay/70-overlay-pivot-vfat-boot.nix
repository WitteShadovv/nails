# Test 70: Overlay Pivot on VFAT /boot
# Uses subtests, deterministic waits, hard assertions, and overlay tags only.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  overlayHelpers = import ./../../lib/overlay-helpers.nix;
in
{
  name = "overlay-pivot-vfat-boot";
  meta.tags = [ "overlay" ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vfat-boot-vm-config.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
    };

  testScript = _: ''
    ${overlayHelpers.writeBootOnlyConfigFn}
    ${testHelpers.runDetachedCommandFn}
    ${testHelpers.canonicalDeactivateFn}
    ${assertions.assertOverlayMountedFn}
    ${assertions.assertNoOverlaysFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("nails-vfat-boot-setup.service")

    config_path = "/tmp/nails-boot-pivot.yaml"
    write_boot_only_config(config_path)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    machine.succeed("mkdir -p /mnt/hidden-volume/boot /mnt/hidden-volume/.work/boot")

    with subtest("phase 1: confirm the decoy boot filesystem is VFAT"):
        machine.succeed("findmnt -n -o FSTYPE /boot | grep -qx vfat")
        machine.succeed("printf %s decoy-boot > /boot/decoy-boot.txt")

    with subtest("phase 2: activation performs snapshot pivot for /boot"):
        machine.succeed(
            f"nails --config {config_path} activate --overlay-only --no-kill-session --accept-pivot-risks -y"
        )
        assert_overlay_mounted("/boot")
        machine.succeed("findmnt -n -o FSTYPE /mnt/nails-pivot/boot-snapshot | grep -qx tmpfs")
        machine.succeed("mountpoint -q /mnt/nails-pivot/boot")
        machine.succeed("test -f /mnt/nails-pivot/boot-snapshot/decoy-boot.txt")
        machine.succeed("printf %s hidden-boot > /boot/hidden-boot.txt")
        machine.succeed("test -f /mnt/hidden-volume/boot/hidden-boot.txt")

    with subtest("phase 3: deactivation restores the original VFAT boot view"):
        canonical_deactivate(config_path, unit_name="nails-deactivate-overlay-boot-pivot")
        assert_no_overlays(["/boot"])
        machine.succeed("findmnt -n -o FSTYPE /boot | grep -qx vfat")
        machine.succeed("test -f /boot/decoy-boot.txt")
        machine.fail("test -e /boot/hidden-boot.txt")
        machine.succeed("""${hiddenVolume.mountHiddenVolume}""")
        machine.succeed("test -f /mnt/hidden-volume/boot/hidden-boot.txt")
        machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")
  '';
}
