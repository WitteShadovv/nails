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
    ${overlayHelpers.nailsRuntimeRootFn}
    ${testHelpers.runDetachedCommandFn}
    ${testHelpers.canonicalDeactivateFn}
    ${assertions.assertOverlayMountedFn}
    ${assertions.assertNoOverlaysFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.wait_until_succeeds("findmnt -n -o FSTYPE /boot | grep -qx vfat")

    config_path = "/tmp/nails-boot-pivot.toml"
    write_boot_only_config(config_path)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    machine.succeed("mkdir -p /mnt/data/boot /mnt/data/.work/boot")

    with subtest("phase 1: confirm the decoy boot filesystem is VFAT"):
        machine.succeed("findmnt -n -o FSTYPE /boot | grep -qx vfat")
        machine.succeed("printf %s decoy-boot > /boot/decoy-boot.txt")

    with subtest("phase 2: activation performs snapshot pivot for /boot"):
        machine.succeed(
            f"nails --config {config_path} activate --overlay-only --session keep --pivot allow -y"
        )
        machine.succeed("findmnt -n -o FSTYPE /boot | grep -qx overlay")
        # The pivot staging and snapshot live inside the per-activation runtime
        # root (a random-named tmpfs under /run), read from the state file.
        runtime_root = nails_runtime_root()
        machine.succeed(f"findmnt -n -o FSTYPE {runtime_root} | grep -qx tmpfs")
        machine.succeed(f"findmnt -n -o FSTYPE {runtime_root}/boot | grep -qx overlay")
        machine.succeed(f"findmnt -n -o FSTYPE {runtime_root}/boot-snapshot | grep -qx tmpfs")
        machine.succeed(f"mountpoint -q {runtime_root}/boot")
        machine.succeed(f"test -f {runtime_root}/boot-snapshot/decoy-boot.txt")
        machine.succeed("printf %s hidden-boot > /boot/hidden-boot.txt")
        machine.succeed("test -f /mnt/data/boot/hidden-boot.txt")

    with subtest("phase 3: deactivation restores the original VFAT boot view"):
        canonical_deactivate(config_path, unit_name="nails-deactivate-overlay-boot-pivot")
        assert_no_overlays(["/boot"])
        # The runtime scaffolding tmpfs and its staging are fully torn down.
        machine.fail(f"findmnt -n {runtime_root}/boot")
        machine.fail(f"findmnt -n {runtime_root}")
        machine.fail(f"test -e {runtime_root}")
        machine.succeed("findmnt -n -o FSTYPE /boot | grep -qx vfat")
        machine.succeed("test -f /boot/decoy-boot.txt")
        machine.fail("test -e /boot/hidden-boot.txt")
        machine.succeed("""${hiddenVolume.mountHiddenVolume}""")
        machine.succeed("test -f /mnt/data/boot/hidden-boot.txt")
        machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")
  '';
}
