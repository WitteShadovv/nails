# Fault test (h): emergency on a session that pivoted a VFAT /boot.
#
# When /boot is VFAT (no overlay support), activation stages a snapshot pivot
# under /run/nails-pivot and overlays that instead. Emergency must detach that
# pivot like any other overlay and leave no NAILS mount live under /boot or the
# staging base, and it must remove the staging directories it created, so nothing
# points back at the hidden session.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  assertions = import ./../../lib/assertions.nix;
  overlayHelpers = import ./../../lib/overlay-helpers.nix;
in
{
  name = "faults-emergency-vfat-pivot";
  meta.tags = [
    "faults"
    "overlay"
  ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vfat-boot-vm-config.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
    };

  testScript = _: ''
    ${overlayHelpers.writeBootOnlyConfigFn}
    ${assertions.assertNoOverlaysFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.wait_until_succeeds("findmnt -n -o FSTYPE /boot | grep -qx vfat")

    config_path = "/tmp/nails-boot-pivot.toml"
    write_boot_only_config(config_path)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    machine.succeed("mkdir -p /mnt/data/boot /mnt/data/.work/boot")

    with subtest("activation pivots the VFAT /boot behind an overlay"):
        machine.succeed(
            f"nails --config {config_path} activate --overlay-only --session keep --pivot allow -y"
        )
        machine.succeed("findmnt -n -o FSTYPE /boot | grep -qx overlay")
        machine.succeed("mountpoint -q /run/nails-pivot/boot")
        machine.succeed("printf %s hidden-boot > /boot/hidden-boot.txt")
        machine.succeed("test -f /mnt/data/boot/hidden-boot.txt")

    with subtest("emergency detaches the pivot and removes the staging"):
        machine.succeed(f"nails --config {config_path} emergency")
        # No NAILS overlay is left at /boot and nothing stays mounted under the
        # pivot staging base.
        assert_no_overlays(["/boot"])
        machine.fail("findmnt -n /run/nails-pivot/boot")
        machine.fail("findmnt -n /run/nails-pivot/boot-snapshot")
        # The staging directories NAILS created are gone, so nothing points back
        # at the hidden session.
        machine.fail("test -e /run/nails-pivot/boot")
        machine.fail("test -e /run/nails-pivot/boot-snapshot")

    with subtest("the backend then closes cleanly with the strict helper"):
        machine.succeed("""${hiddenVolume.unmountHiddenVolumeStrict}""")
        machine.fail("test -e /dev/mapper/data")
  '';
}
