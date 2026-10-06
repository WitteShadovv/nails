# Fault test (h): emergency on a session that pivoted a VFAT /boot.
#
# When /boot is VFAT (no overlay support), activation stages a snapshot pivot
# inside the per-activation runtime root (a random-named tmpfs under /run) and
# overlays that instead. Emergency must detach that pivot like any other overlay
# and leave no NAILS mount live under /boot or inside the runtime root, and it
# must unmount and remove the runtime root itself, so nothing points back at the
# hidden session.

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
    ${overlayHelpers.nailsRuntimeRootFn}
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
        # Capture the random runtime root from state before emergency unmounts the
        # hidden volume (and with it the state file).
        runtime_root = nails_runtime_root()
        machine.succeed(f"mountpoint -q {runtime_root}/boot")
        machine.succeed("printf %s hidden-boot > /boot/hidden-boot.txt")
        machine.succeed("test -f /mnt/data/boot/hidden-boot.txt")

    with subtest("emergency detaches the pivot and removes the runtime root"):
        machine.succeed(f"nails --config {config_path} emergency")
        # No NAILS overlay is left at /boot and nothing stays mounted inside the
        # runtime root — which is itself unmounted and removed.
        assert_no_overlays(["/boot"])
        machine.fail(f"findmnt -n {runtime_root}/boot")
        machine.fail(f"findmnt -n {runtime_root}/boot-snapshot")
        machine.fail(f"findmnt -n {runtime_root}")
        # The runtime scaffolding NAILS created is gone, so nothing points back at
        # the hidden session.
        machine.fail(f"test -e {runtime_root}")

    with subtest("the backend then closes cleanly with the strict helper"):
        machine.succeed("""${hiddenVolume.unmountHiddenVolumeStrict}""")
        machine.fail("test -e /dev/mapper/data")
  '';
}
