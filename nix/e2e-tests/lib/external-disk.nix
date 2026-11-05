# An external drive for the tests of the daily routine: one USB stick that the
# test attaches and detaches while the VM runs.
#
# The node gets an xHCI controller (`module`); the test script plugs a
# usb-storage drive into it through the QEMU monitor, as session-disk-mounts.nix
# hot-plugs a virtio disk. The drive reports removable media, as a USB stick
# does, so udisks2 takes it for a drive a desktop may mount by itself. Its image
# is a sparse file in the machine's state directory, made at the first plug and
# kept across unplugs, so a drive prepared once can be attached again.
#
#   nodes.machine.imports = [ externalDisk.module ];
#   testScript: ${externalDisk.plugFns}
#
#   drive = plug_usb_drive("stick")  # its /dev node, once the guest sees it
#   unplug_usb_drive("stick")
#
# The guest addresses the drive by its node, the one disk on the USB bus: its
# /dev/disk/by-id name carries the vendor and model strings QEMU reports.
{
  module = _: {
    virtualisation.qemu.options = [ "-device qemu-xhci,id=xhci" ];
  };

  plugFns = ''
    _usb_plugs = {}


    def usb_drive_node():
        """The one disk on the USB bus, or "" while there is none."""
        return machine.succeed(
            "lsblk -dnpo NAME,TRAN | awk '$2 == \"usb\" { print $1 }'"
        ).strip()


    def plug_usb_drive(name, size_mib=512):
        """Attach the drive `name` (its image `name`.img, made sparse at the
        first plug) and return its /dev node once udev has handled it."""
        assert not usb_drive_node(), "a USB drive is attached already"
        image = machine.state_dir / f"{name}.img"
        if not image.exists():
            with open(image, "wb") as handle:
                handle.truncate(size_mib * 1024 * 1024)
        plugs = _usb_plugs.get(name, 0) + 1
        _usb_plugs[name] = plugs
        drive = f"{name}-drive-{plugs}"
        machine.log(
            machine.send_monitor_command(f"drive_add 0 file={image},if=none,id={drive},format=raw")
        )
        machine.log(
            machine.send_monitor_command(
                f"device_add usb-storage,bus=xhci.0,drive={drive},id={name}-usb-{plugs},"
                f"serial={name},removable=on"
            )
        )
        machine.wait_until_succeeds("test -n \"$(lsblk -dnpo NAME,TRAN | awk '$2 == \"usb\"')\"", timeout=60)
        machine.succeed("udevadm settle")
        node = usb_drive_node()
        machine.log(machine.succeed(f"lsblk -o NAME,TRAN,RM,SIZE {node}; ls -l /dev/disk/by-id/"))
        return node


    def unplug_usb_drive(name):
        """Detach the drive `name`, plugged last, and wait until the guest let
        it go."""
        node = usb_drive_node()
        machine.log(machine.send_monitor_command(f"device_del {name}-usb-{_usb_plugs[name]}"))
        machine.wait_until_succeeds(f"test ! -b {node}", timeout=60)
        machine.succeed("udevadm settle")
  '';
}
