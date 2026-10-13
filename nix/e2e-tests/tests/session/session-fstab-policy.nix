# The fstab policy: every decoy filesystem the hidden systemd would mount gets
# a safe decision before the switch (ADR 0008, section 2).
#
# The decoy here has an ESP at /boot, a separate ext4 filesystem at /srv/data,
# one on LVM at /srv/files and a swap partition in its fstab, besides the root
# and the VM's own Nix store. Like a Debian or Ubuntu host with dmsetup, it
# also runs blk-availability.service (lib/blk-availability.nix), whose stop in
# every soft-reboot unmounts the filesystems on device-mapper devices. In the
# hidden session:
#
#   - /boot is a read-only bind: a write fails with EROFS and the ESP is
#     unchanged afterwards;
#   - /srv/data is an overlay whose upper is on the hidden volume: a hidden
#     write lands there and never on the extra disk;
#   - the swap unit is masked, so the hidden systemd never swaps onto a decoy
#     disk;
#   - the VM's /nix/store (an overlay of the host store share) is overlaid too,
#     which is what lets PID 1 find its own binary in the hidden root;
#   - the hidden volume and the LVM filesystem the session carries for the way
#     back are still mounted: the switch ran blk-availability's stop with its
#     command cleared. On real hardware the uncleared stop unmounted the hidden
#     volume below /run/nextroot; here the carried store mounts below the
#     volume keep it busy, and the LVM filesystem shows the same loss.
#
# Back on the decoy, the filesystems are mounted by the decoy's own fstab
# again, without a trace of the hidden writes, and blk-availability's stop is
# back for the decoy's own shutdown.
{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
in
{
  name = "session-fstab-policy";
  meta.tags = [
    "forensic"
    "session"
  ];
  globalTimeout = 1200;

  nodes.machine =
    { ... }:
    {
      imports = [
        ./../../lib/vm-config.nix
        ./../../lib/blk-availability.nix
      ];
      environment.systemPackages = [
        self.packages.${pkgs.stdenv.hostPlatform.system}.nails
        pkgs.dosfstools
      ];
      virtualisation.emptyDiskImages = [
        {
          size = 64;
          driveConfig.deviceExtraOpts.serial = "esp";
        }
        {
          size = 256;
          driveConfig.deviceExtraOpts.serial = "extra";
        }
        {
          size = 64;
          driveConfig.deviceExtraOpts.serial = "swap";
        }
        {
          size = 64;
          driveConfig.deviceExtraOpts.serial = "lvm";
        }
      ];
      boot.supportedFilesystems = [ "vfat" ];
      virtualisation.fileSystems = {
        "/boot" = {
          device = "/dev/disk/by-id/virtio-esp";
          fsType = "vfat";
          autoFormat = true;
        };
        "/srv/data" = {
          device = "/dev/disk/by-id/virtio-extra";
          fsType = "ext4";
          autoFormat = true;
        };
      };
    };

  testScript = _: ''
    from nails_e2e import session

    ${testHelpers.canonicalActivateFn}
    ${testHelpers.canonicalDeactivateFn}

    CONFIG = "/mnt/data/config/nails.toml"
    SWAP_UNIT = "dev-disk-by\\x2did-virtio\\x2dswap.swap"
    LV = "/dev/mapper/vg0-files"
    BLK_UNIT = "blk-availability.service"
    BLKDEACTIVATE = "/bin/blkdeactivate -u -l wholevg -m disablequeueing -r wait"


    def esp_hashes():
        return machine.succeed(
            "cd /boot && find . -xdev -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum"
        )


    def blk_availability_stop():
        return machine.succeed(f"systemctl show -P ExecStop {BLK_UNIT}").strip()


    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("mountpoint -q /boot && mountpoint -q /srv/data")
    # A filesystem on LVM, as on many Debian and Ubuntu servers: a
    # device-mapper device, which blk-availability's stop unmounts.
    machine.succeed(
        "pvcreate -q /dev/disk/by-id/virtio-lvm && vgcreate -q vg0 /dev/disk/by-id/virtio-lvm && "
        "lvcreate -q -y -n files -l 100%FREE vg0 && mkfs.ext4 -q /dev/vg0/files && "
        "mkdir -p /srv/files"
    )
    # A swap partition in the decoy's fstab, never activated by the decoy
    # itself (the swap pre-flight check refuses active swap); the hidden
    # systemd must not activate it either. The VM profile overrides
    # swapDevices and the LVM filesystem only exists now, so both lines are
    # added to the decoy's fstab directly.
    machine.succeed("mkswap /dev/disk/by-id/virtio-swap")
    machine.succeed(
        "cp --remove-destination \"$(readlink -f /etc/fstab)\" /etc/fstab && "
        "echo '/dev/disk/by-id/virtio-swap none swap defaults,noauto 0 0' >> /etc/fstab && "
        f"echo '{LV} /srv/files ext4 defaults 0 2' >> /etc/fstab && "
        "systemctl daemon-reload && mount /srv/files"
    )
    machine.succeed(
        "echo decoy > /boot/decoy-file && echo decoy > /srv/data/decoy-file && "
        "echo decoy > /srv/files/decoy-file && sync"
    )
    esp_before = esp_hashes()

    with subtest("blk-availability's stop unmounts the decoy's device-mapper filesystems"):
        # Started at boot, so every soft-reboot runs its stop. Stopping it here
        # shows the stop is the real one: without the session's guard the
        # switch would lose /srv/files the same way.
        machine.succeed(f"systemctl is-active {BLK_UNIT}")
        stop = blk_availability_stop()
        assert BLKDEACTIVATE in stop, stop
        machine.succeed(f"systemctl stop {BLK_UNIT}")
        machine.log(machine.succeed(f"journalctl -b -u {BLK_UNIT} -o cat --no-pager"))
        machine.fail("mountpoint -q /srv/files")
        machine.succeed(
            f"vgchange -q -ay vg0 && udevadm settle && mount /srv/files && systemctl start {BLK_UNIT}"
        )
        assert machine.succeed("cat /srv/files/decoy-file").strip() == "decoy"

    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    machine.succeed("nails init /mnt/data")
    machine.succeed(
        f"cat > {CONFIG} <<'EOF'\n"
        "hidden_volume_root = \"/mnt/data\"\n"
        "minimum_space_mb = 100\n"
        "EOF"
    )

    with subtest("check reports the decision for every decoy filesystem"):
        out = machine.succeed(f"nails --config {CONFIG} check --overlay-only")
        machine.log(out)
        assert "/boot: read-only" in out, out
        assert "/srv/data: overlaid" in out, out
        assert "/srv/files: overlaid" in out, out
        assert "masked" in out, out

    canonical_activate(CONFIG, "--overlay-only", "activate")

    with subtest("the switch left the hidden volume and the carried LVM filesystem mounted"):
        machine.succeed("mountpoint -q /mnt/data")
        source = machine.succeed("findmnt -no SOURCE /mnt/data").strip()
        assert source == "/dev/mapper/data", source
        machine.succeed("test -s /mnt/data/activate.log && test -d /mnt/data/root/upper")
        # The session holds the decoy's own /srv/files for the way back, which
        # binds it at /srv/files again.
        held = machine.succeed(f"lsblk -no MOUNTPOINTS {LV}").strip()
        assert held, f"{LV} is not mounted: the way back has no /srv/files to put back"
        # The unit runs in the hidden session too; its stop stays cleared until
        # the way back has switched.
        machine.succeed(f"systemctl is-active {BLK_UNIT}")
        stop = blk_availability_stop()
        assert stop == "", f"{BLK_UNIT} still stops with {stop}"

    with subtest("the ESP is read-only in the hidden root"):
        assert machine.succeed("cat /boot/decoy-file").strip() == "decoy"
        machine.fail("touch /boot/hidden-write")
        assert "ro" in machine.succeed("findmnt -no OPTIONS /boot").split(",")

    with subtest("a separate decoy filesystem is overlaid with a hidden upper"):
        assert session.root_fstype(machine) == "overlay"
        assert machine.succeed("findmnt -no FSTYPE /srv/data").strip() == "overlay"
        assert machine.succeed("cat /srv/data/decoy-file").strip() == "decoy"
        machine.succeed("echo hidden > /srv/data/hidden-file && sync")
        machine.succeed("test -s /mnt/data/root/mounts/srv-data/upper/hidden-file")
        machine.succeed(
            "mkdir -p /run/peek && mount /dev/disk/by-id/virtio-extra /run/peek "
            "&& mount -o remount,bind,ro /run/peek"
        )
        machine.fail("test -e /run/peek/hidden-file")
        machine.succeed("umount /run/peek && rmdir /run/peek")

    with subtest("decoy swap is masked and never active"):
        state = machine.succeed(f"systemctl show -p LoadState --value '{SWAP_UNIT}'").strip()
        assert state == "masked", f"{SWAP_UNIT}: {state}"
        machine.fail(f"systemctl start '{SWAP_UNIT}'")
        assert machine.succeed("swapon --show --noheadings").strip() == ""

    with subtest("the Nix store of the VM is overlaid too"):
        assert machine.succeed("findmnt -no FSTYPE /nix/store").strip() == "overlay"
        machine.succeed("test -x /run/current-system/systemd/lib/systemd/systemd")

    canonical_deactivate(CONFIG, "deactivate")

    with subtest("back on the decoy, nothing of the hidden writes is on its disks"):
        machine.succeed("mountpoint -q /boot && mountpoint -q /srv/data")
        machine.fail("test -e /srv/data/hidden-file")
        machine.fail("test -e /boot/hidden-write")
        assert machine.succeed("cat /srv/data/decoy-file").strip() == "decoy"
        assert esp_hashes() == esp_before, "the ESP changed"
        state = machine.succeed(f"systemctl show -p LoadState --value '{SWAP_UNIT}'").strip()
        assert state != "masked", f"the swap mask leaked into the decoy: {state}"
        source = machine.succeed("findmnt -no SOURCE /srv/files").strip()
        assert source == LV, f"/srv/files is {source!r} after the way back"
        assert machine.succeed("cat /srv/files/decoy-file").strip() == "decoy"

    with subtest("blk-availability's stop is back for the decoy's own shutdown"):
        machine.fail(f"test -e /run/systemd/system/{BLK_UNIT}.d")
        machine.succeed(f"systemctl is-active {BLK_UNIT}")
        stop = blk_availability_stop()
        assert BLKDEACTIVATE in stop, stop
  '';
}
