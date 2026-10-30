# The fstab policy: every decoy filesystem the hidden systemd would mount gets
# a safe decision before the switch.
#
# The decoy here has an ESP at /boot, a separate ext4 filesystem at /srv/data,
# one on LVM at /srv/files, a disk at /srv/spare that it does not mount now and
# a swap partition in its fstab, besides the root and the VM's own Nix store,
# a disk at /srv/native that a mount unit of its own mounts, outside the
# fstab, and a zram swap unit of its own whose zram device has a backing disk. Like a Debian or Ubuntu host with dmsetup, it also runs
# blk-availability.service (lib/blk-availability.nix), whose stop in every
# soft-reboot unmounts the filesystems on device-mapper devices. In the hidden
# session:
#
#   - /boot is a read-only bind: a write fails with EROFS and the ESP is
#     unchanged afterwards;
#   - /srv/data is an overlay whose upper is on the hidden volume: a hidden
#     write lands there and never on the extra disk;
#   - the swap unit is masked, so the hidden systemd never swaps onto a decoy
#     disk;
#   - /srv/spare, which local-fs.target requires (no nofail), is skipped
#     rather than masked: local-fs.target is reached, the disk stays
#     unmounted and unchanged, and its fsck and makefs never start. A mask
#     there would leave local-fs.target unreached without a failure. status
#     lists it as skipped;
#   - /srv/native, mounted by the decoy's own unit, is an overlay whose upper
#     is on the hidden volume, as an fstab line would be;
#   - the zram swap is masked as disk swap: its device could write pages back
#     to the backing disk;
#   - a disk at /srv/later, noauto in the fstab but pulled in by
#     multi-user.target through x-systemd.wanted-by=, is masked and stays
#     unchanged: the fstab generator links its mount whatever noauto says;
#   - a disk at /srv/pa/child, which nails-pull.target requires, is masked
#     rather than skipped: its mount requires that of its noauto parent
#     /srv/pa, which a skip would mount. Starting the target fails, and the
#     parent disk stays unmounted and unchanged;
#   - the VM's /nix/store (an overlay of the host store share) is overlaid too,
#     which is what lets PID 1 find its own binary in the hidden root;
#   - the hidden volume and the LVM filesystem the session carries for the way
#     back are still mounted: the switch ran blk-availability's stop with its
#     command cleared. On real hardware the uncleared stop unmounted the hidden
#     volume below /run/nextroot; here the carried store mounts below the
#     volume keep it busy, and the LVM filesystem shows the same loss.
#
# Before the entry, check skips /srv/spare only while systemd has its device
# unit active, as activation does: with udev marking the disk not ready, check
# masks it and warns that local-fs.target will not be reached.
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
        {
          size = 64;
          driveConfig.deviceExtraOpts.serial = "spare";
        }
        {
          size = 64;
          driveConfig.deviceExtraOpts.serial = "native";
        }
        {
          size = 64;
          driveConfig.deviceExtraOpts.serial = "zback";
        }
        {
          size = 64;
          driveConfig.deviceExtraOpts.serial = "later";
        }
        {
          size = 64;
          driveConfig.deviceExtraOpts.serial = "pa";
        }
        {
          size = 64;
          driveConfig.deviceExtraOpts.serial = "pc";
        }
      ];
      boot.kernelModules = [ "zram" ];
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
        # No nofail: local-fs.target requires it, with its fsck and makefs.
        "/srv/spare" = {
          device = "/dev/disk/by-id/virtio-spare";
          fsType = "ext4";
          autoFormat = true;
        };
      };
      # A disk the decoy mounts through a unit of its own. The disk is empty
      # at boot: the test makes its filesystem, then starts the mount.
      systemd.mounts = [
        {
          what = "/dev/disk/by-id/virtio-native";
          where = "/srv/native";
          type = "ext4";
          wantedBy = [ "local-fs.target" ];
          unitConfig.ConditionPathExists = "/run/native-disk-ready";
        }
      ];
      # A zram swap of the decoy's own, as zram-generator makes one. The test
      # gives the zram device a backing disk, then leaves the swap off, as the
      # swap check asks of a zram that can write back.
      systemd.units = {
        "dev-zram0.swap" = {
          wantedBy = [ "swap.target" ];
          text = ''
            [Unit]
            ConditionPathExists=/run/zram-ready
            [Swap]
            What=/dev/zram0
          '';
        };
        # Nothing starts it at boot: the test starts it in the hidden session,
        # where it requires the mount of a disk below a noauto one.
        "nails-pull.target".text = ''
          [Unit]
          Description=The child disk below a noauto one
        '';
      };
    };

  testScript = _: ''
    from nails_e2e import session

    ${testHelpers.canonicalActivateFn}
    ${testHelpers.canonicalDeactivateFn}
    ${testHelpers.readStatusJsonFn}

    CONFIG = "/mnt/data/config/nails.toml"
    SWAP_UNIT = "dev-disk-by\\x2did-virtio\\x2dswap.swap"
    SPARE = "/dev/disk/by-id/virtio-spare"
    SPARE_UNIT = "srv-spare.mount"
    # The units the fstab line of /srv/spare has its mount pull in, which act
    # on its disk.
    SPARE_CHECKERS = (
        "systemd-fsck@dev-disk-by\\x2did-virtio\\x2dspare.service",
        "systemd-makefs@dev-disk-by\\x2did-virtio\\x2dspare.service",
    )
    LV = "/dev/mapper/vg0-files"
    ZRAM_UNIT = "dev-zram0.swap"
    SPARE_DEVICE_UNIT = "dev-disk-by\\x2did-virtio\\x2dspare.device"
    LATER = "/dev/disk/by-id/virtio-later"
    LATER_UNIT = "srv-later.mount"
    PARENT = "/dev/disk/by-id/virtio-pa"
    CHILD = "/dev/disk/by-id/virtio-pc"
    CHILD_UNIT = "srv-pa-child.mount"
    NOT_READY_RULE = "/run/udev/rules.d/99-spare-not-ready.rules"
    BLK_UNIT = "blk-availability.service"
    BLKDEACTIVATE = "/bin/blkdeactivate -u -l wholevg -m disablequeueing -r wait"


    def esp_hashes():
        return machine.succeed(
            "cd /boot && find . -xdev -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum"
        )


    def blk_availability_stop():
        return machine.succeed(f"systemctl show -P ExecStop {BLK_UNIT}").strip()


    def unit_props(unit, *props):
        out = machine.succeed(
            "systemctl show " + " ".join(f"-p {p}" for p in props) + f" '{unit}'"
        )
        return dict(line.split("=", 1) for line in out.splitlines() if "=" in line)


    def monotonic_us():
        # The clock of systemd's *Monotonic timestamps, in microseconds. The
        # boot clock /proc/uptime reads runs with it in a machine that never
        # suspends, as this one.
        return int(float(machine.succeed("cut -d' ' -f1 /proc/uptime").strip()) * 1_000_000)


    def assert_skipped_here(unit, entered_after):
        # The hidden PID 1 pulled the unit in and tested its condition, which
        # was unmet, after the entry, and the unit's last run, if any, came
        # before it: a soft-reboot can carry a unit's timestamps into the
        # other root. Only a service has a main process start time.
        props = unit_props(
            unit,
            "ConditionResult",
            "ConditionTimestampMonotonic",
            "ExecMainStartTimestampMonotonic",
        )
        assert props.get("ConditionResult") == "no", f"{unit}: {props}"
        tested = int(props.get("ConditionTimestampMonotonic") or 0)
        assert tested > entered_after, f"{unit}: {props}"
        started = int(props.get("ExecMainStartTimestampMonotonic") or 0)
        assert started < entered_after, f"{unit} ran on the decoy disk: {props}"


    def spare_hash():
        return machine.succeed(f"sha256sum {SPARE}").split()[0]


    def later_hash():
        return machine.succeed(f"sha256sum {LATER}").split()[0]


    def parent_hash():
        return machine.succeed(f"sha256sum {PARENT}").split()[0]


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
    # The decoy's own unit mounts its disk once it has a filesystem.
    machine.succeed(
        "mkfs.ext4 -q /dev/disk/by-id/virtio-native && touch /run/native-disk-ready && "
        "systemctl start srv-native.mount && echo decoy > /srv/native/decoy-file && sync"
    )
    # local-fs.target requires /srv/spare, which the decoy does not mount now:
    # the hidden systemd would mount it read-write.
    machine.succeed("mountpoint -q /srv/spare && umount /srv/spare")
    spare_before = spare_hash()
    # A zram device that can write its pages back to a disk, its swap off.
    machine.succeed(
        "echo /dev/disk/by-id/virtio-zback > /sys/block/zram0/backing_dev && "
        "echo 32M > /sys/block/zram0/disksize && mkswap /dev/zram0 && touch /run/zram-ready"
    )
    assert machine.succeed("cat /sys/block/zram0/backing_dev").strip() != "none"
    # A disk the decoy's fstab marks noauto but names multi-user.target to
    # pull in: the fstab generator links its mount there whatever noauto
    # says. Not mounted now.
    machine.succeed(
        f"mkfs.ext4 -q {LATER} && "
        f"echo '{LATER} /srv/later ext4 noauto,x-systemd.wanted-by=multi-user.target 0 2' "
        ">> /etc/fstab && systemctl daemon-reload && "
        f"test -L /run/systemd/generator/multi-user.target.wants/{LATER_UNIT}"
    )
    machine.fail("mountpoint -q /srv/later")
    later_before = later_hash()
    # A noauto disk at /srv/pa, and below it one that nails-pull.target
    # requires. systemd has the child's mount require its parent's, so the
    # child's skip would mount the noauto disk before its condition is tested.
    machine.succeed(
        f"mkfs.ext4 -q {PARENT} && mkfs.ext4 -q {CHILD} && "
        f"echo '{PARENT} /srv/pa ext4 noauto 0 2' >> /etc/fstab && "
        f"echo '{CHILD} /srv/pa/child ext4 x-systemd.required-by=nails-pull.target 0 2' "
        ">> /etc/fstab && systemctl daemon-reload && "
        f"test -L /run/systemd/generator/nails-pull.target.requires/{CHILD_UNIT}"
    )
    machine.fail("mountpoint -q /srv/pa")
    parent_before = parent_hash()

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
        assert "/srv/spare: skipped" in out, out
        assert "/srv/native: overlaid" in out, out
        assert "/dev/zram0: masked" in out, out
        assert "/srv/later: masked" in out, out
        assert f"{CHILD_UNIT} is masked rather than skipped" in out, out
        assert "srv-pa.mount (the mount of a parent directory)" in out, out

    with subtest("check masks a required disk whose device unit is not active"):
        # udev marks the disk not ready: its node is there, but systemd's
        # device unit is not active, so a skipped mount would wait for it.
        kernel = machine.succeed(f"basename \"$(readlink -f {SPARE})\"").strip()
        machine.succeed(
            f"mkdir -p /run/udev/rules.d && echo 'KERNEL==\"{kernel}\", "
            f"ENV{{SYSTEMD_READY}}=\"0\"' > {NOT_READY_RULE} && udevadm control --reload && "
            f"udevadm trigger --settle --action=change {SPARE}"
        )
        machine.wait_until_fails(f"systemctl is-active '{SPARE_DEVICE_UNIT}'")
        machine.succeed(f"test -e {SPARE}")
        out = machine.succeed(f"nails --config {CONFIG} check --overlay-only")
        machine.log(out)
        assert "/srv/spare: masked" in out, out
        assert "/srv/spare is masked rather than skipped" in out, out
        assert "will not reach local-fs.target" in out, out
        machine.succeed(
            f"rm {NOT_READY_RULE} && udevadm control --reload && "
            f"udevadm trigger --settle --action=change {SPARE}"
        )
        machine.wait_until_succeeds(f"systemctl is-active '{SPARE_DEVICE_UNIT}'")
        out = machine.succeed(f"nails --config {CONFIG} check --overlay-only")
        assert "/srv/spare: skipped" in out, out

    entered_after = monotonic_us()
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

    with subtest("a noauto disk a unit it names pulls in is kept off"):
        state = machine.succeed(f"systemctl show -p LoadState --value '{LATER_UNIT}'").strip()
        assert state == "masked", f"{LATER_UNIT}: {state}"
        machine.fail("mountpoint -q /srv/later")
        assert later_hash() == later_before, "the hidden session changed the noauto disk"

    with subtest("a skip that would mount its noauto parent is masked instead"):
        state = machine.succeed(f"systemctl show -p LoadState --value '{CHILD_UNIT}'").strip()
        assert state == "masked", f"{CHILD_UNIT}: {state}"
        machine.fail("systemctl start nails-pull.target")
        machine.fail("mountpoint -q /srv/pa")
        assert parent_hash() == parent_before, "the hidden session changed the noauto parent disk"

    with subtest("decoy swap is masked and never active"):
        state = machine.succeed(f"systemctl show -p LoadState --value '{SWAP_UNIT}'").strip()
        assert state == "masked", f"{SWAP_UNIT}: {state}"
        machine.fail(f"systemctl start '{SWAP_UNIT}'")
        state = machine.succeed(f"systemctl show -p LoadState --value '{ZRAM_UNIT}'").strip()
        assert state == "masked", f"{ZRAM_UNIT}: {state}"
        assert machine.succeed("swapon --show --noheadings").strip() == ""

    with subtest("a disk local-fs.target requires is skipped, and the target reached"):
        assert machine.succeed("systemctl is-active local-fs.target").strip() == "active"
        spare = unit_props(SPARE_UNIT, "LoadState", "ActiveState", "ConditionResult")
        assert spare == {
            "LoadState": "loaded",
            "ActiveState": "inactive",
            "ConditionResult": "no",
        }, spare
        machine.fail("mountpoint -q /srv/spare")
        for unit in (SPARE_UNIT, *SPARE_CHECKERS):
            assert_skipped_here(unit, entered_after)
        failed = machine.succeed("systemctl --failed --no-legend --plain")
        machine.log(f"failed units in the hidden session:\n{failed}")
        for unit in (SPARE_UNIT, *SPARE_CHECKERS):
            assert unit not in failed, failed
        assert spare_hash() == spare_before, "the hidden session changed the skipped disk"

    with subtest("status lists the skipped disk with why"):
        required = read_status_json(CONFIG)["required_units"]
        machine.log(f"required units in the hidden session: {required}")
        assert {
            "unit": SPARE_UNIT,
            "action": "skipped",
            "reason": "required_at_boot",
        } in required, required
        assert {
            "unit": CHILD_UNIT,
            "action": "masked",
            "reason": "pulls_in_mount",
        } in required, required
        out = machine.succeed(f"nails --config {CONFIG} status")
        assert f"{SPARE_UNIT}: skipped, as a boot target requires it" in out, out

    with subtest("a disk the decoy mounts through a unit of its own is overlaid"):
        assert machine.succeed("findmnt -no FSTYPE /srv/native").strip() == "overlay"
        assert machine.succeed("cat /srv/native/decoy-file").strip() == "decoy"
        machine.succeed("echo hidden > /srv/native/hidden-file && sync")
        machine.succeed("test -s /mnt/data/root/mounts/srv-native/upper/hidden-file")
        machine.succeed(
            "mkdir -p /run/peek && mount /dev/disk/by-id/virtio-native /run/peek "
            "&& mount -o remount,bind,ro /run/peek"
        )
        machine.fail("test -e /run/peek/hidden-file")
        machine.succeed("umount /run/peek && rmdir /run/peek")

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
        state = machine.succeed(f"systemctl show -p LoadState --value '{ZRAM_UNIT}'").strip()
        assert state != "masked", f"the zram swap mask leaked into the decoy: {state}"
        state = machine.succeed(f"systemctl show -p LoadState --value '{LATER_UNIT}'").strip()
        assert state != "masked", f"the noauto disk's mask leaked into the decoy: {state}"
        state = machine.succeed(f"systemctl show -p LoadState --value '{CHILD_UNIT}'").strip()
        assert state != "masked", f"the child disk's mask leaked into the decoy: {state}"
        source = machine.succeed("findmnt -no SOURCE /srv/files").strip()
        assert source == LV, f"/srv/files is {source!r} after the way back"
        assert machine.succeed("cat /srv/files/decoy-file").strip() == "decoy"
        machine.fail("test -e /srv/native/hidden-file")
        assert machine.succeed("cat /srv/native/decoy-file").strip() == "decoy"
        # The decoy mounts its disk again, and skips none of its units.
        machine.fail(f"test -e /run/systemd/system/{SPARE_UNIT}.d")
        machine.succeed(f"systemctl start {SPARE_UNIT} && mountpoint -q /srv/spare")
        assert machine.succeed("systemctl is-active local-fs.target").strip() == "active"

    with subtest("blk-availability's stop is back for the decoy's own shutdown"):
        machine.fail(f"test -e /run/systemd/system/{BLK_UNIT}.d")
        machine.succeed(f"systemctl is-active {BLK_UNIT}")
        stop = blk_availability_stop()
        assert BLKDEACTIVATE in stop, stop
  '';
}
