# The write fence: for the whole hidden session the kernel refuses every write
# to the decoy's disks outside the hidden volume.
#
# The node's disks are SCSI disks (`diskInterface = "scsi"`), so SCSI
# passthrough (SG_IO) reaches them as it reaches a SATA or USB disk. The decoy
# root is a bare ext4 on the first disk; a second disk ("shared") holds a decoy
# ext4 at /srv on its first partition, the hidden volume (LUKS, ext4) on its
# second and a decoy btrfs on its third, whose subvolume `a` is mounted at
# /opt: the hidden volume shares a disk with the decoy, and the fence has to
# set that disk read-only while the hidden volume on it keeps writing.
#
#   1. On the decoy, a raw SG_IO WRITE(10) of one block into the gap between
#      the two partitions succeeds: passthrough works on this machine, so its
#      refusal later is the fence's.
#   2. In the hidden session:
#      - every decoy device reads read-only (`ro` 1), the decoy root's and
#        /srv's superblocks are read-only, discard is off on the shared disk;
#      - opening a decoy device fails with EPERM, for reading too, and so
#        do `dd` onto it, `blockdev --setrw`, a read-write mount of its
#        partition (a read-only one with its type given reuses the live
#        read-only superblock, and stays read-only), and
#        the same SG_IO write through the disk node and through its sg and
#        bsg nodes, also when asked on a read-only descriptor; the decoy's
#        ext4 refuses a read-write remount, and a mount of the btrfs's other
#        subvolume is refused (a read-write remount of the btrfs the session
#        carries is a known gap of the fence; the test logs what it does);
#      - writes through the overlay land in the upper, and the hidden volume
#        on the shared disk keeps writing: its partition's write counter
#        grows, while the counters of the decoy root's disk and of the /srv
#        partition do not move, and the shared disk's grows by exactly what
#        the hidden partition's does.
#      - a decoy XFS on a disk of its own ("xfsdecoy", at /var/lib/xfsdecoy),
#        whose metadata the test dirtied and synced right before the
#        activation, so its log items were still due when the fence went up:
#        its superblock is read-only, its disk's write counter does not move
#        over 90 seconds, and the kernel logs no write to it and no XFS error
#        (a plain `sync` leaves XFS's log covering for tens of seconds later;
#        its read-only reconfigure does it at once);
#   3. `nails deactivate` ends the session in a power-off with the fence up;
#      the cold-booted decoy has neither of the session's files, the block of
#      step 1 still holds what step 1 wrote, and the XFS mounts without log
#      recovery.
{ self, ... }:
let
  testHelpers = import ./../../lib/test-helpers.nix;
in
{
  name = "session-decoy-write-fence";
  meta.tags = [
    "security"
    "session"
  ];
  # One session, two soft-reboots.
  globalTimeout = 1200;

  nodes.machine =
    { pkgs, ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      virtualisation = {
        qemu.diskInterface = "scsi";
        emptyDiskImages = [
          {
            size = 1536;
            driveConfig.deviceExtraOpts.serial = "shared";
          }
          {
            size = 512;
            driveConfig.deviceExtraOpts.serial = "xfsdecoy";
          }
        ];
        fileSystems = {
          "/srv" = {
            device = "/dev/disk/by-label/srvdecoy";
            fsType = "ext4";
            options = [ "nofail" ];
          };
          "/var/lib/xfsdecoy" = {
            device = "/dev/disk/by-label/xfsdecoy";
            fsType = "xfs";
            options = [ "nofail" ];
          };
          "/opt" = {
            device = "/dev/disk/by-label/optdecoy";
            fsType = "btrfs";
            options = [
              "nofail"
              "subvol=a"
            ];
          };
        };
      };
      boot.supportedFilesystems = [
        "btrfs"
        "xfs"
      ];
      environment.systemPackages = [
        self.packages.${pkgs.stdenv.hostPlatform.system}.nails
        pkgs.sg3_utils
        pkgs.btrfs-progs
        pkgs.xfsprogs
      ];
    };

  testScript = _: ''
    import shlex

    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.canonicalActivateFn}
    ${testHelpers.canonicalDeactivateFn}

    CONFIG = "/mnt/data/config/nails.toml"
    #: The control block: in the gap between the shared disk's partitions.
    LBA = 265000


    def disk(serial):
        name = machine.succeed(
            f"lsblk -dno NAME,SERIAL | awk '$2 == \"{serial}\" {{ print $1 }}'"
        ).strip()
        assert name, f"no disk with serial {serial}"
        return name


    def write_sectors(sysdir):
        """Sectors written, from the block layer's own counter (field 7)."""
        return int(machine.succeed(f"cat {sysdir}/stat").split()[6])


    def sg_write(node, extra=""):
        """SG_IO WRITE(10) of the pattern block at LBA through `node`."""
        lba = LBA.to_bytes(4, "big").hex(" ")
        return machine.execute(
            f"sg_raw {extra} -s 512 -i /run/pattern {node} 2a 00 {lba} 00 00 01 00 2>&1"
        )


    machine.start()
    machine.wait_for_unit("multi-user.target")
    root_disk = machine.succeed("lsblk -no PKNAME,NAME $(findmnt -no SOURCE /) | head -1").split()
    root_disk = root_disk[0] if len(root_disk) > 1 and root_disk[0] else root_disk[-1]
    shared = disk("shared")
    xfs_disk = disk("xfsdecoy")
    data_disk = disk("data")
    machine.log(f"decoy root on {root_disk}, shared disk {shared}, unused disk {data_disk}")

    with subtest("the decoy: /srv on the shared disk, the hidden volume beside it"):
        machine.succeed(
            f"printf 'label: gpt\\nstart=2048, size=262144, type=linux\\n"
            f"start=268288, size=2097152, type=linux\\nstart=2365440, type=linux\\n' "
            f"| sfdisk /dev/{shared}",
            "udevadm settle",
        )
        machine.succeed(f"mkfs.ext4 -q -L srvdecoy /dev/{shared}1", "udevadm settle")
        machine.succeed("systemctl daemon-reload && systemctl start srv.mount")
        machine.succeed("mountpoint -q /srv && echo decoy > /srv/decoy-file && sync")
        machine.succeed(
            f"mkfs.btrfs -q -L optdecoy /dev/{shared}3",
            "udevadm settle",
            f"mkdir -p /run/top && mount /dev/{shared}3 /run/top",
            "btrfs subvolume create /run/top/a && btrfs subvolume create /run/top/b",
            "umount /run/top",
            "systemctl daemon-reload && systemctl start opt.mount",
            "mountpoint -q /opt && echo decoy > /opt/decoy-file && sync",
        )
        machine.succeed(
            f"echo -n test-passphrase | cryptsetup luksFormat -q --iter-time=1 /dev/{shared}2 -",
            f"echo -n test-passphrase | cryptsetup luksOpen --key-file - /dev/{shared}2 data",
            "mkfs.ext4 -q /dev/mapper/data",
            "mkdir -p /mnt/data && mount /dev/mapper/data /mnt/data",
            "mkdir -p /mnt/data/root/work /mnt/data/config/nixos",
        )
        machine.succeed(f"mkfs.xfs -q -L xfsdecoy /dev/{xfs_disk}", "udevadm settle")
        machine.succeed("systemctl daemon-reload && systemctl start var-lib-xfsdecoy.mount")
        machine.succeed("mountpoint -q /var/lib/xfsdecoy && echo decoy > /var/lib/xfsdecoy/decoy-file")
        machine.succeed("nails init /mnt/data")
        write_headless_config(CONFIG)

    with subtest("on the decoy, SG_IO writes the control block"):
        machine.succeed("head -c 512 /dev/urandom > /run/pattern")
        pattern = machine.succeed("od -An -tx1 -v /run/pattern | tr -d ' \\n'").strip()
        status, out = sg_write(f"/dev/{shared}")
        assert status == 0, f"SG_IO does not work on this machine: {out}"
        machine.succeed(
            f"dd if=/dev/{shared} bs=512 skip={LBA} count=1 iflag=direct status=none "
            "| cmp - /run/pattern"
        )
        discard_before = machine.succeed(f"cat /sys/block/{shared}/queue/discard_max_bytes").strip()

    # Dirty XFS metadata right before the entry: after this `sync` its log
    # items wait for the log worker, tens of seconds later.
    machine.succeed(
        "mkdir -p /var/lib/xfsdecoy/many && for i in $(seq 1 300); do "
        ": > /var/lib/xfsdecoy/many/f$i; done && rm -f /var/lib/xfsdecoy/many/f1* && sync"
    )
    canonical_activate(CONFIG, "--overlay-only", "activate")

    with subtest("in the session every decoy device and filesystem is read-only"):
        for dev in (root_disk, shared, f"{shared}/{shared}1", f"{shared}/{shared}2"):
            ro = machine.succeed(f"cat /sys/block/{dev}/ro").strip()
            assert ro == "1", f"{dev} reads ro={ro}"
        assert machine.succeed(f"cat /sys/block/{data_disk}/ro").strip() == "0", (
            "a disk the decoy does not mount is no decoy disk"
        )
        for name in (root_disk, f"{shared}1"):
            options = machine.succeed(f"head -c 2 /proc/fs/ext4/{name}/options")
            assert options == "ro", f"the superblock on {name} is {options}"
        # The decoy filesystems the session carries from the shared disk; the
        # VM's store share is no block device and stays as it is.
        for carried in ("/mnt/data/root/decoy/srv", "/mnt/data/root/decoy/opt"):
            if machine.execute(f"mountpoint -q {carried}")[0] != 0:
                continue
            fs_options = machine.succeed(f"findmnt -no FS-OPTIONS {carried}").strip()
            machine.log(f"{carried}: {fs_options}")
            assert fs_options.split(",")[0] == "ro", f"{carried} has a read-write superblock"
        if discard_before != "0":
            off = machine.succeed(f"cat /sys/block/{shared}/queue/discard_max_bytes").strip()
            assert off == "0", f"discard on {shared}: {off}"

    with subtest("every way to the decoy devices is closed"):
        # `mount -w`: without it, mount answers the kernel's refusal of a
        # read-write mount by mounting read-only and exiting 0.
        refusals = {
            "write the disk": f"dd if=/dev/zero of=/dev/{shared} bs=512 seek={LBA} count=1 conv=notrunc",
            "write the root disk": f"dd if=/dev/zero of=/dev/{root_disk} bs=512 seek=8 count=1 conv=notrunc",
            "write a partition": f"dd if=/dev/zero of=/dev/{shared}1 bs=512 count=1 conv=notrunc",
            "read the disk": f"dd if=/dev/{shared} of=/dev/null bs=512 count=1",
            "clear the flag": f"blockdev --setrw /dev/{shared}",
            "mount a partition read-write": f"mkdir -p /run/try && mount -w -t ext4 -o rw /dev/{shared}1 /run/try",
            "make a node": f"mknod /run/again b $(stat -c '%t %T' /dev/{shared} | "
            "while read a b; do echo $((16#$a)) $((16#$b)); done) && "
            "dd if=/run/again of=/dev/null count=1",
        }
        for what, command in refusals.items():
            status, out = machine.execute(command + " 2>&1")
            machine.log(f"{what}: {status} {out.strip()}")
            assert status != 0, f"{what} succeeded in the session"
        status, out = sg_write(f"/dev/{shared}")
        assert status != 0, f"SG_IO through the disk node succeeded: {out}"
        status, out = sg_write(f"/dev/{shared}", "-R")
        assert status != 0, f"SG_IO on a read-only descriptor succeeded: {out}"
        for node in machine.succeed(
            f"ls -d /sys/block/{shared}/device/scsi_generic/* /sys/block/{shared}/device/bsg/* "
            "2>/dev/null || true"
        ).split():
            name = node.rsplit("/", 1)[1]
            dev_node = f"/dev/{name}" if "scsi_generic" in node else f"/dev/bsg/{name}"
            if machine.execute(f"test -e {shlex.quote(dev_node)}")[0] == 0:
                status, out = sg_write(shlex.quote(dev_node))
                assert status != 0, f"SG_IO through {dev_node} succeeded: {out}"
        carried = machine.succeed(
            "findmnt -rn -o TARGET | grep '^/mnt/data/root/decoy/srv$' || true"
        ).strip()
        if carried:
            machine.fail(f"mount -o remount,rw {carried}")
        machine.fail(f"mkdir -p /run/sub && mount -o subvol=b /dev/{shared}3 /run/sub")

    with subtest("the session writes, and only the hidden partition takes it"):
        root_before = write_sectors(f"/sys/block/{root_disk}")
        srv_before = write_sectors(f"/sys/block/{shared}/{shared}1")
        hidden_before = write_sectors(f"/sys/block/{shared}/{shared}2")
        disk_before = write_sectors(f"/sys/block/{shared}")
        opt_before = write_sectors(f"/sys/block/{shared}/{shared}3")
        machine.succeed(
            "echo session > /srv/session-file",
            "echo session > /opt/session-file",
            "echo session > /root/session-file",
            "dd if=/dev/urandom of=/mnt/data/session-blob bs=1M count=4 status=none",
            "touch /etc/hostname /srv/decoy-file",
            "sync",
        )
        machine.execute("fstrim -av 2>&1")
        machine.succeed("sync")
        root_after = write_sectors(f"/sys/block/{root_disk}")
        srv_after = write_sectors(f"/sys/block/{shared}/{shared}1")
        hidden_after = write_sectors(f"/sys/block/{shared}/{shared}2")
        disk_after = write_sectors(f"/sys/block/{shared}")
        opt_after = write_sectors(f"/sys/block/{shared}/{shared}3")
        assert opt_after == opt_before, "the btrfs partition was written"
        machine.log(
            f"written: root {root_after - root_before}, /srv {srv_after - srv_before}, "
            f"hidden {hidden_after - hidden_before}, shared disk {disk_after - disk_before}"
        )
        assert root_after == root_before, "the decoy root's disk was written"
        assert srv_after == srv_before, "the /srv partition was written"
        assert hidden_after > hidden_before, "the hidden volume took no write"
        assert disk_after - disk_before == hidden_after - hidden_before, (
            "the shared disk was written outside the hidden partition"
        )

    with subtest("the known gap: a read-write remount of the carried btrfs"):
        # btrfs keeps no device on its superblock, so the kernel's refusal of a
        # read-write remount on a read-only device skips it (threat model, the
        # write fence). Logged, not asserted: the docs say what it does.
        carried = machine.succeed(
            "findmnt -rn -o TARGET | grep '^/mnt/data/root/decoy/opt$' || true"
        ).strip()
        if carried:
            status, out = machine.execute(f"mount -o remount,rw {carried} 2>&1")
            machine.log(f"remount,rw of the carried btrfs: {status} {out.strip()}")

    with subtest("XFS covered its log at the fence and writes nothing after it"):
        carried = "/mnt/data/root/decoy/var/lib/xfsdecoy"
        if machine.execute(f"mountpoint -q {carried}")[0] == 0:
            fs_options = machine.succeed(f"findmnt -no FS-OPTIONS {carried}").strip()
            assert fs_options.split(",")[0] == "ro", f"the decoy XFS is read-write: {fs_options}"
        assert machine.succeed(f"cat /sys/block/{xfs_disk}/ro").strip() == "1"
        xfs_before = write_sectors(f"/sys/block/{xfs_disk}")
        machine.sleep(90)
        xfs_after = write_sectors(f"/sys/block/{xfs_disk}")
        kernel_log = machine.succeed("dmesg")
        assert f"read-only block-device {xfs_disk}" not in kernel_log, (
            "the kernel let a write to the read-only XFS disk through"
        )
        for line in kernel_log.splitlines():
            if f"XFS ({xfs_disk})" in line:
                machine.log(line)
                assert "error" not in line.lower() and "shutdown" not in line.lower(), line
        assert xfs_after == xfs_before, (
            f"the decoy XFS wrote {xfs_after - xfs_before} sectors in the session"
        )

    with subtest("a read-only mount reuses the read-only superblock and stays read-only"):
        machine.succeed(f"mkdir -p /run/peek && mount -t ext4 -o ro /dev/{shared}1 /run/peek")
        machine.succeed("grep -qx decoy /run/peek/decoy-file")
        machine.fail("touch /run/peek/session-touch")
        machine.succeed("umount /run/peek")

    canonical_deactivate(CONFIG, "deactivate")

    with subtest("after the power-off the decoy disk is as it was"):
        machine.succeed("mountpoint -q /srv && mountpoint -q /opt")
        machine.fail("test -e /srv/session-file")
        machine.fail("test -e /opt/session-file")
        after = machine.succeed(
            f"dd if=/dev/{shared} bs=512 skip={LBA} count=1 iflag=direct status=none "
            "| od -An -tx1 -v | tr -d ' \\n'"
        ).strip()
        assert after == pattern, "the control block changed"
        machine.succeed("mountpoint -q /var/lib/xfsdecoy && grep -qx decoy /var/lib/xfsdecoy/decoy-file")
        boot_log = machine.succeed(f"journalctl -k -b --no-pager | grep -F 'XFS ({xfs_disk})' || true")
        machine.log(boot_log)
        assert "Ending clean mount" in boot_log, "the decoy XFS did not mount clean"
        assert "recovery" not in boot_log.lower(), "the decoy XFS replayed its log"
  '';
}
