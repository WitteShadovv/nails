# Test 25: the attach gate on the decoy's own storage
#
# The decoy here lists two more filesystems in its fstab: ext4 at /srv and
# btrfs at /pool. A hidden root that lives on either is not a volume of its
# own, whatever is mounted there, because everything written to it lands on
# the decoy's disk:
#
#   1. a folder of /srv: init, `activate -y --overlay-only` (with and without
#      --allow-decoy-storage) and check refuse it with not_separate_volume
#      (exit 4), and the folder stays empty with its mtime and ctime unchanged;
#   2. a btrfs subvolume of /pool mounted on its own is refused; its mount
#      table line shows the same device as /pool's, while stat shows another
#      (the judge relies on the first);
#   3. a bind mount of a folder of /srv is refused;
#   4. /srv itself, the filesystem the decoy's fstab mounts there, is refused;
#   5. an unencrypted ext4 image on /srv, loop-mounted, is refused, also with a
#      tmpfs mounted over the image's folder;
#   6. a network block device that qemu-nbd serves from an image on /srv is
#      refused, whole and partitioned, naming --allow-decoy-storage for it in
#      check's report, and init with that flag uses it with a warning;
#   7. an XFS filesystem and an ext4 one on RAM disks of their own are
#      refused when the XFS log, or the ext4 journal, is on a network block
#      device served from an image on /srv, and init with
#      --allow-decoy-storage uses the XFS one with a warning;
#   8. a zram device that writes its pages back to a loop device over an
#      image on /srv is refused as that image file;
#   9. `init --allow-decoy-storage` uses the bind of the /srv folder with a
#      warning, while the folder itself stays refused;
#  10. a LUKS container file on /srv passes the hidden-volume check with a
#      warning that names /srv and its copy-on-write snapshots;
#  11. a LUKS volume on the separate data disk passes the hidden-volume check;
#  12. a tmpfs mounted over that volume is refused with root_covered, and
#      neither the tmpfs nor the volume below receives anything;
#  13. a decoy crypttab line that opens the data disk, then one with
#      tcrypt-hidden for it or for a device that cannot be found, fails the
#      backend-entries check (exit 4), and so does `activate`;
#      a line for another device passes, tcrypt-hidden or not; a decoy fstab
#      line for the data disk or its mapping fails it too;
#  14. the accepted case: a whole session runs on a LUKS container file on
#      /srv (activate warns, naming /srv and its copy-on-write snapshots), a
#      hidden write lands in the container, and deactivate returns to a decoy
#      that does not see it.
#
# Every refused target keeps its mtime and ctime: no probe file was created
# and deleted in it.
{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  preflightHelpers = import ./../../lib/preflight-helpers.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
in
{
  name = "preflight-decoy-filesystem";
  meta.tags = [
    "preflight"
    "security"
  ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [
        self.packages.${pkgs.stdenv.hostPlatform.system}.nails
        pkgs.btrfs-progs
        pkgs.qemu-utils
        pkgs.xfsprogs
      ];
      virtualisation.emptyDiskImages = [
        {
          size = 768;
          driveConfig.deviceExtraOpts.serial = "srv";
        }
        {
          size = 512;
          driveConfig.deviceExtraOpts.serial = "pool";
        }
      ];
      boot.supportedFilesystems = [ "btrfs" ];
      virtualisation.fileSystems = {
        "/srv" = {
          device = "/dev/disk/by-id/virtio-srv";
          fsType = "ext4";
          autoFormat = true;
        };
        "/pool" = {
          device = "/dev/disk/by-id/virtio-pool";
          fsType = "btrfs";
          autoFormat = true;
        };
      };
    };

  testScript = _: ''
    import json

    from nails_e2e import session

    ${testHelpers.canonicalActivateFn}
    ${testHelpers.canonicalDeactivateFn}
    ${preflightHelpers.writeTextFileFn}
    ${preflightHelpers.runCommandCaptureFn}
    ${preflightHelpers.commandAssertionsFn}


    def config_for(root):
        path = f"/run/gate-{root.strip('/').replace('/', '-')}.toml"
        write_text_file(path, f'hidden_volume_root = "{root}"\nminimum_space_mb = 100\n')
        return path


    def last_json(result):
        return json.loads(result["stdout"].strip().splitlines()[-1])


    def times(path):
        return machine.succeed(f"stat -c '%Y %Z' {path}").strip()


    def refused_untouched(label, target, command, needles):
        before = times(target)
        listing = machine.succeed(f"ls -A {target}")
        result = run_command_capture(label, command)
        assert_exit_code(result, 4)
        assert_result_contains(result, needles)
        assert machine.succeed(f"ls -A {target}") == listing, target
        assert times(target) == before, (target, before, times(target))
        return result


    def check_row(report, name):
        rows = [row for row in report["data"]["checks"] if row["name"] == name]
        assert len(rows) == 1, report
        return rows[0]


    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("mountpoint -q /srv && mountpoint -q /pool")
    machine.succeed("grep -q ' /srv ' /etc/fstab && grep -q ' /pool ' /etc/fstab")

    with subtest("a folder of a decoy filesystem is refused and left untouched"):
        machine.succeed("mkdir -p /srv/x && touch -m -d '2001-02-03 04:05:06' /srv/x")
        before = times("/srv/x")
        config = config_for("/srv/x")

        for flags in ["", " --allow-decoy-storage"]:
            result = run_command_capture(
                "gate-init", f"nails init --no-hardware-config{flags} /srv/x"
            )
            assert_exit_code(result, 4)
            assert_result_contains(
                result,
                [
                    "error: /srv/x is not a volume of its own: it is a folder on the "
                    "filesystem mounted at /srv. Nothing was written.",
                    "Where setup happens",
                ],
            )
            assert_result_not_contains(result, ["warning: --allow-decoy-storage"])
        for flags in ["", " --allow-decoy-storage"]:
            result = run_command_capture(
                "gate-activate",
                f"nails --config {config} --json activate -y --overlay-only{flags}",
            )
            assert_exit_code(result, 4)
            assert last_json(result)["error"]["code"] == "not_separate_volume", result
        result = run_command_capture(
            "gate-activate-human", f"nails --config {config} activate -y --overlay-only"
        )
        assert_exit_code(result, 4)
        assert_result_contains(
            result,
            [
                "If the volume is already prepared, unlock and mount it at /srv/x",
                "Where setup happens",
            ],
        )
        assert_result_not_contains(result, ["File logging disabled"])
        result = run_command_capture(
            "gate-check", f"nails --config {config} --json check --overlay-only"
        )
        assert_exit_code(result, 4)
        report = last_json(result)
        assert report["data"]["refusal"]["code"] == "not_separate_volume", report
        assert check_row(report, "hidden-volume")["status"] == "fail", report
        assert check_row(report, "backend-entries")["status"] == "skipped", report

        machine.succeed('test -z "$(ls -A /srv/x)"')
        assert times("/srv/x") == before, (before, times("/srv/x"))

    with subtest("a btrfs subvolume of a decoy filesystem is refused"):
        machine.succeed(
            "btrfs subvolume create /pool/vol && mkdir -p /mnt/sub && "
            "mount -o subvol=vol /dev/disk/by-id/virtio-pool /mnt/sub"
        )
        # The judge compares the mount table's device, which a subvolume
        # shares with its filesystem; stat reports another one.
        sub_dev = machine.succeed("findmnt -no MAJ:MIN /mnt/sub").strip()
        pool_dev = machine.succeed("findmnt -no MAJ:MIN /pool").strip()
        assert sub_dev == pool_dev, (sub_dev, pool_dev)
        assert machine.succeed("stat -c %d /mnt/sub") != machine.succeed("stat -c %d /pool")
        machine.succeed("touch -m -d '2001-02-03 04:05:06' /mnt/sub")
        refused_untouched(
            "gate-subvol",
            "/mnt/sub",
            "nails init --no-hardware-config /mnt/sub",
            ["it is a subvolume of the btrfs filesystem at /pool"],
        )
        machine.succeed("umount /mnt/sub")

    with subtest("a bind mount of a decoy folder is refused"):
        machine.succeed("mkdir -p /mnt/bind && mount --bind /srv/x /mnt/bind")
        refused_untouched(
            "gate-bind",
            "/mnt/bind",
            "nails init --no-hardware-config /mnt/bind",
            ["it is a bind mount of a folder of /srv"],
        )
        machine.succeed("umount /mnt/bind")
        machine.succeed('test -z "$(ls -A /srv/x)"')

    with subtest("the filesystem the decoy's fstab mounts is refused"):
        refused_untouched(
            "gate-fstab-filesystem",
            "/srv",
            "nails init --no-hardware-config /srv",
            [
                "it is the filesystem this computer mounts at /srv per /etc/fstab",
                "If /srv is the volume you prepared, remove its line from /etc/fstab",
            ],
        )

    with subtest("an unencrypted image file on a decoy filesystem is refused"):
        machine.succeed(
            "mkdir -p /srv/imgs && truncate -s 64M /srv/imgs/disk.img && "
            "mkfs.ext4 -q -F /srv/imgs/disk.img && "
            "mkdir -p /mnt/img && mount -o loop /srv/imgs/disk.img /mnt/img && "
            "touch -m -d '2001-02-03 04:05:06' /mnt/img"
        )
        refused_untouched(
            "gate-image",
            "/mnt/img",
            "nails init --no-hardware-config /mnt/img",
            ["it is an unencrypted image file (/srv/imgs/disk.img) on /srv"],
        )
        # A tmpfs mounted over the image's folder leads its path into RAM; the
        # loop driver's record still names /srv's filesystem.
        machine.succeed("mount -t tmpfs cover /srv/imgs")
        refused_untouched(
            "gate-image-covered",
            "/mnt/img",
            "nails init --no-hardware-config /mnt/img",
            ["it is an unencrypted image file (/srv/imgs/disk.img) on /srv"],
        )
        machine.succeed("umount /srv/imgs && umount /mnt/img && rm -rf /srv/imgs")

    with subtest("a network block device served from a decoy filesystem is refused"):
        # qemu-nbd serves an image file on /srv through /dev/nbd0: sysfs shows
        # nothing below the device, and /proc/devices names its driver.
        machine.succeed(
            "modprobe nbd max_part=8 && grep -Eq '^ *43 nbd$' /proc/devices && "
            "truncate -s 64M /srv/nbd.img && "
            "qemu-nbd --connect=/dev/nbd0 --format=raw /srv/nbd.img && "
            "mkfs.ext4 -q /dev/nbd0 && mkdir -p /mnt/nbd && mount /dev/nbd0 /mnt/nbd && "
            "touch -m -d '2001-02-03 04:05:06' /mnt/nbd"
        )
        refused_untouched(
            "gate-nbd",
            "/mnt/nbd",
            "nails init --no-hardware-config /mnt/nbd",
            [
                "error: /mnt/nbd is not a volume of its own: it is stored on a network "
                "block device, which a program can serve from a file on this computer's "
                "own disk. Nothing was written.",
                "Where setup happens",
            ],
        )
        result = run_command_capture(
            "gate-nbd-check",
            f"nails --config {config_for('/mnt/nbd')} --json check --overlay-only",
        )
        assert_exit_code(result, 4)
        report = last_json(result)
        refusal = report["data"]["refusal"]
        assert refusal["code"] == "not_separate_volume", report
        assert refusal["allowable"] == "decoy_storage", report
        row = check_row(report, "hidden-volume")
        assert row["status"] == "fail", row
        assert row["allowable"] == "decoy_storage", row

        # A partition of the device is judged with the device.
        machine.succeed(
            "umount /mnt/nbd && echo type=83 | sfdisk -q /dev/nbd0 && udevadm settle && "
            "mkfs.ext4 -q /dev/nbd0p1 && mount /dev/nbd0p1 /mnt/nbd && "
            "touch -m -d '2001-02-03 04:05:06' /mnt/nbd"
        )
        refused_untouched(
            "gate-nbd-partition",
            "/mnt/nbd",
            "nails init --no-hardware-config /mnt/nbd",
            ["it is stored on a network block device"],
        )
        result = run_command_capture(
            "gate-nbd-allow", "nails init --no-hardware-config --allow-decoy-storage /mnt/nbd"
        )
        assert_exit_code(result, 0)
        assert_result_contains(
            result,
            [
                "warning: --allow-decoy-storage: using /mnt/nbd although it is stored on a "
                "network block device, which a program can serve from a file on this "
                "computer's own disk; everything written there lands on that storage"
            ],
        )
        machine.succeed("test -f /mnt/nbd/state.json")
        machine.succeed("umount /mnt/nbd && qemu-nbd --disconnect /dev/nbd0 && rm -f /srv/nbd.img")

    with subtest("a root whose XFS log or ext4 journal is served from /srv is refused"):
        # Each filesystem keeps its data on a RAM disk of its own, and its
        # log or journal on a network block device that qemu-nbd serves from
        # an image on /srv. The mount table names the XFS log; jbd2 lists the
        # ext4 journal and the filesystem's journal thread names it. mkfs.xfs
        # makes a filesystem smaller than it supports only for its test suite.
        machine.succeed(
            "modprobe brd rd_nr=2 rd_size=131072 && modprobe xfs && "
            "truncate -s 64M /srv/log.img /srv/journal.img && "
            "qemu-nbd --connect=/dev/nbd1 --format=raw /srv/log.img && "
            "qemu-nbd --connect=/dev/nbd2 --format=raw /srv/journal.img && "
            "TEST_DIR=1 TEST_DEV=1 QA_CHECK_FS=1 "
            "mkfs.xfs -q -f -l logdev=/dev/nbd1,size=32m /dev/ram0 && "
            "mkdir -p /mnt/xfslog && mount -o logdev=/dev/nbd1 /dev/ram0 /mnt/xfslog && "
            "mke2fs -q -F -O journal_dev -b 4096 /dev/nbd2 && "
            "mkfs.ext4 -q -F -b 4096 -J device=/dev/nbd2 /dev/ram1 && "
            "mkdir -p /mnt/journal && mount /dev/ram1 /mnt/journal && "
            "touch -m -d '2001-02-03 04:05:06' /mnt/xfslog /mnt/journal"
        )
        assert "logdev=/dev/nbd1" in machine.succeed("findmnt -no OPTIONS /mnt/xfslog")
        assert machine.succeed("ls /proc/fs/jbd2").split().count("nbd2") == 1
        for root in ["/mnt/xfslog", "/mnt/journal"]:
            refused_untouched(
                f"gate-{root.rsplit('/', 1)[1]}",
                root,
                f"nails init --no-hardware-config {root}",
                [
                    f"error: {root} is not a volume of its own: it is stored on a network "
                    "block device, which a program can serve from a file on this computer's "
                    "own disk. Nothing was written.",
                ],
            )
        result = run_command_capture(
            "gate-xfslog-allow",
            "nails init --no-hardware-config --allow-decoy-storage /mnt/xfslog",
        )
        assert_exit_code(result, 0)
        assert_result_contains(
            result,
            [
                "warning: --allow-decoy-storage: using /mnt/xfslog although it is stored on a "
                "network block device"
            ],
        )
        machine.succeed("test -f /mnt/xfslog/state.json")
        machine.succeed(
            "umount /mnt/xfslog /mnt/journal && "
            "qemu-nbd --disconnect /dev/nbd1 && qemu-nbd --disconnect /dev/nbd2 && "
            "rm -f /srv/log.img /srv/journal.img"
        )

    with subtest("a zram device that writes back to the decoy's storage is refused"):
        # zram keeps its pages in RAM until it writes them back to its backing
        # device, here a loop device over an image file on /srv; sysfs shows
        # that device in backing_dev, not below the zram device.
        loop = machine.succeed(
            "modprobe zram num_devices=1 && truncate -s 64M /srv/zram.img && "
            "losetup --find --show /srv/zram.img"
        ).strip()
        machine.succeed(
            f"echo {loop} > /sys/block/zram0/backing_dev && "
            "echo 64M > /sys/block/zram0/disksize && mkfs.ext4 -q /dev/zram0 && "
            "mkdir -p /mnt/zram && mount /dev/zram0 /mnt/zram && "
            "touch -m -d '2001-02-03 04:05:06' /mnt/zram"
        )
        refused_untouched(
            "gate-zram",
            "/mnt/zram",
            "nails init --no-hardware-config /mnt/zram",
            ["it is an unencrypted image file (/srv/zram.img) on /srv"],
        )
        machine.succeed(
            f"umount /mnt/zram && echo 1 > /sys/block/zram0/reset && losetup -d {loop} && "
            "rm -f /srv/zram.img"
        )

    with subtest("--allow-decoy-storage uses decoy storage with a warning, never a folder"):
        refused_untouched(
            "gate-allow-folder",
            "/srv/x",
            "nails init --no-hardware-config --allow-decoy-storage /srv/x",
            ["it is a folder on the filesystem mounted at /srv"],
        )
        machine.succeed("mount --bind /srv/x /mnt/bind")
        result = run_command_capture(
            "gate-allow", "nails init --no-hardware-config --allow-decoy-storage /mnt/bind"
        )
        assert_exit_code(result, 0)
        assert_result_contains(
            result,
            [
                "warning: --allow-decoy-storage: using /mnt/bind although it is a bind mount of "
                "a folder of /srv; everything written there lands on that storage"
            ],
        )
        machine.succeed("test -f /srv/x/state.json")
        machine.succeed("umount /mnt/bind && rm -rf /srv/x")

    with subtest("an encrypted container file on a decoy filesystem only warns"):
        machine.succeed(
            "truncate -s 64M /srv/files.bin && "
            "echo -n pw | cryptsetup luksFormat -q --iter-time=1 /srv/files.bin - && "
            "echo -n pw | cryptsetup open --key-file - /srv/files.bin box && "
            "mkfs.ext4 -q /dev/mapper/box && mkdir -p /mnt/box && "
            "mount /dev/mapper/box /mnt/box"
        )
        result = run_command_capture(
            "gate-container",
            f"nails --config {config_for('/mnt/box')} --json check --overlay-only",
        )
        report = last_json(result)
        assert "refusal" not in report["data"], report
        row = check_row(report, "hidden-volume")
        assert row["status"] == "warn", row
        assert "an encrypted container file (/srv/files.bin) on /srv" in row["message"], row
        assert "copy-on-write snapshots" in row["message"], row
        machine.succeed(
            "umount /mnt/box && cryptsetup close box && rm -f /srv/files.bin"
        )

    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    data_config = config_for("/mnt/data")

    with subtest("a volume of its own on the separate disk passes"):
        result = run_command_capture(
            "gate-volume", f"nails --config {data_config} --json check --overlay-only"
        )
        report = last_json(result)
        assert "refusal" not in report["data"], report
        assert check_row(report, "hidden-volume")["status"] == "pass", report
        assert check_row(report, "backend-entries")["status"] == "pass", report

    with subtest("a second filesystem over the volume is refused"):
        volume_listing = machine.succeed("ls -A /mnt/data")
        volume_times = times("/mnt/data")
        machine.succeed("mount -t tmpfs cover /mnt/data")
        machine.succeed("touch -m -d '2001-02-03 04:05:06' /mnt/data")
        cover_times = times("/mnt/data")
        result = run_command_capture(
            "gate-covered", f"nails --config {data_config} --json check --overlay-only"
        )
        assert_exit_code(result, 4)
        report = last_json(result)
        assert report["data"]["refusal"]["code"] == "root_covered", report
        assert check_row(report, "hidden-volume")["status"] == "fail", report
        result = run_command_capture(
            "gate-covered-activate",
            f"nails --config {data_config} --json activate -y --overlay-only",
        )
        assert_exit_code(result, 4)
        assert last_json(result)["error"]["code"] == "root_covered", result
        machine.succeed('test -z "$(ls -A /mnt/data)"')
        assert times("/mnt/data") == cover_times, (cover_times, times("/mnt/data"))
        machine.succeed("umount /mnt/data")
        # The volume below received nothing either.
        assert machine.succeed("ls -A /mnt/data") == volume_listing
        assert times("/mnt/data") == volume_times, (volume_times, times("/mnt/data"))

    with subtest("a decoy crypttab entry for the volume fails backend-entries"):
        for line in [
            "data /dev/disk/by-id/virtio-data none luks,noauto",
            "vault /dev/disk/by-id/virtio-data none tcrypt-hidden,noauto",
            "vault /dev/disk/by-id/virtio-absent none tcrypt-hidden,noauto",
        ]:
            write_text_file("/etc/crypttab", line + "\n")
            result = run_command_capture(
                "gate-entries", f"nails --config {data_config} --json check --overlay-only"
            )
            assert_exit_code(result, 4)
            row = check_row(last_json(result), "backend-entries")
            assert row["status"] == "fail", row
            assert line.split()[0] + " /dev/" in row["message"], row
        # Activation runs the full registry, so this refusal fires there too.
        # TODO(KVM): confirm full pre-flight passes here now that --no-preflight is gone
        result = run_command_capture(
            "gate-entries-activate",
            f"nails --config {data_config} --json activate -y --overlay-only",
        )
        assert_exit_code(result, 4)
        assert '"backend-entries"' in result["stdout"], result
        for line in [
            "backup /dev/disk/by-id/virtio-pool none luks,noauto",
            "vault /dev/disk/by-id/virtio-pool none tcrypt-hidden,noauto",
        ]:
            write_text_file("/etc/crypttab", line + "\n")
            result = run_command_capture(
                "gate-entries-other", f"nails --config {data_config} --json check --overlay-only"
            )
            row = check_row(last_json(result), "backend-entries")
            assert row["status"] == "pass", row
        machine.succeed("rm -f /etc/crypttab")

    with subtest("a decoy fstab entry for the volume fails backend-entries"):
        # /etc/fstab is a link into the store; keep the link to put it back.
        machine.succeed("cp -P /etc/fstab /run/fstab.orig")
        original = machine.succeed("cat /etc/fstab")
        for line in [
            "/dev/disk/by-id/virtio-data /mnt/data ext4 noauto 0 0",
            "/dev/mapper/data /mnt/data ext4 noauto 0 0",
        ]:
            write_text_file("/run/fstab.gate", original + line + "\n")
            machine.succeed("rm -f /etc/fstab && cp /run/fstab.gate /etc/fstab")
            result = run_command_capture(
                "gate-fstab-entry", f"nails --config {data_config} --json check --overlay-only"
            )
            assert_exit_code(result, 4)
            row = check_row(last_json(result), "backend-entries")
            assert row["status"] == "fail", row
            assert line.split()[0] + " /mnt/data" in row["message"], row
        machine.succeed("rm -f /etc/fstab && mv /run/fstab.orig /etc/fstab")

    machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")

    with subtest("a session runs on an encrypted container file on a decoy filesystem"):
        # The container carries the neutral names of every other hidden volume
        # in the suite: the mapping "data" at /mnt/data.
        machine.succeed(
            "truncate -s 512M /srv/vault.bin && "
            "echo -n pw | cryptsetup luksFormat -q --iter-time=1 /srv/vault.bin - && "
            "echo -n pw | cryptsetup open --key-file - /srv/vault.bin data && "
            "mkfs.ext4 -q -L data /dev/mapper/data && mkdir -p /mnt/data && "
            "mount /dev/mapper/data /mnt/data && "
            "mkdir -p /mnt/data/root/work /mnt/data/config/nixos"
        )
        canonical_activate(data_config, "--overlay-only", "container-activate")
        session.assert_hidden_root(machine, "/mnt/data/root/upper")
        output = machine.succeed("cat /mnt/data/container-activate.log")
        assert "an encrypted container file (/srv/vault.bin) on /srv" in output, output
        assert "copy-on-write snapshots" in output, output
        machine.succeed("echo container-ok > /root/container-note && sync")
        machine.succeed("grep -qx container-ok /mnt/data/root/upper/root/container-note")
        canonical_deactivate(data_config, "container-deactivate")
        machine.fail("test -e /root/container-note")
        machine.succeed(
            "echo -n pw | cryptsetup open --key-file - /srv/vault.bin data && "
            "mount /dev/mapper/data /mnt/data && "
            "grep -qx container-ok /mnt/data/root/upper/root/container-note && "
            "umount /mnt/data && cryptsetup close data && rm -f /srv/vault.bin"
        )
  '';
}
