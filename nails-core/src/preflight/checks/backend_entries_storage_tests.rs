// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The backend-entries check on the lines that name the file the volume is
//! stored in, which a loop device of its stack reads, and on the lines that
//! have the boot write over a device of the hidden drive: they fail with the
//! flag and without it.

use super::*;

/// The failure that names `finding`, a line that names the volume, alone.
fn names_the_volume(finding: &str) -> String {
    format!("The decoy's configuration names the volume at /mnt: {finding}. {STORED}")
}

/// The device the loop driver recorded for the root's file: the decoy's
/// /home, nvme0n1p4.
fn home() -> u64 {
    rustix::fs::makedev(259, 4)
}

/// A root in the file `/home/op/vault.img` on the decoy's /home
/// (nvme0n1p4), through loop0: in a LUKS container, `vault` over loop0,
/// when `encrypted`, else the image's own ext4, at /mnt, with `fstab` lines
/// after / and /home and `crypttab`. The loop driver recorded the file as
/// inode 4242 on /home.
fn root_in_a_file(encrypted: bool, fstab: &str, crypttab: &str) -> Decoy {
    let root = if encrypted {
        "5 1 254:8 / /mnt rw - ext4 /dev/mapper/vault rw\n"
    } else {
        "5 1 7:0 / /mnt rw - ext4 /dev/loop0 rw\n"
    };
    let loop0 = "/sys/devices/virtual/block/loop0";
    let mut decoy = Decoy::new(&format!(
        "1 0 259:3 / / rw - ext4 /dev/nvme0n1p3 rw\n\
         2 1 259:4 / /home rw - ext4 /dev/nvme0n1p4 rw\n{root}"
    ))
    .device(NVME, "nvme0n1", "259:0", &[])
    .partition(P3, "nvme0n1p3", "259:3")
    .partition(
        "/sys/devices/pci0/nvme/nvme0n1/nvme0n1p4",
        "nvme0n1p4",
        "259:4",
    )
    .device(loop0, "loop0", "7:0", &[]);
    if encrypted {
        decoy = decoy.mapping("dm-8", "254:8", "vault", ("loop0", loop0));
    }
    let decoy = decoy
        .file(
            "/etc/fstab",
            &format!(
                "/dev/nvme0n1p3 / ext4 defaults 0 1\n/dev/nvme0n1p4 /home ext4 defaults 0 2\n\
                 {fstab}"
            ),
        )
        .file("/etc/crypttab", crypttab)
        .encrypted();
    decoy.attr(loop0, "loop/backing_file", "/home/op/vault.img");
    decoy.fs.mock_set_loop_record(
        Path::new("/dev/loop0"),
        crate::filesystem::LoopRecord {
            device: home(),
            inode: 4242,
            rdevice: 0,
        },
    );
    decoy.fs.mock_set_file_content("/home/op/vault.img", "x");
    for node in ["nvme0n1", "nvme0n1p3", "nvme0n1p4", "loop0", "dm-8"] {
        decoy.fs.mock_set_device_node(&format!("/dev/{node}"));
    }
    decoy
}

/// That backend-entries fails `decoy` with and without the flag, naming
/// only `finding` and saying to remove the line.
fn fails_naming(decoy: &Decoy, finding: &str) {
    for allow in [Allow::Nothing, Allow::DecoyStorage] {
        let result = run_allowing(&decoy.fs, allow);
        assert_eq!(result.message(), names_the_volume(finding), "{allow:?}");
        assert_eq!(result.remediation(), Some(REMEDIATION), "{allow:?}");
    }
}

#[test]
fn a_line_that_names_the_file_the_volume_is_stored_in_fails() {
    // systemd 260.5's generators made systemd-cryptsetup@vault2.service for
    // `vault2 /home/op/vault.img`, and media-i.mount for the image line, and
    // on a real kernel the attach made a second loop device over the same
    // container and a second mapping that showed the hidden files, and the
    // image's mount a second mount of it. Each such line fails, a noauto one
    // too, with the flag too, which accepts the root's container or image on
    // the decoy's /home only with a warning.
    let stored = |what: &str| format!("{what} is the file the volume at /mnt is stored in");
    for (encrypted, fstab, crypttab, shown, what) in [
        (
            true,
            "",
            "vault2 /home/op/vault.img /etc/vault.key luks\n",
            "/etc/crypttab: 'vault2 /home/op/vault.img'",
            "the file it opens",
        ),
        (
            true,
            "",
            "vault2 /home/op/vault.img none luks,noauto\n",
            "/etc/crypttab: 'vault2 /home/op/vault.img'",
            "the file it opens",
        ),
        (
            true,
            "/dev/mapper/vault2 /media/v ext4 nofail 0 2\n",
            "vault2 /home/op/vault.img /etc/vault.key luks\n",
            "/etc/crypttab: 'vault2 /home/op/vault.img'",
            "the file it opens",
        ),
        (
            true,
            "",
            "sw /home/op/vault.img /dev/urandom swap\n",
            "/etc/crypttab: 'sw /home/op/vault.img'",
            "the file it opens",
        ),
        (
            true,
            "",
            "vault2 /home/op/../op/vault.img /etc/vault.key luks\n",
            "/etc/crypttab: 'vault2 /home/op/../op/vault.img'",
            "the file it opens",
        ),
        (
            false,
            "/home/op/vault.img /media/i ext4 loop,nofail 0 0\n",
            "",
            "/etc/fstab: '/home/op/vault.img /media/i ext4'",
            "the file it names",
        ),
        (
            false,
            "/home/op/vault.img /media/i ext4 nofail 0 0\n",
            "",
            "/etc/fstab: '/home/op/vault.img /media/i ext4'",
            "the file it names",
        ),
        (
            false,
            "",
            "sw /home/op/vault.img /dev/urandom swap\n",
            "/etc/crypttab: 'sw /home/op/vault.img'",
            "the file it opens",
        ),
        (
            false,
            "fuse2fs#/home/op/vault.img /media/i fuse nofail 0 0\n",
            "",
            "/etc/fstab: 'fuse2fs#/home/op/vault.img /media/i fuse'",
            "the file it names",
        ),
        (
            false,
            "",
            "px /home/op/vault.img /etc/plainkey plain,cipher=aes-xts-plain64,size=512\n",
            "/etc/crypttab: 'px /home/op/vault.img'",
            "the file it opens",
        ),
    ] {
        let decoy = root_in_a_file(encrypted, fstab, crypttab);
        fails_naming(&decoy, &format!("{shown} ({})", stored(what)));
    }
    // By another spelling: a hard link, which names the inode the loop
    // driver recorded on /home.
    let decoy = root_in_a_file(true, "", "vault2 /home/op/copy.img /etc/vault.key luks\n");
    decoy.fs.mock_set_file_content("/home/op/copy.img", "x");
    decoy
        .fs
        .mock_set_device_id(Path::new("/home/op/copy.img"), home());
    decoy
        .fs
        .mock_set_inode(Path::new("/home/op/copy.img"), 4242);
    fails_naming(
        &decoy,
        &format!(
            "/etc/crypttab: 'vault2 /home/op/copy.img' ({})",
            stored("the file it opens")
        ),
    );
    // The root alone, and lines for another file or another container,
    // pass.
    for (encrypted, fstab, crypttab) in [
        (true, "", ""),
        (false, "", ""),
        (true, "", "vault2 /home/op/other.img /etc/vault.key luks\n"),
        (
            false,
            "/home/op/other.img /media/i ext4 loop,nofail 0 0\n",
            "",
        ),
    ] {
        let decoy = root_in_a_file(encrypted, fstab, crypttab);
        let result = decoy.run();
        assert!(result.is_pass(), "{fstab}{crypttab}: {result:?}");
    }
    // The root's own mapping and loop device are devices of its stack, as
    // before.
    for (crypttab, shown) in [
        (
            "vault /home/op/vault.img /etc/vault.key luks\n",
            "/etc/crypttab: 'vault /home/op/vault.img'",
        ),
        (
            "vault2 /dev/loop0 /etc/vault.key luks\n",
            "/etc/crypttab: 'vault2 /dev/loop0'",
        ),
    ] {
        let result = root_in_a_file(true, "", crypttab).run();
        assert!(result.is_fail(), "{crypttab}: {result:?}");
        assert!(
            result.message().contains(&format!(
                "{shown} (it opens the volume at /mnt or a device it is stored on"
            )),
            "{crypttab}: {result:?}"
        );
    }
}

#[test]
fn a_line_that_names_the_veracrypt_container_of_the_root_fails() {
    // A VeraCrypt container file on /home as the root: the mapping
    // veracrypt1, with no uuid, over loop0, and a crypttab line that opens the
    // same file under another name.
    let loop0 = "/sys/devices/virtual/block/loop0";
    let container = |crypttab: &str| {
        let decoy = Decoy::new(
            "1 0 259:3 / / rw - ext4 /dev/nvme0n1p3 rw\n\
             2 1 259:4 / /home rw - ext4 /dev/nvme0n1p4 rw\n\
             5 1 254:8 / /mnt rw - ext4 /dev/mapper/veracrypt1 rw\n",
        )
        .device(NVME, "nvme0n1", "259:0", &[])
        .partition(P3, "nvme0n1p3", "259:3")
        .partition(
            "/sys/devices/pci0/nvme/nvme0n1/nvme0n1p4",
            "nvme0n1p4",
            "259:4",
        )
        .device(loop0, "loop0", "7:0", &[])
        .device_mapper("dm-8", "254:8", "veracrypt1", "", ("loop0", loop0))
        .file(
            "/etc/fstab",
            "/dev/nvme0n1p3 / ext4 defaults 0 1\n/dev/nvme0n1p4 /home ext4 defaults 0 2\n",
        )
        .file("/etc/crypttab", crypttab)
        .encrypted();
        decoy.attr(loop0, "loop/backing_file", "/home/op/vault.hc");
        decoy
            .fs
            .mock_set_loop_backing_device(Path::new("/dev/loop0"), home());
        decoy.fs.mock_set_file_content("/home/op/vault.hc", "x");
        decoy
    };
    let decoy = container("vc /home/op/vault.hc /etc/vc.key tcrypt-veracrypt\n");
    fails_naming(
        &decoy,
        "/etc/crypttab: 'vc /home/op/vault.hc' (the file it opens is the file the volume at /mnt \
         is stored in)",
    );
    let result = container("vc /home/op/other.hc /etc/vc.key tcrypt-veracrypt\n").run();
    assert!(result.is_pass(), "{result:?}");
}

/// The decoy with the volume `data` (dm-9) on sdb1 of the partitioned sdb,
/// sdb2 beside it, sdc another drive and loop5 over the whole of sdb, with
/// the links `/dev/disk/by-id/usb-whole` and `/dev/block/8:16` of sdb, and
/// `fstab` and `crypttab`.
fn on_a_partition(fstab: &str, crypttab: &str) -> Decoy {
    let decoy = Decoy::new(
        "1 0 259:3 / / rw - ext4 /dev/nvme0n1p3 rw\n\
         5 1 254:9 / /mnt rw - ext4 /dev/mapper/data rw\n",
    )
    .device(NVME, "nvme0n1", "259:0", &[])
    .partition(P3, "nvme0n1p3", "259:3")
    .device(SDB, "sdb", "8:16", &[])
    .partition(SDB1, "sdb1", "8:17")
    .partition(SDB2, "sdb2", "8:18")
    .device(SDC, "sdc", "8:32", &[])
    .device(
        "/sys/devices/virtual/block/loop5",
        "loop5",
        "7:5",
        &[("sdb", SDB)],
    )
    .mapping("dm-9", "254:9", "data", ("sdb1", SDB1))
    .file(
        "/etc/fstab",
        &format!("/dev/nvme0n1p3 / ext4 defaults 0 1\n{fstab}"),
    )
    .file("/etc/crypttab", crypttab)
    .encrypted();
    decoy.link("/dev/disk/by-id/usb-whole", "../../sdb");
    decoy.link("/dev/block/8:16", "../sdb");
    for node in ["dm-9", "sdb", "sdb1", "sdb2", "sdc", "loop5"] {
        decoy.fs.mock_set_device_node(&format!("/dev/{node}"));
    }
    decoy
}

#[test]
fn a_line_that_has_the_boot_write_over_a_device_of_the_drive_fails() {
    // systemd 260.5 made systemd-makefs@dev-sdb.service for an
    // x-systemd.makefs line on the whole disk sdb, systemd-mkswap@dev-sdb
    // for a swap line, and had `systemd-makefs swap` run on the plain
    // mapping of a crypttab swap line, or make a filesystem for tmp;
    // systemd-makefs probes only for filesystems, so on a real kernel it
    // formatted a whole disk with a partition table on it. A plain
    // mapping of the disk, with an offset into the volume's partition or
    // none, checks no header, so a write to it, an fstab makefs line for its
    // mapping say, lands on the volume. Each fails, with the flag too, on
    // the whole disk by any of its names, on a loop device over it and on
    // the partition beside the volume.
    let makefs = |shown: &str| {
        format!(
            "/etc/fstab: '{shown}' (it has the boot format a device of the drive the volume at \
             /mnt is stored on where it finds no filesystem, through its option x-systemd.makefs)"
        )
    };
    let made = |shown: &str, what: &str, option: &str| {
        format!(
            "/etc/crypttab: '{shown}' (it has the boot make {what} over a device of the drive \
             the volume at /mnt is stored on through its option {option})"
        )
    };
    let plain = |shown: &str| {
        format!(
            "/etc/crypttab: '{shown}' (it opens a device of the drive the volume at /mnt is \
             stored on as plain dm-crypt, which checks no header, so what the boot writes to its \
             mapping lands on that drive)"
        )
    };
    let detached = |shown: &str| {
        format!(
            "/etc/crypttab: '{shown}' (it opens a device of the drive the volume at /mnt is \
             stored on with a header kept apart from it, which checks nothing on that device, so \
             what the boot writes to its mapping lands on that drive)"
        )
    };
    for (fstab, crypttab, finding) in [
        (
            "/dev/sdb /media/x ext4 x-systemd.makefs,nofail 0 0\n",
            "",
            makefs("/dev/sdb /media/x ext4"),
        ),
        (
            "/dev/disk/by-id/usb-whole /media/x ext4 x-systemd.makefs,nofail 0 0\n",
            "",
            makefs("/dev/disk/by-id/usb-whole /media/x ext4"),
        ),
        (
            "/dev/block/8:16 /media/x ext4 x-systemd.makefs,nofail 0 0\n",
            "",
            makefs("/dev/block/8:16 /media/x ext4"),
        ),
        (
            "/dev/sdb none swap sw,x-systemd.makefs 0 0\n",
            "",
            makefs("/dev/sdb none swap"),
        ),
        (
            "/dev/loop5 /media/x ext4 x-systemd.makefs,nofail 0 0\n",
            "",
            makefs("/dev/loop5 /media/x ext4"),
        ),
        (
            "/dev/sdb2 /media/x ext4 x-systemd.makefs,nofail 0 0\n",
            "",
            makefs("/dev/sdb2 /media/x ext4"),
        ),
        (
            "/dev/sdb /media/x ext4 noauto,x-systemd.makefs 0 0\n",
            "",
            makefs("/dev/sdb /media/x ext4"),
        ),
        (
            "",
            "swapcrypt /dev/sdb /dev/urandom swap,cipher=aes-xts-plain64,size=512\n",
            made("swapcrypt /dev/sdb", "swap", "swap"),
        ),
        (
            "",
            "tmpcrypt /dev/sdb /dev/urandom tmp\n",
            made("tmpcrypt /dev/sdb", "a filesystem", "tmp"),
        ),
        (
            "",
            "tmpcrypt /dev/sdb /dev/urandom tmp=ext2\n",
            made("tmpcrypt /dev/sdb", "a filesystem", "tmp"),
        ),
        (
            "",
            "swapcrypt /dev/disk/by-id/usb-whole /dev/urandom swap\n",
            made("swapcrypt /dev/disk/by-id/usb-whole", "swap", "swap"),
        ),
        (
            "",
            "swapcrypt /dev/loop5 /dev/urandom swap\n",
            made("swapcrypt /dev/loop5", "swap", "swap"),
        ),
        (
            "",
            "swapcrypt /dev/sdb2 /dev/urandom swap\n",
            made("swapcrypt /dev/sdb2", "swap", "swap"),
        ),
        (
            "",
            "swapcrypt /dev/sdb /dev/urandom swap,noauto\n",
            made("swapcrypt /dev/sdb", "swap", "swap"),
        ),
        (
            "",
            "px /dev/sdb /etc/plainkey plain,offset=2048,cipher=aes-xts-plain64,size=512\n",
            plain("px /dev/sdb"),
        ),
        (
            "/dev/mapper/plainx /data ext4 x-systemd.makefs,nofail 0 0\n",
            "plainx /dev/sdb /etc/plainkey plain,cipher=aes-xts-plain64,size=512\n",
            plain("plainx /dev/sdb"),
        ),
        (
            "/dev/mapper/hdrx /data ext4 x-systemd.makefs,nofail 0 0\n",
            "hdrx /dev/sdb /etc/hdrkey luks,header=/etc/hdrx.img\n",
            detached("hdrx /dev/sdb"),
        ),
        (
            "",
            "hdrx /dev/sdb2 none luks,header=/etc/hdrx.img,nofail\n",
            detached("hdrx /dev/sdb2"),
        ),
    ] {
        let decoy = on_a_partition(fstab, crypttab);
        fails_naming(&decoy, &finding);
    }
    // Another drive, a line that writes nothing over its device, and one
    // that opens the disk as LUKS, which loads its header or fails, pass,
    // and so does a header kept apart from a source on another drive.
    for (fstab, crypttab) in [
        ("", "swapcrypt /dev/sdc /dev/urandom swap\n"),
        ("", "hdrx /dev/sdc none luks,header=/etc/hdrx.img,nofail\n"),
        ("/dev/sdc /media/x ext4 x-systemd.makefs,nofail 0 0\n", ""),
        ("/dev/sdb none swap sw 0 0\n", ""),
        ("/dev/sdb /media/g ext4 x-systemd.growfs,nofail 0 0\n", ""),
        ("", "vault /dev/sdb none luks,nofail\n"),
    ] {
        let result = on_a_partition(fstab, crypttab).run();
        assert!(result.is_pass(), "{fstab}{crypttab}: {result:?}");
    }
    // On the volume's own partition, the line opens or mounts a device the
    // volume is stored on, as before.
    for (fstab, crypttab, finding) in [
        (
            "",
            "swapcrypt /dev/sdb1 /dev/urandom swap\n",
            "/etc/crypttab: 'swapcrypt /dev/sdb1' (it opens the volume at /mnt or a device it is \
             stored on)",
        ),
        (
            "/dev/sdb1 /media/x ext4 x-systemd.makefs,nofail 0 0\n",
            "",
            "/etc/fstab: '/dev/sdb1 /media/x ext4' (it mounts a device the volume at /mnt is \
             stored on, and the decoy's own boot needs it)",
        ),
    ] {
        let result = on_a_partition(fstab, crypttab).run();
        assert_eq!(
            result.message(),
            names_the_volume(finding),
            "{fstab}{crypttab}"
        );
    }
}

#[test]
fn a_header_device_on_the_drive_fails() {
    // systemd's crypttab generator mounts the device of
    // `header=<path>:<device>` read-write ("LUKS2 recovery requires rw header
    // access"), and cryptsetup writes to a device a `header=` names itself
    // where it repairs a damaged copy of a LUKS2 header: on the volume's
    // drive, the partition beside it or the whole disk by any of its names,
    // that is a write to it at boot, with the flag too.
    let header = |shown: &str| {
        format!(
            "/etc/crypttab: '{shown}' (it mounts a device of the drive the volume at /mnt is \
             stored on read-write for its header)"
        )
    };
    for crypttab in [
        "vault /dev/sdc none luks,header=/hdr.img:/dev/sdb2,nofail\n",
        "vault /dev/sdc none luks,header=/hdr.img:/dev/sdb,nofail\n",
        "vault /dev/sdc none luks,header=/hdr.img:/dev/disk/by-id/usb-whole,nofail\n",
    ] {
        let decoy = on_a_partition("", crypttab);
        fails_naming(&decoy, &header("vault /dev/sdc"));
    }
    let read = |shown: &str| {
        format!(
            "/etc/crypttab: '{shown}' (it reads its header from a device of the drive the volume \
             at /mnt is stored on, which cryptsetup writes to where it repairs that header)"
        )
    };
    for crypttab in [
        "vault /dev/sdc none luks,header=/dev/sdb2,nofail\n",
        "vault /dev/sdc none luks,header=/dev/sdb,nofail\n",
        "vault /dev/sdc none luks,header=/dev/disk/by-id/usb-whole,nofail\n",
    ] {
        let decoy = on_a_partition("", crypttab);
        fails_naming(&decoy, &read("vault /dev/sdc"));
    }
    // The volume's own partition is a device it is stored on.
    let result = on_a_partition(
        "",
        "vault /dev/sdc none luks,header=/hdr.img:/dev/sdb1,nofail\n",
    )
    .run();
    assert_eq!(
        result.message(),
        names_the_volume(
            "/etc/crypttab: 'vault /dev/sdc' (it mounts the volume at /mnt or a device it is \
             stored on for its header)"
        )
    );
    // Another drive, and a key device, which the boot mounts read-only,
    // pass.
    for crypttab in [
        "vault /dev/sdc none luks,header=/hdr.img:/dev/sdc,nofail\n",
        "vault /dev/sdc none luks,header=/dev/sdc,nofail\n",
        "vault /dev/sdc /k:/dev/sdb2 luks,nofail\n",
    ] {
        let result = on_a_partition("", crypttab).run();
        assert!(result.is_pass(), "{crypttab}: {result:?}");
    }
}

#[test]
fn a_line_that_writes_over_another_partition_of_the_disk_a_container_lies_on_fails() {
    // A root in a container file on the decoy's /home lies on the decoy's
    // own disk: that disk is the hidden drive, so a random-key swap line for
    // another partition of it fails as one that has the boot write over a
    // device of that drive, without the flag and with it, though the
    // hidden-volume check accepts the container with a warning.
    let decoy = root_in_a_file(
        true,
        "",
        "cswap /dev/nvme0n1p5 /dev/urandom swap,cipher=aes-xts-plain64,size=512\n",
    )
    .partition(
        "/sys/devices/pci0/nvme/nvme0n1/nvme0n1p5",
        "nvme0n1p5",
        "259:5",
    );
    decoy.fs.mock_set_device_node("/dev/nvme0n1p5");
    assert!(hidden_volume_with_the_flag(&decoy.fs).is_warn());
    fails_naming(
        &decoy,
        "/etc/crypttab: 'cswap /dev/nvme0n1p5' (it has the boot make swap over a device of the \
         drive the volume at /mnt is stored on through its option swap)",
    );
    // A swap line for a partition of another disk passes.
    let decoy = root_in_a_file(true, "", "cswap /dev/sdc /dev/urandom swap\n").device(
        SDC,
        "sdc",
        "8:32",
        &[],
    );
    decoy.fs.mock_set_device_node("/dev/sdc");
    let result = decoy.run();
    assert!(result.is_pass(), "{result:?}");
}

#[test]
fn a_makefs_line_for_a_device_a_filesystem_is_mounted_from_passes() {
    // A root in a container file on the decoy's /home, whose fstab line has
    // x-systemd.makefs, as NixOS writes it for autoFormat: /home's device
    // holds the filesystem mounted at /home, which systemd-makefs finds there
    // and leaves as it is, so the line formats nothing. The same line for a
    // partition of that disk that no filesystem is mounted from fails.
    let fstab = |home: &str| {
        format!("/dev/nvme0n1p3 / ext4 defaults 0 1\n/dev/nvme0n1p4 /home ext4 {home} 0 2\n")
    };
    let decoy = root_in_a_file(true, "", "");
    decoy
        .fs
        .mock_set_file_content("/etc/fstab", &fstab("defaults,x-systemd.makefs"));
    let result = decoy.run();
    assert!(result.is_pass(), "{result:?}");
    let decoy = root_in_a_file(true, "/dev/nvme0n1p5 /data ext4 x-systemd.makefs 0 2\n", "")
        .partition(
            "/sys/devices/pci0/nvme/nvme0n1/nvme0n1p5",
            "nvme0n1p5",
            "259:5",
        );
    decoy.fs.mock_set_device_node("/dev/nvme0n1p5");
    fails_naming(
        &decoy,
        "/etc/fstab: '/dev/nvme0n1p5 /data ext4' (it has the boot format a device of the drive \
         the volume at /mnt is stored on where it finds no filesystem, through its option \
         x-systemd.makefs)",
    );
}
