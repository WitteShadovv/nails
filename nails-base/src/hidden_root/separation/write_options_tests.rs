// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The options that have the boot open a device for writing: one of the
//! hidden drive fails its line, whether the volume is stored on it or not,
//! the drive's whole disk, a partition of it and a device stacked on one of
//! them.

use super::*;

/// The plain decoy and the volume `data` (dm-9) on sdb1 of the external sdb,
/// at /mnt, with sdb2 beside it on that drive, mounted at /media/b, the
/// mapping `other` on sdb2, a loop device over an image file on the
/// filesystem of sdb2, and sdc another drive.
fn partitioned_drive() -> World {
    plain_decoy(
        "5 1 254:9 / /mnt rw - ext4 /dev/mapper/data rw\n\
         6 1 8:18 / /media/b rw - ext4 /dev/sdb2 rw\n",
    )
    .disk("sdb", "8:16")
    .part("sdb1", "8:17", "sdb")
    .part("sdb2", "8:18", "sdb")
    .disk("sdc", "8:32")
    .crypt("dm-9", "254:9", "data", &["sdb1"])
    .crypt("dm-5", "254:5", "other", &["sdb2"])
    .loop_file_held(
        "loop0",
        "7:0",
        "/media/b/disk.img",
        FileHolder::Mount("8:18".into()),
    )
}

#[test]
fn an_option_that_opens_any_device_of_the_drive_for_writing_is_an_entry() {
    // systemd-cryptsetup opens a tpm2-device= and a fido2-device= read-write
    // and writes TPM2 or FIDO2 commands to them, and a filesystem writes its
    // journal or log to the device it names. On the volume's drive, the
    // whole disk, another partition, a mapping on one or an image file on its
    // filesystem, that is a write to that drive at boot.
    let decoys = "/dev/sda1 / ext4 defaults 0 1\n/dev/sda2 /home ext4 defaults 0 2\n";
    for (fstab, crypttab, option) in [
        (
            "",
            "vault /dev/sdc none luks,tpm2-device=/dev/sdb,nofail",
            "tpm2-device",
        ),
        (
            "",
            "vault /dev/sdc none luks,tpm2-device=/dev/mapper/other,nofail",
            "tpm2-device",
        ),
        (
            "",
            "vault /dev/sdc none luks,fido2-device=/dev/sdb2,nofail",
            "fido2-device",
        ),
        (
            "/dev/sdc /data ext4 journal_path=/dev/sdb 0 2",
            "",
            "journal_path",
        ),
        (
            "/dev/sdc /data ext4 journal_path=/dev/sdb2 0 2",
            "",
            "journal_path",
        ),
        (
            "/dev/sdc /data ext4 journal_dev=2066 0 2",
            "",
            "journal_dev",
        ),
        ("/dev/sdc /data xfs logdev=/dev/loop0 0 0", "", "logdev"),
        (
            "/dev/sdc /data xfs rtdev=/dev/mapper/other 0 0",
            "",
            "rtdev",
        ),
        ("/dev/sdc /data btrfs device=/dev/sdb2 0 0", "", "device"),
    ] {
        let judgement = partitioned_drive()
            .fstab(&format!("{decoys}{fstab}\n"))
            .crypttab(&format!("{crypttab}\n"))
            .judge("/mnt");
        let shown = if fstab.is_empty() {
            "vault /dev/sdc".to_string()
        } else {
            fstab
                .split_whitespace()
                .take(3)
                .collect::<Vec<_>>()
                .join(" ")
        };
        assert_eq!(
            entry_needs(&judgement),
            [(EntryKind::Blocking, shown.as_str(), false)],
            "{fstab}{crypttab}"
        );
        assert_eq!(
            judgement.entries[0].why,
            format!(
                "it opens a device of the drive the volume at /mnt is stored on for writing \
                 through its option {option}="
            ),
            "{fstab}{crypttab}"
        );
    }
    // A device of another drive, an option that writes to nothing it names,
    // the device the boot mounts read-only for a key file, a header, and the
    // drive's other partition as a line's own source name none.
    for (fstab, crypttab) in [
        ("", "vault /dev/sdc none luks,tpm2-device=/dev/sdc,nofail"),
        ("", "vault /dev/sdc /key:/dev/sdb2 luks,nofail"),
        ("", "vault /dev/sdc none luks,header=/dev/sdb2,nofail"),
        ("/dev/sdc /data ext4 journal_path=/dev/sdc 0 2", ""),
        (
            "/dev/sdc /data ext4 x-systemd.requires-mounts-for=/dev/sdb 0 2",
            "",
        ),
        ("/dev/sdb2 /media/b ext4 nofail 0 2", ""),
    ] {
        let judgement = partitioned_drive()
            .fstab(&format!("{decoys}{fstab}\n"))
            .crypttab(&format!("{crypttab}\n"))
            .judge("/mnt");
        assert_eq!(entry_needs(&judgement), [], "{fstab}{crypttab}");
    }
}

#[test]
fn a_line_that_has_the_boot_write_over_its_own_device_of_the_drive_is_an_entry() {
    // systemd-makefs formats the device of an x-systemd.makefs line, and
    // makes swap or a filesystem on the mapping of a crypttab line with
    // swap or tmp, wherever it finds no filesystem: a whole disk with a
    // partition table and nothing at its own start among them. A plain
    // mapping checks no header, so whatever writes to it writes over its
    // source. On the volume's drive, a noauto line among them, that is a
    // write over that drive.
    let decoys = "/dev/sda1 / ext4 defaults 0 1\n/dev/sda2 /home ext4 defaults 0 2\n";
    let makefs = "it has the boot format a device of the drive the volume at /mnt is stored on \
                  where it finds no filesystem, through its option x-systemd.makefs";
    let swap = "it has the boot make swap over a device of the drive the volume at /mnt is \
                stored on through its option swap";
    let tmp = "it has the boot make a filesystem over a device of the drive the volume at /mnt \
               is stored on through its option tmp";
    let plain = "it opens a device of the drive the volume at /mnt is stored on as plain \
                 dm-crypt, which checks no header, so what the boot writes to its mapping lands \
                 on that drive";
    for (fstab, crypttab, shown, why) in [
        (
            "/dev/sdb /media/x ext4 x-systemd.makefs,nofail 0 0",
            "",
            "/dev/sdb /media/x ext4",
            makefs,
        ),
        (
            "/dev/disk/by-id/usb-whole /media/x ext4 x-systemd.makefs=yes,nofail 0 0",
            "",
            "/dev/disk/by-id/usb-whole /media/x ext4",
            makefs,
        ),
        (
            "/dev/sdb none swap sw,x-systemd.makefs 0 0",
            "",
            "/dev/sdb none swap",
            makefs,
        ),
        (
            "/dev/sdb /media/x ext4 noauto,x-systemd.makefs 0 0",
            "",
            "/dev/sdb /media/x ext4",
            makefs,
        ),
        (
            "/dev/sdb2 /media/x ext4 x-systemd.makefs 0 0",
            "",
            "/dev/sdb2 /media/x ext4",
            makefs,
        ),
        (
            "/dev/loop0 /media/x ext4 x-systemd.makefs,nofail 0 0",
            "",
            "/dev/loop0 /media/x ext4",
            makefs,
        ),
        (
            "",
            "swapcrypt /dev/sdb /dev/urandom swap,cipher=aes-xts-plain64,size=512",
            "swapcrypt /dev/sdb",
            swap,
        ),
        (
            "",
            "swapcrypt /dev/disk/by-id/usb-whole /dev/urandom swap",
            "swapcrypt /dev/disk/by-id/usb-whole",
            swap,
        ),
        (
            "",
            "swapcrypt /dev/sdb /dev/urandom luks,swap",
            "swapcrypt /dev/sdb",
            swap,
        ),
        (
            "",
            "swapcrypt /dev/sdb /dev/urandom swap,noauto",
            "swapcrypt /dev/sdb",
            swap,
        ),
        (
            "",
            "swapcrypt /dev/sdb2 /dev/urandom swap",
            "swapcrypt /dev/sdb2",
            swap,
        ),
        (
            "",
            "swapcrypt /dev/loop0 /dev/urandom swap",
            "swapcrypt /dev/loop0",
            swap,
        ),
        (
            "",
            "tmpcrypt /dev/sdb /dev/urandom tmp",
            "tmpcrypt /dev/sdb",
            tmp,
        ),
        (
            "",
            "tmpcrypt /dev/sdb /dev/urandom tmp=ext2",
            "tmpcrypt /dev/sdb",
            tmp,
        ),
        (
            "",
            "px /dev/sdb /etc/plainkey plain,offset=2048,cipher=aes-xts-plain64,size=512",
            "px /dev/sdb",
            plain,
        ),
        (
            "/dev/mapper/plainx /data ext4 x-systemd.makefs,nofail 0 0",
            "plainx /dev/sdb /etc/plainkey luks,plain",
            "plainx /dev/sdb",
            plain,
        ),
    ] {
        let judgement = partitioned_drive()
            .spec("/dev/disk/by-id/usb-whole", "sdb")
            .fstab(&format!("{decoys}{fstab}\n"))
            .crypttab(&format!("{crypttab}\n"))
            .judge("/mnt");
        assert_eq!(
            entry_needs(&judgement),
            [(EntryKind::Blocking, shown, false)],
            "{fstab}{crypttab}"
        );
        assert_eq!(judgement.entries[0].why, why, "{fstab}{crypttab}");
    }
    // Another drive, a line that writes nothing over its device, one that
    // opens it as LUKS, which loads its header or fails, and one whose
    // mapping is not open now, name none.
    for (fstab, crypttab) in [
        ("/dev/sdc /media/x ext4 x-systemd.makefs,nofail 0 0", ""),
        ("", "swapcrypt /dev/sdc /dev/urandom swap"),
        ("/dev/sdb none swap sw 0 0", ""),
        ("/dev/sdb /media/g ext4 x-systemd.growfs,nofail 0 0", ""),
        ("", "vault /dev/sdb none luks,nofail"),
        ("", "vault /dev/sdb none plain,luks"),
        ("", "vault /dev/sdb none bitlk"),
        (
            "/dev/mapper/gone /media/x ext4 x-systemd.makefs,nofail 0 0",
            "",
        ),
    ] {
        let judgement = partitioned_drive()
            .fstab(&format!("{decoys}{fstab}\n"))
            .crypttab(&format!("{crypttab}\n"))
            .judge("/mnt");
        assert_eq!(entry_needs(&judgement), [], "{fstab}{crypttab}");
    }
    // On a device the volume is stored on, the line opens or mounts that
    // device, as before.
    for (fstab, crypttab, shown, why) in [
        (
            "/dev/sdb1 /media/x ext4 x-systemd.makefs,nofail 0 0",
            "",
            "/dev/sdb1 /media/x ext4",
            "it mounts a device the volume at /mnt is stored on",
        ),
        (
            "",
            "swapcrypt /dev/sdb1 /dev/urandom swap",
            "swapcrypt /dev/sdb1",
            "it opens the volume at /mnt or a device it is stored on",
        ),
    ] {
        let judgement = partitioned_drive()
            .fstab(&format!("{decoys}{fstab}\n"))
            .crypttab(&format!("{crypttab}\n"))
            .judge("/mnt");
        let needs = !fstab.is_empty();
        assert_eq!(
            entry_needs(&judgement),
            [(EntryKind::Blocking, shown, needs)],
            "{fstab}{crypttab}"
        );
        assert_eq!(judgement.entries[0].why, why, "{fstab}{crypttab}");
    }
}

#[test]
fn a_header_device_on_the_drive_is_an_entry() {
    // systemd's crypttab generator mounts the device of a
    // `header=<path>:<device>` read-write, for LUKS2 recovery: on the
    // volume's drive, that is a write to it at boot.
    let header = "it mounts a device of the drive the volume at /mnt is stored on read-write for \
                  its header";
    for (crypttab, why) in [
        (
            "vault /dev/sdc none luks,header=/hdr.img:/dev/sdb2,nofail",
            header,
        ),
        (
            "vault /dev/sdc none luks,header=/hdr.img:/dev/sdb,nofail",
            header,
        ),
        (
            "vault /dev/sdc none luks,header=/hdr.img:/dev/disk/by-id/usb-whole,nofail",
            header,
        ),
        (
            "vault /dev/sdc none luks,header=/hdr.img:/dev/sdb1,nofail",
            "it mounts the volume at /mnt or a device it is stored on for its header",
        ),
    ] {
        let judgement = partitioned_drive()
            .spec("/dev/disk/by-id/usb-whole", "sdb")
            .crypttab(&format!("{crypttab}\n"))
            .judge("/mnt");
        assert_eq!(
            entry_needs(&judgement),
            [(EntryKind::Blocking, "vault /dev/sdc", false)],
            "{crypttab}"
        );
        assert_eq!(judgement.entries[0].why, why, "{crypttab}");
    }
    // Another drive, and the device the boot mounts read-only for a key
    // file, name none.
    for crypttab in [
        "vault /dev/sdc none luks,header=/hdr.img:/dev/sdc,nofail",
        "vault /dev/sdc /k:/dev/sdb2 luks,nofail",
    ] {
        let judgement = partitioned_drive()
            .crypttab(&format!("{crypttab}\n"))
            .judge("/mnt");
        assert_eq!(entry_needs(&judgement), [], "{crypttab}");
    }
}
