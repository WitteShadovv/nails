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
