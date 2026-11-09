// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Lines for another device of the root's btrfs filesystem: the volume lies
//! on each of its devices, so a line that names any of them, or a device
//! below one, is an entry for the hidden drive, as one for the device its
//! mounts show is.

use super::*;

/// The plain decoy and a btrfs filesystem of the two external devices sdb1
/// and sdc1, mounted whole at the root from sdb1, with `lines` in the fstab
/// beside the decoy's lines for / and /home. `UUID=f9` leads to sdc1, as a
/// filesystem's uuid link can lead to any of its devices.
fn two_devices(lines: &str) -> Judgement {
    plain_decoy("5 1 0:50 / /mnt rw - btrfs /dev/sdb1 rw,subvolid=5,subvol=/\n")
        .disk("sdb", "8:16")
        .part("sdb1", "8:17", "sdb")
        .disk("sdc", "8:32")
        .part("sdc1", "8:33", "sdc")
        .btrfs(&["sdb1", "sdc1"])
        .spec("UUID=f9", "sdc1")
        .fstab(&format!(
            "/dev/sda1 / ext4 defaults 0 1\n/dev/sda2 /home ext4 defaults 0 2\n{lines}"
        ))
        .judge("/mnt")
}

#[test]
fn a_line_for_another_device_of_the_roots_btrfs_mounts_the_volume() {
    // By the device's path or by a uuid link that leads to it, at a system
    // folder: the volume itself, which the decoy's boot mounts there.
    for line in [
        "/dev/sdc1 /srv btrfs defaults,nofail 0 0",
        "UUID=f9 /srv btrfs defaults,nofail 0 0",
    ] {
        let judgement = two_devices(&format!("{line}\n"));
        let shown: Vec<&str> = line.split_whitespace().take(3).collect();
        let shown = shown.join(" ");
        assert_eq!(
            entry_needs(&judgement),
            [(EntryKind::Blocking, shown.as_str(), true)],
            "{line}"
        );
        assert_eq!(judgement.entries[0].why, "it mounts the volume at /mnt");
        assert_eq!(judgement.entries[0].system_folder, None, "{line}");
        assert_eq!(
            judgement.verdict,
            Verdict::OnDecoyFilesystem {
                how: Sharing::Filesystem,
                at: PathBuf::from("/srv"),
                in_fstab: true,
            },
            "{line}"
        );
    }
    // A noauto line at another folder is a recipe for the hidden drive, as
    // one for the device the mounts show is: an entry to remove. It still
    // claims that device, as before it was an entry.
    let judgement = two_devices("UUID=f9 /mnt/hd btrfs noauto 0 0\n");
    assert_eq!(
        entry_needs(&judgement),
        [(EntryKind::Blocking, "UUID=f9 /mnt/hd btrfs", false)]
    );
    assert_eq!(judgement.entries[0].why, "it mounts the volume at /mnt");
    assert_eq!(
        judgement.verdict,
        Verdict::OnDecoyFilesystem {
            how: Sharing::Filesystem,
            at: PathBuf::from("/mnt/hd"),
            in_fstab: true,
        }
    );
}

#[test]
fn a_line_for_another_device_of_the_roots_btrfs_can_be_the_decoys_own() {
    // A subvolume beside /home on a btrfs of sda2 and sdb2, whose /home line
    // names sdb2 by a uuid link: the decoy's own line for /home, as the one
    // that names sda2 is.
    for spec in ["UUID=pool", "/dev/sda2"] {
        let judgement = World::new(
            "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n\
             2 1 0:40 /home /home rw - btrfs /dev/sda2 rw,subvol=/home\n\
             5 1 0:40 /vault /mnt rw - btrfs /dev/sda2 rw,subvol=/vault\n",
        )
        .disk("sda", "8:0")
        .part("sda1", "8:1", "sda")
        .part("sda2", "8:2", "sda")
        .disk("sdb", "8:16")
        .part("sdb2", "8:18", "sdb")
        .btrfs(&["sda2", "sdb2"])
        .spec("UUID=pool", "sdb2")
        .fstab(&format!(
            "/dev/sda1 / ext4 defaults 0 1\n{spec} /home btrfs subvol=/home 0 0\n"
        ))
        .judge("/mnt");
        let line = format!("{spec} /home btrfs");
        assert_eq!(
            entry_needs(&judgement),
            [(EntryKind::Blocking, line.as_str(), true)],
            "{spec}"
        );
        assert_eq!(
            judgement.entries[0].system_folder.as_deref(),
            Some(Path::new("/home")),
            "{spec}"
        );
    }
}

#[test]
fn a_crypttab_line_for_another_device_of_the_roots_btrfs_opens_the_volume() {
    // A btrfs of two LUKS volumes, luks-a on sdb1 and luks-b on sdc1, mounted
    // whole at the root from luks-a: a line that opens luks-b, by its
    // partition or by its name, opens a device the volume is stored on.
    for crypttab in [
        "luks-b /dev/sdc1 none luks,noauto\n",
        "luks-b UUID=gone none luks,noauto\n",
    ] {
        let judgement = plain_decoy("5 1 0:50 / /mnt rw - btrfs /dev/mapper/luks-a rw\n")
            .disk("sdb", "8:16")
            .part("sdb1", "8:17", "sdb")
            .disk("sdc", "8:32")
            .part("sdc1", "8:33", "sdc")
            .crypt("dm-1", "254:1", "luks-a", &["sdb1"])
            .crypt("dm-2", "254:2", "luks-b", &["sdc1"])
            .btrfs(&["dm-1", "dm-2"])
            .crypttab(crypttab)
            .judge("/mnt");
        let line = crypttab.split_whitespace().take(2).collect::<Vec<_>>();
        let line = line.join(" ");
        assert_eq!(
            entry_needs(&judgement),
            [(EntryKind::Blocking, line.as_str(), false)],
            "{crypttab}"
        );
        assert_eq!(
            judgement.entries[0].why,
            "it opens the volume at /mnt or a device it is stored on"
        );
        assert_eq!(judgement.verdict, Verdict::Separate, "{crypttab}");
    }
}
