// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The decoy's own fstab lines for the filesystem a root is part of: the ones
//! its boot mounts at `/` and at the system folders, which a root that
//! `--allow-decoy-storage` accepted lies on by them, and the ones its boot
//! needs, the crypttab line that opens the device that filesystem lies on
//! among them.

use super::*;

/// Each entry's line, and the system folder it is the decoy's own line for.
fn entry_folders(judgement: &Judgement) -> Vec<(&str, Option<&Path>)> {
    judgement
        .entries
        .iter()
        .map(|entry| (entry.line.as_str(), entry.system_folder.as_deref()))
        .collect()
}

#[test]
fn the_lines_the_boot_mounts_at_slash_and_the_system_folders_are_the_decoys_own() {
    for at in [
        "/",
        "/usr",
        "/var",
        "/home",
        "/srv",
        "/boot",
        "/efi",
        "/boot/efi",
        "/nix",
        "/opt",
    ] {
        assert!(is_system_folder(Path::new(at), Path::new("/mnt")), "{at}");
    }
    for at in [
        "/pool",
        "/var/log",
        "/home/u",
        "/.snapshots",
        "/mnt",
        "/media/u",
    ] {
        assert!(!is_system_folder(Path::new(at), Path::new("/mnt")), "{at}");
    }
    // A system folder that the hidden root is, or lies above, is the root's.
    assert!(!is_system_folder(Path::new("/srv"), Path::new("/srv")));
    assert!(!is_system_folder(
        Path::new("/boot/efi"),
        Path::new("/boot")
    ));

    // The decoy's lines for the filesystem a bind of a folder of /, or a
    // subvolume beside /home, is part of.
    let bind = plain_decoy("5 1 8:1 /srv/x /mnt rw - ext4 /dev/sda1 rw\n").judge("/mnt");
    assert_eq!(
        entry_folders(&bind),
        [("/dev/sda1 / ext4", Some(Path::new("/")))]
    );
    let subvolume = |fstab: &str| {
        World::new(
            "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n\
             2 1 0:40 /home /home rw - btrfs /dev/sda2 rw,subvol=/home\n\
             5 1 0:40 /vault /mnt rw - btrfs /dev/sda2 rw,subvol=/vault\n",
        )
        .disk("sda", "8:0")
        .part("sda1", "8:1", "sda")
        .part("sda2", "8:2", "sda")
        .btrfs(&["sda2"])
        .fstab(fstab)
        .judge("/mnt")
    };
    assert_eq!(
        entry_folders(&subvolume("/dev/sda2 /home btrfs subvol=/home 0 0\n")),
        [("/dev/sda2 /home btrfs", Some(Path::new("/home")))]
    );
    // A line for any other folder, below a system folder too, and one the
    // boot does not mount are none.
    assert_eq!(
        entry_folders(&subvolume(
            "/dev/sda2 /pool btrfs defaults 0 0\n/dev/sda2 /var/log btrfs subvol=/log 0 0\n\
             /dev/sda2 /srv btrfs noauto 0 0\n"
        )),
        [
            ("/dev/sda2 /pool btrfs", None),
            ("/dev/sda2 /var/log btrfs", None),
            ("/dev/sda2 /srv btrfs", None)
        ]
    );
    // Neither is a line for a device below the root's own, nor one for the
    // system folder the hidden root is mounted at.
    let below = plain_decoy("5 1 259:8 /x /mnt rw - ext4 /dev/loop1p1 rw\n")
        .node("loop1", "7:1", NodeKind::Loop { file: None }, &["sda2"])
        .part("loop1p1", "259:8", "loop1")
        .judge("/mnt");
    assert_eq!(entry_folders(&below), [("/dev/sda2 /home ext4", None)]);
    let at_the_root = plain_decoy("5 1 8:17 / /srv rw - ext4 /dev/sdb1 rw\n")
        .disk("sdb", "8:16")
        .part("sdb1", "8:17", "sdb")
        .fstab("/dev/sda1 / ext4 defaults 0 1\n/dev/sdb1 /srv ext4 defaults 0 2\n")
        .judge("/srv");
    assert_eq!(entry_folders(&at_the_root), [("/dev/sdb1 /srv ext4", None)]);
}

#[test]
fn the_decoys_line_for_slash_or_a_system_folder_is_one_its_boot_needs_for_a_whole_filesystem() {
    // The decoy's / and its /home partition, each mounted whole at the root
    // as well: the line for / or /home mounts the volume, and the decoy's own
    // boot needs it, so it is never one to remove. It mounts the volume
    // itself, not a filesystem the root is part of, so it is no line the
    // flag lets be.
    let whole_root = plain_decoy("5 1 8:1 / /mnt rw - ext4 /dev/sda1 rw\n").judge("/mnt");
    assert_eq!(
        entry_needs(&whole_root),
        [(EntryKind::Blocking, "/dev/sda1 / ext4", true)]
    );
    assert_eq!(whole_root.entries[0].why, "it mounts the volume at /mnt");
    assert_eq!(entry_folders(&whole_root), [("/dev/sda1 / ext4", None)]);
    let whole_home = plain_decoy("5 1 8:2 / /mnt rw - ext4 /dev/sda2 rw\n").judge("/mnt");
    assert_eq!(
        entry_needs(&whole_home),
        [(EntryKind::Blocking, "/dev/sda2 /home ext4", true)]
    );
    assert_eq!(entry_folders(&whole_home), [("/dev/sda2 /home ext4", None)]);
    // So is a line for a separate drive at a system folder, mounted at the
    // root alone, as one plugged in after the boot is.
    for place in ["/srv", "/opt", "/home"] {
        let fstab =
            format!("/dev/sda1 / ext4 defaults 0 1\n/dev/sdb1 {place} ext4 defaults,nofail 0 2\n");
        let later = World::new(
            "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n\
             5 1 8:17 / /mnt rw - ext4 /dev/sdb1 rw\n",
        )
        .disk("sda", "8:0")
        .part("sda1", "8:1", "sda")
        .disk("sdb", "8:16")
        .part("sdb1", "8:17", "sdb")
        .fstab(&fstab)
        .judge("/mnt");
        let line = format!("/dev/sdb1 {place} ext4");
        assert_eq!(
            entry_needs(&later),
            [(EntryKind::Blocking, line.as_str(), true)],
            "{place}"
        );
        assert_eq!(later.entries[0].why, "it mounts the volume at /mnt");
        assert_eq!(entry_folders(&later), [(line.as_str(), None)], "{place}");
    }
    // A line for it at any other folder may be the hidden drive's own: it is
    // one the volume alone needs, and goes.
    let elsewhere = plain_decoy(
        "5 1 8:17 / /mnt rw - ext4 /dev/sdb1 rw\n\
         6 1 8:17 / /backup rw - ext4 /dev/sdb1 rw\n",
    )
    .disk("sdb", "8:16")
    .part("sdb1", "8:17", "sdb")
    .fstab("/dev/sda1 / ext4 defaults 0 1\n/dev/sdb1 /backup ext4 defaults 0 2\n")
    .judge("/mnt");
    assert_eq!(
        entry_needs(&elsewhere),
        [(EntryKind::Blocking, "/dev/sdb1 /backup ext4", false)]
    );
    assert_eq!(
        entry_folders(&elsewhere),
        [("/dev/sdb1 /backup ext4", None)]
    );
}

/// The decoy's / on sda1, its /home a subvolume (id 257) of the btrfs on
/// sda2, and the subvolume /vault (id 300) of it at the root, judged with
/// `lines` in the fstab beside the decoy's lines for / and /home.
fn beside_home(lines: &str) -> Judgement {
    World::new(
        "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n\
         2 1 0:40 /home /home rw - btrfs /dev/sda2 rw,subvolid=257,subvol=/home\n\
         5 1 0:40 /vault /mnt rw - btrfs /dev/sda2 rw,subvolid=300,subvol=/vault\n",
    )
    .disk("sda", "8:0")
    .part("sda1", "8:1", "sda")
    .part("sda2", "8:2", "sda")
    .btrfs(&["sda2"])
    .fstab(&format!(
        "/dev/sda1 / ext4 defaults 0 1\n/dev/sda2 /home btrfs subvol=/home 0 0\n{lines}"
    ))
    .judge("/mnt")
}

/// The finding for the decoy's line for /srv.
fn srv_line(judgement: &Judgement) -> &EntryFinding {
    let found: Vec<&EntryFinding> = judgement
        .entries
        .iter()
        .filter(|entry| entry.line.contains(" /srv "))
        .collect();
    assert_eq!(found.len(), 1, "{:?}", judgement.entries);
    found[0]
}

#[test]
fn a_line_that_mounts_the_roots_own_subvolume_is_none_of_the_decoys_own() {
    // A line for /srv that mounts the root's subvolume, by its path, its id
    // or both, or a subvolume inside it, mounts the volume itself: the
    // decoy's boot needs it there, and it is no line the flag lets be.
    for options in [
        "subvol=/vault",
        "subvol=vault",
        "subvolid=300",
        "subvol=/vault,subvolid=300",
        "subvol=/vault/inner",
    ] {
        let judgement = beside_home(&format!("/dev/sda2 /srv btrfs {options} 0 0\n"));
        let srv = srv_line(&judgement);
        assert_eq!(srv.why, "it mounts the volume at /mnt", "{options}");
        assert!(srv.boot_needs, "{options}");
        assert_eq!(srv.system_folder, None, "{options}");
        // The line for /home is still the decoy's own.
        assert_eq!(
            entry_folders(&judgement)[0],
            ("/dev/sda2 /home btrfs", Some(Path::new("/home"))),
            "{options}"
        );
    }
    // A line that mounts another part of the filesystem is the decoy's own:
    // the top, by no option, its path or its id, or the /home subvolume, by
    // the id the mount table shows for it.
    for options in [
        "defaults",
        "subvol=/",
        "subvolid=5",
        "subvolid=0",
        "subvolid=257",
        "subvol=home,subvolid=257",
    ] {
        let judgement = beside_home(&format!("/dev/sda2 /srv btrfs {options} 0 0\n"));
        let srv = srv_line(&judgement);
        assert_eq!(
            srv.why, "it mounts the filesystem the volume at /mnt is part of",
            "{options}"
        );
        assert_eq!(
            srv.system_folder.as_deref(),
            Some(Path::new("/srv")),
            "{options}"
        );
    }
    // Nor is one whose subvolume cannot be told (fail closed): an id that no
    // mount shows, one that is no plain number, and options that name two
    // subvolumes.
    for options in [
        "subvolid=301",
        "subvolid=0x12c",
        "subvolid=0300",
        "subvol=/home,subvolid=300",
    ] {
        let judgement = beside_home(&format!("/dev/sda2 /srv btrfs {options} 0 0\n"));
        let srv = srv_line(&judgement);
        assert!(srv.boot_needs, "{options}");
        assert_eq!(srv.system_folder, None, "{options}");
    }
}

#[test]
fn a_line_for_the_subvolume_a_bound_folder_lies_in_is_the_decoys_own() {
    // A folder of the /home subvolume bound at the root, whose mount shows
    // that subvolume's id: the line for /home mounts the subvolume the root
    // is a folder of, by its path or by its id.
    for options in ["subvol=/home", "subvolid=257"] {
        let judgement = World::new(
            "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n\
             2 1 0:40 /home /home rw - btrfs /dev/sda2 rw,subvolid=257,subvol=/home\n\
             5 1 0:40 /home/u/vault /mnt rw - btrfs /dev/sda2 rw,subvolid=257,subvol=/home\n",
        )
        .disk("sda", "8:0")
        .part("sda1", "8:1", "sda")
        .part("sda2", "8:2", "sda")
        .btrfs(&["sda2"])
        .fstab(&format!(
            "/dev/sda1 / ext4 defaults 0 1\n/dev/sda2 /home btrfs {options} 0 0\n"
        ))
        .judge("/mnt");
        assert!(
            matches!(
                judgement.verdict,
                Verdict::OnDecoyFilesystem {
                    how: Sharing::Bind,
                    ..
                }
            ),
            "{:?}",
            judgement.verdict
        );
        assert_eq!(
            entry_folders(&judgement),
            [("/dev/sda2 /home btrfs", Some(Path::new("/home")))],
            "{options}"
        );
    }
}

// ---------------------------------------------------------------------------
// The crypttab line for the device the root's filesystem lies on
// ---------------------------------------------------------------------------

/// Each crypttab entry's line, and whether the decoy's own boot needs it.
fn crypttab_needs(judgement: &Judgement) -> Vec<(&str, bool)> {
    judgement
        .entries
        .iter()
        .filter(|entry| entry.file == CRYPTTAB)
        .map(|entry| (entry.line.as_str(), entry.boot_needs))
        .collect()
}

/// Debian's encrypted ext4 root without LVM, with `root` at the root as
/// well: the decoy's crypttab opens the LUKS volume its / lies on.
fn debian_luks(root: &str) -> Judgement {
    World::new(&format!(
        "1 0 254:0 / / rw - ext4 /dev/mapper/cryptroot rw\n\
         5 1 254:0 {root} /mnt rw - ext4 /dev/mapper/cryptroot rw\n"
    ))
    .disk("nvme0n1", "259:0")
    .part("nvme0n1p3", "259:3", "nvme0n1")
    .crypt("dm-0", "254:0", "cryptroot", &["nvme0n1p3"])
    .spec("UUID=e1", "nvme0n1p3")
    .fstab("/dev/mapper/cryptroot / ext4 defaults 0 1\n")
    .crypttab("cryptroot UUID=e1 none luks,discard\n")
    .judge("/mnt")
}

#[test]
fn the_crypttab_line_for_the_volume_the_decoys_root_lies_on_is_one_its_boot_needs() {
    // A bind of a folder of /, and the decoy's whole / mounted at the root as
    // well: the line opens the volume the decoy's root lies on, which
    // removing it would take from the decoy.
    for root in ["/srv/x", "/"] {
        let judgement = debian_luks(root);
        assert_eq!(
            crypttab_needs(&judgement),
            [("cryptroot UUID=e1", true)],
            "{root}"
        );
        assert_eq!(
            judgement.entries[1].why,
            "it opens the volume at /mnt or a device it is stored on"
        );
    }
    // The line for / is the decoy's own beside the bind only.
    assert_eq!(
        entry_folders(&debian_luks("/srv/x"))[0],
        ("/dev/mapper/cryptroot / ext4", Some(Path::new("/")))
    );
    assert_eq!(
        entry_folders(&debian_luks("/"))[0],
        ("/dev/mapper/cryptroot / ext4", None)
    );

    // LVM on LUKS, with the swap on a logical volume or in a file on /.
    for swap in [
        "/dev/mapper/vg-swap none swap sw 0 0\n",
        "/swap.img none swap sw 0 0\n",
    ] {
        let judgement = World::new(
            "1 0 254:1 / / rw - ext4 /dev/mapper/vg-root rw\n\
             5 1 254:1 /srv/x /mnt rw - ext4 /dev/mapper/vg-root rw\n",
        )
        .disk("nvme0n1", "259:0")
        .part("nvme0n1p3", "259:3", "nvme0n1")
        .crypt("dm-0", "254:0", "nvme0n1p3_crypt", &["nvme0n1p3"])
        .lv("dm-1", "254:1", "vg-root", &["dm-0"])
        .lv("dm-2", "254:2", "vg-swap", &["dm-0"])
        .spec("UUID=part", "nvme0n1p3")
        .fstab(&format!("/dev/mapper/vg-root / ext4 defaults 0 1\n{swap}"))
        .crypttab("nvme0n1p3_crypt UUID=part none luks,discard\n")
        .judge("/mnt");
        assert_eq!(
            crypttab_needs(&judgement),
            [("nvme0n1p3_crypt UUID=part", true)],
            "{swap}"
        );
    }

    // Fedora's default: btrfs on LUKS, with root and home subvolumes, and a
    // subvolume beside /home or a folder of /home at the root.
    for (root, options, how) in [
        ("/vault", "subvol=/vault", Sharing::Subvolume),
        ("/home/u/vault", "subvol=/home", Sharing::Bind),
    ] {
        let judgement = World::new(&format!(
            "1 0 0:35 /root / rw - btrfs /dev/mapper/luks-f1 rw,subvol=/root\n\
             2 1 0:35 /home /home rw - btrfs /dev/mapper/luks-f1 rw,subvol=/home\n\
             3 1 259:2 / /boot rw - ext4 /dev/nvme0n1p2 rw\n\
             5 1 0:35 {root} /mnt rw - btrfs /dev/mapper/luks-f1 rw,{options}\n"
        ))
        .disk("nvme0n1", "259:0")
        .part("nvme0n1p2", "259:2", "nvme0n1")
        .part("nvme0n1p3", "259:3", "nvme0n1")
        .crypt("dm-0", "254:0", "luks-f1", &["nvme0n1p3"])
        .btrfs(&["dm-0"])
        .spec("UUID=fs", "dm-0")
        .spec("UUID=part", "nvme0n1p3")
        .spec("UUID=boot", "nvme0n1p2")
        .fstab(
            "UUID=fs / btrfs subvol=root,compress=zstd:1 0 0\nUUID=boot /boot ext4 defaults 1 2\n\
             UUID=fs /home btrfs subvol=home,compress=zstd:1 0 0\n",
        )
        .crypttab("luks-f1 UUID=part none discard\n")
        .judge("/mnt");
        assert!(
            matches!(judgement.verdict, Verdict::OnDecoyFilesystem { how: h, .. } if h == how),
            "{root}: {:?}",
            judgement.verdict
        );
        assert_eq!(
            entry_folders(&judgement),
            [
                ("UUID=fs / btrfs", Some(Path::new("/"))),
                ("UUID=fs /home btrfs", Some(Path::new("/home"))),
                ("luks-f1 UUID=part", None),
            ],
            "{root}"
        );
        assert_eq!(
            crypttab_needs(&judgement),
            [("luks-f1 UUID=part", true)],
            "{root}"
        );
    }
}

#[test]
fn the_crypttab_line_follows_the_fstab_line_for_a_drive_of_its_own() {
    // A LUKS volume on the external sdb, mounted whole at the root, that the
    // decoy's fstab mounts at /srv when it is there: the line for /srv is one
    // the boot needs, and so is the crypttab line that opens the volume for
    // it. At /backup both serve the hidden volume alone.
    for (place, needed) in [("/srv", true), ("/backup", false)] {
        let judgement = plain_decoy("5 1 254:9 / /mnt rw - ext4 /dev/mapper/data rw\n")
            .disk("sdb", "8:16")
            .crypt("dm-9", "254:9", "data", &["sdb"])
            .fstab(&format!(
                "/dev/sda1 / ext4 defaults 0 1\n/dev/sda2 /home ext4 defaults 0 2\n\
                 /dev/mapper/data {place} ext4 defaults,nofail 0 2\n"
            ))
            .crypttab("data /dev/sdb none luks,nofail\n")
            .judge("/mnt");
        let line = format!("/dev/mapper/data {place} ext4");
        assert_eq!(
            entry_needs(&judgement),
            [
                (EntryKind::Blocking, line.as_str(), needed),
                (EntryKind::Blocking, "data /dev/sdb", needed),
            ],
            "{place}"
        );
    }
}
