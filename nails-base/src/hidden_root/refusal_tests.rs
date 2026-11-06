// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What the operator reads when the attach gate refuses a root: the code,
//! the sentence, the hint and the warning of every kind of refusal, and the
//! words none of them uses.

use super::*;
use crate::hidden_root::separation::{Claimed, Served, Sharing, Untraced, Verdict};
use std::path::PathBuf;

/// One refusal of every kind, of `root`.
pub(crate) fn every_refusal(root: &Path) -> Vec<Refusal> {
    let at = || PathBuf::from("/home");
    [
        RefusalKind::NotConfigured,
        RefusalKind::Missing,
        RefusalKind::MountTableUnreadable {
            error: "permission denied".into(),
        },
        RefusalKind::LookupFailed {
            error: "Permission denied (os error 13)".into(),
            denied: true,
        },
        RefusalKind::LookupFailed {
            error: "Input/output error (os error 5)".into(),
            denied: false,
        },
        RefusalKind::NotLookedUp {
            point: PathBuf::from("/mnt"),
        },
        RefusalKind::NotAMountPoint {
            mount_point: PathBuf::from("/"),
        },
        RefusalKind::DecoyStorage {
            verdict: Verdict::OnDecoyFilesystem {
                how: Sharing::Subvolume,
                at: at(),
                in_fstab: true,
            },
        },
        RefusalKind::DecoyStorage {
            verdict: Verdict::OnDecoyFilesystem {
                how: Sharing::Bind,
                at: at(),
                in_fstab: true,
            },
        },
        RefusalKind::DecoyStorage {
            verdict: Verdict::OnDecoyFilesystem {
                how: Sharing::Filesystem,
                at: PathBuf::from("/srv"),
                in_fstab: true,
            },
        },
        RefusalKind::DecoyStorage {
            verdict: Verdict::InsideDecoyStorage {
                device: "dm-0".into(),
                holds: Claimed::Mount(PathBuf::from("/")),
                noauto_only: false,
            },
        },
        RefusalKind::DecoyStorage {
            verdict: Verdict::InsideDecoyStorage {
                device: "sda3".into(),
                holds: Claimed::Swap("/dev/sda3".into()),
                noauto_only: false,
            },
        },
        RefusalKind::DecoyStorage {
            verdict: Verdict::InsideDecoyStorage {
                device: "sdb".into(),
                holds: Claimed::Encrypted("veracrypt1".into()),
                noauto_only: false,
            },
        },
        RefusalKind::DecoyStorage {
            verdict: Verdict::ImageFileOnDecoy {
                file: PathBuf::from("/home/u/disk.img"),
                at: at(),
            },
        },
        RefusalKind::DecoyStorage {
            verdict: Verdict::ContainerOnDecoy {
                file: PathBuf::from("/home/u/files.bin"),
                at: at(),
            },
        },
        RefusalKind::DecoyStorage {
            verdict: Verdict::ServedDevice {
                kind: Served::Network,
            },
        },
        RefusalKind::DecoyStorage {
            verdict: Verdict::ServedDevice {
                kind: Served::Userspace,
            },
        },
        RefusalKind::SameDeviceAsRoot,
        RefusalKind::Covered {
            below: "ext4".into(),
            above: "vfat".into(),
        },
        RefusalKind::NotTheSessionVolume {
            fstype: "vfat".into(),
        },
        RefusalKind::StorageUnjudged {
            unreadable: vec![PathBuf::from("/etc/crypttab")],
        },
        RefusalKind::StorageUnjudged {
            unreadable: vec![PathBuf::from("/dev/loop0")],
        },
        RefusalKind::StorageUntraced {
            verdict: Verdict::UntracedStorage {
                fstype: "fuse".into(),
            },
        },
        RefusalKind::StorageUntraced {
            verdict: Verdict::UnplacedImageFile {
                file: PathBuf::from("/home/u/disk.img"),
            },
        },
        RefusalKind::StorageUntraced {
            verdict: Verdict::DiskNotFound,
        },
        RefusalKind::StorageUntraced {
            verdict: Verdict::UntracedDevice {
                kind: Untraced::ZfsVolume,
            },
        },
        RefusalKind::StorageUntraced {
            verdict: Verdict::UntracedDevice {
                kind: Untraced::UnnamedDriver,
            },
        },
        RefusalKind::StorageUntraced {
            verdict: Verdict::UntracedDevice {
                kind: Untraced::NotFound,
            },
        },
        RefusalKind::StorageUntraced {
            verdict: Verdict::ClaimedDeviceNotFound,
        },
        RefusalKind::StorageUnjudged {
            unreadable: vec![PathBuf::from("/proc/devices")],
        },
    ]
    .into_iter()
    .chain(
        DEVICE_INPUTS
            .iter()
            .map(|(input, _)| RefusalKind::StorageUnjudged {
                unreadable: vec![PathBuf::from(input)],
            }),
    )
    .map(|kind| Refusal::new(kind, root))
    .collect()
}

/// What the gate reads of one device or filesystem, and what the text
/// calls it.
const DEVICE_INPUTS: &[(&str, &str)] = &[
    (
        "/sys/devices/virtual/block/loop1/loop/backing_file",
        "the path of a loop device's file",
    ),
    (
        "/sys/devices/virtual/block/dm-5/slaves",
        "the devices below a block device",
    ),
    (
        "/sys/devices/virtual/block/zram0/backing_dev",
        "the writeback device of a zram device",
    ),
    (
        "/sys/devices/virtual/block/zd0/dev",
        "the number of a block device",
    ),
    (
        "/sys/fs/btrfs/0a1b2c3d-0000-4000-8000-000000000009/devices",
        "the devices of a btrfs filesystem",
    ),
    (
        "/sys/devices/virtual/block/zd0/size",
        "an attribute of a block device",
    ),
    (
        "/sys/fs/ext4/dm-3/journal_task",
        "where an ext3 or ext4 filesystem keeps its journal",
    ),
    (
        "/proc/412/comm",
        "where an ext3 or ext4 filesystem keeps its journal",
    ),
];

#[test]
fn each_kind_has_its_code() {
    let codes: Vec<&str> = every_refusal(Path::new("/mnt"))
        .iter()
        .map(Refusal::code)
        .collect();
    assert_eq!(&codes[..18], &[NOT_SEPARATE_VOLUME; 18]);
    assert_eq!(&codes[18..20], &[ROOT_COVERED; 2]);
    assert_eq!(&codes[20..], &[STORAGE_UNJUDGED; 18]);
}

#[test]
fn what_was_read_of_a_device_is_named_by_what_it_is() {
    for (input, what) in DEVICE_INPUTS {
        let refusal = Refusal::new(
            RefusalKind::StorageUnjudged {
                unreadable: vec![PathBuf::from(input)],
            },
            Path::new("/mnt"),
        );
        assert_eq!(
            refusal.message(),
            format!("could not read {what} to tell where /mnt lives. Nothing was written."),
            "{input}"
        );
    }
    // A file, and a listing of the kernel's, by its path.
    for input in [
        "/etc/crypttab",
        "/proc/devices",
        "/proc/fs/jbd2",
        "/sys/class/block",
        "/sys/fs/btrfs",
    ] {
        let refusal = Refusal::new(
            RefusalKind::StorageUnjudged {
                unreadable: vec![PathBuf::from(input)],
            },
            Path::new("/mnt"),
        );
        assert!(refusal.reason.contains(input), "{}", refusal.reason);
    }
}

#[test]
fn a_device_that_cannot_be_found_is_named_by_nothing() {
    use crate::hidden_root::Allow;
    let refusal = Refusal::new(
        RefusalKind::StorageUntraced {
            verdict: Verdict::UntracedDevice {
                kind: Untraced::NotFound,
            },
        },
        Path::new("/mnt"),
    );
    assert_eq!(
        refusal.message(),
        "/mnt is stored on a device that cannot be found, so where it lives cannot be told. \
         Nothing was written."
    );
    assert_eq!(refusal.hint(None), [OWN_VOLUME]);
    assert!(!Allow::DecoyStorage.covers(&refusal.kind));
    // What this computer's own storage lies on cannot be found.
    let claimed = Refusal::new(
        RefusalKind::StorageUntraced {
            verdict: Verdict::ClaimedDeviceNotFound,
        },
        Path::new("/mnt"),
    );
    assert_eq!(
        claimed.message(),
        "/mnt cannot be told apart from this computer's own storage, which keeps data on a \
         device that cannot be found, so where it lives cannot be told. Nothing was written."
    );
    assert_eq!(
        claimed.hint(None),
        ["Run the command again on the host rather than in a container, with /sys mounted."]
    );
    assert!(!Allow::DecoyStorage.covers(&claimed.kind));
}

#[test]
fn a_served_disk_says_what_serves_it_and_where_to_read_when_it_is_elsewhere() {
    let refusal = Refusal::new(
        RefusalKind::DecoyStorage {
            verdict: Verdict::ServedDevice {
                kind: Served::Network,
            },
        },
        Path::new("/mnt"),
    );
    assert_eq!(
        refusal.message(),
        "/mnt is not a volume of its own: it is stored on a network block device, which a \
         program can serve from a file on this computer's own disk. Nothing was written."
    );
    // The program on the root is no copy on this computer's disk to
    // name: nothing shows where the device keeps it.
    assert_eq!(
        refusal.hint(Some(Path::new("/mnt/nails"))),
        [
            OWN_VOLUME,
            "If the device keeps its data on storage this computer does not use, read \
             \"Where setup happens\" in the operator guide on another device: opening it \
             here leaves traces such as ~/.lesshst."
        ]
    );
    assert!(refusal.overridden());
    assert_eq!(
        refusal.warning(),
        "--allow-decoy-storage: using /mnt although it is stored on a network block device, \
         which a program can serve from a file on this computer's own disk; everything \
         written there lands on that storage"
    );
    let ublk = Refusal::new(
        RefusalKind::DecoyStorage {
            verdict: Verdict::ServedDevice {
                kind: Served::Userspace,
            },
        },
        Path::new("/mnt"),
    );
    assert!(
        ublk.reason
            .starts_with("/mnt is not a volume of its own: it is stored on a userspace block"),
        "{}",
        ublk.reason
    );
}

#[test]
fn a_zfs_volume_cannot_be_told_apart_from_this_computers_storage() {
    let refusal = Refusal::new(
        RefusalKind::StorageUntraced {
            verdict: Verdict::UntracedDevice {
                kind: Untraced::ZfsVolume,
            },
        },
        Path::new("/mnt"),
    );
    assert_eq!(
        refusal.reason,
        "/mnt is stored on a ZFS volume, which shows no disk it stores its data on, so where \
         it lives cannot be told"
    );
    assert_eq!(refusal.hint(None), [OWN_VOLUME]);
    assert!(!refusal.overridden());
}

#[test]
fn the_text_names_no_tool_and_no_purpose() {
    // The root is the operator's own word: one that contains a blocked
    // word must not count against the text around it.
    let root = Path::new("/mnt/hidden-decoy");
    for refusal in every_refusal(root) {
        let text = std::iter::once(refusal.message())
            .chain(refusal.hint(Some(&root.join("nails"))))
            .collect::<Vec<_>>()
            .join("\n")
            .replace(&root.display().to_string(), "<root>")
            .to_lowercase();
        for word in [
            "hidden",
            "decoy",
            "deniab",
            "veracrypt",
            "tcrypt",
            "cryptsetup",
            // No device either: a mapping's name can name what opened it,
            // and a device's directory in sysfs names the device.
            "/dev/",
            "/sys/devices",
            "/sys/fs/btrfs/",
            "/sys/fs/ext4/",
            "dm-3",
            "dm-5",
            "loop1",
            "zram0",
        ] {
            assert!(!text.contains(word), "{word} in {text}");
        }
    }
}

#[test]
fn the_message_says_nothing_was_written() {
    let refusal = Refusal::new(
        RefusalKind::NotAMountPoint {
            mount_point: PathBuf::from("/"),
        },
        Path::new("/mnt"),
    );
    assert_eq!(
        refusal.message(),
        "/mnt is not a volume of its own: it is a folder on the filesystem mounted at /. \
         Nothing was written."
    );
}

#[test]
fn the_redirect_names_the_program_only_when_it_lies_under_the_root() {
    let refusal = Refusal::new(RefusalKind::SameDeviceAsRoot, Path::new("/mnt"));
    let inside = refusal.hint(Some(Path::new("/mnt/nails")));
    assert_eq!(
        inside[0],
        "This copy of the program (/mnt/nails) is itself on this computer's disk."
    );
    let outside = refusal.hint(Some(Path::new("/usr/bin/nails")));
    assert!(outside[0].starts_with("Setting up here"), "{outside:?}");
    assert_eq!(outside.len() + 1, inside.len());
    assert_eq!(refusal.hint(None), outside);
    // A root that shares only a prefix of the name does not hold it.
    assert_eq!(refusal.hint(Some(Path::new("/mnt2/nails"))), outside);
}

#[test]
fn the_override_covers_only_the_decoys_storage() {
    use crate::hidden_root::Allow;
    for refusal in every_refusal(Path::new("/mnt")) {
        let covered = matches!(refusal.kind, RefusalKind::DecoyStorage { .. });
        assert_eq!(
            Allow::DecoyStorage.covers(&refusal.kind),
            covered,
            "{refusal:?}"
        );
        assert!(!Allow::Nothing.covers(&refusal.kind), "{refusal:?}");
    }
}

#[test]
fn an_unlisted_sysfs_asks_for_the_host_not_only_for_sudo() {
    let hint = |unreadable: &[&str]| {
        Refusal::new(
            RefusalKind::StorageUnjudged {
                unreadable: unreadable.iter().map(PathBuf::from).collect(),
            },
            Path::new("/mnt"),
        )
        .hint(None)
    };
    assert_eq!(
        hint(&["/etc/crypttab"]),
        ["Run the command again with sudo."]
    );
    let sysfs = [
        "Run the command again as root, on the host rather than in a container, with /sys \
         mounted.",
    ];
    assert_eq!(hint(&["/sys/class/block"]), sysfs);
    assert_eq!(hint(&["/sys/devices/virtual/block/zd0/dev"]), sysfs);
    // A loop device's record needs root as well.
    assert_eq!(hint(&["/dev/loop0"]), ["Run the command again with sudo."]);
    assert_eq!(hint(&["/etc/crypttab", "/sys/class/block"]), sysfs);
    // Anyone can read the drivers' list where /proc is mounted.
    assert_eq!(
        hint(&["/proc/devices"]),
        ["Run the command where /proc is mounted and readable."]
    );
    // A loop device's file the kernel cannot show: running the command
    // as root does not bring it back, and how long a path it shows
    // depends on the computer's page size.
    assert_eq!(
        hint(&["/sys/devices/virtual/block/loop1/loop/backing_file"]),
        [
            "Set the loop device up again from a file with a shorter path, then run the \
             command again."
        ]
    );
}

#[test]
fn the_override_warning_names_the_storage() {
    let folder = Refusal::new(
        RefusalKind::NotAMountPoint {
            mount_point: PathBuf::from("/srv"),
        },
        Path::new("/srv/x"),
    );
    assert!(!folder.overridden());
    let subvolume = Refusal::new(
        RefusalKind::DecoyStorage {
            verdict: Verdict::OnDecoyFilesystem {
                how: Sharing::Subvolume,
                at: PathBuf::from("/pool"),
                in_fstab: true,
            },
        },
        Path::new("/mnt"),
    );
    assert!(subvolume.overridden());
    assert_eq!(
        subvolume.warning(),
        "--allow-decoy-storage: using /mnt although it is a subvolume of the btrfs filesystem \
         at /pool; everything written there lands on that storage"
    );
    // A container file only warns by itself: its warning is the reason.
    let container = Refusal::new(
        RefusalKind::DecoyStorage {
            verdict: Verdict::ContainerOnDecoy {
                file: PathBuf::from("/home/u/files.bin"),
                at: PathBuf::from("/home"),
            },
        },
        Path::new("/mnt"),
    );
    assert!(!container.overridden());
    assert!(
        container
            .warning()
            .starts_with("/mnt is an encrypted container file (/home/u/files.bin) on /home;"),
        "{}",
        container.warning()
    );
    let covered = Refusal::new(
        RefusalKind::Covered {
            below: "ext4".into(),
            above: "vfat".into(),
        },
        Path::new("/mnt"),
    );
    assert!(!covered.overridden());
}

#[test]
fn only_the_redirect_kinds_redirect() {
    for refusal in every_refusal(Path::new("/mnt")) {
        let hint = refusal.hint(None).join("\n");
        let redirects = hint.contains(GUIDE_SECTION);
        let expected = !matches!(
            refusal.kind,
            RefusalKind::Covered { .. }
                | RefusalKind::NotTheSessionVolume { .. }
                | RefusalKind::StorageUnjudged { .. }
                | RefusalKind::StorageUntraced { .. }
                | RefusalKind::NotConfigured
                | RefusalKind::LookupFailed { .. }
                | RefusalKind::NotLookedUp { .. }
                | RefusalKind::MountTableUnreadable { .. }
        );
        assert_eq!(redirects, expected, "{refusal:?}: {hint}");
    }
}

#[test]
fn a_folder_or_a_missing_root_first_asks_to_mount_the_volume() {
    for kind in [
        RefusalKind::Missing,
        RefusalKind::NotAMountPoint {
            mount_point: PathBuf::from("/"),
        },
    ] {
        let hint = Refusal::new(kind, Path::new("/mnt")).hint(None);
        assert_eq!(
            hint[0],
            "If the volume is already prepared, unlock and mount it at /mnt, then run the \
             command again."
        );
        assert!(hint[1].starts_with("Setting up here"), "{hint:?}");
    }
}

#[test]
fn a_filesystem_the_boot_mounts_first_asks_to_drop_its_fstab_line() {
    let refusal = Refusal::new(
        RefusalKind::DecoyStorage {
            verdict: Verdict::OnDecoyFilesystem {
                how: Sharing::Filesystem,
                at: PathBuf::from("/srv"),
                in_fstab: true,
            },
        },
        Path::new("/srv"),
    );
    let hint = refusal.hint(None);
    assert_eq!(
        hint[0],
        "If /srv is the volume you prepared, remove its line from /etc/fstab long before the \
         next use, and mount it by hand each time."
    );
    assert!(
        hint.iter().any(|line| line.contains(GUIDE_SECTION)),
        "{hint:?}"
    );
}
