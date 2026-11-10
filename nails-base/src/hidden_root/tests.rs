// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::MockFilesystem;
use std::path::{Path, PathBuf};

const ROOT_DEVICE: u64 = 1;
const VOLUME_DEVICE: u64 = 42;

/// The decoy's `/` and `/home`, and the hidden volume at `/mnt/data`, plus
/// `extra` mount lines.
fn decoy_table(extra: &str) -> String {
    format!(
        "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
         2 1 8:2 / /home rw - ext4 /dev/vda2 rw\n\
         10 1 253:0 / /mnt/data rw - ext4 /dev/mapper/data rw\n{extra}"
    )
}

/// The hidden session's view: `/` is the overlay whose upper lies on the
/// hidden volume, and `mnt_data` is the mount line at `/mnt/data`, if any.
fn session_table(mnt_data: &str) -> String {
    format!(
        "1 0 0:30 / / rw - overlay overlay rw,lowerdir=/run/overlay-runtime/lower,\
         upperdir=/mnt/data/root/upper,workdir=/mnt/data/root/work\n{mnt_data}"
    )
}

const HIDDEN_MOUNT: &str = "10 1 253:0 / /mnt/data rw - ext4 /dev/mapper/data rw\n";

/// A mock where `/mnt/data` exists, with `table` as its mount table.
fn fs_with(table: &str) -> MockFilesystem {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/mnt/data", true);
    fs.mock_set_mount_table(table);
    fs.mock_set_device_id(Path::new("/"), ROOT_DEVICE);
    fs.mock_set_device_id(Path::new("/mnt/data"), VOLUME_DEVICE);
    fs
}

/// Write a session plan to `/run`, recording `hidden_dev` when given.
fn write_plan(fs: &MockFilesystem, hidden_dev: Option<&str>) {
    let dev = hidden_dev
        .map(|dev| format!(",\"hidden_dev\":\"{dev}\""))
        .unwrap_or_default();
    let text = format!(
        "{{\"version\":{version},\"hidden_root\":\"/mnt/data\"{dev},\
         \"upper\":\"/mnt/data/root/upper\",\"work\":\"/mnt/data/root/work\",\
         \"decoy_root\":{{\"source\":\"/dev/vda1\",\"fstype\":\"ext4\"}},\
         \"decoy\":{{\"init\":\"/sbin/init\"}},\"hidden\":{{\"init\":\"/sbin/init\"}}}}",
        version = nails_teardown::whole_root::plan::PLAN_VERSION
    );
    let path = nails_teardown::whole_root::plan::default_plan_path();
    fs.mock_set_file_content(path.to_str().unwrap(), &text);
}

fn refusal(fs: &MockFilesystem, root: &str) -> Refusal {
    match HiddenRoot::assess(fs, Path::new(root)).unwrap() {
        Assessment::Refused(refusal) => refusal,
        other => panic!("{root} was accepted: {other:?}"),
    }
}

/// A mock where `/mnt/data` is a mounted volume of its own, in the default
/// rendered mount table.
fn attached_fs(root: &Path) -> MockFilesystem {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists(root.to_str().unwrap(), true);
    fs.mock_set_mounted(root, true);
    fs.mock_set_device_id(Path::new("/"), ROOT_DEVICE);
    fs.mock_set_device_id(root, VOLUME_DEVICE);
    fs
}

#[test]
fn the_state_gate_refuses_a_directory_on_the_root_filesystem() {
    let _gate = super::state_attach_probe::enforce();
    let fs = crate::MockFilesystem::new();
    fs.mock_set_path_exists("/", true);
    fs.mock_set_path_exists("/mnt/data", true);
    fs.mock_set_path_type("/mnt/data", crate::filesystem::PathKind::Dir);
    let root = Path::new("/mnt/data");
    assert!(super::ensure_state_dir_attached(&fs, root, root).is_err());
}

#[test]
fn the_state_gate_accepts_a_directory_inside_the_volume() {
    let _gate = super::state_attach_probe::enforce();
    let fs = fs_with(&decoy_table(""));
    let root = Path::new("/mnt/data");
    super::ensure_state_dir_attached(&fs, root, root).unwrap();
    super::ensure_state_dir_attached(&fs, root, &root.join("var/state")).unwrap();
}

#[test]
fn the_state_gate_refuses_a_directory_on_a_mount_inside_the_volume() {
    let _gate = super::state_attach_probe::enforce();
    let fs = fs_with(&decoy_table(
        "11 10 0:50 / /mnt/data/var rw - tmpfs tmpfs rw\n",
    ));
    let root = Path::new("/mnt/data");
    let error = super::ensure_state_dir_attached(&fs, root, &root.join("var/state"))
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("another filesystem (/mnt/data/var)"),
        "{error}"
    );
}

#[test]
fn the_state_gate_refuses_a_directory_outside_the_root() {
    let _gate = super::state_attach_probe::enforce();
    let fs = fs_with(&decoy_table(""));
    let error = super::ensure_state_dir_attached(&fs, Path::new("/mnt/data"), Path::new("/home"))
        .unwrap_err()
        .to_string();
    assert!(error.contains("is not inside the hidden root"), "{error}");
}

#[test]
fn the_state_gate_refuses_what_the_gate_refuses() {
    let _gate = super::state_attach_probe::enforce();
    let fs = fs_with(&decoy_table("11 10 0:50 / /mnt/data rw - tmpfs tmpfs rw\n"));
    let root = Path::new("/mnt/data");
    let error = super::ensure_state_dir_attached(&fs, root, root)
        .unwrap_err()
        .to_string();
    assert!(error.contains("two filesystems are mounted"), "{error}");
}

#[test]
fn a_volume_mounted_at_the_root_is_attached() {
    let fs = fs_with(&decoy_table(""));
    assert_eq!(
        HiddenRoot::assess(&fs, Path::new("/mnt/data")).unwrap(),
        Assessment::Attached
    );
}

#[test]
fn a_plain_directory_names_the_filesystem_it_is_on() {
    // A folder on a separate /home partition has a device of its own, which
    // the old device-only test took for a mounted volume.
    let fs = fs_with(&decoy_table(""));
    fs.mock_set_path_exists("/home/op/vault", true);
    let refused = refusal(&fs, "/home/op/vault");
    assert_eq!(
        refused.kind,
        RefusalKind::NotAMountPoint {
            mount_point: PathBuf::from("/home")
        }
    );
    assert!(
        refused.reason.contains(
            "is not a volume of its own: it is a folder on the filesystem mounted at /home"
        ),
        "{}",
        refused.reason
    );

    fs.mock_set_path_exists("/srv/vault", true);
    assert_eq!(
        refusal(&fs, "/srv/vault").kind,
        RefusalKind::NotAMountPoint {
            mount_point: PathBuf::from("/")
        }
    );
}

#[test]
fn a_root_covered_by_a_mount_on_its_parent_is_no_mount_point() {
    // The volume stays in the table, but a lookup of /mnt/data now ends in
    // the tmpfs mounted on /mnt.
    let fs = fs_with(&decoy_table("11 1 0:50 / /mnt rw - tmpfs tmpfs rw\n"));
    assert_eq!(
        refusal(&fs, "/mnt/data").kind,
        RefusalKind::NotAMountPoint {
            mount_point: PathBuf::from("/mnt")
        }
    );
}

#[test]
fn a_mount_on_the_roots_parent_is_a_cover() {
    use crate::filesystem::mountinfo::parse_mountinfo;
    let table = parse_mountinfo(&decoy_table("11 1 8:33 / /mnt rw - vfat /dev/sdc1 rw\n"));
    let root = Path::new("/mnt/data");
    for recorded in [Some("253:0"), None] {
        let cover = shadowing_mount(&table, root, recorded).expect("/mnt covers the volume");
        assert_eq!(cover.mount_id, 11);
    }
    // Another device recorded: the mount at /mnt/data is not the volume, so
    // the volume is gone rather than covered.
    assert_eq!(shadowing_mount(&table, root, Some("8:99")), None);
    // Nothing at /mnt/data at all: gone, not covered.
    let gone = parse_mountinfo("1 0 8:1 / / rw - ext4 /dev/vda1 rw\n");
    assert_eq!(shadowing_mount(&gone, root, Some("253:0")), None);
    // The volume reachable under a parent mount of its own: no cover.
    assert_eq!(
        shadowing_mount(&parse_mountinfo(&decoy_table("")), root, None),
        None
    );
}

#[test]
fn two_filesystems_at_the_root_are_refused_naming_both() {
    let fs = fs_with(&decoy_table(
        "11 10 8:16 / /mnt/data rw - vfat /dev/sdb1 rw\n",
    ));
    let refused = refusal(&fs, "/mnt/data");
    // Each filesystem is shown by its type, never by its source.
    assert_eq!(
        refused.kind,
        RefusalKind::Covered {
            below: "ext4".into(),
            above: "vfat".into(),
        }
    );
    assert!(
        refused.reason.contains(
            "two filesystems are mounted at /mnt/data: one of type ext4, then one of type vfat \
             over it"
        ),
        "{}",
        refused.reason
    );
}

#[test]
fn a_covered_root_names_no_device_of_either_mapping() {
    // The volume and the cover are both mappings whose names say what opened
    // them; the operator is shown neither those names nor /dev/dm-N.
    let fs = fs_with(
        "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
         10 1 253:0 / /mnt/data rw - ext4 /dev/mapper/veracrypt1 rw\n\
         11 10 253:1 / /mnt/data rw - ext4 /dev/mapper/hidden rw\n",
    );
    for (dev, name) in [("253:0", "dm-0"), ("253:1", "dm-1")] {
        let dir = format!("/sys/devices/virtual/block/{name}");
        fs.create_symlink(Path::new(&dir), Path::new(&format!("/sys/dev/block/{dev}")))
            .unwrap();
        fs.mock_add_file(&format!("{dir}/dev"), &format!("{dev}\n"));
    }
    let refused = refusal(&fs, "/mnt/data");
    assert_eq!(
        refused.kind,
        RefusalKind::Covered {
            below: "ext4".into(),
            above: "ext4".into(),
        }
    );
    let text = refused.message().to_lowercase();
    assert!(
        !text.contains("veracrypt") && !text.contains("hidden") && !text.contains("/dev/"),
        "{text}"
    );
}

#[test]
fn a_bind_of_the_same_volume_stacked_on_the_root_is_one_filesystem() {
    let fs = fs_with(&decoy_table(
        "11 10 253:0 / /mnt/data ro - ext4 /dev/mapper/data rw\n",
    ));
    assert!(
        HiddenRoot::assess(&fs, Path::new("/mnt/data"))
            .unwrap()
            .is_attached()
    );
}

/// What [`HiddenRoot::mounted_elsewhere`] finds for the volume at
/// `/mnt/data`, in `table`.
fn mounted_elsewhere(table: &str) -> Option<MountedElsewhere> {
    HiddenRoot::mounted_elsewhere(&fs_with(table), Path::new("/mnt/data")).unwrap()
}

/// Where else [`HiddenRoot::mounted_elsewhere`] finds the volume at
/// `/mnt/data` mounted, in `table`.
fn elsewhere(table: &str) -> Vec<PathBuf> {
    mounted_elsewhere(table)
        .map(|found| {
            assert!(!found.mounts.is_empty(), "{found:?}");
            found.mounts.into_iter().map(|m| m.mount_point).collect()
        })
        .unwrap_or_default()
}

/// The mounts that hide the volume's other mounts in `table`, by the other
/// mount's mount point: `None` for one a lookup of its path reaches.
fn hidden_under(table: &str) -> Vec<(PathBuf, Option<PathBuf>)> {
    mounted_elsewhere(table)
        .map(|found| {
            found
                .mounts
                .into_iter()
                .map(|m| (m.mount_point, m.hidden_under))
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn the_same_device_at_another_place_is_a_second_mount() {
    // A desktop mounted the unlocked volume by itself.
    let table = decoy_table("20 1 253:0 / /media/u/X rw,nosuid,nodev - ext4 /dev/mapper/data rw\n");
    assert_eq!(elsewhere(&table), vec![PathBuf::from("/media/u/X")]);
    let mounts = crate::filesystem::mountinfo::parse_mountinfo(&table);
    let visible = top_mount_at(&mounts, Path::new("/mnt/data")).unwrap();
    let second: Vec<_> = second_mounts(&mounts, visible)
        .into_iter()
        .map(|m| m.mount_id)
        .collect();
    assert_eq!(second, vec![20]);
}

#[test]
fn a_bind_of_the_volume_at_the_root_alone_is_no_second_mount() {
    assert!(elsewhere(&decoy_table("")).is_empty());
    assert!(
        elsewhere(&decoy_table(
            "11 10 253:0 / /mnt/data ro - ext4 /dev/mapper/data rw\n"
        ))
        .is_empty()
    );
}

#[test]
fn another_device_elsewhere_is_no_second_mount() {
    assert!(
        elsewhere(&decoy_table(
            "20 1 8:16 / /media/u/STICK rw - vfat /dev/sdb1 rw\n\
             21 1 253:1 / /run/media/u/other rw - ext4 /dev/mapper/other rw\n"
        ))
        .is_empty()
    );
}

#[test]
fn a_btrfs_subvolume_of_the_volume_elsewhere_is_a_second_mount() {
    // A btrfs filesystem shows one device for every subvolume mounted from
    // it, though stat shows each its own.
    let table = "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
                 10 1 0:45 /data /mnt/data rw - btrfs /dev/mapper/data rw,subvol=/data\n\
                 20 1 0:45 / /run/media/u/X rw - btrfs /dev/mapper/data rw,subvol=/\n\
                 21 1 0:46 / /run/media/u/Y rw - btrfs /dev/sdc1 rw,subvol=/\n\
                 22 1 0:45 /other /run/media/u/Z rw - btrfs /dev/mapper/data rw,subvol=/other\n";
    // On a volume of its own, a subvolume that shows none of the root's
    // folder counts too: the drive is mounted where the decoy's desktop
    // reaches it.
    assert_eq!(
        elsewhere(table),
        vec![
            PathBuf::from("/run/media/u/X"),
            PathBuf::from("/run/media/u/Z")
        ]
    );
}

#[test]
fn a_folder_of_the_volume_bound_at_the_root_while_the_volume_is_mounted_elsewhere() {
    // The volume at /mnt/backing, a folder of it bound at the root: the
    // filesystem is mounted twice, whichever of the two is the root.
    let table = "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
                 10 1 8:32 / /mnt/backing rw - ext4 /dev/sdc rw\n\
                 11 1 8:32 /vol /mnt/data rw - ext4 /dev/sdc rw\n";
    assert_eq!(elsewhere(table), vec![PathBuf::from("/mnt/backing")]);
    // Once the volume's own mount is gone, the bind at the root alone stays.
    let table = "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
                 11 1 8:32 /vol /mnt/data rw - ext4 /dev/sdc rw\n";
    assert!(elsewhere(table).is_empty());
}

#[test]
fn a_hidden_second_mount_and_one_inside_the_root_count_too() {
    // A later mount over /media hides the desktop's mount from lookups, but
    // it is still mounted; a bind of a folder of the volume below the root
    // is a mount of it too.
    let table = decoy_table(
        "20 1 253:0 / /media/u/X rw - ext4 /dev/mapper/data rw\n\
         21 1 0:50 / /media rw - tmpfs tmpfs rw\n\
         22 10 253:0 /a /mnt/data/b rw - ext4 /dev/mapper/data rw\n",
    );
    assert_eq!(
        elsewhere(&table),
        vec![PathBuf::from("/media/u/X"), PathBuf::from("/mnt/data/b")]
    );
    // umount given /media/u/X would end in the tmpfs; the bind below the root
    // is reached by its path.
    assert_eq!(
        hidden_under(&table),
        vec![
            (PathBuf::from("/media/u/X"), Some(PathBuf::from("/media"))),
            (PathBuf::from("/mnt/data/b"), None),
        ]
    );
}

#[test]
fn what_hides_a_second_mount_is_the_mount_a_lookup_of_its_path_ends_in() {
    // Another filesystem stacked on it at its own mount point.
    let stacked = decoy_table(
        "20 1 253:0 / /media/u/X rw - ext4 /dev/mapper/data rw\n\
         21 20 8:16 / /media/u/X rw - vfat /dev/sdb1 rw\n",
    );
    assert_eq!(
        hidden_under(&stacked),
        vec![(
            PathBuf::from("/media/u/X"),
            Some(PathBuf::from("/media/u/X"))
        )]
    );
    // One the root's own mount hides: mounted below /mnt/data before the
    // volume was mounted there.
    let under_the_root = "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
                          9 1 253:0 /a /mnt/data/b rw - ext4 /dev/mapper/data rw\n\
                          10 1 253:0 / /mnt/data rw - ext4 /dev/mapper/data rw\n";
    assert_eq!(
        hidden_under(under_the_root),
        vec![(
            PathBuf::from("/mnt/data/b"),
            Some(PathBuf::from("/mnt/data"))
        )]
    );
    // A second mount of the volume stacked under the root's own mount point
    // is the root, hidden or not.
    let below_the_root = "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
                          9 1 253:0 / /mnt/data rw - ext4 /dev/mapper/data rw\n\
                          10 9 253:0 / /mnt/data rw - ext4 /dev/mapper/data rw\n";
    assert!(mounted_elsewhere(below_the_root).is_none());
}

#[test]
fn what_the_mount_at_the_root_shows_of_the_volume() {
    let shown = |table: &str| {
        let found = mounted_elsewhere(table).expect("mounted elsewhere");
        (found.root_shows, found.root_folder)
    };
    // All of it.
    assert_eq!(
        shown(&decoy_table(
            "20 1 253:0 / /media/u/X rw - ext4 /dev/mapper/data rw\n"
        )),
        (separation::Sharing::Filesystem, PathBuf::from("/"))
    );
    // A folder of it, bound at the root.
    assert_eq!(
        shown(
            "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
             29 1 253:0 / /mnt rw - ext4 /dev/mapper/data rw\n\
             30 29 253:0 /vol /mnt/data rw - ext4 /dev/mapper/data rw\n"
        ),
        (separation::Sharing::Bind, PathBuf::from("/vol"))
    );
    // A btrfs subvolume of it.
    assert_eq!(
        shown(
            "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
             29 1 0:45 / /mnt rw - btrfs /dev/mapper/data rw,subvolid=5,subvol=/\n\
             30 29 0:45 /data /mnt/data rw - btrfs /dev/mapper/data rw,subvolid=256,subvol=/data\n"
        ),
        (separation::Sharing::Subvolume, PathBuf::from("/data"))
    );
}

#[test]
fn the_tree_of_a_mounted_next_root_is_no_second_mount() {
    // An entry binds the volume at its own path inside the next root.
    let entering = decoy_table(
        "30 1 0:60 / /run/nextroot rw - overlay overlay rw,lowerdir=/run/overlay-runtime/lower,\
         upperdir=/mnt/data/root/upper,workdir=/mnt/data/root/work\n\
         31 30 253:0 / /run/nextroot/mnt/data rw - ext4 /dev/mapper/data rw\n\
         32 31 253:0 / /run/nextroot/mnt/data rw - ext4 /dev/mapper/data rw\n",
    );
    assert!(elsewhere(&entering).is_empty());
    // Only that tree is left out: a desktop's mount of the volume while a
    // next root is mounted is still a second mount.
    let with_a_desktop_mount =
        format!("{entering}40 1 253:0 / /media/u/X rw,nosuid,nodev - ext4 /dev/mapper/data rw\n");
    assert_eq!(
        elsewhere(&with_a_desktop_mount),
        vec![PathBuf::from("/media/u/X")]
    );
    // Without a next root mounted there, a mount below it is a mount like
    // any other.
    let stray = decoy_table("31 1 253:0 / /run/nextroot/mnt/data rw - ext4 /dev/mapper/data rw\n");
    assert_eq!(
        elsewhere(&stray),
        vec![PathBuf::from("/run/nextroot/mnt/data")]
    );
}

#[test]
fn the_sessions_own_mounts_are_no_second_mount() {
    // In the hidden session: the volume bound at its own path, bound again
    // over a decoy filesystem mounted at its parent, the decoy filesystems
    // the session carries on it, and the decoy root on the way back.
    let session = session_table(&format!(
        "{HIDDEN_MOUNT}\
         11 1 0:31 / /mnt rw - overlay overlay rw,lowerdir=/run/overlay-runtime/lower-1,\
         upperdir=/mnt/data/root/mounts/mnt/upper,workdir=/mnt/data/root/mounts/mnt/work\n\
         12 11 253:0 / /mnt/data rw - ext4 /dev/mapper/data rw\n\
         13 12 8:3 / /mnt/data/root/decoy/boot ro - ext4 /dev/vda3 rw\n\
         14 1 0:32 / /run rw - tmpfs tmpfs rw\n\
         15 14 8:1 / /run/nextroot rw - ext4 /dev/vda1 rw\n"
    ));
    let fs = fs_with(&session);
    write_plan(&fs, Some("253:0"));
    assert!(
        HiddenRoot::mounted_elsewhere(&fs, Path::new("/mnt/data"))
            .unwrap()
            .is_none()
    );
    // Not one of them is a second mount by the rule itself either.
    let mounts = crate::filesystem::mountinfo::parse_mountinfo(&session);
    let visible = top_mount_at(&mounts, Path::new("/mnt/data")).unwrap();
    assert_eq!(visible.mount_id, 12);
    assert!(second_mounts(&mounts, visible).is_empty());
    // Nothing is judged there: a mount the session makes lies in its own
    // tree, where the decoy's desktop does not run.
    let fs = fs_with(&session_table(&format!(
        "{HIDDEN_MOUNT}20 1 253:0 / /run/media/u/X rw - ext4 /dev/mapper/data rw\n"
    )));
    write_plan(&fs, Some("253:0"));
    assert!(
        HiddenRoot::mounted_elsewhere(&fs, Path::new("/mnt/data"))
            .unwrap()
            .is_none()
    );
    // Nor for a root the operator accepted on a filesystem the decoy uses.
    assert!(
        HiddenRoot::mounted_elsewhere_on_a_decoy_filesystem(&fs, Path::new("/mnt/data"))
            .unwrap()
            .is_none()
    );
}

#[test]
fn nothing_mounted_at_the_root_is_mounted_elsewhere_and_a_table_error_is_an_error() {
    // No mount at the root, which the gate refuses: nothing to compare.
    let table = "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
                 20 1 253:0 / /media/u/X rw - ext4 /dev/mapper/data rw\n";
    assert!(elsewhere(table).is_empty());
    let fs = fs_with(&decoy_table(""));
    fs.mock_set_mount_table_error("permission denied");
    assert!(HiddenRoot::mounted_elsewhere(&fs, Path::new("/mnt/data")).is_err());
    assert!(
        HiddenRoot::mounted_elsewhere_on_a_decoy_filesystem(&fs, Path::new("/mnt/data")).is_err()
    );
}

// ------------------------------------------------------------------------
// A second mount of a root the operator accepted on a decoy filesystem
// ------------------------------------------------------------------------

/// A mock where `/mnt/data` exists, with `table` as its mount table and
/// `fstab` as the decoy's `/etc/fstab`.
fn decoy_fs(table: &str, fstab: &str) -> MockFilesystem {
    let fs = fs_with(table);
    fs.mock_set_file_content("/etc/fstab", fstab);
    fs
}

/// Where [`HiddenRoot::mounted_elsewhere_on_a_decoy_filesystem`] finds the
/// filesystem at `/mnt/data` mounted besides, on `fs`.
fn elsewhere_on_the_decoy(fs: &MockFilesystem) -> Vec<PathBuf> {
    HiddenRoot::mounted_elsewhere_on_a_decoy_filesystem(fs, Path::new("/mnt/data"))
        .unwrap()
        .map(|found| {
            assert!(!found.mounts.is_empty(), "{found:?}");
            found.mounts.into_iter().map(|m| m.mount_point).collect()
        })
        .unwrap_or_default()
}

/// The decoy's `/` on `/dev/vda1`, its folder `/srv/x` bound at the root, and
/// NixOS's read-only bind of `/nix/store`, plus `extra` mount lines.
fn bind_of_a_folder_of_root(extra: &str) -> String {
    format!(
        "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
         5 1 8:1 /nix/store /nix/store ro - ext4 /dev/vda1 rw\n\
         30 1 8:1 /srv/x /mnt/data rw - ext4 /dev/vda1 rw\n{extra}"
    )
}

#[test]
fn on_a_decoy_filesystem_only_mounts_that_show_the_roots_folder_and_are_not_the_decoys_count() {
    // For a volume of its own, the decoy's / and the bind of /nix/store
    // would be second mounts; on the decoy's own filesystem, / is where the
    // decoy mounts it, and /nix/store shows none of /srv/x.
    let table = bind_of_a_folder_of_root("");
    assert_eq!(
        elsewhere(&table),
        vec![PathBuf::from("/"), PathBuf::from("/nix/store")]
    );
    let fs = decoy_fs(&table, "/dev/vda1 / ext4 defaults 0 1\n");
    assert!(elsewhere_on_the_decoy(&fs).is_empty());
    // A bind of a folder above the root's folder, or of one inside it, shows
    // the root's files; a bind of a folder beside it does not.
    let fs = decoy_fs(
        &bind_of_a_folder_of_root(
            "40 1 8:1 /srv /media/u/srv rw - ext4 /dev/vda1 rw\n\
             41 1 8:1 /srv/x/sub /run/media/u/sub rw - ext4 /dev/vda1 rw\n\
             42 1 8:1 /srv/xy /mnt/xy rw - ext4 /dev/vda1 rw\n\
             43 1 8:1 /srv/y /mnt/y rw - ext4 /dev/vda1 rw\n",
        ),
        "/dev/vda1 / ext4 defaults 0 1\n",
    );
    assert_eq!(
        elsewhere_on_the_decoy(&fs),
        vec![
            PathBuf::from("/media/u/srv"),
            PathBuf::from("/run/media/u/sub")
        ]
    );
    // / is the decoy's without an fstab line too.
    let fs = decoy_fs(&table, "");
    assert!(elsewhere_on_the_decoy(&fs).is_empty());
}

#[test]
fn on_a_decoy_filesystem_a_separate_drive_also_mounted_at_a_system_folder_counts() {
    // The gate places a drive mounted at /srv too on the decoy's storage;
    // with no fstab line for /srv, that mount is no mount of the decoy's.
    let table = "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
                 30 1 8:17 / /mnt/data rw - ext4 /dev/sdb1 rw\n\
                 40 1 8:17 / /srv rw - ext4 /dev/sdb1 rw\n";
    let fs = decoy_fs(table, "/dev/vda1 / ext4 defaults 0 1\n");
    assert_eq!(elsewhere_on_the_decoy(&fs), vec![PathBuf::from("/srv")]);
    // A line that mounts that drive at /srv makes it the decoy's own mount.
    let fs = decoy_fs(
        table,
        "/dev/vda1 / ext4 defaults 0 1\n/dev/sdb1 /srv ext4 defaults 0 2\n",
    );
    assert!(elsewhere_on_the_decoy(&fs).is_empty());
    // So does a line that names it by a link udev made for it, and one that
    // systemd mounts after the network.
    let fs = decoy_fs(table, "UUID=b1 /srv ext4 defaults 0 2\n");
    fs.create_symlink(Path::new("/dev/sdb1"), Path::new("/dev/disk/by-uuid/b1"))
        .unwrap();
    assert!(elsewhere_on_the_decoy(&fs).is_empty());
    let fs = decoy_fs(table, "/dev/sdb1 /srv ext4 _netdev 0 0\n");
    assert!(elsewhere_on_the_decoy(&fs).is_empty());
    // A line for another device at /srv, one whose spec leads to no device,
    // one of a kind the judge claims nothing by (swap, RAM, kernel, a host
    // share, a network or an overlay), or one that is not plain, does not,
    // though its spec names the drive.
    for fstab in [
        "/dev/sdc1 /srv ext4 defaults 0 2\n",
        "UUID=c1 /srv ext4 defaults 0 2\n",
        "UUID=gone /srv ext4 defaults 0 2\n",
        "/dev/sdb1 /srv swap defaults 0 0\n",
        "/dev/sdb1 /srv tmpfs defaults 0 0\n",
        "/dev/sdb1 /srv virtiofs defaults 0 0\n",
        "/dev/sdb1 /srv overlay defaults 0 0\n",
        "/dev/sdb1 /srv ext\\064 defaults 0 2\n",
        "/dev/sdb\\061 /srv ext4 defaults 0 2\n",
    ] {
        let fs = decoy_fs(table, fstab);
        fs.create_symlink(Path::new("/dev/sdc1"), Path::new("/dev/disk/by-uuid/c1"))
            .unwrap();
        assert_eq!(
            elsewhere_on_the_decoy(&fs),
            vec![PathBuf::from("/srv")],
            "{fstab}"
        );
    }
    // The drive mounted by hand over the decoy's own /srv is not the mount
    // its line makes, though the one below it is.
    let stacked = "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
                   20 1 8:33 / /srv rw - ext4 /dev/sdc1 rw\n\
                   30 1 8:17 / /mnt/data rw - ext4 /dev/sdb1 rw\n\
                   40 20 8:17 / /srv rw - ext4 /dev/sdb1 rw\n";
    let fs = decoy_fs(stacked, "/dev/sdc1 /srv ext4 defaults 0 2\n");
    assert_eq!(elsewhere_on_the_decoy(&fs), vec![PathBuf::from("/srv")]);
}

#[test]
fn on_a_decoy_filesystem_a_btrfs_subvolume_counts_only_the_mounts_that_show_its_folder() {
    // A subvolume of the decoy's btrfs beside its /home subvolume: every
    // subvolume mounted from it shows the same device in the table.
    let table = |extra: &str| {
        format!(
            "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
             2 1 0:40 /home /home rw - btrfs /dev/vda2 rw,subvol=/home\n\
             30 1 0:40 /vault /mnt/data rw - btrfs /dev/vda2 rw,subvol=/vault\n{extra}"
        )
    };
    let home = "/dev/vda2 /home btrfs subvol=/home 0 0\n";
    let fs = decoy_fs(&table(""), home);
    assert!(elsewhere_on_the_decoy(&fs).is_empty());
    // Its top, mounted by hand, shows every subvolume; one the fstab mounts
    // is the decoy's.
    let top = "50 1 0:40 / /mnt/pool rw - btrfs /dev/vda2 rw,subvolid=5,subvol=/\n";
    let fs = decoy_fs(&table(top), home);
    assert_eq!(
        elsewhere_on_the_decoy(&fs),
        vec![PathBuf::from("/mnt/pool")]
    );
    let fs = decoy_fs(
        &table(top),
        &format!("{home}/dev/vda2 /mnt/pool btrfs subvolid=5 0 0\n"),
    );
    assert!(elsewhere_on_the_decoy(&fs).is_empty());

    // A subvolume nested in /home is reached through the decoy's /home: the
    // fstab line makes that mount the decoy's, and without one (a partition
    // systemd-gpt-auto-generator mounts at /home, say) it counts.
    let nested = "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
                  2 1 0:40 /home /home rw - btrfs /dev/vda2 rw,subvol=/home\n\
                  30 1 0:40 /home/u/vault /mnt/data rw - btrfs /dev/vda2 \
                  rw,subvol=/home/u/vault\n";
    let fs = decoy_fs(nested, home);
    assert!(elsewhere_on_the_decoy(&fs).is_empty());
    let fs = decoy_fs(nested, "");
    assert_eq!(elsewhere_on_the_decoy(&fs), vec![PathBuf::from("/home")]);

    // A line that names another device of the same btrfs filesystem mounts
    // it too: the link for the filesystem's UUID leads to one of them.
    let fs = decoy_fs(nested, "UUID=pool /home btrfs subvol=/home 0 0\n");
    fs.create_symlink(Path::new("/dev/vdb2"), Path::new("/dev/disk/by-uuid/pool"))
        .unwrap();
    fs.mock_set_file_content("/sys/class/block/vdb2/dev", "8:18\n");
    assert_eq!(elsewhere_on_the_decoy(&fs), vec![PathBuf::from("/home")]);
    fs.mock_set_directory_contents(
        Path::new("/sys/fs/btrfs"),
        vec![PathBuf::from("/sys/fs/btrfs/f1")],
    );
    fs.mock_set_directory_contents(
        Path::new("/sys/fs/btrfs/f1/devices"),
        vec![
            PathBuf::from("/sys/fs/btrfs/f1/devices/vda2"),
            PathBuf::from("/sys/fs/btrfs/f1/devices/vdb2"),
        ],
    );
    assert!(elsewhere_on_the_decoy(&fs).is_empty());
}

#[test]
fn on_a_decoy_filesystem_a_bind_line_of_the_fstab_makes_its_mount() {
    // /persist is the decoy's, and its fstab binds /persist/home at /home;
    // the root is a bind of a folder below that.
    let table = "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
                 2 1 8:17 / /persist rw - ext4 /dev/vdb1 rw\n\
                 3 1 8:17 /home /home rw - ext4 /dev/vdb1 rw\n\
                 30 1 8:17 /home/u/vault /mnt/data rw - ext4 /dev/vdb1 rw\n";
    let persist = "/dev/vdb1 /persist ext4 defaults 0 2\n";
    let fs = decoy_fs(
        table,
        &format!("{persist}/persist/home /home none bind 0 0\n"),
    );
    assert!(elsewhere_on_the_decoy(&fs).is_empty());
    // So does a line that binds by an option with a value, whatever its type,
    // as libmount binds for it.
    for line in [
        "/persist/home /home tmpfs bind=x 0 0\n",
        "/persist/home /home none rbind= 0 0\n",
    ] {
        let fs = decoy_fs(table, &format!("{persist}{line}"));
        assert!(elsewhere_on_the_decoy(&fs).is_empty(), "{line}");
    }
    // A bind line whose source holds a link makes none, wherever the link
    // leads: no link is followed, so what the line binds cannot be told.
    let through_a_link = format!("{persist}/persist/link /home none bind 0 0\n");
    for target in ["home", "/persist/gone"] {
        let fs = decoy_fs(table, &through_a_link);
        fs.create_symlink(Path::new(target), Path::new("/persist/link"))
            .unwrap();
        fs.mock_set_mount_root_error("/persist/gone", std::io::ErrorKind::NotFound);
        assert_eq!(
            elsewhere_on_the_decoy(&fs),
            vec![PathBuf::from("/home")],
            "{target}"
        );
    }
    // Without the bind line /home is no mount of the decoy's; a bind line
    // whose source lies on another filesystem does not make it either.
    for fstab in [
        persist.to_string(),
        format!("{persist}/srv/home /home none bind 0 0\n"),
    ] {
        let fs = decoy_fs(table, &fstab);
        assert_eq!(
            elsewhere_on_the_decoy(&fs),
            vec![PathBuf::from("/home")],
            "{fstab}"
        );
    }
    // A chain of bind lines: the decoy binds a folder of its /home bind at
    // /srv/shared too, and a root below that sees all three mounts as the
    // decoy's own.
    let chain = "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
                 2 1 8:17 / /persist rw - ext4 /dev/vdb1 rw\n\
                 3 1 8:17 /home /home rw - ext4 /dev/vdb1 rw\n\
                 4 1 8:17 /home/shared /srv/shared rw - ext4 /dev/vdb1 rw\n\
                 30 1 8:17 /home/shared/vault /mnt/data rw - ext4 /dev/vdb1 rw\n";
    let lines = format!(
        "{persist}/persist/home /home none bind 0 0\n/home/shared /srv/shared none bind 0 0\n"
    );
    assert!(elsewhere_on_the_decoy(&decoy_fs(chain, &lines)).is_empty());
    // Without the line for /home, /home is bound by hand, and so is no mount
    // a line makes, and neither is the bind of a folder of it.
    let fs = decoy_fs(
        chain,
        &format!("{persist}/home/shared /srv/shared none bind 0 0\n"),
    );
    assert_eq!(
        elsewhere_on_the_decoy(&fs),
        vec![PathBuf::from("/home"), PathBuf::from("/srv/shared")]
    );
    // Two bind lines that bind each other's mount point lead to no mount of
    // the decoy's own, however often they are followed.
    let cycle = "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
                 2 1 8:1 /srv /a rw - ext4 /dev/vda1 rw\n\
                 3 1 8:1 /srv /b rw - ext4 /dev/vda1 rw\n\
                 30 1 8:1 /srv/x /mnt/data rw - ext4 /dev/vda1 rw\n";
    let fs = decoy_fs(cycle, "/b /a none bind 0 0\n/a /b none bind 0 0\n");
    assert_eq!(
        elsewhere_on_the_decoy(&fs),
        vec![PathBuf::from("/a"), PathBuf::from("/b")]
    );
}

/// [`elsewhere_on_the_decoy`] for the root at `root`.
fn elsewhere_on_the_decoy_at(fs: &MockFilesystem, root: &str) -> Vec<PathBuf> {
    HiddenRoot::mounted_elsewhere_on_a_decoy_filesystem(fs, Path::new(root))
        .unwrap()
        .map(|found| found.mounts.into_iter().map(|m| m.mount_point).collect())
        .unwrap_or_default()
}

#[test]
fn on_a_decoy_filesystem_a_copy_that_mount_propagation_made_at_a_bind_lines_mount_point_counts() {
    // The fstab binds /persist/home at /home. The hidden drive mounted at
    // /persist/home, the root, is copied to /home by the shared propagation
    // systemd sets up: the decoy's desktop reaches it there, and the line
    // made the bind of /persist/home that lies below the copy, not the copy.
    let table = "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
                 2 1 8:2 / /persist rw - ext4 /dev/vda2 rw\n\
                 20 1 8:2 /home /home rw - ext4 /dev/vda2 rw\n\
                 30 2 253:0 / /persist/home rw - ext4 /dev/mapper/data rw\n\
                 31 20 253:0 / /home rw - ext4 /dev/mapper/data rw\n";
    let fs = decoy_fs(
        table,
        "/dev/vda1 / ext4 defaults 0 1\n/dev/vda2 /persist ext4 defaults 0 2\n\
         /persist/home /home none bind 0 0\n",
    );
    assert_eq!(
        elsewhere_on_the_decoy_at(&fs, "/persist/home"),
        vec![PathBuf::from("/home")]
    );
    // The same with a bind line to a folder outside the system folders.
    let table = "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
                 20 1 8:1 /srv/share /media/share rw - ext4 /dev/vda1 rw\n\
                 30 1 253:0 / /srv/share rw - ext4 /dev/mapper/data rw\n\
                 31 20 253:0 / /media/share rw - ext4 /dev/mapper/data rw\n";
    let fs = decoy_fs(
        table,
        "/dev/vda1 / ext4 defaults 0 1\n/srv/share /media/share none bind 0 0\n",
    );
    assert_eq!(
        elsewhere_on_the_decoy_at(&fs, "/srv/share"),
        vec![PathBuf::from("/media/share")]
    );
    // A bind line whose source lies in the root binds the hidden drive.
    let table = "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
                 30 1 253:0 / /mnt/data rw - ext4 /dev/mapper/data rw\n\
                 40 1 253:0 /srv /srv rw - ext4 /dev/mapper/data rw\n";
    let fs = decoy_fs(
        table,
        "/dev/vda1 / ext4 defaults 0 1\n/mnt/data/srv /srv none bind,nofail 0 0\n",
    );
    assert_eq!(elsewhere_on_the_decoy(&fs), vec![PathBuf::from("/srv")]);
}

#[test]
fn on_a_decoy_filesystem_a_folder_bound_by_hand_where_a_line_mounts_that_filesystem_counts() {
    // The root's folder /srv/x of / bound by hand over /media/a, where the
    // fstab binds /srv/a: the line makes the bind below it, not this one.
    let fs = decoy_fs(
        "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
         20 1 8:1 /srv/a /media/a rw - ext4 /dev/vda1 rw\n\
         30 1 8:1 /srv/x /mnt/data rw - ext4 /dev/vda1 rw\n\
         40 20 8:1 /srv/x /media/a rw - ext4 /dev/vda1 rw\n",
        "/dev/vda1 / ext4 defaults 0 1\n/srv/a /media/a none bind 0 0\n",
    );
    assert_eq!(elsewhere_on_the_decoy(&fs), vec![PathBuf::from("/media/a")]);
    // The root's folder of the /home partition bound by hand over /home,
    // which a line mounts from that partition: the line mounts its top.
    let home = "/dev/vda2 /home ext4 defaults 0 2\n";
    let table = |extra: &str| {
        format!(
            "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
             2 1 8:2 / /home rw - ext4 /dev/vda2 rw\n\
             30 1 8:2 /u/vault /mnt/data rw - ext4 /dev/vda2 rw\n{extra}"
        )
    };
    assert!(elsewhere_on_the_decoy(&decoy_fs(&table(""), home)).is_empty());
    let over = table("40 2 8:2 /u/vault /home rw - ext4 /dev/vda2 rw\n");
    assert_eq!(
        elsewhere_on_the_decoy(&decoy_fs(&over, home)),
        vec![PathBuf::from("/home")]
    );
    // A btrfs subvolume mounted by hand where a line mounts another one of
    // the same filesystem: the line's subvol= names the one it mounts.
    let pool = |at_home: &str| {
        format!(
            "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
             2 1 0:40 /{at_home} /home rw - btrfs /dev/vda2 rw,subvol=/{at_home}\n\
             30 1 0:40 /vault /mnt/data rw - btrfs /dev/vda2 rw,subvol=/vault\n"
        )
    };
    let subvol_home = "/dev/vda2 /home btrfs subvol=home 0 0\n";
    assert!(elsewhere_on_the_decoy(&decoy_fs(&pool("home"), subvol_home)).is_empty());
    assert_eq!(
        elsewhere_on_the_decoy(&decoy_fs(&pool("vault"), subvol_home)),
        vec![PathBuf::from("/home")]
    );
    // A line with neither option mounts the filesystem's top.
    assert_eq!(
        elsewhere_on_the_decoy(&decoy_fs(
            &pool("vault"),
            "/dev/vda2 /home btrfs defaults 0 0\n"
        )),
        vec![PathBuf::from("/home")]
    );
}

#[test]
fn on_a_decoy_filesystem_a_line_that_names_a_subvolume_by_its_id_makes_only_that_subvolume() {
    // The decoy's fstab mounts its /home subvolume, id 257, by subvolid=
    // alone, and the root is a subvolume nested in it: the mount table shows
    // each subvolume's id in its options.
    let nested = |home: &str| {
        format!(
            "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
             2 1 0:40 /home /home rw - btrfs /dev/vda2 rw,{home}\n\
             30 1 0:40 /home/u/vault /mnt/data rw - btrfs /dev/vda2 \
             rw,subvolid=300,subvol=/home/u/vault\n"
        )
    };
    let shown = "subvolid=257,subvol=/home";
    let line = |options: &str| format!("/dev/vda2 /home btrfs {options} 0 0\n");
    for options in ["subvolid=257", "subvol=/home,subvolid=257"] {
        let fs = decoy_fs(&nested(shown), &line(options));
        assert!(elsewhere_on_the_decoy(&fs).is_empty(), "{options}");
    }
    // Another id, one btrfs might read in another way or that is no number,
    // a line whose two names do not both name that subvolume, and one that
    // gives an id twice, of which btrfs takes the last, make no mount of the
    // decoy's.
    for options in [
        "subvolid=258",
        "subvolid=0257",
        "subvolid=0x101",
        "subvolid=home",
        "subvolid=",
        "subvol=/home,subvolid=258",
        "subvol=/srv,subvolid=257",
        "subvolid=257,subvolid=300",
    ] {
        let fs = decoy_fs(&nested(shown), &line(options));
        assert_eq!(
            elsewhere_on_the_decoy(&fs),
            vec![PathBuf::from("/home")],
            "{options}"
        );
    }
    // Neither does the line when the mount table shows no id for the mount.
    let fs = decoy_fs(&nested("subvol=/home"), &line("subvolid=257"));
    assert_eq!(elsewhere_on_the_decoy(&fs), vec![PathBuf::from("/home")]);
    // A folder of subvolume 257 bound by hand over /home shows its id too,
    // but no subvolume: the line does not make that mount.
    let bound = format!(
        "{}40 2 0:40 /home/u /home rw - btrfs /dev/vda2 rw,{shown}\n",
        nested(shown)
    );
    assert_eq!(
        elsewhere_on_the_decoy(&decoy_fs(&bound, &line("subvolid=257"))),
        vec![PathBuf::from("/home")]
    );
    // The root's own subvolume, id 300, mounted by hand over the decoy's
    // /home: the line mounts subvolume 257, not this one.
    let over = "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
                2 1 0:40 /home /home rw - btrfs /dev/vda2 rw,subvolid=257,subvol=/home\n\
                30 1 0:40 /vault /mnt/data rw - btrfs /dev/vda2 rw,subvolid=300,subvol=/vault\n\
                40 2 0:40 /vault /home rw - btrfs /dev/vda2 rw,subvolid=300,subvol=/vault\n";
    assert_eq!(
        elsewhere_on_the_decoy(&decoy_fs(over, &line("subvolid=257"))),
        vec![PathBuf::from("/home")]
    );
    // The top of the filesystem has id 5, which subvolid=0 names as well.
    let top = "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
               2 1 0:40 / /mnt/pool rw - btrfs /dev/vda2 rw,subvolid=5,subvol=/\n\
               30 1 0:40 /vault /mnt/data rw - btrfs /dev/vda2 rw,subvolid=300,subvol=/vault\n";
    for id in ["5", "0"] {
        let fstab = format!("/dev/vda2 /mnt/pool btrfs subvolid={id} 0 0\n");
        assert!(
            elsewhere_on_the_decoy(&decoy_fs(top, &fstab)).is_empty(),
            "{id}"
        );
    }
}

#[test]
fn on_a_decoy_filesystem_a_zfs_dataset_is_named_by_its_source() {
    // NixOS mounts a dataset with a legacy mount point by an fstab line that
    // names it: no device shows for either.
    let table = |home: &str| {
        format!(
            "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
             2 1 0:51 {home} /home rw - zfs rpool/home rw,xattr,noacl\n\
             30 1 0:51 /u/vault /mnt/data rw - zfs rpool/home rw,xattr,noacl\n"
        )
    };
    let line = "rpool/home /home zfs defaults 0 0\n";
    assert!(elsewhere_on_the_decoy(&decoy_fs(&table("/"), line)).is_empty());
    // A dataset ZFS mounts by its own mountpoint property has no line, a
    // line for another dataset or of another type does not name it, and the
    // root's folder bound by hand over /home is no mount the line makes.
    for (home, fstab) in [
        ("/", ""),
        ("/", "rpool/srv /home zfs defaults 0 0\n"),
        ("/", "rpool/home /home ext4 defaults 0 0\n"),
        ("/u/vault", line),
    ] {
        assert_eq!(
            elsewhere_on_the_decoy(&decoy_fs(&table(home), fstab)),
            vec![PathBuf::from("/home")],
            "{home} {fstab}"
        );
    }
}

#[test]
fn the_hint_for_a_root_that_is_the_decoys_filesystem_undoes_what_made_it_the_decoys() {
    let hint = |at: &str, in_fstab: bool| {
        let verdict = separation::Verdict::OnDecoyFilesystem {
            how: separation::Sharing::Filesystem,
            at: PathBuf::from(at),
            in_fstab,
        };
        Refusal::new(
            RefusalKind::DecoyStorage { verdict },
            Path::new("/mnt/data"),
        )
        .hint(None)
    };
    // The boot mounts it at a folder by a line of the fstab: the line goes.
    assert_eq!(
        hint("/backup", true)[0],
        "If /mnt/data is the volume you prepared, remove its line from /etc/fstab long before \
         the next use, and mount it by hand each time."
    );
    // No line mounts it at that system folder: the mount there goes.
    assert_eq!(
        hint("/srv", false)[0],
        "If /mnt/data is the volume you prepared and it was mounted at /srv by hand, run \
         `sudo umount /srv`, then run the command again."
    );
    assert!(
        hint("/srv/my data", false)[0].contains("run `sudo umount '/srv/my data'`, then"),
        "{:?}",
        hint("/srv/my data", false)
    );
    // Neither the line for / or for a system folder, which is the decoy's
    // own, nor a mount that holds the root is to go.
    for (at, in_fstab) in [
        ("/", true),
        ("/", false),
        ("/srv", true),
        ("/home", true),
        ("/mnt", false),
    ] {
        let hint = hint(at, in_fstab);
        assert!(hint[0].starts_with("Setting up here"), "{at}: {hint:?}");
        assert!(
            !hint.iter().any(|line| line.contains("remove its line")),
            "{at}: {hint:?}"
        );
    }
}

#[test]
fn on_a_decoy_filesystem_an_input_that_cannot_be_read_now_is_an_error() {
    // The gate read it a moment ago; a fstab or crypttab that exists but
    // cannot be read now cannot tell which mounts are the decoy's.
    let fs = decoy_fs(&bind_of_a_folder_of_root(""), "");
    fs.mock_set_path_exists("/etc/crypttab", true);
    let error = HiddenRoot::mounted_elsewhere_on_a_decoy_filesystem(&fs, Path::new("/mnt/data"))
        .unwrap_err();
    assert!(
        error.to_string().contains(
            "/etc/crypttab could not be read, so where this computer mounts the filesystem at \
             /mnt/data cannot be told"
        ),
        "{error}"
    );
    // A root with nothing mounted at it reads nothing.
    let fs = decoy_fs("1 0 8:1 / / rw - ext4 /dev/vda1 rw\n", "");
    fs.mock_set_path_exists("/etc/crypttab", true);
    assert!(elsewhere_on_the_decoy(&fs).is_empty());
}

#[test]
fn an_unreadable_mount_table_refuses() {
    let fs = fs_with(&decoy_table(""));
    fs.mock_set_mount_table_error("permission denied");
    let refused = refusal(&fs, "/mnt/data");
    assert!(
        matches!(refused.kind, RefusalKind::MountTableUnreadable { .. }),
        "{refused:?}"
    );
    assert!(
        refused.reason.contains("the mount table cannot be read"),
        "{}",
        refused.reason
    );
}

#[test]
fn in_the_session_the_recorded_volume_is_attached() {
    let fs = fs_with(&session_table(HIDDEN_MOUNT));
    write_plan(&fs, Some("253:0"));
    assert_eq!(
        HiddenRoot::assess(&fs, Path::new("/mnt/data")).unwrap(),
        Assessment::Attached
    );
}

#[test]
fn in_the_session_a_disk_over_the_root_is_refused() {
    let covered = format!("{HIDDEN_MOUNT}11 10 8:16 / /mnt/data rw - vfat /dev/sdb1 rw\n");
    let fs = fs_with(&session_table(&covered));
    write_plan(&fs, Some("253:0"));
    assert!(matches!(
        refusal(&fs, "/mnt/data").kind,
        RefusalKind::Covered { .. }
    ));
}

#[test]
fn in_the_session_another_disk_in_place_of_the_volume_is_refused() {
    // The hidden volume went away and a stick was mounted at its mount point.
    let fs = fs_with(&session_table(
        "12 1 8:16 / /mnt/data rw - vfat /dev/sdb1 rw\n",
    ));
    write_plan(&fs, Some("253:0"));
    let refused = refusal(&fs, "/mnt/data");
    assert_eq!(
        refused.kind,
        RefusalKind::NotTheSessionVolume {
            fstype: "vfat".into()
        }
    );
    assert!(
        refused
            .reason
            .contains("is not the volume this session started from"),
        "{}",
        refused.reason
    );
}

#[test]
fn in_the_session_an_older_plan_falls_back_to_the_upper() {
    let fs = fs_with(&session_table(HIDDEN_MOUNT));
    write_plan(&fs, None);
    // The upper sits on the root's device: the session's own volume.
    fs.mock_set_device_id(Path::new("/mnt/data/root/upper"), VOLUME_DEVICE);
    assert!(
        HiddenRoot::assess(&fs, Path::new("/mnt/data"))
            .unwrap()
            .is_attached()
    );

    // No upper on the filesystem at the root: not the session's volume.
    let fs = fs_with(&session_table(HIDDEN_MOUNT));
    assert!(matches!(
        refusal(&fs, "/mnt/data").kind,
        RefusalKind::NotTheSessionVolume { .. }
    ));
}

#[test]
fn outside_the_session_no_plan_is_consulted() {
    // A plan in /run that records another device does not matter on the decoy.
    let fs = fs_with(&decoy_table(""));
    write_plan(&fs, Some("8:99"));
    assert!(
        HiddenRoot::assess(&fs, Path::new("/mnt/data"))
            .unwrap()
            .is_attached()
    );
}

#[test]
fn attached_when_root_is_its_own_device() {
    let root = PathBuf::from("/mnt/data");
    let fs = attached_fs(&root);
    let state = HiddenRoot::verify_attached(&fs, &root, false).unwrap();
    assert_eq!(state, AttachState::Attached);
}

#[test]
fn unattached_when_root_shares_device_with_slash() {
    // A mount point whose filesystem is `/`'s own, as a bind of `/` is.
    let root = PathBuf::from("/mnt/data");
    let fs = attached_fs(&root);
    fs.mock_set_device_id(&root, ROOT_DEVICE);

    let state = HiddenRoot::verify_attached(&fs, &root, false).unwrap();
    assert!(!state.is_attached());
    assert!(
        state
            .reason()
            .unwrap()
            .contains("it is on the device that holds /")
    );
    assert_eq!(
        refusal(&fs, "/mnt/data").kind,
        RefusalKind::SameDeviceAsRoot
    );
}

#[test]
fn unattached_when_root_missing() {
    let root = PathBuf::from("/mnt/data");
    let fs = MockFilesystem::new();
    let state = HiddenRoot::verify_attached(&fs, &root, false).unwrap();
    assert!(!state.is_attached());
    assert!(state.reason().unwrap().contains("does not exist"));
    assert_eq!(refusal(&fs, "/mnt/data").kind, RefusalKind::Missing);
}

#[test]
fn unattached_when_marker_required_but_absent() {
    let root = PathBuf::from("/mnt/data");
    let fs = attached_fs(&root);
    let state = HiddenRoot::verify_attached(&fs, &root, true).unwrap();
    assert!(!state.is_attached());
    assert!(state.reason().unwrap().contains("no NAILS marker"));
}

#[test]
fn attached_with_marker_via_state_file() {
    let root = PathBuf::from("/mnt/data");
    let fs = attached_fs(&root);
    fs.mock_set_path_exists("/mnt/data/state.json", true);
    let state = HiddenRoot::verify_attached(&fs, &root, true).unwrap();
    assert_eq!(state, AttachState::Attached);
}

#[test]
fn attached_with_marker_via_config_file() {
    let root = PathBuf::from("/mnt/data");
    let fs = attached_fs(&root);
    fs.mock_set_path_exists("/mnt/data/config/nails.toml", true);
    let state = HiddenRoot::verify_attached(&fs, &root, true).unwrap();
    assert_eq!(state, AttachState::Attached);
}

#[test]
fn init_bypasses_marker_requirement() {
    // `init` runs with require_marker = false so a freshly mounted, empty
    // volume can be initialised.
    let root = PathBuf::from("/mnt/data");
    let fs = attached_fs(&root);
    let state = HiddenRoot::verify_attached(&fs, &root, false).unwrap();
    assert_eq!(state, AttachState::Attached);
}

#[test]
fn a_subdirectory_of_an_attached_volume_is_no_hidden_root() {
    // A folder inside the volume is no mount point; the state gate accepts it
    // as a state directory under the root instead.
    let root = PathBuf::from("/mnt/data");
    let fs = attached_fs(&root);
    fs.mock_set_path_exists("/mnt/data/logs", true);
    let state = HiddenRoot::verify_attached(&fs, &root.join("logs"), false).unwrap();
    assert!(!state.is_attached());
}

#[test]
fn empty_root_is_unattached() {
    let fs = MockFilesystem::new();
    let state = HiddenRoot::verify_attached(&fs, Path::new(""), false).unwrap();
    assert!(!state.is_attached());
    assert_eq!(refusal(&fs, "").kind, RefusalKind::NotConfigured);
}

/// The gate on the real kernel, in an unprivileged user + mount namespace.
mod kernel_tests {
    use super::super::separation::Verdict;
    use super::super::{Assessment, HiddenRoot, RefusalKind};
    use crate::RealFilesystem;
    use crate::test_support::{Rerun, ScratchTmpfs};
    use std::path::Path;

    fn kind(root: &Path) -> Option<RefusalKind> {
        match HiddenRoot::assess(&RealFilesystem, root).unwrap() {
            Assessment::Attached | Assessment::Warned(_) => None,
            Assessment::Refused(refusal) => Some(refusal.kind),
        }
    }

    #[test]
    fn a_tmpfs_is_attached_and_a_second_one_over_it_is_refused() {
        let _ = Rerun::new(crate::test_path!(
            a_tmpfs_is_attached_and_a_second_one_over_it_is_refused
        ))
        .in_user_mount_ns()
        .run(|| {
            let volume = ScratchTmpfs::new("");
            assert_eq!(kind(volume.path()), None);

            nix::mount::mount(
                Some("other"),
                volume.path(),
                Some("tmpfs"),
                nix::mount::MsFlags::empty(),
                Some("mode=0755"),
            )
            .expect("mount a second tmpfs over the first");
            assert!(
                matches!(kind(volume.path()), Some(RefusalKind::Covered { .. })),
                "{:?}",
                kind(volume.path())
            );
        });
    }

    #[test]
    fn a_plain_directory_is_refused() {
        let _ = Rerun::new(crate::test_path!(a_plain_directory_is_refused))
            .in_user_mount_ns()
            .run(|| {
                let volume = ScratchTmpfs::new("");
                let folder = volume.mkdir("folder");
                assert_eq!(
                    kind(&folder),
                    Some(RefusalKind::NotAMountPoint {
                        mount_point: volume.path().canonicalize().unwrap()
                    })
                );
                // A temp directory on whatever backs TMPDIR is no volume either.
                let plain = tempfile::tempdir().unwrap();
                assert!(matches!(
                    kind(plain.path()),
                    Some(RefusalKind::NotAMountPoint { .. })
                ));
            });
    }

    #[test]
    fn a_bind_of_the_root_filesystem_is_refused() {
        let _ = Rerun::new(crate::test_path!(a_bind_of_the_root_filesystem_is_refused))
            .in_user_mount_ns()
            .run(|| {
                let target = tempfile::tempdir().unwrap();
                nix::mount::mount(
                    Some("/"),
                    target.path(),
                    None::<&str>,
                    nix::mount::MsFlags::MS_BIND | nix::mount::MsFlags::MS_REC,
                    None::<&str>,
                )
                .expect("bind / at a scratch path");
                let refused = kind(target.path());
                let _ = nix::mount::umount2(target.path(), nix::mount::MntFlags::MNT_DETACH);
                // On a disk root the decoy-storage judge refuses it as the
                // filesystem at / (or cannot judge it, when crypttab is
                // readable by root only); on a RAM root (a live system) the
                // judge has nothing to say and the device backstop refuses it.
                assert!(
                    matches!(
                        refused,
                        Some(
                            RefusalKind::SameDeviceAsRoot
                                | RefusalKind::DecoyStorage {
                                    verdict: Verdict::OnDecoyFilesystem { .. }
                                }
                                | RefusalKind::StorageUnjudged { .. }
                        )
                    ),
                    "{refused:?}"
                );
            });
    }

    /// Bind `source` at `target`, inside the namespace.
    fn bind(source: &Path, target: &Path) {
        nix::mount::mount(
            Some(source),
            target,
            None::<&str>,
            nix::mount::MsFlags::MS_BIND,
            None::<&str>,
        )
        .expect("bind inside the namespace");
    }

    #[test]
    fn a_bind_of_the_volume_elsewhere_is_a_second_mount_and_one_at_the_root_is_not() {
        let _ = Rerun::new(crate::test_path!(
            a_bind_of_the_volume_elsewhere_is_a_second_mount_and_one_at_the_root_is_not
        ))
        .in_user_mount_ns()
        .run(|| {
            let volume = ScratchTmpfs::new("");
            let root = volume.path().canonicalize().unwrap();
            let elsewhere = || {
                HiddenRoot::mounted_elsewhere(&RealFilesystem, &root)
                    .unwrap()
                    .map(|found| {
                        found
                            .mounts
                            .into_iter()
                            .map(|m| m.mount_point)
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default()
            };
            assert!(elsewhere().is_empty());

            // The volume bound again at its own mount point is the root.
            bind(&root, &root);
            assert_eq!(kind(&root), None);
            assert!(elsewhere().is_empty());

            // Mounted again at another place, as a desktop mounts a drive.
            let other = tempfile::tempdir().unwrap();
            let place = other.path().canonicalize().unwrap();
            bind(&root, &place);
            let found = elsewhere();
            let _ = nix::mount::umount2(&place, nix::mount::MntFlags::MNT_DETACH);
            assert_eq!(found, vec![place]);
            assert!(elsewhere().is_empty());
        });
    }

    /// Make `/etc/crypttab` exist but fail to read, inside the namespace: a
    /// tmpfs over `/etc` holding a directory of that name.
    fn unreadable_crypttab() {
        nix::mount::mount(
            Some("etc"),
            "/etc",
            Some("tmpfs"),
            nix::mount::MsFlags::empty(),
            Some("mode=0755"),
        )
        .expect("a private /etc");
        std::fs::create_dir("/etc/crypttab").unwrap();
    }

    #[test]
    fn an_unreadable_crypttab_leaves_a_tmpfs_root_attached() {
        let _ = Rerun::new(crate::test_path!(
            an_unreadable_crypttab_leaves_a_tmpfs_root_attached
        ))
        .in_user_mount_ns()
        .run(|| {
            let volume = ScratchTmpfs::new("");
            unreadable_crypttab();
            assert_eq!(kind(volume.path()), None);
        });
    }

    #[test]
    fn an_unreadable_crypttab_refuses_a_root_on_a_disk() {
        let _ = Rerun::new(crate::test_path!(
            an_unreadable_crypttab_refuses_a_root_on_a_disk
        ))
        .in_user_mount_ns()
        .run(|| {
            // A folder of the filesystem behind TMPDIR, bound at a scratch path.
            let backing = tempfile::tempdir().unwrap();
            let target = tempfile::tempdir().unwrap();
            nix::mount::mount(
                Some(backing.path()),
                target.path(),
                None::<&str>,
                nix::mount::MsFlags::MS_BIND,
                None::<&str>,
            )
            .expect("bind a folder at a scratch path");
            let mounts = crate::filesystem::mountinfo::read_mountinfo().unwrap();
            let fstype = super::super::mount_holding(&mounts, target.path())
                .map(|mount| mount.fstype.clone())
                .unwrap_or_default();
            if matches!(fstype.as_str(), "tmpfs" | "ramfs") {
                let _ = nix::mount::umount2(target.path(), nix::mount::MntFlags::MNT_DETACH);
                crate::test_support::skip_host("TMPDIR is on a RAM filesystem");
            }
            unreadable_crypttab();
            let refused = kind(target.path());
            let _ = nix::mount::umount2(target.path(), nix::mount::MntFlags::MNT_DETACH);
            assert_eq!(
                refused,
                Some(RefusalKind::StorageUnjudged {
                    unreadable: vec![std::path::PathBuf::from("/etc/crypttab")]
                })
            );
        });
    }
}

/// A bind of the decoy's `/home/op/vault` at `/mnt/data`: on the decoy's
/// storage, a refusal the override covers.
const BIND_OF_HOME: &str = "13 1 8:2 /op/vault /mnt/data rw - ext4 /dev/vda2 rw\n";

#[test]
fn the_override_attaches_decoy_storage_with_a_warning_but_never_a_folder_or_a_covered_root() {
    let bind = fs_with(&format!(
        "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n2 1 8:2 / /home rw - ext4 /dev/vda2 rw\n{BIND_OF_HOME}"
    ));
    let root = Path::new("/mnt/data");
    assert!(matches!(
        HiddenRoot::assess_allowing(&bind, root, Allow::Nothing).unwrap(),
        Assessment::Refused(_)
    ));
    match HiddenRoot::assess_allowing(&bind, root, Allow::DecoyStorage).unwrap() {
        Assessment::Warned(refusal) => assert!(refusal.overridden(), "{refusal:?}"),
        other => panic!("{other:?}"),
    }

    // A folder is no volume of its own, whatever the operator says.
    let fs = fs_with(&decoy_table(""));
    fs.mock_set_path_exists("/home/op/vault", true);
    match HiddenRoot::assess_allowing(&fs, Path::new("/home/op/vault"), Allow::DecoyStorage)
        .unwrap()
    {
        Assessment::Refused(refusal) => {
            assert!(
                matches!(refusal.kind, RefusalKind::NotAMountPoint { .. }),
                "{refusal:?}"
            );
            assert!(!refusal.overridden());
        }
        other => panic!("{other:?}"),
    }

    let covered = fs_with(&decoy_table(
        "11 10 8:17 / /mnt/data rw - ext4 /dev/sdb1 rw\n",
    ));
    match HiddenRoot::assess_allowing(&covered, root, Allow::DecoyStorage).unwrap() {
        Assessment::Refused(refusal) => {
            assert_eq!(refusal.code(), super::refusal::ROOT_COVERED, "{refusal:?}");
        }
        other => panic!("{other:?}"),
    }

    let missing = MockFilesystem::new();
    assert!(matches!(
        HiddenRoot::assess_allowing(&missing, Path::new("/srv/x"), Allow::DecoyStorage).unwrap(),
        Assessment::Refused(Refusal {
            kind: RefusalKind::Missing,
            ..
        })
    ));
}

#[test]
fn in_the_session_a_folder_is_refused_even_when_the_plan_accepted_the_root() {
    // Nothing is mounted at the root, `/` is the overlay with its upper there,
    // and the plan says the activation was run with --allow-decoy-storage.
    let fs = fs_with(&session_table(""));
    write_plan(&fs, None);
    assert_eq!(super::recorded_acceptance(&fs), None);
    let path = nails_teardown::whole_root::plan::default_plan_path();
    let text = fs.read_file_content(&path).unwrap().replacen(
        "\"hidden_root\"",
        "\"accepted_decoy_storage\":\"it is a bind mount\",\"hidden_root\"",
        1,
    );
    fs.mock_set_file_content(path.to_str().unwrap(), &text);
    assert_eq!(
        super::recorded_acceptance(&fs).as_deref(),
        Some("it is a bind mount")
    );
    assert!(matches!(
        refusal(&fs, "/mnt/data").kind,
        RefusalKind::NotAMountPoint { .. }
    ));
    let _gate = super::state_attach_probe::enforce();
    assert!(
        super::ensure_state_dir_attached(&fs, Path::new("/mnt/data"), Path::new("/mnt/data"))
            .is_err()
    );
}

#[test]
fn outside_the_session_accepted_decoy_storage_needs_the_override() {
    let table = "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n2 1 8:2 / /home rw - ext4 /dev/vda2 rw\n";
    let fs = fs_with(&format!("{table}{BIND_OF_HOME}"));
    let root = Path::new("/mnt/data");
    let _gate = super::state_attach_probe::enforce();
    assert!(super::ensure_state_dir_attached(&fs, root, root).is_err());
    super::ensure_state_dir_attached_allowing(&fs, root, root, Allow::DecoyStorage).unwrap();
    // A directory below the root on another filesystem is still refused.
    let mounted_below = fs_with(&format!(
        "{table}{BIND_OF_HOME}14 13 8:33 / /mnt/data/state rw - ext4 /dev/sdc1 rw\n"
    ));
    assert!(
        super::ensure_state_dir_attached_allowing(
            &mounted_below,
            root,
            &root.join("state"),
            Allow::DecoyStorage
        )
        .is_err()
    );
}
