// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The mock's mount table: rendered from its mounts, or set explicitly, and
//! the mount queries answering for the visible mount of an explicit table.

use super::MockFilesystem;
use crate::filesystem::mountinfo::top_mount_at;
use crate::filesystem::{Filesystem, MountSource};
use std::path::Path;

#[test]
fn the_default_table_is_the_root_and_every_mounted_path() {
    let fs = MockFilesystem::new();
    let table = fs.mount_table().unwrap();
    assert_eq!(table.len(), 1, "only the root: {table:?}");
    assert_eq!(table[0].mount_point, Path::new("/"));

    fs.mock_set_mounted(Path::new("/mnt/data"), true);
    fs.mock_set_mounted(Path::new("/mnt"), true);
    fs.mock_set_mounted(Path::new("/home"), true);
    fs.mock_set_filesystem_type(Path::new("/home"), "btrfs");
    fs.mock_set_mount_read_only(Path::new("/home"));
    fs.mock_set_mount_source(
        Path::new("/mnt/data"),
        MountSource {
            device: Some("/dev/mapper/data".into()),
            ..MountSource::default()
        },
    );

    let table = fs.mount_table().unwrap();
    let points: Vec<_> = table.iter().map(|e| e.mount_point.as_path()).collect();
    assert_eq!(
        points,
        vec![
            Path::new("/"),
            Path::new("/home"),
            Path::new("/mnt"),
            Path::new("/mnt/data")
        ]
    );
    let devices: std::collections::HashSet<_> = table.iter().map(|e| e.dev.as_str()).collect();
    assert_eq!(devices.len(), table.len(), "every mount has its own device");

    let visible = |path: &str| top_mount_at(&table, Path::new(path)).unwrap();
    assert_eq!(visible("/").fstype, "ext4");
    let home = visible("/home");
    assert_eq!((home.fstype.as_str(), home.read_only()), ("btrfs", true));
    let data = visible("/mnt/data");
    assert_eq!(
        data.parent_id,
        visible("/mnt").mount_id,
        "nested under /mnt"
    );
    assert_eq!(data.source, Path::new("/dev/mapper/data"));
    assert_eq!(data.fstype, "ext4");
    assert!(!data.read_only());
    assert!(
        visible("/mnt")
            .source
            .to_string_lossy()
            .starts_with("/dev/mock"),
        "a device of its own by default"
    );
}

/// Without an explicit table the queries read what a test set for each path,
/// and the rendered table can disagree with them, as `mock_set_mount_table`
/// says: it lists `/` and fills in a type no test set.
#[test]
fn without_an_explicit_table_the_queries_read_their_own_maps() {
    let fs = MockFilesystem::new();
    fs.mock_set_mounted(Path::new("/mnt/data"), true);
    fs.mock_set_mounted(Path::new("/mnt"), true);
    // A mount below another mounted path stays mounted.
    assert!(fs.is_mounted(Path::new("/mnt/data")).unwrap());
    assert!(!fs.is_mounted(Path::new("/")).unwrap(), "as before");
    assert_eq!(fs.get_filesystem_type(Path::new("/mnt")).unwrap(), None);

    let table = fs.mount_table().unwrap();
    assert!(top_mount_at(&table, Path::new("/")).is_some());
    assert_eq!(
        top_mount_at(&table, Path::new("/mnt")).unwrap().fstype,
        "ext4"
    );
}

/// `/mnt/data` holds two filesystems, the second stacked on the first, and
/// `/srv/inner` is covered by a later mount on `/srv`.
const STACKED: &str = "\
1 0 8:1 / / rw - ext4 /dev/sda1 rw
20 1 8:2 / /srv rw - ext4 /dev/sda2 rw
21 20 8:3 / /srv/inner rw - ext4 /dev/sda3 rw
22 20 0:40 / /srv rw - tmpfs cover rw
30 1 253:0 / /mnt/data rw - ext4 /dev/mapper/first rw
31 30 253:1 / /mnt/data ro,relatime - xfs /dev/mapper/second rw
";

#[test]
fn an_explicit_table_is_returned_as_set() {
    let fs = MockFilesystem::new();
    fs.mock_set_mount_table(STACKED);
    let table = fs.mount_table().unwrap();
    assert_eq!(table.len(), 6);
    assert_eq!(table[2].mount_point, Path::new("/srv/inner"));
}

#[test]
fn is_mounted_answers_for_the_visible_mount() {
    let fs = MockFilesystem::new();
    fs.mock_set_mount_table(STACKED);
    assert!(fs.is_mounted(Path::new("/mnt/data")).unwrap());
    assert!(fs.is_mounted(Path::new("/srv")).unwrap());
    assert!(
        !fs.is_mounted(Path::new("/srv/inner")).unwrap(),
        "covered by the mount on /srv"
    );
    assert!(!fs.is_mounted(Path::new("/mnt")).unwrap());
    // The explicit table wins over the mock's own mount set.
    fs.mock_set_mounted(Path::new("/srv/inner"), true);
    assert!(!fs.is_mounted(Path::new("/srv/inner")).unwrap());
}

#[test]
fn the_filesystem_type_is_the_visible_mounts() {
    let fs = MockFilesystem::new();
    fs.mock_set_mount_table(STACKED);
    let fstype = |path: &str| fs.get_filesystem_type(Path::new(path)).unwrap();
    assert_eq!(
        fstype("/mnt/data").as_deref(),
        Some("xfs"),
        "the top of the stack"
    );
    assert_eq!(fstype("/srv").as_deref(), Some("tmpfs"));
    assert_eq!(fstype("/srv/inner"), None);
}

#[test]
fn the_read_only_flag_is_the_visible_mounts() {
    let fs = MockFilesystem::new();
    fs.mock_set_mount_table(STACKED);
    assert!(fs.is_mount_read_only(Path::new("/mnt/data")).unwrap());
    assert!(!fs.is_mount_read_only(Path::new("/srv")).unwrap());
    assert!(
        !fs.is_mount_read_only(Path::new("/srv/inner")).unwrap(),
        "not a mount point reads as writable"
    );
    // A superblock remounted read-only counts too.
    fs.mock_set_mount_table(
        "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n\
         30 1 253:0 / /mnt/data rw - ext4 /dev/mapper/data ro,errors=remount-ro\n",
    );
    assert!(fs.is_mount_read_only(Path::new("/mnt/data")).unwrap());
}

#[test]
fn the_mount_source_is_the_visible_mounts() {
    let fs = MockFilesystem::new();
    fs.mock_set_mount_table(STACKED);
    assert_eq!(
        fs.mount_source(Path::new("/mnt/data")).unwrap(),
        Some(MountSource {
            device: Some("/dev/mapper/second".into()),
            dm_name: Some("second".into()),
            label: None,
        })
    );
    assert_eq!(
        fs.mount_source(Path::new("/srv")).unwrap(),
        Some(MountSource {
            device: Some("cover".into()),
            dm_name: None,
            label: None,
        })
    );
    assert_eq!(fs.mount_source(Path::new("/srv/inner")).unwrap(), None);
}

#[test]
fn the_queries_resolve_the_mocks_symlinks_first() {
    let fs = MockFilesystem::new();
    fs.mock_set_mount_table(STACKED);
    fs.create_symlink(Path::new("/mnt/data"), Path::new("/data"))
        .unwrap();
    assert!(fs.is_mounted(Path::new("/data")).unwrap());
}

#[test]
fn a_set_is_mounted_error_still_wins() {
    let fs = MockFilesystem::new();
    fs.mock_set_mount_table(STACKED);
    fs.mock_set_is_mounted_error(Path::new("/mnt/data"), "mount table unreadable");
    assert!(fs.is_mounted(Path::new("/mnt/data")).is_err());
}

#[test]
fn reset_forgets_the_explicit_table() {
    let fs = MockFilesystem::new();
    fs.mock_set_mount_table(STACKED);
    fs.reset();
    assert_eq!(fs.mount_table().unwrap().len(), 1);
}
