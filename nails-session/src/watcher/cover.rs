// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! A mount stacked on the hidden root during the session.
//!
//! With `/mnt` as the hidden root, an ordinary `mount /dev/sdc1 /mnt` in the
//! session stacks a disk on the hidden volume: every file saved under `/mnt`
//! from then on goes to that disk. A mount on one of the root's parents
//! (`/mnt` over a root at `/mnt/data`) hides it the same way. The attach gate
//! refuses every write NAILS
//! itself would make there, and the backend probe writes nothing and is no
//! failure while the root is covered, so no automatic emergency follows from a
//! cover. What is left is telling the operator, once per covering mount.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use nails_base::hidden_root::shadowing_mount;
use nails_teardown::mountinfo::MountEntry;

/// The watcher's view of mounts stacked on the hidden root: each one is
/// reported once, by mount id.
#[derive(Debug)]
pub struct CoverWatch {
    root: PathBuf,
    hidden_dev: Option<String>,
    seen: BTreeSet<i32>,
}

impl CoverWatch {
    /// Watch the hidden root `root`, resolved the way the mount table names it
    /// (see [`resolved_root`](super::resolved_root)), whose volume the session
    /// plan records as `hidden_dev`.
    pub fn new(root: &Path, hidden_dev: Option<&str>) -> Self {
        Self {
            root: root.to_path_buf(),
            hidden_dev: hidden_dev.map(str::to_string),
            seen: BTreeSet::new(),
        }
    }

    /// The mount covering the hidden root in `mounts`, reported or not: the
    /// mount a lookup reaches at the root or on one of its parents, when it is
    /// not the recorded volume (see
    /// [`nails_base::hidden_root::shadowing_mount`]). `None` when the volume is
    /// not mounted at the root: that is a volume that is gone, which the
    /// backend probe reports.
    pub fn cover<'a>(&self, mounts: &'a [MountEntry]) -> Option<&'a MountEntry> {
        shadowing_mount(mounts, &self.root, self.hidden_dev.as_deref())
    }

    /// The mount covering the hidden root in `mounts`, if it was not reported
    /// before. A covering mount that is gone is forgotten, so its id can alert
    /// again when it is reused.
    pub fn observe(&mut self, mounts: &[MountEntry]) -> Option<MountEntry> {
        let current: BTreeSet<i32> = mounts.iter().map(|m| m.mount_id).collect();
        self.seen.retain(|id| current.contains(id));
        let cover = self.cover(mounts)?;
        self.seen.insert(cover.mount_id).then(|| cover.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nails_teardown::mountinfo::parse_mountinfo;

    fn watch(hidden_dev: Option<&str>) -> CoverWatch {
        CoverWatch::new(Path::new("/mnt"), hidden_dev)
    }

    /// The session's root and the hidden volume at `/mnt`, plus `extra`.
    fn table(extra: &str) -> Vec<MountEntry> {
        parse_mountinfo(&format!(
            "1 0 0:30 / / rw - overlay overlay rw\n\
             10 1 253:0 / /mnt rw - ext4 /dev/mapper/data rw\n{extra}"
        ))
    }

    #[test]
    fn a_tmpfs_over_the_root_is_reported_once() {
        let mut watch = watch(Some("253:0"));
        let covered = table("11 10 0:90 / /mnt rw - tmpfs scratch rw\n");
        let cover = watch.observe(&covered).expect("the tmpfs covers /mnt");
        assert_eq!(cover.mount_id, 11);
        assert_eq!(cover.source, PathBuf::from("scratch"));
        assert_eq!(watch.observe(&covered), None);
        assert_eq!(watch.cover(&covered).map(|m| m.mount_id), Some(11));
        // Unmounted and mounted again under the same id: a new cover.
        assert_eq!(watch.observe(&table("")), None);
        assert!(watch.observe(&covered).is_some());
    }

    #[test]
    fn a_second_bind_of_the_volume_is_no_cover() {
        let rebound = table("11 10 253:0 / /mnt rw - ext4 /dev/mapper/data rw\n");
        assert_eq!(watch(Some("253:0")).observe(&rebound), None);
        assert_eq!(watch(None).observe(&rebound), None);
    }

    #[test]
    fn without_a_recorded_device_a_stacked_disk_still_counts() {
        let covered = table("11 10 8:33 / /mnt rw - vfat /dev/sdc1 rw\n");
        let cover = watch(None).observe(&covered).expect("a cover");
        assert_eq!(cover.source, PathBuf::from("/dev/sdc1"));
    }

    #[test]
    fn a_mount_on_the_roots_parent_is_reported_as_a_cover() {
        let mut watch = CoverWatch::new(Path::new("/mnt/data"), Some("253:0"));
        let covered = parse_mountinfo(
            "1 0 0:30 / / rw - overlay overlay rw\n\
             10 1 253:0 / /mnt/data rw - ext4 /dev/mapper/data rw\n\
             11 1 8:33 / /mnt rw - vfat /dev/sdc1 rw\n",
        );
        let cover = watch.observe(&covered).expect("/mnt covers /mnt/data");
        assert_eq!(cover.mount_id, 11);
        assert_eq!(watch.observe(&covered), None);
    }

    #[test]
    fn an_empty_mount_point_is_left_to_the_backend_probe() {
        let mut watch = watch(Some("253:0"));
        let gone = parse_mountinfo("1 0 0:30 / / rw - overlay overlay rw\n");
        assert_eq!(watch.observe(&gone), None);
        assert_eq!(watch.observe(&table("")), None);
    }
}
