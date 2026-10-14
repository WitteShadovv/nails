// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! A mount stacked on the hidden root during the session.
//!
//! With `/mnt` as the hidden root, an ordinary `mount /dev/sdc1 /mnt` in the
//! session stacks a disk on the hidden volume: every file saved under `/mnt`
//! from then on goes to that disk. The attach gate refuses every write NAILS
//! itself would make there, and the backend probe writes nothing and is no
//! failure while the root is covered, so no automatic emergency follows from a
//! cover. What is left is telling the operator, once per covering mount.

use std::collections::BTreeSet;

use nails_teardown::mountinfo::MountEntry;

use crate::runtime_copy::RuntimeManifest;

/// The mount stacked on the hidden root the manifest records: the visible
/// mount there, when its device is not the recorded `hidden_dev` (see
/// [`nails_base::hidden_root::shadowing_mount`]). `None` when nothing is
/// mounted at the root: that is a volume that is gone, which the backend
/// probe reports.
pub fn shadowing_mount<'a>(
    mounts: &'a [MountEntry],
    manifest: &RuntimeManifest,
) -> Option<&'a MountEntry> {
    nails_base::hidden_root::shadowing_mount(
        mounts,
        &manifest.hidden_root,
        manifest.hidden_dev.as_deref(),
    )
}

/// The watcher's view of mounts stacked on the hidden root: each one is
/// reported once, by mount id.
#[derive(Debug, Default)]
pub struct CoverWatch {
    seen: BTreeSet<i32>,
}

impl CoverWatch {
    /// The mount covering the hidden root in `mounts`, if it was not reported
    /// before. A covering mount that is gone is forgotten, so its id can alert
    /// again when it is reused.
    pub fn observe(
        &mut self,
        mounts: &[MountEntry],
        manifest: &RuntimeManifest,
    ) -> Option<MountEntry> {
        let current: BTreeSet<i32> = mounts.iter().map(|m| m.mount_id).collect();
        self.seen.retain(|id| current.contains(id));
        shadowing_mount(mounts, manifest)
            .filter(|cover| self.seen.insert(cover.mount_id))
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nails_teardown::mountinfo::parse_mountinfo;
    use std::path::PathBuf;

    fn manifest(hidden_dev: Option<&str>) -> RuntimeManifest {
        RuntimeManifest {
            hidden_root: PathBuf::from("/mnt"),
            hidden_dev: hidden_dev.map(str::to_string),
            overlay_targets: Vec::new(),
        }
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
        let mut watch = CoverWatch::default();
        let covered = table("11 10 0:90 / /mnt rw - tmpfs scratch rw\n");
        let manifest = manifest(Some("253:0"));
        let cover = watch
            .observe(&covered, &manifest)
            .expect("the tmpfs covers /mnt");
        assert_eq!(cover.mount_id, 11);
        assert_eq!(cover.source, PathBuf::from("scratch"));
        assert_eq!(watch.observe(&covered, &manifest), None);
        // Unmounted and mounted again under the same id: a new cover.
        assert_eq!(watch.observe(&table(""), &manifest), None);
        assert!(watch.observe(&covered, &manifest).is_some());
    }

    #[test]
    fn a_second_bind_of_the_volume_is_no_cover() {
        let mut watch = CoverWatch::default();
        let rebound = table("11 10 253:0 / /mnt rw - ext4 /dev/mapper/data rw\n");
        assert_eq!(watch.observe(&rebound, &manifest(Some("253:0"))), None);
        assert_eq!(watch.observe(&rebound, &manifest(None)), None);
    }

    #[test]
    fn without_a_recorded_device_a_stacked_disk_still_counts() {
        let mut watch = CoverWatch::default();
        let covered = table("11 10 8:33 / /mnt rw - vfat /dev/sdc1 rw\n");
        let cover = watch.observe(&covered, &manifest(None)).expect("a cover");
        assert_eq!(cover.source, PathBuf::from("/dev/sdc1"));
    }

    #[test]
    fn an_empty_mount_point_is_left_to_the_backend_probe() {
        let mut watch = CoverWatch::default();
        let gone = parse_mountinfo("1 0 0:30 / / rw - overlay overlay rw\n");
        assert_eq!(watch.observe(&gone, &manifest(Some("253:0"))), None);
        assert_eq!(watch.observe(&table(""), &manifest(Some("253:0"))), None);
    }
}
