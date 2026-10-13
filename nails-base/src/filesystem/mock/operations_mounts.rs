// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::super::MountSource;
use super::super::mountinfo::{MountEntry, mount_is_read_only, parse_mountinfo, top_mount_at};
use super::MockFilesystem;
use crate::{NailsError, Result};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

impl MockFilesystem {
    /// The explicit mount table, parsed, when a test set one.
    fn explicit_mount_table(&self) -> Option<Vec<MountEntry>> {
        self.mount_table
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .as_deref()
            .map(parse_mountinfo)
    }

    /// The mount visible at `target` in the explicit table, when a test set
    /// one: `Some(None)` when nothing is mounted there. The target is resolved
    /// through the mock's symlinks first, as the real filesystem canonicalizes
    /// it.
    fn explicit_visible_mount(&self, target: &Path) -> Option<Option<MountEntry>> {
        let table = self.explicit_mount_table()?;
        let canonical = self
            .canonicalize_impl(target)
            .unwrap_or_else(|_| target.to_path_buf());
        Some(top_mount_at(&table, &canonical).cloned())
    }

    /// The explicit table, or one rendered from the mock's mounts: `/` plus
    /// every mounted path, each with a device of its own, the type, source and
    /// read-only flag the test set, else `ext4` from a `/dev/mock<N>` device.
    pub(super) fn mount_table_impl(&self) -> Vec<MountEntry> {
        if let Some(table) = self.explicit_mount_table() {
            return table;
        }
        let mounted: BTreeSet<PathBuf> = self
            .mounted
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .iter()
            .filter(|path| path.as_path() != Path::new("/"))
            .cloned()
            .collect();
        let types = self
            .filesystem_types
            .lock()
            .expect("MockFilesystem mutex poisoned");
        let sources = self
            .mount_sources
            .lock()
            .expect("MockFilesystem mutex poisoned");
        let read_only = self
            .read_only_mounts
            .lock()
            .expect("MockFilesystem mutex poisoned");

        let mut table: Vec<MountEntry> = Vec::new();
        for (index, path) in std::iter::once(PathBuf::from("/"))
            .chain(mounted)
            .enumerate()
        {
            let mount_id = i32::try_from(index).unwrap_or(i32::MAX) + 1;
            // The parent is the deepest mount listed so far that holds `path`;
            // sorting puts every mount point after its ancestors.
            let parent_id = table
                .iter()
                .filter(|entry| path.starts_with(&entry.mount_point))
                .max_by_key(|entry| entry.mount_point.components().count())
                .map_or(0, |entry| entry.mount_id);
            let mount_opts = if read_only.contains(&path) {
                "ro"
            } else {
                "rw"
            };
            table.push(MountEntry {
                mount_id,
                parent_id,
                dev: format!("254:{index}"),
                root: PathBuf::from("/"),
                fstype: types
                    .get(&path)
                    .cloned()
                    .unwrap_or_else(|| "ext4".to_string()),
                source: sources
                    .get(&path)
                    .and_then(|source| source.device.clone())
                    .map_or_else(|| PathBuf::from(format!("/dev/mock{index}")), PathBuf::from),
                mount_point: path,
                mount_opts: mount_opts.to_string(),
                super_opts: "rw".to_string(),
            });
        }
        table
    }

    pub(super) fn is_mounted_impl(&self, target: &Path) -> Result<bool> {
        if let Some(message) = self
            .is_mounted_errors
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .get(target)
        {
            return Err(NailsError::io(
                target,
                std::io::Error::other(message.clone()),
            ));
        }

        if let Some(visible) = self.explicit_visible_mount(target) {
            return Ok(visible.is_some());
        }
        Ok(self
            .mounted
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .contains(target))
    }

    pub(super) fn get_filesystem_type_impl(&self, target: &Path) -> Result<Option<String>> {
        if let Some(visible) = self.explicit_visible_mount(target) {
            return Ok(visible.map(|entry| entry.fstype));
        }
        Ok(self
            .filesystem_types
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .get(target)
            .cloned())
    }

    pub(super) fn mount_source_impl(&self, mount_point: &Path) -> Result<Option<MountSource>> {
        if let Some(visible) = self.explicit_visible_mount(mount_point) {
            return Ok(visible.map(|entry| MountSource {
                dm_name: entry
                    .source
                    .strip_prefix("/dev/mapper")
                    .ok()
                    .map(|name| name.to_string_lossy().into_owned()),
                device: Some(entry.source.to_string_lossy().into_owned()),
                label: None,
            }));
        }
        Ok(self
            .mount_sources
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .get(mount_point)
            .cloned())
    }

    pub(super) fn is_mount_read_only_impl(&self, target: &Path) -> bool {
        if let Some(visible) = self.explicit_visible_mount(target) {
            return visible.is_some_and(|entry| mount_is_read_only(&entry));
        }
        self.read_only_mounts
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .contains(target)
    }
}
