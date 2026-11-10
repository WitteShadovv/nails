// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::{MockFilesystem, MockOp};
use std::path::{Component, Path, PathBuf};

impl MockFilesystem {
    /// Get written file content for test verification
    ///
    /// Returns the content that was written to a file via write_file_content(),
    /// or None if the file was not written.
    pub fn get_written_content(&self, path: &Path) -> Option<String> {
        let written = self
            .written_files
            .lock()
            .expect("MockFilesystem mutex poisoned");
        written.get(path).cloned()
    }

    /// Every path a file write (`write_file_content`, an in-place overwrite,
    /// `write_user_file`) has left content at, sorted: the state a read-only
    /// check must leave empty.
    pub fn mock_written_paths(&self) -> Vec<PathBuf> {
        let mut paths: Vec<PathBuf> = self
            .written_files
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .keys()
            .cloned()
            .collect();
        paths.sort();
        paths
    }

    /// Every path a read was asked about, in the order it was asked: the
    /// lookups (`path_exists`, `is_directory`, `is_regular_file`,
    /// `is_symlink`, `inode`, `mount_root`, `canonicalize`, `read_link` and
    /// the others that look at what is at a path), the file reads, the
    /// listings and the walks. The mount queries, which read the mount
    /// table, are not among them, nor are writes.
    pub fn mock_lookups(&self) -> Vec<PathBuf> {
        self.lookups
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .iter()
            .map(|(path, _)| path.clone())
            .collect()
    }

    /// Whether a read [`mock_lookups`](Self::mock_lookups) recorded passed
    /// `place` or a path below it, with the links `create_symlink` recorded
    /// followed as the kernel follows them: each link on the way, and the one
    /// at the end where the read follows it, as every read does but
    /// `is_symlink`, `read_link`, `mount_root`, `is_overlay_whiteout`,
    /// `change_time` and `record_lock_holder`. A lookup of `/etc/nixos/x`
    /// where `/etc/nixos` links to `/home/bob/nixos` passes `/home/bob`,
    /// though the path asked names none of it.
    pub fn mock_reached(&self, place: &Path) -> bool {
        let lookups = self
            .lookups
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .clone();
        lookups.iter().any(|(path, follows)| {
            self.passed(path, *follows)
                .iter()
                .any(|passed| passed.starts_with(place))
        })
    }

    /// The places a lookup of `path` passes: each place on its way, and on
    /// the way where each link on it leads, the link at its end followed
    /// where `follows`.
    fn passed(&self, path: &Path, follows: bool) -> Vec<PathBuf> {
        // The kernel's own limit on links followed during one lookup.
        const MAX_HOPS: usize = 40;

        let links = self
            .symlink_targets
            .lock()
            .expect("MockFilesystem mutex poisoned");
        let mut passed = Vec::new();
        let mut current = path.to_path_buf();
        for _ in 0..MAX_HOPS {
            let components: Vec<_> = current.components().collect();
            let mut place = PathBuf::new();
            let mut next = None;
            for (i, component) in components.iter().enumerate() {
                // The kernel takes `..` from where the walk is.
                match component {
                    Component::ParentDir => {
                        place.pop();
                        continue;
                    }
                    Component::CurDir => continue,
                    _ => place.push(component),
                }
                passed.push(place.clone());
                if i + 1 == components.len() && !follows {
                    break;
                }
                if let Some(target) = links.get(&place) {
                    let mut resolved = place.parent().unwrap_or(Path::new("/")).join(target);
                    resolved.extend(&components[i + 1..]);
                    next = Some(resolved);
                    break;
                }
            }
            match next {
                Some(resolved) => current = resolved,
                None => break,
            }
        }
        passed
    }

    /// Forget the reads [`mock_lookups`](Self::mock_lookups) recorded so
    /// far.
    pub fn mock_clear_lookups(&self) {
        self.lookups
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .clear();
    }

    /// Record a read of `path` for [`mock_lookups`](Self::mock_lookups), one
    /// that follows a link at its end.
    pub(super) fn looked_at(&self, path: &Path) {
        self.lookups
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .push((path.to_path_buf(), true));
    }

    /// Record a read of `path` itself for
    /// [`mock_lookups`](Self::mock_lookups): one that does not follow a link
    /// at its end.
    pub(super) fn looked_at_itself(&self, path: &Path) {
        self.lookups
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .push((path.to_path_buf(), false));
    }

    /// Get operation log for verifying call ordering in tests
    pub fn mock_ops(&self) -> Vec<MockOp> {
        self.op_log
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .clone()
    }

    /// Get list of currently mounted paths
    ///
    /// Useful for test assertions.
    pub fn get_mounted_paths(&self) -> Vec<PathBuf> {
        self.mounted
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .iter()
            .cloned()
            .collect()
    }

    /// Get the permissions that were set on a path via `set_permissions`
    ///
    /// Returns `None` if no permissions were explicitly set on this path.
    pub fn mock_get_permissions(&self, path: &Path) -> Option<u32> {
        self.permissions
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .get(path)
            .copied()
    }

    /// Get the symlink target recorded by `create_symlink`
    ///
    /// Returns `None` if no symlink was created at this path.
    pub fn mock_get_symlink_target(&self, link: &Path) -> Option<PathBuf> {
        self.symlink_targets
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .get(link)
            .cloned()
    }

    /// Get the numeric `(uid, gid)` ownership recorded by `write_user_file`.
    ///
    /// Returns `None` for a path `write_user_file` never created (ordinary
    /// `write_file_content`, `create_directory`, and similar do not record
    /// ownership).
    pub fn mock_get_owner(&self, path: &Path) -> Option<(u32, u32)> {
        self.owners
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .get(path)
            .copied()
    }
}
