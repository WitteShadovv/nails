// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::MockFilesystem;
use super::state::{DEFAULT_MOCK_FREE_SPACE_BYTES, MockOp};
use crate::filesystem::DiskUsage;
use crate::{NailsError, Result};
use std::path::{Path, PathBuf};

impl MockFilesystem {
    pub(super) fn path_exists_impl(&self, path: &Path) -> Result<bool> {
        let paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
        Ok(paths.get(path).map(|info| info.exists).unwrap_or(false))
    }

    pub(super) fn device_id_impl(&self, path: &Path) -> Result<u64> {
        if let Some(id) = self
            .device_ids
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .get(path)
            .copied()
        {
            return Ok(id);
        }
        // Default: a stable, per-path distinct id, different from `/`'s. A test
        // that wants two paths on one filesystem maps them onto one id with
        // `mock_set_device_id`.
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        path.hash(&mut hasher);
        // Keep it clear of 0 so callers never confuse it with "unset".
        Ok(hasher.finish() | 1)
    }

    pub(super) fn loop_backing_device_impl(&self, node: &Path) -> Result<u64> {
        self.loop_backing_devices
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .get(node)
            .copied()
            .ok_or_else(|| {
                crate::NailsError::io(
                    node,
                    std::io::Error::from(std::io::ErrorKind::PermissionDenied),
                )
            })
    }

    pub(super) fn is_directory_impl(&self, path: &Path) -> Result<bool> {
        let paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
        Ok(paths
            .get(path)
            .map(|info| info.is_directory)
            .unwrap_or(false))
    }

    /// A path that exists and is neither a directory, a link nor a whiteout,
    /// once the links `create_symlink` recorded are followed. A link the mock
    /// cannot follow (one marked with `mock_set_path_type` alone, or a loop)
    /// is no regular file, as a dangling link is none to `stat`; a whiteout is
    /// the character device it is on a real overlay's upper.
    pub(super) fn is_regular_file_impl(&self, path: &Path) -> Result<bool> {
        let Ok(target) = self.canonicalize_impl(path) else {
            return Ok(false);
        };
        let paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
        Ok(paths.get(&target).is_some_and(|info| {
            info.exists && !info.is_directory && !info.is_symlink && !info.is_whiteout
        }))
    }

    pub(super) fn is_symlink_impl(&self, path: &Path) -> Result<bool> {
        let paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
        Ok(paths.get(path).map(|info| info.is_symlink).unwrap_or(false))
    }

    pub(super) fn is_overlay_whiteout_impl(&self, path: &Path) -> Result<bool> {
        let paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
        Ok(paths.get(path).is_some_and(|info| info.is_whiteout))
    }

    /// Resolve the symlinks recorded by `create_symlink`, component by
    /// component. Unlike the real call this never reports a missing path: the
    /// mock does not track existence for most paths, and resolving to the
    /// lexical path is what a fully existing, link-free path does anyway.
    pub(super) fn canonicalize_impl(&self, path: &Path) -> Result<PathBuf> {
        // The kernel's own limit on links followed during one lookup.
        const MAX_HOPS: usize = 40;

        let links = self
            .symlink_targets
            .lock()
            .expect("MockFilesystem mutex poisoned");
        let mut current = path.to_path_buf();
        for _ in 0..MAX_HOPS {
            let components: Vec<_> = current.components().collect();
            let mut prefix = PathBuf::new();
            let mut next = None;
            for (i, component) in components.iter().enumerate() {
                prefix.push(component);
                if let Some(target) = links.get(&prefix) {
                    let base = prefix.parent().unwrap_or(Path::new("/"));
                    let mut resolved = base.join(target);
                    resolved.extend(&components[i + 1..]);
                    next = Some(resolved);
                    break;
                }
            }
            match next {
                Some(resolved) => current = resolved,
                None => return Ok(current),
            }
        }
        Err(NailsError::io(
            path,
            std::io::Error::other(format!(
                "too many levels of symbolic links: {}",
                path.display()
            )),
        ))
    }

    pub(super) fn supports_symlinks_impl(&self, dir: &Path) -> Result<bool> {
        self.op_log
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .push(MockOp::SymlinkProbe {
                dir: dir.to_path_buf(),
            });
        let support = self
            .symlink_support
            .lock()
            .expect("MockFilesystem mutex poisoned");
        Ok(support.get(dir).copied().unwrap_or(true))
    }

    pub(super) fn create_symlink_impl(&self, target: &Path, link: &Path) -> Result<()> {
        let paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
        if let Some(info) = paths.get(link) {
            if info.exists && info.is_symlink {
                drop(paths);
                let symlinks = self
                    .symlink_targets
                    .lock()
                    .expect("MockFilesystem mutex poisoned");
                if symlinks.get(link).map(|t| t == target).unwrap_or(false) {
                    return Ok(());
                }
                return Err(NailsError::io(
                    link,
                    std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        format!(
                            "Symlink at {} already exists pointing to a different target",
                            link.display()
                        ),
                    ),
                ));
            } else if info.exists {
                drop(paths);
                return Err(NailsError::io(
                    link,
                    std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        format!("Path already exists (not a symlink) at {}", link.display()),
                    ),
                ));
            }
        }
        drop(paths);

        let mut paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
        let entry = paths.entry(link.to_path_buf()).or_default();
        entry.exists = true;
        entry.is_symlink = true;
        drop(paths);

        self.symlink_targets
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .insert(link.to_path_buf(), target.to_path_buf());

        Ok(())
    }

    pub(super) fn disk_usage_impl(&self, path: &Path) -> Result<DiskUsage> {
        let paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
        let info = paths.get(path);
        Ok(DiskUsage {
            total: info
                .map(|info| info.total_space)
                .unwrap_or(DEFAULT_MOCK_FREE_SPACE_BYTES),
            available: info
                .map(|info| info.free_space)
                .unwrap_or(DEFAULT_MOCK_FREE_SPACE_BYTES),
        })
    }

    pub(super) fn create_directory_impl(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            let parent_exists = {
                let paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
                paths.get(parent).map(|info| info.exists).unwrap_or(false)
            };

            if !parent_exists {
                if let Some(grandparent) = parent.parent() {
                    let paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
                    let grandparent_writable = paths
                        .get(grandparent)
                        .map(|info| info.is_writable)
                        .unwrap_or(false);
                    drop(paths);
                    if !grandparent_writable {
                        return Err(NailsError::PermissionDenied(format!(
                            "Parent directory not writable: {}",
                            grandparent.display()
                        )));
                    }
                }

                self.create_directory_impl(parent)?;
                let mut paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
                if let Some(entry) = paths.get_mut(parent) {
                    entry.is_writable = true;
                }
            } else {
                let paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
                let parent_writable = paths
                    .get(parent)
                    .map(|info| info.is_writable)
                    .unwrap_or(false);
                drop(paths);
                if !parent_writable {
                    return Err(NailsError::PermissionDenied(format!(
                        "Parent directory not writable: {}",
                        parent.display()
                    )));
                }
            }
        }

        let mut paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
        let entry = paths.entry(path.to_path_buf()).or_default();
        entry.exists = true;
        entry.is_directory = true;
        Ok(())
    }

    pub(super) fn set_permissions_impl(&self, path: &Path, mode: u32) -> Result<()> {
        if self
            .permissions_should_fail
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .contains(path)
        {
            return Err(NailsError::io(
                path,
                std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "Mock: set_permissions configured to fail for {}",
                        path.display()
                    ),
                ),
            ));
        }

        let paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
        if !paths.get(path).map(|info| info.exists).unwrap_or(false) {
            return Err(NailsError::io(
                path,
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("Path does not exist: {}", path.display()),
                ),
            ));
        }
        drop(paths);

        self.permissions
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .insert(path.to_path_buf(), mode);
        Ok(())
    }

    pub(super) fn get_permissions_impl(&self, path: &Path) -> Result<u32> {
        let paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
        if let Some(info) = paths.get(path)
            && !info.exists
        {
            return Err(NailsError::io(
                path,
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("Path does not exist: {}", path.display()),
                ),
            ));
        }
        drop(paths);

        Ok(self
            .permissions
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .get(path)
            .copied()
            .unwrap_or(0o755))
    }

    pub(super) fn is_readable_impl(&self, path: &Path) -> Result<bool> {
        let paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
        Ok(paths
            .get(path)
            .map(|info| info.is_readable)
            .unwrap_or(false))
    }

    pub(super) fn is_writable_impl(&self, path: &Path) -> Result<bool> {
        self.op_log
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .push(MockOp::WritableProbe {
                path: path.to_path_buf(),
            });
        let paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
        Ok(paths
            .get(path)
            .map(|info| info.is_writable)
            .unwrap_or(false))
    }
}
