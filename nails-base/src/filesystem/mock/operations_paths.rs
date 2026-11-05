// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::MockFilesystem;
use super::state::{DEFAULT_MOCK_FREE_SPACE_BYTES, MockOp};
use crate::filesystem::DiskUsage;
use crate::{NailsError, Result};
use std::path::{Path, PathBuf};

/// The error of a lookup of `path` that fails with an error of `kind`.
fn lookup_failure(path: &Path, kind: std::io::ErrorKind) -> NailsError {
    NailsError::io(
        path,
        std::io::Error::new(kind, "Mock: the lookup fails here"),
    )
}

/// The error of a lookup of `path` through links that make a loop, or more
/// than the kernel follows: `ELOOP`, as the kernel gives it.
fn loop_failure(path: &Path) -> NailsError {
    NailsError::io(path, std::io::Error::from_raw_os_error(nix::libc::ELOOP))
}

/// What a lookup that asks whether something is at `path` answers when it
/// fails with an error of `kind`: no where the error says nothing is there,
/// as the real lookups answer, and the error otherwise.
fn absent_or_failure(path: &Path, kind: std::io::ErrorKind) -> Result<bool> {
    match kind {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory => Ok(false),
        kind => Err(lookup_failure(path, kind)),
    }
}

/// Why the mock's links lead `path` nowhere ([`MockFilesystem::resolve`]).
pub(super) enum Unresolved {
    /// A lookup on the way fails with an error of this kind
    /// ([`MockFilesystem::mock_set_lookup_error`]).
    Fails(std::io::ErrorKind),
    /// The links make a loop, or are more than the kernel follows.
    Loop,
}

impl MockFilesystem {
    /// The kind of error a lookup of `path` fails with, when
    /// [`mock_set_lookup_error`](Self::mock_set_lookup_error) set one on it or
    /// on a directory on its way: the one nearest the root, where a real
    /// lookup stops.
    fn lookup_error_kind(&self, path: &Path) -> Option<std::io::ErrorKind> {
        let errors = self
            .lookup_errors
            .lock()
            .expect("MockFilesystem mutex poisoned");
        if errors.is_empty() {
            return None;
        }
        let ancestors: Vec<&Path> = path.ancestors().collect();
        ancestors
            .into_iter()
            .rev()
            .find_map(|prefix| errors.get(prefix).copied())
    }

    /// The error a lookup of `path` fails with, naming `path`, when one was
    /// set on it or on a directory on its way.
    pub(super) fn lookup_error(&self, path: &Path) -> Option<NailsError> {
        self.lookup_error_kind(path)
            .map(|kind| lookup_failure(path, kind))
    }

    /// The answer of a lookup that asks whether something is at `path`, when
    /// a lookup error was set on its way: no where the error says nothing is
    /// there (`NotFound`, `NotADirectory`), the error otherwise.
    fn looked_up(&self, path: &Path) -> Option<Result<bool>> {
        self.lookup_error_kind(path)
            .map(|kind| absent_or_failure(path, kind))
    }

    pub(super) fn path_exists_impl(&self, path: &Path) -> Result<bool> {
        if let Some(answer) = self.looked_up(path) {
            return answer;
        }
        let paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
        Ok(paths.get(path).map(|info| info.exists).unwrap_or(false))
    }

    pub(super) fn device_id_impl(&self, path: &Path) -> Result<u64> {
        if let Some(error) = self.lookup_error(path) {
            return Err(error);
        }
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

    pub(super) fn inode_impl(&self, path: &Path) -> Result<Option<u64>> {
        // Only a path that does not exist is none here: a lookup through a
        // file is an error, as for the real call.
        match self.lookup_error_kind(path) {
            Some(std::io::ErrorKind::NotFound) => return Ok(None),
            Some(kind) => return Err(lookup_failure(path, kind)),
            None => {}
        }
        if let Some(answer) = self
            .inodes
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .get(path)
            .copied()
        {
            return answer
                .map(Some)
                .map_err(|kind| crate::NailsError::io(path, std::io::Error::from(kind)));
        }
        if !self.path_exists_impl(path)? {
            return Ok(None);
        }
        // Default: a stable, per-path distinct inode. A test that wants two
        // paths to name one file maps them onto one with `mock_set_inode`.
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        path.hash(&mut hasher);
        Ok(Some(hasher.finish() | 1))
    }

    pub(super) fn record_lock_holder_impl(&self, path: &Path) -> Result<Option<i32>> {
        if let Some(error) = self.lookup_error(path) {
            return Err(error);
        }
        if let Some(answer) = self
            .record_locks
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .get(path)
            .copied()
        {
            return answer.map_err(|kind| NailsError::io(path, std::io::Error::from(kind)));
        }
        // As the real query: a link is not followed, and only a regular file
        // is asked about.
        let kind = if self.is_symlink_impl(path)? {
            std::io::ErrorKind::InvalidInput
        } else if self.is_regular_file_impl(path)? {
            return Ok(None);
        } else if self.path_exists_impl(path)? {
            std::io::ErrorKind::InvalidInput
        } else {
            std::io::ErrorKind::NotFound
        };
        Err(NailsError::io(path, std::io::Error::from(kind)))
    }

    pub(super) fn loop_record_impl(&self, node: &Path) -> Result<crate::filesystem::LoopRecord> {
        self.loop_records
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
        if let Some(answer) = self.looked_up(path) {
            return answer;
        }
        let paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
        Ok(paths
            .get(path)
            .map(|info| info.is_directory)
            .unwrap_or(false))
    }

    /// A path that exists and is neither a directory, a link nor a whiteout,
    /// once the links `create_symlink` recorded are followed. A link the mock
    /// has no target for (one marked with `mock_set_path_type` alone) is no
    /// regular file, as a dangling link is none to `stat`; a whiteout is the
    /// character device it is on a real overlay's upper. Links that make a
    /// loop fail it with `ELOOP`, as they fail `stat`, and so does a lookup
    /// error set on the way or where a link leads.
    pub(super) fn is_regular_file_impl(&self, path: &Path) -> Result<bool> {
        let target = match self.resolve(path) {
            Ok(target) => target,
            Err(Unresolved::Fails(kind)) => return absent_or_failure(path, kind),
            Err(Unresolved::Loop) => return Err(loop_failure(path)),
        };
        let paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
        Ok(paths.get(&target).is_some_and(|info| {
            info.exists && !info.is_directory && !info.is_symlink && !info.is_whiteout
        }))
    }

    pub(super) fn is_symlink_impl(&self, path: &Path) -> Result<bool> {
        if let Some(answer) = self.looked_up(path) {
            return answer;
        }
        let paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
        Ok(paths.get(path).map(|info| info.is_symlink).unwrap_or(false))
    }

    /// The target `create_symlink` recorded for `path`. Any other path is no
    /// link the mock can read, as `readlink` fails on what is no link.
    pub(super) fn read_link_impl(&self, path: &Path) -> Result<PathBuf> {
        if let Some(error) = self.lookup_error(path) {
            return Err(error);
        }
        self.symlink_targets
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .get(path)
            .cloned()
            .ok_or_else(|| {
                NailsError::io(path, std::io::Error::from(std::io::ErrorKind::InvalidInput))
            })
    }

    pub(super) fn is_overlay_whiteout_impl(&self, path: &Path) -> Result<bool> {
        // A path that cannot be inspected is none, as for the real call.
        if self.lookup_error_kind(path).is_some() {
            return Ok(false);
        }
        let paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
        Ok(paths.get(path).is_some_and(|info| info.is_whiteout))
    }

    /// Resolve the symlinks recorded by `create_symlink`, component by
    /// component. Unlike the real call this never reports a missing path: the
    /// mock does not track existence for most paths, and resolving to the
    /// lexical path is what a fully existing, link-free path does anyway. A
    /// lookup error set on a path the resolution looks up fails it.
    pub(super) fn canonicalize_impl(&self, path: &Path) -> Result<PathBuf> {
        self.resolve(path).map_err(|unresolved| match unresolved {
            Unresolved::Fails(kind) => lookup_failure(path, kind),
            Unresolved::Loop => loop_failure(path),
        })
    }

    /// Where `path` leads once the links `create_symlink` recorded are
    /// followed, component by component, as
    /// [`canonicalize_impl`](Self::canonicalize_impl) gives it.
    pub(super) fn resolve(&self, path: &Path) -> std::result::Result<PathBuf, Unresolved> {
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
                    // The lookup reached the link, and every directory on
                    // its way.
                    if let Some(kind) = self.lookup_error_kind(&prefix) {
                        return Err(Unresolved::Fails(kind));
                    }
                    let base = prefix.parent().unwrap_or(Path::new("/"));
                    let mut resolved = base.join(target);
                    resolved.extend(&components[i + 1..]);
                    next = Some(resolved);
                    break;
                }
            }
            match next {
                Some(resolved) => current = resolved,
                None => {
                    return match self.lookup_error_kind(&current) {
                        Some(kind) => Err(Unresolved::Fails(kind)),
                        None => Ok(current),
                    };
                }
            }
        }
        Err(Unresolved::Loop)
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
        if let Some(error) = self.lookup_error(path) {
            return Err(error);
        }
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
        if let Some(error) = self.lookup_error(path) {
            return Err(error);
        }
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
        // The real call answers no when the path cannot be opened at all.
        if self.lookup_error_kind(path).is_some() {
            return Ok(false);
        }
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
        // The real probe answers no when it cannot open or create there.
        if self.lookup_error_kind(path).is_some() {
            return Ok(false);
        }
        let paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
        Ok(paths
            .get(path)
            .map(|info| info.is_writable)
            .unwrap_or(false))
    }
}
