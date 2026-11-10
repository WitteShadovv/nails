// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! [`Guarded`]: a filesystem that asks the automount guard before every
//! lookup it makes.

use super::{Lookup, Memo, Skipped, Snapshot, Table};
use crate::filesystem::{
    DiskUsage, Filesystem, LoopRecord, MountEntry, MountRoot, MountSource, PatternScan,
    ProcessMatch,
};
use crate::target_user::TargetUser;
use crate::{NailsError, Result};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

/// `F`, with every call that takes a path asked of the automount guard
/// first ([`on_the_way`](super::on_the_way)), by the table of a [`Snapshot`].
///
/// A call that reads what is at its path ([`Lookup::Enters`]) is not made
/// where the lookup would mount an automount point; a call that only
/// resolves its path ([`Lookup::Resolves`]: [`canonicalize`],
/// [`read_link`], [`mount_root`]) is answered without a lookup where the
/// path ends at a direct automount point. A lookup that is not made fails
/// with [`NailsError::NotLookedUp`] and is kept in the ledger
/// ([`skipped`](Guarded::skipped)). A lookup whose way the guard cannot
/// read is not made either: it fails with the error of that read, naming
/// the path, as the lookup itself would fail, and is not kept. With a
/// table that cannot be read, no lookup is made; for a tree that is not
/// the running system's, every call is made as it is.
///
/// A write is asked as a read of its paths, and then made. The mount
/// queries read the mount table, but resolve their path first, so they are
/// asked as [`canonicalize`] is, and made unless that would mount. A walk of
/// a tree ([`find_files_with_pattern`], [`scan_files_with_pattern`]) and a
/// read under another root than `/` cannot be asked about one lookup at a
/// time: by the running system's table they fail with an error of kind
/// `Unsupported` ([`resolve_in_root`] answers none), and are kept in no
/// ledger.
///
/// Clones share the snapshot and the ledger; two views made with
/// [`new`](Guarded::new) share the snapshot only. A view made with
/// [`remembering`](Guarded::remembering) shares both, and reads each place
/// on the way once.
///
/// [`canonicalize`]: Filesystem::canonicalize
/// [`read_link`]: Filesystem::read_link
/// [`mount_root`]: Filesystem::mount_root
/// [`find_files_with_pattern`]: Filesystem::find_files_with_pattern
/// [`scan_files_with_pattern`]: Filesystem::scan_files_with_pattern
/// [`resolve_in_root`]: Filesystem::resolve_in_root
#[derive(Debug, Clone)]
pub struct Guarded<F> {
    inner: F,
    snapshot: Arc<Snapshot>,
    skipped: Arc<Mutex<Vec<Skipped>>>,
    /// What the view read of each place on the way, where it reads each
    /// once.
    memo: Option<Arc<Mutex<Memo>>>,
}

impl<F: Filesystem> Guarded<F> {
    /// `inner`, guarded by `snapshot`, with a ledger of its own.
    pub fn new(inner: F, snapshot: &Arc<Snapshot>) -> Self {
        Self {
            inner,
            snapshot: Arc::clone(snapshot),
            skipped: Arc::new(Mutex::new(Vec::new())),
            memo: None,
        }
    }

    /// This view, reading each place on the way once: a lookup that passes
    /// a place an earlier lookup of this view read takes what was read
    /// then, what the kernel said there and where a link there leads. For
    /// a reader that asks about every lookup of a walk before it makes the
    /// walk, whose answers are as old as that walk either way. The view
    /// keeps this one's snapshot and ledger.
    pub fn remembering(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            snapshot: Arc::clone(&self.snapshot),
            skipped: Arc::clone(&self.skipped),
            memo: Some(Arc::new(Mutex::new(Memo::default()))),
        }
    }

    /// The lookups this view did not make, in the order it was asked them.
    pub fn skipped(&self) -> Vec<Skipped> {
        self.skipped
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Whether a lookup of `path` as `lookup`, which the caller makes itself,
    /// may be made, as [`Snapshot::check`] tells; one that may not is kept in
    /// the ledger.
    ///
    /// # Errors
    ///
    /// As [`Snapshot::check`].
    pub fn ask(&self, path: &Path, lookup: Lookup) -> Result<Option<PathBuf>> {
        let answer = self
            .snapshot
            .check_with(&self.inner, path, lookup, self.memo.as_deref());
        if let Err(error) = &answer
            && let Some((path, reason)) = error.not_looked_up()
        {
            self.skipped
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(Skipped {
                    path: path.to_path_buf(),
                    reason: reason.clone(),
                });
        }
        answer
    }

    /// Ask about a lookup that reads what is at `path`, following a link at
    /// its end when `follow`. Such a lookup gets no
    /// [`AtPoint`](super::Way::AtPoint): it is made, or it is not.
    fn enters(&self, path: &Path, follow: bool) -> Result<()> {
        self.ask(path, Lookup::Enters { follow }).map(drop)
    }

    /// Ask about the resolution a mount query makes of `target` before it
    /// reads the table: a query that cannot resolve it reads the table for
    /// the path as it is named, so only a resolution that would mount keeps
    /// it from being made.
    fn resolves_target(&self, target: &Path) -> Result<()> {
        match self.ask(target, Lookup::Resolves { follow: true }) {
            Err(error) if error.not_looked_up().is_some() => Err(error),
            _ => Ok(()),
        }
    }

    /// Ask about what can only be made where nothing is guarded: a walk of
    /// the tree at `path`, or a read of it below another root than `/`.
    fn unguardable(&self, path: &Path, what: &str) -> Result<()> {
        match &self.snapshot.table {
            Table::Elsewhere => Ok(()),
            Table::Unreadable(_) => self.enters(path, true),
            Table::Running(_) => Err(NailsError::io(
                path,
                std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    format!(
                        "NAILS does not {what} {}, since it cannot ask before each lookup \
                         whether it would mount an automount point",
                        path.display()
                    ),
                ),
            )),
        }
    }

    /// Ask about a lookup of `path` resolved inside the tree at `root`.
    fn in_root(&self, root: &Path, path: &Path) -> Result<()> {
        if root == Path::new("/") {
            self.enters(path, true)
        } else {
            self.unguardable(&root.join(path.strip_prefix("/").unwrap_or(path)), "read")
        }
    }
}

impl<F: Filesystem> Filesystem for Guarded<F> {
    fn mount_table(&self) -> Result<Vec<MountEntry>> {
        match &self.snapshot.table {
            Table::Running(table) => Ok(table.clone()),
            Table::Elsewhere => self.inner.mount_table(),
            Table::Unreadable(error) => Err(NailsError::io(
                nails_teardown::mountinfo::SELF_MOUNTINFO,
                std::io::Error::other(error.clone()),
            )),
        }
    }

    fn is_mounted(&self, target: &Path) -> Result<bool> {
        self.resolves_target(target)?;
        self.inner.is_mounted(target)
    }

    fn get_filesystem_type(&self, target: &Path) -> Result<Option<String>> {
        self.resolves_target(target)?;
        self.inner.get_filesystem_type(target)
    }

    fn is_mount_read_only(&self, target: &Path) -> Result<bool> {
        self.resolves_target(target)?;
        self.inner.is_mount_read_only(target)
    }

    fn mount_source(&self, mount_point: &Path) -> Result<Option<MountSource>> {
        self.resolves_target(mount_point)?;
        self.inner.mount_source(mount_point)
    }

    fn path_exists(&self, path: &Path) -> Result<bool> {
        self.enters(path, true)?;
        self.inner.path_exists(path)
    }

    fn is_directory(&self, path: &Path) -> Result<bool> {
        self.enters(path, true)?;
        self.inner.is_directory(path)
    }

    fn is_regular_file(&self, path: &Path) -> Result<bool> {
        self.enters(path, true)?;
        self.inner.is_regular_file(path)
    }

    fn device_id(&self, path: &Path) -> Result<u64> {
        self.enters(path, true)?;
        self.inner.device_id(path)
    }

    fn inode(&self, path: &Path) -> Result<Option<u64>> {
        self.enters(path, true)?;
        self.inner.inode(path)
    }

    fn record_lock_holder(&self, path: &Path) -> Result<Option<i32>> {
        // The file is opened without following a link at the path.
        self.enters(path, false)?;
        self.inner.record_lock_holder(path)
    }

    fn loop_record(&self, node: &Path) -> Result<LoopRecord> {
        self.enters(node, true)?;
        self.inner.loop_record(node)
    }

    fn mount_root(&self, path: &Path) -> Result<MountRoot> {
        match self.ask(path, Lookup::Resolves { follow: false })? {
            Some(_) => Ok(MountRoot::Automount),
            None => self.inner.mount_root(path),
        }
    }

    fn is_symlink(&self, path: &Path) -> Result<bool> {
        self.enters(path, false)?;
        self.inner.is_symlink(path)
    }

    fn read_link(&self, path: &Path) -> Result<PathBuf> {
        match self.ask(path, Lookup::Resolves { follow: false })? {
            // An automount point is a directory, never a link.
            Some(_) => Err(NailsError::io(
                path,
                std::io::Error::from_raw_os_error(nix::libc::EINVAL),
            )),
            None => self.inner.read_link(path),
        }
    }

    fn is_overlay_whiteout(&self, path: &Path) -> Result<bool> {
        self.enters(path, false)?;
        self.inner.is_overlay_whiteout(path)
    }

    fn canonicalize(&self, path: &Path) -> Result<PathBuf> {
        match self.ask(path, Lookup::Resolves { follow: true })? {
            Some(point) => Ok(point),
            None => self.inner.canonicalize(path),
        }
    }

    fn resolve_in_root(&self, root: &Path, path: &Path) -> Option<PathBuf> {
        if root != Path::new("/") {
            self.unguardable(root, "read").ok()?;
            return self.inner.resolve_in_root(root, path);
        }
        match self.ask(path, Lookup::Resolves { follow: true }).ok()? {
            Some(point) => Some(point),
            None => self.inner.resolve_in_root(root, path),
        }
    }

    fn read_file_in_root(&self, root: &Path, path: &Path) -> Result<String> {
        self.in_root(root, path)?;
        self.inner.read_file_in_root(root, path)
    }

    fn create_symlink(&self, target: &Path, link: &Path) -> Result<()> {
        // The target is only named, never looked up.
        self.enters(link, true)?;
        self.inner.create_symlink(target, link)
    }

    fn disk_usage(&self, path: &Path) -> Result<DiskUsage> {
        self.enters(path, true)?;
        self.inner.disk_usage(path)
    }

    fn create_directory(&self, path: &Path) -> Result<()> {
        self.enters(path, true)?;
        self.inner.create_directory(path)
    }

    fn create_hidden_dir_all(&self, hidden_root: &Path, relative: &Path) -> Result<()> {
        self.enters(&hidden_root.join(relative), true)?;
        self.inner.create_hidden_dir_all(hidden_root, relative)
    }

    fn write_hidden_file_atomic(
        &self,
        hidden_root: &Path,
        relative: &Path,
        content: &str,
        mode: u32,
    ) -> Result<()> {
        self.enters(&hidden_root.join(relative), true)?;
        self.inner
            .write_hidden_file_atomic(hidden_root, relative, content, mode)
    }

    fn set_permissions(&self, path: &Path, mode: u32) -> Result<()> {
        self.enters(path, true)?;
        self.inner.set_permissions(path, mode)
    }

    fn get_permissions(&self, path: &Path) -> Result<u32> {
        self.enters(path, true)?;
        self.inner.get_permissions(path)
    }

    fn is_readable(&self, path: &Path) -> Result<bool> {
        self.enters(path, true)?;
        self.inner.is_readable(path)
    }

    fn is_writable(&self, path: &Path) -> Result<bool> {
        self.enters(path, true)?;
        self.inner.is_writable(path)
    }

    fn nails_process_matches(&self) -> Result<Vec<ProcessMatch>> {
        self.inner.nails_process_matches()
    }

    fn read_file_content(&self, path: &Path) -> Result<String> {
        self.enters(path, true)?;
        self.inner.read_file_content(path)
    }

    fn read_file_bytes(&self, path: &Path) -> Result<Vec<u8>> {
        self.enters(path, true)?;
        self.inner.read_file_bytes(path)
    }

    fn read_file_range(&self, path: &Path, offset: u64, len: usize) -> Result<Vec<u8>> {
        self.enters(path, true)?;
        self.inner.read_file_range(path, offset, len)
    }

    fn find_files_with_pattern(&self, dir: &Path, pattern: &str) -> Result<Vec<PathBuf>> {
        self.unguardable(dir, "walk")?;
        self.inner.find_files_with_pattern(dir, pattern)
    }

    fn scan_files_with_pattern(&self, dir: &Path, pattern: &str) -> Result<PatternScan> {
        self.unguardable(dir, "walk")?;
        self.inner.scan_files_with_pattern(dir, pattern)
    }

    fn write_file_content(&self, path: &Path, content: &str) -> Result<()> {
        self.enters(path, true)?;
        self.inner.write_file_content(path, content)
    }

    fn write_user_file(
        &self,
        path: &Path,
        content: &str,
        user: &TargetUser,
        default_mode: u32,
    ) -> Result<()> {
        self.enters(path, true)?;
        self.inner
            .write_user_file(path, content, user, default_mode)
    }

    fn overwrite_file_in_place(&self, path: &Path, content: &str) -> Result<()> {
        self.enters(path, true)?;
        self.inner.overwrite_file_in_place(path, content)
    }

    fn list_directory(&self, dir: &Path) -> Result<Vec<PathBuf>> {
        self.enters(dir, true)?;
        self.inner.list_directory(dir)
    }

    fn file_size(&self, path: &Path) -> Result<u64> {
        self.enters(path, true)?;
        self.inner.file_size(path)
    }

    fn rename_file(&self, from: &Path, to: &Path) -> Result<()> {
        self.enters(from, true)?;
        self.enters(to, true)?;
        self.inner.rename_file(from, to)
    }

    fn remove_file(&self, path: &Path) -> Result<()> {
        self.enters(path, true)?;
        self.inner.remove_file(path)
    }

    fn remove_directory(&self, path: &Path) -> Result<()> {
        self.enters(path, true)?;
        self.inner.remove_directory(path)
    }

    fn remove_dir_all(&self, path: &Path) -> Result<()> {
        self.enters(path, true)?;
        self.inner.remove_dir_all(path)
    }

    fn secure_delete(&self, path: &Path) -> Result<()> {
        self.enters(path, true)?;
        self.inner.secure_delete(path)
    }

    fn secure_delete_dir_all(&self, path: &Path) -> Result<()> {
        self.enters(path, true)?;
        self.inner.secure_delete_dir_all(path)
    }

    fn supports_symlinks(&self, dir: &Path) -> Result<bool> {
        self.enters(dir, true)?;
        self.inner.supports_symlinks(dir)
    }

    fn modified_time(&self, path: &Path) -> Result<std::time::SystemTime> {
        self.enters(path, true)?;
        self.inner.modified_time(path)
    }

    fn change_time(&self, path: &Path) -> Result<std::time::SystemTime> {
        // The path itself, as lstat reads it: a link at its end is not
        // followed.
        self.enters(path, false)?;
        self.inner.change_time(path)
    }

    fn copy_tree(&self, src: &Path, dst: &Path) -> Result<()> {
        self.enters(src, true)?;
        self.enters(dst, true)?;
        self.inner.copy_tree(src, dst)
    }

    fn copy_file(&self, src: &Path, dst: &Path) -> Result<()> {
        self.enters(src, true)?;
        self.enters(dst, true)?;
        self.inner.copy_file(src, dst)
    }
}
