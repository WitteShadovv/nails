// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Filesystem trait definition and helper functions

use crate::Result;
use crate::filesystem::MountEntry;
use crate::target_user::TargetUser;
use std::path::{Path, PathBuf};

/// Total and available space for a filesystem, taken from a single `statvfs`
/// call so the status path never has to walk directories to report usage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskUsage {
    /// Total size of the filesystem in bytes.
    pub total: u64,
    /// Space available to the caller in bytes (unprivileged availability).
    pub available: u64,
}

impl DiskUsage {
    /// Bytes in use: `total` minus `available`, saturating so a filesystem that
    /// reports more reserved-for-root space than free never underflows.
    pub fn used(&self) -> u64 {
        self.total.saturating_sub(self.available)
    }
}

/// How the kernel and udev name the device a mount is backed by.
///
/// Returned by [`Filesystem::mount_source`] for a single mount point. Every
/// field is optional because a bind mount, a pseudo-filesystem or an unlabelled
/// device supplies only some of them. The names matter on their own: a mapper
/// name, a filesystem label or a mount path that reads as "hidden" survives in
/// the leftover mount-point directory, in generated systemd unit names, in
/// `/dev/disk/by-label` and in kernel and sudo journal lines, so preflight scans
/// them for words that would betray hidden storage to anyone who reads them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MountSource {
    /// The mount source as it appears in `/proc/self/mountinfo`
    /// (`/dev/mapper/data`, `/dev/dm-2`, `/dev/sdb1`, a bind source, ...).
    pub device: Option<String>,
    /// The device-mapper name behind the source, when the source is a dm device
    /// (`/dev/mapper/<name>`, or `/dev/dm-N` resolved via
    /// `/sys/block/dm-N/dm/name`).
    pub dm_name: Option<String>,
    /// The filesystem label, when `/dev/disk/by-label` holds a symlink that
    /// resolves to the source device.
    pub label: Option<String>,
}

/// The result of a permission-tolerant recursive file scan.
///
/// Unlike a plain `Vec<PathBuf>`, this separates the matched files from the
/// directories that could not be read, so a caller (verify) can report an
/// unreadable directory as information rather than letting an `EACCES` abort the
/// whole walk. An unprivileged `verify --deep` over `/tmp` therefore never fails
/// on a `systemd-private-*` directory it is not allowed to enter.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PatternScan {
    /// Files whose name contains the pattern.
    pub matches: Vec<PathBuf>,
    /// Directories that existed but could not be read (permission denied).
    pub unreadable: Vec<PathBuf>,
}

/// One process whose command line references NAILS, classified by how strong the
/// match is.
///
/// A plain substring match ("nails" anywhere in the command line) is weak: it
/// also fires on `sed`, `tee` or an editor operating on a config file, so it is
/// only ever reported as information. A strong match means the process is really
/// the NAILS binary — its `/proc/<pid>/exe` shares an inode with the running
/// binary, or its `argv[0]` basename is exactly `nails` — and warrants a critical
/// finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessMatch {
    /// The process id.
    pub pid: u32,
    /// Whether this is a strong (binary identity) match rather than a weak
    /// (substring) one.
    pub strong: bool,
    /// A short human-readable description of what matched.
    pub detail: String,
}

// ============================================================================
// Core Filesystem Trait
// ============================================================================

/// Filesystem operations abstraction
///
/// This trait defines all filesystem and NixOS operations needed by NAILS.
/// Implementations can use real syscalls (RealFilesystem) or in-memory state (MockFilesystem).
///
/// # Trait Bounds
///
/// - **Send:** Required for thread-safe parallel testing
/// - **Sync:** Required for sharing between threads
/// - **Clone:** Required for passing to multiple managers
/// - **'static:** Implementations own their state (no borrowed filesystems), so
///   platform backends, config layers and progress reporters can be handed out
///   as trait objects that outlive a borrow of the manager
pub trait Filesystem: Send + Sync + Clone + 'static {
    // ------------------------------------------------------------------------
    // Mount Queries
    // ------------------------------------------------------------------------
    //
    // Every query answers for the mount a lookup of the path reaches (see
    // `nails_teardown::mountinfo::top_mount_at`): the last of several mounts
    // stacked on one point, and no mount at all where a later mount on a
    // parent directory covers the path.
    //
    // `MockFilesystem` answers so only from an explicit table
    // (`mock_set_mount_table`). Without one, each query reads what a test set
    // for that path, while `mount_table` renders `/` and every mounted path
    // with defaults for what the test left unset, so the two can disagree: the
    // rendered table lists `/`, which `is_mounted` denies unless a test marked
    // it. A test of code that reads the table and a query together sets a
    // table.

    /// The mount table of this process's mount namespace, in the order
    /// `/proc/self/mountinfo` lists it.
    fn mount_table(&self) -> Result<Vec<MountEntry>>;

    /// Whether a mount is visible at `target`.
    fn is_mounted(&self, target: &Path) -> Result<bool>;

    /// The filesystem type of the mount visible at `target`; `None` when
    /// `target` is not a mount point.
    fn get_filesystem_type(&self, target: &Path) -> Result<Option<String>>;

    /// Whether the mount visible at `target` is mounted read-only.
    ///
    /// NAILS keeps the hidden volume writable (the overlay uppers live on it), so
    /// a read-only hidden root is how a backend failure shows up: on an I/O error
    /// the kernel remounts the filesystem read-only while its dentry cache still
    /// answers directory reads, so a cache-served `list_directory` keeps
    /// succeeding. The backend watcher reads this to notice a device that failed in
    /// place. Defaults to `false` (writable) for filesystems that do not track
    /// per-mount flags.
    fn is_mount_read_only(&self, _target: &Path) -> Result<bool> {
        Ok(false)
    }

    /// Identify the device, device-mapper name and filesystem label backing the
    /// mount visible at `mount_point`.
    ///
    /// Returns `Ok(None)` when `mount_point` is not itself a mount point. This is
    /// a read-only query used to warn about names that hint at hidden storage; a
    /// missing optional attribute (no dm layer, no label) is left `None` rather
    /// than reported as an error.
    fn mount_source(&self, mount_point: &Path) -> Result<Option<MountSource>>;

    // ------------------------------------------------------------------------
    // File System Operations
    // ------------------------------------------------------------------------

    /// Check if a path exists.
    fn path_exists(&self, path: &Path) -> Result<bool>;

    /// Check if a path is a directory.
    fn is_directory(&self, path: &Path) -> Result<bool>;

    /// The id of the device that holds `path` (the `st_dev` of its inode).
    ///
    /// Two paths share a device id only when they sit on the same mounted
    /// filesystem. The attach gate ([`crate::hidden_root::HiddenRoot::assess`])
    /// compares the hidden root against `/` as a backstop, after the mount
    /// table has shown a volume mounted there.
    fn device_id(&self, path: &Path) -> Result<u64>;

    /// The device (`st_dev`) of the file the loop device `node` is bound to,
    /// as the loop driver recorded it when the file was attached
    /// (`LOOP_GET_STATUS64`'s `lo_device`).
    ///
    /// The path in `loop/backing_file` is only a name: a filesystem mounted
    /// over a folder on that path later leads a lookup elsewhere. The device
    /// is what the file is really on. Reading it opens the device node, which
    /// most systems let only root and the `disk` group do.
    fn loop_backing_device(&self, node: &Path) -> Result<u64>;

    /// Check if a path is a symbolic link.
    fn is_symlink(&self, path: &Path) -> Result<bool>;

    /// Resolve every symlink in `path` and return the absolute result, like
    /// `realpath(3)`.
    ///
    /// Fails with an `IoError` of kind `NotFound` when a component does not
    /// exist, so callers that resolve paths created later can walk up to the
    /// deepest existing ancestor.
    fn canonicalize(&self, path: &Path) -> Result<PathBuf>;

    /// Create a symbolic link at `link` pointing to `target` (idempotent).
    fn create_symlink(&self, target: &Path, link: &Path) -> Result<()>;

    /// Get total and available space for the filesystem holding `path`.
    ///
    /// Both figures come from one `statvfs` call, so callers that need free
    /// space and callers that report usage share a single syscall and never
    /// walk the tree.
    fn disk_usage(&self, path: &Path) -> Result<DiskUsage>;

    /// Create a directory (and parents).
    fn create_directory(&self, path: &Path) -> Result<()>;

    /// Create `relative` and any missing parents, resolved strictly beneath
    /// `hidden_root`.
    ///
    /// This is the symlink- and traversal-safe way to create directories *on the
    /// hidden volume*. Unlike [`create_directory`](Self::create_directory), which
    /// takes an absolute path and follows symlinks the way `std::fs` does, a
    /// symlink or `..` planted under `hidden_root` cannot redirect the creation
    /// outside it. The default implementation joins the paths and defers to
    /// [`create_directory`](Self::create_directory) for the in-memory test
    /// double; the real filesystem overrides it with an `openat2` resolution
    /// (see [`crate::filesystem::SafeRoot`]) that fails closed on a kernel
    /// without `openat2`.
    fn create_hidden_dir_all(&self, hidden_root: &Path, relative: &Path) -> Result<()> {
        self.create_directory(&hidden_root.join(relative))
    }

    /// Atomically write `content` to `relative`, resolved strictly beneath
    /// `hidden_root`, with the given permission `mode`.
    ///
    /// This is the symlink- and traversal-safe way to write a file *on the hidden
    /// volume*. Unlike [`write_file_content`](Self::write_file_content), which
    /// takes an absolute path and follows a symlink planted at the final
    /// component, a symlink or `..` planted under `hidden_root` cannot redirect
    /// the write outside it. The default implementation joins the paths and
    /// defers to [`write_file_content`](Self::write_file_content) for the
    /// in-memory test double; the real filesystem overrides it with an `openat2`
    /// resolution (see [`crate::filesystem::SafeRoot`]) that fails closed on a
    /// kernel without `openat2`. The default drops `mode`, which the mock does not
    /// track.
    fn write_hidden_file_atomic(
        &self,
        hidden_root: &Path,
        relative: &Path,
        content: &str,
        mode: u32,
    ) -> Result<()> {
        let _ = mode;
        self.write_file_content(&hidden_root.join(relative), content)
    }

    /// Set Unix permissions on a path.
    fn set_permissions(&self, path: &Path, mode: u32) -> Result<()>;

    /// Get Unix permissions on a path (masked to 0o7777).
    fn get_permissions(&self, path: &Path) -> Result<u32>;

    /// Check if a path is readable.
    fn is_readable(&self, path: &Path) -> Result<bool>;

    /// Check if a path is writable.
    fn is_writable(&self, path: &Path) -> Result<bool>;

    // ------------------------------------------------------------------------
    // Process and File Reading Operations (for verify command)
    // ------------------------------------------------------------------------

    /// Enumerate the running processes whose command line references NAILS,
    /// classified by match strength (see [`ProcessMatch`]).
    ///
    /// The caller's own process and its ancestors are excluded.
    fn nails_process_matches(&self) -> Result<Vec<ProcessMatch>>;

    /// Read the contents of a text file.
    fn read_file_content(&self, path: &Path) -> Result<String>;

    /// Find files matching a pattern in a directory (recursive).
    fn find_files_with_pattern(&self, dir: &Path, pattern: &str) -> Result<Vec<PathBuf>>;

    /// Recursively find files matching a pattern, tolerating directories that
    /// cannot be read.
    ///
    /// Behaves like [`find_files_with_pattern`](Self::find_files_with_pattern)
    /// but, instead of aborting on a directory that returns `EACCES`, records it
    /// in [`PatternScan::unreadable`] and continues. The default implementation
    /// delegates to [`find_files_with_pattern`](Self::find_files_with_pattern)
    /// and reports nothing unreadable, so an implementation that cannot tell the
    /// difference degrades gracefully.
    fn scan_files_with_pattern(&self, dir: &Path, pattern: &str) -> Result<PatternScan> {
        Ok(PatternScan {
            matches: self.find_files_with_pattern(dir, pattern)?,
            unreadable: Vec::new(),
        })
    }

    /// Write content to a file atomically (write to temp, then rename).
    fn write_file_content(&self, path: &Path, content: &str) -> Result<()>;

    /// Write a file on behalf of an unprivileged user with symlink-safe opens
    /// and correct numeric ownership.
    ///
    /// This is the write to use for any file NAILS creates inside a user-owned,
    /// overlaid home path (shell rc files, the XDG autostart entry, and similar).
    /// Unlike [`write_file_content`](Self::write_file_content) it never opens a
    /// predictable sibling temp name, never follows a symlink at the destination
    /// or in its parent chain, and leaves the result owned by the target user
    /// rather than root.
    ///
    /// Contract:
    ///
    /// * Missing parent directories are created and owned by `user`.
    /// * A **new** file is created with `user`'s numeric uid/gid and
    ///   `default_mode` (e.g. `0o600` or `0o644`).
    /// * An **existing** file keeps its current owner and mode; only its content
    ///   is replaced.
    /// * The write is atomic (unique temp opened `O_CREAT | O_EXCL | O_NOFOLLOW`
    ///   relative to a directory fd resolved with the symlinks-disallowed flags,
    ///   then renamed over the destination), so a pre-planted `<path>.tmp` or a
    ///   symlinked parent cannot redirect it (CWE-59).
    /// * An ownership failure is surfaced as an error, never silently ignored.
    fn write_user_file(
        &self,
        path: &Path,
        content: &str,
        user: &TargetUser,
        default_mode: u32,
    ) -> Result<()>;

    /// Overwrite an existing file's contents in place, on the SAME inode.
    ///
    /// Unlike [`write_file_content`](Self::write_file_content) and
    /// [`write_user_file`](Self::write_user_file), which stage a temporary file
    /// and rename it over the destination, this opens the existing file
    /// `O_RDWR | O_NOFOLLOW`, truncates it, and rewrites it. The inode number,
    /// owner and mode are preserved, so no new inode is allocated and the removed
    /// lines are not left behind in the old inode's freed blocks under a fresh
    /// name.
    ///
    /// This is the write used for the opt-in decoy history edit, where leaving the
    /// pre-edit content recoverable in freed blocks (the temp+rename failure mode)
    /// matters more than crash atomicity. The trade-off is explicit: a crash
    /// part-way through can leave a truncated file, because there is no atomic
    /// rename to fall back on.
    ///
    /// The file must already exist; a missing file is an error (callers resolve
    /// and existence-check the path first). A symlink at the path is refused
    /// (`O_NOFOLLOW`).
    fn overwrite_file_in_place(&self, path: &Path, content: &str) -> Result<()>;

    // ------------------------------------------------------------------------
    // Directory Listing Operations (Log Cleanup)
    // ------------------------------------------------------------------------

    /// List files and directories in a directory (non-recursive).
    fn list_directory(&self, dir: &Path) -> Result<Vec<PathBuf>>;

    // ------------------------------------------------------------------------
    // File Size and Rename Operations (Log Rotation)
    // ------------------------------------------------------------------------

    /// Get the size of a file in bytes.
    fn file_size(&self, path: &Path) -> Result<u64>;

    /// Rename a file atomically. Overwrites destination if it exists.
    fn rename_file(&self, from: &Path, to: &Path) -> Result<()>;

    // ------------------------------------------------------------------------
    // File Removal Operations (Temporary Files Cleanup)
    // ------------------------------------------------------------------------

    /// Remove a single file.
    fn remove_file(&self, path: &Path) -> Result<()>;

    /// Remove an empty directory.
    fn remove_directory(&self, path: &Path) -> Result<()>;

    /// Remove a directory and all its contents recursively.
    fn remove_dir_all(&self, path: &Path) -> Result<()>;

    // ------------------------------------------------------------------------
    // Secure Deletion Operations (Anti-forensics)
    // ------------------------------------------------------------------------

    /// Securely delete a file (overwrite zeros, random, zeros, then remove).
    fn secure_delete(&self, path: &Path) -> Result<()>;

    /// Securely delete a directory and all contents recursively.
    fn secure_delete_dir_all(&self, path: &Path) -> Result<()>;

    // ------------------------------------------------------------------------
    // Directory Operations (Log Rotation)
    // ------------------------------------------------------------------------

    /// Check if a directory's filesystem supports symbolic links.
    fn supports_symlinks(&self, dir: &Path) -> Result<bool>;

    /// Get the modification time of a file.
    fn modified_time(&self, path: &Path) -> Result<std::time::SystemTime>;

    // ------------------------------------------------------------------------
    // Copy Operations
    // ------------------------------------------------------------------------

    /// Recursively copy a directory tree preserving all attributes.
    fn copy_tree(&self, src: &Path, dst: &Path) -> Result<()>;

    /// Copy a single regular file's bytes from `src` to `dst`, replacing `dst`.
    ///
    /// Unlike [`write_file_content`](Self::write_file_content) this copies raw
    /// bytes, so it is the right call for a binary (the running executable copied
    /// into the runtime directory). The caller sets the mode afterwards with
    /// [`set_permissions`](Self::set_permissions); the copy itself makes no
    /// promise about the destination mode.
    fn copy_file(&self, src: &Path, dst: &Path) -> Result<()>;
}
