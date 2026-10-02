//! Filesystem trait definition and helper functions

mod helpers;

pub use helpers::verify_mount_preconditions;

use crate::Result;
use crate::target_user::TargetUser;
use std::path::{Path, PathBuf};

use super::MountInfo;

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
///
/// # Implementation Notes
///
/// Operations should be **idempotent** where possible:
/// - `unmount()` succeeds even if not mounted (no-op)
pub trait Filesystem: Send + Sync + Clone {
    // ------------------------------------------------------------------------
    // Overlay Mount Operations (Core Functionality)
    // ------------------------------------------------------------------------

    /// Mount an overlay filesystem combining lower, upper, and work directories.
    ///
    /// * `lower` - Read-only base layers (first element is primary, rest are extra
    ///   lower layers; overlayfs stacks them left-to-right)
    /// * `upper` - Writeable upper layer (typically in hidden volume)
    /// * `work` - Work directory for overlay metadata
    /// * `target` - Mount point where overlay appears
    fn mount_overlay(
        &self,
        lower: &[&Path],
        upper: &Path,
        work: &Path,
        target: &Path,
    ) -> Result<()>;

    /// Unmount an overlay filesystem (idempotent).
    ///
    /// * `target` - Mount point to unmount
    /// * `force` - If true, use MNT_FORCE | MNT_DETACH
    ///
    /// Unmounting a path NAILS did not mount is refused with
    /// [`NailsError::RefusedUnmanagedUnmount`](crate::NailsError::RefusedUnmanagedUnmount)
    /// before any syscall, so the force escalation can never detach a host
    /// filesystem that stale state wrongly points at.
    fn unmount(&self, target: &Path, force: bool) -> Result<()>;

    /// Check if a path is currently mounted.
    fn is_mounted(&self, target: &Path) -> Result<bool>;

    /// Get the filesystem type at a mount point. Returns `None` if not a mount point.
    fn get_filesystem_type(&self, target: &Path) -> Result<Option<String>>;

    /// Check if a path has an overlayfs mount (not other mount types).
    fn is_overlay_mounted(&self, target: &Path) -> Result<bool>;

    /// Get mount info for a currently mounted overlay.
    ///
    /// Retrieves mount metadata (lower, upper, work, target paths) for rollback support.
    fn get_mount_info(&self, target: &Path) -> Option<MountInfo>;

    /// Identify the device, device-mapper name and filesystem label backing the
    /// mount at `mount_point`.
    ///
    /// Returns `Ok(None)` when `mount_point` is not itself a mount point. This is
    /// a read-only query used to warn about names that hint at hidden storage; a
    /// missing optional attribute (no dm layer, no label) is left `None` rather
    /// than reported as an error.
    fn mount_source(&self, mount_point: &Path) -> Result<Option<MountSource>>;

    /// Classify the NAILS-created mounts currently live, from the mount table
    /// rather than any state file.
    ///
    /// This is the enumeration an emergency (or future recover) teardown falls
    /// back to when the state file is corrupt or unreadable: it must tear down
    /// the overlays NAILS actually mounted even though it can no longer trust the
    /// recorded list. `hidden_root` distinguishes persistent overlays from
    /// foreign ones exactly as in
    /// [`NailsMounts::discover`](crate::filesystem::NailsMounts::discover).
    fn discover_nails_mounts(
        &self,
        hidden_root: Option<&Path>,
    ) -> Result<crate::filesystem::NailsMounts>;

    // ------------------------------------------------------------------------
    // Swap Management
    // ------------------------------------------------------------------------

    /// Check if swap is enabled.
    fn swap_is_enabled(&self) -> Result<bool>;

    // ------------------------------------------------------------------------
    // Bind Mount Operations (Pivot Mount Strategy)
    // ------------------------------------------------------------------------

    /// Bind mount a source path to a target path.
    ///
    /// Creates a VFS entry making content at `source` appear at `target`.
    /// Used in pivot mount strategy for overlaying active directories like `/var`.
    fn bind_mount(&self, source: &Path, target: &Path) -> Result<()>;

    /// Unmount a bind mount from target (idempotent).
    fn unmount_bind(&self, target: &Path) -> Result<()>;

    // ------------------------------------------------------------------------
    // Tmpfs Operations (Story 4.11: Extended Overlay Strategy)
    // ------------------------------------------------------------------------

    /// Mount a tmpfs filesystem at target with specified size.
    ///
    /// Creates a RAM-backed temporary filesystem for ephemeral overlay layers.
    /// Mounted with MS_NOSUID | MS_NODEV flags.
    fn mount_tmpfs(&self, target: &Path, size: &str) -> Result<()>;

    /// Unmount a tmpfs filesystem (idempotent). Destroys all data.
    fn unmount_tmpfs(&self, target: &Path) -> Result<()>;

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
    /// filesystem, so comparing a candidate hidden root against `/` tells the
    /// attach gate ([`crate::hidden_root::HiddenRoot::verify_attached`]) whether
    /// anything is actually mounted at that path: an unmounted mount point still
    /// reports its parent's device, a mounted volume reports its own.
    fn device_id(&self, path: &Path) -> Result<u64>;

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

    /// Check if any NAILS-related processes are currently running.
    fn nails_process_running(&self) -> Result<bool>;

    /// Read the contents of a text file.
    fn read_file_content(&self, path: &Path) -> Result<String>;

    /// Find files matching a pattern in a directory (recursive).
    fn find_files_with_pattern(&self, dir: &Path, pattern: &str) -> Result<Vec<PathBuf>>;

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

    // ------------------------------------------------------------------------
    // Directory Listing Operations (Story 5.4: Log Cleanup)
    // ------------------------------------------------------------------------

    /// List files and directories in a directory (non-recursive).
    fn list_directory(&self, dir: &Path) -> Result<Vec<PathBuf>>;

    /// Enumerate all top-level real directories under `/` (sorted alphabetically).
    ///
    /// Returns only real directories (not symlinks, not files). Used for dynamic
    /// overlay enumeration when `overlay_mode: auto` is configured (Story 14.10).
    fn enumerate_root_directories(&self) -> Result<Vec<PathBuf>>;

    // ------------------------------------------------------------------------
    // File Size and Rename Operations (Story 9.2: Log Rotation)
    // ------------------------------------------------------------------------

    /// Get the size of a file in bytes.
    fn file_size(&self, path: &Path) -> Result<u64>;

    /// Rename a file atomically. Overwrites destination if it exists.
    fn rename_file(&self, from: &Path, to: &Path) -> Result<()>;

    // ------------------------------------------------------------------------
    // File Removal Operations (Story 5.3: Temporary Files Cleanup)
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
    // Directory Operations (Story 9.x: Log Rotation)
    // ------------------------------------------------------------------------

    /// Check if a directory's filesystem supports symbolic links.
    fn supports_symlinks(&self, dir: &Path) -> Result<bool>;

    /// Get the modification time of a file.
    fn modified_time(&self, path: &Path) -> Result<std::time::SystemTime>;

    // ------------------------------------------------------------------------
    // Directory Copy and Size Operations (Snapshot Pivot Strategy)
    // ------------------------------------------------------------------------

    /// Recursively copy a directory tree preserving all attributes.
    fn copy_tree(&self, src: &Path, dst: &Path) -> Result<()>;

    /// Get the total size of a directory's contents in bytes.
    fn get_directory_size(&self, path: &Path) -> Result<u64>;

    // ------------------------------------------------------------------------
    // Submount Source Detection (Multi-Lower-Layer Overlayfs)
    // ------------------------------------------------------------------------

    /// Find bind mount sources for submounts within a target directory.
    ///
    /// Returns `(mount_point, source_path)` pairs for bind mounts nested within
    /// `target`. Used to compute extra lower layers for overlayfs.
    fn find_submount_sources(&self, target: &Path) -> Result<Vec<(PathBuf, PathBuf)>>;
}
