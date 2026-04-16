//! Filesystem trait definition and helper functions

mod helpers;

pub use helpers::verify_mount_preconditions;

use crate::Result;
use std::path::{Path, PathBuf};

use super::MountInfo;

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
/// - `swap_disable()` succeeds even if already disabled (no-op)
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

    // ------------------------------------------------------------------------
    // Swap Management
    // ------------------------------------------------------------------------

    /// Check if swap is enabled.
    fn swap_is_enabled(&self) -> Result<bool>;

    /// Disable swap (idempotent).
    fn swap_disable(&self) -> Result<()>;

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

    /// Check if a path is a symbolic link.
    fn is_symlink(&self, path: &Path) -> Result<bool>;

    /// Create a symbolic link at `link` pointing to `target` (idempotent).
    fn create_symlink(&self, target: &Path, link: &Path) -> Result<()>;

    /// Get free space in bytes for a filesystem path.
    fn get_free_space(&self, path: &Path) -> Result<u64>;

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
    // NixOS Profile Operations (Lazy Build Pattern)
    // ------------------------------------------------------------------------

    /// Check if a NixOS profile exists.
    fn nixos_profile_exists(&self, profile: &str) -> Result<bool>;

    /// Build a NixOS profile.
    fn nixos_build_profile(&self, profile: &str) -> Result<()>;

    /// Switch to a NixOS profile.
    fn nixos_switch_profile(&self, profile: &str) -> Result<()>;

    /// Get the current NixOS profile.
    fn nixos_get_current_profile(&self) -> Result<String>;

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

    /// Read the contents of a directory as DirEntry items.
    fn read_directory(&self, path: &Path) -> Result<Vec<std::fs::DirEntry>>;

    /// Check if a directory's filesystem supports symbolic links.
    fn supports_symlinks(&self, dir: &Path) -> Result<bool>;

    /// Get the modification time of a file.
    fn modified_time(&self, path: &Path) -> Result<chrono::DateTime<chrono::Utc>>;

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
