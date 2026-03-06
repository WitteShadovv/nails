//! Filesystem abstraction for testing and production
//!
//! The Filesystem trait enables 99% of tests to run without root privileges:
//! - **Production:** RealFilesystem uses actual syscalls (requires root)
//! - **Testing:** MockFilesystem uses in-memory state (no root needed)
//!
//! # Architecture
//!
//! This trait abstraction is foundational to the entire NAILS testing strategy.
//! By abstracting all filesystem operations behind a trait boundary, we can:
//! - Run tests in parallel without root privileges
//! - Test error conditions that are hard to trigger with real syscalls
//! - Achieve fast CI/CD pipelines (seconds, not minutes)
//! - Maintain type safety with Send + Sync + Clone bounds
//!
//! # Example
//!
//! ```rust
//! use nails_core::filesystem::{Filesystem, MockFilesystem};
//! use std::path::Path;
//!
//! // Testing: No root required
//! let fs = MockFilesystem::new();
//!
//! // Set up paths to exist
//! fs.mock_set_path_exists("/", true);
//! fs.mock_set_path_exists("/mnt/hidden/upper", true);
//! fs.mock_set_path_exists("/mnt/hidden/work", true);
//!
//! let result = fs.mount_overlay(
//!     Path::new("/"),
//!     Path::new("/mnt/hidden/upper"),
//!     Path::new("/mnt/hidden/work"),
//!     Path::new("/home")
//! );
//! assert!(result.is_ok());
//! ```

use crate::{NailsError, Result};
use std::path::{Path, PathBuf};

// Submodules
pub mod mock;
pub mod mount_info;
pub mod real;

// Re-exports
pub use mock::{MockFilesystem, MockOp};
pub use mount_info::MountInfo;
pub use real::RealFilesystem;

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

    /// Mount an overlay filesystem
    ///
    /// Combines lower, upper, and work directories into a single overlay at target.
    ///
    /// # Arguments
    ///
    /// * `lower` - Read-only base layer (typically the base system)
    /// * `upper` - Writeable upper layer (typically in hidden volume)
    /// * `work` - Work directory for overlay metadata
    /// * `target` - Mount point where overlay appears
    ///
    /// # Errors
    ///
    /// Returns `NailsError::AlreadyMounted` if target is already mounted.
    /// Returns `NailsError::OverlayError` if mount operation fails.
    fn mount_overlay(&self, lower: &Path, upper: &Path, work: &Path, target: &Path) -> Result<()>;

    /// Unmount an overlay filesystem
    ///
    /// # Arguments
    ///
    /// * `target` - Mount point to unmount
    /// * `force` - If true, override busy check and force unmount
    ///
    /// # Idempotent
    ///
    /// Succeeds even if target is not currently mounted (no-op).
    ///
    /// # Errors
    ///
    /// Returns `NailsError::MountBusy` if target is busy and force=false.
    /// Returns `NailsError::UnmountError` if unmount fails.
    fn unmount(&self, target: &Path, force: bool) -> Result<()>;

    /// Check if a path is currently mounted
    ///
    /// # Arguments
    ///
    /// * `target` - Path to check
    ///
    /// # Returns
    ///
    /// `Ok(true)` if mounted, `Ok(false)` if not mounted.
    fn is_mounted(&self, target: &Path) -> Result<bool>;

    /// Get mount info for a currently mounted overlay
    ///
    /// Retrieves the mount metadata (lower, upper, work, target paths) for an overlay
    /// that was previously mounted via `mount_overlay()`. This is used during rollback
    /// to remount overlays that were unmounted during a failed deactivation.
    ///
    /// # Arguments
    ///
    /// * `target` - Path of the mounted overlay
    ///
    /// # Returns
    ///
    /// `Some(MountInfo)` if the overlay is tracked, `None` if not found.
    ///
    /// # Requirements
    ///
    /// - AC6: Partial unmount rollback (remount requires mount info)
    /// - AC9: rollback_on_unmount_failure() needs mount metadata
    /// - FR51: Remount overlays if cleanup fails
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::filesystem::{Filesystem, MockFilesystem};
    /// use std::path::Path;
    ///
    /// let fs = MockFilesystem::new();
    /// fs.mock_set_path_exists("/", true);
    /// fs.mock_set_path_exists("/mnt/hidden/upper", true);
    /// fs.mock_set_path_exists("/mnt/hidden/work", true);
    /// fs.mock_set_path_exists("/home", true);
    /// fs.mock_set_path_type("/", "directory");
    /// fs.mock_set_path_type("/mnt/hidden/upper", "directory");
    /// fs.mock_set_path_type("/mnt/hidden/work", "directory");
    /// fs.mock_set_path_type("/home", "directory");
    /// fs.mock_set_writable("/mnt/hidden/upper", true);
    /// fs.mock_set_writable("/mnt/hidden/work", true);
    ///
    /// fs.mount_overlay(
    ///     Path::new("/"),
    ///     Path::new("/mnt/hidden/upper"),
    ///     Path::new("/mnt/hidden/work"),
    ///     Path::new("/home")
    /// ).unwrap();
    ///
    /// let info = fs.get_mount_info(Path::new("/home"));
    /// assert!(info.is_some());
    /// ```
    fn get_mount_info(&self, target: &Path) -> Option<MountInfo>;

    // ------------------------------------------------------------------------
    // Swap Management
    // ------------------------------------------------------------------------

    /// Check if swap is enabled
    ///
    /// # Returns
    ///
    /// `Ok(true)` if swap is enabled, `Ok(false)` if disabled.
    fn swap_is_enabled(&self) -> Result<bool>;

    /// Disable swap
    ///
    /// # Idempotent
    ///
    /// Succeeds even if swap is already disabled (no-op).
    ///
    /// # Errors
    ///
    /// Returns `NailsError::SwapDisableFailed` if disable fails.
    fn swap_disable(&self) -> Result<()>;

    // ------------------------------------------------------------------------
    // Bind Mount Operations (Pivot Mount Strategy)
    // ------------------------------------------------------------------------

    /// Bind mount a source path to a target path
    ///
    /// Creates a VFS entry that makes the content at `source` appear at `target`.
    /// The original content at `target` becomes "hidden" but still exists.
    /// New accesses to `target` see the source content.
    ///
    /// # Arguments
    ///
    /// * `source` - Path to bind from (e.g., "/mnt/nails-pivot/var")
    /// * `target` - Path to bind to (e.g., "/var")
    ///
    /// # Use Case
    ///
    /// Used in pivot mount strategy for overlaying active directories like `/var`:
    /// 1. Mount overlay to staging location (always succeeds)
    /// 2. Bind mount staging to target (handles active-use cases)
    ///
    /// # Process Impact
    ///
    /// - Existing file descriptors continue to reference original content
    /// - Processes with cwd in target keep their original reference
    /// - NEW path resolutions through target see the bound content
    /// - This "split view" is forensically beneficial
    ///
    /// # Errors
    ///
    /// Returns `NailsError::OverlayError` if bind mount fails.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::filesystem::{Filesystem, MockFilesystem};
    /// use std::path::Path;
    ///
    /// let fs = MockFilesystem::new();
    /// fs.mock_set_path_exists("/mnt/nails-pivot/var", true);
    /// fs.mock_set_path_exists("/var", true);
    ///
    /// let result = fs.bind_mount(
    ///     Path::new("/mnt/nails-pivot/var"),
    ///     Path::new("/var")
    /// );
    /// assert!(result.is_ok());
    /// ```
    fn bind_mount(&self, source: &Path, target: &Path) -> Result<()>;

    /// Unmount a bind mount from target
    ///
    /// # Arguments
    ///
    /// * `target` - Bind mount point to unmount
    ///
    /// # Idempotent
    ///
    /// Succeeds even if target is not currently mounted (no-op).
    ///
    /// # Errors
    ///
    /// Returns `NailsError::UnmountError` if unmount fails.
    fn unmount_bind(&self, target: &Path) -> Result<()>;

    // ------------------------------------------------------------------------
    // Tmpfs Operations (Story 4.11: Extended Overlay Strategy)
    // ------------------------------------------------------------------------

    /// Mount a tmpfs filesystem at target with specified size
    ///
    /// Creates a RAM-backed temporary filesystem for ephemeral overlay layers.
    /// Used in extended overlay strategy (Story 4.11) to store runtime artifacts
    /// in RAM for forensic safety.
    ///
    /// # Arguments
    ///
    /// * `target` - Directory where tmpfs will be mounted
    /// * `size` - Maximum tmpfs size (e.g., "1G", "512M")
    ///
    /// # Security
    ///
    /// - Mounted with MS_NOSUID | MS_NODEV flags
    /// - Data destroyed immediately on unmount
    /// - No disk writes, only RAM storage
    ///
    /// # Errors
    ///
    /// Returns `NailsError::OverlayError` if mount fails.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::filesystem::{Filesystem, MockFilesystem};
    /// use std::path::Path;
    ///
    /// let fs = MockFilesystem::new();
    /// fs.mock_set_path_exists("/run/nails/var-upper", true);
    ///
    /// let result = fs.mount_tmpfs(Path::new("/run/nails/var-upper"), "1G");
    /// assert!(result.is_ok());
    /// ```
    fn mount_tmpfs(&self, target: &Path, size: &str) -> Result<()>;

    /// Unmount a tmpfs filesystem from target
    ///
    /// Destroys all data in the tmpfs (RAM-backed storage is lost).
    ///
    /// # Arguments
    ///
    /// * `target` - Mount point to unmount
    ///
    /// # Idempotent
    ///
    /// Succeeds even if target is not currently mounted (no-op).
    ///
    /// # Errors
    ///
    /// Returns `NailsError::UnmountError` if unmount fails.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::filesystem::{Filesystem, MockFilesystem};
    /// use std::path::Path;
    ///
    /// let fs = MockFilesystem::new();
    /// fs.mock_set_path_exists("/run/nails/var-upper", true);
    /// fs.mount_tmpfs(Path::new("/run/nails/var-upper"), "1G").unwrap();
    ///
    /// let result = fs.unmount_tmpfs(Path::new("/run/nails/var-upper"));
    /// assert!(result.is_ok());
    /// ```
    fn unmount_tmpfs(&self, target: &Path) -> Result<()>;

    // ------------------------------------------------------------------------
    // File System Operations
    // ------------------------------------------------------------------------

    /// Check if a path exists
    ///
    /// # Arguments
    ///
    /// * `path` - Path to check
    fn path_exists(&self, path: &Path) -> Result<bool>;

    /// Check if a path is a directory
    ///
    /// # Arguments
    ///
    /// * `path` - Path to check
    fn is_directory(&self, path: &Path) -> Result<bool>;

    /// Check if a path is a symbolic link
    ///
    /// # Arguments
    ///
    /// * `path` - Path to check
    ///
    /// # Returns
    ///
    /// `Ok(true)` if path is a symlink, `Ok(false)` otherwise.
    ///
    /// # Security
    ///
    /// Used to prevent bypassing hidden volume validation via symlink attacks.
    /// An attacker could create a symlink from hidden volume to external
    /// location to redirect logs outside hidden volume.
    fn is_symlink(&self, path: &Path) -> Result<bool>;

    /// Create a symbolic link
    ///
    /// Creates a symlink at `link` pointing to `target`.
    /// Idempotent: if the symlink already exists and points to the same target,
    /// this is a no-op. If a file/symlink already exists at `link` pointing
    /// elsewhere, returns an error.
    ///
    /// # Arguments
    ///
    /// * `target` - Path the symlink should point to
    /// * `link` - Path where the symlink will be created
    ///
    /// # Errors
    ///
    /// Returns `NailsError::IoError` if the symlink cannot be created.
    fn create_symlink(&self, target: &Path, link: &Path) -> Result<()>;

    /// Get free space in bytes for a filesystem path
    ///
    /// # Arguments
    ///
    /// * `path` - Path to query (any path on the filesystem)
    ///
    /// # Returns
    ///
    /// Free space in bytes.
    fn get_free_space(&self, path: &Path) -> Result<u64>;

    /// Create a directory
    ///
    /// # Arguments
    ///
    /// * `path` - Directory path to create
    ///
    /// # Errors
    ///
    /// Returns `NailsError::PermissionDenied` if parent is not writable.
    fn create_directory(&self, path: &Path) -> Result<()>;

    /// Set Unix permissions on a path
    ///
    /// # Arguments
    ///
    /// * `path` - Path to set permissions on
    /// * `mode` - Unix permission mode (e.g., 0o700)
    ///
    /// # Errors
    ///
    /// Returns error if path doesn't exist or permissions cannot be set.
    fn set_permissions(&self, path: &Path, mode: u32) -> Result<()>;

    /// Get Unix permissions on a path
    ///
    /// # Arguments
    ///
    /// * `path` - Path to read permissions from
    ///
    /// # Errors
    ///
    /// Returns error if path doesn't exist or permissions cannot be read.
    fn get_permissions(&self, path: &Path) -> Result<u32>;

    /// Check if a path is readable
    ///
    /// # Arguments
    ///
    /// * `path` - Path to check
    fn is_readable(&self, path: &Path) -> Result<bool>;

    /// Check if a path is writable
    ///
    /// # Arguments
    ///
    /// * `path` - Path to check
    fn is_writable(&self, path: &Path) -> Result<bool>;

    // ------------------------------------------------------------------------
    // NixOS Profile Operations (Lazy Build Pattern)
    // ------------------------------------------------------------------------

    /// Check if a NixOS profile exists
    ///
    /// # Arguments
    ///
    /// * `profile` - Profile name (e.g., "nails-active")
    fn nixos_profile_exists(&self, profile: &str) -> Result<bool>;

    /// Build a NixOS profile
    ///
    /// # Arguments
    ///
    /// * `profile` - Profile name to build
    ///
    /// # Errors
    ///
    /// Returns `NailsError::NixOSBuildFailed` if build fails.
    fn nixos_build_profile(&self, profile: &str) -> Result<()>;

    /// Switch to a NixOS profile
    ///
    /// # Arguments
    ///
    /// * `profile` - Profile name to switch to
    ///
    /// # Errors
    ///
    /// Returns `NailsError::NixOSProfileNotFound` if profile doesn't exist.
    /// Returns `NailsError::NixOSSwitchFailed` if switch fails.
    fn nixos_switch_profile(&self, profile: &str) -> Result<()>;

    /// Get the current NixOS profile
    ///
    /// # Returns
    ///
    /// Current profile name.
    fn nixos_get_current_profile(&self) -> Result<String>;

    // ------------------------------------------------------------------------
    // Process and File Reading Operations (for verify command)
    // ------------------------------------------------------------------------

    /// Check if any NAILS-related processes are currently running
    ///
    /// Scans process list to detect if nails binaries or commands are active.
    ///
    /// # Returns
    ///
    /// `Ok(true)` if nails processes found, `Ok(false)` otherwise.
    fn nails_process_running(&self) -> Result<bool>;

    /// Read the contents of a text file
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the file to read
    ///
    /// # Returns
    ///
    /// File contents as a string.
    ///
    /// # Errors
    ///
    /// Returns `NailsError::IoError` if file cannot be read.
    fn read_file_content(&self, path: &Path) -> Result<String>;

    /// Check if a directory contains any files matching a pattern
    ///
    /// Recursively scans directory for files with names containing the pattern.
    ///
    /// # Arguments
    ///
    /// * `dir` - Directory to scan
    /// * `pattern` - Pattern to match in filenames
    ///
    /// # Returns
    ///
    /// List of matching file paths found.
    fn find_files_with_pattern(&self, dir: &Path, pattern: &str) -> Result<Vec<PathBuf>>;

    /// Write content to a file atomically
    ///
    /// Writes content to a temporary file first, then renames to target.
    /// Preserves file permissions if target exists.
    ///
    /// # Arguments
    ///
    /// * `path` - Target file path
    /// * `content` - Content to write
    ///
    /// # Errors
    ///
    /// Returns `NailsError::IoError` if write fails.
    /// Returns `NailsError::PermissionDenied` if target is not writable.
    fn write_file_content(&self, path: &Path, content: &str) -> Result<()>;

    // ------------------------------------------------------------------------
    // Directory Listing Operations (Story 5.4: Log Cleanup)
    // ------------------------------------------------------------------------

    /// List files and directories in a directory
    ///
    /// Returns paths to all entries in the directory (files and subdirectories).
    /// Does NOT recursively descend into subdirectories.
    ///
    /// # Arguments
    ///
    /// * `dir` - Directory path to list
    ///
    /// # Returns
    ///
    /// Vec of PathBuf for each entry in the directory.
    ///
    /// # Errors
    ///
    /// Returns `NailsError::IoError` if directory doesn't exist or can't be read.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use nails_core::filesystem::{Filesystem, MockFilesystem};
    /// use std::path::Path;
    ///
    /// let fs = MockFilesystem::new();
    /// fs.mock_set_directory_contents(
    ///     &PathBuf::from("/mnt/hidden/logs"),
    ///     vec![
    ///         PathBuf::from("/mnt/hidden/logs/nails.log"),
    ///         PathBuf::from("/mnt/hidden/logs/nails.log.1"),
    ///     ]
    /// );
    ///
    /// let entries = fs.list_directory(Path::new("/mnt/hidden/logs")).unwrap();
    /// assert_eq!(entries.len(), 2);
    /// ```
    fn list_directory(&self, dir: &Path) -> Result<Vec<PathBuf>>;

    /// Enumerate all top-level directories under `/` (Story 14.10)
    ///
    /// Returns only real directories (not symlinks, not files) from the root directory,
    /// sorted alphabetically for consistent mount order. Used for dynamic overlay
    /// enumeration when `overlay_mode: auto` is configured.
    ///
    /// # Returns
    ///
    /// Vec of PathBuf containing all real directories under `/`, sorted alphabetically.
    /// Symlinks (even if they point to directories) are excluded.
    ///
    /// # Errors
    ///
    /// Returns `NailsError::FilesystemError` if root directory cannot be read.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use nails_core::filesystem::{Filesystem, MockFilesystem};
    /// use std::path::PathBuf;
    ///
    /// let fs = MockFilesystem::new();
    /// fs.mock_set_root_directories(vec![
    ///     PathBuf::from("/home"),
    ///     PathBuf::from("/etc"),
    ///     PathBuf::from("/var"),
    /// ]);
    ///
    /// let dirs = fs.enumerate_root_directories().unwrap();
    /// assert_eq!(dirs, vec![
    ///     PathBuf::from("/etc"),
    ///     PathBuf::from("/home"),
    ///     PathBuf::from("/var"),
    /// ]);
    /// ```
    fn enumerate_root_directories(&self) -> Result<Vec<PathBuf>>;

    // ------------------------------------------------------------------------
    // File Size and Rename Operations (Story 9.2: Log Rotation)
    // ------------------------------------------------------------------------

    /// Get the size of a file in bytes
    ///
    /// Returns the size of the file at the specified path.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the file
    ///
    /// # Returns
    ///
    /// File size in bytes.
    ///
    /// # Errors
    ///
    /// Returns `NailsError::IoError` if file doesn't exist or cannot be accessed.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use nails_core::filesystem::{Filesystem, MockFilesystem};
    /// use std::path::Path;
    ///
    /// let fs = MockFilesystem::new();
    /// fs.mock_set_path_exists("/mnt/hidden/logs/nails.log", true);
    /// fs.mock_set_file_size("/mnt/hidden/logs/nails.log", 10485760); // 10MB
    ///
    /// let size = fs.file_size(Path::new("/mnt/hidden/logs/nails.log")).unwrap();
    /// assert_eq!(size, 10485760);
    /// ```
    fn file_size(&self, path: &Path) -> Result<u64>;

    /// Rename a file from source to destination
    ///
    /// Moves/renames a file atomically. Overwrites destination if it exists.
    ///
    /// # Arguments
    ///
    /// * `from` - Source file path
    /// * `to` - Destination file path
    ///
    /// # Errors
    ///
    /// Returns `NailsError::IoError` if rename fails (source doesn't exist, permission denied, etc.)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use nails_core::filesystem::{Filesystem, MockFilesystem};
    /// use std::path::Path;
    ///
    /// let fs = MockFilesystem::new();
    /// fs.mock_set_path_exists("/mnt/hidden/logs/nails.log", true);
    ///
    /// fs.rename_file(
    ///     Path::new("/mnt/hidden/logs/nails.log"),
    ///     Path::new("/mnt/hidden/logs/nails.log.1")
    /// ).unwrap();
    /// ```
    fn rename_file(&self, from: &Path, to: &Path) -> Result<()>;

    // ------------------------------------------------------------------------
    // File Removal Operations (Story 5.3: Temporary Files Cleanup)
    // ------------------------------------------------------------------------

    /// Remove a file
    ///
    /// Removes a single file from the filesystem.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the file to remove
    ///
    /// # Errors
    ///
    /// Returns `NailsError::IoError` if file cannot be removed (doesn't exist, permission denied, etc.)
    ///
    /// # Examples
    ///
    /// **Basic usage:**
    /// ```rust,ignore
    /// use nails_core::filesystem::{Filesystem, MockFilesystem};
    /// use std::path::Path;
    ///
    /// let fs = MockFilesystem::new();
    /// fs.mock_set_path_exists("/tmp/nails.lock", true);
    /// fs.remove_file(Path::new("/tmp/nails.lock")).unwrap();
    /// ```
    ///
    /// **Error handling:**
    /// ```rust,ignore
    /// use nails_core::filesystem::Filesystem;
    /// use std::path::Path;
    ///
    /// match fs.remove_file(Path::new("/tmp/protected.lock")) {
    ///     Ok(()) => println!("File removed successfully"),
    ///     Err(e) => eprintln!("Failed to remove file: {}", e),
    /// }
    /// ```
    ///
    /// **Integration with TempFilesCleaner:**
    /// ```rust,ignore
    /// use nails_core::{TempFilesCleaner, MockFilesystem};
    /// use std::path::PathBuf;
    ///
    /// let fs = MockFilesystem::new();
    /// fs.mock_set_files_with_pattern("/tmp", "nails", &[
    ///     Path::new("/tmp/nails-12345.lock"),
    /// ]);
    ///
    /// let cleaner = TempFilesCleaner::new(fs);
    /// // Internally uses remove_file() to clean matching files
    /// let cleaned = cleaner.clean().unwrap();
    /// ```
    fn remove_file(&self, path: &Path) -> Result<()>;

    /// Remove a directory and all its contents recursively
    ///
    /// Removes a directory and all files/subdirectories within it.
    /// Equivalent to `rm -rf` on Unix systems.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the directory to remove
    ///
    /// # Errors
    ///
    /// Returns `NailsError::IoError` if directory cannot be removed (doesn't exist, permission denied, etc.)
    ///
    /// # Examples
    ///
    /// **Basic usage:**
    /// ```rust,ignore
    /// use nails_core::filesystem::{Filesystem, MockFilesystem};
    /// use std::path::Path;
    ///
    /// let fs = MockFilesystem::new();
    /// fs.mock_set_path_exists("/tmp/nails-cache", true);
    /// fs.mock_set_path_type("/tmp/nails-cache", "directory");
    /// fs.remove_dir_all(Path::new("/tmp/nails-cache")).unwrap();
    /// ```
    ///
    /// **Error handling:**
    /// ```rust,ignore
    /// use nails_core::filesystem::Filesystem;
    /// use std::path::Path;
    ///
    /// match fs.remove_dir_all(Path::new("/tmp/nails-build/")) {
    ///     Ok(()) => println!("Directory removed successfully"),
    ///     Err(e) => eprintln!("Failed to remove directory: {}", e),
    /// }
    /// ```
    ///
    /// **Integration with TempFilesCleaner:**
    /// ```rust,ignore
    /// use nails_core::{TempFilesCleaner, MockFilesystem};
    /// use std::path::{Path, PathBuf};
    ///
    /// let fs = MockFilesystem::new();
    /// fs.mock_set_files_with_pattern("/tmp", "nails", &[
    ///     Path::new("/tmp/nails_build_cache/"),
    /// ]);
    /// fs.mock_set_path_type("/tmp/nails_build_cache/", "directory");
    ///
    /// let cleaner = TempFilesCleaner::new(fs);
    /// // Internally uses remove_dir_all() to recursively clean matching directories
    /// let cleaned = cleaner.clean().unwrap();
    /// ```
    fn remove_dir_all(&self, path: &Path) -> Result<()>;

    // ------------------------------------------------------------------------
    // Directory Operations (Story 9.x: Log Rotation)
    // ------------------------------------------------------------------------

    /// Read the contents of a directory
    ///
    /// Returns an iterator over the entries in a directory.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the directory to read
    ///
    /// # Returns
    ///
    /// A vector of directory entries.
    ///
    /// # Errors
    ///
    /// Returns `NailsError::IoError` if the directory cannot be read
    /// (doesn't exist, permission denied, not a directory, etc.)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use nails_core::filesystem::{Filesystem, MockFilesystem};
    /// use std::path::Path;
    ///
    /// let fs = MockFilesystem::new();
    /// fs.mock_set_path_exists("/mnt/hidden/logs", true);
    ///
    /// let entries = fs.read_directory(Path::new("/mnt/hidden/logs")).unwrap();
    /// for entry in entries {
    ///     println!("{}", entry.path().display());
    /// }
    /// ```
    fn read_directory(&self, path: &Path) -> Result<Vec<std::fs::DirEntry>>;

    /// Check if a directory's filesystem supports symbolic links
    ///
    /// Creates a temporary symlink probe in `dir` to test support.
    /// Useful for detecting FAT32/exFAT volumes that cannot host symlinks.
    ///
    /// # Arguments
    ///
    /// * `dir` - Directory on the filesystem to probe
    ///
    /// # Returns
    ///
    /// `Ok(true)` if symlinks are supported, `Ok(false)` if not (e.g. FAT32/exFAT).
    fn supports_symlinks(&self, dir: &Path) -> Result<bool>;

    /// Get the modification time of a file
    ///
    /// Returns the last modified timestamp of a file.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the file
    ///
    /// # Returns
    ///
    /// The modification time as a UTC DateTime.
    ///
    /// # Errors
    ///
    /// Returns `NailsError::IoError` if the modification time cannot be determined
    /// (file doesn't exist, permission denied, etc.)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use nails_core::filesystem::{Filesystem, MockFilesystem};
    /// use std::path::Path;
    ///
    /// let fs = MockFilesystem::new();
    /// fs.mock_set_path_exists("/mnt/hidden/logs/nails.log", true);
    ///
    /// let modified = fs.modified_time(Path::new("/mnt/hidden/logs/nails.log")).unwrap();
    /// println!("Last modified: {}", modified);
    /// ```
    fn modified_time(&self, path: &Path) -> Result<chrono::DateTime<chrono::Utc>>;
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Verify all preconditions are met before mounting an overlay
///
/// This helper validates that all required directories exist and the target
/// is not already mounted. It provides specific error messages for each
/// failure condition to aid diagnostics.
///
/// # Arguments
///
/// * `fs` - Filesystem trait object to use for checks
/// * `lower` - Lower directory path (must exist)
/// * `upper` - Upper directory path (must exist or be creatable)
/// * `work` - Work directory path (must exist or be creatable)
/// * `target` - Target mount point (must not be already mounted)
///
/// # "Creatable" Definition
///
/// A directory is considered "creatable" if its parent directory exists
/// and is writable. This check does NOT attempt to create the directory,
/// but validates that creation would succeed if attempted.
///
/// # Returns
///
/// `Ok(())` if all preconditions pass, otherwise returns specific error.
///
/// # Errors
///
/// * `NailsError::OverlayError` - If lower, upper, or work directories don't exist
/// * `NailsError::AlreadyMounted` - If target is already mounted
/// * `NailsError::PermissionDenied` - If upper/work directories aren't creatable (parent not writable)
///
/// # Example
///
/// ```rust
/// use nails_core::filesystem::{verify_mount_preconditions, MockFilesystem};
/// use std::path::Path;
///
/// let fs = MockFilesystem::new();
/// fs.mock_set_path_exists("/", true);
/// fs.mock_set_path_exists("/mnt/hidden/upper", true);
/// fs.mock_set_path_exists("/mnt/hidden/work", true);
///
/// let result = verify_mount_preconditions(
///     &fs,
///     Path::new("/"),
///     Path::new("/mnt/hidden/upper"),
///     Path::new("/mnt/hidden/work"),
///     Path::new("/home")
/// );
/// assert!(result.is_ok());
/// ```
pub fn verify_mount_preconditions<F: Filesystem>(
    fs: &F,
    lower: &Path,
    upper: &Path,
    work: &Path,
    target: &Path,
) -> Result<()> {
    // Check lower directory exists
    if !fs.path_exists(lower)? {
        return Err(NailsError::OverlayError(format!(
            "Lower directory not found: {}",
            lower.display()
        )));
    }

    // Check upper directory exists or can be created
    if !fs.path_exists(upper)? {
        // Check if parent directory exists and is writable (can create upper)
        if let Some(parent) = upper.parent() {
            if !fs.path_exists(parent)? {
                return Err(NailsError::OverlayError(format!(
                    "Upper directory not found and parent doesn't exist: {}",
                    upper.display()
                )));
            }
            if !fs.is_writable(parent)? {
                return Err(NailsError::PermissionDenied(format!(
                    "Upper directory not found and parent not writable: {}",
                    upper.display()
                )));
            }
        } else {
            return Err(NailsError::OverlayError(format!(
                "Upper directory not found: {}",
                upper.display()
            )));
        }
    }

    // Check work directory exists or can be created
    if !fs.path_exists(work)? {
        // Check if parent directory exists and is writable (can create work)
        if let Some(parent) = work.parent() {
            if !fs.path_exists(parent)? {
                return Err(NailsError::OverlayError(format!(
                    "Work directory not found and parent doesn't exist: {}",
                    work.display()
                )));
            }
            if !fs.is_writable(parent)? {
                return Err(NailsError::PermissionDenied(format!(
                    "Work directory not found and parent not writable: {}",
                    work.display()
                )));
            }
        } else {
            return Err(NailsError::OverlayError(format!(
                "Work directory not found: {}",
                work.display()
            )));
        }
    }

    // Check target not already mounted
    if fs.is_mounted(target)? {
        return Err(NailsError::AlreadyMounted {
            path: target.to_path_buf(),
        });
    }

    Ok(())
}
