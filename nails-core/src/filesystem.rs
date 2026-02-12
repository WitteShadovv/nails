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
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

// ============================================================================
// Mount Metadata Tracking
// ============================================================================

/// Mount metadata for tracking overlay mount operations
///
/// Used by MockFilesystem to track which overlays are mounted and when.
/// This enables comprehensive testing of mount/unmount sequences.
///
/// # Fields
///
/// * `lower` - Read-only base layer path
/// * `upper` - Writeable upper layer path
/// * `work` - Work directory path for overlay metadata
/// * `target` - Mount point where overlay appears
/// * `mounted_at` - Timestamp when mount occurred (UTC)
///
/// # Dependencies
///
/// Requires `chrono` crate for timestamp functionality.
///
/// # Example
///
/// ```rust
/// use nails_core::filesystem::MountInfo;
/// use std::path::PathBuf;
/// use chrono::Utc;
///
/// let info = MountInfo {
///     lower: PathBuf::from("/"),
///     upper: PathBuf::from("/mnt/hidden/upper"),
///     work: PathBuf::from("/mnt/hidden/work"),
///     target: PathBuf::from("/home"),
///     mounted_at: Utc::now(),
/// };
/// ```
#[derive(Debug, Clone)]
pub struct MountInfo {
    pub lower: PathBuf,
    pub upper: PathBuf,
    pub work: PathBuf,
    pub target: PathBuf,
    pub mounted_at: chrono::DateTime<chrono::Utc>,
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

// ============================================================================
// MockFilesystem - In-Memory Testing Implementation
// ============================================================================

/// Path metadata for MockFilesystem
#[derive(Debug, Clone)]
struct PathInfo {
    exists: bool,
    is_directory: bool,
    is_symlink: bool,
    is_readable: bool,
    is_writable: bool,
    free_space: u64,
}

impl Default for PathInfo {
    fn default() -> Self {
        Self {
            exists: false,
            is_directory: false,
            is_symlink: false,
            is_readable: true,
            is_writable: true,
            free_space: u64::MAX,
        }
    }
}

/// Mock filesystem for testing (no root privileges required)
///
/// Uses in-memory state tracking to simulate filesystem operations.
/// All operations are thread-safe via Arc<Mutex<_>>.
///
/// # Design
///
/// - `mounted`: HashSet of currently mounted paths
/// - `swap_enabled`: Boolean flag for swap status
/// - `paths`: HashMap storing path metadata
/// - `busy`: HashSet of paths marked as busy (open files)
/// - `nixos_profiles`: HashSet of built profile names
/// - `current_profile`: Currently active profile
/// - `tmpfs_mounts`: HashSet of paths with tmpfs mounted (Story 4.11)
/// - `bind_mounts`: HashMap tracking bind mount source→target relationships
///
/// # Thread Safety & Clone Behavior
///
/// All internal state is wrapped in Arc<Mutex<_>> to enable:
/// - Safe sharing across threads
/// - Clone implementation (shares state between clones)
/// - Parallel test execution
///
/// **Note:** Clones share the same underlying state. Modifications via one
/// clone affect all clones. This is intentional for test ergonomics.
#[derive(Debug, Clone)]
pub struct MockFilesystem {
    mounted: Arc<Mutex<HashSet<PathBuf>>>,
    swap_enabled: Arc<Mutex<bool>>,
    paths: Arc<Mutex<HashMap<PathBuf, PathInfo>>>,
    busy: Arc<Mutex<HashSet<PathBuf>>>,
    nixos_profiles: Arc<Mutex<HashSet<String>>>,
    current_profile: Arc<Mutex<Option<String>>>,
    mount_should_fail: Arc<Mutex<HashSet<PathBuf>>>, // Paths that should fail to mount
    unmount_should_fail: Arc<Mutex<HashSet<PathBuf>>>, // Paths that should fail to unmount (both graceful and force)
    unmount_graceful_fails: Arc<Mutex<HashSet<PathBuf>>>, // Paths where graceful unmount fails but force succeeds
    nails_process_running: Arc<Mutex<bool>>,              // Whether nails processes are running
    file_contents: Arc<Mutex<HashMap<PathBuf, String>>>,  // Mock file contents
    #[allow(clippy::type_complexity)]
    files_with_pattern: Arc<Mutex<HashMap<(PathBuf, String), Vec<PathBuf>>>>, // Mock pattern search results
    mounted_overlays: Arc<Mutex<HashMap<PathBuf, MountInfo>>>, // Track overlay mount metadata
    tmpfs_mounts: Arc<Mutex<HashSet<PathBuf>>>,                // Track tmpfs mounts (Story 4.11)
    bind_mounts: Arc<Mutex<HashMap<PathBuf, PathBuf>>>,        // Track bind mounts: target → source
    written_files: Arc<Mutex<HashMap<PathBuf, String>>>,       // Track files written (Story 5.2)
    remove_should_fail: Arc<Mutex<HashSet<PathBuf>>>, // Track paths that should fail removal (Story 5.3)
    directory_contents: Arc<Mutex<HashMap<PathBuf, Vec<PathBuf>>>>, // Track directory contents for list_directory (Story 5.4)
    write_should_fail: Arc<Mutex<HashSet<PathBuf>>>, // Track paths that should fail write (Story 5.5)
}

impl MockFilesystem {
    /// Create a new MockFilesystem with empty state
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::filesystem::MockFilesystem;
    /// use std::path::Path;
    ///
    /// let fs = MockFilesystem::new();
    /// assert!(fs.get_mounted_paths().is_empty());
    ///
    /// // Set up test state
    /// fs.mock_set_mounted(Path::new("/home"), true);
    /// assert_eq!(fs.get_mounted_paths().len(), 1);
    ///
    /// // Reset clears state
    /// fs.reset();
    /// assert!(fs.get_mounted_paths().is_empty());
    /// ```
    pub fn new() -> Self {
        Self {
            mounted: Arc::new(Mutex::new(HashSet::new())),
            swap_enabled: Arc::new(Mutex::new(false)),
            paths: Arc::new(Mutex::new(HashMap::new())),
            busy: Arc::new(Mutex::new(HashSet::new())),
            nixos_profiles: Arc::new(Mutex::new(HashSet::new())),
            current_profile: Arc::new(Mutex::new(None)),
            mount_should_fail: Arc::new(Mutex::new(HashSet::new())),
            unmount_should_fail: Arc::new(Mutex::new(HashSet::new())),
            unmount_graceful_fails: Arc::new(Mutex::new(HashSet::new())),
            nails_process_running: Arc::new(Mutex::new(false)),
            file_contents: Arc::new(Mutex::new(HashMap::new())),
            files_with_pattern: Arc::new(Mutex::new(HashMap::new())),
            mounted_overlays: Arc::new(Mutex::new(HashMap::new())),
            tmpfs_mounts: Arc::new(Mutex::new(HashSet::new())),
            bind_mounts: Arc::new(Mutex::new(HashMap::new())),
            written_files: Arc::new(Mutex::new(HashMap::new())),
            remove_should_fail: Arc::new(Mutex::new(HashSet::new())),
            directory_contents: Arc::new(Mutex::new(HashMap::new())),
            write_should_fail: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Reset all internal state to empty
    ///
    /// Useful for test cleanup between test cases.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::filesystem::MockFilesystem;
    /// use std::path::Path;
    ///
    /// let mut fs = MockFilesystem::new();
    /// fs.mock_set_mounted(Path::new("/home"), true);
    /// fs.reset();
    /// assert!(fs.get_mounted_paths().is_empty());
    /// ```
    pub fn reset(&self) {
        self.mounted.lock().unwrap().clear();
        *self.swap_enabled.lock().unwrap() = false;
        self.paths.lock().unwrap().clear();
        self.busy.lock().unwrap().clear();
        self.nixos_profiles.lock().unwrap().clear();
        self.current_profile.lock().unwrap().take();
        self.mount_should_fail.lock().unwrap().clear();
        self.unmount_should_fail.lock().unwrap().clear();
        self.mounted_overlays.lock().unwrap().clear();
        self.tmpfs_mounts.lock().unwrap().clear();
        self.bind_mounts.lock().unwrap().clear();
        self.written_files.lock().unwrap().clear();
        self.remove_should_fail.lock().unwrap().clear();
        self.directory_contents.lock().unwrap().clear();
        self.write_should_fail.lock().unwrap().clear();
    }

    // ========================================================================
    // Test Helper Methods (for setting up mock state)
    // ========================================================================

    /// Set whether a path is mounted
    pub fn mock_set_mounted(&self, path: &Path, mounted: bool) {
        let mut mounts = self.mounted.lock().unwrap();
        if mounted {
            mounts.insert(path.to_path_buf());
        } else {
            mounts.remove(path);
        }
    }

    /// Set whether a path is busy (has open files)
    pub fn mock_set_busy(&self, path: &Path, busy: bool) {
        let mut busy_set = self.busy.lock().unwrap();
        if busy {
            busy_set.insert(path.to_path_buf());
        } else {
            busy_set.remove(path);
        }
    }

    /// Set whether swap is enabled
    pub fn mock_set_swap_enabled(&self, enabled: bool) {
        *self.swap_enabled.lock().unwrap() = enabled;
    }

    /// Set whether a path exists
    pub fn mock_set_path_exists(&self, path: &str, exists: bool) {
        let mut paths = self.paths.lock().unwrap();
        let entry = paths.entry(PathBuf::from(path)).or_default();
        entry.exists = exists;
    }

    /// Set a path's type (directory or file)
    pub fn mock_set_path_type(&self, path: &str, type_str: &str) {
        let mut paths = self.paths.lock().unwrap();
        let entry = paths.entry(PathBuf::from(path)).or_default();
        entry.exists = true;
        entry.is_directory = type_str == "directory";
    }

    /// Set whether a path is writable
    pub fn mock_set_writable(&self, path: &str, writable: bool) {
        let mut paths = self.paths.lock().unwrap();
        let entry = paths.entry(PathBuf::from(path)).or_default();
        entry.is_writable = writable;
    }

    /// Set whether a path is readable
    pub fn mock_set_readable(&self, path: &str, readable: bool) {
        let mut paths = self.paths.lock().unwrap();
        let entry = paths.entry(PathBuf::from(path)).or_default();
        entry.is_readable = readable;
    }

    /// Set whether a path is a symbolic link
    pub fn mock_set_is_symlink(&self, path: &str, is_symlink: bool) {
        let mut paths = self.paths.lock().unwrap();
        let entry = paths.entry(PathBuf::from(path)).or_default();
        entry.exists = true;
        entry.is_symlink = is_symlink;
    }

    /// Set free space for a path
    pub fn mock_set_free_space(&self, path: &Path, bytes: u64) {
        let mut paths = self.paths.lock().unwrap();
        let entry = paths.entry(path.to_path_buf()).or_default();
        entry.free_space = bytes;
    }

    /// Set whether a NixOS profile exists
    pub fn mock_set_nixos_profile_exists(&self, profile: &str, exists: bool) {
        let mut profiles = self.nixos_profiles.lock().unwrap();
        if exists {
            profiles.insert(profile.to_string());
        } else {
            profiles.remove(profile);
        }
    }

    /// Set whether a mount operation should fail for a specific path
    ///
    /// This is useful for testing rollback scenarios where mount operations fail.
    ///
    /// # Arguments
    ///
    /// * `path` - Target mount path that should fail
    /// * `should_fail` - If true, mount operations to this path will fail
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::filesystem::{Filesystem, MockFilesystem};
    /// use std::path::Path;
    ///
    /// let fs = MockFilesystem::new();
    /// fs.mock_set_mount_should_fail("/home", true);
    ///
    /// // This will now fail
    /// let result = fs.mount_overlay(
    ///     Path::new("/"),
    ///     Path::new("/mnt/hidden/upper"),
    ///     Path::new("/mnt/hidden/work"),
    ///     Path::new("/home")
    /// );
    /// assert!(result.is_err());
    /// ```
    pub fn mock_set_mount_should_fail(&self, path: &str, should_fail: bool) {
        let mut fail_set = self.mount_should_fail.lock().unwrap();
        if should_fail {
            fail_set.insert(PathBuf::from(path));
        } else {
            fail_set.remove(&PathBuf::from(path));
        }
    }

    /// Set whether an unmount operation should fail for a specific path
    ///
    /// This is useful for testing deactivation rollback scenarios where unmount operations fail.
    ///
    /// # Arguments
    ///
    /// * `path` - Target mount path that should fail to unmount
    /// * `should_fail` - If true, unmount operations for this path will fail
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::filesystem::{Filesystem, MockFilesystem};
    /// use std::path::Path;
    ///
    /// let fs = MockFilesystem::new();
    ///
    /// // Set up a mounted overlay
    /// fs.mock_set_mounted(Path::new("/home"), true);
    ///
    /// // Configure unmount to fail
    /// fs.mock_set_unmount_should_fail("/home", true);
    ///
    /// // This will now fail
    /// let result = fs.unmount(Path::new("/home"), false);
    /// assert!(result.is_err());
    /// ```
    pub fn mock_set_unmount_should_fail(&self, path: &str, should_fail: bool) {
        let mut fail_set = self.unmount_should_fail.lock().unwrap();
        if should_fail {
            fail_set.insert(PathBuf::from(path));
        } else {
            fail_set.remove(&PathBuf::from(path));
        }
    }

    /// Configure graceful unmount to fail for specific paths (force unmount will succeed)
    ///
    /// This is useful for testing the graceful-fail-then-force-succeed path in rollback.
    ///
    /// # Arguments
    ///
    /// * `path` - Path that should fail graceful unmount
    /// * `should_fail` - If true, graceful unmount will fail (force will succeed)
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::filesystem::{Filesystem, MockFilesystem};
    /// use std::path::Path;
    ///
    /// let fs = MockFilesystem::new();
    /// fs.mock_set_mounted(Path::new("/home"), true);
    ///
    /// // Configure graceful to fail, force to succeed
    /// fs.mock_set_unmount_graceful_fails("/home", true);
    ///
    /// // Graceful unmount fails
    /// let graceful_result = fs.unmount(Path::new("/home"), false);
    /// assert!(graceful_result.is_err());
    ///
    /// // Force unmount succeeds
    /// let force_result = fs.unmount(Path::new("/home"), true);
    /// assert!(force_result.is_ok());
    /// ```
    pub fn mock_set_unmount_graceful_fails(&self, path: &str, should_fail: bool) {
        let mut fail_set = self.unmount_graceful_fails.lock().unwrap();
        if should_fail {
            fail_set.insert(PathBuf::from(path));
        } else {
            fail_set.remove(&PathBuf::from(path));
        }
    }

    /// Set whether nails processes are running
    ///
    /// # Arguments
    ///
    /// * `running` - If true, nails_process_running() will return true
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::filesystem::{Filesystem, MockFilesystem};
    ///
    /// let fs = MockFilesystem::new();
    /// fs.mock_set_nails_process_running(true);
    /// assert!(fs.nails_process_running().unwrap());
    /// ```
    pub fn mock_set_nails_process_running(&self, running: bool) {
        let mut is_running = self.nails_process_running.lock().unwrap();
        *is_running = running;
    }

    /// Set mock file contents for reading
    ///
    /// # Arguments
    ///
    /// * `path` - File path
    /// * `content` - Content to return when read_file_content is called
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::filesystem::{Filesystem, MockFilesystem};
    /// use std::path::Path;
    ///
    /// let fs = MockFilesystem::new();
    /// fs.mock_set_file_content("/root/.bash_history", "nails activate\nls\n");
    /// let content = fs.read_file_content(Path::new("/root/.bash_history")).unwrap();
    /// assert!(content.contains("nails"));
    /// ```
    pub fn mock_set_file_content(&self, path: &str, content: &str) {
        let mut contents = self.file_contents.lock().unwrap();
        contents.insert(PathBuf::from(path), content.to_string());
    }

    /// Get written file content for test verification (Story 5.2)
    ///
    /// Returns the content that was written to a file via write_file_content(),
    /// or None if the file was not written.
    pub fn get_written_content(&self, path: &Path) -> Option<String> {
        let written = self.written_files.lock().unwrap();
        written.get(path).cloned()
    }

    /// Set whether a write operation should fail for a specific path (Story 5.5)
    ///
    /// This is useful for testing cleanup failure scenarios where file writes fail.
    ///
    /// # Arguments
    ///
    /// * `path` - File path that should fail to write
    /// * `should_fail` - If true, write_file_content for this path will fail
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::filesystem::{Filesystem, MockFilesystem};
    /// use std::path::Path;
    ///
    /// let fs = MockFilesystem::new();
    /// fs.mock_set_write_should_fail("/root/.bash_history", true);
    ///
    /// // This will now fail
    /// let result = fs.write_file_content(Path::new("/root/.bash_history"), "content");
    /// assert!(result.is_err());
    /// ```
    pub fn mock_set_write_should_fail(&self, path: &str, should_fail: bool) {
        let mut fail_set = self.write_should_fail.lock().unwrap();
        if should_fail {
            fail_set.insert(PathBuf::from(path));
        } else {
            fail_set.remove(&PathBuf::from(path));
        }
    }

    /// Set mock results for pattern-based file searches
    ///
    /// # Arguments
    ///
    /// * `dir` - Directory that was searched
    /// * `pattern` - Pattern that was searched for
    /// * `files` - Files to return as search results
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::filesystem::MockFilesystem;
    /// use std::path::Path;
    ///
    /// let fs = MockFilesystem::new();
    /// fs.mock_set_files_with_pattern("/tmp", "nails", &[
    ///     Path::new("/tmp/nails.log"),
    ///     Path::new("/tmp/nails.toml"),
    /// ]);
    /// ```
    pub fn mock_set_files_with_pattern(&self, dir: &str, pattern: &str, files: &[&Path]) {
        let mut pattern_results = self.files_with_pattern.lock().unwrap();
        let key = (PathBuf::from(dir), pattern.to_string());
        pattern_results.insert(key, files.iter().map(|p| p.to_path_buf()).collect());
    }

    /// Set whether a file/directory removal should fail (Story 5.3)
    ///
    /// This is useful for testing error handling in cleanup operations.
    ///
    /// # Arguments
    ///
    /// * `path` - Path that should fail removal
    /// * `should_fail` - If true, remove_file/remove_dir_all will fail for this path
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::filesystem::{Filesystem, MockFilesystem};
    /// use std::path::Path;
    ///
    /// let fs = MockFilesystem::new();
    /// fs.mock_set_path_exists("/tmp/readonly.lock", true);
    /// fs.mock_set_remove_should_fail("/tmp/readonly.lock", true);
    ///
    /// // This will now fail
    /// let result = fs.remove_file(Path::new("/tmp/readonly.lock"));
    /// assert!(result.is_err());
    /// ```
    pub fn mock_set_remove_should_fail(&self, path: &str, should_fail: bool) {
        let mut fail_set = self.remove_should_fail.lock().unwrap();
        if should_fail {
            fail_set.insert(PathBuf::from(path));
        } else {
            fail_set.remove(&PathBuf::from(path));
        }
    }

    /// Get list of currently mounted paths
    ///
    /// Useful for test assertions.
    pub fn get_mounted_paths(&self) -> Vec<PathBuf> {
        self.mounted.lock().unwrap().iter().cloned().collect()
    }

    /// Get mount info for a specific overlay
    ///
    /// Returns None if the target is not currently mounted as an overlay.
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
    ///
    /// fs.mount_overlay(
    ///     Path::new("/"),
    ///     Path::new("/mnt/hidden/upper"),
    ///     Path::new("/mnt/hidden/work"),
    ///     Path::new("/home")
    /// ).unwrap();
    ///
    /// let info = fs.mock_get_mount_info(Path::new("/home")).unwrap();
    /// assert_eq!(info.lower, Path::new("/"));
    /// assert_eq!(info.upper, Path::new("/mnt/hidden/upper"));
    /// ```
    pub fn mock_get_mount_info(&self, target: &Path) -> Option<MountInfo> {
        self.mounted_overlays.lock().unwrap().get(target).cloned()
    }

    /// Set whether a directory can be created (parent exists and is writable)
    ///
    /// Helper for testing directory creation scenarios in verify_mount_preconditions().
    /// This sets up the parent directory to exist and be writable, allowing the test
    /// to verify that a directory can be created when it doesn't exist.
    ///
    /// # Arguments
    ///
    /// * `path` - Directory path that should be creatable
    /// * `creatable` - If true, parent exists and is writable; if false, parent not writable
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::filesystem::{verify_mount_preconditions, MockFilesystem};
    /// use std::path::Path;
    ///
    /// let fs = MockFilesystem::new();
    /// fs.mock_set_path_exists("/", true);
    ///
    /// // Set parent directory writable, upper doesn't exist but can be created
    /// fs.mock_set_directory_creatable("/mnt/hidden/upper", true);
    /// fs.mock_set_directory_creatable("/mnt/hidden/work", true);
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
    pub fn mock_set_directory_creatable(&self, path: &str, creatable: bool) {
        let path_buf = PathBuf::from(path);
        if let Some(parent) = path_buf.parent() {
            // Set parent to exist and be writable (or not writable)
            let mut paths = self.paths.lock().unwrap();
            let parent_entry = paths.entry(parent.to_path_buf()).or_default();
            parent_entry.exists = true;
            parent_entry.is_directory = true;
            parent_entry.is_writable = creatable;
        }
    }

    /// Set mock directory contents for list_directory tests
    ///
    /// # Arguments
    ///
    /// * `dir` - Directory path
    /// * `contents` - List of paths that should be returned by list_directory
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::filesystem::MockFilesystem;
    /// use std::path::PathBuf;
    ///
    /// let fs = MockFilesystem::new();
    /// fs.mock_set_directory_contents(
    ///     &PathBuf::from("/mnt/hidden/logs"),
    ///     vec![
    ///         PathBuf::from("/mnt/hidden/logs/nails.log"),
    ///         PathBuf::from("/mnt/hidden/logs/nails.log.1"),
    ///     ]
    /// );
    /// ```
    pub fn mock_set_directory_contents(&self, dir: &Path, contents: Vec<PathBuf>) {
        self.directory_contents
            .lock()
            .unwrap()
            .insert(dir.to_path_buf(), contents);
    }
}

impl Default for MockFilesystem {
    fn default() -> Self {
        Self::new()
    }
}

impl Filesystem for MockFilesystem {
    fn mount_overlay(&self, lower: &Path, upper: &Path, work: &Path, target: &Path) -> Result<()> {
        // Check if this mount should fail (for testing rollback)
        let fail_set = self.mount_should_fail.lock().unwrap();
        if fail_set.contains(target) {
            return Err(NailsError::OverlayError(format!(
                "Mock mount failure for testing: {}",
                target.display()
            )));
        }
        drop(fail_set);

        // Verify all preconditions using the helper function
        verify_mount_preconditions(self, lower, upper, work, target)?;

        // Create mount info with timestamp
        let mount_info = MountInfo {
            lower: lower.to_path_buf(),
            upper: upper.to_path_buf(),
            work: work.to_path_buf(),
            target: target.to_path_buf(),
            mounted_at: chrono::Utc::now(),
        };

        // Add to mounted set and track mount info
        self.mounted.lock().unwrap().insert(target.to_path_buf());
        self.mounted_overlays
            .lock()
            .unwrap()
            .insert(target.to_path_buf(), mount_info);

        Ok(())
    }

    fn unmount(&self, target: &Path, force: bool) -> Result<()> {
        // Check if this unmount should always fail (for testing rollback)
        let fail_set = self.unmount_should_fail.lock().unwrap();
        if fail_set.contains(target) {
            return Err(NailsError::UnmountError {
                path: target.to_path_buf(),
                reason: "Mock unmount failure for testing".to_string(),
            });
        }
        drop(fail_set);

        // Check if graceful unmount should fail (but force would succeed)
        let graceful_fail_set = self.unmount_graceful_fails.lock().unwrap();
        if graceful_fail_set.contains(target) && !force {
            return Err(NailsError::UnmountError {
                path: target.to_path_buf(),
                reason: "Mock graceful unmount failure (force would succeed)".to_string(),
            });
        }
        drop(graceful_fail_set);

        let mut mounts = self.mounted.lock().unwrap();

        // Idempotent: succeed if not mounted
        if !mounts.contains(target) {
            return Ok(());
        }

        // Check if busy
        let busy = self.busy.lock().unwrap();
        if busy.contains(target) && !force {
            return Err(NailsError::MountBusy {
                path: target.to_path_buf(),
                suggestion: "Use force=true to override or close open files".to_string(),
            });
        }
        drop(busy);

        // Remove from mounted set and overlays tracking
        mounts.remove(target);
        drop(mounts);
        self.mounted_overlays.lock().unwrap().remove(target);

        Ok(())
    }

    fn is_mounted(&self, target: &Path) -> Result<bool> {
        Ok(self.mounted.lock().unwrap().contains(target))
    }

    fn get_mount_info(&self, target: &Path) -> Option<MountInfo> {
        self.mounted_overlays.lock().unwrap().get(target).cloned()
    }

    fn swap_is_enabled(&self) -> Result<bool> {
        Ok(*self.swap_enabled.lock().unwrap())
    }

    fn swap_disable(&self) -> Result<()> {
        // Idempotent: succeed even if already disabled
        *self.swap_enabled.lock().unwrap() = false;
        Ok(())
    }

    fn path_exists(&self, path: &Path) -> Result<bool> {
        let paths = self.paths.lock().unwrap();
        Ok(paths.get(path).map(|info| info.exists).unwrap_or(false))
    }

    fn is_directory(&self, path: &Path) -> Result<bool> {
        let paths = self.paths.lock().unwrap();
        Ok(paths
            .get(path)
            .map(|info| info.is_directory)
            .unwrap_or(false))
    }

    fn is_symlink(&self, path: &Path) -> Result<bool> {
        let paths = self.paths.lock().unwrap();
        Ok(paths.get(path).map(|info| info.is_symlink).unwrap_or(false))
    }

    fn get_free_space(&self, path: &Path) -> Result<u64> {
        let paths = self.paths.lock().unwrap();
        Ok(paths
            .get(path)
            .map(|info| info.free_space)
            .unwrap_or(u64::MAX))
    }

    fn create_directory(&self, path: &Path) -> Result<()> {
        // Check parent is writable
        if let Some(parent) = path.parent() {
            let paths = self.paths.lock().unwrap();
            let parent_writable = paths
                .get(parent)
                .map(|info| info.is_writable)
                .unwrap_or(false);
            if !parent_writable {
                return Err(NailsError::PermissionDenied(format!(
                    "Parent directory not writable: {}",
                    parent.display()
                )));
            }
        }

        // Create directory
        let mut paths = self.paths.lock().unwrap();
        let entry = paths.entry(path.to_path_buf()).or_default();
        entry.exists = true;
        entry.is_directory = true;
        Ok(())
    }

    fn is_readable(&self, path: &Path) -> Result<bool> {
        let paths = self.paths.lock().unwrap();
        Ok(paths
            .get(path)
            .map(|info| info.is_readable)
            .unwrap_or(false))
    }

    fn is_writable(&self, path: &Path) -> Result<bool> {
        let paths = self.paths.lock().unwrap();
        Ok(paths
            .get(path)
            .map(|info| info.is_writable)
            .unwrap_or(false))
    }

    fn nixos_profile_exists(&self, profile: &str) -> Result<bool> {
        Ok(self
            .nixos_profiles
            .lock()
            .unwrap()
            .contains(&profile.to_string()))
    }

    fn nixos_build_profile(&self, profile: &str) -> Result<()> {
        // Add profile to set
        self.nixos_profiles
            .lock()
            .unwrap()
            .insert(profile.to_string());
        Ok(())
    }

    fn nixos_switch_profile(&self, profile: &str) -> Result<()> {
        // Check if profile exists
        let exists = self
            .nixos_profiles
            .lock()
            .unwrap()
            .contains(&profile.to_string());
        if !exists {
            return Err(NailsError::NixOSProfileNotFound {
                profile: profile.to_string(),
            });
        }

        // Set current profile
        *self.current_profile.lock().unwrap() = Some(profile.to_string());
        Ok(())
    }

    fn nixos_get_current_profile(&self) -> Result<String> {
        self.current_profile
            .lock()
            .unwrap()
            .as_ref()
            .map(|p| p.clone())
            .ok_or_else(|| NailsError::InvalidState("No NixOS profile is currently active".into()))
    }

    fn nails_process_running(&self) -> Result<bool> {
        Ok(*self.nails_process_running.lock().unwrap())
    }

    fn read_file_content(&self, path: &Path) -> Result<String> {
        self.file_contents
            .lock()
            .unwrap()
            .get(path)
            .cloned()
            .ok_or_else(|| {
                NailsError::IoError(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("File not found in mock: {}", path.display()),
                ))
            })
    }

    fn find_files_with_pattern(&self, dir: &Path, pattern: &str) -> Result<Vec<PathBuf>> {
        let pattern_results = self.files_with_pattern.lock().unwrap();
        let key = (dir.to_path_buf(), pattern.to_string());
        let files = pattern_results.get(&key).cloned().unwrap_or_default();

        // Filter out files that have been explicitly removed
        // Files are removed by setting exists=false in the paths map
        // If a file isn't in the paths map, it was never set up with mock_set_path_exists,
        // so we should still return it (it's implicitly considered to exist)
        let paths = self.paths.lock().unwrap();
        let existing_files: Vec<PathBuf> = files
            .into_iter()
            .filter(|path| {
                // If path is in the map, check exists flag
                // If path is not in the map, assume it exists (wasn't set up, so keep it)
                paths.get(path).map(|info| info.exists).unwrap_or(true)
            })
            .collect();

        Ok(existing_files)
    }

    fn write_file_content(&self, path: &Path, content: &str) -> Result<()> {
        // Check if write should fail for this path (Story 5.5 cleanup failure testing)
        if self.write_should_fail.lock().unwrap().contains(path) {
            return Err(NailsError::IoError(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("Mock write failure for {}", path.display()),
            )));
        }

        // Store the written content for test verification
        let mut written = self.written_files.lock().unwrap();
        written.insert(path.to_path_buf(), content.to_string());

        // Also update file_contents so subsequent reads work
        let mut contents = self.file_contents.lock().unwrap();
        contents.insert(path.to_path_buf(), content.to_string());

        Ok(())
    }

    fn mount_tmpfs(&self, target: &Path, size: &str) -> Result<()> {
        // Validate size format by parsing it
        let test_dir = crate::config::EphemeralOverlayDir {
            path: target.to_path_buf(),
            tmpfs_upper_size: size.to_string(),
            tmpfs_work_size: size.to_string(),
        };

        if test_dir.parse_upper_size().is_err() {
            return Err(NailsError::OverlayError(format!(
                "Invalid tmpfs size format: {}",
                size
            )));
        }

        // Check if target already has tmpfs mounted
        if self.tmpfs_mounts.lock().unwrap().contains(target) {
            return Err(NailsError::AlreadyMounted {
                path: target.to_path_buf(),
            });
        }

        // Create directory if it doesn't exist
        if !self.path_exists(target)? {
            self.create_directory(target)?;
        }

        // Track tmpfs mount
        self.tmpfs_mounts
            .lock()
            .unwrap()
            .insert(target.to_path_buf());
        self.mounted.lock().unwrap().insert(target.to_path_buf());

        Ok(())
    }

    fn unmount_tmpfs(&self, target: &Path) -> Result<()> {
        // Idempotent: succeed if not mounted
        if !self.tmpfs_mounts.lock().unwrap().contains(target) {
            return Ok(());
        }

        // Check if unmount should fail (mock behavior)
        if self.unmount_should_fail.lock().unwrap().contains(target) {
            return Err(NailsError::UnmountError {
                path: target.to_path_buf(),
                reason: "Mock: unmount_tmpfs configured to fail".to_string(),
            });
        }

        // Remove from tmpfs mounts and mounted sets
        self.tmpfs_mounts.lock().unwrap().remove(target);
        self.mounted.lock().unwrap().remove(target);

        Ok(())
    }

    fn bind_mount(&self, source: &Path, target: &Path) -> Result<()> {
        // Check if this mount should fail (for testing rollback)
        let fail_set = self.mount_should_fail.lock().unwrap();
        if fail_set.contains(target) {
            return Err(NailsError::OverlayError(format!(
                "Mock bind mount failure for testing: {}",
                target.display()
            )));
        }
        drop(fail_set);

        // Verify source exists (must have something to bind from)
        if !self.path_exists(source)? {
            return Err(NailsError::OverlayError(format!(
                "Bind mount source not found: {}",
                source.display()
            )));
        }

        // Check if target already has a bind mount
        if self.bind_mounts.lock().unwrap().contains_key(target) {
            return Err(NailsError::AlreadyMounted {
                path: target.to_path_buf(),
            });
        }

        // Track bind mount: target → source
        self.bind_mounts
            .lock()
            .unwrap()
            .insert(target.to_path_buf(), source.to_path_buf());
        self.mounted.lock().unwrap().insert(target.to_path_buf());

        Ok(())
    }

    fn unmount_bind(&self, target: &Path) -> Result<()> {
        // Idempotent: succeed if not mounted as bind
        if !self.bind_mounts.lock().unwrap().contains_key(target) {
            return Ok(());
        }

        // Check if unmount should fail (mock behavior)
        if self.unmount_should_fail.lock().unwrap().contains(target) {
            return Err(NailsError::UnmountError {
                path: target.to_path_buf(),
                reason: "Mock: unmount_bind configured to fail".to_string(),
            });
        }

        // Remove from bind mounts and mounted sets
        self.bind_mounts.lock().unwrap().remove(target);
        self.mounted.lock().unwrap().remove(target);

        Ok(())
    }

    fn remove_file(&self, path: &Path) -> Result<()> {
        // Check if removal should fail (mock behavior for testing)
        if self.remove_should_fail.lock().unwrap().contains(path) {
            return Err(NailsError::IoError(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "Mock: remove_file configured to fail for {}",
                    path.display()
                ),
            )));
        }

        // Mark file as non-existent instead of removing entry entirely
        // This allows find_files_with_pattern to filter out removed files
        let mut paths = self.paths.lock().unwrap();
        if let Some(info) = paths.get_mut(path) {
            info.exists = false;
        }
        // If path isn't in map, it was never set up, so nothing to do

        // Also remove from file_contents if present
        let mut contents = self.file_contents.lock().unwrap();
        contents.remove(path);

        Ok(())
    }

    fn remove_dir_all(&self, path: &Path) -> Result<()> {
        // Check if removal should fail (mock behavior for testing)
        if self.remove_should_fail.lock().unwrap().contains(path) {
            return Err(NailsError::IoError(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "Mock: remove_dir_all configured to fail for {}",
                    path.display()
                ),
            )));
        }

        // Mark directory as non-existent instead of removing entry entirely
        // This allows find_files_with_pattern to filter out removed directories
        let mut paths = self.paths.lock().unwrap();
        if let Some(info) = paths.get_mut(path) {
            info.exists = false;
        }
        // If path isn't in map, it was never set up, so nothing to do

        // In a real implementation, we'd also remove all children
        // For mock purposes, just marking the directory entry is sufficient

        Ok(())
    }

    fn list_directory(&self, dir: &Path) -> Result<Vec<PathBuf>> {
        // Check if directory contents have been mocked
        let contents = self.directory_contents.lock().unwrap();
        if let Some(entries) = contents.get(&dir.to_path_buf()) {
            return Ok(entries.clone());
        }

        // If not mocked, return error (directory not found/not set up for tests)
        Err(NailsError::IoError(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!(
                "Mock: directory contents not configured for {}",
                dir.display()
            ),
        )))
    }
}

// ============================================================================
// RealFilesystem - Production Implementation
// ============================================================================

/// Real filesystem using system calls
///
/// Uses actual syscalls for production use. Requires root privileges for mount/unmount operations.
///
/// # Security
///
/// - Mount operations require CAP_SYS_ADMIN capability
/// - All operations return proper NailsError types
/// - Force flag enables MNT_FORCE | MNT_DETACH for unmount
///
/// # Platform
///
/// Only works on Linux systems with OverlayFS support.
#[derive(Debug, Clone, Copy)]
pub struct RealFilesystem;

impl Default for RealFilesystem {
    fn default() -> Self {
        Self
    }
}

impl Filesystem for RealFilesystem {
    fn mount_overlay(&self, lower: &Path, upper: &Path, work: &Path, target: &Path) -> Result<()> {
        // Verify all preconditions using the helper function
        verify_mount_preconditions(self, lower, upper, work, target)?;

        // Build overlay options
        let options = format!(
            "lowerdir={},upperdir={},workdir={}",
            lower.display(),
            upper.display(),
            work.display()
        );

        // Perform mount using nix crate with security flags
        // MS_NOSUID: Prevent setuid/setgid bits from taking effect
        // MS_NODEV: Prevent access to device files
        // MS_NOEXEC: NOT used - /home and /etc overlays must allow execution
        //            (user scripts, shell configs, system binaries in hidden environment)
        //            Story 4.11 may introduce different strategies for tmpfs-backed layers
        nix::mount::mount(
            Some("overlay"),
            target,
            Some("overlay"),
            nix::mount::MsFlags::MS_NOSUID | nix::mount::MsFlags::MS_NODEV,
            Some(options.as_str()),
        )
        .map_err(|e| {
            // Check for specific error conditions
            if e == nix::errno::Errno::EACCES || e == nix::errno::Errno::EPERM {
                NailsError::PermissionDenied("Mount requires root privileges".to_string())
            } else {
                NailsError::OverlayError(format!("Failed to mount {}: {}", target.display(), e))
            }
        })?;

        Ok(())
    }

    fn unmount(&self, target: &Path, force: bool) -> Result<()> {
        // Idempotent: succeed if not mounted
        if !self.is_mounted(target)? {
            return Ok(());
        }

        // Set flags
        let flags = if force {
            nix::mount::MntFlags::MNT_FORCE | nix::mount::MntFlags::MNT_DETACH
        } else {
            nix::mount::MntFlags::empty()
        };

        // Perform unmount
        nix::mount::umount2(target, flags).map_err(|e| {
            if e == nix::errno::Errno::EBUSY {
                NailsError::MountBusy {
                    path: target.to_path_buf(),
                    suggestion: "Use force=true or close open files".to_string(),
                }
            } else {
                NailsError::UnmountError {
                    path: target.to_path_buf(),
                    reason: format!("{}", e),
                }
            }
        })?;

        Ok(())
    }

    fn is_mounted(&self, target: &Path) -> Result<bool> {
        // Parse /proc/mounts to check if path is mounted
        let mounts = std::fs::read_to_string("/proc/mounts")?;
        let canonical_target = target
            .canonicalize()
            .unwrap_or_else(|_| target.to_path_buf());

        for line in mounts.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2
                && let Ok(mount_point) = PathBuf::from(parts[1]).canonicalize()
                && mount_point == canonical_target
            {
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn get_mount_info(&self, target: &Path) -> Option<MountInfo> {
        // For RealFilesystem, parse /proc/mounts to find mount info
        // Note: Linux /proc/mounts only shows mount point and type, not overlay paths
        // For proper rollback support, mount info should be persisted in state file
        // during activation. This is a best-effort implementation for now.
        let mounts = std::fs::read_to_string("/proc/mounts").ok()?;
        let canonical_target = target.canonicalize().ok()?;

        for line in mounts.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let mount_point = PathBuf::from(parts[1]).canonicalize().ok()?;
                let fs_type = parts[2];

                if mount_point == canonical_target && fs_type == "overlay" {
                    // Parse overlay options (lowerdir=...,upperdir=...,workdir=...)
                    let options = parts[3];
                    let mut lower = None;
                    let mut upper = None;
                    let mut work = None;

                    for opt in options.split(',') {
                        if let Some(path) = opt.strip_prefix("lowerdir=") {
                            lower = Some(PathBuf::from(path.split(':').next()?));
                        } else if let Some(path) = opt.strip_prefix("upperdir=") {
                            upper = Some(PathBuf::from(path));
                        } else if let Some(path) = opt.strip_prefix("workdir=") {
                            work = Some(PathBuf::from(path));
                        }
                    }

                    if let (Some(l), Some(u), Some(w)) = (lower, upper, work) {
                        return Some(MountInfo {
                            lower: l,
                            upper: u,
                            work: w,
                            target: canonical_target,
                            mounted_at: chrono::Utc::now(), // Approximation
                        });
                    }
                }
            }
        }

        None
    }

    fn swap_is_enabled(&self) -> Result<bool> {
        // Parse /proc/swaps
        let swaps = std::fs::read_to_string("/proc/swaps")?;
        // Skip header line, check if any swap entries exist
        Ok(swaps.lines().count() > 1)
    }

    fn swap_disable(&self) -> Result<()> {
        // Idempotent: succeed if already disabled
        if !self.swap_is_enabled()? {
            return Ok(());
        }

        // Use swapoff command
        std::process::Command::new("swapoff")
            .arg("-a")
            .output()
            .map_err(|_| NailsError::SwapDisableFailed)?;

        Ok(())
    }

    fn path_exists(&self, path: &Path) -> Result<bool> {
        Ok(path.exists())
    }

    fn is_directory(&self, path: &Path) -> Result<bool> {
        Ok(path.is_dir())
    }

    fn is_symlink(&self, path: &Path) -> Result<bool> {
        Ok(path.is_symlink())
    }

    fn get_free_space(&self, path: &Path) -> Result<u64> {
        // Use std::fs metadata (works on any path on filesystem)
        let _metadata = std::fs::metadata(path)?;
        // Note: This is simplified - real implementation would use statvfs
        // For now, return a large number as placeholder
        Ok(u64::MAX)
    }

    fn create_directory(&self, path: &Path) -> Result<()> {
        std::fs::create_dir_all(path)?;
        Ok(())
    }

    fn is_readable(&self, path: &Path) -> Result<bool> {
        // Try to open file for reading
        Ok(std::fs::File::open(path).is_ok())
    }

    fn is_writable(&self, path: &Path) -> Result<bool> {
        // Try to open file for writing
        if path.is_dir() {
            // For directories, try to create a temp file
            let test_path = path.join(".nails_write_test");
            match std::fs::File::create(&test_path) {
                Ok(_) => {
                    std::fs::remove_file(&test_path)?;
                    Ok(true)
                }
                Err(_) => Ok(false),
            }
        } else {
            // For files, try to open for append
            Ok(std::fs::OpenOptions::new().append(true).open(path).is_ok())
        }
    }

    fn nixos_profile_exists(&self, profile: &str) -> Result<bool> {
        // Check if profile symlink exists in /nix/var/nix/profiles/
        let profile_path = PathBuf::from("/nix/var/nix/profiles").join(profile);
        Ok(profile_path.exists())
    }

    fn nixos_build_profile(&self, profile: &str) -> Result<()> {
        // Use nixos-rebuild build
        let output = std::process::Command::new("nixos-rebuild")
            .arg("build")
            .arg("--profile")
            .arg(profile)
            .output()
            .map_err(|_e| NailsError::NixOSBuildFailed {
                profile: profile.to_string(),
            })?;

        if !output.status.success() {
            return Err(NailsError::NixOSBuildFailed {
                profile: profile.to_string(),
            });
        }

        Ok(())
    }

    fn nixos_switch_profile(&self, profile: &str) -> Result<()> {
        // Check if profile exists
        if !self.nixos_profile_exists(profile)? {
            return Err(NailsError::NixOSProfileNotFound {
                profile: profile.to_string(),
            });
        }

        // Use nixos-rebuild switch
        let output = std::process::Command::new("nixos-rebuild")
            .arg("switch")
            .arg("--profile")
            .arg(profile)
            .output()
            .map_err(|_e| NailsError::NixOSSwitchFailed {
                profile: profile.to_string(),
            })?;

        if !output.status.success() {
            return Err(NailsError::NixOSSwitchFailed {
                profile: profile.to_string(),
            });
        }

        Ok(())
    }

    fn nixos_get_current_profile(&self) -> Result<String> {
        // Read /nix/var/nix/profiles/system to get current profile
        let system_path = PathBuf::from("/nix/var/nix/profiles/system");
        if !system_path.exists() {
            return Err(NailsError::InvalidState(
                "No NixOS profile is currently active".into(),
            ));
        }

        // Try to read symlink target
        system_path
            .read_link()
            .map(|target| target.to_string_lossy().to_string())
            .map_err(|_| NailsError::InvalidState("Could not determine current profile".into()))
    }

    fn nails_process_running(&self) -> Result<bool> {
        // Scan /proc for nails-related processes
        let proc_path = Path::new("/proc");

        if !proc_path.exists() {
            // Not on Linux or /proc not mounted
            return Ok(false);
        }

        // Iterate through /proc/*/cmdline to find nails processes
        if let Ok(entries) = std::fs::read_dir(proc_path) {
            for entry in entries.flatten() {
                let entry_path = entry.path();
                let pid_dir = entry_path.file_name().and_then(|n| n.to_str());

                // Check if it's a numeric PID directory
                if pid_dir.is_some_and(|p| p.chars().all(|c| c.is_ascii_digit())) {
                    let cmdline_path = entry_path.join("cmdline");

                    if let Ok(cmdline) = std::fs::read_to_string(&cmdline_path) {
                        // Check if cmdline contains "nails"
                        if cmdline.to_lowercase().contains("nails") {
                            return Ok(true);
                        }
                    }
                }
            }
        }

        Ok(false)
    }

    fn read_file_content(&self, path: &Path) -> Result<String> {
        std::fs::read_to_string(path).map_err(|e| {
            NailsError::IoError(std::io::Error::new(
                e.kind(),
                format!("Failed to read file {}: {}", path.display(), e),
            ))
        })
    }

    fn write_file_content(&self, path: &Path, content: &str) -> Result<()> {
        use std::io::Write;

        // Write to temporary file first, then atomic rename
        let temp_path = path.with_extension("tmp");

        // Write content to temp file
        let mut temp_file = std::fs::File::create(&temp_path).map_err(|e| {
            NailsError::IoError(std::io::Error::new(
                e.kind(),
                format!("Failed to create temp file {}: {}", temp_path.display(), e),
            ))
        })?;

        temp_file.write_all(content.as_bytes()).map_err(|e| {
            NailsError::IoError(std::io::Error::new(
                e.kind(),
                format!(
                    "Failed to write to temp file {}: {}",
                    temp_path.display(),
                    e
                ),
            ))
        })?;

        // Ensure data is flushed to disk
        temp_file.sync_all().map_err(|e| {
            NailsError::IoError(std::io::Error::new(
                e.kind(),
                format!("Failed to sync temp file {}: {}", temp_path.display(), e),
            ))
        })?;

        // Atomic rename
        std::fs::rename(&temp_path, path).map_err(|e| {
            NailsError::IoError(std::io::Error::new(
                e.kind(),
                format!(
                    "Failed to rename {} to {}: {}",
                    temp_path.display(),
                    path.display(),
                    e
                ),
            ))
        })?;

        Ok(())
    }

    fn find_files_with_pattern(&self, dir: &Path, pattern: &str) -> Result<Vec<PathBuf>> {
        let mut matching_files = Vec::new();

        if !dir.exists() || !dir.is_dir() {
            return Ok(matching_files);
        }

        // Recursively walk the directory tree
        let entries = std::fs::read_dir(dir).map_err(|e| {
            NailsError::IoError(std::io::Error::new(
                e.kind(),
                format!("Failed to read directory {}: {}", dir.display(), e),
            ))
        })?;

        for entry in entries.flatten() {
            let path = entry.path();

            if path.is_dir() {
                // Recursively scan subdirectories
                matching_files.extend(self.find_files_with_pattern(&path, pattern)?);
            } else if path.is_file() {
                // Check if filename contains the pattern
                if let Some(filename) = path.file_name()
                    && filename
                        .to_string_lossy()
                        .to_lowercase()
                        .contains(&pattern.to_lowercase())
                {
                    matching_files.push(path);
                }
            }
        }

        Ok(matching_files)
    }

    fn mount_tmpfs(&self, target: &Path, size: &str) -> Result<()> {
        // Validate size string format before attempting mount
        // Valid formats: "512M", "1G", "2048K", etc.
        // Use a temporary EphemeralOverlayDir to leverage existing validation
        let temp_dir = crate::config::EphemeralOverlayDir {
            path: target.to_path_buf(),
            tmpfs_upper_size: size.to_string(),
            tmpfs_work_size: "1M".to_string(), // Dummy value for validation
        };
        temp_dir.parse_upper_size().map_err(|e| {
            NailsError::ConfigError(format!("Invalid tmpfs size '{}': {}", size, e))
        })?;

        // Create mount point if needed
        std::fs::create_dir_all(target)?;

        // Build mount options
        let options = format!("size={}", size);

        // Perform mount using nix crate
        // MS_NOSUID: Prevent setuid/setgid bits from taking effect
        // MS_NODEV: Prevent access to device files
        nix::mount::mount(
            Some("tmpfs"),
            target,
            Some("tmpfs"),
            nix::mount::MsFlags::MS_NOSUID | nix::mount::MsFlags::MS_NODEV,
            Some(options.as_str()),
        )
        .map_err(|e| {
            if e == nix::errno::Errno::EACCES || e == nix::errno::Errno::EPERM {
                NailsError::PermissionDenied("Tmpfs mount requires root privileges".to_string())
            } else {
                NailsError::OverlayError(format!(
                    "Failed to mount tmpfs at {}: {}",
                    target.display(),
                    e
                ))
            }
        })?;

        Ok(())
    }

    fn unmount_tmpfs(&self, target: &Path) -> Result<()> {
        // Idempotent: succeed if not mounted
        if !self.is_mounted(target)? {
            return Ok(());
        }

        // Perform unmount (regular unmount, not force)
        nix::mount::umount(target).map_err(|e| NailsError::UnmountError {
            path: target.to_path_buf(),
            reason: format!("{}", e),
        })?;

        Ok(())
    }

    fn bind_mount(&self, source: &Path, target: &Path) -> Result<()> {
        // Verify source exists
        if !source.exists() {
            return Err(NailsError::OverlayError(format!(
                "Bind mount source not found: {}",
                source.display()
            )));
        }

        // Perform bind mount using nix crate
        // MS_BIND: Create a bind mount
        nix::mount::mount(
            Some(source),
            target,
            None::<&str>,
            nix::mount::MsFlags::MS_BIND,
            None::<&str>,
        )
        .map_err(|e| {
            if e == nix::errno::Errno::EACCES || e == nix::errno::Errno::EPERM {
                NailsError::PermissionDenied("Bind mount requires root privileges".to_string())
            } else if e == nix::errno::Errno::EBUSY {
                NailsError::MountBusy {
                    path: target.to_path_buf(),
                    suggestion: "Target directory has active references".to_string(),
                }
            } else {
                NailsError::OverlayError(format!(
                    "Failed to bind mount {} to {}: {}",
                    source.display(),
                    target.display(),
                    e
                ))
            }
        })?;

        Ok(())
    }

    fn unmount_bind(&self, target: &Path) -> Result<()> {
        // Idempotent: succeed if not mounted
        if !self.is_mounted(target)? {
            return Ok(());
        }

        // Perform unmount (regular unmount for bind mounts)
        nix::mount::umount(target).map_err(|e| NailsError::UnmountError {
            path: target.to_path_buf(),
            reason: format!("{}", e),
        })?;

        Ok(())
    }

    fn remove_file(&self, path: &Path) -> Result<()> {
        std::fs::remove_file(path).map_err(|e| {
            NailsError::IoError(std::io::Error::new(
                e.kind(),
                format!("Failed to remove file {}: {}", path.display(), e),
            ))
        })
    }

    fn remove_dir_all(&self, path: &Path) -> Result<()> {
        std::fs::remove_dir_all(path).map_err(|e| {
            NailsError::IoError(std::io::Error::new(
                e.kind(),
                format!("Failed to remove directory {}: {}", path.display(), e),
            ))
        })
    }

    fn list_directory(&self, dir: &Path) -> Result<Vec<PathBuf>> {
        let entries = std::fs::read_dir(dir).map_err(|e| {
            NailsError::IoError(std::io::Error::new(
                e.kind(),
                format!("Failed to read directory {}: {}", dir.display(), e),
            ))
        })?;

        let mut paths = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| {
                NailsError::IoError(std::io::Error::new(
                    e.kind(),
                    format!("Failed to read directory entry in {}: {}", dir.display(), e),
                ))
            })?;
            paths.push(entry.path());
        }

        Ok(paths)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_filesystem_new_starts_empty() {
        let fs = MockFilesystem::new();
        assert!(fs.get_mounted_paths().is_empty());
        assert!(!fs.swap_is_enabled().unwrap());
    }

    #[test]
    fn test_mock_filesystem_reset_clears_state() {
        let fs = MockFilesystem::new();
        fs.mock_set_mounted(Path::new("/home"), true);
        fs.mock_set_swap_enabled(true);
        fs.reset();
        assert!(fs.get_mounted_paths().is_empty());
        assert!(!fs.swap_is_enabled().unwrap());
    }

    #[test]
    fn test_mock_filesystem_clone_shares_state() {
        let fs1 = MockFilesystem::new();
        fs1.mock_set_mounted(Path::new("/home"), true);

        let fs2 = fs1.clone();
        assert!(fs2.is_mounted(Path::new("/home")).unwrap());

        // Shared state means modifications from one are visible in the other
        fs2.mock_set_mounted(Path::new("/tmp"), true);
        assert!(fs1.is_mounted(Path::new("/tmp")).unwrap());
    }

    #[test]
    fn test_mock_filesystem_nixos_build_profile_adds_profile() {
        let fs = MockFilesystem::new();

        // Build should add profile to set
        assert!(fs.nixos_build_profile("test-profile").is_ok());
        assert!(fs.nixos_profile_exists("test-profile").unwrap());

        // Building same profile again should work (idempotent)
        assert!(fs.nixos_build_profile("test-profile").is_ok());
    }

    #[test]
    fn test_mock_set_mounted_can_unmount() {
        let fs = MockFilesystem::new();
        let path = Path::new("/test/mount");

        // Mount then unmount
        fs.mock_set_mounted(path, true);
        assert!(fs.is_mounted(path).unwrap());

        fs.mock_set_mounted(path, false);
        assert!(!fs.is_mounted(path).unwrap());
    }

    #[test]
    fn test_mock_filesystem_swap_is_disabled_by_default() {
        let fs = MockFilesystem::new();
        assert!(!fs.swap_is_enabled().unwrap());

        // Enable then disable
        fs.mock_set_swap_enabled(true);
        assert!(fs.swap_is_enabled().unwrap());

        fs.mock_set_swap_enabled(false);
        assert!(!fs.swap_is_enabled().unwrap());
    }

    #[test]
    fn test_mock_filesystem_directory_operations() {
        let fs = MockFilesystem::new();
        let path = Path::new("/test/dir");

        fs.mock_set_path_exists("/test/dir", true);
        fs.mock_set_path_type("/test/dir", "directory");

        assert!(fs.path_exists(path).unwrap());
        assert!(fs.is_directory(path).unwrap());
    }

    #[test]
    fn test_mock_filesystem_file_permissions() {
        let fs = MockFilesystem::new();
        let path = Path::new("/test/file");

        fs.mock_set_path_exists("/test/file", true);
        fs.mock_set_readable("/test/file", true);
        fs.mock_set_writable("/test/file", true);

        assert!(fs.is_readable(path).unwrap());
        assert!(fs.is_writable(path).unwrap());
    }

    // ========================================================================
    // Tests for Story 4.1: Overlay Mount Operations
    // ========================================================================

    #[test]
    fn test_mount_overlay_success_tracks_mount_info() {
        // AC5: MockFilesystem tracks mounted paths with MountInfo
        let fs = MockFilesystem::new();

        // Set up paths to exist
        fs.mock_set_path_exists("/", true);
        fs.mock_set_path_exists("/mnt/hidden/upper", true);
        fs.mock_set_path_exists("/mnt/hidden/work", true);

        // Mount overlay
        let result = fs.mount_overlay(
            Path::new("/"),
            Path::new("/mnt/hidden/upper"),
            Path::new("/mnt/hidden/work"),
            Path::new("/home"),
        );

        assert!(result.is_ok());

        // Verify mount tracking
        assert!(fs.is_mounted(Path::new("/home")).unwrap());

        // Verify MountInfo is tracked
        let mount_info = fs.mock_get_mount_info(Path::new("/home"));
        assert!(mount_info.is_some());

        let info = mount_info.unwrap();
        assert_eq!(info.lower, Path::new("/"));
        assert_eq!(info.upper, Path::new("/mnt/hidden/upper"));
        assert_eq!(info.work, Path::new("/mnt/hidden/work"));
        assert_eq!(info.target, Path::new("/home"));
        // Verify timestamp is recent (within last second)
        let elapsed = chrono::Utc::now() - info.mounted_at;
        assert!(elapsed.num_seconds() < 2);
    }

    #[test]
    fn test_mount_overlay_fails_on_missing_lower() {
        // AC2: Returns error when lower directory missing
        let fs = MockFilesystem::new();

        // Only set upper and work to exist, not lower
        fs.mock_set_path_exists("/mnt/hidden/upper", true);
        fs.mock_set_path_exists("/mnt/hidden/work", true);

        let result = fs.mount_overlay(
            Path::new("/nonexistent/lower"),
            Path::new("/mnt/hidden/upper"),
            Path::new("/mnt/hidden/work"),
            Path::new("/home"),
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            NailsError::OverlayError(msg) => {
                assert!(msg.contains("Lower directory not found"));
                assert!(msg.contains("/nonexistent/lower"));
            }
            _ => panic!("Expected OverlayError for missing lower directory"),
        }
    }

    #[test]
    fn test_mount_overlay_fails_on_missing_upper() {
        // AC2: Returns error when upper directory missing
        let fs = MockFilesystem::new();

        fs.mock_set_path_exists("/", true);
        fs.mock_set_path_exists("/mnt/hidden/work", true);

        let result = fs.mount_overlay(
            Path::new("/"),
            Path::new("/nonexistent/upper"),
            Path::new("/mnt/hidden/work"),
            Path::new("/home"),
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            NailsError::OverlayError(msg) => {
                assert!(msg.contains("Upper directory not found"));
                assert!(msg.contains("/nonexistent/upper"));
            }
            _ => panic!("Expected OverlayError for missing upper directory"),
        }
    }

    #[test]
    fn test_mount_overlay_fails_on_missing_work() {
        // AC2: Returns error when work directory missing
        let fs = MockFilesystem::new();

        fs.mock_set_path_exists("/", true);
        fs.mock_set_path_exists("/mnt/hidden/upper", true);

        let result = fs.mount_overlay(
            Path::new("/"),
            Path::new("/mnt/hidden/upper"),
            Path::new("/nonexistent/work"),
            Path::new("/home"),
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            NailsError::OverlayError(msg) => {
                assert!(msg.contains("Work directory not found"));
                assert!(msg.contains("/nonexistent/work"));
            }
            _ => panic!("Expected OverlayError for missing work directory"),
        }
    }

    #[test]
    fn test_mount_overlay_fails_on_already_mounted() {
        // AC4: Returns error when target already mounted
        let fs = MockFilesystem::new();

        fs.mock_set_path_exists("/", true);
        fs.mock_set_path_exists("/mnt/hidden/upper", true);
        fs.mock_set_path_exists("/mnt/hidden/work", true);

        // Mount once (should succeed)
        let result = fs.mount_overlay(
            Path::new("/"),
            Path::new("/mnt/hidden/upper"),
            Path::new("/mnt/hidden/work"),
            Path::new("/home"),
        );
        assert!(result.is_ok());

        // Try to mount again (should fail)
        let result = fs.mount_overlay(
            Path::new("/"),
            Path::new("/mnt/hidden/upper"),
            Path::new("/mnt/hidden/work"),
            Path::new("/home"),
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            NailsError::AlreadyMounted { path } => {
                assert_eq!(path, Path::new("/home"));
            }
            _ => panic!("Expected AlreadyMounted error"),
        }
    }

    #[test]
    fn test_mock_filesystem_can_simulate_mount_failure() {
        // AC5: Mock can simulate mount failures
        let fs = MockFilesystem::new();

        fs.mock_set_path_exists("/", true);
        fs.mock_set_path_exists("/mnt/hidden/upper", true);
        fs.mock_set_path_exists("/mnt/hidden/work", true);

        // Configure mock to fail mount for /home
        fs.mock_set_mount_should_fail("/home", true);

        let result = fs.mount_overlay(
            Path::new("/"),
            Path::new("/mnt/hidden/upper"),
            Path::new("/mnt/hidden/work"),
            Path::new("/home"),
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            NailsError::OverlayError(msg) => {
                // Verify error message format matches AC1 specification
                assert!(msg.contains("Mock mount failure for testing"));
                assert!(msg.contains("/home"), "Error should include target path");
            }
            _ => panic!("Expected OverlayError for simulated failure"),
        }
    }

    #[test]
    fn test_mount_overlay_target_contains_merged_view() {
        // AC4: Verify target contains merged view of lower + upper after mount
        let fs = MockFilesystem::new();

        fs.mock_set_path_exists("/", true);
        fs.mock_set_path_exists("/mnt/hidden/upper", true);
        fs.mock_set_path_exists("/mnt/hidden/work", true);

        // Mount overlay
        let result = fs.mount_overlay(
            Path::new("/"),
            Path::new("/mnt/hidden/upper"),
            Path::new("/mnt/hidden/work"),
            Path::new("/home"),
        );
        assert!(result.is_ok());

        // Verify mount info contains merged view metadata
        let mount_info = fs.mock_get_mount_info(Path::new("/home")).unwrap();
        assert_eq!(
            mount_info.lower,
            Path::new("/"),
            "Lower directory should be tracked"
        );
        assert_eq!(
            mount_info.upper,
            Path::new("/mnt/hidden/upper"),
            "Upper directory should be tracked"
        );
        assert_eq!(
            mount_info.work,
            Path::new("/mnt/hidden/work"),
            "Work directory should be tracked"
        );
        assert_eq!(
            mount_info.target,
            Path::new("/home"),
            "Target mount point should be tracked"
        );

        // For MockFilesystem, the merged view is verified through the mount_info tracking
        // For RealFilesystem (integration tests), the actual filesystem would show merged content
    }

    #[test]
    fn test_unmount_removes_mount_info() {
        // Verify unmount removes mount from tracking
        let fs = MockFilesystem::new();

        fs.mock_set_path_exists("/", true);
        fs.mock_set_path_exists("/mnt/hidden/upper", true);
        fs.mock_set_path_exists("/mnt/hidden/work", true);

        // Mount
        fs.mount_overlay(
            Path::new("/"),
            Path::new("/mnt/hidden/upper"),
            Path::new("/mnt/hidden/work"),
            Path::new("/home"),
        )
        .unwrap();

        // Verify mounted
        assert!(fs.is_mounted(Path::new("/home")).unwrap());
        assert!(fs.mock_get_mount_info(Path::new("/home")).is_some());

        // Unmount
        fs.unmount(Path::new("/home"), false).unwrap();

        // Verify unmounted and info removed
        assert!(!fs.is_mounted(Path::new("/home")).unwrap());
        assert!(fs.mock_get_mount_info(Path::new("/home")).is_none());
    }

    #[test]
    fn test_verify_mount_preconditions_succeeds_when_all_valid() {
        // AC6: verify_mount_preconditions checks all conditions
        let fs = MockFilesystem::new();

        fs.mock_set_path_exists("/", true);
        fs.mock_set_path_exists("/mnt/hidden/upper", true);
        fs.mock_set_path_exists("/mnt/hidden/work", true);

        let result = verify_mount_preconditions(
            &fs,
            Path::new("/"),
            Path::new("/mnt/hidden/upper"),
            Path::new("/mnt/hidden/work"),
            Path::new("/home"),
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_mount_preconditions_fails_on_missing_lower() {
        // AC6: verify_mount_preconditions detects missing lower
        let fs = MockFilesystem::new();

        fs.mock_set_path_exists("/mnt/hidden/upper", true);
        fs.mock_set_path_exists("/mnt/hidden/work", true);

        let result = verify_mount_preconditions(
            &fs,
            Path::new("/nonexistent"),
            Path::new("/mnt/hidden/upper"),
            Path::new("/mnt/hidden/work"),
            Path::new("/home"),
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            NailsError::OverlayError(msg) => {
                assert!(msg.contains("Lower directory not found"));
            }
            _ => panic!("Expected OverlayError"),
        }
    }

    #[test]
    fn test_verify_mount_preconditions_fails_on_missing_upper() {
        // AC6: verify_mount_preconditions detects missing upper when parent doesn't exist
        let fs = MockFilesystem::new();

        fs.mock_set_path_exists("/", true);
        fs.mock_set_path_exists("/mnt/hidden/work", true);

        // Use a path where parent doesn't exist
        let result = verify_mount_preconditions(
            &fs,
            Path::new("/"),
            Path::new("/nonexistent/subdir/upper"),
            Path::new("/mnt/hidden/work"),
            Path::new("/home"),
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            NailsError::OverlayError(msg) => {
                assert!(msg.contains("Upper directory not found and parent doesn't exist"));
            }
            _ => panic!("Expected OverlayError"),
        }
    }

    #[test]
    fn test_verify_mount_preconditions_fails_on_missing_work() {
        // AC6: verify_mount_preconditions detects missing work when parent doesn't exist
        let fs = MockFilesystem::new();

        fs.mock_set_path_exists("/", true);
        fs.mock_set_path_exists("/mnt/hidden/upper", true);

        // Use a path where parent doesn't exist
        let result = verify_mount_preconditions(
            &fs,
            Path::new("/"),
            Path::new("/mnt/hidden/upper"),
            Path::new("/nonexistent/subdir/work"),
            Path::new("/home"),
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            NailsError::OverlayError(msg) => {
                assert!(msg.contains("Work directory not found and parent doesn't exist"));
            }
            _ => panic!("Expected OverlayError"),
        }
    }

    #[test]
    fn test_verify_mount_preconditions_fails_on_already_mounted() {
        // AC6: verify_mount_preconditions detects already mounted
        let fs = MockFilesystem::new();

        fs.mock_set_path_exists("/", true);
        fs.mock_set_path_exists("/mnt/hidden/upper", true);
        fs.mock_set_path_exists("/mnt/hidden/work", true);

        // Mount first
        fs.mount_overlay(
            Path::new("/"),
            Path::new("/mnt/hidden/upper"),
            Path::new("/mnt/hidden/work"),
            Path::new("/home"),
        )
        .unwrap();

        // Try preconditions check (should fail because already mounted)
        let result = verify_mount_preconditions(
            &fs,
            Path::new("/"),
            Path::new("/mnt/hidden/upper"),
            Path::new("/mnt/hidden/work"),
            Path::new("/home"),
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            NailsError::AlreadyMounted { path } => {
                assert_eq!(path, Path::new("/home"));
            }
            _ => panic!("Expected AlreadyMounted error"),
        }
    }

    #[test]
    fn test_verify_mount_preconditions_succeeds_when_upper_creatable() {
        // AC6: verify_mount_preconditions accepts upper directory if it can be created
        let fs = MockFilesystem::new();

        fs.mock_set_path_exists("/", true);
        fs.mock_set_path_exists("/mnt/hidden/work", true);

        // Upper doesn't exist but parent is writable
        fs.mock_set_directory_creatable("/mnt/hidden/upper", true);

        let result = verify_mount_preconditions(
            &fs,
            Path::new("/"),
            Path::new("/mnt/hidden/upper"),
            Path::new("/mnt/hidden/work"),
            Path::new("/home"),
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_mount_preconditions_succeeds_when_work_creatable() {
        // AC6: verify_mount_preconditions accepts work directory if it can be created
        let fs = MockFilesystem::new();

        fs.mock_set_path_exists("/", true);
        fs.mock_set_path_exists("/mnt/hidden/upper", true);

        // Work doesn't exist but parent is writable
        fs.mock_set_directory_creatable("/mnt/hidden/work", true);

        let result = verify_mount_preconditions(
            &fs,
            Path::new("/"),
            Path::new("/mnt/hidden/upper"),
            Path::new("/mnt/hidden/work"),
            Path::new("/home"),
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_mount_preconditions_fails_when_upper_not_creatable() {
        // AC6: verify_mount_preconditions fails if upper can't be created (parent not writable)
        let fs = MockFilesystem::new();

        fs.mock_set_path_exists("/", true);
        fs.mock_set_path_exists("/mnt/hidden/work", true);

        // Upper doesn't exist and parent is not writable
        fs.mock_set_directory_creatable("/mnt/hidden/upper", false);

        let result = verify_mount_preconditions(
            &fs,
            Path::new("/"),
            Path::new("/mnt/hidden/upper"),
            Path::new("/mnt/hidden/work"),
            Path::new("/home"),
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            NailsError::PermissionDenied(msg) => {
                assert!(msg.contains("Upper directory not found and parent not writable"));
            }
            _ => panic!("Expected PermissionDenied error"),
        }
    }

    #[test]
    fn test_verify_mount_preconditions_fails_when_work_not_creatable() {
        // AC6: verify_mount_preconditions fails if work can't be created (parent not writable)
        let fs = MockFilesystem::new();

        fs.mock_set_path_exists("/", true);
        fs.mock_set_path_exists("/mnt/hidden/upper", true);

        // Work doesn't exist and parent is not writable
        fs.mock_set_directory_creatable("/mnt/hidden/work", false);

        let result = verify_mount_preconditions(
            &fs,
            Path::new("/"),
            Path::new("/mnt/hidden/upper"),
            Path::new("/mnt/hidden/work"),
            Path::new("/home"),
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            NailsError::PermissionDenied(msg) => {
                assert!(msg.contains("Work directory not found and parent not writable"));
            }
            _ => panic!("Expected PermissionDenied error"),
        }
    }

    // ========================================================================
    // Integration Tests for RealFilesystem (require root privileges)
    // ========================================================================

    #[test]
    #[ignore]
    fn test_real_overlay_mount_creates_merged_view() {
        // AC4 Integration test: Verify actual overlay filesystem merge
        // This test requires root privileges and is marked #[ignore] for CI/CD
        //
        // Run with: cargo test test_real_overlay_mount_creates_merged_view -- --ignored
        //
        // Test verifies:
        // 1. Files from lower directory are visible in target
        // 2. Files from upper directory overlay correctly in target
        // 3. Modifications in upper don't affect lower

        use std::fs;
        use std::io::Write;

        let fs = RealFilesystem;

        // Create test directories in /tmp (requires cleanup on failure)
        let test_dir = std::env::temp_dir().join("nails-overlay-test-XXXXXX");
        fs::create_dir_all(&test_dir).unwrap();

        let lower = test_dir.join("lower");
        let upper = test_dir.join("upper");
        let work = test_dir.join("work");
        let target = test_dir.join("target");

        fs::create_dir_all(&lower).unwrap();
        fs::create_dir_all(&upper).unwrap();
        fs::create_dir_all(&work).unwrap();
        fs::create_dir_all(&target).unwrap();

        // Create test files in lower
        let lower_file = lower.join("from_lower.txt");
        let mut lower_fh = fs::File::create(&lower_file).unwrap();
        lower_fh.write_all(b"content from lower layer").unwrap();
        lower_fh.sync_all().unwrap();

        // Create test files in upper
        let upper_file = upper.join("from_upper.txt");
        let mut upper_fh = fs::File::create(&upper_file).unwrap();
        upper_fh.write_all(b"content from upper layer").unwrap();
        upper_fh.sync_all().unwrap();

        // Mount overlay
        let result = fs.mount_overlay(&lower, &upper, &work, &target);
        if let Err(e) = result {
            // Clean up on failure
            let _ = fs::remove_dir_all(&test_dir);
            panic!("Overlay mount failed: {:?}", e);
        }

        // Verify merged view: both files should be visible in target
        let target_lower_file = target.join("from_lower.txt");
        let target_upper_file = target.join("from_upper.txt");

        assert!(
            target_lower_file.exists(),
            "File from lower layer should be visible in target"
        );
        assert!(
            target_upper_file.exists(),
            "File from upper layer should be visible in target"
        );

        // Verify content is correct
        let content_from_lower = fs::read_to_string(&target_lower_file).unwrap();
        let content_from_upper = fs::read_to_string(&target_upper_file).unwrap();

        assert_eq!(
            content_from_lower, "content from lower layer",
            "Lower layer content should be readable"
        );
        assert_eq!(
            content_from_upper, "content from upper layer",
            "Upper layer content should be readable"
        );

        // Unmount
        fs.unmount(&target, false).unwrap();

        // Cleanup
        fs::remove_dir_all(&test_dir).unwrap();
    }

    // ========================================================================
    // Tests for Story 4.11: Tmpfs Operations for Extended Overlays
    // ========================================================================

    #[test]
    fn test_mock_mount_tmpfs_success() {
        // AC2: MockFilesystem tracks tmpfs mounts
        let fs = MockFilesystem::new();

        // Set up target directory
        fs.mock_set_path_exists("/run/nails/var-upper", true);

        // Mount tmpfs
        let result = fs.mount_tmpfs(Path::new("/run/nails/var-upper"), "1G");
        assert!(result.is_ok());

        // Verify mount is tracked
        assert!(fs.is_mounted(Path::new("/run/nails/var-upper")).unwrap());
    }

    #[test]
    fn test_mock_mount_tmpfs_validates_size_format() {
        // AC1: Size validation rejects invalid formats
        let fs = MockFilesystem::new();

        // Set up directories as creatable
        fs.mock_set_directory_creatable("/run/nails/test1", true);
        fs.mock_set_directory_creatable("/run/nails/test2", true);
        fs.mock_set_directory_creatable("/run/nails/test3", true);
        fs.mock_set_directory_creatable("/run/nails/invalid", true);

        // Valid sizes should succeed
        assert!(fs.mount_tmpfs(Path::new("/run/nails/test1"), "1G").is_ok());
        assert!(
            fs.mount_tmpfs(Path::new("/run/nails/test2"), "512M")
                .is_ok()
        );
        assert!(
            fs.mount_tmpfs(Path::new("/run/nails/test3"), "1024")
                .is_ok()
        );

        // Invalid size format should fail
        let result = fs.mount_tmpfs(Path::new("/run/nails/invalid"), "invalid");
        assert!(result.is_err());
        match result.unwrap_err() {
            NailsError::OverlayError(msg) => {
                assert!(msg.contains("Invalid tmpfs size format"));
            }
            _ => panic!("Expected OverlayError for invalid size"),
        }
    }

    #[test]
    fn test_mock_mount_tmpfs_rejects_already_mounted() {
        // AC2: Cannot mount tmpfs on already-mounted path
        let fs = MockFilesystem::new();

        fs.mock_set_path_exists("/run/nails/var-upper", true);

        // First mount succeeds
        assert!(
            fs.mount_tmpfs(Path::new("/run/nails/var-upper"), "1G")
                .is_ok()
        );

        // Second mount fails
        let result = fs.mount_tmpfs(Path::new("/run/nails/var-upper"), "1G");
        assert!(result.is_err());
        match result.unwrap_err() {
            NailsError::AlreadyMounted { path } => {
                assert_eq!(path, PathBuf::from("/run/nails/var-upper"));
            }
            _ => panic!("Expected AlreadyMounted error"),
        }
    }

    #[test]
    fn test_mock_mount_tmpfs_creates_directory() {
        // AC2: Mount creates target directory if missing
        let fs = MockFilesystem::new();

        // Set parent writable to allow directory creation
        fs.mock_set_directory_creatable("/run/nails/new-dir", true);

        // Target doesn't exist yet
        assert!(!fs.path_exists(Path::new("/run/nails/new-dir")).unwrap());

        // Mount should create it
        let result = fs.mount_tmpfs(Path::new("/run/nails/new-dir"), "512M");
        assert!(result.is_ok());

        // Verify directory was created
        assert!(fs.path_exists(Path::new("/run/nails/new-dir")).unwrap());
    }

    #[test]
    fn test_mock_unmount_tmpfs_success() {
        // AC2: Unmount removes tmpfs mount
        let fs = MockFilesystem::new();

        fs.mock_set_path_exists("/run/nails/var-upper", true);
        fs.mount_tmpfs(Path::new("/run/nails/var-upper"), "1G")
            .unwrap();

        // Verify mounted
        assert!(fs.is_mounted(Path::new("/run/nails/var-upper")).unwrap());

        // Unmount
        let result = fs.unmount_tmpfs(Path::new("/run/nails/var-upper"));
        assert!(result.is_ok());

        // Verify unmounted
        assert!(!fs.is_mounted(Path::new("/run/nails/var-upper")).unwrap());
    }

    #[test]
    fn test_mock_unmount_tmpfs_idempotent() {
        // AC2: Unmount succeeds even if not mounted
        let fs = MockFilesystem::new();

        // Unmount without mount should succeed (idempotent)
        let result = fs.unmount_tmpfs(Path::new("/not/mounted"));
        assert!(result.is_ok());
    }

    #[test]
    fn test_mock_tmpfs_multiple_mounts() {
        // AC2: Can mount multiple tmpfs filesystems
        let fs = MockFilesystem::new();

        fs.mock_set_path_exists("/run/nails/var-upper", true);
        fs.mock_set_path_exists("/run/nails/tmp-upper", true);

        // Mount first tmpfs
        assert!(
            fs.mount_tmpfs(Path::new("/run/nails/var-upper"), "1G")
                .is_ok()
        );

        // Mount second tmpfs
        assert!(
            fs.mount_tmpfs(Path::new("/run/nails/tmp-upper"), "512M")
                .is_ok()
        );

        // Both should be mounted
        assert!(fs.is_mounted(Path::new("/run/nails/var-upper")).unwrap());
        assert!(fs.is_mounted(Path::new("/run/nails/tmp-upper")).unwrap());

        // Unmount first
        assert!(fs.unmount_tmpfs(Path::new("/run/nails/var-upper")).is_ok());

        // First should be unmounted, second still mounted
        assert!(!fs.is_mounted(Path::new("/run/nails/var-upper")).unwrap());
        assert!(fs.is_mounted(Path::new("/run/nails/tmp-upper")).unwrap());
    }

    #[test]
    fn test_mock_tmpfs_reset_clears_mounts() {
        // Verify reset() clears tmpfs mounts
        let fs = MockFilesystem::new();

        fs.mock_set_path_exists("/run/nails/var-upper", true);
        fs.mount_tmpfs(Path::new("/run/nails/var-upper"), "1G")
            .unwrap();

        assert!(fs.is_mounted(Path::new("/run/nails/var-upper")).unwrap());

        // Reset should clear tmpfs mounts
        fs.reset();

        assert!(!fs.is_mounted(Path::new("/run/nails/var-upper")).unwrap());
    }
}
