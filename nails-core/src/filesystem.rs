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
}

// ============================================================================
// MockFilesystem - In-Memory Testing Implementation
// ============================================================================

/// Path metadata for MockFilesystem
#[derive(Debug, Clone)]
struct PathInfo {
    exists: bool,
    is_directory: bool,
    is_readable: bool,
    is_writable: bool,
    free_space: u64,
}

impl Default for PathInfo {
    fn default() -> Self {
        Self {
            exists: false,
            is_directory: false,
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
    unmount_should_fail: Arc<Mutex<HashSet<PathBuf>>>, // Paths that should fail to unmount
    nails_process_running: Arc<Mutex<bool>>,         // Whether nails processes are running
    file_contents: Arc<Mutex<HashMap<PathBuf, String>>>, // Mock file contents
    #[allow(clippy::type_complexity)]
    files_with_pattern: Arc<Mutex<HashMap<(PathBuf, String), Vec<PathBuf>>>>, // Mock pattern search results
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
            nails_process_running: Arc::new(Mutex::new(false)),
            file_contents: Arc::new(Mutex::new(HashMap::new())),
            files_with_pattern: Arc::new(Mutex::new(HashMap::new())),
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

    /// Get list of currently mounted paths
    ///
    /// Useful for test assertions.
    pub fn get_mounted_paths(&self) -> Vec<PathBuf> {
        self.mounted.lock().unwrap().iter().cloned().collect()
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

        // Check if target already mounted
        let mounts = self.mounted.lock().unwrap();
        if mounts.contains(target) {
            return Err(NailsError::AlreadyMounted {
                path: target.to_path_buf(),
            });
        }
        drop(mounts);

        // Validate lower path exists
        let paths = self.paths.lock().unwrap();
        if !paths.get(lower).map(|info| info.exists).unwrap_or(false) {
            return Err(NailsError::OverlayError(format!(
                "Lower path does not exist: {}",
                lower.display()
            )));
        }

        // Validate upper path exists
        if !paths.get(upper).map(|info| info.exists).unwrap_or(false) {
            return Err(NailsError::OverlayError(format!(
                "Upper path does not exist: {}",
                upper.display()
            )));
        }

        // Validate work path exists
        if !paths.get(work).map(|info| info.exists).unwrap_or(false) {
            return Err(NailsError::OverlayError(format!(
                "Work path does not exist: {}",
                work.display()
            )));
        }
        drop(paths);

        // Add to mounted set
        self.mounted.lock().unwrap().insert(target.to_path_buf());
        Ok(())
    }

    fn unmount(&self, target: &Path, force: bool) -> Result<()> {
        // Check if this unmount should fail (for testing rollback)
        let fail_set = self.unmount_should_fail.lock().unwrap();
        if fail_set.contains(target) {
            return Err(NailsError::UnmountError {
                path: target.to_path_buf(),
                reason: "Mock unmount failure for testing".to_string(),
            });
        }
        drop(fail_set);

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

        // Remove from mounted set
        mounts.remove(target);
        Ok(())
    }

    fn is_mounted(&self, target: &Path) -> Result<bool> {
        Ok(self.mounted.lock().unwrap().contains(target))
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
        Ok(pattern_results.get(&key).cloned().unwrap_or_default())
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
        // Check if already mounted
        if self.is_mounted(target)? {
            return Err(NailsError::AlreadyMounted {
                path: target.to_path_buf(),
            });
        }

        // Validate paths exist
        if !lower.exists() {
            return Err(NailsError::OverlayError(format!(
                "Lower path does not exist: {}",
                lower.display()
            )));
        }
        if !upper.exists() {
            return Err(NailsError::OverlayError(format!(
                "Upper path does not exist: {}",
                upper.display()
            )));
        }
        if !work.exists() {
            return Err(NailsError::OverlayError(format!(
                "Work path does not exist: {}",
                work.display()
            )));
        }

        // Build overlay options
        let options = format!(
            "lowerdir={},upperdir={},workdir={}",
            lower.display(),
            upper.display(),
            work.display()
        );

        // Perform mount using nix crate
        nix::mount::mount(
            Some("overlay"),
            target,
            Some("overlay"),
            nix::mount::MsFlags::empty(),
            Some(options.as_str()),
        )
        .map_err(|e| NailsError::OverlayError(format!("Mount failed: {}", e)))?;

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
}
