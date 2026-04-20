use super::super::MountInfo;
use chrono::{DateTime, Utc};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

pub(super) const DEFAULT_MOCK_FREE_SPACE_BYTES: u64 = 1 << 40;

/// Path metadata for MockFilesystem
#[derive(Debug, Clone)]
pub(super) struct PathInfo {
    pub(super) exists: bool,
    pub(super) is_directory: bool,
    pub(super) is_symlink: bool,
    pub(super) is_readable: bool,
    pub(super) is_writable: bool,
    pub(super) free_space: u64,
}

impl Default for PathInfo {
    fn default() -> Self {
        Self {
            exists: false,
            is_directory: false,
            is_symlink: false,
            is_readable: true,
            is_writable: true,
            free_space: DEFAULT_MOCK_FREE_SPACE_BYTES,
        }
    }
}

/// Operation log entries for MockFilesystem (test assertions)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MockOp {
    MountOverlay { target: PathBuf },
    WriteFile { path: PathBuf },
    CopyTree { src: PathBuf, dst: PathBuf },
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
    pub(super) mounted: Arc<Mutex<HashSet<PathBuf>>>,
    pub(super) swap_enabled: Arc<Mutex<bool>>,
    pub(super) paths: Arc<Mutex<HashMap<PathBuf, PathInfo>>>,
    pub(super) busy: Arc<Mutex<HashSet<PathBuf>>>,
    pub(super) nixos_profiles: Arc<Mutex<HashSet<String>>>,
    pub(super) current_profile: Arc<Mutex<Option<String>>>,
    pub(super) mount_should_fail: Arc<Mutex<HashSet<PathBuf>>>,
    pub(super) unmount_should_fail: Arc<Mutex<HashSet<PathBuf>>>,
    pub(super) unmount_graceful_fails: Arc<Mutex<HashSet<PathBuf>>>,
    pub(super) nails_process_running: Arc<Mutex<bool>>,
    pub(super) file_contents: Arc<Mutex<HashMap<PathBuf, String>>>,
    #[allow(clippy::type_complexity)]
    pub(super) files_with_pattern: Arc<Mutex<HashMap<(PathBuf, String), Vec<PathBuf>>>>,
    pub(super) mounted_overlays: Arc<Mutex<HashMap<PathBuf, MountInfo>>>,
    pub(super) tmpfs_mounts: Arc<Mutex<HashSet<PathBuf>>>,
    pub(super) bind_mounts: Arc<Mutex<HashMap<PathBuf, PathBuf>>>,
    pub(super) written_files: Arc<Mutex<HashMap<PathBuf, String>>>,
    pub(super) remove_should_fail: Arc<Mutex<HashSet<PathBuf>>>,
    pub(super) directory_contents: Arc<Mutex<HashMap<PathBuf, Vec<PathBuf>>>>,
    pub(super) write_should_fail: Arc<Mutex<HashSet<PathBuf>>>,
    pub(super) rename_should_fail: Arc<Mutex<HashSet<PathBuf>>>,
    pub(super) explicit_file_sizes: Arc<Mutex<HashSet<PathBuf>>>,
    pub(super) modified_times: Arc<Mutex<HashMap<PathBuf, DateTime<Utc>>>>,
    pub(super) permissions: Arc<Mutex<HashMap<PathBuf, u32>>>,
    pub(super) root_directories: Arc<Mutex<Vec<PathBuf>>>,
    pub(super) root_symlinks: Arc<Mutex<Vec<PathBuf>>>,
    pub(super) symlink_targets: Arc<Mutex<HashMap<PathBuf, PathBuf>>>,
    pub(super) symlink_support: Arc<Mutex<HashMap<PathBuf, bool>>>,
    pub(super) filesystem_types: Arc<Mutex<HashMap<PathBuf, String>>>,
    pub(super) op_log: Arc<Mutex<Vec<MockOp>>>,
    pub(super) copy_tree_should_fail: Arc<Mutex<HashSet<PathBuf>>>,
    pub(super) directory_sizes: Arc<Mutex<HashMap<PathBuf, u64>>>,
    #[allow(clippy::type_complexity)]
    pub(super) submount_sources: Arc<Mutex<HashMap<PathBuf, Vec<(PathBuf, PathBuf)>>>>,
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
            rename_should_fail: Arc::new(Mutex::new(HashSet::new())),
            explicit_file_sizes: Arc::new(Mutex::new(HashSet::new())),
            modified_times: Arc::new(Mutex::new(HashMap::new())),
            permissions: Arc::new(Mutex::new(HashMap::new())),
            root_directories: Arc::new(Mutex::new(Vec::new())),
            root_symlinks: Arc::new(Mutex::new(Vec::new())),
            symlink_targets: Arc::new(Mutex::new(HashMap::new())),
            symlink_support: Arc::new(Mutex::new(HashMap::new())),
            filesystem_types: Arc::new(Mutex::new(HashMap::new())),
            op_log: Arc::new(Mutex::new(Vec::new())),
            copy_tree_should_fail: Arc::new(Mutex::new(HashSet::new())),
            directory_sizes: Arc::new(Mutex::new(HashMap::new())),
            submount_sources: Arc::new(Mutex::new(HashMap::new())),
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
        self.mounted
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .clear();
        *self
            .swap_enabled
            .lock()
            .expect("MockFilesystem mutex poisoned") = false;
        self.paths
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .clear();
        self.busy
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .clear();
        self.nixos_profiles
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .clear();
        self.current_profile
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .take();
        self.mount_should_fail
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .clear();
        self.unmount_should_fail
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .clear();
        self.mounted_overlays
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .clear();
        self.tmpfs_mounts
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .clear();
        self.bind_mounts
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .clear();
        self.written_files
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .clear();
        self.remove_should_fail
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .clear();
        self.directory_contents
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .clear();
        self.write_should_fail
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .clear();
        self.rename_should_fail
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .clear();
        self.explicit_file_sizes
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .clear();
        self.modified_times
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .clear();
        self.permissions
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .clear();
        self.symlink_targets
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .clear();
        self.symlink_support
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .clear();
        self.op_log
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .clear();
        self.copy_tree_should_fail
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .clear();
        self.directory_sizes
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .clear();
        self.submount_sources
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .clear();
    }
}

impl Default for MockFilesystem {
    fn default() -> Self {
        Self::new()
    }
}
