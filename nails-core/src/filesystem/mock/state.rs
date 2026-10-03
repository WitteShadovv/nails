use super::super::{MountInfo, MountSource, ProcessMatch};
use chrono::{DateTime, Utc};
use nix::errno::Errno;
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
    pub(super) total_space: u64,
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
            total_space: DEFAULT_MOCK_FREE_SPACE_BYTES,
        }
    }
}

/// Operation log entries for MockFilesystem (test assertions)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MockOp {
    MountOverlay { target: PathBuf },
    MountTmpfs { target: PathBuf, size: String },
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
/// - `tmpfs_mounts`: HashSet of paths with tmpfs mounted
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
    /// Paths whose `is_mounted` check fails, mapped to the error message to
    /// return. Lets tests exercise the status command's handling of an
    /// unreadable mount table without a bespoke fake filesystem.
    pub(super) is_mounted_errors: Arc<Mutex<HashMap<PathBuf, String>>>,
    /// Paths whose mount operations fail, mapped to the errno they fail with.
    /// The errno lets tests exercise the strategy's EINVAL/EBUSY/EOPNOTSUPP
    /// pivot-fallback branch versus a fatal errno.
    pub(super) mount_should_fail: Arc<Mutex<HashMap<PathBuf, Errno>>>,
    pub(super) unmount_should_fail: Arc<Mutex<HashSet<PathBuf>>>,
    pub(super) unmount_graceful_fails: Arc<Mutex<HashSet<PathBuf>>>,
    pub(super) nails_process_running: Arc<Mutex<bool>>,
    /// Explicit classified process matches returned by
    /// [`Filesystem::nails_process_matches`](crate::Filesystem::nails_process_matches).
    /// When unset, the match list is derived from `nails_process_running` (a
    /// single strong match when it is true), so tests that only set the boolean
    /// keep their meaning.
    pub(super) nails_process_matches: Arc<Mutex<Option<Vec<ProcessMatch>>>>,
    /// Directories that [`Filesystem::scan_files_with_pattern`](crate::Filesystem::scan_files_with_pattern)
    /// reports as unreadable (permission denied) rather than walking.
    pub(super) unreadable_dirs: Arc<Mutex<HashSet<PathBuf>>>,
    pub(super) file_contents: Arc<Mutex<HashMap<PathBuf, String>>>,
    #[allow(clippy::type_complexity)]
    pub(super) files_with_pattern: Arc<Mutex<HashMap<(PathBuf, String), Vec<PathBuf>>>>,
    pub(super) mounted_overlays: Arc<Mutex<HashMap<PathBuf, MountInfo>>>,
    /// Device, dm name and label backing a mount point, keyed by mount point.
    /// Lets tests drive the hidden-volume name check without a real mount table.
    pub(super) mount_sources: Arc<Mutex<HashMap<PathBuf, MountSource>>>,
    /// Device ids reported by [`Filesystem::device_id`](crate::Filesystem::device_id),
    /// keyed by path. Unset paths fall back to a per-path distinct id (see
    /// [`MockFilesystem::device_id_impl`]), so by default a path differs from `/`
    /// and only reads as unattached when a test maps it onto `/`'s id with
    /// [`mock_set_device_id`](Self::mock_set_device_id).
    pub(super) device_ids: Arc<Mutex<HashMap<PathBuf, u64>>>,
    /// Mounts NAILS is considered to own and may therefore unmount. Mirrors the
    /// real ownership gate: `unmount` of a mounted-but-unowned path (e.g. a plain
    /// ext4 `/home` set up with `mock_set_mount_unmanaged`) is refused. Every
    /// mount created through a mount API, or marked with `mock_set_mounted`, is
    /// owned.
    pub(super) nails_owned_mounts: Arc<Mutex<HashSet<PathBuf>>>,
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
    pub(super) permissions_should_fail: Arc<Mutex<HashSet<PathBuf>>>,
    /// Numeric `(uid, gid)` ownership recorded by `write_user_file`, so tests can
    /// assert a file or created directory ends up owned by the target user.
    pub(super) owners: Arc<Mutex<HashMap<PathBuf, (u32, u32)>>>,
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
    /// Classified submounts per target, returned by
    /// [`Filesystem::find_submounts`](crate::Filesystem::find_submounts).
    pub(super) submounts: Arc<Mutex<HashMap<PathBuf, Vec<crate::filesystem::Submount>>>>,
    /// Paths a read-only self-bind guard was applied to via
    /// [`Filesystem::remount_read_only`](crate::Filesystem::remount_read_only).
    pub(super) read_only_guards: Arc<Mutex<HashSet<PathBuf>>>,
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
            is_mounted_errors: Arc::new(Mutex::new(HashMap::new())),
            mount_should_fail: Arc::new(Mutex::new(HashMap::new())),
            unmount_should_fail: Arc::new(Mutex::new(HashSet::new())),
            unmount_graceful_fails: Arc::new(Mutex::new(HashSet::new())),
            nails_process_running: Arc::new(Mutex::new(false)),
            nails_process_matches: Arc::new(Mutex::new(None)),
            unreadable_dirs: Arc::new(Mutex::new(HashSet::new())),
            file_contents: Arc::new(Mutex::new(HashMap::new())),
            files_with_pattern: Arc::new(Mutex::new(HashMap::new())),
            mounted_overlays: Arc::new(Mutex::new(HashMap::new())),
            mount_sources: Arc::new(Mutex::new(HashMap::new())),
            device_ids: Arc::new(Mutex::new(HashMap::new())),
            nails_owned_mounts: Arc::new(Mutex::new(HashSet::new())),
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
            permissions_should_fail: Arc::new(Mutex::new(HashSet::new())),
            owners: Arc::new(Mutex::new(HashMap::new())),
            root_directories: Arc::new(Mutex::new(Vec::new())),
            root_symlinks: Arc::new(Mutex::new(Vec::new())),
            symlink_targets: Arc::new(Mutex::new(HashMap::new())),
            symlink_support: Arc::new(Mutex::new(HashMap::new())),
            filesystem_types: Arc::new(Mutex::new(HashMap::new())),
            op_log: Arc::new(Mutex::new(Vec::new())),
            copy_tree_should_fail: Arc::new(Mutex::new(HashSet::new())),
            directory_sizes: Arc::new(Mutex::new(HashMap::new())),
            submount_sources: Arc::new(Mutex::new(HashMap::new())),
            submounts: Arc::new(Mutex::new(HashMap::new())),
            read_only_guards: Arc::new(Mutex::new(HashSet::new())),
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
        self.is_mounted_errors
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .clear();
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
        self.mount_sources
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .clear();
        self.device_ids
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .clear();
        self.nails_owned_mounts
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
        self.read_only_guards
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
        self.permissions_should_fail
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .clear();
        self.owners
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
        self.submounts
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
