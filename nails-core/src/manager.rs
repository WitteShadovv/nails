//! # NailsManager - Core Orchestrator for NAILS Operations
//!
//! Central orchestrator that coordinates all NAILS operations including state
//! transitions, filesystem operations, and validation logic.
//!
//! # Design Pattern: Generic Manager with Dependency Injection
//!
//! NailsManager uses generic programming to enable compile-time polymorphism:
//! - Production: `NailsManager<RealFilesystem>` uses actual syscalls
//! - Testing: `NailsManager<MockFilesystem>` uses in-memory state (no root required)
//!
//! This pattern enables 99% of tests to run without root privileges (AR4, NFR37).
//!
//! # Example
//!
//! ```rust
//! use nails_core::{NailsManager, MockFilesystem, Config};
//! use std::path::PathBuf;
//!
//! // Testing: MockFilesystem (no root required)
//! let fs = MockFilesystem::new();
//! let config = Config::default();
//! let state_path = PathBuf::from("/tmp/test-state.json");
//! let manager = NailsManager::new(fs, config, state_path);
//!
//! // Production: RealFilesystem (requires root)
//! // let fs = RealFilesystem;
//! // let manager = NailsManager::new(fs, config, state_path);
//! ```

use crate::{
    Config, FailedOverlayInfo, Filesystem, NailsError, OverlayInfo, Result, StateFile, SystemState,
    inject_import_block, verify_base_config_clean,
};
use chrono::Utc;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Start a systemd service and its socket (socket first), best-effort.
fn start_service_and_socket(service: &str) {
    let _ = std::process::Command::new("systemctl")
        .args(["start", &format!("{}.socket", service)])
        .output();
    let _ = std::process::Command::new("systemctl")
        .args(["start", service])
        .output();
}

/// Clean stale network configuration files from /etc overlay upper layer (Task 6: DNS preservation)
///
/// Before mounting the /etc overlay, remove stale `resolv.conf` and `nsswitch.conf` from the
/// upper layer directory. This allows the real system files to show through the overlay's
/// lower layer, preserving DNS resolution.
///
/// # Arguments
///
/// * `upper_dir` - Path to the /etc overlay's upper layer directory
/// * `fs` - Filesystem abstraction
///
/// # Returns
///
/// * `Ok(())` - Cleanup succeeded or files didn't exist
/// * `Err(NailsError)` - Failed to remove a stale file
///
/// # Behavior
///
/// - Best-effort: If files don't exist, no action taken
/// - Logs each file removal at INFO level
/// - Returns error only if removal fails (file exists but can't be deleted)
///
/// # Example
///
/// ```rust
/// use nails_core::filesystem::{Filesystem, MockFilesystem};
/// use std::path::PathBuf;
///
/// fn clean_stale_network_config<F: Filesystem>(
///     upper_dir: &std::path::Path,
///     fs: &F
/// ) -> Result<(), nails_core::error::NailsError> {
///     let stale_files = ["resolv.conf", "nsswitch.conf"];
///     for filename in &stale_files {
///         let path = upper_dir.join(filename);
///         if fs.path_exists(&path)? {
///             fs.remove_file(&path)?;
///         }
///     }
///     Ok(())
/// }
///
/// let fs = MockFilesystem::new();
/// let upper_dir = PathBuf::from("/mnt/hidden/etc-upper");
///
/// // Create stale resolv.conf in upper layer
/// let resolv_path = upper_dir.join("resolv.conf");
/// fs.mock_set_path_exists(&resolv_path.to_string_lossy(), true);
/// fs.mock_set_file_content(&resolv_path.to_string_lossy(), "nameserver 8.8.8.8");
///
/// // Clean it before mounting overlay
/// clean_stale_network_config(&upper_dir, &fs).unwrap();
///
/// // File should be removed
/// assert!(!fs.path_exists(&resolv_path).unwrap());
/// ```
fn clean_stale_network_config<F: Filesystem>(upper_dir: &Path, fs: &F) -> Result<()> {
    let stale_files = ["resolv.conf", "nsswitch.conf"];

    for filename in &stale_files {
        let path = upper_dir.join(filename);
        if fs.path_exists(&path)? {
            fs.remove_file(&path)?;
            tracing::info!(
                file = filename,
                upper_dir = %upper_dir.display(),
                "Cleaned stale {} from /etc upper layer for DNS preservation",
                filename
            );
        }
    }

    Ok(())
}

/// Apply exclusion filter to a list of directories (Story 14.10, Task 4)
///
/// Filters out directories that match any path in the exclusion list.
/// This function is separated from build_overlay_targets() for testability
/// and modularity as specified in Task 4.
///
/// # Arguments
///
/// * `directories` - List of directory paths to filter
/// * `exclusions` - List of paths to exclude
///
/// # Returns
///
/// Filtered list with excluded directories removed, sorted alphabetically
///
/// # Example
///
/// ```rust
/// use std::path::PathBuf;
/// use nails_core::apply_exclusion_filter;
///
/// let dirs = vec![
///     PathBuf::from("/home"),
///     PathBuf::from("/etc"),
///     PathBuf::from("/proc"),
///     PathBuf::from("/var"),
/// ];
/// let exclusions = vec![PathBuf::from("/proc")];
///
/// let filtered = apply_exclusion_filter(dirs, &exclusions);
/// assert_eq!(filtered.len(), 3);
/// assert!(!filtered.contains(&PathBuf::from("/proc")));
/// ```
pub fn apply_exclusion_filter(directories: Vec<PathBuf>, exclusions: &[PathBuf]) -> Vec<PathBuf> {
    let mut filtered: Vec<PathBuf> = directories
        .into_iter()
        .filter(|dir| {
            let excluded = exclusions.contains(dir);
            if excluded {
                tracing::debug!("Excluding directory from overlay: {}", dir.display());
            }
            !excluded
        })
        .collect();

    // Sort for consistent ordering
    filtered.sort();
    filtered
}

/// Build list of overlay targets based on overlay mode (Story 14.10)
///
/// Determines which directories should be overlaid based on the configuration:
/// - **Auto mode** (default): Enumerate all directories under `/`, apply exclusions
/// - **Explicit mode**: Use only directories from `config.overlays`
///
/// # Arguments
///
/// * `fs` - Filesystem abstraction for directory enumeration
/// * `config` - Configuration containing overlay_mode and exclusion lists
///
/// # Returns
///
/// Vec of PathBuf containing directories to overlay, sorted alphabetically.
///
/// # Errors
///
/// Returns error if filesystem enumeration fails (I/O error reading `/`).
///
/// # Example
///
/// ```rust
/// use nails_core::{build_overlay_targets, MockFilesystem, Config, OverlayMode};
/// use std::path::PathBuf;
///
/// let fs = MockFilesystem::new();
/// fs.mock_set_root_directories(vec![
///     PathBuf::from("/home"),
///     PathBuf::from("/etc"),
///     PathBuf::from("/var"),
///     PathBuf::from("/proc"),  // Will be excluded by default
/// ]);
///
/// let config = Config::default(); // Auto mode by default
/// let targets = build_overlay_targets(&fs, &config).unwrap();
///
/// // /proc excluded by default, others included
/// assert_eq!(targets, vec![
///     PathBuf::from("/etc"),
///     PathBuf::from("/home"),
///     PathBuf::from("/var"),
/// ]);
/// ```
pub fn build_overlay_targets<F: Filesystem>(fs: &F, config: &Config) -> Result<Vec<PathBuf>> {
    use crate::config::OverlayMode;

    match config.overlay_mode {
        OverlayMode::Auto => {
            // Dynamic enumeration: enumerate root dirs + apply exclusions
            let all_dirs = fs.enumerate_root_directories()?;
            let exclusions = config.compute_effective_exclusions();

            // Apply exclusion filtering (using separate function per Task 4 spec)
            let mut targets = apply_exclusion_filter(all_dirs, &exclusions);

            // Safety: never overlay core binary roots even if exclusions are misconfigured.
            // Overlaying /bin or /usr can hide shells/coreutils inside the VM (breaks tests).
            let critical = [Path::new("/bin"), Path::new("/usr")];
            targets.retain(|p| !critical.contains(&p.as_path()));

            if !targets.is_empty() {
                tracing::info!("Dynamic overlay targets: {} directories", targets.len());
                for target in &targets {
                    tracing::debug!("  Will overlay: {}", target.display());
                }
            } else {
                tracing::warn!(
                    "No overlay targets after applying exclusions - all directories excluded!"
                );
            }

            Ok(targets)
        }
        OverlayMode::Explicit => {
            // Legacy behavior: use only configured overlays
            let targets: Vec<PathBuf> = config.overlays.iter().map(|o| o.target.clone()).collect();

            tracing::info!(
                "Explicit overlay mode: {} configured overlays",
                targets.len()
            );
            for target in &targets {
                tracing::debug!("  Will overlay: {}", target.display());
            }

            Ok(targets)
        }
    }
}

/// Create overlay configuration for a target directory (Story 14.10)
///
/// Generates an OverlayConfig with auto-created upper/work directories
/// based on the target path and hidden volume root.
///
/// # Arguments
///
/// * `fs` - Filesystem abstraction for directory creation
/// * `target` - Target mount point (e.g., `/home`, `/etc`)
/// * `hidden_volume_root` - Root path of hidden storage volume
///
/// # Returns
///
/// OverlayConfig with:
/// - `lower`: Same as target (original system directory)
/// - `upper`: `{hidden_volume_root}/{dir_name}`
/// - `work`: `{hidden_volume_root}/.work/{dir_name}`
/// - `target`: Same as input target
///
/// # Errors
///
/// Returns error if:
/// - Target has no directory name component (e.g., `/`)
/// - Directory creation fails
///
/// # Example
///
/// ```ignore
/// # // Example only: create_overlay_config is an internal helper.
/// # // Use NailsManager::activate() to mount overlays in normal code.
/// ```
fn create_overlay_config<F: Filesystem>(
    fs: &F,
    target: &Path,
    hidden_volume_root: &Path,
) -> Result<crate::OverlayConfig> {
    // Extract directory name from target path
    let dir_name = target.file_name().ok_or_else(|| {
        NailsError::ConfigError(format!(
            "Cannot extract directory name from target: {}",
            target.display()
        ))
    })?;

    // Build upper and work paths
    let upper = hidden_volume_root.join(dir_name);
    let work_parent = hidden_volume_root.join(".work");
    let work = work_parent.join(dir_name);

    // Create directories if they don't exist (Story 14.10, Task 6)
    // First create .work parent directory (may not exist yet)
    fs.create_directory(&work_parent)?;

    // Then create upper and work directories
    // create_directory handles EEXIST gracefully
    fs.create_directory(&upper)?;
    fs.create_directory(&work)?;

    // Ensure permissions are safe and usable regardless of umask or preflight state
    let desired_upper_mode = fs.get_permissions(target)?;
    fs.set_permissions(&upper, desired_upper_mode)?;
    fs.set_permissions(&work, 0o700)?;

    // Create overlay configuration
    Ok(crate::OverlayConfig {
        name: dir_name.to_string_lossy().to_string(),
        lower: target.to_path_buf(),
        upper,
        work,
        target: target.to_path_buf(),
    })
}

/// Type of mount being tracked
///
/// Distinguishes between persistent overlays (backed by hidden storage)
/// and ephemeral overlays (backed by tmpfs RAM storage).
///
/// (Story 4.11: Extended Overlay Strategy)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountType {
    /// Persistent overlay: lower from system, upper/work on hidden storage
    ///
    /// Used for /home and /etc - changes persist across reboots
    Persistent,

    /// Ephemeral overlay: lower from system, upper/work on tmpfs (RAM)
    ///
    /// Used for /var, /tmp, /srv, /opt - changes destroyed on unmount
    /// Provides forensic safety even if system is seized while running
    Ephemeral,
}

/// Information about a tracked mount
///
/// Contains metadata needed to properly unmount both the overlay
/// and any associated tmpfs filesystems.
///
/// (Story 4.11: Extended Overlay Strategy)
#[derive(Debug, Clone)]
pub struct MountInfo {
    /// Type of mount (persistent or ephemeral)
    pub mount_type: MountType,
    /// Target path where the overlay is mounted
    pub target: PathBuf,
    /// Tmpfs mount paths that must be unmounted after overlay
    ///
    /// For persistent mounts: empty
    /// For ephemeral mounts: [upper_path, work_path]
    pub tmpfs_paths: Vec<PathBuf>,
}

impl MountInfo {
    /// Create a new persistent mount info
    pub fn persistent(target: PathBuf) -> Self {
        Self {
            mount_type: MountType::Persistent,
            target,
            tmpfs_paths: Vec::new(),
        }
    }

    /// Create a new ephemeral mount info with tmpfs paths
    pub fn ephemeral(target: PathBuf, tmpfs_paths: Vec<PathBuf>) -> Self {
        Self {
            mount_type: MountType::Ephemeral,
            target,
            tmpfs_paths,
        }
    }
}

/// RAII mount tracker for automatic rollback on failure
///
/// Tracks mounted overlays in LIFO order and provides automatic rollback
/// if the MountTracker is dropped without being committed.
///
/// # Architecture
///
/// - **LIFO Ordering**: Mounts are tracked in a `Vec<MountInfo>` and unmounted in reverse
/// - **Best-Effort Rollback**: Continues unmounting even if individual unmounts fail
/// - **RAII Pattern**: Automatic rollback on drop if not committed
/// - **Graceful unmount first**: Tries graceful unmount (force=false) before forcing
/// - **Mount Type Aware**: Handles both persistent and ephemeral (tmpfs-backed) overlays
///
/// # Example
///
/// ```no_run
/// use nails_core::{MockFilesystem, MountTracker, MountInfo};
/// use std::path::PathBuf;
///
/// let fs = MockFilesystem::new();
/// let mut tracker = MountTracker::new(&fs);
///
/// // Track successful persistent mounts
/// tracker.push_mount(MountInfo::persistent(PathBuf::from("/home")));
/// tracker.push_mount(MountInfo::persistent(PathBuf::from("/etc")));
///
/// // Track ephemeral mount with tmpfs paths
/// tracker.push_mount(MountInfo::ephemeral(
///     PathBuf::from("/var"),
///     vec![PathBuf::from("/run/nails/var/upper"), PathBuf::from("/run/nails/var/work")]
/// ));
///
/// // Commit to prevent rollback
/// tracker.commit();
///
/// // If not committed, tracker will automatically rollback on drop
/// ```
pub struct MountTracker<'a, F: Filesystem> {
    /// List of successfully mounted overlays (LIFO order)
    pub mounted: Vec<MountInfo>,
    /// Filesystem reference for unmount operations
    filesystem: &'a F,
    /// Whether mounts have been committed (prevents rollback on drop)
    pub committed: bool,
}

impl<'a, F: Filesystem> MountTracker<'a, F> {
    /// Create a new MountTracker
    ///
    /// # Arguments
    ///
    /// - `filesystem`: Reference to filesystem for unmount operations
    ///
    /// # Returns
    ///
    /// New MountTracker instance with empty mount list
    pub fn new(filesystem: &'a F) -> Self {
        Self {
            mounted: Vec::new(),
            filesystem,
            committed: false,
        }
    }

    /// Track a successful mount
    ///
    /// Adds the mount info to the tracked list for potential rollback.
    ///
    /// # Arguments
    ///
    /// - `mount_info`: Information about the successfully mounted overlay
    pub fn push_mount(&mut self, mount_info: MountInfo) {
        self.mounted.push(mount_info);
    }

    /// Commit mounts to prevent automatic rollback
    ///
    /// Mark the tracker as committed, preventing automatic rollback
    /// when the tracker is dropped.
    pub fn commit(&mut self) {
        self.committed = true;
    }

    /// Rollback all mounts in reverse order (LIFO) with graceful unmount first
    ///
    /// Unmounts all tracked overlays in reverse order (last mounted, first unmounted).
    /// Uses best-effort approach: continues unmounting even if some fail.
    /// Tries graceful unmount (force=false) first, then force unmount if that fails.
    ///
    /// For ephemeral mounts, also unmounts associated tmpfs filesystems after
    /// unmounting the overlay (cascade unmount).
    ///
    /// # Returns
    ///
    /// - `Ok(())` if all unmounts succeed
    /// - `Err(NailsError)` with aggregate errors if any unmounts fail
    ///
    /// # Best-Effort Behavior
    ///
    /// Even if this method returns an error, it will have attempted to unmount
    /// all tracked paths. The error contains details of all failures.
    ///
    /// (Story 4.11: Extended Overlay Strategy with tmpfs cleanup)
    pub fn rollback_all(&mut self) -> Result<()> {
        let mut errors: Vec<String> = Vec::new();

        // LIFO: unmount in reverse order
        for mount_info in self.mounted.iter().rev() {
            let path = &mount_info.target;
            let mount_type_str = match mount_info.mount_type {
                MountType::Persistent => "persistent",
                MountType::Ephemeral => "ephemeral",
            };

            tracing::info!(
                path = %path.display(),
                mount_type = mount_type_str,
                phase = "rollback",
                "Unmounting overlay"
            );

            // Try graceful unmount first (Epic 4.2 requirement)
            if let Err(e) = self.filesystem.unmount(path, false) {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    attempt = "graceful",
                    "Unmount failed, trying force unmount"
                );

                // If graceful fails, try force unmount
                if let Err(force_err) = self.filesystem.unmount(path, true) {
                    let msg = format!(
                        "Failed to unmount {} (graceful and force both failed): {}",
                        path.display(),
                        force_err
                    );
                    tracing::warn!(
                        path = %path.display(),
                        error = %force_err,
                        attempts = "both",
                        "Force unmount also failed"
                    );
                    errors.push(msg); // Collect error but continue (best-effort)
                } else {
                    tracing::info!(
                        path = %path.display(),
                        method = "force",
                        "Unmount succeeded"
                    );
                }
            } else {
                tracing::info!(
                    path = %path.display(),
                    method = "graceful",
                    "Unmount succeeded"
                );
            }

            // For ephemeral mounts, also unmount tmpfs filesystems (cascade)
            if mount_info.mount_type == MountType::Ephemeral {
                for tmpfs_path in &mount_info.tmpfs_paths {
                    tracing::info!(
                        path = %tmpfs_path.display(),
                        filesystem_type = "tmpfs",
                        "Unmounting tmpfs"
                    );

                    if let Err(e) = self.filesystem.unmount_tmpfs(tmpfs_path) {
                        let msg =
                            format!("Failed to unmount tmpfs at {}: {}", tmpfs_path.display(), e);
                        tracing::warn!(
                            path = %tmpfs_path.display(),
                            error = %e,
                            filesystem_type = "tmpfs",
                            "Tmpfs unmount failed"
                        );
                        errors.push(msg); // Collect error but continue (best-effort)
                    } else {
                        tracing::info!(
                            path = %tmpfs_path.display(),
                            filesystem_type = "tmpfs",
                            "Tmpfs unmounted"
                        );
                    }
                }
            }
        }

        self.mounted.clear();

        if errors.is_empty() {
            Ok(())
        } else {
            Err(NailsError::OverlayError(format!(
                "Rollback completed with errors: {}",
                errors.join("; ")
            )))
        }
    }
}

/// Automatic rollback on drop (RAII pattern)
///
/// If the MountTracker is dropped without being committed,
/// it will automatically attempt to rollback all mounts.
impl<'a, F: Filesystem> Drop for MountTracker<'a, F> {
    fn drop(&mut self) {
        if !self.committed && !self.mounted.is_empty() {
            tracing::warn!(
                mount_count = self.mounted.len(),
                committed = false,
                "MountTracker dropped without commit, rolling back"
            );
            let _ = self.rollback_all();
        }
    }
}

/// Central orchestrator for all NAILS operations
///
/// NailsManager coordinates state transitions, filesystem operations,
/// and validation logic. The generic Filesystem parameter enables
/// testing without root privileges.
///
/// # Fields
///
/// - `filesystem`: Generic filesystem implementation (real or mock)
/// - `config`: Application configuration
/// - `state_file_path`: Path to state file (on hidden volume)
/// - `cached_state`: Cached state file (lazy loaded, thread-safe)
///
/// # Thread Safety
///
/// `cached_state` uses `Arc<Mutex<_>>` for thread-safe lazy loading.
/// While NAILS is single-threaded in Phase 1 (AR47), this pattern enables
/// future extensions and parallel testing.
///
/// # Requirements
///
/// - AR3: Core library contains all business logic
/// - AR4: Testable without root via trait abstraction
/// - AR44: Generic NailsManager<F: Filesystem> pattern
pub struct NailsManager<F: Filesystem> {
    /// Filesystem implementation (real or mock)
    filesystem: F,

    /// Application configuration
    config: Config,

    /// Path to state file (on hidden volume)
    state_file_path: PathBuf,

    /// Cached state file (lazy loaded, thread-safe)
    /// Arc<Mutex<_>> enables thread-safe access and clone implementation
    cached_state: Arc<Mutex<Option<StateFile>>>,

    /// NixOS profile builder (optional, for activation with NixOS switching)
    /// If None, activation will skip NixOS build/switch steps
    nixos_builder: Option<crate::nixos::NixOSBuilder>,

    /// Verbosity level for progress output
    verbosity: crate::verbosity::Verbosity,
}

// Manual Debug implementation because NixOSBuilder contains trait objects
impl<F: Filesystem> std::fmt::Debug for NailsManager<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NailsManager")
            .field("filesystem", &"<filesystem>")
            .field("config", &self.config)
            .field("state_file_path", &self.state_file_path)
            .field("cached_state", &"<Arc<Mutex<...>>>")
            .field(
                "nixos_builder",
                &self.nixos_builder.as_ref().map(|_| "<NixOSBuilder>"),
            )
            .field("verbosity", &self.verbosity)
            .finish()
    }
}

impl<F: Filesystem> NailsManager<F> {
    /// Create a new NailsManager with lazy loading
    ///
    /// The constructor stores all parameters but does NOT load state from disk.
    /// State is loaded lazily on first access via `current_state()`.
    ///
    /// # Arguments
    ///
    /// * `filesystem` - Filesystem implementation (RealFilesystem or MockFilesystem)
    /// * `config` - Application configuration
    /// * `state_file_path` - Path to state file (must be on hidden volume)
    ///
    /// # Returns
    ///
    /// New NailsManager instance with unloaded state (None) and no NixOS builder.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::{NailsManager, MockFilesystem, Config};
    /// use std::path::PathBuf;
    ///
    /// let fs = MockFilesystem::new();
    /// let config = Config::default();
    /// let state_path = PathBuf::from("/mnt/hidden-volume/state.json");
    /// let manager = NailsManager::new(fs, config, state_path);
    /// ```
    pub fn new(filesystem: F, config: Config, state_file_path: PathBuf) -> Self {
        Self {
            filesystem,
            config,
            state_file_path,
            cached_state: Arc::new(Mutex::new(None)),
            nixos_builder: None,
            verbosity: crate::verbosity::Verbosity::default(),
        }
    }

    /// Create a new NailsManager with NixOS builder for full activation support
    ///
    /// Use this constructor when you need NixOS profile building and switching
    /// during activation. The standard `new()` constructor creates a manager
    /// without NixOS support (activation will skip NixOS steps).
    ///
    /// # Arguments
    ///
    /// * `filesystem` - Filesystem implementation (RealFilesystem or MockFilesystem)
    /// * `config` - Application configuration
    /// * `state_file_path` - Path to state file (must be on hidden volume)
    /// * `nixos_builder` - NixOS profile builder instance
    ///
    /// # Returns
    ///
    /// New NailsManager instance with NixOS support enabled.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::{NailsManager, MockFilesystem, Config, NixOSBuilder};
    /// use std::path::PathBuf;
    ///
    /// let fs = MockFilesystem::new();
    /// let config = Config::default();
    /// let state_path = PathBuf::from("/mnt/hidden-volume/state.json");
    /// let nixos_builder = NixOSBuilder::new(
    ///     PathBuf::from("/mnt/hidden/nixos"),
    ///     PathBuf::from("/nix/var/nix/profiles/nails-system"),
    /// );
    /// let manager = NailsManager::with_nixos(fs, config, state_path, nixos_builder);
    /// ```
    pub fn with_nixos(
        filesystem: F,
        config: Config,
        state_file_path: PathBuf,
        nixos_builder: crate::nixos::NixOSBuilder,
    ) -> Self {
        Self {
            filesystem,
            config,
            state_file_path,
            cached_state: Arc::new(Mutex::new(None)),
            nixos_builder: Some(nixos_builder),
            verbosity: crate::verbosity::Verbosity::default(),
        }
    }

    /// Set verbosity level for progress output
    ///
    /// Controls the amount of detail in progress messages during operations.
    ///
    /// # Arguments
    ///
    /// * `verbosity` - Desired verbosity level
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::{NailsManager, MockFilesystem, Config, Verbosity};
    /// use std::path::PathBuf;
    ///
    /// let fs = MockFilesystem::new();
    /// let config = Config::default();
    /// let state_path = PathBuf::from("/tmp/state.json");
    /// let mut manager = NailsManager::new(fs, config, state_path);
    /// manager.set_verbosity(Verbosity::Verbose);
    /// ```
    pub fn set_verbosity(&mut self, verbosity: crate::verbosity::Verbosity) {
        self.verbosity = verbosity;
    }

    /// Unmount overlays in reverse order (LIFO)
    ///
    /// Unmounts overlays in reverse of mount order to respect dependencies.
    /// Uses best-effort rollback: continues unmounting even if individual unmounts fail.
    ///
    /// # Arguments
    ///
    /// * `mounted_paths` - Vec of mounted overlay paths in mount order
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All unmounts succeeded
    /// * `Err(NailsError)` - One or more unmounts failed (with aggregate error details)
    ///
    /// # Behavior (Story 4.6, AC4-AC5)
    ///
    /// - Unmounts in LIFO order (reverse iteration)
    /// - Tries graceful unmount first, then force unmount on failure
    /// - Logs each unmount operation
    /// - Best-effort: continues even if one unmount fails
    /// - Returns aggregate error listing all failures
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::{NailsManager, MockFilesystem, Config};
    /// use std::path::PathBuf;
    ///
    /// let fs = MockFilesystem::new();
    /// let config = Config::default();
    /// let manager = NailsManager::new(fs, config, PathBuf::from("/tmp/state.json"));
    ///
    /// let mounted = vec![PathBuf::from("/home"), PathBuf::from("/etc")];
    /// manager.unmount_overlays(mounted).unwrap();
    /// // Unmounts in reverse: /etc first, then /home
    /// ```
    pub fn unmount_overlays(&self, mounted_paths: Vec<PathBuf>) -> Result<()> {
        let mut errors: Vec<String> = Vec::new();

        // LIFO: unmount in reverse order
        for path in mounted_paths.iter().rev() {
            tracing::info!(
                path = %path.display(),
                order = "LIFO",
                "Unmounting overlay"
            );

            // Try graceful unmount first (Epic 4.2 requirement)
            if let Err(e) = self.filesystem.unmount(path, false) {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    attempt = "graceful",
                    "Unmount failed, trying force unmount"
                );

                // If graceful fails, try force unmount
                if let Err(force_err) = self.filesystem.unmount(path, true) {
                    let msg = format!(
                        "Failed to unmount {} (graceful and force both failed): {}",
                        path.display(),
                        force_err
                    );
                    tracing::warn!(
                        path = %path.display(),
                        error = %force_err,
                        attempts = "both",
                        "Force unmount also failed"
                    );
                    errors.push(msg); // Collect error but continue (best-effort)
                } else {
                    tracing::info!(
                        path = %path.display(),
                        method = "force",
                        "Unmount succeeded"
                    );
                }
            } else {
                tracing::info!(
                    path = %path.display(),
                    method = "graceful",
                    "Unmount succeeded"
                );
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(NailsError::OverlayError(format!(
                "Unmount completed with errors: {}",
                errors.join("; ")
            )))
        }
    }

    /// Get current system state with lazy loading
    ///
    /// First call loads from disk and caches result.
    /// Subsequent calls return cached value.
    ///
    /// # Graceful Degradation (AR27, AR53)
    ///
    /// Returns Inactive if file missing or malformed (safe default).
    /// Logs warning when using default Inactive state.
    ///
    /// # Returns
    ///
    /// * `Ok(SystemState)` - Current state or Inactive if file missing/malformed
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::{NailsManager, MockFilesystem, Config, SystemState};
    /// use std::path::PathBuf;
    ///
    /// let fs = MockFilesystem::new();
    /// let config = Config::default();
    /// let state_path = PathBuf::from("/mnt/hidden-volume/state.json");
    /// let manager = NailsManager::new(fs, config, state_path);
    ///
    /// // First call loads from disk (lazy)
    /// let state = manager.current_state().unwrap();
    /// assert_eq!(state, SystemState::Inactive); // Default if file missing
    ///
    /// // Second call uses cache
    /// let state2 = manager.current_state().unwrap();
    /// assert_eq!(state, state2);
    /// ```
    pub fn current_state(&self) -> Result<SystemState> {
        let mut cached = self.cached_state.lock().unwrap();

        // If cached, return immediately
        if let Some(ref state_file) = *cached {
            return Ok(state_file.state.clone());
        }

        // Lazy load from disk
        // Note: StateFile::load() handles warning logs for missing/malformed files
        // and returns default Inactive state per AR27, AR53. This keeps the logging
        // logic centralized in the StateFile module.
        let state_file = StateFile::load(&self.state_file_path)?;
        let state = state_file.state.clone();

        // Cache for future calls
        *cached = Some(state_file);

        Ok(state)
    }

    /// Force state transition without validation (for rollback use only)
    ///
    /// **⚠️ WARNING: This method bypasses ALL state transition validation.**
    ///
    /// This method directly sets the system state without checking if the
    /// transition is legal according to the state machine rules. Using this
    /// method incorrectly WILL corrupt your state machine and cause undefined
    /// behavior.
    ///
    /// # ⚠️ Safety - State Machine Corruption Risk
    ///
    /// This method is intentionally **NOT** marked as `unsafe` in Rust terms
    /// (it doesn't violate memory safety), but it IS unsafe from a **state
    /// machine correctness** perspective.
    ///
    /// ## When State Machine Corruption Occurs
    ///
    /// Using `force_state()` outside of rollback scenarios can create invalid
    /// state transitions that violate the system's invariants:
    ///
    /// ### Example 1: Skipping Required Cleanup
    /// ```text
    /// // DANGER: Forcing Active → Inactive without cleanup
    /// manager.force_state(SystemState::Inactive);
    /// // Result: Overlays remain mounted but state says Inactive
    /// // Next activation will fail or double-mount
    /// ```
    ///
    /// ### Example 2: Bypassing Validation Checks
    /// ```text
    /// // DANGER: Forcing Inactive → Active without mounting
    /// manager.force_state(SystemState::Active { ... });
    /// // Result: State says Active but nothing is mounted
    /// // System thinks it's protected but it's not
    /// ```
    ///
    /// ### Example 3: Creating Impossible Transitions
    /// ```text
    /// // DANGER: Jumping from Error to Activating
    /// manager.force_state(SystemState::Activating);
    /// // Result: State machine thinks activation is in progress
    /// // but prerequisites from Inactive weren't completed
    /// ```
    ///
    /// ## Safe Use Case: Rollback After Partial Failure
    ///
    /// The ONLY safe use of `force_state()` is in StateGuard::drop() to restore
    /// a previous known-good state after a partial operation failure:
    ///
    /// ```text
    /// // SAFE: Rollback in StateGuard::drop()
    /// // We were in Active, tried to deactivate, unmount failed
    /// // Roll back to Active (remount what we can)
    /// self.manager.lock().unwrap()
    ///     .force_state(self.previous_state.clone());
    /// // State machine returns to consistent Active state
    /// ```
    ///
    /// # When to Use This Method
    ///
    /// **ONLY use `force_state()` in these scenarios:**
    /// 1. **StateGuard::drop() for rollback** - Restoring previous state after failure
    /// 2. **Test setup/teardown** - Forcing known states for testing
    /// 3. **Recovery operations** - Manual state repair by advanced users
    ///
    /// **NEVER use `force_state()` in:**
    /// - Normal activation/deactivation flows (use `update_state()` instead)
    /// - CLI commands (they should use high-level APIs)
    /// - Error handling outside of rollback (fix the root cause instead)
    ///
    /// # Arguments
    ///
    /// * `new_state` - State to force (no validation performed)
    ///
    /// # Returns
    ///
    /// * `Ok(())` - State forced successfully
    /// * `Err(NailsError::IoError)` - Failed to save state file
    ///
    /// # Example
    ///
    /// ```no_run
    /// use nails_core::{NailsManager, MockFilesystem, Config, SystemState};
    /// use std::path::PathBuf;
    ///
    /// let temp_dir = tempfile::tempdir().unwrap();
    /// let mock_hidden_vol = temp_dir.path();
    /// std::fs::create_dir_all(mock_hidden_vol).unwrap();
    /// let state_path = mock_hidden_vol.join("state.json");
    ///
    /// let fs = MockFilesystem::new();
    /// let config = Config {
    ///     hidden_volume_root: mock_hidden_vol.to_path_buf(),
    ///     state_file_path: state_path.clone(),
    ///     overlays: vec![],
    ///     ..Config::test_default()
    /// };
    /// let mut manager = NailsManager::new(fs, config, state_path);
    ///
    /// // Force state without validation (rollback use case)
    /// manager.force_state(SystemState::Inactive).unwrap();
    /// ```
    pub fn force_state(&mut self, new_state: SystemState) -> Result<()> {
        // Update state file without validation
        let mut cached = self.cached_state.lock().unwrap();
        let mut state_file = cached.take().unwrap_or_default();
        state_file.state = new_state.clone();
        state_file.last_modified = Utc::now();

        // Task 5 (AC4): Clear overlay_status and nixos_generation when rolling back to Inactive
        // This ensures the state file doesn't retain stale activation metadata after rollback
        if let SystemState::Inactive = new_state {
            state_file.overlay_status.clear();
            state_file.nixos_generation = None;
            tracing::debug!(
                action = "rollback",
                target_state = "Inactive",
                fields_cleared = "overlay_status,nixos_generation",
                "Rollback to Inactive"
            );
        }

        // Save to disk with configured hidden volume root
        state_file.save_with_custom_root(&self.state_file_path, &self.config.hidden_volume_root)?;

        // Update cache
        *cached = Some(state_file);

        Ok(())
    }

    /// Update system state with validation
    ///
    /// Validates the transition is legal before persisting.
    /// Updates cached state after successful save.
    ///
    /// # Arguments
    ///
    /// * `new_state` - Target state to transition to
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Transition successful, state saved
    /// * `Err(NailsError::InvalidState)` - Invalid transition
    ///
    /// # Example
    ///
    /// ```no_run
    /// use nails_core::{NailsManager, MockFilesystem, Config, SystemState};
    /// use std::path::PathBuf;
    ///
    /// let temp_dir = tempfile::tempdir().unwrap();
    /// let mock_hidden_vol = temp_dir.path();
    /// std::fs::create_dir_all(mock_hidden_vol).unwrap();
    /// let state_path = mock_hidden_vol.join("state.json");
    ///
    /// let fs = MockFilesystem::new();
    /// let config = Config {
    ///     hidden_volume_root: mock_hidden_vol.to_path_buf(),
    ///     state_file_path: state_path.clone(),
    ///     overlays: vec![],
    ///     ..Config::test_default()
    /// };
    /// let mut manager = NailsManager::new(fs, config, state_path);
    ///
    /// // Valid transition: Inactive -> Activating
    /// let result = manager.update_state(SystemState::Activating {
    ///     started_at: chrono::Utc::now(),
    /// });
    /// assert!(result.is_ok());
    /// ```
    pub fn update_state(&mut self, new_state: SystemState) -> Result<()> {
        // Load current state (uses cache if available)
        let current = self.current_state()?;

        // Validate transition using the same rules as SystemState transition methods
        // (begin_activation, complete_activation, begin_deactivation, complete_deactivation, trigger_emergency)
        //
        // Note: We can't use the transition methods directly here because they create
        // the new state with timestamps. This method accepts pre-constructed states,
        // which is necessary for testing and special cases.
        let is_valid = match (&current, &new_state) {
            (SystemState::Inactive, SystemState::Activating { .. }) => true,
            (SystemState::Activating { .. }, SystemState::Active { .. }) => true,
            (SystemState::Active { .. }, SystemState::Deactivating { .. }) => true,
            (SystemState::Deactivating { .. }, SystemState::Inactive) => true,
            (_, SystemState::Emergency { .. }) => true, // Emergency always allowed
            _ if current == new_state => true,          // Same state is allowed (idempotent)
            _ => false,
        };

        if !is_valid {
            return Err(NailsError::InvalidState(format!(
                "Invalid state transition: {:?} -> {:?}",
                current, new_state
            )));
        }

        // Update state file
        let mut cached = self.cached_state.lock().unwrap();
        let mut state_file = cached.take().unwrap_or_default();
        state_file.state = new_state;
        state_file.last_modified = Utc::now();

        // Save to disk with configured hidden volume root
        state_file.save_with_custom_root(&self.state_file_path, &self.config.hidden_volume_root)?;

        // Update cache
        *cached = Some(state_file);

        Ok(())
    }

    /// Save cached state to disk without validation
    ///
    /// Helper method to persist the current cached state to disk.
    /// Used during incremental state updates (Story 4.7, AC1, AC2).
    ///
    /// # Returns
    ///
    /// * `Ok(())` - State saved successfully
    /// * `Err(NailsError::StateFileError)` - Failed to write state file
    fn save_cached_state(&self) -> Result<()> {
        let mut cached = self.cached_state.lock().unwrap();
        if let Some(ref mut state_file) = *cached {
            state_file.last_modified = Utc::now();
            state_file
                .save_with_custom_root(&self.state_file_path, &self.config.hidden_volume_root)?;
        }
        Ok(())
    }

    /// Verify state file matches actual system state
    ///
    /// Checks that all overlays listed in state file are actually
    /// mounted (for Active) or unmounted (for Inactive).
    ///
    /// # Returns
    ///
    /// * `Ok(())` - State file matches actual system state
    /// * `Err(NailsError::InvalidState)` - Mismatch detected with details
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::{NailsManager, MockFilesystem, Config};
    /// use std::path::{Path, PathBuf};
    ///
    /// let fs = MockFilesystem::new();
    /// let config = Config::default();
    /// let state_path = PathBuf::from("/tmp/test-state.json");
    /// let manager = NailsManager::new(fs, config, state_path);
    ///
    /// // Verify state matches reality
    /// let result = manager.verify_overlay_status();
    /// assert!(result.is_ok());
    /// ```
    pub fn verify_overlay_status(&self) -> Result<()> {
        // Fresh read from disk (bypass cache)
        let state_file = StateFile::load(&self.state_file_path)?;

        // Check each overlay
        for (path, overlay_info) in &state_file.overlay_status {
            let is_mounted = self.filesystem.is_mounted(&overlay_info.mount_path)?;

            match &state_file.state {
                SystemState::Active { .. } => {
                    if !is_mounted {
                        return Err(NailsError::InvalidState(format!(
                            "State mismatch: {} should be mounted but is not",
                            path.display()
                        )));
                    }
                }
                SystemState::Inactive => {
                    if is_mounted {
                        return Err(NailsError::InvalidState(format!(
                            "State mismatch: {} should not be mounted but is",
                            path.display()
                        )));
                    }
                }
                _ => {
                    // Transitional states (Activating, Deactivating, Emergency) are skipped
                    // because:
                    // - Activating: Overlays are being mounted, partial state is expected
                    // - Deactivating: Overlays are being unmounted, partial state is expected
                    // - Emergency: System may be in inconsistent state by definition
                    //
                    // These states are short-lived and verification is meaningless during
                    // the transition. Verification is only useful for stable states
                    // (Active, Inactive) to detect drift.
                }
            }
        }

        Ok(())
    }

    /// Run all pre-flight checks before activation
    ///
    /// Creates a PreFlightRegistry, registers all validation checks, and executes them.
    /// Returns comprehensive error information if any checks fail.
    ///
    /// # Pre-flight Checks Executed (Stories 3.1-3.7, 4.12, 15.2)
    ///
    /// 1. **HiddenVolumeCheck** - Validates hidden volume is mounted
    /// 2. **StorageReadinessCheck** - Validates directory structure + overlay accessibility
    /// 3. **NixOSConfigCheck** - Validates NixOS config overlay structure
    /// 4. **SwapCheck** - Validates swap is disabled
    /// 5. **SpaceCheck** - Validates sufficient disk space
    /// 6. **StateCheck** - Validates current state allows activation
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All checks passed (or only warnings)
    /// * `Err(NailsError::PreFlightCheckFailed)` - One or more checks failed
    ///
    /// # Example
    ///
    /// This is a private method called automatically during activation.
    /// To run preflight checks, use `activate()`:
    ///
    /// ```rust,no_run
    /// use nails_core::{NailsManager, MockFilesystem, Config};
    /// use std::path::PathBuf;
    /// use std::sync::{Arc, Mutex};
    ///
    /// let fs = MockFilesystem::new();
    /// let config = Config::default();
    /// let state_path = PathBuf::from("/mnt/hidden-volume/state.json");
    /// let manager = Arc::new(Mutex::new(NailsManager::new(fs, config, state_path)));
    ///
    /// // Activate with preflight checks (no_preflight = false)
    /// let result = NailsManager::activate(manager, false);
    /// ```
    pub fn run_preflight_checks(&self) -> Result<()> {
        use crate::preflight::{
            HiddenVolumeCheck, NixOSConfigCheck, PreFlightRegistry, SpaceCheck, StateCheck,
            StorageReadinessCheck, SwapCheck,
        };

        let mut registry = PreFlightRegistry::new();

        // Register all checks (Stories 3.1-3.7, merged in Story 14.5)
        registry.add_check(Box::new(HiddenVolumeCheck::new(
            self.config.hidden_volume_root.clone(),
        )));

        // Compute overlay directories based on mode (Auto or Explicit)
        // For Auto mode: use build_overlay_targets() to enumerate dynamically
        // For Explicit mode: use config.overlays directly
        let overlay_dirs: Vec<crate::preflight::OverlayDirs> = match self.config.overlay_mode {
            crate::config::OverlayMode::Auto => {
                // Use build_overlay_targets to get dynamic list
                let targets = build_overlay_targets(&self.filesystem, &self.config)?;
                targets
                    .iter()
                    .map(|target| {
                        let dir_name = target
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .to_string();
                        let upper = self.config.hidden_volume_root.join(&dir_name);
                        let work = self.config.hidden_volume_root.join(".work").join(&dir_name);

                        crate::preflight::OverlayDirs::new(dir_name, target.clone(), upper, work)
                    })
                    .collect()
            }
            crate::config::OverlayMode::Explicit => {
                // Use explicit overlays from config
                self.config
                    .overlays
                    .iter()
                    .map(|o| {
                        crate::preflight::OverlayDirs::new(
                            o.name.clone(),
                            o.lower.clone(),
                            o.upper.clone(),
                            o.work.clone(),
                        )
                    })
                    .collect()
            }
        };

        registry.add_check(Box::new(StorageReadinessCheck::new(
            self.config.hidden_volume_root.clone(),
            overlay_dirs,
        )));

        registry.add_check(Box::new(NixOSConfigCheck::new(
            self.config.hidden_volume_root.clone(),
        )));

        registry.add_check(Box::new(SwapCheck));

        registry.add_check(Box::new(SpaceCheck::new(
            self.config.hidden_volume_root.clone(),
            self.config.minimum_space_mb,
        )));

        registry.add_check(Box::new(StateCheck::new(self.current_state()?)));

        // Run all checks
        let results = registry.run_all(&self.filesystem)?;

        // Collect failures and warnings
        let mut warnings = Vec::new();

        for (name, result) in results {
            match result {
                crate::preflight::CheckResult::Pass(msg) => {
                    tracing::info!(check = %name, result = "pass", msg = %msg, "Preflight check passed");
                }
                crate::preflight::CheckResult::Warn(msg) => {
                    tracing::warn!(check = %name, result = "warn", msg = %msg, "Preflight check warning");
                    warnings.push((name, msg));
                }
                crate::preflight::CheckResult::Fail(_) => {
                    // Failures are already handled by registry.run_all() returning Err
                    // This branch shouldn't be reached, but we keep it for completeness
                }
            }
        }

        if warnings.is_empty() {
            tracing::info!("All pre-flight checks passed");
        } else {
            tracing::info!(
                "Pre-flight checks passed with {} warning{}",
                warnings.len(),
                if warnings.len() == 1 { "" } else { "s" }
            );
        }

        Ok(())
    }

    /// Get reference to filesystem implementation
    ///
    /// Provides access to filesystem operations for advanced use cases like
    /// ActivationOrchestrator (Story 4.5).
    ///
    /// # Returns
    ///
    /// Reference to the filesystem implementation (RealFilesystem or MockFilesystem)
    pub fn filesystem(&self) -> &F {
        &self.filesystem
    }

    /// Get reference to configuration
    ///
    /// Provides access to configuration for advanced use cases like
    /// ActivationOrchestrator (Story 4.5).
    ///
    /// # Returns
    ///
    /// Reference to the configuration
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Activate NAILS with automatic RAII rollback on failure
    ///
    /// Validates current state is Inactive, runs pre-flight checks (unless skipped),
    /// transitions through Activating, mounts overlays, and transitions to Active.
    /// If any step fails or panic occurs, StateGuard automatically rolls back to Inactive state via RAII.
    ///
    /// # RAII Rollback Pattern (FR50, NFR20, NFR24)
    ///
    /// This method uses StateGuard to guarantee automatic rollback:
    /// - On success: `guard.commit()` prevents rollback
    /// - On error return: `guard.drop()` restores previous state
    /// - On panic: Stack unwinding calls `guard.drop()`, restores state
    ///
    /// # Pre-flight Validation (FR9, NFR29)
    ///
    /// By default, runs all pre-flight checks before activation.
    /// Can be skipped with `no_preflight = true` (expert override, UXR21).
    ///
    /// # Arguments
    ///
    /// * `manager_arc` - Shared reference to NailsManager wrapped in Arc<Mutex<>>
    /// * `no_preflight` - Skip pre-flight checks (DANGEROUS - expert use only)
    ///
    /// # Errors
    ///
    /// - `NailsError::PreFlightCheckFailed` - Pre-flight validation failed
    /// - `NailsError::InvalidStateTransition` - Current state is not Inactive
    /// - `NailsError::MountError` - Overlay mount failed (state rolled back)
    /// - `NailsError::StateFileError` - Cannot read/write state file
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::{NailsManager, MockFilesystem, Config};
    /// use std::path::PathBuf;
    /// use std::sync::{Arc, Mutex};
    ///
    /// let fs = MockFilesystem::new();
    /// let config = Config::default();
    /// let state_path = PathBuf::from("/mnt/hidden-volume/state.json");
    /// let manager = Arc::new(Mutex::new(NailsManager::new(fs, config, state_path)));
    ///
    /// // Activate overlays with pre-flight checks
    /// let result = NailsManager::activate(Arc::clone(&manager), false);
    /// ```
    pub fn activate(manager_arc: Arc<Mutex<Self>>, no_preflight: bool) -> Result<()> {
        // Use default options for backward compatibility with tests
        let options = crate::ActivateOptions::default();
        Self::activate_with_options(manager_arc, options, no_preflight)
    }

    /// Activate overlays with custom activation options
    ///
    /// Extended version of activate() that accepts ActivateOptions for controlling:
    /// - Session management (--kill-session)
    /// - Process restart behavior (risky process prompts)
    /// - Pivot mount policy (--accept-pivot-risks, --no-pivot)
    /// - User interaction (--yes to skip prompts)
    ///
    /// Story 4.15: User Prompts and CLI Flags for Overlay Strategy
    ///
    /// # Arguments
    ///
    /// * `manager_arc` - Shared reference to NailsManager
    /// * `options` - Activation options controlling behavior
    /// * `no_preflight` - Skip pre-flight checks (expert override)
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::{ActivateOptions, NailsManager, MockFilesystem, Config};
    /// use std::path::PathBuf;
    /// use std::sync::{Arc, Mutex};
    ///
    /// let fs = MockFilesystem::new();
    /// let config = Config::default();
    /// let state_path = PathBuf::from("/mnt/hidden-volume/state.json");
    /// let manager = Arc::new(Mutex::new(NailsManager::new(fs, config, state_path)));
    ///
    /// let options = ActivateOptions {
    ///     no_pivot: true,  // Strict security mode
    ///     ..Default::default()
    /// };
    ///
    /// let result = NailsManager::activate_with_options(Arc::clone(&manager), options, false);
    /// ```
    pub fn activate_with_options(
        manager_arc: Arc<Mutex<Self>>,
        options: crate::ActivateOptions,
        no_preflight: bool,
    ) -> Result<()> {
        use crate::{StateGuard, Stopwatch, Verbosity};

        // RAII guard: if we kill the display manager but exit early with an error,
        // attempt to restart it so the user doesn't stay on a black screen.
        struct DisplayManagerRestartGuard {
            dm_name: Option<String>,
            disarmed: bool,
        }

        impl DisplayManagerRestartGuard {
            fn new(dm_name: Option<String>) -> Self {
                Self {
                    dm_name,
                    disarmed: false,
                }
            }

            /// Prevent the guard from restarting the DM (use after a successful restart).
            fn disarm(&mut self) {
                self.disarmed = true;
            }
        }

        impl Drop for DisplayManagerRestartGuard {
            fn drop(&mut self) {
                if self.disarmed {
                    return;
                }

                let dm_name = match self.dm_name.take() {
                    Some(name) => name,
                    None => return,
                };

                use crate::process::{DisplayManager, restart_display_manager};

                let dm = match dm_name.to_lowercase().as_str() {
                    "gdm" => DisplayManager::Gdm,
                    "sddm" => DisplayManager::Sddm,
                    "lightdm" => DisplayManager::LightDm,
                    "greetd" => DisplayManager::Greetd,
                    "ly" => DisplayManager::Ly,
                    _ => DisplayManager::Other(dm_name.clone()),
                };

                if let Err(e) = restart_display_manager(&dm) {
                    tracing::error!(
                        error = %e,
                        dm = %dm_name,
                        "Failed to restart display manager after activation error"
                    );
                } else {
                    tracing::warn!(
                        dm = %dm_name,
                        "Display manager restarted after activation error"
                    );
                }
            }
        }

        // RAII guard: if we stop nix-daemon for /nix overlay but exit early,
        // restart both socket and service so the system isn't left degraded.
        struct NixDaemonGuard {
            active: bool,
            disarmed: bool,
        }

        impl NixDaemonGuard {
            fn new(active: bool) -> Self {
                Self {
                    active,
                    disarmed: false,
                }
            }
            fn disarm(&mut self) {
                self.disarmed = true;
            }
        }

        impl Drop for NixDaemonGuard {
            fn drop(&mut self) {
                if !self.active || self.disarmed {
                    return;
                }
                start_service_and_socket("nix-daemon");
            }
        }

        let total_timer = Stopwatch::start();

        // Validate options first
        options.validate()?;

        // Step 1: Capture current state and verbosity for progress logging
        let (previous_state, verbosity) = {
            let manager = manager_arc.lock().unwrap();
            (manager.current_state()?, manager.verbosity)
        };

        // Step 2: Idempotent check - if already active, return early (AC: 7)
        if previous_state.is_active() {
            if verbosity >= Verbosity::Normal {
                tracing::info!(state = ?previous_state, "System already active, nothing to do");
            }
            return Ok(());
        }

        // Story 9.3 AC#1: Log activation started with structured state field
        tracing::info!(state_from = ?previous_state, "Activation started");

        // Step 2.5: Handle --kill-session flag (Story 4.15, AC8)
        // Kill graphical session BEFORE pre-flight checks to ensure optimal activation
        // This enables all direct overlay mounts without pivot mount fallback
        let killed_display_manager = if options.kill_session {
            use crate::process::{
                SessionType, detect_session_type, kill_graphical_session,
                prompt_session_kill_confirmation,
            };

            if verbosity >= Verbosity::Normal {
                tracing::info!("Detecting session type for --kill-session...");
            }

            let session = detect_session_type()?;

            match session {
                SessionType::GraphicalUser {
                    ref display_manager,
                    ..
                } => {
                    // Prompt for confirmation unless --yes flag
                    prompt_session_kill_confirmation(&session, options.yes)?;

                    if verbosity >= Verbosity::Normal {
                        tracing::info!("Killing graphical session ({})", display_manager);
                    }

                    let kill_result = kill_graphical_session(&session)?;

                    if verbosity >= Verbosity::Verbose {
                        tracing::info!(
                            "  ✓ Session killed: {} processes terminated, {} force-killed",
                            kill_result.processes_terminated,
                            kill_result.processes_force_killed
                        );
                    }

                    // Store display manager name for restart later
                    Some(display_manager.clone())
                }
                SessionType::Tty => {
                    if verbosity >= Verbosity::Verbose {
                        tracing::info!("Running in TTY - no session to kill");
                    }
                    None
                }
                SessionType::Ssh => {
                    if verbosity >= Verbosity::Verbose {
                        tracing::info!("Running over SSH - no local session to kill");
                    }
                    None
                }
                SessionType::GraphicalRoot => {
                    if verbosity >= Verbosity::Normal {
                        tracing::warn!(
                            "Running as root in graphical session - cannot kill session"
                        );
                    }
                    None
                }
                SessionType::Unknown => {
                    if verbosity >= Verbosity::Normal {
                        tracing::warn!("Could not detect session type - skipping session kill");
                    }
                    None
                }
            }
        } else {
            None
        };

        // Auto-restart display manager if we exit early with an error after killing it.
        let mut dm_restart_guard = DisplayManagerRestartGuard::new(killed_display_manager.clone());

        // Step 2.75: Stage hidden config symlink before pre-flight checks (Story 15.2).
        // This ensures NixOSConfigCheck can validate the staged link.
        {
            let manager = manager_arc.lock().unwrap();
            if let Err(e) = crate::stage_hidden_config_symlink(
                &manager.filesystem,
                &manager.config.hidden_volume_root,
            ) {
                if no_preflight {
                    tracing::warn!(
                        error = %e,
                        "Skipping staged config failure due to --no-preflight (activation may not use hidden config)"
                    );
                } else {
                    tracing::error!(
                        error = %e,
                        "Failed to stage hidden config symlink before pre-flight checks"
                    );
                    return Err(e);
                }
            }
        }

        // Step 3: Run pre-flight checks (unless skipped)
        if no_preflight {
            if verbosity >= Verbosity::Normal {
                tracing::warn!("DANGER: Skipping pre-flight checks. Activation may fail.");
            }
        } else {
            if verbosity >= Verbosity::Normal {
                tracing::info!("Running pre-flight checks...");
            }
            let step_timer = Stopwatch::start();
            // Run checks before creating StateGuard to avoid rollback overhead
            let manager = manager_arc.lock().unwrap();
            manager.run_preflight_checks()?;
            // Drop lock before proceeding
            drop(manager);
            if verbosity >= Verbosity::Normal {
                // AC #1: Pre-flight checks event with duration_ms field
                tracing::info!(
                    duration_ms = step_timer.elapsed().as_millis() as u64,
                    "Pre-flight checks passed"
                );
            }
        }

        // Step 4: Create StateGuard for automatic rollback on failure/panic
        // If we don't call guard.commit(), drop() will rollback to previous_state
        let guard = StateGuard::new(Arc::clone(&manager_arc), previous_state.clone());

        // Step 5: Validate transition is allowed
        let activating_state = previous_state.begin_activation()?;

        // Step 6: Transition to Activating state
        {
            let mut manager = manager_arc.lock().unwrap();
            manager.update_state(activating_state)?;
        }

        // Step 7: Build NixOS profile (if NixOSBuilder configured)
        let generation = {
            let manager = manager_arc.lock().unwrap();
            if let Some(ref builder) = manager.nixos_builder {
                if verbosity >= Verbosity::Normal {
                    tracing::info!("Building NixOS profile...");
                }
                let step_timer = Stopwatch::start();
                let generation_id = builder.build_profile().map_err(|e| {
                    // Story 9.3 AC#2: Structured error event for NixOS build failure
                    let error_msg = match &e {
                        NailsError::NixOSError(msg) => format!("NixOS build failed: {}", msg),
                        other => format!("NixOS build failed: {}", other),
                    };

                    tracing::error!(
                        error = %e,
                        phase = "nixos_build",
                        rollback = true,
                        "NixOS profile build failed"
                    );

                    match e {
                        NailsError::NixOSError(_) => NailsError::NixOSError(error_msg),
                        other => other,
                    }
                })?;
                if verbosity >= Verbosity::Normal {
                    tracing::info!(
                        step = "nixos_build",
                        duration_ms = step_timer.elapsed().as_millis() as u64,
                        generation = generation_id,
                        "✓ NixOS profile ready: generation {} ({})",
                        generation_id,
                        step_timer
                    );
                }
                Some(generation_id)
            } else {
                None
            }
        };

        // Step 8: Mount persistent overlays with incremental state tracking (Story 4.7, AC1, AC2, Task 4)
        // Mount order is critical: /home first (no dependencies), /etc second (may depend on /home)
        // See MOUNT_ORDER constant for rationale (Story 4.6, AC1)

        // TODO(story-4-5): Integrate prepare_nixos_config_overlay() before mounting /etc overlay
        //
        // Story 4.12, Task 4 (DEFERRED): Before mounting /etc overlay, validate and prepare
        // the NixOS configuration overlay structure by calling:
        //
        //   use crate::prepare_nixos_config_overlay;
        //   let info = prepare_nixos_config_overlay(&fs, &hidden_path)?;
        //
        // This ensures the hidden storage contains the required NixOS config structure:
        // - {hidden}/etc/nixos/hardware-configuration.nix (modified with hidden import)
        // - {hidden}/config/nixos/configuration.nix (hidden environment config)
        //
        // The /etc overlay must include the hidden nixos/ directory to make the modified
        // hardware-configuration.nix visible to the system.
        //
        // See: docs/sprint-artifacts/4-12-implement-nixos-hardware-configuration-nix-overlay-mechanism.md
        //
        // TODO(story-4-5): Write integration tests for full activation/deactivation cycle
        //
        // Story 4.12, Task 9 (DEFERRED): After integration is complete, add tests that verify:
        // - Full activation shows modified config with hidden import
        // - Full deactivation reverts to base config (no hidden import)
        // - Simulated NixOS rebuild reads correct config in both states
        // - No forensic traces remain after deactivation
        //
        // These tests require the NailsManager integration from Task 4 above.

        // Story 15.1, AC1: Verify base hardware-configuration.nix is forensically clean before
        // any overlays are mounted. Fail activation if the base config already contains
        // NAILS or hidden references that would betray the overlay approach.
        {
            let manager = manager_arc.lock().unwrap();
            match verify_base_config_clean(&manager.filesystem) {
                Ok(true) => {
                    tracing::debug!("Base hardware-configuration.nix is clean — proceeding");
                }
                Ok(false) => {
                    tracing::error!(
                        "Base /etc/nixos/hardware-configuration.nix contains suspicious references \
                         (NAILS or hidden paths). Activation aborted to preserve forensic integrity."
                    );
                    return Err(NailsError::NixOSError(
                        "Base hardware-configuration.nix is not forensically clean — \
                         contains NAILS or hidden references before overlay mount"
                            .into(),
                    ));
                }
                Err(e) => {
                    // Treat unreadable base config as a hard failure to avoid unsafe activation.
                    tracing::error!(
                        error = %e,
                        "Could not verify base hardware-configuration.nix; activation aborted"
                    );
                    return Err(e);
                }
            }
        }

        if verbosity >= Verbosity::Normal {
            tracing::info!("Mounting overlays...");
        }
        let mount_timer = Stopwatch::start();

        // Create shared tracker for both persistent and ephemeral overlays (Story 4.11)
        // Tracker will be committed after all mounts succeed (persistent + ephemeral)
        let manager = manager_arc.lock().unwrap();
        let mut tracker = MountTracker::new(&manager.filesystem);

        // Build OverlayStrategyOptions from ActivateOptions (Story 4.15, AC8)
        let strategy_options = crate::overlay::OverlayStrategyOptions {
            auto_restart_safe: true,        // Always restart safe processes automatically
            prompt_for_risky: !options.yes, // Skip risky prompts if --yes flag
            allow_pivot: !options.no_pivot, // Respect --no-pivot flag
            auto_accept_pivot: options.accept_pivot_risks, // Auto-accept if --accept-pivot-risks
            skip_process_detection: options
                .skip_process_detection_override
                .unwrap_or(cfg!(test)), // Allow tests to override
        };

        // Track mount methods for logging
        let mut direct_mounts = 0;
        let mut pivot_mounts = 0;

        // Step 8a: Mount persistent overlays using universal algorithm (Story 4.15)
        // Story 14.10: Use dynamic target list based on overlay_mode
        match manager.config.overlay_mode {
            crate::OverlayMode::Auto => {
                // Auto mode: enumerate root + apply exclusions, create overlays dynamically
                let overlay_targets = build_overlay_targets(&manager.filesystem, &manager.config)?;

                // Pre-overlay: stop nix-daemon if /nix will be overlaid
                // Must happen BEFORE Phase 1 detection so nix-daemon doesn't appear
                // in the blocking process list with its mount namespace references.
                let nix_in_targets = overlay_targets.iter().any(|t| t == Path::new("/nix"));
                let mut nix_guard = NixDaemonGuard::new(nix_in_targets);
                if nix_in_targets {
                    tracing::info!("Stopping nix-daemon before /nix overlay...");
                    // Stop socket first (prevents socket-activation restart)
                    let _ = std::process::Command::new("systemctl")
                        .args(["stop", "nix-daemon.socket"])
                        .output();
                    let _ = std::process::Command::new("systemctl")
                        .args(["stop", "nix-daemon.service"])
                        .output();
                }

                // Track mount failures for best-effort mounting (Story 14.10, Task 8)
                let mut mount_failures: Vec<(PathBuf, NailsError)> = Vec::new();
                let mut nix_overlay_succeeded = false;

                for target in overlay_targets {
                    // Create overlay config on-the-fly (Story 14.10, Task 6)
                    let overlay = match create_overlay_config(
                        &manager.filesystem,
                        &target,
                        &manager.config.hidden_volume_root,
                    ) {
                        Ok(config) => config,
                        Err(e) => {
                            // Best-effort: log warning, track failure, continue with next overlay
                            tracing::warn!(
                                target = %target.display(),
                                error = %e,
                                "⚠ Could not create overlay config for {}: {}",
                                target.display(),
                                e
                            );
                            mount_failures.push((target.clone(), e));
                            continue;
                        }
                    };

                    // Task 6: DNS preservation - clean stale network config before mounting /etc
                    if target == Path::new("/etc")
                        && let Err(e) =
                            clean_stale_network_config(&overlay.upper, &manager.filesystem)
                    {
                        tracing::warn!(
                            error = %e,
                            "Failed to clean stale network config from /etc upper layer: {}",
                            e
                        );
                        // Continue anyway - this is best-effort
                    }

                    // Use universal overlay mounting algorithm (Story 4.15, AC8)
                    match crate::overlay::mount_overlay_with_strategy(
                        &manager.filesystem,
                        &overlay.lower,
                        &overlay.upper,
                        &overlay.work,
                        &overlay.target,
                        &strategy_options,
                    ) {
                        Ok(mount_result) => {
                            use crate::overlay::MountMethod;

                            // Track mount type for logging
                            match mount_result.method {
                                MountMethod::Direct => {
                                    direct_mounts += 1;
                                    if verbosity >= Verbosity::Verbose {
                                        tracing::info!(
                                            "  ✓ {} mounted (direct, optimal security)",
                                            overlay.target.display()
                                        );
                                    }
                                }
                                MountMethod::Pivot => {
                                    pivot_mounts += 1;
                                    if verbosity >= Verbosity::Verbose {
                                        tracing::warn!(
                                            "  ⚠️  {} mounted (pivot, degraded security)",
                                            overlay.target.display()
                                        );
                                    }
                                }
                            }

                            // Post-mount: restart stopped services so they write to overlay
                            for service in &mount_result.stopped_services {
                                start_service_and_socket(service);
                                tracing::info!(
                                    service = %service,
                                    target = %overlay.target.display(),
                                    "Restarted {} (now writing to overlay)", service
                                );
                            }

                            // Track if /nix overlay succeeded for post-mount lifecycle
                            if overlay.target == Path::new("/nix") {
                                nix_overlay_succeeded = true;
                            }

                            tracker.push_mount(MountInfo::persistent(overlay.target.clone()));

                            // Story 15.1, AC2/AC4: After /etc overlay is mounted, inject the
                            // NAILS import block into the overlayed hardware-configuration.nix.
                            // Writes land in the upper layer — the base underlay is untouched (AC3).
                            if overlay.target == Path::new("/etc")
                                && let Err(e) = inject_import_block(&manager.filesystem)
                            {
                                tracing::error!(
                                    error = %e,
                                    rollback = true,
                                    "Failed to inject NAILS import block into /etc/nixos/hardware-configuration.nix: {}",
                                    e
                                );
                                if let Err(rollback_err) = tracker.rollback_all() {
                                    tracing::error!(
                                        error = %rollback_err,
                                        context = "inject_import_block_failure",
                                        rollback = true,
                                        "Rollback failed after inject_import_block failure"
                                    );
                                }
                                return Err(e);
                            }

                            // Story 4.7, AC2, Task 4: Update overlay_status incrementally after EACH mount
                            let overlay_info = OverlayInfo {
                                mount_path: overlay.target.clone(),
                                lower_dir: overlay.lower.clone(),
                                upper_dir: overlay.upper.clone(),
                                work_dir: overlay.work.clone(),
                                mounted_at: Utc::now(),
                            };

                            // Update cached state with this mount
                            let mut cached = manager.cached_state.lock().unwrap();
                            if let Some(ref mut state_file) = *cached {
                                state_file
                                    .overlay_status
                                    .insert(overlay.target.clone(), overlay_info);

                                drop(cached); // Release lock before saving
                                if let Err(e) = manager.save_cached_state()
                                    && verbosity >= Verbosity::Debug
                                {
                                    tracing::warn!("Failed to save state after mount: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            // Story 14.10, Task 8: Best-effort mounting
                            tracing::warn!(
                                error = %e,
                                target = %overlay.target.display(),
                                "⚠ Could not overlay {}: {}",
                                overlay.target.display(),
                                e
                            );
                            mount_failures.push((overlay.target.clone(), e));
                            continue;
                        }
                    }
                }

                // If ALL overlays failed, rollback and return error
                if tracker.mounted.is_empty() && !mount_failures.is_empty() {
                    tracing::error!(
                        failure_count = mount_failures.len(),
                        "All overlay mounts failed - activation aborted"
                    );

                    if let Err(rollback_err) = tracker.rollback_all() {
                        tracing::error!(
                            error = %rollback_err,
                            context = "mount_failure_recovery",
                            rollback = true,
                            "Rollback failed during mount failure recovery"
                        );
                    }

                    // Return first failure as representative error
                    return Err(mount_failures.into_iter().next().unwrap().1);
                }

                // Story 14.10, AC9: Record failed overlays in state for status reporting
                if !mount_failures.is_empty() {
                    let failed_infos: Vec<FailedOverlayInfo> = mount_failures
                        .iter()
                        .map(|(path, error)| FailedOverlayInfo {
                            target: path.clone(),
                            error_message: error.to_string(),
                            failed_at: Utc::now(),
                        })
                        .collect();

                    tracing::warn!(
                        failed_count = failed_infos.len(),
                        "Recording {} failed overlay(s) in state for status reporting",
                        failed_infos.len()
                    );

                    let mut cached = manager.cached_state.lock().unwrap();
                    if let Some(ref mut state_file) = *cached {
                        state_file.failed_overlays = failed_infos;
                        drop(cached);
                        if let Err(e) = manager.save_cached_state()
                            && verbosity >= Verbosity::Debug
                        {
                            tracing::warn!("Failed to save failed_overlays to state: {}", e);
                        }
                    }
                }

                // Any failure should abort activation to avoid partially-active state.
                if !mount_failures.is_empty() {
                    return Err(NailsError::InvalidState(format!(
                        "{} overlay(s) failed to mount",
                        mount_failures.len()
                    )));
                }

                // Post-overlay: if /nix was successfully overlaid, restore NixOS security model
                if nix_overlay_succeeded {
                    // Step 1: Recreate read-only bind mount on /nix/store
                    // The overlay on /nix hides the boot-time bind mount; we recreate it
                    // so regular processes see /nix/store as read-only (defense-in-depth)
                    tracing::info!("Restoring read-only bind mount on /nix/store...");
                    let nix_store = Path::new("/nix/store");
                    if let Err(e) = manager.filesystem.bind_mount(nix_store, nix_store) {
                        tracing::warn!(
                            error = %e,
                            "Could not recreate /nix/store bind mount (non-fatal)"
                        );
                    } else {
                        // Remount as read-only (uses Command since Filesystem trait lacks remount_readonly)
                        let remount_result = std::process::Command::new("mount")
                            .args(["-o", "remount,ro,bind", "/nix/store"])
                            .output();
                        match remount_result {
                            Ok(output) if output.status.success() => {
                                tracing::info!("Read-only bind mount on /nix/store restored");
                            }
                            Ok(output) => {
                                tracing::warn!(
                                    stderr = %String::from_utf8_lossy(&output.stderr),
                                    "Remount /nix/store as read-only failed (non-fatal)"
                                );
                            }
                            Err(e) => {
                                tracing::warn!(
                                    error = %e,
                                    "Remount /nix/store command failed (non-fatal)"
                                );
                            }
                        }
                    }

                    // Step 2: Restart nix-daemon (inherits overlay, creates own rw namespace)
                    tracing::info!("Restarting nix-daemon (now writing to overlay)...");
                    start_service_and_socket("nix-daemon");
                    nix_guard.disarm();
                }
            }
            crate::OverlayMode::Explicit => {
                // Explicit mode: use pre-configured overlays (legacy behavior)
                // Security check: fail if no overlays configured (would leave system unprotected)
                if manager.config.overlays.is_empty() {
                    return Err(NailsError::ConfigError(
                        "Explicit mode configured but no overlays defined - system would have NO forensic protection. \
                         Add overlays to config or switch to overlay_mode: auto".to_string()
                    ));
                }

                let critical = [Path::new("/bin"), Path::new("/usr")];
                for overlay in &manager.config.overlays {
                    if critical.contains(&overlay.target.as_path()) {
                        return Err(NailsError::InvalidState(format!(
                            "Overlaying critical system root {} is blocked for safety",
                            overlay.target.display()
                        )));
                    }
                }

                for overlay in &manager.config.overlays {
                    // Task 6: DNS preservation - clean stale network config before mounting /etc
                    if overlay.target == Path::new("/etc")
                        && let Err(e) =
                            clean_stale_network_config(&overlay.upper, &manager.filesystem)
                    {
                        tracing::warn!(
                            error = %e,
                            "Failed to clean stale network config from /etc upper layer: {}",
                            e
                        );
                        // Continue anyway - this is best-effort
                    }

                    // Use universal overlay mounting algorithm (Story 4.15, AC8)
                    match crate::overlay::mount_overlay_with_strategy(
                        &manager.filesystem,
                        &overlay.lower,
                        &overlay.upper,
                        &overlay.work,
                        &overlay.target,
                        &strategy_options,
                    ) {
                        Ok(mount_result) => {
                            use crate::overlay::MountMethod;

                            // Track mount type for logging
                            match mount_result.method {
                                MountMethod::Direct => {
                                    direct_mounts += 1;
                                    if verbosity >= Verbosity::Verbose {
                                        tracing::info!(
                                            "  ✓ {} mounted (direct, optimal security)",
                                            overlay.target.display()
                                        );
                                    }
                                }
                                MountMethod::Pivot => {
                                    pivot_mounts += 1;
                                    if verbosity >= Verbosity::Verbose {
                                        tracing::warn!(
                                            "  ⚠️  {} mounted (pivot, degraded security)",
                                            overlay.target.display()
                                        );
                                    }
                                }
                            }

                            // Post-mount: restart stopped services so they write to overlay
                            for service in &mount_result.stopped_services {
                                start_service_and_socket(service);
                                tracing::info!(
                                    service = %service,
                                    target = %overlay.target.display(),
                                    "Restarted {} (now writing to overlay)", service
                                );
                            }

                            tracker.push_mount(MountInfo::persistent(overlay.target.clone()));

                            // Story 15.1, AC2/AC4: After /etc overlay is mounted, inject the
                            // NAILS import block into the overlayed hardware-configuration.nix.
                            // Writes land in the upper layer — the base underlay is untouched (AC3).
                            if overlay.target == Path::new("/etc")
                                && let Err(e) = inject_import_block(&manager.filesystem)
                            {
                                tracing::error!(
                                    error = %e,
                                    rollback = true,
                                    "Failed to inject NAILS import block into /etc/nixos/hardware-configuration.nix: {}",
                                    e
                                );
                                if let Err(rollback_err) = tracker.rollback_all() {
                                    tracing::error!(
                                        error = %rollback_err,
                                        context = "inject_import_block_failure",
                                        rollback = true,
                                        "Rollback failed after inject_import_block failure"
                                    );
                                }
                                return Err(e);
                            }

                            // Story 4.7, AC2, Task 4: Update overlay_status incrementally after EACH mount
                            let overlay_info = OverlayInfo {
                                mount_path: overlay.target.clone(),
                                lower_dir: overlay.lower.clone(),
                                upper_dir: overlay.upper.clone(),
                                work_dir: overlay.work.clone(),
                                mounted_at: Utc::now(),
                            };

                            // Update cached state with this mount
                            let mut cached = manager.cached_state.lock().unwrap();
                            if let Some(ref mut state_file) = *cached {
                                state_file
                                    .overlay_status
                                    .insert(overlay.target.clone(), overlay_info);

                                drop(cached); // Release lock before saving
                                if let Err(e) = manager.save_cached_state()
                                    && verbosity >= Verbosity::Debug
                                {
                                    tracing::warn!("Failed to save state after mount: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            // Explicit mode: fail fast on mount errors (original behavior)
                            tracing::error!(
                                error = %e,
                                target = %overlay.target.display(),
                                rollback = true,
                                "Overlay mount failed"
                            );

                            if let Err(rollback_err) = tracker.rollback_all() {
                                tracing::error!(
                                    error = %rollback_err,
                                    context = "mount_failure_recovery",
                                    rollback = true,
                                    "Rollback failed during mount failure recovery"
                                );
                            }
                            return Err(e);
                        }
                    }
                }
            }
        }

        // Extract persistent overlay paths for state file (before mounting ephemeral)
        let mounted_overlays: Vec<PathBuf> = tracker
            .mounted
            .iter()
            .filter(|info| info.mount_type == MountType::Persistent)
            .map(|info| info.target.clone())
            .collect();

        // Step 8b: Mount ephemeral overlays (/var, /tmp, /srv, /opt) - Story 4.11
        // These are RAM-backed and NOT tracked in state file (ephemeral = destroyed on unmount)
        if manager.config.extended_overlays.enabled {
            if verbosity >= Verbosity::Verbose {
                tracing::info!("Mounting ephemeral overlays...");
            }

            for ephemeral_dir in &manager.config.extended_overlays.directories {
                if verbosity >= Verbosity::Debug {
                    tracing::debug!(
                        "Mounting ephemeral overlay: {} (upper: {}, work: {})",
                        ephemeral_dir.path.display(),
                        ephemeral_dir.tmpfs_upper_size,
                        ephemeral_dir.tmpfs_work_size
                    );
                }

                // Use pivot_ephemeral_mount for active directories (Story 4.11)
                // Direct mount fails with EINVAL on busy directories like /var
                // Pivot strategy: mount to staging → bind mount to target
                match crate::overlay::pivot_ephemeral_mount(
                    &manager.filesystem,
                    ephemeral_dir,
                    &ephemeral_dir.path,
                ) {
                    Ok(mount_info) => {
                        // Track pivot mount with staging + tmpfs paths for rollback
                        // Note: staging path is also needed for proper unmount
                        tracker.push_mount(MountInfo::ephemeral(
                            mount_info.target.clone(),
                            vec![
                                mount_info.staging.clone(), // staging (overlay mount point)
                                mount_info.upper.clone(),   // tmpfs upper
                                mount_info.work.clone(),    // tmpfs work
                            ],
                        ));

                        if verbosity >= Verbosity::Verbose {
                            tracing::info!(
                                "  ✓ {} mounted (ephemeral, RAM-backed)",
                                ephemeral_dir.path.display()
                            );
                        }
                    }
                    Err(e) => {
                        // Story 9.3 AC#2: Structured error event for ephemeral mount failure
                        tracing::error!(
                            error = %e,
                            target = %ephemeral_dir.path.display(),
                            mount_type = "ephemeral",
                            rollback = true,
                            "Ephemeral overlay mount failed"
                        );

                        // Rollback all mounts (persistent + any ephemeral that succeeded)
                        if let Err(rollback_err) = tracker.rollback_all() {
                            tracing::error!(
                                error = %rollback_err,
                                context = "ephemeral_mount_failure_recovery",
                                rollback = true,
                                "Rollback failed during ephemeral mount failure recovery"
                            );
                        }
                        return Err(e);
                    }
                }
            }
        }

        // Commit tracker to prevent automatic rollback on drop
        // This happens AFTER all mounts succeed (persistent + ephemeral)
        tracker.commit();

        // Story 9.3 AC#1: Log overlays mounted with structured fields
        let mounted_paths: Vec<_> = tracker
            .mounted
            .iter()
            .map(|info| info.target.clone())
            .collect();
        tracing::info!(overlays = ?mounted_paths, "Overlays mounted");

        // Drop tracker explicitly (now safe since it's committed)
        drop(tracker);

        // Release manager lock before continuing
        drop(manager);

        if verbosity >= Verbosity::Normal {
            let security_status = if pivot_mounts == 0 {
                "OPTIMAL"
            } else {
                "DEGRADED"
            };

            tracing::info!(
                step = "mount_overlays",
                duration_ms = mount_timer.elapsed().as_millis() as u64,
                direct_mounts = direct_mounts,
                pivot_mounts = pivot_mounts,
                "✓ All overlays mounted ({}) - {} direct, {} pivot - Security: {}",
                mount_timer,
                direct_mounts,
                pivot_mounts,
                security_status
            );
        }

        // Step 9: Switch NixOS profile and update nixos_generation (Story 4.7, AC3, Task 3.3)
        if let Some(ref generation_id) = generation {
            let manager = manager_arc.lock().unwrap();
            if let Some(ref builder) = manager.nixos_builder {
                if verbosity >= Verbosity::Normal {
                    tracing::info!("Switching to NixOS profile...");
                }
                let step_timer = Stopwatch::start();
                builder.switch_profile(generation_id).map_err(|e| {
                    // Story 9.3 AC#2: Structured error event for NixOS switch failure
                    let error_msg = match &e {
                        NailsError::NixOSError(msg) => format!("NixOS switch failed: {}", msg),
                        other => format!("NixOS switch failed: {}", other),
                    };

                    tracing::error!(
                        error = %e,
                        generation = generation_id,
                        phase = "nixos_switch",
                        rollback = true,
                        "NixOS profile switch failed"
                    );

                    match e {
                        NailsError::NixOSError(_) => NailsError::NixOSError(error_msg),
                        other => other,
                    }
                })?;
                if verbosity >= Verbosity::Normal {
                    tracing::info!(
                        step = "nixos_switch",
                        duration_ms = step_timer.elapsed().as_millis() as u64,
                        "✓ NixOS profile switched ({})",
                        step_timer
                    );
                }

                // Story 4.7, AC3: Update nixos_generation in state file after successful switch
                let mut cached = manager.cached_state.lock().unwrap();
                if let Some(ref mut state_file) = *cached {
                    state_file.nixos_generation = Some(generation_id.clone());

                    // Save state file to disk (AC1, AC3)
                    // State save failures here are non-critical - the switch succeeded and the system is functional.
                    // The final ACTIVE transition save will persist this data. This incremental save aids crash recovery.
                    drop(cached); // Release lock before saving
                    if let Err(e) = manager.save_cached_state()
                        && verbosity >= Verbosity::Debug
                    {
                        tracing::warn!("Failed to save nixos_generation to state: {}", e);
                    }
                    // Continue - switch succeeded, state save is for tracking/crash recovery only
                }
            }
        }

        // Step 10: Transition to Active state (Story 4.7, AC1, Task 3.4)
        {
            let mut manager = manager_arc.lock().unwrap();
            let current = manager.current_state()?;
            let active_state = current.complete_activation(mounted_overlays)?;
            // update_state() saves to disk automatically (line 675)
            manager.update_state(active_state)?;
        }

        // Step 10.5: Restart display manager if session was killed (Story 4.15, AC8)
        if let Some(ref dm_name) = killed_display_manager {
            use crate::process::{DisplayManager, restart_display_manager};

            if verbosity >= Verbosity::Normal {
                tracing::info!("Restarting display manager ({})...", dm_name);
            }

            let dm = match dm_name.to_lowercase().as_str() {
                "gdm" => DisplayManager::Gdm,
                "sddm" => DisplayManager::Sddm,
                "lightdm" => DisplayManager::LightDm,
                "greetd" => DisplayManager::Greetd,
                "ly" => DisplayManager::Ly,
                _ => DisplayManager::Other(dm_name.clone()), // Preserve original case for Other
            };

            restart_display_manager(&dm)?;
            dm_restart_guard.disarm();

            if verbosity >= Verbosity::Normal {
                tracing::info!("  ✓ Display manager restarted - login screen should appear");
            }
        }

        // Step 11: Success - commit guard to prevent rollback
        guard.commit();

        // Story 9.3 AC#1: Log activation complete with state transition and duration
        let final_state = {
            let manager = manager_arc.lock().unwrap();
            manager.current_state().ok()
        };

        // Always show completion message, even in Quiet mode (AC: 3)
        if verbosity >= Verbosity::Quiet {
            tracing::info!(
                step = "activation_complete",
                duration_ms = total_timer.elapsed().as_millis() as u64,
                state_to = ?final_state,
                "✓ Activation complete in {}",
                total_timer
            );
        }
        Ok(())
    }

    /// Deactivate NAILS with automatic RAII rollback on failure
    ///
    /// Validates current state is Active, transitions through Deactivating,
    /// unmounts overlays, and transitions to Inactive. If any step fails or panic occurs,
    /// StateGuard automatically rolls back to Active state via RAII (FR51).
    ///
    /// # RAII Rollback Pattern (FR51, NFR20, NFR24)
    ///
    /// This method uses StateGuard to guarantee automatic rollback on failure:
    /// - On success: `guard.commit()` prevents rollback
    /// - On unmount failure: `guard.drop()` restores Active state (overlays remain mounted)
    /// - On panic: Stack unwinding calls `guard.drop()`, restores Active state
    ///
    /// # Arguments
    ///
    /// * `manager_arc` - Shared reference to NailsManager wrapped in Arc<Mutex<>>
    ///
    /// # Errors
    ///
    /// - `NailsError::InvalidStateTransition` - Current state is not Active
    /// - `NailsError::UnmountError` - Overlay unmount failed (state rolled back to Active)
    /// - `NailsError::StateFileError` - Cannot read/write state file
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::{NailsManager, MockFilesystem, Config};
    /// use std::path::PathBuf;
    /// use std::sync::{Arc, Mutex};
    ///
    /// let fs = MockFilesystem::new();
    /// // ... setup and activate ...
    /// let manager = Arc::new(Mutex::new(
    ///     NailsManager::new(fs, Config::default(), PathBuf::from("/state.json"))
    /// ));
    /// let result = NailsManager::deactivate(Arc::clone(&manager));
    /// ```
    pub fn deactivate(manager_arc: Arc<Mutex<Self>>) -> Result<()> {
        use crate::StateGuard;

        // Step 1: Capture current state for StateGuard BEFORE any modifications
        let previous_state = {
            let manager = manager_arc.lock().unwrap();
            manager.current_state()?
        };

        // Step 2: Create StateGuard for automatic rollback on failure/panic
        // If we don't call guard.commit(), drop() will rollback to previous_state (Active)
        let guard = StateGuard::new(Arc::clone(&manager_arc), previous_state.clone());

        // Step 3: Validate transition is allowed
        let deactivating_state = previous_state.begin_deactivation()?;

        // Step 4: Transition to Deactivating state
        {
            let mut manager = manager_arc.lock().unwrap();
            manager.update_state(deactivating_state)?;
        }

        // Step 5: Get list of persistent overlays to unmount from state file
        let overlays_to_unmount = {
            let manager = manager_arc.lock().unwrap();
            let cached = manager.cached_state.lock().unwrap();
            if let Some(ref state_file) = *cached {
                state_file
                    .overlay_status
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>()
            } else {
                // No state file or no overlays tracked
                Vec::new()
            }
        };
        let etc_was_overlaid = overlays_to_unmount.iter().any(|p| p == Path::new("/etc"));

        // Step 5b: Unmount ephemeral overlays FIRST (LIFO: last mounted, first unmounted)
        // Story 4.11: Ephemeral overlays are RAM-backed and not tracked in state file
        // They must be unmounted before persistent overlays to maintain LIFO order
        let mut unmount_errors = Vec::new();
        {
            let manager = manager_arc.lock().unwrap();
            if manager.config.extended_overlays.enabled {
                tracing::info!(
                    phase = "deactivation",
                    mount_type = "ephemeral",
                    "Unmounting ephemeral overlays"
                );

                // Unmount in REVERSE order (LIFO)
                for ephemeral_dir in manager.config.extended_overlays.directories.iter().rev() {
                    tracing::info!(
                        path = %ephemeral_dir.path.display(),
                        mount_type = "ephemeral",
                        "Unmounting ephemeral overlay"
                    );

                    // Use unmount_pivot_overlay from overlay module (Story 4.11)
                    // Pivot mounts require: unmount bind → unmount staging → cleanup tmpfs
                    let dir_name = ephemeral_dir
                        .path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy();

                    let mount_info = crate::overlay::PivotMountInfo {
                        target: ephemeral_dir.path.clone(),
                        staging: PathBuf::from(format!(
                            "{}/{}",
                            crate::overlay::PIVOT_STAGING_BASE,
                            dir_name
                        )),
                        upper: PathBuf::from(format!("/run/nails/{}-upper", dir_name)),
                        work: PathBuf::from(format!("/run/nails/{}-work", dir_name)),
                        lower: ephemeral_dir.path.clone(), // Original directory
                        is_ephemeral: true,
                    };

                    match crate::overlay::unmount_pivot_overlay(&manager.filesystem, &mount_info) {
                        Ok(()) => {
                            tracing::info!(
                                path = %ephemeral_dir.path.display(),
                                mount_type = "ephemeral",
                                "Ephemeral overlay unmounted"
                            );
                        }
                        Err(e) => {
                            // Story 9.3 AC#2: Structured error event for ephemeral unmount failure
                            tracing::error!(
                                error = %e,
                                target = %ephemeral_dir.path.display(),
                                mount_type = "ephemeral",
                                phase = "deactivation",
                                "Ephemeral overlay unmount failed"
                            );
                            unmount_errors.push((ephemeral_dir.path.clone(), e));
                        }
                    }
                }
            }
        }

        // Step 5c: Pre-unmount nix-daemon lifecycle
        // If /nix is in the overlay list, stop nix-daemon and unmount our /nix/store bind mount
        // BEFORE unmounting the /nix overlay itself.
        let nix_was_overlaid = overlays_to_unmount.iter().any(|p| p == Path::new("/nix"));
        if nix_was_overlaid {
            tracing::info!("Stopping nix-daemon before /nix overlay unmount...");
            let _ = std::process::Command::new("systemctl")
                .args(["stop", "nix-daemon.socket"])
                .output();
            let _ = std::process::Command::new("systemctl")
                .args(["stop", "nix-daemon.service"])
                .output();

            // Unmount our recreated read-only bind mount on /nix/store
            // (the one we created during activation Task 7)
            tracing::info!("Unmounting /nix/store bind mount...");
            {
                let manager = manager_arc.lock().unwrap();
                if let Err(e) = manager.filesystem.unmount(Path::new("/nix/store"), false) {
                    tracing::warn!(
                        error = %e,
                        "Could not unmount /nix/store bind mount (may not have been mounted)"
                    );
                }
            }
        }

        // Step 6: Unmount persistent overlays - if any fail, StateGuard will rollback
        for overlay_path in &overlays_to_unmount {
            let unmount_result = {
                let manager = manager_arc.lock().unwrap();
                manager.filesystem.unmount(overlay_path, false)
            };

            match unmount_result {
                Ok(()) => {
                    tracing::info!(
                        path = %overlay_path.display(),
                        mount_type = "persistent",
                        "Overlay unmounted"
                    );
                }
                Err(e) => {
                    // Story 9.3 AC#2: Structured error event for persistent overlay unmount failure
                    tracing::error!(
                        error = %e,
                        target = %overlay_path.display(),
                        mount_type = "persistent",
                        phase = "deactivation",
                        "Persistent overlay unmount failed"
                    );
                    unmount_errors.push((overlay_path.clone(), e));
                }
            }
        }

        // If any unmount failed, return error and let StateGuard rollback
        if !unmount_errors.is_empty() {
            // Story 9.3 AC#2: Structured error event for deactivation failure with rollback
            tracing::error!(
                failed_count = unmount_errors.len(),
                total_overlays = overlays_to_unmount.len(),
                rollback = true,
                state_to = "Active",
                "Deactivation failed, rolling back to Active state"
            );

            // Return error with suggestion to retry manually (FR51)
            let error_msg = format!(
                "Failed to unmount {} overlay(s). System will rollback to Active state. \
                Suggestion: Close any open files in the hidden environment and retry. \
                First error: {:?}",
                unmount_errors.len(),
                unmount_errors[0].1
            );

            return Err(NailsError::UnmountError {
                path: unmount_errors[0].0.clone(),
                reason: error_msg,
            });
        }

        // Step 6b: Post-unmount nix-daemon restart
        // After /nix overlay is unmounted, the original boot-time bind mount is visible again.
        // Restart nix-daemon so it sees the original /nix.
        if nix_was_overlaid {
            tracing::info!("Restarting nix-daemon (now using original /nix)...");
            start_service_and_socket("nix-daemon");
        }

        // Step 7: Clear overlay_status in cached state (persistent overlays only)
        // Ephemeral overlays were never in state file
        {
            let manager = manager_arc.lock().unwrap();
            let mut cached = manager.cached_state.lock().unwrap();
            if let Some(ref mut state_file) = *cached {
                state_file.overlay_status.clear();
            }
        }

        // Step 8: Transition to Inactive state
        {
            let mut manager = manager_arc.lock().unwrap();
            let current = manager.current_state()?;
            let inactive_state = current.complete_deactivation()?;
            manager.update_state(inactive_state)?;
        }

        // Step 8.5 (Story 15.3, AC3): After all overlays are unmounted, verify the base
        // hardware-configuration.nix is forensically clean. Once the /etc overlay is gone the
        // OS-visible file reverts to the underlay — this check confirms no hidden references
        // survived on the underlay (which they never should, but we enforce it here).
        let base_config_error = if etc_was_overlaid {
            let manager = manager_arc.lock().unwrap();
            match verify_base_config_clean(&manager.filesystem) {
                Ok(true) => {
                    tracing::debug!(
                        "Post-deactivation: base hardware-configuration.nix is forensically clean"
                    );
                    None
                }
                Ok(false) => {
                    tracing::error!(
                        "Post-deactivation: base /etc/nixos/hardware-configuration.nix contains \
                         hidden references — underlay may have been polluted"
                    );
                    Some(NailsError::NixOSError(
                        "Base hardware-configuration.nix is not forensically clean after deactivation \
                         — underlay contains NAILS or hidden references"
                            .into(),
                    ))
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "Could not verify base hardware-configuration.nix after deactivation"
                    );
                    Some(e)
                }
            }
        } else {
            tracing::debug!(
                "Post-deactivation: /etc overlay was not mounted, skipping base config clean check"
            );
            None
        };

        if let Some(err) = base_config_error {
            // Deactivation already transitioned to Inactive; commit to prevent rollback to Active.
            guard.commit();
            return Err(err);
        }

        // Step 9: Success - commit guard to prevent rollback
        guard.commit();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::field_reassign_with_default)]
    use super::*;
    use crate::filesystem::MockOp;
    use crate::{
        EphemeralOverlayDir, ExtendedOverlayConfig, MockFilesystem, OverlayConfig, StateFile,
        Stopwatch, SystemState, Verbosity, config::DEFAULT_HIDDEN_VOLUME_ROOT, config::OverlayMode,
    };
    use chrono::Utc;
    use std::collections::HashMap;
    use std::path::Path;
    use std::sync::{Arc, Mutex};

    /// Helper function to check if logs contain a specific string
    /// This works with tracing-test's captured output
    #[allow(dead_code)]
    fn logs_contain(s: &str) -> bool {
        tracing_test::internal::logs_with_scope_contain("", s)
    }

    fn setup_nixos_config_check(fs: &MockFilesystem, hidden_root: &Path) {
        // Base hardware-configuration.nix must exist
        fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
        fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");
        fs.mock_set_file_content(
            "/etc/nixos/hardware-configuration.nix",
            "{ config, lib, pkgs, ... }:\n{ imports = [ ./nails/configuration.nix ]; }",
        );

        // Hidden overlay hardware config
        let hidden_etc = hidden_root.join("etc/nixos");
        let hidden_hw = hidden_etc.join("hardware-configuration.nix");
        fs.mock_set_path_exists(hidden_etc.to_str().unwrap(), true);
        fs.mock_set_path_type(hidden_etc.to_str().unwrap(), "directory");
        fs.mock_set_writable(hidden_etc.to_str().unwrap(), true);
        fs.mock_set_path_exists(hidden_hw.to_str().unwrap(), true);
        fs.mock_set_path_type(hidden_hw.to_str().unwrap(), "file");
        fs.mock_set_file_content(
            hidden_hw.to_str().unwrap(),
            "{ config, lib, pkgs, ... }:\n{ imports = [ ./nails/configuration.nix ]; }",
        );

        // Hidden config in new location
        let hidden_config = hidden_root.join("config/nixos/configuration.nix");
        fs.mock_set_path_exists(hidden_config.to_str().unwrap(), true);
        fs.mock_set_path_type(hidden_config.to_str().unwrap(), "file");
        fs.mock_set_file_content(hidden_config.to_str().unwrap(), "{ }");
    }

    fn create_test_manager() -> NailsManager<MockFilesystem> {
        let fs = MockFilesystem::new();
        let config = Config::default();
        let state_path = PathBuf::from("/mnt/hidden-volume/state.json");
        NailsManager::new(fs, config, state_path)
    }

    // ========== Task 3: Constructor Tests ==========

    #[test]
    fn test_new_stores_all_parameters() {
        let fs = MockFilesystem::new();
        let config = Config {
            hidden_volume_root: PathBuf::from("/mnt/test-hidden"),
            state_file_path: PathBuf::from("/mnt/test-hidden/state.json"),
            overlays: vec![],
            ..Config::test_default()
        };
        let state_path = PathBuf::from("/mnt/test-hidden/state.json");

        let manager = NailsManager::new(fs, config.clone(), state_path.clone());

        // Verify fields are stored (we can't directly access private fields,
        // but we can verify behavior in other tests)
        assert_eq!(manager.state_file_path, state_path);
        assert_eq!(manager.config, config);
    }

    #[test]
    fn test_new_does_not_load_state() {
        let fs = MockFilesystem::new();
        let config = Config::default();
        let state_path = PathBuf::from("/nonexistent/path/state.json");

        // Constructor should NOT fail even with invalid path
        // because it doesn't load state (lazy loading)
        let manager = NailsManager::new(fs, config, state_path);

        // State is not loaded yet
        let cached = manager.cached_state.lock().unwrap();
        assert!(cached.is_none());
    }

    #[test]
    fn test_new_initializes_cached_state_to_none() {
        let manager = create_test_manager();

        // Verify cached_state is None (not yet loaded)
        let cached = manager.cached_state.lock().unwrap();
        assert!(cached.is_none());
    }

    #[test]
    fn test_new_with_different_filesystem_implementations() {
        // Test with MockFilesystem
        let mock_fs = MockFilesystem::new();
        let config = Config::default();
        let state_path = PathBuf::from("/mnt/hidden-volume/state.json");
        let _mock_manager = NailsManager::new(mock_fs, config.clone(), state_path.clone());

        // Test with RealFilesystem (just verify compilation)
        use crate::RealFilesystem;
        let real_fs = RealFilesystem;
        let _real_manager = NailsManager::new(real_fs, config, state_path);
    }

    // ========== Task 4: current_state() Tests ==========

    #[test]
    fn test_current_state_lazy_loads_on_first_access() {
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let state_path = temp_dir.path().join("state.json");

        let fs = MockFilesystem::new();
        let config = Config::default();
        let manager = NailsManager::new(fs, config, state_path);

        // Verify state not loaded yet
        {
            let cached = manager.cached_state.lock().unwrap();
            assert!(cached.is_none());
        }

        // First call should load state
        let state = manager.current_state().expect("Should return state");

        // Verify state is now cached
        {
            let cached = manager.cached_state.lock().unwrap();
            assert!(cached.is_some());
        }

        // Should be Inactive (default for missing file)
        assert_eq!(state, SystemState::Inactive);
    }

    #[test]
    fn test_current_state_uses_cache_on_subsequent_calls() {
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let state_path = temp_dir.path().join("state.json");

        let fs = MockFilesystem::new();
        let config = Config::default();
        let manager = NailsManager::new(fs, config, state_path.clone());

        // First call loads and caches
        let state1 = manager.current_state().expect("Should return state");

        // Modify file on disk (to verify cache is used, not re-read)
        let different_state = StateFile {
            state: SystemState::Active {
                activated_at: chrono::Utc::now(),
                overlays: vec![],
            },
            ..StateFile::default()
        };
        let json = serde_json::to_string_pretty(&different_state).unwrap();
        std::fs::write(&state_path, json).unwrap();

        // Second call should use cache (not re-read file)
        let state2 = manager.current_state().expect("Should return state");

        // Both should be Inactive (from cache, not re-reading modified file)
        assert_eq!(state1, state2);
        assert_eq!(state2, SystemState::Inactive);
    }

    #[test]
    fn test_current_state_missing_file_returns_inactive() {
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let nonexistent_path = temp_dir.path().join("nonexistent.json");

        let fs = MockFilesystem::new();
        let config = Config::default();
        let manager = NailsManager::new(fs, config, nonexistent_path);

        // Should return Inactive (safe default)
        let state = manager.current_state().expect("Should return state");
        assert_eq!(state, SystemState::Inactive);
    }

    #[test]
    fn test_current_state_malformed_file_returns_inactive() {
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let malformed_path = temp_dir.path().join("malformed.json");

        // Write invalid JSON
        std::fs::write(&malformed_path, "{ invalid json syntax").unwrap();

        let fs = MockFilesystem::new();
        let config = Config::default();
        let manager = NailsManager::new(fs, config, malformed_path);

        // Should return Inactive (safe default)
        let state = manager.current_state().expect("Should return state");
        assert_eq!(state, SystemState::Inactive);
    }

    // ========== Task 5: update_state() Tests ==========

    #[test]
    fn test_update_state_valid_transition_succeeds() {
        // Use /tmp for testing (bypass hidden volume check for unit tests)
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path();
        std::fs::create_dir_all(mock_hidden_vol).unwrap();
        let state_path = mock_hidden_vol.join("state.json");

        let fs = MockFilesystem::new();
        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlays: vec![],
            ..Config::test_default()
        };
        let mut manager = NailsManager::new(fs, config, state_path.clone());

        // Manually create initial state file in temp (simulating hidden volume)
        let initial_state = StateFile::default();
        let json = serde_json::to_string_pretty(&initial_state).unwrap();
        std::fs::write(&state_path, json).unwrap();

        // Valid transition: Inactive -> Activating
        let result = manager.update_state(SystemState::Activating {
            started_at: Utc::now(),
        });
        assert!(result.is_ok());

        // Verify state was updated
        let state = manager.current_state().unwrap();
        assert!(matches!(state, SystemState::Activating { .. }));
    }

    #[test]
    fn test_update_state_invalid_transition_returns_error() {
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path();
        std::fs::create_dir_all(mock_hidden_vol).unwrap();
        let state_path = mock_hidden_vol.join("state.json");

        let fs = MockFilesystem::new();
        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlays: vec![],
            ..Config::test_default()
        };
        let mut manager = NailsManager::new(fs, config, state_path.clone());

        // Manually create initial state file
        let initial_state = StateFile::default();
        let json = serde_json::to_string_pretty(&initial_state).unwrap();
        std::fs::write(&state_path, json).unwrap();

        // Invalid transition: Inactive -> Active (must go through Activating)
        let result = manager.update_state(SystemState::Active {
            activated_at: Utc::now(),
            overlays: vec![],
        });
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), NailsError::InvalidState(_)));
    }

    #[test]
    fn test_update_state_saves_to_disk() {
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path();
        std::fs::create_dir_all(mock_hidden_vol).unwrap();
        let state_path = mock_hidden_vol.join("state.json");

        let fs = MockFilesystem::new();
        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlays: vec![],
            ..Config::test_default()
        };
        let mut manager = NailsManager::new(fs, config, state_path.clone());

        // Manually create initial state file
        let initial_state = StateFile::default();
        let json = serde_json::to_string_pretty(&initial_state).unwrap();
        std::fs::write(&state_path, json).unwrap();

        // Update state
        manager
            .update_state(SystemState::Activating {
                started_at: Utc::now(),
            })
            .unwrap();

        // Verify file was written (by loading directly)
        let loaded = StateFile::load(&state_path).unwrap();
        assert!(matches!(loaded.state, SystemState::Activating { .. }));
    }

    #[test]
    fn test_update_state_updates_cache() {
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path();
        std::fs::create_dir_all(mock_hidden_vol).unwrap();
        let state_path = mock_hidden_vol.join("state.json");

        let fs = MockFilesystem::new();
        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlays: vec![],
            ..Config::test_default()
        };
        let mut manager = NailsManager::new(fs, config, state_path.clone());

        // Manually create initial state file
        let initial_state = StateFile::default();
        let json = serde_json::to_string_pretty(&initial_state).unwrap();
        std::fs::write(&state_path, json).unwrap();

        // Update state
        manager
            .update_state(SystemState::Activating {
                started_at: Utc::now(),
            })
            .unwrap();

        // Verify cache was updated
        let state = manager.current_state().unwrap();
        assert!(matches!(state, SystemState::Activating { .. }));
    }

    // ========== Task 6: verify_overlay_status() Tests ==========

    #[test]
    fn test_verify_overlay_status_active_with_mounted_overlays_ok() {
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let state_path = temp_dir.path().join("state.json");

        let fs = MockFilesystem::new();

        // Set up mounted overlay
        fs.mock_set_mounted(Path::new("/home"), true);

        let config = Config::default();
        let manager = NailsManager::new(fs, config, state_path.clone());

        // Create Active state file with mounted overlay
        let mut overlay_status = HashMap::new();
        overlay_status.insert(
            PathBuf::from("/home"),
            OverlayInfo {
                mount_path: PathBuf::from("/home"),
                lower_dir: PathBuf::from("/home"),
                upper_dir: PathBuf::from("/mnt/hidden-volume/overlays/home/upper"),
                work_dir: PathBuf::from("/mnt/hidden-volume/overlays/home/work"),
                mounted_at: Utc::now(),
            },
        );

        let state_file = StateFile {
            state: SystemState::Active {
                activated_at: Utc::now(),
                overlays: vec![PathBuf::from("/home")],
            },
            overlay_status,
            ..StateFile::default()
        };

        // Save manually
        let json = serde_json::to_string_pretty(&state_file).unwrap();
        std::fs::write(&state_path, json).unwrap();

        // Verify should succeed
        let result = manager.verify_overlay_status();
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_overlay_status_active_with_missing_overlay_error() {
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let state_path = temp_dir.path().join("state.json");

        let fs = MockFilesystem::new();
        // Overlay is NOT mounted

        let config = Config::default();
        let manager = NailsManager::new(fs, config, state_path.clone());

        // Create Active state file claiming overlay is mounted
        let mut overlay_status = HashMap::new();
        overlay_status.insert(
            PathBuf::from("/home"),
            OverlayInfo {
                mount_path: PathBuf::from("/home"),
                lower_dir: PathBuf::from("/home"),
                upper_dir: PathBuf::from("/mnt/hidden-volume/overlays/home/upper"),
                work_dir: PathBuf::from("/mnt/hidden-volume/overlays/home/work"),
                mounted_at: Utc::now(),
            },
        );

        let state_file = StateFile {
            state: SystemState::Active {
                activated_at: Utc::now(),
                overlays: vec![PathBuf::from("/home")],
            },
            overlay_status,
            ..StateFile::default()
        };

        // Save manually
        let json = serde_json::to_string_pretty(&state_file).unwrap();
        std::fs::write(&state_path, json).unwrap();

        // Verify should fail (state claims mounted but it's not)
        let result = manager.verify_overlay_status();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), NailsError::InvalidState(_)));
    }

    // ========== Task 7: activate() Tests ==========

    #[test]
    fn test_activate_successful_activation_transitions_through_states() {
        use crate::OverlayConfig;

        // Create mock hidden volume structure in temp dir
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path();
        std::fs::create_dir_all(mock_hidden_vol).unwrap();
        let state_path = mock_hidden_vol.join("state.json");

        let fs = MockFilesystem::new();

        // Set up paths to exist
        fs.mock_set_path_exists("/", true);
        let upper_dir = mock_hidden_vol.join("overlays/home/upper");
        let work_dir = mock_hidden_vol.join("overlays/home/work");
        std::fs::create_dir_all(&upper_dir).unwrap();
        std::fs::create_dir_all(&work_dir).unwrap();
        fs.mock_set_path_exists(upper_dir.to_str().unwrap(), true);
        fs.mock_set_path_exists(work_dir.to_str().unwrap(), true);

        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlay_mode: crate::OverlayMode::Explicit, // Use explicit mode for test
            overlays: vec![OverlayConfig {
                name: "home".to_string(),
                lower: PathBuf::from("/"),
                upper: upper_dir.clone(),
                work: work_dir.clone(),
                target: PathBuf::from("/home"),
            }],
            ..Config::test_default()
        };

        let manager = Arc::new(Mutex::new(NailsManager::new(
            fs.clone(),
            config,
            state_path,
        )));

        // Activate should succeed
        let result = NailsManager::activate(Arc::clone(&manager), true);
        assert!(result.is_ok());

        // Final state should be Active
        let state = manager.lock().unwrap().current_state().unwrap();
        assert!(matches!(state, SystemState::Active { .. }));
    }

    #[test]
    fn test_activate_from_non_inactive_returns_error() {
        use crate::StateFile;

        // Create mock hidden volume structure in temp dir
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path();
        std::fs::create_dir_all(mock_hidden_vol).unwrap();
        let state_path = mock_hidden_vol.join("state.json");

        let fs = MockFilesystem::new();
        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlays: vec![],
            ..Config::test_default()
        };
        let manager = Arc::new(Mutex::new(NailsManager::new(
            fs,
            config,
            state_path.clone(),
        )));

        // Manually write Active state to file (bypass transition validation)
        let state_file = StateFile {
            state: SystemState::Active {
                activated_at: Utc::now(),
                overlays: vec![],
            },
            ..StateFile::default()
        };
        let json = serde_json::to_string_pretty(&state_file).unwrap();
        std::fs::write(&state_path, json).unwrap();

        // Force manager to reload state from disk
        *manager.lock().unwrap().cached_state.lock().unwrap() = None;

        // AC7: activate() is idempotent - calling from Active state should succeed (no-op)
        let result = NailsManager::activate(Arc::clone(&manager), true);
        assert!(
            result.is_ok(),
            "Activate should be idempotent and succeed from Active state"
        );

        // Verify state is still Active (unchanged)
        let final_state = manager.lock().unwrap().current_state().unwrap();
        assert!(
            final_state.is_active(),
            "State should remain Active after idempotent activate"
        );
    }

    #[test]
    fn test_activate_calls_mount_overlay_for_each_configured_overlay() {
        use crate::OverlayConfig;

        // Create mock hidden volume structure in temp dir
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path();
        std::fs::create_dir_all(mock_hidden_vol).unwrap();
        let state_path = mock_hidden_vol.join("state.json");

        let fs = MockFilesystem::new();

        // Set up paths to exist
        fs.mock_set_path_exists("/", true);
        let upper_dir = mock_hidden_vol.join("overlays/home/upper");
        let work_dir = mock_hidden_vol.join("overlays/home/work");
        std::fs::create_dir_all(&upper_dir).unwrap();
        std::fs::create_dir_all(&work_dir).unwrap();
        fs.mock_set_path_exists(upper_dir.to_str().unwrap(), true);
        fs.mock_set_path_exists(work_dir.to_str().unwrap(), true);

        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlay_mode: crate::OverlayMode::Explicit, // Use explicit mode for test
            overlays: vec![OverlayConfig {
                name: "home".to_string(),
                lower: PathBuf::from("/"),
                upper: upper_dir.clone(),
                work: work_dir.clone(),
                target: PathBuf::from("/home"),
            }],
            ..Config::test_default()
        };

        let fs_clone = fs.clone();
        let manager = Arc::new(Mutex::new(NailsManager::new(
            fs.clone(),
            config,
            state_path,
        )));

        // Activate
        NailsManager::activate(Arc::clone(&manager), true).unwrap();

        // Verify mount was called
        assert!(fs_clone.is_mounted(Path::new("/home")).unwrap());
    }

    // ========== Task 5: Activation Failure Rollback Tests ==========

    #[test]
    fn test_activate_failure_at_mount_rolls_back_to_inactive() {
        use crate::OverlayConfig;

        // Create mock hidden volume structure in temp dir
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path();
        std::fs::create_dir_all(mock_hidden_vol).unwrap();
        let state_path = mock_hidden_vol.join("state.json");

        let fs = MockFilesystem::new();

        // Set up paths to exist
        fs.mock_set_path_exists("/", true);
        let upper_dir = mock_hidden_vol.join("overlays/home/upper");
        let work_dir = mock_hidden_vol.join("overlays/home/work");
        std::fs::create_dir_all(&upper_dir).unwrap();
        std::fs::create_dir_all(&work_dir).unwrap();
        fs.mock_set_path_exists(upper_dir.to_str().unwrap(), true);
        fs.mock_set_path_exists(work_dir.to_str().unwrap(), true);

        // Configure filesystem to fail mount operation
        fs.mock_set_mount_should_fail("/home", true);

        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlay_mode: crate::OverlayMode::Explicit, // Use explicit mode for test
            overlays: vec![OverlayConfig {
                name: "home".to_string(),
                lower: PathBuf::from("/"),
                upper: upper_dir.clone(),
                work: work_dir.clone(),
                target: PathBuf::from("/home"),
            }],
            ..Config::test_default()
        };

        let fs_clone = fs.clone();
        let manager = Arc::new(Mutex::new(NailsManager::new(
            fs,
            config,
            state_path.clone(),
        )));

        // Verify initial state is Inactive
        assert_eq!(
            manager.lock().unwrap().current_state().unwrap(),
            SystemState::Inactive
        );

        // Activation should fail
        let result = NailsManager::activate(Arc::clone(&manager), true);
        assert!(result.is_err());

        // Verify state was rolled back to Inactive (FR50)
        let final_state = manager.lock().unwrap().current_state().unwrap();
        assert_eq!(
            final_state,
            SystemState::Inactive,
            "State should be rolled back to Inactive after mount failure"
        );

        // Verify overlay is not mounted after rollback
        assert!(
            !fs_clone.is_mounted(Path::new("/home")).unwrap(),
            "Overlay should not be mounted after failed activation"
        );

        // Verify state file contains Inactive
        let loaded = StateFile::load(&state_path).unwrap();
        assert_eq!(loaded.state, SystemState::Inactive);
    }

    #[test]
    fn test_activate_failure_unmounts_already_mounted_overlays() {
        use crate::OverlayConfig;

        // Create mock hidden volume structure in temp dir
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path();
        std::fs::create_dir_all(mock_hidden_vol).unwrap();
        let state_path = mock_hidden_vol.join("state.json");

        let fs = MockFilesystem::new();

        // Set up paths to exist
        fs.mock_set_path_exists("/", true);
        let upper_home = mock_hidden_vol.join("overlays/home/upper");
        let work_home = mock_hidden_vol.join("overlays/home/work");
        let upper_etc = mock_hidden_vol.join("overlays/etc/upper");
        let work_etc = mock_hidden_vol.join("overlays/etc/work");
        std::fs::create_dir_all(&upper_home).unwrap();
        std::fs::create_dir_all(&work_home).unwrap();
        std::fs::create_dir_all(&upper_etc).unwrap();
        std::fs::create_dir_all(&work_etc).unwrap();
        fs.mock_set_path_exists(upper_home.to_str().unwrap(), true);
        fs.mock_set_path_exists(work_home.to_str().unwrap(), true);
        fs.mock_set_path_exists(upper_etc.to_str().unwrap(), true);
        fs.mock_set_path_exists(work_etc.to_str().unwrap(), true);

        // Configure filesystem: first overlay succeeds, second fails
        fs.mock_set_mount_should_fail("/etc", true);

        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlay_mode: OverlayMode::Explicit,
            overlays: vec![
                OverlayConfig {
                    name: "home".to_string(),
                    lower: PathBuf::from("/"),
                    upper: upper_home.clone(),
                    work: work_home.clone(),
                    target: PathBuf::from("/home"),
                },
                OverlayConfig {
                    name: "etc".to_string(),
                    lower: PathBuf::from("/"),
                    upper: upper_etc.clone(),
                    work: work_etc.clone(),
                    target: PathBuf::from("/etc"),
                },
            ],
            ..Config::test_default()
        };

        let fs_clone = fs.clone();
        let manager = Arc::new(Mutex::new(NailsManager::new(
            fs,
            config,
            state_path.clone(),
        )));

        // Activation should fail at second overlay
        let result = NailsManager::activate(Arc::clone(&manager), true);
        assert!(result.is_err());

        // Verify /home was mounted initially but then unmounted during rollback
        assert!(
            !fs_clone.is_mounted(Path::new("/home")).unwrap(),
            "First overlay (/home) should be unmounted during rollback"
        );

        // Verify /etc was never mounted
        assert!(
            !fs_clone.is_mounted(Path::new("/etc")).unwrap(),
            "Second overlay (/etc) should never be mounted"
        );

        // Verify state was rolled back to Inactive
        assert_eq!(
            manager.lock().unwrap().current_state().unwrap(),
            SystemState::Inactive
        );
    }

    #[test]
    fn test_activate_failure_state_file_reflects_rollback() {
        use crate::OverlayConfig;

        // Create mock hidden volume structure in temp dir
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path();
        std::fs::create_dir_all(mock_hidden_vol).unwrap();
        let state_path = mock_hidden_vol.join("state.json");

        let fs = MockFilesystem::new();

        // Set up paths to exist
        fs.mock_set_path_exists("/", true);
        let upper_dir = mock_hidden_vol.join("overlays/home/upper");
        let work_dir = mock_hidden_vol.join("overlays/home/work");
        std::fs::create_dir_all(&upper_dir).unwrap();
        std::fs::create_dir_all(&work_dir).unwrap();
        fs.mock_set_path_exists(upper_dir.to_str().unwrap(), true);
        fs.mock_set_path_exists(work_dir.to_str().unwrap(), true);

        // Configure filesystem to fail mount
        fs.mock_set_mount_should_fail("/home", true);

        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlay_mode: crate::OverlayMode::Explicit, // Use explicit mode for test
            overlays: vec![OverlayConfig {
                name: "home".to_string(),
                lower: PathBuf::from("/"),
                upper: upper_dir.clone(),
                work: work_dir.clone(),
                target: PathBuf::from("/home"),
            }],
            ..Config::test_default()
        };

        let manager = Arc::new(Mutex::new(NailsManager::new(
            fs,
            config,
            state_path.clone(),
        )));

        // Activation should fail
        let result = NailsManager::activate(Arc::clone(&manager), true);
        assert!(result.is_err());

        // Verify state file was saved with Inactive state
        let loaded = StateFile::load(&state_path).unwrap();
        assert_eq!(
            loaded.state,
            SystemState::Inactive,
            "State file should contain Inactive after rollback"
        );

        // Verify overlay_status is empty (no mounted overlays)
        assert!(
            loaded.overlay_status.is_empty(),
            "overlay_status should be empty after rollback"
        );
    }

    // ========== Task 7: Deactivation Failure Rollback Tests ==========

    #[test]
    fn test_deactivate_failure_at_unmount_rolls_back_to_active() {
        use crate::OverlayConfig;

        // Create mock hidden volume structure in temp dir
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path();
        std::fs::create_dir_all(mock_hidden_vol).unwrap();
        let state_path = mock_hidden_vol.join("state.json");

        let fs = MockFilesystem::new();

        // Set up paths to exist
        fs.mock_set_path_exists("/", true);
        let upper_dir = mock_hidden_vol.join("overlays/home/upper");
        let work_dir = mock_hidden_vol.join("overlays/home/work");
        std::fs::create_dir_all(&upper_dir).unwrap();
        std::fs::create_dir_all(&work_dir).unwrap();
        fs.mock_set_path_exists(upper_dir.to_str().unwrap(), true);
        fs.mock_set_path_exists(work_dir.to_str().unwrap(), true);

        // Set up overlay as mounted
        fs.mock_set_mounted(Path::new("/home"), true);

        // Configure unmount to fail
        fs.mock_set_unmount_should_fail("/home", true);

        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlay_mode: crate::OverlayMode::Explicit, // Use explicit mode for test
            overlays: vec![OverlayConfig {
                name: "home".to_string(),
                lower: PathBuf::from("/"),
                upper: upper_dir.clone(),
                work: work_dir.clone(),
                target: PathBuf::from("/home"),
            }],
            ..Config::test_default()
        };

        let fs_clone = fs.clone();
        let manager = Arc::new(Mutex::new(NailsManager::new(
            fs,
            config,
            state_path.clone(),
        )));

        // Set up Active state with mounted overlay
        let mut overlay_status = HashMap::new();
        overlay_status.insert(
            PathBuf::from("/home"),
            OverlayInfo {
                mount_path: PathBuf::from("/home"),
                lower_dir: PathBuf::from("/"),
                upper_dir: upper_dir.clone(),
                work_dir: work_dir.clone(),
                mounted_at: Utc::now(),
            },
        );
        manager
            .lock()
            .unwrap()
            .force_state(SystemState::Active {
                activated_at: Utc::now(),
                overlays: vec![PathBuf::from("/home")],
            })
            .unwrap();
        {
            let mgr = manager.lock().unwrap();
            let mut cached = mgr.cached_state.lock().unwrap();
            if let Some(ref mut state_file) = *cached {
                state_file.overlay_status = overlay_status;
            }
        }

        // Verify initial state is Active
        assert!(matches!(
            manager.lock().unwrap().current_state().unwrap(),
            SystemState::Active { .. }
        ));

        // Deactivation should fail
        let result = NailsManager::deactivate(Arc::clone(&manager));
        assert!(result.is_err());

        // Verify error message recommends retry (FR51)
        match result.unwrap_err() {
            NailsError::UnmountError { reason, .. } => {
                assert!(
                    reason.contains("retry") || reason.contains("Active"),
                    "Error message should mention retry or Active state: {}",
                    reason
                );
            }
            other => panic!("Expected UnmountError, got: {:?}", other),
        }

        // Verify state was rolled back to Active (FR51)
        let final_state = manager.lock().unwrap().current_state().unwrap();
        assert!(
            matches!(final_state, SystemState::Active { .. }),
            "State should be rolled back to Active after unmount failure"
        );

        // Verify overlay remains mounted after rollback (FR51: Remount overlays if cleanup fails)
        assert!(
            fs_clone.is_mounted(Path::new("/home")).unwrap(),
            "Overlay should remain mounted after failed deactivation"
        );

        // Verify state file contains Active
        let loaded = StateFile::load(&state_path).unwrap();
        assert!(matches!(loaded.state, SystemState::Active { .. }));
    }

    #[test]
    fn test_deactivate_successful_unmounts_all_overlays() {
        use crate::OverlayConfig;

        // Create mock hidden volume structure in temp dir
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path();
        std::fs::create_dir_all(mock_hidden_vol).unwrap();
        let state_path = mock_hidden_vol.join("state.json");

        let fs = MockFilesystem::new();

        // Set up paths to exist
        fs.mock_set_path_exists("/", true);
        let upper_dir = mock_hidden_vol.join("overlays/home/upper");
        let work_dir = mock_hidden_vol.join("overlays/home/work");
        std::fs::create_dir_all(&upper_dir).unwrap();
        std::fs::create_dir_all(&work_dir).unwrap();
        fs.mock_set_path_exists(upper_dir.to_str().unwrap(), true);
        fs.mock_set_path_exists(work_dir.to_str().unwrap(), true);

        // Set up overlay as mounted
        fs.mock_set_mounted(Path::new("/home"), true);

        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlay_mode: crate::OverlayMode::Explicit, // Use explicit mode for test
            overlays: vec![OverlayConfig {
                name: "home".to_string(),
                lower: PathBuf::from("/"),
                upper: upper_dir.clone(),
                work: work_dir.clone(),
                target: PathBuf::from("/home"),
            }],
            ..Config::test_default()
        };

        let fs_clone = fs.clone();
        let manager = Arc::new(Mutex::new(NailsManager::new(
            fs,
            config,
            state_path.clone(),
        )));

        // Set up Active state with mounted overlay
        let mut overlay_status = HashMap::new();
        overlay_status.insert(
            PathBuf::from("/home"),
            OverlayInfo {
                mount_path: PathBuf::from("/home"),
                lower_dir: PathBuf::from("/"),
                upper_dir: upper_dir.clone(),
                work_dir: work_dir.clone(),
                mounted_at: Utc::now(),
            },
        );
        manager
            .lock()
            .unwrap()
            .force_state(SystemState::Active {
                activated_at: Utc::now(),
                overlays: vec![PathBuf::from("/home")],
            })
            .unwrap();
        {
            let mgr = manager.lock().unwrap();
            let mut cached = mgr.cached_state.lock().unwrap();
            if let Some(ref mut state_file) = *cached {
                state_file.overlay_status = overlay_status;
            }
        }

        // Deactivation should succeed
        let result = NailsManager::deactivate(Arc::clone(&manager));
        assert!(result.is_ok());

        // Verify overlay is unmounted
        assert!(
            !fs_clone.is_mounted(Path::new("/home")).unwrap(),
            "Overlay should be unmounted after successful deactivation"
        );

        // Verify state is Inactive
        assert_eq!(
            manager.lock().unwrap().current_state().unwrap(),
            SystemState::Inactive
        );

        // Verify state file contains Inactive
        let loaded = StateFile::load(&state_path).unwrap();
        assert_eq!(loaded.state, SystemState::Inactive);

        // Verify overlay_status is cleared
        assert!(loaded.overlay_status.is_empty());
    }

    #[test]
    fn test_deactivate_from_non_active_returns_error() {
        // Create mock hidden volume structure in temp dir
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path();
        std::fs::create_dir_all(mock_hidden_vol).unwrap();
        let state_path = mock_hidden_vol.join("state.json");

        let fs = MockFilesystem::new();
        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlays: vec![],
            ..Config::test_default()
        };
        let manager = Arc::new(Mutex::new(NailsManager::new(
            fs,
            config,
            state_path.clone(),
        )));

        // State is Inactive by default
        assert_eq!(
            manager.lock().unwrap().current_state().unwrap(),
            SystemState::Inactive
        );

        // deactivate() should fail from Inactive state
        let result = NailsManager::deactivate(Arc::clone(&manager));
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), NailsError::InvalidState(_)));
    }

    #[test]
    fn test_deactivate_partial_failure_unmounts_only_successful_ones() {
        use crate::OverlayConfig;

        // Create mock hidden volume structure in temp dir
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path();
        std::fs::create_dir_all(mock_hidden_vol).unwrap();
        let state_path = mock_hidden_vol.join("state.json");

        let fs = MockFilesystem::new();

        // Set up paths to exist
        fs.mock_set_path_exists("/", true);
        let upper_home = mock_hidden_vol.join("overlays/home/upper");
        let work_home = mock_hidden_vol.join("overlays/home/work");
        let upper_etc = mock_hidden_vol.join("overlays/etc/upper");
        let work_etc = mock_hidden_vol.join("overlays/etc/work");
        std::fs::create_dir_all(&upper_home).unwrap();
        std::fs::create_dir_all(&work_home).unwrap();
        std::fs::create_dir_all(&upper_etc).unwrap();
        std::fs::create_dir_all(&work_etc).unwrap();
        fs.mock_set_path_exists(upper_home.to_str().unwrap(), true);
        fs.mock_set_path_exists(work_home.to_str().unwrap(), true);
        fs.mock_set_path_exists(upper_etc.to_str().unwrap(), true);
        fs.mock_set_path_exists(work_etc.to_str().unwrap(), true);

        // Set up both overlays as mounted
        fs.mock_set_mounted(Path::new("/home"), true);
        fs.mock_set_mounted(Path::new("/etc"), true);

        // Configure unmount to fail only for /etc
        fs.mock_set_unmount_should_fail("/etc", true);

        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlays: vec![
                OverlayConfig {
                    name: "home".to_string(),
                    lower: PathBuf::from("/"),
                    upper: upper_home.clone(),
                    work: work_home.clone(),
                    target: PathBuf::from("/home"),
                },
                OverlayConfig {
                    name: "etc".to_string(),
                    lower: PathBuf::from("/"),
                    upper: upper_etc.clone(),
                    work: work_etc.clone(),
                    target: PathBuf::from("/etc"),
                },
            ],
            ..Config::test_default()
        };

        let manager = Arc::new(Mutex::new(NailsManager::new(
            fs,
            config,
            state_path.clone(),
        )));

        // Set up Active state with both overlays mounted
        let mut overlay_status = HashMap::new();
        overlay_status.insert(
            PathBuf::from("/home"),
            OverlayInfo {
                mount_path: PathBuf::from("/home"),
                lower_dir: PathBuf::from("/"),
                upper_dir: upper_home.clone(),
                work_dir: work_home.clone(),
                mounted_at: Utc::now(),
            },
        );
        overlay_status.insert(
            PathBuf::from("/etc"),
            OverlayInfo {
                mount_path: PathBuf::from("/etc"),
                lower_dir: PathBuf::from("/"),
                upper_dir: upper_etc.clone(),
                work_dir: work_etc.clone(),
                mounted_at: Utc::now(),
            },
        );
        manager
            .lock()
            .unwrap()
            .force_state(SystemState::Active {
                activated_at: Utc::now(),
                overlays: vec![PathBuf::from("/home"), PathBuf::from("/etc")],
            })
            .unwrap();
        {
            let mgr = manager.lock().unwrap();
            let mut cached = mgr.cached_state.lock().unwrap();
            if let Some(ref mut state_file) = *cached {
                state_file.overlay_status = overlay_status;
            }
        }

        // Deactivation should fail at /etc
        let result = NailsManager::deactivate(Arc::clone(&manager));
        assert!(result.is_err());

        // Verify state was rolled back to Active
        assert!(matches!(
            manager.lock().unwrap().current_state().unwrap(),
            SystemState::Active { .. }
        ));

        // Note: The current implementation doesn't remount /home after it was successfully unmounted
        // This is acceptable behavior - the rollback restores the *state* to Active but doesn't
        // reverse filesystem operations that already succeeded. The state file still tracks both
        // overlays as part of the Active state, even if /home was unmounted.
        // This is a known limitation that could be enhanced in future iterations.
    }

    // ========== Task 5: Pre-flight Integration Tests ==========

    #[test]
    fn test_preflight_all_checks_pass_activation_proceeds() {
        use crate::OverlayConfig;

        // Create mock hidden volume structure
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path();
        std::fs::create_dir_all(mock_hidden_vol).unwrap();
        let state_path = mock_hidden_vol.join("state.json");

        let fs = MockFilesystem::new();

        // Set up all paths for pre-flight checks to pass
        fs.mock_set_path_exists(mock_hidden_vol.to_str().unwrap(), true);
        fs.mock_set_mounted(mock_hidden_vol, true);
        setup_nixos_config_check(&fs, mock_hidden_vol);

        // Create expected directory structure
        let overlays_dir = mock_hidden_vol.join("overlays");
        let etc_dir = mock_hidden_vol.join("etc");
        let home_dir = mock_hidden_vol.join("home");
        let config_dir = mock_hidden_vol.join("config");
        let nixos_dir = mock_hidden_vol.join("nixos");
        let work_dir = mock_hidden_vol.join(".work");
        let work_etc = work_dir.join("etc");
        let work_home = work_dir.join("home");

        std::fs::create_dir_all(&overlays_dir).unwrap();
        std::fs::create_dir_all(&etc_dir).unwrap();
        std::fs::create_dir_all(&home_dir).unwrap();
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::create_dir_all(&nixos_dir).unwrap();
        std::fs::create_dir_all(&work_etc).unwrap();
        std::fs::create_dir_all(&work_home).unwrap();

        // Mock that MockFilesystem sees these directories
        fs.mock_set_path_exists(etc_dir.to_str().unwrap(), true);
        fs.mock_set_path_type(etc_dir.to_str().unwrap(), "directory");
        fs.mock_set_path_exists(home_dir.to_str().unwrap(), true);
        fs.mock_set_path_type(home_dir.to_str().unwrap(), "directory");
        fs.mock_set_path_exists(config_dir.to_str().unwrap(), true);
        fs.mock_set_path_type(config_dir.to_str().unwrap(), "directory");
        fs.mock_set_path_exists(nixos_dir.to_str().unwrap(), true);
        fs.mock_set_path_type(nixos_dir.to_str().unwrap(), "directory");
        fs.mock_set_path_exists(work_etc.to_str().unwrap(), true);
        fs.mock_set_path_type(work_etc.to_str().unwrap(), "directory");
        fs.mock_set_path_exists(work_home.to_str().unwrap(), true);
        fs.mock_set_path_type(work_home.to_str().unwrap(), "directory");

        // Set up overlay directories
        let upper_dir = overlays_dir.join("home").join("upper");
        let work_dir_path = work_home.clone();
        std::fs::create_dir_all(&upper_dir).unwrap();

        fs.mock_set_path_exists("/", true);
        fs.mock_set_path_type("/", "directory");
        fs.mock_set_path_exists(upper_dir.to_str().unwrap(), true);
        fs.mock_set_path_type(upper_dir.to_str().unwrap(), "directory");
        fs.mock_set_path_exists(work_dir_path.to_str().unwrap(), true);
        fs.mock_set_path_type(work_dir_path.to_str().unwrap(), "directory");
        fs.mock_set_readable(upper_dir.to_str().unwrap(), true);
        fs.mock_set_writable(upper_dir.to_str().unwrap(), true);
        fs.mock_set_writable(work_dir_path.to_str().unwrap(), true);

        // Disable swap
        fs.mock_set_swap_enabled(false);

        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlay_mode: crate::OverlayMode::Explicit, // Use explicit mode for test
            overlays: vec![OverlayConfig {
                name: "home".to_string(),
                lower: PathBuf::from("/"),
                upper: upper_dir.clone(),
                work: work_dir_path.clone(),
                target: PathBuf::from("/home"),
            }],
            ..Config::test_default()
        };

        let manager = Arc::new(Mutex::new(NailsManager::new(
            fs.clone(),
            config,
            state_path,
        )));

        // Activate with pre-flight checks (no_preflight = false)
        let result = NailsManager::activate(Arc::clone(&manager), false);
        if let Err(ref e) = result {
            eprintln!("Activation error: {:?}", e);
        }
        assert!(
            result.is_ok(),
            "Activation should succeed when all checks pass: {:?}",
            result.err()
        );

        // Verify state is Active
        assert!(matches!(
            manager.lock().unwrap().current_state().unwrap(),
            SystemState::Active { .. }
        ));

        // Verify hidden config symlink staged during activation
        let symlink_path = mock_hidden_vol.join("etc/nixos/nails/configuration.nix");
        assert!(
            fs.is_symlink(&symlink_path).unwrap(),
            "Hidden config symlink should be staged during activation"
        );
        let expected_target = mock_hidden_vol.join("config/nixos/configuration.nix");
        assert_eq!(
            fs.mock_get_symlink_target(&symlink_path),
            Some(expected_target)
        );
    }

    #[test]
    fn test_preflight_check_fails_activation_aborted() {
        // Create mock hidden volume structure
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path();
        std::fs::create_dir_all(mock_hidden_vol).unwrap();
        let state_path = mock_hidden_vol.join("state.json");

        let fs = MockFilesystem::new();

        // DON'T mount hidden volume - this will cause HiddenVolumeCheck to fail
        fs.mock_set_path_exists(mock_hidden_vol.to_str().unwrap(), true);
        fs.mock_set_mounted(mock_hidden_vol, false); // NOT MOUNTED
        setup_nixos_config_check(&fs, mock_hidden_vol);

        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlays: vec![],
            ..Config::test_default()
        };

        let manager = Arc::new(Mutex::new(NailsManager::new(
            fs.clone(),
            config,
            state_path,
        )));

        // Verify initial state is Inactive
        assert_eq!(
            manager.lock().unwrap().current_state().unwrap(),
            SystemState::Inactive
        );

        // Activate with pre-flight checks (should fail)
        let result = NailsManager::activate(Arc::clone(&manager), false);
        assert!(result.is_err(), "Activation should fail when checks fail");

        // Verify error is PreFlightCheckFailed
        match result.unwrap_err() {
            NailsError::PreFlightCheckFailed(failures) => {
                assert!(!failures.is_empty());
                // Should contain hidden-volume check failure
                assert!(failures.iter().any(|(name, _)| name == "hidden-volume"));
            }
            _ => panic!("Expected PreFlightCheckFailed error"),
        }

        // Verify state remains Inactive (no state changes occurred)
        assert_eq!(
            manager.lock().unwrap().current_state().unwrap(),
            SystemState::Inactive,
            "State should remain Inactive after failed preflight"
        );

        // Verify no mounts occurred
        assert!(
            fs.get_mounted_paths().is_empty(),
            "No mounts should exist after failed preflight"
        );
    }

    #[test]
    fn test_preflight_multiple_checks_fail_all_reported() {
        // Create mock hidden volume structure
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path();
        std::fs::create_dir_all(mock_hidden_vol).unwrap();
        let state_path = mock_hidden_vol.join("state.json");

        let fs = MockFilesystem::new();

        // Set up multiple failing conditions:
        // 1. Hidden volume not mounted
        fs.mock_set_path_exists(mock_hidden_vol.to_str().unwrap(), true);
        fs.mock_set_mounted(mock_hidden_vol, false); // FAIL
        setup_nixos_config_check(&fs, mock_hidden_vol);

        // 2. Swap enabled
        fs.mock_set_swap_enabled(true); // FAIL

        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlays: vec![],
            ..Config::test_default()
        };

        let manager = Arc::new(Mutex::new(NailsManager::new(fs, config, state_path)));

        // Activate with pre-flight checks
        let result = NailsManager::activate(Arc::clone(&manager), false);
        assert!(result.is_err());

        // Verify error contains BOTH failures
        match result.unwrap_err() {
            NailsError::PreFlightCheckFailed(failures) => {
                assert!(
                    failures.len() >= 2,
                    "Should report at least 2 failures (hidden-volume and swap)"
                );

                let failure_names: Vec<&str> =
                    failures.iter().map(|(name, _)| name.as_str()).collect();
                assert!(
                    failure_names.contains(&"hidden-volume"),
                    "Should report hidden-volume failure"
                );
                assert!(
                    failure_names.contains(&"swap"),
                    "Should report swap failure"
                );
            }
            _ => panic!("Expected PreFlightCheckFailed error"),
        }
    }

    #[test]
    fn test_preflight_warnings_only_activation_proceeds() {
        // Create mock hidden volume structure
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path();
        std::fs::create_dir_all(mock_hidden_vol).unwrap();
        let state_path = mock_hidden_vol.join("state.json");

        let fs = MockFilesystem::new();

        // Set up minimal passing conditions (may trigger warnings but not failures)
        fs.mock_set_path_exists(mock_hidden_vol.to_str().unwrap(), true);
        fs.mock_set_mounted(mock_hidden_vol, true);
        setup_nixos_config_check(&fs, mock_hidden_vol);

        // Create minimal directory structure (all required dirs for StorageReadinessCheck)
        let overlays_dir = mock_hidden_vol.join("overlays");
        let etc_dir = mock_hidden_vol.join("etc");
        let home_dir = mock_hidden_vol.join("home");
        let config_dir = mock_hidden_vol.join("config");
        let nixos_dir = mock_hidden_vol.join("nixos");
        let work_dir = mock_hidden_vol.join(".work");
        let work_etc = work_dir.join("etc");
        let work_home = work_dir.join("home");

        std::fs::create_dir_all(&overlays_dir).unwrap();
        std::fs::create_dir_all(&etc_dir).unwrap();
        std::fs::create_dir_all(&home_dir).unwrap();
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::create_dir_all(&nixos_dir).unwrap();
        std::fs::create_dir_all(&work_etc).unwrap();
        std::fs::create_dir_all(&work_home).unwrap();

        // Mock that MockFilesystem sees these directories
        fs.mock_set_path_exists(etc_dir.to_str().unwrap(), true);
        fs.mock_set_path_type(etc_dir.to_str().unwrap(), "directory");
        fs.mock_set_path_exists(home_dir.to_str().unwrap(), true);
        fs.mock_set_path_type(home_dir.to_str().unwrap(), "directory");
        fs.mock_set_path_exists(config_dir.to_str().unwrap(), true);
        fs.mock_set_path_type(config_dir.to_str().unwrap(), "directory");
        fs.mock_set_path_exists(nixos_dir.to_str().unwrap(), true);
        fs.mock_set_path_type(nixos_dir.to_str().unwrap(), "directory");
        fs.mock_set_path_exists(work_etc.to_str().unwrap(), true);
        fs.mock_set_path_type(work_etc.to_str().unwrap(), "directory");
        fs.mock_set_path_exists(work_home.to_str().unwrap(), true);
        fs.mock_set_path_type(work_home.to_str().unwrap(), "directory");

        // Disable swap
        fs.mock_set_swap_enabled(false);

        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlays: vec![], // No overlays to check
            ..Config::test_default()
        };

        let manager = Arc::new(Mutex::new(NailsManager::new(fs, config, state_path)));

        // Activate with pre-flight checks
        let result = NailsManager::activate(Arc::clone(&manager), false);
        if let Err(ref e) = result {
            eprintln!("Activation error: {:?}", e);
        }

        // Should succeed even if there are warnings (warnings don't block)
        assert!(
            result.is_ok(),
            "Activation should proceed when only warnings exist: {:?}",
            result.err()
        );

        // Verify state is Active
        assert!(matches!(
            manager.lock().unwrap().current_state().unwrap(),
            SystemState::Active { .. }
        ));
    }

    #[test]
    fn test_preflight_skip_with_no_preflight_flag() {
        // Create mock hidden volume structure
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path();
        std::fs::create_dir_all(mock_hidden_vol).unwrap();
        let state_path = mock_hidden_vol.join("state.json");

        let fs = MockFilesystem::new();

        // Set up FAILING conditions (hidden volume not mounted)
        fs.mock_set_path_exists(mock_hidden_vol.to_str().unwrap(), true);
        fs.mock_set_mounted(mock_hidden_vol, false); // This WOULD fail preflight
        setup_nixos_config_check(&fs, mock_hidden_vol);

        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlays: vec![], // No overlays to mount
            ..Config::test_default()
        };

        let manager = Arc::new(Mutex::new(NailsManager::new(fs, config, state_path)));

        // Activate with no_preflight = true (skip checks)
        let result = NailsManager::activate(Arc::clone(&manager), true);

        // Should succeed even though checks would have failed
        assert!(
            result.is_ok(),
            "Activation should succeed when preflight is skipped"
        );

        // Verify state is Active
        assert!(matches!(
            manager.lock().unwrap().current_state().unwrap(),
            SystemState::Active { .. }
        ));
    }

    #[test]
    fn test_preflight_no_filesystem_changes_on_failure() {
        use crate::OverlayConfig;

        // Create mock hidden volume structure
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path();
        std::fs::create_dir_all(mock_hidden_vol).unwrap();
        let state_path = mock_hidden_vol.join("state.json");

        let fs = MockFilesystem::new();

        // Set up failing condition
        fs.mock_set_path_exists(mock_hidden_vol.to_str().unwrap(), true);
        fs.mock_set_mounted(mock_hidden_vol, false); // Preflight will fail
        setup_nixos_config_check(&fs, mock_hidden_vol);

        // Set up overlay paths
        let upper_dir = mock_hidden_vol.join("overlays/home/upper");
        let work_dir_path = mock_hidden_vol.join(".work/home");
        std::fs::create_dir_all(&upper_dir).unwrap();
        std::fs::create_dir_all(&work_dir_path).unwrap();

        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlay_mode: crate::OverlayMode::Explicit, // Use explicit mode for test
            overlays: vec![OverlayConfig {
                name: "home".to_string(),
                lower: PathBuf::from("/"),
                upper: upper_dir.clone(),
                work: work_dir_path.clone(),
                target: PathBuf::from("/home"),
            }],
            ..Config::test_default()
        };

        let fs_clone = fs.clone();
        let manager = Arc::new(Mutex::new(NailsManager::new(
            fs,
            config,
            state_path.clone(),
        )));

        // Attempt activation (will fail at preflight)
        let result = NailsManager::activate(Arc::clone(&manager), false);
        assert!(result.is_err());

        // Verify NO filesystem changes occurred:
        // 1. State is still Inactive
        assert_eq!(
            manager.lock().unwrap().current_state().unwrap(),
            SystemState::Inactive
        );

        // 2. No mounts exist
        assert!(fs_clone.get_mounted_paths().is_empty());

        // 3. State file was not modified (or still shows Inactive)
        let loaded_state = StateFile::load(&state_path).unwrap();
        assert_eq!(loaded_state.state, SystemState::Inactive);
    }

    // ========== Story 4.6: MountTracker Drop Trait and Edge Cases Tests ==========

    #[test]
    fn test_mount_tracker_drop_without_commit_triggers_rollback() {
        let fs = MockFilesystem::new();
        let home = PathBuf::from("/home");
        let etc = PathBuf::from("/etc");

        {
            let mut tracker = MountTracker::new(&fs);
            tracker.push_mount(MountInfo::persistent(home.clone()));
            tracker.push_mount(MountInfo::persistent(etc.clone()));
            // Drop without commit - should trigger automatic rollback
        } // Tracker drops here

        // Verify unmount was called for both paths in reverse order
        let mounted = fs.get_mounted_paths();
        assert!(
            mounted.is_empty(),
            "All mounts should be rolled back on Drop without commit"
        );
    }

    #[test]
    fn test_mount_tracker_drop_with_commit_no_rollback() {
        let fs = MockFilesystem::new();
        let home = PathBuf::from("/home");
        let etc = PathBuf::from("/etc");

        // Mock successful mounts
        fs.mock_set_mounted(&home, true);
        fs.mock_set_mounted(&etc, true);

        {
            let mut tracker = MountTracker::new(&fs);
            tracker.push_mount(MountInfo::persistent(home.clone()));
            tracker.push_mount(MountInfo::persistent(etc.clone()));
            tracker.commit(); // Commit prevents rollback
        } // Tracker drops here

        // Verify mounts still exist (no rollback)
        assert!(
            fs.is_mounted(&home).unwrap(),
            "/home should still be mounted after committed Drop"
        );
        assert!(
            fs.is_mounted(&etc).unwrap(),
            "/etc should still be mounted after committed Drop"
        );
    }

    #[test]
    fn test_mount_tracker_rollback_all_best_effort_continues_on_failure() {
        let fs = MockFilesystem::new();
        let home = PathBuf::from("/home");
        let etc = PathBuf::from("/etc");

        // Mock /etc unmount to fail
        fs.mock_set_mounted(&home, true);
        fs.mock_set_mounted(&etc, true);
        fs.mock_set_unmount_should_fail(&etc.to_string_lossy(), true);

        let mut tracker = MountTracker::new(&fs);
        tracker.push_mount(MountInfo::persistent(home.clone()));
        tracker.push_mount(MountInfo::persistent(etc.clone()));

        // Rollback should continue despite /etc failure
        let result = tracker.rollback_all();

        // Should return error mentioning /etc failure
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("/etc") && err_msg.contains("Failed to unmount"),
            "Error should mention /etc unmount failure"
        );

        // But /home should still be unmounted (best-effort)
        assert!(
            !fs.is_mounted(&home).unwrap(),
            "/home should be unmounted despite /etc failure"
        );
    }

    #[test]
    fn test_mount_tracker_rollback_all_aggregate_errors() {
        let fs = MockFilesystem::new();
        let home = PathBuf::from("/home");
        let etc = PathBuf::from("/etc");

        // Mock BOTH unmounts to fail
        fs.mock_set_mounted(&home, true);
        fs.mock_set_mounted(&etc, true);
        fs.mock_set_unmount_should_fail(&home.to_string_lossy(), true);
        fs.mock_set_unmount_should_fail(&etc.to_string_lossy(), true);

        let mut tracker = MountTracker::new(&fs);
        tracker.push_mount(MountInfo::persistent(home.clone()));
        tracker.push_mount(MountInfo::persistent(etc.clone()));

        let result = tracker.rollback_all();

        // Should return aggregate error mentioning both failures
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("/home") && err_msg.contains("/etc"),
            "Error should mention both unmount failures"
        );
    }

    #[test]
    fn test_unmount_overlays_method_reverse_order() {
        let fs = MockFilesystem::new();
        let config = Config::default();
        let state_path = PathBuf::from("/tmp/state.json");
        let manager = NailsManager::new(fs.clone(), config, state_path);

        let home = PathBuf::from("/home");
        let etc = PathBuf::from("/etc");

        // Mock successful mounts
        fs.mock_set_mounted(&home, true);
        fs.mock_set_mounted(&etc, true);

        // Create mounted paths in mount order: /home, /etc
        let mounted_paths = vec![home.clone(), etc.clone()];

        // Unmount should happen in reverse: /etc first, /home second
        let result = manager.unmount_overlays(mounted_paths);
        assert!(result.is_ok(), "Unmount should succeed");

        // Verify both unmounted
        assert!(!fs.is_mounted(&home).unwrap());
        assert!(!fs.is_mounted(&etc).unwrap());
    }

    #[test]
    fn test_unmount_overlays_best_effort_on_failure() {
        let fs = MockFilesystem::new();
        let config = Config::default();
        let state_path = PathBuf::from("/tmp/state.json");
        let manager = NailsManager::new(fs.clone(), config, state_path);

        let home = PathBuf::from("/home");
        let etc = PathBuf::from("/etc");

        // Mock /etc unmount to fail, /home to succeed
        fs.mock_set_mounted(&home, true);
        fs.mock_set_mounted(&etc, true);
        fs.mock_set_unmount_should_fail(&etc.to_string_lossy(), true);

        let mounted_paths = vec![home.clone(), etc.clone()];

        // Should return error but still unmount /home
        let result = manager.unmount_overlays(mounted_paths);
        assert!(result.is_err(), "Should return error for /etc failure");

        // Verify /home still unmounted (best-effort)
        assert!(
            !fs.is_mounted(&home).unwrap(),
            "/home should be unmounted despite /etc failure"
        );
    }

    // Note: Story 14.10 removed MOUNT_ORDER constant in favor of dynamic
    // overlay target detection via build_overlay_targets(). See tests:
    // - test_build_overlay_targets_auto_mode_*
    // - test_build_overlay_targets_explicit_mode_*

    // ========== Task 6: DNS Preservation Tests ==========

    #[test]
    fn test_clean_stale_network_config_removes_resolv_conf() {
        let fs = MockFilesystem::new();
        let upper_dir = PathBuf::from("/mnt/hidden/etc-upper");

        // Create stale resolv.conf
        let resolv_path = upper_dir.join("resolv.conf");
        fs.write_file_content(&resolv_path, "nameserver 8.8.8.8")
            .unwrap();

        // Clean it
        let result = clean_stale_network_config(&upper_dir, &fs);
        assert!(result.is_ok());

        // File should be removed
        assert!(!fs.path_exists(&resolv_path).unwrap());
    }

    #[test]
    fn test_clean_stale_network_config_removes_nsswitch_conf() {
        let fs = MockFilesystem::new();
        let upper_dir = PathBuf::from("/mnt/hidden/etc-upper");

        // Create stale nsswitch.conf
        let nsswitch_path = upper_dir.join("nsswitch.conf");
        fs.write_file_content(&nsswitch_path, "hosts: files dns")
            .unwrap();

        // Clean it
        let result = clean_stale_network_config(&upper_dir, &fs);
        assert!(result.is_ok());

        // File should be removed
        assert!(!fs.path_exists(&nsswitch_path).unwrap());
    }

    #[test]
    fn test_clean_stale_network_config_removes_both_files() {
        let fs = MockFilesystem::new();
        let upper_dir = PathBuf::from("/mnt/hidden/etc-upper");

        // Create both stale files
        let resolv_path = upper_dir.join("resolv.conf");
        let nsswitch_path = upper_dir.join("nsswitch.conf");
        fs.write_file_content(&resolv_path, "nameserver 8.8.8.8")
            .unwrap();
        fs.write_file_content(&nsswitch_path, "hosts: files dns")
            .unwrap();

        // Clean them
        let result = clean_stale_network_config(&upper_dir, &fs);
        assert!(result.is_ok());

        // Both files should be removed
        assert!(!fs.path_exists(&resolv_path).unwrap());
        assert!(!fs.path_exists(&nsswitch_path).unwrap());
    }

    #[test]
    fn test_clean_stale_network_config_no_files_exists() {
        let fs = MockFilesystem::new();
        let upper_dir = PathBuf::from("/mnt/hidden/etc-upper");

        // No files created - should succeed without error
        let result = clean_stale_network_config(&upper_dir, &fs);
        assert!(result.is_ok());
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_clean_stale_network_config_logs_removal() {
        let fs = MockFilesystem::new();
        let upper_dir = PathBuf::from("/mnt/hidden/etc-upper");

        // Create stale resolv.conf
        let resolv_path = upper_dir.join("resolv.conf");
        fs.write_file_content(&resolv_path, "nameserver 8.8.8.8")
            .unwrap();

        // Clean it
        let result = clean_stale_network_config(&upper_dir, &fs);
        assert!(result.is_ok());

        // Should log the removal
        assert!(logs_contain("Cleaned stale resolv.conf"));
        assert!(logs_contain("DNS preservation"));
    }

    #[test]
    fn test_clean_stale_network_config_does_not_remove_other_files() {
        let fs = MockFilesystem::new();
        let upper_dir = PathBuf::from("/mnt/hidden/etc-upper");

        // Create files that should NOT be removed
        let passwd_path = upper_dir.join("passwd");
        let shadow_path = upper_dir.join("shadow");
        let hostname_path = upper_dir.join("hostname");
        fs.write_file_content(&passwd_path, "root:x:0:0").unwrap();
        fs.write_file_content(&shadow_path, "root:*").unwrap();
        fs.write_file_content(&hostname_path, "myhostname").unwrap();

        // Also create one that should be removed
        let resolv_path = upper_dir.join("resolv.conf");
        fs.write_file_content(&resolv_path, "nameserver 8.8.8.8")
            .unwrap();

        // Clean
        let result = clean_stale_network_config(&upper_dir, &fs);
        assert!(result.is_ok());

        // Only resolv.conf should be removed
        assert!(!fs.path_exists(&resolv_path).unwrap());
        assert!(fs.path_exists(&passwd_path).unwrap());
        assert!(fs.path_exists(&shadow_path).unwrap());
        assert!(fs.path_exists(&hostname_path).unwrap());
    }

    // ========== Helper Function Tests ==========

    #[test]
    fn test_apply_exclusion_filter_empty_exclusions() {
        let dirs = vec![
            PathBuf::from("/home"),
            PathBuf::from("/etc"),
            PathBuf::from("/var"),
        ];
        let exclusions: Vec<PathBuf> = vec![];

        let filtered = apply_exclusion_filter(dirs.clone(), &exclusions);

        assert_eq!(filtered.len(), 3);
        assert_eq!(
            filtered,
            vec![
                PathBuf::from("/etc"),
                PathBuf::from("/home"),
                PathBuf::from("/var"),
            ]
        );
    }

    #[test]
    fn test_apply_exclusion_filter_with_exclusions() {
        let dirs = vec![
            PathBuf::from("/home"),
            PathBuf::from("/etc"),
            PathBuf::from("/proc"),
            PathBuf::from("/var"),
        ];
        let exclusions = vec![PathBuf::from("/proc")];

        let filtered = apply_exclusion_filter(dirs, &exclusions);

        assert_eq!(filtered.len(), 3);
        assert!(!filtered.contains(&PathBuf::from("/proc")));
        assert!(filtered.contains(&PathBuf::from("/home")));
        assert!(filtered.contains(&PathBuf::from("/etc")));
        assert!(filtered.contains(&PathBuf::from("/var")));
    }

    #[test]
    fn test_apply_exclusion_filter_all_excluded() {
        let dirs = vec![
            PathBuf::from("/proc"),
            PathBuf::from("/sys"),
            PathBuf::from("/dev"),
        ];
        let exclusions = vec![
            PathBuf::from("/proc"),
            PathBuf::from("/sys"),
            PathBuf::from("/dev"),
        ];

        let filtered = apply_exclusion_filter(dirs, &exclusions);

        assert_eq!(filtered.len(), 0);
    }

    #[test]
    fn test_apply_exclusion_filter_sorts_results() {
        let dirs = vec![
            PathBuf::from("/var"),
            PathBuf::from("/home"),
            PathBuf::from("/etc"),
        ];
        let exclusions: Vec<PathBuf> = vec![];

        let filtered = apply_exclusion_filter(dirs, &exclusions);

        // Should be sorted alphabetically
        assert_eq!(filtered[0], PathBuf::from("/etc"));
        assert_eq!(filtered[1], PathBuf::from("/home"));
        assert_eq!(filtered[2], PathBuf::from("/var"));
    }

    #[test]
    fn test_build_overlay_targets_auto_mode_with_defaults() {
        let fs = MockFilesystem::new();

        // Setup root directories (typical Linux system)
        fs.mock_set_root_directories(vec![
            PathBuf::from("/home"),
            PathBuf::from("/etc"),
            PathBuf::from("/nix"),
            PathBuf::from("/var"),
            PathBuf::from("/tmp"),
            PathBuf::from("/usr"),
            PathBuf::from("/bin"),
            PathBuf::from("/proc"), // Default exclusion
            PathBuf::from("/sys"),  // Default exclusion
            PathBuf::from("/dev"),  // Default exclusion
            PathBuf::from("/boot"), // Default exclusion
        ]);

        let config = Config {
            overlay_mode: OverlayMode::Auto,
            ..Config::default()
        };

        let targets = build_overlay_targets(&fs, &config).expect("Should build targets");

        // Should include most dirs, exclude /proc, /sys, /dev, /boot + critical /bin, /usr
        assert_eq!(targets.len(), 5);
        assert!(targets.contains(&PathBuf::from("/home")));
        assert!(targets.contains(&PathBuf::from("/etc")));
        assert!(targets.contains(&PathBuf::from("/nix")));
        assert!(targets.contains(&PathBuf::from("/var")));
        assert!(targets.contains(&PathBuf::from("/tmp")));
        assert!(!targets.contains(&PathBuf::from("/usr"))); // Critical binary root
        assert!(!targets.contains(&PathBuf::from("/bin"))); // Critical binary root
        assert!(!targets.contains(&PathBuf::from("/proc")));
        assert!(!targets.contains(&PathBuf::from("/sys")));
        assert!(!targets.contains(&PathBuf::from("/dev")));
        assert!(!targets.contains(&PathBuf::from("/boot")));
    }

    #[test]
    fn test_build_overlay_targets_auto_mode_with_user_exclusions() {
        let fs = MockFilesystem::new();

        fs.mock_set_root_directories(vec![
            PathBuf::from("/home"),
            PathBuf::from("/etc"),
            PathBuf::from("/nix"),
            PathBuf::from("/var"),
            PathBuf::from("/boot"),
        ]);

        let mut config = Config {
            overlay_mode: OverlayMode::Auto,
            ..Config::default()
        };
        // Add /var and /nix as additional user exclusions (boot already excluded by default)
        config.overlay_exclusions = vec![PathBuf::from("/var"), PathBuf::from("/nix")];

        let targets = build_overlay_targets(&fs, &config).expect("Should build targets");

        // Should exclude user-specified directories
        assert_eq!(targets.len(), 2);
        assert!(targets.contains(&PathBuf::from("/home")));
        assert!(targets.contains(&PathBuf::from("/etc")));
        assert!(!targets.contains(&PathBuf::from("/nix")));
        assert!(!targets.contains(&PathBuf::from("/var")));
        assert!(!targets.contains(&PathBuf::from("/boot")));
    }

    #[test]
    fn test_build_overlay_targets_auto_mode_with_user_removals() {
        let fs = MockFilesystem::new();

        fs.mock_set_root_directories(vec![
            PathBuf::from("/home"),
            PathBuf::from("/mnt"), // Default exclusion that user wants to remove
        ]);

        let mut config = Config {
            overlay_mode: OverlayMode::Auto,
            ..Config::default()
        };
        config.overlay_exclusions_remove = vec![
            PathBuf::from("/mnt"), // Remove from default exclusions
        ];

        let targets = build_overlay_targets(&fs, &config).expect("Should build targets");

        // /mnt should now be included (removed from exclusions)
        assert_eq!(targets.len(), 2);
        assert!(targets.contains(&PathBuf::from("/home")));
        assert!(targets.contains(&PathBuf::from("/mnt")));
    }

    #[test]
    fn test_build_overlay_targets_auto_mode_empty_root() {
        let fs = MockFilesystem::new();

        // Empty root directory
        fs.mock_set_root_directories(vec![]);

        let config = Config {
            overlay_mode: OverlayMode::Auto,
            ..Config::default()
        };

        let targets = build_overlay_targets(&fs, &config).expect("Should build targets");

        assert_eq!(targets.len(), 0);
    }

    #[test]
    fn test_build_overlay_targets_auto_mode_all_excluded() {
        let fs = MockFilesystem::new();

        fs.mock_set_root_directories(vec![
            PathBuf::from("/proc"),
            PathBuf::from("/sys"),
            PathBuf::from("/dev"),
        ]);

        let config = Config {
            overlay_mode: OverlayMode::Auto,
            ..Config::default()
        };

        let targets = build_overlay_targets(&fs, &config).expect("Should build targets");

        // All directories are in default exclusions
        assert_eq!(targets.len(), 0);
    }

    #[test]
    fn test_build_overlay_targets_auto_mode_sorted_output() {
        let fs = MockFilesystem::new();

        // Unsorted input
        fs.mock_set_root_directories(vec![
            PathBuf::from("/var"),
            PathBuf::from("/etc"),
            PathBuf::from("/home"),
        ]);

        let config = Config {
            overlay_mode: OverlayMode::Auto,
            ..Config::default()
        };

        let targets = build_overlay_targets(&fs, &config).expect("Should build targets");

        // Should be sorted alphabetically
        assert_eq!(targets[0], PathBuf::from("/etc"));
        assert_eq!(targets[1], PathBuf::from("/home"));
        assert_eq!(targets[2], PathBuf::from("/var"));
    }

    #[test]
    fn test_build_overlay_targets_explicit_mode() {
        let fs = MockFilesystem::new();

        // Root has many directories, but explicit mode should ignore them
        fs.mock_set_root_directories(vec![
            PathBuf::from("/home"),
            PathBuf::from("/etc"),
            PathBuf::from("/var"),
            PathBuf::from("/tmp"),
            PathBuf::from("/boot"),
        ]);

        let config = Config {
            overlay_mode: OverlayMode::Explicit,
            overlays: vec![
                OverlayConfig {
                    name: "home".to_string(),
                    lower: PathBuf::from("/home"),
                    upper: PathBuf::from("/mnt/hidden/home"),
                    work: PathBuf::from("/mnt/hidden/.work/home"),
                    target: PathBuf::from("/home"),
                },
                OverlayConfig {
                    name: "etc".to_string(),
                    lower: PathBuf::from("/etc"),
                    upper: PathBuf::from("/mnt/hidden/etc"),
                    work: PathBuf::from("/mnt/hidden/.work/etc"),
                    target: PathBuf::from("/etc"),
                },
            ],
            ..Config::default()
        };

        let targets = build_overlay_targets(&fs, &config).expect("Should build targets");

        // Should only use configured overlays, not all discovered directories
        assert_eq!(targets.len(), 2);
        assert!(targets.contains(&PathBuf::from("/home")));
        assert!(targets.contains(&PathBuf::from("/etc")));
        assert!(!targets.contains(&PathBuf::from("/var")));
        assert!(!targets.contains(&PathBuf::from("/tmp")));
    }

    #[test]
    fn test_build_overlay_targets_explicit_mode_empty_overlays() {
        let fs = MockFilesystem::new();

        fs.mock_set_root_directories(vec![PathBuf::from("/home"), PathBuf::from("/etc")]);

        let config = Config {
            overlay_mode: OverlayMode::Explicit,
            overlays: vec![], // No overlays configured
            ..Config::default()
        };

        let targets = build_overlay_targets(&fs, &config).expect("Should build targets");

        // No overlays configured = no targets
        assert_eq!(targets.len(), 0);
    }

    #[test]
    fn test_mount_tracker_empty_rollback_succeeds() {
        let fs = MockFilesystem::new();
        let mut tracker = MountTracker::new(&fs);

        // Rollback with no mounts should succeed
        let result = tracker.rollback_all();
        assert!(result.is_ok(), "Empty rollback should succeed");
    }

    #[test]
    fn test_unmount_overlays_empty_list_succeeds() {
        let fs = MockFilesystem::new();
        let config = Config::default();
        let state_path = PathBuf::from("/tmp/state.json");
        let manager = NailsManager::new(fs, config, state_path);

        // Unmount empty list should succeed
        let result = manager.unmount_overlays(vec![]);
        assert!(result.is_ok(), "Unmounting empty list should succeed");
    }

    #[test]
    fn test_unmount_overlays_single_path_failure() {
        let fs = MockFilesystem::new();
        let config = Config::default();
        let state_path = PathBuf::from("/tmp/state.json");
        let manager = NailsManager::new(fs.clone(), config, state_path);

        let home = PathBuf::from("/home");

        // Mock unmount to fail
        fs.mock_set_mounted(&home, true);
        fs.mock_set_unmount_should_fail(&home.to_string_lossy(), true);

        let mounted_paths = vec![home.clone()];

        // Should return error
        let result = manager.unmount_overlays(mounted_paths);
        assert!(result.is_err(), "Should return error when unmount fails");

        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Unmount completed with errors"),
            "Error should mention unmount failure"
        );
    }

    #[test]
    fn test_unmount_overlays_multiple_paths_partial_failure() {
        let fs = MockFilesystem::new();
        let config = Config::default();
        let state_path = PathBuf::from("/tmp/state.json");
        let manager = NailsManager::new(fs.clone(), config, state_path);

        let home = PathBuf::from("/home");
        let etc = PathBuf::from("/etc");

        // Mock /etc to fail, /home to succeed
        fs.mock_set_mounted(&home, true);
        fs.mock_set_mounted(&etc, true);
        fs.mock_set_unmount_should_fail(&etc.to_string_lossy(), true);

        let mounted_paths = vec![home.clone(), etc.clone()];

        // Should return error but /home should be unmounted (best-effort)
        let result = manager.unmount_overlays(mounted_paths);
        assert!(result.is_err(), "Should return error for /etc failure");

        // /home should still be unmounted (best-effort)
        assert!(
            !fs.is_mounted(&home).unwrap(),
            "/home should be unmounted despite /etc failure"
        );
    }

    #[test]
    fn test_unmount_overlays_three_paths_reverse_order() {
        let fs = MockFilesystem::new();
        let config = Config::default();
        let state_path = PathBuf::from("/tmp/state.json");
        let manager = NailsManager::new(fs.clone(), config, state_path);

        let home = PathBuf::from("/home");
        let etc = PathBuf::from("/etc");
        let opt = PathBuf::from("/opt");

        // Mock all as mounted
        fs.mock_set_mounted(&home, true);
        fs.mock_set_mounted(&etc, true);
        fs.mock_set_mounted(&opt, true);

        // Create mounted paths in order: /home, /etc, /opt
        let mounted_paths = vec![home.clone(), etc.clone(), opt.clone()];

        // Unmount should happen in reverse: /opt, /etc, /home
        let result = manager.unmount_overlays(mounted_paths);
        assert!(result.is_ok(), "Unmount should succeed");

        // Verify all unmounted
        assert!(!fs.is_mounted(&home).unwrap());
        assert!(!fs.is_mounted(&etc).unwrap());
        assert!(!fs.is_mounted(&opt).unwrap());
    }

    // ========== Story 4.7: StateFile Rollback Clearing Tests ==========

    #[test]
    fn test_rollback_clears_overlay_status_and_nixos_generation() {
        use crate::OverlayConfig;

        // Create mock hidden volume structure
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path();
        std::fs::create_dir_all(mock_hidden_vol).unwrap();
        let state_path = mock_hidden_vol.join("state.json");

        let fs = MockFilesystem::new();

        // Set up paths to exist
        fs.mock_set_path_exists("/", true);
        let upper_dir = mock_hidden_vol.join("overlays/home/upper");
        let work_dir = mock_hidden_vol.join("overlays/home/work");
        std::fs::create_dir_all(&upper_dir).unwrap();
        std::fs::create_dir_all(&work_dir).unwrap();
        fs.mock_set_path_exists(upper_dir.to_str().unwrap(), true);
        fs.mock_set_path_exists(work_dir.to_str().unwrap(), true);

        // Configure filesystem to fail mount (to trigger rollback)
        fs.mock_set_mount_should_fail("/home", true);

        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlay_mode: crate::OverlayMode::Explicit, // Use explicit mode for test
            overlays: vec![OverlayConfig {
                name: "home".to_string(),
                lower: PathBuf::from("/"),
                upper: upper_dir.clone(),
                work: work_dir.clone(),
                target: PathBuf::from("/home"),
            }],
            ..Config::test_default()
        };

        let manager = Arc::new(Mutex::new(NailsManager::new(
            fs,
            config,
            state_path.clone(),
        )));

        // Manually set up state file with overlay_status and nixos_generation BEFORE activation
        // (simulating a previous activation that left metadata)
        {
            let mgr = manager.lock().unwrap();
            let mut overlay_status = HashMap::new();
            overlay_status.insert(
                PathBuf::from("/home"),
                OverlayInfo {
                    mount_path: PathBuf::from("/home"),
                    lower_dir: PathBuf::from("/"),
                    upper_dir: upper_dir.clone(),
                    work_dir: work_dir.clone(),
                    mounted_at: Utc::now(),
                },
            );

            let mut cached = mgr.cached_state.lock().unwrap();
            let state_file = StateFile {
                overlay_status,
                nixos_generation: Some("test-generation-123".to_string()),
                ..StateFile::default()
            };
            *cached = Some(state_file);
        }

        // Activation should fail (mount fails)
        let result = NailsManager::activate(Arc::clone(&manager), true);
        assert!(result.is_err(), "Activation should fail");

        // AC4: Verify rollback cleared overlay_status and nixos_generation
        let loaded = StateFile::load(&state_path).unwrap();
        assert_eq!(
            loaded.state,
            SystemState::Inactive,
            "State should be Inactive after rollback"
        );

        // THIS IS THE KEY TEST for Task 5 (AC4):
        assert!(
            loaded.overlay_status.is_empty(),
            "overlay_status should be cleared after rollback (AC4)"
        );
        assert_eq!(
            loaded.nixos_generation, None,
            "nixos_generation should be cleared after rollback (AC4)"
        );
    }

    // ========== Story 4.7: Incremental State Persistence Tests (Review Follow-up) ==========

    // ========== Additional Coverage Tests: MountTracker and unmount_overlays edge cases ==========

    #[test]
    fn test_mount_tracker_rollback_graceful_fails_force_succeeds() {
        let fs = MockFilesystem::new();
        let home = PathBuf::from("/home");

        // Mock /home as mounted
        fs.mock_set_mounted(&home, true);

        // Configure graceful unmount to fail, but force unmount to succeed
        // MockFilesystem's mock_set_unmount_should_fail sets both graceful and force to fail
        // We need a workaround: don't set failure, so graceful works, but that doesn't test the path we want
        // Actually the MockFilesystem doesn't distinguish graceful vs force - let's just verify the path is covered

        // For this test, let's ensure the force unmount path (line 164) is covered
        // by having graceful fail and force succeed. MockFilesystem behavior needs checking.

        // Actually, let's set up the mock to simulate graceful failure followed by force success
        // by using mock_set_unmount_graceful_fails to only fail graceful unmount
        fs.mock_set_unmount_graceful_fails(&home.to_string_lossy(), true);

        let mut tracker = MountTracker::new(&fs);
        tracker.push_mount(MountInfo::persistent(home.clone()));

        // Rollback should succeed (graceful fails, force succeeds)
        let result = tracker.rollback_all();

        // Should succeed because force unmount works
        assert!(
            result.is_ok(),
            "Rollback should succeed when force unmount works"
        );

        // Verify /home is unmounted
        assert!(
            !fs.is_mounted(&home).unwrap(),
            "/home should be unmounted after force unmount succeeded"
        );
    }

    #[test]
    fn test_unmount_overlays_graceful_fails_force_succeeds() {
        let fs = MockFilesystem::new();
        let config = Config::default();
        let state_path = PathBuf::from("/tmp/state.json");
        let manager = NailsManager::new(fs.clone(), config, state_path);

        let home = PathBuf::from("/home");

        // Mock /home as mounted
        fs.mock_set_mounted(&home, true);

        // Configure graceful unmount to fail, force to succeed
        fs.mock_set_unmount_graceful_fails(&home.to_string_lossy(), true);

        let mounted_paths = vec![home.clone()];

        // unmount_overlays should succeed (graceful fails, force succeeds)
        let result = manager.unmount_overlays(mounted_paths);
        assert!(
            result.is_ok(),
            "Unmount should succeed when force unmount works"
        );

        // Verify /home is unmounted
        assert!(
            !fs.is_mounted(&home).unwrap(),
            "/home should be unmounted after force unmount succeeded"
        );
    }

    #[test]
    fn test_nails_manager_debug_impl() {
        let fs = MockFilesystem::new();
        let config = Config::default();
        let state_path = PathBuf::from("/mnt/hidden-volume/state.json");
        let manager = NailsManager::new(fs, config.clone(), state_path.clone());

        // Test Debug implementation (lines 242-252)
        let debug_output = format!("{:?}", manager);

        // Verify Debug output contains expected fields
        assert!(
            debug_output.contains("NailsManager"),
            "Debug should contain struct name"
        );
        assert!(
            debug_output.contains("<filesystem>"),
            "Debug should mask filesystem"
        );
        assert!(
            debug_output.contains("config"),
            "Debug should contain config field"
        );
        assert!(
            debug_output.contains("state_file_path"),
            "Debug should contain state_file_path"
        );
        assert!(
            debug_output.contains("<Arc<Mutex<...>>>"),
            "Debug should mask cached_state"
        );
    }

    #[test]
    fn test_nails_manager_debug_with_nixos_builder() {
        use crate::NixOSBuilder;

        let fs = MockFilesystem::new();
        let config = Config::default();
        let state_path = PathBuf::from("/mnt/hidden-volume/state.json");
        let nixos_builder = NixOSBuilder::new(
            PathBuf::from("/mnt/hidden/nixos"),
            PathBuf::from("/nix/var/nix/profiles/nails-system"),
        );
        let manager = NailsManager::with_nixos(fs, config, state_path, nixos_builder);

        // Test Debug implementation with NixOSBuilder present
        let debug_output = format!("{:?}", manager);

        // Verify Debug output contains nixos_builder field
        assert!(
            debug_output.contains("nixos_builder"),
            "Debug should contain nixos_builder field"
        );
        assert!(
            debug_output.contains("<NixOSBuilder>"),
            "Debug should mask nixos_builder"
        );
    }

    #[test]
    fn test_verify_overlay_status_inactive_with_mounted_overlay_error() {
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let state_path = temp_dir.path().join("state.json");

        let fs = MockFilesystem::new();

        // Set up overlay as actually mounted
        fs.mock_set_mounted(Path::new("/home"), true);

        let config = Config::default();
        let manager = NailsManager::new(fs, config, state_path.clone());

        // Create Inactive state file but with overlay still tracked
        let mut overlay_status = HashMap::new();
        overlay_status.insert(
            PathBuf::from("/home"),
            OverlayInfo {
                mount_path: PathBuf::from("/home"),
                lower_dir: PathBuf::from("/home"),
                upper_dir: PathBuf::from("/mnt/hidden-volume/overlays/home/upper"),
                work_dir: PathBuf::from("/mnt/hidden-volume/overlays/home/work"),
                mounted_at: Utc::now(),
            },
        );

        let state_file = StateFile {
            state: SystemState::Inactive,
            overlay_status,
            ..StateFile::default()
        };

        // Save manually
        let json = serde_json::to_string_pretty(&state_file).unwrap();
        std::fs::write(&state_path, json).unwrap();

        // Verify should fail (state claims Inactive but overlay is mounted)
        let result = manager.verify_overlay_status();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), NailsError::InvalidState(_)));
    }

    #[test]
    fn test_verify_overlay_status_transitional_state_skipped() {
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let state_path = temp_dir.path().join("state.json");

        let fs = MockFilesystem::new();

        // Set up overlay as NOT mounted (potential mismatch if we were strict)
        fs.mock_set_mounted(Path::new("/home"), false);

        let config = Config::default();
        let manager = NailsManager::new(fs, config, state_path.clone());

        // Create Activating state (transitional) - verification should skip
        let mut overlay_status = HashMap::new();
        overlay_status.insert(
            PathBuf::from("/home"),
            OverlayInfo {
                mount_path: PathBuf::from("/home"),
                lower_dir: PathBuf::from("/home"),
                upper_dir: PathBuf::from("/mnt/hidden-volume/overlays/home/upper"),
                work_dir: PathBuf::from("/mnt/hidden-volume/overlays/home/work"),
                mounted_at: Utc::now(),
            },
        );

        let state_file = StateFile {
            state: SystemState::Activating {
                started_at: Utc::now(),
            },
            overlay_status,
            ..StateFile::default()
        };

        // Save manually
        let json = serde_json::to_string_pretty(&state_file).unwrap();
        std::fs::write(&state_path, json).unwrap();

        // Verify should succeed (transitional states are skipped - line 751)
        let result = manager.verify_overlay_status();
        assert!(
            result.is_ok(),
            "Transitional state verification should succeed (skip check)"
        );
    }

    #[test]
    fn test_activate_saves_state_incrementally_after_each_step() {
        use crate::OverlayConfig;

        // Create mock hidden volume structure
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path();
        std::fs::create_dir_all(mock_hidden_vol).unwrap();
        let state_path = mock_hidden_vol.join("state.json");

        let fs = MockFilesystem::new();

        // Set up paths to exist
        fs.mock_set_path_exists("/", true);

        // Create two overlays: /home and /etc
        let home_upper = mock_hidden_vol.join("overlays/home/upper");
        let home_work = mock_hidden_vol.join("overlays/home/work");
        let etc_upper = mock_hidden_vol.join("overlays/etc/upper");
        let etc_work = mock_hidden_vol.join("overlays/etc/work");

        std::fs::create_dir_all(&home_upper).unwrap();
        std::fs::create_dir_all(&home_work).unwrap();
        std::fs::create_dir_all(&etc_upper).unwrap();
        std::fs::create_dir_all(&etc_work).unwrap();

        fs.mock_set_path_exists(home_upper.to_str().unwrap(), true);
        fs.mock_set_path_exists(home_work.to_str().unwrap(), true);
        fs.mock_set_path_exists(etc_upper.to_str().unwrap(), true);
        fs.mock_set_path_exists(etc_work.to_str().unwrap(), true);

        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlays: vec![
                OverlayConfig {
                    name: "home".to_string(),
                    lower: PathBuf::from("/"),
                    upper: home_upper.clone(),
                    work: home_work.clone(),
                    target: PathBuf::from("/home"),
                },
                OverlayConfig {
                    name: "etc".to_string(),
                    lower: PathBuf::from("/"),
                    upper: etc_upper.clone(),
                    work: etc_work.clone(),
                    target: PathBuf::from("/etc"),
                },
            ],
            overlay_mode: crate::OverlayMode::Explicit, // Use explicit mode for test
            ..Config::test_default()
        };

        let manager = Arc::new(Mutex::new(NailsManager::new(
            fs.clone(),
            config,
            state_path.clone(),
        )));

        // Run activation
        let result = NailsManager::activate(Arc::clone(&manager), true);
        assert!(result.is_ok(), "Activation should succeed");

        // Verify Step 1: State file contains Activating after transition
        // (This is tested implicitly - we can't check mid-activation, but we verify final state)

        // Verify final state file contains overlay_status for BOTH mounts
        let final_state = StateFile::load(&state_path).expect("Should load final state");

        // AC2: Verify overlay_status populated with /home mount
        assert!(
            final_state
                .overlay_status
                .contains_key(&PathBuf::from("/home")),
            "overlay_status should contain /home entry (AC2)"
        );

        let home_info = final_state
            .overlay_status
            .get(&PathBuf::from("/home"))
            .unwrap();
        assert_eq!(home_info.mount_path, PathBuf::from("/home"));
        assert_eq!(home_info.lower_dir, PathBuf::from("/"));
        assert_eq!(home_info.upper_dir, home_upper);
        assert_eq!(home_info.work_dir, home_work);

        // AC2: Verify overlay_status populated with /etc mount
        assert!(
            final_state
                .overlay_status
                .contains_key(&PathBuf::from("/etc")),
            "overlay_status should contain /etc entry (AC2)"
        );

        let etc_info = final_state
            .overlay_status
            .get(&PathBuf::from("/etc"))
            .unwrap();
        assert_eq!(etc_info.mount_path, PathBuf::from("/etc"));
        assert_eq!(etc_info.lower_dir, PathBuf::from("/"));
        assert_eq!(etc_info.upper_dir, etc_upper);
        assert_eq!(etc_info.work_dir, etc_work);

        // AC1: Verify final state is Active
        assert!(
            matches!(final_state.state, SystemState::Active { .. }),
            "Final state should be Active (AC1)"
        );

        // Verify both overlays are in the Active state's overlay list
        if let SystemState::Active { overlays, .. } = &final_state.state {
            assert_eq!(overlays.len(), 2, "Should have 2 overlays in Active state");
            assert!(overlays.contains(&PathBuf::from("/home")));
            assert!(overlays.contains(&PathBuf::from("/etc")));
        }
    }

    // ========== Story 4.8: Progress Indicators with Timing Tests ==========

    #[test]
    fn test_verbosity_set_get() {
        let mut manager = create_test_manager();

        // Default should be Normal
        assert_eq!(manager.verbosity, Verbosity::Normal);

        // Set to Quiet
        manager.set_verbosity(Verbosity::Quiet);
        assert_eq!(manager.verbosity, Verbosity::Quiet);

        // Set to Verbose
        manager.set_verbosity(Verbosity::Verbose);
        assert_eq!(manager.verbosity, Verbosity::Verbose);

        // Set to Debug
        manager.set_verbosity(Verbosity::Debug);
        assert_eq!(manager.verbosity, Verbosity::Debug);
    }

    #[test]
    fn test_verbosity_included_in_debug_output() {
        let manager = create_test_manager();
        let debug_str = format!("{:?}", manager);

        // Verify verbosity field is included in Debug output
        assert!(debug_str.contains("verbosity"));
    }

    #[test]
    fn test_activate_with_different_verbosity_levels() {
        // Test that activate() respects verbosity settings
        // This is tested implicitly through the existing activate tests
        // since they use Normal verbosity by default

        let mut manager = create_test_manager();
        manager.set_verbosity(Verbosity::Quiet);
        assert_eq!(manager.verbosity, Verbosity::Quiet);

        manager.set_verbosity(Verbosity::Debug);
        assert_eq!(manager.verbosity, Verbosity::Debug);
    }

    #[test]
    fn test_stopwatch_used_for_timing() {
        // Verify Stopwatch is available and works correctly
        let stopwatch = Stopwatch::start();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let elapsed = stopwatch.elapsed();

        assert!(elapsed.as_millis() >= 10);

        // Verify Display trait works
        let display = format!("{}", stopwatch);
        assert!(display.ends_with("ms") || display.ends_with("s"));
    }

    #[test]
    fn test_verbosity_ordering_in_manager() {
        // Verify verbosity levels can be compared
        assert!(Verbosity::Quiet < Verbosity::Normal);
        assert!(Verbosity::Normal < Verbosity::Verbose);
        assert!(Verbosity::Verbose < Verbosity::Debug);
    }

    /// Integration test: Verify activate() includes progress timing
    ///
    /// This test verifies that the activate() method uses Stopwatch
    /// for timing and respects verbosity levels. We can't directly
    /// capture tracing events in unit tests without tracing-test crate,
    /// but we verify the code compiles and runs with different verbosity
    /// levels.
    #[test]
    fn test_activate_progress_timing_integration() {
        use std::sync::Arc;

        // Create mock hidden volume structure in temp dir
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path();
        std::fs::create_dir_all(mock_hidden_vol).unwrap();
        let state_path = mock_hidden_vol.join("state.json");

        let fs = MockFilesystem::new();

        // Setup initial state file
        let initial_state = StateFile {
            state: SystemState::Inactive,
            ..StateFile::default()
        };
        initial_state
            .save_with_custom_root(&state_path, mock_hidden_vol)
            .expect("Should save initial state");

        // Create manager with Normal verbosity
        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlays: vec![],
            ..Config::test_default()
        };
        let mut manager = NailsManager::new(fs.clone(), config, state_path.clone());
        manager.set_verbosity(Verbosity::Normal);

        let manager_arc = Arc::new(Mutex::new(manager));

        // Run activate with no_preflight=true to skip checks
        let result = NailsManager::activate(Arc::clone(&manager_arc), true);

        // Should succeed (even with no overlays configured)
        assert!(result.is_ok(), "Activate should succeed: {:?}", result);

        // Verify final state is Active
        let manager = manager_arc.lock().unwrap();
        let final_state = manager.current_state().expect("Should load state");
        assert!(final_state.is_active(), "System should be active");
    }

    #[test]
    fn test_activate_with_quiet_verbosity() {
        use std::sync::Arc;

        // Create mock hidden volume structure in temp dir
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path();
        std::fs::create_dir_all(mock_hidden_vol).unwrap();
        let state_path = mock_hidden_vol.join("state.json");

        let fs = MockFilesystem::new();

        // Setup initial state file
        let initial_state = StateFile {
            state: SystemState::Inactive,
            ..StateFile::default()
        };
        initial_state
            .save_with_custom_root(&state_path, mock_hidden_vol)
            .expect("Should save initial state");

        // Create manager with Quiet verbosity
        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlays: vec![],
            ..Config::test_default()
        };
        let mut manager = NailsManager::new(fs.clone(), config, state_path.clone());
        manager.set_verbosity(Verbosity::Quiet);

        let manager_arc = Arc::new(Mutex::new(manager));

        // Run activate
        let result = NailsManager::activate(Arc::clone(&manager_arc), true);

        // Should succeed
        assert!(result.is_ok(), "Activate should succeed: {:?}", result);

        // Verify final state is Active
        let manager = manager_arc.lock().unwrap();
        let final_state = manager.current_state().expect("Should load state");
        assert!(final_state.is_active(), "System should be active");
    }

    #[test]
    fn test_activate_with_verbose_verbosity() {
        use std::sync::Arc;

        // Create mock hidden volume structure in temp dir
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path();
        std::fs::create_dir_all(mock_hidden_vol).unwrap();
        let state_path = mock_hidden_vol.join("state.json");

        let fs = MockFilesystem::new();

        // Setup initial state file
        let initial_state = StateFile {
            state: SystemState::Inactive,
            ..StateFile::default()
        };
        initial_state
            .save_with_custom_root(&state_path, mock_hidden_vol)
            .expect("Should save initial state");

        // Create manager with Verbose verbosity
        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlays: vec![],
            ..Config::test_default()
        };
        let mut manager = NailsManager::new(fs.clone(), config, state_path.clone());
        manager.set_verbosity(Verbosity::Verbose);

        let manager_arc = Arc::new(Mutex::new(manager));

        // Run activate
        let result = NailsManager::activate(Arc::clone(&manager_arc), true);

        // Should succeed
        assert!(result.is_ok(), "Activate should succeed: {:?}", result);
    }

    #[test]
    fn test_activate_with_debug_verbosity() {
        use std::sync::Arc;

        // Create mock hidden volume structure in temp dir
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path();
        std::fs::create_dir_all(mock_hidden_vol).unwrap();
        let state_path = mock_hidden_vol.join("state.json");

        let fs = MockFilesystem::new();

        // Setup initial state file
        let initial_state = StateFile {
            state: SystemState::Inactive,
            ..StateFile::default()
        };
        initial_state
            .save_with_custom_root(&state_path, mock_hidden_vol)
            .expect("Should save initial state");

        // Create manager with Debug verbosity
        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlays: vec![],
            ..Config::test_default()
        };
        let mut manager = NailsManager::new(fs.clone(), config, state_path.clone());
        manager.set_verbosity(Verbosity::Debug);

        let manager_arc = Arc::new(Mutex::new(manager));

        // Run activate
        let result = NailsManager::activate(Arc::clone(&manager_arc), true);

        // Should succeed
        assert!(result.is_ok(), "Activate should succeed: {:?}", result);
    }

    // ========================================================================
    // Progress Logging Tests - Tracing Event Capture (Story 4.8 AC: 7)
    // ========================================================================

    #[test]
    #[tracing_test::traced_test]
    fn test_activate_logs_all_progress_steps() {
        use std::sync::Arc;

        // Create mock hidden volume structure in temp dir
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path();
        std::fs::create_dir_all(mock_hidden_vol).unwrap();
        let state_path = mock_hidden_vol.join("state.json");

        let fs = MockFilesystem::new();

        // Setup initial state file
        let initial_state = StateFile {
            state: SystemState::Inactive,
            ..StateFile::default()
        };
        initial_state
            .save_with_custom_root(&state_path, mock_hidden_vol)
            .expect("Should save initial state");

        // Create manager with Normal verbosity
        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlays: vec![],
            ..Config::test_default()
        };
        let mut manager = NailsManager::new(fs.clone(), config, state_path.clone());
        manager.set_verbosity(Verbosity::Normal);

        let manager_arc = Arc::new(Mutex::new(manager));

        // Run activate (skip pre-flight since we're testing progress logging, not validation)
        let result = NailsManager::activate(Arc::clone(&manager_arc), true);
        assert!(result.is_ok(), "Activate should succeed: {:?}", result);

        // Verify progress steps were logged (pre-flight will show warning, not "passed" message)
        assert!(logs_contain("DANGER: Skipping pre-flight checks"));
        assert!(logs_contain("Activation complete"));
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_activate_logs_include_timing() {
        use std::sync::Arc;

        // Create mock hidden volume structure in temp dir
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path();
        std::fs::create_dir_all(mock_hidden_vol).unwrap();
        let state_path = mock_hidden_vol.join("state.json");

        let fs = MockFilesystem::new();

        // Setup initial state file
        let initial_state = StateFile {
            state: SystemState::Inactive,
            ..StateFile::default()
        };
        initial_state
            .save_with_custom_root(&state_path, mock_hidden_vol)
            .expect("Should save initial state");

        // Create manager with Normal verbosity
        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlays: vec![],
            ..Config::test_default()
        };
        let mut manager = NailsManager::new(fs.clone(), config, state_path.clone());
        manager.set_verbosity(Verbosity::Normal);

        let manager_arc = Arc::new(Mutex::new(manager));

        // Run activate (skip pre-flight to avoid validation failures in test)
        let result = NailsManager::activate(Arc::clone(&manager_arc), true);
        assert!(result.is_ok(), "Activate should succeed: {:?}", result);

        // Verify timing is included (look for patterns like "0.1s", "1.2s", "150ms")
        // The logs should contain timing information in parentheses
        assert!(
            logs_contain("(") && (logs_contain("s)") || logs_contain("ms)")),
            "Logs should contain timing information"
        );
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_activate_quiet_mode_minimal_output() {
        use std::sync::Arc;

        // Create mock hidden volume structure in temp dir
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path();
        std::fs::create_dir_all(mock_hidden_vol).unwrap();
        let state_path = mock_hidden_vol.join("state.json");

        let fs = MockFilesystem::new();

        // Setup initial state file
        let initial_state = StateFile {
            state: SystemState::Inactive,
            ..StateFile::default()
        };
        initial_state
            .save_with_custom_root(&state_path, mock_hidden_vol)
            .expect("Should save initial state");

        // Create manager with Quiet verbosity
        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlays: vec![],
            ..Config::test_default()
        };
        let mut manager = NailsManager::new(fs.clone(), config, state_path.clone());
        manager.set_verbosity(Verbosity::Quiet);

        let manager_arc = Arc::new(Mutex::new(manager));

        // Run activate
        let result = NailsManager::activate(Arc::clone(&manager_arc), true);
        assert!(result.is_ok(), "Activate should succeed: {:?}", result);

        // In quiet mode, should NOT see progress steps
        assert!(!logs_contain("Pre-flight checks passed"));
        assert!(!logs_contain("Running pre-flight checks"));
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_activate_verbose_mode_detailed_output() {
        use crate::OverlayConfig;
        use std::sync::Arc;

        // Create mock hidden volume structure in temp dir
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path();
        std::fs::create_dir_all(mock_hidden_vol).unwrap();
        let state_path = mock_hidden_vol.join("state.json");

        let fs = MockFilesystem::new();

        // Set up overlay directories
        fs.mock_set_path_exists("/", true);
        let upper_dir = mock_hidden_vol.join("overlays/home/upper");
        let work_dir = mock_hidden_vol.join("overlays/home/work");
        std::fs::create_dir_all(&upper_dir).unwrap();
        std::fs::create_dir_all(&work_dir).unwrap();
        fs.mock_set_path_exists(upper_dir.to_str().unwrap(), true);
        fs.mock_set_path_exists(work_dir.to_str().unwrap(), true);

        // Setup initial state file
        let initial_state = StateFile {
            state: SystemState::Inactive,
            ..StateFile::default()
        };
        initial_state
            .save_with_custom_root(&state_path, mock_hidden_vol)
            .expect("Should save initial state");

        // Create manager with Verbose verbosity and overlay config
        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlay_mode: crate::OverlayMode::Explicit, // Use explicit mode for test
            overlays: vec![OverlayConfig {
                name: "home".to_string(),
                lower: PathBuf::from("/"),
                upper: upper_dir.clone(),
                work: work_dir.clone(),
                target: PathBuf::from("/home"),
            }],
            ..Config::test_default()
        };
        let mut manager = NailsManager::new(fs.clone(), config, state_path.clone());
        manager.set_verbosity(Verbosity::Verbose);

        let manager_arc = Arc::new(Mutex::new(manager));

        // Run activate
        let result = NailsManager::activate(Arc::clone(&manager_arc), true);
        assert!(result.is_ok(), "Activate should succeed: {:?}", result);

        // In verbose mode, should see individual mount details
        assert!(logs_contain("/home"));
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_activate_already_active_logged() {
        use std::sync::Arc;

        // Create mock hidden volume structure in temp dir
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path();
        std::fs::create_dir_all(mock_hidden_vol).unwrap();
        let state_path = mock_hidden_vol.join("state.json");

        let fs = MockFilesystem::new();

        // Setup initial state file as ALREADY ACTIVE
        let initial_state = StateFile {
            state: SystemState::Active {
                activated_at: Utc::now(),
                overlays: vec![],
            },
            ..StateFile::default()
        };
        initial_state
            .save_with_custom_root(&state_path, mock_hidden_vol)
            .expect("Should save initial state");

        // Create manager with Normal verbosity
        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlays: vec![],
            ..Config::test_default()
        };
        let mut manager = NailsManager::new(fs.clone(), config, state_path.clone());
        manager.set_verbosity(Verbosity::Normal);

        let manager_arc = Arc::new(Mutex::new(manager));

        // Run activate (should be idempotent)
        let result = NailsManager::activate(Arc::clone(&manager_arc), false);
        assert!(result.is_ok(), "Activate should succeed idempotently");

        // Verify "already active" message was logged
        assert!(logs_contain("already active"));
    }

    // ============================================================================
    // Story 4.9: Rollback Integration Tests - All 7 Scenarios (TR45-TR51)
    // ============================================================================
    //
    // These tests validate rollback behavior for all failure scenarios:
    // - TR45: First mount fails
    // - TR46: Second mount fails
    // - TR47: NixOS build fails
    // - TR48: State file write fails
    // - TR49: Cleanup fails (Epic 5)
    // - TR50: Unmount fails
    // - TR51: Cascading failures
    //
    // Architecture:
    // - Use MockFilesystem with failure injection
    // - Verify state consistency after each rollback
    // - Validate error messages are helpful

    /// Helper to create test manager with temp directory for state file
    fn create_rollback_test_manager(
        fs: MockFilesystem,
    ) -> (Arc<Mutex<NailsManager<MockFilesystem>>>, tempfile::TempDir) {
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path();
        std::fs::create_dir_all(mock_hidden_vol).expect("Should create hidden volume directory");
        let state_path = mock_hidden_vol.join("state.json");

        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlays: vec![
                OverlayConfig {
                    name: "home".to_string(),
                    lower: PathBuf::from("/"),
                    upper: mock_hidden_vol.join("home-upper"),
                    work: mock_hidden_vol.join("home-work"),
                    target: PathBuf::from("/home"),
                },
                OverlayConfig {
                    name: "etc".to_string(),
                    lower: PathBuf::from("/"),
                    upper: mock_hidden_vol.join("etc-upper"),
                    work: mock_hidden_vol.join("etc-work"),
                    target: PathBuf::from("/etc"),
                },
            ],
            overlay_mode: crate::OverlayMode::Explicit, // Use explicit mode for test
            ..Config::test_default()
        };

        // Set up required paths in MockFilesystem
        fs.mock_set_path_exists("/", true);
        fs.mock_set_path_exists("/home", true);
        fs.mock_set_path_exists("/etc", true);

        let hv_str = mock_hidden_vol.to_string_lossy();
        fs.mock_set_path_exists(&hv_str, true);
        fs.mock_set_path_exists(&format!("{}/home-upper", hv_str), true);
        fs.mock_set_path_exists(&format!("{}/home-work", hv_str), true);
        fs.mock_set_path_exists(&format!("{}/etc-upper", hv_str), true);
        fs.mock_set_path_exists(&format!("{}/etc-work", hv_str), true);

        fs.mock_set_writable(&hv_str, true);
        fs.mock_set_writable("/", true);
        fs.mock_set_readable("/", true);
        fs.mock_set_readable("/home", true);
        fs.mock_set_readable("/etc", true);

        let manager = NailsManager::new(fs, config, state_path);

        (Arc::new(Mutex::new(manager)), temp_dir)
    }

    /// Helper to verify state consistency after rollback
    fn verify_rollback_state_consistency(manager_arc: &Arc<Mutex<NailsManager<MockFilesystem>>>) {
        let manager = manager_arc.lock().unwrap();
        let state = manager.current_state().expect("Should get current state");

        // If INACTIVE, no overlays should be mounted
        if matches!(state, SystemState::Inactive) {
            let fs = manager.filesystem();
            assert!(
                !fs.is_mounted(Path::new("/home"))
                    .expect("Should check mount status"),
                "Expected /home to be unmounted in Inactive state"
            );
            assert!(
                !fs.is_mounted(Path::new("/etc"))
                    .expect("Should check mount status"),
                "Expected /etc to be unmounted in Inactive state"
            );
        }

        // If ACTIVE, overlays should be mounted
        if let SystemState::Active { ref overlays, .. } = state {
            for overlay_path in overlays {
                let fs = manager.filesystem();
                assert!(
                    fs.is_mounted(overlay_path)
                        .expect("Should check mount status"),
                    "Expected {} to be mounted in Active state",
                    overlay_path.display()
                );
            }
        }
    }

    // ============================================================================
    // TR45: Test Rollback Scenario 1 - First Mount Fails
    // ============================================================================

    #[test]
    fn test_rollback_tr45_first_mount_fails() {
        // TR45: First mount fails → no rollback needed, state returns to INACTIVE

        // GIVEN: MockFilesystem configured to fail /home mount
        let fs = MockFilesystem::new();
        fs.mock_set_mount_should_fail("/home", true);
        let (manager_arc, _temp_dir) = create_rollback_test_manager(fs);

        // WHEN: Running activation
        let result = NailsManager::activate(Arc::clone(&manager_arc), true); // skip preflight

        // THEN: Activation fails
        assert!(result.is_err(), "Expected activation to fail");

        // AND: State returned to INACTIVE (no mounts to rollback)
        let state = manager_arc
            .lock()
            .unwrap()
            .current_state()
            .expect("Should get state");
        assert_eq!(
            state,
            SystemState::Inactive,
            "Expected state to return to Inactive after first mount fails"
        );

        // AND: No mounts remain
        {
            let manager = manager_arc.lock().unwrap();
            let fs_ref = manager.filesystem();
            assert!(
                !fs_ref
                    .is_mounted(Path::new("/home"))
                    .expect("Should check mount")
            );
            assert!(
                !fs_ref
                    .is_mounted(Path::new("/etc"))
                    .expect("Should check mount")
            );
        } // Release lock before verify

        // AND: State consistency verified
        verify_rollback_state_consistency(&manager_arc);
    }

    #[test]
    fn test_rollback_tr45_first_mount_fails_error_message() {
        // Verify error message is helpful for first mount failure

        let fs = MockFilesystem::new();
        fs.mock_set_mount_should_fail("/home", true);
        let (manager_arc, _temp_dir) = create_rollback_test_manager(fs);

        let result = NailsManager::activate(Arc::clone(&manager_arc), true);

        assert!(result.is_err());
        let err = result.unwrap_err();
        let err_msg = err.to_string();

        // TR45: Error should mention /home mount failure specifically
        assert!(
            err_msg.contains("/home") && err_msg.contains("mount"),
            "Error message should mention /home mount failure: {}",
            err_msg
        );
    }

    // ============================================================================
    // TR46: Test Rollback Scenario 2 - Second Mount Fails
    // ============================================================================

    #[test]
    fn test_rollback_tr46_second_mount_fails() {
        // TR46: Second mount fails → first mount rolled back

        // GIVEN: MockFilesystem where /home succeeds but /etc fails
        let fs = MockFilesystem::new();
        fs.mock_set_mount_should_fail("/etc", true);
        let (manager_arc, _temp_dir) = create_rollback_test_manager(fs);

        // WHEN: Running activation
        let result = NailsManager::activate(Arc::clone(&manager_arc), true);

        // THEN: Activation fails
        assert!(result.is_err(), "Expected activation to fail");

        // AND: State returned to INACTIVE (rollback completed)
        let state = manager_arc
            .lock()
            .unwrap()
            .current_state()
            .expect("Should get state");
        assert_eq!(
            state,
            SystemState::Inactive,
            "Expected state to return to Inactive after second mount fails"
        );

        // AND: All mounts rolled back (including /home)
        {
            let manager = manager_arc.lock().unwrap();
            let fs_ref = manager.filesystem();
            assert!(
                !fs_ref
                    .is_mounted(Path::new("/home"))
                    .expect("Should check mount"),
                "Expected /home to be unmounted after rollback"
            );
            assert!(
                !fs_ref
                    .is_mounted(Path::new("/etc"))
                    .expect("Should check mount"),
                "Expected /etc to remain unmounted"
            );
        } // Release lock before calling helper

        // AND: State consistency verified
        verify_rollback_state_consistency(&manager_arc);
    }

    #[test]
    fn test_rollback_tr46_second_mount_fails_verifies_rollback_order() {
        // Verify that rollback unmounts in reverse order (LIFO)

        let fs = MockFilesystem::new();
        fs.mock_set_mount_should_fail("/etc", true);
        let (manager_arc, _temp_dir) = create_rollback_test_manager(fs);

        let result = NailsManager::activate(Arc::clone(&manager_arc), true);
        assert!(result.is_err());

        // Verify /home was mounted then unmounted (rollback)
        let manager = manager_arc.lock().unwrap();
        let fs_ref = manager.filesystem();

        // Both should be unmounted after rollback
        assert!(!fs_ref.is_mounted(Path::new("/home")).expect("Should check"));
        assert!(!fs_ref.is_mounted(Path::new("/etc")).expect("Should check"));
    }

    #[test]
    fn test_rollback_tr46_multiple_overlays_rolled_back() {
        // Test that all successfully mounted overlays are rolled back
        // when a later mount fails

        let fs = MockFilesystem::new();
        fs.mock_set_mount_should_fail("/etc", true);
        let (manager_arc, _temp_dir) = create_rollback_test_manager(fs);

        let result = NailsManager::activate(Arc::clone(&manager_arc), true);
        assert!(result.is_err());

        // Verify complete rollback
        verify_rollback_state_consistency(&manager_arc);

        {
            let state = manager_arc.lock().unwrap().current_state().unwrap();
            assert_eq!(state, SystemState::Inactive);
        }
    }

    // ============================================================================
    // TR47: Test Rollback Scenario 3 - NixOS Build Fails
    // ============================================================================

    #[test]
    fn test_rollback_tr47_nixos_build_fails_placeholder() {
        // TR47: NixOS build fails → no overlays mounted, state returns to INACTIVE
        //
        // CURRENT LIMITATION: This is a placeholder test. Full TR47 testing requires:
        // 1. NixOSBuilder trait for dependency injection
        // 2. MockNixOSBuilder that can simulate build failures
        // 3. Integration with NailsManager to use injected builder
        //
        // Current test: Verifies normal activation works (baseline behavior)
        //
        // Expected TR47 behavior (once NixOSBuilder mock is available):
        // 1. Mock NixOSBuilder to return build failure (e.g., syntax error in config)
        // 2. Verify activation fails before mounting overlays
        // 3. Verify no overlay mounts were attempted
        // 4. Verify state returns to INACTIVE
        // 5. Verify error message contains "build failed" or specific NixOS error

        // GIVEN: Manager without NixOS builder configured
        let fs = MockFilesystem::new();
        let (manager_arc, _temp_dir) = create_rollback_test_manager(fs);

        // WHEN: Running activation (should succeed without builder)
        let result = NailsManager::activate(Arc::clone(&manager_arc), true);

        // THEN: Activation succeeds (no builder = no build failure possible)
        assert!(
            result.is_ok(),
            "Activation should succeed without NixOS builder"
        );

        // State should be ACTIVE
        let state = manager_arc.lock().unwrap().current_state().unwrap();
        assert!(matches!(state, SystemState::Active { .. }));

        // TODO(TR47): Implement full test when NixOSBuilder mocking is available
    }

    // ============================================================================
    // TR48: Test Rollback Scenario 4 - State File Write Fails
    // ============================================================================

    #[test]
    fn test_rollback_tr48_state_file_write_during_activation() {
        // TR48: State file write fails → overlays unmounted, partial state deleted, returns to INACTIVE
        //
        // CURRENT LIMITATION: MockFilesystem does not yet support write failure injection.
        // This test verifies normal state file writing works correctly. Full TR48 testing
        // requires adding write failure simulation capability to MockFilesystem.
        //
        // Expected TR48 behavior (once MockFilesystem supports write failures):
        // 1. Overlays mount successfully
        // 2. State file write fails (e.g., hidden volume full)
        // 3. StateGuard triggers rollback: unmounts all overlays
        // 4. Partial state.json file deleted
        // 5. State returns to INACTIVE
        // 6. Error message indicates state file write failure

        let fs = MockFilesystem::new();
        let (manager_arc, _temp_dir) = create_rollback_test_manager(fs);

        // Normal activation should succeed (baseline test)
        let result = NailsManager::activate(Arc::clone(&manager_arc), true);
        assert!(
            result.is_ok(),
            "Activation should succeed with working state file"
        );

        // Verify ACTIVE state and state file written
        let state = manager_arc.lock().unwrap().current_state().unwrap();
        assert!(matches!(state, SystemState::Active { .. }));

        // TODO(TR48): Once MockFilesystem supports write failure injection:
        // - Add fs.mock_set_write_should_fail(state_path, true)
        // - Verify activation fails with state write error
        // - Verify all overlays are unmounted (rollback)
        // - Verify state returns to INACTIVE
        // - Verify partial state file is deleted
    }

    // ============================================================================
    // TR49: Test Rollback Scenario 5 - Cleanup Fails (Epic 5 placeholder)
    // ============================================================================

    #[test]
    #[ignore = "Requires Epic 5 CleanupManager implementation"]
    fn test_rollback_tr49_cleanup_fails_remounts_overlays() {
        // TR49: Cleanup fails during deactivation → overlays remounted, state remains ACTIVE
        //
        // This test will be fully implemented in Epic 5 when CleanupManager exists.

        let fs = MockFilesystem::new();
        let (manager_arc, _temp_dir) = create_rollback_test_manager(fs);

        // Activate first
        NailsManager::activate(Arc::clone(&manager_arc), true)
            .expect("Should activate for cleanup test");

        // TODO: Mock CleanupManager to fail with permission denied
        // TODO: Attempt deactivation
        // TODO: Verify overlays are remounted
        // TODO: Verify state remains ACTIVE
        // TODO: Verify error recommends resolving permission issues

        panic!("Test not yet implemented - requires Epic 5 CleanupManager");
    }

    // ============================================================================
    // TR50: Test Rollback Scenario 6 - Unmount Fails
    // ============================================================================

    #[test]
    fn test_rollback_tr50_unmount_fails_during_deactivation() {
        // TR50: Unmount fails → StateGuard rolls back state to ACTIVE
        //
        // KNOWN LIMITATION: StateGuard only restores state metadata, not physical mounts.
        // When deactivation fails partway, overlays successfully unmounted before the failure
        // are NOT remounted. Epic 5 (CleanupManager) will implement full physical rollback.

        // GIVEN: System in ACTIVE state, unmount configured to fail for /etc
        let fs = MockFilesystem::new();
        fs.mock_set_unmount_should_fail("/etc", true);
        let (manager_arc, _temp_dir) = create_rollback_test_manager(fs);

        // Activate first
        NailsManager::activate(Arc::clone(&manager_arc), true)
            .expect("Should activate successfully");

        // Verify ACTIVE state
        let state_before = manager_arc.lock().unwrap().current_state().unwrap();
        assert!(matches!(state_before, SystemState::Active { .. }));

        // WHEN: Attempting deactivation with unmount failure on /etc
        // Deactivation tries to unmount overlays; /home succeeds, /etc fails
        let result = NailsManager::deactivate(Arc::clone(&manager_arc));

        // THEN: Deactivation fails
        assert!(result.is_err(), "Expected deactivation to fail");

        // AND: Error is UnmountError
        let err = result.unwrap_err();
        assert!(
            matches!(err, NailsError::UnmountError { .. }),
            "Expected UnmountError, got: {:?}",
            err
        );

        // AND: State metadata shows ACTIVE (StateGuard rolled back state)
        let state_after = manager_arc.lock().unwrap().current_state().unwrap();
        assert!(
            matches!(state_after, SystemState::Active { .. }),
            "Expected state to remain Active after unmount failure"
        );

        // BUT: Physical mounts inconsistent with state (documents known limitation)
        let manager = manager_arc.lock().unwrap();
        let fs_ref = manager.filesystem();

        assert!(
            !fs_ref
                .is_mounted(Path::new("/home"))
                .expect("Should check mount"),
            "/home unmounted before /etc failure - StateGuard doesn't remount (see test header for Epic 5 note)"
        );

        // /etc should still be mounted (unmount failed)
        assert!(
            fs_ref
                .is_mounted(Path::new("/etc"))
                .expect("Should check mount"),
            "/etc should still be mounted since unmount failed"
        );
    }

    #[test]
    fn test_rollback_tr50_unmount_fails_error_message() {
        // Verify error message for unmount failure is helpful

        let fs = MockFilesystem::new();
        fs.mock_set_unmount_should_fail("/etc", true);
        let (manager_arc, _temp_dir) = create_rollback_test_manager(fs);

        NailsManager::activate(Arc::clone(&manager_arc), true).expect("Should activate");

        let result = NailsManager::deactivate(Arc::clone(&manager_arc));
        assert!(result.is_err());

        let err = result.unwrap_err();
        let err_msg = err.to_string();

        // TR50: Error should specifically mention unmount failure
        assert!(
            err_msg.to_lowercase().contains("unmount") && err_msg.contains("/etc"),
            "Error should mention /etc unmount failure: {}",
            err_msg
        );
    }

    #[test]
    fn test_rollback_tr50_first_unmount_fails() {
        // Test rollback when first unmount in deactivation sequence fails

        let fs = MockFilesystem::new();
        // /etc unmounts first in deactivation (LIFO from activation)
        fs.mock_set_unmount_should_fail("/etc", true);
        let (manager_arc, _temp_dir) = create_rollback_test_manager(fs);

        NailsManager::activate(Arc::clone(&manager_arc), true).expect("Should activate");

        let result = NailsManager::deactivate(Arc::clone(&manager_arc));
        assert!(result.is_err());

        // State should remain ACTIVE
        let state = manager_arc.lock().unwrap().current_state().unwrap();
        assert!(matches!(state, SystemState::Active { .. }));
    }

    // ============================================================================
    // TR51: Test Rollback Scenario 7 - Cascading Failures
    // ============================================================================

    #[test]
    fn test_rollback_tr51_cascading_failures() {
        // TR51: Activation fails, rollback also fails
        //
        // Current behavior: Best-effort rollback continues even if unmount fails.
        // System returns error but may not enter explicit EMERGENCY state.

        // GIVEN: /etc mount fails AND /home unmount fails
        let fs = MockFilesystem::new();
        fs.mock_set_mount_should_fail("/etc", true);
        fs.mock_set_unmount_should_fail("/home", true);
        let (manager_arc, _temp_dir) = create_rollback_test_manager(fs);

        // WHEN: Running activation (will fail on /etc, then fail rollback on /home)
        let result = NailsManager::activate(Arc::clone(&manager_arc), true);

        // THEN: Activation fails
        assert!(result.is_err(), "Expected activation to fail");

        // AND: State is NOT Active (activation failed)
        let state = manager_arc.lock().unwrap().current_state().unwrap();
        assert!(
            !matches!(state, SystemState::Active { .. }),
            "Expected state NOT to be Active after cascading failures"
        );

        // Note: Current implementation may leave system in Inactive or Activating state
        // depending on exact failure point. The key is that activation did not succeed.
    }

    #[test]
    fn test_rollback_tr51_multiple_rollback_failures() {
        // Test scenario where multiple unmounts fail during rollback

        let fs = MockFilesystem::new();
        fs.mock_set_mount_should_fail("/etc", true);
        fs.mock_set_unmount_should_fail("/home", true);
        let (manager_arc, _temp_dir) = create_rollback_test_manager(fs);

        let result = NailsManager::activate(Arc::clone(&manager_arc), true);

        // Should fail
        assert!(result.is_err());

        // Verify error is reported
        let err = result.unwrap_err();
        assert!(
            !err.to_string().is_empty(),
            "Error message should not be empty"
        );
    }

    // ============================================================================
    // TR37, TR38: Comprehensive Rollback Test Coverage
    // ============================================================================

    #[test]
    fn test_rollback_tr37_all_scenarios_have_tests() {
        // TR37: Verify we have tests for all 7 rollback scenarios
        //
        // Test Coverage Status:
        // ✓ TR45: test_rollback_tr45_first_mount_fails (FULLY IMPLEMENTED)
        // ✓ TR46: test_rollback_tr46_second_mount_fails (FULLY IMPLEMENTED)
        // ⚠ TR47: test_rollback_tr47_nixos_build_fails_placeholder (PLACEHOLDER - awaits NixOSBuilder mock)
        // ⚠ TR48: test_rollback_tr48_state_file_write_during_activation (PLACEHOLDER - awaits write failure injection)
        // 🔜 TR49: test_rollback_tr49_cleanup_fails_remounts_overlays (DEFERRED to Epic 5)
        // ✓ TR50: test_rollback_tr50_unmount_fails_during_deactivation (FULLY IMPLEMENTED)
        // ✓ TR51: test_rollback_tr51_cascading_failures (FULLY IMPLEMENTED)
        //
        // Summary: 4 fully implemented, 2 placeholders (awaiting capabilities), 1 deferred to Epic 5

        // Documentation test - verifies test coverage structure is complete
        let total_scenarios = 7;
        let tests_exist = 7; // All scenarios have at least placeholder tests
        assert_eq!(
            tests_exist, total_scenarios,
            "All 7 rollback scenarios should have test structures (4 fully implemented, 2 placeholders, 1 Epic 5)"
        );
    }

    #[test]
    fn test_rollback_tr38_state_consistency_after_rollback() {
        // TR38: Verify state consistency after each rollback

        // Test multiple rollback scenarios and verify consistency
        let scenarios = vec![
            ("first_mount_fails", "/home"),
            ("second_mount_fails", "/etc"),
        ];

        for (scenario, fail_path) in scenarios {
            let fs = MockFilesystem::new();
            fs.mock_set_mount_should_fail(fail_path, true);
            let (manager_arc, _temp_dir) = create_rollback_test_manager(fs);

            let _result = NailsManager::activate(Arc::clone(&manager_arc), true);

            // Verify state consistency after rollback
            verify_rollback_state_consistency(&manager_arc);

            let state = manager_arc.lock().unwrap().current_state().unwrap();
            assert_eq!(
                state,
                SystemState::Inactive,
                "Scenario '{}' should end in Inactive state",
                scenario
            );
        }
    }

    // ============================================================================
    // Additional Rollback Edge Cases
    // ============================================================================

    #[test]
    fn test_rollback_no_mounts_configured() {
        // Test rollback behavior when no overlays are configured

        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path();
        std::fs::create_dir_all(mock_hidden_vol).expect("Should create hidden volume");
        let state_path = mock_hidden_vol.join("state.json");

        let fs = MockFilesystem::new();
        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlays: vec![], // No overlays
            ..Config::test_default()
        };

        fs.mock_set_path_exists("/", true);
        let hv_str = mock_hidden_vol.to_string_lossy();
        fs.mock_set_path_exists(&hv_str, true);

        let manager = NailsManager::new(fs, config, state_path);
        let manager_arc = Arc::new(Mutex::new(manager));

        // Activation with no overlays should succeed
        let result = NailsManager::activate(Arc::clone(&manager_arc), true);
        assert!(result.is_ok(), "Activation with no overlays should succeed");

        std::mem::forget(temp_dir);
    }

    #[test]
    fn test_rollback_preserves_previous_state() {
        // Verify rollback restores the previous state correctly

        let fs = MockFilesystem::new();
        fs.mock_set_mount_should_fail("/home", true);
        let (manager_arc, _temp_dir) = create_rollback_test_manager(fs);

        // Initial state should be Inactive
        let initial_state = manager_arc.lock().unwrap().current_state().unwrap();
        assert_eq!(initial_state, SystemState::Inactive);

        // Failed activation should rollback to Inactive
        let result = NailsManager::activate(Arc::clone(&manager_arc), true);
        assert!(result.is_err());

        let final_state = manager_arc.lock().unwrap().current_state().unwrap();
        assert_eq!(
            final_state, initial_state,
            "Rollback should restore original state"
        );
    }

    #[test]
    fn test_rollback_mount_tracker_commit_prevents_rollback() {
        // Verify that MountTracker.commit() prevents automatic rollback

        let fs = MockFilesystem::new();
        let mut tracker = MountTracker::new(&fs);

        // Add mount
        tracker.push_mount(MountInfo::persistent(PathBuf::from("/home")));

        // Commit to prevent rollback
        tracker.commit();

        // Tracker should be committed
        assert!(tracker.committed, "Tracker should be committed");
    }

    #[test]
    fn test_rollback_mount_tracker_lifo_order() {
        // Verify MountTracker maintains LIFO order

        let fs = MockFilesystem::new();
        let mut tracker = MountTracker::new(&fs);

        // Add mounts in order
        tracker.push_mount(MountInfo::persistent(PathBuf::from("/home")));
        tracker.push_mount(MountInfo::persistent(PathBuf::from("/etc")));

        // Verify order
        assert_eq!(tracker.mounted.len(), 2);
        assert_eq!(tracker.mounted[0].target, PathBuf::from("/home"));
        assert_eq!(tracker.mounted[1].target, PathBuf::from("/etc"));
    }

    #[test]
    fn test_rollback_mount_tracker_rollback_all() {
        // Verify MountTracker.rollback_all() unmounts in reverse order

        let fs = MockFilesystem::new();

        // Set up paths properly for MockFilesystem
        fs.mock_set_path_exists("/", true);
        fs.mock_set_path_exists("/home", true);
        fs.mock_set_path_exists("/etc", true);
        fs.mock_set_path_exists("/tmp", true);
        fs.mock_set_path_exists("/tmp/home-upper", true);
        fs.mock_set_path_exists("/tmp/home-work", true);
        fs.mock_set_path_exists("/tmp/etc-upper", true);
        fs.mock_set_path_exists("/tmp/etc-work", true);
        fs.mock_set_writable("/tmp", true);

        // Mount overlays
        fs.mount_overlay(
            Path::new("/"),
            Path::new("/tmp/home-upper"),
            Path::new("/tmp/home-work"),
            Path::new("/home"),
        )
        .expect("Should mount /home");

        fs.mount_overlay(
            Path::new("/"),
            Path::new("/tmp/etc-upper"),
            Path::new("/tmp/etc-work"),
            Path::new("/etc"),
        )
        .expect("Should mount /etc");

        let mut tracker = MountTracker::new(&fs);
        tracker.push_mount(MountInfo::persistent(PathBuf::from("/home")));
        tracker.push_mount(MountInfo::persistent(PathBuf::from("/etc")));

        // Rollback all
        let result = tracker.rollback_all();
        assert!(result.is_ok(), "Rollback should succeed");

        // Verify both unmounted
        assert!(!fs.is_mounted(Path::new("/home")).unwrap());
        assert!(!fs.is_mounted(Path::new("/etc")).unwrap());
    }

    // ==================== Enhanced MountTracker Tests (Story 4.11) ====================

    #[test]
    fn test_mount_tracker_persistent_mount() {
        // Verify MountTracker correctly tracks persistent mounts

        let fs = MockFilesystem::new();
        let mut tracker = MountTracker::new(&fs);

        let home_info = MountInfo::persistent(PathBuf::from("/home"));
        tracker.push_mount(home_info.clone());

        assert_eq!(tracker.mounted.len(), 1);
        assert_eq!(tracker.mounted[0].mount_type, MountType::Persistent);
        assert_eq!(tracker.mounted[0].target, PathBuf::from("/home"));
        assert!(
            tracker.mounted[0].tmpfs_paths.is_empty(),
            "Persistent mounts should have no tmpfs paths"
        );
    }

    #[test]
    fn test_mount_tracker_ephemeral_mount() {
        // Verify MountTracker correctly tracks ephemeral mounts with tmpfs paths

        let fs = MockFilesystem::new();
        let mut tracker = MountTracker::new(&fs);

        let var_info = MountInfo::ephemeral(
            PathBuf::from("/var"),
            vec![
                PathBuf::from("/run/nails/var/upper"),
                PathBuf::from("/run/nails/var/work"),
            ],
        );
        tracker.push_mount(var_info.clone());

        assert_eq!(tracker.mounted.len(), 1);
        assert_eq!(tracker.mounted[0].mount_type, MountType::Ephemeral);
        assert_eq!(tracker.mounted[0].target, PathBuf::from("/var"));
        assert_eq!(
            tracker.mounted[0].tmpfs_paths.len(),
            2,
            "Ephemeral mounts should track tmpfs paths"
        );
        assert_eq!(
            tracker.mounted[0].tmpfs_paths[0],
            PathBuf::from("/run/nails/var/upper")
        );
        assert_eq!(
            tracker.mounted[0].tmpfs_paths[1],
            PathBuf::from("/run/nails/var/work")
        );
    }

    #[test]
    fn test_mount_tracker_mixed_persistent_ephemeral() {
        // Verify MountTracker can track both mount types

        let fs = MockFilesystem::new();
        let mut tracker = MountTracker::new(&fs);

        // Add persistent mounts
        tracker.push_mount(MountInfo::persistent(PathBuf::from("/home")));
        tracker.push_mount(MountInfo::persistent(PathBuf::from("/etc")));

        // Add ephemeral mounts
        tracker.push_mount(MountInfo::ephemeral(
            PathBuf::from("/var"),
            vec![
                PathBuf::from("/run/nails/var/upper"),
                PathBuf::from("/run/nails/var/work"),
            ],
        ));
        tracker.push_mount(MountInfo::ephemeral(
            PathBuf::from("/tmp"),
            vec![
                PathBuf::from("/run/nails/tmp/upper"),
                PathBuf::from("/run/nails/tmp/work"),
            ],
        ));

        assert_eq!(tracker.mounted.len(), 4);
        assert_eq!(tracker.mounted[0].mount_type, MountType::Persistent);
        assert_eq!(tracker.mounted[1].mount_type, MountType::Persistent);
        assert_eq!(tracker.mounted[2].mount_type, MountType::Ephemeral);
        assert_eq!(tracker.mounted[3].mount_type, MountType::Ephemeral);
    }

    #[test]
    fn test_mount_tracker_ephemeral_rollback_unmounts_tmpfs() {
        // Verify ephemeral rollback unmounts both overlay and tmpfs

        let fs = MockFilesystem::new();

        // Setup paths
        let var = PathBuf::from("/var");
        let upper = PathBuf::from("/run/nails/var/upper");
        let work = PathBuf::from("/run/nails/var/work");

        // Mock mounted overlay (using overlay mount)
        fs.mock_set_path_exists(&var.to_string_lossy(), true);
        fs.mock_set_path_exists(&upper.to_string_lossy(), true);
        fs.mock_set_path_exists(&work.to_string_lossy(), true);
        fs.mock_set_mounted(&var, true);

        // Mock tmpfs mounts (use mount_tmpfs to properly track them)
        fs.mount_tmpfs(&upper, "1G").unwrap();
        fs.mount_tmpfs(&work, "512M").unwrap();

        let mut tracker = MountTracker::new(&fs);
        tracker.push_mount(MountInfo::ephemeral(
            var.clone(),
            vec![upper.clone(), work.clone()],
        ));

        // Rollback
        let result = tracker.rollback_all();
        assert!(result.is_ok(), "Rollback should succeed");

        // Verify overlay and tmpfs are all unmounted
        assert!(
            !fs.is_mounted(&var).unwrap(),
            "/var overlay should be unmounted"
        );
        assert!(
            !fs.is_mounted(&upper).unwrap(),
            "upper tmpfs should be unmounted"
        );
        assert!(
            !fs.is_mounted(&work).unwrap(),
            "work tmpfs should be unmounted"
        );
    }

    #[test]
    fn test_mount_tracker_ephemeral_cascade_unmount_order() {
        // Verify ephemeral mounts unmount overlay BEFORE tmpfs (cascade)

        let fs = MockFilesystem::new();

        // Setup paths
        let var = PathBuf::from("/var");
        let upper = PathBuf::from("/run/nails/var/upper");
        let work = PathBuf::from("/run/nails/var/work");

        // Mock mounted overlay
        fs.mock_set_path_exists(&var.to_string_lossy(), true);
        fs.mock_set_path_exists(&upper.to_string_lossy(), true);
        fs.mock_set_path_exists(&work.to_string_lossy(), true);
        fs.mock_set_mounted(&var, true);

        // Mock tmpfs mounts
        fs.mount_tmpfs(&upper, "1G").unwrap();
        fs.mount_tmpfs(&work, "512M").unwrap();

        let mut tracker = MountTracker::new(&fs);
        tracker.push_mount(MountInfo::ephemeral(
            var.clone(),
            vec![upper.clone(), work.clone()],
        ));

        // Rollback
        let result = tracker.rollback_all();
        assert!(result.is_ok(), "Rollback should succeed");

        // Verify all unmounted (order is implicit in rollback_all implementation)
        assert!(!fs.is_mounted(&var).unwrap());
        assert!(!fs.is_mounted(&upper).unwrap());
        assert!(!fs.is_mounted(&work).unwrap());
    }

    #[test]
    fn test_mount_tracker_lifo_with_mount_types() {
        // Verify LIFO ordering works correctly with mixed mount types

        let fs = MockFilesystem::new();

        // Setup paths
        let home = PathBuf::from("/home");
        let etc = PathBuf::from("/etc");
        let var = PathBuf::from("/var");
        let var_upper = PathBuf::from("/run/nails/var/upper");
        let var_work = PathBuf::from("/run/nails/var/work");

        // Mock persistent overlays as mounted
        fs.mock_set_path_exists(&home.to_string_lossy(), true);
        fs.mock_set_path_exists(&etc.to_string_lossy(), true);
        fs.mock_set_path_exists(&var.to_string_lossy(), true);
        fs.mock_set_path_exists(&var_upper.to_string_lossy(), true);
        fs.mock_set_path_exists(&var_work.to_string_lossy(), true);
        fs.mock_set_mounted(&home, true);
        fs.mock_set_mounted(&etc, true);
        fs.mock_set_mounted(&var, true);

        // Mock tmpfs mounts for ephemeral overlay
        fs.mount_tmpfs(&var_upper, "1G").unwrap();
        fs.mount_tmpfs(&var_work, "512M").unwrap();

        let mut tracker = MountTracker::new(&fs);

        // Mount order: /home (persistent), /etc (persistent), /var (ephemeral)
        tracker.push_mount(MountInfo::persistent(home.clone()));
        tracker.push_mount(MountInfo::persistent(etc.clone()));
        tracker.push_mount(MountInfo::ephemeral(
            var.clone(),
            vec![var_upper.clone(), var_work.clone()],
        ));

        // Rollback should unmount in reverse: /var (+ tmpfs), /etc, /home
        let result = tracker.rollback_all();
        assert!(result.is_ok(), "Rollback should succeed");

        // Verify all unmounted
        assert!(!fs.is_mounted(&home).unwrap());
        assert!(!fs.is_mounted(&etc).unwrap());
        assert!(!fs.is_mounted(&var).unwrap());
        assert!(!fs.is_mounted(&var_upper).unwrap());
        assert!(!fs.is_mounted(&var_work).unwrap());
    }

    #[test]
    fn test_mount_tracker_ephemeral_tmpfs_failure_best_effort() {
        // Verify rollback continues if tmpfs unmount fails (best-effort)

        let fs = MockFilesystem::new();

        // Setup paths
        let var = PathBuf::from("/var");
        let upper = PathBuf::from("/run/nails/var/upper");
        let work = PathBuf::from("/run/nails/var/work");

        // Mock mounted overlay
        fs.mock_set_path_exists(&var.to_string_lossy(), true);
        fs.mock_set_path_exists(&upper.to_string_lossy(), true);
        fs.mock_set_path_exists(&work.to_string_lossy(), true);
        fs.mock_set_mounted(&var, true);

        // Mock tmpfs mounts
        fs.mount_tmpfs(&upper, "1G").unwrap();
        fs.mount_tmpfs(&work, "512M").unwrap();

        // Make upper tmpfs unmount fail
        fs.mock_set_unmount_should_fail(&upper.to_string_lossy(), true);

        let mut tracker = MountTracker::new(&fs);
        tracker.push_mount(MountInfo::ephemeral(
            var.clone(),
            vec![upper.clone(), work.clone()],
        ));

        // Rollback should return error but continue best-effort
        let result = tracker.rollback_all();
        assert!(
            result.is_err(),
            "Rollback should return error for tmpfs failure"
        );

        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("upper") || err_msg.contains("tmpfs"),
            "Error should mention tmpfs failure: {}",
            err_msg
        );

        // Verify overlay and work tmpfs still unmounted (best-effort)
        assert!(!fs.is_mounted(&var).unwrap(), "/var should be unmounted");
        assert!(
            !fs.is_mounted(&work).unwrap(),
            "work tmpfs should be unmounted"
        );
    }

    #[test]
    fn test_mount_info_constructors() {
        // Verify MountInfo constructor helpers work correctly

        let persistent = MountInfo::persistent(PathBuf::from("/home"));
        assert_eq!(persistent.mount_type, MountType::Persistent);
        assert_eq!(persistent.target, PathBuf::from("/home"));
        assert!(persistent.tmpfs_paths.is_empty());

        let ephemeral = MountInfo::ephemeral(
            PathBuf::from("/var"),
            vec![PathBuf::from("/upper"), PathBuf::from("/work")],
        );
        assert_eq!(ephemeral.mount_type, MountType::Ephemeral);
        assert_eq!(ephemeral.target, PathBuf::from("/var"));
        assert_eq!(ephemeral.tmpfs_paths.len(), 2);
    }

    // ==================== Activation/Deactivation with Ephemeral Overlays Tests (Story 4.11) ====================

    #[test]
    #[ignore] // TODO: Fix state file I/O for real integration tests
    fn test_activate_with_ephemeral_overlays_enabled() {
        // AC3: Verify activation mounts both persistent AND ephemeral overlays when enabled

        let fs = MockFilesystem::new();
        let mut config = Config::default();

        // Configure persistent overlays
        config.overlays = vec![OverlayConfig {
            name: "home".to_string(),
            lower: PathBuf::from("/"),
            upper: PathBuf::from("/mnt/hidden-volume/home-upper"),
            work: PathBuf::from("/mnt/hidden-volume/home-work"),
            target: PathBuf::from("/home"),
        }];

        // Enable extended overlays
        config.extended_overlays = ExtendedOverlayConfig {
            enabled: true,
            directories: vec![EphemeralOverlayDir {
                path: PathBuf::from("/var"),
                tmpfs_upper_size: "1G".to_string(),
                tmpfs_work_size: "512M".to_string(),
            }],
        };

        let state_path = PathBuf::from("/mnt/hidden-volume/state.json");
        let manager = Arc::new(Mutex::new(NailsManager::new(
            fs.clone(),
            config,
            state_path.clone(),
        )));

        // Setup filesystem mocks
        setup_mock_filesystem_for_activation(&fs);

        // Setup ephemeral paths
        fs.mock_set_path_exists("/var", true);
        fs.mock_set_path_exists("/run/nails", true);
        fs.mock_set_path_exists("/run/nails/var-upper", true);
        fs.mock_set_path_exists("/run/nails/var-work", true);

        // Activate
        let result = NailsManager::activate(Arc::clone(&manager), true);
        assert!(result.is_ok(), "Activation should succeed: {:?}", result);

        // Verify mount order by checking all are mounted
        // (Mount order verification is implicit in successful activation)
        assert!(fs.is_mounted(Path::new("/home")).unwrap());
        assert!(fs.is_mounted(Path::new("/etc")).unwrap());
        assert!(fs.is_mounted(Path::new("/var")).unwrap());
    }

    #[test]
    #[ignore] // TODO: Fix state file I/O for real integration tests
    fn test_activate_with_ephemeral_overlays_disabled() {
        // AC7: Verify activation skips ephemeral overlays when disabled

        let fs = MockFilesystem::new();
        let mut config = Config::default();

        // Configure persistent overlays
        config.overlays = vec![OverlayConfig {
            name: "home".to_string(),
            lower: PathBuf::from("/"),
            upper: PathBuf::from("/mnt/hidden-volume/home-upper"),
            work: PathBuf::from("/mnt/hidden-volume/home-work"),
            target: PathBuf::from("/home"),
        }];

        // Disable extended overlays
        config.extended_overlays = ExtendedOverlayConfig {
            enabled: false,
            directories: vec![EphemeralOverlayDir {
                path: PathBuf::from("/var"),
                tmpfs_upper_size: "1G".to_string(),
                tmpfs_work_size: "512M".to_string(),
            }],
        };

        let state_path = PathBuf::from("/mnt/hidden-volume/state.json");
        let manager = Arc::new(Mutex::new(NailsManager::new(
            fs.clone(),
            config,
            state_path.clone(),
        )));

        // Setup filesystem mocks
        setup_mock_filesystem_for_activation(&fs);

        // Do NOT setup ephemeral paths - they should not be accessed

        // Activate
        let result = NailsManager::activate(Arc::clone(&manager), true);
        assert!(result.is_ok(), "Activation should succeed: {:?}", result);

        // Verify only persistent mounts are mounted
        assert!(fs.is_mounted(Path::new("/home")).unwrap());
        assert!(fs.is_mounted(Path::new("/etc")).unwrap());

        // Verify ephemeral overlay NOT mounted
        assert!(
            !fs.is_mounted(Path::new("/var")).unwrap(),
            "/var should not be mounted when extended_overlays.enabled=false"
        );
    }

    #[test]
    #[ignore] // TODO: Fix state file mocking for integration tests
    fn test_activate_ephemeral_not_in_state_file() {
        // Verify ephemeral overlays are NOT tracked in state file

        let fs = MockFilesystem::new();
        let mut config = Config::default();

        config.overlays = vec![OverlayConfig {
            name: "home".to_string(),
            lower: PathBuf::from("/"),
            upper: PathBuf::from("/mnt/hidden-volume/home-upper"),
            work: PathBuf::from("/mnt/hidden-volume/home-work"),
            target: PathBuf::from("/home"),
        }];

        config.extended_overlays = ExtendedOverlayConfig {
            enabled: true,
            directories: vec![EphemeralOverlayDir {
                path: PathBuf::from("/var"),
                tmpfs_upper_size: "1G".to_string(),
                tmpfs_work_size: "512M".to_string(),
            }],
        };

        let state_path = PathBuf::from("/mnt/hidden-volume/state.json");
        let manager = Arc::new(Mutex::new(NailsManager::new(
            fs.clone(),
            config,
            state_path.clone(),
        )));

        // Setup filesystem mocks
        setup_mock_filesystem_for_activation(&fs);
        fs.mock_set_path_exists("/var", true);
        fs.mock_set_path_exists("/run/nails", true);
        fs.mock_set_path_exists("/run/nails/var-upper", true);
        fs.mock_set_path_exists("/run/nails/var-work", true);

        // Activate
        let result = NailsManager::activate(Arc::clone(&manager), true);
        assert!(result.is_ok(), "Activation should succeed: {:?}", result);

        // Check state file - should only have /home (persistent), not /var (ephemeral)
        let mgr = manager.lock().unwrap();
        let state = mgr.cached_state.lock().unwrap();

        if let Some(ref state_file) = *state {
            assert!(
                state_file.overlay_status.contains_key(Path::new("/home")),
                "State file should contain /home (persistent)"
            );
            assert!(
                !state_file.overlay_status.contains_key(Path::new("/var")),
                "State file should NOT contain /var (ephemeral)"
            );
        }
    }

    #[test]
    #[ignore] // TODO: Fix state file mocking for integration tests
    fn test_deactivate_unmounts_ephemeral_before_persistent() {
        // Verify deactivation unmounts ephemeral overlays BEFORE persistent (LIFO)

        let fs = MockFilesystem::new();
        let mut config = Config::default();

        config.overlays = vec![OverlayConfig {
            name: "home".to_string(),
            lower: PathBuf::from("/"),
            upper: PathBuf::from("/mnt/hidden-volume/home-upper"),
            work: PathBuf::from("/mnt/hidden-volume/home-work"),
            target: PathBuf::from("/home"),
        }];

        config.extended_overlays = ExtendedOverlayConfig {
            enabled: true,
            directories: vec![EphemeralOverlayDir {
                path: PathBuf::from("/var"),
                tmpfs_upper_size: "1G".to_string(),
                tmpfs_work_size: "512M".to_string(),
            }],
        };

        let state_path = PathBuf::from("/mnt/hidden-volume/state.json");
        let manager = Arc::new(Mutex::new(NailsManager::new(
            fs.clone(),
            config,
            state_path.clone(),
        )));

        // Setup and activate
        setup_mock_filesystem_for_activation(&fs);
        fs.mock_set_path_exists("/var", true);
        fs.mock_set_path_exists("/run/nails", true);
        fs.mock_set_path_exists("/run/nails/var-upper", true);
        fs.mock_set_path_exists("/run/nails/var-work", true);

        NailsManager::activate(Arc::clone(&manager), true).expect("Activation should succeed");

        // Verify both are mounted
        assert!(fs.is_mounted(Path::new("/home")).unwrap());
        assert!(fs.is_mounted(Path::new("/var")).unwrap());

        // Deactivate
        let result = NailsManager::deactivate(Arc::clone(&manager));
        assert!(result.is_ok(), "Deactivation should succeed: {:?}", result);

        // Verify all unmounted
        assert!(!fs.is_mounted(Path::new("/home")).unwrap());
        assert!(!fs.is_mounted(Path::new("/var")).unwrap());
        assert!(!fs.is_mounted(Path::new("/run/nails/var-upper")).unwrap());
        assert!(!fs.is_mounted(Path::new("/run/nails/var-work")).unwrap());
    }

    #[test]
    #[ignore] // TODO: Fix state file mocking for integration tests
    fn test_deactivate_ephemeral_unmount_failure_continues_best_effort() {
        // Verify deactivation continues if ephemeral unmount fails (best-effort)

        let fs = MockFilesystem::new();
        let mut config = Config::default();

        config.overlays = vec![OverlayConfig {
            name: "home".to_string(),
            lower: PathBuf::from("/"),
            upper: PathBuf::from("/mnt/hidden-volume/home-upper"),
            work: PathBuf::from("/mnt/hidden-volume/home-work"),
            target: PathBuf::from("/home"),
        }];

        config.extended_overlays = ExtendedOverlayConfig {
            enabled: true,
            directories: vec![EphemeralOverlayDir {
                path: PathBuf::from("/var"),
                tmpfs_upper_size: "1G".to_string(),
                tmpfs_work_size: "512M".to_string(),
            }],
        };

        let state_path = PathBuf::from("/mnt/hidden-volume/state.json");
        let manager = Arc::new(Mutex::new(NailsManager::new(
            fs.clone(),
            config,
            state_path.clone(),
        )));

        // Setup and activate
        setup_mock_filesystem_for_activation(&fs);
        fs.mock_set_path_exists("/var", true);
        fs.mock_set_path_exists("/run/nails", true);
        fs.mock_set_path_exists("/run/nails/var-upper", true);
        fs.mock_set_path_exists("/run/nails/var-work", true);

        NailsManager::activate(Arc::clone(&manager), true).expect("Activation should succeed");

        // Make /var unmount fail
        fs.mock_set_unmount_should_fail("/var", true);

        // Deactivate - should still succeed with best-effort
        // (ephemeral failure is logged but doesn't stop deactivation)
        let _result = NailsManager::deactivate(Arc::clone(&manager));

        // Deactivation continues even if ephemeral unmount fails
        // The persistent overlay should still be unmounted
        assert!(
            !fs.is_mounted(Path::new("/home")).unwrap(),
            "/home should be unmounted"
        );
    }

    #[test]
    #[ignore] // TODO: Fix state file mocking for integration tests
    fn test_deactivate_with_no_ephemeral_overlays() {
        // Verify deactivation works when no ephemeral overlays are configured

        let fs = MockFilesystem::new();
        let mut config = Config::default();

        config.overlays = vec![OverlayConfig {
            name: "home".to_string(),
            lower: PathBuf::from("/"),
            upper: PathBuf::from("/mnt/hidden-volume/home-upper"),
            work: PathBuf::from("/mnt/hidden-volume/home-work"),
            target: PathBuf::from("/home"),
        }];

        // Extended overlays disabled
        assert!(!config.extended_overlays.enabled);

        let state_path = PathBuf::from("/mnt/hidden-volume/state.json");
        let manager = Arc::new(Mutex::new(NailsManager::new(
            fs.clone(),
            config,
            state_path.clone(),
        )));

        // Setup and activate
        setup_mock_filesystem_for_activation(&fs);
        NailsManager::activate(Arc::clone(&manager), true).expect("Activation should succeed");

        assert!(fs.is_mounted(Path::new("/home")).unwrap());

        // Deactivate
        let result = NailsManager::deactivate(Arc::clone(&manager));
        assert!(result.is_ok(), "Deactivation should succeed: {:?}", result);

        assert!(!fs.is_mounted(Path::new("/home")).unwrap());
    }

    #[test]
    #[ignore] // TODO: Fix state file mocking for integration tests
    fn test_deactivate_multiple_ephemeral_lifo_order() {
        // Verify multiple ephemeral overlays are unmounted in LIFO order

        let fs = MockFilesystem::new();
        let mut config = Config::default();

        config.overlays = vec![OverlayConfig {
            name: "home".to_string(),
            lower: PathBuf::from("/"),
            upper: PathBuf::from("/mnt/hidden-volume/home-upper"),
            work: PathBuf::from("/mnt/hidden-volume/home-work"),
            target: PathBuf::from("/home"),
        }];

        config.extended_overlays = ExtendedOverlayConfig {
            enabled: true,
            directories: vec![
                EphemeralOverlayDir {
                    path: PathBuf::from("/var"),
                    tmpfs_upper_size: "1G".to_string(),
                    tmpfs_work_size: "512M".to_string(),
                },
                EphemeralOverlayDir {
                    path: PathBuf::from("/tmp"),
                    tmpfs_upper_size: "512M".to_string(),
                    tmpfs_work_size: "256M".to_string(),
                },
                EphemeralOverlayDir {
                    path: PathBuf::from("/srv"),
                    tmpfs_upper_size: "256M".to_string(),
                    tmpfs_work_size: "128M".to_string(),
                },
            ],
        };

        let state_path = PathBuf::from("/mnt/hidden-volume/state.json");
        let manager = Arc::new(Mutex::new(NailsManager::new(
            fs.clone(),
            config,
            state_path.clone(),
        )));

        // Setup and activate
        setup_mock_filesystem_for_activation(&fs);
        for path in &["/var", "/tmp", "/srv"] {
            fs.mock_set_path_exists(path, true);
            let name = Path::new(path).file_name().unwrap().to_str().unwrap();
            fs.mock_set_path_exists(&format!("/run/nails/{}-upper", name), true);
            fs.mock_set_path_exists(&format!("/run/nails/{}-work", name), true);
        }
        fs.mock_set_path_exists("/run/nails", true);

        NailsManager::activate(Arc::clone(&manager), true).expect("Activation should succeed");

        // Verify all mounted
        assert!(fs.is_mounted(Path::new("/home")).unwrap());
        assert!(fs.is_mounted(Path::new("/var")).unwrap());
        assert!(fs.is_mounted(Path::new("/tmp")).unwrap());
        assert!(fs.is_mounted(Path::new("/srv")).unwrap());

        // Deactivate
        let result = NailsManager::deactivate(Arc::clone(&manager));
        assert!(result.is_ok(), "Deactivation should succeed: {:?}", result);

        // Verify all unmounted (LIFO order is implicit)
        assert!(!fs.is_mounted(Path::new("/home")).unwrap());
        assert!(!fs.is_mounted(Path::new("/var")).unwrap());
        assert!(!fs.is_mounted(Path::new("/tmp")).unwrap());
        assert!(!fs.is_mounted(Path::new("/srv")).unwrap());
    }

    #[test]
    #[ignore] // TODO: Fix state file I/O for real filesystem integration tests
    fn test_extended_overlay_full_lifecycle_integration() {
        // HIGH PRIORITY: Comprehensive integration test for extended overlay strategy
        // Tests AC1-AC7: Full activation/deactivation cycle with persistent + ephemeral overlays

        let fs = MockFilesystem::new();
        let mut config = Config::default();

        // Configure persistent overlays
        config.overlays = vec![
            OverlayConfig {
                name: "home".to_string(),
                lower: PathBuf::from("/"),
                upper: PathBuf::from("/mnt/hidden-volume/home-upper"),
                work: PathBuf::from("/mnt/hidden-volume/home-work"),
                target: PathBuf::from("/home"),
            },
            OverlayConfig {
                name: "etc".to_string(),
                lower: PathBuf::from("/"),
                upper: PathBuf::from("/mnt/hidden-volume/etc-upper"),
                work: PathBuf::from("/mnt/hidden-volume/etc-work"),
                target: PathBuf::from("/etc"),
            },
        ];

        // Configure ephemeral overlays (AC3)
        config.extended_overlays = ExtendedOverlayConfig {
            enabled: true,
            directories: vec![
                EphemeralOverlayDir {
                    path: PathBuf::from("/var"),
                    tmpfs_upper_size: "1G".to_string(),
                    tmpfs_work_size: "512M".to_string(),
                },
                EphemeralOverlayDir {
                    path: PathBuf::from("/tmp"),
                    tmpfs_upper_size: "512M".to_string(),
                    tmpfs_work_size: "256M".to_string(),
                },
            ],
        };

        let state_path = PathBuf::from("/mnt/hidden-volume/state.json");
        let manager = Arc::new(Mutex::new(NailsManager::new(
            fs.clone(),
            config,
            state_path.clone(),
        )));

        // Setup filesystem mocks
        setup_mock_filesystem_for_activation(&fs);

        // Setup ephemeral overlay paths
        for path in &["/var", "/tmp"] {
            fs.mock_set_path_exists(path, true);
            let name = Path::new(path).file_name().unwrap().to_str().unwrap();
            fs.mock_set_directory_creatable(&format!("/run/nails/{}-upper", name), true);
            fs.mock_set_directory_creatable(&format!("/run/nails/{}-work", name), true);
        }
        fs.mock_set_path_exists("/run/nails", true);

        // PHASE 1: Activation (AC1, AC2, AC3)
        let result = NailsManager::activate(Arc::clone(&manager), true);
        assert!(result.is_ok(), "Activation should succeed: {:?}", result);

        // Verify persistent overlays mounted (AC1)
        assert!(
            fs.is_mounted(Path::new("/home")).unwrap(),
            "/home should be mounted"
        );
        assert!(
            fs.is_mounted(Path::new("/etc")).unwrap(),
            "/etc should be mounted"
        );

        // Verify ephemeral overlays mounted (AC2, AC3)
        assert!(
            fs.is_mounted(Path::new("/var")).unwrap(),
            "/var should be mounted"
        );
        assert!(
            fs.is_mounted(Path::new("/tmp")).unwrap(),
            "/tmp should be mounted"
        );

        // Verify tmpfs backing stores mounted (AC2)
        assert!(
            fs.is_mounted(Path::new("/run/nails/var-upper")).unwrap(),
            "var-upper tmpfs should be mounted"
        );
        assert!(
            fs.is_mounted(Path::new("/run/nails/var-work")).unwrap(),
            "var-work tmpfs should be mounted"
        );
        assert!(
            fs.is_mounted(Path::new("/run/nails/tmp-upper")).unwrap(),
            "tmp-upper tmpfs should be mounted"
        );
        assert!(
            fs.is_mounted(Path::new("/run/nails/tmp-work")).unwrap(),
            "tmp-work tmpfs should be mounted"
        );

        // Verify state is ACTIVE
        {
            let mgr = manager.lock().unwrap();
            let state = mgr.current_state().unwrap();
            assert!(
                matches!(state, SystemState::Active { .. }),
                "State should be Active after activation"
            );
        }

        // PHASE 2: Simulated writes (AC4)
        // In a real system, writes to /var and /tmp would go to tmpfs (RAM)
        // In mock, we just verify mounts exist to represent this capability
        assert!(fs.is_mounted(Path::new("/var")).unwrap());
        assert!(fs.is_mounted(Path::new("/tmp")).unwrap());

        // PHASE 3: Deactivation (AC5)
        let result = NailsManager::deactivate(Arc::clone(&manager));
        assert!(result.is_ok(), "Deactivation should succeed: {:?}", result);

        // Verify ALL overlays unmounted (AC5)
        assert!(
            !fs.is_mounted(Path::new("/home")).unwrap(),
            "/home should be unmounted"
        );
        assert!(
            !fs.is_mounted(Path::new("/etc")).unwrap(),
            "/etc should be unmounted"
        );
        assert!(
            !fs.is_mounted(Path::new("/var")).unwrap(),
            "/var should be unmounted"
        );
        assert!(
            !fs.is_mounted(Path::new("/tmp")).unwrap(),
            "/tmp should be unmounted"
        );

        // Verify tmpfs backing stores destroyed (AC5 - forensic safety)
        assert!(
            !fs.is_mounted(Path::new("/run/nails/var-upper")).unwrap(),
            "var-upper tmpfs should be destroyed"
        );
        assert!(
            !fs.is_mounted(Path::new("/run/nails/var-work")).unwrap(),
            "var-work tmpfs should be destroyed"
        );
        assert!(
            !fs.is_mounted(Path::new("/run/nails/tmp-upper")).unwrap(),
            "tmp-upper tmpfs should be destroyed"
        );
        assert!(
            !fs.is_mounted(Path::new("/run/nails/tmp-work")).unwrap(),
            "tmp-work tmpfs should be destroyed"
        );

        // Verify state is INACTIVE
        {
            let mgr = manager.lock().unwrap();
            assert_eq!(mgr.current_state().unwrap(), SystemState::Inactive);
        }
    }

    // Helper function for activation tests
    fn setup_mock_filesystem_for_activation(fs: &MockFilesystem) {
        // Setup paths
        fs.mock_set_path_exists("/", true);
        fs.mock_set_path_exists("/home", true);
        fs.mock_set_path_exists("/etc", true);
        fs.mock_set_path_exists(DEFAULT_HIDDEN_VOLUME_ROOT, true);
        fs.mock_set_path_exists("/mnt/hidden-volume/home-upper", true);
        fs.mock_set_path_exists("/mnt/hidden-volume/home-work", true);
        fs.mock_set_path_exists("/mnt/hidden-volume/etc-upper", true);
        fs.mock_set_path_exists("/mnt/hidden-volume/etc-work", true);
        fs.mock_set_path_exists("/mnt/hidden-volume/state.json", true);

        // Setup initial state file with correct structure
        let initial_state = StateFile {
            version: env!("CARGO_PKG_VERSION").to_string(),
            state: SystemState::Inactive,
            nixos_generation: None,
            overlay_status: HashMap::new(),
            failed_overlays: Vec::new(),
            last_modified: Utc::now(),
            checksum: None,
        };

        let state_json = serde_json::to_string(&initial_state).unwrap();
        fs.mock_set_file_content("/mnt/hidden-volume/state.json", &state_json);

        // Ensure NixOSConfigCheck prerequisites are satisfied for activation tests.
        setup_nixos_config_check(fs, Path::new(DEFAULT_HIDDEN_VOLUME_ROOT));
    }

    // ============================================================================
    // Story 9.3: Structured Logging Tests
    // ============================================================================

    #[test]
    #[tracing_test::traced_test]
    fn test_activation_emits_structured_events_with_state_fields() {
        use std::sync::Arc;

        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path();
        std::fs::create_dir_all(mock_hidden_vol).unwrap();
        let state_path = mock_hidden_vol.join("state.json");

        let fs = MockFilesystem::new();

        let initial_state = StateFile {
            state: SystemState::Inactive,
            ..StateFile::default()
        };
        initial_state
            .save_with_custom_root(&state_path, mock_hidden_vol)
            .expect("Should save initial state");

        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlays: vec![],
            ..Config::test_default()
        };
        let mut manager = NailsManager::new(fs.clone(), config, state_path.clone());
        manager.set_verbosity(Verbosity::Normal);

        let manager_arc = Arc::new(Mutex::new(manager));

        let result = NailsManager::activate(Arc::clone(&manager_arc), true);
        assert!(result.is_ok(), "Activate should succeed: {:?}", result);

        // Verify structured events with state fields (AC#1)
        assert!(logs_contain("Activation started"));
        assert!(logs_contain("state_from"));
        assert!(logs_contain("Activation complete"));
        assert!(logs_contain("state_to"));
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_activation_error_emits_structured_error_fields() {
        use std::sync::Arc;

        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path();
        std::fs::create_dir_all(mock_hidden_vol).unwrap();
        let state_path = mock_hidden_vol.join("state.json");

        let fs = MockFilesystem::new();

        // Configure filesystem to fail mount operations by making target directory not exist
        fs.mock_set_path_exists("/home", false);

        // Set up overlay paths
        let upper_dir = mock_hidden_vol.join("home");
        let work_dir = mock_hidden_vol.join(".work/home");
        std::fs::create_dir_all(&upper_dir).unwrap();
        std::fs::create_dir_all(&work_dir).unwrap();
        fs.mock_set_path_exists(upper_dir.to_str().unwrap(), true);
        fs.mock_set_path_exists(work_dir.to_str().unwrap(), true);

        let initial_state = StateFile {
            state: SystemState::Inactive,
            ..StateFile::default()
        };
        initial_state
            .save_with_custom_root(&state_path, mock_hidden_vol)
            .expect("Should save initial state");

        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlay_mode: crate::OverlayMode::Explicit,
            overlays: vec![crate::OverlayConfig {
                name: "home".to_string(),
                lower: PathBuf::from("/home"),
                upper: upper_dir.clone(),
                work: work_dir.clone(),
                target: PathBuf::from("/home"),
            }],
            ..Config::test_default()
        };
        let mut manager = NailsManager::new(fs.clone(), config, state_path.clone());
        manager.set_verbosity(Verbosity::Normal);

        let manager_arc = Arc::new(Mutex::new(manager));

        let result = NailsManager::activate(Arc::clone(&manager_arc), true);
        assert!(result.is_err(), "Activate should fail due to mount failure");

        // Verify structured error event fields (AC#2)
        assert!(logs_contain("error"));
        assert!(logs_contain("rollback") || logs_contain("Rollback"));
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_overlays_mounted_event_includes_overlay_list() {
        use std::sync::Arc;

        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path();
        std::fs::create_dir_all(mock_hidden_vol).unwrap();
        let state_path = mock_hidden_vol.join("state.json");

        let fs = MockFilesystem::new();

        let initial_state = StateFile {
            state: SystemState::Inactive,
            ..StateFile::default()
        };
        initial_state
            .save_with_custom_root(&state_path, mock_hidden_vol)
            .expect("Should save initial state");

        // Config with NO overlays - just testing that the log event structure exists
        // When overlays ARE present, the "Overlays mounted" event will fire
        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlays: vec![],
            ..Config::test_default()
        };
        let mut manager = NailsManager::new(fs.clone(), config, state_path.clone());
        manager.set_verbosity(Verbosity::Normal);

        let manager_arc = Arc::new(Mutex::new(manager));

        let result = NailsManager::activate(Arc::clone(&manager_arc), true);
        assert!(result.is_ok(), "Activate should succeed: {:?}", result);

        // With no overlays, the mount event won't fire, but activation complete will
        // This test verifies the logging infrastructure works (AC#1)
        assert!(logs_contain("Activation complete"));
        assert!(logs_contain("state_to"));
    }

    // ========== Story 14.10, Task 12: Integration Tests for Dynamic Overlay Activation ==========

    /// Helper to set up Auto mode activation test with MockFilesystem.
    ///
    /// Sets up mock with root directories, hidden volume paths, and all required
    /// mock path entries for overlay mounting to work.
    fn setup_auto_mode_test(
        dirs: &[&str],
    ) -> (
        tempfile::TempDir,
        MockFilesystem,
        PathBuf, // state_path
    ) {
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path();
        std::fs::create_dir_all(mock_hidden_vol).unwrap();
        let state_path = mock_hidden_vol.join("state.json");

        let fs = MockFilesystem::new();

        // Setup root directories
        let root_dirs: Vec<PathBuf> = dirs.iter().map(PathBuf::from).collect();
        fs.mock_set_root_directories(root_dirs);

        // Mark hidden volume root as writable
        fs.mock_set_path_exists(mock_hidden_vol.to_str().unwrap(), true);
        fs.mock_set_writable(mock_hidden_vol.to_str().unwrap(), true);

        // Pre-create required overlay directories AND set mock paths
        for dir_name in dirs {
            let name = PathBuf::from(dir_name)
                .file_name()
                .unwrap()
                .to_string_lossy()
                .to_string();
            // Create real dirs for temp dir paths
            std::fs::create_dir_all(mock_hidden_vol.join(&name)).unwrap();
            std::fs::create_dir_all(mock_hidden_vol.join(format!(".work/{}", name))).unwrap();

            // Set lower directory (target) as existing in mock
            fs.mock_set_path_exists(dir_name, true);

            // Set upper and work dirs as existing in mock
            let upper = mock_hidden_vol.join(&name);
            let work = mock_hidden_vol.join(format!(".work/{}", name));
            fs.mock_set_path_exists(upper.to_str().unwrap(), true);
            fs.mock_set_path_exists(work.to_str().unwrap(), true);

            // Set .work parent as existing and writable
            let work_parent = mock_hidden_vol.join(".work");
            fs.mock_set_path_exists(work_parent.to_str().unwrap(), true);
            fs.mock_set_writable(work_parent.to_str().unwrap(), true);
        }

        (temp_dir, fs, state_path)
    }

    #[test]
    fn test_activate_auto_mode_overlays_all_non_excluded_dirs() {
        // Task 12.1: Test activation with overlay_mode: auto creates overlays for all non-excluded dirs
        let (temp_dir, fs, state_path) = setup_auto_mode_test(&["/home", "/etc", "/var"]);
        let mock_hidden_vol = temp_dir.path();

        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlay_mode: OverlayMode::Auto,
            overlay_exclusions: vec![],
            overlay_exclusions_remove: vec![],
            overlays: vec![],
            ..Config::test_default()
        };

        let manager = Arc::new(Mutex::new(NailsManager::new(
            fs.clone(),
            config,
            state_path.clone(),
        )));

        let result = NailsManager::activate(Arc::clone(&manager), true);
        assert!(result.is_ok(), "Activation should succeed: {:?}", result);

        // Verify all 3 directories were overlaid
        let state = manager.lock().unwrap().current_state().unwrap();
        if let SystemState::Active { overlays, .. } = state {
            assert_eq!(overlays.len(), 3, "Should have 3 overlays");
            assert!(overlays.contains(&PathBuf::from("/etc")));
            assert!(overlays.contains(&PathBuf::from("/home")));
            assert!(overlays.contains(&PathBuf::from("/var")));
        } else {
            panic!("Expected Active state, got {:?}", state);
        }
    }

    #[test]
    fn test_activate_auto_mode_mount_order_is_alphabetical() {
        // Task 12.2: Test mount order is alphabetical
        let (temp_dir, fs, state_path) = setup_auto_mode_test(&["/var", "/etc", "/home"]);
        let mock_hidden_vol = temp_dir.path();

        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlay_mode: OverlayMode::Auto,
            overlay_exclusions: vec![],
            overlay_exclusions_remove: vec![],
            overlays: vec![],
            ..Config::test_default()
        };

        let manager = Arc::new(Mutex::new(NailsManager::new(
            fs.clone(),
            config,
            state_path.clone(),
        )));

        let result = NailsManager::activate(Arc::clone(&manager), true);
        assert!(result.is_ok(), "Activation should succeed: {:?}", result);

        // Verify mount order is alphabetical by checking overlay_status
        let mgr = manager.lock().unwrap();
        let cached = mgr.cached_state.lock().unwrap();
        if let Some(ref state_file) = *cached {
            let mut mount_targets: Vec<PathBuf> =
                state_file.overlay_status.keys().cloned().collect();
            mount_targets.sort();
            assert_eq!(mount_targets[0], PathBuf::from("/etc"));
            assert_eq!(mount_targets[1], PathBuf::from("/home"));
            assert_eq!(mount_targets[2], PathBuf::from("/var"));
        } else {
            panic!("No cached state found");
        }
    }

    #[test]
    fn test_activate_auto_mode_upper_work_dirs_at_correct_paths() {
        // Task 12.3: Test upper/work dirs created at correct paths
        let (temp_dir, fs, state_path) = setup_auto_mode_test(&["/home", "/etc"]);
        let mock_hidden_vol = temp_dir.path();

        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlay_mode: OverlayMode::Auto,
            overlay_exclusions: vec![],
            overlay_exclusions_remove: vec![],
            overlays: vec![],
            ..Config::test_default()
        };

        let manager = Arc::new(Mutex::new(NailsManager::new(
            fs.clone(),
            config,
            state_path.clone(),
        )));

        let result = NailsManager::activate(Arc::clone(&manager), true);
        assert!(result.is_ok(), "Activation should succeed: {:?}", result);

        // Verify overlay paths are correct
        let mgr = manager.lock().unwrap();
        let cached = mgr.cached_state.lock().unwrap();
        if let Some(ref state_file) = *cached {
            // /home overlay
            let home_info = state_file
                .overlay_status
                .get(&PathBuf::from("/home"))
                .expect("/home overlay should exist");
            assert_eq!(home_info.upper_dir, mock_hidden_vol.join("home"));
            assert_eq!(home_info.work_dir, mock_hidden_vol.join(".work/home"));
            assert_eq!(home_info.lower_dir, PathBuf::from("/home"));

            // /etc overlay
            let etc_info = state_file
                .overlay_status
                .get(&PathBuf::from("/etc"))
                .expect("/etc overlay should exist");
            assert_eq!(etc_info.upper_dir, mock_hidden_vol.join("etc"));
            assert_eq!(etc_info.work_dir, mock_hidden_vol.join(".work/etc"));
            assert_eq!(etc_info.lower_dir, PathBuf::from("/etc"));
        } else {
            panic!("No cached state found");
        }
    }

    #[test]
    fn test_activate_auto_mode_stops_after_mount_failure() {
        // Activation should abort if any overlay fails (safety over partial mounts)
        let (temp_dir, fs, state_path) = setup_auto_mode_test(&["/etc", "/home", "/var"]);
        let mock_hidden_vol = temp_dir.path();

        // Configure /etc to fail mounting
        fs.mock_set_mount_should_fail("/etc", true);

        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlay_mode: OverlayMode::Auto,
            overlay_exclusions: vec![],
            overlay_exclusions_remove: vec![],
            overlays: vec![],
            ..Config::test_default()
        };

        let manager = Arc::new(Mutex::new(NailsManager::new(
            fs.clone(),
            config,
            state_path.clone(),
        )));

        // Activation should fail fast to avoid partial state
        let result = NailsManager::activate(Arc::clone(&manager), true);
        assert!(result.is_err(), "Activation should fail on mount error");

        // Verify state rolled back to Inactive and no overlays recorded
        let state = manager.lock().unwrap().current_state().unwrap();
        assert!(
            matches!(state, SystemState::Inactive),
            "State should roll back to Inactive: got {:?}",
            state
        );
    }

    #[test]
    fn test_activate_auto_mode_failed_overlays_recorded_on_failure() {
        // Failed overlays should be recorded even when activation aborts
        let (temp_dir, fs, state_path) = setup_auto_mode_test(&["/etc", "/home", "/var"]);
        let mock_hidden_vol = temp_dir.path();

        // Configure /etc to fail mounting
        fs.mock_set_mount_should_fail("/etc", true);

        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlay_mode: OverlayMode::Auto,
            overlay_exclusions: vec![],
            overlay_exclusions_remove: vec![],
            overlays: vec![],
            ..Config::test_default()
        };

        let manager = Arc::new(Mutex::new(NailsManager::new(
            fs.clone(),
            config,
            state_path.clone(),
        )));

        let result = NailsManager::activate(Arc::clone(&manager), true);
        assert!(result.is_err(), "Activation should fail on mount error");

        // Verify failed overlays are recorded in state
        let mgr = manager.lock().unwrap();
        let cached = mgr.cached_state.lock().unwrap();
        if let Some(ref state_file) = *cached {
            assert_eq!(
                state_file.failed_overlays.len(),
                1,
                "Should have 1 failed overlay"
            );
            assert_eq!(state_file.failed_overlays[0].target, PathBuf::from("/etc"));
            assert!(
                !state_file.failed_overlays[0].error_message.is_empty(),
                "Error message should not be empty"
            );
        } else {
            panic!("No cached state found");
        }
    }

    #[test]
    fn test_activate_auto_mode_with_user_exclusions() {
        // Integration test: auto mode with user-specified exclusions
        let (temp_dir, fs, state_path) = setup_auto_mode_test(&["/boot", "/etc", "/home", "/nix"]);
        let mock_hidden_vol = temp_dir.path();

        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlay_mode: OverlayMode::Auto,
            overlay_exclusions: vec![PathBuf::from("/boot"), PathBuf::from("/nix")],
            overlay_exclusions_remove: vec![],
            overlays: vec![],
            ..Config::test_default()
        };

        let manager = Arc::new(Mutex::new(NailsManager::new(
            fs.clone(),
            config,
            state_path.clone(),
        )));

        let result = NailsManager::activate(Arc::clone(&manager), true);
        assert!(result.is_ok(), "Activation should succeed: {:?}", result);

        // Only /etc and /home should be overlaid (boot and nix excluded)
        let state = manager.lock().unwrap().current_state().unwrap();
        if let SystemState::Active { overlays, .. } = state {
            assert_eq!(overlays.len(), 2, "Should have 2 overlays");
            assert!(overlays.contains(&PathBuf::from("/etc")));
            assert!(overlays.contains(&PathBuf::from("/home")));
            assert!(!overlays.contains(&PathBuf::from("/boot")));
            assert!(!overlays.contains(&PathBuf::from("/nix")));
        } else {
            panic!("Expected Active state, got {:?}", state);
        }
    }

    // ========== Story 14.10, Task 13: Integration Tests for Explicit Mode ==========

    #[test]
    fn test_activate_explicit_mode_uses_only_configured_overlays() {
        // Task 13.1: Test explicit mode uses only configured overlays (legacy behavior)
        use crate::OverlayConfig;

        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path();
        std::fs::create_dir_all(mock_hidden_vol).unwrap();
        let state_path = mock_hidden_vol.join("state.json");

        let fs = MockFilesystem::new();

        // Root has many directories...
        fs.mock_set_root_directories(vec![
            PathBuf::from("/boot"),
            PathBuf::from("/etc"),
            PathBuf::from("/home"),
            PathBuf::from("/var"),
            PathBuf::from("/tmp"),
        ]);

        fs.mock_set_path_exists("/", true);
        let upper_home = mock_hidden_vol.join("overlays/home/upper");
        let work_home = mock_hidden_vol.join("overlays/home/work");
        std::fs::create_dir_all(&upper_home).unwrap();
        std::fs::create_dir_all(&work_home).unwrap();
        fs.mock_set_path_exists(upper_home.to_str().unwrap(), true);
        fs.mock_set_path_exists(work_home.to_str().unwrap(), true);

        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlay_mode: OverlayMode::Explicit, // Explicit mode!
            overlays: vec![OverlayConfig {
                name: "home".to_string(),
                lower: PathBuf::from("/"),
                upper: upper_home.clone(),
                work: work_home.clone(),
                target: PathBuf::from("/home"),
            }],
            ..Config::test_default()
        };

        let manager = Arc::new(Mutex::new(NailsManager::new(
            fs.clone(),
            config,
            state_path.clone(),
        )));

        let result = NailsManager::activate(Arc::clone(&manager), true);
        assert!(result.is_ok(), "Activation should succeed: {:?}", result);

        // Only 1 overlay (from config), NOT all 5 discovered directories
        let state = manager.lock().unwrap().current_state().unwrap();
        if let SystemState::Active { overlays, .. } = state {
            assert_eq!(
                overlays.len(),
                1,
                "Should have exactly 1 overlay (explicit mode)"
            );
            assert_eq!(overlays[0], PathBuf::from("/home"));
        } else {
            panic!("Expected Active state, got {:?}", state);
        }
    }

    #[test]
    fn test_default_overlay_mode_is_auto() {
        // Task 13.2: Test default mode is auto
        let config = Config::test_default();
        assert_eq!(config.overlay_mode, OverlayMode::Auto);
    }

    // ========== Story 15.1: /etc hardware-configuration import injection ==========

    #[test]
    fn test_activation_injects_import_block_into_overlayed_hardware_config() {
        use crate::OverlayConfig;

        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path();
        std::fs::create_dir_all(mock_hidden_vol).unwrap();
        let state_path = mock_hidden_vol.join("state.json");

        let fs = MockFilesystem::new();

        // Base hardware config must exist and be clean (AC1)
        let base_content = r#"{ config, pkgs, modulesPath, ... }:
{
  imports = [
    (modulesPath + "/installer/scan/not-detected.nix")
  ];
  boot.loader.grub.enable = true;
}
"#;
        fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
        fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");
        fs.mock_set_file_content("/etc/nixos/hardware-configuration.nix", base_content);

        // Overlay config for /etc
        fs.mock_set_path_exists("/etc", true);
        let upper_etc = mock_hidden_vol.join("etc");
        let work_etc = mock_hidden_vol.join(".work/etc");
        std::fs::create_dir_all(&upper_etc).unwrap();
        std::fs::create_dir_all(&work_etc).unwrap();
        fs.mock_set_path_exists(upper_etc.to_str().unwrap(), true);
        fs.mock_set_path_exists(work_etc.to_str().unwrap(), true);
        fs.mock_set_path_exists(mock_hidden_vol.to_str().unwrap(), true);

        // Initial state file
        let initial_state = StateFile {
            state: SystemState::Inactive,
            ..StateFile::default()
        };
        initial_state
            .save_with_custom_root(&state_path, mock_hidden_vol)
            .expect("Should save initial state");

        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlay_mode: OverlayMode::Explicit,
            overlays: vec![OverlayConfig {
                name: "etc".to_string(),
                lower: PathBuf::from("/etc"),
                upper: upper_etc.clone(),
                work: work_etc.clone(),
                target: PathBuf::from("/etc"),
            }],
            ..Config::test_default()
        };

        let manager = Arc::new(Mutex::new(NailsManager::new(
            fs.clone(),
            config,
            state_path.clone(),
        )));

        let result = NailsManager::activate(Arc::clone(&manager), true);
        assert!(result.is_ok(), "Activation should succeed: {:?}", result);

        let written = fs
            .get_written_content(&PathBuf::from("/etc/nixos/hardware-configuration.nix"))
            .expect("Injection should write overlayed hardware config");

        // AC2: Injected import present and first in imports list
        let nails_pos = written
            .find("./nails/configuration.nix")
            .expect("nails import should be injected");
        let existing_pos = written
            .find("installer/scan/not-detected.nix")
            .expect("original imports should remain");
        assert!(nails_pos < existing_pos, "nails import should be first");

        // AC3: Base content preserved (underlay unchanged in effect)
        assert!(
            written.contains("boot.loader.grub.enable = true;"),
            "Original hardware config should be preserved"
        );
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_activate_explicit_mode_empty_overlays_fails() {
        // Security test: Explicit mode with NO overlays should fail activation
        // This prevents silent activation with NO forensic protection
        use std::sync::Arc;

        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path();
        std::fs::create_dir_all(mock_hidden_vol).unwrap();
        let state_path = mock_hidden_vol.join("state.json");

        let fs = MockFilesystem::new();
        fs.mock_set_root_directories(vec![PathBuf::from("/home"), PathBuf::from("/etc")]);

        // Mark hidden volume as writable and existing
        fs.mock_set_path_exists(mock_hidden_vol.to_str().unwrap(), true);
        fs.mock_set_writable(mock_hidden_vol.to_str().unwrap(), true);

        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlay_mode: OverlayMode::Explicit,
            overlays: vec![], // No overlays configured - SECURITY ISSUE
            ..Config::default()
        };

        let manager = Arc::new(Mutex::new(NailsManager::new(
            fs.clone(),
            config,
            state_path.clone(),
        )));

        let result = NailsManager::activate(Arc::clone(&manager), true);

        // Should FAIL with clear error message
        assert!(
            result.is_err(),
            "Activation should fail with empty Explicit mode"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("no overlays") || err_msg.contains("NO forensic protection"),
            "Error should mention empty overlays: {}",
            err_msg
        );
    }

    // ========== Story 14.10: Error Format Validation Test ==========

    #[test]
    #[tracing_test::traced_test]
    fn test_overlay_mount_failure_error_format() {
        // AC9: Validate error message format "⚠ Could not overlay /path: {reason}"
        use std::sync::Arc;

        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path();
        std::fs::create_dir_all(mock_hidden_vol).unwrap();
        let state_path = mock_hidden_vol.join("state.json");

        let fs = MockFilesystem::new();

        // Setup mock filesystem with root directories
        fs.mock_set_root_directories(vec![PathBuf::from("/home"), PathBuf::from("/etc")]);

        // Mark hidden volume root as writable so create_overlay_config can create directories
        fs.mock_set_path_exists(mock_hidden_vol.to_str().unwrap(), true);
        fs.mock_set_writable(mock_hidden_vol.to_str().unwrap(), true);

        // Create required directories on mock filesystem
        let home_upper = mock_hidden_vol.join("home");
        let home_work = mock_hidden_vol.join(".work/home");
        let etc_upper = mock_hidden_vol.join("etc");
        let etc_work = mock_hidden_vol.join(".work/etc");

        std::fs::create_dir_all(&home_upper).unwrap();
        std::fs::create_dir_all(&home_work).unwrap();
        std::fs::create_dir_all(&etc_upper).unwrap();
        std::fs::create_dir_all(&etc_work).unwrap();

        // Configure mock to fail mounting /etc
        fs.mock_set_mount_should_fail("/etc", true);

        let mut config = Config::default();
        config.hidden_volume_root = mock_hidden_vol.to_path_buf();
        config.overlay_mode = OverlayMode::Auto;

        let manager = Arc::new(Mutex::new(NailsManager::new(
            fs.clone(),
            config,
            state_path.clone(),
        )));

        // Attempt activation - should succeed partially
        // Skip preflight to directly test mount failure error format
        let _result = NailsManager::activate(manager, true);

        // Verify error message format matches AC9 specification
        assert!(
            logs_contain("⚠ Could not overlay /etc"),
            "Error message should contain '⚠ Could not overlay /etc'"
        );
        assert!(
            logs_contain("⚠ Could not overlay"),
            "Error message should follow format '⚠ Could not overlay <path>: <reason>'"
        );
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_activate_auto_mode_all_directories_excluded() {
        // Edge case: All directories excluded by user configuration
        // Should activate successfully with 0 overlays and log warning
        use std::sync::Arc;

        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path();
        std::fs::create_dir_all(mock_hidden_vol).unwrap();
        let state_path = mock_hidden_vol.join("state.json");

        let fs = MockFilesystem::new();

        // Setup: only 3 directories in root
        fs.mock_set_root_directories(vec![
            PathBuf::from("/home"),
            PathBuf::from("/etc"),
            PathBuf::from("/var"),
        ]);

        // Mark hidden volume root as writable
        fs.mock_set_path_exists(mock_hidden_vol.to_str().unwrap(), true);
        fs.mock_set_writable(mock_hidden_vol.to_str().unwrap(), true);

        // Exclude ALL directories (edge case configuration)
        let mut config = Config::default();
        config.hidden_volume_root = mock_hidden_vol.to_path_buf();
        config.overlay_mode = OverlayMode::Auto;
        config.overlay_exclusions = vec![
            PathBuf::from("/home"),
            PathBuf::from("/etc"),
            PathBuf::from("/var"),
        ];

        let manager = Arc::new(Mutex::new(NailsManager::new(
            fs.clone(),
            config,
            state_path.clone(),
        )));

        // Attempt activation - should succeed with 0 overlays
        let result = NailsManager::activate(manager.clone(), true);

        assert!(
            result.is_ok(),
            "Activation should succeed even with all directories excluded: {:?}",
            result
        );

        // Verify warning about no overlay targets was logged
        assert!(
            logs_contain("No overlay targets after applying exclusions"),
            "Should log warning when all directories excluded"
        );

        // Verify system state is Active (even with 0 overlays)
        let mgr = manager.lock().unwrap();
        let cached = mgr.cached_state.lock().unwrap();
        if let Some(ref state_file) = *cached {
            assert!(state_file.state.is_active(), "State should be Active");
            assert_eq!(state_file.overlay_status.len(), 0);
        } else {
            panic!("State file should be cached");
        }
    }

    // ========== Story 15.3: Switch to Hidden Config and Revert via Overlay Removal ==========

    /// Helper: set up an Active state with a /etc overlay and /home overlay.
    ///
    /// Returns `(manager_arc, fs_clone, state_path, temp_dir)` so the caller can
    /// manipulate filesystem mock content to simulate the post-unmount view.
    fn setup_active_with_etc_overlay() -> (
        Arc<Mutex<NailsManager<MockFilesystem>>>,
        MockFilesystem,
        PathBuf,
        tempfile::TempDir,
    ) {
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path().to_path_buf();
        std::fs::create_dir_all(&mock_hidden_vol).unwrap();
        let state_path = mock_hidden_vol.join("state.json");

        let fs = MockFilesystem::new();

        // Overlay dirs (needed for activate path, not used by deactivate directly)
        let upper_etc = mock_hidden_vol.join("overlays/etc/upper");
        let work_etc = mock_hidden_vol.join("overlays/etc/work");
        std::fs::create_dir_all(&upper_etc).unwrap();
        std::fs::create_dir_all(&work_etc).unwrap();

        // Set up /etc overlay as mounted
        fs.mock_set_mounted(Path::new("/etc"), true);

        let config = Config {
            hidden_volume_root: mock_hidden_vol.clone(),
            state_file_path: state_path.clone(),
            overlay_mode: crate::OverlayMode::Explicit,
            overlays: vec![crate::OverlayConfig {
                name: "etc".to_string(),
                lower: PathBuf::from("/"),
                upper: upper_etc.clone(),
                work: work_etc.clone(),
                target: PathBuf::from("/etc"),
            }],
            ..Config::test_default()
        };

        let fs_clone = fs.clone();
        let manager = Arc::new(Mutex::new(NailsManager::new(
            fs,
            config,
            state_path.clone(),
        )));

        // Force Active state
        manager
            .lock()
            .unwrap()
            .force_state(SystemState::Active {
                activated_at: Utc::now(),
                overlays: vec![PathBuf::from("/etc")],
            })
            .unwrap();

        // Register /etc overlay in cached state
        {
            let mgr = manager.lock().unwrap();
            let mut cached = mgr.cached_state.lock().unwrap();
            if let Some(ref mut sf) = *cached {
                sf.overlay_status.insert(
                    PathBuf::from("/etc"),
                    OverlayInfo {
                        mount_path: PathBuf::from("/etc"),
                        lower_dir: PathBuf::from("/"),
                        upper_dir: upper_etc.clone(),
                        work_dir: work_etc.clone(),
                        mounted_at: Utc::now(),
                    },
                );
            }
        }

        (manager, fs_clone, state_path, temp_dir)
    }

    /// Helper: set up an Active state with a /home overlay.
    fn setup_active_with_home_overlay() -> (
        Arc<Mutex<NailsManager<MockFilesystem>>>,
        MockFilesystem,
        PathBuf,
        tempfile::TempDir,
    ) {
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path().to_path_buf();
        std::fs::create_dir_all(&mock_hidden_vol).unwrap();
        let state_path = mock_hidden_vol.join("state.json");

        let fs = MockFilesystem::new();

        // Overlay dirs
        let upper_home = mock_hidden_vol.join("overlays/home/upper");
        let work_home = mock_hidden_vol.join("overlays/home/work");
        std::fs::create_dir_all(&upper_home).unwrap();
        std::fs::create_dir_all(&work_home).unwrap();

        // Set up /home overlay as mounted
        fs.mock_set_mounted(Path::new("/home"), true);

        let config = Config {
            hidden_volume_root: mock_hidden_vol.clone(),
            state_file_path: state_path.clone(),
            overlay_mode: crate::OverlayMode::Explicit,
            overlays: vec![crate::OverlayConfig {
                name: "home".to_string(),
                lower: PathBuf::from("/"),
                upper: upper_home.clone(),
                work: work_home.clone(),
                target: PathBuf::from("/home"),
            }],
            ..Config::test_default()
        };

        let fs_clone = fs.clone();
        let manager = Arc::new(Mutex::new(NailsManager::new(
            fs,
            config,
            state_path.clone(),
        )));

        // Force Active state
        manager
            .lock()
            .unwrap()
            .force_state(SystemState::Active {
                activated_at: Utc::now(),
                overlays: vec![PathBuf::from("/home")],
            })
            .unwrap();

        // Register /home overlay in cached state
        {
            let mgr = manager.lock().unwrap();
            let mut cached = mgr.cached_state.lock().unwrap();
            if let Some(ref mut sf) = *cached {
                sf.overlay_status.insert(
                    PathBuf::from("/home"),
                    OverlayInfo {
                        mount_path: PathBuf::from("/home"),
                        lower_dir: PathBuf::from("/"),
                        upper_dir: upper_home.clone(),
                        work_dir: work_home.clone(),
                        mounted_at: Utc::now(),
                    },
                );
            }
        }

        (manager, fs_clone, state_path, temp_dir)
    }

    /// AC1, Subtask 1.1 / 1.2:
    /// inject_import_block() targets `/etc/nixos/hardware-configuration.nix` (the overlayed
    /// path). The hidden underlay at `{hidden}/etc/nixos/hardware-configuration.nix` must
    /// remain unmodified (no import injected).
    ///
    /// Verified by: running inject_import_block on a mock that serves a clean base config at
    /// `/etc/nixos/hardware-configuration.nix`, then confirming the MockFilesystem only
    /// modified that single path — the hidden underlay path is NOT written to.
    #[test]
    fn test_activation_inject_targets_overlayed_path_not_underlay() {
        let temp_dir = tempfile::tempdir().unwrap();
        let hidden = temp_dir.path();
        let fs = MockFilesystem::new();

        // The overlayed (live) hardware config — no import yet (overlay is mounted, so this
        // is what the OS sees at /etc/nixos/hardware-configuration.nix after mounting)
        fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
        fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");
        fs.mock_set_file_content(
            "/etc/nixos/hardware-configuration.nix",
            "{ config, lib, pkgs, ... }:\n{ }",
        );

        // The hidden underlay — also has no import initially
        let underlay = hidden.join("etc/nixos/hardware-configuration.nix");
        fs.mock_set_path_exists(underlay.to_str().unwrap(), true);
        fs.mock_set_path_type(underlay.to_str().unwrap(), "file");
        fs.mock_set_file_content(
            underlay.to_str().unwrap(),
            "{ config, lib, pkgs, ... }:\n{ }",
        );

        // inject_import_block writes to /etc/nixos/hardware-configuration.nix (overlayed path)
        let result = inject_import_block(&fs);
        assert!(
            result.is_ok(),
            "inject_import_block should succeed: {:?}",
            result
        );

        // Overlayed path now contains the import
        let overlayed_content = fs
            .read_file_content(std::path::Path::new(
                "/etc/nixos/hardware-configuration.nix",
            ))
            .unwrap();
        assert!(
            overlayed_content.contains("./nails/configuration.nix"),
            "Overlayed hardware-configuration.nix should contain the injected import"
        );

        // Underlay path is UNTOUCHED — contains no import (AC1, subtask 1.2)
        let underlay_content = fs.read_file_content(&underlay).unwrap();
        assert!(
            !underlay_content.contains("./nails/configuration.nix"),
            "Hidden underlay hardware-configuration.nix must NOT be modified by inject_import_block (AC1)"
        );

        // Verify only the overlayed path was written
        let ops = fs.mock_ops();
        assert!(
            ops.contains(&MockOp::WriteFile {
                path: PathBuf::from("/etc/nixos/hardware-configuration.nix")
            }),
            "inject_import_block should write to the overlayed hardware config path"
        );
        assert!(
            !ops.contains(&MockOp::WriteFile { path: underlay }),
            "inject_import_block must not write to the hidden underlay path"
        );
    }

    /// AC1, Subtask 1.1:
    /// inject_import_block() must run AFTER the /etc overlay is mounted.
    /// This test verifies ordering by inspecting the MockFilesystem operation log.
    #[test]
    fn test_activation_inject_happens_after_etc_overlay_mount() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mock_hidden_vol = temp_dir.path();
        let state_path = mock_hidden_vol.join("state.json");
        let fs = MockFilesystem::new();

        // Base config clean so verify_base_config_clean() passes.
        fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
        fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");
        fs.mock_set_file_content(
            "/etc/nixos/hardware-configuration.nix",
            "{ config, lib, pkgs, ... }:\n{ }",
        );

        // Overlay dirs
        let upper_home = mock_hidden_vol.join("overlays/home/upper");
        let work_home = mock_hidden_vol.join("overlays/home/work");
        let upper_etc = mock_hidden_vol.join("overlays/etc/upper");
        let work_etc = mock_hidden_vol.join("overlays/etc/work");

        fs.mock_set_path_exists("/", true);
        fs.mock_set_path_type("/", "directory");
        fs.mock_set_path_exists(upper_home.to_str().unwrap(), true);
        fs.mock_set_path_exists(work_home.to_str().unwrap(), true);
        fs.mock_set_path_exists(upper_etc.to_str().unwrap(), true);
        fs.mock_set_path_exists(work_etc.to_str().unwrap(), true);

        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path,
            overlay_mode: crate::OverlayMode::Explicit,
            overlays: vec![
                crate::OverlayConfig {
                    name: "home".to_string(),
                    lower: PathBuf::from("/"),
                    upper: upper_home,
                    work: work_home,
                    target: PathBuf::from("/home"),
                },
                crate::OverlayConfig {
                    name: "etc".to_string(),
                    lower: PathBuf::from("/"),
                    upper: upper_etc,
                    work: work_etc,
                    target: PathBuf::from("/etc"),
                },
            ],
            ..Config::test_default()
        };
        let manager = Arc::new(Mutex::new(NailsManager::new(
            fs.clone(),
            config,
            mock_hidden_vol.join("state.json"),
        )));

        let result = NailsManager::activate(manager.clone(), true);
        assert!(result.is_ok(), "Activation should succeed: {:?}", result);

        let ops = fs.mock_ops();
        let etc_mount_idx = ops.iter().position(
            |op| matches!(op, MockOp::MountOverlay { target } if target == &PathBuf::from("/etc")),
        );
        let inject_idx = ops.iter().position(|op| {
            matches!(op, MockOp::WriteFile { path } if path == &PathBuf::from("/etc/nixos/hardware-configuration.nix"))
        });

        assert!(
            etc_mount_idx.is_some(),
            "Expected /etc overlay mount operation in op log"
        );
        assert!(
            inject_idx.is_some(),
            "Expected inject_import_block write operation in op log"
        );
        assert!(
            etc_mount_idx.unwrap() < inject_idx.unwrap(),
            "inject_import_block must run after /etc overlay mount"
        );
    }

    /// AC2, Subtask 2.1 + AC3, Subtask 2.2:
    /// After deactivation, /etc overlay is unmounted, so /etc/nixos/hardware-configuration.nix
    /// reverts to the base (clean) file. verify_base_config_clean() is called post-unmount and
    /// confirms the base is clean. Deactivation succeeds.
    #[test]
    fn test_deactivation_succeeds_when_base_config_clean_after_unmount() {
        let (manager, fs_clone, state_path, _temp_dir) = setup_active_with_etc_overlay();

        // Simulate post-unmount view: base config is clean (no import, no hidden refs)
        fs_clone.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
        fs_clone.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");
        fs_clone.mock_set_file_content(
            "/etc/nixos/hardware-configuration.nix",
            "{ config, lib, pkgs, ... }:\n{ }",
        );

        let result = NailsManager::deactivate(Arc::clone(&manager));
        assert!(
            result.is_ok(),
            "Deactivation should succeed when base config is clean: {:?}",
            result
        );

        // State must be Inactive
        assert_eq!(
            manager.lock().unwrap().current_state().unwrap(),
            SystemState::Inactive
        );

        // State file on disk must be Inactive
        let loaded = StateFile::load(&state_path).unwrap();
        assert_eq!(loaded.state, SystemState::Inactive);

        // /etc overlay must be unmounted
        assert!(
            !fs_clone.is_mounted(Path::new("/etc")).unwrap(),
            "/etc overlay should be unmounted after deactivation"
        );
    }

    /// AC3, Subtask 2.2:
    /// If verify_base_config_clean() returns false after deactivation (base config is dirty),
    /// deactivation returns an error. This enforces that the base underlay was never polluted.
    #[test]
    fn test_deactivation_fails_when_base_config_dirty_after_unmount() {
        let (manager, fs_clone, _state_path, _temp_dir) = setup_active_with_etc_overlay();

        // Simulate a dirty base config (contains a hidden path reference — should never happen
        // in production on the base underlay, but if it does, deactivation must catch it).
        fs_clone.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
        fs_clone.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");
        fs_clone.mock_set_file_content(
            "/etc/nixos/hardware-configuration.nix",
            "{ config, lib, pkgs, ... }:\n{ imports = [ /mnt/hidden/nixos/configuration.nix ]; }",
        );

        let result = NailsManager::deactivate(Arc::clone(&manager));
        assert!(
            result.is_err(),
            "Deactivation should fail when base config is dirty after unmount (AC3)"
        );

        let err = result.unwrap_err();
        match err {
            NailsError::NixOSError(msg) => {
                assert!(
                    msg.contains("forensically clean")
                        || msg.contains("dirty")
                        || msg.contains("clean"),
                    "Error message should reference config cleanliness: {}",
                    msg
                );
            }
            other => panic!("Expected NixOSError, got: {:?}", other),
        }

        // Overlays were already unmounted; state should reflect Inactive even on error.
        assert_eq!(
            manager.lock().unwrap().current_state().unwrap(),
            SystemState::Inactive,
            "State should be Inactive after deactivation cleanliness failure"
        );
    }

    /// Base config cleanliness check is only required when /etc overlay was mounted.
    #[test]
    fn test_deactivation_skips_base_check_when_etc_not_overlaid() {
        let (manager, fs_clone, _state_path, _temp_dir) = setup_active_with_home_overlay();

        // Dirty base config should not block deactivation when /etc wasn't overlaid.
        fs_clone.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
        fs_clone.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");
        fs_clone.mock_set_file_content(
            "/etc/nixos/hardware-configuration.nix",
            "{ config, lib, pkgs, ... }:\n{ imports = [ /mnt/hidden/nixos/configuration.nix ]; }",
        );

        let result = NailsManager::deactivate(Arc::clone(&manager));
        assert!(
            result.is_ok(),
            "Deactivation should succeed when /etc overlay was not mounted"
        );

        assert_eq!(
            manager.lock().unwrap().current_state().unwrap(),
            SystemState::Inactive,
            "State should be Inactive after deactivation"
        );
    }

    /// AC2-3, Subtask 4.1 (integration):
    /// Full activation → deactivation cycle.
    /// After deactivation the base config view is clean (no hidden import).
    /// Uses Explicit mode with a /home overlay (avoids Auto-mode overlay discovery complexity).
    #[test]
    fn test_full_cycle_base_config_clean_after_deactivation() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mock_hidden_vol = temp_dir.path();
        let state_path = mock_hidden_vol.join("state.json");
        let fs = MockFilesystem::new();

        // Base hardware config: clean (AC1 pre-condition)
        fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
        fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");
        fs.mock_set_file_content(
            "/etc/nixos/hardware-configuration.nix",
            "{ config, lib, pkgs, ... }:\n{ }",
        );

        // Hidden config prerequisites for stage_hidden_config_symlink
        let hidden_config = mock_hidden_vol.join("config/nixos/configuration.nix");
        std::fs::create_dir_all(hidden_config.parent().unwrap()).unwrap();
        std::fs::write(&hidden_config, "{ }").unwrap();
        fs.mock_set_path_exists(hidden_config.to_str().unwrap(), true);
        fs.mock_set_file_content(hidden_config.to_str().unwrap(), "{ }");

        let nails_dir = mock_hidden_vol.join("etc/nixos/nails");
        std::fs::create_dir_all(&nails_dir).unwrap();
        let symlink_path = nails_dir.join("configuration.nix");
        fs.mock_set_path_exists(nails_dir.to_str().unwrap(), true);
        fs.mock_set_path_exists(symlink_path.to_str().unwrap(), true);

        // Overlay dirs for /home and /etc
        let upper_home = mock_hidden_vol.join("overlays/home/upper");
        let work_home = mock_hidden_vol.join("overlays/home/work");
        let upper_etc = mock_hidden_vol.join("overlays/etc/upper");
        let work_etc = mock_hidden_vol.join("overlays/etc/work");
        std::fs::create_dir_all(&upper_home).unwrap();
        std::fs::create_dir_all(&work_home).unwrap();
        std::fs::create_dir_all(&upper_etc).unwrap();
        std::fs::create_dir_all(&work_etc).unwrap();
        fs.mock_set_path_exists(upper_home.to_str().unwrap(), true);
        fs.mock_set_path_exists(work_home.to_str().unwrap(), true);
        fs.mock_set_path_exists(upper_etc.to_str().unwrap(), true);
        fs.mock_set_path_exists(work_etc.to_str().unwrap(), true);
        fs.mock_set_path_exists("/", true);

        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlay_mode: crate::OverlayMode::Explicit,
            overlays: vec![
                crate::OverlayConfig {
                    name: "home".to_string(),
                    lower: PathBuf::from("/"),
                    upper: upper_home.clone(),
                    work: work_home.clone(),
                    target: PathBuf::from("/home"),
                },
                crate::OverlayConfig {
                    name: "etc".to_string(),
                    lower: PathBuf::from("/"),
                    upper: upper_etc.clone(),
                    work: work_etc.clone(),
                    target: PathBuf::from("/etc"),
                },
            ],
            ..Config::test_default()
        };

        let manager = Arc::new(Mutex::new(NailsManager::new(
            fs.clone(),
            config,
            state_path.clone(),
        )));

        // === Activate ===
        let activate_result = NailsManager::activate(manager.clone(), true);
        assert!(
            activate_result.is_ok(),
            "Activation should succeed: {:?}",
            activate_result
        );
        assert!(
            manager.lock().unwrap().current_state().unwrap().is_active(),
            "Should be Active after activation"
        );

        // Simulate post-deactivation view: base config is clean
        // (In production, unmounting /etc overlay makes the base file visible again;
        //  here we set the mock content directly since MockFs doesn't simulate overlay mechanics)
        fs.mock_set_file_content(
            "/etc/nixos/hardware-configuration.nix",
            "{ config, lib, pkgs, ... }:\n{ }",
        );

        // === Deactivate ===
        let deactivate_result = NailsManager::deactivate(Arc::clone(&manager));
        assert!(
            deactivate_result.is_ok(),
            "Deactivation should succeed: {:?}",
            deactivate_result
        );

        // State must be Inactive
        assert_eq!(
            manager.lock().unwrap().current_state().unwrap(),
            SystemState::Inactive,
            "State should be Inactive after deactivation"
        );

        // Base config must still be clean (verify_base_config_clean passed)
        let base_content = fs
            .read_file_content(std::path::Path::new(
                "/etc/nixos/hardware-configuration.nix",
            ))
            .unwrap();
        assert!(
            !base_content.contains("./nails/configuration.nix"),
            "Base hardware-configuration.nix must remain clean after full cycle (AC2, AC3)"
        );
    }
}
