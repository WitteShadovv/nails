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
//! # Module Structure
//!
//! - **mod.rs** - Core NailsManager struct, constructors, and helper functions
//! - **mount_tracker.rs** - RAII mount tracking for automatic rollback
//! - **state_management.rs** - State transitions and verification
//! - **activation.rs** - 10-step activation flow
//! - **deactivation.rs** - Deactivation and emergency mode
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

use crate::{Config, Filesystem, NailsError, Result, StateFile};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

// Module declarations
pub mod activation;
pub mod deactivation;
pub mod mount_tracker;
pub mod state_management;

// Tests are kept in a separate module file
#[cfg(test)]
#[path = "tests.rs"]
mod tests;

// Re-export key types for convenience
pub use mount_tracker::{MountInfo, MountTracker, MountType};

/// Start a systemd service and its socket (socket first), best-effort.
fn start_service_and_socket(service: &str) {
    // Skip actual systemctl calls during tests to prevent leaking to host system
    if cfg!(test) {
        return;
    }

    let _ = std::process::Command::new("systemctl")
        .args(["start", &format!("{}.socket", service)])
        .output();
    let _ = std::process::Command::new("systemctl")
        .args(["start", service])
        .output();
}

/// Return the system profile path, honoring NAILS_SYSTEM_PROFILE_PATH if set.
pub(crate) fn system_profile_path() -> PathBuf {
    std::env::var_os("NAILS_SYSTEM_PROFILE_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/nix/var/nix/profiles/system"))
}

fn system_profiles_dir() -> PathBuf {
    system_profile_path()
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("/nix/var/nix/profiles"))
}

fn parse_system_generation(name: &str) -> Option<u64> {
    let prefix = "system-";
    let suffix = "-link";
    if !name.starts_with(prefix) || !name.ends_with(suffix) {
        return None;
    }
    let num = &name[prefix.len()..name.len() - suffix.len()];
    num.parse::<u64>().ok()
}

/// Return the newest available system profile (system-<n>-link), if present.
fn find_newest_system_profile<F: Filesystem>(fs: &F) -> Result<Option<PathBuf>> {
    let profiles_dir = system_profiles_dir();
    if !fs.path_exists(&profiles_dir)? {
        return Ok(None);
    }

    let mut best: Option<(u64, PathBuf)> = None;
    for entry in fs.list_directory(&profiles_dir)? {
        let name = entry.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if let Some(generation) = parse_system_generation(name)
            && best.as_ref().map(|(g, _)| generation > *g).unwrap_or(true)
        {
            best = Some((generation, entry));
        }
    }

    Ok(best.map(|(_, path)| path))
}

/// Prefer the newest available system profile, fall back to the system symlink.
pub(crate) fn select_system_profile<F: Filesystem>(fs: &F) -> Result<Option<PathBuf>> {
    if let Some(path) = find_newest_system_profile(fs)? {
        return Ok(Some(path));
    }
    let system_profile = system_profile_path();
    if fs.path_exists(&system_profile)? {
        return Ok(Some(system_profile));
    }
    Ok(None)
}

/// Ensure /run/current-system exists as a symlink to the provided system profile.
pub(crate) fn ensure_run_current_system_symlink<F: Filesystem>(
    fs: &F,
    target: &Path,
) -> Result<()> {
    let run_current = PathBuf::from("/run/current-system");
    // Handle dangling symlinks: path_exists() is false for them, so check is_symlink first.
    if fs.is_symlink(&run_current)? {
        fs.remove_file(&run_current)?;
    } else if fs.path_exists(&run_current)? {
        return Err(NailsError::NixOSError(format!(
            "{} exists but is not a symlink",
            run_current.display()
        )));
    }

    fs.create_symlink(target, &run_current)?;
    Ok(())
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
pub(crate) fn clean_stale_network_config<F: Filesystem>(upper_dir: &Path, fs: &F) -> Result<()> {
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
pub(crate) fn create_overlay_config<F: Filesystem>(
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
}
