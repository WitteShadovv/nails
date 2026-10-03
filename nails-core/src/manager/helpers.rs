//! Helper functions for the manager module
//!
//! Free functions used by NailsManager and its sub-modules for overlay target
//! building, system profile selection, network config cleanup, and overlay
//! configuration creation.

mod command_cache;
mod runtime_cache;
mod service_controller;

use crate::constants::ENV_SYSTEM_PROFILE_PATH;
use crate::{Config, Filesystem, NailsError, Result};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

static SYSTEMCTL_COMMAND: OnceLock<command_cache::CachedCommand> = OnceLock::new();
static NIX_DAEMON_PATH: OnceLock<PathBuf> = OnceLock::new();
static NIX_COMMAND_PATH: OnceLock<PathBuf> = OnceLock::new();
static CURRENT_SYSTEM_PROFILE: OnceLock<PathBuf> = OnceLock::new();

pub(crate) use runtime_cache::{cache_nix_overlay_runtime_commands, cached_current_system_profile};
pub(crate) use service_controller::{ServiceController, start_service_and_socket};

#[cfg(test)]
pub(crate) use service_controller::recorder::drain as drain_recorded_service_actions;

/// Return the system profile path, honoring NAILS_SYSTEM_PROFILE_PATH if set.
pub(crate) fn system_profile_path() -> PathBuf {
    std::env::var_os(ENV_SYSTEM_PROFILE_PATH)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/nix/var/nix/profiles/system"))
}

pub(crate) fn system_profiles_dir() -> PathBuf {
    system_profile_path()
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("/nix/var/nix/profiles"))
}

pub(crate) fn parse_system_generation(name: &str) -> Option<u64> {
    let prefix = "system-";
    let suffix = "-link";
    if !name.starts_with(prefix) || !name.ends_with(suffix) {
        return None;
    }
    let num = &name[prefix.len()..name.len() - suffix.len()];
    num.parse::<u64>().ok()
}

/// Return the newest available system profile (system-<n>-link), if present.
pub(crate) fn find_newest_system_profile<F: Filesystem>(fs: &F) -> Result<Option<PathBuf>> {
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

/// Clean stale network configuration files from /etc overlay upper layer (DNS preservation)
///
/// Before mounting the /etc overlay, remove stale `resolv.conf` and `nsswitch.conf` from the
/// upper layer directory. This allows the real system files to show through the overlay's
/// lower layer, preserving DNS resolution.
///
/// This touches **only** DNS resolution: it preserves `resolv.conf` and `nsswitch.conf`
/// and nothing else. It does not alter the machine-id, hostname, MAC addresses or
/// NetworkManager profiles, so those network identifiers are shared between the decoy and the
/// hidden session. Correlation through them is out of scope for the overlay; see the user
/// security guide for the optional hidden network-identity configuration.
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

/// Apply exclusion filter to a list of directories
///
/// Filters out directories that match any path in the exclusion list.
/// This function is separated from build_overlay_targets() for testability
/// and modularity.
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

/// Build list of overlay targets based on overlay mode
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
            let mut exclusions = config.compute_effective_exclusions();

            // Fold the active platform's overlay policy in. The base-OS trees it
            // keeps read-only or treats as immutable (`/usr`, `/bin`, `/sbin`,
            // `/lib*` on FHS; the core roots on NixOS) are not overlay targets,
            // and the pseudo-filesystems plus the hidden-root mount are never
            // overlaid. Carrying these as platform data (rather than the former
            // unconditional `/bin`,`/usr` retain hack) keeps a NixOS-only
            // exclusion from leaking onto Debian and vice versa.
            let policy = crate::platform::detect_platform(fs)?.overlay_policy();
            exclusions.extend(policy.overlay_exclusions());
            if !config.hidden_volume_root.as_os_str().is_empty() {
                exclusions.push(config.hidden_volume_root.clone());
            }

            // Apply exclusion filtering (separate helper for clarity)
            let targets = apply_exclusion_filter(all_dirs, &exclusions);

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

/// Derive the persistent upper and work directories for a target on the hidden
/// volume.
///
/// The layout is single-sourced here so overlay creation and `reset-upper`
/// always agree: the upper lives at `<hidden_root>/<dir>` and the work directory
/// at `<hidden_root>/.work/<dir>`, where `<dir>` is the target's final path
/// component.
pub(crate) fn derive_upper_work_paths(
    target: &Path,
    hidden_volume_root: &Path,
) -> Result<(PathBuf, PathBuf)> {
    let dir_name = target.file_name().ok_or_else(|| {
        NailsError::ConfigError(format!(
            "Cannot extract directory name from target: {}",
            target.display()
        ))
    })?;

    let upper = hidden_volume_root.join(dir_name);
    let work = hidden_volume_root.join(".work").join(dir_name);
    Ok((upper, work))
}

/// Create overlay configuration for a target directory
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

    // Build upper and work paths from the single-sourced layout
    let (upper, work) = derive_upper_work_paths(target, hidden_volume_root)?;

    // Create the upper and work directories *beneath the hidden root* through the
    // symlink-safe path: a link or `..` planted under the root cannot redirect
    // these creations onto the decoy filesystem. The relatives below join back to
    // `{root}/.work`, `{root}/{dir_name}` and `{root}/.work/{dir_name}`.
    let work_relative = Path::new(".work").join(dir_name);
    fs.create_hidden_dir_all(hidden_volume_root, Path::new(".work"))?;
    fs.create_hidden_dir_all(hidden_volume_root, Path::new(dir_name))?;
    fs.create_hidden_dir_all(hidden_volume_root, &work_relative)?;

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
