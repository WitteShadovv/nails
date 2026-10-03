//! Default value functions and derivation logic

use std::path::PathBuf;

use super::colors::ColorSchemeConfig;
use super::overlay::{OverlayConfig, OverlayMode};
use super::persona::PersonaConfig;
use super::types::{Config, DEFAULT_HIDDEN_VOLUME_ROOT, get_default_hidden_volume_root};

/// Derive hidden volume root from binary location
///
/// Automatically determines the hidden volume root by extracting the parent
/// directory of the nails binary (after symlink resolution). This enables
/// zero-config operation where users can simply place the binary on the
/// hidden volume and everything "just works" without explicit configuration.
///
/// # Returns
///
/// The parent directory of the nails binary (after symlink resolution).
/// Falls back to `DEFAULT_HIDDEN_VOLUME_ROOT` if binary path cannot be determined.
///
/// # Algorithm
///
/// 1. Call `std::env::current_exe()` to get binary path
/// 2. Call `.canonicalize()` to resolve all symlinks
/// 3. Extract parent directory with `.parent()`
/// 4. Return parent, or fallback to `DEFAULT_HIDDEN_VOLUME_ROOT` on any error
///
/// # Logging
///
/// - DEBUG: Logs detected binary path and canonical path
/// - INFO: Logs successfully derived path when successful
/// - WARN: Logs fallback when `current_exe()` fails
/// - WARN: Logs fallback when `canonicalize()` fails (uses original path)
/// - WARN: Logs fallback when `parent()` returns None (binary at root)
///
/// # Example
///
/// Binary at `/mnt/hidden-volume/nails` → returns `/mnt/hidden-volume`
/// Binary at `/custom/nails` → returns `/custom`
/// Symlink at `/usr/local/bin/nails` → `/mnt/hidden-volume/nails` → returns `/mnt/hidden-volume`
///
/// # Errors
///
/// Does not return `Result`. All errors handled internally with fallback.
/// This design ensures config loading never fails due to binary path resolution.
///
/// # Priority Order
///
/// This function provides the middle-priority default:
/// 1. Config file value (explicit user intent - highest priority)
/// 2. **Binary-derived default (smart inference - this function)**
/// 3. `DEFAULT_HIDDEN_VOLUME_ROOT` constant (hardcoded fallback - lowest priority)
pub fn derive_hidden_volume_root() -> PathBuf {
    match std::env::current_exe() {
        Ok(exe_path) => {
            tracing::debug!("Binary path detected: {}", exe_path.display());

            // Resolve symlinks
            let canonical_path = exe_path.canonicalize().unwrap_or_else(|e| {
                tracing::warn!(
                    "Failed to canonicalize binary path {:?}: {}. Using original path.",
                    exe_path,
                    e
                );
                exe_path.clone()
            });

            tracing::debug!("Canonical binary path: {}", canonical_path.display());

            // Extract parent directory
            match canonical_path.parent() {
                Some(parent) => {
                    // The derived root is the binary's parent directory. Writes are
                    // guarded at runtime by the hidden-volume attach check, so there
                    // is no path-substring heuristic here: an operator who installs
                    // the binary under an unusual path (including one that merely
                    // looks like a build directory) still gets a usable default.
                    let parent_path = parent.to_path_buf();
                    tracing::debug!(
                        "Derived hidden volume root from binary location: {}",
                        parent_path.display()
                    );
                    parent_path
                }
                None => {
                    let fallback = get_default_hidden_volume_root();
                    tracing::warn!(
                        "Binary at root directory (no parent): {}. Falling back to {}",
                        canonical_path.display(),
                        fallback
                    );
                    PathBuf::from(fallback)
                }
            }
        }
        Err(e) => {
            let fallback = get_default_hidden_volume_root();
            tracing::warn!(
                "Failed to determine binary location: {}. Falling back to {}",
                e,
                fallback
            );
            PathBuf::from(fallback)
        }
    }
}

// Serde default functions
pub(super) fn default_hidden_volume_root() -> PathBuf {
    derive_hidden_volume_root()
}

pub(super) fn default_state_file_path() -> PathBuf {
    // Replaced by `{hidden_volume_root}/state.json` when a config file omits it
    PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join("state.json")
}

pub(super) fn default_minimum_space_mb() -> u64 {
    500
}

pub(super) fn default_rebuild_space_mb() -> u64 {
    4096
}

pub(super) fn default_clear_history() -> bool {
    true
}

pub(super) fn default_show_opsec_reminders() -> bool {
    true
}

pub(super) fn default_nixos_switch_required() -> bool {
    true
}

pub(super) fn default_accept_persistent_decoy() -> bool {
    false
}

pub(super) fn default_log_path() -> PathBuf {
    // Replaced by `{hidden_volume_root}/logs` when a config file omits it
    PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join("logs")
}

impl Default for Config {
    /// Create default configuration with sensible test defaults
    ///
    /// Uses binary-derived hidden volume root for zero-config operation.
    /// Includes default overlays for /home, /etc, and /var for VM testing.
    fn default() -> Self {
        // Derive the hidden volume root from the binary location
        let hidden_root = derive_hidden_volume_root();

        Self {
            hidden_volume_root: hidden_root.clone(),
            state_file_path: hidden_root.join("state.json"),
            overlays: vec![
                OverlayConfig {
                    name: "boot".to_string(),
                    lower: PathBuf::from("/boot"),
                    upper: hidden_root.join("boot"),
                    work: hidden_root.join(".work/boot"),
                    target: PathBuf::from("/boot"),
                },
                OverlayConfig {
                    name: "home".to_string(),
                    lower: PathBuf::from("/home"),
                    upper: hidden_root.join("home"),
                    work: hidden_root.join(".work/home"),
                    target: PathBuf::from("/home"),
                },
                OverlayConfig {
                    name: "etc".to_string(),
                    lower: PathBuf::from("/etc"),
                    upper: hidden_root.join("etc"),
                    work: hidden_root.join(".work/etc"),
                    target: PathBuf::from("/etc"),
                },
                OverlayConfig {
                    name: "var".to_string(),
                    lower: PathBuf::from("/var"),
                    upper: hidden_root.join("var"),
                    work: hidden_root.join(".work/var"),
                    target: PathBuf::from("/var"),
                },
            ],
            minimum_space_mb: default_minimum_space_mb(),
            rebuild_space_mb: default_rebuild_space_mb(),
            overlay_mode: OverlayMode::Auto,
            overlay_exclusions: vec![],
            overlay_exclusions_remove: vec![],
            allow_leaky_exclusions: vec![],
            clear_history: default_clear_history(),
            show_opsec_reminders: default_show_opsec_reminders(),
            log_path: hidden_root.join("logs"), // Derived from hidden_volume_root
            loaded_config_path: None,
            color_scheme: ColorSchemeConfig::default(),
            persona: PersonaConfig::default(),
            backend_watch: super::backend_watch::BackendWatchConfig::default(),
            prompt_label: String::new(),
            nixos_flake: None,
            nixos_switch_required: true,
            risky_services: None,
            accept_persistent_decoy: false,
        }
    }
}
