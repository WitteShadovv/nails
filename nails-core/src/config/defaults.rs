//! Default value functions and derivation logic

use std::path::PathBuf;

use super::colors::ColorSchemeConfig;
use super::overlay::{ExtendedOverlayConfig, OverlayConfig, OverlayMode};
use super::types::{Config, DEFAULT_HIDDEN_VOLUME_ROOT};

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
                    let parent_path = parent.to_path_buf();

                    // TEST SAFETY GUARD (Layer 4): Detect build directories
                    // Prevents tests from treating target/debug/ as a valid hidden volume
                    // This is a defense-in-depth measure to protect against accidental
                    // system operations during test execution.
                    let path_str = parent_path.to_string_lossy();
                    if path_str.contains("/target/debug")
                        || path_str.contains("/target/release")
                        || path_str.contains("/target/llvm-cov-target")
                        || path_str.starts_with("/nix/store")
                    {
                        tracing::warn!(
                            "Binary path not suitable for deriving hidden volume (build/store location): {}. \
                             Refusing to derive hidden volume root from build artifacts. \
                             Falling back to {}",
                            parent_path.display(),
                            DEFAULT_HIDDEN_VOLUME_ROOT
                        );
                        return PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT);
                    }

                    tracing::debug!(
                        "Derived hidden volume root from binary location: {}",
                        parent_path.display()
                    );
                    parent_path
                }
                None => {
                    tracing::warn!(
                        "Binary at root directory (no parent): {}. Falling back to {}",
                        canonical_path.display(),
                        DEFAULT_HIDDEN_VOLUME_ROOT
                    );
                    PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT)
                }
            }
        }
        Err(e) => {
            tracing::warn!(
                "Failed to determine binary location: {}. Falling back to {}",
                e,
                DEFAULT_HIDDEN_VOLUME_ROOT
            );
            PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT)
        }
    }
}

// Serde default functions for new user-configurable fields
pub(super) fn default_hidden_volume_root() -> PathBuf {
    derive_hidden_volume_root()
}

pub(super) fn default_state_file_path() -> PathBuf {
    // This will be overridden in load() to use the actual hidden_volume_root
    PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join("state.json")
}

pub(super) fn default_minimum_space_mb() -> u64 {
    500
}

pub(super) fn default_clear_history() -> bool {
    true
}

pub(super) fn default_preflight_checks() -> bool {
    true
}

pub(super) fn default_verbosity() -> String {
    "info".to_string()
}

pub(super) fn default_color_output() -> bool {
    true
}

pub(super) fn default_verify_on_deactivate() -> bool {
    true
}

pub(super) fn default_milestone_tips() -> bool {
    true
}

pub(super) fn default_show_opsec_reminders() -> bool {
    true
}

pub(super) fn default_log_path() -> PathBuf {
    // Default will be derived from hidden_volume_root in builder
    PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join("logs")
}

pub(super) fn default_max_log_size_mb() -> u64 {
    10
}

pub(super) fn default_retention_days() -> u64 {
    7
}

impl Default for Config {
    /// Create default configuration with sensible test defaults
    ///
    /// Uses binary-derived hidden volume root for zero-config operation.
    /// Includes default overlays for /home, /etc, and /var for VM testing.
    fn default() -> Self {
        // Auto-derive hidden volume root from binary location (Story 14.9)
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
            minimum_space_mb: 500, // Default minimum: 500 MB
            // Ephemeral overlays DISABLED - using regular overlays instead (Story 4.11)
            extended_overlays: ExtendedOverlayConfig {
                enabled: false,
                directories: vec![],
            },
            // Dynamic overlay configuration (Story 14.10)
            overlay_mode: OverlayMode::Auto,
            overlay_exclusions: vec![],
            overlay_exclusions_remove: vec![],
            // User-configurable options with smart defaults (Epic 10)
            clear_history: default_clear_history(),
            preflight_checks: default_preflight_checks(),
            default_verbosity: default_verbosity(),
            color_output: default_color_output(),
            verify_on_deactivate: default_verify_on_deactivate(),
            milestone_tips: default_milestone_tips(),
            show_opsec_reminders: default_show_opsec_reminders(),
            log_path: hidden_root.join("logs"), // Derived from hidden_volume_root
            max_log_size_mb: default_max_log_size_mb(),
            retention_days: default_retention_days(),
            color_scheme: ColorSchemeConfig::default(),
        }
    }
}
