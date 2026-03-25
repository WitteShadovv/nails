//! Overlay filesystem configuration
//!
//! This module provides configuration structures for overlay filesystem management,
//! including explicit overlay definitions and extended overlay configurations for
//! ephemeral (tmpfs-backed) overlays.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Overlay filesystem configuration
///
/// Defines the paths for a single overlay mount point. OverlayFS combines
/// multiple directories into a single view:
/// - **lower**: Read-only base layer (from decoy system)
/// - **upper**: Writable layer (on hidden volume)
/// - **work**: Work directory for overlay metadata
/// - **target**: Where the overlay is mounted
///
/// # Security Consideration
///
/// All writable layers (upper, work) MUST be on the hidden volume to prevent
/// forensic evidence from leaking to the decoy system.
///
/// # Example
///
/// ```rust
/// use nails_core::config::OverlayConfig;
/// use std::path::PathBuf;
///
/// let overlay = OverlayConfig {
///     name: "home".to_string(),
///     lower: PathBuf::from("/home"),
///     upper: PathBuf::from("/mnt/hidden-volume").join("overlays/home/upper"),
///     work: PathBuf::from("/mnt/hidden-volume").join("overlays/home/work"),
///     target: PathBuf::from("/home"),
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverlayConfig {
    /// Human-readable name for this overlay (e.g., "home", "etc")
    pub name: String,

    /// Lower directory (read-only base layer)
    pub lower: PathBuf,

    /// Upper directory (writable, on hidden volume)
    pub upper: PathBuf,

    /// Work directory (overlay metadata)
    pub work: PathBuf,

    /// Target mount point
    pub target: PathBuf,
}

impl Default for OverlayConfig {
    /// Create an empty overlay configuration for testing
    fn default() -> Self {
        Self {
            name: String::new(),
            lower: PathBuf::new(),
            upper: PathBuf::new(),
            work: PathBuf::new(),
            target: PathBuf::new(),
        }
    }
}

/// Overlay mode determines how overlay targets are selected
///
/// This enum controls whether NAILS automatically overlays all directories
/// under `/` (auto mode) or only explicitly configured directories (explicit mode).
///
/// # Modes
///
/// - **Auto**: Dynamic enumeration - discovers all directories under `/` at runtime
///   and overlays them (except exclusions). This is the default and recommended mode
///   for maximum forensic protection.
/// - **Explicit**: Legacy mode - only overlays directories explicitly listed in
///   the `overlays` configuration. Use this if you need fine-grained control.
///
/// # Security Implications
///
/// Auto mode provides maximum forensic artifact protection by ensuring no directory
/// on the base system can leak artifacts from the hidden environment. Explicit mode
/// may leave some directories unprotected if not configured correctly.
///
/// # Example
///
/// ```rust
/// use nails_core::config::OverlayMode;
///
/// let mode = OverlayMode::Auto;  // Default - overlay everything
/// let legacy = OverlayMode::Explicit;  // Only overlay configured dirs
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum OverlayMode {
    /// Auto mode: enumerate all directories under `/` and overlay them (except exclusions)
    /// This is the default and recommended mode for maximum forensic protection.
    #[default]
    Auto,

    /// Explicit mode: only overlay directories explicitly listed in `overlays` config
    /// This preserves legacy behavior for users who want fine-grained control.
    Explicit,
}

/// Extended overlay configuration for ephemeral (tmpfs-backed) overlays
///
/// Enables optional extended overlay mounting for high-activity directories
/// (/var, /tmp, /srv, /opt) with tmpfs-backed upper layers.
///
/// This strategy provides defense-in-depth against forensic analysis by:
/// - Storing runtime artifacts in RAM only (tmpfs)
/// - Destroying data immediately on unmount
/// - Preventing hidden storage capacity waste on transient files
///
/// # Forensic Rationale (Thesis Section 4.3.6)
///
/// - Persistent overlays (home/etc): Data on hidden encrypted storage
/// - Ephemeral overlays (var/tmp): Data in RAM, destroyed on unmount
/// - Different threat models for different data types
///
/// # Example
///
/// ```rust
/// use nails_core::config::ExtendedOverlayConfig;
///
/// let config = ExtendedOverlayConfig::default();
/// assert!(!config.enabled); // Disabled by default for safety
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtendedOverlayConfig {
    /// Whether extended overlays are enabled
    pub enabled: bool,

    /// List of ephemeral overlay directories
    #[serde(default)]
    pub directories: Vec<crate::config::EphemeralOverlayDir>,
}

impl Default for ExtendedOverlayConfig {
    /// Extended overlays disabled by default for safety
    ///
    /// User must explicitly opt-in via configuration.
    fn default() -> Self {
        Self {
            enabled: false,
            directories: vec![],
        }
    }
}
