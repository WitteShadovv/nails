// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Overlay filesystem configuration
//!
//! This module provides configuration structures for overlay filesystem management:
//! explicit overlay definitions and the overlay target selection mode.

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
#[serde(deny_unknown_fields)]
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
