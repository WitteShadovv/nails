//! Terminal color scheme configuration
//!
//! This module provides configuration structures for automatic terminal color scheme
//! switching when entering/leaving the hidden environment. Provides visual feedback
//! beyond the shell prompt.

use serde::{Deserialize, Serialize};

/// Color scheme configuration for terminal appearance changes
///
/// Controls automatic terminal color scheme switching when entering/leaving
/// the hidden environment. Provides visual feedback beyond the shell prompt.
///
/// # Example
///
/// ```rust
/// use nails_core::config::ColorSchemeConfig;
///
/// let config = ColorSchemeConfig::default();
/// assert!(config.enabled);
/// assert_eq!(config.hidden.background, "#1a1a2e");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColorSchemeConfig {
    /// Whether color scheme switching is enabled
    #[serde(default = "default_color_scheme_enabled")]
    pub enabled: bool,

    /// Hidden environment color profile
    #[serde(default)]
    pub hidden: ColorProfile,

    /// Decoy environment color profile
    #[serde(default)]
    pub decoy: DecoyProfile,
}

impl Default for ColorSchemeConfig {
    fn default() -> Self {
        Self {
            enabled: default_color_scheme_enabled(),
            hidden: ColorProfile::default(),
            decoy: DecoyProfile::default(),
        }
    }
}

/// Color profile for terminal appearance
///
/// Defines foreground and background colors using hex color format.
///
/// # Color Format
///
/// Colors should be specified in hex format (e.g., "#1a1a2e" or "#e0e0e0").
/// The format is expected to be compatible with OSC (Operating System Command)
/// escape sequences. Common formats include:
/// - 6-digit hex: `#1a1a2e` (recommended)
/// - 3-digit hex: `#abc` (may work with some terminals)
/// - RGB: `rgb:1a/1a/2e` (alternative OSC format)
///
/// # Validation
///
/// **No format validation is performed** on color values. Invalid formats
/// are passed directly to the terminal via OSC sequences. Terminals that
/// don't recognize the format will silently ignore the sequences (per AC8).
///
/// This design choice prioritizes:
/// 1. Flexibility: Support various terminal color formats without restriction
/// 2. Simplicity: No complex regex validation or color parsing needed
/// 3. Robustness: Invalid colors fail silently (terminal ignores them)
///
/// Users are responsible for providing valid hex color values. The default
/// values provide working examples.
///
/// # Example
///
/// ```rust
/// use nails_core::config::ColorProfile;
///
/// let profile = ColorProfile {
///     background: "#1a1a2e".to_string(),
///     foreground: "#e0e0e0".to_string(),
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColorProfile {
    /// Background color (hex format, e.g., "#1a1a2e")
    ///
    /// No validation is performed. Invalid formats are passed to the terminal
    /// and silently ignored if not supported.
    #[serde(default = "default_hidden_background")]
    pub background: String,

    /// Foreground color (hex format, e.g., "#e0e0e0")
    ///
    /// No validation is performed. Invalid formats are passed to the terminal
    /// and silently ignored if not supported.
    #[serde(default = "default_hidden_foreground")]
    pub foreground: String,
}

impl Default for ColorProfile {
    fn default() -> Self {
        Self {
            background: default_hidden_background(),
            foreground: default_hidden_foreground(),
        }
    }
}

/// Decoy profile configuration
///
/// Controls whether to reset terminal colors to defaults when
/// returning to decoy environment.
///
/// # Example
///
/// ```rust
/// use nails_core::config::DecoyProfile;
///
/// let profile = DecoyProfile::default();
/// assert!(profile.reset);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecoyProfile {
    /// Whether to reset terminal to defaults (true = use OSC reset sequences)
    #[serde(default = "default_decoy_reset")]
    pub reset: bool,
}

impl Default for DecoyProfile {
    fn default() -> Self {
        Self {
            reset: default_decoy_reset(),
        }
    }
}

// Serde default functions

fn default_color_scheme_enabled() -> bool {
    true
}

fn default_hidden_background() -> String {
    "#1a1a2e".to_string()
}

fn default_hidden_foreground() -> String {
    "#e0e0e0".to_string()
}

fn default_decoy_reset() -> bool {
    true
}
