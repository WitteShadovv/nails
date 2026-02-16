//! Terminal color scheme management via OSC ANSI escape sequences
//!
//! This module provides functions to generate OSC (Operating System Command)
//! escape sequences for changing terminal colors when entering or leaving
//! the hidden environment.
//!
//! # OSC Escape Sequences
//!
//! - OSC 10 - Set foreground color
//! - OSC 11 - Set background color
//! - OSC 110 - Reset foreground to default
//! - OSC 111 - Reset background to default
//! - OSC 104 - Reset palette to default
//!
//! Uses BEL (`\x07`) terminator for maximum terminal compatibility.
//!
//! # Terminal Compatibility
//!
//! These sequences are supported by most modern terminals:
//! - kitty, alacritty, foot
//! - gnome-terminal, konsole
//! - xterm, urxvt
//! - iTerm2, Terminal.app (macOS)
//!
//! Terminals that don't support OSC sequences silently ignore them.
//!
//! # Example
//!
//! ```rust
//! use nails_core::shell::color_scheme::{apply_hidden_color_scheme, apply_decoy_color_scheme};
//! use nails_core::config::ColorSchemeConfig;
//!
//! let config = ColorSchemeConfig::default();
//!
//! // Enter hidden environment - dark navy theme
//! let hidden_sequences = apply_hidden_color_scheme(&config);
//! print!("{}", hidden_sequences);
//!
//! // Return to decoy environment - reset to terminal defaults
//! let decoy_sequences = apply_decoy_color_scheme(&config);
//! print!("{}", decoy_sequences);
//! ```

use crate::config::ColorSchemeConfig;

/// Apply hidden environment color scheme
///
/// Generates OSC escape sequences to change terminal colors to the "hidden"
/// profile configured in the ColorSchemeConfig. This provides visual feedback
/// when entering the hidden environment.
///
/// # Arguments
///
/// * `config` - Color scheme configuration
///
/// # Returns
///
/// String containing OSC escape sequences to set terminal colors.
/// Returns empty string if color scheme is disabled.
///
/// # OSC Sequences Generated
///
/// - `\x1b]11;{background}\x07` - Set background color
/// - `\x1b]10;{foreground}\x07` - Set foreground color
///
/// # Example
///
/// ```rust
/// use nails_core::shell::color_scheme::apply_hidden_color_scheme;
/// use nails_core::config::ColorSchemeConfig;
///
/// let config = ColorSchemeConfig::default();
/// let sequences = apply_hidden_color_scheme(&config);
///
/// // sequences contains: "\x1b]11;#1a1a2e\x07\x1b]10;#e0e0e0\x07"
/// assert!(!sequences.is_empty());
/// ```
pub fn apply_hidden_color_scheme(config: &ColorSchemeConfig) -> String {
    // Check if color scheme is enabled
    if !config.enabled {
        return String::new();
    }

    // Generate OSC sequences for hidden environment
    let background_seq = format!("\x1b]11;{}\x07", config.hidden.background);
    let foreground_seq = format!("\x1b]10;{}\x07", config.hidden.foreground);

    format!("{}{}", background_seq, foreground_seq)
}

/// Apply decoy environment color scheme (reset to defaults)
///
/// Generates OSC escape sequences to reset terminal colors to their defaults
/// when returning to the decoy environment. This removes the visual indicator
/// of the hidden environment.
///
/// # Arguments
///
/// * `config` - Color scheme configuration
///
/// # Returns
///
/// String containing OSC reset sequences.
/// Returns empty string if color scheme is disabled or reset is disabled.
///
/// # OSC Sequences Generated
///
/// When `config.decoy.reset` is true:
/// - `\x1b]111\x07` - Reset background to default
/// - `\x1b]110\x07` - Reset foreground to default
/// - `\x1b]104\x07` - Reset color palette to default
///
/// # Example
///
/// ```rust
/// use nails_core::shell::color_scheme::apply_decoy_color_scheme;
/// use nails_core::config::ColorSchemeConfig;
///
/// let config = ColorSchemeConfig::default();
/// let sequences = apply_decoy_color_scheme(&config);
///
/// // sequences contains: "\x1b]111\x07\x1b]110\x07\x1b]104\x07"
/// assert!(!sequences.is_empty());
/// ```
pub fn apply_decoy_color_scheme(config: &ColorSchemeConfig) -> String {
    // Check if color scheme is enabled
    if !config.enabled {
        return String::new();
    }

    // Check if decoy reset is enabled
    if !config.decoy.reset {
        return String::new();
    }

    // Generate OSC reset sequences
    let reset_background = "\x1b]111\x07"; // Reset background to default
    let reset_foreground = "\x1b]110\x07"; // Reset foreground to default
    let reset_palette = "\x1b]104\x07"; // Reset color palette to default

    format!("{}{}{}", reset_background, reset_foreground, reset_palette)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ColorProfile, ColorSchemeConfig, DecoyProfile};

    #[test]
    fn test_apply_hidden_color_scheme_default_config() {
        let config = ColorSchemeConfig::default();
        let sequences = apply_hidden_color_scheme(&config);

        // Should contain OSC sequences for background and foreground
        assert!(sequences.contains("\x1b]11;#1a1a2e\x07")); // Background
        assert!(sequences.contains("\x1b]10;#e0e0e0\x07")); // Foreground
    }

    #[test]
    fn test_apply_hidden_color_scheme_custom_colors() {
        let config = ColorSchemeConfig {
            enabled: true,
            hidden: ColorProfile {
                background: "#2e3440".to_string(),
                foreground: "#d8dee9".to_string(),
            },
            decoy: DecoyProfile::default(),
        };

        let sequences = apply_hidden_color_scheme(&config);

        assert!(sequences.contains("\x1b]11;#2e3440\x07"));
        assert!(sequences.contains("\x1b]10;#d8dee9\x07"));
    }

    #[test]
    fn test_apply_hidden_color_scheme_disabled() {
        let config = ColorSchemeConfig {
            enabled: false,
            hidden: ColorProfile::default(),
            decoy: DecoyProfile::default(),
        };

        let sequences = apply_hidden_color_scheme(&config);

        // Should return empty string when disabled
        assert_eq!(sequences, "");
    }

    #[test]
    fn test_apply_decoy_color_scheme_default_config() {
        let config = ColorSchemeConfig::default();
        let sequences = apply_decoy_color_scheme(&config);

        // Should contain OSC reset sequences
        assert!(sequences.contains("\x1b]111\x07")); // Reset background
        assert!(sequences.contains("\x1b]110\x07")); // Reset foreground
        assert!(sequences.contains("\x1b]104\x07")); // Reset palette
    }

    #[test]
    fn test_apply_decoy_color_scheme_disabled() {
        let config = ColorSchemeConfig {
            enabled: false,
            hidden: ColorProfile::default(),
            decoy: DecoyProfile::default(),
        };

        let sequences = apply_decoy_color_scheme(&config);

        // Should return empty string when disabled
        assert_eq!(sequences, "");
    }

    #[test]
    fn test_apply_decoy_color_scheme_reset_disabled() {
        let config = ColorSchemeConfig {
            enabled: true,
            hidden: ColorProfile::default(),
            decoy: DecoyProfile { reset: false },
        };

        let sequences = apply_decoy_color_scheme(&config);

        // Should return empty string when reset is disabled
        assert_eq!(sequences, "");
    }

    #[test]
    fn test_hidden_sequence_format() {
        let config = ColorSchemeConfig::default();
        let sequences = apply_hidden_color_scheme(&config);

        // Verify format: background first, then foreground
        let expected = "\x1b]11;#1a1a2e\x07\x1b]10;#e0e0e0\x07";
        assert_eq!(sequences, expected);
    }

    #[test]
    fn test_decoy_sequence_format() {
        let config = ColorSchemeConfig::default();
        let sequences = apply_decoy_color_scheme(&config);

        // Verify format: background reset, foreground reset, palette reset
        let expected = "\x1b]111\x07\x1b]110\x07\x1b]104\x07";
        assert_eq!(sequences, expected);
    }

    #[test]
    fn test_hidden_uses_bel_terminator() {
        let config = ColorSchemeConfig::default();
        let sequences = apply_hidden_color_scheme(&config);

        // Verify BEL (\x07) terminator is used for compatibility
        assert!(sequences.contains("\x07"));
        // Verify ST (\x1b\\) terminator is NOT used
        assert!(!sequences.contains("\x1b\\"));
    }

    #[test]
    fn test_decoy_uses_bel_terminator() {
        let config = ColorSchemeConfig::default();
        let sequences = apply_decoy_color_scheme(&config);

        // Verify BEL (\x07) terminator is used for compatibility
        assert!(sequences.contains("\x07"));
        // Verify ST (\x1b\\) terminator is NOT used
        assert!(!sequences.contains("\x1b\\"));
    }
}
