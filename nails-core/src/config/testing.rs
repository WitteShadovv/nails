//! Test utilities for configuration

use std::path::PathBuf;

use super::colors::ColorSchemeConfig;
use super::defaults::{
    default_clear_history, default_color_output, default_max_log_size_mb, default_milestone_tips,
    default_preflight_checks, default_retention_days, default_show_opsec_reminders,
    default_verbosity, default_verify_on_deactivate,
};
use super::overlay::{ExtendedOverlayConfig, OverlayConfig, OverlayMode};
use super::types::{Config, DEFAULT_HIDDEN_VOLUME_ROOT};

impl Config {
    /// Create test configuration with disabled extended overlays
    ///
    /// This provides a minimal config for unit tests that don't need
    /// ephemeral overlay functionality. Extended overlays are disabled
    /// to avoid tests needing to set up pivot mount staging directories.
    ///
    /// For tests that specifically need extended overlays, configure
    /// them explicitly in the test setup.
    pub fn test_default() -> Self {
        let hidden_root = PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT);

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
            minimum_space_mb: 500,
            // Disabled for tests - avoids needing to set up pivot mount paths
            extended_overlays: ExtendedOverlayConfig {
                enabled: false,
                directories: vec![],
            },
            // Dynamic overlay configuration (Story 14.10)
            // Use Auto mode by default (test actual default behavior)
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
