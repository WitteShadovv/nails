//! Test utilities for configuration

use std::path::PathBuf;

use super::colors::ColorSchemeConfig;
use super::defaults::{default_clear_history, default_show_opsec_reminders};
use super::overlay::{OverlayConfig, OverlayMode};
use super::types::{Config, DEFAULT_HIDDEN_VOLUME_ROOT};

impl Config {
    /// Create a deterministic test configuration
    ///
    /// Unlike `Config::default()`, the hidden volume root is the fixed
    /// `DEFAULT_HIDDEN_VOLUME_ROOT` rather than derived from the test binary.
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
            // Use Auto mode by default (test actual default behavior)
            overlay_mode: OverlayMode::Auto,
            overlay_exclusions: vec![],
            overlay_exclusions_remove: vec![],
            clear_history: default_clear_history(),
            show_opsec_reminders: default_show_opsec_reminders(),
            log_path: hidden_root.join("logs"), // Derived from hidden_volume_root
            loaded_config_path: None,
            color_scheme: ColorSchemeConfig::default(),
            prompt_label: String::new(),
            nixos_flake: None,
            risky_services: None,
        }
    }
}
