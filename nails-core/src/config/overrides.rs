//! CLI override handling

use super::types::{CliOverrides, Config};

impl Config {
    /// Apply CLI flag overrides to this config
    ///
    /// Priority order: CLI flags > Config file > Defaults (UXR26)
    /// Only overrides values that are explicitly set (Some).
    ///
    /// # Arguments
    ///
    /// * `overrides` - CLI overrides to apply
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::{Config, CliOverrides};
    ///
    /// let mut config = Config::default();
    /// let overrides = CliOverrides {
    ///     preflight_checks: Some(false),
    ///     verbosity: Some("debug".to_string()),
    ///     ..Default::default()
    /// };
    ///
    /// config.apply_cli_overrides(&overrides);
    /// assert!(!config.preflight_checks);
    /// assert_eq!(config.default_verbosity, "debug");
    /// ```
    pub fn apply_cli_overrides(&mut self, overrides: &CliOverrides) {
        if let Some(v) = overrides.preflight_checks {
            self.preflight_checks = v;
        }
        if let Some(v) = overrides.clear_history {
            self.clear_history = v;
        }
        if let Some(v) = &overrides.verbosity {
            self.default_verbosity = v.clone();
        }
        if let Some(v) = overrides.color_output {
            self.color_output = v;
        }
        if let Some(v) = overrides.verify_on_deactivate {
            self.verify_on_deactivate = v;
        }
        if let Some(ref v) = overrides.nixos_flake {
            self.nixos_flake = Some(v.clone());
        }
    }

    /// Load config from file and apply CLI overrides
    ///
    /// This is the primary entry point for CLI applications.
    ///
    /// # Priority Order (UXR26)
    /// 1. CLI flags (highest priority)
    /// 2. Config file values
    /// 3. Default values (lowest priority)
    ///
    /// # Arguments
    ///
    /// * `config_path` - Path to YAML config file (uses defaults if missing)
    /// * `overrides` - CLI argument overrides
    ///
    /// # Errors
    ///
    /// Returns `NailsError::ConfigError` for malformed YAML or missing required fields.
    /// Missing config file is not an error (uses defaults).
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::{Config, CliOverrides};
    /// use std::path::PathBuf;
    ///
    /// let overrides = CliOverrides {
    ///     preflight_checks: Some(false),
    ///     ..Default::default()
    /// };
    ///
    /// let config = Config::from_file_and_cli(
    ///     &PathBuf::from("~/.nails/config.yaml"),
    ///     &overrides,
    /// ).expect("Failed to load config");
    /// ```
    pub fn from_file_and_cli(
        config_path: &std::path::Path,
        overrides: &CliOverrides,
    ) -> crate::error::Result<Self> {
        let mut config = Self::load_or_default(config_path)?;
        config.apply_cli_overrides(overrides);
        Ok(config)
    }
}
