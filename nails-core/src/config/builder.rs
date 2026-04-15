//! Builder pattern for Config construction

use std::path::PathBuf;

use super::colors::ColorSchemeConfig;
use super::defaults::{
    default_clear_history, default_color_output, default_max_log_size_mb, default_milestone_tips,
    default_preflight_checks, default_retention_days, default_show_opsec_reminders,
    default_verbosity, default_verify_on_deactivate, derive_hidden_volume_root,
};
use super::overlay::{ExtendedOverlayConfig, OverlayConfig, OverlayMode};
use super::types::Config;

/// Builder for Config with validation and smart defaults
///
/// Provides fluent API for constructing Config instances with validation.
/// Required fields must be set before calling `build()`.
///
/// # Example
///
/// ```rust
/// use nails_core::config::ConfigBuilder;
/// use std::path::PathBuf;
///
/// let config = ConfigBuilder::new()
///     .hidden_volume_path(PathBuf::from("/mnt/hidden-volume"))
///     .clear_history(false)
///     .default_verbosity("debug")
///     .build()
///     .expect("Failed to build config");
/// ```
#[derive(Debug, Default, Clone)]
pub struct ConfigBuilder {
    hidden_volume_root: Option<PathBuf>,
    state_file_path: Option<PathBuf>,
    overlays: Option<Vec<OverlayConfig>>,
    minimum_space_mb: Option<u64>,
    extended_overlays: Option<ExtendedOverlayConfig>,
    overlay_mode: Option<OverlayMode>,
    overlay_exclusions: Option<Vec<PathBuf>>,
    overlay_exclusions_remove: Option<Vec<PathBuf>>,
    clear_history: Option<bool>,
    preflight_checks: Option<bool>,
    default_verbosity: Option<String>,
    color_output: Option<bool>,
    verify_on_deactivate: Option<bool>,
    milestone_tips: Option<bool>,
    show_opsec_reminders: Option<bool>,
    log_path: Option<PathBuf>,
    max_log_size_mb: Option<u64>,
    retention_days: Option<u64>,
    color_scheme: Option<ColorSchemeConfig>,
}

impl ConfigBuilder {
    /// Create a new ConfigBuilder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the hidden volume root path (required)
    ///
    /// This is the only required field. All other fields have smart defaults.
    pub fn hidden_volume_path(mut self, path: PathBuf) -> Self {
        self.hidden_volume_root = Some(path);
        self
    }

    /// Set the state file path
    ///
    /// Default: `{hidden_volume_root}/state.json`
    pub fn state_file_path(mut self, path: PathBuf) -> Self {
        self.state_file_path = Some(path);
        self
    }

    /// Set overlay configurations
    ///
    /// Default: empty list
    pub fn overlays(mut self, overlays: Vec<OverlayConfig>) -> Self {
        self.overlays = Some(overlays);
        self
    }

    /// Set minimum space in megabytes
    ///
    /// Default: 500 MB
    pub fn minimum_space_mb(mut self, mb: u64) -> Self {
        self.minimum_space_mb = Some(mb);
        self
    }

    /// Set extended overlay configuration
    ///
    /// Default: disabled
    pub fn extended_overlays(mut self, config: ExtendedOverlayConfig) -> Self {
        self.extended_overlays = Some(config);
        self
    }

    /// Set whether to clear shell history during deactivation
    ///
    /// Default: `true`
    pub fn clear_history(mut self, enabled: bool) -> Self {
        self.clear_history = Some(enabled);
        self
    }

    /// Set whether to run preflight checks before activation
    ///
    /// Default: `true`
    pub fn preflight_checks(mut self, enabled: bool) -> Self {
        self.preflight_checks = Some(enabled);
        self
    }

    /// Set default verbosity level for logging
    ///
    /// Common values: "quiet", "info", "debug"
    ///
    /// Default: `"info"`
    pub fn default_verbosity(mut self, level: &str) -> Self {
        self.default_verbosity = Some(level.to_string());
        self
    }

    /// Set whether to use colored output in terminal
    ///
    /// Default: `true`
    pub fn color_output(mut self, enabled: bool) -> Self {
        self.color_output = Some(enabled);
        self
    }

    /// Set whether to run verify command after deactivation
    ///
    /// Default: `true`
    pub fn verify_on_deactivate(mut self, enabled: bool) -> Self {
        self.verify_on_deactivate = Some(enabled);
        self
    }

    /// Set whether to show milestone tips during operations
    ///
    /// Default: `true`
    pub fn milestone_tips(mut self, enabled: bool) -> Self {
        self.milestone_tips = Some(enabled);
        self
    }

    /// Set whether to show OpSec reminders based on uptime thresholds
    ///
    /// Default: `true`
    pub fn show_opsec_reminders(mut self, enabled: bool) -> Self {
        self.show_opsec_reminders = Some(enabled);
        self
    }

    /// Set log file directory path
    ///
    /// Default: `{hidden_volume_root}/logs`
    pub fn log_path(mut self, path: PathBuf) -> Self {
        self.log_path = Some(path);
        self
    }

    /// Set maximum log file size in megabytes before rotation
    ///
    /// Default: 10 MB
    pub fn max_log_size_mb(mut self, size: u64) -> Self {
        self.max_log_size_mb = Some(size);
        self
    }

    /// Set number of days to retain log files
    ///
    /// Default: 7 days
    pub fn retention_days(mut self, days: u64) -> Self {
        self.retention_days = Some(days);
        self
    }

    /// Set terminal color scheme configuration
    ///
    /// Default: enabled with dark navy background
    pub fn color_scheme(mut self, config: ColorSchemeConfig) -> Self {
        self.color_scheme = Some(config);
        self
    }

    /// Build the Config with validation and smart defaults
    ///
    /// # Errors
    ///
    /// Returns `NailsError::ConfigError` if required fields are missing.
    pub fn build(self) -> crate::error::Result<Config> {
        // Use explicit value if set, otherwise derive from binary (Story 14.9)
        // Priority order: explicit value > binary-derived > DEFAULT_HIDDEN_VOLUME_ROOT
        let hidden_volume_root = self
            .hidden_volume_root
            .unwrap_or_else(derive_hidden_volume_root);

        // Apply smart defaults for optional fields
        let state_file_path = self
            .state_file_path
            .unwrap_or_else(|| hidden_volume_root.join("state.json"));

        let overlays = self.overlays.unwrap_or_default();

        let minimum_space_mb = self.minimum_space_mb.unwrap_or(500);

        let extended_overlays = self.extended_overlays.unwrap_or_default();

        let overlay_mode = self.overlay_mode.unwrap_or_default();

        let overlay_exclusions = self.overlay_exclusions.unwrap_or_default();

        let overlay_exclusions_remove = self.overlay_exclusions_remove.unwrap_or_default();

        let clear_history = self.clear_history.unwrap_or_else(default_clear_history);

        let preflight_checks = self
            .preflight_checks
            .unwrap_or_else(default_preflight_checks);

        let default_verbosity = self.default_verbosity.unwrap_or_else(default_verbosity);

        let color_output = self.color_output.unwrap_or_else(default_color_output);

        let verify_on_deactivate = self
            .verify_on_deactivate
            .unwrap_or_else(default_verify_on_deactivate);

        let milestone_tips = self.milestone_tips.unwrap_or_else(default_milestone_tips);

        let show_opsec_reminders = self
            .show_opsec_reminders
            .unwrap_or_else(default_show_opsec_reminders);

        // Derive log_path from hidden_volume_root if not specified
        let log_path = self
            .log_path
            .unwrap_or_else(|| hidden_volume_root.join("logs"));

        let max_log_size_mb = self.max_log_size_mb.unwrap_or_else(default_max_log_size_mb);

        let retention_days = self.retention_days.unwrap_or_else(default_retention_days);

        let color_scheme = self.color_scheme.unwrap_or_default();

        Ok(Config {
            hidden_volume_root,
            state_file_path,
            overlays,
            minimum_space_mb,
            extended_overlays,
            overlay_mode,
            overlay_exclusions,
            overlay_exclusions_remove,
            clear_history,
            preflight_checks,
            default_verbosity,
            color_output,
            verify_on_deactivate,
            milestone_tips,
            show_opsec_reminders,
            log_path,
            max_log_size_mb,
            retention_days,
            color_scheme,
            nixos_flake: None,
        })
    }
}
