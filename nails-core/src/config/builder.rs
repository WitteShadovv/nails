//! Builder pattern for Config construction

use std::path::PathBuf;

use super::colors::ColorSchemeConfig;
use super::defaults::{
    default_clear_history, default_minimum_space_mb, default_show_opsec_reminders,
    derive_hidden_volume_root,
};
use super::overlay::{OverlayConfig, OverlayMode};
use super::types::Config;

/// Builder for Config with validation and smart defaults
///
/// Provides a fluent API for constructing Config instances. Every field is
/// optional; `build()` fills in defaults and then validates every path.
///
/// # Example
///
/// ```rust
/// use nails_core::config::ConfigBuilder;
/// use std::path::PathBuf;
///
/// let config = ConfigBuilder::new()
///     .hidden_volume_root(PathBuf::from("/mnt/hidden-volume"))
///     .clear_history(false)
///     .build()
///     .expect("Failed to build config");
/// ```
#[derive(Debug, Default, Clone)]
pub struct ConfigBuilder {
    hidden_volume_root: Option<PathBuf>,
    state_file_path: Option<PathBuf>,
    overlays: Option<Vec<OverlayConfig>>,
    minimum_space_mb: Option<u64>,
    overlay_mode: Option<OverlayMode>,
    overlay_exclusions: Option<Vec<PathBuf>>,
    overlay_exclusions_remove: Option<Vec<PathBuf>>,
    allow_leaky_exclusions: Option<Vec<PathBuf>>,
    clear_history: Option<bool>,
    show_opsec_reminders: Option<bool>,
    log_path: Option<PathBuf>,
    color_scheme: Option<ColorSchemeConfig>,
}

impl ConfigBuilder {
    /// Create a new ConfigBuilder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the hidden volume root path
    ///
    /// Default: derived from the binary location. All other paths default to
    /// locations under this root.
    pub fn hidden_volume_root(mut self, path: PathBuf) -> Self {
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

    /// Set the overlay target selection mode
    ///
    /// Default: `OverlayMode::Auto`
    pub fn overlay_mode(mut self, mode: OverlayMode) -> Self {
        self.overlay_mode = Some(mode);
        self
    }

    /// Set additional overlay exclusions (Auto mode)
    ///
    /// Default: empty list
    pub fn overlay_exclusions(mut self, exclusions: Vec<PathBuf>) -> Self {
        self.overlay_exclusions = Some(exclusions);
        self
    }

    /// Set default exclusions to remove (Auto mode)
    ///
    /// Default: empty list
    pub fn overlay_exclusions_remove(mut self, removals: Vec<PathBuf>) -> Self {
        self.overlay_exclusions_remove = Some(removals);
        self
    }

    /// Set the load-bearing directories that may be excluded (Auto mode)
    ///
    /// Default: empty list, so excluding a load-bearing directory is refused
    pub fn allow_leaky_exclusions(mut self, allowed: Vec<PathBuf>) -> Self {
        self.allow_leaky_exclusions = Some(allowed);
        self
    }

    /// Set whether to clear shell history during deactivation
    ///
    /// Default: `true`
    pub fn clear_history(mut self, enabled: bool) -> Self {
        self.clear_history = Some(enabled);
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

    /// Set terminal color scheme configuration
    ///
    /// Default: enabled with dark navy background
    pub fn color_scheme(mut self, config: ColorSchemeConfig) -> Self {
        self.color_scheme = Some(config);
        self
    }

    /// Build the Config, applying defaults for every unset field
    ///
    /// # Errors
    ///
    /// [`NailsError::UnsafeConfigPath`](crate::NailsError::UnsafeConfigPath)
    /// when a path breaks a rule of [`Config::validate_paths`]: for example a
    /// relative or symlinked hidden volume root, a `..` segment, a `,` or `:`
    /// in an overlay path, or a state file outside the hidden volume root.
    pub fn build(self) -> crate::error::Result<Config> {
        // Priority order: explicit value > binary-derived > DEFAULT_HIDDEN_VOLUME_ROOT
        let hidden_volume_root = self
            .hidden_volume_root
            .unwrap_or_else(derive_hidden_volume_root);

        // Apply smart defaults for optional fields
        let state_file_path = self
            .state_file_path
            .unwrap_or_else(|| hidden_volume_root.join("state.json"));

        let overlays = self.overlays.unwrap_or_default();

        let minimum_space_mb = self
            .minimum_space_mb
            .unwrap_or_else(default_minimum_space_mb);

        let overlay_mode = self.overlay_mode.unwrap_or_default();

        let overlay_exclusions = self.overlay_exclusions.unwrap_or_default();

        let overlay_exclusions_remove = self.overlay_exclusions_remove.unwrap_or_default();

        let allow_leaky_exclusions = self.allow_leaky_exclusions.unwrap_or_default();

        let clear_history = self.clear_history.unwrap_or_else(default_clear_history);

        let show_opsec_reminders = self
            .show_opsec_reminders
            .unwrap_or_else(default_show_opsec_reminders);

        // Derive log_path from hidden_volume_root if not specified
        let log_path = self
            .log_path
            .unwrap_or_else(|| hidden_volume_root.join("logs"));

        let color_scheme = self.color_scheme.unwrap_or_default();

        let config = Config {
            hidden_volume_root,
            state_file_path,
            overlays,
            minimum_space_mb,
            overlay_mode,
            overlay_exclusions,
            overlay_exclusions_remove,
            allow_leaky_exclusions,
            clear_history,
            show_opsec_reminders,
            log_path,
            loaded_config_path: None,
            color_scheme,
            persona: super::persona::PersonaConfig::default(),
            prompt_label: String::new(),
            nixos_flake: None,
            nixos_switch_required: true,
            risky_services: None,
            accept_persistent_decoy: false,
        };
        config.validate_paths()?;
        Ok(config)
    }
}
