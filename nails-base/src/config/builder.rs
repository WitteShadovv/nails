// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Builder pattern for Config construction

use std::path::PathBuf;

use super::defaults::{
    default_minimum_space_mb, default_rebuild_space_mb, default_show_opsec_reminders,
    derive_hidden_volume_root,
};
use super::types::Config;

/// Builder for Config with validation and smart defaults
///
/// Provides a fluent API for constructing Config instances. Every field is
/// optional; `build()` fills in defaults and then validates every path.
///
/// # Example
///
/// ```rust
/// use nails_base::config::ConfigBuilder;
/// use std::path::PathBuf;
///
/// let config = ConfigBuilder::new()
///     .hidden_volume_root(PathBuf::from("/mnt/hidden-volume"))
///     .minimum_space_mb(750)
///     .build()
///     .expect("Failed to build config");
/// ```
#[derive(Debug, Default, Clone)]
pub struct ConfigBuilder {
    hidden_volume_root: Option<PathBuf>,
    state_file_path: Option<PathBuf>,
    minimum_space_mb: Option<u64>,
    rebuild_space_mb: Option<u64>,
    show_opsec_reminders: Option<bool>,
    log_path: Option<PathBuf>,
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

    /// Set minimum space in megabytes
    ///
    /// Default: 500 MB
    pub fn minimum_space_mb(mut self, mb: u64) -> Self {
        self.minimum_space_mb = Some(mb);
        self
    }

    /// Set the free-space floor used when a NixOS rebuild is expected
    ///
    /// Default: 4096 MB (4 GiB)
    pub fn rebuild_space_mb(mut self, mb: u64) -> Self {
        self.rebuild_space_mb = Some(mb);
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

    /// Build the Config, applying defaults for every unset field
    ///
    /// # Errors
    ///
    /// [`NailsError::UnsafeConfigPath`](crate::NailsError::UnsafeConfigPath)
    /// when a path breaks a rule of [`Config::validate_paths`]: for example a
    /// relative or symlinked hidden volume root, a `..` segment, a `,` or `:`
    /// in a layer path, or a state file outside the hidden volume root.
    pub fn build(self) -> crate::error::Result<Config> {
        // Priority order: explicit value > binary-derived > DEFAULT_HIDDEN_VOLUME_ROOT
        let hidden_volume_root = self
            .hidden_volume_root
            .unwrap_or_else(derive_hidden_volume_root);

        // Apply smart defaults for optional fields
        let state_file_path = self
            .state_file_path
            .unwrap_or_else(|| hidden_volume_root.join("state.json"));

        let minimum_space_mb = self
            .minimum_space_mb
            .unwrap_or_else(default_minimum_space_mb);

        let rebuild_space_mb = self
            .rebuild_space_mb
            .unwrap_or_else(default_rebuild_space_mb);

        let show_opsec_reminders = self
            .show_opsec_reminders
            .unwrap_or_else(default_show_opsec_reminders);

        // Derive log_path from hidden_volume_root if not specified
        let log_path = self
            .log_path
            .unwrap_or_else(|| hidden_volume_root.join("logs"));

        let config = Config {
            hidden_volume_root,
            state_file_path,
            minimum_space_mb,
            rebuild_space_mb,
            show_opsec_reminders,
            log_path,
            loaded_config_path: None,
            persona: super::persona::PersonaConfig::default(),
            backend_watch: super::backend_watch::BackendWatchConfig::default(),
            nixos_flake: None,
            accept_persistent_decoy: false,
            sleep_policy: super::types::SleepPolicyConfig::default(),
        };
        config.validate_paths()?;
        Ok(config)
    }
}
