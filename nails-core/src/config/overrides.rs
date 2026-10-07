// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! CLI override handling

use super::types::{CliOverrides, Config};

impl Config {
    /// Apply CLI flag overrides to this config
    ///
    /// Priority order: CLI flags > Config file > Defaults.
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
    ///     nixos_flake: Some("/etc/nixos#host".to_string()),
    /// };
    ///
    /// config.apply_cli_overrides(&overrides);
    /// assert_eq!(config.nixos_flake.as_deref(), Some("/etc/nixos#host"));
    /// ```
    pub fn apply_cli_overrides(&mut self, overrides: &CliOverrides) {
        if let Some(ref v) = overrides.nixos_flake {
            self.nixos_flake = Some(v.clone());
        }
    }
}

impl CliOverrides {
    /// Top-level config keys this set of overrides replaces.
    pub(super) fn overridden_keys(&self) -> Vec<&'static str> {
        let mut keys = Vec::new();
        if self.nixos_flake.is_some() {
            keys.push("nixos_flake");
        }
        keys
    }
}
