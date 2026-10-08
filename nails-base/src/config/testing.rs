// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The deterministic test configuration.
//!
//! This module is compiled for this crate's own tests and, through the
//! `test-support` feature, for downstream test code. None of it reaches the
//! release binary. The manager-building `TestWorld` is in `nails-core`.

use std::path::PathBuf;

use super::defaults::default_show_opsec_reminders;
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
            minimum_space_mb: 500,
            rebuild_space_mb: 4096,
            show_opsec_reminders: default_show_opsec_reminders(),
            log_path: hidden_root.join("logs"), // Derived from hidden_volume_root
            loaded_config_path: None,
            persona: super::persona::PersonaConfig::default(),
            backend_watch: super::backend_watch::BackendWatchConfig::default(),
            session_mounts: super::session_mounts::SessionMountsConfig::default(),
            nixos_flake: None,
            accept_persistent_decoy: false,
            sleep_policy: super::types::SleepPolicyConfig::default(),
        }
    }
}
