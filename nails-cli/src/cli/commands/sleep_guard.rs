// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Hidden `sleep-guard` command: hold a logind inhibitor for the session.
//!
//! Not an operator-facing command. It is launched at activation from the
//! RAM-backed runtime copy as a transient systemd unit (see
//! [`nails_core::sleep_guard`]) when `sleep_policy.mode` is `block` or `teardown`,
//! and runs for the life of the session. It is marked `hide = true` so it never
//! appears in help, and it reads its configuration from the `/run` copy so it
//! keeps working even after the hidden volume is gone.

use std::path::Path;

use nails_core::{NailsManager, RealFilesystem, runtime_copy, sleep_guard};

use crate::cli::output::{ExitStatus, OutputSettings};

/// Execute the sleep guard.
///
/// Reads the mirrored configuration from the `/run` copy, then holds the logind
/// inhibitor the configured mode calls for. In `teardown` mode the guard runs the
/// bounded emergency teardown when the host is about to sleep.
///
/// Always exits [`ExitStatus::Ok`]: like the backend watcher, this is a
/// best-effort safety net, so a missing copy or an unreachable bus is a logged
/// no-op rather than an error dialog.
pub fn execute(_settings: &OutputSettings, config_override: Option<&Path>) -> ExitStatus {
    let filesystem = RealFilesystem;

    // Prefer the configuration mirrored into the runtime copy; the real config
    // file lives on the hidden volume, which a teardown may be racing against.
    let config = match runtime_copy::read_config_copy(&filesystem) {
        Ok(Some(config)) => config,
        _ => super::load_config_or_defaults(config_override).into_config(),
    };

    let mode = config.sleep_policy.mode;
    if !mode.runs_guard() {
        tracing::debug!("Sleep policy runs no guard; exiting");
        return ExitStatus::Ok;
    }

    tracing::info!(?mode, "Sleep guard started");

    let emergency_config = config.clone();
    let on_prepare_for_sleep = move || {
        let state_path = emergency_config.state_file_path.clone();
        let mut manager = NailsManager::new(RealFilesystem, emergency_config.clone(), state_path);
        if let Err(e) = manager.emergency_deactivate() {
            tracing::error!(error = %e, "Emergency teardown on suspend failed");
        }
    };

    if let Err(e) = sleep_guard::run_guard(mode, on_prepare_for_sleep) {
        tracing::warn!(error = %e, "Sleep guard exiting; the session runs without sleep protection");
    }

    ExitStatus::Ok
}
