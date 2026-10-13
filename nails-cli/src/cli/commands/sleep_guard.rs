// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Hidden `sleep-guard` command: hold a logind inhibitor for the session.
//!
//! Not an operator-facing command. It runs from the RAM-backed runtime copy as
//! a runtime unit of the hidden session (installed in `/run` by the entry
//! transition) when `sleep_policy.mode` is `block` or `teardown`, and runs for
//! the life of the session. In `teardown` mode an imminent sleep powers the
//! machine off instead: a session kept in RAM behind a lock screen is what the
//! policy exists to prevent. It is marked `hide = true` so it never
//! appears in help, and it reads its configuration from the `/run` copy so it
//! keeps working even after the hidden volume is gone.

use std::path::Path;

use nails_core::{RealFilesystem, runtime_copy, sleep_guard};

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
pub fn execute(
    _settings: &OutputSettings,
    env: &nails_core::RuntimeEnv,
    config_override: Option<&Path>,
) -> ExitStatus {
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

    let _ = env;
    let on_prepare_for_sleep = || {
        tracing::warn!("The host is about to sleep; powering off instead");
        super::emergency::run_hot_path_with(
            nails_teardown::whole_root::emergency::Finish::Poweroff,
        );
    };

    if let Err(e) = sleep_guard::run_guard(mode, on_prepare_for_sleep) {
        tracing::warn!(error = %e, "Sleep guard exiting; the session runs without sleep protection");
    }

    ExitStatus::Ok
}
