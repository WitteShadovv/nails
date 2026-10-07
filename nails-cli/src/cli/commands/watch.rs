// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Hidden `watch` command: the in-session backend watcher.
//!
//! This is not an operator-facing command. It runs from the RAM-backed runtime
//! copy as a runtime unit of the hidden session (installed in `/run` by the
//! entry transition) for the life of the session, polling the hidden backend
//! and alerting the operator the moment it fails. It is marked
//! `hide = true` so it never appears in help, and it keeps all of its state in the
//! `/run` copy so it keeps working even after the hidden volume is gone.

use std::path::Path;

use nails_core::notification::{Notification, send_immediate};
use nails_core::{RealFilesystem, runtime_copy, watcher};

use crate::cli::output::{ExitStatus, OutputSettings};

/// Execute the watcher.
///
/// Reads the mount manifest and the mirrored configuration from the `/run` copy,
/// then polls the backend on the configured interval. On a failed probe it alerts
/// the operator; it tears the session down on its own only when the operator
/// opted into `auto_emergency` and the failure outlasts the debounce window.
///
/// Always exits [`ExitStatus::Ok`]: the watcher is a best-effort safety net, so a
/// missing manifest (no activation wrote one) or an unreadable copy is a quiet
/// no-op rather than an error dialog.
pub fn execute(
    _settings: &OutputSettings,
    env: &nails_core::RuntimeEnv,
    config_override: Option<&Path>,
) -> ExitStatus {
    let filesystem = RealFilesystem;

    let manifest = match runtime_copy::read_manifest(&filesystem) {
        Ok(Some(manifest)) => manifest,
        Ok(None) => {
            tracing::debug!("No runtime manifest present; nothing to watch");
            return ExitStatus::Ok;
        }
        Err(e) => {
            tracing::warn!(error = %e, "Could not read the runtime manifest; watcher exiting");
            return ExitStatus::Ok;
        }
    };

    // Prefer the configuration mirrored into the runtime copy, since the real
    // config file lives on the hidden volume that may already be failing. Fall
    // back to the binary-relative config only if the copy cannot be read.
    let config = match runtime_copy::read_config_copy(&filesystem) {
        Ok(Some(config)) => config,
        _ => super::load_config_or_defaults(config_override).into_config(),
    };

    let watch_config = config.backend_watch.clone();
    if !watch_config.enabled {
        tracing::debug!("Backend watch disabled in config; watcher exiting");
        return ExitStatus::Ok;
    }

    tracing::info!(
        poll_interval_secs = watch_config.poll_interval_secs,
        auto_emergency = watch_config.auto_emergency,
        "Backend watcher started"
    );

    watcher::run_loop(
        &watch_config,
        || watcher::probe_backend(&filesystem, &manifest),
        || {
            if let Err(e) = send_immediate(&backend_alert(), env) {
                tracing::warn!(error = %e, "Could not deliver the backend-failure alert");
            }
        },
        || {
            tracing::warn!("Backend failure outlasted the debounce; running the emergency");
            super::emergency::run_hot_path_with(
                nails_teardown::whole_root::emergency::Finish::Return,
            );
        },
    );

    ExitStatus::Ok
}

/// The neutral desktop alert raised when the backend stops responding.
///
/// Worded so it reveals nothing about a hidden environment: to anyone watching
/// the screen it reads as an ordinary removable-storage warning.
fn backend_alert() -> Notification {
    Notification {
        title: "Storage unavailable".to_string(),
        body: "A mounted volume stopped responding. Save your work and reconnect it.".to_string(),
        urgency: "critical".to_string(),
        icon: Some("drive-harddisk".to_string()),
        created_at: chrono::Utc::now().to_rfc3339(),
    }
}
