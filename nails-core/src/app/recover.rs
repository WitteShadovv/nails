// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The `recover` operation: remove what an interrupted entry left behind.
//!
//! An activation that dies after building `/run/nextroot` leaves a populated
//! next root, its runtime directory and the transition drop-in behind. Recovery
//! detaches the next root, removes the runtime pieces, reloads the service
//! manager, resets the state and closes the hidden backend's device-mapper
//! devices where nothing uses them. It never reboots and refuses in the hidden
//! session (where the upper is the live root).

use std::path::Path;

use nails_api::ExitStatus;
use nails_teardown::whole_root::ret::BackendClose;
use serde::Serialize;

pub use crate::manager::RecoverError;
use crate::manager::SessionRecovery;
use crate::session::RealEntryHost;
use crate::{NailsManager, RealFilesystem, RuntimeEnv};

/// The machine-readable payload of a recovery.
#[derive(Debug, Serialize)]
pub struct RecoverData {
    /// `clean` (nothing to do) or `rolled_back`.
    pub outcome: &'static str,
    /// Mounts still below `/run/nextroot`.
    pub remaining_mounts: Vec<String>,
    /// The hidden backend's devices that were still open.
    pub backend: Vec<BackendData>,
}

/// One hidden-backend device the recovery touched.
#[derive(Debug, Serialize)]
pub struct BackendData {
    /// The device-mapper name.
    pub name: String,
    /// `closed`, or `in_use` (left open: its key is still in RAM).
    pub state: &'static str,
}

/// A completed recovery: the payload to render and the exit code it earns.
pub struct RecoverOutcome {
    /// The machine-readable payload.
    pub data: RecoverData,
    /// [`ExitStatus::Ok`] once nothing is left, or [`ExitStatus::DegradedReboot`]
    /// when a mount stayed below `/run/nextroot`.
    pub exit: ExitStatus,
}

/// Run a recovery for the given configuration override.
///
/// Loads the teardown configuration (never refusing, falling back off a failed
/// hidden volume), takes the emergency state lock for the duration, and runs the
/// recovery. A refusal says why ([`RecoverError`]: the hidden session, or an
/// entry under way), so the front end names the next step that fits it.
pub fn recover(
    env: &RuntimeEnv,
    config_override: Option<&Path>,
) -> Result<RecoverOutcome, RecoverError> {
    let (config, source) = super::config::load_config_for_teardown(config_override);
    tracing::info!("Recovery using the {}", source.describe());
    let state_path = config.state_file_path.clone();
    let hidden_root = config.hidden_volume_root.clone();
    let mut manager =
        NailsManager::new(RealFilesystem, config, state_path.clone()).with_runtime_env(env.clone());
    let _state_lock = super::lock::acquire_for_emergency(&hidden_root, &state_path);

    let recovery = manager.recover_session(&RealEntryHost)?;
    let data = recover_data(&recovery);
    let exit = if data.remaining_mounts.is_empty() {
        ExitStatus::Ok
    } else {
        ExitStatus::DegradedReboot
    };
    Ok(RecoverOutcome { data, exit })
}

/// The `data` payload for `recovery`.
pub fn recover_data(recovery: &SessionRecovery) -> RecoverData {
    let (name, remaining, backend): (_, &[std::path::PathBuf], &[(String, BackendClose)]) =
        match recovery {
            SessionRecovery::Clean => ("clean", &[], &[]),
            SessionRecovery::RolledBack { remaining, backend } => {
                ("rolled_back", remaining, backend)
            }
        };
    RecoverData {
        outcome: name,
        remaining_mounts: remaining.iter().map(|p| p.display().to_string()).collect(),
        backend: backend
            .iter()
            .map(|(name, state)| BackendData {
                name: name.clone(),
                state: match state {
                    BackendClose::Closed => "closed",
                    BackendClose::InUse => "in_use",
                },
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_clean_recovery_is_an_empty_payload() {
        let data = recover_data(&SessionRecovery::Clean);
        assert_eq!(
            serde_json::to_value(&data).unwrap(),
            serde_json::json!({"outcome": "clean", "remaining_mounts": [], "backend": []})
        );
    }

    #[test]
    fn a_rollback_reports_leftover_mounts_and_each_backend_device() {
        let data = recover_data(&SessionRecovery::RolledBack {
            remaining: vec!["/run/nextroot/home".into()],
            backend: vec![
                ("hidden-crypt".to_string(), BackendClose::Closed),
                ("hidden-loop".to_string(), BackendClose::InUse),
            ],
        });
        assert_eq!(
            serde_json::to_value(&data).unwrap(),
            serde_json::json!({
                "outcome": "rolled_back",
                "remaining_mounts": ["/run/nextroot/home"],
                "backend": [
                    {"name": "hidden-crypt", "state": "closed"},
                    {"name": "hidden-loop", "state": "in_use"},
                ],
            })
        );
    }
}
