//! Serde data-transfer types shared by the machine-readable renderers.
//!
//! These are deliberately separate from the on-disk and in-memory types in
//! `nails_core`: the wire contract renders enums as tagged `{"kind": …}` objects
//! in `snake_case`, never as Rust `Debug` strings, so the JSON output stays
//! stable even if the internal types are refactored.

use nails_core::status::VerificationStatus;
use nails_core::{DecoyWriter, LoadOutcome, SystemState};
use serde::Serialize;

/// The stable `snake_case` name for a system state, used wherever a state needs
/// to appear in machine-readable output as a short label.
pub fn system_state_kind(state: &SystemState) -> &'static str {
    match state {
        SystemState::Inactive => "inactive",
        SystemState::Activating { .. } => "activating",
        SystemState::Active { .. } => "active",
        SystemState::Deactivating { .. } => "deactivating",
        SystemState::Degraded { .. } => "degraded",
    }
}

/// A short human label for a system state (Title Case), for text output.
pub fn system_state_label(state: &SystemState) -> &'static str {
    match state {
        SystemState::Inactive => "Inactive",
        SystemState::Activating { .. } => "Activating",
        SystemState::Active { .. } => "Active",
        SystemState::Deactivating { .. } => "Deactivating",
        SystemState::Degraded { .. } => "Degraded",
    }
}

/// The system state as a tagged object in machine output.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StateJson {
    /// Decoy system in use.
    Inactive,
    /// Activation in progress.
    Activating,
    /// Hidden environment mounted.
    Active,
    /// Deactivation in progress.
    Deactivating,
    /// Teardown left the system partly dismantled.
    Degraded {
        /// Why teardown could not complete.
        reason: String,
        /// Mount points that may still be live.
        remaining_mounts: Vec<String>,
    },
    /// The state file could not be trusted, so the real state is unknown.
    Unknown {
        /// Why the state is unknown.
        reason: String,
    },
}

impl StateJson {
    /// Build the wire state from a report's state and how its file loaded. An
    /// untrusted load (corrupt or unreadable) renders as `unknown`, never as a
    /// confident claim of the safe default.
    pub fn from_report(state: &SystemState, load_outcome: &LoadOutcome) -> Self {
        match load_outcome {
            LoadOutcome::Corrupt => StateJson::Unknown {
                reason:
                    "state file is corrupt or has no integrity digest; the real state is unknown"
                        .to_string(),
            },
            LoadOutcome::Unreadable => StateJson::Unknown {
                reason: "state file could not be read; the real state is unknown".to_string(),
            },
            LoadOutcome::Loaded | LoadOutcome::Missing => StateJson::from_state(state),
        }
    }

    /// Build the wire state directly from a system state (trusted load).
    pub fn from_state(state: &SystemState) -> Self {
        match state {
            SystemState::Inactive => StateJson::Inactive,
            SystemState::Activating { .. } => StateJson::Activating,
            SystemState::Active { .. } => StateJson::Active,
            SystemState::Deactivating { .. } => StateJson::Deactivating,
            SystemState::Degraded {
                reason,
                remaining_mounts,
                ..
            } => StateJson::Degraded {
                reason: reason.clone(),
                remaining_mounts: remaining_mounts
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect(),
            },
        }
    }
}

/// Overlay verification as a tagged object in machine output.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum VerificationJson {
    /// Overlays match the state file.
    Verified,
    /// Overlay mismatch, with the specific errors.
    Mismatch {
        /// Human-readable descriptions of each mismatch.
        errors: Vec<String>,
    },
    /// Transitional state - verification not meaningful.
    Skipped,
    /// No overlays to verify.
    NotApplicable,
}

impl From<&VerificationStatus> for VerificationJson {
    fn from(status: &VerificationStatus) -> Self {
        match status {
            VerificationStatus::Verified => VerificationJson::Verified,
            VerificationStatus::Mismatch { errors } => VerificationJson::Mismatch {
                errors: errors.clone(),
            },
            VerificationStatus::Skipped => VerificationJson::Skipped,
            VerificationStatus::NotApplicable => VerificationJson::NotApplicable,
        }
    }
}

/// A process still writing to the decoy, as reported by `activate` and
/// `status`.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct DecoyWriterJson {
    /// Process ID recorded at activation.
    pub pid: u32,
    /// Process name.
    pub name: String,
    /// Systemd service backing the process, when there is one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    /// Overlay targets it still writes to through the decoy.
    pub targets: Vec<String>,
}

impl From<&DecoyWriter> for DecoyWriterJson {
    fn from(writer: &DecoyWriter) -> Self {
        DecoyWriterJson {
            pid: writer.pid,
            name: writer.name.clone(),
            service: writer.service.clone(),
            targets: writer
                .targets
                .iter()
                .map(|target| target.display().to_string())
                .collect(),
        }
    }
}

/// The writers recorded in `state`, for machine output (empty unless Active).
pub fn decoy_writers_json(state: &SystemState) -> Vec<DecoyWriterJson> {
    match state {
        SystemState::Active { decoy_writers, .. } => {
            decoy_writers.iter().map(DecoyWriterJson::from).collect()
        }
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::path::PathBuf;

    #[test]
    fn decoy_writers_render_with_paths_as_strings() {
        let state = SystemState::Active {
            activated_at: Utc::now(),
            overlays: vec![PathBuf::from("/var")],
            decoy_writers: vec![
                DecoyWriter {
                    pid: 812,
                    name: "tail".to_string(),
                    service: None,
                    targets: vec![PathBuf::from("/var")],
                },
                DecoyWriter {
                    pid: 600,
                    name: "NetworkManager".to_string(),
                    service: Some("NetworkManager".to_string()),
                    targets: vec![PathBuf::from("/etc"), PathBuf::from("/var")],
                },
            ],
        };

        let value = serde_json::to_value(decoy_writers_json(&state)).unwrap();
        assert_eq!(
            value,
            serde_json::json!([
                {"pid": 812, "name": "tail", "targets": ["/var"]},
                {
                    "pid": 600,
                    "name": "NetworkManager",
                    "service": "NetworkManager",
                    "targets": ["/etc", "/var"]
                }
            ])
        );
    }

    #[test]
    fn decoy_writers_are_empty_outside_the_active_state() {
        assert!(decoy_writers_json(&SystemState::Inactive).is_empty());
    }

    #[test]
    fn active_state_renders_as_a_kind_object_not_a_debug_string() {
        let state = SystemState::Active {
            activated_at: Utc::now(),
            overlays: vec![PathBuf::from("/home")],
            decoy_writers: Vec::new(),
        };
        let json = StateJson::from_report(&state, &LoadOutcome::Loaded);
        let value = serde_json::to_value(&json).unwrap();
        assert_eq!(value["kind"], "active");
        assert!(value.get("activated_at").is_none(), "state is minimal");
    }

    #[test]
    fn corrupt_load_renders_as_unknown_with_reason() {
        let json = StateJson::from_report(&SystemState::Inactive, &LoadOutcome::Corrupt);
        let value = serde_json::to_value(&json).unwrap();
        assert_eq!(value["kind"], "unknown");
        assert!(value["reason"].as_str().unwrap().contains("corrupt"));
    }

    #[test]
    fn verification_mismatch_renders_snake_case_kind() {
        let status = VerificationStatus::Mismatch {
            errors: vec!["/etc not mounted".to_string()],
        };
        let value = serde_json::to_value(VerificationJson::from(&status)).unwrap();
        assert_eq!(value["kind"], "mismatch");
        assert_eq!(value["errors"][0], "/etc not mounted");
    }

    #[test]
    fn state_kinds_are_snake_case() {
        assert_eq!(system_state_kind(&SystemState::Inactive), "inactive");
        assert_eq!(
            system_state_kind(&SystemState::Active {
                activated_at: Utc::now(),
                overlays: vec![],
                decoy_writers: Vec::new(),
            }),
            "active"
        );
    }
}
