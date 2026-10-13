// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Serde data-transfer helpers shared by the machine-readable renderers.
//!
//! The wire contract renders enums as `snake_case` names or tagged objects,
//! never as Rust `Debug` strings, so the JSON stays stable if the internal
//! types change.

use nails_core::{LoadOutcome, SystemState};
use serde::Serialize;

/// The machine name of a recorded state.
pub fn system_state_kind(state: &SystemState) -> &'static str {
    state.label()
}

/// The human label of a recorded state.
pub fn system_state_label(state: &SystemState) -> &'static str {
    match state {
        SystemState::Inactive => "Inactive",
        SystemState::Active { .. } => "Active",
        SystemState::Degraded { .. } => "Degraded",
    }
}

/// The recorded state as a tagged object.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StateJson {
    /// No session recorded.
    Inactive,
    /// A session recorded.
    Active,
    /// A degraded session recorded.
    Degraded {
        /// Why.
        reason: String,
    },
    /// The state file could not be trusted.
    Unknown {
        /// Why.
        reason: String,
    },
}

impl StateJson {
    /// The recorded state, or `Unknown` when the file could not be trusted.
    pub fn from_report(state: &SystemState, load_outcome: &LoadOutcome) -> Self {
        match load_outcome {
            LoadOutcome::Corrupt => StateJson::Unknown {
                reason: "state file is corrupt or has no integrity digest".to_string(),
            },
            LoadOutcome::Unreadable => StateJson::Unknown {
                reason: "state file could not be read".to_string(),
            },
            LoadOutcome::Loaded | LoadOutcome::Missing => match state {
                SystemState::Inactive => StateJson::Inactive,
                SystemState::Active { .. } => StateJson::Active,
                SystemState::Degraded { reason, .. } => StateJson::Degraded {
                    reason: reason.clone(),
                },
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn states_serialize_as_tagged_objects() {
        let degraded = SystemState::Degraded {
            since: chrono::Utc::now(),
            reason: "x".into(),
        };
        let json =
            serde_json::to_value(StateJson::from_report(&degraded, &LoadOutcome::Loaded)).unwrap();
        assert_eq!(json["kind"], "degraded");
        assert_eq!(json["reason"], "x");
        let unknown = StateJson::from_report(&SystemState::Inactive, &LoadOutcome::Corrupt);
        assert_eq!(serde_json::to_value(unknown).unwrap()["kind"], "unknown");
        assert_eq!(system_state_kind(&SystemState::Inactive), "inactive");
        assert_eq!(system_state_label(&degraded), "Degraded");
    }
}
