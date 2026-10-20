// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Serde data-transfer helpers shared by the machine-readable renderers.
//!
//! [`StateJson`] (the recorded state as a tagged object) lives in
//! [`nails_api::dto`]; this module re-exports it and bridges the NAILS domain
//! types ([`SystemState`], [`LoadOutcome`]) onto the wire shapes.

use nails_core::{LoadOutcome, SystemState};

pub use nails_api::dto::StateJson;

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

/// The recorded state as a [`StateJson`], or `Unknown` when the file could not
/// be trusted.
pub fn state_json_from_report(state: &SystemState, load_outcome: &LoadOutcome) -> StateJson {
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
            serde_json::to_value(state_json_from_report(&degraded, &LoadOutcome::Loaded)).unwrap();
        assert_eq!(json["kind"], "degraded");
        assert_eq!(json["reason"], "x");
        let unknown = state_json_from_report(&SystemState::Inactive, &LoadOutcome::Corrupt);
        assert_eq!(serde_json::to_value(unknown).unwrap()["kind"], "unknown");
        assert_eq!(system_state_kind(&SystemState::Inactive), "inactive");
        assert_eq!(system_state_label(&degraded), "Degraded");
    }
}
