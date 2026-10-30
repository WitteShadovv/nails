// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Serde data-transfer types shared by the machine-readable renderers.
//!
//! The wire contract renders enums as `snake_case` names or tagged objects,
//! never as Rust `Debug` strings, so the JSON stays stable if the internal
//! types change. The CLI maps its domain state onto these shapes.

use serde::{Deserialize, Serialize};

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

/// The override a refused check accepts for one run: the CLI flag that turns
/// that refusal into a warning. A check names it only on a failure the flag
/// covers. Every other failure stands whatever flag is given, so a front end
/// offers an override only where a check names one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Allowable {
    /// `--allow-persistent-decoy`: the decoy keeps a persistent record of the
    /// session.
    PersistentDecoy,
    /// `--allow-decoy-storage`: the hidden root lives on storage the decoy
    /// uses.
    DecoyStorage,
    /// `--allow-discards`: discards are enabled over the hidden volume.
    Discards,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_override_goes_by_its_snake_case_name_and_no_other() {
        for (allowable, name) in [
            (Allowable::PersistentDecoy, "persistent_decoy"),
            (Allowable::DecoyStorage, "decoy_storage"),
            (Allowable::Discards, "discards"),
        ] {
            let json = format!("\"{name}\"");
            assert_eq!(serde_json::to_string(&allowable).unwrap(), json);
            assert_eq!(serde_json::from_str::<Allowable>(&json).unwrap(), allowable);
        }
        assert!(serde_json::from_str::<Allowable>("\"no_preflight\"").is_err());
    }
}
