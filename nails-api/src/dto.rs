// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Serde data-transfer types shared by the machine-readable renderers.
//!
//! The wire contract renders enums as `snake_case` names or tagged objects,
//! never as Rust `Debug` strings, so the JSON stays stable if the internal
//! types change. The CLI maps its domain state onto these shapes.

use serde::Serialize;

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
