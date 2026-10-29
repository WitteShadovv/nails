// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! # nails-api
//!
//! The stable machine-readable contract the `nails` CLI writes under `--json`,
//! as types that depend on `serde` alone.
//!
//! One [`envelope`] shape carries every result, typed [`exit`] codes name every
//! outcome a script can branch on, the serde [`dto`] payloads are the
//! renderers' shared data-transfer types, the [`events`] stream is what a
//! front end watches while a long operation runs, and the [`protocol`] is how a
//! window drives the engine through its root helper. Keeping the contract in a
//! crate with no NAILS dependency lets a consumer link the wire types without
//! the whole tool and pins the contract as a small, reviewable surface
//! (`nails-core/tests/crate_graph.rs` holds the boundary).

// Unsafe code is denied workspace-wide (see the root Cargo.toml). Test code
// may use it freely; production code opts in per site with a scoped allow.
#![cfg_attr(test, allow(unsafe_code))]

pub mod dto;
pub mod envelope;
pub mod events;
pub mod exit;
pub mod protocol;

pub use dto::StateJson;
pub use envelope::{Envelope, ErrorBody, NextStep, SCHEMA_VERSION, error_envelope};
pub use events::{CheckOutcome, Event};
pub use exit::ExitStatus;
