// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The catalog rows. Data only: no logic lives here.
//!
//! The rows are split by kind across sibling files — session residue in
//! [`session`], setup traces in [`setup`] — and concatenated here, session
//! classes first, into the one [`CATALOG`] the catalog reads. Keeping the split
//! inside a `rows/` folder lets the catalog's own `mod.rs` keep a single
//! `mod rows;` and `pub use rows::CATALOG;`, so adding a kind touches only this
//! file and never the catalog module.
//!
//! Adding a row: give it a detector or a reason there is none, a VM test or a
//! reason there is none, and a doc anchor that exists. Then regenerate the doc
//! tables (`REGENERATE_CATALOG_DOCS=1 cargo test -p nails-forensics residue_catalog`)
//! and commit the result. The unit tests in `tests.rs` enforce all of it.

use super::ResidueClass;

mod session;
mod setup;

/// Every class of residue, session classes first, then setup traces.
///
/// Assembled at compile time from the per-kind row lists so the catalog stays a
/// single `&'static [ResidueClass]`: the consumers, the docs generator and the
/// tests read one slice regardless of how the rows are filed.
pub const CATALOG: &[ResidueClass] = &{
    const LEN: usize = session::ROWS.len() + setup::ROWS.len();
    // ResidueClass is Copy, so the array starts from any row and is then
    // overwritten in full, session rows first and setup rows after them.
    let mut rows = [session::ROWS[0]; LEN];
    let mut i = 0;
    while i < session::ROWS.len() {
        rows[i] = session::ROWS[i];
        i += 1;
    }
    let mut j = 0;
    while j < setup::ROWS.len() {
        rows[session::ROWS.len() + j] = setup::ROWS[j];
        j += 1;
    }
    rows
};
