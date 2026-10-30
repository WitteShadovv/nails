// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The catalog rows. Data only: no logic lives here.
//!
//! The rows are split by kind across sibling files — session residue in
//! [`session`] and, for the decoy's own services and mechanisms that act
//! across a switch, in [`decoy_services`]; setup traces in [`setup`] — and
//! concatenated here, session classes first, into the one [`CATALOG`] the
//! catalog reads. Keeping the split inside a `rows/` folder lets the catalog's
//! own `mod.rs` keep a single `mod rows;` and `pub use rows::CATALOG;`, so
//! adding a kind or a file touches only this file and never the catalog
//! module.
//!
//! Adding a row: give it a detector or a reason there is none, a VM test or a
//! reason there is none, and a doc anchor that exists. Then regenerate the doc
//! tables (`REGENERATE_CATALOG_DOCS=1 cargo test -p nails-forensics residue_catalog`)
//! and commit the result. The unit tests in `tests.rs` enforce all of it.

use super::ResidueClass;

mod decoy_services;
mod session;
mod setup;

/// Every class of residue, session classes first, then setup traces.
///
/// Assembled at compile time from the per-file row lists so the catalog stays a
/// single `&'static [ResidueClass]`: the consumers, the docs generator and the
/// tests read one slice regardless of how the rows are filed.
pub const CATALOG: &[ResidueClass] = &{
    const PARTS: [&[ResidueClass]; 3] = [session::ROWS, decoy_services::ROWS, setup::ROWS];
    const LEN: usize = {
        let mut len = 0;
        let mut part = 0;
        while part < PARTS.len() {
            len += PARTS[part].len();
            part += 1;
        }
        len
    };
    // ResidueClass is Copy, so the array starts from any row and is then
    // overwritten in full, each part's rows after the previous part's.
    let mut rows = [session::ROWS[0]; LEN];
    let mut at = 0;
    let mut part = 0;
    while part < PARTS.len() {
        let mut i = 0;
        while i < PARTS[part].len() {
            rows[at] = PARTS[part][i];
            at += 1;
            i += 1;
        }
        part += 1;
    }
    rows
};
