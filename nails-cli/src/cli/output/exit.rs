// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The documented exit-code table, defined in [`nails_api::exit`].
//!
//! Re-exported here so the handlers keep returning
//! `crate::cli::output::exit::ExitStatus`; the numeric contract and the table
//! that pins it live in the `nails-api` crate, next to the JSON envelope.

pub use nails_api::exit::ExitStatus;
