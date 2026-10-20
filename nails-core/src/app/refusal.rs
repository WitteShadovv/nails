// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! A refused hidden root as the machine-readable error body every command
//! shares. The text and the codes come from the attach gate
//! ([`crate::hidden_root::refusal`]); a front end renders this body as the JSON
//! error or the human error.

use std::path::Path;

use nails_api::ErrorBody;

use crate::hidden_root::Refusal;

/// The error body of a refused root. `exe` is the running program, named in the
/// hint when it lies under the root.
pub fn refusal_body(refusal: &Refusal, exe: Option<&Path>) -> ErrorBody {
    ErrorBody::new(refusal.code(), refusal.message()).with_hint(refusal.hint(exe).join("\n"))
}
