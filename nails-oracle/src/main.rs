// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! # NAILS forensic oracle binary entry point
//!
//! The actual CLI logic is in lib.rs to allow for proper unit test coverage.

use std::process::ExitCode;

fn main() -> ExitCode {
    nails_oracle::run(std::env::args().skip(1))
}
