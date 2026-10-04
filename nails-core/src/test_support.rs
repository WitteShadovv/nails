// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Shared test helpers that are not tied to one module.
//!
//! Compiled for this crate's own tests and, through the `test-support` feature,
//! for downstream test code in `nails-cli` and this crate's integration tests.
//! None of it reaches the release binary.

pub mod env;

pub use env::EnvGuard;
