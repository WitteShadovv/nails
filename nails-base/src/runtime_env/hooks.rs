// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Test-only override knobs carried in the startup snapshot.
//!
//! The E2E harness marks a run as a test runtime and enables the root gate
//! through a few variables. They are read once, with the rest of the
//! [`RuntimeEnv`](super::RuntimeEnv), and passed down.
//!
//! This module only exists in builds that carry the `test-hooks` feature (and
//! this crate's own unit tests); a shipped binary carries none of these names.

use std::ffi::OsString;

/// The test-only override knobs, each the verbatim value of its variable.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TestHooks {
    /// `NAILS_TEST_RUNTIME` — skip real host interaction.
    pub test_runtime: Option<OsString>,
    /// `NAILS_TEST_ENFORCE_ROOT` — enable the root gate in a test build.
    pub enforce_root: Option<OsString>,
    /// `NAILS_TEST_ADMIT_WINDOW` — let `nails gui` open the window on a decoy
    /// without its posture and desktop gate, which no test host passes.
    pub admit_window: Option<OsString>,
    /// `NAILS_TEST_USER_RUNTIME_BASE` — the directory `nails gui` looks for the
    /// operator's runtime directory in, instead of `/run/user`.
    pub user_runtime_base: Option<OsString>,
}

impl TestHooks {
    /// Read the knobs from the live process environment (part of
    /// [`RuntimeEnv::from_process_env`](super::RuntimeEnv::from_process_env)).
    pub(super) fn from_process_env() -> Self {
        let os = |key: &str| std::env::var_os(key);
        Self {
            test_runtime: os("NAILS_TEST_RUNTIME"),
            enforce_root: os("NAILS_TEST_ENFORCE_ROOT"),
            admit_window: os("NAILS_TEST_ADMIT_WINDOW"),
            user_runtime_base: os("NAILS_TEST_USER_RUNTIME_BASE"),
        }
    }
}
