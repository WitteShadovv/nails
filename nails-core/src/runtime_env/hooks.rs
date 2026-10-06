// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Test-only override knobs carried in the startup snapshot.
//!
//! The E2E harness steers a `test-hooks` build through a handful of variables:
//! it pauses an activation or deactivation mid-flight, swaps `systemctl`,
//! `reboot` and `systemd-run` for recorders, marks a runtime as a test runtime,
//! and names the PIDs and services shell cleanup must spare. They used to be read
//! straight from the live environment wherever they were consulted; they are now
//! read once, with the rest of the [`RuntimeEnv`](super::RuntimeEnv), and passed
//! down (or reached through the installed snapshot by the leaf helpers). The
//! variable names and their meaning are unchanged, so the VM suite, which sets
//! them in the guest, behaves exactly as before.
//!
//! This module only exists in builds that carry the `test-hooks` feature (and
//! this crate's own unit tests); a shipped binary carries none of these names.

use std::ffi::OsString;
use std::path::PathBuf;

/// The test-only override knobs, each the verbatim value of its variable.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TestHooks {
    /// `NAILS_TEST_RUNTIME` — skip real host interaction.
    pub test_runtime: Option<OsString>,
    /// `NAILS_TEST_FORCE_ATTACHED` — bypass the attach-gate device comparison.
    pub force_attached: Option<OsString>,
    /// `NAILS_TEST_ENFORCE_ROOT` — enable the root gate in a test build.
    pub enforce_root: Option<OsString>,
    /// `NAILS_TEST_ACTIVATING_GATE_PATH` — pause after the Activating transition.
    pub activating_gate_path: Option<PathBuf>,
    /// `NAILS_TEST_ACTIVATING_ENTERED_PATH` — marker written when that gate engages.
    pub activating_entered_path: Option<PathBuf>,
    /// `NAILS_TEST_DEACTIVATING_GATE_PATH` — pause after the Deactivating transition.
    pub deactivating_gate_path: Option<PathBuf>,
    /// `NAILS_TEST_DEACTIVATING_ENTERED_PATH` — marker written when that gate engages.
    pub deactivating_entered_path: Option<PathBuf>,
    /// `NAILS_SYSTEMCTL_PATH` — fake `systemctl` for the post-teardown reboot.
    pub systemctl_path: Option<OsString>,
    /// `NAILS_REBOOT_PATH` — fake `reboot` for the post-teardown reboot.
    pub reboot_path: Option<OsString>,
    /// `NAILS_SYSTEMD_RUN_PATH` — fake `systemd-run` for the detach handoff.
    pub systemd_run_path: Option<OsString>,
    /// `NAILS_UNSAFE_REAL_OPS` — `1` opts a test build into real host operations.
    pub unsafe_real_ops: Option<String>,
    /// `NAILS_SHELL_CLEANUP_PROTECTED_PIDS` — PIDs shell cleanup must spare.
    pub shell_cleanup_protected_pids: Option<OsString>,
    /// `NAILS_SHELL_CLEANUP_PROTECTED_SERVICES` — services shell cleanup must spare.
    pub shell_cleanup_protected_services: Option<String>,
}

/// Name of the protected-PIDs knob, forwarded across the detach boundary.
pub const SHELL_CLEANUP_PROTECTED_PIDS_ENV: &str = "NAILS_SHELL_CLEANUP_PROTECTED_PIDS";
/// Name of the fake `systemd-run` knob, quoted in the refusal message.
pub const SYSTEMD_RUN_PATH_ENV: &str = "NAILS_SYSTEMD_RUN_PATH";

impl TestHooks {
    /// Read the knobs from the live process environment (part of
    /// [`RuntimeEnv::from_process_env`](super::RuntimeEnv::from_process_env)).
    pub(super) fn from_process_env() -> Self {
        let os = |key: &str| std::env::var_os(key);
        let path = |key: &str| std::env::var_os(key).map(PathBuf::from);
        Self {
            test_runtime: os("NAILS_TEST_RUNTIME"),
            force_attached: os("NAILS_TEST_FORCE_ATTACHED"),
            enforce_root: os("NAILS_TEST_ENFORCE_ROOT"),
            activating_gate_path: path("NAILS_TEST_ACTIVATING_GATE_PATH"),
            activating_entered_path: path("NAILS_TEST_ACTIVATING_ENTERED_PATH"),
            deactivating_gate_path: path("NAILS_TEST_DEACTIVATING_GATE_PATH"),
            deactivating_entered_path: path("NAILS_TEST_DEACTIVATING_ENTERED_PATH"),
            systemctl_path: os("NAILS_SYSTEMCTL_PATH"),
            reboot_path: os("NAILS_REBOOT_PATH"),
            systemd_run_path: os(SYSTEMD_RUN_PATH_ENV),
            unsafe_real_ops: std::env::var("NAILS_UNSAFE_REAL_OPS").ok(),
            shell_cleanup_protected_pids: os(SHELL_CLEANUP_PROTECTED_PIDS_ENV),
            shell_cleanup_protected_services: std::env::var(
                "NAILS_SHELL_CLEANUP_PROTECTED_SERVICES",
            )
            .ok(),
        }
    }

    /// Whether `NAILS_UNSAFE_REAL_OPS=1` opted into real host operations.
    pub fn unsafe_real_ops_enabled(&self) -> bool {
        self.unsafe_real_ops.as_deref() == Some("1")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsafe_real_ops_requires_exactly_one() {
        let mut hooks = TestHooks::default();
        assert!(!hooks.unsafe_real_ops_enabled());
        hooks.unsafe_real_ops = Some("1".into());
        assert!(hooks.unsafe_real_ops_enabled());
        hooks.unsafe_real_ops = Some("yes".into());
        assert!(!hooks.unsafe_real_ops_enabled());
    }
}
