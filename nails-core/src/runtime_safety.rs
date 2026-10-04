// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Runtime safeguards that keep test and E2E builds from touching the host.
//!
//! The decision is a compile-time constant in shipped builds. Only a build that
//! carries the `test-hooks` feature — or this crate's own `cfg(test)` unit tests
//! — compiles in any environment check, and even then it skips host interaction
//! only when `NAILS_TEST_RUNTIME` is set. A shipped binary therefore always
//! performs real host operations: there is no environment variable, executable
//! name or path layout that can turn them off.

/// Return true when the running build should avoid real host interaction.
///
/// In this crate's own unit tests the answer is always true. In any other build
/// that carries the `test-hooks` feature (integration tests and the packaged
/// `nails-e2e` binary) it is true only when `NAILS_TEST_RUNTIME` is set, so the
/// E2E harness can still drive real operations by leaving that variable unset.
#[cfg(any(test, feature = "test-hooks"))]
pub(crate) fn should_skip_host_interaction() -> bool {
    if cfg!(test) {
        return true;
    }

    std::env::var_os("NAILS_TEST_RUNTIME").is_some()
}

/// Shipped builds never skip host interaction: the check is a compile-time
/// constant, so no environment variable or executable path can disable real
/// operations.
#[cfg(not(any(test, feature = "test-hooks")))]
#[inline]
pub(crate) fn should_skip_host_interaction() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::should_skip_host_interaction;

    #[test]
    fn unit_tests_always_skip_host_interaction() {
        // Inside this crate's own test harness the skip is unconditional, so the
        // hundreds of mock-filesystem tests never reach a real syscall.
        assert!(should_skip_host_interaction());
    }
}
