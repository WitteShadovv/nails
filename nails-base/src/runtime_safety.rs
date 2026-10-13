// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Runtime safeguards that keep test and E2E builds from touching the host.
//!
//! The decision is a compile-time constant in shipped builds. Only a build that
//! carries the `test-hooks` feature — or this crate's own `cfg(test)` unit tests
//! — compiles in any check, and even then it skips host interaction only in a
//! unit-test binary of a NAILS library crate (see [`in_unit_tests`]) or when
//! `NAILS_TEST_RUNTIME` was set in the startup snapshot `main` installed (see
//! [`crate::runtime_env::current`]). A shipped binary therefore always
//! performs real host operations: there is no environment variable, executable
//! name or path layout that can turn them off.

#[cfg(any(test, feature = "test-hooks"))]
use std::sync::atomic::{AtomicBool, Ordering};

/// Set before `main` in the unit-test binary of a NAILS library crate other
/// than this one (see [`unit_test_mode!`](crate::unit_test_mode)).
#[cfg(any(test, feature = "test-hooks"))]
static UNIT_TESTS: AtomicBool = AtomicBool::new(false);

/// Whether this process is the unit-test binary of a NAILS library crate.
///
/// The library crates' unit tests share one rule, as they did when they were
/// one crate: they never reach the host (no tool runs, no desktop alert, no
/// state attach gate unless a test arms it). This crate's own unit tests know
/// it from `cfg(test)`; every other library crate marks its unit-test binary
/// with [`unit_test_mode!`](crate::unit_test_mode), which needs the
/// `test-hooks` feature. Always false in a shipped build.
#[cfg(any(test, feature = "test-hooks"))]
pub fn in_unit_tests() -> bool {
    cfg!(test) || UNIT_TESTS.load(Ordering::Relaxed)
}

/// Shipped builds are never a unit-test binary.
#[cfg(not(any(test, feature = "test-hooks")))]
#[inline]
pub fn in_unit_tests() -> bool {
    false
}

/// Mark this process as a unit-test binary. Called only by the code that
/// [`unit_test_mode!`](crate::unit_test_mode) expands to.
#[cfg(any(test, feature = "test-hooks"))]
#[doc(hidden)]
pub fn mark_unit_tests() {
    UNIT_TESTS.store(true, Ordering::Relaxed);
}

/// Mark the unit-test binary of the calling crate as one (see
/// [`in_unit_tests`]). Expands to nothing outside the calling crate's
/// `cfg(test)` build, and the crate needs `nails-base`'s `test-hooks` feature
/// for its tests. The mark is set from an ELF `.init_array` entry, so it holds
/// before the test harness starts the first test.
#[macro_export]
macro_rules! unit_test_mode {
    () => {
        #[cfg(test)]
        mod nails_unit_test_mode {
            extern "C" fn mark() {
                $crate::runtime_safety::mark_unit_tests();
            }

            // SAFETY: a function pointer in `.init_array` is called once by the
            // loader before `main`, with no arguments it must read; `mark`
            // only stores to an atomic.
            #[used]
            #[unsafe(link_section = ".init_array")]
            static MARK: extern "C" fn() = mark;
        }
    };
}

/// Return true when the running build should avoid real host interaction.
///
/// In the unit tests of a NAILS library crate ([`in_unit_tests`]) the answer is
/// always true. In any other build that carries the `test-hooks` feature
/// (integration tests and the packaged `nails-e2e` binary) it is true only when
/// `NAILS_TEST_RUNTIME` was set in the
/// installed startup snapshot, so the E2E harness can still drive real
/// operations by leaving that variable unset. It is read through the installed
/// snapshot because this switch sits below every handler, at dozens of call
/// sites with no handler state in hand.
#[cfg(any(test, feature = "test-hooks"))]
pub fn should_skip_host_interaction() -> bool {
    if in_unit_tests() {
        return true;
    }

    crate::runtime_env::current()
        .test_hooks
        .test_runtime
        .is_some()
}

/// Shipped builds never skip host interaction: the check is a compile-time
/// constant, so no environment variable or executable path can disable real
/// operations.
#[cfg(not(any(test, feature = "test-hooks")))]
#[inline]
pub fn should_skip_host_interaction() -> bool {
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
