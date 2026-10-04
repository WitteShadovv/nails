// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The cross-crate contract of [`EnvGuard`].
//!
//! `EnvGuard` is the mechanism that keeps the test suites order-independent:
//! every test that touches the process environment holds one, so a shuffled,
//! threaded run never sees a half-configured environment. nails-cli relies on
//! the same guarantees through the public `test-support` feature. These tests
//! exercise it the way an external crate does — through
//! `nails_core::test_support` — so a later change to the environment plumbing
//! cannot quietly drop a guarantee the rest of the suite is built on.

#![cfg(feature = "test-support")]

use std::panic::{AssertUnwindSafe, catch_unwind};

use nails_core::test_support::EnvGuard;

const PRESENT: &str = "NAILS_ENV_GUARD_CONTRACT_PRESENT";
const ABSENT: &str = "NAILS_ENV_GUARD_CONTRACT_ABSENT";

fn var(key: &str) -> Option<String> {
    std::env::var(key).ok()
}

/// A panic inside a guarded scope still restores the environment, and the lock
/// stays usable for the next test rather than staying poisoned. This is the
/// property the whole suite depends on: one failing test must not corrupt the
/// environment every later test reads.
#[test]
fn a_panic_under_a_guard_restores_the_environment_and_leaves_the_lock_usable() {
    let mut outer = EnvGuard::lock();
    outer.set(PRESENT, "before").remove(ABSENT);

    let result = catch_unwind(AssertUnwindSafe(|| {
        let mut env = EnvGuard::lock();
        env.set(PRESENT, "during").set(ABSENT, "during");
        assert_eq!(var(PRESENT).as_deref(), Some("during"));
        panic!("simulated failure while the environment is reconfigured");
    }));
    assert!(result.is_err(), "the guarded closure must have panicked");

    // The inner guard's Drop ran despite the panic.
    assert_eq!(var(PRESENT).as_deref(), Some("before"));
    assert_eq!(var(ABSENT), None);

    // The outer guard still owns a working lock: a fresh guard taken now sees
    // and restores the current values rather than blocking or observing a leak.
    {
        let mut env = EnvGuard::lock();
        env.set(PRESENT, "again");
        assert_eq!(var(PRESENT).as_deref(), Some("again"));
    }
    assert_eq!(var(PRESENT).as_deref(), Some("before"));
}

/// Nested guards on one thread share the single lock instead of deadlocking,
/// and dropping the inner one keeps the environment under the outer one's
/// control until it, too, is dropped.
#[test]
fn nested_guards_on_one_thread_do_not_deadlock() {
    let mut outer = EnvGuard::lock();
    outer.set(PRESENT, "outer");

    {
        let mut inner = EnvGuard::lock();
        inner.set(PRESENT, "inner");
        assert_eq!(var(PRESENT).as_deref(), Some("inner"));
    }

    // Dropping the inner guard restored the outer guard's value, not the
    // pre-test one, and did not release the lock.
    assert_eq!(var(PRESENT).as_deref(), Some("outer"));

    drop(outer);
    assert_eq!(var(PRESENT), None);
}

/// The working directory is process-wide too, so the guard restores it even
/// when the guarded scope unwinds.
#[test]
fn a_panic_under_a_guard_restores_the_working_directory() {
    let temp_dir = tempfile::tempdir().unwrap();
    let _outer = EnvGuard::lock();
    let original = std::env::current_dir().unwrap();

    let result = catch_unwind(AssertUnwindSafe(|| {
        let mut env = EnvGuard::lock();
        env.set_current_dir(temp_dir.path());
        panic!("simulated failure after changing the working directory");
    }));
    assert!(result.is_err());

    assert_eq!(std::env::current_dir().unwrap(), original);
}
