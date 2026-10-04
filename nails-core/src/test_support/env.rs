// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Process-environment isolation for tests.
//!
//! Every test thread of a test binary shares one process environment.
//! `#[serial]` does not protect it: it orders a test only against other
//! `#[serial]` tests, so an unmarked test can read `HOME` or spawn a child while
//! a serial test has removed `HOME` or pointed `PATH` somewhere else. Cleaning up
//! with `remove_var` is wrong as well, because it deletes a value that existed
//! before the test and that later tests rely on.
//!
//! The rule is therefore: every test that reads or writes the process
//! environment holds an [`EnvGuard`] for as long as it does so. That includes
//! tests that only read a variable, directly or through the code under test, and
//! tests that spawn a child whose behaviour depends on what it inherits at spawn
//! time. The guard:
//!
//! - takes the single environment lock of the test binary, so no other guarded
//!   test sees a half-configured environment;
//! - puts every variable changed through it back to its previous value, or
//!   removes it again, when it is dropped, including when the test panics;
//! - tolerates a poisoned lock, so one failing test does not fail every later
//!   test that touches the environment;
//! - is re-entrant on the thread that holds it, so a helper can take a guard
//!   inside a test that already holds one.
//!
//! The working directory is process-wide in the same way, so the guard covers
//! it too: a test that changes it uses [`EnvGuard::set_current_dir`], and a
//! test that resolves a relative path holds a guard while it does.
//!
//! A guard only protects tests that take it. Passing a value in (a home
//! directory, a search path) is still better than mutating the environment.
//!
//! ```
//! use nails_core::test_support::EnvGuard;
//!
//! let mut env = EnvGuard::lock();
//! env.set("NAILS_EXAMPLE_SET", "1").remove("NAILS_EXAMPLE_REMOVED");
//! assert_eq!(std::env::var("NAILS_EXAMPLE_SET").as_deref(), Ok("1"));
//! drop(env);
//! assert!(std::env::var_os("NAILS_EXAMPLE_SET").is_none());
//! ```

use std::cell::Cell;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

/// The environment lock of this test binary.
static ENV_LOCK: Mutex<()> = Mutex::new(());

thread_local! {
    /// Number of live guards on this thread. Only the outermost one owns the lock.
    static DEPTH: Cell<usize> = const { Cell::new(0) };
}

/// Holds the environment lock and undoes its own changes when dropped.
///
/// Take it with `let mut env = EnvGuard::lock();` before touching the
/// environment, or `let _env = EnvGuard::lock();` in a test that only reads it.
///
/// Guards on one thread must be dropped in the reverse order they were taken,
/// which normal scoping does. Dropping the outer guard first would release the
/// lock while the inner one can still change the environment, so it panics.
#[must_use = "the environment lock is released as soon as the guard is dropped"]
pub struct EnvGuard {
    /// The value each changed variable had before this guard first changed it.
    saved: Vec<(OsString, Option<OsString>)>,
    /// The working directory before this guard first changed it.
    saved_cwd: Option<PathBuf>,
    /// This guard's nesting level on its thread, starting at 1.
    level: usize,
    /// `Some` for the outermost guard on this thread. `MutexGuard` is not
    /// `Send`, which keeps the guard on the thread whose depth it raised.
    _lock: Option<MutexGuard<'static, ()>>,
}

impl EnvGuard {
    /// Takes the environment lock, or joins the one this thread already holds.
    pub fn lock() -> Self {
        let lock = (DEPTH.get() == 0).then(|| {
            // A test that panicked while holding the lock has already had its
            // changes undone by its guard's `Drop`, so the poison carries no
            // information worth failing for.
            ENV_LOCK.lock().unwrap_or_else(PoisonError::into_inner)
        });
        let level = DEPTH.get() + 1;
        DEPTH.set(level);
        Self {
            saved: Vec::new(),
            saved_cwd: None,
            level,
            _lock: lock,
        }
    }

    /// Sets `key` to `value` until the guard is dropped.
    // This module also compiles without cfg(test), under the test-support
    // feature, so the crate root's test-only allow does not reach it.
    #[allow(unsafe_code)]
    pub fn set(&mut self, key: impl AsRef<OsStr>, value: impl AsRef<OsStr>) -> &mut Self {
        let key = key.as_ref();
        self.remember(key);
        // SAFETY: this thread holds the environment lock, which every test that
        // reads or writes the environment takes, so no other thread of the test
        // binary accesses the environment concurrently.
        unsafe { std::env::set_var(key, value) };
        self
    }

    /// Removes `key` until the guard is dropped.
    #[allow(unsafe_code)]
    pub fn remove(&mut self, key: impl AsRef<OsStr>) -> &mut Self {
        let key = key.as_ref();
        self.remember(key);
        // SAFETY: as in `set`.
        unsafe { std::env::remove_var(key) };
        self
    }

    /// Changes the working directory to `dir` until the guard is dropped.
    ///
    /// # Panics
    ///
    /// Panics if the current or the new working directory is unusable, which
    /// leaves nothing for the test to check.
    pub fn set_current_dir(&mut self, dir: impl AsRef<Path>) -> &mut Self {
        if self.saved_cwd.is_none() {
            self.saved_cwd =
                Some(std::env::current_dir().expect("the working directory must be readable"));
        }
        std::env::set_current_dir(dir).expect("the test's working directory must exist");
        self
    }

    /// Records the value `key` has right now unless this guard already changed
    /// it, so dropping the guard restores the value from before its first change.
    fn remember(&mut self, key: &OsStr) {
        if !self.saved.iter().any(|(saved, _)| saved == key) {
            self.saved.push((key.to_os_string(), std::env::var_os(key)));
        }
    }
}

impl Drop for EnvGuard {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        for (key, value) in self.saved.drain(..).rev() {
            // SAFETY: the lock is still held; it is released only after this
            // body, when the `_lock` field is dropped.
            unsafe {
                match value {
                    Some(value) => std::env::set_var(&key, value),
                    None => std::env::remove_var(&key),
                }
            }
        }
        if let Some(dir) = self.saved_cwd.take() {
            let restored = std::env::set_current_dir(&dir);
            if !std::thread::panicking() {
                restored.expect("the original working directory must still exist");
            }
        }
        let depth = DEPTH.get();
        DEPTH.set(depth - 1);
        assert!(
            depth == self.level || std::thread::panicking(),
            "EnvGuard dropped out of order: a guard taken later on this thread is still alive"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::TryLockError;

    fn var(key: &str) -> Option<String> {
        std::env::var(key).ok()
    }

    #[test]
    fn set_is_undone_by_restoring_the_previous_value_or_removing_the_variable() {
        let mut outer = EnvGuard::lock();
        outer
            .set("NAILS_ENV_GUARD_PREVIOUS", "before")
            .remove("NAILS_ENV_GUARD_ABSENT");

        {
            let mut env = EnvGuard::lock();
            env.set("NAILS_ENV_GUARD_PREVIOUS", "during")
                .set("NAILS_ENV_GUARD_ABSENT", "during");
            assert_eq!(var("NAILS_ENV_GUARD_PREVIOUS").as_deref(), Some("during"));
            assert_eq!(var("NAILS_ENV_GUARD_ABSENT").as_deref(), Some("during"));
        }

        assert_eq!(var("NAILS_ENV_GUARD_PREVIOUS").as_deref(), Some("before"));
        assert_eq!(var("NAILS_ENV_GUARD_ABSENT"), None);
    }

    #[test]
    fn remove_is_undone_by_restoring_the_removed_value() {
        let mut outer = EnvGuard::lock();
        outer.set("NAILS_ENV_GUARD_REMOVED", "kept");

        {
            let mut env = EnvGuard::lock();
            env.remove("NAILS_ENV_GUARD_REMOVED");
            assert_eq!(var("NAILS_ENV_GUARD_REMOVED"), None);
        }

        assert_eq!(var("NAILS_ENV_GUARD_REMOVED").as_deref(), Some("kept"));
    }

    #[test]
    fn repeated_changes_restore_the_value_from_before_the_first_change() {
        let mut outer = EnvGuard::lock();
        outer.set("NAILS_ENV_GUARD_REPEATED", "original");

        {
            let mut env = EnvGuard::lock();
            env.set("NAILS_ENV_GUARD_REPEATED", "first")
                .remove("NAILS_ENV_GUARD_REPEATED")
                .set("NAILS_ENV_GUARD_REPEATED", "last");
            assert_eq!(var("NAILS_ENV_GUARD_REPEATED").as_deref(), Some("last"));
        }

        assert_eq!(var("NAILS_ENV_GUARD_REPEATED").as_deref(), Some("original"));
    }

    #[test]
    fn nested_guards_share_the_lock_until_the_outermost_is_dropped() {
        let outer = EnvGuard::lock();
        let inner = EnvGuard::lock();
        assert!(matches!(ENV_LOCK.try_lock(), Err(TryLockError::WouldBlock)));

        drop(inner);
        assert!(
            matches!(ENV_LOCK.try_lock(), Err(TryLockError::WouldBlock)),
            "dropping a nested guard must not release the outer guard's lock"
        );
        drop(outer);
    }

    #[test]
    fn set_current_dir_is_undone_when_the_guard_is_dropped() {
        let temp_dir = tempfile::tempdir().unwrap();
        let _outer = EnvGuard::lock();
        let original = std::env::current_dir().unwrap();

        {
            let mut env = EnvGuard::lock();
            env.set_current_dir(temp_dir.path());
            assert_eq!(
                std::env::current_dir().unwrap().canonicalize().unwrap(),
                temp_dir.path().canonicalize().unwrap()
            );
        }

        assert_eq!(std::env::current_dir().unwrap(), original);
    }

    #[test]
    #[should_panic(expected = "dropped out of order")]
    fn dropping_an_outer_guard_before_an_inner_one_panics() {
        let outer = EnvGuard::lock();
        let _inner = EnvGuard::lock();
        drop(outer);
    }

    #[test]
    fn a_test_that_panics_while_holding_the_lock_neither_leaks_nor_blocks() {
        let panicked = std::thread::spawn(|| {
            let mut env = EnvGuard::lock();
            env.set("NAILS_ENV_GUARD_PANICKED", "leaked");
            panic!("simulated test failure while holding the environment lock");
        })
        .join();
        assert!(panicked.is_err());

        let _env = EnvGuard::lock();
        assert_eq!(var("NAILS_ENV_GUARD_PANICKED"), None);
    }
}
