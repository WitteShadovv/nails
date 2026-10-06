// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The process-wide startup snapshot, for helpers below every command handler.
//!
//! Most code receives the [`RuntimeEnv`] explicitly: `main` passes it to the
//! handler, which attaches it to the manager. A few leaf helpers sit underneath
//! everything — the process runner that spawns every tool, the runtime-safety
//! switch, the attach gate — and are reached from dozens of call sites with no
//! handler state in hand. They read the snapshot `main` installed here with
//! [`install`], through [`current`], instead of the live environment. Nothing in
//! this module reads the environment itself.
//!
//! Before anything is installed (a library caller, an in-process unit test)
//! [`current`] answers with an empty snapshot. A test that needs the leaf helpers
//! to see particular values scopes them to its own thread with
//! [`ScopedRuntimeEnv`], so no other test is affected.

use super::RuntimeEnv;
use std::sync::{Arc, OnceLock};

static INSTALLED: OnceLock<Arc<RuntimeEnv>> = OnceLock::new();
static EMPTY: OnceLock<Arc<RuntimeEnv>> = OnceLock::new();

#[cfg(any(test, feature = "test-hooks"))]
thread_local! {
    static SCOPED: std::cell::RefCell<Vec<Arc<RuntimeEnv>>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Install the startup snapshot for the leaf helpers. `main` calls this once,
/// right after [`RuntimeEnv::from_process_env`]. Returns `false` when a snapshot
/// was already installed (the first one stays).
pub fn install(env: RuntimeEnv) -> bool {
    INSTALLED.set(Arc::new(env)).is_ok()
}

/// The snapshot the leaf helpers read: a thread-scoped test override when one
/// is active, otherwise the installed snapshot, otherwise an empty one.
pub fn current() -> Arc<RuntimeEnv> {
    #[cfg(any(test, feature = "test-hooks"))]
    if let Some(scoped) = SCOPED.with(|stack| stack.borrow().last().cloned()) {
        return scoped;
    }
    INSTALLED
        .get()
        .cloned()
        .unwrap_or_else(|| EMPTY.get_or_init(|| Arc::new(RuntimeEnv::empty())).clone())
}

/// Makes [`current`] answer with a given snapshot on this thread until dropped.
///
/// Test-only (compiled under the `test-hooks` feature): it lets an in-process
/// test steer the leaf helpers without touching the shared process environment.
/// Guards nest; each drop restores the previous answer.
#[cfg(any(test, feature = "test-hooks"))]
#[must_use = "the override ends as soon as the guard is dropped"]
pub struct ScopedRuntimeEnv {
    // Not `Send`: the override belongs to the thread that pushed it.
    _thread_bound: std::marker::PhantomData<*const ()>,
}

#[cfg(any(test, feature = "test-hooks"))]
impl ScopedRuntimeEnv {
    /// Start answering [`current`] with `env` on this thread.
    pub fn new(env: RuntimeEnv) -> Self {
        SCOPED.with(|stack| stack.borrow_mut().push(Arc::new(env)));
        Self {
            _thread_bound: std::marker::PhantomData,
        }
    }
}

#[cfg(any(test, feature = "test-hooks"))]
impl Drop for ScopedRuntimeEnv {
    fn drop(&mut self) {
        SCOPED.with(|stack| {
            stack.borrow_mut().pop();
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scoped_override_applies_to_this_thread_and_nests() {
        let outer = ScopedRuntimeEnv::new(RuntimeEnv::empty().with_shell("/bin/zsh"));
        assert_eq!(current().shell.as_deref(), Some("/bin/zsh"));
        {
            let _inner = ScopedRuntimeEnv::new(RuntimeEnv::empty().with_shell("/bin/fish"));
            assert_eq!(current().shell.as_deref(), Some("/bin/fish"));
            let other = std::thread::spawn(|| current().shell.clone())
                .join()
                .unwrap();
            assert_ne!(other.as_deref(), Some("/bin/fish"));
        }
        assert_eq!(current().shell.as_deref(), Some("/bin/zsh"));
        drop(outer);
    }
}
