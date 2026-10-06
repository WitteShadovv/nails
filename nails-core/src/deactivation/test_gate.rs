// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::Result;

/// Block after the Deactivating transition when the E2E harness has armed the gate.
///
/// Like the activation gate, this exists only to pause a deactivation mid-flight
/// for the E2E suite. It is compiled in solely under the `test-hooks` feature (and
/// this crate's own `cfg(test)` builds); a shipped binary gets the no-op variant.
/// The gate and marker paths (`NAILS_TEST_DEACTIVATING_*`) come from the
/// manager's startup snapshot.
#[cfg(any(test, feature = "test-hooks"))]
pub(crate) fn maybe_block_after_deactivating_state_transition(
    env: &crate::RuntimeEnv,
) -> Result<()> {
    let hooks = &env.test_hooks;
    crate::runtime_env::wait_at_gate(
        hooks.deactivating_gate_path.as_deref(),
        hooks.deactivating_entered_path.as_deref(),
        "deactivation",
        "Deactivation test gate engaged after Deactivating state transition",
    )
}

#[cfg(not(any(test, feature = "test-hooks")))]
pub(crate) fn maybe_block_after_deactivating_state_transition(
    _env: &crate::RuntimeEnv,
) -> Result<()> {
    Ok(())
}

/// Whether shell cleanup must be skipped so the deactivation gate can engage first.
///
/// Only meaningful for the E2E harness (a non-test build carrying `test-hooks`
/// with the gate armed in the startup snapshot). In this crate's own tests, and
/// in shipped builds, it is always false.
#[cfg(all(not(test), feature = "test-hooks"))]
pub(crate) fn should_skip_shell_cleanup_before_deactivation_gate(env: &crate::RuntimeEnv) -> bool {
    env.test_hooks.deactivating_gate_path.is_some()
}

#[cfg(all(not(test), not(feature = "test-hooks")))]
pub(crate) fn should_skip_shell_cleanup_before_deactivation_gate(_env: &crate::RuntimeEnv) -> bool {
    false
}
