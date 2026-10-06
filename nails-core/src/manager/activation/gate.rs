// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::Result;

/// Block after the Activating transition when the E2E harness has armed the gate.
///
/// The gate exists only to let the E2E suite pause an activation mid-flight. It is
/// compiled in solely under the `test-hooks` feature (and this crate's own
/// `cfg(test)` builds); a shipped binary gets the no-op variant below. The gate
/// and marker paths (`NAILS_TEST_ACTIVATING_*`) come from the manager's startup
/// snapshot, so a test arms the gate for its own manager only.
#[cfg(any(test, feature = "test-hooks"))]
pub(super) fn maybe_block_after_activating_state_transition(env: &crate::RuntimeEnv) -> Result<()> {
    let hooks = &env.test_hooks;
    crate::runtime_env::wait_at_gate(
        hooks.activating_gate_path.as_deref(),
        hooks.activating_entered_path.as_deref(),
        "activation",
        "Activation test gate engaged after Activating state transition",
    )
}

#[cfg(not(any(test, feature = "test-hooks")))]
pub(super) fn maybe_block_after_activating_state_transition(
    _env: &crate::RuntimeEnv,
) -> Result<()> {
    Ok(())
}
