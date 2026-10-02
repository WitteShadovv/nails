#[cfg(any(test, feature = "test-hooks"))]
use crate::NailsError;
use crate::Result;

#[cfg(test)]
thread_local! {
    static DEACTIVATION_GATE_TEST_ENABLED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
pub(crate) struct DeactivationGateTestGuard {
    previous: bool,
}

#[cfg(test)]
impl DeactivationGateTestGuard {
    pub(crate) fn enable() -> Self {
        let previous = DEACTIVATION_GATE_TEST_ENABLED.with(|enabled| {
            let previous = enabled.get();
            enabled.set(true);
            previous
        });
        Self { previous }
    }
}

#[cfg(test)]
impl Drop for DeactivationGateTestGuard {
    fn drop(&mut self) {
        DEACTIVATION_GATE_TEST_ENABLED.with(|enabled| enabled.set(self.previous));
    }
}

/// Block after the Deactivating transition when the E2E harness has armed the gate.
///
/// Like the activation gate, this exists only to pause a deactivation mid-flight
/// for the E2E suite. It is compiled in solely under the `test-hooks` feature (and
/// this crate's own `cfg(test)` builds); a shipped binary gets the no-op variant
/// and never reads the `NAILS_TEST_DEACTIVATING_*` environment.
#[cfg(any(test, feature = "test-hooks"))]
pub(crate) fn maybe_block_after_deactivating_state_transition() -> Result<()> {
    #[cfg(test)]
    if !DEACTIVATION_GATE_TEST_ENABLED.with(|enabled| enabled.get()) {
        return Ok(());
    }

    let Some(gate_path) = std::env::var_os("NAILS_TEST_DEACTIVATING_GATE_PATH") else {
        return Ok(());
    };
    let gate_path = std::path::PathBuf::from(gate_path);
    let entered_path = std::env::var_os("NAILS_TEST_DEACTIVATING_ENTERED_PATH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(format!("{}.entered", gate_path.display())));

    if let Some(parent) = entered_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            NailsError::NixOSError(format!(
                "Failed to prepare deactivation test marker directory {}: {}",
                parent.display(),
                e
            ))
        })?;
    }

    std::fs::write(&entered_path, []).map_err(|e| {
        NailsError::NixOSError(format!(
            "Failed to write deactivation test marker {}: {}",
            entered_path.display(),
            e
        ))
    })?;

    tracing::info!(
        gate_path = %gate_path.display(),
        entered_path = %entered_path.display(),
        "Deactivation test gate engaged after Deactivating state transition"
    );

    while gate_path.exists() {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    Ok(())
}

#[cfg(not(any(test, feature = "test-hooks")))]
pub(crate) fn maybe_block_after_deactivating_state_transition() -> Result<()> {
    Ok(())
}

/// Whether shell cleanup must be skipped so the deactivation gate can engage first.
///
/// Only meaningful for the E2E harness (a non-test build carrying `test-hooks`
/// with the gate armed). In this crate's own tests, and in shipped builds, it is
/// always false and reads no environment.
#[cfg(all(not(test), feature = "test-hooks"))]
pub(crate) fn should_skip_shell_cleanup_before_deactivation_gate() -> bool {
    std::env::var_os("NAILS_TEST_DEACTIVATING_GATE_PATH").is_some()
}

#[cfg(all(not(test), not(feature = "test-hooks")))]
pub(crate) fn should_skip_shell_cleanup_before_deactivation_gate() -> bool {
    false
}
