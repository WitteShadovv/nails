use crate::{NailsError, Result};

thread_local! {
    static DEACTIVATION_GATE_TEST_ENABLED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[allow(dead_code)]
pub(crate) struct DeactivationGateTestGuard {
    previous: bool,
}

#[allow(dead_code)]
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

#[cfg(not(test))]
#[allow(dead_code)]
pub(crate) fn should_skip_shell_cleanup_before_deactivation_gate() -> bool {
    std::env::var_os("NAILS_TEST_DEACTIVATING_GATE_PATH").is_some()
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn should_skip_shell_cleanup_before_deactivation_gate() -> bool {
    false
}
