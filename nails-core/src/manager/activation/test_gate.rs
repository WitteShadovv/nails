use crate::{NailsError, Result};

#[cfg(test)]
use std::sync::{Mutex, OnceLock};

#[cfg(test)]
pub(super) fn activation_gate_test_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

pub(super) fn maybe_block_after_activating_state_transition() -> Result<()> {
    #[cfg(test)]
    let _test_lock = activation_gate_test_lock().lock().unwrap();

    maybe_block_after_activating_state_transition_inner()
}

pub(super) fn maybe_block_after_activating_state_transition_inner() -> Result<()> {
    let Some(gate_path) = std::env::var_os("NAILS_TEST_ACTIVATING_GATE_PATH") else {
        return Ok(());
    };
    let gate_path = std::path::PathBuf::from(gate_path);
    let entered_path = std::env::var_os("NAILS_TEST_ACTIVATING_ENTERED_PATH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(format!("{}.entered", gate_path.display())));
    if let Some(parent) = entered_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            NailsError::NixOSError(format!(
                "Failed to prepare activation test marker directory {}: {}",
                parent.display(),
                e
            ))
        })?;
    }
    std::fs::write(&entered_path, []).map_err(|e| {
        NailsError::NixOSError(format!(
            "Failed to write activation test marker {}: {}",
            entered_path.display(),
            e
        ))
    })?;
    tracing::info!(
        gate_path = %gate_path.display(),
        entered_path = %entered_path.display(),
        "Activation test gate engaged after Activating state transition"
    );
    while gate_path.exists() {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    Ok(())
}
