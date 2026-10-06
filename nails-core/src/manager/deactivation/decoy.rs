// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Restoring the decoy configuration on teardown.

use crate::manager::{
    NailsManager, ensure_run_current_system_symlink, select_decoy_restore_target,
};
use crate::{Filesystem, NailsError, Result};

pub(super) fn requires_decoy_restore<F: Filesystem>(manager: &NailsManager<F>) -> Result<bool> {
    let _ = manager.current_state()?;

    let cached = manager.cached_state.borrow();

    Ok(cached
        .as_ref()
        .and_then(|state_file| state_file.hidden_toplevel())
        .is_some())
}

/// The decoy system store path recorded at activation, if any.
///
/// Read from the cached state so deactivation can restore the exact generation
/// that was running before the hidden switch, rather than inferring it from the
/// system profile.
pub(super) fn recorded_decoy_system<F: Filesystem>(manager: &NailsManager<F>) -> Option<String> {
    manager
        .cached_state
        .borrow()
        .as_ref()
        .and_then(|state_file| state_file.decoy_system.clone())
}

/// Point `/run/current-system` back at the decoy system on deactivation.
///
/// We never run `switch-to-configuration switch` here. The reboot that follows a
/// Normal deactivation boots the decoy from the bootloader default (activation
/// only ever used `test`), so a real switch would be pure redundancy — and it
/// would reinstall the bootloader, write the ESP and rewrite EFI NVRAM and
/// /var/lib/nixos, leaving evidence that the hidden mode existed. Swapping only
/// the live `/run/current-system` symlink restores the decoy for any caller that
/// does not reboot (emergency) without touching the bootloader, ESP or NVRAM.
///
/// The target is the decoy system recorded at activation (the exact generation
/// that was running before the hidden switch), falling back to the newest system
/// profile only when nothing was recorded or the recorded path is gone. A host
/// whose system profile is absent (an impermanent or freshly imaged decoy) or
/// stale (it points at a newer, never-switched generation) is then still restored
/// correctly. Returns `Some(error)` when neither a recorded system nor a profile
/// is available, or when the symlink swap failed.
pub(super) fn restore_decoy_current_system<F: Filesystem>(
    fs: &F,
    recorded_decoy: Option<&str>,
) -> Result<Option<NailsError>> {
    let Some(decoy_system) = select_decoy_restore_target(fs, recorded_decoy)? else {
        return Ok(Some(NailsError::NixOSError(
            "No recorded decoy system and no system profile available for decoy restore".into(),
        )));
    };
    tracing::info!(
        target = %decoy_system.display(),
        "Restoring /run/current-system to the decoy system..."
    );
    Ok(ensure_run_current_system_symlink(fs, &decoy_system)
        .err()
        .map(|e| {
            NailsError::NixOSError(format!(
                "Failed to restore /run/current-system to the decoy system: {e}"
            ))
        }))
}
