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
    env: &crate::RuntimeEnv,
) -> Result<Option<NailsError>> {
    let Some(decoy_system) = select_decoy_restore_target(fs, recorded_decoy, env)? else {
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

/// The live system link a teardown may have to repoint.
const RUN_CURRENT_SYSTEM: &str = "/run/current-system";
/// The generation the machine booted: the decoy, on a decoy host.
const RUN_BOOTED_SYSTEM: &str = "/run/booted-system";

/// Whether `/run/current-system` still points at the hidden system: it equals
/// the recorded hidden toplevel, or it dangles (the hidden toplevel lived in the
/// `/nix` overlay that is now gone). `false` when it is no symlink at all.
pub(super) fn current_system_points_into_hidden<F: Filesystem>(
    fs: &F,
    recorded_hidden: Option<&str>,
) -> bool {
    let link = std::path::Path::new(RUN_CURRENT_SYSTEM);
    if !fs.is_symlink(link).unwrap_or(false) {
        return false;
    }
    let Ok(target) = fs.canonicalize(link) else {
        return true;
    };
    if !fs.path_exists(&target).unwrap_or(true) {
        return true;
    }
    recorded_hidden.is_some_and(|hidden| {
        let hidden = std::path::Path::new(hidden);
        hidden == target || fs.canonicalize(hidden).is_ok_and(|h| h == target)
    })
}

/// The decoy system to point `/run/current-system` back at when no reboot
/// follows: the generation recorded at activation, else the generation the
/// machine booted (the decoy, which was running before activation unless the
/// decoy itself was switched since boot), else the system profile.
pub(super) fn decoy_system_for_session<F: Filesystem>(
    fs: &F,
    recorded_decoy: Option<&str>,
    env: &crate::RuntimeEnv,
) -> Option<std::path::PathBuf> {
    if let Some(recorded) = recorded_decoy
        && fs
            .path_exists(std::path::Path::new(recorded))
            .unwrap_or(false)
    {
        return Some(std::path::PathBuf::from(recorded));
    }
    let booted = std::path::Path::new(RUN_BOOTED_SYSTEM);
    if let Ok(target) = fs.canonicalize(booted)
        && fs.path_exists(&target).unwrap_or(false)
    {
        return Some(target);
    }
    select_decoy_restore_target(fs, None, env).ok().flatten()
}

/// Best-effort: repoint `/run/current-system` at the decoy system when an
/// untrusted or degraded teardown left it pointing into the hidden system.
///
/// Only a `/run` symlink is swapped (RAM, never the decoy disk), and only when
/// it really points into the hidden system, so a host that was never switched
/// is left alone. A failure is logged and returned as a message for the report.
pub(super) fn restore_hidden_current_system<F: Filesystem>(
    fs: &F,
    recorded_decoy: Option<&str>,
    recorded_hidden: Option<&str>,
    env: &crate::RuntimeEnv,
) -> Option<String> {
    if !current_system_points_into_hidden(fs, recorded_hidden) {
        return None;
    }
    let Some(decoy) = decoy_system_for_session(fs, recorded_decoy, env) else {
        tracing::warn!(
            "/run/current-system points into the hidden system and no decoy system is known"
        );
        return Some("no decoy system known to restore /run/current-system to".to_string());
    };
    match ensure_run_current_system_symlink(fs, &decoy) {
        Ok(()) => {
            tracing::info!(target = %decoy.display(), "Restored /run/current-system to the decoy system");
            None
        }
        Err(e) => {
            tracing::warn!(error = %e, "Could not restore /run/current-system to the decoy system");
            Some(format!("restoring /run/current-system failed: {e}"))
        }
    }
}

/// The hidden toplevel recorded at activation, if any.
pub(super) fn recorded_hidden_toplevel<F: Filesystem>(manager: &NailsManager<F>) -> Option<String> {
    manager
        .cached_state
        .borrow()
        .as_ref()
        .and_then(|state_file| state_file.hidden_toplevel().map(str::to_string))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MockFilesystem;
    use std::path::Path;

    #[test]
    fn a_dangling_or_hidden_current_system_is_restored_to_the_recorded_decoy() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/nix/store/decoy-system", true);
        // The hidden toplevel lived in the /nix overlay, now gone: the link dangles.
        fs.create_symlink(
            Path::new("/nix/store/hidden-system"),
            Path::new(RUN_CURRENT_SYSTEM),
        )
        .unwrap();
        assert!(current_system_points_into_hidden(&fs, None));

        let failure = restore_hidden_current_system(
            &fs,
            Some("/nix/store/decoy-system"),
            None,
            &crate::RuntimeEnv::empty(),
        );
        assert_eq!(failure, None);
        assert_eq!(
            fs.canonicalize(Path::new(RUN_CURRENT_SYSTEM)).unwrap(),
            Path::new("/nix/store/decoy-system")
        );
        assert!(!current_system_points_into_hidden(&fs, None));
    }

    #[test]
    fn a_live_hidden_toplevel_is_recognised_by_the_record() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/nix/store/hidden-system", true);
        fs.create_symlink(
            Path::new("/nix/store/hidden-system"),
            Path::new(RUN_CURRENT_SYSTEM),
        )
        .unwrap();
        assert!(current_system_points_into_hidden(
            &fs,
            Some("/nix/store/hidden-system")
        ));
        assert!(!current_system_points_into_hidden(
            &fs,
            Some("/nix/store/other")
        ));
    }

    #[test]
    fn the_booted_decoy_is_the_fallback_without_a_record() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/nix/store/booted-decoy", true);
        fs.create_symlink(
            Path::new("/nix/store/booted-decoy"),
            Path::new(RUN_BOOTED_SYSTEM),
        )
        .unwrap();
        assert_eq!(
            decoy_system_for_session(&fs, None, &crate::RuntimeEnv::empty()),
            Some(std::path::PathBuf::from("/nix/store/booted-decoy"))
        );
    }
}
