use super::NailsManager;
use crate::{Filesystem, NailsError, Result};
use std::path::{Path, PathBuf};

#[allow(dead_code)]
fn cleanup_ephemeral_overlays_after_activation_failure<F: Filesystem>(
    manager: &NailsManager<F>,
) -> Result<()> {
    if !manager.config.extended_overlays.enabled {
        return Ok(());
    }

    let mut cleanup_errors = Vec::new();

    for ephemeral_dir in manager.config.extended_overlays.directories.iter().rev() {
        let dir_name = ephemeral_dir
            .path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy();

        let mount_info = crate::overlay::PivotMountInfo {
            target: ephemeral_dir.path.clone(),
            staging: PathBuf::from(format!(
                "{}/{}",
                crate::overlay::PIVOT_STAGING_BASE,
                dir_name
            )),
            upper: PathBuf::from(format!("/run/nails/{}-ephemeral/upper", dir_name)),
            work: PathBuf::from(format!("/run/nails/{}-ephemeral/work", dir_name)),
            lower: ephemeral_dir.path.clone(),
            is_ephemeral: true,
        };

        if let Err(err) = crate::overlay::unmount_pivot_overlay(&manager.filesystem, &mount_info) {
            tracing::error!(
                error = %err,
                path = %ephemeral_dir.path.display(),
                rollback = true,
                "Ephemeral overlay cleanup failed after activation error"
            );
            cleanup_errors.push(format!("{}: {}", ephemeral_dir.path.display(), err));
        }
    }

    if cleanup_errors.is_empty() {
        Ok(())
    } else {
        Err(NailsError::OverlayError(format!(
            "Activation rollback ephemeral cleanup failed: {}",
            cleanup_errors.join("; ")
        )))
    }
}

#[allow(dead_code)]
pub(super) fn rollback_overlay_mounts_after_activation_failure<F: Filesystem>(
    manager: &NailsManager<F>,
    mounted_overlays: &[PathBuf],
) -> Result<()> {
    let nix_was_overlaid = mounted_overlays
        .iter()
        .any(|path| path == Path::new("/nix"));
    let mut rollback_errors = Vec::new();

    if nix_was_overlaid {
        tracing::info!(
            rollback = true,
            "Stopping nix-daemon before activation rollback cleanup"
        );
        let _ = crate::manager::helpers::ServiceController::stop_nix_daemon();
        let _ = manager.filesystem.unmount(Path::new("/nix/store"), false);
    }

    if let Err(err) = cleanup_ephemeral_overlays_after_activation_failure(manager) {
        rollback_errors.push(err.to_string());
    }

    if let Err(err) = manager.unmount_overlays(mounted_overlays.to_vec()) {
        rollback_errors.push(err.to_string());
    }

    let rollback_cleanup_succeeded = rollback_errors.is_empty();

    if nix_was_overlaid && rollback_cleanup_succeeded {
        tracing::info!(
            rollback = true,
            "Restarting nix-daemon after activation rollback cleanup"
        );
        crate::manager::helpers::ServiceController::start_nix_daemon();
    } else if nix_was_overlaid {
        tracing::warn!(
            rollback = true,
            "Skipping nix-daemon restart because activation rollback cleanup did not complete cleanly"
        );
    }

    if rollback_cleanup_succeeded {
        Ok(())
    } else {
        Err(NailsError::OverlayError(format!(
            "Activation rollback cleanup failed: {}",
            rollback_errors.join("; ")
        )))
    }
}
