// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Choosing the overlay targets to unmount and judging whether a target is
//! still a live NAILS mount after the teardown attempted it.

use crate::filesystem::NailsMounts;
use crate::manager::NailsManager;
use crate::{Filesystem, NailsError, Result, SystemState};
use std::path::{Path, PathBuf};

pub(super) fn overlay_unmount_targets<F: Filesystem>(
    manager: &NailsManager<F>,
    current_state: &SystemState,
) -> Result<Vec<PathBuf>> {
    let active_overlays = match current_state {
        SystemState::Active { overlays, .. } => overlays.clone(),
        _ => {
            return Err(NailsError::InvalidState(
                "Cannot extract overlays: not in ACTIVE state".to_string(),
            ));
        }
    };

    let mut merged = manager.tracked_overlay_paths_by_mount_order()?;
    for path in active_overlays {
        if !merged.iter().any(|existing| existing == &path) {
            merged.push(path);
        }
    }

    Ok(merged)
}

/// Targets to unmount for an untrusted-state teardown, in mount order.
///
/// [`unmount_overlays`](DeactivationOrchestrator::unmount_overlays) reverses this
/// list, so placing the `/nix/store` restore bind last makes it come off before
/// the `/nix` overlay it sits on, the fresh-home persona binds come off before
/// the `/home` overlay they sit on, and the persistent overlays come off last.
/// The `/nix/store` bind is only ours when `/nix` is overlaid, so it is included
/// only then (and only when still present — the `/nix` teardown path may already
/// have removed it before the orchestrator runs).
pub(super) fn discovered_unmount_targets(mounts: &NailsMounts) -> Vec<PathBuf> {
    let mut targets = Vec::new();
    targets.extend(mounts.persistent_overlays.iter().cloned());
    targets.extend(mounts.ephemeral_overlays.iter().cloned());
    targets.extend(mounts.persona_binds.iter().cloned());
    targets.extend(mounts.pivot_binds.iter().cloned());
    if mounts.nix_overlay_present
        && let Some(bind) = &mounts.nix_store_bind
    {
        targets.push(bind.clone());
    }
    targets
}

/// The trusted teardown's targets: the recorded overlays in mount order, then
/// every live NAILS mount the recorded list misses (a persona bind, a staging
/// mount, an overlay the state never recorded), in discovery order.
///
/// The list is unmounted in reverse, so the discovered extras come off first:
/// they sit on top of the recorded overlays (a persona bind over `/home`, the
/// `/nix/store` bind over `/nix`) or inside the runtime root. Each mount point
/// appears once.
pub(super) fn merge_recorded_with_discovered(
    recorded: Vec<PathBuf>,
    discovered: Option<&NailsMounts>,
) -> Vec<PathBuf> {
    let mut targets = recorded;
    for path in discovered
        .map(discovered_unmount_targets)
        .unwrap_or_default()
    {
        if !targets.contains(&path) {
            targets.push(path);
        }
    }
    targets
}

/// Result of attempting to unmount every tracked overlay.
///
/// The teardown attempts all targets rather than aborting on the first failure,
/// so both the detached and the still-failing targets are recorded.
pub(super) struct UnmountOutcome {
    /// Targets detached successfully, in the order they were attempted.
    pub(super) unmounted: Vec<String>,
    /// Targets whose unmount failed after both graceful and forced attempts.
    pub(super) failed: Vec<PathBuf>,
    /// Targets that only came down after the forced (lazy) detach fallback,
    /// because the graceful unmount failed. A subset of `unmounted`.
    pub(super) force_detached: Vec<String>,
}

/// Re-read the mount table and return the attempted targets — and every other
/// NAILS mount still in the live table — where a NAILS mount is still live.
///
/// Checking only the attempted targets let a NAILS mount the teardown never
/// tried (a persona bind missing from the recorded list) pass as a clean
/// teardown. The runtime-root tmpfs is left out: it is removed after this check,
/// together with whatever is staged in it.
///
/// A target counts as live when something is still mounted there *and* that
/// mount is NAILS's own: an overlay, or a mount the live-table classifier
/// ([`Filesystem::discover_nails_mounts`](crate::Filesystem::discover_nails_mounts))
/// recognises as NAILS-created. A target that is itself a decoy mount point —
/// a VFAT `/boot`, a separate `/home` partition — stays mounted after its
/// overlay comes down, because the decoy's own filesystem is what the overlay
/// was stacked on; that mount is not a leftover and must not turn a clean
/// teardown into `Degraded`. A target whose unmount reported failure is always
/// live. A probe or discovery error is treated
/// conservatively as "still live" so an unreadable mount table can never be
/// mistaken for a clean teardown.
pub(super) fn remaining_nails_mounts<F: Filesystem>(
    manager: &NailsManager<F>,
    attempted: &[PathBuf],
    failed: &[PathBuf],
) -> Vec<PathBuf> {
    let hidden_root = manager.config().hidden_volume_root.clone();
    let discovered = manager
        .filesystem()
        .discover_nails_mounts(Some(&hidden_root));
    let mut candidates = attempted.to_vec();
    if let Ok(mounts) = &discovered {
        for point in mounts.owned_mount_points() {
            if mounts.runtime_tmpfs.as_ref() != Some(&point) && !candidates.contains(&point) {
                candidates.push(point);
            }
        }
    }
    candidates
        .iter()
        .filter(|target| {
            let mounted = match manager.filesystem().is_mounted(target) {
                Ok(mounted) => mounted,
                Err(e) => {
                    tracing::warn!(
                        path = %target.display(),
                        error = %e,
                        phase = "unmount",
                        "Could not confirm unmount; treating target as still live"
                    );
                    return true;
                }
            };
            if !mounted {
                return false;
            }
            // An unmount that reported failure leaves its NAILS mount in place.
            if failed.contains(target) {
                return true;
            }
            let overlay_still_mounted = manager
                .filesystem()
                .is_overlay_mounted(target)
                .unwrap_or(true);
            still_nails_owned(
                mounted,
                overlay_still_mounted,
                discovered.as_ref().ok(),
                target,
            )
        })
        .cloned()
        .collect()
}

/// Decide whether a still-mounted teardown target is a NAILS leftover.
///
/// Live when an overlay is still mounted there, when the live-table classifier
/// recognises the mount as NAILS-created, or when that classifier could not run
/// (`discovered` is `None`): fail closed. Otherwise the mount is the decoy's own
/// filesystem the overlay was stacked on, which is expected to remain.
pub(super) fn still_nails_owned(
    mounted: bool,
    overlay_still_mounted: bool,
    discovered: Option<&crate::filesystem::NailsMounts>,
    target: &Path,
) -> bool {
    if !mounted {
        return false;
    }
    if overlay_still_mounted {
        return true;
    }
    match discovered {
        Some(mounts) => mounts.is_owned(target),
        None => true,
    }
}
