// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Universal overlay mounting strategy with automatic process management
//!
//! Implements a 4-phase algorithm to mount overlays intelligently:
//! 1. Detect blocking processes
//! 2. Classify and restart safe/risky processes (the ones left running are the
//!    security-relevant signal — they keep writing to the decoy)
//! 3. Attempt a direct mount
//! 4. Fall back to a pivot mount if the direct mount is rejected (with consent)

use crate::{Filesystem, NailsError, Result};
use nix::errno::Errno;
use std::path::Path;

use super::pivot::{pivot_overlay_mount, snapshot_pivot_overlay_mount};
use super::types::{MountMethod, MountResult, OverlayStrategyOptions};

mod process_phase;
#[cfg(test)]
use process_phase::check_interactive_terminations;
pub use process_phase::refuse_interactive_terminations;
use process_phase::run_process_phase;

#[cfg(test)]
mod tests;

/// Filesystems that do not support overlayfs as a lower layer.
///
/// These lack POSIX semantics overlayfs requires (xattrs, d_type, etc.).
/// When the target mount point uses one of these, the snapshot pivot strategy
/// is used instead: copy contents to tmpfs, overlay the tmpfs, bind mount back.
pub const OVERLAY_INCOMPATIBLE_FSTYPES: &[&str] = &[
    "vfat",
    "fat",
    "msdos",
    "exfat",
    "ntfs",
    "ntfs3",
    "fuse.ntfs-3g",
];

/// Check whether a filesystem type supports overlayfs
fn fstype_supports_overlay(fstype: &str) -> bool {
    !OVERLAY_INCOMPATIBLE_FSTYPES.contains(&fstype)
}

/// Best-effort restart of services that were stopped during Phase 2 when the
/// mount ultimately fails. Delegates to [`ServiceController`] for socket-aware
/// start ordering.
fn restart_services_after_failure(services: &[String]) {
    crate::manager::helpers::ServiceController::restart_services_after_failure(services);
}

/// Mount overlay using the universal 4-phase algorithm
///
/// This function implements the **Universal Overlay Mounting Strategy** from
/// `/docs/architecture/universal-overlay-mounting-strategy.md`.
///
/// # Algorithm Phases
///
/// 1. **Phase 1: Detect** - Find processes using target directory
/// 2. **Phase 2: Classify & Restart** - Classify processes and restart safe/risky ones
/// 3. **Phase 3: Direct Mount** - Attempt a direct overlay mount
/// 4. **Phase 4: Pivot Fallback** - Use a pivot mount as last resort (with user consent)
///
/// # Arguments
///
/// * `fs` - Filesystem trait implementation
/// * `lower` - Read-only base layer (original filesystem content)
/// * `upper` - Upper layer directory (on hidden volume)
/// * `work` - Work directory for overlay
/// * `target` - Target directory to overlay (e.g., `/home`, `/etc`, `/var`)
/// * `options` - Strategy options controlling behavior
///
/// # Returns
///
/// * `Ok(MountResult)` - Mount succeeded, includes method and stopped services
/// * `Err(NailsError)` - Mount failed or user declined pivot
///
/// # Security Implications
///
/// The security posture is determined by surviving writers, not by the mount
/// method. A process that opened the target before the mount keeps resolving the
/// original inode and keeps writing to the decoy lower tree under **both** a
/// direct and a pivot mount; a direct mount does not give those pre-existing
/// processes a "unified view". The algorithm therefore minimises leakage by
/// restarting writers in Phase 2, and reports any writer it could not restart
/// via [`MountResult::survivors`]. A pivot mount is only accepted after
/// explicit user consent because it is the point at which a busy, still-referenced
/// target is overlaid anyway.
///
/// # Example
///
/// ```no_run
/// use nails_core::overlay::{mount_overlay_with_strategy, OverlayStrategyOptions, MountMethod};
/// use nails_core::filesystem::RealFilesystem;
/// use nails_core::process::detection::ProcSnapshot;
/// use std::path::Path;
///
/// let fs = RealFilesystem;
/// let options = OverlayStrategyOptions::default();
/// // One snapshot is captured per mount phase and shared across targets.
/// let snapshot = ProcSnapshot::capture()?;
///
/// let result = mount_overlay_with_strategy(
///     &fs,
///     &[Path::new("/home")],
///     Path::new("/mnt/hidden/home/.upper"),
///     Path::new("/mnt/hidden/home/.work"),
///     Path::new("/home"),
///     &options,
///     &snapshot,
/// )?;
///
/// match result.method {
///     MountMethod::Direct => println!("Mounted directly"),
///     MountMethod::Pivot => println!("Mounted via the pivot fallback"),
///     MountMethod::SnapshotPivot => println!("Mounted via the snapshot pivot"),
/// }
/// if result.surviving_writers() > 0 {
///     println!(
///         "⚠️  {} writer(s) still reference the decoy",
///         result.surviving_writers()
///     );
/// }
/// # Ok::<(), nails_core::NailsError>(())
/// ```
pub fn mount_overlay_with_strategy<F: Filesystem>(
    fs: &F,
    lower: &[&Path],
    upper: &Path,
    work: &Path,
    target: &Path,
    options: &OverlayStrategyOptions,
    snapshot: &crate::process::detection::ProcSnapshot,
) -> Result<MountResult> {
    use crate::process::detect_processes_using;
    use crate::prompts::{display_abort_message, prompt_pivot_mount_acceptance};

    // ========== Pre-check: Filesystem compatibility ==========
    //
    // Some filesystems (vfat, exfat, ntfs) lack POSIX semantics that overlayfs
    // requires — not just as mount target, but also as a lower layer (missing d_type).
    // Neither direct overlay nor plain pivot works. Instead, we use the "snapshot pivot":
    // copy target contents to a tmpfs in RAM, use that as the overlay lower layer,
    // then bind mount over the original.
    //
    // No --accept-pivot-risks flag needed because there's no split-view security concern
    // (no active processes on these mounts). Also bypasses --no-pivot for the same reason.
    let target_fstype = fs.get_filesystem_type(target)?;
    let fs_incompatible = target_fstype
        .as_deref()
        .is_some_and(|ft| !fstype_supports_overlay(ft));

    if fs_incompatible {
        let fstype = target_fstype.as_deref().unwrap_or("unknown");
        tracing::info!(
            target = %target.display(),
            fstype = fstype,
            "[Snapshot Pivot] {} is on {} (overlay-incompatible), copying to tmpfs",
            target.display(),
            fstype,
        );

        let pivot_info = snapshot_pivot_overlay_mount(fs, lower, upper, work, target)?;

        tracing::info!(
            target = %target.display(),
            snapshot = %pivot_info.lower.display(),
            "  ✓ Snapshot pivot succeeded for {} (snapshot: {})",
            target.display(),
            pivot_info.lower.display()
        );

        return Ok(MountResult {
            method: MountMethod::SnapshotPivot,
            stopped_services: Vec::new(),
            // Snapshot pivot is used for filesystems with no active writers, so
            // there is nothing left referencing the target.
            survivors: Vec::new(),
        });
    }

    // Skip process detection for tests/mock filesystems
    if options.skip_process_detection {
        tracing::info!("[Test Mode] Skipping process detection, attempting direct mount...");
        match fs.mount_overlay(lower, upper, work, target) {
            Ok(()) => {
                tracing::info!("  ✓ Direct overlay mount succeeded (test mode)");
                return Ok(MountResult {
                    method: MountMethod::Direct,
                    stopped_services: Vec::new(),
                    // Process detection is skipped in this mode, so no survivors
                    // are tracked.
                    survivors: Vec::new(),
                });
            }
            Err(e) => {
                return Err(e);
            }
        }
    }

    // ========== Phase 1: Detect Blocking Processes ==========

    tracing::info!(
        target_path = %target.display(),
        "[Phase 1: Detect] Detecting processes using {}...",
        target.display()
    );

    // Classify against the one `/proc` snapshot captured for this whole mount
    // phase, rather than walking `/proc` again for this target.
    let blocking = snapshot.processes_using(target);

    if blocking.is_empty() {
        tracing::info!("  Found 0 processes ✓");
    } else {
        tracing::info!(
            count = blocking.len(),
            "  Found {} processes",
            blocking.len()
        );
    }

    // ========== Phase 2: Classify and Restart Processes ==========
    //
    // Classification, the interactive-termination guard and the actual restarts
    // live in `run_process_phase` so they can be unit-tested with a scripted
    // command executor. An aborting guard returns here before any mount.
    let (stopped_services, survivors) = run_process_phase(
        blocking,
        target,
        options,
        &crate::process::restart::RealCommandExecutor,
    )?;

    // ========== Phase 3: Attempt Direct Overlay Mount ==========
    // (fs_incompatible targets already returned via pivot above)

    tracing::info!(
        target_path = %target.display(),
        "[Phase 3: Direct Mount] Attempting direct overlay mount for {}...",
        target.display()
    );

    match fs.mount_overlay(lower, upper, work, target) {
        Ok(()) => {
            tracing::info!(
                target_path = %target.display(),
                "  ✓ Direct overlay mount succeeded for {}",
                target.display()
            );
            return Ok(MountResult {
                method: MountMethod::Direct,
                stopped_services,
                survivors,
            });
        }
        Err(e) => match &e {
            // A busy or unsupported target reports EINVAL/EBUSY/EOPNOTSUPP; those
            // are recoverable via the pivot fallback. Any other errno (and any
            // non-mount error) is fatal. Branching on the typed errno avoids
            // depending on libc's human-readable error strings.
            NailsError::Mount { errno, .. }
                if matches!(*errno, Errno::EINVAL | Errno::EBUSY | Errno::EOPNOTSUPP) =>
            {
                tracing::warn!(
                    error = %e,
                    "  ✗ Direct mount failed, trying pivot fallback"
                );
                // Continue to Phase 4
            }
            _ => {
                // Other errors are fatal
                restart_services_after_failure(&stopped_services);
                return Err(e);
            }
        },
    }

    // ========== Phase 4: Pivot Mount Fallback ==========
    //
    // Reached only when the direct mount was rejected on a compatible filesystem
    // (EINVAL/EBUSY/EOPNOTSUPP). The pivot overlays the target anyway, so any
    // pre-existing writer keeps leaking to the decoy under it — respect --no-pivot
    // and prompt for consent.

    tracing::warn!("[Phase 4: Fallback] Direct mount failed, pivot mount required...");

    if !options.allow_pivot {
        tracing::warn!("  ✗ Pivot mount not allowed (--no-pivot flag)");
        display_abort_message(target);
        restart_services_after_failure(&stopped_services);
        return Err(NailsError::InvalidState(format!(
            "Pivot mount required for {} but --no-pivot flag specified",
            target.display()
        )));
    }

    // Re-detect blocking processes to show user what's still blocking
    let still_blocking = detect_processes_using(target)?;

    // Prompt for user acceptance (unless auto-accept enabled)
    if !options.auto_accept_pivot && !prompt_pivot_mount_acceptance(target, &still_blocking)? {
        tracing::warn!(target_path = %target.display(), "  ✗ User declined pivot mount for {}", target.display());
        display_abort_message(target);
        restart_services_after_failure(&stopped_services);
        return Err(NailsError::InvalidState(format!(
            "User declined pivot mount for {}",
            target.display()
        )));
    }

    tracing::warn!(
        target_path = %target.display(),
        "  ⚠️  User accepted pivot mount risk for {}",
        target.display()
    );

    // Perform pivot mount
    let pivot_info = match pivot_overlay_mount(fs, lower, upper, work, target) {
        Ok(info) => info,
        Err(e) => {
            restart_services_after_failure(&stopped_services);
            return Err(e);
        }
    };

    tracing::warn!(
        target_path = %target.display(),
        staging = %pivot_info.staging.display(),
        "  ⚠️  Pivot mount active for {} - split-view behavior enabled",
        target.display()
    );
    tracing::info!("  Staging: {}", pivot_info.staging.display());

    Ok(MountResult {
        method: MountMethod::Pivot,
        stopped_services,
        survivors,
    })
}
