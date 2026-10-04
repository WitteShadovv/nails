// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Deactivation report structure and formatting
//!
//! Provides `DeactivationReport` for tracking deactivation operation results,
//! including cleanup details, unmounted overlays, duration, and final state.

use crate::{CleanupReport, SystemState};
use std::path::PathBuf;
use std::time::Duration;

/// Report of post-unmount cleanup operations on the real disk
///
/// This tracks the second phase of cleanup that runs AFTER overlay unmount
/// to clean history files on the actual filesystem (not the overlay layer).
#[derive(Debug, Clone, Default)]
pub struct PostUnmountCleanupReport {
    /// Items that were successfully cleaned from the real disk
    pub cleaned_items: Vec<String>,

    /// Warnings encountered during cleanup (best-effort continues)
    pub warnings: Vec<String>,

    /// Whether post-unmount cleanup was performed
    pub was_performed: bool,
}

/// Report of deactivation operations
///
/// Provides detailed accounting of what was cleaned, which overlays were unmounted,
/// timing information, and the final system state after deactivation.
///
/// # Fields
///
/// - `cleanup_report`: Results from CleanupManager (history, temp files, logs)
/// - `unmounted_overlays`: List of overlay paths that were successfully unmounted
/// - `failed_overlays`: Overlays whose unmount failed after both graceful and
///   forced attempts
/// - `remaining_mounts`: NAILS mounts still live after every target was attempted
///   (non-empty only for a degraded teardown)
/// - `duration`: Total time taken for the deactivation operation
/// - `final_state`: System state after deactivation (Inactive on success,
///   Degraded when overlays were left behind)
/// - `was_already_inactive`: Whether system was already inactive (idempotent case)
/// - `post_unmount_cleanup`: Results from the post-unmount cleanup phase
#[derive(Debug, Clone)]
pub struct DeactivationReport {
    /// Cleanup operation results (Phase 1: overlay layer cleanup)
    pub cleanup_report: CleanupReport,

    /// Overlays that were unmounted
    pub unmounted_overlays: Vec<String>,

    /// Overlays whose unmount failed after both graceful and forced attempts.
    pub failed_overlays: Vec<String>,

    /// NAILS mounts still live after the teardown attempted every target.
    ///
    /// Non-empty only for a degraded teardown: the system is recorded as
    /// [`SystemState::Degraded`](crate::SystemState) and never returns to
    /// `Active`, because a detached overlay would route hidden-session writes
    /// onto the decoy disk.
    pub remaining_mounts: Vec<PathBuf>,

    /// Total duration of deactivation
    pub duration: Duration,

    /// Final system state after deactivation
    pub final_state: SystemState,

    /// Whether deactivation was a no-op (already inactive)
    pub was_already_inactive: bool,

    /// Post-unmount cleanup results (Phase 2: real disk cleanup)
    pub post_unmount_cleanup: PostUnmountCleanupReport,

    /// Overlays that only came down after the forced (lazy) detach fallback,
    /// because the graceful unmount failed. Empty when every overlay detached
    /// cleanly. An emergency teardown expects these when processes still hold the
    /// mount; they signal that the backend cannot be closed until those holders
    /// exit (or the host reboots).
    pub force_detached_overlays: Vec<String>,

    /// Whether the page cache was dropped after unmount (emergency only).
    pub page_cache_dropped: bool,

    /// Result of the opt-in post-unmount history-truncation check.
    ///
    /// `None` when the check did not run (no post-unmount edit was performed);
    /// `Some(true)` when every decoy history file was verified small afterwards,
    /// `Some(false)` when one was still large enough to carry artifacts.
    pub history_truncation_verified: Option<bool>,

    /// Whether the volatile runtime journal under `/run/log/journal` was scrubbed
    /// after unmount.
    ///
    /// journald's volatile store keeps a hidden session's records in RAM on a
    /// decoy with no persistent journal; `/run` is never overlaid, so teardown
    /// scrubs it explicitly once journald has been restarted onto the decoy.
    pub runtime_journal_scrubbed: bool,

    /// Whether only a full reboot is a complete remedy.
    ///
    /// `true` after a teardown that does not reboot on its own (emergency and
    /// recovery): the on-disk and runtime journals are handled, but kernel and RAM
    /// residue of the hidden session can only be cleared by powering the machine
    /// off, so the operator is warned.
    pub reboot_recommended: bool,
}

impl DeactivationReport {
    /// Check if deactivation completed successfully
    ///
    /// Returns true if the final state is Inactive, indicating successful deactivation.
    pub fn is_successful(&self) -> bool {
        self.final_state == SystemState::Inactive
    }
}

impl std::fmt::Display for DeactivationReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.was_already_inactive {
            writeln!(f, "✓ Already inactive - no action needed")?;
            return Ok(());
        }

        writeln!(f, "Deactivation Report")?;
        writeln!(f, "===================")?;
        writeln!(f, "Duration: {:?}", self.duration)?;
        writeln!(f, "Final State: {:?}", self.final_state)?;
        writeln!(f)?;

        // Cleanup summary (Phase 1: overlay layer)
        writeln!(f, "Phase 1 - Overlay Cleanup:")?;
        for item in &self.cleanup_report.cleaned_items {
            writeln!(f, "  ✓ {}", item)?;
        }

        // Unmounted overlays
        writeln!(f)?;
        writeln!(f, "Unmounted Overlays:")?;
        for overlay in &self.unmounted_overlays {
            writeln!(f, "  ✓ {}", overlay)?;
        }

        // Overlays that could not be unmounted (degraded teardown)
        if !self.failed_overlays.is_empty() {
            writeln!(f)?;
            writeln!(f, "Failed to Unmount:")?;
            for overlay in &self.failed_overlays {
                writeln!(f, "  ✗ {}", overlay)?;
            }
        }

        // NAILS mounts still live after the teardown (degraded teardown)
        if !self.remaining_mounts.is_empty() {
            writeln!(f)?;
            writeln!(f, "Still Mounted (degraded):")?;
            for mount in &self.remaining_mounts {
                writeln!(f, "  ! {}", mount.display())?;
            }
            writeln!(f)?;
            writeln!(
                f,
                "Run `nails emergency` or `nails recover` to finish the teardown."
            )?;
        }

        // Overlays that only came down after the forced detach fallback.
        if !self.force_detached_overlays.is_empty() {
            writeln!(f)?;
            writeln!(f, "Force-Detached (processes still held the mount):")?;
            for overlay in &self.force_detached_overlays {
                writeln!(f, "  ! {}", overlay)?;
            }
        }

        if self.page_cache_dropped {
            writeln!(f)?;
            writeln!(f, "✓ Page cache dropped")?;
        }

        if let Some(passed) = self.history_truncation_verified {
            writeln!(f)?;
            if passed {
                writeln!(f, "✓ History truncation verified")?;
            } else {
                writeln!(f, "⚠ History truncation incomplete: some files remain")?;
            }
        }

        // Post-unmount cleanup (Phase 2: real disk)
        if self.post_unmount_cleanup.was_performed {
            writeln!(f)?;
            writeln!(f, "Phase 2 - Real Disk Cleanup:")?;
            for item in &self.post_unmount_cleanup.cleaned_items {
                writeln!(f, "  ✓ {}", item)?;
            }
            for warning in &self.post_unmount_cleanup.warnings {
                writeln!(f, "  ⚠ {}", warning)?;
            }
        }

        if self.runtime_journal_scrubbed {
            writeln!(f)?;
            writeln!(f, "✓ Runtime journal scrubbed (/run/log/journal)")?;
        }

        if self.reboot_recommended {
            writeln!(f)?;
            writeln!(
                f,
                "⚠ Only a full reboot is a complete remedy: this teardown does not \
                 reboot, so kernel and RAM residue of the hidden session remains until \
                 the machine is powered off."
            )?;
        }

        if self.is_successful() {
            writeln!(f)?;
            writeln!(f, "✓ Deactivation complete")?;
        }

        Ok(())
    }
}
