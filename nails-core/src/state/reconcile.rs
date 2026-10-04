// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Reconcile persisted state against the boot and the live kernel mount table.
//!
//! `state.json` lives on the hidden root and survives reboots and crashes, so it
//! can disagree with reality: it may say `Active` after an unclean shutdown
//! mounted nothing, or `Inactive` while NAILS overlays are still live. Trusting
//! it blindly makes `activate` a silent no-op (mounting nothing, then writing the
//! shell integration straight onto the bare decoy home) and makes `status` lie.
//!
//! [`reconcile`] compares the persisted [`StateFile`] against three sources of
//! ground truth — the kernel boot id, the owner process, and the NAILS-owned
//! mounts discovered from `/proc/self/mountinfo` — and collapses them into a
//! single [`EffectiveState`] the commands can act on. It is a pure function over
//! its inputs so every outcome is hermetically testable; the manager wrapper
//! ([`reconcile_state`](crate::NailsManager::reconcile_state)) does the `/proc`
//! reads and the mount discovery and then calls it.

use super::{LoadOutcome, StateFile, SystemState};
use crate::filesystem::NailsMounts;
use std::path::PathBuf;

/// Which transitional operation a crashed state file was recording.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterruptedPhase {
    /// The crash happened while mounting overlays.
    Activating,
    /// The crash happened while tearing overlays down.
    Deactivating,
}

impl InterruptedPhase {
    /// A short lowercase label for diagnostics.
    pub fn as_str(self) -> &'static str {
        match self {
            InterruptedPhase::Activating => "activating",
            InterruptedPhase::Deactivating => "deactivating",
        }
    }
}

/// Which shape of inconsistency a [`EffectiveState::Degraded`] records.
///
/// The two are dangerous in opposite directions, so the consumers (activation's
/// refusal and status's posture) need to tell them apart without string-sniffing
/// the reason: an active system missing overlays leaks hidden writes onto the
/// decoy disk, while live NAILS mounts under an inactive state mean the backend
/// was torn down out from under them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DegradedKind {
    /// State is Active but one or more tracked overlays are not mounted (or none
    /// are): hidden writes may be reaching the decoy disk.
    ActiveOverlaysMissing,
    /// NAILS mounts are still live while the persisted state is not Active (it is
    /// Inactive, or a teardown that left mounts behind): an inconsistent system
    /// recovery must tear down.
    InactiveMountsLive,
}

/// The real state of the system after reconciling the persisted [`StateFile`]
/// against the current boot, the owner process, and the live mount table.
///
/// This is deliberately richer than [`SystemState`]: it separates a cleanly
/// active system from one that only *claims* to be active, and a safe-to-reset
/// stale file from a genuinely inconsistent one that must never be auto-reset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EffectiveState {
    /// State is Inactive and no NAILS mount is live. The system is the decoy.
    Inactive,
    /// State is Active and every tracked overlay is present in the mount table.
    VerifiedActive {
        /// The persistent overlay targets confirmed mounted.
        overlays: Vec<PathBuf>,
    },
    /// The state file records a live or transitional state but was written under
    /// a previous boot, so it is stale. It is safe to reset to Inactive; the
    /// caller keeps the cached build metadata (`hidden_toplevel`,
    /// `config_fingerprint`) because those survive a reboot.
    StaleFromPreviousBoot,
    /// A transitional state from the *current* boot whose owner process is gone:
    /// an activation or deactivation that crashed partway. Never auto-reset.
    Interrupted {
        /// Which operation was in progress when it was interrupted.
        phase: InterruptedPhase,
        /// Whether the recorded owner pid is still alive (pid reuse is possible,
        /// so an alive pid does not prove the operation is still running once the
        /// caller holds the exclusive state lock).
        owner_alive: bool,
    },
    /// The system is inconsistent and must not be trusted: either Active with
    /// overlays missing from the kernel, or Inactive with NAILS mounts still
    /// live. Hidden writes may be reaching the decoy disk. Never auto-reset.
    Degraded {
        /// Which direction the inconsistency runs (see [`DegradedKind`]).
        kind: DegradedKind,
        /// Human-readable explanation of the inconsistency.
        reason: String,
        /// NAILS-owned mount points still live, which recovery must tear down.
        remaining: Vec<PathBuf>,
    },
    /// The persisted state could not be read or trusted, so the real state is
    /// unknown. Fail closed rather than assume inactive.
    Unknown,
}

impl EffectiveState {
    /// Whether the system is cleanly, verifiably active.
    pub fn is_verified_active(&self) -> bool {
        matches!(self, EffectiveState::VerifiedActive { .. })
    }

    /// Whether the system is cleanly inactive (the decoy).
    pub fn is_inactive(&self) -> bool {
        matches!(self, EffectiveState::Inactive)
    }
}

/// Reconcile a persisted [`StateFile`] against ground truth.
///
/// * `outcome` — how the file was loaded; an unknown outcome short-circuits to
///   [`EffectiveState::Unknown`] so a damaged file never masquerades as inactive.
/// * `mounts` — the NAILS-owned mounts discovered from the live mount table.
/// * `current_boot_id` — `/proc/sys/kernel/random/boot_id` now, or `None` when
///   the kernel does not expose it.
/// * `owner_pid_alive` — whether the pid recorded in the state file is alive.
///
/// The function never performs I/O; the manager wrapper supplies every input.
pub fn reconcile(
    state: &StateFile,
    outcome: &LoadOutcome,
    mounts: &NailsMounts,
    current_boot_id: Option<&str>,
    owner_pid_alive: bool,
) -> EffectiveState {
    // A file that could not be read or trusted means the real state is unknown.
    // Never fall back to "inactive" when hidden mounts might still be live.
    if outcome.is_unknown() {
        return EffectiveState::Unknown;
    }

    let live = mounts.owned_mount_points();

    match &state.state {
        SystemState::Inactive => {
            if live.is_empty() {
                EffectiveState::Inactive
            } else {
                // Inactive on paper but NAILS overlays are mounted: hidden writes
                // may be reaching the decoy disk. Inconsistent, never auto-reset.
                EffectiveState::Degraded {
                    kind: DegradedKind::InactiveMountsLive,
                    reason: format!(
                        "state is inactive but {} NAILS mount(s) are still live",
                        live.len()
                    ),
                    remaining: live,
                }
            }
        }

        SystemState::Active { overlays, .. } => {
            if written_before_this_boot(state, current_boot_id) {
                return EffectiveState::StaleFromPreviousBoot;
            }
            let missing: Vec<PathBuf> = overlays
                .iter()
                .filter(|target| !mounts.is_owned(target))
                .cloned()
                .collect();

            if overlays.is_empty() {
                EffectiveState::Degraded {
                    kind: DegradedKind::ActiveOverlaysMissing,
                    reason: "state is active but records no overlays".to_string(),
                    remaining: live,
                }
            } else if missing.is_empty() {
                EffectiveState::VerifiedActive {
                    overlays: overlays.clone(),
                }
            } else {
                EffectiveState::Degraded {
                    kind: DegradedKind::ActiveOverlaysMissing,
                    reason: format!(
                        "state is active but {} of {} overlay(s) are not mounted: {}",
                        missing.len(),
                        overlays.len(),
                        join_paths(&missing)
                    ),
                    remaining: live,
                }
            }
        }

        SystemState::Activating { .. } | SystemState::Deactivating { .. } => {
            if written_before_this_boot(state, current_boot_id) {
                return EffectiveState::StaleFromPreviousBoot;
            }
            let phase = match &state.state {
                SystemState::Activating { .. } => InterruptedPhase::Activating,
                _ => InterruptedPhase::Deactivating,
            };
            EffectiveState::Interrupted {
                phase,
                owner_alive: owner_pid_alive,
            }
        }

        SystemState::Degraded {
            reason,
            remaining_mounts,
            ..
        } => EffectiveState::Degraded {
            // A persisted Degraded is a teardown that left NAILS mounts behind
            // while heading for Inactive: live mounts under a non-active state.
            kind: DegradedKind::InactiveMountsLive,
            reason: reason.clone(),
            // Prefer what the kernel actually still has over the recorded list.
            remaining: if live.is_empty() {
                remaining_mounts.clone()
            } else {
                live
            },
        },
    }
}

/// Whether the state file was written under a different boot than the current
/// one. Returns false when either boot id is unavailable: staleness cannot be
/// proven, so the caller falls through to verifying against the mount table.
fn written_before_this_boot(state: &StateFile, current_boot_id: Option<&str>) -> bool {
    match (state.boot_id.as_deref(), current_boot_id) {
        (Some(saved), Some(current)) => saved != current,
        _ => false,
    }
}

/// Join mount points into a comma-separated list for a diagnostic message.
fn join_paths(paths: &[PathBuf]) -> String {
    paths
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SystemState;
    use chrono::Utc;

    const BOOT_A: &str = "aaaaaaaa-0000-0000-0000-000000000000";
    const BOOT_B: &str = "bbbbbbbb-1111-1111-1111-111111111111";

    fn state_with(state: SystemState, boot_id: Option<&str>) -> StateFile {
        StateFile {
            state,
            boot_id: boot_id.map(str::to_string),
            ..StateFile::default()
        }
    }

    fn active(overlays: &[&str]) -> SystemState {
        SystemState::Active {
            decoy_writers: Vec::new(),
            activated_at: Utc::now(),
            overlays: overlays.iter().map(PathBuf::from).collect(),
        }
    }

    fn mounts_with_persistent(paths: &[&str]) -> NailsMounts {
        NailsMounts {
            persistent_overlays: paths.iter().map(PathBuf::from).collect(),
            ..NailsMounts::default()
        }
    }

    #[test]
    fn unknown_outcome_is_unknown_regardless_of_state() {
        let st = state_with(active(&["/home"]), Some(BOOT_A));
        let mounts = mounts_with_persistent(&["/home"]);
        for outcome in [LoadOutcome::Corrupt, LoadOutcome::Unreadable] {
            let eff = reconcile(&st, &outcome, &mounts, Some(BOOT_A), true);
            assert_eq!(eff, EffectiveState::Unknown, "{outcome:?}");
        }
    }

    #[test]
    fn active_different_boot_is_stale() {
        let st = state_with(active(&["/home", "/var"]), Some(BOOT_A));
        let mounts = NailsMounts::default();
        let eff = reconcile(&st, &LoadOutcome::Loaded, &mounts, Some(BOOT_B), false);
        assert_eq!(eff, EffectiveState::StaleFromPreviousBoot);
    }

    #[test]
    fn active_same_boot_all_overlays_mounted_is_verified() {
        let st = state_with(active(&["/home", "/var"]), Some(BOOT_A));
        let mounts = mounts_with_persistent(&["/home", "/var"]);
        let eff = reconcile(&st, &LoadOutcome::Loaded, &mounts, Some(BOOT_A), true);
        assert_eq!(
            eff,
            EffectiveState::VerifiedActive {
                overlays: vec![PathBuf::from("/home"), PathBuf::from("/var")],
            }
        );
    }

    #[test]
    fn active_same_boot_one_overlay_missing_is_degraded() {
        let st = state_with(active(&["/home", "/var"]), Some(BOOT_A));
        let mounts = mounts_with_persistent(&["/home"]);
        let eff = reconcile(&st, &LoadOutcome::Loaded, &mounts, Some(BOOT_A), true);
        match eff {
            EffectiveState::Degraded {
                kind,
                reason,
                remaining,
            } => {
                assert_eq!(kind, DegradedKind::ActiveOverlaysMissing);
                assert!(reason.contains("/var"), "reason: {reason}");
                assert_eq!(remaining, vec![PathBuf::from("/home")]);
            }
            other => panic!("expected Degraded, got {other:?}"),
        }
    }

    #[test]
    fn active_same_boot_no_overlays_mounted_is_degraded() {
        // The headline done-when: a stale Active with nothing actually mounted
        // must be Degraded (so activate refuses) rather than a silent no-op.
        let st = state_with(active(&["/home"]), Some(BOOT_A));
        let mounts = NailsMounts::default();
        let eff = reconcile(&st, &LoadOutcome::Loaded, &mounts, Some(BOOT_A), true);
        assert!(matches!(eff, EffectiveState::Degraded { .. }));
    }

    #[test]
    fn active_recording_no_overlays_is_degraded() {
        let st = state_with(active(&[]), Some(BOOT_A));
        let mounts = NailsMounts::default();
        let eff = reconcile(&st, &LoadOutcome::Loaded, &mounts, Some(BOOT_A), true);
        assert!(matches!(eff, EffectiveState::Degraded { .. }));
    }

    #[test]
    fn active_with_unknown_boot_ids_falls_through_to_mount_verification() {
        // Kernel exposes no boot id: cannot prove staleness, so verify mounts.
        let st = state_with(active(&["/home"]), None);
        let mounts = mounts_with_persistent(&["/home"]);
        let eff = reconcile(&st, &LoadOutcome::Loaded, &mounts, None, true);
        assert!(eff.is_verified_active());
    }

    #[test]
    fn activating_same_boot_dead_pid_is_interrupted() {
        let st = state_with(
            SystemState::Activating {
                started_at: Utc::now(),
            },
            Some(BOOT_A),
        );
        let mounts = NailsMounts::default();
        let eff = reconcile(&st, &LoadOutcome::Loaded, &mounts, Some(BOOT_A), false);
        assert_eq!(
            eff,
            EffectiveState::Interrupted {
                phase: InterruptedPhase::Activating,
                owner_alive: false,
            }
        );
    }

    #[test]
    fn deactivating_same_boot_dead_pid_is_interrupted() {
        let st = state_with(
            SystemState::Deactivating {
                started_at: Utc::now(),
            },
            Some(BOOT_A),
        );
        let mounts = NailsMounts::default();
        let eff = reconcile(&st, &LoadOutcome::Loaded, &mounts, Some(BOOT_A), false);
        assert_eq!(
            eff,
            EffectiveState::Interrupted {
                phase: InterruptedPhase::Deactivating,
                owner_alive: false,
            }
        );
    }

    #[test]
    fn activating_different_boot_is_stale_not_interrupted() {
        let st = state_with(
            SystemState::Activating {
                started_at: Utc::now(),
            },
            Some(BOOT_A),
        );
        let mounts = NailsMounts::default();
        let eff = reconcile(&st, &LoadOutcome::Loaded, &mounts, Some(BOOT_B), false);
        assert_eq!(eff, EffectiveState::StaleFromPreviousBoot);
    }

    #[test]
    fn inactive_with_a_nails_overlay_is_degraded() {
        let st = state_with(SystemState::Inactive, Some(BOOT_A));
        let mounts = mounts_with_persistent(&["/home"]);
        let eff = reconcile(&st, &LoadOutcome::Loaded, &mounts, Some(BOOT_A), true);
        match eff {
            EffectiveState::Degraded {
                kind, remaining, ..
            } => {
                assert_eq!(kind, DegradedKind::InactiveMountsLive);
                assert_eq!(remaining, vec![PathBuf::from("/home")]);
            }
            other => panic!("expected Degraded, got {other:?}"),
        }
    }

    #[test]
    fn inactive_with_no_mounts_is_inactive() {
        let st = state_with(SystemState::Inactive, Some(BOOT_A));
        let mounts = NailsMounts::default();
        let eff = reconcile(&st, &LoadOutcome::Loaded, &mounts, Some(BOOT_A), false);
        assert_eq!(eff, EffectiveState::Inactive);
    }

    #[test]
    fn missing_outcome_is_treated_as_loaded_inactive() {
        // A missing file legitimately means inactive, not unknown.
        let st = state_with(SystemState::Inactive, None);
        let mounts = NailsMounts::default();
        let eff = reconcile(&st, &LoadOutcome::Missing, &mounts, Some(BOOT_A), false);
        assert_eq!(eff, EffectiveState::Inactive);
    }

    #[test]
    fn degraded_state_stays_degraded_and_reports_live_mounts() {
        let st = state_with(
            SystemState::Degraded {
                since: Utc::now(),
                reason: "unmount of /home failed".to_string(),
                remaining_mounts: vec![PathBuf::from("/home")],
            },
            Some(BOOT_A),
        );
        let mounts = mounts_with_persistent(&["/home"]);
        let eff = reconcile(&st, &LoadOutcome::Loaded, &mounts, Some(BOOT_A), false);
        match eff {
            EffectiveState::Degraded { remaining, .. } => {
                assert_eq!(remaining, vec![PathBuf::from("/home")]);
            }
            other => panic!("expected Degraded, got {other:?}"),
        }
    }
}
