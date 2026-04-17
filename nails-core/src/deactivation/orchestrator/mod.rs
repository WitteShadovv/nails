//! Deactivation orchestration logic
//!
//! Implements the core deactivation workflow: state transitions, cleanup,
//! overlay unmounting, and automatic rollback on failures.

mod cleanup;
mod unmount;

use super::report::{DeactivationReport, PostUnmountCleanupReport};
use crate::cleanup::history::truncate_all_history_files;
use crate::manager::{ensure_run_current_system_symlink, select_system_profile};
use crate::{
    CleanupConfig, CleanupManager, CleanupMode, CleanupReport, Filesystem, NailsError,
    NailsManager, Result, StateGuard, SystemState,
};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Controls deactivation behavior.
///
/// - `Normal`: Full cleanup with verification, rollback on cleanup errors.
///   Idempotent – returns `Ok` when the system is already inactive.
/// - `Emergency`: Fast cleanup (best-effort, non-fatal errors), skips
///   post-unmount cleanup. Fails if the system is not in `Active` state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeactivationMode {
    /// Run all steps including thorough cleanup with verification.
    Normal,
    /// Skip non-essential cleanup for speed; cleanup errors are non-fatal.
    Emergency,
}

/// Orchestrates the deactivation process
///
/// DeactivationOrchestrator coordinates:
/// 1. State transition (ACTIVE -> DEACTIVATING)
/// 2. Artifact cleanup (history, temp files, logs)
/// 3. Overlay unmounting (reverse LIFO order)
/// 4. Final state transition (DEACTIVATING -> INACTIVE)
///
/// # Rollback Guarantees
///
/// If any step fails, the orchestrator rolls back to ACTIVE state:
/// - Cleanup failure: Overlays remain mounted, state returns to ACTIVE
/// - Unmount failure: Remount any unmounted overlays, state returns to ACTIVE
///
/// # Generic Parameter
///
/// `F: Filesystem` - Abstracted filesystem operations for testability
///
/// # Requirements
///
/// - AC1: Generic struct with manager, cleanup_config
/// - AC2: run() method with 5-step sequence
/// - FR51: Remount overlays if cleanup fails
/// - FR62: Idempotent deactivation
/// - NFR13: Atomic operations
/// - NFR20: Rollback on failures
pub struct DeactivationOrchestrator<F: Filesystem> {
    manager: Arc<Mutex<NailsManager<F>>>,
    cleanup_config: CleanupConfig,
    mode: DeactivationMode,
    execute_switch_script: bool,
    restore_decoy_profile: bool,
}

impl<F: Filesystem + 'static> DeactivationOrchestrator<F> {
    /// Create a new DeactivationOrchestrator
    ///
    /// # Arguments
    ///
    /// * `manager` - Shared reference to NailsManager for state management
    /// * `cleanup_config` - Configuration for cleanup operations
    ///
    /// # Returns
    ///
    /// New DeactivationOrchestrator instance
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use nails_core::{DeactivationOrchestrator, CleanupConfig};
    /// use std::sync::{Arc, Mutex};
    ///
    /// let orchestrator = DeactivationOrchestrator::new(
    ///     Arc::clone(&manager),
    ///     CleanupConfig::default(),
    /// );
    /// ```
    pub fn new(manager: Arc<Mutex<NailsManager<F>>>, cleanup_config: CleanupConfig) -> Self {
        Self {
            manager,
            cleanup_config,
            mode: DeactivationMode::Normal,
            execute_switch_script: true,
            restore_decoy_profile: true,
        }
    }

    /// Set the deactivation mode (builder pattern).
    ///
    /// # Arguments
    ///
    /// * `mode` - `DeactivationMode::Normal` (default) or `DeactivationMode::Emergency`
    pub fn with_mode(mut self, mode: DeactivationMode) -> Self {
        self.mode = mode;
        self
    }

    /// Control whether the decoy switch script is executed after symlink preparation.
    pub(crate) fn with_switch_script_execution(mut self, execute_switch_script: bool) -> Self {
        self.execute_switch_script = execute_switch_script;
        self
    }

    /// Control whether the decoy profile symlink/switch path runs at all.
    pub(crate) fn with_decoy_profile_restore(mut self, restore_decoy_profile: bool) -> Self {
        self.restore_decoy_profile = restore_decoy_profile;
        self
    }

    /// Execute deactivation
    ///
    /// # Steps
    ///
    /// 1. Check if already inactive (idempotent)
    /// 2. Transition ACTIVE -> DEACTIVATING
    /// 3. Cleanup artifacts (Thorough mode)
    /// 4. Unmount overlays in reverse order
    /// 5. Transition DEACTIVATING -> INACTIVE
    ///
    /// # Returns
    ///
    /// `DeactivationReport` with full details of the operation.
    ///
    /// # Errors
    ///
    /// Returns Err with details if deactivation fails. State is rolled back.
    ///
    /// # Requirements
    ///
    /// - AC2: 5-step sequence implementation
    /// - AC3: Successful deactivation report
    /// - AC4: Rollback on cleanup failure
    /// - AC5: Rollback on unmount failure
    /// - AC7: Idempotent deactivation
    pub fn run(&self) -> Result<DeactivationReport> {
        let start = Instant::now();

        // Story 9.3 AC#3: Log deactivation started with state
        tracing::info!(phase = "deactivation", "Deactivation started");

        // Lock manager for the duration
        let mut manager = self
            .manager
            .lock()
            .map_err(|_| NailsError::InvalidState("Failed to acquire manager lock".to_string()))?;

        // Step 0: Check if already inactive (idempotent) - AC7
        // In Emergency mode, we do NOT allow idempotent behavior - fail if not Active
        let current_state = manager.current_state()?;
        if current_state == SystemState::Inactive {
            if self.mode == DeactivationMode::Emergency {
                return Err(NailsError::InvalidState(
                    "Cannot deactivate from state Inactive. Must be ACTIVE.".to_string(),
                ));
            }
            tracing::info!(
                state = ?current_state,
                already_inactive = true,
                "System already inactive, nothing to do"
            );
            return Ok(DeactivationReport {
                cleanup_report: CleanupReport::default(),
                unmounted_overlays: Vec::new(),
                duration: start.elapsed(),
                final_state: SystemState::Inactive,
                was_already_inactive: true,
                post_unmount_cleanup: PostUnmountCleanupReport::default(),
            });
        }

        // Verify we're in ACTIVE state
        if !current_state.is_active() {
            return Err(NailsError::InvalidState(format!(
                "Cannot deactivate from state {:?}. Must be ACTIVE.",
                current_state
            )));
        }

        // Extract overlays BEFORE transitioning to DEACTIVATING state
        // This fixes the bug where get_mounted_overlay_paths() returns empty vec for Deactivating state
        let overlays_to_unmount = match &current_state {
            SystemState::Active { overlays, .. } => overlays.clone(),
            _ => {
                return Err(NailsError::InvalidState(
                    "Cannot extract overlays: not in ACTIVE state".to_string(),
                ));
            }
        };

        // Step 1: Create StateGuard for ACTIVE -> DEACTIVATING transition
        // StateGuard will automatically rollback to ACTIVE if we don't call commit()
        let guard = StateGuard::new(Arc::clone(&self.manager), current_state.clone());

        // Transition to DEACTIVATING state
        let deactivating_state = SystemState::Deactivating {
            started_at: chrono::Utc::now(),
        };
        manager.update_state(deactivating_state)?;

        // Step 2: Cleanup artifacts - AC2, AC4
        // Normal mode: Thorough cleanup, fatal on errors
        // Emergency mode: Fast cleanup, best-effort (errors are non-fatal)
        let cleanup_start = Instant::now();
        let cleanup_report = if self.mode == DeactivationMode::Emergency {
            match self.execute_emergency_cleanup(&manager) {
                Ok(report) => {
                    tracing::info!(
                        cleaned_items = report.cleaned_items.len(),
                        errors = report.errors.len(),
                        duration_ms = cleanup_start.elapsed().as_millis() as u64,
                        "Emergency cleanup complete (best-effort)"
                    );
                    report
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        phase = "cleanup",
                        "Emergency cleanup failed (non-fatal) - continuing deactivation"
                    );
                    CleanupReport::default()
                }
            }
        } else {
            match self.execute_cleanup(&manager) {
                Ok(report) => {
                    // Story 9.3 AC#3: Log cleanup completion with structured fields
                    tracing::info!(
                        cleaned_items = report.cleaned_items.len(),
                        duration_ms = cleanup_start.elapsed().as_millis() as u64,
                        "Cleanup complete"
                    );
                    report
                }
                Err(e) => {
                    // Story 9.3 AC#2: Structured error event for cleanup failure
                    tracing::error!(
                        error = %e,
                        state = ?current_state,
                        rollback = true,
                        phase = "cleanup",
                        "Cleanup failed, keeping system ACTIVE with overlays mounted"
                    );
                    // IMPORTANT: Drop manager lock BEFORE returning so StateGuard can acquire it for rollback
                    drop(manager);
                    return Err(e);
                }
            }
        };

        // Step 3: Unmount overlays - AC2, AC5, AC6
        let unmount_start = Instant::now();
        let unmounted = match self.unmount_overlays(&manager, &overlays_to_unmount) {
            Ok(overlays) => {
                // Story 9.3 AC#3: Log overlays unmounted with structured fields
                // AC #3 specifies "unmounted_paths" for literal compliance
                tracing::info!(
                    unmounted_paths = ?overlays,
                    duration_ms = unmount_start.elapsed().as_millis() as u64,
                    "Overlays unmounted"
                );
                overlays
            }
            Err(e) => {
                // Story 9.3 AC#2: Structured error event for unmount failure
                tracing::error!(
                    error = %e,
                    state = ?current_state,
                    rollback = true,
                    phase = "unmount",
                    "Unmount failed, rolling back to ACTIVE"
                );
                // IMPORTANT: Drop manager lock BEFORE returning so StateGuard can acquire it for rollback
                drop(manager);
                return Err(e);
            }
        };

        // Step 3.5: Post-unmount cleanup
        // Normal mode: clean REAL DISK (not overlay layer) if enabled
        // Emergency mode: skip post-unmount cleanup (speed priority)
        let post_unmount_report = if self.mode == DeactivationMode::Emergency {
            tracing::debug!("Skipping post-unmount cleanup in emergency mode");
            PostUnmountCleanupReport::default()
        } else if self.cleanup_config.post_unmount_cleanup {
            self.execute_post_unmount_cleanup(&manager)
        } else {
            tracing::debug!("Post-unmount cleanup disabled in configuration");
            PostUnmountCleanupReport::default()
        };

        // Step 4: Clear overlay_status and transition to INACTIVE - AC2
        manager.clear_overlay_status_in_cache()?;
        let inactive_state = manager.current_state()?.complete_deactivation()?;
        manager.update_state(inactive_state)?;

        // Step 5: Switch to newest available base system generation (decoy)
        let switch_error = if !self.restore_decoy_profile {
            None
        } else if let Some(system_profile) = select_system_profile(manager.filesystem())? {
            tracing::info!("Switching to decoy NixOS configuration...");

            if let Err(e) = ensure_run_current_system_symlink(manager.filesystem(), &system_profile)
            {
                Some(NailsError::NixOSError(format!(
                    "Failed to prepare /run/current-system for NixOS switch: {}",
                    e
                )))
            } else if !self.execute_switch_script {
                None
            } else {
                let switch_script = system_profile.join("bin/switch-to-configuration");
                match manager.filesystem().path_exists(&switch_script) {
                    Ok(true) => {
                        if crate::runtime_safety::should_skip_host_interaction() {
                            // Skip actual switch-to-configuration execution in tests
                            None
                        } else {
                            match std::process::Command::new(&switch_script)
                                .arg("switch")
                                .output()
                            {
                                Ok(output) => {
                                    if output.status.success() {
                                        None
                                    } else {
                                        Some(NailsError::NixOSError(format!(
                                            "System profile switch failed: {}",
                                            String::from_utf8_lossy(&output.stderr)
                                        )))
                                    }
                                }
                                Err(e) => Some(NailsError::NixOSError(format!(
                                    "System profile switch failed: {}",
                                    e
                                ))),
                            }
                        }
                    }
                    Ok(false) => Some(NailsError::NixOSError(format!(
                        "System profile switch script missing: {}",
                        switch_script.display()
                    ))),
                    Err(e) => Some(e),
                }
            }
        } else {
            Some(NailsError::NixOSError(
                "No system profile available for decoy switch".into(),
            ))
        };

        if let Some(err) = switch_error {
            guard.commit();
            return Err(err);
        }

        // Step 6: Commit StateGuard (prevent rollback) - AC2
        guard.commit();

        // Story 9.3 AC#3: Log deactivation complete with structured fields
        let duration_ms = start.elapsed().as_millis() as u64;
        tracing::info!(
            duration_ms = duration_ms,
            state_to = ?SystemState::Inactive,
            unmounted_count = unmounted.len(),
            post_unmount_cleaned = post_unmount_report.cleaned_items.len(),
            "Deactivation complete"
        );

        Ok(DeactivationReport {
            cleanup_report,
            unmounted_overlays: unmounted,
            duration: start.elapsed(),
            final_state: SystemState::Inactive,
            was_already_inactive: false,
            post_unmount_cleanup: post_unmount_report,
        })
    }
}
