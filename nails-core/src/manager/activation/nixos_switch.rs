//! NixOS Profile Switching Logic
//!
//! Handles switching to the built NixOS profile with generation tracking.

use super::{ensure_run_current_system_symlink, select_system_profile};
use crate::{Filesystem, NailsError, NailsManager, Result, Stopwatch, Verbosity};

impl<F: Filesystem> NailsManager<F> {
    /// Switch NixOS profile and update nixos_generation (Story 4.7, AC3, Task 3.3)
    pub(super) fn switch_nixos_profile(
        &self,
        generation: &Option<String>,
        new_fingerprint: &Option<String>,
        verbosity: Verbosity,
    ) -> Result<()> {
        let Some(ref builder) = self.nixos_builder else {
            return Ok(());
        };

        if builder.is_flake() {
            self.switch_flake_profile(generation, new_fingerprint, verbosity)
        } else {
            self.switch_legacy_profile(generation, new_fingerprint, verbosity)
        }
    }

    /// Switch flake-based NixOS profile
    fn switch_flake_profile(
        &self,
        generation: &Option<String>,
        new_fingerprint: &Option<String>,
        verbosity: Verbosity,
    ) -> Result<()> {
        let builder = self.nixos_builder.as_ref().unwrap();
        let Some(generation_id) = generation else {
            return Ok(());
        };

        if verbosity >= Verbosity::Normal {
            tracing::info!("Switching to hidden NixOS configuration...");
        }

        if let Some(system_profile) = select_system_profile(&self.filesystem)? {
            ensure_run_current_system_symlink(&self.filesystem, &system_profile).map_err(|e| {
                NailsError::NixOSError(format!(
                    "Failed to prepare /run/current-system for NixOS switch: {}",
                    e
                ))
            })?;
        }

        let step_timer = Stopwatch::start();

        // Use "test" action to avoid updating bootloader (keeps /boot pristine)
        builder.switch_profile(generation_id, "test").map_err(|e| {
            // Story 9.3 AC#2: Structured error event for NixOS switch failure
            let error_msg = match &e {
                NailsError::NixOSError(msg) => {
                    format!("NixOS switch failed: {}", msg)
                }
                other => format!("NixOS switch failed: {}", other),
            };

            tracing::error!(
                error = %e,
                generation = generation_id,
                phase = "nixos_switch",
                rollback = true,
                "NixOS profile switch failed"
            );

            match e {
                NailsError::NixOSError(_) => NailsError::NixOSError(error_msg),
                other => other,
            }
        })?;

        if verbosity >= Verbosity::Normal {
            tracing::info!(
                step = "nixos_switch",
                duration_ms = step_timer.elapsed().as_millis() as u64,
                "✓ NixOS profile switched ({})",
                step_timer
            );
        }

        // Story 4.7, AC3: Update nixos_generation in state file after successful switch
        // Story 15.4, AC4: Persist config_fingerprint so fast path works on next activation
        let mut cached = self.cached_state.lock().unwrap();
        if let Some(ref mut state_file) = *cached {
            state_file.nixos_generation = Some(generation_id.clone());
            state_file.config_fingerprint = new_fingerprint.clone();

            // Save state file to disk (AC1, AC3)
            // State save failures here are non-critical - the switch succeeded and the system is functional.
            // The final ACTIVE transition save will persist this data. This incremental save aids crash recovery.
            drop(cached); // Release lock before saving
            if let Err(e) = self.save_cached_state()
                && verbosity >= Verbosity::Debug
            {
                tracing::warn!("Failed to save nixos_generation to state: {}", e);
            }
            // Continue - switch succeeded, state save is for tracking/crash recovery only
        }

        Ok(())
    }

    /// Switch legacy (non-flake) NixOS profile
    fn switch_legacy_profile(
        &self,
        generation: &Option<String>,
        new_fingerprint: &Option<String>,
        verbosity: Verbosity,
    ) -> Result<()> {
        let builder = self.nixos_builder.as_ref().unwrap();

        if verbosity >= Verbosity::Normal {
            tracing::info!("Switching to hidden NixOS configuration...");
        }

        if let Some(system_profile) = select_system_profile(&self.filesystem)? {
            ensure_run_current_system_symlink(&self.filesystem, &system_profile).map_err(|e| {
                NailsError::NixOSError(format!(
                    "Failed to prepare /run/current-system for NixOS switch: {}",
                    e
                ))
            })?;
        }

        let step_timer = Stopwatch::start();

        if let Some(generation_id) = generation {
            // Use "test" action to avoid updating bootloader (keeps /boot pristine)
            if let Err(e) = builder.switch_system_generation(generation_id, "test") {
                if verbosity >= Verbosity::Normal {
                    tracing::warn!(
                        error = %e,
                        generation = generation_id,
                        "Legacy fast-path switch failed, falling back to nixos-rebuild"
                    );
                }

                // Use "test" action to avoid updating bootloader (keeps /boot pristine)
                builder.switch_profile("", "test").map_err(|e| {
                    let error_msg = match &e {
                        NailsError::NixOSError(msg) => {
                            format!("Legacy NixOS switch failed: {}", msg)
                        }
                        other => format!("Legacy NixOS switch failed: {}", other),
                    };

                    tracing::error!(
                        error = %e,
                        phase = "nixos_switch",
                        rollback = true,
                        "Legacy NixOS switch failed"
                    );

                    match e {
                        NailsError::NixOSError(_) => NailsError::NixOSError(error_msg),
                        other => other,
                    }
                })?;
            }
        } else {
            // Use "test" action to avoid updating bootloader (keeps /boot pristine)
            builder.switch_profile("", "test").map_err(|e| {
                let error_msg = match &e {
                    NailsError::NixOSError(msg) => {
                        format!("Legacy NixOS switch failed: {}", msg)
                    }
                    other => format!("Legacy NixOS switch failed: {}", other),
                };

                tracing::error!(
                    error = %e,
                    phase = "nixos_switch",
                    rollback = true,
                    "Legacy NixOS switch failed"
                );

                match e {
                    NailsError::NixOSError(_) => NailsError::NixOSError(error_msg),
                    other => other,
                }
            })?;
        }

        if verbosity >= Verbosity::Normal {
            tracing::info!(
                step = "nixos_switch",
                duration_ms = step_timer.elapsed().as_millis() as u64,
                "✓ Legacy NixOS switch complete ({})",
                step_timer
            );
        }

        let mut cached = self.cached_state.lock().unwrap();
        if let Some(ref mut state_file) = *cached {
            if let Some(generation_id) = generation {
                state_file.nixos_generation = Some(generation_id.clone());
            } else if let Ok(current_gen) = builder.current_system_generation() {
                state_file.nixos_generation = current_gen;
            }
            state_file.config_fingerprint = new_fingerprint.clone();

            drop(cached);
            if let Err(e) = self.save_cached_state()
                && verbosity >= Verbosity::Debug
            {
                tracing::warn!("Failed to save nixos_generation to state: {}", e);
            }
        }

        Ok(())
    }
}
