//! NixOS Profile Switching Logic (Step 9)
//!
//! Handles building (if needed) and switching to the hidden NixOS profile.
//! Both flake and legacy paths share the same control flow:
//!
//! 1. If Step 7 supplied a fast-path generation, attempt
//!    `switch-to-configuration test` directly.
//! 2. On failure (or if no cached generation), fall back to
//!    `nixos-rebuild test` which does a combined build + switch.
//! 3. Persist the resulting generation and fingerprint.

use super::{ensure_run_current_system_symlink, select_system_profile};
use crate::{Filesystem, NailsError, NailsManager, Result, Stopwatch, Verbosity};

impl<F: Filesystem> NailsManager<F> {
    /// Switch NixOS profile — unified for flake and legacy (Step 9).
    pub(super) fn switch_nixos_profile(
        &self,
        generation: &Option<String>,
        new_fingerprint: &Option<String>,
        verbosity: Verbosity,
    ) -> Result<()> {
        if self.nixos_builder.is_none() {
            return Ok(());
        }

        if verbosity >= Verbosity::Normal {
            tracing::info!("Switching to hidden NixOS configuration...");
        }

        // Ensure /run/current-system points at the right profile.
        if let Some(system_profile) = select_system_profile(&self.filesystem)? {
            ensure_run_current_system_symlink(&self.filesystem, &system_profile).map_err(|e| {
                NailsError::NixOSError(format!(
                    "Failed to prepare /run/current-system for NixOS switch: {}",
                    e
                ))
            })?;
        }

        let step_timer = Stopwatch::start();
        let builder = self.nixos_builder.as_ref().unwrap();

        // --- Fast path: try switching to cached generation directly -------
        // Both flake and legacy slow-paths use `nixos-rebuild test` which
        // writes to the system profile, so the cached generation ID is always
        // a system generation number.
        let mut switched = false;
        if let Some(generation_id) = generation {
            if verbosity >= Verbosity::Normal {
                tracing::info!(
                    generation = %generation_id,
                    "Attempting fast-path switch-to-configuration"
                );
            }

            match builder.switch_system_generation(generation_id, "test") {
                Ok(()) => {
                    switched = true;
                    if verbosity >= Verbosity::Normal {
                        tracing::info!(
                            step = "nixos_switch",
                            duration_ms = step_timer.elapsed().as_millis() as u64,
                            "NixOS switch complete via fast path ({})",
                            step_timer
                        );
                    }
                }
                Err(e) => {
                    if verbosity >= Verbosity::Normal {
                        tracing::warn!(
                            error = %e,
                            "Fast-path switch failed, falling back to nixos-rebuild"
                        );
                    }
                }
            }
        }

        // --- Slow path: nixos-rebuild test (build + switch) ---------------
        if !switched {
            builder.build_and_switch().map_err(|e| {
                let error_msg = format!("NixOS build+switch failed: {}", e);

                tracing::error!(
                    error = %e,
                    phase = "nixos_switch",
                    rollback = true,
                    "NixOS build+switch failed"
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
                    "NixOS build+switch complete ({})",
                    step_timer
                );
            }
        }

        // --- Persist generation + fingerprint -----------------------------
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
