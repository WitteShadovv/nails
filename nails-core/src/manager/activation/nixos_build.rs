//! NixOS Profile Building with Fingerprinting
//!
//! Handles NixOS configuration building with fast-path fingerprint optimization.

use crate::{Filesystem, NailsError, NailsManager, Result, Stopwatch, Verbosity};

impl<F: Filesystem> NailsManager<F> {
    /// Build NixOS profile (if NixOSBuilder configured)
    ///
    /// Story 15.4: Use fingerprint-based fast path. We compute a fingerprint of the
    /// two NixOS config files that live in the hidden volume. If the fingerprint
    /// matches the one we persisted after the last successful activation, the cached
    /// profile is reused and the expensive `nixos-rebuild` invocation is skipped.
    /// `new_fingerprint` is carried through to Step 9 so it can be persisted after a
    /// successful `switch-to-configuration`.
    ///
    /// Returns: (generation_id, fingerprint)
    pub(super) fn build_nixos_profile(
        &self,
        verbosity: Verbosity,
    ) -> Result<(Option<String>, Option<String>)> {
        let Some(ref builder) = self.nixos_builder else {
            return Ok((None, None));
        };

        // Handle legacy (non-flake) configs
        if !builder.is_flake() {
            return self.handle_legacy_config_fingerprint(verbosity);
        }

        // Handle flake-based configs
        if verbosity >= Verbosity::Normal {
            tracing::info!("Building NixOS profile...");
        }

        // Story 15.4, AC1: compute config fingerprint
        let hw_path = self
            .config
            .hidden_volume_root
            .join("etc/nixos/hardware-configuration.nix");
        let cfg_path = self
            .config
            .hidden_volume_root
            .join("config/nixos/configuration.nix");

        // Read config files for fingerprint computation (Story 15.4, AC1)
        // Log warnings but continue if files are missing - build will fail later if truly required
        let hw_content = match self.filesystem.read_file_content(&hw_path) {
            Ok(content) => content,
            Err(e) => {
                tracing::warn!(
                    path = %hw_path.display(),
                    error = %e,
                    "Failed to read hardware-configuration.nix for fingerprint, using empty content"
                );
                String::new()
            }
        };
        let cfg_content = match self.filesystem.read_file_content(&cfg_path) {
            Ok(content) => content,
            Err(e) => {
                tracing::warn!(
                    path = %cfg_path.display(),
                    error = %e,
                    "Failed to read configuration.nix for fingerprint, using empty content"
                );
                String::new()
            }
        };

        let current_fp = crate::nixos::compute_config_fingerprint(&hw_content, &cfg_content);

        // Load stored fingerprint from persisted state (may be None on first run)
        let stored_fp: Option<String> = {
            let cached = self.cached_state.lock().unwrap();
            cached.as_ref().and_then(|sf| sf.config_fingerprint.clone())
        };

        let step_timer = Stopwatch::start();

        // Story 15.4, AC2/AC3: fast-path decision
        // Story 15.5: when build is required, build_profile_with_fingerprint() delegates
        // to build_profile_missing_only() which reuses the existing store path when
        // available, and always passes --no-update-lock-file to avoid package updates.
        let (generation_id, fp_out, fast_path_used) = builder
            .build_profile_with_fingerprint(&current_fp, stored_fp.as_deref())
            .map_err(|e| {
                // Story 9.3 AC#2: Structured error event for NixOS build failure
                let error_msg = match &e {
                    NailsError::NixOSError(msg) => {
                        format!("NixOS build failed: {}", msg)
                    }
                    other => format!("NixOS build failed: {}", other),
                };

                tracing::error!(
                    error = %e,
                    phase = "nixos_build",
                    rollback = true,
                    "NixOS profile build failed"
                );

                match e {
                    NailsError::NixOSError(_) => NailsError::NixOSError(error_msg),
                    other => other,
                }
            })?;

        if verbosity >= Verbosity::Normal {
            if fast_path_used {
                tracing::info!(
                    step = "nixos_build",
                    duration_ms = step_timer.elapsed().as_millis() as u64,
                    generation = generation_id,
                    "NixOS profile ready (fast path): generation {} ({})",
                    generation_id,
                    step_timer
                );
            } else {
                tracing::info!(
                    step = "nixos_build",
                    duration_ms = step_timer.elapsed().as_millis() as u64,
                    generation = generation_id,
                    "✓ NixOS profile ready: generation {} ({})",
                    generation_id,
                    step_timer
                );
            }
        }

        Ok((Some(generation_id), Some(fp_out)))
    }

    /// Handle legacy (non-flake) NixOS configuration fingerprinting
    fn handle_legacy_config_fingerprint(
        &self,
        verbosity: Verbosity,
    ) -> Result<(Option<String>, Option<String>)> {
        if verbosity >= Verbosity::Normal {
            tracing::info!(
                "Legacy NixOS config detected — deferring nixos-rebuild switch until after /etc overlay"
            );
        }

        // Still compute fingerprint so we can persist it after switch.
        let hw_path = self
            .config
            .hidden_volume_root
            .join("etc/nixos/hardware-configuration.nix");
        let cfg_path = self
            .config
            .hidden_volume_root
            .join("config/nixos/configuration.nix");

        let hw_content = match self.filesystem.read_file_content(&hw_path) {
            Ok(content) => content,
            Err(e) => {
                tracing::warn!(
                    path = %hw_path.display(),
                    error = %e,
                    "Failed to read hardware-configuration.nix for fingerprint, using empty content"
                );
                String::new()
            }
        };
        let cfg_content = match self.filesystem.read_file_content(&cfg_path) {
            Ok(content) => content,
            Err(e) => {
                tracing::warn!(
                    path = %cfg_path.display(),
                    error = %e,
                    "Failed to read configuration.nix for fingerprint, using empty content"
                );
                String::new()
            }
        };

        let current_fp = crate::nixos::compute_config_fingerprint(&hw_content, &cfg_content);

        let (stored_fp, stored_generation) = {
            let cached = self.cached_state.lock().unwrap();
            (
                cached.as_ref().and_then(|sf| sf.config_fingerprint.clone()),
                cached.as_ref().and_then(|sf| sf.nixos_generation.clone()),
            )
        };

        // Debug visibility into fast-path decision (Story 15.4)
        if verbosity >= Verbosity::Normal {
            tracing::info!(
                stored_fingerprint = %stored_fp.as_deref().unwrap_or("none"),
                current_fingerprint = %current_fp,
                stored_generation = %stored_generation.as_deref().unwrap_or("none"),
                "Legacy fast-path check"
            );
        }

        let mut fast_path_generation: Option<String> = None;
        if stored_fp.as_deref() == Some(current_fp.as_str())
            && let Some(ref generation_id) = stored_generation
        {
            if verbosity >= Verbosity::Normal {
                tracing::info!(
                    generation = %generation_id,
                    "Legacy fast path: fingerprint matches — attempting generation switch"
                );
            }
            fast_path_generation = Some(generation_id.clone());
        }

        Ok((fast_path_generation, Some(current_fp)))
    }
}
