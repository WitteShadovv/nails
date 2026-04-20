//! NixOS Config Fingerprinting (Step 7)
//!
//! Computes a config fingerprint and checks the fast-path cache.  No actual
//! `nixos-rebuild` runs here — the real build + switch is deferred to Step 9
//! so the display-manager restart (Step 8.5) always happens *before* the
//! potentially expensive rebuild.

use crate::{Filesystem, NailsManager, Result, Verbosity};

impl<F: Filesystem> NailsManager<F> {
    /// Compute NixOS config fingerprint and check fast-path cache (Step 7).
    ///
    /// Both flake and legacy paths are handled identically:
    /// 1. Read the two NixOS config files from the hidden volume.
    /// 2. Compute a fingerprint over them.
    /// 3. Compare against the stored fingerprint from the last successful
    ///    activation.  When they match *and* the stored generation is known,
    ///    carry it forward so Step 9 can attempt a cheap
    ///    `switch-to-configuration` before falling back to a full rebuild.
    ///
    /// Returns `(Option<fast_path_generation>, Option<fingerprint>)`.
    pub(super) fn build_nixos_profile(
        &self,
        verbosity: Verbosity,
    ) -> Result<(Option<String>, Option<String>)> {
        if self.nixos_builder.is_none() {
            return Ok((None, None));
        }

        if verbosity >= Verbosity::Normal {
            tracing::info!(
                "Computing NixOS config fingerprint — deferring rebuild until after overlays"
            );
        }

        // --- Read config files for fingerprint computation ----------------
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

        // --- Fast-path: check stored fingerprint + generation -------------
        let (stored_fp, stored_generation) = {
            let cached = self
                .cached_state
                .lock()
                .map_err(|e| crate::NailsError::LockPoisoned(e.to_string()))?;
            (
                cached.as_ref().and_then(|sf| sf.config_fingerprint.clone()),
                cached.as_ref().and_then(|sf| sf.nixos_generation.clone()),
            )
        };

        if verbosity >= Verbosity::Normal {
            tracing::info!(
                stored_fingerprint = %stored_fp.as_deref().unwrap_or("none"),
                current_fingerprint = %current_fp,
                stored_generation = %stored_generation.as_deref().unwrap_or("none"),
                "Fast-path check"
            );
        }

        let mut fast_path_generation: Option<String> = None;
        if stored_fp.as_deref() == Some(current_fp.as_str())
            && let Some(ref generation_id) = stored_generation
        {
            if verbosity >= Verbosity::Normal {
                tracing::info!(
                    generation = %generation_id,
                    "Fast path: fingerprint matches — will attempt generation switch at Step 9"
                );
            }
            fast_path_generation = Some(generation_id.clone());
        }

        Ok((fast_path_generation, Some(current_fp)))
    }
}
