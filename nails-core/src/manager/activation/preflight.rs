//! Preflight Checks and Config Staging
//!
//! Handles pre-activation validation and config preparation.

use crate::{Filesystem, NailsManager, Result, Stopwatch, Verbosity};

impl<F: Filesystem> NailsManager<F> {
    /// Stage hidden config symlink and run preflight checks
    pub(super) fn run_preflight_phase(
        &self,
        no_preflight: bool,
        overlay_only: bool,
        verbosity: Verbosity,
    ) -> Result<()> {
        // Step 2.5: Probe symlink support on hidden volume before staging.
        // Catches FAT32/exFAT volumes early with a clear error message.
        match self
            .filesystem
            .supports_symlinks(&self.config.hidden_volume_root)
        {
            Ok(false) => {
                let msg = format!(
                    "Filesystem at {} does not support symbolic links. \
                     The hidden volume must be formatted with a Linux filesystem (e.g. ext4). \
                     FAT32 and exFAT do not support symlinks.",
                    self.config.hidden_volume_root.display()
                );
                if no_preflight {
                    tracing::warn!("{}", msg);
                } else {
                    return Err(crate::NailsError::NixOSError(msg));
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "Could not probe symlink support; continuing");
            }
            Ok(true) => {}
        }

        // Step 2.75: Stage hidden config symlink before pre-flight checks (Story 15.2).
        // This ensures NixOSConfigCheck can validate the staged link.
        if let Err(e) =
            crate::stage_hidden_config_symlink(&self.filesystem, &self.config.hidden_volume_root)
        {
            if no_preflight {
                tracing::warn!(
                    error = %e,
                    "Skipping staged config failure due to --no-preflight (activation may not use hidden config)"
                );
            } else {
                tracing::error!(
                    error = %e,
                    "Failed to stage hidden config symlink before pre-flight checks"
                );
                return Err(e);
            }
        }

        // Step 3: Run pre-flight checks (unless skipped)
        if no_preflight {
            if verbosity >= Verbosity::Normal {
                tracing::warn!("DANGER: Skipping pre-flight checks. Activation may fail.");
            }
            return Ok(());
        }

        if verbosity >= Verbosity::Normal {
            tracing::info!("Running pre-flight checks...");
        }

        let step_timer = Stopwatch::start();
        self.run_preflight_checks(overlay_only)?;

        if verbosity >= Verbosity::Normal {
            // AC #1: Pre-flight checks event with duration_ms field
            tracing::info!(
                duration_ms = step_timer.elapsed().as_millis() as u64,
                "Pre-flight checks passed"
            );
        }

        Ok(())
    }
}
