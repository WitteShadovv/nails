//! Preflight Checks and Config Staging
//!
//! Handles pre-activation validation and config preparation.

use crate::{Filesystem, NailsManager, Result, Stopwatch, Verbosity};

impl<F: Filesystem> NailsManager<F> {
    /// Stage hidden config symlink and run preflight checks
    pub(super) fn run_preflight_phase(
        &self,
        no_preflight: bool,
        verbosity: Verbosity,
    ) -> Result<()> {
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
        self.run_preflight_checks()?;

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
