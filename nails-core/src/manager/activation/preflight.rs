//! Preflight Checks and Config Staging
//!
//! Handles pre-activation validation and config preparation.

use crate::cleanup::history::HistoryCleaner;
use crate::{Filesystem, NailsManager, Result, Stopwatch, Verbosity};

/// Security-sensitive patterns to remove from shell history during pre-activation cleanup.
/// These patterns indicate encrypted volume operations that should not remain on the REAL disk.
const PRE_ACTIVATION_CLEANUP_PATTERNS: &[&str] = &[
    "nails",
    "cryptsetup",
    "veracrypt",
    "luks",
    "luksOpen",
    "luksClose",
    "/dev/mapper",
];

impl<F: Filesystem> NailsManager<F> {
    /// Stage hidden config symlink and run preflight checks
    pub(super) fn run_preflight_phase(
        &self,
        no_preflight: bool,
        overlay_only: bool,
        verbosity: Verbosity,
        pre_activation_cleanup: bool,
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

        // Step 2.8: Pre-activation history cleanup (runs even with --no-preflight)
        // Security feature: Clean shell history BEFORE overlays are mounted to remove
        // evidence of cryptsetup, nails activate, etc. from the REAL disk.
        if pre_activation_cleanup {
            self.run_pre_activation_cleanup(verbosity);
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

    /// Run pre-activation history cleanup (best-effort)
    ///
    /// Cleans shell history BEFORE overlays are mounted to remove evidence of
    /// sensitive commands (nails, cryptsetup, veracrypt, luks, etc.) from the
    /// REAL disk. This is a critical security feature that ensures forensic
    /// evidence is removed from the actual storage, not just the overlay.
    ///
    /// # Best-Effort Approach
    ///
    /// - Failures are logged as warnings but don't fail activation
    /// - Continues even if individual shell history files can't be cleaned
    /// - This is intentional: security cleanup shouldn't block activation
    ///
    /// # Security Note
    ///
    /// This runs even when `--no-preflight` is set because it's a security
    /// feature, not a validation check.
    fn run_pre_activation_cleanup(&self, verbosity: Verbosity) {
        if verbosity >= Verbosity::Normal {
            tracing::info!("Running pre-activation history cleanup...");
        }

        let patterns: Vec<String> = PRE_ACTIVATION_CLEANUP_PATTERNS
            .iter()
            .map(|s| s.to_string())
            .collect();

        let cleaner = HistoryCleaner::new(self.filesystem.clone()).with_patterns(patterns);

        match cleaner.clean() {
            Ok(cleaned_items) => {
                if cleaned_items.is_empty() {
                    if verbosity >= Verbosity::Verbose {
                        tracing::debug!(
                            "Pre-activation cleanup: no history entries matched patterns"
                        );
                    }
                } else {
                    for item in &cleaned_items {
                        tracing::info!(cleanup_result = %item, "Pre-activation history cleanup");
                    }
                    if verbosity >= Verbosity::Normal {
                        tracing::info!(
                            patterns = ?PRE_ACTIVATION_CLEANUP_PATTERNS,
                            items_cleaned = cleaned_items.len(),
                            "Pre-activation history cleanup complete"
                        );
                    }
                }
            }
            Err(e) => {
                // Best-effort: log warning but continue with activation
                tracing::warn!(
                    error = %e,
                    "Pre-activation history cleanup failed (best-effort, continuing)"
                );
            }
        }
    }
}
