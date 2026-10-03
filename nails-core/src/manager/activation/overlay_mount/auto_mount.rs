//! Auto mode overlay mounting (dynamic target enumeration)

use super::{MountFailureMode, OverlayMountOutcome, build_overlay_targets, create_overlay_config};
use crate::{Filesystem, NailsError, NailsManager, OverlayConfig, Result, Verbosity};
use std::path::PathBuf;

impl<F: Filesystem> NailsManager<F> {
    /// Mount overlays in Auto mode (dynamic target enumeration).
    ///
    /// Auto mode selects its targets by enumerating the root and applying the
    /// platform exclusions, builds an [`OverlayConfig`] for each on the hidden
    /// volume (best-effort — a target whose config cannot be built is recorded and
    /// skipped), then hands the list to the shared loop in
    /// [`mount_overlay_targets`](NailsManager::mount_overlay_targets) with
    /// [`MountFailureMode::BestEffort`].
    pub(in crate::manager::activation) fn mount_auto_overlays(
        &self,
        tracker: &mut super::MountTracker<F>,
        strategy_options: &crate::overlay::OverlayStrategyOptions,
        verbosity: Verbosity,
        outcome: &mut OverlayMountOutcome,
    ) -> Result<()> {
        // Auto mode: enumerate root + apply exclusions, create overlays dynamically.
        let overlay_targets = build_overlay_targets(&self.filesystem, &self.config)?;
        // Checked again on the exact list about to be mounted: a top-level directory
        // created since the pre-flight checks is a new target.
        crate::preflight::ensure_targets_clear(&self.filesystem, &self.config, &overlay_targets)?;
        // Refuse before anything is stopped or mounted if a user's terminal
        // program would have to be force-terminated on any target.
        crate::overlay::refuse_interactive_terminations(&overlay_targets, strategy_options)?;

        // Resolve each target's overlay config on the hidden volume. A build failure
        // is best-effort: record it and carry on, exactly as the merged loop treats
        // a mount failure, so a single unbuildable target cannot abort the rest.
        let mut overlays: Vec<OverlayConfig> = Vec::new();
        let mut config_failures: Vec<(PathBuf, NailsError)> = Vec::new();
        for target in &overlay_targets {
            match create_overlay_config(&self.filesystem, target, &self.config.hidden_volume_root) {
                Ok(config) => overlays.push(config),
                Err(e) => {
                    tracing::warn!(
                        target = %target.display(),
                        error = %e,
                        "⚠ Could not create overlay config for {}: {}",
                        target.display(),
                        e
                    );
                    config_failures.push((target.clone(), e));
                }
            }
        }

        self.mount_overlay_targets(
            tracker,
            &overlays,
            config_failures,
            MountFailureMode::BestEffort,
            strategy_options,
            verbosity,
            outcome,
        )
    }
}
