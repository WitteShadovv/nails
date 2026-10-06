// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Explicit mode overlay mounting (pre-configured overlays)

use super::{MountFailureMode, OverlayMountOutcome};
use crate::{Filesystem, NailsError, NailsManager, Result, Verbosity};
use std::path::PathBuf;

impl<F: Filesystem> NailsManager<F> {
    /// Mount overlays in Explicit mode (pre-configured overlays).
    ///
    /// Explicit mode uses the configured overlays verbatim after the platform
    /// policy checks, then hands them to the shared loop in
    /// [`mount_overlay_targets`](NailsManager::mount_overlay_targets) with
    /// [`MountFailureMode::FailFast`].
    pub(in crate::manager::activation) fn mount_explicit_overlays(
        &self,
        tracker: &mut super::MountTracker<F>,
        runtime_root: &std::path::Path,
        strategy_options: &crate::overlay::OverlayStrategyOptions,
        verbosity: Verbosity,
        outcome: &mut OverlayMountOutcome,
    ) -> Result<()> {
        // Security check: fail if no overlays configured (would leave system
        // unprotected).
        if self.config.overlays.is_empty() {
            return Err(NailsError::ConfigError(
                "Explicit mode configured but no overlays defined - system would have NO forensic protection. \
                 Add overlays to config or switch to overlay_mode: auto".to_string()
            ));
        }

        // Refuse overlaying anything the active platform never overlays (the
        // pseudo-filesystems and the hidden-root mount) or keeps read-only (the
        // base-OS trees such as /usr on an FHS host). This is the policy-driven
        // replacement for the former hardcoded /bin,/usr block: on NixOS those two
        // trees are legitimately overlaid, while on Debian /usr is read-only.
        let policy = crate::platform::detect_platform(&self.filesystem)?.overlay_policy();
        for overlay in &self.config.overlays {
            let target = overlay.target.as_path();
            if policy.is_never_overlay(target, &self.config.hidden_volume_root)
                || policy.read_only.iter().any(|tree| tree == target)
            {
                return Err(NailsError::InvalidState(format!(
                    "Overlaying system tree {} is blocked: it is kept read-only or must never be overlaid on this platform",
                    overlay.target.display()
                )));
            }
        }

        // A target that covers the hidden volume (for example through a symlink the
        // lexical config check cannot see) would hide the layers it writes to.
        let targets: Vec<PathBuf> = self
            .config
            .overlays
            .iter()
            .map(|overlay| overlay.target.clone())
            .collect();
        crate::preflight::ensure_targets_clear(&self.filesystem, &self.config, &targets)?;
        // Refuse before anything is stopped or mounted if a non-service process
        // would have to be signalled on any target without the opt-in.
        crate::overlay::refuse_unconsented_signals(&targets, strategy_options)?;

        let overlays = self.config.overlays.clone();
        self.mount_overlay_targets(
            tracker,
            runtime_root,
            &overlays,
            Vec::new(),
            MountFailureMode::FailFast,
            strategy_options,
            verbosity,
            outcome,
        )
    }
}
