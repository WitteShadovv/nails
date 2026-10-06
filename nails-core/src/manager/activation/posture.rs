// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Re-checking swap and hidden-volume space during activation, and the small
//! predicates that decide whether a rebuild runs.

use super::*;

impl<F: Filesystem> NailsManager<F> {
    /// Re-classify swap and hibernation and, if a device that can leak memory to
    /// persistent storage is active, log loudly and write a critical
    /// notification. `phase` names the point in the flow for the operator.
    ///
    /// Runs after the NixOS switch (which starts `swap.target` and can re-enable
    /// a disk swap the operator turned off to pass pre-flight) and before
    /// deactivation. RAM-only zram never trips this.
    pub(crate) fn recheck_swap_posture(&self, phase: &str, hidden_root: &Path) {
        let posture = crate::preflight::classify_swap(self.filesystem());
        if posture.severity == crate::preflight::SwapSeverity::Fail {
            let detail = posture.findings.join("; ");
            tracing::error!("swap can leak memory to persistent storage {phase}: {detail}");
            let notif = Notification {
                title: "Swap re-enabled".to_string(),
                body: format!("Swap can leak memory to persistent storage {phase}: {detail}"),
                urgency: "critical".to_string(),
                icon: Some("dialog-error".to_string()),
                created_at: chrono::Utc::now().to_rfc3339(),
            };
            if let Err(e) = write_notification(hidden_root, &notif) {
                tracing::warn!("Failed to write swap re-check notification: {}", e);
            }
        }
    }

    /// Post-mount guards that run after the overlays are mounted and before the
    /// NixOS build/switch: validate the hidden flake (unless the run opted out)
    /// now that `/nix` and `/root` are overlaid, then re-check free space against
    /// the rebuild floor. Returning an error leaves the overlays to roll back
    /// before any build or session restart.
    ///
    /// The flake validation is skipped on the fast path: a carried-forward
    /// toplevel means the fingerprint matched, so the build inputs are byte-for-byte
    /// the ones a previous activation already built and validated. Re-validating
    /// them would make the fast path require the flake to still evaluate, defeating
    /// the point of reusing a cached toplevel — an operator whose flake is
    /// temporarily broken could no longer re-enter a hidden session that needs no
    /// rebuild. A changed flake invalidates the fingerprint, drops the fast path
    /// and is validated here as usual.
    pub(crate) fn run_post_mount_guards(
        &self,
        options: &crate::ActivateOptions,
        fast_path_toplevel: &Option<String>,
    ) -> Result<()> {
        if !options.skip_flake_validation && fast_path_toplevel.is_none() {
            self.run_read_only_nixos_preflight(options.overlay_only)?;
        }
        self.ensure_rebuild_space_before_build(fast_path_toplevel)
    }

    /// Whether a full hidden NixOS rebuild is expected for this activation.
    ///
    /// A rebuild runs when no cached toplevel can be reused (the fast path is
    /// absent) and the host has both a declarative config layer and a builder.
    /// An overlay-only run (no builder / no layer) or a fast-path reuse writes no
    /// large store delta, so only the base space floor applies to it.
    pub(crate) fn rebuild_expected(&self, fast_path_toplevel: &Option<String>) -> bool {
        fast_path_toplevel.is_none() && self.hidden_switch_configured()
    }

    /// Whether this activation can run the hidden NixOS switch at all: the host
    /// has a declarative config layer and a builder was wired. Mirrors the
    /// preconditions of `switch_nixos_profile`, which reports `NotRequested`
    /// without either (an overlay-only run has no builder).
    pub(crate) fn hidden_switch_configured(&self) -> bool {
        self.nixos_builder.is_some() && self.config_layer().is_some()
    }

    /// Re-check free space on the hidden volume against the rebuild floor.
    ///
    /// Called after the overlays are mounted and before the NixOS build runs. A
    /// no-op unless a full rebuild is expected (see [`rebuild_expected`]). The
    /// build writes its store delta into the overlaid `/nix` upper, so a volume
    /// that passed the base pre-flight floor can still be too small. Returns an
    /// error when short so the caller rolls the overlays back before any build or
    /// session restart.
    ///
    /// [`rebuild_expected`]: Self::rebuild_expected
    pub(crate) fn ensure_rebuild_space_before_build(
        &self,
        fast_path_toplevel: &Option<String>,
    ) -> Result<()> {
        if !self.rebuild_expected(fast_path_toplevel) {
            return Ok(());
        }
        let root = self.config().hidden_volume_root.clone();
        let available_mb = self.filesystem().disk_usage(&root)?.available / (1024 * 1024);
        let floor = self.config().rebuild_space_mb;
        if available_mb < floor {
            return Err(NailsError::NixOSError(format!(
                "hidden volume has only {} MB free but a NixOS rebuild needs at least {} MB \
                 (rebuild_space_mb). Free space or enlarge the hidden volume, then retry. \
                 Overlays were rolled back before any build or session restart.",
                available_mb, floor
            )));
        }
        Ok(())
    }

    /// Re-check free space after a successful switch and warn when the hidden
    /// volume is nearly full. The rebuild wrote its store delta into the `/nix`
    /// upper, so a volume that cleared the pre-build floor can now be low; a
    /// notification lets the operator free space before the next activation.
    pub(crate) fn recheck_hidden_volume_space(&self, phase: &str, hidden_root: &Path) {
        let floor = self.config().rebuild_space_mb;
        let available_mb = match self.filesystem().disk_usage(hidden_root) {
            Ok(usage) => usage.available / (1024 * 1024),
            Err(e) => {
                tracing::warn!("Failed to re-check hidden volume space {phase}: {e}");
                return;
            }
        };
        if available_mb < floor {
            tracing::warn!(
                "hidden volume nearly full {phase}: {available_mb} MB free (below the \
                 {floor} MB rebuild floor); free space before the next activation"
            );
            let notif = Notification {
                title: "Hidden volume nearly full".to_string(),
                body: format!(
                    "Only {available_mb} MB free on the hidden volume {phase} (below the \
                     {floor} MB rebuild floor). Free or enlarge the volume before the next \
                     activation."
                ),
                urgency: "critical".to_string(),
                icon: Some("dialog-warning".to_string()),
                created_at: chrono::Utc::now().to_rfc3339(),
            };
            if let Err(e) = write_notification(hidden_root, &notif) {
                tracing::warn!("Failed to write hidden-volume-full notification: {}", e);
            }
        }
    }
}
