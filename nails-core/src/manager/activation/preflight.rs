// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Preflight Checks and Config Staging
//!
//! Handles pre-activation validation and config preparation.

use crate::cleanup::history::HistoryCleaner;
use crate::cleanup::patterns;
use crate::platform::ConfigLayer;
use crate::preflight::OverlayTargetsCheck;
use crate::{
    AttachState, Filesystem, HiddenRoot, NailsError, NailsManager, PreFlightCheck, Result,
    Stopwatch, SuspiciousNailsReferenceCheck, Verbosity,
};

fn suspicious_check_name<F: Filesystem>() -> String {
    <SuspiciousNailsReferenceCheck as PreFlightCheck<F>>::name(
        &SuspiciousNailsReferenceCheck::default(),
    )
    .to_string()
}

impl<F: Filesystem> NailsManager<F> {
    /// Run preflight checks and then stage hidden config symlink
    pub(super) fn run_preflight_phase(
        &self,
        no_preflight: bool,
        overlay_only: bool,
        verbosity: Verbosity,
        pre_activation_cleanup: bool,
        accept_persistent_decoy: bool,
    ) -> Result<()> {
        // The overlay-target floor holds even with --no-preflight, and runs
        // before every side effect below (symlink probe, history cleanup,
        // config staging) and before any session kill: an overlay that would
        // hide the hidden volume or a leaky exclusion is never worth starting.
        self.enforce_overlay_target_floor()?;

        // Step 2.5: Probe symlink support on hidden volume before staging.
        // Catches FAT32/exFAT volumes early with a clear error message.
        match self
            .filesystem
            .supports_symlinks(&self.config.hidden_volume_root)
        {
            Ok(false) => {
                let reason = "does not support symbolic links; the hidden volume must be \
                     formatted with a Linux filesystem (e.g. ext4). FAT32 and exFAT do not \
                     support symlinks."
                    .to_string();
                if no_preflight {
                    tracing::warn!(
                        path = %self.config.hidden_volume_root.display(),
                        "Filesystem {reason}"
                    );
                } else {
                    return Err(crate::NailsError::UnsupportedFilesystem {
                        path: self.config.hidden_volume_root.clone(),
                        reason,
                    });
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "Could not probe symlink support; continuing");
            }
            Ok(true) => {}
        }

        // Step 3: Run pre-flight checks (unless skipped)
        if no_preflight {
            // Step 2.8: Pre-activation history cleanup (runs even with --no-preflight)
            // Security feature: Clean shell history BEFORE overlays are mounted to remove
            // evidence of cryptsetup, nails activate, etc. from the REAL disk.
            if pre_activation_cleanup {
                self.run_pre_activation_cleanup(verbosity);
            }

            // --no-preflight waives the pre-flight registry, but it must not waive
            // the attach gate: staging a config symlink onto an unmounted mount
            // point would drop identifying files onto the decoy disk, which is the
            // exact harm this chunk exists to prevent. Honour the gate here too,
            // as a best-effort skip (every step in this branch is best-effort):
            // stage only when the hidden root is positively attached, otherwise
            // warn and leave the directory untouched. The staging itself is a
            // declarative-config step: it runs through the platform config layer
            // and is skipped on a host without one (FHS / Debian) and in
            // overlay-only mode, which is "no layer" rather than a parallel path.
            if let Some(layer) = self.config_layer().filter(|_| !overlay_only) {
                match HiddenRoot::verify_attached(
                    &self.filesystem,
                    &self.config.hidden_volume_root,
                    false,
                ) {
                    Ok(AttachState::Attached) => {
                        if let Err(e) =
                            layer.stage_symlink(&self.filesystem, &self.config.hidden_volume_root)
                        {
                            tracing::warn!(
                                error = %e,
                                "Skipping staged config failure due to --no-preflight (activation may not use hidden config)"
                            );
                        }
                    }
                    Ok(AttachState::Unattached(reason)) => {
                        tracing::warn!(
                            %reason,
                            "Hidden root is not attached; skipping config staging (--no-preflight)"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "Could not verify hidden-root attach state; skipping config staging (--no-preflight)"
                        );
                    }
                }
            }

            if verbosity >= Verbosity::Normal {
                tracing::warn!("DANGER: Skipping pre-flight checks. Activation may fail.");
            }
            return Ok(());
        }

        if !overlay_only {
            if verbosity >= Verbosity::Normal {
                tracing::info!("Running static flake checks before any detach or session kill...");
            }

            // Static checks only: `flake.nix`/`flake.lock` exist and the
            // configuration attribute name resolves. The real
            // `nix flake metadata`/eval validation is deferred until after the
            // overlays are mounted (see `activate_with_options`), so nothing is
            // copied into the decoy `/nix/store`, Nix DB or root cache before
            // `/nix` and `/root` are overlaid.
            self.run_static_nixos_preflight(overlay_only)?;
        }

        // Suspicious-reference validation must happen before ANY activation side effects,
        // including pre-activation cleanup and config symlink staging.
        let suspicious_check =
            SuspiciousNailsReferenceCheck::new(self.config.hidden_volume_root.clone());
        match suspicious_check.run(&self.filesystem)? {
            crate::CheckResult::Pass(_)
            | crate::CheckResult::Warn(_)
            | crate::CheckResult::Skipped(_) => {}
            crate::CheckResult::Fail {
                message,
                remediation,
            } => {
                return Err(NailsError::PreFlightCheckFailed(vec![(
                    suspicious_check_name::<F>(),
                    message,
                    remediation,
                )]));
            }
        }

        // Attach gate: nothing below this line may write until the hidden root is
        // a positively attached volume. An unmounted mount point on the
        // persistent disk reports `/`'s device, so staging a `configuration.nix`
        // or symlink there would seed the decoy disk; the registry's
        // `hidden-volume` check runs only after staging, so it cannot prevent
        // that. This gate is the same one that keeps file logging on stderr when
        // nothing is mounted, so staging now happens strictly after the hidden
        // volume has been confirmed attached. `require_marker` is cleared for
        // parity with the logging gate: the device difference is what proves a
        // mount, and a first `activate` on a freshly mounted volume may precede
        // the state file.
        self.enforce_hidden_root_attached()?;

        // Step 2.8: Pre-activation history cleanup (runs after early safety gates)
        // Security feature: Clean shell history BEFORE overlays are mounted to remove
        // evidence of cryptsetup, nails activate, etc. from the REAL disk.
        if pre_activation_cleanup {
            self.run_pre_activation_cleanup(verbosity);
        }

        // Stage the hidden NixOS layout (module symlink plus the hardware
        // wrapper) before the read-only pre-flight checks run. The checks no
        // longer create these files, so staging must produce them here. Staging
        // is a declarative-config step, so it runs through the platform config
        // layer and is skipped on a host without one (FHS / Debian) and in
        // overlay-only mode, which is "no layer" rather than a parallel path.
        if let Some(layer) = self.config_layer().filter(|_| !overlay_only)
            && let Err(e) = layer.stage(&self.filesystem, &self.config.hidden_volume_root, false)
        {
            tracing::error!(
                error = %e,
                "Failed to stage hidden NixOS config after early pre-flight checks"
            );
            return Err(NailsError::PreFlightCheckFailed(vec![(
                "nixos-config-staging".to_string(),
                e.to_string(),
                None,
            )]));
        }

        if verbosity >= Verbosity::Normal {
            tracing::info!("Running pre-flight checks...");
        }

        let step_timer = Stopwatch::start();
        self.run_preflight_checks(overlay_only, accept_persistent_decoy)?;

        if verbosity >= Verbosity::Normal {
            // Pre-flight checks event with duration_ms field
            tracing::info!(
                duration_ms = step_timer.elapsed().as_millis() as u64,
                "Pre-flight checks passed"
            );
        }

        Ok(())
    }

    /// Run the static NixOS flake checks that are safe before any session kill,
    /// detach or overlay mount.
    ///
    /// This only reads the hidden-root flake layout from the filesystem and
    /// never invokes `nix`, so the plaintext hidden configuration is never
    /// copied onto the decoy `/nix/store`, Nix DB or root cache. The real
    /// `nix flake metadata`/eval validation is deferred to the post-overlay
    /// phase in [`activate_with_options`](NailsManager::activate_with_options).
    /// Failures are reported as `nixos-build-target`, matching the previous
    /// pre-detach flake preflight so the surfaced error is unchanged.
    pub fn run_static_nixos_preflight(&self, overlay_only: bool) -> Result<()> {
        if overlay_only {
            return Ok(());
        }

        if let Some(builder) = self.nixos_builder.as_ref()
            && builder.is_flake()
        {
            builder.preflight_flake_static().map_err(|err| match err {
                NailsError::NixOSPreflightError { message, .. } => {
                    NailsError::PreFlightCheckFailed(vec![(
                        "nixos-build-target".to_string(),
                        message,
                        None,
                    )])
                }
                other => other,
            })?;
        }

        Ok(())
    }

    /// Refuse activation unless the hidden root is a positively attached volume.
    ///
    /// Delegates to [`HiddenRoot::verify_attached`], the single gate every write
    /// path consults, and turns an unattached verdict into a
    /// [`NailsError::PreFlightCheckFailed`] under the `hidden-root` name so the
    /// operator sees why nothing was written. `require_marker` is cleared: the
    /// `st_dev` difference is what proves the volume is mounted, and a first
    /// `activate` on a freshly mounted volume may legitimately precede the state
    /// file.
    fn enforce_hidden_root_attached(&self) -> Result<()> {
        match HiddenRoot::verify_attached(&self.filesystem, &self.config.hidden_volume_root, false)?
        {
            AttachState::Attached => Ok(()),
            AttachState::Unattached(reason) => Err(NailsError::PreFlightCheckFailed(vec![(
                "hidden-root".to_string(),
                reason,
                Some(
                    "Mount the hidden storage at its configured root, then re-run activation."
                        .to_string(),
                ),
            )])),
        }
    }

    /// Refuse activation when the `overlay-targets` check fails.
    fn enforce_overlay_target_floor(&self) -> Result<()> {
        let check = OverlayTargetsCheck::new(self.config.clone());
        match check.run(&self.filesystem)? {
            crate::CheckResult::Pass(_)
            | crate::CheckResult::Warn(_)
            | crate::CheckResult::Skipped(_) => Ok(()),
            crate::CheckResult::Fail {
                message,
                remediation,
            } => Err(NailsError::PreFlightCheckFailed(vec![(
                <OverlayTargetsCheck as PreFlightCheck<F>>::name(&check).to_string(),
                message,
                remediation,
            )])),
        }
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

        let history_patterns = patterns::pre_activation_cleanup_patterns();

        let cleaner = HistoryCleaner::new(self.filesystem.clone()).with_patterns(history_patterns);

        match cleaner.clean() {
            Ok(cleaned_items) => {
                if cleaned_items.is_empty() {
                    if verbosity >= Verbosity::Verbose {
                        tracing::debug!(
                            "Pre-activation cleanup: no history entries matched patterns"
                        );
                    }
                } else {
                    // The matched patterns and the per-file results name the very
                    // commands and paths this phase exists to erase. This runs in
                    // the detached worker before /var is overlaid, so it must never
                    // reach the decoy journal: keep both out of the info stream and
                    // emit only a count there; the detail goes to the hidden-root
                    // log at debug.
                    for item in &cleaned_items {
                        tracing::debug!(cleanup_result = %item, "Pre-activation history cleanup");
                    }
                    if verbosity >= Verbosity::Normal {
                        tracing::info!(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cleanup::test_utils::TEST_HOME;
    use crate::{Config, MockFilesystem, NailsManager};

    /// The whole capture buffer `tracing-test` has accumulated. We read it
    /// directly rather than through the scope-filtered helper so the rendered
    /// level of each line is visible.
    fn captured_logs() -> String {
        String::from_utf8(tracing_test::internal::global_buf().lock().unwrap().clone())
            .expect("captured logs are valid UTF-8")
    }

    // ------------------------------------------------------------------------
    // Hidden-root attach gate
    // ------------------------------------------------------------------------

    /// Build a manager rooted at `root`, wiring the mock so the attach gate sees
    /// the requested device layout. `root` exists and is writable; `/` reports
    /// `slash_device` and `root` reports `root_device`. Returns the manager and a
    /// clone of its filesystem for assertions. Overlays are empty under explicit
    /// mode so the overlay-target floor passes without extra setup.
    fn attach_gate_manager(
        root: &std::path::Path,
        root_device: u64,
        slash_device: u64,
    ) -> (NailsManager<MockFilesystem>, MockFilesystem) {
        use std::path::Path;
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists(root.to_str().unwrap(), true);
        fs.mock_set_writable(root.to_str().unwrap(), true);
        fs.mock_set_device_id(Path::new("/"), slash_device);
        fs.mock_set_device_id(root, root_device);

        let config = Config {
            hidden_volume_root: root.to_path_buf(),
            state_file_path: root.join("state.json"),
            overlay_mode: crate::OverlayMode::Explicit,
            overlays: vec![],
            ..Config::test_default()
        };
        let state_path = config.state_file_path.clone();
        let manager = NailsManager::new(fs.clone(), config, state_path);
        (manager, fs)
    }

    /// A hidden root that shares `/`'s device is an unmounted mount point, not a
    /// mounted volume, so the gate refuses it under the `hidden-root` name.
    #[test]
    fn attach_gate_rejects_a_root_that_shares_slash_device() {
        let root = std::path::PathBuf::from("/mnt/data");
        let (manager, _fs) = attach_gate_manager(&root, 7, 7);

        match manager.enforce_hidden_root_attached().unwrap_err() {
            NailsError::PreFlightCheckFailed(failures) => {
                assert!(
                    failures.iter().any(|(name, _, _)| name == "hidden-root"),
                    "expected a hidden-root failure, got {failures:?}"
                );
            }
            other => panic!("expected PreFlightCheckFailed, got {other:?}"),
        }
    }

    /// A hidden root on its own device is a mounted volume, so the gate accepts it.
    #[test]
    fn attach_gate_accepts_a_root_on_its_own_device() {
        let root = std::path::PathBuf::from("/mnt/data");
        let (manager, _fs) = attach_gate_manager(&root, 42, 7);
        manager
            .enforce_hidden_root_attached()
            .expect("a root on its own device is attached");
    }

    /// A normal `activate` must refuse an unattached root before anything is
    /// written: the preflight phase errors with `hidden-root` and no config is
    /// staged into the hidden `/etc/nixos` tree.
    #[test]
    fn preflight_phase_refuses_before_staging_when_root_is_unattached() {
        let root = std::path::PathBuf::from("/mnt/data");
        let (manager, fs) = attach_gate_manager(&root, 7, 7);
        let staged = root.join("etc/nixos/nails/configuration.nix");

        match manager
            .run_preflight_phase(false, true, Verbosity::Normal, false, false)
            .unwrap_err()
        {
            NailsError::PreFlightCheckFailed(failures) => {
                assert!(
                    failures.iter().any(|(name, _, _)| name == "hidden-root"),
                    "expected a hidden-root failure, got {failures:?}"
                );
            }
            other => panic!("expected PreFlightCheckFailed, got {other:?}"),
        }

        assert!(
            !fs.is_symlink(&staged).unwrap(),
            "no config may be staged onto an unattached hidden root"
        );
    }

    /// `--no-preflight` waives the registry but not the attach gate: an unattached
    /// root is left untouched (best-effort skip), and the phase still succeeds.
    #[test]
    fn preflight_phase_skips_staging_for_unattached_root_under_no_preflight() {
        let root = std::path::PathBuf::from("/mnt/data");
        let (manager, fs) = attach_gate_manager(&root, 7, 7);
        let staged = root.join("etc/nixos/nails/configuration.nix");

        manager
            .run_preflight_phase(true, true, Verbosity::Normal, false, false)
            .expect("--no-preflight never fails the preflight phase");

        assert!(
            !fs.is_symlink(&staged).unwrap(),
            "an unattached root must not be staged even with --no-preflight"
        );
    }

    /// With `--no-preflight` and an attached root, staging proceeds: the gate's
    /// positive branch is reached and the hidden config symlink is created. This
    /// proves the skip above is the gate acting, not staging failing anyway. The
    /// run is not overlay-only, because overlay-only is "no config layer" and so
    /// stages nothing; with no detected host profile the manager assumes the NixOS
    /// seam, so a config layer is present.
    #[test]
    fn preflight_phase_stages_for_attached_root_under_no_preflight() {
        use crate::filesystem::PathKind;

        let root = std::path::PathBuf::from("/mnt/data");
        let (manager, fs) = attach_gate_manager(&root, 42, 7);

        // Pre-create the hidden layout dirs so staging only has to create the
        // symlink; this keeps the test off the mock's parent-creation rules.
        for dir in ["/mnt/data/config/nixos", "/mnt/data/etc/nixos/nails"] {
            fs.mock_set_path_exists(dir, true);
            fs.mock_set_path_type(dir, PathKind::Dir);
            fs.mock_set_writable(dir, true);
        }

        let staged = root.join("etc/nixos/nails/configuration.nix");
        manager
            .run_preflight_phase(true, false, Verbosity::Normal, false, false)
            .expect("an attached root passes the preflight phase");

        assert!(
            fs.is_symlink(&staged).unwrap(),
            "an attached root must be staged under --no-preflight"
        );
    }

    /// Overlay-only activation is "no config layer", so the `--no-preflight` path
    /// stages nothing even when the hidden root is attached: no `/etc/nixos`
    /// symlink is created.
    #[test]
    fn preflight_phase_overlay_only_stages_nothing_under_no_preflight() {
        let root = std::path::PathBuf::from("/mnt/data");
        let (manager, fs) = attach_gate_manager(&root, 42, 7);
        let staged = root.join("etc/nixos/nails/configuration.nix");

        manager
            .run_preflight_phase(true, true, Verbosity::Normal, false, false)
            .expect("overlay-only --no-preflight passes the preflight phase");

        assert!(
            !fs.is_symlink(&staged).unwrap(),
            "overlay-only is no config layer, so nothing may be staged"
        );
    }

    /// A Debian/FHS host has no config layer, so even a full (not overlay-only)
    /// `--no-preflight` run stages nothing: no `/etc/nixos` symlink is created on
    /// the attached hidden root.
    #[test]
    fn preflight_phase_fhs_host_stages_nothing() {
        let root = std::path::PathBuf::from("/mnt/data");
        let (mut manager, fs) = attach_gate_manager(&root, 42, 7);
        manager.set_fake_platform(crate::platform::FakePlatform::fhs());
        let staged = root.join("etc/nixos/nails/configuration.nix");

        manager
            .run_preflight_phase(true, false, Verbosity::Normal, false, false)
            .expect("an FHS host passes the preflight phase");

        assert!(
            !fs.is_symlink(&staged).unwrap(),
            "an FHS host has no config layer, so nothing may be staged"
        );
    }

    /// The public pre-detach staging entry point stages through the config layer:
    /// on the default NixOS seam (no detected profile) with an attached root it
    /// creates the `/etc/nixos` symlink, matching the pre-flight phase's own gate.
    #[test]
    fn stage_hidden_config_stages_on_nixos_seam() {
        use crate::filesystem::PathKind;

        let root = std::path::PathBuf::from("/mnt/data");
        let (manager, fs) = attach_gate_manager(&root, 42, 7);
        for dir in [
            "/mnt/data/config/nixos",
            "/mnt/data/etc/nixos",
            "/mnt/data/etc/nixos/nails",
        ] {
            fs.mock_set_path_exists(dir, true);
            fs.mock_set_path_type(dir, PathKind::Dir);
            fs.mock_set_writable(dir, true);
        }
        // Full staging (overlay_only = false) also seeds the hardware wrapper from
        // the decoy hardware config, so it must be readable.
        fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
        fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", PathKind::File);
        fs.mock_set_file_content(
            "/etc/nixos/hardware-configuration.nix",
            "{ config, lib, pkgs, ... }:\n{ }",
        );
        let staged = root.join("etc/nixos/nails/configuration.nix");

        manager
            .stage_hidden_config(false)
            .expect("staging succeeds on the NixOS seam");

        assert!(
            fs.is_symlink(&staged).unwrap(),
            "the NixOS seam stages the hidden config symlink"
        );
        assert!(
            fs.path_exists(&root.join("etc/nixos/hardware-configuration.nix"))
                .unwrap(),
            "the NixOS seam stages the hardware wrapper"
        );
    }

    /// The pre-detach staging entry point skips entirely in overlay-only mode:
    /// overlay-only is "no config layer", so nothing is written to `/etc/nixos`.
    #[test]
    fn stage_hidden_config_skips_overlay_only() {
        let root = std::path::PathBuf::from("/mnt/data");
        let (manager, fs) = attach_gate_manager(&root, 42, 7);
        let staged = root.join("etc/nixos/nails/configuration.nix");

        manager
            .stage_hidden_config(true)
            .expect("overlay-only staging is a no-op that succeeds");

        assert!(
            !fs.is_symlink(&staged).unwrap(),
            "overlay-only is no config layer, so nothing may be staged"
        );
    }

    /// The pre-detach staging entry point skips on a Debian/FHS host: with no
    /// config layer the hidden `/etc/nixos` tree is never touched, so the CLI
    /// parent process stages nothing before detaching.
    #[test]
    fn stage_hidden_config_skips_on_fhs_host() {
        let root = std::path::PathBuf::from("/mnt/data");
        let (mut manager, fs) = attach_gate_manager(&root, 42, 7);
        manager.set_fake_platform(crate::platform::FakePlatform::fhs());
        let staged = root.join("etc/nixos/nails/configuration.nix");

        manager
            .stage_hidden_config(false)
            .expect("an FHS host stages nothing and succeeds");

        assert!(
            !fs.is_symlink(&staged).unwrap(),
            "an FHS host has no config layer, so nothing may be staged"
        );
    }

    /// The matched patterns and the per-file results name the very commands this
    /// phase erases, so they must stay off the INFO stream that a detached worker
    /// would otherwise feed into the decoy journal before `/var` is overlaid.
    #[tracing_test::traced_test]
    #[test]
    fn pre_activation_cleanup_keeps_patterns_and_per_file_detail_off_info() {
        let fs = MockFilesystem::new();
        let bash_history = format!("{TEST_HOME}/.bash_history");
        fs.mock_set_file_content(
            bash_history.as_str(),
            "ls -la\ncryptsetup open /dev/sdb secret\nnails activate\n",
        );
        fs.mock_set_path_exists(bash_history.as_str(), true);

        let config = Config::test_default();
        let state_path = config.state_file_path.clone();
        let manager = NailsManager::new(fs, config, state_path);

        manager.run_pre_activation_cleanup(Verbosity::Normal);

        let logs = captured_logs();

        // The pattern list is never logged, at any level.
        assert!(
            !logs.contains("patterns="),
            "cleanup pattern list leaked into the logs:\n{logs}"
        );

        // Per-file detail must not ride an INFO line; only the count summary does.
        let mut saw_info_summary = false;
        for line in logs.lines() {
            if !line.contains("INFO") {
                continue;
            }
            assert!(
                !line.contains("cleanup_result"),
                "per-file cleanup detail reached INFO: {line}"
            );
            if line.contains("items_cleaned") {
                saw_info_summary = true;
            }
        }
        assert!(
            saw_info_summary,
            "expected an INFO summary carrying only the cleaned count:\n{logs}"
        );
    }

    /// Write a `nix` stub that records every invocation and then fails. The
    /// static preflight must never run it before the overlays are mounted.
    fn write_recording_nix_stub(bin_dir: &std::path::Path, log_path: &std::path::Path) {
        std::fs::create_dir_all(bin_dir).unwrap();
        let nix = bin_dir.join("nix");
        std::fs::write(
            &nix,
            format!(
                "#!/usr/bin/env sh\nprintf '%s\\n' \"$*\" >> '{}'\nprintf 'nix must not run before the overlays are mounted\\n' 1>&2\nexit 1\n",
                log_path.display()
            ),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&nix).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&nix, perms).unwrap();
        }
    }

    /// Build a manager whose flake builder resolves `nix` from `bin_dir`.
    fn flake_manager_with_nix_stub(
        hidden_root: &std::path::Path,
        flake_dir: &std::path::Path,
        bin_dir: &std::path::Path,
    ) -> NailsManager<MockFilesystem> {
        let state_path = hidden_root.join("state.json");
        let flake_ref = format!("{}#host-alpha", flake_dir.display());
        let builder = crate::NixOSBuilder::new_with_flake_ref(
            flake_ref.clone(),
            hidden_root.join("nails-system"),
        )
        .with_executor(Box::new(
            crate::nixos::RealCommandExecutor::with_search_path(bin_dir),
        ));

        NailsManager::with_nixos(
            MockFilesystem::new(),
            Config {
                hidden_volume_root: hidden_root.to_path_buf(),
                state_file_path: state_path.clone(),
                nixos_flake: Some(flake_ref),
                ..Config::test_default()
            },
            state_path,
            builder,
        )
    }

    /// The pre-overlay static preflight validates the flake layout from disk and
    /// never invokes `nix`, so the plaintext hidden configuration is never copied
    /// onto the decoy store before `/nix` and `/root` are overlaid.
    #[test]
    fn static_nixos_preflight_runs_no_nix_for_a_complete_local_flake() {
        let temp_dir = tempfile::tempdir().unwrap();
        let hidden_root = temp_dir.path();
        let flake_dir = hidden_root.join("nixos");
        std::fs::create_dir_all(&flake_dir).unwrap();
        std::fs::write(flake_dir.join("flake.nix"), "{ outputs = _: {}; }\n").unwrap();
        std::fs::write(flake_dir.join("flake.lock"), "{}\n").unwrap();

        let bin_dir = hidden_root.join("bin");
        let nix_log = hidden_root.join("nix-invocations.log");
        write_recording_nix_stub(&bin_dir, &nix_log);

        let manager = flake_manager_with_nix_stub(hidden_root, &flake_dir, &bin_dir);

        manager
            .run_static_nixos_preflight(false)
            .expect("static checks should pass for a complete local flake");

        assert!(
            !nix_log.exists(),
            "the static preflight must not invoke nix"
        );
    }

    /// The static preflight fails without `flake.nix`, without `flake.lock`, and
    /// passes when both are present and the configuration attribute parses — all
    /// without invoking `nix`.
    #[test]
    fn static_nixos_preflight_requires_flake_nix_and_lock() {
        let temp_dir = tempfile::tempdir().unwrap();
        let hidden_root = temp_dir.path();
        let flake_dir = hidden_root.join("nixos");
        std::fs::create_dir_all(&flake_dir).unwrap();

        let bin_dir = hidden_root.join("bin");
        let nix_log = hidden_root.join("nix-invocations.log");
        write_recording_nix_stub(&bin_dir, &nix_log);

        let manager = flake_manager_with_nix_stub(hidden_root, &flake_dir, &bin_dir);

        // No flake.nix yet.
        let err = manager
            .run_static_nixos_preflight(false)
            .expect_err("missing flake.nix must fail");
        assert!(
            err.to_string().contains("flake.nix not found"),
            "unexpected error: {err}"
        );

        // flake.nix present, flake.lock still missing.
        std::fs::write(flake_dir.join("flake.nix"), "{ outputs = _: {}; }\n").unwrap();
        let err = manager
            .run_static_nixos_preflight(false)
            .expect_err("missing flake.lock must fail");
        assert!(
            err.to_string().contains("flake.lock not found"),
            "unexpected error: {err}"
        );

        // Both present: the static checks pass.
        std::fs::write(flake_dir.join("flake.lock"), "{}\n").unwrap();
        manager
            .run_static_nixos_preflight(false)
            .expect("static checks should pass once flake.nix and flake.lock exist");

        assert!(
            !nix_log.exists(),
            "none of the static checks may invoke nix"
        );
    }

    /// The deferred, post-overlay flake validation runs the real `nix` only after
    /// the overlays are mounted; when the hidden flake is broken it fails there,
    /// so the overlays are rolled back and the state returns to Inactive.
    #[test]
    fn post_overlay_flake_validation_failure_rolls_back_overlays() {
        use crate::{OverlayConfig, OverlayMode, SystemState};
        use std::path::{Path, PathBuf};

        let temp_dir = tempfile::tempdir().unwrap();
        let hidden_root = temp_dir.path();
        std::fs::create_dir_all(hidden_root).unwrap();
        let state_path = hidden_root.join("state.json");

        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/", true);
        let upper_dir = hidden_root.join("overlays/home/upper");
        let work_dir = hidden_root.join("overlays/home/work");
        std::fs::create_dir_all(&upper_dir).unwrap();
        std::fs::create_dir_all(&work_dir).unwrap();
        fs.mock_set_path_exists(upper_dir.to_str().unwrap(), true);
        fs.mock_set_path_exists(work_dir.to_str().unwrap(), true);

        // A hidden flake that passes the static checks but whose real metadata
        // validation (deferred to post-overlay) fails via the stub.
        let flake_dir = hidden_root.join("nixos");
        std::fs::create_dir_all(&flake_dir).unwrap();
        std::fs::write(flake_dir.join("flake.nix"), "{ outputs = _: {}; }\n").unwrap();
        std::fs::write(flake_dir.join("flake.lock"), "{}\n").unwrap();
        let bin_dir = hidden_root.join("bin");
        let nix_log = hidden_root.join("nix-invocations.log");
        write_recording_nix_stub(&bin_dir, &nix_log);

        let flake_ref = format!("{}#host-alpha", flake_dir.display());
        let builder = crate::NixOSBuilder::new_with_flake_ref(
            flake_ref.clone(),
            hidden_root.join("nails-system"),
        )
        .with_executor(Box::new(
            crate::nixos::RealCommandExecutor::with_search_path(&bin_dir),
        ));

        let config = Config {
            hidden_volume_root: hidden_root.to_path_buf(),
            state_file_path: state_path.clone(),
            overlay_mode: OverlayMode::Explicit,
            overlays: vec![OverlayConfig {
                name: "home".to_string(),
                lower: PathBuf::from("/"),
                upper: upper_dir.clone(),
                work: work_dir.clone(),
                target: PathBuf::from("/home"),
            }],
            nixos_flake: Some(flake_ref),
            ..Config::test_default()
        };

        let fs_clone = fs.clone();
        let mut manager = NailsManager::with_nixos(fs, config, state_path.clone(), builder);

        let options = crate::ActivateOptions {
            kill_session: false,
            no_pivot: false,
            pre_activation_cleanup: false,
            skip_flake_validation: false,
            ..crate::ActivateOptions::default()
        };

        // `no_preflight = true` skips the pre-overlay registry, so the only nix
        // invocation is the deferred validation that runs after the mounts.
        let result = manager.activate_with_options(options, true);
        assert!(
            result.is_err(),
            "a broken hidden flake must fail activation post-overlay"
        );

        assert!(
            nix_log.exists(),
            "the deferred validation must invoke nix only after the overlays are mounted"
        );
        assert!(
            !fs_clone.is_mounted(Path::new("/home")).unwrap(),
            "overlays must be unmounted after the post-overlay validation fails"
        );
        assert_eq!(
            manager.current_state().unwrap(),
            SystemState::Inactive,
            "state must roll back to Inactive after the post-overlay validation fails"
        );
    }
}
