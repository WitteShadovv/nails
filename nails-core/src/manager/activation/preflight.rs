//! Preflight Checks and Config Staging
//!
//! Handles pre-activation validation and config preparation.

use crate::cleanup::history::HistoryCleaner;
use crate::cleanup::patterns;
use crate::preflight::OverlayTargetsCheck;
use crate::{
    Filesystem, NailsError, NailsManager, PreFlightCheck, Result, Stopwatch,
    SuspiciousNailsReferenceCheck, Verbosity,
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

        // Step 3: Run pre-flight checks (unless skipped)
        if no_preflight {
            // Step 2.8: Pre-activation history cleanup (runs even with --no-preflight)
            // Security feature: Clean shell history BEFORE overlays are mounted to remove
            // evidence of cryptsetup, nails activate, etc. from the REAL disk.
            if pre_activation_cleanup {
                self.run_pre_activation_cleanup(verbosity);
            }

            if let Err(e) = crate::stage_hidden_config_symlink(
                &self.filesystem,
                &self.config.hidden_volume_root,
            ) {
                tracing::warn!(
                    error = %e,
                    "Skipping staged config failure due to --no-preflight (activation may not use hidden config)"
                );
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
            crate::CheckResult::Pass(_) | crate::CheckResult::Warn(_) => {}
            crate::CheckResult::Fail(message) => {
                return Err(NailsError::PreFlightCheckFailed(vec![(
                    suspicious_check_name::<F>(),
                    message,
                )]));
            }
        }

        // Step 2.8: Pre-activation history cleanup (runs after early safety gates)
        // Security feature: Clean shell history BEFORE overlays are mounted to remove
        // evidence of cryptsetup, nails activate, etc. from the REAL disk.
        if pre_activation_cleanup {
            self.run_pre_activation_cleanup(verbosity);
        }

        // Stage the hidden NixOS layout (module symlink plus the hardware
        // wrapper) before the read-only pre-flight checks run. The checks no
        // longer create these files, so staging must produce them here.
        if let Err(e) = crate::stage_hidden_nixos_config(
            &self.filesystem,
            &self.config.hidden_volume_root,
            overlay_only,
        ) {
            tracing::error!(
                error = %e,
                "Failed to stage hidden NixOS config after early pre-flight checks"
            );
            return Err(NailsError::PreFlightCheckFailed(vec![(
                "nixos-config-staging".to_string(),
                e.to_string(),
            )]));
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
                    )])
                }
                other => other,
            })?;
        }

        Ok(())
    }

    /// Refuse activation when the `overlay-targets` check fails.
    fn enforce_overlay_target_floor(&self) -> Result<()> {
        let check = OverlayTargetsCheck::new(self.config.clone());
        match check.run(&self.filesystem)? {
            crate::CheckResult::Pass(_) | crate::CheckResult::Warn(_) => Ok(()),
            crate::CheckResult::Fail(message) => Err(NailsError::PreFlightCheckFailed(vec![(
                <OverlayTargetsCheck as PreFlightCheck<F>>::name(&check).to_string(),
                message,
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
