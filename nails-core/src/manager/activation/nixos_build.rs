// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! NixOS Config Fingerprinting (Step 7)
//!
//! Computes a config fingerprint and checks the fast-path cache.  No actual
//! `nixos-rebuild` runs here — the real build + switch is deferred to Step 9
//! so the display-manager restart (Step 8.5) always happens *before* the
//! potentially expensive rebuild.
//!
//! The fingerprint computation itself lives in the platform
//! [`ConfigLayer`](crate::platform::ConfigLayer); this step routes through it so
//! a host without a config layer (any FHS / Debian host, or an overlay-only run)
//! does no NixOS work at all.

use crate::platform::ConfigLayer;
use crate::{Filesystem, NailsManager, Result, Verbosity};

impl<F: Filesystem> NailsManager<F> {
    /// Compute NixOS config fingerprint and check fast-path cache (Step 7).
    ///
    /// Both flake and legacy paths are handled identically:
    /// 1. Walk the hidden config tree and compute a fingerprint over it, plus the
    ///    flake reference and configuration name.
    /// 2. Compare against the stored fingerprint from the last successful
    ///    activation. When it matches *and* the cached toplevel store path still
    ///    exists on disk, carry that store path forward so Step 9 can switch to it
    ///    directly without rebuilding.
    ///
    /// Returns `(Option<fast_path_toplevel>, Option<fingerprint>)`, or
    /// `(None, None)` when the host has no config layer or no builder.
    pub(super) fn build_nixos_profile(
        &self,
        verbosity: Verbosity,
    ) -> Result<(Option<String>, Option<String>)> {
        // No declarative config layer (FHS / Debian host, or an overlay-only run)
        // means no fingerprint and no build target at all.
        let Some(layer) = self.config_layer() else {
            return Ok((None, None));
        };
        let Some(builder) = self.nixos_builder.as_ref() else {
            return Ok((None, None));
        };

        // The stored fingerprint and toplevel are manager state; the layer
        // computes the current fingerprint from the hidden config tree and decides
        // the fast path (checking the cached toplevel still exists itself).
        let (stored_fp, stored_toplevel) = {
            let cached = self.cached_state.borrow();
            (
                cached.as_ref().and_then(|sf| sf.config_fingerprint.clone()),
                cached
                    .as_ref()
                    .and_then(|sf| sf.hidden_toplevel().map(str::to_string)),
            )
        };

        let (flake_ref, config_name) = builder.fingerprint_inputs();
        // For a flake build the flake source directory is the build input the
        // fingerprint must track; a legacy build has none and falls back to the
        // staged hidden config trees.
        let flake_source = builder.flake_dir();

        let plan = layer.plan(
            &self.filesystem,
            &self.config.hidden_volume_root,
            stored_fp.as_deref(),
            stored_toplevel.as_deref(),
            flake_ref.as_deref(),
            config_name.as_deref(),
            flake_source,
            verbosity,
        )?;

        Ok((plan.fast_path_toplevel, Some(plan.fingerprint)))
    }
}

#[cfg(test)]
mod tests {
    use crate::nixos::{CommandExecutor, NixOSBuilder, SwitchAction};
    use crate::{
        ActivateOptions, Config, Filesystem, MockFilesystem, NailsManager, OverlayConfig,
        OverlayMode, Result,
    };
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};

    /// A command executor that records every invocation and runs nothing. A host
    /// without a config layer must never reach it.
    #[derive(Clone, Default)]
    struct RecordingExecutor {
        calls: Arc<Mutex<Vec<String>>>,
    }

    impl CommandExecutor for RecordingExecutor {
        fn execute_nixos_rebuild(
            &self,
            args: &[&str],
            _clear_nix_path: bool,
        ) -> Result<(bool, String, String)> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("nixos-rebuild {}", args.join(" ")));
            Ok((true, String::new(), String::new()))
        }

        fn execute_nix(
            &self,
            args: &[&str],
            _clear_nix_path: bool,
        ) -> Result<(bool, String, String)> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("nix {}", args.join(" ")));
            Ok((true, String::new(), String::new()))
        }

        fn execute_switch_to_configuration(
            &self,
            script_path: &Path,
            action: SwitchAction,
        ) -> Result<(bool, String, String)> {
            self.calls.lock().unwrap().push(format!(
                "switch-to-configuration {} {}",
                script_path.display(),
                action.as_arg()
            ));
            Ok((true, String::new(), String::new()))
        }
    }

    /// Done-when: with no config layer (an FHS host) and a recording command
    /// runner, a full activation never touches `/etc/nixos`, hidden NixOS staging,
    /// `nixos-rebuild` or `switch-to-configuration` — even though a NixOS builder
    /// is wired in. The layer, not the builder, is what gates the declarative half.
    #[test]
    fn activation_without_config_layer_runs_no_nixos_work() {
        let temp_dir = tempfile::tempdir().unwrap();
        let hidden_root = temp_dir.path();
        let state_path = hidden_root.join("state.json");

        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/", true);
        let upper_dir = hidden_root.join("overlays/home/upper");
        let work_dir = hidden_root.join("overlays/home/work");
        std::fs::create_dir_all(&upper_dir).unwrap();
        std::fs::create_dir_all(&work_dir).unwrap();
        fs.mock_set_path_exists(upper_dir.to_str().unwrap(), true);
        fs.mock_set_path_exists(work_dir.to_str().unwrap(), true);

        // A real flake-mode builder, but with a recording executor: if any
        // nixos-rebuild / switch-to-configuration were issued it would be seen.
        let executor = RecordingExecutor::default();
        let recorded = executor.calls.clone();
        let builder =
            NixOSBuilder::new(hidden_root.join("nixos"), hidden_root.join("nails-system"))
                .with_executor(Box::new(executor));

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
            ..Config::test_default()
        };

        let fs_clone = fs.clone();
        let mut manager = NailsManager::with_nixos(fs, config, state_path, builder);
        // A Debian/FHS host: no declarative config layer.
        manager.set_fake_platform(crate::platform::FakePlatform::fhs());

        assert!(
            manager.config_layer().is_none(),
            "FHS host has no config layer"
        );

        let options = ActivateOptions {
            kill_session: false,
            no_pivot: false,
            pre_activation_cleanup: false,
            skip_flake_validation: true,
            ..ActivateOptions::default()
        };

        // `no_preflight = true` keeps the test off the full registry; the staging
        // and switch gates are what this exercises.
        manager
            .activate_with_options(options, true)
            .expect("overlay activation succeeds on an FHS host");

        assert!(
            manager.current_state().unwrap().is_active(),
            "the overlay half still completes without a config layer"
        );

        // No nixos-rebuild and no switch-to-configuration were ever issued.
        assert!(
            recorded.lock().unwrap().is_empty(),
            "no NixOS command may run without a config layer, saw: {:?}",
            recorded.lock().unwrap()
        );

        // No hidden NixOS staging touched the hidden /etc/nixos tree.
        let staged = hidden_root.join("etc/nixos/nails/configuration.nix");
        assert!(
            !fs_clone.is_symlink(&staged).unwrap_or(false),
            "no hidden NixOS config may be staged without a config layer"
        );
        let module = hidden_root.join("etc/nixos/nails");
        assert!(
            !fs_clone.path_exists(&module).unwrap_or(false),
            "the hidden /etc/nixos tree must be untouched without a config layer"
        );
    }
}
