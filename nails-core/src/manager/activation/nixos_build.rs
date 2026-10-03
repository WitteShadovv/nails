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
    /// 1. Read the two NixOS config files from the hidden volume.
    /// 2. Compute a fingerprint over them.
    /// 3. Compare against the stored fingerprint from the last successful
    ///    activation.  When they match *and* the stored generation is known,
    ///    carry it forward so Step 9 can attempt a cheap
    ///    `switch-to-configuration` before falling back to a full rebuild.
    ///
    /// Returns `(Option<fast_path_generation>, Option<fingerprint>)`, or
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
        if self.nixos_builder.is_none() {
            return Ok((None, None));
        }

        // The stored fingerprint and generation are manager state; the layer
        // computes the current fingerprint from the hidden config and decides the
        // fast path.
        let (stored_fp, stored_generation) = {
            let cached = self.cached_state.borrow();
            (
                cached.as_ref().and_then(|sf| sf.config_fingerprint.clone()),
                cached.as_ref().and_then(|sf| sf.nixos_generation.clone()),
            )
        };

        let plan = layer.plan(
            &self.filesystem,
            &self.config.hidden_volume_root,
            stored_fp.as_deref(),
            stored_generation.as_deref(),
            verbosity,
        )?;

        // The fingerprint matching does not prove the cached generation's closure
        // still exists: the decoy's garbage collector may have removed it between
        // sessions. Before carrying the fast path forward, confirm the hidden
        // profile still resolves to that generation; if it is gone (or now points
        // elsewhere) drop the fast path so Step 9 does a full rebuild instead of
        // switching to a vanished closure.
        let fast_path_generation = match plan.fast_path_generation {
            Some(generation) => self.verify_fast_path_generation(generation),
            None => None,
        };

        Ok((fast_path_generation, Some(plan.fingerprint)))
    }

    /// Keep `generation` as the fast path only when the on-disk hidden profile
    /// still resolves to it; otherwise warn and return `None` to force a rebuild.
    fn verify_fast_path_generation(&self, generation: String) -> Option<String> {
        let Some(builder) = self.nixos_builder.as_ref() else {
            return Some(generation);
        };
        match builder.cached_generation() {
            Ok(Some(on_disk)) if on_disk == generation => Some(generation),
            other => {
                tracing::warn!(
                    generation = %generation,
                    found = ?other,
                    "Cached hidden NixOS generation is no longer present in /nix; forcing a full rebuild"
                );
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::nixos::{CommandExecutor, NixOSBuilder, SwitchAction};
    use crate::platform::{HostProfile, PlatformKind};
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
        manager.set_host_profile(HostProfile {
            kind: PlatformKind::Fhs,
            id: Some("debian".to_string()),
            id_like: vec![],
            version_id: Some("12".to_string()),
            is_systemd: true,
            is_ostree: false,
            has_current_system: false,
            unsupported_reason: None,
        });

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
