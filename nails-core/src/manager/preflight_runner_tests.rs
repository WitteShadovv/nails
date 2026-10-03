//! Tests for the shared pre-flight registry builder.
//!
//! Kept in a sibling file so `preflight_runner.rs` stays within the production
//! line budget; compiled only under `#[cfg(test)]`.

use super::{RegistryInputs, build_registry};
use crate::config::OverlayMode;
use crate::manager::NailsManager;
use crate::preflight::CheckResult;
use crate::{Config, MockFilesystem, NailsError, SystemState};

fn check_names(results: &[(String, CheckResult)]) -> Vec<String> {
    results.iter().map(|(name, _)| name.clone()).collect()
}

fn explicit_config() -> Config {
    Config {
        // Explicit mode keeps the check set independent of the host's layout.
        overlay_mode: OverlayMode::Explicit,
        overlays: vec![],
        ..Config::test_default()
    }
}

#[test]
fn build_registry_includes_the_shared_checks() {
    let fs = MockFilesystem::new();
    let config = explicit_config();
    let inputs = RegistryInputs {
        overlay_only: false,
        has_config_layer: true,
        read_only: true,
        current_state: SystemState::Inactive,
        flake_target_already_validated: false,
        selected_flake_dir: None,
        operator: None,
        allow_persistent_journal: false,
    };

    let registry = build_registry(&fs, &config, &inputs).expect("registry builds");
    let (results, _) = registry.run_all_detailed(&fs);
    let names = check_names(&results);

    for expected in [
        "hidden-volume",
        "storage-readiness",
        "suspicious-nails-reference",
        "nixos-config",
        "nixos-build-target",
        "binary-location",
        "state",
    ] {
        assert!(
            names.iter().any(|name| name == expected),
            "expected {expected} among {names:?}"
        );
    }
}

#[test]
fn overlay_only_registry_drops_the_nixos_checks() {
    let fs = MockFilesystem::new();
    let config = explicit_config();
    let inputs = RegistryInputs {
        overlay_only: true,
        has_config_layer: true,
        read_only: true,
        current_state: SystemState::Inactive,
        flake_target_already_validated: false,
        selected_flake_dir: None,
        operator: None,
        allow_persistent_journal: false,
    };

    let registry = build_registry(&fs, &config, &inputs).expect("registry builds");
    let names = check_names(&registry.run_all_detailed(&fs).0);

    assert!(!names.iter().any(|name| name == "nixos-config"));
    assert!(!names.iter().any(|name| name == "nixos-build-target"));
}

#[test]
fn fhs_host_registry_drops_the_nixos_checks_without_overlay_only() {
    // A non-NixOS host has no config layer, so the NixOS checks must not be
    // registered even when `--overlay-only` was not passed: otherwise they would
    // fire and fail with NixOS-only guidance on a Debian/Ubuntu host.
    let fs = MockFilesystem::new();
    let config = explicit_config();
    let inputs = RegistryInputs {
        overlay_only: false,
        has_config_layer: false,
        read_only: true,
        current_state: SystemState::Inactive,
        flake_target_already_validated: false,
        selected_flake_dir: None,
        operator: None,
        allow_persistent_journal: false,
    };

    let registry = build_registry(&fs, &config, &inputs).expect("registry builds");
    let names = check_names(&registry.run_all_detailed(&fs).0);

    assert!(!names.iter().any(|name| name == "nixos-config"));
    assert!(!names.iter().any(|name| name == "nixos-build-target"));
    // The shared, platform-agnostic checks are still present.
    assert!(names.iter().any(|name| name == "hidden-volume"));
    assert!(names.iter().any(|name| name == "state"));
}

#[test]
fn activation_and_check_build_identical_check_lists() {
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let hidden_root = temp_dir.path();
    let state_path = hidden_root.join("state.json");

    let config = Config {
        hidden_volume_root: hidden_root.to_path_buf(),
        state_file_path: state_path.clone(),
        ..explicit_config()
    };
    let manager = NailsManager::new(MockFilesystem::new(), config, state_path);

    // Activation (read_only = false) and check (read_only = true) route through
    // the same `preflight_registry`, so for the same inputs the sequence of
    // check names is identical — only individual checks' write behaviour differs.
    let activation = manager
        .preflight_registry(false, false, false)
        .expect("activation registry");
    let check = manager
        .preflight_registry(false, true, false)
        .expect("check registry");

    let activation_names = check_names(&activation.run_all_detailed(&MockFilesystem::new()).0);
    let doctor_names = check_names(&check.run_all_detailed(&MockFilesystem::new()).0);

    assert_eq!(activation_names, doctor_names);
}

#[test]
fn read_only_registry_creates_nothing() {
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let hidden_root = temp_dir.path();
    let fs = MockFilesystem::new();
    let config = Config {
        hidden_volume_root: hidden_root.to_path_buf(),
        state_file_path: hidden_root.join("state.json"),
        ..explicit_config()
    };
    let inputs = RegistryInputs {
        overlay_only: false,
        has_config_layer: true,
        read_only: true,
        current_state: SystemState::Inactive,
        flake_target_already_validated: false,
        selected_flake_dir: None,
        operator: None,
        allow_persistent_journal: false,
    };

    let registry = build_registry(&fs, &config, &inputs).expect("registry builds");
    let _ = registry.run_all_detailed(&fs);

    // The read-only registry must not stage the hidden NixOS layout or create
    // any of the directories the auto-creating checks would otherwise write.
    let hidden_module = hidden_root.join("config/nixos/configuration.nix");
    assert!(
        fs.get_written_content(&hidden_module).is_none(),
        "check wrote the hidden module"
    );
    assert!(
        fs.mock_get_symlink_target(&hidden_root.join("etc/nixos/nails/configuration.nix"))
            .is_none(),
        "check staged a config symlink"
    );
    assert!(
        fs.mock_get_permissions(&hidden_root.join("etc")).is_none(),
        "check created or chmodded a required directory"
    );
}

/// Preflight progress now travels on one channel: tracing events the CLI
/// subscriber renders under the resolved verbosity. This asserts a failing
/// check is reported as a `fail` event and folded into `PreFlightCheckFailed`,
/// with no second ad-hoc report (the old `output::check_result` print is gone).
#[test]
#[tracing_test::traced_test]
fn failing_check_is_reported_through_tracing() {
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let hidden_root = temp_dir.path();
    let state_path = hidden_root.join("state.json");

    let fs = MockFilesystem::new();
    fs.mock_set_path_exists(hidden_root.to_str().unwrap(), true);
    // Leave the hidden volume unmounted so HiddenVolumeCheck fails.
    fs.mock_set_mounted(hidden_root, false);

    let config = Config {
        hidden_volume_root: hidden_root.to_path_buf(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        // Explicit mode keeps the check set independent of the host's layout.
        overlay_mode: OverlayMode::Explicit,
        ..Config::test_default()
    };

    let manager = NailsManager::new(fs, config, state_path);

    let err = manager
        .run_preflight_checks(true, false)
        .expect_err("an unmounted hidden volume must fail preflight");
    match err {
        NailsError::PreFlightCheckFailed(failures) => {
            assert!(
                failures.iter().any(|(name, _, _)| name == "hidden-volume"),
                "expected the hidden-volume check among {failures:?}"
            );
        }
        other => panic!("expected PreFlightCheckFailed, got {other:?}"),
    }

    // The failure is reported on the one progress channel (tracing); the old
    // unconditional `output::check_result` print is gone, so this is the only
    // report of the check. `logs_contain` is injected by `traced_test`.
    assert!(logs_contain("Preflight check failed"));
}
