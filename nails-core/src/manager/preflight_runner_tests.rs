// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests for the shared pre-flight registry builder.
//!
//! Kept in a sibling file so `preflight_runner.rs` stays within the production
//! line budget; compiled only under `#[cfg(test)]`.

use super::{PreflightOptions, RegistryInputs, build_registry};
use crate::manager::NailsManager;
use crate::platform::NixOsConfigLayer;
use crate::preflight::CheckResult;
use crate::{Config, MockFilesystem, NailsError, SystemState};

fn check_names(results: &[(String, CheckResult)]) -> Vec<String> {
    results.iter().map(|(name, _)| name.clone()).collect()
}

fn explicit_config() -> Config {
    Config::test_default()
}

#[test]
fn build_registry_includes_the_shared_checks() {
    let fs = MockFilesystem::new();
    let config = explicit_config();
    let inputs = RegistryInputs {
        options: PreflightOptions::default(),
        current_state: SystemState::Inactive,
        flake_target_already_validated: false,
        selected_flake_dir: None,
        discovered_target: crate::platform::HostTarget::None,
        operator: None,
        caller_path: None,
    };

    let registry =
        build_registry(&fs, &config, &inputs, Some(&NixOsConfigLayer)).expect("registry builds");
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
        options: PreflightOptions {
            overlay_only: true,
            ..PreflightOptions::default()
        },
        current_state: SystemState::Inactive,
        flake_target_already_validated: false,
        selected_flake_dir: None,
        discovered_target: crate::platform::HostTarget::None,
        operator: None,
        caller_path: None,
    };

    let registry =
        build_registry(&fs, &config, &inputs, Some(&NixOsConfigLayer)).expect("registry builds");
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
        options: PreflightOptions::default(),
        current_state: SystemState::Inactive,
        flake_target_already_validated: false,
        selected_flake_dir: None,
        discovered_target: crate::platform::HostTarget::None,
        operator: None,
        caller_path: None,
    };

    let registry = build_registry(&fs, &config, &inputs, None).expect("registry builds");
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

    // A registry that may stage storage and a read-only one route through the
    // same `preflight_registry`, so for the same inputs the sequence of check
    // names is identical — only individual checks' write behaviour differs.
    let staging = manager
        .preflight_registry(&PreflightOptions {
            read_only: false,
            ..PreflightOptions::default()
        })
        .expect("staging registry");
    let check = manager
        .preflight_registry(&PreflightOptions::default())
        .expect("check registry");

    let staging_names = check_names(&staging.run_all_detailed(&MockFilesystem::new()).0);
    let doctor_names = check_names(&check.run_all_detailed(&MockFilesystem::new()).0);

    assert_eq!(staging_names, doctor_names);
}

/// `nails check` builds its options from its flags and activation takes them
/// from `EnterOptions::preflight`: the same flags give the same options and so
/// the same checks (T-062).
#[test]
fn check_and_activation_build_the_same_checks_from_the_same_flags() {
    let manager = manager_with(MockFilesystem::new());
    let names = |options: &PreflightOptions| {
        manager
            .preflight_registry(options)
            .expect("registry builds")
            .names()
    };
    for (overlay_only, accept_persistent_decoy) in
        [(false, false), (true, false), (false, true), (true, true)]
    {
        let check = PreflightOptions {
            overlay_only,
            accept_persistent_decoy,
            ..PreflightOptions::default()
        };
        let activation = crate::manager::EnterOptions {
            overlay_only,
            accept_persistent_decoy,
            ..crate::manager::EnterOptions::default()
        }
        .preflight();
        assert_eq!(activation, check);
        assert!(activation.read_only, "activation never stages storage");
        assert_eq!(names(&activation), names(&check));
    }
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
        options: PreflightOptions::default(),
        current_state: SystemState::Inactive,
        flake_target_already_validated: false,
        selected_flake_dir: None,
        discovered_target: crate::platform::HostTarget::None,
        operator: None,
        caller_path: None,
    };

    let registry =
        build_registry(&fs, &config, &inputs, Some(&NixOsConfigLayer)).expect("registry builds");
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
        ..Config::test_default()
    };

    let manager = NailsManager::new(fs, config, state_path);

    let err = manager
        .run_preflight_checks(&PreflightOptions {
            overlay_only: true,
            ..PreflightOptions::default()
        })
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

/// The build-target check's verdict for a manager's registry.
fn build_target_result(manager: &NailsManager<MockFilesystem>) -> Option<CheckResult> {
    let registry = manager
        .preflight_registry(&PreflightOptions::default())
        .expect("registry builds");
    registry
        .run_all_detailed(manager.filesystem())
        .0
        .into_iter()
        .find(|(name, _)| name == "nixos-build-target")
        .map(|(_, result)| result)
}

fn manager_with(fs: MockFilesystem) -> NailsManager<MockFilesystem> {
    let config = Config {
        hidden_volume_root: std::path::PathBuf::from("/mnt/hidden"),
        ..explicit_config()
    };
    NailsManager::new(
        fs,
        config,
        std::path::PathBuf::from("/mnt/hidden/state.json"),
    )
}

/// The cross-path agreement case on a detected NixOS host where only the system
/// profile exists. Activation and `check`/`--dry-run` both take the target from
/// `discover_host_target` (activation wires its builder from it, `check` renders
/// its profile summary from it), and the `nixos-build-target` pre-flight reports
/// the target resolved by that same call — so all three agree on the legacy
/// build.
#[test]
fn lone_system_profile_agrees_across_activation_check_and_preflight() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/nix/var/nix/profiles/system", true);
    let mut manager = manager_with(fs);
    manager.set_host_profile(crate::platform::FakePlatform::nixos().host_profile());

    let legacy = crate::platform::HostTarget::Legacy(std::path::PathBuf::from(
        "/etc/nixos/configuration.nix",
    ));
    assert_eq!(manager.discover_host_target(false).unwrap(), legacy);

    let result = build_target_result(&manager).expect("the check runs on NixOS");
    assert!(result.is_pass(), "{result:?}");
    assert!(result.message().contains("/etc/nixos/configuration.nix"));
}

/// With a fake platform the pre-flight reports exactly the pinned target, with
/// no NixOS discovery fixtures on the mock host.
#[test]
fn preflight_reports_the_fake_platform_target() {
    let mut manager = manager_with(MockFilesystem::new());
    manager.set_fake_platform(crate::platform::FakePlatform::nixos().with_build_target(
        crate::platform::HostTarget::Flake(std::path::PathBuf::from("/cfg/flake")),
    ));
    let result = build_target_result(&manager).expect("the check runs on NixOS");
    assert!(result.is_pass(), "{result:?}");
    assert!(result.message().contains("/cfg/flake"));

    let mut manager = manager_with(MockFilesystem::new());
    manager.set_fake_platform(crate::platform::FakePlatform::nixos());
    let result = build_target_result(&manager).expect("the check runs on NixOS");
    assert!(
        result.is_fail(),
        "no discovered target must fail: {result:?}"
    );
}

/// On a host without a config layer every path agrees there is no build
/// target: discovery says `None` (so activation wires no builder and `check`
/// reports no switch) and the build-target check is not registered at all —
/// even when the host carries NixOS files.
#[test]
fn host_without_config_layer_agrees_there_is_no_target() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/nix/var/nix/profiles/system", true);
    fs.mock_set_path_exists("/etc/nixos/flake.nix", true);
    let mut manager = manager_with(fs);
    manager.set_fake_platform(crate::platform::FakePlatform::fhs());

    assert_eq!(
        manager.discover_host_target(false).unwrap(),
        crate::platform::HostTarget::None
    );
    assert!(build_target_result(&manager).is_none());
}
