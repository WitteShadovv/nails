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
use crate::{Config, Filesystem, MockFilesystem, NailsError, SystemState};

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
/// the same checks.
#[test]
fn check_and_activation_build_the_same_checks_from_the_same_flags() {
    let manager = manager_with(MockFilesystem::new());
    let names = |options: &PreflightOptions| {
        manager
            .preflight_registry(options)
            .expect("registry builds")
            .names()
    };
    for bits in 0..8u8 {
        let (overlay_only, accept_persistent_decoy, allow_decoy_storage) =
            (bits & 1 != 0, bits & 2 != 0, bits & 4 != 0);
        let check = PreflightOptions {
            overlay_only,
            accept_persistent_decoy,
            allow_decoy_storage,
            ..PreflightOptions::default()
        };
        let activation = crate::manager::EnterOptions {
            overlay_only,
            accept_persistent_decoy,
            allow_decoy_storage,
            ..crate::manager::EnterOptions::default()
        }
        .preflight();
        assert_eq!(activation, check);
        assert!(activation.read_only, "activation never stages storage");
        assert_eq!(names(&activation), names(&check));
    }
}

/// Activation's pre-flight never stages storage, even with options that ask
/// for a registry that may: a refused activation leaves nothing on the hidden
/// volume.
#[test]
fn run_preflight_checks_creates_nothing_whatever_the_options_say() {
    let hidden_root = std::path::Path::new("/mnt/hidden");
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/mnt/hidden", true);
    fs.mock_set_mounted(hidden_root, true);
    fs.mock_set_writable("/mnt/hidden", true);
    let manager = manager_with(fs);

    let _ = manager.run_preflight_checks(&PreflightOptions {
        read_only: false,
        ..PreflightOptions::default()
    });

    for dir in ["root", "root/upper", "root/work"] {
        assert!(
            !manager
                .filesystem()
                .path_exists(&hidden_root.join(dir))
                .unwrap(),
            "pre-flight created {dir}"
        );
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

    // The failure reaches the log as a debug event; the console shows it once,
    // from the returned error, which the caller prints as a formatted list.
    // `logs_contain` is injected by `traced_test`.
    assert!(logs_contain("Preflight check failed"));
    assert!(
        !logs_contain("ERROR"),
        "a failed check is not logged as an error"
    );
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

/// A decoy whose `/etc/nixos` holds its own flake, with no hidden flake: the
/// detected NixOS host discovers the refused decoy flake (activation wires no
/// builder for it, so nothing is built), and the build-target check fails
/// with the instructions, although a legacy configuration sits beside it.
#[test]
fn a_decoy_flake_is_refused_across_discovery_and_preflight() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/etc/nixos/flake.nix", true);
    fs.mock_set_path_exists("/etc/nixos/configuration.nix", true);
    fs.mock_set_path_exists("/nix/var/nix/profiles/system", true);
    let mut manager = manager_with(fs);
    manager.set_host_profile(crate::platform::FakePlatform::nixos().host_profile());

    assert_eq!(
        manager.discover_host_target(false).unwrap(),
        crate::platform::HostTarget::DecoyFlake {
            dir: std::path::PathBuf::from("/etc/nixos"),
            hidden_volume_root: std::path::PathBuf::from("/mnt/hidden"),
        }
    );
    let result = build_target_result(&manager).expect("the check runs on NixOS");
    assert!(result.is_fail(), "{result:?}");
    assert!(
        result
            .remediation()
            .is_some_and(|fix| fix.starts_with("Write a self-contained flake in /mnt/hidden/nixos")),
        "{result:?}"
    );
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

/// Every refusal of the attach gate fails the hidden-volume check, skips the
/// checks that inspect the volume, and leaves no write probe behind.
#[test]
fn every_gate_refusal_fails_the_hidden_volume_check_and_skips_its_dependents() {
    use crate::filesystem::MockOp;
    let config = explicit_config();
    let root = config.hidden_volume_root.display().to_string();
    let decoy = "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n";
    let scenes = [
        ("folder", decoy.to_string(), false),
        (
            "covered",
            format!(
                "{decoy}30 1 253:0 / {root} rw - ext4 /dev/mapper/data rw\n\
                 31 30 8:17 / {root} rw - ext4 /dev/sdb1 rw\n"
            ),
            false,
        ),
        (
            "bind of a decoy folder",
            format!("{decoy}30 1 8:1 /srv/x {root} rw - ext4 /dev/vda1 rw\n"),
            false,
        ),
        (
            "unjudged",
            format!("{decoy}30 1 8:17 / {root} rw - ext4 /dev/sdb1 rw\n"),
            true,
        ),
    ];
    let inputs = RegistryInputs {
        options: PreflightOptions::default(),
        current_state: SystemState::Inactive,
        flake_target_already_validated: false,
        selected_flake_dir: None,
        discovered_target: crate::platform::HostTarget::None,
        operator: None,
        caller_path: None,
    };
    for (scene, table, unreadable_crypttab) in scenes {
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists(&root, true);
        fs.mock_set_writable(&root, true);
        fs.mock_set_mount_table(&table);
        if unreadable_crypttab {
            fs.mock_set_path_exists("/etc/crypttab", true);
        }
        let registry = build_registry(&fs, &config, &inputs, None).expect("registry builds");
        let (results, passed) = registry.run_all_detailed(&fs);
        assert!(!passed, "{scene}");
        let result = |name: &str| {
            results
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, r)| r.clone())
                .unwrap_or_else(|| panic!("{scene}: no {name}"))
        };
        assert!(result("hidden-volume").is_fail(), "{scene}");
        for dependent in [
            "symlink-support",
            "upper-fs-capability",
            "storage-readiness",
            "space",
        ] {
            assert!(result(dependent).is_skipped(), "{scene}: {dependent}");
        }
        let probes: Vec<MockOp> = fs
            .mock_ops()
            .into_iter()
            .filter(|op| {
                matches!(
                    op,
                    MockOp::WritableProbe { .. } | MockOp::SymlinkProbe { .. }
                )
            })
            .collect();
        assert!(probes.is_empty(), "{scene}: {probes:?}");
    }
}

#[test]
fn backend_entries_runs_right_after_the_hidden_volume_check() {
    let manager = manager_with(MockFilesystem::new());
    let names = manager
        .preflight_registry(&PreflightOptions::default())
        .expect("registry builds")
        .names();
    assert_eq!(&names[..2], &["hidden-volume", "backend-entries"]);
}

#[test]
fn the_entries_check_alone_refuses_a_decoy_entry_for_the_volume() {
    // What activation runs under --no-preflight: the hidden volume is the
    // whole of sdb, and the decoy's crypttab opens it.
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/mnt/hidden", true);
    fs.mock_set_mount_table(
        "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n\
         5 1 8:16 / /mnt/hidden rw - ext4 /dev/sdb rw\n",
    );
    let manager = manager_with(fs);
    manager.run_backend_entries_check().unwrap();

    manager
        .filesystem()
        .mock_add_file("/etc/crypttab", "data /dev/sdb none luks,noauto\n");
    match manager.run_backend_entries_check() {
        Err(NailsError::PreFlightCheckFailed(failures)) => {
            assert_eq!(failures.len(), 1, "{failures:?}");
            assert_eq!(failures[0].0, "backend-entries");
            assert!(failures[0].1.contains("data /dev/sdb"), "{failures:?}");
        }
        other => panic!("expected the check to refuse, got {other:?}"),
    }
}

#[test]
fn the_entries_check_alone_only_logs_its_warning() {
    // The volume is the whole of sdb, and the decoy opens a container on sdb1
    // of the same drive: a warning, reported as the pre-flight run reports
    // one, which does not refuse activation.
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/mnt/hidden", true);
    fs.mock_set_mount_table(
        "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n\
         5 1 8:16 / /mnt/hidden rw - ext4 /dev/sdb rw\n",
    );
    let mut class = Vec::new();
    for (dir, name, dev) in [
        ("/sys/devices/usb/sdb", "sdb", "8:16"),
        ("/sys/devices/usb/sdb/sdb1", "sdb1", "8:17"),
    ] {
        fs.mock_set_file_content(&format!("{dir}/dev"), &format!("{dev}\n"));
        fs.mock_set_file_content(&format!("{dir}/uevent"), &format!("DEVNAME={name}\n"));
        let link = format!("/sys/class/block/{name}");
        fs.create_symlink(std::path::Path::new(dir), std::path::Path::new(&link))
            .unwrap();
        class.push(std::path::PathBuf::from(link));
    }
    fs.mock_set_file_content("/sys/devices/usb/sdb/sdb1/partition", "1\n");
    fs.mock_set_directory_contents(std::path::Path::new("/sys/class/block"), class);
    fs.mock_add_file("/etc/crypttab", "outer /dev/sdb1 none tcrypt,noauto\n");
    let manager = manager_with(fs);
    let check =
        crate::preflight::checks::BackendEntriesCheck::new(std::path::PathBuf::from("/mnt/hidden"));
    match crate::preflight::PreFlightCheck::run(&check, manager.filesystem()).unwrap() {
        CheckResult::Warn(message) => assert!(
            message.contains("the decoy is configured to open storage on this drive"),
            "{message}"
        ),
        other => panic!("expected a warning, got {other:?}"),
    }
    manager
        .run_backend_entries_check()
        .expect("a warning does not refuse");
}
