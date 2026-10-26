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
        host_profile: None,
        systemd_version: None,
    };

    let registry =
        build_registry(&fs, &config, &inputs, Some(&NixOsConfigLayer)).expect("registry builds");
    let (results, _) = registry.run_all_detailed(&fs);
    let names = check_names(&results);

    for expected in [
        "hidden-volume",
        "backend-detect",
        "storage-readiness",
        "suspicious-nails-reference",
        "nixos-config",
        "nixos-build-target",
        "binary-location",
        "dma-protection",
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
        host_profile: None,
        systemd_version: None,
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
        host_profile: None,
        systemd_version: None,
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
    let read_only_names = check_names(&check.run_all_detailed(&MockFilesystem::new()).0);

    assert_eq!(staging_names, read_only_names);
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
    for bits in 0..16u8 {
        let (overlay_only, allow_persistent_decoy, allow_decoy_storage, allow_discards) =
            (bits & 1 != 0, bits & 2 != 0, bits & 4 != 0, bits & 8 != 0);
        let check = PreflightOptions {
            overlay_only,
            allow_persistent_decoy,
            allow_decoy_storage,
            allow_discards,
            ..PreflightOptions::default()
        };
        let activation = crate::manager::EnterOptions {
            overlay_only,
            allow_persistent_decoy,
            allow_decoy_storage,
            allow_discards,
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
        host_profile: None,
        systemd_version: None,
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

/// A watching event stream sees every check of the registry, in execution
/// order, with its outcome: the run hands each result on as its check ends.
#[test]
fn every_check_reaches_a_watching_event_stream_in_order() {
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let hidden_root = temp_dir.path();
    let state_path = hidden_root.join("state.json");
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists(hidden_root.to_str().unwrap(), true);
    fs.mock_set_mounted(hidden_root, false);
    let config = Config {
        hidden_volume_root: hidden_root.to_path_buf(),
        state_file_path: state_path.clone(),
        ..Config::test_default()
    };
    let manager = NailsManager::new(fs, config, state_path);
    let options = PreflightOptions {
        overlay_only: true,
        read_only: true,
        ..PreflightOptions::default()
    };
    let names = manager.preflight_registry(&options).unwrap().names();

    let sink = crate::reporter::CollectingSink::new();
    {
        let reporter = crate::reporter::EventReporter::new(sink.clone());
        let _scope =
            crate::reporter::progress::install(crate::reporter::progress::shared(reporter));
        let _ = manager.run_preflight_checks(&options);
    }
    let checks: Vec<(String, nails_api::CheckOutcome)> = sink
        .events()
        .into_iter()
        .filter_map(|event| match event {
            nails_api::Event::Check { name, outcome, .. } => Some((name, outcome)),
            _ => None,
        })
        .collect();

    assert_eq!(
        checks
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>(),
        names
    );
    assert!(
        checks.contains(&("hidden-volume".to_string(), nails_api::CheckOutcome::Fail)),
        "{checks:?}"
    );
}

/// The routine pre-flight events stay at debug level: at the default
/// verbosity the console shows only what needs the operator.
#[test]
#[tracing_test::traced_test]
fn passing_checks_log_at_debug_only() {
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let hidden_root = temp_dir.path();
    let state_path = hidden_root.join("state.json");
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists(hidden_root.to_str().unwrap(), true);
    fs.mock_set_mounted(hidden_root, false);
    let config = Config {
        hidden_volume_root: hidden_root.to_path_buf(),
        state_file_path: state_path.clone(),
        ..Config::test_default()
    };
    let manager = NailsManager::new(fs, config, state_path);
    let _ = manager.run_preflight_checks(&PreflightOptions {
        overlay_only: true,
        ..PreflightOptions::default()
    });

    assert!(logs_contain("Preflight check passed"), "no check passed");
    logs_assert(|lines: &[&str]| {
        match lines.iter().find(|line| {
            (line.contains("Preflight check passed")
                || line.contains("All pre-flight checks passed"))
                && !line.contains("DEBUG")
        }) {
            Some(line) => Err(format!("a routine event above debug: {line}")),
            None => Ok(()),
        }
    });
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

/// Naming the decoy's own flake is no way around the refusal: in each
/// spelling of /etc/nixos it fails the build-target check. With a hidden flake
/// beside it, the refusal says the decoy's flake was named and how to take the
/// hidden one.
#[test]
fn the_decoy_flake_named_explicitly_is_refused_in_every_spelling() {
    for (spelling, hidden_flake) in [
        ("/etc/nixos#host", false),
        ("path:/etc/nixos#host", false),
        ("/etc/nixos/#host", true),
        ("git+file:///etc/nixos?ref=main#host", true),
        ("/etc/nixos?dir=.#host", false),
        ("/etc/nixos/?ref=main#host", true),
        ("path:/etc?dir=nixos#host", false),
        ("git+file:///etc?dir=nixos#host", true),
    ] {
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/etc/nixos/flake.nix", true);
        fs.mock_set_path_exists("/mnt/hidden/nixos/flake.nix", hidden_flake);
        let config = Config {
            hidden_volume_root: std::path::PathBuf::from("/mnt/hidden"),
            nixos_flake: Some(spelling.to_string()),
            ..explicit_config()
        };
        let mut manager = NailsManager::new(
            fs,
            config,
            std::path::PathBuf::from("/mnt/hidden/state.json"),
        );
        manager.set_host_profile(crate::platform::FakePlatform::nixos().host_profile());

        let result = build_target_result(&manager).expect("the check runs on NixOS");
        assert!(result.is_fail(), "{spelling}: {result:?}");
        let fix = result.remediation().unwrap_or_default();
        if hidden_flake {
            assert!(
                result
                    .message()
                    .contains("--nixos-flake or nixos_flake names it"),
                "{spelling}: {result:?}"
            );
            assert!(
                fix.starts_with("Name the hidden flake in /mnt/hidden/nixos instead"),
                "{spelling}: {fix}"
            );
        } else {
            assert!(
                result.message().contains("/mnt/hidden/nixos holds none"),
                "{spelling}: {result:?}"
            );
        }
    }
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
        host_profile: None,
        systemd_version: None,
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

/// Register one block device under `dir` in the mock sysfs, as the
/// backend-detect fixtures do: a `dev`/`uevent` pair, an optional dm uuid and
/// loop backing file, and the runtime discard policy.
fn add_block_device(
    fs: &MockFilesystem,
    dir: &str,
    devname: &str,
    dm_uuid: Option<&str>,
    backing_file: Option<&str>,
    discard_max_bytes: &str,
) {
    fs.mock_set_file_content(&format!("{dir}/dev"), "0:0\n");
    fs.mock_set_file_content(
        &format!("{dir}/uevent"),
        &format!("MAJOR=0\nMINOR=0\nDEVNAME={devname}\nDEVTYPE=disk\n"),
    );
    if let Some(uuid) = dm_uuid {
        fs.mock_set_file_content(&format!("{dir}/dm/uuid"), &format!("{uuid}\n"));
    }
    if let Some(file) = backing_file {
        fs.mock_set_file_content(&format!("{dir}/loop/backing_file"), &format!("{file}\n"));
    }
    fs.mock_set_file_content(
        &format!("{dir}/queue/discard_max_bytes"),
        &format!("{discard_max_bytes}\n"),
    );
}

/// A tcrypt mapping (`253:3` -> dm-3) over a loop-backed container under the
/// `/mnt/hidden` root [`manager_with`] configures, with the given runtime
/// discard policy on the crypt layer. A tcrypt mapping reads no LUKS2 header,
/// so the fixture never touches the host's `/dev`.
fn tcrypt_discard_fixture(discard_max_bytes: &str) -> MockFilesystem {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/mnt/hidden", true);
    // BackendDetectCheck reads the raw /proc/self/mountinfo (not fs.mount_table),
    // so set the file directly, as the backend-detect fixtures do.
    fs.mock_set_file_content(
        "/proc/self/mountinfo",
        "23 1 254:0 / / rw,relatime shared:1 - ext4 /dev/mapper/cryptroot rw\n\
         40 23 253:3 / /mnt/hidden rw,relatime shared:9 - ext4 /dev/mapper/veracrypt-hidden rw\n",
    );
    add_block_device(
        &fs,
        "/sys/dev/block/253:3",
        "dm-3",
        Some("CRYPT-TCRYPT-veracrypt-hidden"),
        None,
        discard_max_bytes,
    );
    fs.mock_set_directory_contents(
        std::path::Path::new("/sys/dev/block/253:3/slaves"),
        vec![std::path::PathBuf::from(
            "/sys/dev/block/253:3/slaves/loop0",
        )],
    );
    add_block_device(
        &fs,
        "/sys/dev/block/253:3/slaves/loop0",
        "loop0",
        None,
        Some("/home/alice/family_photos"),
        "4096",
    );
    fs
}

/// The pre-flight options an activation runs with, `--allow-discards` given
/// or not: what `enter_session` passes to `run_preflight_checks`.
fn activation_preflight(allow_discards: bool) -> PreflightOptions {
    crate::manager::EnterOptions {
        allow_discards,
        ..crate::manager::EnterOptions::default()
    }
    .preflight()
}

/// The `backend-detect` failure, as message and remediation, that an
/// activation's pre-flight over `fs` refuses with; `None` when it does not
/// refuse on that check. The mock host fails checks of its own, so this looks
/// for the one row among the failures.
fn backend_detect_refusal(
    fs: MockFilesystem,
    allow_discards: bool,
) -> Option<(String, Option<String>)> {
    let manager = manager_with(fs);
    match manager.run_preflight_checks(&activation_preflight(allow_discards)) {
        Ok(()) => None,
        Err(NailsError::PreFlightCheckFailed(failures)) => failures
            .into_iter()
            .find(|(name, _, _)| name == "backend-detect")
            .map(|(_, message, remediation)| (message, remediation)),
        Err(other) => panic!("expected a pre-flight result, got {other:?}"),
    }
}

/// The `backend-detect` row of the registry an activation's pre-flight runs
/// over `fs`.
fn backend_detect_row(fs: MockFilesystem, allow_discards: bool) -> CheckResult {
    let manager = manager_with(fs);
    manager
        .preflight_registry(&activation_preflight(allow_discards))
        .expect("registry builds")
        .run_all_detailed(manager.filesystem())
        .0
        .into_iter()
        .find(|(name, _)| name == "backend-detect")
        .map(|(_, result)| result)
        .expect("every activation runs backend-detect")
}

/// Every activation refuses discards over the hidden volume: a cryptsetup
/// mapping that forwards TRIM to the physical device makes the used/free map
/// readable where a deniable volume must look like random data, so the
/// activation's own pre-flight fails `backend-detect` with no flag given. The
/// check's detection is covered in `backend_detect/tests.rs`; this pins the
/// fail-closed default the activation registry builds it with.
#[test]
fn activation_refuses_discards_over_the_hidden_volume() {
    let refusal = backend_detect_refusal(tcrypt_discard_fixture("2147450880"), false);
    let (message, remediation) = refusal.expect("activation refuses on backend-detect");
    assert!(
        message.contains("Discards are enabled over the hidden volume"),
        "{message}"
    );
    let remediation = remediation.expect("the refusal says how to fix it");
    assert!(
        remediation.starts_with("Re-open the hidden volume with discards off"),
        "{remediation}"
    );
    // The refusal names no device-mapper node.
    assert!(!message.contains("dm-"), "{message}");
    assert!(!remediation.contains("dm-"), "{remediation}");
}

/// The same backend with discards off is not refused: the loop-backed file
/// container only warns (its ctime cannot be restored), and a warning does not
/// refuse.
#[test]
fn activation_does_not_refuse_the_backend_without_discards() {
    assert_eq!(
        backend_detect_refusal(tcrypt_discard_fixture("0"), false),
        None
    );
    let row = backend_detect_row(tcrypt_discard_fixture("0"), false);
    assert!(row.is_warn(), "{row:?}");
    assert!(row.message().contains("file container"), "{row:?}");
    assert!(!row.message().contains("Discards"), "{row:?}");
}

/// `--allow-discards` accepts the discards for this run only: the activation's
/// pre-flight no longer refuses on `backend-detect`, and the check warns with
/// the accepted-for-this-run message, which the operator sees as a console
/// warning like a row of `nails check`.
#[test]
#[tracing_test::traced_test]
fn allow_discards_turns_the_activation_refusal_into_a_warning() {
    assert_eq!(
        backend_detect_refusal(tcrypt_discard_fixture("2147450880"), true),
        None
    );
    logs_assert(|lines: &[&str]| {
        let warned = lines.iter().any(|line| {
            line.contains("WARN")
                && line.contains("backend-detect: Hidden root backend")
                && line.contains("accepted for this run")
        });
        if warned {
            Ok(())
        } else {
            Err("no backend-detect warning at activation".to_string())
        }
    });

    let row = backend_detect_row(tcrypt_discard_fixture("2147450880"), true);
    assert!(row.is_warn(), "{row:?}");
    assert!(
        row.message()
            .contains("Discards are enabled over the hidden volume, accepted for this run"),
        "{row:?}"
    );
}

/// A manager over a mock host whose os-release is `os_release`, with the host
/// detected as `check` and activation detect it.
fn manager_on_host(os_release: &str) -> NailsManager<MockFilesystem> {
    let fs = MockFilesystem::new();
    fs.mock_set_file_content("/etc/os-release", os_release);
    fs.mock_set_file_content("/proc/1/comm", "systemd\n");
    let mut manager = manager_with(fs);
    manager
        .initialize_platform()
        .expect("detection reads through the mock");
    manager
}

/// The platform row's verdict in a manager's registry.
fn platform_result(manager: &NailsManager<MockFilesystem>) -> Option<CheckResult> {
    let registry = manager
        .preflight_registry(&PreflightOptions::default())
        .expect("registry builds");
    registry
        .run_all_detailed(manager.filesystem())
        .0
        .into_iter()
        .find(|(name, _)| name == "platform")
        .map(|(_, result)| result)
}

/// A release NAILS has not been tested on warns in `check` and at activation
/// alike: the platform row, right before the systemd checks, warns, and
/// activation logs the warning as the console shows one, `<check>: <message>`.
#[test]
#[tracing_test::traced_test]
fn an_untested_release_warns_in_check_and_at_activation() {
    let manager = manager_on_host("ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"28.04\"\n");
    let names = manager
        .preflight_registry(&PreflightOptions::default())
        .expect("registry builds")
        .names();
    let at = names
        .iter()
        .position(|name| *name == "platform")
        .expect("a platform row");
    assert_eq!(names[at + 1], "systemd-version", "{names:?}");

    let result = platform_result(&manager).expect("a platform row");
    assert!(result.is_warn(), "{result:?}");

    let _ = manager.run_preflight_checks(&PreflightOptions::default());
    assert!(logs_contain(
        "platform: Ubuntu 28.04 is not a release NAILS has been tested on"
    ));
}

/// A tested release passes with its name; a host activation refuses fails the
/// row with activation's reason, so `check` no longer reports it ready.
#[test]
fn the_platform_row_names_a_tested_host_and_fails_a_refused_one() {
    let manager = manager_on_host("ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"24.04\"\n");
    let result = platform_result(&manager).expect("a platform row");
    assert!(result.is_pass(), "{result:?}");
    assert_eq!(result.message(), "Ubuntu 24.04");

    let manager = manager_on_host("ID=arch\nBUILD_ID=rolling\n");
    let result = platform_result(&manager).expect("a platform row");
    assert!(result.is_fail(), "{result:?}");
    let refusal = manager
        .host_profile()
        .and_then(|profile| profile.unsupported_reason.clone())
        .expect("arch is refused");
    assert_eq!(result.message(), refusal);
}

/// Without a detected host there is no platform row: activation then refuses
/// no host either.
#[test]
fn no_platform_row_without_a_detected_host() {
    let manager = manager_with(MockFilesystem::new());
    assert!(platform_result(&manager).is_none());
}

/// The systemd-version row of the registry built from inputs that carry the
/// host a manager detects on `os_release` (no host for `None`) and the running
/// systemd's `version`.
fn systemd_version_row(os_release: Option<&str>, version: Option<u32>) -> CheckResult {
    let fs = MockFilesystem::new();
    let inputs = RegistryInputs {
        options: PreflightOptions::default(),
        current_state: SystemState::Inactive,
        flake_target_already_validated: false,
        selected_flake_dir: None,
        discovered_target: crate::platform::HostTarget::None,
        operator: None,
        caller_path: None,
        host_profile: os_release
            .and_then(|os_release| manager_on_host(os_release).host_profile().cloned()),
        systemd_version: version,
    };
    build_registry(&fs, &explicit_config(), &inputs, None)
        .expect("registry builds")
        .run_all_detailed(&fs)
        .0
        .into_iter()
        .find(|(name, _)| name == "systemd-version")
        .map(|(_, result)| result)
        .expect("a systemd-version row")
}

/// The registry judges the running systemd on the detected host: a systemd
/// too old is told how that host's distribution upgrades, and without a host
/// the platforms NAILS runs on.
#[test]
fn an_old_systemd_is_told_how_the_detected_host_upgrades() {
    for (os_release, version, upgrade) in [
        (
            "ID=debian\nVERSION_ID=\"12\"\n",
            252,
            "Upgrade to Debian 13 as its release notes describe, then reboot.",
        ),
        (
            "ID=fedora\nVERSION_ID=38\n",
            253,
            "Upgrade to Fedora 44 with `dnf system-upgrade`, at most two releases at a time.",
        ),
    ] {
        let row = systemd_version_row(Some(os_release), Some(version));
        assert!(row.is_fail(), "{os_release}: {row:?}");
        assert!(
            row.message()
                .contains(&format!("systemd {version} is too old")),
            "{row:?}"
        );
        assert_eq!(row.remediation(), Some(upgrade), "{os_release}");
    }

    let unknown = systemd_version_row(None, Some(252));
    assert_eq!(
        unknown.remediation(),
        Some(crate::platform::upgrade_hint(None).as_str()),
        "{unknown:?}"
    );
}

/// The row judges the version the inputs carry: one new enough passes, and
/// one that could not be read fails.
#[test]
fn the_systemd_version_row_judges_the_version_it_is_given() {
    let debian = Some("ID=debian\nVERSION_ID=\"13\"\n");
    let current = systemd_version_row(debian, Some(257));
    assert!(current.is_pass(), "{current:?}");
    let unread = systemd_version_row(debian, None);
    assert!(unread.is_fail(), "{unread:?}");
}
