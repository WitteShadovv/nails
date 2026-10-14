// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use nails_core::filesystem::PathKind;
use nails_core::{Config, Filesystem, MockFilesystem, SystemState};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

fn write_test_base_hardware_config(root: &Path) -> PathBuf {
    let path = root.join("decoy/etc/nixos/hardware-configuration.nix");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(
        &path,
        "{ config, lib, pkgs, modulesPath, ... }:\n{\n  imports = [ (modulesPath + \"/installer/scan/not-detected.nix\") ];\n}\n",
    )
    .unwrap();
    path
}

/// Arguments that initialize a real volume, with the base hardware config
/// pinned so the run never consults the host.
fn real_init_args(path: &Path, base_hardware_config: &Path) -> InitArgs {
    InitArgs {
        path: path.to_path_buf(),
        allow_decoy_storage: false,
        hardware_config: Some(base_hardware_config.to_path_buf()),
        no_hardware_config: false,
    }
}

/// Run a full init against a real volume at `root`, asserting success.
fn init_real(root: &Path, base_hardware_config: &Path) {
    let status = run(
        &OutputSettings::default(),
        &RealFilesystem,
        &real_init_args(root, base_hardware_config),
    );
    assert_eq!(status, ExitStatus::Ok);
}

/// A mock whose `root` reads as a mounted, writable, symlink-capable directory.
fn attached_mock(root: &Path) -> MockFilesystem {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists(root.to_str().unwrap(), true);
    fs.mock_set_path_type(root.to_str().unwrap(), PathKind::Dir);
    fs.mock_set_writable(root.to_str().unwrap(), true);
    fs.mock_set_supports_symlinks(root, true);
    // A volume mounted there; the default mock device id for an unmapped path
    // is distinct from `/`'s, so it is a filesystem of its own.
    fs.mock_set_mounted(root, true);
    fs
}

/// Make the mock host detect as NixOS (a host with a declarative config layer),
/// so the auto bootstrap path chooses the hidden NixOS layout.
fn mark_host_nixos(fs: &MockFilesystem) {
    fs.mock_set_file_content("/etc/os-release", "ID=nixos\nVERSION_ID=\"24.11\"\n");
    fs.mock_set_file_content("/proc/1/comm", "systemd\n");
}

/// Make the mock host detect as a supported FHS (Debian) host with no config
/// layer, so the auto bootstrap path skips the hidden NixOS layout.
fn mark_host_debian(fs: &MockFilesystem) {
    fs.mock_set_file_content(
        "/etc/os-release",
        "ID=debian\nID_LIKE=debian\nVERSION_ID=\"12\"\n",
    );
    fs.mock_set_file_content("/proc/1/comm", "systemd\n");
}

#[test]
fn test_init_nonexistent_path() {
    let args = InitArgs {
        path: PathBuf::from("/tmp/nails-test-nonexistent-path-xyz"),
        ..Default::default()
    };
    let status = execute(&OutputSettings::default(), &args, None);
    assert_ne!(status, ExitStatus::Ok);
}

#[test]
fn global_config_flag_is_rejected() {
    let args = InitArgs {
        path: PathBuf::from("/mnt/data"),
        ..Default::default()
    };
    let status = execute(
        &OutputSettings::default(),
        &args,
        Some(Path::new("/tmp/other-config.toml")),
    );
    assert_eq!(status, ExitStatus::Config);
}

#[test]
fn unmounted_target_refused_with_zero_writes() {
    let root = Path::new("/mnt/data");
    let fs = attached_mock(root);
    // Share a device with `/`, so nothing is mounted at the target.
    fs.mock_set_device_id(Path::new("/"), 7);
    fs.mock_set_device_id(root, 7);

    let args = InitArgs {
        path: root.to_path_buf(),
        allow_decoy_storage: false,
        hardware_config: None,
        no_hardware_config: true,
    };

    let status = run(&OutputSettings::default(), &fs, &args);
    assert_eq!(status, ExitStatus::PreflightRefused);
    assert!(probes(&fs).is_empty(), "{:?}", fs.mock_ops());

    for rel in COMMON_SUBDIRS.iter().chain(NIXOS_SUBDIRS) {
        assert!(
            !fs.path_exists(&root.join(rel)).unwrap(),
            "{rel} must not be created when the target is refused"
        );
    }
    assert!(
        !fs.path_exists(&root.join("config").join(CONFIG_FILE_NAME))
            .unwrap()
    );
}

#[test]
fn obstructing_file_refused_before_any_write() {
    let root = Path::new("/mnt/data");
    let fs = attached_mock(root);
    // A file sits where the layout needs the config directory.
    fs.mock_set_path_exists("/mnt/data/config", true);
    fs.mock_set_path_type("/mnt/data/config", PathKind::File);

    let args = InitArgs {
        path: root.to_path_buf(),
        allow_decoy_storage: false,
        hardware_config: None,
        no_hardware_config: true,
    };

    match plan(&fs, &args) {
        Err(InitFailure::Preconditions(failures)) => assert!(
            failures
                .iter()
                .any(|reason| reason.contains("/mnt/data/config exists but is not a directory")),
            "{failures:?}"
        ),
        other => panic!("expected a precondition failure, got {:?}", other.is_ok()),
    }

    let status = run(&OutputSettings::default(), &fs, &args);
    assert_eq!(status, ExitStatus::PreflightRefused);
    assert!(
        !fs.path_exists(&root.join("logs")).unwrap(),
        "no directory may be created before the obstruction is reported"
    );
    assert_eq!(
        fs.mock_get_permissions(Path::new("/mnt/data/config")),
        None,
        "the obstructing file's permissions must be left alone"
    );
}

#[test]
fn directory_in_place_of_the_state_file_is_refused() {
    let root = Path::new("/mnt/data");
    let fs = attached_mock(root);
    fs.mock_set_path_exists("/mnt/data/state.json", true);
    fs.mock_set_path_type("/mnt/data/state.json", PathKind::Dir);

    let args = InitArgs {
        path: root.to_path_buf(),
        allow_decoy_storage: false,
        hardware_config: None,
        no_hardware_config: true,
    };

    match plan(&fs, &args) {
        Err(InitFailure::Preconditions(failures)) => assert!(
            failures
                .iter()
                .any(|reason| reason.contains("/mnt/data/state.json exists but is a directory")),
            "{failures:?}"
        ),
        other => panic!("expected a precondition failure, got {:?}", other.is_ok()),
    }
}

#[test]
fn same_device_target_reports_the_mount_reason() {
    let root = Path::new("/mnt/data");
    let fs = attached_mock(root);
    fs.mock_set_device_id(Path::new("/"), 7);
    fs.mock_set_device_id(root, 7);

    let args = InitArgs {
        path: root.to_path_buf(),
        allow_decoy_storage: false,
        hardware_config: None,
        no_hardware_config: true,
    };

    match plan(&fs, &args) {
        Err(InitFailure::NotSeparate(refusal)) => {
            assert_eq!(refusal.code(), "not_separate_volume");
            assert!(
                refusal.reason.contains("it is on the device that holds /"),
                "{refusal:?}"
            );
        }
        other => panic!("expected a refusal, got {:?}", other.is_ok()),
    }
}

/// A mock where `root` is a folder of the `/` filesystem: it exists, is a
/// writable directory, and nothing is mounted there.
fn folder_mock(root: &Path) -> MockFilesystem {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists(root.to_str().unwrap(), true);
    fs.mock_set_path_type(root.to_str().unwrap(), PathKind::Dir);
    fs.mock_set_writable(root.to_str().unwrap(), true);
    fs.mock_set_mount_table("1 0 8:1 / / rw - ext4 /dev/vda1 rw\n");
    fs
}

fn probes(fs: &MockFilesystem) -> Vec<nails_core::filesystem::MockOp> {
    fs.mock_ops()
        .into_iter()
        .filter(|op| {
            matches!(
                op,
                nails_core::filesystem::MockOp::WritableProbe { .. }
                    | nails_core::filesystem::MockOp::SymlinkProbe { .. }
            )
        })
        .collect()
}

#[test]
fn refused_target_is_never_probed() {
    let root = Path::new("/srv/x");
    let fs = folder_mock(root);
    for allow_decoy_storage in [false, true] {
        let args = InitArgs {
            path: root.to_path_buf(),
            allow_decoy_storage,
            hardware_config: None,
            no_hardware_config: true,
        };
        // A folder is no volume of its own, whatever the operator says.
        let status = run(&OutputSettings::default(), &fs, &args);
        assert_eq!(
            status,
            ExitStatus::PreflightRefused,
            "{allow_decoy_storage}"
        );
        assert!(fs.mock_ops().is_empty(), "{:?}", fs.mock_ops());
    }
}

/// A mock where `root` is a bind of a folder of the decoy's `/srv`: a mount
/// point, on storage the decoy uses.
fn bind_mock(root: &Path) -> MockFilesystem {
    let fs = folder_mock(root);
    fs.mock_set_supports_symlinks(root, true);
    fs.mock_set_mount_table(&format!(
        "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
         2 1 8:2 / /srv rw - ext4 /dev/vda2 rw\n\
         3 1 8:2 /x {} rw - ext4 /dev/vda2 rw\n",
        root.display()
    ));
    fs
}

#[test]
fn allow_decoy_storage_proceeds_on_decoy_storage_with_a_warning() {
    let root = Path::new("/mnt/data");
    let fs = bind_mock(root);
    let args = InitArgs {
        path: root.to_path_buf(),
        allow_decoy_storage: false,
        hardware_config: None,
        no_hardware_config: true,
    };
    match plan(&fs, &args) {
        Err(InitFailure::NotSeparate(refusal)) => {
            assert_eq!(refusal.code(), "not_separate_volume");
        }
        other => panic!("expected a refusal, got {:?}", other.is_ok()),
    }
    assert!(probes(&fs).is_empty());

    // The same target passes the gate once overridden, and only then is probed.
    let plan = plan(
        &fs,
        &InitArgs {
            allow_decoy_storage: true,
            ..args
        },
    )
    .expect("--allow-decoy-storage should pass validation");
    assert_eq!(
        plan.warnings,
        vec![
            "--allow-decoy-storage: using /mnt/data although it is a bind mount of a folder of \
             /srv; everything written there lands on that storage"
                .to_string()
        ]
    );
    assert_eq!(probes(&fs).len(), 2, "{:?}", fs.mock_ops());
}

#[test]
fn allow_decoy_storage_never_covers_a_covered_root_or_unjudged_storage() {
    let args = |root: &Path| InitArgs {
        path: root.to_path_buf(),
        allow_decoy_storage: true,
        hardware_config: None,
        no_hardware_config: true,
    };

    let root = Path::new("/mnt/data");
    let covered = attached_mock(root);
    covered.mock_set_mount_table(
        "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
         10 1 253:0 / /mnt/data rw - ext4 /dev/mapper/data rw\n\
         11 10 8:17 / /mnt/data rw - ext4 /dev/sdb1 rw\n",
    );
    match plan(&covered, &args(root)) {
        Err(InitFailure::NotSeparate(refusal)) => assert_eq!(refusal.code(), "root_covered"),
        other => panic!("expected a refusal, got {:?}", other.is_ok()),
    }
    assert!(probes(&covered).is_empty());

    let unjudged = attached_mock(root);
    unjudged.mock_set_mount_table(
        "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
         10 1 8:17 / /mnt/data rw - ext4 /dev/sdb1 rw\n",
    );
    // A crypttab that exists but cannot be read.
    unjudged.mock_set_path_exists("/etc/crypttab", true);
    match plan(&unjudged, &args(root)) {
        Err(InitFailure::NotSeparate(refusal)) => assert_eq!(refusal.code(), "storage_unjudged"),
        other => panic!("expected a refusal, got {:?}", other.is_ok()),
    }
    assert!(probes(&unjudged).is_empty());
}

#[test]
fn missing_hardware_config_fails_before_any_write() {
    let root = Path::new("/mnt/data");
    let fs = attached_mock(root);
    // A NixOS host, but the default base hardware config is absent.
    mark_host_nixos(&fs);

    let args = InitArgs {
        path: root.to_path_buf(),
        allow_decoy_storage: false,
        hardware_config: None,
        no_hardware_config: false,
    };

    match plan(&fs, &args) {
        Err(InitFailure::Preconditions(failures)) => assert!(
            failures
                .iter()
                .any(|reason| reason.contains("hardware configuration")),
            "{failures:?}"
        ),
        other => panic!("expected a precondition failure, got {:?}", other.is_ok()),
    }
}

#[test]
fn non_nixos_host_skips_the_layout() {
    let root = Path::new("/mnt/data");
    let fs = attached_mock(root);
    // A supported FHS host (Debian) with no config layer: overlay-only.
    mark_host_debian(&fs);

    let args = InitArgs {
        path: root.to_path_buf(),
        allow_decoy_storage: false,
        hardware_config: None,
        no_hardware_config: false,
    };

    let plan = plan(&fs, &args).expect("a supported FHS host should still pass");
    match plan.bootstrap {
        HardwareBootstrap::Skip(reason) => {
            assert!(reason.contains("no NixOS config layer"), "{reason}")
        }
        HardwareBootstrap::From(path) => panic!("expected a skip, got From({})", path.display()),
    }
}

#[test]
fn debian_host_init_creates_no_nixos_paths() {
    // The root is a real temp dir (so the state file and its lock can be written
    // through the core's own atomic path), while the mock backs the layout writes
    // and the host detection, letting us drive a Debian host without a real one.
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let fs = attached_mock(root);
    mark_host_debian(&fs);

    let args = InitArgs {
        path: root.to_path_buf(),
        allow_decoy_storage: false,
        hardware_config: None,
        no_hardware_config: false,
    };

    let report = apply(
        &fs,
        root,
        plan(&fs, &args).expect("a Debian host should plan"),
    )
    .unwrap();

    // The skip is reported as information, naming the overlay-only decision.
    assert!(
        report
            .notes
            .iter()
            .any(|note| note.contains("no NixOS config layer")),
        "{:?}",
        report.notes
    );

    // The platform-agnostic layout is present...
    for rel in COMMON_SUBDIRS {
        assert!(
            fs.path_exists(&root.join(rel)).unwrap(),
            "{rel} should be created on a Debian host"
        );
    }
    // ...but no NixOS paths are ever written.
    for rel in NIXOS_SUBDIRS {
        assert!(
            !fs.path_exists(&root.join(rel)).unwrap(),
            "{rel} must not be created on a Debian host"
        );
    }
    assert!(
        fs.mock_get_symlink_target(&root.join("root/upper/etc/nixos/nails/configuration.nix"))
            .is_none(),
        "the hidden NixOS symlink must not be staged on a Debian host"
    );
    assert!(
        fs.get_written_content(&root.join("config/nixos/configuration.nix"))
            .is_none(),
        "the hidden NixOS module must not be written on a Debian host"
    );
}

#[test]
fn unsupported_host_is_refused_before_any_write() {
    let root = Path::new("/mnt/data");
    let fs = attached_mock(root);
    // A non-systemd PID 1: an unsupported host the platform seam refuses.
    fs.mock_set_file_content("/etc/os-release", "ID=debian\nVERSION_ID=\"12\"\n");
    fs.mock_set_file_content("/proc/1/comm", "openrc-init\n");

    let args = InitArgs {
        path: root.to_path_buf(),
        allow_decoy_storage: false,
        hardware_config: None,
        no_hardware_config: false,
    };

    match plan(&fs, &args) {
        Err(InitFailure::Preconditions(failures)) => assert!(
            failures.iter().any(|reason| reason.contains("systemd")),
            "{failures:?}"
        ),
        other => panic!(
            "expected an unsupported-host refusal, got {:?}",
            other.is_ok()
        ),
    }

    // Nothing was written during planning.
    for rel in COMMON_SUBDIRS.iter().chain(NIXOS_SUBDIRS) {
        assert!(
            !fs.path_exists(&root.join(rel)).unwrap(),
            "{rel} must not be created when the host is refused"
        );
    }
}

#[test]
fn full_validation_passes_on_a_mock_nixos_volume() {
    let root = Path::new("/mnt/data");
    let fs = attached_mock(root);
    mark_host_nixos(&fs);
    fs.mock_set_path_exists(DEFAULT_HARDWARE_CONFIG, true);
    fs.mock_set_readable(DEFAULT_HARDWARE_CONFIG, true);

    let args = InitArgs {
        path: root.to_path_buf(),
        allow_decoy_storage: false,
        hardware_config: None,
        no_hardware_config: false,
    };

    let plan = plan(&fs, &args).expect("a mounted NixOS volume should validate");
    assert!(plan.warnings.is_empty());
    assert!(matches!(plan.bootstrap, HardwareBootstrap::From(_)));
}

#[test]
fn json_report_lists_each_item_and_its_status() {
    let report = InitReport {
        root: "/mnt/data".to_string(),
        items: vec![
            InitItem {
                path: "/mnt/data/logs".to_string(),
                status: ItemStatus::Created,
            },
            InitItem {
                path: "/mnt/data/config/nails.toml".to_string(),
                status: ItemStatus::AlreadyPresent,
            },
        ],
        warnings: Vec::new(),
        notes: vec!["host is not NixOS".to_string()],
        next_steps: vec!["activate".to_string()],
    };

    let line = Envelope::success("init", &report).to_line();
    let value: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(value["command"], "init");
    assert_eq!(value["ok"], true);
    assert_eq!(value["data"]["root"], "/mnt/data");
    assert_eq!(value["data"]["items"][0]["path"], "/mnt/data/logs");
    assert_eq!(value["data"]["items"][0]["status"], "created");
    assert_eq!(value["data"]["items"][1]["status"], "already_present");
    assert_eq!(value["data"]["notes"][0], "host is not NixOS");
    assert_eq!(value["data"]["next_steps"][0], "activate");
    assert!(
        value["data"].get("warnings").is_none(),
        "an empty warning list is omitted: {line}"
    );
}

/// The cases that run init against a real directory. The attach gate accepts
/// only a mounted volume, so each runs in an unprivileged user + mount
/// namespace with a tmpfs as the root.
mod kernel_tests {
    use super::*;
    use nails_core::test_path;
    use nails_core::test_support::{Rerun, ScratchTmpfs};

    /// Run `body` with a fresh tmpfs volume as its root, in a namespace.
    fn on_a_volume(test: &str, body: impl FnOnce(&Path)) {
        let _ = Rerun::new(test).in_user_mount_ns().run(|| {
            let volume = ScratchTmpfs::new("");
            body(volume.path());
        });
    }

    #[test]
    fn test_init_creates_directory_structure() {
        on_a_volume(test_path!(test_init_creates_directory_structure), |root| {
            let base_hardware_config = write_test_base_hardware_config(root);

            init_real(root, &base_hardware_config);

            for dir_name in COMMON_SUBDIRS.iter().chain(NIXOS_SUBDIRS) {
                let dir = root.join(dir_name);
                assert!(dir.is_dir(), "{} should exist", dir.display());
                let meta = fs::metadata(&dir).unwrap();
                assert_eq!(meta.permissions().mode() & 0o777, 0o700);
            }
            assert!(!root.join("state").exists());
            assert!(
                !root.join("overlays").exists(),
                "the unused overlays/ directory must not be created"
            );

            let state_file = root.join("state.json");
            assert!(state_file.is_file());
            let state_meta = fs::metadata(&state_file).unwrap();
            assert_eq!(state_meta.permissions().mode() & 0o777, 0o600);
            let state = nails_core::StateFile::load(&state_file).unwrap();
            assert!(matches!(state.state, SystemState::Inactive));

            let config_file = root.join("config").join(CONFIG_FILE_NAME);
            assert!(config_file.is_file());
            let meta = fs::metadata(&config_file).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);

            let contents = fs::read_to_string(&config_file).unwrap();
            assert!(contents.contains("generated by `nails init`"));
            assert!(contents.contains(&format!("# hidden_volume_root = \"{}\"", root.display())));
            assert!(
                !contents
                    .lines()
                    .any(|line| line.starts_with("hidden_volume_root")),
                "the root must stay commented out so it is derived from the binary"
            );
            assert!(contents.contains("# minimum_space_mb = 500"));
            assert!(contents.contains("# nixos_flake = "));
            assert_eq!(contents, Config::init_template(root));

            let loaded = Config::load(&config_file).unwrap();
            assert_eq!(
                loaded.hidden_volume_root,
                nails_core::config::derive_hidden_volume_root()
            );

            let hidden_config = root.join("config/nixos/configuration.nix");
            assert!(hidden_config.is_file());
            let hidden_config_meta = fs::metadata(&hidden_config).unwrap();
            assert_eq!(hidden_config_meta.permissions().mode() & 0o777, 0o600);
            let hidden_config_contents = fs::read_to_string(&hidden_config).unwrap();
            assert!(hidden_config_contents.contains("Hidden-session configuration"));

            let hidden_hardware = root.join("root/upper/etc/nixos/hardware-configuration.nix");
            assert!(hidden_hardware.is_file());
            let hidden_hardware_meta = fs::metadata(&hidden_hardware).unwrap();
            assert_eq!(hidden_hardware_meta.permissions().mode() & 0o777, 0o600);
            let hidden_hardware_contents = fs::read_to_string(&hidden_hardware).unwrap();
            // hardware-configuration.nix is the fixed wrapper importing the preserved
            // base and the hidden module.
            assert!(hidden_hardware_contents.contains("./nails/configuration.nix"));
            assert!(hidden_hardware_contents.contains("./hardware-configuration.base.nix"));

            let hidden_base = root.join("root/upper/etc/nixos/hardware-configuration.base.nix");
            assert!(hidden_base.is_file());
            let hidden_base_meta = fs::metadata(&hidden_base).unwrap();
            assert_eq!(hidden_base_meta.permissions().mode() & 0o777, 0o600);
            let hidden_base_contents = fs::read_to_string(&hidden_base).unwrap();
            assert!(
                hidden_base_contents.contains("modulesPath + \"/installer/scan/not-detected.nix\"")
            );

            let staged_dir = root.join("root/upper/etc/nixos/nails");
            let staged_dir_meta = fs::metadata(&staged_dir).unwrap();
            assert_eq!(staged_dir_meta.permissions().mode() & 0o777, 0o700);

            let staged_symlink = root.join("root/upper/etc/nixos/nails/configuration.nix");
            assert!(staged_symlink.is_symlink());
            assert_eq!(fs::read_link(&staged_symlink).unwrap(), hidden_config);
        });
    }

    #[test]
    fn test_init_idempotent() {
        on_a_volume(test_path!(test_init_idempotent), |root| {
            let base_hardware_config = write_test_base_hardware_config(root);
            init_real(root, &base_hardware_config);
            init_real(root, &base_hardware_config);
        });
    }

    #[test]
    fn rerun_reports_already_present_and_creates_nothing() {
        on_a_volume(
            test_path!(rerun_reports_already_present_and_creates_nothing),
            |root| {
                let base_hardware_config = write_test_base_hardware_config(root);
                let args = real_init_args(root, &base_hardware_config);
                let fs = RealFilesystem;

                let first = apply(&fs, root, plan(&fs, &args).unwrap()).unwrap();
                assert!(
                    first
                        .items
                        .iter()
                        .any(|item| item.status == ItemStatus::Created),
                    "the first run must create something"
                );

                let second = apply(&fs, root, plan(&fs, &args).unwrap()).unwrap();
                assert!(
                    second
                        .items
                        .iter()
                        .all(|item| item.status == ItemStatus::AlreadyPresent),
                    "a re-run must report everything already present: {:?}",
                    second.items
                );
                assert!(!root.join("overlays").exists());
            },
        );
    }

    #[test]
    fn a_refused_real_directory_keeps_its_timestamps_and_stays_empty() {
        on_a_volume(
            test_path!(a_refused_real_directory_keeps_its_timestamps_and_stays_empty),
            |volume| {
                use std::os::unix::fs::MetadataExt;
                // A folder on the volume is no mount point, so the gate
                // refuses it, with the override too.
                let folder = volume.join("x");
                fs::create_dir(&folder).unwrap();
                let past = std::time::SystemTime::UNIX_EPOCH
                    + std::time::Duration::from_secs(1_000_000_000);
                fs::File::open(&folder)
                    .unwrap()
                    .set_times(fs::FileTimes::new().set_modified(past))
                    .unwrap();
                let before = fs::metadata(&folder).unwrap();

                for allow_decoy_storage in [false, true] {
                    let args = InitArgs {
                        path: folder.clone(),
                        allow_decoy_storage,
                        hardware_config: None,
                        no_hardware_config: true,
                    };
                    let status = run(&OutputSettings::default(), &RealFilesystem, &args);
                    assert_eq!(
                        status,
                        ExitStatus::PreflightRefused,
                        "{allow_decoy_storage}"
                    );
                }

                let after = fs::metadata(&folder).unwrap();
                assert_eq!(
                    (after.mtime(), after.mtime_nsec()),
                    (before.mtime(), before.mtime_nsec())
                );
                assert_eq!(
                    (after.ctime(), after.ctime_nsec()),
                    (before.ctime(), before.ctime_nsec())
                );
                assert_eq!(fs::read_dir(&folder).unwrap().count(), 0);
            },
        );
    }

    #[test]
    fn no_hardware_config_skips_bootstrap_on_a_real_volume() {
        on_a_volume(
            test_path!(no_hardware_config_skips_bootstrap_on_a_real_volume),
            |root| {
                let args = InitArgs {
                    path: root.to_path_buf(),
                    allow_decoy_storage: false,
                    hardware_config: None,
                    no_hardware_config: true,
                };
                let fs = RealFilesystem;

                let report = apply(&fs, root, plan(&fs, &args).unwrap()).unwrap();

                // Skipping the layout on request is information, not a warning.
                assert!(
                    report
                        .notes
                        .iter()
                        .any(|note| note.contains("--no-hardware-config")),
                    "{:?}",
                    report.notes
                );
                assert!(
                    !report
                        .warnings
                        .iter()
                        .any(|warning| warning.contains("--no-hardware-config")),
                    "{:?}",
                    report.warnings
                );
                assert!(root.join("logs").is_dir());
                assert!(root.join("config").join(CONFIG_FILE_NAME).is_file());
                assert!(root.join("state.json").is_file());
                assert!(
                    !root
                        .join("root/upper/etc/nixos/hardware-configuration.nix")
                        .exists()
                );
                assert!(!root.join("config/nixos/configuration.nix").exists());
                assert!(!root.join("root/upper/etc/nixos/nails").exists());
            },
        );
    }

    #[test]
    fn human_output_ends_with_the_numbered_next_steps() {
        on_a_volume(
            test_path!(human_output_ends_with_the_numbered_next_steps),
            |root| {
                let args = InitArgs {
                    path: root.to_path_buf(),
                    allow_decoy_storage: false,
                    hardware_config: None,
                    no_hardware_config: true,
                };
                let fs = RealFilesystem;
                let report = apply(&fs, root, plan(&fs, &args).unwrap()).unwrap();

                let text = render_text(&report);
                let lines: Vec<&str> = text.lines().collect();

                let header = lines
                    .iter()
                    .position(|line| *line == "Next steps:")
                    .unwrap_or_else(|| panic!("no next steps header: {text}"));
                let steps = &lines[header + 1..];
                assert_eq!(steps.len(), 4, "{text}");
                for (index, step) in steps.iter().enumerate() {
                    assert!(step.starts_with(&format!("  {}. ", index + 1)), "{text}");
                }
                let root = root.display().to_string();
                assert!(steps[0].contains(&format!("{root}/nails")), "{text}");
                assert!(
                    steps[3].contains(&format!("sudo {root}/nails activate")),
                    "{text}"
                );

                assert!(text.contains("  created: "), "{text}");
                assert!(text.contains("info: --no-hardware-config"), "{text}");
                // Errors and statuses are rendered with Display, never Debug.
                assert!(!text.contains("NixOSError("), "{text}");
                assert!(!text.contains("AlreadyPresent"), "{text}");
            },
        );
    }
}
