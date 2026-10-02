use super::*;
use nails_core::filesystem::PathKind;
use nails_core::test_support::EnvGuard;
use nails_core::{
    Config, Filesystem, MockFilesystem, NailsManager, StateFile, SystemState,
    stage_hidden_config_symlink,
};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// Opt the calling test into test-runtime mode until the guard is dropped.
///
/// `nails-core` is linked here as a plain dependency, so its `cfg(test)` is not
/// active and the runtime-safety skip is keyed solely on `NAILS_TEST_RUNTIME`.
/// Tests that drive a real activation (and therefore the host preflight checks)
/// set it so those checks are bypassed, exactly as the E2E harness does. It is
/// scoped to the test rather than set once for the binary, so no other test's
/// behaviour depends on whether an init test happened to run before it.
fn test_runtime_env() -> EnvGuard {
    let mut env = EnvGuard::lock();
    env.set("NAILS_TEST_RUNTIME", "1");
    env
}

fn write_test_base_hardware_config(tmp: &TempDir) -> PathBuf {
    let path = tmp
        .path()
        .join("decoy/etc/nixos/hardware-configuration.nix");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(
        &path,
        "{ config, lib, pkgs, modulesPath, ... }:\n{\n  imports = [ (modulesPath + \"/installer/scan/not-detected.nix\") ];\n}\n",
    )
    .unwrap();
    path
}

/// Arguments that initialise a real temp directory: the target is not a separate
/// mount (a `TempDir` shares `/`'s device), so `--allow-unmounted` is required,
/// and the base hardware config is pinned so the run never consults the host.
fn real_init_args(path: &Path, base_hardware_config: &Path) -> InitArgs {
    InitArgs {
        path: path.to_path_buf(),
        allow_unmounted: true,
        hardware_config: Some(base_hardware_config.to_path_buf()),
        no_hardware_config: false,
    }
}

/// Run a full init against a real temp directory, asserting success.
fn init_real(tmp: &TempDir, base_hardware_config: &Path) {
    let status = run(
        &OutputSettings::default(),
        &RealFilesystem,
        &real_init_args(tmp.path(), base_hardware_config),
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
    // The default mock device id for an unmapped path is distinct from `/`'s, so
    // `root` already reads as a mounted volume of its own.
    fs
}

/// Load the config `nails init` generated under `root`.
///
/// The template leaves `hidden_volume_root` unset so it is derived from the
/// binary location. A test binary does not live on the volume, so pin the
/// root (and the paths derived from it) to `root` as the installed binary would.
fn load_generated_config(root: &Path) -> Config {
    let generated = Config::load(&root.join("config").join(CONFIG_FILE_NAME)).unwrap();
    Config {
        hidden_volume_root: root.to_path_buf(),
        state_file_path: root.join("state.json"),
        log_path: root.join("logs"),
        ..generated
    }
}

fn mock_init_layout(fs: &MockFilesystem, hidden_root: &Path) {
    fs.mock_set_path_exists(hidden_root.to_str().unwrap(), true);
    fs.mock_set_path_type(hidden_root.to_str().unwrap(), PathKind::Dir);
    fs.mock_set_mounted(hidden_root, true);
    fs.mock_set_readable(hidden_root.to_str().unwrap(), true);
    fs.mock_set_writable(hidden_root.to_str().unwrap(), true);
    fs.mock_set_supports_symlinks(hidden_root, true);

    for rel in SUBDIRS {
        let path = hidden_root.join(rel);
        fs.mock_set_path_exists(path.to_str().unwrap(), true);
        fs.mock_set_path_type(path.to_str().unwrap(), PathKind::Dir);
        fs.mock_set_readable(path.to_str().unwrap(), true);
        fs.mock_set_writable(path.to_str().unwrap(), true);
    }
}

fn mock_minimal_activation_prereqs(fs: &MockFilesystem) {
    fs.mock_set_path_exists("/", true);
    fs.mock_set_path_type("/", PathKind::Dir);

    for dir in ["/etc", "/etc/nixos", "/home", "/nix", "/nix/store"] {
        fs.mock_set_path_exists(dir, true);
        fs.mock_set_path_type(dir, PathKind::Dir);
        fs.mock_set_readable(dir, true);
        fs.mock_set_writable(dir, true);
    }

    fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", PathKind::File);
    fs.mock_set_file_content(
        "/etc/nixos/hardware-configuration.nix",
        "{ config, lib, pkgs, ... }:\n{\n  imports = [ ];\n}\n",
    );

    fs.mock_set_path_exists("/etc/nixos/configuration.nix", true);
    fs.mock_set_path_type("/etc/nixos/configuration.nix", PathKind::File);
    fs.mock_set_file_content("/etc/nixos/configuration.nix", "{ }\n");

    fs.mock_set_root_directories(vec!["/etc".into(), "/home".into(), "/nix".into()]);
    fs.mock_set_swap_enabled(false);
}

#[test]
fn test_init_creates_directory_structure() {
    let tmp = TempDir::new().unwrap();
    let base_hardware_config = write_test_base_hardware_config(&tmp);

    init_real(&tmp, &base_hardware_config);

    for dir_name in SUBDIRS {
        let dir = tmp.path().join(dir_name);
        assert!(dir.is_dir(), "{} should exist", dir.display());
        let meta = fs::metadata(&dir).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o700);
    }
    assert!(!tmp.path().join("state").exists());
    assert!(
        !tmp.path().join("overlays").exists(),
        "the unused overlays/ directory must not be created"
    );

    let state_file = tmp.path().join("state.json");
    assert!(state_file.is_file());
    let state_meta = fs::metadata(&state_file).unwrap();
    assert_eq!(state_meta.permissions().mode() & 0o777, 0o600);
    let state = nails_core::StateFile::load(&state_file).unwrap();
    assert!(matches!(state.state, SystemState::Inactive));

    let config_file = tmp.path().join("config").join(CONFIG_FILE_NAME);
    assert!(config_file.is_file());
    let meta = fs::metadata(&config_file).unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);

    let contents = fs::read_to_string(&config_file).unwrap();
    assert!(contents.contains("generated by `nails init`"));
    assert!(contents.contains(&format!(
        "# hidden_volume_root = \"{}\"",
        tmp.path().display()
    )));
    assert!(
        !contents
            .lines()
            .any(|line| line.starts_with("hidden_volume_root")),
        "the root must stay commented out so it is derived from the binary"
    );
    assert!(contents.contains("# clear_history = true"));
    assert!(contents.contains("# minimum_space_mb = 500"));
    assert!(contents.contains("# nixos_flake = "));
    assert!(contents.contains("# [[overlays]]"));
    assert_eq!(contents, Config::init_template(tmp.path()));

    let loaded = Config::load(&config_file).unwrap();
    assert_eq!(
        loaded.hidden_volume_root,
        nails_core::config::derive_hidden_volume_root()
    );
    assert_eq!(loaded.overlay_mode, nails_core::OverlayMode::Auto);

    let hidden_config = tmp.path().join("config/nixos/configuration.nix");
    assert!(hidden_config.is_file());
    let hidden_config_meta = fs::metadata(&hidden_config).unwrap();
    assert_eq!(hidden_config_meta.permissions().mode() & 0o777, 0o600);
    let hidden_config_contents = fs::read_to_string(&hidden_config).unwrap();
    assert!(hidden_config_contents.contains("pkgs.ripgrep"));

    let hidden_hardware = tmp.path().join("etc/nixos/hardware-configuration.nix");
    assert!(hidden_hardware.is_file());
    let hidden_hardware_meta = fs::metadata(&hidden_hardware).unwrap();
    assert_eq!(hidden_hardware_meta.permissions().mode() & 0o777, 0o600);
    let hidden_hardware_contents = fs::read_to_string(&hidden_hardware).unwrap();
    // hardware-configuration.nix is the fixed wrapper importing the preserved
    // base and the hidden module.
    assert!(hidden_hardware_contents.contains("./nails/configuration.nix"));
    assert!(hidden_hardware_contents.contains("./hardware-configuration.base.nix"));

    let hidden_base = tmp.path().join("etc/nixos/hardware-configuration.base.nix");
    assert!(hidden_base.is_file());
    let hidden_base_meta = fs::metadata(&hidden_base).unwrap();
    assert_eq!(hidden_base_meta.permissions().mode() & 0o777, 0o600);
    let hidden_base_contents = fs::read_to_string(&hidden_base).unwrap();
    assert!(hidden_base_contents.contains("modulesPath + \"/installer/scan/not-detected.nix\""));

    let staged_dir = tmp.path().join("etc/nixos/nails");
    let staged_dir_meta = fs::metadata(&staged_dir).unwrap();
    assert_eq!(staged_dir_meta.permissions().mode() & 0o777, 0o700);

    let staged_symlink = tmp.path().join("etc/nixos/nails/configuration.nix");
    assert!(staged_symlink.is_symlink());
    assert_eq!(fs::read_link(&staged_symlink).unwrap(), hidden_config);
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
fn test_init_idempotent() {
    let tmp = TempDir::new().unwrap();
    let base_hardware_config = write_test_base_hardware_config(&tmp);
    init_real(&tmp, &base_hardware_config);
    init_real(&tmp, &base_hardware_config);
}

#[test]
fn rerun_reports_already_present_and_creates_nothing() {
    let tmp = TempDir::new().unwrap();
    let base_hardware_config = write_test_base_hardware_config(&tmp);
    let args = real_init_args(tmp.path(), &base_hardware_config);
    let fs = RealFilesystem;

    let first = apply(&fs, tmp.path(), plan(&fs, &args).unwrap()).unwrap();
    assert!(
        first
            .items
            .iter()
            .any(|item| item.status == ItemStatus::Created),
        "the first run must create something"
    );

    let second = apply(&fs, tmp.path(), plan(&fs, &args).unwrap()).unwrap();
    assert!(
        second
            .items
            .iter()
            .all(|item| item.status == ItemStatus::AlreadyPresent),
        "a re-run must report everything already present: {:?}",
        second.items
    );
    assert!(!tmp.path().join("overlays").exists());
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
        allow_unmounted: false,
        hardware_config: None,
        no_hardware_config: true,
    };

    let status = run(&OutputSettings::default(), &fs, &args);
    assert_eq!(status, ExitStatus::PreflightRefused);

    for rel in SUBDIRS {
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
fn same_device_target_reports_the_mount_reason() {
    let root = Path::new("/mnt/data");
    let fs = attached_mock(root);
    fs.mock_set_device_id(Path::new("/"), 7);
    fs.mock_set_device_id(root, 7);

    let args = InitArgs {
        path: root.to_path_buf(),
        allow_unmounted: false,
        hardware_config: None,
        no_hardware_config: true,
    };

    match plan(&fs, &args) {
        Err(InitFailure::Preconditions(failures)) => assert!(
            failures
                .iter()
                .any(|reason| reason.contains("shares a device with /")),
            "{failures:?}"
        ),
        other => panic!("expected a precondition failure, got {:?}", other.is_ok()),
    }
}

#[test]
fn allow_unmounted_proceeds_with_a_warning() {
    let root = Path::new("/mnt/data");
    let fs = attached_mock(root);
    fs.mock_set_device_id(Path::new("/"), 7);
    fs.mock_set_device_id(root, 7);

    let args = InitArgs {
        path: root.to_path_buf(),
        allow_unmounted: true,
        hardware_config: None,
        no_hardware_config: true,
    };

    let plan = plan(&fs, &args).expect("--allow-unmounted should pass validation");
    assert!(
        plan.warnings
            .iter()
            .any(|warning| warning.contains("--allow-unmounted")),
        "{:?}",
        plan.warnings
    );
}

#[test]
fn missing_hardware_config_fails_before_any_write() {
    let root = Path::new("/mnt/data");
    let fs = attached_mock(root);
    // A NixOS host, but the default base hardware config is absent.
    fs.mock_set_path_exists("/etc/NIXOS", true);

    let args = InitArgs {
        path: root.to_path_buf(),
        allow_unmounted: false,
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
    // No /etc/NIXOS marker: not a NixOS host.

    let args = InitArgs {
        path: root.to_path_buf(),
        allow_unmounted: false,
        hardware_config: None,
        no_hardware_config: false,
    };

    let plan = plan(&fs, &args).expect("non-NixOS host should still pass");
    match plan.bootstrap {
        HardwareBootstrap::Skip(reason) => assert!(reason.contains("not NixOS"), "{reason}"),
        HardwareBootstrap::From(path) => panic!("expected a skip, got From({})", path.display()),
    }
}

#[test]
fn no_hardware_config_skips_bootstrap_on_a_real_volume() {
    let tmp = TempDir::new().unwrap();
    let args = InitArgs {
        path: tmp.path().to_path_buf(),
        allow_unmounted: true,
        hardware_config: None,
        no_hardware_config: true,
    };
    let fs = RealFilesystem;

    let report = apply(&fs, tmp.path(), plan(&fs, &args).unwrap()).unwrap();

    assert!(
        report
            .warnings
            .iter()
            .any(|warning| warning.contains("--no-hardware-config")),
        "{:?}",
        report.warnings
    );
    assert!(tmp.path().join("logs").is_dir());
    assert!(tmp.path().join("config").join(CONFIG_FILE_NAME).is_file());
    assert!(tmp.path().join("state.json").is_file());
    assert!(
        !tmp.path()
            .join("etc/nixos/hardware-configuration.nix")
            .exists()
    );
    assert!(!tmp.path().join("config/nixos/configuration.nix").exists());
    assert!(!tmp.path().join("etc/nixos/nails").exists());
}

#[test]
fn full_validation_passes_on_a_mock_nixos_volume() {
    let root = Path::new("/mnt/data");
    let fs = attached_mock(root);
    fs.mock_set_path_exists("/etc/NIXOS", true);
    fs.mock_set_path_exists(DEFAULT_HARDWARE_CONFIG, true);
    fs.mock_set_readable(DEFAULT_HARDWARE_CONFIG, true);

    let args = InitArgs {
        path: root.to_path_buf(),
        allow_unmounted: false,
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
    assert_eq!(value["data"]["next_steps"][0], "activate");
}

#[test]
fn test_init_generated_config_is_preflight_ready_for_activation() {
    let _env = test_runtime_env();
    let tmp = TempDir::new().unwrap();
    let base_hardware_config = write_test_base_hardware_config(&tmp);
    init_real(&tmp, &base_hardware_config);

    let config = load_generated_config(tmp.path());

    let fs = MockFilesystem::new();
    let hidden_root = config.hidden_volume_root.clone();

    fs.mock_set_path_exists(hidden_root.to_str().unwrap(), true);
    fs.mock_set_mounted(&hidden_root, true);
    fs.mock_set_writable(hidden_root.to_str().unwrap(), true);

    for rel in [
        "config",
        "config/nixos",
        "etc",
        "etc/nixos",
        "home",
        "nix",
        ".work",
        ".work/etc",
        ".work/home",
        ".work/nix",
    ] {
        let path = hidden_root.join(rel);
        fs.mock_set_path_exists(path.to_str().unwrap(), true);
        fs.mock_set_path_type(path.to_str().unwrap(), PathKind::Dir);
        fs.mock_set_writable(path.to_str().unwrap(), true);
        fs.mock_set_readable(path.to_str().unwrap(), true);
    }

    fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", PathKind::File);
    fs.mock_set_file_content(
        "/etc/nixos/hardware-configuration.nix",
        "{ config, lib, pkgs, ... }:\n{ }",
    );
    fs.mock_set_path_exists("/etc/nixos/configuration.nix", true);
    fs.mock_set_path_type("/etc/nixos/configuration.nix", PathKind::File);
    for lower in ["/etc", "/home", "/nix"] {
        fs.mock_set_path_exists(lower, true);
        fs.mock_set_path_type(lower, PathKind::Dir);
        fs.mock_set_readable(lower, true);
    }
    fs.mock_set_root_directories(vec!["/etc".into(), "/home".into(), "/nix".into()]);
    fs.mock_set_swap_enabled(false);

    stage_hidden_config_symlink(&fs, &hidden_root).unwrap();

    let manager = NailsManager::new(fs.clone(), config.clone(), config.state_file_path.clone());
    manager.run_preflight_checks(false).unwrap();

    let work_nix = hidden_root.join(".work/nix");
    assert_eq!(fs.mock_get_permissions(&work_nix), Some(0o700));

    let symlink_path = hidden_root.join("etc/nixos/nails/configuration.nix");
    assert_eq!(
        fs.mock_get_symlink_target(&symlink_path),
        Some(hidden_root.join("config/nixos/configuration.nix"))
    );
    assert!(
        fs.path_exists(&hidden_root.join("config/nixos/configuration.nix"))
            .unwrap()
    );
}

#[test]
fn test_init_generated_config_activates_with_minimal_mock_filesystem_setup() {
    let _env = test_runtime_env();
    let tmp = TempDir::new().unwrap();
    let base_hardware_config = write_test_base_hardware_config(&tmp);
    init_real(&tmp, &base_hardware_config);

    let config = load_generated_config(tmp.path());

    let fs = MockFilesystem::new();
    let hidden_root = config.hidden_volume_root.clone();

    mock_init_layout(&fs, &hidden_root);
    mock_minimal_activation_prereqs(&fs);

    let mut manager = NailsManager::new(fs.clone(), config.clone(), config.state_file_path.clone());

    manager.activate(false).unwrap();

    let state = manager.current_state().unwrap();
    match state {
        SystemState::Active { overlays, .. } => {
            assert_eq!(
                overlays,
                vec![
                    Path::new("/etc").to_path_buf(),
                    Path::new("/home").to_path_buf(),
                    Path::new("/nix").to_path_buf(),
                ]
            );
        }
        other => panic!("expected active state after init+activate, got {other:?}"),
    }

    for target in ["/etc", "/home", "/nix"] {
        assert!(
            fs.is_mounted(Path::new(target)).unwrap(),
            "{target} should be mounted"
        );
    }

    let hidden_config = hidden_root.join("config/nixos/configuration.nix");
    assert!(fs.path_exists(&hidden_config).unwrap());
    assert!(
        !fs.read_file_content(&hidden_config)
            .unwrap()
            .trim()
            .is_empty()
    );

    let hidden_hardware = hidden_root.join("etc/nixos/hardware-configuration.nix");
    assert!(fs.path_exists(&hidden_hardware).unwrap());
    assert!(
        fs.read_file_content(&hidden_hardware)
            .unwrap()
            .contains("./nails/configuration.nix")
    );

    let staged_symlink = hidden_root.join("etc/nixos/nails/configuration.nix");
    assert_eq!(
        fs.mock_get_symlink_target(&staged_symlink),
        Some(hidden_root.join("config/nixos/configuration.nix"))
    );

    let overlayed_hardware = fs
        .get_written_content(Path::new("/etc/nixos/hardware-configuration.nix"))
        .expect("activation should inject import into overlayed hardware config");
    assert!(overlayed_hardware.contains("./nails/configuration.nix"));

    for rel in [".work/etc", ".work/home", ".work/nix"] {
        assert_eq!(fs.mock_get_permissions(&hidden_root.join(rel)), Some(0o700));
    }

    let persisted = StateFile::load(&config.state_file_path).unwrap();
    assert!(matches!(persisted.state, SystemState::Active { .. }));
    assert_eq!(persisted.overlay_status.len(), 3);
    for target in ["/etc", "/home", "/nix"] {
        assert!(
            persisted
                .overlay_status
                .contains_key(&Path::new(target).to_path_buf())
        );
    }
}
