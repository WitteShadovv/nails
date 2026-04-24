use nails_core::{
    RealFilesystem, ensure_hidden_configuration_module, ensure_hidden_hardware_configuration,
    prepare_nixos_config_overlay, stage_hidden_config_symlink,
};
use std::os::unix::fs::PermissionsExt;

#[test]
fn prepare_nixos_config_overlay_real_filesystem_accepts_valid_staged_layout() {
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path();
    let etc_nixos = hidden_root.join("etc/nixos");
    let hardware = etc_nixos.join("hardware-configuration.nix");
    let hidden_config = hidden_root.join("config/nixos/configuration.nix");

    std::fs::create_dir_all(hidden_config.parent().unwrap()).unwrap();
    std::fs::create_dir_all(&etc_nixos).unwrap();
    std::fs::write(
        &hardware,
        "{ ... }: { imports = [ ./nails/configuration.nix ./base.nix ]; }",
    )
    .unwrap();
    std::fs::write(
        &hidden_config,
        "{ pkgs, ... }: { environment.systemPackages = [ pkgs.jq ]; }",
    )
    .unwrap();

    let info = prepare_nixos_config_overlay(&RealFilesystem, hidden_root).unwrap();
    assert_eq!(info.hardware_config_path, hardware);
    assert_eq!(info.hidden_config_path, hidden_config);
    assert_eq!(info.etc_nixos_overlay, etc_nixos);
}

#[test]
fn ensure_hidden_configuration_module_real_filesystem_creates_secure_defaults() {
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path();

    ensure_hidden_configuration_module(&RealFilesystem, hidden_root).unwrap();

    let config_dir = hidden_root.join("config/nixos");
    let hidden_config = config_dir.join("configuration.nix");
    let content = std::fs::read_to_string(&hidden_config).unwrap();
    let dir_mode = std::fs::metadata(&config_dir).unwrap().permissions().mode() & 0o777;
    let file_mode = std::fs::metadata(&hidden_config)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;

    assert!(content.contains("pkgs.ripgrep"));
    assert_eq!(dir_mode, 0o700);
    assert_eq!(file_mode, 0o600);
}

#[test]
fn ensure_hidden_hardware_configuration_real_filesystem_injects_import_into_existing_imports() {
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden");
    let base_hardware = temp_dir.path().join("hardware-configuration.nix");

    std::fs::create_dir_all(hidden_root.join("etc/nixos")).unwrap();
    std::fs::write(
        &base_hardware,
        "{ ... }: {\n  imports = [\n    ./foo.nix\n  ];\n}\n",
    )
    .unwrap();

    ensure_hidden_hardware_configuration(&RealFilesystem, &hidden_root, &base_hardware).unwrap();

    let hidden_hardware = hidden_root.join("etc/nixos/hardware-configuration.nix");
    let content = std::fs::read_to_string(&hidden_hardware).unwrap();
    let dir_mode = std::fs::metadata(hidden_root.join("etc/nixos"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    let file_mode = std::fs::metadata(&hidden_hardware)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;

    assert!(
        content.contains("./nails/configuration.nix"),
        "content={content}"
    );
    assert!(content.contains("./foo.nix"), "content={content}");
    assert_eq!(dir_mode, 0o700);
    assert_eq!(file_mode, 0o600);
}

#[test]
fn stage_hidden_config_symlink_real_filesystem_is_idempotent() {
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path();
    std::fs::create_dir_all(hidden_root.join("etc/nixos")).unwrap();

    stage_hidden_config_symlink(&RealFilesystem, hidden_root).unwrap();
    stage_hidden_config_symlink(&RealFilesystem, hidden_root).unwrap();

    let symlink_path = hidden_root.join("etc/nixos/nails/configuration.nix");
    let target = std::fs::read_link(&symlink_path).unwrap();
    let hidden_config = hidden_root.join("config/nixos/configuration.nix");
    let symlink_parent_mode = std::fs::metadata(hidden_root.join("etc/nixos/nails"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;

    assert_eq!(target, hidden_config);
    assert_eq!(symlink_parent_mode, 0o700);
}

#[test]
fn prepare_nixos_config_overlay_real_filesystem_rejects_missing_import() {
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path();
    let etc_nixos = hidden_root.join("etc/nixos");
    let hardware = etc_nixos.join("hardware-configuration.nix");
    let hidden_config = hidden_root.join("config/nixos/configuration.nix");

    std::fs::create_dir_all(hidden_config.parent().unwrap()).unwrap();
    std::fs::create_dir_all(&etc_nixos).unwrap();
    std::fs::write(&hardware, "{ ... }: { imports = [ ./base.nix ]; }").unwrap();
    std::fs::write(&hidden_config, "{ pkgs, ... }: { }").unwrap();

    let err = prepare_nixos_config_overlay(&RealFilesystem, hidden_root).unwrap_err();
    assert!(err.to_string().contains("does not contain required import"));
}

#[test]
fn prepare_nixos_config_overlay_real_filesystem_rejects_missing_hidden_configuration() {
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path();
    let etc_nixos = hidden_root.join("etc/nixos");
    let hardware = etc_nixos.join("hardware-configuration.nix");

    std::fs::create_dir_all(&etc_nixos).unwrap();
    std::fs::write(
        &hardware,
        "{ ... }: { imports = [ ./nails/configuration.nix ]; }",
    )
    .unwrap();

    let err = prepare_nixos_config_overlay(&RealFilesystem, hidden_root).unwrap_err();
    assert!(
        err.to_string()
            .contains("Hidden configuration.nix not found")
    );
}
