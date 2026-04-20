use super::*;
use crate::{Filesystem, filesystem::MockFilesystem};

#[test]
fn test_prepare_nixos_config_overlay_success() {
    let fs = MockFilesystem::new();
    let hidden_path = std::path::PathBuf::from("/mnt/hidden");

    // Setup filesystem structure using mock
    fs.mock_set_path_exists("/mnt/hidden/etc/nixos", true);
    fs.mock_set_path_type("/mnt/hidden/etc/nixos", "directory");
    fs.mock_set_path_exists("/mnt/hidden/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_type("/mnt/hidden/etc/nixos/hardware-configuration.nix", "file");
    fs.mock_set_path_exists("/mnt/hidden/config/nixos/configuration.nix", true);
    fs.mock_set_path_type("/mnt/hidden/config/nixos/configuration.nix", "file");

    let etc_nixos = hidden_path.join("etc/nixos");
    let hardware_config = etc_nixos.join("hardware-configuration.nix");
    let hidden_config = hidden_path.join("config/nixos/configuration.nix");

    // Create file content with import
    <MockFilesystem as Filesystem>::write_file_content(
        &fs,
        &hardware_config,
        "imports = [ ./nails/configuration.nix ];",
    )
    .unwrap();
    <MockFilesystem as Filesystem>::write_file_content(&fs, &hidden_config, "{ ... }: { }")
        .unwrap();

    // Validate overlay
    let result = prepare_nixos_config_overlay(&fs, &hidden_path).unwrap();

    assert_eq!(result.hardware_config_path, hardware_config);
    assert_eq!(result.hidden_config_path, hidden_config);
    assert_eq!(result.etc_nixos_overlay, etc_nixos);
}

#[test]
fn test_verify_base_config_clean_success() {
    let fs = MockFilesystem::new();
    let base_config = std::path::PathBuf::from("/etc/nixos/hardware-configuration.nix");

    // Create base config with no suspicious patterns
    <MockFilesystem as Filesystem>::write_file_content(
        &fs,
        &base_config,
        "{ config, pkgs, ... }: { }",
    )
    .unwrap();

    let is_clean = verify_base_config_clean(&fs).unwrap();
    assert!(is_clean, "Base config should be clean");
}

#[test]
fn test_verify_base_config_clean_suspicious_hidden_path() {
    let fs = MockFilesystem::new();
    let base_config = std::path::PathBuf::from("/etc/nixos/hardware-configuration.nix");

    // Create base config with suspicious /mnt/hidden reference
    <MockFilesystem as Filesystem>::write_file_content(
        &fs,
        &base_config,
        "{ fileSystems.\"/mnt/hidden\" = { }; }",
    )
    .unwrap();

    let is_clean = verify_base_config_clean(&fs).unwrap();
    assert!(
        !is_clean,
        "Base config should not be clean with /mnt/hidden"
    );
}

#[test]
fn test_inject_import_block_no_imports_prepends_full_block() {
    let fs = MockFilesystem::new();
    let target = std::path::PathBuf::from("/etc/nixos/hardware-configuration.nix");

    // Create base config without imports
    let original = "{ config, pkgs, ... }: {\n  boot.loader.grub.enable = true;\n}";
    <MockFilesystem as Filesystem>::write_file_content(&fs, &target, original).unwrap();

    // Inject import block
    inject_import_block(&fs).unwrap();

    // Verify import was prepended
    let content = <MockFilesystem as Filesystem>::read_file_content(&fs, &target).unwrap();
    assert!(content.contains("# NAILS: injected import"));
    assert!(content.contains("imports = ["));
    assert!(content.contains("./nails/configuration.nix"));
    assert!(
        content.contains(original),
        "Original content should be preserved"
    );
}

#[test]
fn test_inject_import_block_idempotent_when_already_injected() {
    let fs = MockFilesystem::new();
    let target = std::path::PathBuf::from("/etc/nixos/hardware-configuration.nix");

    // Create config that already has the import
    let original = "imports = [ ./nails/configuration.nix ];\n{ config, pkgs, ... }: { }";
    <MockFilesystem as Filesystem>::write_file_content(&fs, &target, original).unwrap();

    // Inject import block (should be no-op)
    inject_import_block(&fs).unwrap();

    // Verify content unchanged
    let content = <MockFilesystem as Filesystem>::read_file_content(&fs, &target).unwrap();
    assert_eq!(
        content, original,
        "Content should be unchanged (idempotent)"
    );
}

#[test]
fn test_stage_hidden_config_symlink_creates_dir_and_symlink() {
    let fs = MockFilesystem::new();
    let hidden_path = std::path::PathBuf::from("/mnt/hidden");

    // Setup hidden config
    fs.mock_set_path_exists("/mnt/hidden/etc/nixos", true);
    fs.mock_set_path_type("/mnt/hidden/etc/nixos", "directory");
    fs.mock_set_path_exists("/mnt", true);
    fs.mock_set_path_type("/mnt", "directory");
    fs.mock_set_writable("/mnt", true);
    fs.mock_set_path_exists("/mnt/hidden", true);
    fs.mock_set_path_type("/mnt/hidden", "directory");
    fs.mock_set_writable("/mnt/hidden", true);
    let hidden_config = hidden_path.join("config/nixos/configuration.nix");

    // Stage symlink
    stage_hidden_config_symlink(&fs, &hidden_path).unwrap();

    assert!(
        <MockFilesystem as Filesystem>::path_exists(&fs, &hidden_config).unwrap(),
        "hidden configuration should exist"
    );
    let generated = <MockFilesystem as Filesystem>::read_file_content(&fs, &hidden_config).unwrap();
    assert!(generated.contains("pkgs.ripgrep"));
    assert_eq!(fs.mock_get_permissions(&hidden_config), Some(0o600));

    // Verify nails directory was created
    let nails_dir = hidden_path.join("etc/nixos/nails");
    assert!(
        <MockFilesystem as Filesystem>::path_exists(&fs, &nails_dir).unwrap(),
        "nails directory should exist"
    );
    assert_eq!(fs.mock_get_permissions(&nails_dir), Some(0o700));

    // Verify symlink was created
    let symlink_path = nails_dir.join("configuration.nix");
    assert!(
        <MockFilesystem as Filesystem>::path_exists(&fs, &symlink_path).unwrap(),
        "symlink should exist"
    );
}

#[test]
fn test_ensure_hidden_configuration_module_creates_minimal_module() {
    let fs = MockFilesystem::new();
    let hidden_path = std::path::PathBuf::from("/mnt/hidden");
    let hidden_root = hidden_path.clone();

    fs.mock_set_path_exists("/mnt", true);
    fs.mock_set_path_type("/mnt", "directory");
    fs.mock_set_writable("/mnt", true);
    fs.mock_set_path_exists(hidden_root.to_str().unwrap(), true);
    fs.mock_set_path_type(hidden_root.to_str().unwrap(), "directory");
    fs.mock_set_writable(hidden_root.to_str().unwrap(), true);

    ensure_hidden_configuration_module(&fs, &hidden_path).unwrap();

    let hidden_config = hidden_path.join("config/nixos/configuration.nix");
    let content = <MockFilesystem as Filesystem>::read_file_content(&fs, &hidden_config).unwrap();
    assert!(content.contains("environment.systemPackages"));
    assert!(content.contains("pkgs.ripgrep"));
    assert!(content.starts_with("{ pkgs, ... }"));
    assert_eq!(
        fs.mock_get_permissions(&hidden_path.join("config/nixos")),
        Some(0o700)
    );
    assert_eq!(fs.mock_get_permissions(&hidden_config), Some(0o600));
}

#[test]
fn test_ensure_hidden_configuration_module_preserves_existing_file() {
    let fs = MockFilesystem::new();
    let hidden_path = std::path::PathBuf::from("/mnt/hidden");
    let hidden_config = hidden_path.join("config/nixos/configuration.nix");

    fs.mock_set_path_exists("/mnt", true);
    fs.mock_set_path_type("/mnt", "directory");
    fs.mock_set_writable("/mnt", true);
    fs.mock_set_path_exists("/mnt/hidden", true);
    fs.mock_set_path_type("/mnt/hidden", "directory");
    fs.mock_set_writable("/mnt/hidden", true);
    fs.mock_set_path_exists("/mnt/hidden/config", true);
    fs.mock_set_path_type("/mnt/hidden/config", "directory");
    fs.mock_set_writable("/mnt/hidden/config", true);
    fs.mock_set_path_exists("/mnt/hidden/config/nixos", true);
    fs.mock_set_path_type("/mnt/hidden/config/nixos", "directory");
    fs.mock_set_writable("/mnt/hidden/config/nixos", true);

    fs.mock_set_path_exists("/mnt/hidden/config/nixos/configuration.nix", true);
    fs.mock_set_path_type("/mnt/hidden/config/nixos/configuration.nix", "file");
    <MockFilesystem as Filesystem>::write_file_content(
        &fs,
        &hidden_config,
        "{ pkgs, ... }: { environment.systemPackages = [ pkgs.jq ]; }",
    )
    .unwrap();

    ensure_hidden_configuration_module(&fs, &hidden_path).unwrap();

    let content = <MockFilesystem as Filesystem>::read_file_content(&fs, &hidden_config).unwrap();
    assert!(content.contains("pkgs.jq"));
    assert!(!content.contains("pkgs.ripgrep"));
    assert_eq!(fs.mock_get_permissions(&hidden_config), Some(0o600));
}

#[test]
fn test_ensure_hidden_hardware_configuration_bootstraps_from_base_config() {
    let fs = MockFilesystem::new();
    let hidden_path = std::path::PathBuf::from("/mnt/hidden");
    let base_hardware = std::path::PathBuf::from("/etc/nixos/hardware-configuration.nix");
    let hidden_hardware = hidden_path.join("etc/nixos/hardware-configuration.nix");

    fs.mock_set_path_exists("/etc", true);
    fs.mock_set_path_type("/etc", "directory");
    fs.mock_set_writable("/etc", true);
    fs.mock_set_path_exists("/etc/nixos", true);
    fs.mock_set_path_type("/etc/nixos", "directory");
    fs.mock_set_writable("/etc/nixos", true);
    fs.mock_set_path_exists(base_hardware.to_str().unwrap(), true);
    fs.mock_set_path_type(base_hardware.to_str().unwrap(), "file");
    fs.mock_set_file_content(
        base_hardware.to_str().unwrap(),
        "{ config, lib, pkgs, modulesPath, ... }:\n{\n  imports = [ (modulesPath + \"/installer/scan/not-detected.nix\") ];\n}\n",
    );

    fs.mock_set_path_exists("/mnt", true);
    fs.mock_set_path_type("/mnt", "directory");
    fs.mock_set_writable("/mnt", true);
    fs.mock_set_path_exists(hidden_path.to_str().unwrap(), true);
    fs.mock_set_path_type(hidden_path.to_str().unwrap(), "directory");
    fs.mock_set_writable(hidden_path.to_str().unwrap(), true);
    fs.mock_set_path_exists("/mnt/hidden/etc", true);
    fs.mock_set_path_type("/mnt/hidden/etc", "directory");
    fs.mock_set_writable("/mnt/hidden/etc", true);
    fs.mock_set_path_exists("/mnt/hidden/etc/nixos", true);
    fs.mock_set_path_type("/mnt/hidden/etc/nixos", "directory");
    fs.mock_set_writable("/mnt/hidden/etc/nixos", true);

    ensure_hidden_hardware_configuration(&fs, &hidden_path, &base_hardware).unwrap();

    let content = <MockFilesystem as Filesystem>::read_file_content(&fs, &hidden_hardware).unwrap();
    assert!(content.contains("modulesPath + \"/installer/scan/not-detected.nix\""));
    assert!(content.contains("./nails/configuration.nix"));
    assert_eq!(
        fs.mock_get_permissions(&hidden_path.join("etc/nixos")),
        Some(0o700)
    );
    assert_eq!(fs.mock_get_permissions(&hidden_hardware), Some(0o600));
}

#[test]
fn test_ensure_hidden_hardware_configuration_updates_existing_hidden_file() {
    let fs = MockFilesystem::new();
    let hidden_path = std::path::PathBuf::from("/mnt/hidden");
    let base_hardware = std::path::PathBuf::from("/etc/nixos/hardware-configuration.nix");
    let hidden_hardware = hidden_path.join("etc/nixos/hardware-configuration.nix");

    fs.mock_set_path_exists("/mnt", true);
    fs.mock_set_path_type("/mnt", "directory");
    fs.mock_set_writable("/mnt", true);
    fs.mock_set_path_exists(hidden_path.to_str().unwrap(), true);
    fs.mock_set_path_type(hidden_path.to_str().unwrap(), "directory");
    fs.mock_set_writable(hidden_path.to_str().unwrap(), true);
    fs.mock_set_path_exists("/mnt/hidden/etc", true);
    fs.mock_set_path_type("/mnt/hidden/etc", "directory");
    fs.mock_set_writable("/mnt/hidden/etc", true);
    fs.mock_set_path_exists("/mnt/hidden/etc/nixos", true);
    fs.mock_set_path_type("/mnt/hidden/etc/nixos", "directory");
    fs.mock_set_writable("/mnt/hidden/etc/nixos", true);
    fs.mock_set_path_exists(hidden_hardware.to_str().unwrap(), true);
    fs.mock_set_path_type(hidden_hardware.to_str().unwrap(), "file");
    fs.mock_set_file_content(
        hidden_hardware.to_str().unwrap(),
        "{ config, lib, pkgs, ... }:\n{\n  networking.hostName = \"hidden\";\n}\n",
    );
    fs.mock_set_path_exists(base_hardware.to_str().unwrap(), true);
    fs.mock_set_path_type(base_hardware.to_str().unwrap(), "file");
    fs.mock_set_file_content(base_hardware.to_str().unwrap(), "{ }: { }\n");

    ensure_hidden_hardware_configuration(&fs, &hidden_path, &base_hardware).unwrap();

    let content = <MockFilesystem as Filesystem>::read_file_content(&fs, &hidden_hardware).unwrap();
    assert!(content.contains("networking.hostName = \"hidden\";"));
    assert!(content.contains("./nails/configuration.nix"));
    assert_eq!(fs.mock_get_permissions(&hidden_hardware), Some(0o600));
}
