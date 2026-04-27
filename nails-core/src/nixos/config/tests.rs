use super::*;
use crate::{Filesystem, filesystem::MockFilesystem};
use std::os::unix::fs::PermissionsExt;

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
fn test_prepare_nixos_config_overlay_missing_etc_nixos_returns_error() {
    let fs = MockFilesystem::new();
    let hidden_path = std::path::PathBuf::from("/mnt/hidden");

    let err = prepare_nixos_config_overlay(&fs, &hidden_path).unwrap_err();
    assert!(err.to_string().contains("missing etc/nixos directory"));
}

#[test]
fn test_prepare_nixos_config_overlay_missing_hardware_config_returns_error() {
    let fs = MockFilesystem::new();
    let hidden_path = std::path::PathBuf::from("/mnt/hidden");

    fs.mock_set_path_exists("/mnt/hidden/etc/nixos", true);
    fs.mock_set_path_type("/mnt/hidden/etc/nixos", "directory");

    let err = prepare_nixos_config_overlay(&fs, &hidden_path).unwrap_err();
    assert!(
        err.to_string()
            .contains("Modified hardware-configuration.nix not found")
    );
}

#[test]
fn test_prepare_nixos_config_overlay_missing_hidden_configuration_returns_error() {
    let fs = MockFilesystem::new();
    let hidden_path = std::path::PathBuf::from("/mnt/hidden");
    let hardware_config = hidden_path.join("etc/nixos/hardware-configuration.nix");

    fs.mock_set_path_exists("/mnt/hidden/etc/nixos", true);
    fs.mock_set_path_type("/mnt/hidden/etc/nixos", "directory");
    fs.mock_set_path_exists("/mnt/hidden/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_type("/mnt/hidden/etc/nixos/hardware-configuration.nix", "file");
    <MockFilesystem as Filesystem>::write_file_content(
        &fs,
        &hardware_config,
        "imports = [ ./nails/configuration.nix ];",
    )
    .unwrap();

    let err = prepare_nixos_config_overlay(&fs, &hidden_path).unwrap_err();
    assert!(
        err.to_string()
            .contains("Hidden configuration.nix not found")
    );
}

#[test]
fn test_prepare_nixos_config_overlay_rejects_missing_required_import() {
    let fs = MockFilesystem::new();
    let hidden_path = std::path::PathBuf::from("/mnt/hidden");
    let hardware_config = hidden_path.join("etc/nixos/hardware-configuration.nix");
    let hidden_config = hidden_path.join("config/nixos/configuration.nix");

    fs.mock_set_path_exists("/mnt/hidden/etc/nixos", true);
    fs.mock_set_path_type("/mnt/hidden/etc/nixos", "directory");
    fs.mock_set_path_exists("/mnt/hidden/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_type("/mnt/hidden/etc/nixos/hardware-configuration.nix", "file");
    fs.mock_set_path_exists("/mnt/hidden/config/nixos/configuration.nix", true);
    fs.mock_set_path_type("/mnt/hidden/config/nixos/configuration.nix", "file");

    <MockFilesystem as Filesystem>::write_file_content(
        &fs,
        &hardware_config,
        "{ config, pkgs, ... }: { imports = [ ./foo.nix ]; }",
    )
    .unwrap();
    <MockFilesystem as Filesystem>::write_file_content(&fs, &hidden_config, "{ ... }: { }")
        .unwrap();

    let err = prepare_nixos_config_overlay(&fs, &hidden_path).unwrap_err();
    assert!(err.to_string().contains("does not contain required import"));
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
fn test_verify_base_config_clean_missing_file_is_treated_as_clean() {
    let fs = MockFilesystem::new();

    let is_clean = verify_base_config_clean(&fs).unwrap();
    assert!(is_clean, "Missing base config should be treated as clean");
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
fn test_verify_base_config_clean_detects_relative_nails_import() {
    let fs = MockFilesystem::new();
    let base_config = std::path::PathBuf::from("/etc/nixos/hardware-configuration.nix");

    <MockFilesystem as Filesystem>::write_file_content(
        &fs,
        &base_config,
        "{ ... }: { imports = [ ./nails/configuration.nix ]; }",
    )
    .unwrap();

    let is_clean = verify_base_config_clean(&fs).unwrap();
    assert!(
        !is_clean,
        "Base config should not be clean with relative nails import"
    );
}

#[test]
fn test_verify_base_config_clean_detects_nails_token_without_spaces() {
    let fs = MockFilesystem::new();
    let base_config = std::path::PathBuf::from("/etc/nixos/hardware-configuration.nix");

    <MockFilesystem as Filesystem>::write_file_content(
        &fs,
        &base_config,
        "{ config.nails.enable = true; }",
    )
    .unwrap();

    let is_clean = verify_base_config_clean(&fs).unwrap();
    assert!(
        !is_clean,
        "Base config should not be clean with dotted nails reference"
    );
}

#[test]
fn test_verify_base_config_clean_ignores_embedded_non_token_nails_text() {
    let fs = MockFilesystem::new();
    let base_config = std::path::PathBuf::from("/etc/nixos/hardware-configuration.nix");

    <MockFilesystem as Filesystem>::write_file_content(
        &fs,
        &base_config,
        "{ networking.hostName = \"snails-box\"; }",
    )
    .unwrap();

    let is_clean = verify_base_config_clean(&fs).unwrap();
    assert!(
        is_clean,
        "Base config should remain clean when 'nails' only appears inside a larger token"
    );
}

#[test]
fn test_verify_base_config_clean_detects_hidden_keyword_boundary() {
    let fs = MockFilesystem::new();
    let base_config = std::path::PathBuf::from("/etc/nixos/hardware-configuration.nix");

    <MockFilesystem as Filesystem>::write_file_content(
        &fs,
        &base_config,
        "{ boot.kernelParams = [ \"hidden\" ]; }",
    )
    .unwrap();

    let is_clean = verify_base_config_clean(&fs).unwrap();
    assert!(!is_clean, "Standalone hidden token should be flagged");
}

#[test]
fn test_verify_base_config_clean_detects_plausible_deniability_keywords() {
    let fs = MockFilesystem::new();
    let base_config = std::path::PathBuf::from("/etc/nixos/hardware-configuration.nix");

    <MockFilesystem as Filesystem>::write_file_content(
        &fs,
        &base_config,
        "{ assertions = [ { message = \"plausible deniability\"; } ]; }",
    )
    .unwrap();

    let is_clean = verify_base_config_clean(&fs).unwrap();
    assert!(
        !is_clean,
        "Plausible deniability keywords should be flagged"
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
fn test_ensure_nails_import_block_inserts_into_existing_imports_as_first_entry() {
    let original = "{ ... }: {\n  imports = [\n    ./foo.nix\n    ./bar.nix\n  ];\n}\n";

    let updated = ensure_nails_import_block(original);

    assert_eq!(
        updated,
        "{ ... }: {\n  imports = [\n    ./nails/configuration.nix\n    ./foo.nix\n    ./bar.nix\n  ];\n}\n"
    );
}

#[test]
fn test_ensure_nails_import_block_detects_imports_without_spaces() {
    let original = "{ ... }: {\n  imports=[\n    ./foo.nix\n  ];\n}\n";

    let updated = ensure_nails_import_block(original);

    assert_eq!(
        updated,
        "{ ... }: {\n  imports=[\n    ./nails/configuration.nix\n    ./foo.nix\n  ];\n}\n"
    );
}

#[test]
fn test_ensure_nails_import_block_ignores_commented_out_nails_path() {
    let original =
        "{ ... }: {\n  # ./nails/configuration.nix\n  imports = [\n    ./foo.nix\n  ];\n}\n";

    let updated = ensure_nails_import_block(original);

    assert_eq!(
        updated,
        "{ ... }: {\n  # ./nails/configuration.nix\n  imports = [\n    ./nails/configuration.nix\n    ./foo.nix\n  ];\n}\n"
    );
}

#[test]
fn test_ensure_nails_import_block_ignores_string_literal_nails_path() {
    let original = "{ ... }: {\n  environment.etc.\"example\".text = \"./nails/configuration.nix\";\n  imports = [\n    ./foo.nix\n  ];\n}\n";

    let updated = ensure_nails_import_block(original);

    assert_eq!(
        updated,
        "{ ... }: {\n  environment.etc.\"example\".text = \"./nails/configuration.nix\";\n  imports = [\n    ./nails/configuration.nix\n    ./foo.nix\n  ];\n}\n"
    );
}

#[test]
fn test_ensure_nails_import_block_ignores_dotted_and_larger_identifier_matches() {
    let original =
        "{ ... }: {\n  config.imports = [ ./foo.nix ];\n  importsExtra = [ ./bar.nix ];\n}\n";

    let updated = ensure_nails_import_block(original);

    assert_eq!(
        updated,
        "# NAILS: injected import (do not edit)\nimports = [\n  ./nails/configuration.nix\n];\n\n{ ... }: {\n  config.imports = [ ./foo.nix ];\n  importsExtra = [ ./bar.nix ];\n}\n"
    );
}

#[test]
fn test_contains_nails_import_ignores_comment_only_references() {
    let content = "# ./nails/configuration.nix\n/* ./nails/configuration.nix */\n{ ... }: { }\n";

    assert!(!contains_nails_import(content));
}

#[test]
fn test_contains_nails_import_accepts_active_reference_after_comments() {
    let content = "# comment\n{ ... }: { imports = [ ./nails/configuration.nix ]; }\n";

    assert!(contains_nails_import(content));
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
fn test_ensure_hidden_configuration_module_errors_when_directory_creation_fails() {
    let fs = MockFilesystem::new();
    let hidden_path = std::path::PathBuf::from("/mnt/hidden");

    fs.mock_set_path_exists("/mnt", true);
    fs.mock_set_path_type("/mnt", "directory");
    fs.mock_set_writable("/mnt", true);
    fs.mock_set_path_exists("/mnt/hidden", true);
    fs.mock_set_path_type("/mnt/hidden", "directory");
    fs.mock_set_writable("/mnt/hidden", false);

    let err = ensure_hidden_configuration_module(&fs, &hidden_path).unwrap_err();
    assert!(
        err.to_string()
            .contains("Failed to create hidden config directory")
    );
}

#[test]
fn test_ensure_hidden_configuration_module_errors_when_write_fails() {
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
    fs.mock_set_write_should_fail(hidden_config.to_str().unwrap(), true);

    let err = ensure_hidden_configuration_module(&fs, &hidden_path).unwrap_err();
    assert!(
        err.to_string()
            .contains("Failed to auto-generate hidden configuration.nix")
    );
}

#[test]
fn test_ensure_hidden_configuration_module_errors_when_directory_permission_update_fails() {
    let fs = MockFilesystem::new();
    let hidden_path = std::path::PathBuf::from("/mnt/hidden");
    let config_dir = hidden_path.join("config/nixos");

    fs.mock_set_path_exists("/mnt", true);
    fs.mock_set_path_type("/mnt", "directory");
    fs.mock_set_writable("/mnt", true);
    fs.mock_set_path_exists("/mnt/hidden", true);
    fs.mock_set_path_type("/mnt/hidden", "directory");
    fs.mock_set_writable("/mnt/hidden", true);
    fs.mock_set_path_exists(config_dir.to_str().unwrap(), true);
    fs.mock_set_path_type(config_dir.to_str().unwrap(), "directory");
    fs.mock_set_permissions_should_fail(config_dir.to_str().unwrap(), true);

    let err = ensure_hidden_configuration_module(&fs, &hidden_path).unwrap_err();
    assert!(
        err.to_string()
            .contains("Failed to set permissions on hidden config directory")
    );
}

#[test]
fn test_ensure_hidden_configuration_module_errors_when_existing_file_permission_update_fails() {
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
    fs.mock_set_path_exists(hidden_config.to_str().unwrap(), true);
    fs.mock_set_path_type(hidden_config.to_str().unwrap(), "file");
    fs.mock_set_file_content(hidden_config.to_str().unwrap(), "{ ... }: { }");
    fs.mock_set_permissions_should_fail(hidden_config.to_str().unwrap(), true);

    let err = ensure_hidden_configuration_module(&fs, &hidden_path).unwrap_err();
    assert!(
        err.to_string()
            .contains("Failed to set permissions on hidden configuration.nix")
    );
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

#[test]
fn test_ensure_hidden_hardware_configuration_errors_when_base_read_fails() {
    let fs = MockFilesystem::new();
    let hidden_path = std::path::PathBuf::from("/mnt/hidden");
    let base_hardware = std::path::PathBuf::from("/etc/nixos/hardware-configuration.nix");

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
    fs.mock_set_path_exists(base_hardware.to_str().unwrap(), true);
    fs.mock_set_path_type(base_hardware.to_str().unwrap(), "file");

    let err = ensure_hidden_hardware_configuration(&fs, &hidden_path, &base_hardware).unwrap_err();
    assert!(
        err.to_string()
            .contains("Failed to bootstrap hidden hardware-configuration.nix")
    );
}

#[test]
fn test_ensure_hidden_hardware_configuration_errors_when_directory_creation_fails() {
    let fs = MockFilesystem::new();
    let hidden_path = std::path::PathBuf::from("/mnt/hidden");
    let base_hardware = std::path::PathBuf::from("/etc/nixos/hardware-configuration.nix");

    fs.mock_set_path_exists("/mnt", true);
    fs.mock_set_path_type("/mnt", "directory");
    fs.mock_set_writable("/mnt", true);
    fs.mock_set_path_exists(hidden_path.to_str().unwrap(), true);
    fs.mock_set_path_type(hidden_path.to_str().unwrap(), "directory");
    fs.mock_set_writable(hidden_path.to_str().unwrap(), false);

    let err = ensure_hidden_hardware_configuration(&fs, &hidden_path, &base_hardware).unwrap_err();
    assert!(
        err.to_string()
            .contains("Failed to create hidden etc/nixos directory")
    );
}

#[test]
fn test_ensure_hidden_hardware_configuration_errors_when_directory_permission_update_fails() {
    let fs = MockFilesystem::new();
    let hidden_path = std::path::PathBuf::from("/mnt/hidden");
    let base_hardware = std::path::PathBuf::from("/etc/nixos/hardware-configuration.nix");
    let hidden_etc_nixos = hidden_path.join("etc/nixos");

    fs.mock_set_path_exists("/mnt", true);
    fs.mock_set_path_type("/mnt", "directory");
    fs.mock_set_writable("/mnt", true);
    fs.mock_set_path_exists(hidden_path.to_str().unwrap(), true);
    fs.mock_set_path_type(hidden_path.to_str().unwrap(), "directory");
    fs.mock_set_writable(hidden_path.to_str().unwrap(), true);
    fs.mock_set_path_exists(hidden_etc_nixos.to_str().unwrap(), true);
    fs.mock_set_path_type(hidden_etc_nixos.to_str().unwrap(), "directory");
    fs.mock_set_permissions_should_fail(hidden_etc_nixos.to_str().unwrap(), true);

    let err = ensure_hidden_hardware_configuration(&fs, &hidden_path, &base_hardware).unwrap_err();
    assert!(
        err.to_string()
            .contains("Failed to set permissions on hidden etc/nixos directory")
    );
}

#[test]
fn test_ensure_hidden_hardware_configuration_errors_when_existing_file_permission_update_fails() {
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
        "{ config, lib, pkgs, ... }:\n{\n  imports = [ ./nails/configuration.nix ];\n}\n",
    );
    fs.mock_set_path_exists(base_hardware.to_str().unwrap(), true);
    fs.mock_set_path_type(base_hardware.to_str().unwrap(), "file");
    fs.mock_set_file_content(base_hardware.to_str().unwrap(), "{ }: { }\n");
    fs.mock_set_permissions_should_fail(hidden_hardware.to_str().unwrap(), true);

    let err = ensure_hidden_hardware_configuration(&fs, &hidden_path, &base_hardware).unwrap_err();
    assert!(
        err.to_string()
            .contains("Failed to set permissions on hidden hardware-configuration.nix")
    );
}

#[test]
fn test_ensure_hidden_hardware_configuration_errors_when_write_fails() {
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
    fs.mock_set_file_content(hidden_hardware.to_str().unwrap(), "{ }: { }\n");
    fs.mock_set_write_should_fail(hidden_hardware.to_str().unwrap(), true);

    let err = ensure_hidden_hardware_configuration(&fs, &hidden_path, &base_hardware).unwrap_err();
    assert!(
        err.to_string()
            .contains("Failed to write hidden hardware-configuration.nix")
    );
}

#[test]
fn test_stage_hidden_config_symlink_is_idempotent_for_existing_correct_symlink() {
    let fs = MockFilesystem::new();
    let hidden_path = std::path::PathBuf::from("/mnt/hidden");
    let nails_dir = hidden_path.join("etc/nixos/nails");
    let hidden_config = hidden_path.join("config/nixos/configuration.nix");
    let symlink_path = nails_dir.join("configuration.nix");

    fs.mock_set_path_exists("/mnt", true);
    fs.mock_set_path_type("/mnt", "directory");
    fs.mock_set_writable("/mnt", true);
    fs.mock_set_path_exists("/mnt/hidden", true);
    fs.mock_set_path_type("/mnt/hidden", "directory");
    fs.mock_set_writable("/mnt/hidden", true);
    fs.mock_set_path_exists("/mnt/hidden/etc", true);
    fs.mock_set_path_type("/mnt/hidden/etc", "directory");
    fs.mock_set_writable("/mnt/hidden/etc", true);
    fs.mock_set_path_exists("/mnt/hidden/etc/nixos", true);
    fs.mock_set_path_type("/mnt/hidden/etc/nixos", "directory");
    fs.mock_set_writable("/mnt/hidden/etc/nixos", true);
    fs.mock_set_path_exists("/mnt/hidden/etc/nixos/nails", true);
    fs.mock_set_path_type("/mnt/hidden/etc/nixos/nails", "directory");
    fs.mock_set_writable("/mnt/hidden/etc/nixos/nails", true);
    fs.mock_set_path_exists("/mnt/hidden/config", true);
    fs.mock_set_path_type("/mnt/hidden/config", "directory");
    fs.mock_set_writable("/mnt/hidden/config", true);
    fs.mock_set_path_exists("/mnt/hidden/config/nixos", true);
    fs.mock_set_path_type("/mnt/hidden/config/nixos", "directory");
    fs.mock_set_writable("/mnt/hidden/config/nixos", true);
    fs.mock_set_path_exists(hidden_config.to_str().unwrap(), true);
    fs.mock_set_path_type(hidden_config.to_str().unwrap(), "file");
    fs.mock_set_file_content(hidden_config.to_str().unwrap(), "{ ... }: { }");
    <MockFilesystem as Filesystem>::create_symlink(&fs, &hidden_config, &symlink_path).unwrap();

    stage_hidden_config_symlink(&fs, &hidden_path).unwrap();

    assert_eq!(
        fs.mock_get_symlink_target(&symlink_path),
        Some(hidden_config)
    );
    assert_eq!(fs.mock_get_permissions(&nails_dir), Some(0o700));
}

#[test]
fn test_stage_hidden_config_symlink_errors_for_conflicting_existing_symlink() {
    let fs = MockFilesystem::new();
    let hidden_path = std::path::PathBuf::from("/mnt/hidden");
    let nails_dir = hidden_path.join("etc/nixos/nails");
    let hidden_config = hidden_path.join("config/nixos/configuration.nix");
    let symlink_path = nails_dir.join("configuration.nix");

    fs.mock_set_path_exists("/mnt", true);
    fs.mock_set_path_type("/mnt", "directory");
    fs.mock_set_writable("/mnt", true);
    fs.mock_set_path_exists("/mnt/hidden", true);
    fs.mock_set_path_type("/mnt/hidden", "directory");
    fs.mock_set_writable("/mnt/hidden", true);
    fs.mock_set_path_exists("/mnt/hidden/etc", true);
    fs.mock_set_path_type("/mnt/hidden/etc", "directory");
    fs.mock_set_writable("/mnt/hidden/etc", true);
    fs.mock_set_path_exists("/mnt/hidden/etc/nixos", true);
    fs.mock_set_path_type("/mnt/hidden/etc/nixos", "directory");
    fs.mock_set_writable("/mnt/hidden/etc/nixos", true);
    fs.mock_set_path_exists("/mnt/hidden/etc/nixos/nails", true);
    fs.mock_set_path_type("/mnt/hidden/etc/nixos/nails", "directory");
    fs.mock_set_writable("/mnt/hidden/etc/nixos/nails", true);
    fs.mock_set_path_exists("/mnt/hidden/config", true);
    fs.mock_set_path_type("/mnt/hidden/config", "directory");
    fs.mock_set_writable("/mnt/hidden/config", true);
    fs.mock_set_path_exists("/mnt/hidden/config/nixos", true);
    fs.mock_set_path_type("/mnt/hidden/config/nixos", "directory");
    fs.mock_set_writable("/mnt/hidden/config/nixos", true);
    fs.mock_set_path_exists(hidden_config.to_str().unwrap(), true);
    fs.mock_set_path_type(hidden_config.to_str().unwrap(), "file");
    fs.mock_set_file_content(hidden_config.to_str().unwrap(), "{ ... }: { }");
    <MockFilesystem as Filesystem>::create_symlink(
        &fs,
        &std::path::PathBuf::from("/wrong/target.nix"),
        &symlink_path,
    )
    .unwrap();

    let err = stage_hidden_config_symlink(&fs, &hidden_path).unwrap_err();
    assert!(err.to_string().contains("Failed to create symlink"));
}

#[test]
fn test_stage_hidden_config_symlink_errors_when_nails_directory_permission_update_fails() {
    let fs = MockFilesystem::new();
    let hidden_path = std::path::PathBuf::from("/mnt/hidden");
    let nails_dir = hidden_path.join("etc/nixos/nails");
    let hidden_config = hidden_path.join("config/nixos/configuration.nix");

    fs.mock_set_path_exists("/mnt", true);
    fs.mock_set_path_type("/mnt", "directory");
    fs.mock_set_writable("/mnt", true);
    fs.mock_set_path_exists("/mnt/hidden", true);
    fs.mock_set_path_type("/mnt/hidden", "directory");
    fs.mock_set_writable("/mnt/hidden", true);
    fs.mock_set_path_exists("/mnt/hidden/etc", true);
    fs.mock_set_path_type("/mnt/hidden/etc", "directory");
    fs.mock_set_writable("/mnt/hidden/etc", true);
    fs.mock_set_path_exists("/mnt/hidden/etc/nixos", true);
    fs.mock_set_path_type("/mnt/hidden/etc/nixos", "directory");
    fs.mock_set_writable("/mnt/hidden/etc/nixos", true);
    fs.mock_set_path_exists(nails_dir.to_str().unwrap(), true);
    fs.mock_set_path_type(nails_dir.to_str().unwrap(), "directory");
    fs.mock_set_writable(nails_dir.to_str().unwrap(), true);
    fs.mock_set_path_exists("/mnt/hidden/config", true);
    fs.mock_set_path_type("/mnt/hidden/config", "directory");
    fs.mock_set_writable("/mnt/hidden/config", true);
    fs.mock_set_path_exists("/mnt/hidden/config/nixos", true);
    fs.mock_set_path_type("/mnt/hidden/config/nixos", "directory");
    fs.mock_set_writable("/mnt/hidden/config/nixos", true);
    fs.mock_set_path_exists(hidden_config.to_str().unwrap(), true);
    fs.mock_set_path_type(hidden_config.to_str().unwrap(), "file");
    fs.mock_set_file_content(hidden_config.to_str().unwrap(), "{ ... }: { }\n");
    fs.mock_set_permissions_should_fail(nails_dir.to_str().unwrap(), true);

    let err = stage_hidden_config_symlink(&fs, &hidden_path).unwrap_err();
    assert!(
        err.to_string()
            .contains("Failed to set permissions on hidden nails config directory")
    );
}

#[test]
fn test_ensure_hidden_configuration_module_real_filesystem_preserves_existing_permissions() {
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_path = temp_dir.path();
    let config_dir = hidden_path.join("config/nixos");
    let hidden_config = config_dir.join("configuration.nix");

    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::write(
        &hidden_config,
        "{ pkgs, ... }: { environment.systemPackages = [ pkgs.jq ]; }",
    )
    .unwrap();
    std::fs::set_permissions(&config_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::set_permissions(&hidden_config, std::fs::Permissions::from_mode(0o644)).unwrap();

    ensure_hidden_configuration_module(&crate::RealFilesystem, hidden_path).unwrap();

    let mode_dir = std::fs::metadata(&config_dir).unwrap().permissions().mode() & 0o777;
    let mode_file = std::fs::metadata(&hidden_config)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    let content = std::fs::read_to_string(&hidden_config).unwrap();

    assert_eq!(mode_dir, 0o700);
    assert_eq!(mode_file, 0o600);
    assert!(content.contains("pkgs.jq"));
    assert!(!content.contains("pkgs.ripgrep"));
}

#[test]
fn test_ensure_hidden_hardware_configuration_real_filesystem_bootstraps_permissions_and_import() {
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_path = temp_dir.path().join("hidden");
    let base_dir = temp_dir.path().join("base");
    let base_hardware = base_dir.join("hardware-configuration.nix");
    let hidden_etc_nixos = hidden_path.join("etc/nixos");
    let hidden_hardware = hidden_etc_nixos.join("hardware-configuration.nix");

    std::fs::create_dir_all(&base_dir).unwrap();
    std::fs::create_dir_all(&hidden_etc_nixos).unwrap();
    std::fs::write(
        &base_hardware,
        "{ config, lib, pkgs, modulesPath, ... }:\n{\n  imports = [ (modulesPath + \"/installer/scan/not-detected.nix\") ];\n}\n",
    )
    .unwrap();
    std::fs::set_permissions(&hidden_etc_nixos, std::fs::Permissions::from_mode(0o755)).unwrap();

    ensure_hidden_hardware_configuration(&crate::RealFilesystem, &hidden_path, &base_hardware)
        .unwrap();

    let content = std::fs::read_to_string(&hidden_hardware).unwrap();
    let dir_mode = std::fs::metadata(&hidden_etc_nixos)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    let file_mode = std::fs::metadata(&hidden_hardware)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;

    assert!(content.contains("./nails/configuration.nix"));
    assert!(content.contains("modulesPath + \"/installer/scan/not-detected.nix\""));
    assert_eq!(dir_mode, 0o700);
    assert_eq!(file_mode, 0o600);
}

#[test]
fn test_stage_hidden_config_symlink_real_filesystem_creates_expected_symlink() {
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_path = temp_dir.path();
    let etc_nixos = hidden_path.join("etc/nixos");
    std::fs::create_dir_all(&etc_nixos).unwrap();

    stage_hidden_config_symlink(&crate::RealFilesystem, hidden_path).unwrap();

    let nails_dir = hidden_path.join("etc/nixos/nails");
    let symlink_path = nails_dir.join("configuration.nix");
    let hidden_config = hidden_path.join("config/nixos/configuration.nix");

    let link_target = std::fs::read_link(&symlink_path).unwrap();
    let nails_mode = std::fs::metadata(&nails_dir).unwrap().permissions().mode() & 0o777;
    let config_mode = std::fs::metadata(&hidden_config)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    let config_content = std::fs::read_to_string(&hidden_config).unwrap();

    assert_eq!(link_target, hidden_config);
    assert_eq!(nails_mode, 0o700);
    assert_eq!(config_mode, 0o600);
    assert!(config_content.contains("pkgs.ripgrep"));
}
