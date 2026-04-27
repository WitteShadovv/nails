use super::*;
use crate::filesystem::MockFilesystem;

#[test]
fn test_nixos_config_check_success() {
    // AC5: Pre-flight validation - all conditions pass
    let fs = MockFilesystem::new();

    // Setup: All required files exist with correct content
    fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");
    fs.mock_set_path_exists("/etc/nixos/configuration.nix", true);
    fs.mock_set_path_type("/etc/nixos/configuration.nix", "file");

    fs.mock_set_path_exists("/mnt/hidden/etc/nixos", true);
    fs.mock_set_path_type("/mnt/hidden/etc/nixos", "directory");

    fs.mock_set_path_exists("/mnt/hidden/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_type("/mnt/hidden/etc/nixos/hardware-configuration.nix", "file");
    fs.mock_set_file_content(
        "/mnt/hidden/etc/nixos/hardware-configuration.nix",
        "{ config, lib, pkgs, ... }:\n{ imports = [ ./nails/configuration.nix ]; }",
    );

    fs.mock_set_path_exists("/mnt/hidden/config/nixos/configuration.nix", true);
    fs.mock_set_path_type("/mnt/hidden/config/nixos/configuration.nix", "file");

    let check = NixOSConfigCheck::new(PathBuf::from("/mnt/hidden"));
    let result = check.run(&fs).expect("Check should not error");

    assert!(
        result.is_pass(),
        "Check should pass when all conditions met"
    );
    assert_eq!(
        result.message(),
        "NixOS configuration overlay structure is valid"
    );
}

#[test]
fn test_nixos_config_check_missing_base_config() {
    // AC5: Check 1 - Base hardware-configuration.nix missing
    let fs = MockFilesystem::new();

    // Base config does NOT exist
    fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", false);
    fs.mock_set_path_exists("/etc/nixos/configuration.nix", true);
    fs.mock_set_path_type("/etc/nixos/configuration.nix", "file");

    let check = NixOSConfigCheck::new(PathBuf::from("/mnt/hidden"));
    let result = check.run(&fs).expect("Check should not error");

    assert!(
        result.is_fail(),
        "Check should fail when base config missing"
    );
    assert!(
        result
            .message()
            .contains("Base /etc/nixos/hardware-configuration.nix not found")
    );
    assert!(
        result
            .message()
            .contains("Ensure NixOS is properly installed")
    );
}

#[test]
fn test_nixos_config_check_missing_base_nixos_config() {
    // Check 2 - Base NixOS config missing (neither configuration.nix nor flake.nix)
    let fs = MockFilesystem::new();

    fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");

    // Neither configuration.nix nor flake.nix exists
    fs.mock_set_path_exists("/etc/nixos/configuration.nix", false);
    fs.mock_set_path_exists("/etc/nixos/flake.nix", false);

    let check = NixOSConfigCheck::new(PathBuf::from("/mnt/hidden"));
    let result = check.run(&fs).expect("Check should not error");

    assert!(
        result.is_fail(),
        "Check should fail when base NixOS config is missing"
    );
    assert!(
        result.message().contains("Base NixOS config missing"),
        "Failure should mention missing base NixOS config"
    );
}

#[test]
fn test_nixos_config_check_missing_hidden_etc_nixos() {
    // AC5: Check 2 - Hidden etc/nixos directory missing
    let fs = MockFilesystem::new();

    fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");
    fs.mock_set_path_exists("/etc/nixos/configuration.nix", true);
    fs.mock_set_path_type("/etc/nixos/configuration.nix", "file");

    // Hidden etc/nixos directory does NOT exist
    fs.mock_set_path_exists("/mnt/hidden/etc/nixos", false);

    let check = NixOSConfigCheck::new(PathBuf::from("/mnt/hidden"));
    let result = check.run(&fs).expect("Check should not error");

    assert!(
        result.is_fail(),
        "Check should fail when hidden etc/nixos missing"
    );
    assert!(
        result
            .message()
            .contains("Hidden storage missing etc/nixos/ directory")
    );
    assert!(result.message().contains("/mnt/hidden/etc/nixos"));
    assert!(result.message().contains("Create this directory"));
}

#[test]
fn test_nixos_config_check_missing_modified_hardware_config() {
    // AC5: Check 3 - Modified hardware-configuration.nix missing (auto-create)
    let fs = MockFilesystem::new();

    fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");
    fs.mock_set_file_content(
        "/etc/nixos/hardware-configuration.nix",
        "# base config\n{ imports = [ ]; }\n",
    );
    fs.mock_set_path_exists("/etc/nixos/configuration.nix", true);
    fs.mock_set_path_type("/etc/nixos/configuration.nix", "file");

    fs.mock_set_path_exists("/mnt/hidden/etc/nixos", true);
    fs.mock_set_path_type("/mnt/hidden/etc/nixos", "directory");

    // Modified hardware-configuration.nix does NOT exist
    fs.mock_set_path_exists("/mnt/hidden/etc/nixos/hardware-configuration.nix", false);

    fs.mock_set_path_exists("/mnt/hidden/config/nixos/configuration.nix", true);
    fs.mock_set_path_type("/mnt/hidden/config/nixos/configuration.nix", "file");

    let check = NixOSConfigCheck::new(PathBuf::from("/mnt/hidden"));
    let result = check.run(&fs).expect("Check should not error");

    assert!(
        result.is_pass(),
        "Check should pass after auto-creating modified hardware config"
    );
    let created = fs
        .read_file_content(&PathBuf::from(
            "/mnt/hidden/etc/nixos/hardware-configuration.nix",
        ))
        .expect("Auto-created hardware config should be readable");
    assert!(
        created.contains("./nails/configuration.nix"),
        "Auto-created config should include hidden import"
    );
    assert!(
        created.contains("# base config"),
        "Auto-created config should preserve base content"
    );
}

#[test]
fn test_nixos_config_check_auto_create_modified_hardware_config_write_fails() {
    // Auto-create should fail cleanly when write fails
    let fs = MockFilesystem::new();

    fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");
    fs.mock_set_file_content(
        "/etc/nixos/hardware-configuration.nix",
        "{ imports = [ ]; }\n",
    );
    fs.mock_set_path_exists("/etc/nixos/configuration.nix", true);
    fs.mock_set_path_type("/etc/nixos/configuration.nix", "file");

    fs.mock_set_path_exists("/mnt/hidden/etc/nixos", true);
    fs.mock_set_path_type("/mnt/hidden/etc/nixos", "directory");

    // Modified hardware-configuration.nix does NOT exist and write should fail
    fs.mock_set_path_exists("/mnt/hidden/etc/nixos/hardware-configuration.nix", false);
    fs.mock_set_write_should_fail("/mnt/hidden/etc/nixos/hardware-configuration.nix", true);

    let check = NixOSConfigCheck::new(PathBuf::from("/mnt/hidden"));
    let result = check.run(&fs).expect("Check should not error");

    assert!(
        result.is_fail(),
        "Check should fail when auto-create write fails"
    );
    assert!(
        result.message().contains("Auto-create failed"),
        "Failure should mention auto-create"
    );
}

#[test]
fn test_nixos_config_check_missing_hidden_import() {
    // AC5: Check 4 - Modified hardware-configuration.nix missing hidden import
    let fs = MockFilesystem::new();

    fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");
    fs.mock_set_path_exists("/etc/nixos/configuration.nix", true);
    fs.mock_set_path_type("/etc/nixos/configuration.nix", "file");

    fs.mock_set_path_exists("/mnt/hidden/etc/nixos", true);
    fs.mock_set_path_type("/mnt/hidden/etc/nixos", "directory");

    fs.mock_set_path_exists("/mnt/hidden/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_type("/mnt/hidden/etc/nixos/hardware-configuration.nix", "file");
    // Content does NOT contain the hidden import
    fs.mock_set_file_content(
        "/mnt/hidden/etc/nixos/hardware-configuration.nix",
        "{ config, lib, pkgs, ... }:\n{ imports = [ ]; }",
    );

    let check = NixOSConfigCheck::new(PathBuf::from("/mnt/hidden"));
    let result = check.run(&fs).expect("Check should not error");

    assert!(
        result.is_fail(),
        "Check should fail when hidden import missing"
    );
    assert!(
        result
            .message()
            .contains("Modified hardware-configuration.nix missing hidden import")
    );
    assert!(result.message().contains("./nails/configuration.nix"));
    assert!(result.message().contains("imports = [ ..."));
}

#[test]
fn test_nixos_config_check_commented_import_fails() {
    // Comment-only import should not pass validation
    let fs = MockFilesystem::new();

    fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");
    fs.mock_set_path_exists("/etc/nixos/configuration.nix", true);
    fs.mock_set_path_type("/etc/nixos/configuration.nix", "file");

    fs.mock_set_path_exists("/mnt/hidden/etc/nixos", true);
    fs.mock_set_path_type("/mnt/hidden/etc/nixos", "directory");

    fs.mock_set_path_exists("/mnt/hidden/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_type("/mnt/hidden/etc/nixos/hardware-configuration.nix", "file");
    fs.mock_set_file_content(
        "/mnt/hidden/etc/nixos/hardware-configuration.nix",
        "{ imports = [\n  # ./nails/configuration.nix\n  (modulesPath + \"/installer/scan/not-detected.nix\")\n]; }",
    );

    fs.mock_set_path_exists("/mnt/hidden/config/nixos/configuration.nix", true);
    fs.mock_set_path_type("/mnt/hidden/config/nixos/configuration.nix", "file");

    let check = NixOSConfigCheck::new(PathBuf::from("/mnt/hidden"));
    let result = check.run(&fs).expect("Check should not error");

    assert!(
        result.is_fail(),
        "Check should fail when import is commented out"
    );
    assert!(
        result
            .message()
            .contains("Modified hardware-configuration.nix missing hidden import")
    );
}

#[test]
fn test_nixos_config_check_missing_hidden_configuration_auto_creates() {
    // AC5: Check 5 - Hidden configuration.nix missing, auto-create it
    let fs = MockFilesystem::new();

    fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");
    fs.mock_set_path_exists("/etc/nixos/configuration.nix", true);
    fs.mock_set_path_type("/etc/nixos/configuration.nix", "file");

    fs.mock_set_path_exists("/mnt/hidden/etc/nixos", true);
    fs.mock_set_path_type("/mnt/hidden/etc/nixos", "directory");
    fs.mock_set_path_exists("/mnt", true);
    fs.mock_set_path_type("/mnt", "directory");
    fs.mock_set_writable("/mnt", true);
    fs.mock_set_path_exists("/mnt/hidden", true);
    fs.mock_set_path_type("/mnt/hidden", "directory");
    fs.mock_set_writable("/mnt/hidden", true);

    fs.mock_set_path_exists("/mnt/hidden/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_type("/mnt/hidden/etc/nixos/hardware-configuration.nix", "file");
    fs.mock_set_file_content(
        "/mnt/hidden/etc/nixos/hardware-configuration.nix",
        "{ config, lib, pkgs, ... }:\n{ imports = [ ./nails/configuration.nix ]; }",
    );

    // Hidden configuration.nix does NOT exist at new path
    fs.mock_set_path_exists("/mnt/hidden/config/nixos/configuration.nix", false);
    let check = NixOSConfigCheck::new(PathBuf::from("/mnt/hidden"));
    let result = check.run(&fs).expect("Check should not error");

    assert!(
        result.is_pass(),
        "Check should pass after auto-creating hidden config"
    );
    let created = fs
        .read_file_content(&PathBuf::from("/mnt/hidden/config/nixos/configuration.nix"))
        .expect("Auto-created hidden config should be readable");
    assert!(created.contains("pkgs.ripgrep"));
}

#[test]
fn test_nixos_config_check_auto_create_hidden_configuration_write_fails() {
    let fs = MockFilesystem::new();

    fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");
    fs.mock_set_path_exists("/etc/nixos/configuration.nix", true);
    fs.mock_set_path_type("/etc/nixos/configuration.nix", "file");
    fs.mock_set_path_exists("/mnt", true);
    fs.mock_set_path_type("/mnt", "directory");
    fs.mock_set_writable("/mnt", true);
    fs.mock_set_path_exists("/mnt/hidden", true);
    fs.mock_set_path_type("/mnt/hidden", "directory");
    fs.mock_set_writable("/mnt/hidden", true);
    fs.mock_set_path_exists("/mnt/hidden/etc/nixos", true);
    fs.mock_set_path_type("/mnt/hidden/etc/nixos", "directory");
    fs.mock_set_path_exists("/mnt/hidden/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_type("/mnt/hidden/etc/nixos/hardware-configuration.nix", "file");
    fs.mock_set_file_content(
        "/mnt/hidden/etc/nixos/hardware-configuration.nix",
        "{ config, lib, pkgs, ... }:\n{ imports = [ ./nails/configuration.nix ]; }",
    );
    fs.mock_set_write_should_fail("/mnt/hidden/config/nixos/configuration.nix", true);

    let check = NixOSConfigCheck::new(PathBuf::from("/mnt/hidden"));
    let result = check.run(&fs).expect("Check should not error");

    assert!(result.is_fail());
    assert!(result.message().contains("Auto-create failed"));
}

#[test]
fn test_nixos_config_check_different_hidden_path() {
    // AC5: Test with non-standard hidden storage path
    let fs = MockFilesystem::new();

    fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");
    fs.mock_set_path_exists("/etc/nixos/flake.nix", true);
    fs.mock_set_path_type("/etc/nixos/flake.nix", "file");

    fs.mock_set_path_exists("/media/secret/etc/nixos", true);
    fs.mock_set_path_type("/media/secret/etc/nixos", "directory");

    fs.mock_set_path_exists("/media/secret/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_type("/media/secret/etc/nixos/hardware-configuration.nix", "file");
    fs.mock_set_file_content(
        "/media/secret/etc/nixos/hardware-configuration.nix",
        "{ imports = [ ./nails/configuration.nix ]; }",
    );

    fs.mock_set_path_exists("/media/secret/config/nixos/configuration.nix", true);
    fs.mock_set_path_type("/media/secret/config/nixos/configuration.nix", "file");

    let check = NixOSConfigCheck::new(PathBuf::from("/media/secret"));
    let result = check.run(&fs).expect("Check should not error");

    assert!(
        result.is_pass(),
        "Check should work with custom hidden paths"
    );
}

#[test]
fn test_nixos_config_check_allows_flake_only() {
    let fs = MockFilesystem::new();

    // Base hardware-configuration.nix exists
    fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");

    // Base flake exists, configuration.nix missing
    fs.mock_set_path_exists("/etc/nixos/flake.nix", true);
    fs.mock_set_path_type("/etc/nixos/flake.nix", "file");

    // Hidden overlay structure valid
    fs.mock_set_path_exists("/mnt/hidden/etc/nixos", true);
    fs.mock_set_path_type("/mnt/hidden/etc/nixos", "directory");
    fs.mock_set_path_exists("/mnt/hidden/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_type("/mnt/hidden/etc/nixos/hardware-configuration.nix", "file");
    fs.mock_set_file_content(
        "/mnt/hidden/etc/nixos/hardware-configuration.nix",
        "{ imports = [ ./nails/configuration.nix ]; }",
    );
    fs.mock_set_path_exists("/mnt/hidden/config/nixos/configuration.nix", true);
    fs.mock_set_path_type("/mnt/hidden/config/nixos/configuration.nix", "file");
    let check = NixOSConfigCheck::new(PathBuf::from("/mnt/hidden"));
    let result = check.run(&fs).expect("Check should not error");

    assert!(result.is_pass(), "Flake-only base config should pass");
}

#[test]
fn test_nixos_config_check_fails_without_base_config_or_flake() {
    let fs = MockFilesystem::new();

    // Base hardware-configuration.nix exists
    fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");

    // Neither configuration.nix nor flake.nix exists
    fs.mock_set_path_exists("/etc/nixos/configuration.nix", false);
    fs.mock_set_path_exists("/etc/nixos/flake.nix", false);

    let check = NixOSConfigCheck::new(PathBuf::from("/mnt/hidden"));
    let result = check.run(&fs).expect("Check should not error");

    assert!(
        result.is_fail(),
        "Missing base config and flake should fail"
    );
    assert!(
        result
            .message()
            .contains("neither /etc/nixos/configuration.nix nor /etc/nixos/flake.nix exists"),
        "Expected failure to reference missing base config or flake"
    );
}

#[test]
fn test_nixos_config_check_integration_with_registry() {
    // AC5: Integration test - NixOSConfigCheck works with PreFlightRegistry
    use crate::preflight::PreFlightRegistry;

    let fs = MockFilesystem::new();

    // Setup valid configuration
    fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");
    fs.mock_set_path_exists("/etc/nixos/configuration.nix", true);
    fs.mock_set_path_type("/etc/nixos/configuration.nix", "file");

    fs.mock_set_path_exists("/mnt/hidden/etc/nixos", true);
    fs.mock_set_path_type("/mnt/hidden/etc/nixos", "directory");

    fs.mock_set_path_exists("/mnt/hidden/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_type("/mnt/hidden/etc/nixos/hardware-configuration.nix", "file");
    fs.mock_set_file_content(
        "/mnt/hidden/etc/nixos/hardware-configuration.nix",
        "{ imports = [ ./nails/configuration.nix ]; }",
    );

    fs.mock_set_path_exists("/mnt/hidden/config/nixos/configuration.nix", true);
    fs.mock_set_path_type("/mnt/hidden/config/nixos/configuration.nix", "file");

    let mut registry: PreFlightRegistry<MockFilesystem> = PreFlightRegistry::new();
    registry.add_check(Box::new(NixOSConfigCheck::new(PathBuf::from(
        "/mnt/hidden",
    ))));

    let result = registry.run_all(&fs);
    assert!(
        result.is_ok(),
        "Registry should succeed with valid NixOS config"
    );

    let results = result.unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, "nixos-config");
    assert!(results[0].1.is_pass());
}
