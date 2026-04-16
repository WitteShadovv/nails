use super::*;
use crate::filesystem::MockFilesystem;

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
    fs.mock_set_is_symlink("/mnt/hidden/etc/nixos/nails/configuration.nix", true);
    fs.mock_set_is_symlink("/mnt/hidden/etc/nixos/nails/configuration.nix", true);

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
fn test_nixos_config_check_missing_symlink() {
    // Check 6: symlink at {hidden}/etc/nixos/nails/configuration.nix not staged
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
        "{ imports = [ ./nails/configuration.nix ]; }",
    );

    fs.mock_set_path_exists("/mnt/hidden/config/nixos/configuration.nix", true);
    fs.mock_set_path_type("/mnt/hidden/config/nixos/configuration.nix", "file");

    // Symlink is NOT set — is_symlink returns false by default

    let check = NixOSConfigCheck::new(PathBuf::from("/mnt/hidden"));
    let result = check.run(&fs).expect("Check should not error");

    assert!(
        result.is_fail(),
        "Check should fail when symlink not staged"
    );
    assert!(result
        .message()
        .contains("Hidden config symlink not staged at"));
    assert!(result
        .message()
        .contains("/mnt/hidden/etc/nixos/nails/configuration.nix"));
    assert!(result.message().contains("ln -s"));
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

    fs.mock_set_is_symlink("/media/secret/etc/nixos/nails/configuration.nix", true);

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
    fs.mock_set_is_symlink("/mnt/hidden/etc/nixos/nails/configuration.nix", true);

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

    fs.mock_set_is_symlink("/mnt/hidden/etc/nixos/nails/configuration.nix", true);

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
