//! NixOS configuration pre-flight check
//!
//! Validates NixOS configuration overlay structure in hidden storage (Story 4.12).

use super::super::{CheckResult, PreFlightCheck};
use crate::{Filesystem, Result};
use std::path::PathBuf;

/// Validates NixOS configuration overlay structure in hidden storage
///
/// Ensures the hidden storage contains all required NixOS configuration files
/// for the overlay mechanism:
/// - `{hidden}/etc/nixos/` directory exists
/// - `{hidden}/etc/nixos/hardware-configuration.nix` exists (modified with import)
/// - `{hidden}/config/nixos/configuration.nix` exists (hidden environment config)
/// - Modified hardware-configuration.nix contains relative import `./nails/configuration.nix`
/// - `{hidden}/etc/nixos/nails/configuration.nix` symlink exists (staged by Story 15.2)
/// - Base `/etc/nixos/configuration.nix` OR `/etc/nixos/flake.nix` exists
///
/// # Example
///
/// ```rust
/// use nails_core::preflight::{NixOSConfigCheck, PreFlightCheck, CheckResult};
/// use nails_core::MockFilesystem;
/// use std::path::PathBuf;
///
/// let fs = MockFilesystem::new();
/// fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
/// fs.mock_set_path_exists("/etc/nixos/configuration.nix", true);
/// fs.mock_set_path_exists("/mnt/hidden/etc/nixos", true);
/// fs.mock_set_path_exists("/mnt/hidden/etc/nixos/hardware-configuration.nix", true);
/// fs.mock_set_path_exists("/mnt/hidden/config/nixos/configuration.nix", true);
/// fs.mock_set_is_symlink("/mnt/hidden/etc/nixos/nails/configuration.nix", true);
/// fs.mock_set_file_content(
///     "/mnt/hidden/etc/nixos/hardware-configuration.nix",
///     "{ imports = [ ./nails/configuration.nix ]; }"
/// );
///
/// let check = NixOSConfigCheck::new(PathBuf::from("/mnt/hidden"));
/// let result = check.run(&fs).unwrap();
/// assert!(result.is_pass());
/// ```
#[derive(Debug, Clone)]
pub struct NixOSConfigCheck {
    hidden_storage_path: PathBuf,
}

impl NixOSConfigCheck {
    /// Create a new NixOSConfigCheck
    ///
    /// # Arguments
    ///
    /// * `hidden_storage_path` - Path to hidden storage root
    pub fn new(hidden_storage_path: PathBuf) -> Self {
        Self {
            hidden_storage_path,
        }
    }
}

impl<F: Filesystem> PreFlightCheck<F> for NixOSConfigCheck {
    fn name(&self) -> &'static str {
        "nixos-config"
    }

    fn description(&self) -> &'static str {
        "Validates NixOS configuration overlay structure"
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        // Check 1: Base hardware-configuration.nix exists
        let base_config = PathBuf::from("/etc/nixos/hardware-configuration.nix");
        if !fs.path_exists(&base_config)? {
            return Ok(CheckResult::Fail(
                "Base /etc/nixos/hardware-configuration.nix not found. Ensure NixOS is properly installed.".into()
            ));
        }

        // Check 2: Base NixOS config exists (non-flake or flake)
        let base_config_nix = PathBuf::from("/etc/nixos/configuration.nix");
        let base_flake = PathBuf::from("/etc/nixos/flake.nix");
        if !fs.path_exists(&base_config_nix)? && !fs.path_exists(&base_flake)? {
            return Ok(CheckResult::Fail(
                "Base NixOS config missing: neither /etc/nixos/configuration.nix nor /etc/nixos/flake.nix exists."
                    .into(),
            ));
        }

        // Check 3: Hidden etc/nixos directory exists
        let hidden_etc_nixos = self.hidden_storage_path.join("etc/nixos");
        if !fs.path_exists(&hidden_etc_nixos)? {
            return Ok(CheckResult::Fail(format!(
                "Hidden storage missing etc/nixos/ directory at {}. Create this directory with modified hardware-configuration.nix.",
                hidden_etc_nixos.display()
            )));
        }

        // Check 4: Modified hardware-configuration.nix exists (auto-create if missing)
        let modified_config = hidden_etc_nixos.join("hardware-configuration.nix");
        if !fs.path_exists(&modified_config)? {
            let base_content = match fs.read_file_content(&base_config) {
                Ok(content) => content,
                Err(e) => {
                    return Ok(CheckResult::Fail(format!(
                        "Modified hardware-configuration.nix not found at {}. Auto-create failed to read base config: {}",
                        modified_config.display(),
                        e
                    )));
                }
            };

            let new_content = crate::nixos::ensure_nails_import_block(&base_content);
            if let Err(e) = fs.write_file_content(&modified_config, &new_content) {
                return Ok(CheckResult::Fail(format!(
                    "Modified hardware-configuration.nix not found at {}. Auto-create failed: {}",
                    modified_config.display(),
                    e
                )));
            }
            tracing::info!(
                "Auto-created modified hardware-configuration.nix at {}",
                modified_config.display()
            );
        }

        // Check 5: Modified hardware-configuration.nix has relative import to hidden config
        let content = fs.read_file_content(&modified_config)?;
        let expected_import = "./nails/configuration.nix";
        if !crate::nixos::contains_nails_import(&content) {
            return Ok(CheckResult::Fail(format!(
                "Modified hardware-configuration.nix missing hidden import. Add: imports = [ ... {} ];",
                expected_import
            )));
        }

        // Check 6: Hidden configuration.nix exists at new location
        let hidden_config = self
            .hidden_storage_path
            .join("config/nixos/configuration.nix");
        if !fs.path_exists(&hidden_config)? {
            return Ok(CheckResult::Fail(format!(
                "Hidden configuration.nix not found at {}. Create this file with hidden environment settings.",
                hidden_config.display()
            )));
        }

        // Check 7: Symlink staged into hidden /etc/nixos/nails/configuration.nix
        let symlink_path = hidden_etc_nixos.join("nails/configuration.nix");
        if !fs.is_symlink(&symlink_path)? {
            return Ok(CheckResult::Fail(format!(
                "Hidden config symlink not staged at {}. Create it with: ln -s {}/config/nixos/configuration.nix {} (or call stage_hidden_config_symlink()).",
                symlink_path.display(),
                self.hidden_storage_path.display(),
                symlink_path.display()
            )));
        }

        Ok(CheckResult::Pass(
            "NixOS configuration overlay structure is valid".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
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

        fs.mock_set_is_symlink("/mnt/hidden/etc/nixos/nails/configuration.nix", true);

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

        fs.mock_set_is_symlink("/mnt/hidden/etc/nixos/nails/configuration.nix", true);

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
    fn test_nixos_config_check_missing_hidden_configuration() {
        // AC5: Check 5 - Hidden configuration.nix missing
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
            "{ config, lib, pkgs, ... }:\n{ imports = [ ./nails/configuration.nix ]; }",
        );

        // Hidden configuration.nix does NOT exist at new path
        fs.mock_set_path_exists("/mnt/hidden/config/nixos/configuration.nix", false);

        let check = NixOSConfigCheck::new(PathBuf::from("/mnt/hidden"));
        let result = check.run(&fs).expect("Check should not error");

        assert!(
            result.is_fail(),
            "Check should fail when hidden configuration.nix missing"
        );
        assert!(
            result
                .message()
                .contains("Hidden configuration.nix not found")
        );
        assert!(
            result
                .message()
                .contains("/mnt/hidden/config/nixos/configuration.nix")
        );
        assert!(
            result
                .message()
                .contains("Create this file with hidden environment settings")
        );
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
        assert!(
            result
                .message()
                .contains("Hidden config symlink not staged at")
        );
        assert!(
            result
                .message()
                .contains("/mnt/hidden/etc/nixos/nails/configuration.nix")
        );
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
}
