//! NixOS build target validation pre-flight check
//!
//! Validates that the NixOS build target (flake reference or legacy config)
//! will resolve before any destructive operations begin.

use super::super::{CheckResult, PreFlightCheck};
use crate::{Filesystem, Result};
use std::path::PathBuf;

/// Validates the NixOS build target reference will resolve
///
/// When an explicit `--flake` is provided, validates:
/// - The path is absolute (not relative)
/// - The directory exists
/// - The directory contains a `flake.nix`
///
/// When no flake is specified, probes auto-discovery locations in order:
/// 1. `{hidden_volume_root}/nixos/flake.nix`
/// 2. `/etc/nixos/flake.nix`
/// 3. `/etc/nixos/configuration.nix`
/// 4. `/nix/var/nix/profiles/system`
///
/// This is separate from `NixOSConfigCheck` which validates the hidden storage
/// overlay structure (symlinks, imports). This check validates the build target
/// reference itself.
#[derive(Debug, Clone)]
pub struct NixOSBuildTargetCheck {
    nixos_flake: Option<String>,
    hidden_volume_root: PathBuf,
}

impl NixOSBuildTargetCheck {
    /// Create a new NixOSBuildTargetCheck
    ///
    /// # Arguments
    ///
    /// * `nixos_flake` - Optional flake reference from config/CLI (e.g., "/etc/nixos#hostname")
    /// * `hidden_volume_root` - Path to hidden volume root for auto-discovery
    pub fn new(nixos_flake: Option<String>, hidden_volume_root: PathBuf) -> Self {
        Self {
            nixos_flake,
            hidden_volume_root,
        }
    }

    /// Validate an explicit flake reference
    fn check_explicit_flake<F: Filesystem>(&self, fs: &F, flake_ref: &str) -> Result<CheckResult> {
        // Parse flake reference: "dir_path#attr" or just "dir_path"
        let dir_path = if let Some(hash_pos) = flake_ref.find('#') {
            &flake_ref[..hash_pos]
        } else {
            flake_ref
        };

        // Check 1: Path must be absolute
        if !dir_path.starts_with('/') {
            return Ok(CheckResult::Fail(format!(
                "Flake path '{}' is relative. Use an absolute path (e.g., '/etc/nixos#attr').",
                dir_path
            )));
        }

        let dir = PathBuf::from(dir_path);

        // Check 2: Directory must exist
        if !fs.path_exists(&dir)? {
            return Ok(CheckResult::Fail(format!(
                "Flake directory '{}' not found.",
                dir_path
            )));
        }

        // Check 3: flake.nix must exist in directory
        let flake_nix = dir.join("flake.nix");
        if !fs.path_exists(&flake_nix)? {
            return Ok(CheckResult::Fail(format!(
                "flake.nix not found in '{}'.",
                dir_path
            )));
        }

        Ok(CheckResult::Pass(format!(
            "Flake build target '{}' validated (attribute selection deferred to build time)",
            flake_ref
        )))
    }

    /// Probe auto-discovery locations for NixOS configuration
    fn check_auto_discovery<F: Filesystem>(&self, fs: &F) -> Result<CheckResult> {
        // Probe 1: Hidden volume flake
        let hidden_flake = self.hidden_volume_root.join("nixos/flake.nix");
        if fs.path_exists(&hidden_flake)? {
            return Ok(CheckResult::Pass(format!(
                "Auto-discovered flake at {}",
                self.hidden_volume_root.join("nixos").display()
            )));
        }

        // Probe 2: /etc/nixos/flake.nix
        let etc_flake = PathBuf::from("/etc/nixos/flake.nix");
        if fs.path_exists(&etc_flake)? {
            return Ok(CheckResult::Pass(
                "Auto-discovered flake at /etc/nixos".to_string(),
            ));
        }

        // Probe 3: /etc/nixos/configuration.nix (legacy)
        let legacy_config = PathBuf::from("/etc/nixos/configuration.nix");
        if fs.path_exists(&legacy_config)? {
            return Ok(CheckResult::Pass(
                "Auto-discovered legacy config at /etc/nixos/configuration.nix".to_string(),
            ));
        }

        // Probe 4: /nix/var/nix/profiles/system
        let system_profile = PathBuf::from("/nix/var/nix/profiles/system");
        if fs.path_exists(&system_profile)? {
            return Ok(CheckResult::Pass(
                "Auto-discovered NixOS via system profile at /nix/var/nix/profiles/system"
                    .to_string(),
            ));
        }

        // Nothing found
        Ok(CheckResult::Fail(
            "No NixOS configuration found. Provide --flake or ensure /etc/nixos contains flake.nix or configuration.nix.".to_string()
        ))
    }
}

impl<F: Filesystem> PreFlightCheck<F> for NixOSBuildTargetCheck {
    fn name(&self) -> &'static str {
        "nixos-build-target"
    }

    fn description(&self) -> &'static str {
        "Validates NixOS build target reference will resolve"
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        if let Some(ref flake_ref) = self.nixos_flake {
            self.check_explicit_flake(fs, flake_ref)
        } else {
            self.check_auto_discovery(fs)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::MockFilesystem;

    // ========================================================================
    // Trait metadata
    // ========================================================================

    #[test]
    fn test_name_and_description() {
        let check = NixOSBuildTargetCheck::new(None, PathBuf::from("/mnt/hidden"));
        assert_eq!(
            PreFlightCheck::<MockFilesystem>::name(&check),
            "nixos-build-target"
        );
        assert_eq!(
            PreFlightCheck::<MockFilesystem>::description(&check),
            "Validates NixOS build target reference will resolve"
        );
    }

    // ========================================================================
    // Branch A: Explicit flake reference
    // ========================================================================

    #[test]
    fn test_explicit_flake_with_attr_all_paths_exist() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/etc/nixos", true);
        fs.mock_set_path_exists("/etc/nixos/flake.nix", true);

        let check = NixOSBuildTargetCheck::new(
            Some("/etc/nixos#amnesia-virtualbox".to_string()),
            PathBuf::from("/mnt/hidden"),
        );
        let result = check.run(&fs).unwrap();

        assert!(result.is_pass());
        assert!(result.message().contains("/etc/nixos#amnesia-virtualbox"));
        assert!(result.message().contains("attribute selection deferred"));
    }

    #[test]
    fn test_explicit_flake_without_attr() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/etc/nixos", true);
        fs.mock_set_path_exists("/etc/nixos/flake.nix", true);

        let check = NixOSBuildTargetCheck::new(
            Some("/etc/nixos".to_string()),
            PathBuf::from("/mnt/hidden"),
        );
        let result = check.run(&fs).unwrap();

        assert!(result.is_pass());
        assert!(result.message().contains("/etc/nixos"));
    }

    #[test]
    fn test_explicit_flake_relative_path() {
        let fs = MockFilesystem::new();

        let check = NixOSBuildTargetCheck::new(
            Some("etc/nixos#amnesia-virtualbox".to_string()),
            PathBuf::from("/mnt/hidden"),
        );
        let result = check.run(&fs).unwrap();

        assert!(result.is_fail());
        assert!(result.message().contains("relative"));
        assert!(result.message().contains("etc/nixos"));
        assert!(result.message().contains("absolute path"));
    }

    #[test]
    fn test_explicit_flake_directory_missing() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/nonexistent/path", false);

        let check = NixOSBuildTargetCheck::new(
            Some("/nonexistent/path#hostname".to_string()),
            PathBuf::from("/mnt/hidden"),
        );
        let result = check.run(&fs).unwrap();

        assert!(result.is_fail());
        assert!(result.message().contains("not found"));
        assert!(result.message().contains("/nonexistent/path"));
    }

    #[test]
    fn test_explicit_flake_no_flake_nix() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/etc/nixos", true);
        fs.mock_set_path_exists("/etc/nixos/flake.nix", false);

        let check = NixOSBuildTargetCheck::new(
            Some("/etc/nixos#amnesia-virtualbox".to_string()),
            PathBuf::from("/mnt/hidden"),
        );
        let result = check.run(&fs).unwrap();

        assert!(result.is_fail());
        assert!(result.message().contains("flake.nix not found"));
        assert!(result.message().contains("/etc/nixos"));
    }

    // ========================================================================
    // Branch B: Auto-discovery
    // ========================================================================

    #[test]
    fn test_auto_discovery_hidden_volume_flake() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/mnt/hidden/nixos/flake.nix", true);

        let check = NixOSBuildTargetCheck::new(None, PathBuf::from("/mnt/hidden"));
        let result = check.run(&fs).unwrap();

        assert!(result.is_pass());
        assert!(result.message().contains("Auto-discovered flake"));
        assert!(result.message().contains("/mnt/hidden/nixos"));
    }

    #[test]
    fn test_auto_discovery_etc_nixos_flake() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/mnt/hidden/nixos/flake.nix", false);
        fs.mock_set_path_exists("/etc/nixos/flake.nix", true);

        let check = NixOSBuildTargetCheck::new(None, PathBuf::from("/mnt/hidden"));
        let result = check.run(&fs).unwrap();

        assert!(result.is_pass());
        assert!(
            result
                .message()
                .contains("Auto-discovered flake at /etc/nixos")
        );
    }

    #[test]
    fn test_auto_discovery_legacy_configuration_nix() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/mnt/hidden/nixos/flake.nix", false);
        fs.mock_set_path_exists("/etc/nixos/flake.nix", false);
        fs.mock_set_path_exists("/etc/nixos/configuration.nix", true);

        let check = NixOSBuildTargetCheck::new(None, PathBuf::from("/mnt/hidden"));
        let result = check.run(&fs).unwrap();

        assert!(result.is_pass());
        assert!(result.message().contains("legacy config"));
        assert!(result.message().contains("configuration.nix"));
    }

    #[test]
    fn test_auto_discovery_system_profile() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/mnt/hidden/nixos/flake.nix", false);
        fs.mock_set_path_exists("/etc/nixos/flake.nix", false);
        fs.mock_set_path_exists("/etc/nixos/configuration.nix", false);
        fs.mock_set_path_exists("/nix/var/nix/profiles/system", true);

        let check = NixOSBuildTargetCheck::new(None, PathBuf::from("/mnt/hidden"));
        let result = check.run(&fs).unwrap();

        assert!(result.is_pass());
        assert!(result.message().contains("system profile"));
    }

    #[test]
    fn test_auto_discovery_nothing_found() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/mnt/hidden/nixos/flake.nix", false);
        fs.mock_set_path_exists("/etc/nixos/flake.nix", false);
        fs.mock_set_path_exists("/etc/nixos/configuration.nix", false);
        fs.mock_set_path_exists("/nix/var/nix/profiles/system", false);

        let check = NixOSBuildTargetCheck::new(None, PathBuf::from("/mnt/hidden"));
        let result = check.run(&fs).unwrap();

        assert!(result.is_fail());
        assert!(result.message().contains("No NixOS configuration found"));
        assert!(result.message().contains("--flake"));
    }
}
