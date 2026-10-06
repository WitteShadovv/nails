// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! NixOS build target validation pre-flight check
//!
//! Validates that the NixOS build target (flake reference or legacy config)
//! will resolve before any destructive operations begin.

use super::super::{CheckResult, PreFlightCheck};
use crate::nixos::{resolve_local_flake_dir, split_flake_ref};
use crate::platform::HostTarget;
use crate::{Filesystem, Result};
use std::path::{Path, PathBuf};

/// Validates the NixOS build target reference will resolve
///
/// When an explicit `--flake` is provided, validates:
/// - The path is absolute (not relative)
/// - The directory exists
/// - The directory contains a `flake.nix`
///
/// When no flake is specified, it reports the target the host's platform
/// discovered ([`discover_host_target`](crate::platform::discover_host_target)),
/// the same answer activation and `check`/`--dry-run` use, and fails when the
/// platform found none.
///
/// This is separate from `NixOSConfigCheck` which validates the hidden storage
/// overlay structure (symlinks, imports). This check validates the build target
/// reference itself.
#[derive(Debug, Clone)]
pub struct NixOSBuildTargetCheck {
    nixos_flake: Option<String>,
    selected_flake_dir: Option<PathBuf>,
    discovered: HostTarget,
}

impl NixOSBuildTargetCheck {
    /// Create a new NixOSBuildTargetCheck
    ///
    /// # Arguments
    ///
    /// * `nixos_flake` - Optional flake reference from config/CLI (e.g., "/etc/nixos#hostname")
    /// * `discovered` - The build target the host's platform discovered
    pub fn new(nixos_flake: Option<String>, discovered: HostTarget) -> Self {
        Self {
            nixos_flake,
            selected_flake_dir: None,
            discovered,
        }
    }

    /// Create a new NixOSBuildTargetCheck for a pre-selected flake build target.
    ///
    /// This is used when activation has already selected a flake directory via
    /// auto-discovery. In that case preflight must validate the chosen flake
    /// directly rather than falling back to legacy detection.
    pub fn with_selected_flake_dir(
        nixos_flake: Option<String>,
        selected_flake_dir: Option<PathBuf>,
        discovered: HostTarget,
    ) -> Self {
        Self {
            nixos_flake,
            selected_flake_dir,
            discovered,
        }
    }

    /// Validate an explicit flake reference
    fn check_explicit_flake<F: Filesystem>(&self, fs: &F, flake_ref: &str) -> Result<CheckResult> {
        let (base_ref, _) = split_flake_ref(flake_ref);
        let Some(dir) = resolve_local_flake_dir(base_ref)? else {
            return Ok(CheckResult::Pass(format!(
                "Flake build target '{}' validated as a generic flake reference",
                flake_ref
            )));
        };

        // Check 2: Directory must exist
        if !fs.path_exists(&dir)? {
            return Ok(CheckResult::fail(format!(
                "Flake directory '{}' not found.",
                dir.display()
            )));
        }

        // Check 3: flake.nix must exist in directory
        let flake_nix = dir.join("flake.nix");
        if !fs.path_exists(&flake_nix)? {
            return Ok(CheckResult::fail(format!(
                "flake.nix not found in '{}'.",
                dir.display()
            )));
        }

        Ok(CheckResult::Pass(format!(
            "Flake build target '{}' validated (attribute selection deferred to build time)",
            flake_ref
        )))
    }

    fn check_selected_flake_dir<F: Filesystem>(&self, fs: &F, dir: &Path) -> Result<CheckResult> {
        if !fs.path_exists(dir)? {
            return Ok(CheckResult::fail(format!(
                "Flake directory '{}' not found.",
                dir.display()
            )));
        }

        let flake_nix = dir.join("flake.nix");
        if !fs.path_exists(&flake_nix)? {
            return Ok(CheckResult::fail(format!(
                "flake.nix not found in '{}'.",
                dir.display()
            )));
        }

        Ok(CheckResult::Pass(format!(
            "Flake build target '{}' validated",
            dir.display()
        )))
    }

    /// Report the auto-discovered build target.
    ///
    /// The target comes from the host's platform through
    /// [`discover_host_target`](crate::platform::discover_host_target), shared with
    /// activation and the `check`/`--dry-run` summary, so the pre-flight check can
    /// never disagree with the target activation would actually build. In
    /// particular a lone system profile resolves to the same legacy build target
    /// here as it does on the activation path.
    fn check_auto_discovery(&self) -> CheckResult {
        match &self.discovered {
            HostTarget::Flake(dir) => {
                CheckResult::Pass(format!("Auto-discovered flake at {}", dir.display()))
            }
            HostTarget::Legacy(path) => CheckResult::Pass(format!(
                "Auto-discovered legacy config at {}",
                path.display()
            )),
            // An explicit reference is validated by `check_explicit_flake` before
            // this runs; mapping it keeps the check total.
            HostTarget::ExplicitFlake(flake_ref) => {
                CheckResult::Pass(format!("Auto-discovered flake reference {flake_ref}"))
            }
            HostTarget::OverlayOnly => {
                CheckResult::Pass("Overlay-only: no NixOS build target".to_string())
            }
            HostTarget::None => CheckResult::fail(
                "No NixOS configuration found. Provide --nixos-flake or ensure /etc/nixos contains flake.nix or configuration.nix.".to_string()
            ),
        }
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
        } else if let Some(ref selected_flake_dir) = self.selected_flake_dir {
            self.check_selected_flake_dir(fs, selected_flake_dir)
        } else {
            Ok(self.check_auto_discovery())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::MockFilesystem;
    use crate::test_support::EnvGuard;

    // ========================================================================
    // Trait metadata
    // ========================================================================

    #[test]
    fn test_name_and_description() {
        let check = NixOSBuildTargetCheck::new(None, HostTarget::None);
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
            HostTarget::None,
        );
        let result = check.run(&fs).unwrap();

        assert!(result.is_pass());
        assert!(result.message().contains("/etc/nixos#amnesia-virtualbox"));
    }

    #[test]
    fn test_explicit_flake_without_attr() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/etc/nixos", true);
        fs.mock_set_path_exists("/etc/nixos/flake.nix", true);

        let check = NixOSBuildTargetCheck::new(Some("/etc/nixos".to_string()), HostTarget::None);
        let result = check.run(&fs).unwrap();

        assert!(result.is_pass());
        assert!(result.message().contains("/etc/nixos"));
    }

    #[test]
    fn test_explicit_generic_github_flake_ref_passes_without_local_path_checks() {
        let fs = MockFilesystem::new();

        let check = NixOSBuildTargetCheck::new(
            Some("github:owner/repo#machine".to_string()),
            HostTarget::None,
        );
        let result = check.run(&fs).unwrap();

        assert!(result.is_pass());
        assert!(result.message().contains("github:owner/repo#machine"));
    }

    #[test]
    fn test_explicit_path_scheme_flake_ref_with_query_uses_local_directory() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/some/dir", true);
        fs.mock_set_path_exists("/some/dir/flake.nix", true);

        let check = NixOSBuildTargetCheck::new(
            Some("path:/some/dir?foo=bar#machine".to_string()),
            HostTarget::None,
        );
        let result = check.run(&fs).unwrap();

        assert!(result.is_pass());
        assert!(result.message().contains("path:/some/dir?foo=bar#machine"));
    }

    #[test]
    fn test_explicit_relative_flake_ref_with_dot_slash_passes() {
        // The check resolves the relative ref against the working directory.
        let _env = EnvGuard::lock();
        let fs = MockFilesystem::new();
        let current_dir = std::env::current_dir().unwrap();
        let flake_dir = current_dir.join("relative-flake");
        let flake_nix = flake_dir.join("flake.nix");

        fs.mock_set_path_exists(&flake_dir.to_string_lossy(), true);
        fs.mock_set_path_exists(&flake_nix.to_string_lossy(), true);

        let check = NixOSBuildTargetCheck::new(
            Some("./relative-flake#host-alpha".to_string()),
            HostTarget::None,
        );
        let result = check.run(&fs).unwrap();

        assert!(result.is_pass());
        assert!(result.message().contains("./relative-flake#host-alpha"));
    }

    #[test]
    fn test_explicit_relative_current_directory_flake_ref_passes() {
        // The check resolves the relative ref against the working directory.
        let _env = EnvGuard::lock();
        let fs = MockFilesystem::new();
        let current_dir = std::env::current_dir().unwrap();
        let flake_nix = current_dir.join("flake.nix");

        fs.mock_set_path_exists(&current_dir.to_string_lossy(), true);
        fs.mock_set_path_exists(&flake_nix.to_string_lossy(), true);

        let check = NixOSBuildTargetCheck::new(Some(".#host-alpha".to_string()), HostTarget::None);
        let result = check.run(&fs).unwrap();

        assert!(result.is_pass());
        assert!(result.message().contains(".#host-alpha"));
    }

    #[test]
    fn test_explicit_flake_directory_missing() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/nonexistent/path", false);

        let check = NixOSBuildTargetCheck::new(
            Some("/nonexistent/path#hostname".to_string()),
            HostTarget::None,
        );
        let result = check.run(&fs).unwrap();

        assert!(result.is_fail());
        assert!(result.message().contains("/nonexistent/path"));
    }

    #[test]
    fn test_explicit_flake_no_flake_nix() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/etc/nixos", true);
        fs.mock_set_path_exists("/etc/nixos/flake.nix", false);

        let check = NixOSBuildTargetCheck::new(
            Some("/etc/nixos#amnesia-virtualbox".to_string()),
            HostTarget::None,
        );
        let result = check.run(&fs).unwrap();

        assert!(result.is_fail());
        assert!(result.message().contains("/etc/nixos"));
    }

    #[test]
    fn test_selected_flake_dir_no_flake_nix_does_not_fall_back_to_legacy() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/mnt/hidden/nixos", true);
        fs.mock_set_path_exists("/mnt/hidden/nixos/flake.nix", false);
        fs.mock_set_path_exists("/etc/nixos/configuration.nix", true);

        let check = NixOSBuildTargetCheck::with_selected_flake_dir(
            None,
            Some(PathBuf::from("/mnt/hidden/nixos")),
            HostTarget::None,
        );
        let result = check.run(&fs).unwrap();

        assert!(result.is_fail());
        assert!(result.message().contains("/mnt/hidden/nixos"));
        assert!(!result.message().contains("legacy"));
    }

    #[test]
    fn test_selected_flake_dir_with_flake_nix_passes() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/mnt/hidden/nixos", true);
        fs.mock_set_path_exists("/mnt/hidden/nixos/flake.nix", true);

        let check = NixOSBuildTargetCheck::with_selected_flake_dir(
            None,
            Some(PathBuf::from("/mnt/hidden/nixos")),
            HostTarget::None,
        );
        let result = check.run(&fs).unwrap();

        assert!(result.is_pass());
        assert!(result.message().contains("/mnt/hidden/nixos"));
    }

    // ========================================================================
    // Branch B: Auto-discovery (the target comes from the platform; the
    // discovery cascade itself is tested in `platform::nixos`)
    // ========================================================================

    fn auto(target: HostTarget) -> CheckResult {
        NixOSBuildTargetCheck::new(None, target)
            .run(&MockFilesystem::new())
            .unwrap()
    }

    #[test]
    fn test_auto_discovery_reports_discovered_flake() {
        let result = auto(HostTarget::Flake(PathBuf::from("/mnt/hidden/nixos")));
        assert!(result.is_pass());
        assert!(result.message().contains("/mnt/hidden/nixos"));
    }

    #[test]
    fn test_auto_discovery_reports_discovered_legacy_config() {
        let result = auto(HostTarget::Legacy(PathBuf::from("/cfg/configuration.nix")));
        assert!(result.is_pass());
        assert!(result.message().contains("/cfg/configuration.nix"));
    }

    #[test]
    fn test_auto_discovery_overlay_only_and_explicit_pass() {
        assert!(auto(HostTarget::OverlayOnly).is_pass());
        let result = auto(HostTarget::ExplicitFlake("gh:me/cfg".into()));
        assert!(result.is_pass());
        assert!(result.message().contains("gh:me/cfg"));
    }

    #[test]
    fn test_auto_discovery_nothing_found() {
        let result = auto(HostTarget::None);
        assert!(result.is_fail());
        assert!(result.message().contains("--nixos-flake"));
    }

    /// The check reports the platform's answer, not a filesystem probe of its
    /// own: NixOS files on disk cannot override what the platform discovered.
    #[test]
    fn test_auto_discovery_does_not_probe_the_filesystem() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/etc/nixos/flake.nix", true);
        let result = NixOSBuildTargetCheck::new(None, HostTarget::None)
            .run(&fs)
            .unwrap();
        assert!(result.is_fail());
    }
}
