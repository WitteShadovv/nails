// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The declarative config layer: the NixOS-only part of the session.
//!
//! On NixOS the hidden session can run its own system toplevel, built from a
//! hidden configuration (ADR 0008, section 3). [`ConfigLayer`] is the seam for
//! what that needs before the entry: staging the hidden configuration in the
//! root upper's `/etc/nixos`, and the pre-flight checks that inspect it. A host
//! without a layer (FHS / Debian) never runs them; its hidden configuration is
//! whatever the upper's `/etc` holds. The build and the activation of the hidden
//! toplevel are in `nails_session::session::nixos`.

use std::path::Path;

use crate::Result;
use crate::filesystem::Filesystem;
use crate::hidden_root::Allow;
use crate::nixos::{stage_hidden_config_symlink, stage_hidden_nixos_config};
use crate::preflight::{NixOSConfigCheck, PreFlightCheck, SuspiciousNailsReferenceCheck};

/// The platform-specific preparation of the hidden configuration.
pub trait ConfigLayer<F: Filesystem>: std::fmt::Debug + Send + Sync {
    /// The gate that refuses a base (decoy) configuration that references the
    /// hidden environment.
    fn base_reference_check(&self, hidden_volume_root: &Path) -> Box<dyn PreFlightCheck<F>>;

    /// The checks that inspect the staged hidden configuration.
    fn preflight_checks(&self, hidden_volume_root: &Path) -> Vec<Box<dyn PreFlightCheck<F>>>;

    /// Stage the hidden configuration on the hidden volume.
    /// `allow` is what the operator accepted of the attach gate's refusals.
    fn stage(
        &self,
        fs: &F,
        hidden_volume_root: &Path,
        overlay_only: bool,
        allow: Allow,
    ) -> Result<()>;

    /// Stage only the link from the hidden `/etc/nixos` to the hidden module.
    fn stage_symlink(&self, fs: &F, hidden_volume_root: &Path) -> Result<()>;
}

/// The NixOS declarative config layer — the only implementation today.
#[derive(Debug, Clone, Copy, Default)]
pub struct NixOsConfigLayer;

impl<F: Filesystem> ConfigLayer<F> for NixOsConfigLayer {
    fn base_reference_check(&self, hidden_volume_root: &Path) -> Box<dyn PreFlightCheck<F>> {
        Box::new(SuspiciousNailsReferenceCheck::new(
            hidden_volume_root.to_path_buf(),
        ))
    }

    fn preflight_checks(&self, hidden_volume_root: &Path) -> Vec<Box<dyn PreFlightCheck<F>>> {
        vec![Box::new(NixOSConfigCheck::new(
            hidden_volume_root.to_path_buf(),
        ))]
    }

    fn stage(
        &self,
        fs: &F,
        hidden_volume_root: &Path,
        overlay_only: bool,
        allow: Allow,
    ) -> Result<()> {
        stage_hidden_nixos_config(fs, hidden_volume_root, overlay_only, allow)
    }

    fn stage_symlink(&self, fs: &F, hidden_volume_root: &Path) -> Result<()> {
        stage_hidden_config_symlink(fs, hidden_volume_root)
    }
}

/// The NixOS layer's own checks against NixOS host fixtures.
#[cfg(test)]
mod nixos_layer_tests {
    use super::*;
    use crate::filesystem::{MockFilesystem, PathKind};

    const LIVE_HARDWARE: &str = "/etc/nixos/hardware-configuration.nix";

    /// The layer's base-config gate refuses a base configuration that already
    /// references the hidden environment, and passes a clean one.
    #[test]
    fn base_reference_check_refuses_a_dirty_base() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_type(LIVE_HARDWARE, PathKind::File);
        fs.mock_set_files_with_pattern("/etc/nixos", ".nix", &[Path::new(LIVE_HARDWARE)]);
        let gate = ConfigLayer::<MockFilesystem>::base_reference_check(
            &NixOsConfigLayer,
            Path::new("/mnt/hidden"),
        );
        assert_eq!(gate.name(), "suspicious-nails-reference");

        fs.mock_set_file_content(LIVE_HARDWARE, "{ config, lib, pkgs, ... }:\n{ }");
        assert!(gate.run(&fs).unwrap().is_pass());

        fs.mock_set_file_content(
            LIVE_HARDWARE,
            "{ imports = [ /mnt/hidden/nixos/configuration.nix ]; }",
        );
        assert!(gate.run(&fs).unwrap().is_fail());
    }

    #[test]
    fn preflight_checks_validate_the_staged_hidden_config() {
        let checks = ConfigLayer::<MockFilesystem>::preflight_checks(
            &NixOsConfigLayer,
            Path::new("/mnt/hidden"),
        );
        let names: Vec<_> = checks.iter().map(|check| check.name()).collect();
        assert_eq!(names, vec!["nixos-config"]);
    }
}
