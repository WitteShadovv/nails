// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Suspicious NAILS/base-config reference pre-flight check.

use super::super::{CheckResult, PreFlightCheck};
use crate::{Filesystem, Result, verify_base_config_clean};
use std::path::PathBuf;

/// Validates the base hardware configuration is forensically clean before activation starts.
#[derive(Debug, Clone, Default)]
pub struct SuspiciousNailsReferenceCheck {
    hidden_volume_root: PathBuf,
}

impl SuspiciousNailsReferenceCheck {
    /// Creates a check that matches the base config against the configured hidden root.
    pub fn new(hidden_volume_root: PathBuf) -> Self {
        Self { hidden_volume_root }
    }
}

impl<F: Filesystem> PreFlightCheck<F> for SuspiciousNailsReferenceCheck {
    fn name(&self) -> &'static str {
        "suspicious-nails-reference"
    }

    fn description(&self) -> &'static str {
        "Fails before activation if the base hardware configuration contains suspicious hidden or NAILS references"
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        match verify_base_config_clean(fs, &self.hidden_volume_root)? {
            true => Ok(CheckResult::Pass(
                "Base /etc/nixos NixOS config contains no suspicious hidden or NAILS references"
                    .into(),
            )),
            false => Ok(CheckResult::fail(
                "Base /etc/nixos NixOS config contains suspicious hidden or NAILS references. Refusing activation before any side effects.".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::{MockFilesystem, PathKind};
    use std::path::Path;

    fn register_base_config(fs: &MockFilesystem, content: &str) {
        let path = "/etc/nixos/hardware-configuration.nix";
        fs.mock_set_path_exists(path, true);
        fs.mock_set_path_type(path, PathKind::File);
        fs.mock_set_file_content(path, content);
        fs.mock_set_files_with_pattern("/etc/nixos", ".nix", &[Path::new(path)]);
    }

    #[test]
    fn suspicious_reference_check_passes_for_clean_base_config() {
        let fs = MockFilesystem::new();
        register_base_config(&fs, "{ config, lib, pkgs, ... }: { }");

        let check = SuspiciousNailsReferenceCheck::new(PathBuf::from("/mnt/hidden"));
        let result = check.run(&fs).unwrap();
        assert!(result.is_pass());
    }

    #[test]
    fn suspicious_reference_check_fails_for_dirty_base_config() {
        let fs = MockFilesystem::new();
        register_base_config(&fs, "{ imports = [ ./nails/configuration.nix ]; }");

        let check = SuspiciousNailsReferenceCheck::new(PathBuf::from("/mnt/hidden"));
        let result = check.run(&fs).unwrap();
        assert!(result.is_fail());
        assert!(result.message().contains("before any side effects"));
    }

    #[test]
    fn suspicious_reference_check_metadata_is_stable() {
        let check = SuspiciousNailsReferenceCheck::default();
        assert_eq!(
            <SuspiciousNailsReferenceCheck as PreFlightCheck<MockFilesystem>>::name(&check),
            "suspicious-nails-reference"
        );
        assert!(
            <SuspiciousNailsReferenceCheck as PreFlightCheck<MockFilesystem>>::description(&check)
                .contains("before activation")
        );
    }
}
