//! Suspicious NAILS/base-config reference pre-flight check.

use super::super::{CheckResult, PreFlightCheck};
use crate::{Filesystem, Result, verify_base_config_clean};

/// Validates the base hardware configuration is forensically clean before activation starts.
#[derive(Debug, Clone, Copy, Default)]
pub struct SuspiciousNailsReferenceCheck;

impl<F: Filesystem> PreFlightCheck<F> for SuspiciousNailsReferenceCheck {
    fn name(&self) -> &'static str {
        "suspicious-nails-reference"
    }

    fn description(&self) -> &'static str {
        "Fails before activation if the base hardware configuration contains suspicious hidden or NAILS references"
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        match verify_base_config_clean(fs)? {
            true => Ok(CheckResult::Pass(
                "Base hardware-configuration.nix contains no suspicious hidden or NAILS references"
                    .into(),
            )),
            false => Ok(CheckResult::Fail(
                "Base /etc/nixos/hardware-configuration.nix contains suspicious hidden or NAILS references. Refusing activation before any side effects.".into(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::MockFilesystem;

    #[test]
    fn suspicious_reference_check_passes_for_clean_base_config() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
        fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");
        fs.mock_set_file_content(
            "/etc/nixos/hardware-configuration.nix",
            "{ config, lib, pkgs, ... }: { }",
        );

        let result = SuspiciousNailsReferenceCheck.run(&fs).unwrap();
        assert!(result.is_pass());
    }

    #[test]
    fn suspicious_reference_check_fails_for_dirty_base_config() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
        fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");
        fs.mock_set_file_content(
            "/etc/nixos/hardware-configuration.nix",
            "{ imports = [ ./nails/configuration.nix ]; }",
        );

        let result = SuspiciousNailsReferenceCheck.run(&fs).unwrap();
        assert!(result.is_fail());
        assert!(result.message().contains("before any side effects"));
    }

    #[test]
    fn suspicious_reference_check_metadata_is_stable() {
        let check = SuspiciousNailsReferenceCheck;
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
