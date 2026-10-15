// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Suspicious NAILS/base-config reference pre-flight check.

use super::{CheckResult, PreFlightCheck};
use crate::nixos::config::BaseConfigScan;
use crate::{Filesystem, Result, verify_base_config_clean};
use std::path::PathBuf;

/// Refuses activation while the decoy's own `/etc/nixos` names the hidden
/// environment: the hidden volume's device or mount point (or the units
/// systemd names after them), its mapping where a line opens it, or NAILS.
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
        "Fails before activation if the decoy's /etc/nixos names the hidden volume, its device or mount point, or NAILS"
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        let scan = verify_base_config_clean(fs, &self.hidden_volume_root)?;
        Ok(scan_result(&scan))
    }
}

/// The check result for a scan: the first reference with its file, line,
/// text, reason and remedy, or what was read.
fn scan_result(scan: &BaseConfigScan) -> CheckResult {
    let Some(first) = scan.references.first() else {
        return CheckResult::Pass(match scan.files_read {
            0 => "No .nix file under /etc/nixos, so nothing was inspected; a configuration \
                  kept elsewhere is not checked"
                .to_string(),
            1 => "The one .nix file under /etc/nixos names nothing of the hidden environment"
                .to_string(),
            files => {
                format!(
                    "The {files} .nix files under /etc/nixos name nothing of the hidden environment"
                )
            }
        });
    };
    let more = match scan.references.len() - 1 {
        0 => String::new(),
        1 => " One more line does too.".to_string(),
        lines => format!(" {lines} more lines do too."),
    };
    CheckResult::fail_with(
        format!(
            "The decoy's /etc/nixos names the hidden environment: {}, line {}: '{}' ({}). An \
             examination of the decoy reads this file.{more}",
            first.file.display(),
            first.line,
            first.text,
            first.kind.reason()
        ),
        first.kind.remedy(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::MockFilesystem;
    use std::path::Path;

    fn run_on(files: &[(&str, &str)]) -> CheckResult {
        let fs = MockFilesystem::new();
        for (path, content) in files {
            fs.mock_set_file_content(path, content);
        }
        let paths: Vec<&Path> = files.iter().map(|(path, _)| Path::new(*path)).collect();
        fs.mock_set_files_with_pattern("/etc/nixos", ".nix", &paths);
        SuspiciousNailsReferenceCheck::new(PathBuf::from("/mnt/hidden"))
            .run(&fs)
            .unwrap()
    }

    #[test]
    fn a_clean_base_config_passes_and_says_what_was_read() {
        let one = run_on(&[(
            "/etc/nixos/hardware-configuration.nix",
            "{ config, lib, pkgs, ... }: { }",
        )]);
        assert!(one.is_pass());
        assert!(one.message().contains("one .nix file"), "{one:?}");

        let two = run_on(&[
            ("/etc/nixos/configuration.nix", "{ }"),
            ("/etc/nixos/hardware-configuration.nix", "{ }"),
        ]);
        assert!(two.is_pass());
        assert!(two.message().contains("The 2 .nix files"), "{two:?}");
    }

    /// Without a `.nix` file the check passes but says it inspected nothing,
    /// instead of claiming the configuration is clean.
    #[test]
    fn no_nix_file_passes_and_says_nothing_was_inspected() {
        let result = run_on(&[]);
        assert!(result.is_pass());
        assert!(
            result.message().contains("nothing was inspected"),
            "{result:?}"
        );
    }

    #[test]
    fn a_reference_fails_with_its_file_line_text_reason_and_remedy() {
        let result = run_on(&[(
            "/etc/nixos/hardware-configuration.nix",
            "{\n  imports = [ ./nails/configuration.nix ];\n}\n",
        )]);
        assert!(result.is_fail());
        let message = result.message();
        for part in [
            "/etc/nixos/hardware-configuration.nix, line 2",
            "'./nails/configuration.nix'",
            "(text NAILS writes during a session)",
        ] {
            assert!(message.contains(part), "{part} missing: {message}");
        }
        assert!(!message.contains("more line"), "{message}");
        assert!(
            result
                .remediation()
                .is_some_and(|remedy| remedy.starts_with("Remove it from that file")),
            "{result:?}"
        );
    }

    #[test]
    fn further_references_are_counted() {
        let result = run_on(&[
            ("/etc/nixos/a.nix", "{ config.nails.enable = true; }"),
            (
                "/etc/nixos/b.nix",
                "{\n  fileSystems.\"/mnt/hidden\" = { };\n  x = \"mnt-hidden.mount\";\n  y = \"plausible\";\n}",
            ),
        ]);
        assert!(result.is_fail());
        assert!(result.message().contains("/etc/nixos/a.nix, line 1"));
        assert!(
            result.message().ends_with(" 2 more lines do too."),
            "{result:?}"
        );

        let result = run_on(&[(
            "/etc/nixos/a.nix",
            "{ x = /mnt/hidden;\n y = /mnt/hidden; }",
        )]);
        assert!(
            result.message().ends_with(" One more line does too."),
            "{result:?}"
        );
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
                .contains("decoy's /etc/nixos")
        );
    }
}
