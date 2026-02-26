//! Output formatting for the verify command

/// Print verification results in human-readable format
///
/// This function is pub(crate) to enable testing of the output formatting.
pub fn print_verify_result(result: &nails_core::VerifyResult) {
    use colored::Colorize;
    use nails_core::{Severity, VerifyStatus};

    // Print header
    match result.status {
        VerifyStatus::Secure => {
            println!(
                "{}",
                "✓ SECURE: No traces found. System appears clean."
                    .green()
                    .bold()
            );
        }
        VerifyStatus::Warning => {
            println!(
                "{}",
                format!(
                    "⚠ WARNING: Found {} potential issues",
                    result.findings.len()
                )
                .yellow()
                .bold()
            );
        }
        VerifyStatus::Critical => {
            println!(
                "{}",
                format!(
                    "✗ CRITICAL: Found {} artifacts requiring attention",
                    result.findings.len()
                )
                .red()
                .bold()
            );
        }
    }

    // Print scan depth info
    match result.scan_depth {
        nails_core::ScanDepth::Deep => {
            println!(
                "{}",
                "Deep scan enabled - comprehensive validation".dimmed()
            );
        }
        nails_core::ScanDepth::Standard => {}
    }

    // Print findings
    if !result.findings.is_empty() {
        println!();
        for finding in &result.findings {
            let severity_str = match finding.severity {
                Severity::Info => "[INFO]".blue(),
                Severity::Warn => "[WARN]".yellow(),
                Severity::Critical => "[CRIT]".red(),
            };

            println!(
                "{} [{}] {}",
                severity_str, finding.category, finding.message
            );

            if let Some(ref guidance) = finding.fix_guidance {
                println!("  → {}", guidance.dimmed());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nails_core::{Finding, ScanDepth, Severity, VerifyResult, VerifyStatus};

    #[test]
    fn test_print_verify_result_secure_status() {
        // Test that secure status prints correctly
        let result = VerifyResult::new(VerifyStatus::Secure, vec![], ScanDepth::Standard);
        // This will print to stdout - we're testing it doesn't panic and covers the code path
        print_verify_result(&result);
    }

    #[test]
    fn test_print_verify_result_warning_status() {
        // Test warning status with findings
        let findings = vec![
            Finding::new(Severity::Warn, "file", "Artifact found")
                .with_fix_guidance("Delete the file"),
        ];
        let result = VerifyResult::new(VerifyStatus::Warning, findings, ScanDepth::Standard);
        print_verify_result(&result);
    }

    #[test]
    fn test_print_verify_result_critical_status() {
        // Test critical status with findings
        let findings = vec![
            Finding::new(Severity::Critical, "mount", "Overlay mount found"),
            Finding::new(Severity::Warn, "file", "Artifact file found"),
        ];
        let result = VerifyResult::new(VerifyStatus::Critical, findings, ScanDepth::Standard);
        print_verify_result(&result);
    }

    #[test]
    fn test_print_verify_result_deep_scan() {
        // Test deep scan depth message
        let result = VerifyResult::new(VerifyStatus::Secure, vec![], ScanDepth::Deep);
        print_verify_result(&result);
    }

    #[test]
    fn test_print_verify_result_all_severity_levels() {
        // Test all severity levels in findings
        let findings = vec![
            Finding::new(Severity::Info, "memory", "RAM may retain data"),
            Finding::new(Severity::Warn, "file", "Artifact found")
                .with_fix_guidance("Delete artifact"),
            Finding::new(Severity::Critical, "mount", "Overlay mounted")
                .with_fix_guidance("Run nails deactivate"),
        ];
        let result = VerifyResult::new(VerifyStatus::Critical, findings, ScanDepth::Deep);
        print_verify_result(&result);
    }

    #[test]
    fn test_print_verify_result_finding_without_fix_guidance() {
        // Test finding without fix guidance (None path)
        let findings = vec![Finding::new(
            Severity::Info,
            "memory",
            "RAM may retain data briefly",
        )];
        let result = VerifyResult::new(VerifyStatus::Secure, findings, ScanDepth::Standard);
        print_verify_result(&result);
    }

    #[test]
    fn test_print_verify_result_empty_findings() {
        // Test with empty findings array
        let result = VerifyResult::new(VerifyStatus::Secure, vec![], ScanDepth::Standard);
        print_verify_result(&result);
    }

    #[test]
    fn test_print_verify_result_multiple_findings_same_category() {
        // Test multiple findings in same category
        let findings = vec![
            Finding::new(Severity::Warn, "file", "Artifact 1").with_fix_guidance("Delete file 1"),
            Finding::new(Severity::Warn, "file", "Artifact 2").with_fix_guidance("Delete file 2"),
            Finding::new(Severity::Warn, "file", "Artifact 3"),
        ];
        let result = VerifyResult::new(VerifyStatus::Warning, findings, ScanDepth::Standard);
        print_verify_result(&result);
    }

    #[test]
    fn test_print_verify_result_standard_scan_no_depth_message() {
        // Test that standard scan doesn't print depth message
        let result = VerifyResult::new(VerifyStatus::Secure, vec![], ScanDepth::Standard);
        print_verify_result(&result);
    }

    #[test]
    fn test_print_verify_result_warning_with_single_finding() {
        // Edge case: warning status with exactly 1 finding
        let findings = vec![Finding::new(Severity::Warn, "test", "Single warning")];
        let result = VerifyResult::new(VerifyStatus::Warning, findings, ScanDepth::Standard);
        print_verify_result(&result);
    }

    #[test]
    fn test_print_verify_result_critical_with_many_findings() {
        // Edge case: critical status with many findings
        let findings: Vec<Finding> = (0..10)
            .map(|i| {
                Finding::new(
                    Severity::Critical,
                    format!("category{}", i),
                    format!("Finding {}", i),
                )
                .with_fix_guidance(format!("Fix {}", i))
            })
            .collect();
        let result = VerifyResult::new(VerifyStatus::Critical, findings, ScanDepth::Deep);
        print_verify_result(&result);
    }
}
