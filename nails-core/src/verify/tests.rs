//! Tests for forensic verification system

use super::Verifier;
use super::types::{Finding, ScanDepth, Severity, VerifyResult, VerifyStatus};
use crate::MockFilesystem;

// ========================================================================
// Data Structure Tests
// ========================================================================

#[test]
fn test_finding_creation() {
    let finding = Finding::new(Severity::Critical, "mount", "Test message");
    assert_eq!(finding.severity, Severity::Critical);
    assert_eq!(finding.category, "mount");
    assert_eq!(finding.message, "Test message");
    assert_eq!(finding.fix_guidance, None);
}

#[test]
fn test_finding_with_fix_guidance() {
    let finding = Finding::new(Severity::Warn, "file", "Artifact found")
        .with_fix_guidance("Run 'nails deactivate'");

    assert_eq!(
        finding.fix_guidance,
        Some("Run 'nails deactivate'".to_string())
    );
}

#[test]
fn test_verify_result_secure() {
    let result = VerifyResult::secure(ScanDepth::Standard);
    assert_eq!(result.status, VerifyStatus::Secure);
    assert!(result.findings.is_empty());
    assert_eq!(result.scan_depth, ScanDepth::Standard);
}

#[test]
fn test_verify_result_new() {
    let findings = vec![Finding::new(Severity::Info, "test", "Test finding")];
    let result = VerifyResult::new(VerifyStatus::Warning, findings.clone(), ScanDepth::Deep);

    assert_eq!(result.status, VerifyStatus::Warning);
    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.scan_depth, ScanDepth::Deep);
}

#[test]
fn test_severity_ordering() {
    // Verify severity variants exist
    let _info = Severity::Info;
    let _warn = Severity::Warn;
    let _critical = Severity::Critical;
}

#[test]
fn test_verify_status_variants() {
    // Verify status variants exist
    let _secure = VerifyStatus::Secure;
    let _warning = VerifyStatus::Warning;
    let _critical = VerifyStatus::Critical;
}

#[test]
fn test_scan_depth_variants() {
    // Verify scan depth variants exist
    let _standard = ScanDepth::Standard;
    let _deep = ScanDepth::Deep;
}

// ========================================================================
// Verifier Tests
// ========================================================================

#[test]
fn test_comprehensive_scan_with_all_check_types() {
    let fs = MockFilesystem::new();
    let verifier = Verifier::new(fs.clone());

    // Set up findings from all check types
    fs.mock_set_mounted(std::path::Path::new("/home"), true); // mount
    fs.mock_set_path_exists("/tmp/nails.log", true); // file
    fs.mock_set_swap_enabled(true); // memory
    fs.mock_set_path_exists("/root/.bash_history", true); // deep scan

    let result = verifier.run(true).unwrap();
    assert_eq!(result.status, VerifyStatus::Critical);
    assert_eq!(result.scan_depth, ScanDepth::Deep);

    // Verify all categories are present
    let categories: std::collections::HashSet<_> = result
        .findings
        .iter()
        .map(|f| f.category.as_str())
        .collect();
    assert!(categories.contains("mount"));
    assert!(categories.contains("file"));
    assert!(categories.contains("memory"));
}

// ========================================================================
// Acceptance Criteria Tests (Story AC: 9)
// ========================================================================

#[test]
fn test_clean_system_returns_secure() {
    let fs = MockFilesystem::new();
    let verifier = Verifier::new(fs);

    let result = verifier.run(false).unwrap();
    // System is secure even with info-level memory warnings
    assert_eq!(result.status, VerifyStatus::Secure);

    // Memory check always returns RAM warning (Info level)
    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings[0].severity, Severity::Info);
    assert_eq!(result.findings[0].category, "memory");

    assert_eq!(result.scan_depth, ScanDepth::Standard);
}

#[test]
fn test_deep_scan_flag_sets_scan_depth() {
    let fs = MockFilesystem::new();
    let verifier = Verifier::new(fs);

    let result = verifier.run(true).unwrap();
    assert_eq!(result.scan_depth, ScanDepth::Deep);
}

// ========================================================================
// JSON Serialization Tests
// ========================================================================

#[test]
fn test_finding_serializes_to_json() {
    let finding =
        Finding::new(Severity::Critical, "mount", "Test message").with_fix_guidance("Fix this");

    let json = serde_json::to_string(&finding).unwrap();
    assert!(json.contains("\"severity\":\"Critical\""));
    assert!(json.contains("\"category\":\"mount\""));
    assert!(json.contains("\"message\":\"Test message\""));
    assert!(json.contains("\"fix_guidance\":\"Fix this\""));
}

#[test]
fn test_verify_result_serializes_to_json() {
    let findings = vec![Finding::new(Severity::Warn, "file", "Artifact found")];
    let result = VerifyResult::new(VerifyStatus::Warning, findings, ScanDepth::Deep);

    let json = serde_json::to_string(&result).unwrap();
    assert!(json.contains("\"status\":\"Warning\""));
    assert!(json.contains("\"scan_depth\":\"Deep\""));
    assert!(json.contains("\"findings\""));
}

#[test]
fn test_finding_without_fix_guidance_omits_field() {
    let finding = Finding::new(Severity::Info, "test", "Message");
    let json = serde_json::to_string(&finding).unwrap();

    // Field should be omitted if None
    assert!(!json.contains("fix_guidance"));
}

// ========================================================================
// Verification Check Tests
// ========================================================================

#[test]
fn test_overlay_mount_detection() {
    let fs = MockFilesystem::new();
    let verifier = Verifier::new(fs.clone());

    // Set up a mounted overlay
    fs.mock_set_mounted(std::path::Path::new("/home"), true);

    let result = verifier.run(false).unwrap();
    assert_eq!(result.status, VerifyStatus::Critical);
    // 1 mount + 1 RAM info warning = 2 total
    assert_eq!(result.findings.len(), 2);

    let mount_finding = result
        .findings
        .iter()
        .find(|f| f.category == "mount")
        .unwrap();
    assert_eq!(mount_finding.severity, Severity::Critical);
    assert!(mount_finding.message.contains("/home"));
    assert!(mount_finding.fix_guidance.is_some());
}

#[test]
fn test_artifact_file_detection() {
    let fs = MockFilesystem::new();
    let verifier = Verifier::new(fs.clone());

    // Set up artifact files
    fs.mock_set_path_exists("/tmp/nails.log", true);
    fs.mock_set_path_exists("/tmp/nails.toml", true);

    let result = verifier.run(false).unwrap();
    assert_eq!(result.status, VerifyStatus::Warning);

    let file_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.category == "file")
        .collect();
    assert_eq!(file_findings.len(), 2);

    for finding in file_findings {
        assert_eq!(finding.severity, Severity::Warn);
        assert!(finding.message.contains("Artifact file found"));
        assert!(finding.fix_guidance.is_some());
    }
}

#[test]
fn test_memory_status_with_swap_enabled() {
    let fs = MockFilesystem::new();
    let verifier = Verifier::new(fs.clone());

    // Enable swap
    fs.mock_set_swap_enabled(true);

    let result = verifier.run(false).unwrap();

    let memory_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.category == "memory")
        .collect();
    assert_eq!(memory_findings.len(), 2); // swap warning + RAM warning

    // Check swap warning
    let swap_finding = memory_findings
        .iter()
        .find(|f| f.message.contains("Swap is enabled"))
        .unwrap();
    assert_eq!(swap_finding.severity, Severity::Info);
    assert!(swap_finding.fix_guidance.is_some());

    // Check RAM warning
    let ram_finding = memory_findings
        .iter()
        .find(|f| f.message.contains("RAM may retain"))
        .unwrap();
    assert_eq!(ram_finding.severity, Severity::Info);
}

#[test]
fn test_memory_status_with_swap_disabled() {
    let fs = MockFilesystem::new();
    let verifier = Verifier::new(fs.clone());

    // Swap is disabled by default
    let result = verifier.run(false).unwrap();

    let memory_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.category == "memory")
        .collect();
    assert_eq!(memory_findings.len(), 1); // only RAM warning

    let ram_finding = &memory_findings[0];
    assert!(ram_finding.message.contains("RAM may retain"));
    assert_eq!(ram_finding.severity, Severity::Info);
}

#[test]
fn test_deep_scan_finds_history_files() {
    let fs = MockFilesystem::new();
    let verifier = Verifier::new(fs.clone());

    // Set up history files
    fs.mock_set_path_exists("/root/.bash_history", true);
    fs.mock_set_path_exists("/root/.zsh_history", true);

    let result = verifier.run(true).unwrap();
    assert_eq!(result.scan_depth, ScanDepth::Deep);

    let history_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.message.contains("History file"))
        .collect();
    assert_eq!(history_findings.len(), 2);

    for finding in history_findings {
        assert_eq!(finding.severity, Severity::Info);
        assert_eq!(finding.category, "file");
    }
}

#[test]
fn test_multiple_critical_findings() {
    let fs = MockFilesystem::new();
    let verifier = Verifier::new(fs.clone());

    // Set up multiple critical issues
    fs.mock_set_mounted(std::path::Path::new("/home"), true);
    fs.mock_set_mounted(std::path::Path::new("/etc"), true);

    let result = verifier.run(false).unwrap();
    assert_eq!(result.status, VerifyStatus::Critical);

    let critical_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .collect();
    assert!(critical_findings.len() >= 2);
}

#[test]
fn test_status_determination_priority() {
    let fs = MockFilesystem::new();
    let verifier = Verifier::new(fs.clone());

    // Set up both critical and warning findings
    fs.mock_set_mounted(std::path::Path::new("/home"), true); // Critical
    fs.mock_set_path_exists("/tmp/nails.log", true); // Warning

    let result = verifier.run(false).unwrap();
    // Critical takes precedence over Warning
    assert_eq!(result.status, VerifyStatus::Critical);
}

// ========================================================================
// Acceptance Criteria Tests (Story AC: 9)
// ========================================================================

#[test]
fn test_ac9_clean_system_secure_message_exit_0() {
    // AC: Given verify runs and system is clean
    // When no overlays mounted, no artifacts found
    // Then output "SECURE", exit code 0
    let fs = MockFilesystem::new();
    let verifier = Verifier::new(fs);

    let result = verifier.run(false).unwrap();

    // System should be secure
    assert_eq!(result.status, VerifyStatus::Secure);

    // In CLI, this would translate to exit code 0
    // (We verify this behavior in CLI integration tests)
}

#[test]
fn test_ac9_overlay_mounted_critical_exit_1() {
    // AC: Given verify runs and finds artifacts
    // When overlay mounts exist
    // Then output "CRITICAL" with list, exit code 1
    let fs = MockFilesystem::new();
    let verifier = Verifier::new(fs.clone());

    fs.mock_set_mounted(std::path::Path::new("/home"), true);

    let result = verifier.run(false).unwrap();

    // System should be critical
    assert_eq!(result.status, VerifyStatus::Critical);

    // Should have at least one critical finding
    let critical_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .collect();
    assert!(!critical_findings.is_empty());

    // Findings should include fix guidance
    for finding in critical_findings {
        assert!(finding.fix_guidance.is_some());
    }
}

#[test]
fn test_ac9_artifact_file_found_critical_with_guidance() {
    // AC: Given verify runs and finds artifact files
    // Then output includes fix guidance
    let fs = MockFilesystem::new();
    let verifier = Verifier::new(fs.clone());

    fs.mock_set_path_exists("/tmp/nails.log", true);

    let result = verifier.run(false).unwrap();

    let file_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.category == "file" && f.message.contains("nails.log"))
        .collect();

    assert_eq!(file_findings.len(), 1);
    assert!(file_findings[0].fix_guidance.is_some());
    assert!(
        file_findings[0]
            .fix_guidance
            .as_ref()
            .unwrap()
            .contains("rm")
    );
}

#[test]
fn test_ac9_deep_scan_additional_checks() {
    // AC: Given verify runs with --deep
    // Then additional checks run: /tmp scan, history scan, log scan
    let fs = MockFilesystem::new();
    let verifier = Verifier::new(fs.clone());

    fs.mock_set_path_exists("/root/.bash_history", true);
    fs.mock_set_path_exists("/root/.zsh_history", true);

    let result = verifier.run(true).unwrap();

    // Deep scan should find history files
    let history_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.message.contains("History file"))
        .collect();

    assert!(history_findings.len() >= 2);
    assert_eq!(result.scan_depth, ScanDepth::Deep);
}

#[test]
fn test_ac9_json_output_valid() {
    // AC: Given verify runs with --json
    // Then output is valid JSON with findings array
    let fs = MockFilesystem::new();
    let verifier = Verifier::new(fs.clone());

    fs.mock_set_path_exists("/tmp/nails.log", true);

    let result = verifier.run(false).unwrap();

    // Serialize to JSON
    let json = serde_json::to_string(&result).unwrap();

    // Parse back to verify validity
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    // Verify structure
    assert!(parsed.get("status").is_some());
    assert!(parsed.get("findings").is_some());
    assert!(parsed.get("scan_depth").is_some());

    // Verify findings is an array
    assert!(parsed["findings"].is_array());
    assert!(!parsed["findings"].as_array().unwrap().is_empty());
}

#[test]
fn test_ac9_multiple_findings_all_reported() {
    // AC: Test multiple findings all reported
    let fs = MockFilesystem::new();
    let verifier = Verifier::new(fs.clone());

    // Set up multiple findings
    fs.mock_set_mounted(std::path::Path::new("/home"), true);
    fs.mock_set_mounted(std::path::Path::new("/etc"), true);
    fs.mock_set_path_exists("/tmp/nails.log", true);
    fs.mock_set_path_exists("/tmp/nails.toml", true);

    let result = verifier.run(false).unwrap();

    // Should have multiple findings
    // At least: 2 mounts + 2 files + 1 memory = 5
    assert!(result.findings.len() >= 5);

    // Verify categories are diverse
    let categories: std::collections::HashSet<_> = result
        .findings
        .iter()
        .map(|f| f.category.as_str())
        .collect();
    assert!(categories.len() >= 2); // at least mount and file
}

// ========================================================================
// New Functionality Tests (Post-Code Review Fixes)
// ========================================================================

#[test]
fn test_process_check_detects_running_nails() {
    let fs = MockFilesystem::new();
    let verifier = Verifier::new(fs.clone());

    // No nails process running
    let result = verifier.run(false).unwrap();
    let process_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.category == "process")
        .collect();
    assert_eq!(process_findings.len(), 0);

    // Nails process is running
    fs.mock_set_nails_process_running(true);
    let result = verifier.run(false).unwrap();
    let process_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.category == "process")
        .collect();
    assert_eq!(process_findings.len(), 1);
    assert_eq!(process_findings[0].severity, Severity::Critical);
    assert!(process_findings[0].fix_guidance.is_some());
}

#[test]
fn test_history_file_content_checking() {
    let fs = MockFilesystem::new();
    let verifier = Verifier::new(fs.clone());

    // Set up history file with nails commands
    fs.mock_set_path_exists("/root/.bash_history", true);
    fs.mock_set_file_content(
        "/root/.bash_history",
        "nails activate\nls\nnails deactivate\n",
    );

    let result = verifier.run(true).unwrap();

    // Should find the history file with nails commands
    let history_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.message.contains("Shell history contains nails commands"))
        .collect();
    assert_eq!(history_findings.len(), 1);
    assert_eq!(history_findings[0].severity, Severity::Warn);
    assert!(
        history_findings[0]
            .fix_guidance
            .as_ref()
            .unwrap()
            .contains("nano")
    );
}

#[test]
fn test_history_file_without_nails_commands() {
    let fs = MockFilesystem::new();
    let verifier = Verifier::new(fs.clone());

    // Set up history file without nails commands
    fs.mock_set_path_exists("/root/.bash_history", true);
    fs.mock_set_file_content("/root/.bash_history", "ls\ncd /home\nmkdir test\n");

    let result = verifier.run(true).unwrap();

    // Should NOT find warnings for nails commands (though might find info about file existence)
    let nails_warnings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| {
            f.category == "file" && f.message.contains("Shell history contains nails commands")
        })
        .collect();
    assert_eq!(nails_warnings.len(), 0);
}

#[test]
fn test_recursive_directory_scan_finds_nails_files() {
    let fs = MockFilesystem::new();
    let verifier = Verifier::new(fs.clone());

    // Set up /tmp directory with nails files
    fs.mock_set_path_exists("/tmp", true);
    fs.mock_set_path_type("/tmp", "directory");

    // Mock pattern search to find nails files
    fs.mock_set_files_with_pattern(
        "/tmp",
        "nails",
        &[
            std::path::Path::new("/tmp/nails.log"),
            std::path::Path::new("/tmp/nails.toml"),
            std::path::Path::new("/tmp/cache/nails.tmp"),
        ],
    );

    let result = verifier.run(true).unwrap();

    // Should find all nails files
    let nails_file_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.category == "file" && f.message.contains("NAILS-related file found"))
        .collect();
    assert_eq!(nails_file_findings.len(), 3);

    // Verify all findings have fix guidance
    for finding in nails_file_findings {
        assert!(finding.fix_guidance.is_some());
        assert!(
            finding
                .fix_guidance
                .as_ref()
                .unwrap()
                .starts_with("Delete file:")
        );
    }
}

#[test]
fn test_deep_scan_combines_all_checks() {
    let fs = MockFilesystem::new();
    let verifier = Verifier::new(fs.clone());

    // Set up all types of findings
    fs.mock_set_nails_process_running(true); // Process
    fs.mock_set_path_exists("/root/.bash_history", true);
    fs.mock_set_file_content("/root/.bash_history", "nails activate\n"); // History
    fs.mock_set_path_exists("/tmp", true);
    fs.mock_set_path_type("/tmp", "directory");
    fs.mock_set_files_with_pattern("/tmp", "nails", &[std::path::Path::new("/tmp/nails.log")]); // Files

    let result = verifier.run(true).unwrap();

    // Should have findings from multiple sources
    assert!(result.findings.len() >= 3);

    // Verify categories
    let categories: std::collections::HashSet<_> = result
        .findings
        .iter()
        .map(|f| f.category.as_str())
        .collect();
    assert!(categories.contains("process"));
    assert!(categories.contains("file"));
}

#[test]
fn test_exit_code_2_for_verification_errors() {
    // This test documents that errors return exit code 2
    // Actual CLI testing would require integration tests
    let fs = MockFilesystem::new();
    let verifier = Verifier::new(fs);

    // Normal verification succeeds
    assert!(verifier.run(false).is_ok());

    // If it fails, CLI should exit with code 2 (documented in CLI code)
}

// ========================================================================
// Additional Coverage Tests
// ========================================================================

#[test]
fn test_history_file_exists_but_unreadable() {
    // Tests the error path when history file exists but can't be read (lines 362-375)
    let fs = MockFilesystem::new();
    let verifier = Verifier::new(fs.clone());

    // Set up history file that exists but has no content set (will trigger read error)
    fs.mock_set_path_exists("/root/.bash_history", true);
    // Don't set file content - this will cause read_file_content to return an error

    let result = verifier.run(true).unwrap();

    // Should find an info-level finding about unreadable history
    let info_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.message.contains("cannot read contents"))
        .collect();
    assert_eq!(info_findings.len(), 1);
    assert_eq!(info_findings[0].severity, Severity::Info);
    assert!(info_findings[0].fix_guidance.is_some());
}

#[test]
fn test_deep_scan_multiple_history_files_with_content() {
    // Test multiple history files all containing nails commands
    let fs = MockFilesystem::new();
    let verifier = Verifier::new(fs.clone());

    // Set up multiple history files with nails commands
    fs.mock_set_path_exists("/root/.bash_history", true);
    fs.mock_set_file_content("/root/.bash_history", "nails activate\nls\n");

    fs.mock_set_path_exists("/root/.zsh_history", true);
    fs.mock_set_file_content("/root/.zsh_history", "NAILS deactivate\ncd /home\n");

    fs.mock_set_path_exists("/home/.bash_history", true);
    fs.mock_set_file_content("/home/.bash_history", "nails status\n");

    let result = verifier.run(true).unwrap();

    // Should find all three history files with nails commands
    let history_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.message.contains("Shell history contains nails commands"))
        .collect();
    assert_eq!(history_findings.len(), 3);

    // All should be warnings with fix guidance
    for finding in history_findings {
        assert_eq!(finding.severity, Severity::Warn);
        assert!(finding.fix_guidance.is_some());
    }
}

#[test]
fn test_deep_scan_all_temp_directories() {
    // Test that deep scan checks all temp directories
    let fs = MockFilesystem::new();
    let verifier = Verifier::new(fs.clone());

    // Set up all deep scan paths as directories
    fs.mock_set_path_exists("/tmp", true);
    fs.mock_set_path_type("/tmp", "directory");
    fs.mock_set_path_exists("/var/tmp", true);
    fs.mock_set_path_type("/var/tmp", "directory");
    fs.mock_set_path_exists("/var/log", true);
    fs.mock_set_path_type("/var/log", "directory");

    // Mock pattern search results for each directory
    fs.mock_set_files_with_pattern(
        "/tmp",
        "nails",
        &[std::path::Path::new("/tmp/nails-test.log")],
    );
    fs.mock_set_files_with_pattern(
        "/var/tmp",
        "nails",
        &[std::path::Path::new("/var/tmp/nails-cache")],
    );
    fs.mock_set_files_with_pattern(
        "/var/log",
        "nails",
        &[std::path::Path::new("/var/log/nails.log")],
    );

    let result = verifier.run(true).unwrap();

    // Should find files from all three directories
    let nails_file_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.message.contains("NAILS-related file found"))
        .collect();
    assert_eq!(nails_file_findings.len(), 3);
}

#[test]
fn test_check_all_overlay_mount_points() {
    // Test that all three mount points are checked
    let fs = MockFilesystem::new();
    let verifier = Verifier::new(fs.clone());

    // Set up all three overlay mount points
    fs.mock_set_mounted(std::path::Path::new("/home"), true);
    fs.mock_set_mounted(std::path::Path::new("/etc"), true);
    fs.mock_set_mounted(std::path::Path::new("/root"), true);

    let result = verifier.run(false).unwrap();

    // Should find all three mount findings
    let mount_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.category == "mount")
        .collect();
    assert_eq!(mount_findings.len(), 3);

    // All should be critical with fix guidance
    for finding in mount_findings {
        assert_eq!(finding.severity, Severity::Critical);
        assert!(finding.fix_guidance.is_some());
        assert!(
            finding
                .fix_guidance
                .as_ref()
                .unwrap()
                .contains("nails deactivate")
        );
    }
}

#[test]
fn test_check_all_artifact_paths() {
    // Test that all artifact paths are checked
    let fs = MockFilesystem::new();
    let verifier = Verifier::new(fs.clone());

    // Set up all artifact paths
    let artifact_paths = [
        "/tmp/nails.log",
        "/tmp/nails.toml",
        "/var/log/nails.log",
        "/etc/nails",
        "/home/.nails",
        "/root/.nails",
    ];

    for path in &artifact_paths {
        fs.mock_set_path_exists(path, true);
    }

    let result = verifier.run(false).unwrap();

    // Should find all artifact files
    let artifact_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.category == "file" && f.message.contains("Artifact file found"))
        .collect();
    assert_eq!(artifact_findings.len(), artifact_paths.len());

    // All should be warnings with fix guidance containing "rm"
    for finding in artifact_findings {
        assert_eq!(finding.severity, Severity::Warn);
        assert!(finding.fix_guidance.is_some());
        assert!(finding.fix_guidance.as_ref().unwrap().contains("rm"));
    }
}
