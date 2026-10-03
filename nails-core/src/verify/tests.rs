//! Tests for forensic verification system

use super::Verifier;
use super::types::{Finding, ScanDepth, Severity, StateFileStatus, VerifyResult, VerifyStatus};
use crate::MockFilesystem;
use crate::filesystem::PathKind;

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
    assert_eq!(result.state_file_status, StateFileStatus::NotChecked);
}

#[test]
fn test_verify_result_new_config_aware_includes_state_file_status() {
    let result = VerifyResult::new_config_aware(
        VerifyStatus::Secure,
        vec![],
        ScanDepth::Standard,
        4,
        StateFileStatus::Missing {
            path: std::path::PathBuf::from("/mnt/hidden/state.json"),
        },
    );

    assert!(result.config_aware);
    assert_eq!(result.config_paths_checked, 4);
    assert_eq!(
        result.state_file_status,
        StateFileStatus::Missing {
            path: std::path::PathBuf::from("/mnt/hidden/state.json")
        }
    );
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
    fs.mock_set_overlay_mounted(std::path::Path::new("/home"), true); // mount
    fs.mock_set_path_exists("/run/nails", true); // file (runtime artifact)
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
    assert!(json.contains("\"state_file_status\""));
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
    fs.mock_set_overlay_mounted(std::path::Path::new("/home"), true);

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

    // Set up leftover runtime artifacts from the shared registry.
    fs.mock_set_path_exists("/run/nails", true);
    fs.mock_set_path_exists("/mnt/nails-pivot", true);

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
    fs.mock_set_overlay_mounted(std::path::Path::new("/home"), true);
    fs.mock_set_overlay_mounted(std::path::Path::new("/etc"), true);

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
    fs.mock_set_overlay_mounted(std::path::Path::new("/home"), true); // Critical
    fs.mock_set_path_exists("/run/nails", true); // Warning (runtime artifact)

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

    fs.mock_set_overlay_mounted(std::path::Path::new("/home"), true);

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
    // AC: Given verify runs and finds a decoy-side artifact
    // Then the finding is critical and includes fix guidance
    let fs = MockFilesystem::new();
    let verifier = Verifier::new(fs.clone());

    // The staged /etc/nixos symlink is a decoy-side, critical leak.
    fs.mock_set_path_exists("/etc/nixos/nails/configuration.nix", true);

    let result = verifier.run(false).unwrap();

    let file_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| {
            f.category == "file" && f.message.contains("/etc/nixos/nails/configuration.nix")
        })
        .collect();

    assert_eq!(file_findings.len(), 1);
    assert_eq!(file_findings[0].severity, Severity::Critical);
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

    fs.mock_set_path_exists("/run/nails", true);

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
    fs.mock_set_overlay_mounted(std::path::Path::new("/home"), true);
    fs.mock_set_overlay_mounted(std::path::Path::new("/etc"), true);
    fs.mock_set_path_exists("/run/nails", true);
    fs.mock_set_path_exists("/mnt/nails-pivot", true);

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
    fs.mock_set_path_type("/tmp", PathKind::Dir);

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
    fs.mock_set_path_type("/tmp", PathKind::Dir);
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
    fs.mock_set_path_type("/tmp", PathKind::Dir);
    fs.mock_set_path_exists("/var/tmp", true);
    fs.mock_set_path_type("/var/tmp", PathKind::Dir);
    fs.mock_set_path_exists("/var/log", true);
    fs.mock_set_path_type("/var/log", PathKind::Dir);

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
    fs.mock_set_overlay_mounted(std::path::Path::new("/home"), true);
    fs.mock_set_overlay_mounted(std::path::Path::new("/etc"), true);
    fs.mock_set_overlay_mounted(std::path::Path::new("/root"), true);

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
fn test_non_overlay_mounts_are_not_reported_as_overlay_findings() {
    let fs = MockFilesystem::new();
    let verifier = Verifier::new(fs.clone());

    fs.mock_set_mounted(std::path::Path::new("/home"), true);

    let result = verifier.run(false).unwrap();

    assert!(result.findings.iter().all(|f| f.category != "mount"));
}

#[test]
fn test_verify_flags_every_registry_path_artifact() {
    // Every artifact in the shared registry that resolves to a filesystem path
    // and the activation path creates must be flagged by verify when it is left
    // behind. Absolute paths plus hidden-root paths (resolved against the
    // configured hidden volume root) are all covered here.
    use crate::artifacts;
    use crate::config::Config;
    use std::path::PathBuf;

    let fs = MockFilesystem::new();
    let hidden_root = PathBuf::from("/mnt/data");
    let config = Config {
        hidden_volume_root: hidden_root.clone(),
        ..Config::default()
    };

    let mut expected: Vec<PathBuf> = Vec::new();
    for artifact in artifacts::ARTIFACTS {
        if let Some(path) = artifact.resolve_path(&hidden_root) {
            fs.mock_set_path_exists(path.to_str().unwrap(), true);
            expected.push(path);
        }
    }
    assert!(
        !expected.is_empty(),
        "registry must contain path-type artifacts"
    );

    let verifier = Verifier::with_config(fs, config, None, StateFileStatus::NotChecked);
    let result = verifier.run(false).unwrap();

    for path in &expected {
        let display = path.display().to_string();
        assert!(
            result.findings.iter().any(|f| f.message.contains(&display)),
            "verify did not flag registry artifact at {display}"
        );
    }
}

#[test]
fn test_block_device_scan_is_silent_without_sysblock() {
    // When /sys/block is unavailable (offline scan, container, or a mock without
    // the fixture) the crypt/loop scan must stay quiet rather than erroring.
    let fs = MockFilesystem::new();
    let verifier = Verifier::new(fs);

    let result = verifier.run(false).unwrap();
    assert!(result.findings.iter().all(|f| f.category != "block-device"));
}

#[test]
fn test_block_device_scan_flags_foreign_crypt_and_reports_own_as_info() {
    use crate::config::Config;
    use std::path::{Path, PathBuf};

    let fs = MockFilesystem::new();
    let hidden_root = PathBuf::from("/mnt/data");
    let config = Config {
        hidden_volume_root: hidden_root,
        ..Config::default()
    };

    // The hidden volume is backed by /dev/mapper/data.
    fs.mock_set_file_content(
        "/proc/self/mountinfo",
        "36 35 254:0 / /mnt/data rw,relatime shared:1 - ext4 /dev/mapper/data rw\n",
    );

    // /sys/block lists two crypt mappers and one loop device.
    fs.mock_set_directory_contents(
        Path::new("/sys/block"),
        vec![
            PathBuf::from("/sys/block/dm-0"),
            PathBuf::from("/sys/block/dm-1"),
            PathBuf::from("/sys/block/loop0"),
        ],
    );
    // dm-0 = the hidden volume's own mapper ("data").
    fs.mock_set_file_content("/sys/block/dm-0/dm/uuid", "CRYPT-LUKS2-abc-data\n");
    fs.mock_set_file_content("/sys/block/dm-0/dm/name", "data\n");
    // dm-1 = an unrelated crypt mapper with an arbitrary neutral name.
    fs.mock_set_file_content("/sys/block/dm-1/dm/uuid", "CRYPT-LUKS2-def-vault\n");
    fs.mock_set_file_content("/sys/block/dm-1/dm/name", "vault\n");
    // loop0 = an unrelated attached loop device.
    fs.mock_set_file_content(
        "/sys/block/loop0/loop/backing_file",
        "/home/user/other.img\n",
    );

    let verifier = Verifier::with_config(fs, config, None, StateFileStatus::NotChecked);
    let result = verifier.run(false).unwrap();

    let block_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.category == "block-device")
        .collect();
    assert_eq!(block_findings.len(), 3);

    let own = block_findings
        .iter()
        .find(|f| f.message.contains("/dev/mapper/data"))
        .expect("own mapper reported");
    assert_eq!(own.severity, Severity::Info);
    assert!(own.message.contains("backing the hidden volume"));

    let foreign_crypt = block_findings
        .iter()
        .find(|f| f.message.contains("/dev/mapper/vault"))
        .expect("foreign mapper reported");
    assert_eq!(foreign_crypt.severity, Severity::Warn);
    assert!(
        foreign_crypt
            .message
            .contains("not backing the hidden volume")
    );

    let foreign_loop = block_findings
        .iter()
        .find(|f| f.message.contains("/dev/loop0"))
        .expect("foreign loop device reported");
    assert_eq!(foreign_loop.severity, Severity::Warn);
    assert!(foreign_loop.message.contains("other.img"));
}

// ========================================================================
// Config-Aware and State-Aware Verification Tests
// ========================================================================

#[test]
fn test_verify_with_config_is_config_aware() {
    use crate::config::Config;

    let fs = MockFilesystem::new();
    let config = Config::default();
    let verifier = Verifier::with_config(fs, config, None, StateFileStatus::NotChecked);

    let result = verifier.run(false).unwrap();
    assert!(result.config_aware);
    // Should have checked at least hidden_volume_root, log_path, state_file_path
    assert!(result.config_paths_checked >= 3);
}

#[test]
fn test_verify_without_config_not_config_aware() {
    let fs = MockFilesystem::new();
    let verifier = Verifier::new(fs);

    let result = verifier.run(false).unwrap();
    assert!(!result.config_aware);
    assert_eq!(result.config_paths_checked, 0);
}

#[test]
fn test_verify_detects_config_specific_hidden_volume() {
    use crate::config::Config;
    use std::path::PathBuf;

    let fs = MockFilesystem::new();
    let config = Config {
        hidden_volume_root: PathBuf::from("/mnt/test-hidden"),
        ..Config::default()
    };

    // Mark hidden volume as accessible
    fs.mock_set_path_exists("/mnt/test-hidden", true);

    let verifier = Verifier::with_config(fs, config, None, StateFileStatus::NotChecked);
    let result = verifier.run(false).unwrap();

    let config_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.category == "config" && f.message.contains("Hidden volume"))
        .collect();
    assert_eq!(config_findings.len(), 1);
    assert_eq!(config_findings[0].severity, Severity::Warn);
}

#[test]
fn test_verify_detects_state_file_exists() {
    use crate::config::Config;
    use std::path::PathBuf;

    let fs = MockFilesystem::new();
    let config = Config {
        state_file_path: PathBuf::from("/mnt/hidden/state.json"),
        ..Config::default()
    };

    fs.mock_set_path_exists("/mnt/hidden/state.json", true);

    let verifier = Verifier::with_config(fs, config, None, StateFileStatus::NotChecked);
    let result = verifier.run(false).unwrap();

    let state_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.category == "config" && f.message.contains("State file exists"))
        .collect();
    assert_eq!(state_findings.len(), 1);
}

#[test]
fn test_verify_detects_config_overlay_mounts_and_log_files() {
    use crate::config::{Config, OverlayConfig};
    use std::path::PathBuf;

    let fs = MockFilesystem::new();
    let config = Config {
        hidden_volume_root: PathBuf::from("/mnt/hidden"),
        log_path: PathBuf::from("/var/custom-log"),
        overlays: vec![OverlayConfig {
            name: "srv".to_string(),
            lower: PathBuf::from("/srv"),
            upper: PathBuf::from("/mnt/hidden/overlays/srv/upper"),
            work: PathBuf::from("/mnt/hidden/overlays/srv/work"),
            target: PathBuf::from("/srv"),
        }],
        ..Config::default()
    };

    fs.mock_set_overlay_mounted(std::path::Path::new("/srv"), true);
    fs.mock_set_path_exists("/var/custom-log", true);
    fs.mock_set_path_type("/var/custom-log", PathKind::Dir);
    fs.mock_set_files_with_pattern(
        "/var/custom-log",
        "nails",
        &[std::path::Path::new("/var/custom-log/nails-debug.log")],
    );

    let verifier = Verifier::with_config(fs, config, None, StateFileStatus::NotChecked);
    let result = verifier.run(false).unwrap();

    let overlay_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.category == "config" && f.message.contains("still mounted: /srv"))
        .collect();
    assert_eq!(overlay_findings.len(), 1);
    assert_eq!(overlay_findings[0].severity, Severity::Critical);

    let log_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| {
            f.category == "config"
                && f.message.contains("Log file found in config log directory")
                && f.message.contains("nails-debug.log")
        })
        .collect();
    assert_eq!(log_findings.len(), 1);
    assert_eq!(log_findings[0].severity, Severity::Warn);
}

#[test]
fn test_verify_does_not_flag_logs_inside_the_hidden_volume() {
    use crate::config::Config;
    use std::path::PathBuf;

    // The log directory sits on the hidden volume (its intended, on-volume
    // location). Running `verify` from the hidden environment must not report
    // those logs as residue: they belong there and are only reachable while the
    // volume is mounted, which the hidden-volume-path finding already covers.
    let fs = MockFilesystem::new();
    let config = Config {
        hidden_volume_root: PathBuf::from("/mnt/data"),
        log_path: PathBuf::from("/mnt/data/logs"),
        overlays: vec![],
        ..Config::default()
    };

    fs.mock_set_path_exists("/mnt/data/logs", true);
    fs.mock_set_path_type("/mnt/data/logs", PathKind::Dir);
    fs.mock_set_files_with_pattern(
        "/mnt/data/logs",
        "nails",
        &[std::path::Path::new("/mnt/data/logs/nails.log")],
    );

    let verifier = Verifier::with_config(fs, config, None, StateFileStatus::NotChecked);
    let result = verifier.run(false).unwrap();

    let log_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| {
            f.category == "config" && f.message.contains("Log file found in config log directory")
        })
        .collect();
    assert!(
        log_findings.is_empty(),
        "on-volume logs must not be flagged as residue: {log_findings:?}"
    );
}

#[test]
fn test_verify_state_active_is_critical() {
    use crate::SystemState;
    use crate::state::StateFile;
    use chrono::Utc;

    let fs = MockFilesystem::new();
    let state = StateFile {
        state: SystemState::Active {
            activated_at: Utc::now(),
            overlays: vec![],
        },
        ..StateFile::default()
    };

    let config = crate::config::Config::default();
    let verifier = Verifier::with_config(fs, config, Some(state), StateFileStatus::NotChecked);
    let result = verifier.run(false).unwrap();

    let state_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.category == "state" && f.severity == Severity::Critical)
        .collect();
    assert!(!state_findings.is_empty());
    assert!(state_findings[0].message.contains("ACTIVE"));
}

#[test]
fn test_verify_state_transition_states_are_critical() {
    use crate::SystemState;
    use crate::state::StateFile;
    use chrono::Utc;

    let fs = MockFilesystem::new();
    let config = crate::config::Config::default();

    let activating = StateFile {
        state: SystemState::Activating {
            started_at: Utc::now(),
        },
        ..StateFile::default()
    };
    let activating_result = Verifier::with_config(
        fs.clone(),
        config.clone(),
        Some(activating),
        StateFileStatus::NotChecked,
    )
    .run(false)
    .unwrap();
    let activating_findings: Vec<_> = activating_result
        .findings
        .iter()
        .filter(|f| f.category == "state" && f.message.contains("ACTIVATING"))
        .collect();
    assert_eq!(activating_findings.len(), 1);
    assert_eq!(activating_findings[0].severity, Severity::Critical);

    let deactivating = StateFile {
        state: SystemState::Deactivating {
            started_at: Utc::now(),
        },
        ..StateFile::default()
    };
    let deactivating_result =
        Verifier::with_config(fs, config, Some(deactivating), StateFileStatus::NotChecked)
            .run(false)
            .unwrap();
    let deactivating_findings: Vec<_> = deactivating_result
        .findings
        .iter()
        .filter(|f| f.category == "state" && f.message.contains("DEACTIVATING"))
        .collect();
    assert_eq!(deactivating_findings.len(), 1);
    assert_eq!(deactivating_findings[0].severity, Severity::Critical);
}

#[test]
fn test_verify_state_inactive_no_state_findings() {
    use crate::state::StateFile;

    let fs = MockFilesystem::new();
    let state = StateFile::default(); // Inactive

    let config = crate::config::Config::default();
    let verifier = Verifier::with_config(fs, config, Some(state), StateFileStatus::NotChecked);
    let result = verifier.run(false).unwrap();

    let state_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.category == "state")
        .collect();
    assert!(state_findings.is_empty());
}

#[test]
fn test_verify_state_degraded_is_critical() {
    use crate::SystemState;
    use crate::state::StateFile;
    use chrono::Utc;
    use std::path::PathBuf;

    let fs = MockFilesystem::new();
    let state = StateFile {
        state: SystemState::Degraded {
            since: Utc::now(),
            reason: "unmount of /home failed".into(),
            remaining_mounts: vec![PathBuf::from("/home")],
        },
        ..StateFile::default()
    };

    let config = crate::config::Config::default();
    let verifier = Verifier::with_config(fs, config, Some(state), StateFileStatus::NotChecked);
    let result = verifier.run(false).unwrap();

    let degraded_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.category == "state" && f.message.contains("DEGRADED"))
        .collect();
    assert_eq!(degraded_findings.len(), 1);
    assert_eq!(degraded_findings[0].severity, Severity::Critical);
}

#[test]
fn test_verify_state_with_failed_overlays_info() {
    use crate::state::{FailedOverlayInfo, StateFile};
    use chrono::Utc;
    use std::path::PathBuf;

    let fs = MockFilesystem::new();
    let state = StateFile {
        failed_overlays: vec![FailedOverlayInfo {
            target: PathBuf::from("/var"),
            error_message: "Mount failed".to_string(),
            failed_at: Utc::now(),
        }],
        ..StateFile::default()
    };

    let config = crate::config::Config::default();
    let verifier = Verifier::with_config(fs, config, Some(state), StateFileStatus::NotChecked);
    let result = verifier.run(false).unwrap();

    let info_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.category == "state" && f.message.contains("failed overlay"))
        .collect();
    assert_eq!(info_findings.len(), 1);
    assert_eq!(info_findings[0].severity, Severity::Info);
}

/// Build an active-state verifier over a crafted `/proc/self/mountinfo`.
#[cfg(test)]
fn active_verifier_with_mountinfo(mountinfo: &str) -> Verifier<MockFilesystem> {
    use crate::SystemState;
    use crate::state::StateFile;
    use chrono::Utc;

    let fs = MockFilesystem::new();
    fs.mock_add_file("/proc/self/mountinfo", mountinfo);
    let state = StateFile {
        state: SystemState::Active {
            activated_at: Utc::now(),
            overlays: vec![],
        },
        ..StateFile::default()
    };
    let config = crate::config::Config {
        hidden_volume_root: std::path::PathBuf::from("/mnt/hidden"),
        ..crate::config::Config::default()
    };
    Verifier::with_config(fs, config, Some(state), StateFileStatus::NotChecked)
}

fn writable_mount_findings(result: &crate::verify::VerifyResult) -> Vec<&Finding> {
    result
        .findings
        .iter()
        .filter(|f| f.category == "mount" && f.message.contains("Writable non-overlay decoy mount"))
        .collect()
}

#[test]
fn test_verify_flags_writable_non_overlaid_decoy_root() {
    let verifier =
        active_verifier_with_mountinfo("23 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n");
    let result = verifier.run(false).unwrap();
    let findings = writable_mount_findings(&result);
    assert_eq!(findings.len(), 1, "{:?}", result.findings);
    assert_eq!(findings[0].severity, Severity::Critical);
    assert!(findings[0].message.contains('/'));
}

#[test]
fn test_verify_accepts_read_only_decoy_root_and_usr() {
    let verifier = active_verifier_with_mountinfo(
        "23 1 8:1 / / ro,relatime - ext4 /dev/sda1 ro\n\
         36 23 8:1 /usr /usr ro,relatime - ext4 /dev/sda1 ro\n",
    );
    let result = verifier.run(false).unwrap();
    assert!(
        writable_mount_findings(&result).is_empty(),
        "a read-only decoy root must not be flagged: {:?}",
        result.findings
    );
}

#[test]
fn test_verify_ignores_writable_non_os_tree() {
    // An ext4 /home that is not an overlay is not reported by this OS-tree check.
    let verifier = active_verifier_with_mountinfo(
        "23 1 8:1 / / ro,relatime - ext4 /dev/sda1 ro\n\
         40 23 8:2 /home /home rw,relatime - ext4 /dev/sdb1 rw\n",
    );
    let result = verifier.run(false).unwrap();
    assert!(
        writable_mount_findings(&result).is_empty(),
        "/home is out of scope for the OS-tree check: {:?}",
        result.findings
    );
}

#[test]
fn test_verify_writable_decoy_check_is_inactive_only() {
    // The same writable root, but with no active state, is not flagged: a
    // writable decoy root is expected when nothing is hidden.
    let fs = MockFilesystem::new();
    fs.mock_add_file(
        "/proc/self/mountinfo",
        "23 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n",
    );
    let config = crate::config::Config::default();
    let verifier = Verifier::with_config(fs, config, None, StateFileStatus::NotChecked);
    let result = verifier.run(false).unwrap();
    assert!(writable_mount_findings(&result).is_empty());
}

#[test]
fn test_verify_overlaid_decoy_tree_is_not_flagged() {
    // /usr presented as an overlay mount is protection, not a leak.
    let verifier = active_verifier_with_mountinfo(
        "23 1 8:1 / / ro,relatime - ext4 /dev/sda1 ro\n\
         36 23 0:40 / /usr rw,relatime - overlay overlay rw,lowerdir=/usr\n",
    );
    let result = verifier.run(false).unwrap();
    assert!(
        writable_mount_findings(&result).is_empty(),
        "an overlaid /usr is protection: {:?}",
        result.findings
    );
}
