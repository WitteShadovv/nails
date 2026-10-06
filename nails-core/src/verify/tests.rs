// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests for forensic verification system

use super::Verifier;
use super::types::{Finding, ScanDepth, Severity, StateFileStatus, VerifyResult, VerifyStatus};
use crate::MockFilesystem;
use crate::filesystem::PathKind;

/// A `/proc/self/mountinfo` line for an overlay at `mount_point` whose upper
/// layer lives on the hidden volume `/mnt/hidden`, i.e. one NAILS mounted.
#[cfg(test)]
fn hidden_overlay_line(mount_point: &str) -> String {
    format!(
        "30 1 0:50 / {mount_point} rw,relatime - overlay overlay \
         rw,lowerdir={mount_point},upperdir=/mnt/hidden/overlays/x/upper,\
         workdir=/mnt/hidden/overlays/x/work\n"
    )
}

/// A config-aware verifier (hidden root `/mnt/hidden`, no active state) over a
/// crafted `/proc/self/mountinfo`, used to exercise the upperdir overlay scan.
#[cfg(test)]
fn overlay_verifier(mountinfo: &str) -> (MockFilesystem, Verifier<MockFilesystem>) {
    let fs = MockFilesystem::new();
    fs.mock_add_file("/proc/self/mountinfo", mountinfo);
    let config = crate::config::Config {
        hidden_volume_root: std::path::PathBuf::from("/mnt/hidden"),
        ..crate::config::Config::default()
    };
    let verifier = Verifier::with_config(fs.clone(), config, None, StateFileStatus::NotChecked);
    (fs, verifier)
}

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
    let (fs, verifier) = overlay_verifier(&hidden_overlay_line("/home"));

    // Set up findings from all check types
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
    // An overlay at /home whose upper layer is on the hidden volume is flagged
    // from the mount table, by upperdir, not from a fixed list of mount points.
    let (_fs, verifier) = overlay_verifier(&hidden_overlay_line("/home"));

    let result = verifier.run(false).unwrap();
    assert_eq!(result.status, VerifyStatus::Critical);

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
fn test_overlay_leftover_at_var_is_detected() {
    // The old three-path loop (/home, /etc, /root) would miss a leftover /var
    // overlay; the upperdir scan catches it wherever it is mounted.
    let (_fs, verifier) = overlay_verifier(&hidden_overlay_line("/var"));

    let result = verifier.run(false).unwrap();
    let mount_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.category == "mount")
        .collect();
    assert_eq!(mount_findings.len(), 1, "{:?}", result.findings);
    assert_eq!(mount_findings[0].severity, Severity::Critical);
    assert!(mount_findings[0].message.contains("/var"));
}

#[test]
fn test_overlay_with_foreign_upperdir_is_not_flagged() {
    // An overlay whose upper layer is not on the hidden volume is somebody
    // else's overlay and must not be attributed to NAILS.
    let (_fs, verifier) = overlay_verifier(
        "30 1 0:50 / /var rw,relatime - overlay overlay \
         rw,lowerdir=/var,upperdir=/opt/other/upper,workdir=/opt/other/work\n",
    );
    let result = verifier.run(false).unwrap();
    assert!(
        result.findings.iter().all(|f| f.category != "mount"),
        "a foreign-upperdir overlay must not be flagged: {:?}",
        result.findings
    );
}

#[test]
fn test_offline_scan_finds_planted_indicator_and_skips_live_checks() {
    use crate::filesystem::ProcessMatch;

    // A read-only decoy image mounted at /mnt/decoy with a leftover /run/nails.
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/mnt/decoy/run/nails", true);
    // A live NAILS process and a hidden-volume overlay that an offline scan must
    // ignore: they describe the machine running verify, not the image.
    fs.mock_set_nails_process_matches(vec![ProcessMatch {
        pid: 7,
        strong: true,
        detail: "live worker".to_string(),
    }]);
    fs.mock_add_file("/proc/self/mountinfo", &hidden_overlay_line("/home"));

    let config = crate::config::Config {
        hidden_volume_root: std::path::PathBuf::from("/mnt/hidden"),
        ..crate::config::Config::default()
    };
    let verifier = Verifier::with_config(fs, config, None, StateFileStatus::NotChecked)
        .offline_under(std::path::PathBuf::from("/mnt/decoy"));

    let result = verifier.run(false).unwrap();

    // The planted runtime artifact under the image root is found...
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.category == "file" && f.message.contains("/run/nails")),
        "offline scan missed the planted indicator: {:?}",
        result.findings
    );
    // ...while the live process and mount checks are skipped entirely.
    assert!(
        result
            .findings
            .iter()
            .all(|f| f.category != "process" && f.category != "mount"),
        "offline scan reported a live-only finding: {:?}",
        result.findings
    );
    assert!(
        result
            .areas_not_checked
            .iter()
            .any(|area| area.contains("offline image scan")),
        "offline scan did not disclose its skipped areas: {:?}",
        result.areas_not_checked
    );
}

#[test]
fn test_artifact_file_detection() {
    let fs = MockFilesystem::new();
    let verifier = Verifier::new(fs.clone());

    // Set up leftover runtime artifacts from the shared registry (both on the
    // /run tmpfs, so both carry the Warn severity).
    fs.mock_set_path_exists("/run/nails", true);
    fs.mock_set_path_exists("/run/nails-pivot", true);

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

    // Check swap finding: a plain disk partition can leak memory, so it is
    // reported as Critical (not Info), matching the pre-flight classification.
    let swap_finding = memory_findings
        .iter()
        .find(|f| f.message.contains("Swap can leak memory"))
        .unwrap();
    assert_eq!(swap_finding.severity, Severity::Critical);
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
    // Two hidden-volume overlays at different mount points.
    let mountinfo = format!(
        "{}{}",
        hidden_overlay_line("/home"),
        hidden_overlay_line("/etc")
    );
    let (_fs, verifier) = overlay_verifier(&mountinfo);

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
    // Set up both critical (overlay) and warning (runtime artifact) findings.
    let (fs, verifier) = overlay_verifier(&hidden_overlay_line("/home"));
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
    let (_fs, verifier) = overlay_verifier(&hidden_overlay_line("/home"));

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
    // Set up multiple findings: two hidden-volume overlays plus two artifacts.
    let mountinfo = format!(
        "{}{}",
        hidden_overlay_line("/home"),
        hidden_overlay_line("/etc")
    );
    let (fs, verifier) = overlay_verifier(&mountinfo);
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
    // History under root and under a real login account from /etc/passwd are both
    // scanned; the old hardcoded bare-`/home` history file (which never exists) is
    // gone, so a real user's home must be discovered from passwd.
    let fs = MockFilesystem::new();
    fs.mock_add_file(
        "/etc/passwd",
        "root:x:0:0:root:/root:/bin/bash\n\
         alice:x:1000:1000:Alice:/home/alice:/bin/bash\n\
         daemon:x:2:2:daemon:/usr/sbin:/usr/sbin/nologin\n",
    );
    let verifier = Verifier::new(fs.clone());

    fs.mock_set_path_exists("/root/.bash_history", true);
    fs.mock_set_file_content("/root/.bash_history", "nails activate\nls\n");

    fs.mock_set_path_exists("/root/.zsh_history", true);
    fs.mock_set_file_content("/root/.zsh_history", "NAILS deactivate\ncd /home\n");

    fs.mock_set_path_exists("/home/alice/.bash_history", true);
    fs.mock_set_file_content("/home/alice/.bash_history", "nails status\n");

    let result = verifier.run(true).unwrap();

    // Should find all three history files with nails commands.
    let history_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.message.contains("Shell history contains nails commands"))
        .collect();
    assert_eq!(history_findings.len(), 3, "{:?}", history_findings);

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
    // Overlays at three mount points, all with upper layers on the hidden volume.
    let mountinfo = format!(
        "{}{}{}",
        hidden_overlay_line("/home"),
        hidden_overlay_line("/etc"),
        hidden_overlay_line("/root"),
    );
    let (_fs, verifier) = overlay_verifier(&mountinfo);

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
fn test_verify_ignores_defaulted_install_dir_without_marker() {
    use crate::config::Config;

    // No config/override: the hidden root defaults to the binary's own install
    // directory. On a read-only store install that directory exists (and may sit
    // on its own device), but it carries no NAILS marker, so it is the program's
    // install location, not a mounted hidden volume, and must not be flagged.
    let install_dir = crate::config::derive_hidden_volume_root();
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists(install_dir.to_str().unwrap(), true);
    // Give it its own device to mimic a dedicated /nix/store image; the missing
    // marker alone must keep it from being reported.
    fs.mock_set_device_id(std::path::Path::new("/"), 1);
    fs.mock_set_device_id(&install_dir, 42);
    let config = Config {
        hidden_volume_root: install_dir,
        ..Config::default()
    };
    let verifier = Verifier::with_config(fs, config, None, StateFileStatus::NotChecked);
    let result = verifier.run(false).unwrap();
    let hits: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.category == "config" && f.message.contains("Hidden volume"))
        .collect();
    assert!(
        hits.is_empty(),
        "a defaulted install dir without a NAILS marker must not be flagged: {hits:?}"
    );
}

#[test]
fn test_verify_flags_defaulted_root_when_attached_marked_volume() {
    use crate::config::Config;

    // The binary lives on the hidden volume itself (the normal NAILS layout), so
    // the defaulted root *is* the hidden volume: mounted on its own device and
    // carrying a marker. That genuine exposure must still be reported.
    let root = crate::config::derive_hidden_volume_root();
    let marker = root.join(crate::artifacts::STATE_FILE_NAME);
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists(root.to_str().unwrap(), true);
    fs.mock_set_path_exists(marker.to_str().unwrap(), true);
    fs.mock_set_device_id(std::path::Path::new("/"), 1);
    fs.mock_set_device_id(&root, 42);
    let config = Config {
        hidden_volume_root: root,
        ..Config::default()
    };
    let verifier = Verifier::with_config(fs, config, None, StateFileStatus::NotChecked);
    let result = verifier.run(false).unwrap();
    let hits: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.category == "config" && f.message.contains("Hidden volume"))
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "an attached, marked hidden volume must be flagged"
    );
    assert_eq!(hits[0].severity, Severity::Warn);
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
            decoy_writers: Vec::new(),
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
            decoy_writers: Vec::new(),
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

// ========================================================================
// Mount-Table Scan for Leftover NAILS Scaffolding
// ========================================================================

#[test]
fn test_mount_scan_flags_leftover_overlay_at_non_standard_target() {
    use crate::config::Config;
    use std::path::PathBuf;

    let fs = MockFilesystem::new();
    let config = Config {
        hidden_volume_root: PathBuf::from("/mnt/hidden"),
        ..Config::default()
    };

    // A leftover ephemeral /var overlay (upper under the runtime dir), a pivot
    // staging bind, and an expected /home overlay (upper under the hidden root).
    // Only the first two are at non-standard targets and must be flagged; the
    // /home overlay is covered by the standard overlay check and must not be
    // double-reported here.
    let mountinfo = concat!(
        "9 1 0:49 / /run/0123456789abcdef rw - tmpfs tmpfs rw,mode=700\n",
        "10 1 0:50 / /home rw - overlay overlay ",
        "rw,lowerdir=/home,upperdir=/mnt/hidden/home/upper,workdir=/mnt/hidden/home/work\n",
        "11 1 0:51 / /var rw - overlay overlay ",
        "rw,lowerdir=/var,upperdir=/run/0123456789abcdef/var/upper,workdir=/run/0123456789abcdef/var/work\n",
        "12 1 0:52 / /run/0123456789abcdef/etc rw - overlay overlay ",
        "rw,lowerdir=/etc,upperdir=/mnt/hidden/etc/upper,workdir=/mnt/hidden/etc/work\n",
    );
    fs.mock_set_file_content("/proc/self/mountinfo", mountinfo);

    let verifier = Verifier::with_config(fs, config, None, StateFileStatus::NotChecked);
    let result = verifier.run(false).unwrap();

    let scaffolding: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.category == "mount" && f.message.contains("non-standard target"))
        .collect();
    assert_eq!(
        scaffolding.len(),
        2,
        "the /var ephemeral overlay and the pivot staging bind must be flagged, not /home: {:?}",
        result.findings
    );
    for finding in &scaffolding {
        assert_eq!(finding.severity, Severity::Critical);
        assert!(finding.fix_guidance.is_some());
    }
    assert!(scaffolding.iter().any(|f| f.message.contains("/var")));
    assert!(
        scaffolding
            .iter()
            .any(|f| f.message.contains("/run/0123456789abcdef/etc"))
    );
    assert!(
        !scaffolding.iter().any(|f| f.message.contains("/home")),
        "the expected /home overlay must not be reported as leftover scaffolding"
    );
}

#[test]
fn test_mount_scan_without_config_ignores_foreign_overlays() {
    let fs = MockFilesystem::new();

    // Without a configured hidden root, a generic overlay (e.g. a container's)
    // cannot be attributed to NAILS and must not be flagged. A runtime-backed
    // ephemeral overlay still is, since its upper is unambiguously ours.
    let mountinfo = concat!(
        "19 1 0:59 / /run/0123456789abcdef rw - tmpfs tmpfs rw,mode=700\n",
        "20 1 0:60 / /var/lib/docker/overlay2/x/merged rw - overlay overlay ",
        "rw,lowerdir=/foreign,upperdir=/foreign/upper,workdir=/foreign/work\n",
        "21 1 0:61 / /opt rw - overlay overlay ",
        "rw,lowerdir=/opt,upperdir=/run/0123456789abcdef/opt/upper,workdir=/run/0123456789abcdef/opt/work\n",
    );
    fs.mock_set_file_content("/proc/self/mountinfo", mountinfo);

    let verifier = Verifier::new(fs);
    let result = verifier.run(false).unwrap();

    let scaffolding: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.category == "mount" && f.message.contains("non-standard target"))
        .collect();
    assert_eq!(
        scaffolding.len(),
        1,
        "only the runtime-backed /opt overlay is attributable to NAILS: {:?}",
        result.findings
    );
    assert!(scaffolding[0].message.contains("/opt"));
}

// ========================================================================
// Decoy-Scoped Pre-Activation Baseline Tests
// ========================================================================

/// Fixture shared by the decoy-scope tests: a configured hidden root at
/// `/mnt/hidden` that is attached (mounted on `/dev/mapper/data`) with its own
/// on-volume files present, exactly as it is during a pre-activation baseline.
#[cfg(test)]
fn attached_hidden_volume_fs() -> (MockFilesystem, crate::config::Config) {
    use crate::config::Config;
    use std::path::{Path, PathBuf};

    let fs = MockFilesystem::new();
    let config = Config {
        hidden_volume_root: PathBuf::from("/mnt/hidden"),
        state_file_path: PathBuf::from("/mnt/hidden/state.json"),
        ..Config::default()
    };

    // The hidden volume is mounted on its own crypt mapper for the activation.
    fs.mock_set_mounted(Path::new("/mnt/hidden"), true);
    fs.mock_set_path_exists("/mnt/hidden", true);
    fs.mock_set_file_content(
        "/proc/self/mountinfo",
        "36 35 254:0 / /mnt/hidden rw,relatime shared:1 - ext4 /dev/mapper/data rw\n",
    );

    // Its own on-volume files exist (the registry's hidden-root artifacts).
    fs.mock_set_path_exists("/mnt/hidden/config/nails.toml", true);
    fs.mock_set_path_exists("/mnt/hidden/state.json", true);
    fs.mock_set_path_exists("/mnt/hidden/logs/nails.log", true);
    fs.mock_set_path_exists("/mnt/hidden/reports", true);

    // /sys/block lists the hidden volume's own backing mapper.
    fs.mock_set_directory_contents(
        Path::new("/sys/block"),
        vec![PathBuf::from("/sys/block/dm-0")],
    );
    fs.mock_set_file_content("/sys/block/dm-0/dm/uuid", "CRYPT-LUKS2-abc-data\n");
    fs.mock_set_file_content("/sys/block/dm-0/dm/name", "data\n");

    (fs, config)
}

#[test]
fn test_plain_host_scan_reports_hidden_volume_as_self_inflicted() {
    // A plain host scan of an attached hidden volume (state unknown) reports the
    // hidden volume itself — the defect the decoy baseline must not reproduce.
    let (fs, config) = attached_hidden_volume_fs();
    let verifier = Verifier::with_config(fs, config, None, StateFileStatus::NotChecked);
    let result = verifier.run(false).unwrap();

    assert_eq!(result.status, VerifyStatus::Critical);
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.severity == Severity::Critical
                && f.message.contains("hidden root still mounted")),
        "plain scan is expected to self-report the mounted hidden root: {:?}",
        result.findings
    );
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.message.contains("Hidden volume path is accessible")),
        "plain scan is expected to self-report the hidden volume path"
    );
}

#[test]
fn test_decoy_scoped_baseline_suppresses_self_inflicted_findings() {
    // Scoping the same scan to the decoy must drop every finding about the hidden
    // volume itself: its mount, its on-volume files, its path, its state file and
    // its own backing device. Nothing is self-inflicted, so the baseline is clean.
    let (fs, config) = attached_hidden_volume_fs();
    let verifier =
        Verifier::with_config(fs, config, None, StateFileStatus::NotChecked).scoped_to_decoy();
    let result = verifier.run(false).unwrap();

    assert_eq!(
        result.status,
        VerifyStatus::Secure,
        "a decoy baseline over nothing but the attached hidden volume must be clean: {:?}",
        result.findings
    );
    assert!(
        !result
            .findings
            .iter()
            .any(|f| f.message.contains("hidden root still mounted")),
        "the deliberately attached hidden root must not be flagged: {:?}",
        result.findings
    );
    assert!(
        !result
            .findings
            .iter()
            .any(|f| f.message.contains("Hidden volume path is accessible")
                || f.message.contains("State file exists")),
        "hidden-volume path and state file must be suppressed: {:?}",
        result.findings
    );
    assert!(
        !result
            .findings
            .iter()
            .any(|f| f.category == "file" && f.message.contains("/mnt/hidden/")),
        "hidden-root artifact files must be skipped: {:?}",
        result.findings
    );
    assert!(
        !result.findings.iter().any(|f| f.category == "block-device"),
        "the hidden volume's own backing device must not be listed: {:?}",
        result.findings
    );
}

#[test]
fn test_decoy_scoped_baseline_still_catches_real_decoy_leak_and_foreign_device() {
    use std::path::{Path, PathBuf};

    // The decoy scope only excludes the hidden volume itself: a genuine trace on
    // the decoy and a *second*, unexpected crypt mapper are still reported.
    let (fs, config) = attached_hidden_volume_fs();
    // A runtime leftover on the decoy root.
    fs.mock_set_path_exists("/run/nails", true);
    // A second crypt mapper with an arbitrary neutral name (a different hidden
    // volume), plus the own mapper that must stay suppressed.
    fs.mock_set_directory_contents(
        Path::new("/sys/block"),
        vec![
            PathBuf::from("/sys/block/dm-0"),
            PathBuf::from("/sys/block/dm-1"),
        ],
    );
    fs.mock_set_file_content("/sys/block/dm-1/dm/uuid", "CRYPT-LUKS2-def-vault\n");
    fs.mock_set_file_content("/sys/block/dm-1/dm/name", "vault\n");

    let verifier =
        Verifier::with_config(fs, config, None, StateFileStatus::NotChecked).scoped_to_decoy();
    let result = verifier.run(false).unwrap();

    assert!(
        result
            .findings
            .iter()
            .any(|f| f.category == "file" && f.message.contains("/run/nails")),
        "a decoy-side runtime leftover must still be reported: {:?}",
        result.findings
    );
    let block: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.category == "block-device")
        .collect();
    assert_eq!(
        block.len(),
        1,
        "only the foreign mapper is reported, not the own one: {block:?}"
    );
    assert!(block[0].message.contains("/dev/mapper/vault"));
    assert_eq!(block[0].severity, Severity::Warn);
}
