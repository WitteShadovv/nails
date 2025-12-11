//! Unit tests for artifact cleanup module
//!
//! Artifact cleanup is CRITICAL for forensic undetectability (ASR-DATA-1):
//! - Shell history removal (bash, zsh, fish)
//! - Temp file cleanup (hidden volume only)
//! - Log file removal (audit trail destruction)
//! - State file cleanup (prevent state leakage)
//! - Verification step (confirm completeness)
//!
//! Architecture Reference: docs/architecture.md lines 171, 1657-1765
//! Test Design Reference: docs/test-design-system.md lines 621-625

use nails::cleanup::{ArtifactCleaner, CleanupResult, CleanupReport};
use nails::config::NailsConfig;
use nails::filesystem::Filesystem;
use std::path::{Path, PathBuf};

// ============================================================================
// P0: Shell History Cleanup (ASR-DATA-1 - Forensic Undetectability)
// ============================================================================

#[test]
#[should_panic(expected = "not yet implemented")]
fn test_cleanup_removes_bash_history() {
    // GIVEN: Hidden volume with bash history file
    let config = NailsConfig::builder()
        .hidden_volume_path("/mnt/hidden-volume")
        .build()
        .unwrap();
    
    let mut fs = nails::filesystem::MockFilesystem::new();
    let history_path = "/mnt/hidden-volume/.bash_history";
    
    fs.mock_set_path_exists(history_path, true);
    fs.mock_create_file(history_path, "cd /secret\nrm sensitive.txt\n");
    
    let cleaner = ArtifactCleaner::new(config, fs);
    
    // WHEN: Running artifact cleanup
    let result = cleaner.cleanup_shell_history();
    
    // THEN: Bash history file removed
    assert!(result.is_ok());
    assert!(!cleaner.filesystem().path_exists(Path::new(history_path)).unwrap());
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn test_cleanup_removes_zsh_history() {
    // GIVEN: Hidden volume with zsh history file
    let config = NailsConfig::builder()
        .hidden_volume_path("/mnt/hidden-volume")
        .build()
        .unwrap();
    
    let mut fs = nails::filesystem::MockFilesystem::new();
    let history_path = "/mnt/hidden-volume/.zsh_history";
    
    fs.mock_set_path_exists(history_path, true);
    fs.mock_create_file(history_path, ": 1234567890:0;cd /secret\n");
    
    let cleaner = ArtifactCleaner::new(config, fs);
    
    // WHEN: Running artifact cleanup
    let result = cleaner.cleanup_shell_history();
    
    // THEN: Zsh history file removed
    assert!(result.is_ok());
    assert!(!cleaner.filesystem().path_exists(Path::new(history_path)).unwrap());
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn test_cleanup_removes_fish_history() {
    // GIVEN: Hidden volume with fish history file
    let config = NailsConfig::builder()
        .hidden_volume_path("/mnt/hidden-volume")
        .build()
        .unwrap();
    
    let mut fs = nails::filesystem::MockFilesystem::new();
    let history_path = "/mnt/hidden-volume/.local/share/fish/fish_history";
    
    fs.mock_set_path_exists(history_path, true);
    fs.mock_create_file(history_path, "- cmd: cd /secret\n  when: 1234567890\n");
    
    let cleaner = ArtifactCleaner::new(config, fs);
    
    // WHEN: Running artifact cleanup
    let result = cleaner.cleanup_shell_history();
    
    // THEN: Fish history file removed
    assert!(result.is_ok());
    assert!(!cleaner.filesystem().path_exists(Path::new(history_path)).unwrap());
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn test_cleanup_handles_missing_history_files_gracefully() {
    // GIVEN: Hidden volume without history files (new environment)
    let config = NailsConfig::builder()
        .hidden_volume_path("/mnt/hidden-volume")
        .build()
        .unwrap();
    
    let fs = nails::filesystem::MockFilesystem::new();
    let cleaner = ArtifactCleaner::new(config, fs);
    
    // WHEN: Running artifact cleanup
    let result = cleaner.cleanup_shell_history();
    
    // THEN: Cleanup succeeds (no-op for missing files)
    assert!(result.is_ok());
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn test_cleanup_only_removes_hidden_volume_history() {
    // GIVEN: Config with decoy system history (should NOT be touched)
    let config = NailsConfig::builder()
        .hidden_volume_path("/mnt/hidden-volume")
        .build()
        .unwrap();
    
    let mut fs = nails::filesystem::MockFilesystem::new();
    
    // Hidden volume history (should be removed)
    let hidden_history = "/mnt/hidden-volume/.bash_history";
    fs.mock_set_path_exists(hidden_history, true);
    fs.mock_create_file(hidden_history, "secret commands\n");
    
    // Decoy system history (should NOT be removed)
    let decoy_history = "/home/user/.bash_history";
    fs.mock_set_path_exists(decoy_history, true);
    fs.mock_create_file(decoy_history, "innocent commands\n");
    
    let cleaner = ArtifactCleaner::new(config, fs.clone());
    
    // WHEN: Running artifact cleanup
    let result = cleaner.cleanup_shell_history();
    
    // THEN: Only hidden volume history removed
    assert!(result.is_ok());
    assert!(!fs.path_exists(Path::new(hidden_history)).unwrap());
    assert!(fs.path_exists(Path::new(decoy_history)).unwrap()); // Decoy untouched
}

// ============================================================================
// P0: Temp File Cleanup (ASR-DATA-1)
// ============================================================================

#[test]
#[should_panic(expected = "not yet implemented")]
fn test_cleanup_removes_hidden_volume_temp_files() {
    // GIVEN: Hidden volume with temp files
    let config = NailsConfig::builder()
        .hidden_volume_path("/mnt/hidden-volume")
        .build()
        .unwrap();
    
    let mut fs = nails::filesystem::MockFilesystem::new();
    
    // Create temp files
    fs.mock_create_file("/mnt/hidden-volume/tmp/secret.tmp", "data");
    fs.mock_create_file("/mnt/hidden-volume/.cache/nails/state.cache", "cache");
    
    let cleaner = ArtifactCleaner::new(config, fs);
    
    // WHEN: Running temp file cleanup
    let result = cleaner.cleanup_temp_files();
    
    // THEN: Temp files removed
    assert!(result.is_ok());
    assert!(!cleaner.filesystem().path_exists(Path::new("/mnt/hidden-volume/tmp/secret.tmp")).unwrap());
    assert!(!cleaner.filesystem().path_exists(Path::new("/mnt/hidden-volume/.cache/nails/state.cache")).unwrap());
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn test_cleanup_preserves_user_data_files() {
    // GIVEN: Hidden volume with user data (not temp files)
    let config = NailsConfig::builder()
        .hidden_volume_path("/mnt/hidden-volume")
        .build()
        .unwrap();
    
    let mut fs = nails::filesystem::MockFilesystem::new();
    
    // User data files (should NOT be removed)
    fs.mock_create_file("/mnt/hidden-volume/documents/important.txt", "user data");
    fs.mock_create_file("/mnt/hidden-volume/projects/code.rs", "source code");
    
    // Temp files (should be removed)
    fs.mock_create_file("/mnt/hidden-volume/tmp/temp.tmp", "temp data");
    
    let cleaner = ArtifactCleaner::new(config, fs.clone());
    
    // WHEN: Running temp file cleanup
    let result = cleaner.cleanup_temp_files();
    
    // THEN: Only temp files removed, user data preserved
    assert!(result.is_ok());
    assert!(fs.path_exists(Path::new("/mnt/hidden-volume/documents/important.txt")).unwrap());
    assert!(fs.path_exists(Path::new("/mnt/hidden-volume/projects/code.rs")).unwrap());
    assert!(!fs.path_exists(Path::new("/mnt/hidden-volume/tmp/temp.tmp")).unwrap());
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn test_cleanup_removes_nails_cache_directory() {
    // GIVEN: Hidden volume with NAILS cache directory
    let config = NailsConfig::builder()
        .hidden_volume_path("/mnt/hidden-volume")
        .build()
        .unwrap();
    
    let mut fs = nails::filesystem::MockFilesystem::new();
    
    // NAILS cache directory
    let cache_dir = "/mnt/hidden-volume/.cache/nails";
    fs.mock_create_directory(cache_dir);
    fs.mock_create_file(&format!("{}/state.cache", cache_dir), "cache");
    
    let cleaner = ArtifactCleaner::new(config, fs);
    
    // WHEN: Running temp file cleanup
    let result = cleaner.cleanup_temp_files();
    
    // THEN: Cache directory completely removed
    assert!(result.is_ok());
    assert!(!cleaner.filesystem().path_exists(Path::new(cache_dir)).unwrap());
}

// ============================================================================
// P0: Log File Cleanup (ASR-OPS-2 - Security Audit Trail)
// ============================================================================

#[test]
#[should_panic(expected = "not yet implemented")]
fn test_cleanup_removes_nails_log_files() {
    // GIVEN: Hidden volume with NAILS log files
    let config = NailsConfig::builder()
        .hidden_volume_path("/mnt/hidden-volume")
        .log_file_path("/mnt/hidden-volume/logs/nails.log")
        .build()
        .unwrap();
    
    let mut fs = nails::filesystem::MockFilesystem::new();
    
    // Log files
    fs.mock_create_file("/mnt/hidden-volume/logs/nails.log", "log entries");
    fs.mock_create_file("/mnt/hidden-volume/logs/nails.log.1", "old logs");
    
    let cleaner = ArtifactCleaner::new(config, fs);
    
    // WHEN: Running log cleanup
    let result = cleaner.cleanup_logs();
    
    // THEN: All log files removed
    assert!(result.is_ok());
    assert!(!cleaner.filesystem().path_exists(Path::new("/mnt/hidden-volume/logs/nails.log")).unwrap());
    assert!(!cleaner.filesystem().path_exists(Path::new("/mnt/hidden-volume/logs/nails.log.1")).unwrap());
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn test_cleanup_removes_empty_log_directory() {
    // GIVEN: Hidden volume with empty log directory after cleanup
    let config = NailsConfig::builder()
        .hidden_volume_path("/mnt/hidden-volume")
        .log_file_path("/mnt/hidden-volume/logs/nails.log")
        .build()
        .unwrap();
    
    let mut fs = nails::filesystem::MockFilesystem::new();
    
    let log_dir = "/mnt/hidden-volume/logs";
    fs.mock_create_directory(log_dir);
    fs.mock_create_file("/mnt/hidden-volume/logs/nails.log", "log entries");
    
    let cleaner = ArtifactCleaner::new(config, fs);
    
    // WHEN: Running log cleanup
    let result = cleaner.cleanup_logs();
    
    // THEN: Log directory also removed (zero traces)
    assert!(result.is_ok());
    assert!(!cleaner.filesystem().path_exists(Path::new(log_dir)).unwrap());
}

// ============================================================================
// P0: State File Cleanup (ASR-DATA-2)
// ============================================================================

#[test]
#[should_panic(expected = "not yet implemented")]
fn test_cleanup_removes_state_file() {
    // GIVEN: Hidden volume with NAILS state file
    let config = NailsConfig::builder()
        .hidden_volume_path("/mnt/hidden-volume")
        .state_file_path("/mnt/hidden-volume/.nails/state.json")
        .build()
        .unwrap();
    
    let mut fs = nails::filesystem::MockFilesystem::new();
    
    fs.mock_create_file("/mnt/hidden-volume/.nails/state.json", r#"{"state": "Active"}"#);
    
    let cleaner = ArtifactCleaner::new(config, fs);
    
    // WHEN: Running state file cleanup
    let result = cleaner.cleanup_state_file();
    
    // THEN: State file removed
    assert!(result.is_ok());
    assert!(!cleaner.filesystem().path_exists(Path::new("/mnt/hidden-volume/.nails/state.json")).unwrap());
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn test_cleanup_removes_state_directory() {
    // GIVEN: Hidden volume with NAILS state directory
    let config = NailsConfig::builder()
        .hidden_volume_path("/mnt/hidden-volume")
        .state_file_path("/mnt/hidden-volume/.nails/state.json")
        .build()
        .unwrap();
    
    let mut fs = nails::filesystem::MockFilesystem::new();
    
    let state_dir = "/mnt/hidden-volume/.nails";
    fs.mock_create_directory(state_dir);
    fs.mock_create_file("/mnt/hidden-volume/.nails/state.json", "state");
    
    let cleaner = ArtifactCleaner::new(config, fs);
    
    // WHEN: Running state file cleanup
    let result = cleaner.cleanup_state_file();
    
    // THEN: State directory also removed (zero traces)
    assert!(result.is_ok());
    assert!(!cleaner.filesystem().path_exists(Path::new(state_dir)).unwrap());
}

// ============================================================================
// P0: Complete Cleanup (All Artifacts)
// ============================================================================

#[test]
#[should_panic(expected = "not yet implemented")]
fn test_cleanup_all_removes_all_artifact_types() {
    // GIVEN: Hidden volume with all artifact types
    let config = NailsConfig::builder()
        .hidden_volume_path("/mnt/hidden-volume")
        .state_file_path("/mnt/hidden-volume/.nails/state.json")
        .log_file_path("/mnt/hidden-volume/logs/nails.log")
        .build()
        .unwrap();
    
    let mut fs = nails::filesystem::MockFilesystem::new();
    
    // Create all artifact types
    fs.mock_create_file("/mnt/hidden-volume/.bash_history", "history");
    fs.mock_create_file("/mnt/hidden-volume/tmp/temp.tmp", "temp");
    fs.mock_create_file("/mnt/hidden-volume/logs/nails.log", "logs");
    fs.mock_create_file("/mnt/hidden-volume/.nails/state.json", "state");
    
    let cleaner = ArtifactCleaner::new(config, fs);
    
    // WHEN: Running complete cleanup
    let result = cleaner.cleanup_all();
    
    // THEN: All artifacts removed
    assert!(result.is_ok());
    assert!(!cleaner.filesystem().path_exists(Path::new("/mnt/hidden-volume/.bash_history")).unwrap());
    assert!(!cleaner.filesystem().path_exists(Path::new("/mnt/hidden-volume/tmp/temp.tmp")).unwrap());
    assert!(!cleaner.filesystem().path_exists(Path::new("/mnt/hidden-volume/logs/nails.log")).unwrap());
    assert!(!cleaner.filesystem().path_exists(Path::new("/mnt/hidden-volume/.nails/state.json")).unwrap());
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn test_cleanup_all_returns_detailed_report() {
    // GIVEN: Hidden volume with artifacts
    let config = NailsConfig::builder()
        .hidden_volume_path("/mnt/hidden-volume")
        .build()
        .unwrap();
    
    let mut fs = nails::filesystem::MockFilesystem::new();
    
    fs.mock_create_file("/mnt/hidden-volume/.bash_history", "history");
    fs.mock_create_file("/mnt/hidden-volume/tmp/temp.tmp", "temp");
    
    let cleaner = ArtifactCleaner::new(config, fs);
    
    // WHEN: Running complete cleanup
    let report = cleaner.cleanup_all().unwrap();
    
    // THEN: Report includes counts
    assert_eq!(report.history_files_removed, 1);
    assert_eq!(report.temp_files_removed, 1);
    assert_eq!(report.log_files_removed, 0);
    assert_eq!(report.state_files_removed, 0);
    assert_eq!(report.total_files_removed, 2);
}

// ============================================================================
// P0: Verification Step (Completeness Check)
// ============================================================================

#[test]
#[should_panic(expected = "not yet implemented")]
fn test_verify_cleanup_succeeds_when_no_artifacts_remain() {
    // GIVEN: Hidden volume after complete cleanup
    let config = NailsConfig::builder()
        .hidden_volume_path("/mnt/hidden-volume")
        .build()
        .unwrap();
    
    let fs = nails::filesystem::MockFilesystem::new();
    let cleaner = ArtifactCleaner::new(config, fs);
    
    // WHEN: Verifying cleanup
    let result = cleaner.verify_cleanup();
    
    // THEN: Verification succeeds (no artifacts found)
    assert!(result.is_ok());
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn test_verify_cleanup_fails_if_history_remains() {
    // GIVEN: Hidden volume with remaining history file
    let config = NailsConfig::builder()
        .hidden_volume_path("/mnt/hidden-volume")
        .build()
        .unwrap();
    
    let mut fs = nails::filesystem::MockFilesystem::new();
    fs.mock_create_file("/mnt/hidden-volume/.bash_history", "remaining history");
    
    let cleaner = ArtifactCleaner::new(config, fs);
    
    // WHEN: Verifying cleanup
    let result = cleaner.verify_cleanup();
    
    // THEN: Verification fails with details
    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(error.to_string().contains("bash_history"));
    assert!(error.to_string().contains("incomplete cleanup"));
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn test_verify_cleanup_fails_if_temp_files_remain() {
    // GIVEN: Hidden volume with remaining temp files
    let config = NailsConfig::builder()
        .hidden_volume_path("/mnt/hidden-volume")
        .build()
        .unwrap();
    
    let mut fs = nails::filesystem::MockFilesystem::new();
    fs.mock_create_file("/mnt/hidden-volume/tmp/leftover.tmp", "temp");
    
    let cleaner = ArtifactCleaner::new(config, fs);
    
    // WHEN: Verifying cleanup
    let result = cleaner.verify_cleanup();
    
    // THEN: Verification fails
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("temp"));
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn test_verify_cleanup_returns_list_of_remaining_artifacts() {
    // GIVEN: Hidden volume with multiple remaining artifacts
    let config = NailsConfig::builder()
        .hidden_volume_path("/mnt/hidden-volume")
        .build()
        .unwrap();
    
    let mut fs = nails::filesystem::MockFilesystem::new();
    
    fs.mock_create_file("/mnt/hidden-volume/.bash_history", "history");
    fs.mock_create_file("/mnt/hidden-volume/tmp/temp.tmp", "temp");
    fs.mock_create_file("/mnt/hidden-volume/.nails/state.json", "state");
    
    let cleaner = ArtifactCleaner::new(config, fs);
    
    // WHEN: Verifying cleanup
    let result = cleaner.verify_cleanup();
    
    // THEN: Error includes all remaining artifacts
    assert!(result.is_err());
    let error = result.unwrap_err();
    
    if let nails::error::NailsError::IncompleteCleanup { remaining_artifacts } = error {
        assert_eq!(remaining_artifacts.len(), 3);
        assert!(remaining_artifacts.contains(&PathBuf::from("/mnt/hidden-volume/.bash_history")));
        assert!(remaining_artifacts.contains(&PathBuf::from("/mnt/hidden-volume/tmp/temp.tmp")));
        assert!(remaining_artifacts.contains(&PathBuf::from("/mnt/hidden-volume/.nails/state.json")));
    } else {
        panic!("Expected IncompleteCleanup error");
    }
}

// ============================================================================
// P0: Emergency Cleanup (Best-Effort Mode)
// ============================================================================

#[test]
#[should_panic(expected = "not yet implemented")]
fn test_emergency_cleanup_continues_on_errors() {
    // GIVEN: Hidden volume with artifacts, some deletions will fail
    let config = NailsConfig::builder()
        .hidden_volume_path("/mnt/hidden-volume")
        .build()
        .unwrap();
    
    let mut fs = nails::filesystem::MockFilesystem::new();
    
    // File that will fail deletion (permission denied)
    fs.mock_create_file("/mnt/hidden-volume/.bash_history", "history");
    fs.mock_set_permissions("/mnt/hidden-volume/.bash_history", 0o000); // No permissions
    
    // File that will succeed
    fs.mock_create_file("/mnt/hidden-volume/tmp/temp.tmp", "temp");
    
    let cleaner = ArtifactCleaner::new(config, fs);
    
    // WHEN: Running emergency cleanup (best-effort)
    let result = cleaner.emergency_cleanup();
    
    // THEN: Cleanup continues despite errors (best-effort)
    assert!(result.is_ok());
    
    let report = result.unwrap();
    assert_eq!(report.errors_encountered, 1);
    assert_eq!(report.temp_files_removed, 1);
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn test_emergency_cleanup_skips_verification() {
    // GIVEN: Hidden volume after emergency cleanup with some artifacts remaining
    let config = NailsConfig::builder()
        .hidden_volume_path("/mnt/hidden-volume")
        .build()
        .unwrap();
    
    let mut fs = nails::filesystem::MockFilesystem::new();
    
    // Artifact that couldn't be removed
    fs.mock_create_file("/mnt/hidden-volume/.bash_history", "history");
    fs.mock_set_permissions("/mnt/hidden-volume/.bash_history", 0o000);
    
    let cleaner = ArtifactCleaner::new(config, fs);
    
    // WHEN: Running emergency cleanup
    let result = cleaner.emergency_cleanup();
    
    // THEN: Succeeds despite remaining artifacts (no verification)
    assert!(result.is_ok());
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn test_emergency_cleanup_completes_within_timeout() {
    // GIVEN: Hidden volume with many artifacts
    let config = NailsConfig::builder()
        .hidden_volume_path("/mnt/hidden-volume")
        .emergency_timeout_ms(500) // 500ms timeout
        .build()
        .unwrap();
    
    let mut fs = nails::filesystem::MockFilesystem::new();
    
    // Create many artifacts
    for i in 0..100 {
        fs.mock_create_file(&format!("/mnt/hidden-volume/tmp/file{}.tmp", i), "data");
    }
    
    let cleaner = ArtifactCleaner::new(config, fs);
    
    // WHEN: Running emergency cleanup
    let start = std::time::Instant::now();
    let result = cleaner.emergency_cleanup();
    let duration = start.elapsed();
    
    // THEN: Completes within timeout (or stops at timeout)
    assert!(result.is_ok());
    assert!(duration.as_millis() < 600); // 100ms buffer for overhead
}

// ============================================================================
// P0: Alias Cleanup (Shell RC Files)
// ============================================================================

#[test]
#[should_panic(expected = "not yet implemented")]
fn test_cleanup_removes_nails_alias_from_bashrc() {
    // GIVEN: .bashrc with NAILS alias marker
    let config = NailsConfig::builder()
        .hidden_volume_path("/mnt/hidden-volume")
        .build()
        .unwrap();
    
    let mut fs = nails::filesystem::MockFilesystem::new();
    
    let bashrc_path = "/home/user/.bashrc";
    let bashrc_content = r#"
# User's existing config
export PATH=$PATH:/usr/local/bin

# NAILS-ALIAS-MARKER
alias nails='sudo /mnt/hidden-volume/nails/bin/nails'

# More user config
alias ll='ls -la'
"#;
    
    fs.mock_create_file(bashrc_path, bashrc_content);
    
    let cleaner = ArtifactCleaner::new(config, fs.clone());
    
    // WHEN: Cleaning up aliases (emergency mode)
    let result = cleaner.cleanup_aliases();
    
    // THEN: NAILS alias removed from .bashrc
    assert!(result.is_ok());
    
    let new_content = fs.read_file(bashrc_path).unwrap();
    assert!(!new_content.contains("NAILS-ALIAS-MARKER"));
    assert!(!new_content.contains("alias nails="));
    assert!(new_content.contains("export PATH")); // User config preserved
    assert!(new_content.contains("alias ll")); // User config preserved
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn test_cleanup_preserves_non_nails_aliases() {
    // GIVEN: .bashrc with NAILS alias and user aliases
    let config = NailsConfig::builder()
        .hidden_volume_path("/mnt/hidden-volume")
        .build()
        .unwrap();
    
    let mut fs = nails::filesystem::MockFilesystem::new();
    
    let bashrc_path = "/home/user/.bashrc";
    let bashrc_content = r#"
alias ll='ls -la'
alias gs='git status'

# NAILS-ALIAS-MARKER
alias nails='sudo /mnt/hidden-volume/nails/bin/nails'

alias gp='git pull'
"#;
    
    fs.mock_create_file(bashrc_path, bashrc_content);
    
    let cleaner = ArtifactCleaner::new(config, fs.clone());
    
    // WHEN: Cleaning up aliases
    let result = cleaner.cleanup_aliases();
    
    // THEN: Only NAILS alias removed, user aliases preserved
    assert!(result.is_ok());
    
    let new_content = fs.read_file(bashrc_path).unwrap();
    assert!(!new_content.contains("alias nails="));
    assert!(new_content.contains("alias ll='ls -la'"));
    assert!(new_content.contains("alias gs='git status'"));
    assert!(new_content.contains("alias gp='git pull'"));
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn test_cleanup_handles_missing_alias_gracefully() {
    // GIVEN: .bashrc without NAILS alias (never activated)
    let config = NailsConfig::builder()
        .hidden_volume_path("/mnt/hidden-volume")
        .build()
        .unwrap();
    
    let mut fs = nails::filesystem::MockFilesystem::new();
    
    let bashrc_path = "/home/user/.bashrc";
    fs.mock_create_file(bashrc_path, "# User's bashrc\nalias ll='ls -la'\n");
    
    let cleaner = ArtifactCleaner::new(config, fs);
    
    // WHEN: Cleaning up aliases
    let result = cleaner.cleanup_aliases();
    
    // THEN: Succeeds as no-op (no alias to remove)
    assert!(result.is_ok());
}
