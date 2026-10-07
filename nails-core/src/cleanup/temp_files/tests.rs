// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests for TempFilesCleaner

use super::*;
use crate::MockFilesystem;
use crate::filesystem::PathKind;

#[test]
fn test_temp_files_cleaner_new() {
    // Configuration only: the filesystem is never touched.
    let fs = crate::RealFilesystem;
    let cleaner = TempFilesCleaner::new(fs);

    assert_eq!(cleaner.temp_dirs, vec![PathBuf::from("/tmp")]);
    assert_eq!(cleaner.patterns, vec!["nails".to_string()]);
}

#[test]
fn test_with_temp_dirs() {
    // Configuration only: the filesystem is never touched.
    let fs = crate::RealFilesystem;
    let custom_dirs = vec![PathBuf::from("/custom/tmp"), PathBuf::from("/another/tmp")];
    let cleaner = TempFilesCleaner::new(fs).with_temp_dirs(custom_dirs.clone());

    assert_eq!(cleaner.temp_dirs, custom_dirs);
}

#[test]
fn test_with_patterns() {
    // Configuration only: the filesystem is never touched.
    let fs = crate::RealFilesystem;
    let custom_patterns = vec!["test1".to_string(), "test2".to_string()];
    let cleaner = TempFilesCleaner::new(fs).with_patterns(custom_patterns.clone());

    assert_eq!(cleaner.patterns, custom_patterns);
}

#[test]
fn test_safety_validation_blocks_root() {
    let fs = MockFilesystem::new();
    let cleaner = TempFilesCleaner::new(fs).with_temp_dirs(vec![PathBuf::from("/")]);

    let result = cleaner.clean();
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("system-critical"));
    assert!(err_msg.contains("/"));
}

#[test]
fn test_safety_validation_blocks_etc() {
    let fs = MockFilesystem::new();
    let cleaner = TempFilesCleaner::new(fs).with_temp_dirs(vec![PathBuf::from("/etc")]);

    let result = cleaner.clean();
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("system-critical"));
}

#[test]
fn test_safety_validation_blocks_home() {
    let fs = MockFilesystem::new();
    let cleaner = TempFilesCleaner::new(fs).with_temp_dirs(vec![PathBuf::from("/home")]);

    let result = cleaner.clean();
    assert!(result.is_err());
}

#[test]
fn test_safety_validation_blocks_var() {
    let fs = MockFilesystem::new();
    let cleaner = TempFilesCleaner::new(fs).with_temp_dirs(vec![PathBuf::from("/var")]);

    let result = cleaner.clean();
    assert!(result.is_err());
}

#[test]
fn test_safety_validation_blocks_usr() {
    let fs = MockFilesystem::new();
    let cleaner = TempFilesCleaner::new(fs).with_temp_dirs(vec![PathBuf::from("/usr")]);

    let result = cleaner.clean();
    assert!(result.is_err());
}

#[test]
fn test_safety_validation_blocks_home_subdirectory() {
    let fs = MockFilesystem::new();
    let cleaner = TempFilesCleaner::new(fs).with_temp_dirs(vec![PathBuf::from("/home/user")]);

    let result = cleaner.clean();
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("system-critical path"));
}

#[test]
fn test_safety_validation_allows_tmp() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/tmp", true);
    fs.mock_set_files_with_pattern("/tmp", "nails", &[]);

    let cleaner = TempFilesCleaner::new(fs);
    let result = cleaner.clean();
    assert!(result.is_ok());
}

#[test]
fn test_safety_validation_allows_tmp_subdirectory() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/tmp/custom", true);
    fs.mock_set_files_with_pattern("/tmp/custom", "nails", &[]);

    let cleaner = TempFilesCleaner::new(fs).with_temp_dirs(vec![PathBuf::from("/tmp/custom")]);
    let result = cleaner.clean();
    assert!(result.is_ok());
}

#[test]
fn test_safety_validation_allows_run_nails() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/run/nails", true);
    fs.mock_set_files_with_pattern("/run/nails", "nails", &[]);

    let cleaner = TempFilesCleaner::new(fs).with_temp_dirs(vec![PathBuf::from("/run/nails")]);
    let result = cleaner.clean();
    assert!(result.is_ok());
}

#[test]
fn test_safety_validation_blocks_run_without_nails() {
    let fs = MockFilesystem::new();
    let cleaner = TempFilesCleaner::new(fs).with_temp_dirs(vec![PathBuf::from("/run")]);

    let result = cleaner.clean();
    assert!(result.is_err());
}

#[test]
fn test_safety_validation_blocks_run_nails_prefix_trick() {
    let fs = MockFilesystem::new();
    let cleaner = TempFilesCleaner::new(fs).with_temp_dirs(vec![PathBuf::from("/run/nails-evil")]);

    let result = cleaner.clean();
    assert!(
        result.is_err(),
        "Should block /run/nails-evil (prefix trick)"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("system-critical path"));
}

#[test]
fn test_pattern_matching_case_insensitive() {
    // Pure name matching: the filesystem is never touched.
    let cleaner = TempFilesCleaner::new(crate::RealFilesystem);

    assert!(cleaner.matches_pattern("nails-12345.lock"));
    assert!(cleaner.matches_pattern("NAILS-build-cache"));
    assert!(cleaner.matches_pattern("some-NaIlS-temp.txt"));
    assert!(cleaner.matches_pattern("prefix-nails-suffix"));
    assert!(!cleaner.matches_pattern("nails-headless.yaml"));
    assert!(!cleaner.matches_pattern("unrelated-file.txt"));
}

#[test]
fn test_pattern_matching_multiple_patterns() {
    let cleaner = TempFilesCleaner::new(crate::RealFilesystem)
        .with_patterns(vec!["nails".to_string(), "test".to_string()]);

    assert!(cleaner.matches_pattern("nails-file"));
    assert!(cleaner.matches_pattern("test-file"));
    assert!(cleaner.matches_pattern("NAILS-TEST-file"));
    assert!(!cleaner.matches_pattern("unrelated-file"));
}

#[test]
fn test_cleanup_continues_on_permission_error() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/tmp", true);
    fs.mock_set_files_with_pattern(
        "/tmp",
        "nails",
        &[
            Path::new("/tmp/nails-readonly.lock"),
            Path::new("/tmp/nails-normal.txt"),
        ],
    );
    fs.mock_set_path_exists("/tmp/nails-readonly.lock", true);
    fs.mock_set_path_exists("/tmp/nails-normal.txt", true);
    fs.mock_set_path_type("/tmp/nails-readonly.lock", PathKind::File);
    fs.mock_set_path_type("/tmp/nails-normal.txt", PathKind::File);

    // Configure first file to fail removal
    fs.mock_set_remove_should_fail("/tmp/nails-readonly.lock", true);

    let cleaner = TempFilesCleaner::new(fs);
    let result = cleaner.clean();

    // Should succeed overall (best-effort)
    assert!(result.is_ok());
    let cleaned = result.unwrap();
    // Should have cleaned the second file
    assert!(cleaned.iter().any(|s| s.contains("nails-normal.txt")));
}
