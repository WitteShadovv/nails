//! Tests for TempFilesCleaner

use super::*;
use crate::MockFilesystem;

#[test]
fn test_temp_files_cleaner_new() {
    let fs = MockFilesystem::new();
    let cleaner = TempFilesCleaner::new(fs);

    assert_eq!(cleaner.temp_dirs, vec![PathBuf::from("/tmp")]);
    assert_eq!(cleaner.patterns, vec!["nails".to_string()]);
}

#[test]
fn test_with_temp_dirs() {
    let fs = MockFilesystem::new();
    let custom_dirs = vec![PathBuf::from("/custom/tmp"), PathBuf::from("/another/tmp")];
    let cleaner = TempFilesCleaner::new(fs).with_temp_dirs(custom_dirs.clone());

    assert_eq!(cleaner.temp_dirs, custom_dirs);
}

#[test]
fn test_with_patterns() {
    let fs = MockFilesystem::new();
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
    let fs = MockFilesystem::new();
    let cleaner = TempFilesCleaner::new(fs);

    assert!(cleaner.matches_pattern("nails-12345.lock"));
    assert!(cleaner.matches_pattern("NAILS-build-cache"));
    assert!(cleaner.matches_pattern("some-NaIlS-temp.txt"));
    assert!(cleaner.matches_pattern("prefix-nails-suffix"));
    assert!(!cleaner.matches_pattern("nails-headless.yaml"));
    assert!(!cleaner.matches_pattern("unrelated-file.txt"));
}

#[test]
fn test_pattern_matching_multiple_patterns() {
    let fs = MockFilesystem::new();
    let cleaner =
        TempFilesCleaner::new(fs).with_patterns(vec!["nails".to_string(), "test".to_string()]);

    assert!(cleaner.matches_pattern("nails-file"));
    assert!(cleaner.matches_pattern("test-file"));
    assert!(cleaner.matches_pattern("NAILS-TEST-file"));
    assert!(!cleaner.matches_pattern("unrelated-file"));
}

#[test]
fn test_cleanup_removes_matching_files() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/tmp", true);
    fs.mock_set_files_with_pattern(
        "/tmp",
        "nails",
        &[
            Path::new("/tmp/nails-12345.lock"),
            Path::new("/tmp/nails_cache"),
        ],
    );
    fs.mock_set_path_exists("/tmp/nails-12345.lock", true);
    fs.mock_set_path_exists("/tmp/nails_cache", true);
    fs.mock_set_path_type("/tmp/nails-12345.lock", "file");
    fs.mock_set_path_type("/tmp/nails_cache", "directory");

    let cleaner = TempFilesCleaner::new(fs);
    let result = cleaner.clean().unwrap();

    assert_eq!(result.len(), 2);
    assert!(result.iter().any(|s| s.contains("nails-12345.lock")));
    assert!(result.iter().any(|s| s.contains("nails_cache")));
}

#[test]
fn test_cleanup_preserves_nails_config_files() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/tmp", true);
    fs.mock_set_files_with_pattern(
        "/tmp",
        "nails",
        &[
            Path::new("/tmp/nails-headless.yaml"),
            Path::new("/tmp/nails-overlay.toml"),
            Path::new("/tmp/nails-12345.lock"),
        ],
    );
    fs.mock_set_path_exists("/tmp/nails-headless.yaml", true);
    fs.mock_set_path_exists("/tmp/nails-overlay.toml", true);
    fs.mock_set_path_exists("/tmp/nails-12345.lock", true);
    fs.mock_set_path_type("/tmp/nails-headless.yaml", "file");
    fs.mock_set_path_type("/tmp/nails-overlay.toml", "file");
    fs.mock_set_path_type("/tmp/nails-12345.lock", "file");

    let cleaner = TempFilesCleaner::new(fs.clone());
    let result = cleaner.clean().unwrap();

    assert_eq!(result.len(), 1);
    assert!(result.iter().any(|s| s.contains("nails-12345.lock")));
    assert!(
        fs.path_exists(Path::new("/tmp/nails-headless.yaml"))
            .unwrap()
    );
    assert!(
        fs.path_exists(Path::new("/tmp/nails-overlay.toml"))
            .unwrap()
    );
}

#[test]
fn test_cleanup_empty_result_when_no_matches() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/tmp", true);
    fs.mock_set_files_with_pattern("/tmp", "nails", &[]); // No matching files

    let cleaner = TempFilesCleaner::new(fs);
    let result = cleaner.clean().unwrap();

    assert_eq!(result.len(), 0);
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
    fs.mock_set_path_type("/tmp/nails-readonly.lock", "file");
    fs.mock_set_path_type("/tmp/nails-normal.txt", "file");

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

#[test]
fn test_cleanup_preserves_explicit_config_path() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/tmp", true);
    fs.mock_set_files_with_pattern(
        "/tmp",
        "nails",
        &[
            Path::new("/tmp/nails-tracker-integrity.yaml"),
            Path::new("/tmp/nails-status.stdout"),
        ],
    );
    fs.mock_set_path_exists("/tmp/nails-tracker-integrity.yaml", true);
    fs.mock_set_path_exists("/tmp/nails-status.stdout", true);
    fs.mock_set_path_type("/tmp/nails-tracker-integrity.yaml", "file");
    fs.mock_set_path_type("/tmp/nails-status.stdout", "file");

    let cleaner = TempFilesCleaner::new(fs.clone())
        .with_preserved_paths(vec![PathBuf::from("/tmp/nails-tracker-integrity.yaml")]);

    let cleaned = cleaner.clean().unwrap();

    assert!(
        cleaned.iter().any(|s| s.contains("nails-status.stdout")),
        "expected non-preserved temp file to be cleaned"
    );
    assert!(
        fs.path_exists(Path::new("/tmp/nails-tracker-integrity.yaml"))
            .expect("preserved config path should still be queryable"),
        "explicit config path should be preserved"
    );
}

#[test]
fn test_filesystem_trait_contract_honored() {
    // Verify MockFilesystem::find_files_with_pattern honors the trait contract
    // by only returning files that actually match the pattern
    let fs = MockFilesystem::new();

    // Set up specific files matching "nails" pattern
    let matching_files = [
        PathBuf::from("/tmp/nails-12345.lock"),
        PathBuf::from("/tmp/nails_cache"),
        PathBuf::from("/tmp/NAILS-UPPER"),
    ];

    // Set up files that should NOT match
    let non_matching_files = [
        PathBuf::from("/tmp/unrelated-file.txt"),
        PathBuf::from("/tmp/other-cache"),
    ];

    fs.mock_set_files_with_pattern(
        "/tmp",
        "nails",
        &matching_files
            .iter()
            .map(|p| p.as_path())
            .collect::<Vec<_>>(),
    );

    // Verify that only matching files are returned
    let result = fs.find_files_with_pattern(Path::new("/tmp"), "nails");
    assert!(result.is_ok());

    let returned_files = result.unwrap();
    assert_eq!(
        returned_files.len(),
        matching_files.len(),
        "Should return exactly the files set via mock_set_files_with_pattern"
    );

    // Verify all returned files were in our matching set
    for file in &returned_files {
        assert!(
            matching_files.contains(file),
            "Returned file {:?} should be in matching_files set",
            file
        );
        assert!(
            !non_matching_files.contains(file),
            "Returned file {:?} should NOT be in non_matching_files set",
            file
        );
    }
}
