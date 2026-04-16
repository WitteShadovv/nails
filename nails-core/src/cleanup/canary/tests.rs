//! Tests for CanaryScanner

use super::*;
use crate::MockFilesystem;

#[test]
fn test_canary_config_default() {
    let config = CanaryConfig::default();
    assert!(config.forbidden_patterns.contains(&"nails".to_string()));
    assert!(config.forbidden_patterns.contains(&"veracrypt".to_string()));
    assert!(
        config
            .forbidden_patterns
            .contains(&"cryptsetup".to_string())
    );
    assert!(config.forbidden_patterns.contains(&"tcrypt".to_string()));
    assert!(
        config
            .forbidden_patterns
            .contains(&"/mnt/hidden".to_string())
    );
    assert!(
        config
            .forbidden_patterns
            .contains(&"hidden-volume".to_string())
    );
    assert!(
        config
            .forbidden_patterns
            .contains(&"hidden_volume".to_string())
    );
    assert!(
        config
            .forbidden_patterns
            .contains(&"NAILS_CANARY".to_string())
    );
    assert!(config.scan_paths.is_empty());
    assert_eq!(config.max_file_size, 10 * 1024 * 1024);
}

#[test]
fn test_canary_config_builder() {
    let config = CanaryConfig::default()
        .with_patterns(vec!["custom".to_string()])
        .with_scan_paths(vec![PathBuf::from("/custom/path")])
        .with_max_file_size(1024);

    assert_eq!(config.forbidden_patterns, vec!["custom".to_string()]);
    assert_eq!(config.scan_paths, vec![PathBuf::from("/custom/path")]);
    assert_eq!(config.max_file_size, 1024);
}

#[test]
fn test_canary_scan_result_new() {
    let result = CanaryScanResult::new();
    assert!(result.is_clean());
    assert_eq!(result.finding_count(), 0);
    assert!(result.scanned_paths.is_empty());
    assert!(result.skipped_paths.is_empty());
    assert!(result.errors.is_empty());
}

#[test]
fn test_canary_scan_result_with_findings() {
    let mut result = CanaryScanResult::new();
    result.add_finding(CanaryFinding {
        path: PathBuf::from("/test"),
        pattern: "nails".to_string(),
        line_number: Some(1),
        context: Some("nails activate".to_string()),
    });

    assert!(!result.is_clean());
    assert_eq!(result.finding_count(), 1);
}

#[test]
fn test_scanner_detects_forbidden_pattern() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/test/history", true);
    fs.mock_set_file_content("/test/history", "ls\nnails activate\ncd /home\n");

    // Use specific patterns to get predictable results
    let config = CanaryConfig::default()
        .with_patterns(vec!["nails".to_string()]) // Only one pattern
        .with_scan_paths(vec![PathBuf::from("/test/history")]);
    let scanner = CanaryScanner::new(fs, config);

    let result = scanner.scan();
    assert!(!result.is_clean());
    assert_eq!(result.finding_count(), 1);
    assert_eq!(result.findings[0].pattern, "nails");
    assert_eq!(result.findings[0].line_number, Some(2));
}

#[test]
fn test_scanner_case_insensitive() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/test/history", true);
    fs.mock_set_file_content("/test/history", "NAILS_CANARY\n");

    let config = CanaryConfig::default()
        .with_patterns(vec!["nails_canary".to_string()])
        .with_scan_paths(vec![PathBuf::from("/test/history")]);
    let scanner = CanaryScanner::new(fs, config);

    let result = scanner.scan();
    assert!(!result.is_clean());
}

#[test]
fn test_scanner_clean_file() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/test/history", true);
    fs.mock_set_file_content("/test/history", "ls\ncd /home\nexit\n");

    let config = CanaryConfig::default().with_scan_paths(vec![PathBuf::from("/test/history")]);
    let scanner = CanaryScanner::new(fs, config);

    let result = scanner.scan();
    assert!(result.is_clean());
    assert_eq!(result.scanned_paths.len(), 1);
}

#[test]
fn test_scanner_skips_missing_files() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/test/missing", false);

    let config = CanaryConfig::default().with_scan_paths(vec![PathBuf::from("/test/missing")]);
    let scanner = CanaryScanner::new(fs, config);

    let result = scanner.scan();
    assert!(result.is_clean());
    assert_eq!(result.skipped_paths.len(), 1);
    assert_eq!(result.skipped_paths[0].1, "File not found");
}

#[test]
fn test_scanner_skips_large_files() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/test/largefile", true);
    fs.mock_set_file_size("/test/largefile", 100 * 1024 * 1024); // 100MB

    let config = CanaryConfig::default().with_scan_paths(vec![PathBuf::from("/test/largefile")]);
    let scanner = CanaryScanner::new(fs, config);

    let result = scanner.scan();
    assert!(result.is_clean());
    assert_eq!(result.skipped_paths.len(), 1);
    assert!(result.skipped_paths[0].1.contains("too large"));
}

#[test]
fn test_scanner_multiple_patterns() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/test/history", true);
    fs.mock_set_file_content(
        "/test/history",
        "nails activate\nhidden-volume mount\nsecret-project\n",
    );

    let config = CanaryConfig::default().with_scan_paths(vec![PathBuf::from("/test/history")]);
    let scanner = CanaryScanner::new(fs, config);

    let result = scanner.scan();
    assert!(!result.is_clean());
    // Should find nails, hidden-volume, and secret-project
    assert!(result.finding_count() >= 3);
}

#[test]
fn test_scanner_truncates_long_context() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/test/history", true);

    // Create a very long line
    let long_line = format!("nails {}", "x".repeat(200));
    fs.mock_set_file_content("/test/history", &long_line);

    let config = CanaryConfig::default().with_scan_paths(vec![PathBuf::from("/test/history")]);
    let scanner = CanaryScanner::new(fs, config);

    let result = scanner.scan();
    assert!(!result.is_clean());
    let context = result.findings[0].context.as_ref().unwrap();
    assert!(context.len() <= 103); // 100 chars + "..."
    assert!(context.ends_with("..."));
}
