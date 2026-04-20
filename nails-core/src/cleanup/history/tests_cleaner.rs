//! Tests for HistoryCleaner and fish history filtering

use super::*;
use crate::MockFilesystem;

/// Test home directory path - safe for tests, doesn't exist on real filesystem
const TEST_HOME: &str = "/home/testuser";

fn test_home() -> PathBuf {
    PathBuf::from(TEST_HOME)
}

// ============================================================================
// HistoryCleaner tests (using with_home for explicit path)
// ============================================================================

#[test]
fn test_history_cleaner_new() {
    let fs = MockFilesystem::new();
    let cleaner = HistoryCleaner::new(fs);

    assert_eq!(cleaner.test_patterns(), ["nails".to_string()]);
    assert_eq!(cleaner.test_shells().len(), 3);
    assert!(!cleaner.secure_delete);
    assert!(cleaner.test_home().is_none());
}

#[test]
fn test_history_cleaner_with_home() {
    let fs = MockFilesystem::new();
    let cleaner = HistoryCleaner::new(fs).with_home(test_home());

    assert_eq!(cleaner.test_home(), Some(&test_home()));
}

#[test]
fn test_history_cleaner_with_patterns() {
    let fs = MockFilesystem::new();
    let patterns = vec!["test1".to_string(), "test2".to_string()];
    let cleaner = HistoryCleaner::new(fs).with_patterns(patterns.clone());

    assert_eq!(cleaner.test_patterns(), patterns);
}

#[test]
fn test_history_cleaner_with_shells() {
    let fs = MockFilesystem::new();
    let shells = vec![ShellType::Bash, ShellType::Fish];
    let cleaner = HistoryCleaner::new(fs).with_shells(shells.clone());

    assert_eq!(cleaner.test_shells(), shells);
}

#[test]
fn test_case_insensitive_pattern_matching() {
    let fs = MockFilesystem::new();
    let cleaner = HistoryCleaner::new(fs);

    assert!(cleaner.line_matches_patterns("nails activate"));
    assert!(cleaner.line_matches_patterns("NAILS status"));
    assert!(cleaner.line_matches_patterns("sudo NaIlS emergency"));
    assert!(cleaner.line_matches_patterns("grep nails log.txt"));
    assert!(!cleaner.line_matches_patterns("ls -la"));
}

#[test]
fn test_partial_line_removal() {
    let fs = MockFilesystem::new();
    let cleaner = HistoryCleaner::new(fs);

    // Lines with nails anywhere should match
    assert!(cleaner.line_matches_patterns("nails activate && ls"));
    assert!(cleaner.line_matches_patterns("echo test | nails"));
    assert!(cleaner.line_matches_patterns("vim /etc/nails.conf"));
}

#[test]
fn test_history_file_cleanup() {
    let fs = MockFilesystem::new();
    let home = test_home();

    let bash_history = PathBuf::from("/home/testuser/.bash_history");
    fs.mock_set_file_content(
        bash_history.to_str().unwrap(),
        "ls -la\nnails activate\ncd /tmp\nNAILS status\ngrep nails logfile.txt\nvim nails_config.yaml\n",
    );
    fs.mock_set_path_exists(bash_history.to_str().unwrap(), true);

    let cleaner = HistoryCleaner::new(fs.clone())
        .with_home(home)
        .with_shells(vec![ShellType::Bash]);

    let result = cleaner.clean().unwrap();

    // Should report removal of 4 entries (nails activate, NAILS status, grep nails, vim nails)
    assert_eq!(result.len(), 1);
    assert!(result[0].contains("Removed 4 entries"));

    // Verify the file was written with filtered content
    let written_content = fs.get_written_content(&bash_history).unwrap();
    assert_eq!(written_content, "ls -la\ncd /tmp\n");
}

#[test]
fn test_missing_history_file() {
    let fs = MockFilesystem::new();
    let home = test_home();
    // Don't set up any history files

    let cleaner = HistoryCleaner::new(fs).with_home(home);
    let result = cleaner.clean().unwrap();

    // Should succeed with empty results (no files to clean)
    // No errors should be raised for missing files
    assert_eq!(result.len(), 0);
}

#[test]
fn test_empty_history_file() {
    let fs = MockFilesystem::new();
    let home = test_home();

    let bash_history = PathBuf::from("/home/testuser/.bash_history");
    fs.mock_set_file_content(bash_history.to_str().unwrap(), "");
    fs.mock_set_path_exists(bash_history.to_str().unwrap(), true);

    let cleaner = HistoryCleaner::new(fs.clone())
        .with_home(home)
        .with_shells(vec![ShellType::Bash]);

    let result = cleaner.clean().unwrap();

    // Should report no matching entries
    assert_eq!(result.len(), 1);
    assert!(result[0].contains("No matching entries"));
}

#[test]
fn test_history_file_with_no_matches() {
    let fs = MockFilesystem::new();
    let home = test_home();

    let bash_history = PathBuf::from("/home/testuser/.bash_history");
    fs.mock_set_file_content(bash_history.to_str().unwrap(), "ls -la\ncd /tmp\npwd\n");
    fs.mock_set_path_exists(bash_history.to_str().unwrap(), true);

    let cleaner = HistoryCleaner::new(fs.clone())
        .with_home(home)
        .with_shells(vec![ShellType::Bash]);

    let result = cleaner.clean().unwrap();

    // Should report no matching entries
    assert_eq!(result.len(), 1);
    assert!(result[0].contains("No matching entries"));

    // File should not be modified
    let written = fs.get_written_content(&bash_history);
    assert!(written.is_none());
}

#[test]
fn test_history_file_all_matches_removed() {
    let fs = MockFilesystem::new();
    let home = test_home();

    let bash_history = PathBuf::from("/home/testuser/.bash_history");
    fs.mock_set_file_content(
        bash_history.to_str().unwrap(),
        "nails activate\nNAILS status\n",
    );
    fs.mock_set_path_exists(bash_history.to_str().unwrap(), true);

    let cleaner = HistoryCleaner::new(fs.clone())
        .with_home(home)
        .with_shells(vec![ShellType::Bash]);

    let result = cleaner.clean().unwrap();

    // Should report removal of 2 entries
    assert_eq!(result.len(), 1);
    assert!(result[0].contains("Removed 2 entries"));

    // File should be empty
    let written_content = fs.get_written_content(&bash_history).unwrap();
    assert_eq!(written_content, "");
}

#[test]
fn test_multiple_shells_cleanup() {
    let fs = MockFilesystem::new();
    let home = test_home();

    let bash_history = PathBuf::from("/home/testuser/.bash_history");
    let zsh_history = PathBuf::from("/home/testuser/.zsh_history");

    fs.mock_set_file_content(bash_history.to_str().unwrap(), "ls -la\nnails activate\n");
    fs.mock_set_path_exists(bash_history.to_str().unwrap(), true);

    fs.mock_set_file_content(zsh_history.to_str().unwrap(), "pwd\nNAILS status\n");
    fs.mock_set_path_exists(zsh_history.to_str().unwrap(), true);

    let cleaner = HistoryCleaner::new(fs.clone())
        .with_home(home)
        .with_shells(vec![ShellType::Bash, ShellType::Zsh]);

    let result = cleaner.clean().unwrap();

    // Should report removal from both shells
    assert_eq!(result.len(), 2);
    assert!(
        result
            .iter()
            .any(|s| s.contains("Removed 1 entries") && s.contains(".bash_history"))
    );
    assert!(
        result
            .iter()
            .any(|s| s.contains("Removed 1 entries") && s.contains(".zsh_history"))
    );
}

#[test]
fn test_custom_patterns() {
    let fs = MockFilesystem::new();
    let home = test_home();

    let bash_history = PathBuf::from("/home/testuser/.bash_history");
    fs.mock_set_file_content(
        bash_history.to_str().unwrap(),
        "ls -la\nsecret command\npwd\n",
    );
    fs.mock_set_path_exists(bash_history.to_str().unwrap(), true);

    let cleaner = HistoryCleaner::new(fs.clone())
        .with_home(home)
        .with_patterns(vec!["secret".to_string()])
        .with_shells(vec![ShellType::Bash]);

    let result = cleaner.clean().unwrap();

    // Should report removal of 1 entry
    assert_eq!(result.len(), 1);
    assert!(result[0].contains("Removed 1 entries"));

    // Verify correct line was removed
    let written_content = fs.get_written_content(&bash_history).unwrap();
    assert_eq!(written_content, "ls -la\npwd\n");
}

#[test]
fn test_multiple_patterns() {
    let fs = MockFilesystem::new();
    let home = test_home();

    let bash_history = PathBuf::from("/home/testuser/.bash_history");
    fs.mock_set_file_content(
        bash_history.to_str().unwrap(),
        "ls -la\nnails activate\nsecret command\npwd\n",
    );
    fs.mock_set_path_exists(bash_history.to_str().unwrap(), true);

    let cleaner = HistoryCleaner::new(fs.clone())
        .with_home(home)
        .with_patterns(vec!["nails".to_string(), "secret".to_string()])
        .with_shells(vec![ShellType::Bash]);

    let result = cleaner.clean().unwrap();

    // Should report removal of 2 entries
    assert_eq!(result.len(), 1);
    assert!(result[0].contains("Removed 2 entries"));

    // Verify correct lines were removed
    let written_content = fs.get_written_content(&bash_history).unwrap();
    assert_eq!(written_content, "ls -la\npwd\n");
}

// ============================================================================
// Fish YAML history filtering tests (M1)
// ============================================================================

#[test]
fn test_filter_fish_history_removes_matching_entries() {
    let content = "\
- cmd: ls -la
  when: 1700000001
- cmd: nails activate
  when: 1700000002
- cmd: cd /tmp
  when: 1700000003
";
    let patterns = vec!["nails".to_string()];
    let (filtered, removed) = filter_fish_history(content, &patterns);

    assert_eq!(removed, 1);
    assert!(!filtered.contains("nails"));
    assert!(filtered.contains("ls -la"));
    assert!(filtered.contains("cd /tmp"));
    // No orphaned `when:` lines
    let when_count = filtered
        .lines()
        .filter(|l| l.trim_start().starts_with("when:"))
        .count();
    assert_eq!(when_count, 2); // Only the 2 non-matching entries
}

#[test]
fn test_filter_fish_history_removes_multiple_entries() {
    let content = "\
- cmd: nails activate
  when: 1700000001
- cmd: cryptsetup open /dev/sda1
  when: 1700000002
- cmd: ls
  when: 1700000003
";
    let patterns = vec!["nails".to_string(), "cryptsetup".to_string()];
    let (filtered, removed) = filter_fish_history(content, &patterns);

    assert_eq!(removed, 2);
    assert!(filtered.contains("ls"));
    assert!(!filtered.contains("nails"));
    assert!(!filtered.contains("cryptsetup"));
}

#[test]
fn test_filter_fish_history_cmd_at_eof_without_when() {
    let content = "\
- cmd: ls -la
  when: 1700000001
- cmd: nails activate";
    let patterns = vec!["nails".to_string()];
    let (filtered, removed) = filter_fish_history(content, &patterns);

    assert_eq!(removed, 1);
    assert!(filtered.contains("ls -la"));
    assert!(!filtered.contains("nails"));
}

#[test]
fn test_filter_fish_history_preserves_non_matching() {
    let content = "\
- cmd: git status
  when: 1700000001
- cmd: cargo build
  when: 1700000002
";
    let patterns = vec!["nails".to_string()];
    let (filtered, removed) = filter_fish_history(content, &patterns);

    assert_eq!(removed, 0);
    assert!(filtered.contains("git status"));
    assert!(filtered.contains("cargo build"));
}

#[test]
fn test_filter_fish_history_all_entries_removed() {
    let content = "\
- cmd: nails activate
  when: 1700000001
- cmd: nails status
  when: 1700000002
";
    let patterns = vec!["nails".to_string()];
    let (filtered, removed) = filter_fish_history(content, &patterns);

    assert_eq!(removed, 2);
    assert_eq!(filtered, "");
}

#[test]
fn test_filter_fish_history_case_insensitive() {
    let content = "\
- cmd: NAILS status
  when: 1700000001
- cmd: ls
  when: 1700000002
";
    let patterns = vec!["nails".to_string()];
    let (filtered, removed) = filter_fish_history(content, &patterns);

    assert_eq!(removed, 1);
    assert!(!filtered.contains("NAILS"));
    assert!(filtered.contains("ls"));
}

#[test]
fn test_filter_fish_history_with_extra_metadata() {
    // Fish can have `paths:` metadata after `when:`
    let content = "\
- cmd: nails activate
  when: 1700000001
  paths:
    - /home/user
- cmd: ls
  when: 1700000002
";
    let patterns = vec!["nails".to_string()];
    let (filtered, removed) = filter_fish_history(content, &patterns);

    assert_eq!(removed, 1);
    assert!(!filtered.contains("nails"));
    assert!(!filtered.contains("paths:"));
    assert!(filtered.contains("ls"));
}

#[test]
fn test_fish_history_cleaned_via_history_cleaner() {
    let fs = MockFilesystem::new();
    let home = test_home();

    let fish_history = PathBuf::from("/home/testuser/.local/share/fish/fish_history");
    fs.mock_set_file_content(
        fish_history.to_str().unwrap(),
        "- cmd: ls -la\n  when: 1700000001\n- cmd: nails activate\n  when: 1700000002\n- cmd: cd /tmp\n  when: 1700000003\n",
    );
    fs.mock_set_path_exists(fish_history.to_str().unwrap(), true);

    let cleaner = HistoryCleaner::new(fs.clone())
        .with_home(home)
        .with_shells(vec![ShellType::Fish]);

    let result = cleaner.clean().unwrap();
    assert_eq!(result.len(), 1);
    assert!(result[0].contains("Removed 1 entries"));

    let written = fs.get_written_content(&fish_history).unwrap();
    assert!(!written.contains("nails"));
    assert!(written.contains("ls -la"));
    assert!(written.contains("cd /tmp"));
    // No orphaned when: lines
    let cmd_count = written.lines().filter(|l| l.starts_with("- cmd:")).count();
    let when_count = written
        .lines()
        .filter(|l| l.trim_start().starts_with("when:"))
        .count();
    assert_eq!(cmd_count, when_count);
}
