// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests for HistoryCleaner and fish history filtering

use super::*;
use crate::MockFilesystem;
use std::path::Path;

/// Test home directory path - safe for tests, doesn't exist on real filesystem
const TEST_HOME: &str = "/home/testuser";

fn test_home() -> PathBuf {
    PathBuf::from(TEST_HOME)
}

/// A temporary home on the real filesystem; the guard removes it.
fn real_home() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().to_path_buf();
    (dir, home)
}

// ============================================================================
// HistoryCleaner tests (using with_home for explicit path)
// ============================================================================

#[test]
fn test_history_cleaner_new() {
    // Configuration only: the filesystem is never touched.
    let fs = crate::RealFilesystem;
    let cleaner = HistoryCleaner::new(fs);

    assert_eq!(cleaner.test_patterns(), ["nails".to_string()]);
    assert_eq!(cleaner.test_shells().len(), 3);
    assert!(!cleaner.secure_delete);
    assert!(cleaner.test_home().is_none());
}

#[test]
fn test_history_cleaner_with_home() {
    // Configuration only: the filesystem is never touched.
    let fs = crate::RealFilesystem;
    let cleaner = HistoryCleaner::new(fs).with_home(test_home());

    assert_eq!(cleaner.test_home(), Some(&test_home()));
}

#[test]
fn test_history_cleaner_with_homes_cleans_operator_home_and_root() {
    // The operator's home plus root's, as produced by TargetUser::cleanup_homes.
    let (_operator_dir, operator) = real_home();
    let (_root_dir, root) = real_home();
    let operator_hist = operator.join(".bash_history");
    let root_hist = root.join(".bash_history");
    std::fs::write(&operator_hist, "ls\nnails activate\n").unwrap();
    std::fs::write(&root_hist, "pwd\nnails status\n").unwrap();

    let cleaner = HistoryCleaner::new(crate::RealFilesystem)
        .with_homes(vec![operator.clone(), root.clone()])
        .with_shells(vec![ShellType::Bash]);

    let result = cleaner.clean().unwrap();

    // One message per (home, shell): both homes were filtered.
    assert_eq!(result.len(), 2);
    for home in [&operator, &root] {
        assert!(
            result
                .iter()
                .any(|s| s.contains("Removed 1 entries") && s.contains(&*home.to_string_lossy())),
            "{} was cleaned: {result:?}",
            home.display()
        );
    }
    assert_eq!(std::fs::read_to_string(&operator_hist).unwrap(), "ls\n");
    assert_eq!(std::fs::read_to_string(&root_hist).unwrap(), "pwd\n");
}

#[test]
fn test_history_cleaner_with_patterns() {
    // Configuration only: the filesystem is never touched.
    let fs = crate::RealFilesystem;
    let patterns = vec!["test1".to_string(), "test2".to_string()];
    let cleaner = HistoryCleaner::new(fs).with_patterns(patterns.clone());

    assert_eq!(cleaner.test_patterns(), patterns);
}

#[test]
fn test_history_cleaner_with_shells() {
    // Configuration only: the filesystem is never touched.
    let fs = crate::RealFilesystem;
    let shells = vec![ShellType::Bash, ShellType::Fish];
    let cleaner = HistoryCleaner::new(fs).with_shells(shells.clone());

    assert_eq!(cleaner.test_shells(), shells);
}

#[test]
fn test_case_insensitive_pattern_matching() {
    // Configuration only: the filesystem is never touched.
    let fs = crate::RealFilesystem;
    let cleaner = HistoryCleaner::new(fs);

    assert!(cleaner.line_matches_patterns("nails activate"));
    assert!(cleaner.line_matches_patterns("NAILS status"));
    assert!(cleaner.line_matches_patterns("sudo NaIlS emergency"));
    assert!(cleaner.line_matches_patterns("grep nails log.txt"));
    assert!(!cleaner.line_matches_patterns("ls -la"));
}

#[test]
fn test_partial_line_removal() {
    // Configuration only: the filesystem is never touched.
    let fs = crate::RealFilesystem;
    let cleaner = HistoryCleaner::new(fs);

    // Lines with nails anywhere should match
    assert!(cleaner.line_matches_patterns("nails activate && ls"));
    assert!(cleaner.line_matches_patterns("echo test | nails"));
    assert!(cleaner.line_matches_patterns("vim /etc/nails.conf"));
}

#[test]
fn test_history_file_cleanup() {
    let (_dir, home) = real_home();
    let fs = crate::RealFilesystem;

    let bash_history = home.join(".bash_history");
    std::fs::write(&bash_history, "ls -la\nnails activate\ncd /tmp\nNAILS status\ngrep nails logfile.txt\nvim nails_config.yaml\n").unwrap();

    let cleaner = HistoryCleaner::new(fs)
        .with_home(home)
        .with_shells(vec![ShellType::Bash]);

    let result = cleaner.clean().unwrap();

    // Should report removal of 4 entries (nails activate, NAILS status, grep nails, vim nails)
    assert_eq!(result.len(), 1);
    assert!(result[0].contains("Removed 4 entries"));

    // Verify the file was written with filtered content
    let written_content = std::fs::read_to_string(&bash_history).unwrap();
    assert_eq!(written_content, "ls -la\ncd /tmp\n");
}

#[test]
fn test_missing_history_file() {
    let (_dir, home) = real_home();
    let fs = crate::RealFilesystem;
    // Don't set up any history files

    let cleaner = HistoryCleaner::new(fs).with_home(home);
    let result = cleaner.clean().unwrap();

    // Should succeed with empty results (no files to clean)
    // No errors should be raised for missing files
    assert_eq!(result.len(), 0);
}

#[test]
fn test_empty_history_file() {
    let (_dir, home) = real_home();
    let fs = crate::RealFilesystem;

    let bash_history = home.join(".bash_history");
    std::fs::write(&bash_history, "").unwrap();

    let cleaner = HistoryCleaner::new(fs)
        .with_home(home)
        .with_shells(vec![ShellType::Bash]);

    let result = cleaner.clean().unwrap();

    // Should report no matching entries
    assert_eq!(result.len(), 1);
    assert!(result[0].contains("No matching entries"));
}

#[test]
fn test_history_file_with_no_matches() {
    let (_dir, home) = real_home();
    let fs = crate::RealFilesystem;

    let bash_history = home.join(".bash_history");
    std::fs::write(&bash_history, "ls -la\ncd /tmp\npwd\n").unwrap();
    let inode = std::os::unix::fs::MetadataExt::ino(&std::fs::metadata(&bash_history).unwrap());

    let cleaner = HistoryCleaner::new(fs)
        .with_home(home)
        .with_shells(vec![ShellType::Bash]);

    let result = cleaner.clean().unwrap();

    // Should report no matching entries
    assert_eq!(result.len(), 1);
    assert!(result[0].contains("No matching entries"));

    // The file is left exactly as it was, not rewritten.
    use std::os::unix::fs::MetadataExt;
    assert_eq!(
        std::fs::read_to_string(&bash_history).unwrap(),
        "ls -la\ncd /tmp\npwd\n"
    );
    assert_eq!(std::fs::metadata(&bash_history).unwrap().ino(), inode);
}

#[test]
fn test_history_file_all_matches_removed() {
    let (_dir, home) = real_home();
    let fs = crate::RealFilesystem;

    let bash_history = home.join(".bash_history");
    std::fs::write(&bash_history, "nails activate\nNAILS status\n").unwrap();

    let cleaner = HistoryCleaner::new(fs)
        .with_home(home)
        .with_shells(vec![ShellType::Bash]);

    let result = cleaner.clean().unwrap();

    // Should report removal of 2 entries
    assert_eq!(result.len(), 1);
    assert!(result[0].contains("Removed 2 entries"));

    // File should be empty
    let written_content = std::fs::read_to_string(&bash_history).unwrap();
    assert_eq!(written_content, "");
}

#[test]
fn test_multiple_shells_cleanup() {
    let (_dir, home) = real_home();
    let fs = crate::RealFilesystem;

    let bash_history = home.join(".bash_history");
    let zsh_history = home.join(".zsh_history");

    std::fs::write(&bash_history, "ls -la\nnails activate\n").unwrap();

    std::fs::write(&zsh_history, "pwd\nNAILS status\n").unwrap();

    let cleaner = HistoryCleaner::new(fs)
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
    let (_dir, home) = real_home();
    let fs = crate::RealFilesystem;

    let bash_history = home.join(".bash_history");
    std::fs::write(&bash_history, "ls -la\nsecret command\npwd\n").unwrap();

    let cleaner = HistoryCleaner::new(fs)
        .with_home(home)
        .with_patterns(vec!["secret".to_string()])
        .with_shells(vec![ShellType::Bash]);

    let result = cleaner.clean().unwrap();

    // Should report removal of 1 entry
    assert_eq!(result.len(), 1);
    assert!(result[0].contains("Removed 1 entries"));

    // Verify correct line was removed
    let written_content = std::fs::read_to_string(&bash_history).unwrap();
    assert_eq!(written_content, "ls -la\npwd\n");
}

#[test]
fn test_multiple_patterns() {
    let (_dir, home) = real_home();
    let fs = crate::RealFilesystem;

    let bash_history = home.join(".bash_history");
    std::fs::write(
        &bash_history,
        "ls -la\nnails activate\nsecret command\npwd\n",
    )
    .unwrap();

    let cleaner = HistoryCleaner::new(fs)
        .with_home(home)
        .with_patterns(vec!["nails".to_string(), "secret".to_string()])
        .with_shells(vec![ShellType::Bash]);

    let result = cleaner.clean().unwrap();

    // Should report removal of 2 entries
    assert_eq!(result.len(), 1);
    assert!(result[0].contains("Removed 2 entries"));

    // Verify correct lines were removed
    let written_content = std::fs::read_to_string(&bash_history).unwrap();
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
    let (_dir, home) = real_home();
    let fs = crate::RealFilesystem;

    let fish_history = home.join(".local/share/fish/fish_history");
    std::fs::create_dir_all(fish_history.parent().unwrap()).unwrap();
    std::fs::write(&fish_history, "- cmd: ls -la\n  when: 1700000001\n- cmd: nails activate\n  when: 1700000002\n- cmd: cd /tmp\n  when: 1700000003\n").unwrap();

    let cleaner = HistoryCleaner::new(fs)
        .with_home(home)
        .with_shells(vec![ShellType::Fish]);

    let result = cleaner.clean().unwrap();
    assert_eq!(result.len(), 1);
    assert!(result[0].contains("Removed 1 entries"));

    let written = std::fs::read_to_string(&fish_history).unwrap();
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

// ============================================================================
// Opt-in in-place decoy history edit
// ============================================================================

#[test]
fn test_in_place_edit_overwrites_same_inode_not_temp_rename() {
    use crate::filesystem::mock::MockOp;

    let fs = MockFilesystem::new();
    let hist = "/home/operator/.bash_history";
    fs.mock_set_file_content(hist, "ls\nnails activate\npwd\n");

    let cleaner = HistoryCleaner::new(fs.clone())
        .with_home(PathBuf::from("/home/operator"))
        .with_shells(vec![ShellType::Bash])
        .with_in_place(true);

    let result = cleaner.clean().unwrap();
    assert_eq!(result.len(), 1);
    assert!(result[0].contains("in place"));

    // The matching line is gone, the others survive.
    let written = fs.get_written_content(Path::new(hist)).unwrap();
    assert!(!written.contains("nails"));
    assert!(written.contains("ls"));
    assert!(written.contains("pwd"));

    // The edit went through the same-inode overwrite path, never the temp+rename
    // write that would allocate a new inode.
    let ops = fs.mock_ops();
    assert!(
        ops.iter()
            .any(|op| matches!(op, MockOp::OverwriteInPlace { path } if path == Path::new(hist))),
        "expected an in-place overwrite, got {ops:?}"
    );
    assert!(
        !ops.iter()
            .any(|op| matches!(op, MockOp::WriteFile { path } if path == Path::new(hist))),
        "in-place edit must not use the temp+rename write path"
    );
}

/// Clean a real `.bash_history` in a temporary home and return the inode
/// before and after, with the content left behind.
fn clean_real_history(in_place: bool) -> (u64, u64, String) {
    use std::os::unix::fs::MetadataExt;
    let home = tempfile::tempdir().unwrap();
    let hist = home.path().join(".bash_history");
    std::fs::write(&hist, "ls\nnails activate\npwd\n").unwrap();
    let before = std::fs::metadata(&hist).unwrap().ino();

    HistoryCleaner::new(crate::RealFilesystem)
        .with_home(home.path().to_path_buf())
        .with_shells(vec![ShellType::Bash])
        .with_in_place(in_place)
        .clean()
        .unwrap();

    let after = std::fs::metadata(&hist).unwrap().ino();
    (before, after, std::fs::read_to_string(&hist).unwrap())
}

#[test]
fn test_default_edit_replaces_the_file_through_a_new_inode() {
    // The atomic temp+rename write leaves a new file at the path: a crash
    // mid-edit can never leave a half-written history.
    let (before, after, content) = clean_real_history(false);
    assert_eq!(content, "ls\npwd\n");
    assert_ne!(before, after, "the cleaned history is a renamed temp file");
}

#[test]
fn test_in_place_edit_keeps_the_same_inode() {
    // In place: the same inode is rewritten, so the old content's blocks are
    // overwritten instead of being freed with a replaced inode.
    let (before, after, content) = clean_real_history(true);
    assert_eq!(content, "ls\npwd\n");
    assert_eq!(before, after, "the history was overwritten in place");
}
