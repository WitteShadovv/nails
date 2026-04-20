//! Tests for ShellType, get_extended_history_files, and truncate_all_history_files

use super::*;
use crate::MockFilesystem;

/// Test home directory path - safe for tests, doesn't exist on real filesystem
const TEST_HOME: &str = "/home/testuser";

fn test_home() -> PathBuf {
    PathBuf::from(TEST_HOME)
}

// ============================================================================
// ShellType::history_file_path_for_home tests (no env vars needed)
// ============================================================================

#[test]
fn test_shell_type_bash_history_path_for_home() {
    let home = test_home();
    let path = ShellType::Bash.history_file_path_for_home(&home);
    assert_eq!(path, PathBuf::from("/home/testuser/.bash_history"));
}

#[test]
fn test_shell_type_zsh_history_path_for_home() {
    let home = test_home();
    let path = ShellType::Zsh.history_file_path_for_home(&home);
    assert_eq!(path, PathBuf::from("/home/testuser/.zsh_history"));
}

#[test]
fn test_shell_type_fish_history_path_for_home() {
    let home = test_home();
    let path = ShellType::Fish.history_file_path_for_home(&home);
    assert_eq!(
        path,
        PathBuf::from("/home/testuser/.local/share/fish/fish_history")
    );
}

#[test]
fn test_shell_type_in_memory_clear_command() {
    assert_eq!(ShellType::Bash.in_memory_clear_command(), "history -c");
    assert_eq!(ShellType::Zsh.in_memory_clear_command(), "fc -W; fc -p");
    assert_eq!(ShellType::Fish.in_memory_clear_command(), "history clear");
}

#[test]
fn test_shell_type_all() {
    let all_shells = ShellType::all();
    assert_eq!(all_shells.len(), 3);
    assert!(all_shells.contains(&ShellType::Bash));
    assert!(all_shells.contains(&ShellType::Zsh));
    assert!(all_shells.contains(&ShellType::Fish));
}

#[test]
fn test_shell_type_equality() {
    assert_eq!(ShellType::Bash, ShellType::Bash);
    assert_ne!(ShellType::Bash, ShellType::Zsh);
    assert_ne!(ShellType::Zsh, ShellType::Fish);
}

#[test]
fn test_shell_type_clone() {
    let shell = ShellType::Bash;
    #[allow(clippy::clone_on_copy)]
    let cloned = shell.clone();
    assert_eq!(shell, cloned);
}

// ============================================================================
// get_extended_history_files_for_home tests (no env vars needed)
// ============================================================================

#[test]
fn test_get_extended_history_files_for_home() {
    let home = test_home();
    let files = get_extended_history_files_for_home(&home);

    // Should contain common history files
    assert!(files.contains(&PathBuf::from("/home/testuser/.bash_history")));
    assert!(files.contains(&PathBuf::from("/home/testuser/.zsh_history")));
    assert!(files.contains(&PathBuf::from(
        "/home/testuser/.local/share/fish/fish_history"
    )));
    assert!(files.contains(&PathBuf::from("/home/testuser/.lesshst")));
    assert!(files.contains(&PathBuf::from("/home/testuser/.python_history")));
    assert!(files.contains(&PathBuf::from(
        "/home/testuser/.local/share/recently-used.xbel"
    )));
}

// ============================================================================
// truncate_all_history_files_for_home tests (no env vars needed)
// ============================================================================

#[test]
fn test_truncate_all_history_files_for_home_truncates_existing() {
    let fs = MockFilesystem::new();
    let home = test_home();

    let bash_history = "/home/testuser/.bash_history";
    let zsh_history = "/home/testuser/.zsh_history";
    fs.mock_set_path_exists(bash_history, true);
    fs.mock_set_file_content(bash_history, "nails activate\nls\n");
    fs.mock_set_path_exists(zsh_history, true);
    fs.mock_set_file_content(zsh_history, "cryptsetup open\npwd\n");

    let results = truncate_all_history_files_for_home(&fs, &home, false);

    assert!(results.iter().any(|r| r.contains(".bash_history")));
    assert!(results.iter().any(|r| r.contains(".zsh_history")));

    // Verify files are now empty
    let bash_written = fs
        .get_written_content(&PathBuf::from(bash_history))
        .unwrap();
    assert_eq!(bash_written, "");
    let zsh_written = fs.get_written_content(&PathBuf::from(zsh_history)).unwrap();
    assert_eq!(zsh_written, "");
}

#[test]
fn test_truncate_all_history_files_for_home_with_secure_delete() {
    let fs = MockFilesystem::new();
    let home = test_home();

    let bash_history = "/home/testuser/.bash_history";
    fs.mock_set_path_exists(bash_history, true);
    fs.mock_set_file_content(bash_history, "some commands\n");

    let results = truncate_all_history_files_for_home(&fs, &home, true);

    assert!(!results.is_empty());
    let bash_written = fs
        .get_written_content(&PathBuf::from(bash_history))
        .unwrap();
    assert_eq!(bash_written, "");
}

#[test]
fn test_truncate_all_history_files_for_home_skips_nonexistent() {
    let fs = MockFilesystem::new();
    let home = test_home();
    // Don't set any files as existing

    let results = truncate_all_history_files_for_home(&fs, &home, false);

    // No files existed, so nothing was truncated
    assert!(results.is_empty());
}

#[test]
fn test_truncate_all_history_files_for_home_includes_recently_used_xbel() {
    let fs = MockFilesystem::new();
    let home = test_home();

    let xbel_path = "/home/testuser/.local/share/recently-used.xbel";
    fs.mock_set_path_exists(xbel_path, true);
    fs.mock_set_file_content(xbel_path, "<xbel>some data</xbel>\n");

    let results = truncate_all_history_files_for_home(&fs, &home, false);

    assert!(results.iter().any(|r| r.contains("recently-used.xbel")));
    let written = fs.get_written_content(&PathBuf::from(xbel_path)).unwrap();
    assert_eq!(written, "");
}
