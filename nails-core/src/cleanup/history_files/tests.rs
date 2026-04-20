//! Tests for history file registry and types

use super::registry::{ALL_HISTORY_FILES, get_by_category, get_common, get_existing};
use super::*;

/// Test home directory path - safe for tests, doesn't exist on real filesystem
const TEST_HOME: &str = "/home/testuser";

fn test_home() -> PathBuf {
    PathBuf::from(TEST_HOME)
}

#[test]
fn test_history_category_display_name() {
    assert_eq!(HistoryCategory::Shell.display_name(), "Shell");
    assert_eq!(HistoryCategory::Database.display_name(), "Database");
    assert_eq!(HistoryCategory::Repl.display_name(), "REPL");
    assert_eq!(HistoryCategory::Editor.display_name(), "Editor");
    assert_eq!(HistoryCategory::Alternative.display_name(), "Alternative");
    assert_eq!(HistoryCategory::Misc.display_name(), "Misc");
}

#[test]
fn test_history_format_is_text_editable() {
    assert!(HistoryFormat::PlainText.is_text_editable());
    assert!(HistoryFormat::Yaml.is_text_editable());
    assert!(HistoryFormat::Json.is_text_editable());
    assert!(!HistoryFormat::Sqlite.is_text_editable());
    assert!(!HistoryFormat::Binary.is_text_editable());
}

#[test]
fn test_history_format_description() {
    assert_eq!(HistoryFormat::PlainText.description(), "Plain text");
    assert_eq!(HistoryFormat::Yaml.description(), "YAML");
    assert_eq!(HistoryFormat::Sqlite.description(), "SQLite database");
    assert_eq!(HistoryFormat::Json.description(), "JSON");
    assert_eq!(HistoryFormat::Binary.description(), "Binary");
}

// ============================================================================
// HistoryPath::resolve_with_home tests (no env vars needed)
// ============================================================================

#[test]
fn test_history_path_resolve_with_home_relative() {
    let home = test_home();
    let path = HistoryPath::HomeRelative(".bash_history");
    let resolved = path.resolve_with_home(&home, None, None, None);
    assert_eq!(resolved, PathBuf::from("/home/testuser/.bash_history"));
}

#[test]
fn test_history_path_resolve_with_home_xdg_data_default() {
    let home = test_home();
    let path = HistoryPath::XdgData("fish/fish_history");
    let resolved = path.resolve_with_home(&home, None, None, None);
    assert_eq!(
        resolved,
        PathBuf::from("/home/testuser/.local/share/fish/fish_history")
    );
}

#[test]
fn test_history_path_resolve_with_home_xdg_data_custom() {
    let home = test_home();
    let custom_xdg_data = PathBuf::from("/custom/data");
    let path = HistoryPath::XdgData("fish/fish_history");
    let resolved = path.resolve_with_home(&home, Some(&custom_xdg_data), None, None);
    assert_eq!(resolved, PathBuf::from("/custom/data/fish/fish_history"));
}

#[test]
fn test_history_path_resolve_with_home_xdg_config_default() {
    let home = test_home();
    let path = HistoryPath::XdgConfig("nushell/history.txt");
    let resolved = path.resolve_with_home(&home, None, None, None);
    assert_eq!(
        resolved,
        PathBuf::from("/home/testuser/.config/nushell/history.txt")
    );
}

#[test]
fn test_history_path_resolve_with_home_xdg_config_custom() {
    let home = test_home();
    let custom_xdg_config = PathBuf::from("/custom/config");
    let path = HistoryPath::XdgConfig("nushell/history.txt");
    let resolved = path.resolve_with_home(&home, None, Some(&custom_xdg_config), None);
    assert_eq!(
        resolved,
        PathBuf::from("/custom/config/nushell/history.txt")
    );
}

#[test]
fn test_history_path_resolve_with_home_xdg_state_default() {
    let home = test_home();
    let path = HistoryPath::XdgState("nvim/shada/main.shada");
    let resolved = path.resolve_with_home(&home, None, None, None);
    assert_eq!(
        resolved,
        PathBuf::from("/home/testuser/.local/state/nvim/shada/main.shada")
    );
}

#[test]
fn test_history_path_resolve_with_home_xdg_state_custom() {
    let home = test_home();
    let custom_xdg_state = PathBuf::from("/custom/state");
    let path = HistoryPath::XdgState("nvim/shada/main.shada");
    let resolved = path.resolve_with_home(&home, None, None, Some(&custom_xdg_state));
    assert_eq!(
        resolved,
        PathBuf::from("/custom/state/nvim/shada/main.shada")
    );
}

#[test]
fn test_history_path_resolve_with_home_absolute() {
    let home = test_home();
    let path = HistoryPath::Absolute("/etc/some/path");
    let resolved = path.resolve_with_home(&home, None, None, None);
    assert_eq!(resolved, PathBuf::from("/etc/some/path"));
}

// ============================================================================
// ALL_HISTORY_FILES tests (no env vars needed)
// ============================================================================

#[test]
fn test_all_history_files_not_empty() {
    assert!(!ALL_HISTORY_FILES.is_empty());
    // Should have at least the core shell history files
    assert!(ALL_HISTORY_FILES.len() >= 10);
}

#[test]
fn test_all_history_files_has_bash() {
    let bash = ALL_HISTORY_FILES.iter().find(|f| f.name == "bash");
    assert!(bash.is_some());
    let bash = bash.unwrap();
    assert_eq!(bash.category, HistoryCategory::Shell);
    assert_eq!(bash.format, HistoryFormat::PlainText);
    assert!(bash.common);
}

#[test]
fn test_all_history_files_has_zsh() {
    let zsh = ALL_HISTORY_FILES.iter().find(|f| f.name == "zsh");
    assert!(zsh.is_some());
    let zsh = zsh.unwrap();
    assert_eq!(zsh.category, HistoryCategory::Shell);
    assert_eq!(zsh.format, HistoryFormat::PlainText);
    assert!(zsh.common);
}

#[test]
fn test_all_history_files_has_fish_yaml() {
    let fish = ALL_HISTORY_FILES.iter().find(|f| f.name == "fish");
    assert!(fish.is_some());
    let fish = fish.unwrap();
    assert_eq!(fish.category, HistoryCategory::Shell);
    assert_eq!(fish.format, HistoryFormat::Yaml);
    assert!(fish.common);
}

#[test]
fn test_all_history_files_has_ipython_sqlite() {
    let ipython = ALL_HISTORY_FILES.iter().find(|f| f.name == "ipython");
    assert!(ipython.is_some());
    let ipython = ipython.unwrap();
    assert_eq!(ipython.category, HistoryCategory::Repl);
    assert_eq!(ipython.format, HistoryFormat::Sqlite);
}

#[test]
fn test_all_history_files_has_nvim_binary() {
    let nvim = ALL_HISTORY_FILES.iter().find(|f| f.name == "nvim");
    assert!(nvim.is_some());
    let nvim = nvim.unwrap();
    assert_eq!(nvim.category, HistoryCategory::Editor);
    assert_eq!(nvim.format, HistoryFormat::Binary);
    assert!(nvim.common);
}

#[test]
fn test_all_history_files_has_atuin_sqlite() {
    let atuin = ALL_HISTORY_FILES.iter().find(|f| f.name == "atuin");
    assert!(atuin.is_some());
    let atuin = atuin.unwrap();
    assert_eq!(atuin.category, HistoryCategory::Alternative);
    assert_eq!(atuin.format, HistoryFormat::Sqlite);
    assert!(!atuin.common);
}

#[test]
fn test_get_by_category_shell() {
    let shell_files = get_by_category(HistoryCategory::Shell);
    assert!(!shell_files.is_empty());

    // All returned files should be in Shell category
    for file in &shell_files {
        assert_eq!(file.category, HistoryCategory::Shell);
    }

    // Should include bash, zsh, fish
    let names: Vec<_> = shell_files.iter().map(|f| f.name).collect();
    assert!(names.contains(&"bash"));
    assert!(names.contains(&"zsh"));
    assert!(names.contains(&"fish"));
}

#[test]
fn test_get_by_category_database() {
    let db_files = get_by_category(HistoryCategory::Database);
    assert!(!db_files.is_empty());

    for file in &db_files {
        assert_eq!(file.category, HistoryCategory::Database);
    }

    let names: Vec<_> = db_files.iter().map(|f| f.name).collect();
    assert!(names.contains(&"mysql"));
    assert!(names.contains(&"psql"));
    assert!(names.contains(&"sqlite"));
    assert!(names.contains(&"redis"));
}

#[test]
fn test_get_by_category_repl() {
    let repl_files = get_by_category(HistoryCategory::Repl);
    assert!(!repl_files.is_empty());

    for file in &repl_files {
        assert_eq!(file.category, HistoryCategory::Repl);
    }

    let names: Vec<_> = repl_files.iter().map(|f| f.name).collect();
    assert!(names.contains(&"python"));
    assert!(names.contains(&"node"));
    assert!(names.contains(&"irb"));
}

#[test]
fn test_get_by_category_editor() {
    let editor_files = get_by_category(HistoryCategory::Editor);
    assert!(!editor_files.is_empty());

    for file in &editor_files {
        assert_eq!(file.category, HistoryCategory::Editor);
    }

    let names: Vec<_> = editor_files.iter().map(|f| f.name).collect();
    assert!(names.contains(&"vim"));
    assert!(names.contains(&"nvim"));
    assert!(names.contains(&"less"));
}

#[test]
fn test_get_by_category_alternative() {
    let alt_files = get_by_category(HistoryCategory::Alternative);
    assert!(!alt_files.is_empty());

    for file in &alt_files {
        assert_eq!(file.category, HistoryCategory::Alternative);
    }

    let names: Vec<_> = alt_files.iter().map(|f| f.name).collect();
    assert!(names.contains(&"atuin"));
    assert!(names.contains(&"mcfly"));
}

#[test]
fn test_get_by_category_misc() {
    let misc_files = get_by_category(HistoryCategory::Misc);
    assert!(!misc_files.is_empty());

    for file in &misc_files {
        assert_eq!(file.category, HistoryCategory::Misc);
    }

    let names: Vec<_> = misc_files.iter().map(|f| f.name).collect();
    assert!(names.contains(&"wget"));
    assert!(names.contains(&"gdb"));
    assert!(names.contains(&"fzf"));
}

#[test]
fn test_get_common() {
    let common_files = get_common();
    assert!(!common_files.is_empty());

    // All returned files should have common=true
    for file in &common_files {
        assert!(file.common, "{} should be marked as common", file.name);
    }

    // Should include bash, zsh, fish, mysql, psql, sqlite, redis, python, node, irb, vim, nvim, less
    let names: Vec<_> = common_files.iter().map(|f| f.name).collect();
    assert!(names.contains(&"bash"));
    assert!(names.contains(&"zsh"));
    assert!(names.contains(&"fish"));
    assert!(names.contains(&"mysql"));
    assert!(names.contains(&"psql"));
    assert!(names.contains(&"sqlite"));
    assert!(names.contains(&"redis"));
    assert!(names.contains(&"python"));
    assert!(names.contains(&"node"));
    assert!(names.contains(&"irb"));
    assert!(names.contains(&"vim"));
    assert!(names.contains(&"nvim"));
    assert!(names.contains(&"less"));
}

#[test]
fn test_get_common_excludes_uncommon() {
    let common_files = get_common();
    let names: Vec<_> = common_files.iter().map(|f| f.name).collect();

    // These should NOT be in common
    assert!(!names.contains(&"atuin"));
    assert!(!names.contains(&"mcfly"));
    assert!(!names.contains(&"ghci"));
    assert!(!names.contains(&"scala"));
    assert!(!names.contains(&"ksh"));
    assert!(!names.contains(&"tcsh"));
}

// ============================================================================
// HistoryFile::resolve_path_for_home tests (no env vars needed)
// ============================================================================

#[test]
fn test_history_file_resolve_path_for_home() {
    let home = test_home();
    let bash = ALL_HISTORY_FILES.iter().find(|f| f.name == "bash").unwrap();
    let resolved = bash.resolve_path_for_home(&home);
    assert_eq!(resolved, PathBuf::from("/home/testuser/.bash_history"));
}

#[test]
fn test_history_file_resolve_path_for_home_fish() {
    let home = test_home();
    let fish = ALL_HISTORY_FILES.iter().find(|f| f.name == "fish").unwrap();
    let resolved = fish.resolve_path_for_home(&home);
    assert_eq!(
        resolved,
        PathBuf::from("/home/testuser/.local/share/fish/fish_history")
    );
}

#[test]
fn test_history_file_resolve_path_for_home_nvim() {
    let home = test_home();
    let nvim = ALL_HISTORY_FILES.iter().find(|f| f.name == "nvim").unwrap();
    let resolved = nvim.resolve_path_for_home(&home);
    assert_eq!(
        resolved,
        PathBuf::from("/home/testuser/.local/state/nvim/shada/main.shada")
    );
}

#[test]
fn test_get_existing_returns_only_existing_files() {
    // This test verifies the function signature and that it doesn't panic
    // Actual file existence depends on the test environment
    let existing = get_existing();

    // All returned paths should exist
    for (file, path) in &existing {
        assert!(
            path.exists(),
            "File {} at {} should exist",
            file.name,
            path.display()
        );
    }
}

#[test]
fn test_all_categories_covered() {
    // Ensure all categories have at least one entry
    let categories = [
        HistoryCategory::Shell,
        HistoryCategory::Database,
        HistoryCategory::Repl,
        HistoryCategory::Editor,
        HistoryCategory::Alternative,
        HistoryCategory::Misc,
    ];

    for category in categories {
        let files = get_by_category(category);
        assert!(
            !files.is_empty(),
            "Category {:?} should have at least one file",
            category
        );
    }
}

#[test]
fn test_no_duplicate_names() {
    let mut names: Vec<_> = ALL_HISTORY_FILES.iter().map(|f| f.name).collect();
    let original_len = names.len();
    names.sort();
    names.dedup();
    assert_eq!(
        names.len(),
        original_len,
        "History file names should be unique"
    );
}
