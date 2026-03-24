//! Comprehensive history file location definitions
//!
//! This module provides a centralized registry of known shell and application
//! history file locations for cleanup operations. It supports multiple shells,
//! database clients, REPLs, editors, and alternative history tools.
//!
//! # Design
//!
//! History files are categorized by type and marked with a `common` flag to
//! indicate which files are most frequently encountered in typical systems.
//! This allows cleanup operations to prioritize common files for faster cleanup.
//!
//! # Path Resolution
//!
//! History files can be located in various standard locations:
//! - Home-relative paths (e.g., `~/.bash_history`)
//! - XDG data directory (e.g., `~/.local/share/fish/fish_history`)
//! - XDG config directory (e.g., `~/.config/nushell/history.txt`)
//! - XDG state directory (e.g., `~/.local/state/nvim/shada/main.shada`)
//! - Absolute paths (rare, but supported)
//!
//! # Example
//!
//! ```rust,ignore
//! use nails_core::cleanup::history_files::{
//!     ALL_HISTORY_FILES, HistoryCategory, get_by_category, get_common, get_existing
//! };
//!
//! // Get all shell history files
//! let shell_files = get_by_category(HistoryCategory::Shell);
//!
//! // Get only common history files (fast cleanup)
//! let common_files = get_common();
//!
//! // Get files that exist on the current system
//! let existing_files = get_existing();
//! for (file, path) in existing_files {
//!     println!("{}: {}", file.name, path.display());
//! }
//! ```

use std::path::PathBuf;

/// Category of history file
///
/// Groups history files by their source application type for
/// targeted cleanup operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HistoryCategory {
    /// Shell command history (bash, zsh, fish, etc.)
    Shell,
    /// Database client history (mysql, psql, sqlite, etc.)
    Database,
    /// Programming language REPL history (python, node, irb, etc.)
    Repl,
    /// Text editor history and state files (vim, nvim, less)
    Editor,
    /// Alternative shell history tools (atuin, mcfly)
    Alternative,
    /// Miscellaneous application history (wget, gdb, fzf)
    Misc,
}

impl HistoryCategory {
    /// Get a human-readable name for this category
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Shell => "Shell",
            Self::Database => "Database",
            Self::Repl => "REPL",
            Self::Editor => "Editor",
            Self::Alternative => "Alternative",
            Self::Misc => "Misc",
        }
    }
}

/// Format of the history file
///
/// Different applications store history in different formats.
/// This affects how the file should be processed for cleanup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HistoryFormat {
    /// Plain text, one entry per line (bash, zsh, most REPLs)
    PlainText,
    /// YAML format (fish shell)
    Yaml,
    /// SQLite database (ipython, atuin, mcfly, nushell sqlite)
    Sqlite,
    /// JSON format (some modern tools)
    Json,
    /// Binary/proprietary format (vim shada, nvim shada)
    Binary,
}

impl HistoryFormat {
    /// Whether this format can be edited with simple text tools
    pub fn is_text_editable(&self) -> bool {
        matches!(self, Self::PlainText | Self::Yaml | Self::Json)
    }

    /// Get a human-readable description of this format
    pub fn description(&self) -> &'static str {
        match self {
            Self::PlainText => "Plain text",
            Self::Yaml => "YAML",
            Self::Sqlite => "SQLite database",
            Self::Json => "JSON",
            Self::Binary => "Binary",
        }
    }
}

/// Path location type for history files
///
/// History files are stored in various standard locations.
/// This enum allows resolution relative to XDG directories
/// or the user's home directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoryPath {
    /// Relative to $HOME (e.g., ".bash_history" -> "~/.bash_history")
    HomeRelative(&'static str),
    /// Relative to $XDG_DATA_HOME (default: ~/.local/share)
    /// e.g., "fish/fish_history" -> "~/.local/share/fish/fish_history"
    XdgData(&'static str),
    /// Relative to $XDG_CONFIG_HOME (default: ~/.config)
    /// e.g., "nushell/history.txt" -> "~/.config/nushell/history.txt"
    XdgConfig(&'static str),
    /// Relative to $XDG_STATE_HOME (default: ~/.local/state)
    /// e.g., "nvim/shada/main.shada" -> "~/.local/state/nvim/shada/main.shada"
    XdgState(&'static str),
    /// Absolute path (rarely used)
    Absolute(&'static str),
}

impl HistoryPath {
    /// Resolve the path to an absolute PathBuf using explicit base paths
    ///
    /// This version accepts explicit paths instead of reading environment variables,
    /// making it suitable for testing without env var manipulation.
    ///
    /// # Arguments
    ///
    /// * `home` - The home directory path (equivalent to $HOME)
    /// * `xdg_data` - Optional XDG_DATA_HOME path (defaults to $HOME/.local/share)
    /// * `xdg_config` - Optional XDG_CONFIG_HOME path (defaults to $HOME/.config)
    /// * `xdg_state` - Optional XDG_STATE_HOME path (defaults to $HOME/.local/state)
    ///
    /// # Returns
    ///
    /// PathBuf for the resolved path.
    pub fn resolve_with_home(
        &self,
        home: &std::path::Path,
        xdg_data: Option<&std::path::Path>,
        xdg_config: Option<&std::path::Path>,
        xdg_state: Option<&std::path::Path>,
    ) -> PathBuf {
        match self {
            Self::HomeRelative(path) => home.join(path),
            Self::XdgData(path) => {
                let base = xdg_data
                    .map(|p| p.to_path_buf())
                    .unwrap_or_else(|| home.join(".local/share"));
                base.join(path)
            }
            Self::XdgConfig(path) => {
                let base = xdg_config
                    .map(|p| p.to_path_buf())
                    .unwrap_or_else(|| home.join(".config"));
                base.join(path)
            }
            Self::XdgState(path) => {
                let base = xdg_state
                    .map(|p| p.to_path_buf())
                    .unwrap_or_else(|| home.join(".local/state"));
                base.join(path)
            }
            Self::Absolute(path) => PathBuf::from(path),
        }
    }

    /// Resolve the path to an absolute PathBuf
    ///
    /// Uses XDG base directory specification with fallbacks to standard defaults:
    /// - $XDG_DATA_HOME defaults to ~/.local/share
    /// - $XDG_CONFIG_HOME defaults to ~/.config
    /// - $XDG_STATE_HOME defaults to ~/.local/state
    ///
    /// # Returns
    ///
    /// Some(PathBuf) if the path can be resolved, None if $HOME is not set.
    pub fn resolve(&self) -> Option<PathBuf> {
        match self {
            Self::HomeRelative(path) => {
                let home = std::env::var("HOME").ok()?;
                Some(PathBuf::from(home).join(path))
            }
            Self::XdgData(path) => {
                let base = std::env::var("XDG_DATA_HOME").ok().unwrap_or_else(|| {
                    std::env::var("HOME")
                        .map(|h| format!("{}/.local/share", h))
                        .unwrap_or_default()
                });
                if base.is_empty() {
                    return None;
                }
                Some(PathBuf::from(base).join(path))
            }
            Self::XdgConfig(path) => {
                let base = std::env::var("XDG_CONFIG_HOME").ok().unwrap_or_else(|| {
                    std::env::var("HOME")
                        .map(|h| format!("{}/.config", h))
                        .unwrap_or_default()
                });
                if base.is_empty() {
                    return None;
                }
                Some(PathBuf::from(base).join(path))
            }
            Self::XdgState(path) => {
                let base = std::env::var("XDG_STATE_HOME").ok().unwrap_or_else(|| {
                    std::env::var("HOME")
                        .map(|h| format!("{}/.local/state", h))
                        .unwrap_or_default()
                });
                if base.is_empty() {
                    return None;
                }
                Some(PathBuf::from(base).join(path))
            }
            Self::Absolute(path) => Some(PathBuf::from(path)),
        }
    }
}

/// Definition of a known history file location
///
/// Contains all metadata needed to locate and process a history file
/// for cleanup operations.
#[derive(Debug, Clone)]
pub struct HistoryFile {
    /// Short identifier name (e.g., "bash", "mysql", "vim")
    pub name: &'static str,
    /// Category of the history file
    pub category: HistoryCategory,
    /// Path specification for locating the file
    pub path: HistoryPath,
    /// Format of the history file
    pub format: HistoryFormat,
    /// Whether this is a commonly-used application (prioritize in fast cleanup)
    pub common: bool,
}

impl HistoryFile {
    /// Create a new HistoryFile definition
    const fn new(
        name: &'static str,
        category: HistoryCategory,
        path: HistoryPath,
        format: HistoryFormat,
        common: bool,
    ) -> Self {
        Self {
            name,
            category,
            path,
            format,
            common,
        }
    }

    /// Resolve the path to this history file using explicit home directory
    ///
    /// This version accepts an explicit home path instead of reading $HOME,
    /// making it suitable for testing without env var manipulation.
    ///
    /// # Arguments
    ///
    /// * `home` - The home directory path
    ///
    /// # Returns
    ///
    /// PathBuf for the resolved path.
    pub fn resolve_path_for_home(&self, home: &std::path::Path) -> PathBuf {
        self.path.resolve_with_home(home, None, None, None)
    }

    /// Resolve the path to this history file
    ///
    /// # Returns
    ///
    /// Some(PathBuf) if the path can be resolved, None if required
    /// environment variables (e.g., $HOME) are not set.
    pub fn resolve_path(&self) -> Option<PathBuf> {
        self.path.resolve()
    }
}

/// Complete registry of known history file locations
///
/// This const array contains all known history file locations organized by category.
/// Use helper functions like `get_by_category()`, `get_common()`, and `get_existing()`
/// for filtered access.
pub const ALL_HISTORY_FILES: &[HistoryFile] = &[
    // ===== Shell History Files =====
    // Bash - most common Unix shell
    HistoryFile::new(
        "bash",
        HistoryCategory::Shell,
        HistoryPath::HomeRelative(".bash_history"),
        HistoryFormat::PlainText,
        true,
    ),
    // Zsh - popular among power users, default on macOS
    HistoryFile::new(
        "zsh",
        HistoryCategory::Shell,
        HistoryPath::HomeRelative(".zsh_history"),
        HistoryFormat::PlainText,
        true,
    ),
    // Zsh alternate location (older convention)
    HistoryFile::new(
        "zsh-alt",
        HistoryCategory::Shell,
        HistoryPath::HomeRelative(".zhistory"),
        HistoryFormat::PlainText,
        false, // Less common alternate location
    ),
    // Fish - user-friendly shell, uses YAML-like format
    HistoryFile::new(
        "fish",
        HistoryCategory::Shell,
        HistoryPath::XdgData("fish/fish_history"),
        HistoryFormat::Yaml,
        true,
    ),
    // Korn shell - Unix heritage
    HistoryFile::new(
        "ksh",
        HistoryCategory::Shell,
        HistoryPath::HomeRelative(".sh_history"),
        HistoryFormat::PlainText,
        false,
    ),
    // TENEX C shell
    HistoryFile::new(
        "tcsh",
        HistoryCategory::Shell,
        HistoryPath::HomeRelative(".history"),
        HistoryFormat::PlainText,
        false,
    ),
    // Almquist shell (BusyBox default)
    HistoryFile::new(
        "ash",
        HistoryCategory::Shell,
        HistoryPath::HomeRelative(".ash_history"),
        HistoryFormat::PlainText,
        false,
    ),
    // Nushell - modern shell, plain text history
    HistoryFile::new(
        "nushell",
        HistoryCategory::Shell,
        HistoryPath::XdgConfig("nushell/history.txt"),
        HistoryFormat::PlainText,
        false,
    ),
    // Nushell - SQLite history variant
    HistoryFile::new(
        "nushell-sqlite",
        HistoryCategory::Shell,
        HistoryPath::XdgConfig("nushell/history.sqlite3"),
        HistoryFormat::Sqlite,
        false,
    ),
    // ===== Database Client History Files =====
    // MySQL client
    HistoryFile::new(
        "mysql",
        HistoryCategory::Database,
        HistoryPath::HomeRelative(".mysql_history"),
        HistoryFormat::PlainText,
        true,
    ),
    // PostgreSQL client
    HistoryFile::new(
        "psql",
        HistoryCategory::Database,
        HistoryPath::HomeRelative(".psql_history"),
        HistoryFormat::PlainText,
        true,
    ),
    // SQLite client
    HistoryFile::new(
        "sqlite",
        HistoryCategory::Database,
        HistoryPath::HomeRelative(".sqlite_history"),
        HistoryFormat::PlainText,
        true,
    ),
    // Redis CLI
    HistoryFile::new(
        "redis",
        HistoryCategory::Database,
        HistoryPath::HomeRelative(".rediscli_history"),
        HistoryFormat::PlainText,
        true,
    ),
    // MongoDB shell (legacy)
    HistoryFile::new(
        "mongo",
        HistoryCategory::Database,
        HistoryPath::HomeRelative(".dbshell"),
        HistoryFormat::PlainText,
        false,
    ),
    // MongoDB shell (mongosh - modern)
    HistoryFile::new(
        "mongosh",
        HistoryCategory::Database,
        HistoryPath::HomeRelative(".mongosh/.mongosh_repl_history"),
        HistoryFormat::PlainText,
        false,
    ),
    // ===== REPL History Files =====
    // Python REPL
    HistoryFile::new(
        "python",
        HistoryCategory::Repl,
        HistoryPath::HomeRelative(".python_history"),
        HistoryFormat::PlainText,
        true,
    ),
    // IPython - SQLite database format
    HistoryFile::new(
        "ipython",
        HistoryCategory::Repl,
        HistoryPath::HomeRelative(".ipython/profile_default/history.sqlite"),
        HistoryFormat::Sqlite,
        false,
    ),
    // Node.js REPL
    HistoryFile::new(
        "node",
        HistoryCategory::Repl,
        HistoryPath::HomeRelative(".node_repl_history"),
        HistoryFormat::PlainText,
        true,
    ),
    // Ruby IRB
    HistoryFile::new(
        "irb",
        HistoryCategory::Repl,
        HistoryPath::HomeRelative(".irb_history"),
        HistoryFormat::PlainText,
        true,
    ),
    // Haskell GHCi
    HistoryFile::new(
        "ghci",
        HistoryCategory::Repl,
        HistoryPath::HomeRelative(".ghci_history"),
        HistoryFormat::PlainText,
        false,
    ),
    // Scala REPL
    HistoryFile::new(
        "scala",
        HistoryCategory::Repl,
        HistoryPath::HomeRelative(".scala_history"),
        HistoryFormat::PlainText,
        false,
    ),
    // ===== Editor History Files =====
    // Vim - viminfo file
    HistoryFile::new(
        "vim",
        HistoryCategory::Editor,
        HistoryPath::HomeRelative(".viminfo"),
        HistoryFormat::PlainText, // Vim's viminfo is mostly text-parseable
        true,
    ),
    // Neovim - ShaDa format (binary)
    HistoryFile::new(
        "nvim",
        HistoryCategory::Editor,
        HistoryPath::XdgState("nvim/shada/main.shada"),
        HistoryFormat::Binary,
        true,
    ),
    // Less pager history
    HistoryFile::new(
        "less",
        HistoryCategory::Editor,
        HistoryPath::HomeRelative(".lesshst"),
        HistoryFormat::PlainText,
        true,
    ),
    // ===== Alternative Shell History Tools =====
    // Atuin - enhanced shell history with sync
    HistoryFile::new(
        "atuin",
        HistoryCategory::Alternative,
        HistoryPath::XdgData("atuin/history.db"),
        HistoryFormat::Sqlite,
        false,
    ),
    // McFly - intelligent shell history
    HistoryFile::new(
        "mcfly",
        HistoryCategory::Alternative,
        HistoryPath::XdgData("mcfly/history.db"),
        HistoryFormat::Sqlite,
        false,
    ),
    // ===== Miscellaneous History Files =====
    // wget HSTS file (contains visited hosts)
    HistoryFile::new(
        "wget",
        HistoryCategory::Misc,
        HistoryPath::HomeRelative(".wget-hsts"),
        HistoryFormat::PlainText,
        false,
    ),
    // GDB debugger history
    HistoryFile::new(
        "gdb",
        HistoryCategory::Misc,
        HistoryPath::HomeRelative(".gdb_history"),
        HistoryFormat::PlainText,
        false,
    ),
    // fzf fuzzy finder history
    HistoryFile::new(
        "fzf",
        HistoryCategory::Misc,
        HistoryPath::HomeRelative(".fzf_history"),
        HistoryFormat::PlainText,
        false,
    ),
];

/// Get all history files in a specific category
///
/// # Arguments
///
/// * `category` - The category to filter by
///
/// # Returns
///
/// Vector of references to history files in the specified category.
///
/// # Example
///
/// ```rust,ignore
/// use nails_core::cleanup::history_files::{HistoryCategory, get_by_category};
///
/// let shell_files = get_by_category(HistoryCategory::Shell);
/// for file in shell_files {
///     println!("{}: {:?}", file.name, file.path);
/// }
/// ```
pub fn get_by_category(category: HistoryCategory) -> Vec<&'static HistoryFile> {
    ALL_HISTORY_FILES
        .iter()
        .filter(|f| f.category == category)
        .collect()
}

/// Get all commonly-used history files
///
/// Returns history files with `common = true`, which are the files
/// most likely to exist on typical systems. Use this for fast cleanup
/// operations that prioritize speed over completeness.
///
/// # Returns
///
/// Vector of references to common history files.
///
/// # Example
///
/// ```rust,ignore
/// use nails_core::cleanup::history_files::get_common;
///
/// let common_files = get_common();
/// println!("Found {} common history file types", common_files.len());
/// ```
pub fn get_common() -> Vec<&'static HistoryFile> {
    ALL_HISTORY_FILES.iter().filter(|f| f.common).collect()
}

/// Get all history files that exist on the current system
///
/// Resolves paths and checks filesystem existence for each known
/// history file location. Only returns files that actually exist.
///
/// # Returns
///
/// Vector of tuples containing:
/// - Reference to the HistoryFile definition
/// - Resolved PathBuf to the existing file
///
/// # Example
///
/// ```rust,ignore
/// use nails_core::cleanup::history_files::get_existing;
///
/// let existing = get_existing();
/// for (file, path) in existing {
///     println!("{} ({:?}): {}", file.name, file.format, path.display());
/// }
/// ```
pub fn get_existing() -> Vec<(&'static HistoryFile, PathBuf)> {
    ALL_HISTORY_FILES
        .iter()
        .filter_map(|file| {
            let path = file.resolve_path()?;
            if path.exists() {
                Some((file, path))
            } else {
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
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
}
