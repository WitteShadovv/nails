//! Registry of known history file locations and query functions

use std::path::PathBuf;

use super::{HistoryCategory, HistoryFile, HistoryFormat, HistoryPath};

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
