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

mod registry;

#[cfg(test)]
mod tests;

pub use registry::{ALL_HISTORY_FILES, get_by_category, get_common, get_existing};

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
    pub(crate) const fn new(
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
