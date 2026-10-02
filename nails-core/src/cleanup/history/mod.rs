//! Shell history cleanup for bash, zsh, and fish shells
//!
//! This module provides [`HistoryCleaner`] which removes command history entries
//! containing specified patterns from shell history files.
//!
//! Supports:
//! - Bash (~/.bash_history)
//! - Zsh (~/.zsh_history)
//! - Fish (~/.local/share/fish/fish_history)
//!
//! # Example
//!
//! ```rust,ignore
//! use nails_core::{HistoryCleaner, MockFilesystem};
//!
//! let fs = MockFilesystem::new();
//! let cleaner = HistoryCleaner::new(fs);
//! let report = cleaner.clean()?;
//! for item in report {
//!     println!("{}", item);
//! }
//! ```

mod cleaner;

#[cfg(test)]
mod tests_cleaner;
#[cfg(test)]
mod tests_shell;

pub use cleaner::HistoryCleaner;

use crate::Filesystem;
use std::path::PathBuf;

/// Home directories that history cleanup must cover for the current run.
///
/// Returns the operator's home (resolved through [`crate::TargetUser`]) plus
/// `/root`. This is the fix for the long-standing bug where cleanup read `$HOME`
/// directly: under `sudo` `$HOME` is `/root`, and in the detached `systemd-run`
/// unit it is unset, so the operator's own history was never touched. Resolving
/// through [`crate::TargetUser`] instead uses the forwarded target-uid and
/// privilege-tool environment, which identify the real account in both contexts.
///
/// If no target user can be resolved, cleanup still covers `/root`, where a
/// `sudo` invocation always leaves residue; it never silently cleans nothing.
///
/// On the static musl build only local `/etc/passwd` accounts resolve (no NSS).
#[cfg(not(test))]
pub fn history_cleanup_homes() -> Vec<PathBuf> {
    match crate::TargetUser::resolve() {
        Ok(user) => user.cleanup_homes(),
        Err(e) => {
            tracing::warn!(
                error = %e,
                "Could not resolve the target user for history cleanup; cleaning /root only"
            );
            vec![PathBuf::from("/root")]
        }
    }
}

/// Test build: history cleanup operates on the safe fake home so unit tests never
/// touch the real operator's files or require environment manipulation.
#[cfg(test)]
pub fn history_cleanup_homes() -> Vec<PathBuf> {
    vec![PathBuf::from(crate::cleanup::test_utils::TEST_HOME)]
}

/// Supported shell types for history cleanup
///
/// Each shell stores its command history in a different file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellType {
    /// GNU Bash shell
    Bash,
    /// Z shell
    Zsh,
    /// Fish shell
    Fish,
}

impl ShellType {
    /// Get the default history file path for this shell, given a home directory
    ///
    /// # Arguments
    ///
    /// * `home` - The home directory path (e.g., from $HOME or for testing)
    ///
    /// # Returns
    ///
    /// PathBuf to the history file.
    pub fn history_file_path_for_home(&self, home: &std::path::Path) -> PathBuf {
        match self {
            ShellType::Bash => home.join(".bash_history"),
            ShellType::Zsh => home.join(".zsh_history"),
            ShellType::Fish => home
                .join(".local")
                .join("share")
                .join("fish")
                .join("fish_history"),
        }
    }

    /// Get the display name of this shell type
    pub fn name(&self) -> &'static str {
        match self {
            ShellType::Bash => "bash",
            ShellType::Zsh => "zsh",
            ShellType::Fish => "fish",
        }
    }

    /// Get all supported shell types
    pub fn all() -> Vec<ShellType> {
        vec![ShellType::Bash, ShellType::Zsh, ShellType::Fish]
    }
}

/// Get an extended list of history file paths for forensic cleanup, given a home directory
///
/// This function returns paths to all known history files that might contain
/// NAILS-related commands, including:
/// - Standard shell history files (bash, zsh, fish)
/// - Less pager history
/// - Python/IPython history
/// - Database CLI history (psql, mysql, sqlite)
/// - GDB debugger history
/// - Recently used files trackers
/// - Node.js REPL history
/// - Ruby IRB history
///
/// This list is used for post-unmount cleanup to ensure the REAL disk
/// (not the overlay) is cleaned of any forensic artifacts.
///
/// # Arguments
///
/// * `home` - The home directory path (e.g., from $HOME or for testing)
///
/// # Returns
///
/// Vector of PathBuf for all history file locations that may exist.
/// Note: Not all paths will exist on every system.
pub fn get_extended_history_files_for_home(home: &std::path::Path) -> Vec<std::path::PathBuf> {
    vec![
        // Shell history files
        home.join(".bash_history"),
        home.join(".zsh_history"),
        home.join(".local/share/fish/fish_history"),
        // Less pager history
        home.join(".lesshst"),
        // Python history
        home.join(".python_history"),
        home.join(".ipython/profile_default/history.sqlite"),
        // Database CLI history
        home.join(".psql_history"),
        home.join(".mysql_history"),
        home.join(".sqlite_history"),
        // GDB debugger history
        home.join(".gdb_history"),
        // Node.js REPL history
        home.join(".node_repl_history"),
        // Ruby IRB history
        home.join(".irb_history"),
        // Vim/Neovim history and info
        home.join(".viminfo"),
        home.join(".local/state/nvim/shada/main.shada"),
        // Recently used files (GNOME/GTK)
        home.join(".local/share/recently-used.xbel"),
        // Wget history
        home.join(".wget-hsts"),
        // Atuin shell history (modern shell history tool)
        home.join(".local/share/atuin/history.db"),
    ]
}

/// Get an extended list of history file paths for forensic cleanup across the
/// given home directories.
///
/// This is the multi-home form of [`get_extended_history_files_for_home`]: it
/// concatenates the per-home lists for every home in `homes`. Callers pass
/// [`history_cleanup_homes`] so post-unmount cleanup covers both the operator's
/// home and `/root`.
pub fn get_extended_history_files_for_homes(homes: &[PathBuf]) -> Vec<PathBuf> {
    homes
        .iter()
        .flat_map(|home| get_extended_history_files_for_home(home))
        .collect()
}

/// Filter fish shell YAML history by removing matching `- cmd:` entries and their `when:` lines
///
/// Fish history format:
/// ```yaml
/// - cmd: nails activate
///   when: 1700000000
/// - cmd: ls -la
///   when: 1700000001
/// ```
///
/// When a `- cmd:` line matches any pattern (case-insensitive), the line and its
/// following `  when:` line are both removed.
///
/// # Returns
///
/// `(filtered_content, removed_entry_count)` — the filtered string and how many
/// entries (cmd+when pairs) were removed.
pub(crate) fn filter_fish_history(content: &str, patterns: &[String]) -> (String, usize) {
    let lines: Vec<&str> = content.lines().collect();
    let mut result = Vec::new();
    let mut removed_count = 0;
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i];

        // Check if this is a `- cmd:` line
        if line.starts_with("- cmd:") {
            let line_lower = line.to_lowercase();
            let matches = patterns
                .iter()
                .any(|p| line_lower.contains(&p.to_lowercase()));

            if matches {
                removed_count += 1;
                i += 1;
                // Skip the following `when:` line if present
                if i < lines.len() && lines[i].trim_start().starts_with("when:") {
                    i += 1;
                }
                // Also skip any other indented metadata lines (e.g., `  paths:`)
                while i < lines.len()
                    && !lines[i].starts_with("- cmd:")
                    && (lines[i].starts_with("  ") || lines[i].starts_with('\t'))
                {
                    i += 1;
                }
                continue;
            }
        }

        result.push(line);
        i += 1;
    }

    let text = if result.is_empty() {
        String::new()
    } else {
        format!("{}\n", result.join("\n"))
    };
    (text, removed_count)
}

/// Truncate all known history files to zero length, given a home directory
///
/// This is the forensically safe approach: rather than pattern-filtering (which
/// is fragile), truncate every known history file on the real disk. This ensures
/// ZERO commands remain visible to an adversary.
///
/// # Arguments
///
/// * `fs` - Filesystem implementation
/// * `home` - The home directory path (e.g., from $HOME or for testing)
/// * `secure` - If true, use secure_delete before truncating (overwrite with zeros/random)
///
/// # Returns
///
/// Vec of descriptions of what was done (best-effort, never fails overall).
pub fn truncate_all_history_files_for_home<F: Filesystem>(
    fs: &F,
    home: &std::path::Path,
    secure: bool,
) -> Vec<String> {
    let history_files = get_extended_history_files_for_home(home);
    let mut results = Vec::new();

    for path in &history_files {
        match fs.path_exists(path) {
            Ok(true) => {
                // Secure delete first if requested
                if secure && let Err(e) = fs.secure_delete(path) {
                    tracing::debug!(
                        file = %path.display(),
                        error = %e,
                        "Secure delete failed, proceeding with truncation"
                    );
                }

                // Truncate to empty
                match fs.write_file_content(path, "") {
                    Ok(()) => {
                        results.push(format!("Truncated {}", path.display()));
                    }
                    Err(e) => {
                        tracing::warn!(
                            file = %path.display(),
                            error = %e,
                            "Failed to truncate history file"
                        );
                    }
                }
            }
            Ok(false) => {
                // File doesn't exist, skip silently
            }
            Err(e) => {
                tracing::warn!(
                    file = %path.display(),
                    error = %e,
                    "Failed to check history file existence"
                );
            }
        }
    }

    results
}

/// Truncate all known history files to zero length across the given homes.
///
/// This is the multi-home form of [`truncate_all_history_files_for_home`].
/// Callers pass [`history_cleanup_homes`] so post-unmount cleanup covers both
/// the operator's home and `/root` — the fix for cleanup that previously read
/// `$HOME` and so only ever reached root's home under `sudo`.
///
/// # Arguments
///
/// * `fs` - Filesystem implementation
/// * `homes` - Home directories to clean
/// * `secure` - If true, use secure_delete before truncating (overwrite with zeros/random)
///
/// # Returns
///
/// Vec of descriptions of what was done (best-effort, never fails overall).
pub fn truncate_all_history_files_for_homes<F: Filesystem>(
    fs: &F,
    homes: &[PathBuf],
    secure: bool,
) -> Vec<String> {
    let mut results = Vec::new();
    for home in homes {
        results.extend(truncate_all_history_files_for_home(fs, home, secure));
    }
    results
}
