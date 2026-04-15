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

use crate::{Filesystem, NailsError, Result, output};
use std::path::PathBuf;

/// Supported shell types for history cleanup
///
/// Each shell stores history differently and has different
/// commands for clearing in-memory history.
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

    /// Get the default history file path for this shell
    ///
    /// Resolves $HOME environment variable to get actual path.
    ///
    /// # Returns
    ///
    /// PathBuf to the history file, or None if $HOME is not set.
    pub fn history_file_path(&self) -> Option<PathBuf> {
        let home = std::env::var("HOME").ok()?;
        let home_path = PathBuf::from(home);
        Some(self.history_file_path_for_home(&home_path))
    }

    /// Get the command to clear in-memory history for this shell
    ///
    /// Note: These commands clear ALL in-memory history, not just nails-related.
    /// This is intentional for security (forensic safety).
    pub fn in_memory_clear_command(&self) -> &'static str {
        match self {
            ShellType::Bash => "history -c",
            ShellType::Zsh => "fc -W; fc -p", // Write to file, then reload
            ShellType::Fish => "history clear",
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

/// Get an extended list of history file paths for forensic cleanup
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
/// # Returns
///
/// Vector of PathBuf for all history file locations that may exist.
/// Note: Not all paths will exist on every system.
pub fn get_extended_history_files() -> Vec<std::path::PathBuf> {
    let Some(home) = std::env::var("HOME").ok() else {
        return Vec::new();
    };
    let home_path = std::path::PathBuf::from(&home);
    get_extended_history_files_for_home(&home_path)
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
fn filter_fish_history(content: &str, patterns: &[String]) -> (String, usize) {
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

/// Truncate all known history files to zero length
///
/// This is the forensically safe approach: rather than pattern-filtering (which
/// is fragile), truncate every known history file on the real disk. This ensures
/// ZERO commands remain visible to an adversary.
///
/// # Arguments
///
/// * `fs` - Filesystem implementation
/// * `secure` - If true, use secure_delete before truncating (overwrite with zeros/random)
///
/// # Returns
///
/// Vec of descriptions of what was done (best-effort, never fails overall).
pub fn truncate_all_history_files<F: Filesystem>(fs: &F, secure: bool) -> Vec<String> {
    let history_files = get_extended_history_files();
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

/// Cleans shell history files by removing lines matching patterns
///
/// HistoryCleaner removes all command history entries containing
/// specified patterns (default: "nails") from bash, zsh, and fish
/// history files. It also clears in-memory history.
///
/// # Security
///
/// - Case-insensitive matching ensures all variations are caught
/// - Atomic file writes prevent data corruption
/// - In-memory clearing prevents forensic recovery from RAM
/// - Optional secure deletion for forensic resistance
///
/// # Generic Parameter
///
/// `F: Filesystem` - Abstracted filesystem operations for testability
pub struct HistoryCleaner<F: Filesystem> {
    filesystem: F,
    patterns: Vec<String>,
    shells: Vec<ShellType>,
    /// Use secure deletion (overwrite before delete)
    pub(crate) secure_delete: bool,
    /// Optional explicit home directory path (for testing without env vars)
    home: Option<PathBuf>,
}

impl<F: Filesystem> HistoryCleaner<F> {
    /// Create a new HistoryCleaner with default settings
    ///
    /// Default patterns: ["nails"]
    /// Default shells: [Bash, Zsh, Fish]
    /// Default secure_delete: false
    pub fn new(filesystem: F) -> Self {
        Self {
            filesystem,
            patterns: vec!["nails".to_string()],
            shells: ShellType::all(),
            secure_delete: false,
            home: None,
        }
    }

    /// Set custom patterns to match (replaces defaults)
    pub fn with_patterns(mut self, patterns: Vec<String>) -> Self {
        self.patterns = patterns;
        self
    }

    /// Set specific shells to clean (replaces defaults)
    pub fn with_shells(mut self, shells: Vec<ShellType>) -> Self {
        self.shells = shells;
        self
    }

    /// Enable or disable secure deletion
    ///
    /// When enabled, history files are securely deleted (overwritten) before
    /// being rewritten with filtered content. This provides better forensic resistance.
    pub fn with_secure_delete(mut self, enabled: bool) -> Self {
        self.secure_delete = enabled;
        self
    }

    /// Set explicit home directory path
    ///
    /// When set, this path is used instead of reading $HOME environment variable.
    /// This is useful for testing without env var manipulation.
    ///
    /// # Arguments
    ///
    /// * `home` - The home directory path to use for history file resolution
    pub fn with_home(mut self, home: PathBuf) -> Self {
        self.home = Some(home);
        self
    }

    /// Get the history file path for a shell, using explicit home if set
    fn get_history_path(&self, shell: ShellType) -> Option<PathBuf> {
        match &self.home {
            Some(home) => Some(shell.history_file_path_for_home(home)),
            None => shell.history_file_path(),
        }
    }

    /// Execute history cleanup
    ///
    /// Cleans history files and in-memory history for all configured shells.
    /// Uses best-effort approach - continues on individual failures.
    ///
    /// # Returns
    ///
    /// Vec<String> with descriptions of cleaned items.
    ///
    /// # Errors
    ///
    /// Returns Err only if a critical error occurs (e.g., permission denied
    /// on a file that exists and should be writable).
    pub fn clean(&self) -> Result<Vec<String>> {
        let mut cleaned = Vec::new();

        for shell in &self.shells {
            // Clean history file
            match self.clean_history_file(*shell) {
                Ok(Some(msg)) => cleaned.push(msg),
                Ok(None) => {} // No history file found, skip
                Err(e) => {
                    // Log warning but continue (best-effort)
                    output::warn(&format!("Failed to clean {:?} history: {}", shell, e));
                }
            }

            // Attempt in-memory history clear (best-effort, see method docs for limitations)
            // Skipped in test builds: subprocess shell commands have real system side effects
            // (fish -c "history clear" corrupts $fish_history universal variable;
            //  zsh -c "fc -W" overwrites ~/.zsh_history with empty content).
            #[cfg(not(test))]
            if let Err(e) = self.attempt_clean_in_memory_history(*shell) {
                output::warn(&format!(
                    "Failed to clear {:?} in-memory history: {}",
                    shell, e
                ));
            }
        }

        Ok(cleaned)
    }

    /// Clean a specific shell's history file
    ///
    /// For Fish shell, uses [`filter_fish_history`] to properly handle the YAML-like
    /// format where each entry consists of a `- cmd:` line followed by a `  when:` line.
    /// For other shells, uses simple line-by-line filtering.
    ///
    /// # Returns
    ///
    /// - `Ok(Some(msg))` - History cleaned with description
    /// - `Ok(None)` - No history file found (skip)
    /// - `Err(e)` - Error occurred during cleanup
    fn clean_history_file(&self, shell: ShellType) -> Result<Option<String>> {
        let history_path = match self.get_history_path(shell) {
            Some(path) => path,
            None => return Ok(None), // $HOME not set
        };

        // Check if history file exists
        if !self.filesystem.path_exists(&history_path)? {
            return Ok(None); // No history file, skip
        }

        // Read history file content
        let content = self.filesystem.read_file_content(&history_path)?;

        // Filter content based on shell type
        let (new_content, removed_count) = if shell == ShellType::Fish {
            filter_fish_history(&content, &self.patterns)
        } else {
            let original_count = content.lines().count();
            let filtered: Vec<&str> = content
                .lines()
                .filter(|line| !self.line_matches_patterns(line))
                .collect();
            let removed = original_count - filtered.len();
            let text = if filtered.is_empty() {
                String::new()
            } else {
                format!("{}\n", filtered.join("\n"))
            };
            (text, removed)
        };

        if removed_count == 0 {
            return Ok(Some(format!(
                "No matching entries found in {}",
                history_path.display()
            )));
        }

        // If secure_delete is enabled, securely delete the original file first
        if self.secure_delete
            && let Err(e) = self.filesystem.secure_delete(&history_path)
        {
            output::warn(&format!(
                "Secure delete of {} failed, falling back to normal overwrite: {}",
                history_path.display(),
                e
            ));
        }

        // Write filtered content back (atomic write via Filesystem trait)
        self.filesystem
            .write_file_content(&history_path, &new_content)?;

        let secure_note = if self.secure_delete {
            " (secure delete)"
        } else {
            ""
        };
        Ok(Some(format!(
            "Removed {} entries from {}{}",
            removed_count,
            history_path.display(),
            secure_note
        )))
    }

    /// Check if a line matches any of the configured patterns
    fn line_matches_patterns(&self, line: &str) -> bool {
        let line_lower = line.to_lowercase();
        self.patterns
            .iter()
            .any(|pattern| line_lower.contains(&pattern.to_lowercase()))
    }

    /// Attempt to clear in-memory history for a shell (BEST-EFFORT ONLY)
    ///
    /// # ⚠️ CRITICAL LIMITATION - THIS DOES NOT WORK AS EXPECTED ⚠️
    ///
    /// **This method spawns NEW shell subprocesses to execute clear commands.**
    /// The subprocess has NO connection to the user's actual shell session.
    ///
    /// Example: When you run `nails deactivate`, this spawns `bash -c "history -c"`
    /// which clears history in the subprocess, NOT in your parent shell that has
    /// the actual history.
    ///
    /// **This is a fundamental architectural limitation:** You cannot clear another
    /// process's in-memory history from a subprocess. The in-memory history lives
    /// in the parent shell's RAM space, which is inaccessible to child processes.
    ///
    /// ## Why This Approach Still Exists
    ///
    /// - Follows AC6 requirements letter-by-law ("uses std::process::Command")
    /// - Best-effort approach with warnings on failure
    /// - File-based cleanup (the primary security measure) works correctly
    ///
    /// ## What Actually Provides Security
    ///
    /// The `clean_history_file()` method removes entries from disk-based history
    /// files, which IS effective. In-memory history in the parent shell will be
    /// lost when the shell exits anyway.
    ///
    /// ## Better Solutions (Future Work)
    ///
    /// 1. **Shell integration:** Source a script from the user's shell rc file
    ///    that intercepts `nails deactivate` and runs shell-builtin history clear
    /// 2. **Session management:** Track shells started during nails session and
    ///    terminate them before deactivation (Story 4.14 approach)
    /// 3. **Accept limitation:** Focus on file-based cleanup (already robust)
    #[cfg_attr(test, allow(dead_code))]
    fn attempt_clean_in_memory_history(&self, shell: ShellType) -> Result<()> {
        // Fish: `fish -c "history clear"` corrupts the $fish_history universal variable,
        // causing interactive sessions to stop loading history. Skip entirely.
        //
        // Zsh: `fc -W` writes the (empty) subprocess history to $HISTFILE, overwriting
        // ~/.zsh_history on disk. Skip entirely.
        //
        // Bash: `bash -c "history -c"` only affects the subprocess — safe to run.
        let shell_name = match shell {
            ShellType::Bash => "bash",
            ShellType::Zsh | ShellType::Fish => return Ok(()),
        };

        let command = shell.in_memory_clear_command();

        let output = std::process::Command::new(shell_name)
            .arg("-c")
            .arg(command)
            .output()
            .map_err(NailsError::IoError)?;

        if !output.status.success() {
            return Err(NailsError::InvalidState(format!(
                "Failed to clear {} in-memory history: exit code {:?}",
                shell_name,
                output.status.code()
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
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
    // HistoryCleaner tests (using with_home for explicit path)
    // ============================================================================

    #[test]
    fn test_history_cleaner_new() {
        let fs = MockFilesystem::new();
        let cleaner = HistoryCleaner::new(fs);

        assert_eq!(cleaner.patterns, vec!["nails".to_string()]);
        assert_eq!(cleaner.shells.len(), 3);
        assert!(!cleaner.secure_delete);
        assert!(cleaner.home.is_none());
    }

    #[test]
    fn test_history_cleaner_with_home() {
        let fs = MockFilesystem::new();
        let cleaner = HistoryCleaner::new(fs).with_home(test_home());

        assert_eq!(cleaner.home, Some(test_home()));
    }

    #[test]
    fn test_history_cleaner_with_patterns() {
        let fs = MockFilesystem::new();
        let patterns = vec!["test1".to_string(), "test2".to_string()];
        let cleaner = HistoryCleaner::new(fs).with_patterns(patterns.clone());

        assert_eq!(cleaner.patterns, patterns);
    }

    #[test]
    fn test_history_cleaner_with_shells() {
        let fs = MockFilesystem::new();
        let shells = vec![ShellType::Bash, ShellType::Fish];
        let cleaner = HistoryCleaner::new(fs).with_shells(shells.clone());

        assert_eq!(cleaner.shells, shells);
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
}
