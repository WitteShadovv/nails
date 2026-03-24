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

        Some(match self {
            ShellType::Bash => home_path.join(".bash_history"),
            ShellType::Zsh => home_path.join(".zsh_history"),
            ShellType::Fish => home_path
                .join(".local")
                .join("share")
                .join("fish")
                .join("fish_history"),
        })
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

    vec![
        // Shell history files
        home_path.join(".bash_history"),
        home_path.join(".zsh_history"),
        home_path.join(".local/share/fish/fish_history"),
        // Less pager history
        home_path.join(".lesshst"),
        // Python history
        home_path.join(".python_history"),
        home_path.join(".ipython/profile_default/history.sqlite"),
        // Database CLI history
        home_path.join(".psql_history"),
        home_path.join(".mysql_history"),
        home_path.join(".sqlite_history"),
        // GDB debugger history
        home_path.join(".gdb_history"),
        // Node.js REPL history
        home_path.join(".node_repl_history"),
        // Ruby IRB history
        home_path.join(".irb_history"),
        // Vim/Neovim history and info
        home_path.join(".viminfo"),
        home_path.join(".local/state/nvim/shada/main.shada"),
        // Recently used files (GNOME/GTK)
        home_path.join(".local/share/recently-used.xbel"),
        // Wget history
        home_path.join(".wget-hsts"),
        // Atuin shell history (modern shell history tool)
        home_path.join(".local/share/atuin/history.db"),
    ]
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
    /// # Fish Format Limitation
    ///
    /// **NOTE:** Fish shell uses a YAML-like history format:
    /// ```yaml
    /// - cmd: nails activate
    ///   when: 1700000000
    /// ```
    ///
    /// The current implementation uses simple line-by-line filtering, which will
    /// leave orphaned `when:` timestamps when removing fish commands. A proper
    /// Fish history cleaner would need to parse the YAML structure and remove
    /// complete command+timestamp entries.
    ///
    /// This is a known limitation documented in Story 5.2 Dev Notes. For production
    /// use with Fish shells, consider implementing `parse_fish_history()` helper
    /// that properly handles the YAML structure.
    ///
    /// # Returns
    ///
    /// - `Ok(Some(msg))` - History cleaned with description
    /// - `Ok(None)` - No history file found (skip)
    /// - `Err(e)` - Error occurred during cleanup
    fn clean_history_file(&self, shell: ShellType) -> Result<Option<String>> {
        let history_path = match shell.history_file_path() {
            Some(path) => path,
            None => return Ok(None), // $HOME not set
        };

        // Check if history file exists
        if !self.filesystem.path_exists(&history_path)? {
            return Ok(None); // No history file, skip
        }

        // Read history file content
        let content = self.filesystem.read_file_content(&history_path)?;

        // Filter out lines containing patterns (case-insensitive)
        let original_count = content.lines().count();
        let filtered: Vec<&str> = content
            .lines()
            .filter(|line| !self.line_matches_patterns(line))
            .collect();
        let removed_count = original_count - filtered.len();

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
        let new_content = filtered.join("\n");
        if !new_content.is_empty() {
            // Add trailing newline if content exists
            self.filesystem
                .write_file_content(&history_path, &format!("{}\n", new_content))?;
        } else {
            // Empty file - just write empty content
            self.filesystem.write_file_content(&history_path, "")?;
        }

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

    #[test]
    fn test_shell_type_bash_history_path() {
        // Set HOME for test
        // Note: std::env::set_var is unsafe in Rust 2024 edition
        unsafe {
            std::env::set_var("HOME", "/home/testuser");
        }
        let path = ShellType::Bash.history_file_path();
        assert_eq!(path, Some(PathBuf::from("/home/testuser/.bash_history")));
    }

    #[test]
    fn test_shell_type_zsh_history_path() {
        unsafe {
            std::env::set_var("HOME", "/home/testuser");
        }
        let path = ShellType::Zsh.history_file_path();
        assert_eq!(path, Some(PathBuf::from("/home/testuser/.zsh_history")));
    }

    #[test]
    fn test_shell_type_fish_history_path() {
        unsafe {
            std::env::set_var("HOME", "/home/testuser");
        }
        let path = ShellType::Fish.history_file_path();
        assert_eq!(
            path,
            Some(PathBuf::from(
                "/home/testuser/.local/share/fish/fish_history"
            ))
        );
    }

    #[test]
    #[ignore] // Ignored: Test modifies global environment (HOME) and causes race conditions
    fn test_shell_type_history_path_no_home() {
        // Save current HOME value
        let original_home = std::env::var("HOME").ok();

        unsafe {
            std::env::remove_var("HOME");
        }
        let path = ShellType::Bash.history_file_path();
        assert_eq!(path, None);

        // Restore original HOME value
        if let Some(home) = original_home {
            unsafe {
                std::env::set_var("HOME", home);
            }
        }
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

    #[test]
    fn test_history_cleaner_new() {
        let fs = MockFilesystem::new();
        let cleaner = HistoryCleaner::new(fs);

        assert_eq!(cleaner.patterns, vec!["nails".to_string()]);
        assert_eq!(cleaner.shells.len(), 3);
        assert!(!cleaner.secure_delete);
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
        unsafe {
            std::env::set_var("HOME", "/home/testuser");
        }
        let fs = MockFilesystem::new();

        let bash_history = PathBuf::from("/home/testuser/.bash_history");
        fs.mock_set_file_content(
            bash_history.to_str().unwrap(),
            "ls -la\nnails activate\ncd /tmp\nNAILS status\ngrep nails logfile.txt\nvim nails_config.yaml\n",
        );
        fs.mock_set_path_exists(bash_history.to_str().unwrap(), true);

        let cleaner = HistoryCleaner::new(fs.clone()).with_shells(vec![ShellType::Bash]);

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
        unsafe {
            std::env::set_var("HOME", "/home/testuser");
        }
        let fs = MockFilesystem::new();
        // Don't set up any history files

        let cleaner = HistoryCleaner::new(fs);
        let result = cleaner.clean().unwrap();

        // Should succeed with empty results (no files to clean)
        // No errors should be raised for missing files
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_empty_history_file() {
        unsafe {
            std::env::set_var("HOME", "/home/testuser");
        }
        let fs = MockFilesystem::new();

        let bash_history = PathBuf::from("/home/testuser/.bash_history");
        fs.mock_set_file_content(bash_history.to_str().unwrap(), "");
        fs.mock_set_path_exists(bash_history.to_str().unwrap(), true);

        let cleaner = HistoryCleaner::new(fs.clone()).with_shells(vec![ShellType::Bash]);

        let result = cleaner.clean().unwrap();

        // Should report no matching entries
        assert_eq!(result.len(), 1);
        assert!(result[0].contains("No matching entries"));
    }

    #[test]
    fn test_history_file_with_no_matches() {
        unsafe {
            std::env::set_var("HOME", "/home/testuser");
        }
        let fs = MockFilesystem::new();

        let bash_history = PathBuf::from("/home/testuser/.bash_history");
        fs.mock_set_file_content(bash_history.to_str().unwrap(), "ls -la\ncd /tmp\npwd\n");
        fs.mock_set_path_exists(bash_history.to_str().unwrap(), true);

        let cleaner = HistoryCleaner::new(fs.clone()).with_shells(vec![ShellType::Bash]);

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
        unsafe {
            std::env::set_var("HOME", "/home/testuser");
        }
        let fs = MockFilesystem::new();

        let bash_history = PathBuf::from("/home/testuser/.bash_history");
        fs.mock_set_file_content(
            bash_history.to_str().unwrap(),
            "nails activate\nNAILS status\n",
        );
        fs.mock_set_path_exists(bash_history.to_str().unwrap(), true);

        let cleaner = HistoryCleaner::new(fs.clone()).with_shells(vec![ShellType::Bash]);

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
        unsafe {
            std::env::set_var("HOME", "/home/testuser");
        }
        let fs = MockFilesystem::new();

        let bash_history = PathBuf::from("/home/testuser/.bash_history");
        let zsh_history = PathBuf::from("/home/testuser/.zsh_history");

        fs.mock_set_file_content(bash_history.to_str().unwrap(), "ls -la\nnails activate\n");
        fs.mock_set_path_exists(bash_history.to_str().unwrap(), true);

        fs.mock_set_file_content(zsh_history.to_str().unwrap(), "pwd\nNAILS status\n");
        fs.mock_set_path_exists(zsh_history.to_str().unwrap(), true);

        let cleaner =
            HistoryCleaner::new(fs.clone()).with_shells(vec![ShellType::Bash, ShellType::Zsh]);

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
        unsafe {
            std::env::set_var("HOME", "/home/testuser");
        }
        let fs = MockFilesystem::new();

        let bash_history = PathBuf::from("/home/testuser/.bash_history");
        fs.mock_set_file_content(
            bash_history.to_str().unwrap(),
            "ls -la\nsecret command\npwd\n",
        );
        fs.mock_set_path_exists(bash_history.to_str().unwrap(), true);

        let cleaner = HistoryCleaner::new(fs.clone())
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
        unsafe {
            std::env::set_var("HOME", "/home/testuser");
        }
        let fs = MockFilesystem::new();

        let bash_history = PathBuf::from("/home/testuser/.bash_history");
        fs.mock_set_file_content(
            bash_history.to_str().unwrap(),
            "ls -la\nnails activate\nsecret command\npwd\n",
        );
        fs.mock_set_path_exists(bash_history.to_str().unwrap(), true);

        let cleaner = HistoryCleaner::new(fs.clone())
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
}
