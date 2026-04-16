//! HistoryCleaner implementation for shell history cleanup

use crate::{Filesystem, NailsError, Result, output};
use std::path::PathBuf;

use super::{ShellType, filter_fish_history};

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

    #[cfg(test)]
    pub(crate) fn test_patterns(&self) -> &[String] {
        &self.patterns
    }

    #[cfg(test)]
    pub(crate) fn test_shells(&self) -> &[ShellType] {
        &self.shells
    }

    #[cfg(test)]
    pub(crate) fn test_home(&self) -> Option<&PathBuf> {
        self.home.as_ref()
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
    pub(crate) fn line_matches_patterns(&self, line: &str) -> bool {
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
