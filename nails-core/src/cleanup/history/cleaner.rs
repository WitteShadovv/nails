// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! HistoryCleaner implementation for shell history cleanup

use crate::{Filesystem, Result, output};
use std::path::{Path, PathBuf};

use super::{ShellType, filter_fish_history, history_cleanup_homes};

/// Cleans shell history files by removing lines matching patterns
///
/// HistoryCleaner removes all command history entries containing
/// specified patterns (default: "nails") from bash, zsh, and fish
/// history files on disk.
///
/// In-memory history living in a running shell is not addressed here: a
/// subprocess cannot reach a parent shell's RAM. That defense is handled
/// separately by killing the user's shells (SIGKILL before overlay teardown,
/// see `process::shell_cleanup::kill_user_shells`), which stops those shells
/// from flushing their in-memory history back to disk on exit.
///
/// # Security
///
/// - Case-insensitive matching ensures all variations are caught
/// - Atomic file writes prevent data corruption
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
    /// Overwrite the filtered content in place on the same inode instead of the
    /// default atomic temp-file-then-rename.
    ///
    /// This is the opt-in decoy history edit: temp+rename allocates a new inode,
    /// leaving the removed lines recoverable in the old inode's freed blocks under
    /// a sibling name, which defeats the point of filtering history on a decoy. An
    /// in-place overwrite keeps the existing inode, owner and mode and rewrites
    /// only its bytes. It is off by default, so ordinary overlay-layer cleanup
    /// keeps its crash-atomic write.
    pub(crate) in_place: bool,
    /// Optional explicit single home directory path (for testing without env vars)
    home: Option<PathBuf>,
    /// Optional explicit list of home directories to clean. Takes precedence over
    /// `home` when set; when both are unset, cleanup falls back to
    /// [`history_cleanup_homes`] (the operator's home plus `/root`).
    homes: Option<Vec<PathBuf>>,
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
            in_place: false,
            home: None,
            homes: None,
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

    /// Enable or disable in-place overwrite on the same inode.
    ///
    /// When enabled, filtered history is written back with
    /// [`Filesystem::overwrite_file_in_place`](crate::Filesystem::overwrite_file_in_place)
    /// (truncate + rewrite the existing inode) instead of the default atomic
    /// temp-file-then-rename, so the removed lines are not left behind in a freed
    /// inode. This is the opt-in decoy history edit; see the field docs.
    pub fn with_in_place(mut self, enabled: bool) -> Self {
        self.in_place = enabled;
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

    /// Set an explicit list of home directories to clean.
    ///
    /// This takes precedence over [`Self::with_home`] and over the default
    /// [`history_cleanup_homes`] resolution. Callers use it to clean the
    /// operator's home and `/root` in one pass.
    pub fn with_homes(mut self, homes: Vec<PathBuf>) -> Self {
        self.homes = Some(homes);
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

    /// The home directories this cleaner will operate on.
    ///
    /// Precedence: an explicit [`Self::with_homes`] list, then a single
    /// [`Self::with_home`], then the default [`history_cleanup_homes`] (the
    /// operator's home plus `/root`). Duplicates are removed so a file is never
    /// cleaned twice when, for example, the operator's home is `/root`.
    fn resolved_homes(&self) -> Vec<PathBuf> {
        let mut homes = match (&self.homes, &self.home) {
            (Some(homes), _) => homes.clone(),
            (None, Some(home)) => vec![home.clone()],
            (None, None) => history_cleanup_homes(),
        };
        homes.dedup();
        let mut seen = std::collections::HashSet::new();
        homes.retain(|home| seen.insert(home.clone()));
        homes
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

        for home in self.resolved_homes() {
            for shell in &self.shells {
                // Clean history file
                match self.clean_history_file(*shell, &home) {
                    Ok(Some(msg)) => cleaned.push(msg),
                    Ok(None) => {} // No history file found, skip
                    Err(e) => {
                        // Log warning but continue (best-effort)
                        output::warn(&format!("Failed to clean {:?} history: {}", shell, e));
                    }
                }

                // In-memory history in running shells is not cleared from here: a
                // subprocess cannot touch a parent shell's RAM. The real mitigation
                // is killing the user's shells before overlay teardown (SIGKILL, see
                // process::shell_cleanup::kill_user_shells), so they never flush
                // their in-memory history back to disk on exit.
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
    fn clean_history_file(&self, shell: ShellType, home: &Path) -> Result<Option<String>> {
        let history_path = shell.history_file_path_for_home(home);

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

        // If secure_delete is enabled, securely delete the original file first.
        // Skip it under in-place mode: secure_delete unlinks the inode, which
        // would defeat the same-inode overwrite that in-place mode exists to do.
        if self.secure_delete
            && !self.in_place
            && let Err(e) = self.filesystem.secure_delete(&history_path)
        {
            output::warn(&format!(
                "Secure delete of {} failed, falling back to normal overwrite: {}",
                history_path.display(),
                e
            ));
        }

        // Write filtered content back. The opt-in decoy edit overwrites in place on
        // the same inode (no new inode, so the removed lines are not stranded in
        // freed blocks); the default keeps the crash-atomic temp+rename write.
        if self.in_place {
            self.filesystem
                .overwrite_file_in_place(&history_path, &new_content)?;
        } else {
            self.filesystem
                .write_file_content(&history_path, &new_content)?;
        }

        let secure_note = if self.secure_delete {
            " (secure delete)"
        } else if self.in_place {
            " (in place)"
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
}
