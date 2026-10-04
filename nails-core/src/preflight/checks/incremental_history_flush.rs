// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Incremental shell-history flush pre-flight check.
//!
//! Warns, never fails: it inspects the invoking operator's shell startup files
//! for settings that flush command history to disk after every command, rather
//! than only on shell exit. Those settings matter because NAILS defends shell
//! history by SIGKILLing the operator's shells before overlay teardown so their
//! in-memory history is never flushed — but a shell configured to append after
//! each command has already written the `cryptsetup`/mount/`nails activate` lines
//! to disk long before teardown, so the kill cannot help.
//!
//! The check reads the resolved operator's startup files directly; it performs no
//! writes and makes no change. When the operator cannot be resolved it reports a
//! skipped Pass rather than erroring.

use std::path::PathBuf;

use super::super::{CheckResult, PreFlightCheck};
use crate::{Filesystem, Result};

/// The zsh options that flush history incrementally (case-insensitive match on
/// `setopt` / `set -o`-style lines).
const ZSH_INCREMENTAL_OPTIONS: &[&str] = &[
    "inc_append_history",
    "incappendhistory",
    "share_history",
    "sharehistory",
];

/// Startup files to inspect, relative to the operator's home.
const STARTUP_FILES: &[&str] = &[
    ".zshrc",
    ".zshenv",
    ".zprofile",
    ".bashrc",
    ".bash_profile",
    ".profile",
];

/// Reports when the operator's shell flushes history incrementally.
#[derive(Debug, Clone, Default)]
pub struct IncrementalHistoryFlushCheck {
    /// The operator's home directory. `None` when the target user could not be
    /// resolved, in which case the check reports a skipped Pass.
    home: Option<PathBuf>,
}

impl IncrementalHistoryFlushCheck {
    /// Create a check for a resolved operator home.
    pub fn new(home: PathBuf) -> Self {
        Self { home: Some(home) }
    }

    /// Create a check that reports Pass without inspecting anything, used when the
    /// target user could not be resolved.
    pub fn disabled() -> Self {
        Self { home: None }
    }
}

/// Whether a startup file's text enables incremental history flushing.
///
/// Returns the list of human-readable reasons found (empty when none). Split out
/// from the filesystem so it is unit-testable on raw text.
fn incremental_flush_reasons(file_name: &str, content: &str) -> Vec<String> {
    let mut reasons = Vec::new();

    // Strip trailing comments so a commented-out line does not trigger the warning.
    let effective: String = content
        .lines()
        .map(|line| match line.split_once('#') {
            Some((code, _comment)) => code,
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n");
    let lower = effective.to_lowercase();

    // zsh: `setopt inc_append_history` / `share_history` (with or without the
    // underscore, in any case).
    for option in ZSH_INCREMENTAL_OPTIONS {
        if lower.contains(option) {
            reasons.push(format!("{} sets zsh `{}`", file_name, option));
        }
    }

    // bash: `history -a` inside PROMPT_COMMAND appends after every prompt.
    if lower.contains("prompt_command") && lower.contains("history -a") {
        reasons.push(format!(
            "{} runs `history -a` from PROMPT_COMMAND",
            file_name
        ));
    }

    reasons
}

impl<F: Filesystem> PreFlightCheck<F> for IncrementalHistoryFlushCheck {
    fn name(&self) -> &'static str {
        "incremental-history-flush"
    }

    fn description(&self) -> &'static str {
        "Reports shell settings that flush history to disk after every command"
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        let Some(home) = self.home.as_ref() else {
            return Ok(CheckResult::Pass(
                "Target user could not be resolved; shell history-flush settings were not inspected"
                    .into(),
            ));
        };

        let mut reasons = Vec::new();
        for file_name in STARTUP_FILES {
            let path = home.join(file_name);
            // A missing or unreadable startup file is simply not inspected.
            if !fs.path_exists(&path).unwrap_or(false) {
                continue;
            }
            let Ok(content) = fs.read_file_content(&path) else {
                continue;
            };
            reasons.extend(incremental_flush_reasons(file_name, &content));
        }

        if reasons.is_empty() {
            return Ok(CheckResult::Pass(
                "The operator's shell does not flush command history incrementally".into(),
            ));
        }

        Ok(CheckResult::Warn(format!(
            "The operator's shell flushes history to disk after every command, so \
             hidden-session commands reach the history file before the pre-teardown \
             shell kill can prevent it: {}. Disable incremental flushing (unset zsh \
             `INC_APPEND_HISTORY`/`SHARE_HISTORY`, drop `history -a` from \
             PROMPT_COMMAND) for the session you run nails from.",
            reasons.join("; ")
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::MockFilesystem;
    use std::path::PathBuf;

    fn home() -> PathBuf {
        PathBuf::from("/home/alice")
    }

    fn seed(fs: &MockFilesystem, file_name: &str, content: &str) {
        let path = home().join(file_name);
        fs.mock_set_file_content(path.to_str().unwrap(), content);
    }

    fn run_check(fs: &MockFilesystem) -> CheckResult {
        let check = IncrementalHistoryFlushCheck::new(home());
        PreFlightCheck::run(&check, fs).unwrap()
    }

    #[test]
    fn warns_on_zsh_inc_append_history() {
        let fs = MockFilesystem::new();
        seed(
            &fs,
            ".zshrc",
            "setopt INC_APPEND_HISTORY\nexport PATH=$PATH\n",
        );
        assert!(matches!(run_check(&fs), CheckResult::Warn(_)));
    }

    #[test]
    fn warns_on_zsh_share_history_lowercase() {
        let fs = MockFilesystem::new();
        seed(&fs, ".zshrc", "setopt share_history\n");
        assert!(matches!(run_check(&fs), CheckResult::Warn(_)));
    }

    #[test]
    fn warns_on_bash_history_append_in_prompt_command() {
        let fs = MockFilesystem::new();
        seed(
            &fs,
            ".bashrc",
            "export PROMPT_COMMAND='history -a; history -n'\n",
        );
        assert!(matches!(run_check(&fs), CheckResult::Warn(_)));
    }

    #[test]
    fn passes_on_clean_config() {
        let fs = MockFilesystem::new();
        seed(&fs, ".bashrc", "export PATH=$PATH\nalias ll='ls -la'\n");
        seed(&fs, ".zshrc", "setopt APPEND_HISTORY\n");
        assert!(matches!(run_check(&fs), CheckResult::Pass(_)));
    }

    #[test]
    fn ignores_commented_out_settings() {
        let fs = MockFilesystem::new();
        seed(&fs, ".zshrc", "# setopt INC_APPEND_HISTORY\n");
        assert!(matches!(run_check(&fs), CheckResult::Pass(_)));
    }

    #[test]
    fn bash_history_append_without_prompt_command_does_not_warn() {
        // `history -a` in a function the operator runs by hand, with no
        // PROMPT_COMMAND hook, does not flush after every command.
        let fs = MockFilesystem::new();
        seed(&fs, ".bashrc", "alias save='history -a'\n");
        assert!(matches!(run_check(&fs), CheckResult::Pass(_)));
    }

    #[test]
    fn disabled_check_passes_without_inspecting() {
        let fs = MockFilesystem::new();
        seed(&fs, ".zshrc", "setopt INC_APPEND_HISTORY\n");
        let check = IncrementalHistoryFlushCheck::disabled();
        assert!(matches!(
            PreFlightCheck::run(&check, &fs).unwrap(),
            CheckResult::Pass(_)
        ));
    }

    #[test]
    fn missing_startup_files_pass() {
        let fs = MockFilesystem::new();
        assert!(matches!(run_check(&fs), CheckResult::Pass(_)));
    }
}
