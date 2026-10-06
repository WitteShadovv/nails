// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Freed-memory wiping pre-flight report.
//!
//! When the hidden session ends, the pages it used go back to the kernel's free
//! lists with their contents intact: file data, keys and terminal scrollback stay
//! readable in RAM until something else overwrites them. The kernel zeroes pages
//! as they are freed when booted with `init_on_free=1`, which shrinks that window
//! to the pages still in use. The operator guide recommends it for the decoy
//! kernel.
//!
//! The check is informational: it reads the booted command line and reports
//! whether the parameter is set. It always passes, because a kernel built with
//! `CONFIG_INIT_ON_FREE_DEFAULT_ON` wipes freed pages without the parameter and
//! the command line alone cannot tell.

use super::super::{CheckResult, PreFlightCheck};
use crate::{Filesystem, Result};
use std::path::PathBuf;

/// The booted kernel command line.
const PROC_CMDLINE: &str = "/proc/cmdline";

/// The kernel parameter that zeroes pages as they are freed.
const INIT_ON_FREE: &str = "init_on_free";

/// What the booted command line says about `init_on_free`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitOnFree {
    /// The last `init_on_free=` on the command line enables it.
    Enabled,
    /// The last `init_on_free=` on the command line disables it.
    Disabled,
    /// The command line does not mention the parameter.
    Unset,
}

/// Classify `init_on_free` from the contents of `/proc/cmdline`.
///
/// The kernel parses every occurrence and the last valid one wins. Arguments
/// after a bare `--` are passed to init, not to the kernel, so they are ignored.
/// Values follow the kernel's `kstrtobool`: a leading `y`/`t`/`1` or `on`
/// enables, a leading `n`/`f`/`0` or `off` disables, and anything else
/// (including a bare `init_on_free` with no value) is rejected and leaves the
/// previous setting in place.
pub fn parse_init_on_free(cmdline: &str) -> InitOnFree {
    let mut state = InitOnFree::Unset;
    for token in cmdline.split_whitespace() {
        if token == "--" {
            break;
        }
        let Some((key, value)) = token.split_once('=') else {
            continue;
        };
        // The kernel treats `-` and `_` in parameter names as equivalent.
        if key.replace('-', "_") != INIT_ON_FREE {
            continue;
        }
        if let Some(enabled) = kstrtobool(value.trim_matches('"')) {
            state = if enabled {
                InitOnFree::Enabled
            } else {
                InitOnFree::Disabled
            };
        }
    }
    state
}

/// The kernel's `kstrtobool`: `None` for a value it rejects.
fn kstrtobool(value: &str) -> Option<bool> {
    let mut chars = value.chars().map(|c| c.to_ascii_lowercase());
    match chars.next()? {
        'y' | 't' | '1' => Some(true),
        'n' | 'f' | '0' => Some(false),
        'o' => match chars.next()? {
            'n' => Some(true),
            'f' => Some(false),
            _ => None,
        },
        _ => None,
    }
}

/// Informational pre-flight check reporting whether the decoy kernel wipes freed
/// memory (`init_on_free=1`).
pub struct MemoryWipeCheck {
    cmdline_path: PathBuf,
}

impl MemoryWipeCheck {
    /// Create the check over the booted `/proc/cmdline`.
    pub fn new() -> Self {
        Self {
            cmdline_path: PathBuf::from(PROC_CMDLINE),
        }
    }

    /// Read the command line from `path` instead of `/proc/cmdline`.
    pub fn with_cmdline_path(path: impl Into<PathBuf>) -> Self {
        Self {
            cmdline_path: path.into(),
        }
    }
}

impl Default for MemoryWipeCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: Filesystem> PreFlightCheck<F> for MemoryWipeCheck {
    fn name(&self) -> &'static str {
        "memory-wipe"
    }

    fn description(&self) -> &'static str {
        "Reports whether the decoy kernel zeroes freed memory (init_on_free=1)"
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        let Ok(cmdline) = fs.read_file_content(&self.cmdline_path) else {
            return Ok(CheckResult::Pass(format!(
                "Could not read {}; init_on_free not checked",
                self.cmdline_path.display()
            )));
        };
        let message = match parse_init_on_free(&cmdline) {
            InitOnFree::Enabled => {
                "Kernel command line sets init_on_free=1: freed pages are zeroed".to_string()
            }
            InitOnFree::Disabled => "Kernel command line disables init_on_free: pages freed by \
                 the hidden session keep their contents in RAM until reused. Recommended: \
                 init_on_free=1 on the decoy kernel command line"
                .to_string(),
            InitOnFree::Unset => "Kernel command line does not set init_on_free=1: unless the \
                 kernel enables it by default, pages freed by the hidden session keep their \
                 contents in RAM until reused. Recommended: add init_on_free=1 to the decoy \
                 kernel command line"
                .to_string(),
        };
        Ok(CheckResult::Pass(message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RealFilesystem;

    #[test]
    fn classifies_the_parameter() {
        assert_eq!(parse_init_on_free("quiet"), InitOnFree::Unset);
        assert_eq!(parse_init_on_free(""), InitOnFree::Unset);
        assert_eq!(
            parse_init_on_free("BOOT_IMAGE=/vmlinuz init_on_free=1 quiet\n"),
            InitOnFree::Enabled
        );
        assert_eq!(parse_init_on_free("init_on_free=on"), InitOnFree::Enabled);
        assert_eq!(parse_init_on_free("init-on-free=Y"), InitOnFree::Enabled);
        assert_eq!(parse_init_on_free("init_on_free"), InitOnFree::Unset);
        assert_eq!(parse_init_on_free("init_on_free=maybe"), InitOnFree::Unset);
        assert_eq!(
            parse_init_on_free("init_on_free=1 init_on_free=bogus"),
            InitOnFree::Enabled
        );
        assert_eq!(parse_init_on_free("init_on_free=0"), InitOnFree::Disabled);
        assert_eq!(parse_init_on_free("init_on_free=off"), InitOnFree::Disabled);
    }

    #[test]
    fn the_last_occurrence_wins() {
        assert_eq!(
            parse_init_on_free("init_on_free=1 init_on_free=0"),
            InitOnFree::Disabled
        );
        assert_eq!(
            parse_init_on_free("init_on_free=0 init_on_free=1"),
            InitOnFree::Enabled
        );
    }

    #[test]
    fn init_arguments_after_double_dash_are_ignored() {
        assert_eq!(
            parse_init_on_free("quiet -- init_on_free=1"),
            InitOnFree::Unset
        );
    }

    #[test]
    fn a_similar_parameter_does_not_count() {
        assert_eq!(parse_init_on_free("init_on_alloc=1"), InitOnFree::Unset);
        assert_eq!(parse_init_on_free("xinit_on_free=1"), InitOnFree::Unset);
    }

    fn run_on(contents: Option<&str>) -> CheckResult {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cmdline");
        if let Some(contents) = contents {
            std::fs::write(&path, contents).unwrap();
        }
        MemoryWipeCheck::with_cmdline_path(&path)
            .run(&RealFilesystem)
            .unwrap()
    }

    #[test]
    fn reports_an_enabled_parameter() {
        let result = run_on(Some("root=/dev/sda1 init_on_free=1\n"));
        assert!(result.is_pass());
        assert!(result.message().contains("zeroed"), "{}", result.message());
    }

    #[test]
    fn recommends_the_parameter_when_absent_without_blocking() {
        let result = run_on(Some("root=/dev/sda1 quiet\n"));
        assert!(result.is_pass());
        assert!(
            result.message().contains("Recommended: add init_on_free=1"),
            "{}",
            result.message()
        );
    }

    #[test]
    fn reports_an_explicitly_disabled_parameter() {
        let result = run_on(Some("init_on_free=0\n"));
        assert!(result.is_pass());
        assert!(
            result.message().contains("disables"),
            "{}",
            result.message()
        );
    }

    #[test]
    fn an_unreadable_cmdline_degrades_to_a_pass() {
        let result = run_on(None);
        assert!(result.is_pass());
        assert!(result.message().contains("not checked"));
    }
}
