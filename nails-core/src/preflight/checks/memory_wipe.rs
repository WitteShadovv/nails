// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Freed-memory posture pre-flight report.
//!
//! When the hidden session ends, the pages it used go back to the kernel's free
//! lists with their contents intact: file data, keys and terminal scrollback stay
//! readable in RAM until something else overwrites them. The kernel zeroes pages
//! as they are freed when booted with `init_on_free=1`, or when it is built with
//! `CONFIG_INIT_ON_FREE_DEFAULT_ON` (what the kernel's own `mem auto-init: …
//! heap free:on` boot line reports); that shrinks the window to the pages still
//! in use.
//!
//! The check reads the kernel's own report, not just the command line: the
//! booted command line decides when it sets `init_on_free`, and otherwise the
//! booted kernel's config (`/boot/config-<release>`) decides through
//! `CONFIG_INIT_ON_FREE_DEFAULT_ON`. It warns when freed memory is not zeroed and
//! stays an informational pass only when neither source can be read. It also
//! notes a RAM-wipe-on-shutdown mechanism (the dracut `ram-wipe` module) when one
//! is installed. Every probe reads; nothing here writes.

use super::super::{CheckResult, PreFlightCheck};
use crate::{Filesystem, Result};
use std::path::PathBuf;

/// The booted kernel command line.
const PROC_CMDLINE: &str = "/proc/cmdline";

/// The booted kernel's release (`uname -r`), used to find its config.
const PROC_OSRELEASE: &str = "/proc/sys/kernel/osrelease";

/// Where the booted kernel's config file lives, as `config-<release>`.
const BOOT_DIR: &str = "/boot";

/// dracut's module directory; a RAM-wipe module installs itself here.
const DRACUT_MODULES_DIR: &str = "/usr/lib/dracut/modules.d";

/// The kernel parameter that zeroes pages as they are freed.
const INIT_ON_FREE: &str = "init_on_free";

/// The kernel config symbol that makes `init_on_free` the built-in default.
const INIT_ON_FREE_DEFAULT_ON: &str = "CONFIG_INIT_ON_FREE_DEFAULT_ON";

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

/// Whether the kernel config makes `init_on_free` the built-in default.
///
/// `CONFIG_INIT_ON_FREE_DEFAULT_ON=y` enables it, the commented
/// `# CONFIG_INIT_ON_FREE_DEFAULT_ON is not set` (or `=n`) disables it, and a
/// config that does not mention it at all leaves the answer unknown. This is the
/// readable face of the kernel's `mem auto-init: … heap free:on/off` report.
fn parse_init_on_free_config(config: &str) -> Option<bool> {
    for line in config.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix(INIT_ON_FREE_DEFAULT_ON)
            && let Some(value) = rest.strip_prefix('=')
        {
            return Some(value.trim() == "y");
        }
        if line.starts_with('#')
            && line.contains(INIT_ON_FREE_DEFAULT_ON)
            && line.contains("is not set")
        {
            return Some(false);
        }
    }
    None
}

/// Whether freed pages are zeroed, told from the command line and, when it does
/// not decide, the kernel config. `None` when neither source could be read.
fn freed_pages_zeroed(cmdline: Option<&str>, config_default: Option<bool>) -> Option<bool> {
    match cmdline.map(parse_init_on_free) {
        Some(InitOnFree::Enabled) => Some(true),
        Some(InitOnFree::Disabled) => Some(false),
        // The command line is silent (or unreadable): the kernel's built-in
        // default decides.
        _ => config_default,
    }
}

/// Pre-flight check reporting whether the decoy kernel zeroes freed memory,
/// warning when it does not.
pub struct MemoryWipeCheck {
    /// The booted kernel command line.
    cmdline_path: PathBuf,
    /// The booted kernel release, read to find its config.
    osrelease_path: PathBuf,
    /// The directory holding `config-<release>`.
    boot_dir: PathBuf,
    /// dracut's module directory, scanned for a RAM-wipe module.
    dracut_modules_dir: PathBuf,
}

impl MemoryWipeCheck {
    /// Create the check over the booted kernel's real paths.
    pub fn new() -> Self {
        Self {
            cmdline_path: PathBuf::from(PROC_CMDLINE),
            osrelease_path: PathBuf::from(PROC_OSRELEASE),
            boot_dir: PathBuf::from(BOOT_DIR),
            dracut_modules_dir: PathBuf::from(DRACUT_MODULES_DIR),
        }
    }

    /// The kernel's built-in `init_on_free` default, read from its config
    /// (`<boot>/config-<release>`), or `None` when it cannot be read.
    fn config_default<F: Filesystem>(&self, fs: &F) -> Option<bool> {
        let release = fs.read_file_content(&self.osrelease_path).ok()?;
        let release = release.trim();
        if release.is_empty() {
            return None;
        }
        let config = fs
            .read_file_content(&self.boot_dir.join(format!("config-{release}")))
            .ok()?;
        parse_init_on_free_config(&config)
    }

    /// Whether a RAM-wipe-on-shutdown mechanism (the dracut `ram-wipe` module,
    /// also packaged as `cold-boot-attack-defense`) is installed on the decoy.
    fn ram_wipe_present<F: Filesystem>(&self, fs: &F) -> bool {
        fs.list_directory(&self.dracut_modules_dir)
            .map(|entries| {
                entries.iter().any(|entry| {
                    entry
                        .file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| {
                            name.contains("ram-wipe") || name.contains("cold-boot-attack")
                        })
                })
            })
            .unwrap_or(false)
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
        "Reports whether the decoy kernel zeroes freed memory, warning when it does not"
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        let cmdline = fs.read_file_content(&self.cmdline_path).ok();
        let zeroed = freed_pages_zeroed(cmdline.as_deref(), self.config_default(fs));

        let ram_wipe_note = if self.ram_wipe_present(fs) {
            " A RAM-wipe mechanism (the dracut ram-wipe module) is installed: the decoy wipes \
             RAM during reboot and shutdown, though not on a forced power loss."
        } else {
            ""
        };

        match zeroed {
            Some(true) => Ok(CheckResult::Pass(format!(
                "The decoy kernel zeroes freed memory (init_on_free), so pages the hidden \
                 session frees do not linger in RAM.{ram_wipe_note}"
            ))),
            Some(false) => Ok(CheckResult::warn_with(
                format!(
                    "The decoy kernel does not zero freed memory: pages the hidden session frees \
                     keep their contents in RAM until something reuses them.{ram_wipe_note}"
                ),
                "Add init_on_free=1 to the decoy kernel command line, and power off after a \
                 session rather than leaving the machine running.",
            )),
            None => Ok(CheckResult::Pass(format!(
                "Could not read whether the decoy kernel zeroes freed memory (init_on_free on \
                 the command line, or CONFIG_INIT_ON_FREE_DEFAULT_ON in its config); whether \
                 freed pages are zeroed is unknown. Recommended: add init_on_free=1 to the \
                 decoy kernel command line.{ram_wipe_note}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RealFilesystem;
    use std::path::Path;

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

    #[test]
    fn config_default_is_read_from_the_kernel_config() {
        assert_eq!(
            parse_init_on_free_config("CONFIG_INIT_ON_FREE_DEFAULT_ON=y\n"),
            Some(true)
        );
        assert_eq!(
            parse_init_on_free_config("# CONFIG_INIT_ON_FREE_DEFAULT_ON is not set\n"),
            Some(false)
        );
        assert_eq!(
            parse_init_on_free_config("CONFIG_INIT_ON_FREE_DEFAULT_ON=n\n"),
            Some(false)
        );
        // A different, similarly named symbol does not decide it.
        assert_eq!(
            parse_init_on_free_config("CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y\n"),
            None
        );
        assert_eq!(parse_init_on_free_config("CONFIG_FOO=y\n"), None);
    }

    fn write(dir: &Path, rel: &str, content: &str) {
        let path = dir.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }

    /// Run the check over a tmpdir, writing the command line, the booted kernel's
    /// config (for release `test-kernel`) and a dracut RAM-wipe module as asked.
    fn run_with(cmdline: Option<&str>, config: Option<&str>, ram_wipe: bool) -> CheckResult {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        if let Some(cmdline) = cmdline {
            write(root, "cmdline", cmdline);
        }
        if let Some(config) = config {
            write(root, "osrelease", "test-kernel\n");
            write(root, "boot/config-test-kernel", config);
        }
        if ram_wipe {
            std::fs::create_dir_all(root.join("dracut-modules.d/40ram-wipe")).unwrap();
        }
        let check = MemoryWipeCheck {
            cmdline_path: root.join("cmdline"),
            osrelease_path: root.join("osrelease"),
            boot_dir: root.join("boot"),
            dracut_modules_dir: root.join("dracut-modules.d"),
        };
        check.run(&RealFilesystem).unwrap()
    }

    #[test]
    fn the_command_line_enabling_it_passes() {
        let result = run_with(Some("root=/dev/sda1 init_on_free=1\n"), None, false);
        assert!(result.is_pass(), "{}", result.message());
        assert!(
            result.message().contains("zeroes freed memory"),
            "{}",
            result.message()
        );
    }

    #[test]
    fn the_command_line_disabling_it_warns() {
        let result = run_with(Some("init_on_free=0\n"), None, false);
        assert!(result.is_warn(), "{}", result.message());
        assert!(
            result.message().contains("does not zero freed memory"),
            "{}",
            result.message()
        );
        assert!(
            result.message().contains("init_on_free=1"),
            "a fix is named"
        );
    }

    #[test]
    fn the_kernel_config_decides_when_the_command_line_is_silent() {
        let on = run_with(
            Some("quiet\n"),
            Some("CONFIG_INIT_ON_FREE_DEFAULT_ON=y\n"),
            false,
        );
        assert!(on.is_pass(), "{}", on.message());

        let off = run_with(
            Some("quiet\n"),
            Some("# CONFIG_INIT_ON_FREE_DEFAULT_ON is not set\n"),
            false,
        );
        assert!(off.is_warn(), "{}", off.message());
    }

    #[test]
    fn the_command_line_overrides_the_kernel_config() {
        // init_on_free=1 wins over a config default of off.
        let forced_on = run_with(
            Some("init_on_free=1\n"),
            Some("# CONFIG_INIT_ON_FREE_DEFAULT_ON is not set\n"),
            false,
        );
        assert!(forced_on.is_pass(), "{}", forced_on.message());
        // init_on_free=0 wins over a config default of on.
        let forced_off = run_with(
            Some("init_on_free=0\n"),
            Some("CONFIG_INIT_ON_FREE_DEFAULT_ON=y\n"),
            false,
        );
        assert!(forced_off.is_warn(), "{}", forced_off.message());
    }

    #[test]
    fn without_a_readable_source_it_stays_an_informational_pass() {
        // Command line silent and no kernel config: the answer is unknown, so the
        // check stays an informational pass rather than warning on a guess.
        let silent = run_with(Some("quiet\n"), None, false);
        assert!(silent.is_pass(), "{}", silent.message());
        assert!(silent.message().contains("unknown"), "{}", silent.message());

        // Nothing readable at all.
        let nothing = run_with(None, None, false);
        assert!(nothing.is_pass(), "{}", nothing.message());
    }

    #[test]
    fn a_ram_wipe_module_is_noted() {
        let result = run_with(Some("init_on_free=0\n"), None, true);
        assert!(result.is_warn(), "{}", result.message());
        assert!(
            result.message().contains("RAM-wipe mechanism"),
            "{}",
            result.message()
        );
    }
}
