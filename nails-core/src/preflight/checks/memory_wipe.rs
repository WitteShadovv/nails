// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Freed-memory posture pre-flight report.
//!
//! When the hidden session ends, the memory it used goes back to the kernel's
//! free lists with its contents intact: file data, keys and terminal scrollback
//! stay readable in RAM until something else overwrites them. The kernel zeroes
//! memory as it is freed, whole pages and its small slab objects alike, when it
//! is booted with `init_on_free=1` or built with `CONFIG_INIT_ON_FREE_DEFAULT_ON`
//! (what its own `mem auto-init: … heap free:on` boot line reports); that
//! shrinks the window to the memory still in use.
//!
//! The check reaches the kernel's verdict the way the kernel does. Page
//! poisoning comes first: `page_poison=1` on a kernel built with
//! `CONFIG_PAGE_POISONING` takes precedence over `init_on_free` and turns it off
//! (`mem auto-init: CONFIG_PAGE_POISONING is on, will take precedence over
//! init_on_alloc and init_on_free`); the kernel then writes a pattern over each
//! freed page but leaves freed slab objects as they were. Otherwise the booted
//! command line decides when it sets `init_on_free`, and the booted kernel's
//! config (`CONFIG_INIT_ON_FREE_DEFAULT_ON`) when it does not. Every value goes
//! through the booted release's `kstrtobool` ([`super::kernel_cmdline`]).
//!
//! The config comes from `/proc/config.gz`, the running kernel's own copy (the
//! NixOS and Arch kernels have it), or else from the copy a package installs,
//! `/boot/config-<release>` (Debian, Ubuntu, Fedora) or
//! `/usr/lib/modules/<release>/config` (Fedora). The check warns when freed
//! memory is not zeroed and stays an informational pass only when it cannot
//! tell. It also notes a RAM-wipe-on-shutdown mechanism (the dracut `ram-wipe`
//! module) when one is installed. Every probe reads; nothing here writes.

use super::super::{CheckResult, PreFlightCheck};
use super::kernel_cmdline::{self, BoolSpellings};
use crate::{Filesystem, Result};
use std::path::PathBuf;

// The gzip reader of `/proc/config.gz`. Public for the fuzz target that drives
// it only; not part of any interface.
#[doc(hidden)]
pub mod gzip;
mod kernel_config;

use kernel_config::{ConfigSources, KernelConfig};

/// The booted kernel command line.
const PROC_CMDLINE: &str = "/proc/cmdline";

/// The booted kernel's release (`uname -r`), used to find its config and to
/// tell which boolean spellings it accepts.
const PROC_OSRELEASE: &str = "/proc/sys/kernel/osrelease";

/// The running kernel's own config, gzip-compressed (`CONFIG_IKCONFIG_PROC`).
const PROC_CONFIG_GZ: &str = "/proc/config.gz";

/// Where a kernel package installs its config as `config-<release>`.
const BOOT_DIR: &str = "/boot";

/// Where a kernel package can also install it, as `<release>/config`.
const MODULES_DIR: &str = "/usr/lib/modules";

/// dracut's module directory; a RAM-wipe module installs itself here.
const DRACUT_MODULES_DIR: &str = "/usr/lib/dracut/modules.d";

/// The kernel parameter that zeroes memory as it is freed.
const INIT_ON_FREE: &str = "init_on_free";

/// The kernel parameter that turns page poisoning on.
const PAGE_POISON: &str = "page_poison";

/// What the booted command line says about `init_on_free`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitOnFree {
    /// The last `init_on_free=` the kernel accepts enables it.
    Enabled,
    /// The last `init_on_free=` the kernel accepts disables it.
    Disabled,
    /// The command line sets no value the kernel accepts.
    Unset,
}

/// Classify `init_on_free` from the contents of `/proc/cmdline`, as a kernel
/// that accepts `spellings` reads it.
///
/// The kernel parses every occurrence, and the last one it accepts wins.
/// Arguments after a bare `--` go to init, not to the kernel, so they are
/// ignored. A value `kstrtobool` rejects (a bare `init_on_free` among them)
/// leaves the previous setting in place.
pub fn parse_init_on_free(cmdline: &str, spellings: BoolSpellings) -> InitOnFree {
    match kernel_cmdline::last_bool(cmdline, INIT_ON_FREE, spellings) {
        Some(true) => InitOnFree::Enabled,
        Some(false) => InitOnFree::Disabled,
        None => InitOnFree::Unset,
    }
}

/// What becomes of memory the hidden session frees.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FreedMemory {
    /// `init_on_free` is in effect: freed pages and slab objects are zeroed.
    Zeroed,
    /// Page poisoning turned `init_on_free` off: freed pages are overwritten
    /// with a poison pattern, freed slab objects keep their contents.
    Poisoned,
    /// Nothing wipes freed memory.
    Kept,
    /// Neither the command line nor a readable kernel config decides.
    Unknown,
}

/// What becomes of freed memory, from the booted command line (`None` when it
/// could not be read), the spellings its kernel accepts and its config (`None`
/// when none could be read).
///
/// A config that cannot be read is taken to have page poisoning built in: of
/// the two readings, that one never reports freed memory zeroed when the
/// kernel leaves slab objects as they were.
fn freed_memory(
    cmdline: Option<&str>,
    spellings: BoolSpellings,
    config: Option<&KernelConfig>,
) -> FreedMemory {
    let poisoning_built = config.and_then(|config| config.page_poisoning) != Some(false);
    if let Some(cmdline) = cmdline
        && poisoning_built
        && kernel_cmdline::last_bool(cmdline, PAGE_POISON, spellings) == Some(true)
    {
        return FreedMemory::Poisoned;
    }
    let enabled = match cmdline.map(|cmdline| parse_init_on_free(cmdline, spellings)) {
        Some(InitOnFree::Enabled) => Some(true),
        Some(InitOnFree::Disabled) => Some(false),
        // The command line is silent (or unreadable): the kernel's built-in
        // default decides.
        _ => config.and_then(|config| config.init_on_free_default),
    };
    match enabled {
        Some(true) => FreedMemory::Zeroed,
        Some(false) => FreedMemory::Kept,
        None => FreedMemory::Unknown,
    }
}

/// Pre-flight check reporting whether the decoy kernel zeroes freed memory,
/// warning when it does not.
pub struct MemoryWipeCheck {
    /// The booted kernel command line.
    cmdline_path: PathBuf,
    /// The booted kernel release, read to find its config.
    osrelease_path: PathBuf,
    /// Where the booted kernel's config is read from.
    config: ConfigSources,
    /// dracut's module directory, scanned for a RAM-wipe module.
    dracut_modules_dir: PathBuf,
}

impl MemoryWipeCheck {
    /// Create the check over the booted kernel's real paths.
    pub fn new() -> Self {
        Self {
            cmdline_path: PathBuf::from(PROC_CMDLINE),
            osrelease_path: PathBuf::from(PROC_OSRELEASE),
            config: ConfigSources {
                proc_config: PathBuf::from(PROC_CONFIG_GZ),
                boot_dir: PathBuf::from(BOOT_DIR),
                modules_dir: PathBuf::from(MODULES_DIR),
            },
            dracut_modules_dir: PathBuf::from(DRACUT_MODULES_DIR),
        }
    }

    /// The booted kernel's release, or `None` when it cannot be read.
    fn release<F: Filesystem>(&self, fs: &F) -> Option<String> {
        let release = fs.read_file_content(&self.osrelease_path).ok()?;
        let release = release.trim();
        (!release.is_empty()).then(|| release.to_string())
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
        let release = self.release(fs);
        let spellings = BoolSpellings::of_release(release.as_deref());
        let config = self.config.read(fs, release.as_deref());
        let freed = freed_memory(cmdline.as_deref(), spellings, config.as_ref());

        let ram_wipe_note = if self.ram_wipe_present(fs) {
            " A RAM-wipe mechanism (the dracut ram-wipe module) is installed: the decoy wipes \
             RAM during reboot and shutdown, though not on a forced power loss."
        } else {
            ""
        };

        match freed {
            FreedMemory::Zeroed => Ok(CheckResult::Pass(format!(
                "The decoy kernel zeroes freed memory (init_on_free), so pages the hidden \
                 session frees do not linger in RAM.{ram_wipe_note}"
            ))),
            FreedMemory::Poisoned => Ok(CheckResult::warn_with(
                format!(
                    "The decoy kernel does not zero all freed memory: page poisoning \
                     (page_poison=1 on its command line) takes precedence over init_on_free \
                     and turns it off. The kernel writes a poison pattern over each page as it \
                     is freed, but freed slab objects, its small allocations such as the names \
                     of files the hidden session opened, keep their contents in RAM until \
                     something reuses them.{ram_wipe_note}"
                ),
                "Remove page_poison from the decoy kernel command line and boot it with \
                 init_on_free=1, and power off after a session rather than leaving the \
                 machine running.",
            )),
            FreedMemory::Kept => Ok(CheckResult::warn_with(
                format!(
                    "The decoy kernel does not zero freed memory: pages the hidden session frees \
                     keep their contents in RAM until something reuses them.{ram_wipe_note}"
                ),
                "Add init_on_free=1 to the decoy kernel command line, and power off after a \
                 session rather than leaving the machine running.",
            )),
            FreedMemory::Unknown => Ok(CheckResult::Pass(format!(
                "Could not read whether the decoy kernel zeroes freed memory (init_on_free on \
                 the command line, or CONFIG_INIT_ON_FREE_DEFAULT_ON in its config); whether \
                 freed pages are zeroed is unknown. Recommended: add init_on_free=1 to the \
                 decoy kernel command line.{ram_wipe_note}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests;
