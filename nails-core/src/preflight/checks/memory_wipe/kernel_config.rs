// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The booted kernel's build configuration, read for the defaults its command
//! line does not set.
//!
//! The kernel keeps its own copy, gzip-compressed, at `/proc/config.gz` when it
//! is built with `CONFIG_IKCONFIG_PROC`, as the NixOS and Arch kernels are;
//! neither installs a copy on disk. Debian, Ubuntu and Fedora install it as
//! `/boot/config-<release>`, and Fedora also as
//! `/usr/lib/modules/<release>/config`. The first one that can be read counts.
//! `/proc/config.gz` comes first: it is the running kernel's own, and reading
//! it leaves no access time on the decoy disk.

use super::gzip;
use crate::Filesystem;
use std::path::{Path, PathBuf};

/// The kernel config symbol that makes `init_on_free` the built-in default.
const INIT_ON_FREE_DEFAULT_ON: &str = "CONFIG_INIT_ON_FREE_DEFAULT_ON";

/// The kernel config symbol that builds page poisoning in. Without it the
/// kernel does not know `page_poison=` and leaves it to init.
const PAGE_POISONING: &str = "CONFIG_PAGE_POISONING";

/// What the booted kernel's config says about wiping freed memory. A field is
/// `None` when the config does not mention its symbol.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct KernelConfig {
    /// `CONFIG_INIT_ON_FREE_DEFAULT_ON`: `init_on_free` is on unless the
    /// command line turns it off.
    pub(super) init_on_free_default: Option<bool>,
    /// `CONFIG_PAGE_POISONING`: the kernel honours `page_poison=`.
    pub(super) page_poisoning: Option<bool>,
}

impl KernelConfig {
    /// The symbols as the config text `text` sets them.
    pub(super) fn parse(text: &str) -> Self {
        Self {
            init_on_free_default: symbol(text, INIT_ON_FREE_DEFAULT_ON),
            page_poisoning: symbol(text, PAGE_POISONING),
        }
    }
}

/// Whether the config text `text` turns the boolean symbol `name` on.
///
/// `NAME=y` turns it on and `NAME=n` off; Kconfig writes a symbol that is off
/// as the comment `# NAME is not set`, which only counts in exactly that form.
/// A symbol whose name merely starts with `name` (`CONFIG_PAGE_POISONING_ZERO`)
/// is another symbol. `None` when the text does not set it, as a kernel too
/// old to have the symbol does not.
pub(super) fn symbol(text: &str, name: &str) -> Option<bool> {
    for line in text.lines() {
        let line = line.trim();
        if let Some(value) = line
            .strip_prefix(name)
            .and_then(|rest| rest.strip_prefix('='))
        {
            return Some(value.trim() == "y");
        }
        if line
            .strip_prefix('#')
            .and_then(|comment| comment.trim_start().strip_prefix(name))
            == Some(" is not set")
        {
            return Some(false);
        }
    }
    None
}

/// Where the booted kernel's config is read from.
pub(super) struct ConfigSources {
    /// The running kernel's own gzip-compressed copy (`/proc/config.gz`).
    pub(super) proc_config: PathBuf,
    /// The directory holding `config-<release>` (`/boot`).
    pub(super) boot_dir: PathBuf,
    /// The directory holding `<release>/config` (`/usr/lib/modules`).
    pub(super) modules_dir: PathBuf,
}

impl ConfigSources {
    /// The booted kernel's config from the first source that can be read: the
    /// running kernel's own copy, then the files a package installs for the
    /// booted `release`, when it is known. `None` when none can be read.
    pub(super) fn read<F: Filesystem>(
        &self,
        fs: &F,
        release: Option<&str>,
    ) -> Option<KernelConfig> {
        if let Some(text) = proc_config_text(fs, &self.proc_config) {
            return Some(KernelConfig::parse(&text));
        }
        let release = release?;
        [
            self.boot_dir.join(format!("config-{release}")),
            self.modules_dir.join(release).join("config"),
        ]
        .iter()
        .find_map(|path| fs.read_file_content(path).ok())
        .map(|text| KernelConfig::parse(&text))
    }
}

/// The text of the kernel's own config at `path`, when it is there and
/// decodes.
fn proc_config_text<F: Filesystem>(fs: &F, path: &Path) -> Option<String> {
    let compressed = fs.read_file_bytes(path).ok()?;
    let text = gzip::decompress(&compressed).ok()?;
    Some(String::from_utf8_lossy(&text).into_owned())
}
