// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! When systemd-coredump puts a core dump on the decoy disk.
//!
//! The kernel hands every crashing process's memory to systemd-coredump when
//! `kernel.core_pattern` pipes to it. Two `[Coredump]` settings in
//! `coredump.conf` and its drop-ins then decide what reaches
//! `/var/lib/systemd/coredump` on the decoy disk (coredump.conf(5)):
//!
//! - `Storage=` decides what is kept: `external` (the default) keeps the core
//!   there, `journal` stores it in the journal, `none` keeps nothing;
//! - `ProcessSizeMax=` (32G by default) bounds the cores it processes. Unless
//!   it is 0, systemd-coredump first writes each core into
//!   `/var/lib/systemd/coredump` (under a temporary or an unlinked name) to
//!   process it, whatever `Storage=` says.
//!
//! So only `Storage=none` together with `ProcessSizeMax=0` keeps every core
//! off the disk; systemd-coredump then logs one line per crash and nothing
//! else. The advice never says to turn systemd-coredump off: without it the
//! kernel writes a `core` file into the crashing program's working directory.

use super::super::systemd_conf::{self, Assignment};
use crate::Filesystem;
use std::path::Path;

/// systemd-coredump configuration name, resolved with its drop-ins.
const COREDUMP_CONF: &str = "coredump.conf";
/// The section its settings are read from.
const COREDUMP_SECTION: &str = "Coredump";
/// `ProcessSizeMax=`'s default on 64-bit systems, for the message.
const PROCESS_SIZE_MAX_DEFAULT: &str = "32G";

/// What `Storage=` tells systemd-coredump to keep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Storage {
    External,
    Journal,
    None,
}

impl Storage {
    fn as_str(self) -> &'static str {
        match self {
            Storage::External => "external",
            Storage::Journal => "journal",
            Storage::None => "none",
        }
    }
}

/// systemd-coredump's effective settings that decide whether a core reaches
/// the disk. `None` means never assigned, so the default applies.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct CoredumpSettings {
    pub(super) storage: Option<Storage>,
    /// The last valid `ProcessSizeMax=` as written, with its value in bytes.
    pub(super) process_size_max: Option<(String, u64)>,
}

impl CoredumpSettings {
    /// Fold `[Coredump]` assignments, in the order systemd applies them.
    ///
    /// As in systemd, a value it rejects leaves the previous one in place, and
    /// an empty `Storage=` resets it to the default.
    pub(super) fn from_assignments(assignments: &[Assignment]) -> Self {
        let mut settings = Self::default();
        for assignment in assignments {
            let value = assignment.value.as_str();
            match assignment.key.as_str() {
                "Storage" => match value {
                    "" => settings.storage = None,
                    "external" => settings.storage = Some(Storage::External),
                    "journal" => settings.storage = Some(Storage::Journal),
                    "none" => settings.storage = Some(Storage::None),
                    _ => {}
                },
                "ProcessSizeMax" => {
                    if let Some(bytes) = parse_iec_size(value) {
                        settings.process_size_max = Some((value.to_string(), bytes));
                    }
                }
                _ => {}
            }
        }
        settings
    }

    /// The effective settings under `root`, with every drop-in. When no file
    /// exists at all, the defaults apply: the kernel's pipe to systemd-coredump
    /// shows it is installed.
    pub(super) fn read<F: Filesystem>(fs: &F, root: &Path) -> Self {
        Self::from_assignments(&systemd_conf::section_assignments(
            fs,
            root,
            COREDUMP_CONF,
            COREDUMP_SECTION,
        ))
    }

    fn effective_storage(&self) -> Storage {
        self.storage.unwrap_or(Storage::External)
    }

    /// Whether every core stays off the disk: only `Storage=none` with
    /// `ProcessSizeMax=0` does that.
    pub(super) fn keeps_cores_off_disk(&self) -> bool {
        self.effective_storage() == Storage::None
            && self
                .process_size_max
                .as_ref()
                .is_some_and(|(_, bytes)| *bytes == 0)
    }

    /// The warning for these settings, naming the fix for the platform, or
    /// `None` when no core reaches the disk.
    pub(super) fn finding(&self, is_nixos: bool) -> Option<String> {
        if self.keeps_cores_off_disk() {
            return None;
        }
        let storage = self.effective_storage();
        let storage_set = match self.storage {
            Some(storage) => format!("Storage={}", storage.as_str()),
            None => "Storage unset, so external".to_string(),
        };
        let what = match storage {
            Storage::External => format!(
                "systemd-coredump keeps core dumps in /var/lib/systemd/coredump on the decoy \
                 disk ({storage_set})"
            ),
            Storage::Journal => format!(
                "systemd-coredump writes each core dump to /var/lib/systemd/coredump on the \
                 decoy disk before it stores it in the journal ({storage_set})"
            ),
            Storage::None => {
                let size = match &self.process_size_max {
                    Some((raw, _)) => format!("ProcessSizeMax={raw}"),
                    None => format!("ProcessSizeMax unset, so {PROCESS_SIZE_MAX_DEFAULT}"),
                };
                format!(
                    "systemd-coredump still writes each core dump to /var/lib/systemd/coredump \
                     on the decoy disk while it processes it ({storage_set} with {size}, not 0)"
                )
            }
        };
        let fix = if is_nixos {
            "set systemd.coredump.settings.Coredump = { Storage = \"none\"; ProcessSizeMax = 0; } \
             in the decoy configuration"
        } else {
            "set Storage=none and ProcessSizeMax=0 under [Coredump] in a drop-in such as \
             /etc/systemd/coredump.conf.d/50-discard.conf"
        };
        Some(format!("{what}; {fix}"))
    }
}

/// Whether `kernel.core_pattern` hands crashing processes to systemd-coredump,
/// by either transport it uses:
///
/// - the classic pipe `|/path/to/systemd-coredump ...`, on every kernel;
/// - the kernel coredump socket (Linux 6.17+ with systemd 262):
///   `systemd-coredump-register.service` sets
///   `kernel.core_pattern=@@/run/systemd/coredumpd/kernel`, where a leading `@`
///   selects the socket transport and the second `@` is the request protocol.
///   Older systemd keeps the per-dump `systemd-coredump@.service` pipe form.
///
/// When it does, `coredump.conf` decides what reaches the disk
/// ([`CoredumpSettings`]). A pattern that pipes or sockets to any other handler
/// is that handler's business, so it is left alone, as is the plain-file form,
/// which [`super`] reports directly.
pub(super) fn pattern_targets_systemd_coredump(pattern: &str) -> bool {
    if let Some(helper) = pattern.strip_prefix('|') {
        return helper.contains("systemd-coredump");
    }
    if let Some(socket) = pattern.strip_prefix('@') {
        let socket = socket.strip_prefix('@').unwrap_or(socket);
        return socket.contains("systemd") && socket.contains("coredump");
    }
    false
}

/// A size as systemd's `parse_size()` reads it with base 1024, the way
/// `ProcessSizeMax=` is parsed: one or more `<number>[.<fraction>]` parts, each
/// with an optional suffix `E`, `P`, `T`, `G`, `M`, `K` or `B` (in that order
/// across parts), summed; `infinity` is the largest size. `None` for a value
/// systemd rejects.
pub(super) fn parse_iec_size(value: &str) -> Option<u64> {
    const SUFFIXES: [(&str, u64); 8] = [
        ("E", 1 << 60),
        ("P", 1 << 50),
        ("T", 1 << 40),
        ("G", 1 << 30),
        ("M", 1 << 20),
        ("K", 1 << 10),
        ("B", 1),
        ("", 1),
    ];
    if value == "infinity" {
        return Some(u64::MAX);
    }
    let is_ws = |c: char| matches!(c, ' ' | '\t' | '\n' | '\r');
    let mut rest = value;
    let mut first_suffix = 0;
    let mut total: u64 = 0;
    loop {
        let part = rest.trim_start_matches(is_ws);
        if part.starts_with('-') {
            return None;
        }
        let digits = part.strip_prefix('+').unwrap_or(part);
        let len = digits.bytes().take_while(u8::is_ascii_digit).count();
        if len == 0 {
            return None;
        }
        let whole: u64 = digits[..len].parse().ok()?;
        let mut after = &digits[len..];
        let mut fraction = 0.0_f64;
        if let Some(decimals) = after.strip_prefix('.') {
            let count = decimals.bytes().take_while(u8::is_ascii_digit).count();
            if count > 0 {
                fraction = format!("0.{}", &decimals[..count]).parse().ok()?;
            }
            after = &decimals[count..];
        }
        after = after.trim_start_matches(is_ws);
        let (index, (suffix, factor)) = SUFFIXES
            .iter()
            .enumerate()
            .skip(first_suffix)
            .find(|(_, (suffix, _))| after.starts_with(suffix))?;
        let part_bytes = whole
            .checked_mul(*factor)?
            // Truncated like systemd's cast of the fraction's bytes.
            .checked_add((fraction * *factor as f64) as u64)?;
        total = total.checked_add(part_bytes)?;
        rest = &after[suffix.len()..];
        first_suffix = index + 1;
        if rest.is_empty() {
            return Some(total);
        }
    }
}

#[cfg(test)]
#[path = "coredump_tests.rs"]
mod tests;
