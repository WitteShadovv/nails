// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The units the kernel's command line has the service manager start.
//!
//! For each `systemd.wants=<unit>` on it, systemd-debug-generator links the
//! unit into the `.wants` directory of the default target in
//! `/run/systemd/generator.early` each time the service manager starts, the
//! start after the way back among them, since a soft-reboot keeps the
//! command line: so the unit it names counts as enabled, even where that
//! link is gone now. The words are read as systemd's `proc_cmdline_parse()`
//! reads them: split at white space outside quotes, the quotes (`'` or `"`)
//! dropped and a backslash kept as it is, and a word that begins with `rd.`
//! counts only in the initrd. A value names a unit as systemd's
//! `unit_name_mangle()` makes one of it: a `/` stands for a `-`, and a name
//! without a unit type is a service's. systemd before 258 reads the words of
//! the `SystemdOptions` EFI variable first, from the copy the manager keeps
//! in `/run/systemd/efivars`, which is read too.

use crate::Filesystem;
use std::path::Path;

/// The kernel's command line, relative to the root.
const CMDLINE: &str = "proc/cmdline";

/// The copy of the `SystemdOptions` EFI variable, of systemd's vendor GUID,
/// that the service manager keeps, relative to the root. systemd reads its
/// first line.
const EFI_OPTIONS: &str = "run/systemd/efivars/SystemdOptions-8cf2644b-4b0b-428f-9387-6d876050dc67";

/// How a word that has the service manager start a unit begins.
const WANTS: &str = "systemd.wants=";

/// The unit types systemd knows, as a unit name ends with one.
const UNIT_TYPES: &[&str] = &[
    "service",
    "socket",
    "target",
    "device",
    "mount",
    "automount",
    "swap",
    "timer",
    "path",
    "slice",
    "scope",
];

/// Whether the kernel's command line under `root`, or the copy of the
/// `SystemdOptions` EFI variable, has the service manager start `unit`
/// (see the [module docs](self)).
///
/// # Errors
///
/// Why NAILS cannot tell: one of them is there but cannot be read.
pub(super) fn wants<F: Filesystem>(fs: &F, root: &Path, unit: &str) -> Result<bool, String> {
    for (rel, first_line) in [(EFI_OPTIONS, true), (CMDLINE, false)] {
        let text = match fs.read_file_content(&root.join(rel)) {
            Ok(text) => text,
            Err(e) if e.io_kind() == Some(std::io::ErrorKind::NotFound) => continue,
            Err(e) => {
                let why = if e.io_kind() == Some(std::io::ErrorKind::PermissionDenied) {
                    format!("NAILS cannot read /{rel}; run the command again with sudo")
                } else {
                    format!("NAILS cannot read /{rel} ({e})")
                };
                return Err(format!(
                    "NAILS cannot tell whether {unit} is enabled, which a systemd.wants= there \
                     makes it: {why}"
                ));
            }
        };
        let text = if first_line {
            text.lines().next().unwrap_or_default()
        } else {
            text.as_str()
        };
        if words(text).iter().any(|word| {
            word.strip_prefix(WANTS)
                .is_some_and(|value| mangled(value).as_deref() == Some(unit))
        }) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The words of `line`, as systemd splits the kernel's command line: at
/// white space outside quotes, with the quotes dropped and a backslash kept
/// as it is.
fn words(line: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word: Option<String> = None;
    let mut quote = None;
    for c in line.chars() {
        match quote {
            Some(open) if c == open => quote = None,
            Some(_) => word.get_or_insert_with(String::new).push(c),
            None if c == '\'' || c == '"' => {
                quote = Some(c);
                word.get_or_insert_with(String::new);
            }
            None if matches!(c, ' ' | '\t' | '\n' | '\r') => words.extend(word.take()),
            None => word.get_or_insert_with(String::new).push(c),
        }
    }
    words.extend(word);
    words
}

/// Whether `name` is a unit name as systemd takes one: a known unit type
/// after its last `.`, and before it letters, digits and `:-_.\@`, with no
/// `@` first.
fn valid_unit_name(name: &str) -> bool {
    let Some((stem, kind)) = name.rsplit_once('.') else {
        return false;
    };
    name.len() < 256
        && !stem.is_empty()
        && !stem.starts_with('@')
        && UNIT_TYPES.contains(&kind)
        && stem
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ":-_.\\@".contains(c))
}

/// The unit name systemd makes of `value`, as `unit_name_mangle()` makes it
/// for `systemd.wants=`, where it can be one NAILS asks about: `None` for a
/// path, which it makes a mount or a device of, and for a value it escapes,
/// one with a character a unit name does not hold.
fn mangled(value: &str) -> Option<String> {
    if valid_unit_name(value) {
        return Some(value.to_string());
    }
    if value.is_empty() || value.starts_with('/') {
        return None;
    }
    let name = value.replace('/', "-");
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || ":-_.\\@".contains(c))
    {
        return None;
    }
    Some(if valid_unit_name(&name) {
        name
    } else {
        format!("{name}.service")
    })
}

#[cfg(test)]
#[path = "command_line_tests.rs"]
mod tests;
