// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The `kernel.core_pattern` the decoy's `sysctl.d` files set, which
//! systemd-sysctl applies again when the decoy starts after the way back.
//!
//! systemd-sysctl reads the `*.conf` files of `/etc/sysctl.d`,
//! `/run/sysctl.d`, `/usr/local/lib/sysctl.d` and `/usr/lib/sysctl.d`
//! (sysctl.d(5)), and of `/lib/sysctl.d` where `/usr` is split, sorted by file
//! name, where a name found in a directory earlier in that list shadows the
//! same name further on; an empty file, or a link to `/dev/null`, sets
//! nothing. A line is `key = value`, stripped of whitespace; one that starts
//! with `#` or `;` is a comment, and a `-` before the key only quiets a
//! failure. A key whose first separator is a `.` reads its dots as slashes,
//! so `kernel.core_pattern` and `kernel/core_pattern` are one key. The last
//! assignment of a key counts. A key with a glob (`*`, `?`, `[`) sets every
//! key it matches that no line names, a `-key` line without a value among
//! them, so a glob that may match `kernel.core_pattern` leaves the value
//! unknown, and so does a file NAILS cannot read. Files are read as the
//! locate-database check reads the decoy ([`DecoyFiles`]).

use super::super::locate_database::files::{DecoyFile, DecoyFiles};
use super::super::systemd_conf::decode_config_bytes;
use crate::Filesystem;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;

/// The directories systemd-sysctl reads, relative to the root, highest
/// priority first.
const SYSCTL_DIRS: &[&str] = &[
    "etc/sysctl.d",
    "run/sysctl.d",
    "usr/local/lib/sysctl.d",
    "usr/lib/sysctl.d",
    "lib/sysctl.d",
];

/// The key, normalized as systemd-sysctl normalizes keys.
const CORE_PATTERN_KEY: &str = "kernel/core_pattern";

/// A key with its dots and slashes as systemd-sysctl reads them: where the
/// first separator is a `.`, each `.` is a `/` and each `/` a `.`; then as a
/// path without empty or `.` parts.
fn normalized(key: &str) -> String {
    let swapped: String = if key
        .find(['.', '/'])
        .is_some_and(|at| key.as_bytes()[at] == b'.')
    {
        key.chars()
            .map(|c| match c {
                '.' => '/',
                '/' => '.',
                other => other,
            })
            .collect()
    } else {
        key.to_string()
    };
    swapped
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect::<Vec<_>>()
        .join("/")
}

/// Whether the glob `pattern` may match `key` as a path under `/proc/sys`:
/// `*` and `?` match within one part of the path; a `[` class NAILS does
/// not read may match anything.
fn may_match(pattern: &[u8], key: &[u8]) -> bool {
    match (pattern.split_first(), key.split_first()) {
        (None, None) => true,
        (Some((b'[', _)), _) => true,
        (Some((b'*', rest)), _) => (0..=key.len())
            .take_while(|&taken| !key[..taken].contains(&b'/'))
            .any(|taken| may_match(rest, &key[taken..])),
        (Some((b'?', rest)), Some((&c, key_rest))) => c != b'/' && may_match(rest, key_rest),
        (Some((&p, rest)), Some((&c, key_rest))) => p == c && may_match(rest, key_rest),
        _ => false,
    }
}

/// The `kernel.core_pattern` the `sysctl.d` files under the root of `files`
/// set, with the file that sets it, as the decoy names it; `None` when none
/// does (see the [module docs](self)).
///
/// # Errors
///
/// Why NAILS cannot tell what they set.
pub(super) fn core_pattern<F: Filesystem>(
    files: &DecoyFiles<'_, F>,
) -> Result<Option<(String, String)>, String> {
    let mut found: BTreeMap<OsString, PathBuf> = BTreeMap::new();
    for dir in SYSCTL_DIRS {
        for entry in files.list(&files.root().join(dir))? {
            let Some(name) = entry.file_name() else {
                continue;
            };
            let bytes = name.as_encoded_bytes();
            if bytes.ends_with(b".conf") && !bytes.starts_with(b".") {
                found.entry(name.to_os_string()).or_insert(entry);
            }
        }
    }
    // The explicit setting, `None` within for a `-key` line without a value.
    let mut explicit: Option<(Option<String>, PathBuf)> = None;
    let mut glob: Option<PathBuf> = None;
    for path in found.into_values() {
        let text = match files.read(&path) {
            DecoyFile::Text(text) => decode_config_bytes(&text),
            DecoyFile::Absent | DecoyFile::Null => continue,
            DecoyFile::Unread(why) => return Err(why),
        };
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with(['#', ';']) {
                continue;
            }
            let (key, value) = match line.split_once('=') {
                Some((key, value)) => (key, Some(value.trim().to_string())),
                None if line.starts_with('-') => (line, None),
                None => continue,
            };
            let key = normalized(key.strip_prefix('-').unwrap_or(key).trim());
            if key == CORE_PATTERN_KEY {
                explicit = Some((value, path.clone()));
            } else if key.contains(['*', '?', '['])
                && value.is_some()
                && may_match(key.as_bytes(), CORE_PATTERN_KEY.as_bytes())
            {
                glob = Some(path.clone());
            }
        }
    }
    match (explicit, glob) {
        (Some((value, path)), _) => Ok(value.map(|value| (value, files.shown(&path)))),
        (None, Some(path)) => Err(format!(
            "{} sets keys by a glob that may match kernel.core_pattern",
            files.shown(&path)
        )),
        (None, None) => Ok(None),
    }
}

#[cfg(test)]
#[path = "sysctl_tests.rs"]
mod tests;
