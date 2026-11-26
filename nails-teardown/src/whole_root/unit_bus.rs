// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! A service's commands as PID 1 has them loaded, read over D-Bus.
//!
//! `systemctl show` prints each command as one line of text (`{ path=... ;
//! argv[]=... ; ... }`) that sets neither the program nor an argument apart:
//! an argument may itself hold ` ; `, `{` or `}`, and so read as another
//! field or another command. PID 1's D-Bus property (`ExecStart` of
//! `org.freedesktop.systemd1.Service`, `a(sasbttttuii)`) keeps each apart, and
//! `busctl --json=short` prints it as JSON, which reads in one way only.

use crate::whole_root::logind;
use serde_json::Value;
use std::path::Path;

/// One command of a service, as PID 1 runs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecCommand {
    /// The program it runs (`path`), which an `@` prefix sets apart from the
    /// program's name in `argv`.
    pub path: String,
    /// Its arguments, the program's name first.
    pub argv: Vec<String>,
    /// Whether its failure is ignored (a `-` prefix).
    pub ignores: bool,
}

/// The D-Bus object path of `unit`, as systemd escapes a unit's name into one
/// (`bus_label_escape()`): every byte but an ASCII letter or digit becomes `_`
/// and its two lower-case hex digits.
pub fn object_path(unit: &str) -> String {
    let mut path = String::from("/org/freedesktop/systemd1/unit/");
    if unit.is_empty() {
        path.push('_');
    }
    for byte in unit.bytes() {
        if byte.is_ascii_alphanumeric() {
            path.push(char::from(byte));
        } else {
            path.push_str(&format!("_{byte:02x}"));
        }
    }
    path
}

/// The commands of `unit`'s `property` (`ExecStart`, say), asked of PID 1
/// over D-Bus with `busctl`. `None` when it does not answer, or answers in a
/// form [`parse_commands`] does not read.
pub fn commands(busctl: &Path, unit: &str, property: &str) -> Option<Vec<ExecCommand>> {
    let path = object_path(unit);
    let reply = logind::busctl_json(
        busctl,
        &[
            "get-property",
            "org.freedesktop.systemd1",
            &path,
            "org.freedesktop.systemd1.Service",
            property,
        ],
    )?;
    if reply.get("type")?.as_str()? != "a(sasbttttuii)" {
        return None;
    }
    parse_commands(reply.get("data")?)
}

/// The commands in the data of an `a(sasbttttuii)` reply: an array of
/// `(path, argv, ignore, ...)`. `None` when an entry has another shape.
pub fn parse_commands(data: &Value) -> Option<Vec<ExecCommand>> {
    data.as_array()?
        .iter()
        .map(|entry| {
            Some(ExecCommand {
                path: entry.get(0)?.as_str()?.to_string(),
                argv: entry
                    .get(1)?
                    .as_array()?
                    .iter()
                    .map(|arg| arg.as_str().map(str::to_string))
                    .collect::<Option<_>>()?,
                ignores: entry.get(2)?.as_bool()?,
            })
        })
        .collect()
}

#[cfg(test)]
#[path = "unit_bus_tests.rs"]
mod tests;
