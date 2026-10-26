// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Keys for plaso timeline events, so that a record subtracts across the three
//! images exactly when its content does.
//!
//! An event is keyed by what it records, never by when or where in its file:
//! the timestamps, the record's offset, the file's inode and hash and plaso's
//! own rendering of the event are left out, so the same record seen in two
//! images is one key, and a record a plain reboot also writes (a boot record,
//! a getty started at boot) subtracts against the one the control cycle wrote.
//! Everything else the event carries is kept, so a record that differs in any
//! field it records (a user, a host, an address, a terminal) is a new key.
//!
//! A file-system event (`fs:stat` and the other `fs:` types) is keyed by its
//! path alone: the restore channel compares what a file holds, and its times
//! change on every read. A systemd-journal line is keyed by its reporter, host
//! and message body (see [`normalize_journal_body`]), because the journal file
//! it sits in is renamed on every rotation.

use crate::model::{Finding, Tool};
use serde_json::Value;

/// The event fields that place or date an event rather than say what it
/// records: plaso's container bookkeeping, the event's time and its kind of
/// time, where the record sits in its file, which file it came from (the key's
/// path) and that file's identity and hash, plaso's rendering of the record
/// as text and the parser that read it. A field whose value is a date and time
/// is left out too, whatever its name.
const NOT_CONTENT: &[&str] = &[
    "__container_type__",
    "__type__",
    "_event_values_hash",
    "data_type",
    "date_time",
    "display_name",
    "filename",
    "inode",
    "md5_hash",
    "message",
    "offset",
    "parser",
    "path",
    "pathspec",
    "sha1_hash",
    "sha256_hash",
    "timestamp",
    "timestamp_desc",
];

/// Parse one plaso JSON-line event into a finding: its source path and a key
/// for what it records (see the module docs). Returns `None` when the line is
/// not JSON or names no source path. Pure, so it is unit-tested directly.
pub fn plaso_finding(line: &str) -> Option<Finding> {
    let value: Value = serde_json::from_str(line).ok()?;
    let data_type = first_string(&value, &["data_type"]).unwrap_or_default();

    // A systemd-journal event is keyed on its content, not on the journal file:
    // journald rotates files named by a per-boot sequence and realtime stamp
    // (`system@<seq>-<first>-<time>.journal`), so the path is unique on every
    // image and could never subtract across before/control/after.
    if data_type == "systemd:journal" {
        return journal_finding(&value);
    }

    let source = first_string(&value, &["path", "filename", "display_name"])?;
    let path = strip_type_indicator(&source);
    // A non-journal event that still points at a rotating journal file (plaso's
    // own `fs:stat` for the file, say) is dropped for the same reason: the
    // file's identity is volatile; its content is compared above.
    if is_journal_file(path) {
        return None;
    }
    let field = if is_file_event(&data_type) {
        data_type
    } else {
        record_key(&data_type, &value)
    };
    Some(Finding::new(Tool::Plaso, path, field))
}

/// Whether a plaso key is a file-system event (`fs:stat` and the other `fs:`
/// types), which plaso reports for every file it sees, rather than a record
/// it read out of the file.
pub(crate) fn is_file_event(key: &str) -> bool {
    key.starts_with("fs:")
}

/// The key of a record event: its data type, then every field that says what
/// it records as `name=value`, in name order. A process id is kept to its
/// power-of-two range ([`pid_range`]).
fn record_key(data_type: &str, value: &Value) -> String {
    let mut fields: Vec<(&str, String)> = Vec::new();
    for (name, field) in value.as_object().into_iter().flatten() {
        if NOT_CONTENT.contains(&name.as_str()) || is_date_time(field) {
            continue;
        }
        let text = match field {
            Value::Null => continue,
            Value::String(s) => s.clone(),
            Value::Number(n) if name == "pid" => {
                n.as_i64().map_or_else(|| n.to_string(), pid_range)
            }
            other => other.to_string(),
        };
        fields.push((name, text));
    }
    fields.sort();
    let mut key = data_type.to_string();
    for (name, text) in fields {
        if !key.is_empty() {
            key.push(' ');
        }
        key.push_str(name);
        key.push('=');
        key.push_str(&text);
    }
    key
}

/// Whether a field holds one of plaso's date-and-time values.
fn is_date_time(field: &Value) -> bool {
    field.get("__type__").and_then(Value::as_str) == Some("DateTimeValues")
}

/// A process id as the power-of-two range it falls in (`512-1023`), or as
/// itself when it is not positive. A process a fresh kernel starts at boot
/// gets a low number that drifts by a few from boot to boot, and the range
/// absorbs that drift; one started after a soft-reboot continues the numbers
/// of the boot before it, which lands it in a higher range: the tell the
/// residue catalog's login- and boot-record row describes.
pub(crate) fn pid_range(pid: i64) -> String {
    if pid <= 0 {
        return pid.to_string();
    }
    let low = 1_i64 << (63 - pid.leading_zeros());
    format!("{low}-{}", low + (low - 1))
}

/// Drop the file-system type indicator plaso puts before a location
/// (`EXT:/var/log/wtmp`), so a record event and the file's own `fs:stat`
/// event, which names the plain path, share the path an allowlist entry gives.
fn strip_type_indicator(source: &str) -> &str {
    match source.split_once(':') {
        Some((indicator, rest))
            if rest.starts_with('/')
                && !indicator.is_empty()
                && indicator
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_') =>
        {
            rest
        }
        _ => source,
    }
}

/// A systemd-journal file, `/var/log/journal/<machine-id>/<...>.journal`. plaso
/// prefixes the location with a type indicator (`EXT:`), which `contains`
/// tolerates. These rotate under per-boot unique names, so they are compared by
/// message content, never by path.
pub(crate) fn is_journal_file(path: &str) -> bool {
    path.contains("/var/log/journal/") && path.ends_with(".journal")
}

/// Key a systemd-journal event on its content: the reporting unit, the host
/// and the message body, with only the tokens [`normalize_journal_body`]
/// knows to change on every boot masked. The event's time, process id and
/// source file are left out; they vary every boot and would stop any line from
/// ever subtracting. The host is kept: a line the decoy logs under another
/// hostname is not the decoy's own. The locus is the fixed pseudo-path
/// `journal`, so a residual line is allowlistable by its exact content like
/// any feature.
fn journal_finding(value: &Value) -> Option<Finding> {
    let reporter = first_string(value, &["reporter", "_COMM"]).unwrap_or_default();
    let hostname = first_string(value, &["hostname", "_HOSTNAME"]).unwrap_or_default();
    let body = first_string(value, &["body", "message_body", "message"])?;
    let mut field = reporter;
    if !hostname.is_empty() {
        field.push('@');
        field.push_str(&hostname);
    }
    if !field.is_empty() {
        field.push_str(": ");
    }
    field.push_str(&normalize_journal_body(&body));
    Some(Finding::new(Tool::Plaso, "journal", field))
}

/// The units a duration or a size is written with right after its number
/// (`1.234s`, `500ms`, `64.0M`).
const UNITS: &[&str] = &[
    "us", "µs", "ms", "s", "sec", "min", "h", "d", "B", "K", "KB", "KiB", "M", "MB", "MiB", "G",
    "GB", "GiB", "T", "TB", "TiB",
];

/// Mask the tokens of a journal message body that change on every boot
/// without saying who or where, and only in the positions where they are known
/// to: a process id after `PID`, `pid=` or inside `name[...]`, a boot id after
/// `boot` or `boot_id=`, a duration or a size written with its unit, and the
/// stamp of an audit record. Everything else is kept verbatim, an address, a
/// port, a user or group id, a MAC, a hostname, a user name with digits in it,
/// so a line that names another machine, account or network than the decoy's
/// own line does never subtracts against it. A volatile number in any other
/// position keeps its line from subtracting too: a false leak, never a hidden
/// one.
pub(crate) fn normalize_journal_body(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    let mut previous = "";
    let mut rest = body;
    while !rest.is_empty() {
        let space = rest.len() - rest.trim_start().len();
        if space > 0 {
            out.push_str(&rest[..space]);
            rest = &rest[space..];
            continue;
        }
        let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        let token = &rest[..end];
        out.push_str(&mask_token(previous, token));
        previous = token;
        rest = &rest[end..];
    }
    out
}

/// Mask one whitespace-separated token of a journal body, given the token
/// before it (see [`normalize_journal_body`]).
fn mask_token(previous: &str, token: &str) -> String {
    let previous = previous
        .trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .to_ascii_lowercase();
    match previous.as_str() {
        "pid" => return mask_digits(token, 0),
        "boot" => return mask_boot_id(token, 0),
        _ => {}
    }
    // ASCII lowercasing keeps every byte offset, so a match in `lower` is the
    // same position in `token`.
    let lower = token.to_ascii_lowercase();
    if let Some(at) = lower.find("boot_id=") {
        return mask_boot_id(token, at + "boot_id=".len());
    }
    for key in ["pid=", "pid:"] {
        if let Some(at) = lower.find(key) {
            return mask_digits(token, at + key.len());
        }
    }
    mask_bracketed_pid(token)
        .or_else(|| mask_audit_stamp(token))
        .or_else(|| mask_quantity(token))
        .unwrap_or_else(|| token.to_string())
}

/// The run of ASCII digits at byte `start` of `token` masked as `N`; the token
/// unchanged when no digit is there.
fn mask_digits(token: &str, start: usize) -> String {
    let tail = &token[start..];
    let len = tail
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(tail.len());
    if len == 0 {
        return token.to_string();
    }
    format!("{}N{}", &token[..start], &tail[len..])
}

/// The id at byte `start` of `token` masked as `X` when it looks like a boot id
/// (at least 16 hex digits and dashes, with a digit and a letter among them);
/// the token unchanged otherwise, so `boot` before a short word keeps it.
fn mask_boot_id(token: &str, start: usize) -> String {
    let tail = &token[start..];
    let len = tail
        .find(|c: char| !(c.is_ascii_hexdigit() || c == '-'))
        .unwrap_or(tail.len());
    let id = &tail[..len];
    let has_digit = id.bytes().any(|b| b.is_ascii_digit());
    let has_letter = id.bytes().any(|b| b.is_ascii_alphabetic());
    if len < 16 || !has_digit || !has_letter {
        return token.to_string();
    }
    format!("{}X{}", &token[..start], &tail[len..])
}

/// `name[1234]` with the digits masked, or `None` when the token has no
/// bracketed all-digit run after a name.
fn mask_bracketed_pid(token: &str) -> Option<String> {
    let open = token.find('[')?;
    let close = open + token[open..].find(']')?;
    let inside = &token[open + 1..close];
    if open == 0 || inside.is_empty() || !inside.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(format!("{}[N]{}", &token[..open], &token[close + 1..]))
}

/// `audit(1700000000.123:42)` with the stamp masked, or `None` when the token
/// carries no audit stamp.
fn mask_audit_stamp(token: &str) -> Option<String> {
    let start = token.find("audit(")? + "audit(".len();
    let close = start + token[start..].find(')')?;
    let stamp = &token[start..close];
    if stamp.is_empty()
        || !stamp
            .bytes()
            .all(|b| b.is_ascii_digit() || b == b'.' || b == b':')
    {
        return None;
    }
    Some(format!("{}N{}", &token[..start], &token[close..]))
}

/// A number written with a duration or size unit (`1.234s,`, `(64.0M)`) with
/// the number masked, or `None` when the token is not one.
fn mask_quantity(token: &str) -> Option<String> {
    let start = token.find(|c: char| c.is_ascii_digit())?;
    if !token[..start].bytes().all(|b| b == b'(') {
        return None;
    }
    let core = &token[start..];
    let unit_start = core.find(|c: char| !(c.is_ascii_digit() || c == '.'))?;
    let number = &core[..unit_start];
    if number.ends_with('.') || number.matches('.').count() > 1 {
        return None;
    }
    let after = &core[unit_start..];
    let unit_len = after
        .find(|c: char| !c.is_alphabetic())
        .unwrap_or(after.len());
    let (unit, tail) = after.split_at(unit_len);
    let punctuation = |c: char| matches!(c, ',' | '.' | ';' | ':' | ')');
    if !UNITS.contains(&unit) || !tail.chars().all(punctuation) {
        return None;
    }
    Some(format!("{}N{unit}{tail}", &token[..start]))
}

/// The first of `keys` that `value` (a JSON object) carries as a string.
fn first_string(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
        .map(str::to_string)
}

#[cfg(test)]
#[path = "plaso_tests.rs"]
mod tests;
