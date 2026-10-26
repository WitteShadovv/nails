// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The boundary of the forensics crate: it only reads.
//!
//! Verification needs to recognise a session and its leftovers, so it reads
//! the session plan's format, the mount table and the session's unit names.
//! It must never reach the code that enters, leaves or tears down a session:
//! a verify run that could unmount, kill or soft-reboot would change the very
//! state it reports on. This test lists every item of `nails-teardown` and
//! `nails-session` the crate may name; anything else fails it.

use std::path::{Path, PathBuf};

/// The items of nails-teardown this crate may use, as paths below the crate.
/// A trailing `*` allows a whole module (pure parsers only).
const TEARDOWN_ALLOWED: &[&str] = &[
    "mountinfo::*",
    "whole_root::disk_guard::RULE_DIR",
    "whole_root::disk_guard::RULE_NAME",
    "whole_root::plan::PLAN_NAME",
    "whole_root::plan::PLAN_VERSION",
    "whole_root::plan::Plan",
    "whole_root::plan::RUNTIME_DIR",
    "whole_root::nextroot::NEXTROOT",
    "whole_root::nextroot::is_mount_point",
    "whole_root::skips::SKIP_DROPIN_NAME",
    "whole_root::skips::SKIP_TEXT",
    "whole_root::transition::DROPIN_DIR",
    "whole_root::transition::DROPIN_NAME",
    "whole_root::transition::STOP_GUARD_NAME",
    "whole_root::transition::runtime_guards",
    "whole_root::transition::stop_guard_dir",
];

/// The items of nails-session this crate may use. The crate root imports the
/// `session` and `sleep_guard` modules (and nothing else of nails-session),
/// so the code names them as `crate::session::…` and `crate::sleep_guard::…`.
const SESSION_ALLOWED: &[&str] = &[
    "session::probe::*",
    "session::units::WATCH_UNIT",
    "sleep_guard::SLEEP_GUARD_UNIT_NAME",
];

fn src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn sources() -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut stack = vec![src()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                files.push(path);
            }
        }
    }
    files
}

/// Every full path written after `prefix` in `text`, with `{a, b}` groups
/// expanded (one level, which is all the code uses).
fn paths_after(text: &str, prefix: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find(prefix) {
        rest = &rest[at + prefix.len()..];
        let head: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == ':')
            .collect();
        let after = &rest[head.len()..];
        if (head.ends_with("::") || head.is_empty())
            && let Some(group) = after.strip_prefix('{')
        {
            let group = &group[..group.find('}').expect("closed use group")];
            for item in group.split(',').map(str::trim).filter(|i| !i.is_empty()) {
                let item = item.split(" as ").next().unwrap().trim();
                found.push(format!("{head}{item}"));
            }
            continue;
        }
        found.push(head);
    }
    found
}

fn allowed(path: &str, list: &[&str]) -> bool {
    list.iter().any(|entry| match entry.strip_suffix('*') {
        Some(module) => path.starts_with(module),
        None => path == *entry,
    })
}

/// Every use of `prefix` in the crate's sources, as `(file, path)` with the
/// path rewritten under `rename`.
fn uses(prefix: &str, rename: &str) -> Vec<(PathBuf, String)> {
    let mut found = Vec::new();
    for file in sources() {
        let text = std::fs::read_to_string(&file).unwrap();
        for path in paths_after(&text, prefix) {
            found.push((file.clone(), format!("{rename}{path}")));
        }
    }
    found
}

fn assert_allowed(found: &[(PathBuf, String)], list: &[&str]) {
    assert!(!found.is_empty(), "no use found: the scan is broken");
    for (file, path) in found {
        assert!(
            allowed(path, list),
            "{} uses {path}, which this crate may not name",
            file.display()
        );
    }
}

#[test]
fn only_the_teardown_readers_are_used() {
    assert_allowed(&uses("nails_teardown::", ""), TEARDOWN_ALLOWED);
}

#[test]
fn only_the_session_probes_and_unit_names_are_used() {
    let mut found = uses("crate::session::", "session::");
    found.extend(uses("crate::sleep_guard::", "sleep_guard::"));
    assert_allowed(&found, SESSION_ALLOWED);
}

#[test]
fn the_crate_root_imports_only_the_session_and_sleep_guard_modules() {
    let found = uses("nails_session::", "");
    assert!(!found.is_empty(), "no use found: the scan is broken");
    for (file, path) in found {
        assert_eq!(
            file,
            src().join("lib.rs"),
            "{} names nails_session",
            file.display()
        );
        assert!(
            ["session", "sleep_guard"].contains(&path.as_str()),
            "the crate root imports nails_session::{path}"
        );
    }
}

#[test]
fn the_scan_expands_use_groups() {
    assert_eq!(
        paths_after("use nails_teardown::a::{B, c as d};", "nails_teardown::"),
        ["a::B", "a::c"]
    );
    assert_eq!(
        paths_after("x = nails_teardown::a::f(1);", "nails_teardown::"),
        ["a::f"]
    );
}
