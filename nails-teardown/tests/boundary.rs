// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The dependency boundary of the emergency hot path.
//!
//! Everything the panic path runs lives in this crate, and the crate may only
//! depend on `rustix`, `libc` and `serde`. Cargo already refuses a dependency on
//! another NAILS crate (every one of them sits above this one, so it would be a
//! cycle); this test also fails when any other dependency is added, so growing
//! the reviewed surface is a deliberate change to this list.

use std::path::PathBuf;

const ALLOWED: &[&str] = &["libc", "rustix", "serde", "serde_json"];

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The keys of the `[dependencies]` table of this crate's manifest.
fn dependencies() -> Vec<String> {
    let manifest = std::fs::read_to_string(manifest_dir().join("Cargo.toml")).unwrap();
    let mut in_table = false;
    let mut names = Vec::new();
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_table = line == "[dependencies]";
            continue;
        }
        if in_table
            && !line.is_empty()
            && !line.starts_with('#')
            && let Some((name, _)) = line.split_once('=')
        {
            names.push(name.trim().to_string());
        }
    }
    names.sort();
    names
}

#[test]
fn the_crate_depends_only_on_the_allowed_crates() {
    assert_eq!(dependencies(), ALLOWED);
}

#[test]
fn no_source_reaches_for_core_logging_or_config() {
    let mut stack = vec![manifest_dir().join("src")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            for forbidden in [
                "nails_base",
                "nails_core",
                "nails_forensics",
                "nails_platform",
                "nails_session",
                "tracing::",
                "toml::",
            ] {
                assert!(
                    !text.contains(forbidden),
                    "{} uses {forbidden}",
                    path.display()
                );
            }
        }
    }
}
