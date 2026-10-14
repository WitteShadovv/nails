// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The attach gate only reads.
//!
//! Every writer consults `nails-base/src/hidden_root/` before it writes, often
//! on the decoy itself, so the gate must leave nothing behind: no file it
//! writes, creates or removes, no mode it changes, and no process it starts,
//! which the decoy's journal or audit log could record. This scans the gate's
//! production sources for the calls that would do any of that.

use std::path::{Path, PathBuf};

/// Calls that write, create, remove or start something.
const FORBIDDEN: &[&str] = &[
    "ProcessCommand",
    "std::process::Command",
    "process::Command",
    "write_file_content",
    "create_directory",
    "create_dir",
    "remove_",
    "set_permissions",
    ".write(true)",
    ".append(true)",
    ".create(true)",
    ".create_new(true)",
    ".truncate(true)",
];

fn gate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/hidden_root")
}

/// The production `.rs` files under `dir`; test modules may build fixtures.
fn production_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if path.is_dir() {
            production_sources(&path, out);
        } else if name.ends_with(".rs") && !name.ends_with("tests.rs") {
            out.push(path);
        }
    }
}

/// Every forbidden call in `text`, as `line: call`; comment lines are skipped.
fn forbidden_calls(text: &str) -> Vec<String> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| !line.trim_start().starts_with("//"))
        .flat_map(|(number, line)| {
            FORBIDDEN
                .iter()
                .filter(|call| line.contains(*call))
                .map(move |call| format!("{}: {call}", number + 1))
        })
        .collect()
}

#[test]
fn the_attach_gate_writes_nothing_and_starts_nothing() {
    let mut sources = Vec::new();
    production_sources(&gate_dir(), &mut sources);
    assert!(
        sources.iter().any(|p| p.ends_with("hidden_root/mod.rs")),
        "the scan found the gate: {sources:?}"
    );
    for path in sources {
        let found = forbidden_calls(&std::fs::read_to_string(&path).unwrap());
        assert!(
            found.is_empty(),
            "{} must only read, but calls {found:?}",
            path.display()
        );
    }
}

#[test]
fn the_scan_finds_each_forbidden_call() {
    let fixture = "\
fn probe(fs: &RealFilesystem, root: &Path) {
    // A comment may name write_file_content.
    fs.write_file_content(&root.join(\"x\"), \"\");
    std::process::Command::new(\"blkid\");
    std::fs::OpenOptions::new().write(true).open(root);
    fs.remove_file(root);
}
";
    assert_eq!(
        forbidden_calls(fixture),
        vec![
            "3: write_file_content",
            "4: std::process::Command",
            "4: process::Command",
            "5: .write(true)",
            "6: remove_",
        ]
    );
}
