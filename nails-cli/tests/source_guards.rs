//! Guards that keep the machine-interface invariants from regressing.
//!
//! These scan the crate source so the contract T-028 establishes - one process
//! exit chokepoint, no `Debug`-formatted state/verification, and no hand-built
//! JSON - stays enforced without a reviewer having to remember it.

use std::path::{Path, PathBuf};

fn src_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

fn all_sources() -> Vec<PathBuf> {
    let mut out = Vec::new();
    rust_sources(&src_dir(), &mut out);
    out
}

fn rel(path: &Path) -> String {
    path.strip_prefix(env!("CARGO_MANIFEST_DIR"))
        .unwrap_or(path)
        .display()
        .to_string()
}

#[test]
fn process_exit_lives_only_in_the_detach_chokepoint() {
    for path in all_sources() {
        let text = std::fs::read_to_string(&path).unwrap();
        for (line_no, line) in text.lines().enumerate() {
            if line.contains("process::exit") {
                let is_detach = path.ends_with("cli/detach.rs");
                assert!(
                    is_detach,
                    "{}:{} uses process::exit outside the detach chokepoint: {}",
                    rel(&path),
                    line_no + 1,
                    line.trim()
                );
            }
        }
    }
}

#[test]
fn state_and_verification_are_never_debug_formatted_in_renderers() {
    // Modules that render a system state or overlay verification must emit tagged
    // objects / short labels, never `{:?}`. (Other `{:?}` uses, e.g. ShellType,
    // are fine and live in other files.)
    let guarded = [
        "cli/output/status/json.rs",
        "cli/output/status/human.rs",
        "cli/output/verify.rs",
        "cli/output/dto.rs",
        "cli/commands/status.rs",
        "cli/commands/verify.rs",
    ];
    for path in all_sources() {
        let relpath = rel(&path);
        if guarded.iter().any(|g| relpath.ends_with(g)) {
            let text = std::fs::read_to_string(&path).unwrap();
            assert!(
                !text.contains("{:?}"),
                "{relpath} formats a value with Debug; render state/verification as typed data instead"
            );
        }
    }
}

#[test]
fn no_hand_built_json_string_literals_remain() {
    // Hand-built JSON shows up as escaped braces in a format string (`{{"`) or a
    // raw-string JSON object (`r#"{"`). Everything machine-readable goes through
    // serde now.
    for path in all_sources() {
        let relpath = rel(&path);
        // Test modules legitimately build JSON fixtures (e.g. log lines); the
        // guard is about production output code.
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name.ends_with("tests.rs") || name.starts_with("tests_") {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            !text.contains("{{\""),
            "{relpath} builds JSON with a format string; use serde instead"
        );
        assert!(
            !text.contains("r#\"{\""),
            "{relpath} builds JSON with a raw string literal; use serde instead"
        );
    }
}
