// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Keeps the configuration snippets in README.md runnable.
//!
//! The README's Quick start shows a `nails.toml` example. If a key is renamed
//! or the loader is made stricter, a stale example would send operators to a
//! configuration that no longer parses. Every ```toml``` block in the README is
//! therefore loaded through the real, strict loader here.

use std::io::Write;

use nails_core::config::Config;

const README: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../README.md");

/// Extract the body of every ```toml fenced block in `markdown`.
fn toml_blocks(markdown: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut current: Option<String> = None;
    for line in markdown.lines() {
        match current {
            None if line.trim_start().starts_with("```toml") => current = Some(String::new()),
            None => {}
            Some(ref mut body) if line.trim_start() == "```" => {
                blocks.push(std::mem::take(body));
                current = None;
            }
            Some(ref mut body) => {
                body.push_str(line);
                body.push('\n');
            }
        }
    }
    blocks
}

#[test]
fn readme_toml_examples_parse_with_the_strict_loader() {
    let markdown =
        std::fs::read_to_string(README).unwrap_or_else(|e| panic!("cannot read {README}: {e}"));
    let blocks = toml_blocks(&markdown);

    assert!(
        !blocks.is_empty(),
        "README.md should show at least one nails.toml example"
    );

    for block in blocks {
        let mut file = tempfile::NamedTempFile::new().expect("temp file");
        file.write_all(block.as_bytes()).expect("write example");
        Config::load(file.path()).unwrap_or_else(|e| {
            panic!(
                "a README nails.toml example does not parse with the strict loader: {e}\n\n{block}"
            )
        });
    }
}
