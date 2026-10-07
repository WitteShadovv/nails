// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Property-based tests for the text parsers that read kernel and system files.
//!
//! Each property generates inputs from a model of the real format (the kernel's
//! escaping, systemd's assignment rules, os-release quoting), renders them the
//! way the producer would, and checks that the parser recovers the model; a
//! second family feeds arbitrary bytes and only requires that nothing panics.
//! `cargo test` runs the default number of cases; `just fuzz` raises
//! `PROPTEST_CASES` for a long run.

mod conf;
mod mountinfo;
mod overlay_opts;
mod swaps;

use proptest::prelude::*;

/// Characters a path component may hold, biased towards the ones the kernel and
/// the overlay option syntax escape.
pub(super) fn path_char() -> impl Strategy<Value = char> {
    prop_oneof![15 => mountable_char(), 1 => Just('\n')]
}

/// [`path_char`] without the newline.
fn mountable_char() -> impl Strategy<Value = char> {
    prop_oneof![
        4 => proptest::char::range('a', 'z'),
        1 => Just(' '),
        1 => Just('\t'),
        1 => Just('\\'),
        1 => Just(','),
        1 => Just(':'),
        1 => Just('='),
        1 => Just('#'),
        1 => Just('0'),
        1 => Just('7'),
        1 => Just('é'),
    ]
}

/// An absolute path of one to four non-empty components.
pub(super) fn abs_path() -> impl Strategy<Value = String> {
    path_of(path_char().boxed())
}

/// [`abs_path`] without newlines, which an overlay mount option cannot carry.
pub(super) fn mountable_path() -> impl Strategy<Value = String> {
    path_of(
        path_char()
            .prop_filter("no newline", |c| *c != '\n')
            .boxed(),
    )
}

fn path_of(chars: BoxedStrategy<char>) -> impl Strategy<Value = String> {
    prop::collection::vec(prop::collection::vec(chars, 1..8), 1..4).prop_map(|parts| {
        parts
            .into_iter()
            .map(|chars| format!("/{}", chars.into_iter().collect::<String>()))
            .collect()
    })
}

/// The kernel's `seq_escape`/`mangle`: every byte in `set` becomes `\ooo`.
pub(super) fn octal_escape(s: &str, set: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if set.contains(c) {
            for b in c.to_string().bytes() {
                out.push_str(&format!("\\{b:03o}"));
            }
        } else {
            out.push(c);
        }
    }
    out
}
