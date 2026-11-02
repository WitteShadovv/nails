// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What a startup file's lines name, counted without the lexer: the options
//! that write each command line to the history file, the `source` and `.`
//! commands, and the `ZDOTDIR` settings. The walk counts the same as it
//! reads them, and what the lines name beyond that is what a misread hid
//! from it, in a quote, a comment or a here-document it took for one: an
//! option named there counts as on, and a `source`, `.` or `ZDOTDIR` there
//! is a doubt.
//!
//! Only a line whose first character that is not a blank is `#` is left out,
//! so an option a comment at the end of a line names counts as on too, and a
//! `source` in a string or a here-document is a doubt.

use super::walk::option;

/// What the lines of a file name, outside the lines that are a comment.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct Named {
    /// Each of [`super::OPTIONS`], in any spelling and in its `no` form too.
    pub(super) options: [usize; 3],
    /// `source` and `.` where a command can start.
    pub(super) sources: usize,
    /// `ZDOTDIR` where it is not read ([`zdotdir_writes`]).
    pub(super) zdotdirs: usize,
}

/// The words that can come before a command at the start of a line or after
/// an operator.
const BEFORE_COMMAND: &[&str] = &[
    "if",
    "then",
    "else",
    "elif",
    "do",
    "while",
    "until",
    "!",
    "time",
    "builtin",
    "command",
    "noglob",
    "nocorrect",
    "exec",
    "-",
];

/// What the lines of zsh code `text` name.
pub(super) fn named(text: &str) -> Named {
    let mut named = Named::default();
    for line in text.lines() {
        if line.trim_start().starts_with('#') {
            continue;
        }
        for (at, _) in options(line) {
            named.options[at] += 1;
        }
        named.sources += line
            .split([';', '&', '|', '(', '{', '`'])
            .filter(|piece| {
                let mut words = piece
                    .split_whitespace()
                    .skip_while(|word| BEFORE_COMMAND.contains(word));
                matches!(words.next(), Some("source" | "."))
            })
            .count();
        named.zdotdirs += zdotdir_writes(line);
    }
    named
}

/// The options that `text` names, by their place in [`super::OPTIONS`], in
/// any word of it and either form.
pub(super) fn options(text: &str) -> impl Iterator<Item = (usize, bool)> + '_ {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter_map(option)
}

/// How often `text` names `ZDOTDIR` otherwise than to read it: anywhere but
/// after `$` or `${` (with a `#`, `+`, `=`, `~` or `^` between), and in
/// `${ZDOTDIR=...}`, `${ZDOTDIR:=...}` or `${ZDOTDIR::=...}`.
pub(super) fn zdotdir_writes(text: &str) -> usize {
    let name = |c: char| c.is_ascii_alphanumeric() || c == '_';
    text.match_indices("ZDOTDIR")
        .filter(|&(at, found)| {
            let before = &text[..at];
            let after = &text[at + found.len()..];
            if before.chars().next_back().is_some_and(name)
                || after.chars().next().is_some_and(name)
            {
                return false;
            }
            let before = before.trim_end_matches(['#', '+', '=', '~', '^']);
            let braced = before.ends_with("${");
            let read = braced || before.ends_with('$');
            !read
                || (braced
                    && (after.starts_with('=')
                        || after.starts_with(":=")
                        || after.starts_with("::=")))
        })
        .count()
}
