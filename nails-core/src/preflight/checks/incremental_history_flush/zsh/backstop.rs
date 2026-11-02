// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What a startup file's lines name, counted without the lexer and
//! wherever it stands: the options that write each command line to the
//! history file, `source`, a `.` with a word after it, `eval`, an alias that
//! stands for `.`, and the `ZDOTDIR` settings. The walk counts the same as it
//! reads them as code it follows, and what the lines name beyond that is what
//! it did not follow: an option named there counts as on, and the rest is a
//! doubt.
//!
//! Only a line whose first character that is not a blank is `#` is left out,
//! so an option a comment at the end of a line names counts as on too, and a
//! `source` or `eval` anywhere else than in a command the walk follows, as in
//! a string, an `echo`, an alias or a here-document, is a doubt.

use super::walk::option;

/// What the lines of a file name, outside the lines that are a comment.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct Named {
    /// Each of [`super::OPTIONS`], in any spelling and in its `no` form too.
    pub(super) options: [usize; 3],
    /// `source`, a `.` with a word after it, and a `.` an alias stands for.
    pub(super) sources: usize,
    /// `eval`.
    pub(super) evals: usize,
    /// `ZDOTDIR` where it is not read ([`zdotdir_writes`]).
    pub(super) zdotdirs: usize,
}

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
        named.sources += whole_words(line, "source") + dot_words(line) + alias_dots(line);
        named.evals += whole_words(line, "eval");
        named.zdotdirs += zdotdir_writes(line);
    }
    named
}

/// How often `word` stands in `line` as a word of its own: with no letter,
/// digit, `_`, `.`, `/` or `-` beside it.
fn whole_words(line: &str, word: &str) -> usize {
    let part = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '/' | '-');
    line.match_indices(word)
        .filter(|&(at, found)| {
            !line[..at].chars().next_back().is_some_and(part)
                && !line[at + found.len()..].chars().next().is_some_and(part)
        })
        .count()
}

/// How often a `.` stands in `line` as a word of its own, quotes and a
/// backslash around it taken off, with another word after it, as in
/// `. file`; not before an option or a `]]` (`find . -name`, `[[ -d . ]]`).
fn dot_words(line: &str) -> usize {
    line.split([';', '&', '|', '(', ')', '{', '}', '`'])
        .map(|piece| {
            let words: Vec<&str> = piece
                .split_whitespace()
                .map(|word| word.trim_matches(['\'', '"', '\\']))
                .collect();
            words
                .windows(2)
                .filter(|pair| {
                    pair[0] == "." && !pair[1].starts_with('-') && !matches!(pair[1], "]]" | "]")
                })
                .count()
        })
        .sum()
}

/// How often an alias in `line` stands for `.`, past the precommands before
/// it, its quotes and backslashes taken off (`alias s=.`, `alias s='. f'`,
/// `alias s='builtin .'`, `alias s=\.`, `aliases[s]=.`).
fn alias_dots(line: &str) -> usize {
    if whole_words(line, "alias") == 0 && !line.contains("aliases[") {
        return 0;
    }
    line.match_indices('=')
        .filter(|&(at, _)| {
            let value = line[at + 1..].replace(['\'', '"', '\\'], " ");
            value
                .split_whitespace()
                .find(|word| {
                    !matches!(
                        *word,
                        "builtin" | "command" | "noglob" | "nocorrect" | "exec" | "-"
                    )
                })
                .is_some_and(|word| word == "." || word.starts_with(".;"))
        })
        .count()
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
