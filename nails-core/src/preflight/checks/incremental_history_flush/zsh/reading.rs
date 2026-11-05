// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What may make zsh read the files' code otherwise than the check reads it:
//! a `histchars` set, whose third character starts a comment in place of `#`
//! (none, when it has no third), so that a line the check leaves out as a
//! comment may run; `RC_QUOTES` and csh's quotes (`CSH_JUNKIE_QUOTES`, which
//! `emulate csh` turns on), which change what a quote holds and so the code
//! an `eval` or an alias's value runs; `IGNORE_BRACES` and
//! `IGNORE_CLOSE_BRACES` (`set -I`, `NO_BRACE_EXPAND`, `emulate sh`), with
//! which a `}` after a command's words is a word of it, so that a function's
//! body ends at a later `}` and holds the code after it; and `ALIAS_FUNC_DEF`
//! (`emulate sh` and `emulate ksh` too), with which zsh puts an alias's
//! value in place of the name of a function defined as `name ()`, which may
//! then be a hook's. Each option counts where a file names it, in either
//! form, as the three the check asks about do, and where none does, zsh
//! reads the code as the check does.

use super::Reader;
use super::backstop::{Forms, code_lines, names_any, whole_words};
use super::walk::Event;
use crate::Filesystem;

/// What the files read may change of how zsh reads code, and what that
/// may then read otherwise ([`super::reading`]).
#[derive(Debug, Default)]
pub(super) struct Reading {
    /// Where a file read may turn `IGNORE_BRACES` or `IGNORE_CLOSE_BRACES`
    /// on, and each command whose words a `}` follows, as written, and
    /// where ([`Event::WordBrace`]).
    braces: Option<String>,
    word_braces: Vec<(String, String)>,
    /// Where a file read may turn `ALIAS_FUNC_DEF` on, each function defined
    /// as `name ()` and where ([`Event::NamedBody`]), and the regular aliases
    /// the files define.
    alias_func_def: Option<String>,
    named_bodies: Vec<(String, String)>,
    regular_aliases: Vec<String>,
}

/// Whether `text`, zsh code, may run an `emulate` of a mode whose first
/// letter past one `r` is among `modes`, as zsh picks a mode by it: past the
/// flags of an `emulate` (and the option after `-o` or `+o`), its first
/// word, or one an expansion, brace expansion or a glob makes, which may be
/// any. A line that is a comment is left out.
fn emulates(text: &str, modes: &[char]) -> bool {
    let part = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '/' | '-');
    code_lines(text).any(|line| {
        line.match_indices("emulate").any(|(at, found)| {
            if line[..at].chars().next_back().is_some_and(part)
                || line[at + found.len()..].chars().next().is_some_and(part)
            {
                return false;
            }
            let rest = line[at + found.len()..]
                .split([';', '&', '|', '(', ')', '`'])
                .next()
                .unwrap_or_default();
            let mut words = rest.split_whitespace();
            while let Some(word) = words.next() {
                let word = word.trim_matches(['\'', '"', '\\']);
                if matches!(word, "-o" | "+o") {
                    words.next();
                } else if !word.starts_with(['-', '+']) {
                    let mode = word.strip_prefix('r').unwrap_or(word);
                    return word.contains(['$', '`', '{', '*', '?', '['])
                        || mode.starts_with(modes);
                }
            }
            false
        })
    })
}

/// Whether `text`, zsh code, runs a `set`, a `setopt` or an `unsetopt` with
/// a word of flags that holds `letter`, an option's (`set -I` for
/// `IGNORE_BRACES`). A line that is a comment is left out.
fn sets_letter(text: &str, letter: char) -> bool {
    code_lines(text).any(|line| {
        ["set", "setopt", "unsetopt"]
            .iter()
            .any(|command| whole_words(line, command) > 0)
            && line.split_whitespace().any(|word| {
                let word = word.trim_matches(['\'', '"', '\\']);
                word.len() > 1
                    && word.starts_with(['-', '+'])
                    && word[1..].chars().all(|c| c.is_ascii_alphanumeric())
                    && word.contains(letter)
            })
    })
}

impl<F: Filesystem> Reader<'_, F> {
    /// Note what `text`, the code of the file at `place`, in its forms
    /// `forms`, may change of how zsh reads code ([`super::reading`]): a
    /// `histchars` it sets, and the `RC_QUOTES` and csh's quotes it names,
    /// are doubts at once; where it may turn `IGNORE_BRACES`,
    /// `IGNORE_CLOSE_BRACES` or `ALIAS_FUNC_DEF` on is noted for
    /// [`Reader::reading_doubts`].
    pub(super) fn reading(&mut self, text: &str, forms: &Forms, place: &str) {
        if ["histchars", "HISTCHARS"]
            .iter()
            .any(|name| forms.writes(name) > 0)
        {
            self.doubt(format!(
                "it cannot tell which lines of the files zsh runs, as {place} sets histchars, \
                 whose third character starts a comment in place of `#`"
            ));
        }
        if names_any(text, &["rcquotes", "cshjunkiequotes"]) || emulates(text, &['c']) {
            self.doubt(format!(
                "it cannot read the quotes of the files as zsh may, as {place} may turn \
                 RC_QUOTES or CSH_JUNKIE_QUOTES on, which change what a quote holds"
            ));
        }
        if self.reading.braces.is_none()
            && (names_any(text, &["ignorebraces", "ignoreclosebraces", "braceexpand"])
                || sets_letter(text, 'I')
                || emulates(text, &['s', 'b']))
        {
            self.reading.braces = Some(place.to_string());
        }
        if self.reading.alias_func_def.is_none()
            && (names_any(text, &["aliasfuncdef"]) || emulates(text, &['s', 'b', 'k']))
        {
            self.reading.alias_func_def = Some(place.to_string());
        }
    }

    /// Note an event of the file at `place` that zsh may read otherwise
    /// ([`Event::WordBrace`], [`Event::NamedBody`], [`Event::RegularAlias`]).
    pub(super) fn reading_event(&mut self, event: Event, place: &str) {
        let reading = &mut self.reading;
        match event {
            Event::WordBrace(command) => {
                let entry = (command, place.to_string());
                if !reading.word_braces.contains(&entry) {
                    reading.word_braces.push(entry);
                }
            }
            Event::NamedBody(name) => reading.named_bodies.push((name, place.to_string())),
            Event::RegularAlias(name) if !reading.regular_aliases.contains(&name) => {
                reading.regular_aliases.push(name);
            }
            _ => {}
        }
    }

    /// Note the doubts of what zsh may read otherwise, once every file is
    /// read: each `}` after a command's words where a file may turn
    /// `IGNORE_BRACES` or `IGNORE_CLOSE_BRACES` on, and each function defined
    /// as `name ()` where an alias of that name is defined and a file may turn
    /// `ALIAS_FUNC_DEF` on. Of zsh's own functions the check reads by their
    /// bytes only `add-zle-hook-widget` holds such a `}`, and zsh 5.9.2 then
    /// cannot load it (a parse error), so that it makes no hook.
    pub(super) fn reading_doubts(&mut self) {
        let reading = std::mem::take(&mut self.reading);
        if let Some(set) = &reading.braces {
            for (command, place) in &reading.word_braces {
                self.doubt(format!(
                    "it cannot tell where the code that `{command}` in {place} ends with its `}}` \
                     ends, as {set} may turn IGNORE_BRACES or IGNORE_CLOSE_BRACES on, with which \
                     that `}}` is a word of the command"
                ));
            }
        }
        if let Some(set) = &reading.alias_func_def {
            for (name, place) in &reading.named_bodies {
                if reading.regular_aliases.contains(name) {
                    self.doubt(format!(
                        "it cannot tell which function `{name} ()` in {place} defines, as {set} \
                         may turn ALIAS_FUNC_DEF on, with which zsh puts the value of the alias \
                         `{name}` in place of its name"
                    ));
                }
            }
        }
    }
}
