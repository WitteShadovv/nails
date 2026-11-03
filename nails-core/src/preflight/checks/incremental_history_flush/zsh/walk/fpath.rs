// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The directories a file adds to `fpath`, where zsh looks for the functions
//! it autoloads, as the walk reads them: an array of them, an element, a part
//! of `FPATH`, and NixOS's loop over the Nix profiles.

use super::super::lexer::Word;
use super::command::assigned;
use super::{Event, Frame, Walker};

/// Whether `text` stands for what `fpath` or `FPATH` holds, or some of it:
/// `$fpath`, `${fpath[@]}`, `${(@)fpath}`, `${fpath[1]}`, `${fpath:#pat}`;
/// not a directory made from it (`${fpath[1]}/sub`, `${fpath/a/b}`).
fn holds_fpath(text: &str) -> bool {
    let Some(rest) = text.strip_prefix('$') else {
        return false;
    };
    let (inner, braced) = match rest.strip_prefix('{') {
        Some(braced) => match braced.strip_suffix('}') {
            Some(inner) if !inner.contains(['{', '}', '$']) => (inner, true),
            _ => return false,
        },
        None => (rest, false),
    };
    let inner = match inner.strip_prefix('(') {
        Some(flagged) if braced => match flagged.split_once(')') {
            Some((_, name)) => name,
            None => return false,
        },
        _ => inner,
    };
    let end = inner
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(inner.len());
    let (name, after) = inner.split_at(end);
    let subscript =
        after.starts_with('[') && after.ends_with(']') && !after[1..after.len() - 1].contains(']');
    matches!(name, "fpath" | "FPATH")
        && (after.is_empty() || subscript || (braced && after.starts_with(":#")))
}

impl Walker<'_> {
    /// The event of `word`, an element added to `fpath`, unless it stands
    /// for what `fpath` holds already ([`holds_fpath`]); a loop's variable
    /// stands for each item the check can list.
    pub(super) fn fpath_dir(&mut self, word: &Word, first: bool) {
        if holds_fpath(&word.text) {
            return;
        }
        if let Some(items) = Self::variable(word).and_then(|var| self.loop_items(var)) {
            let dirs: Vec<Event> = items
                .iter()
                .map(|text| Event::Fpath {
                    dir: Some(Word {
                        text: text.clone(),
                        expands: false,
                    }),
                    first,
                })
                .collect();
            self.events.extend(dirs);
            return;
        }
        self.events.push(Event::Fpath {
            dir: Some(word.clone()),
            first,
        });
    }

    /// The events of `items` assigned to `fpath` as an array, or appended to
    /// it (`append`): those before what `fpath` held (`$fpath`), or all
    /// where it held nothing they keep, come first ([`Event::Fpath`]).
    pub(super) fn fpath_items(&mut self, items: &[Word], append: bool) {
        let held = items.iter().position(|item| holds_fpath(&item.text));
        for (at, item) in items.iter().enumerate() {
            let first = !append && held.is_none_or(|held| at < held);
            self.fpath_dir(item, first);
        }
    }

    /// The events of the `fpath` assignment NixOS's `/etc/zshenv` makes in
    /// its loop over the profiles, `fpath=($p/share/zsh/site-functions
    /// $p/share/zsh/$ZSH_VERSION/functions $p/share/zsh/vendor-completions
    /// $fpath)`, when `items` are those and the loop is that one: each of
    /// the three directories under every profile, in front of the others
    /// ([`Event::ProfileFpath`]). Whether they are.
    pub(super) fn profiles_fpath(&mut self, items: &[Word]) -> bool {
        const RESTS: [&str; 3] = [
            "/share/zsh/site-functions",
            "/share/zsh/$ZSH_VERSION/functions",
            "/share/zsh/vendor-completions",
        ];
        let in_loop = self
            .frames
            .last()
            .is_some_and(|open| matches!(open.frame, Frame::Loop { profiles: true, .. }));
        let texts: Vec<&str> = items.iter().map(|item| item.text.as_str()).collect();
        let written: Vec<String> = RESTS.iter().map(|rest| format!("$p{rest}")).collect();
        let exact = texts.len() == 4
            && texts[..3]
                .iter()
                .zip(&written)
                .all(|(text, written)| text == written)
            && texts[3] == "$fpath"
            && items[..3].iter().all(|item| item.expands);
        if !in_loop || !exact || !self.pending.words.is_empty() {
            return false;
        }
        for (rest, written) in RESTS.iter().zip(written) {
            self.events.push(Event::ProfileFpath {
                written,
                rest: (*rest).to_string(),
                first: true,
            });
        }
        true
    }

    /// The events of `word` when it sets `fpath` (`fpath+=dir`,
    /// `fpath[1,0]=dir`) or `FPATH`, whose directories a `:` parts, or
    /// declares one as it is (`typeset -U fpath`); whether it does.
    pub(super) fn fpath_assignment(&mut self, word: &Word) -> bool {
        let (target, value) = match word.text.split_once('=') {
            Some((target, value)) => (target, Some(value)),
            None => (word.text.as_str(), None),
        };
        let name = assigned(target);
        if !matches!(name, "fpath" | "FPATH") {
            return false;
        }
        self.fpaths += 1;
        self.mention(&word.text);
        let parts: Vec<&str> = match value {
            Some(value) if name == "FPATH" => value.split(':').collect(),
            Some(value) => vec![value],
            None => Vec::new(),
        };
        let items: Vec<Word> = parts
            .into_iter()
            .filter(|part| !part.is_empty())
            .map(|part| Word {
                text: part.to_string(),
                expands: part.contains(['$', '`']),
            })
            .collect();
        // `fpath+=dir` appends; `fpath[1,0]=dir` and `fpath[1]=dir` put it
        // in front, and any other element is somewhere after the front.
        let subscript = target.split_once('[').map(|(_, key)| key);
        let append = target.ends_with('+')
            || subscript.is_some_and(|key| !(key.starts_with("1]") || key.starts_with("1,")));
        self.fpath_items(&items, append);
        true
    }
}
