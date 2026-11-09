// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What a file does to where zsh finds the programs it runs by name, as the
//! walk reads it: the directories it puts in `PATH`, as an array of them
//! (`path=(...)`), an element (`path+=dir`) or a part of `PATH`'s value
//! (`PATH=dir:$PATH`), and the programs a `hash` or the `commands`
//! parameter names for a command (`hash locale=~/bin/locale`), which zsh
//! runs by that name wherever they are.

use super::super::lexer::Word;
use super::command::assigned;
use super::fpath::{Given, holds_tied};
use super::{Event, PathChange, Walker};

/// A part of `value`, a value given `path` or `PATH` in `word`, as a word of
/// its own: it expands where it holds a `$` or a backquote.
fn part(value: &str, word: &Word) -> Word {
    let expands = value.contains(['$', '`']);
    Word {
        text: value.to_string(),
        expands,
        quoted: word.quoted,
        bare: word.bare && expands,
    }
}

impl Walker<'_> {
    /// The event of `word`, an element given `path` where `given` says,
    /// unless it stands for what `path` or `PATH` holds already
    /// ([`holds_tied`]: `$path`, `${path[@]}`, `$PATH` as a part of `PATH`'s
    /// value); a loop's variable stands for each item the check can list.
    /// Either, in an array, may split into others
    /// ([`PathChange::Splits`]).
    pub(super) fn path_dir(&mut self, word: &Word, given: Given) {
        let array = given == Given::Array;
        if holds_tied(word, given, "path", "PATH") {
            if array || word.text.ends_with(']') && !word.text.starts_with("${") {
                self.events
                    .push(Event::Path(PathChange::Splits(word.text.clone())));
            }
            return;
        }
        if let Some(items) = Self::variable(word)
            .and_then(|var| self.loop_items(var))
            .map(<[String]>::to_vec)
        {
            if array {
                self.events
                    .push(Event::Path(PathChange::Splits(word.text.clone())));
            }
            for text in items {
                self.events.push(Event::Path(PathChange::Dir(Word {
                    text,
                    ..Word::default()
                })));
            }
            return;
        }
        self.events.push(Event::Path(PathChange::Dir(word.clone())));
    }

    /// The events of `items`, the elements of an array given `path`
    /// (`path=(...)`, `path+=(...)`, `path[1,0]=(...)`): each is a directory
    /// zsh may look in, wherever the array puts it.
    pub(super) fn path_items(&mut self, items: &[Word]) {
        for item in items {
            self.path_dir(item, Given::Array);
        }
    }

    /// The events of `word` when it sets `path` or `PATH`, or declares one
    /// as it is (`typeset -U path`, `export PATH`); whether it does. An
    /// element given `path` is one directory, whatever its subscript
    /// (`path+=~/bin`, `path[1]=~/bin`); `PATH`'s value is parted at each
    /// `:`, and a part that an append or a subscript joins to a directory it
    /// held is one the check cannot follow (`PATH+=x`, `PATH[1,0]=x`), but
    /// for an append that starts with a `:` (`PATH+=:~/bin`).
    pub(super) fn path_assignment(&mut self, word: &Word) -> bool {
        let (target, value) = match word.text.split_once('=') {
            Some((target, value)) => (target, Some(value)),
            None => (word.text.as_str(), None),
        };
        let name = assigned(target);
        if !matches!(name, "path" | "PATH") {
            return false;
        }
        self.paths += 1;
        self.mention(&word.text);
        let Some(value) = value else {
            return true;
        };
        if name == "path" {
            self.path_dir(&part(value, word), Given::Value);
            return true;
        }
        let append = target.ends_with('+');
        if target.contains('[') || (append && !value.starts_with(':')) {
            self.events
                .push(Event::Path(PathChange::Unfollowed(word.text.clone())));
            return true;
        }
        let parts: Vec<&str> = value.split(':').collect();
        // An append's first part is what joins its `:` to the value.
        for text in &parts[usize::from(append)..] {
            self.path_dir(&part(text, word), Given::Parts);
        }
        true
    }

    /// The events of `word` when it sets or declares `commands`, zsh's
    /// table of the programs it runs for each command name
    /// (`commands[locale]=~/bin/locale`); whether it does.
    pub(super) fn commands_assignment(&mut self, word: &Word) -> bool {
        let target = word
            .text
            .split_once('=')
            .map_or(word.text.as_str(), |(target, _)| target);
        if assigned(target) != "commands" {
            return false;
        }
        self.paths += 1;
        self.mention(&word.text);
        if word.text.contains('=') {
            self.events
                .push(Event::Path(PathChange::Hashed(word.text.clone())));
        }
        true
    }

    /// The events of a `hash` of `args`: one that names a program for a
    /// command (`hash locale=~/bin/locale`), which zsh then runs by that name,
    /// or whose words an expansion, brace expansion or a glob may make; with
    /// `-d` it names directories (`hash -d proj=~/src`), which run nothing.
    pub(super) fn hash(&mut self, args: &[Word]) {
        self.paths += 1;
        let mut directories = false;
        let mut options = true;
        let mut names = false;
        for arg in args {
            if arg.expands || arg.bare {
                names = true;
                continue;
            }
            if options && arg.text.len() > 1 && arg.text.starts_with('-') {
                if arg.text == "--" {
                    options = false;
                } else {
                    directories |= arg.text.contains('d');
                }
                continue;
            }
            options = false;
            names |= arg.text.contains('=');
        }
        if names && !directories {
            let words: Vec<&str> = args.iter().map(|arg| arg.text.as_str()).collect();
            self.events.push(Event::Path(PathChange::Hashed(format!(
                "hash {}",
                words.join(" ")
            ))));
        }
    }
}
