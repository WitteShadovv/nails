// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What one simple command of a startup file does, as the walk reads it: the
//! options a `setopt`, `unsetopt` or `set -o` turns on or off, the files a
//! `source` or `.` reads, what an `eval` of words the walk can read runs, the
//! `ZDOTDIR` and `XDG_CONFIG_HOME` an assignment sets, and the options any
//! other word names.

use super::super::OH_MY_ZSH;
use super::super::backstop::zdotdir_writes;
use super::super::lexer::{Word, is_name};
use super::{Event, Frame, Walker, mentioned, option, walk_text};

/// The precommand words that run the word after them as the command.
const PRECOMMANDS: &[&str] = &[
    "builtin",
    "command",
    "noglob",
    "nocorrect",
    "exec",
    "-",
    "time",
    "!",
];

impl Walker<'_> {
    /// The items of the innermost loop over `var`, when the check can list
    /// them.
    pub(super) fn loop_items(&self, var: &str) -> Option<&[String]> {
        self.frames
            .iter()
            .rev()
            .find_map(|open| match &open.frame {
                Frame::Loop {
                    var: Some(name),
                    items,
                    ..
                } if name == var => Some(items.as_deref()),
                _ => None,
            })?
    }

    /// The list `words` stands for in a `for` header, when the check can list
    /// it: literal words, or one array the file assigned literally.
    pub(super) fn list(&self, words: &[Word]) -> Option<Vec<String>> {
        if let [word] = words
            && word.expands
        {
            let name = word
                .text
                .trim_start_matches('$')
                .trim_start_matches('{')
                .trim_end_matches('}')
                .trim_end_matches("[@]")
                .trim_end_matches("[*]");
            return self.arrays.get(name).cloned();
        }
        words
            .iter()
            .map(|word| (!word.expands).then(|| word.text.clone()))
            .collect()
    }

    /// The name of the variable `word` expands to, when it is nothing but
    /// one (`$opt`, `${opt}`).
    pub(super) fn variable(word: &Word) -> Option<&str> {
        let text = word.text.strip_prefix('$')?;
        let name = text
            .strip_prefix('{')
            .and_then(|text| text.strip_suffix('}'))
            .unwrap_or(text);
        is_name(name).then_some(name)
    }

    /// The event of a `setopt`-like command turning the option `word` names
    /// on (`on`), or of none when it names another.
    pub(super) fn set(&mut self, word: &str, on: bool, unconditional: bool) {
        if let Some((option, named_on)) = option(word) {
            self.events.push(Event::Set {
                option,
                on: on == named_on,
                unconditional,
            });
        }
    }

    /// Note every option `text` names as a mention.
    pub(super) fn mention_options(&mut self, text: &str) {
        let found: Vec<usize> = mentioned(text).collect();
        self.events.extend(found.into_iter().map(Event::Mention));
    }

    /// Note what a word of the file's code names: its options, and a
    /// `ZDOTDIR` it may set otherwise than by an assignment the walk reads
    /// (`${ZDOTDIR:=...}`, `ZDOTDIR+=...`), which is a doubt.
    pub(super) fn mention(&mut self, text: &str) {
        self.mention_options(text);
        if ["ZDOTDIR=", "ZDOTDIR:=", "ZDOTDIR::=", "ZDOTDIR+="]
            .iter()
            .any(|form| text.contains(form))
        {
            self.zdotdirs += zdotdir_writes(text);
            self.events.push(Event::Doubt(format!(
                "it cannot follow where `{text}` in {} sets ZDOTDIR",
                self.place
            )));
        }
    }

    /// The events of one simple command, `words`, which ran `after` a
    /// condition (`&&`, `||`) or not, and in a pipeline or the background or
    /// not.
    pub(super) fn command(&mut self, words: Vec<Word>, after_condition: bool, piped: bool) {
        let unconditional = self.certain(after_condition, piped);
        let mut words = words.into_iter().peekable();
        // Assignments before the command word.
        while let Some(word) = words.next_if(|word| word.text.contains('=')) {
            self.assignment(&word, unconditional);
        }
        while words
            .next_if(|word| PRECOMMANDS.contains(&word.text.as_str()))
            .is_some()
        {}
        let Some(command) = words.next() else {
            return;
        };
        let args: Vec<Word> = words.collect();
        if command.expands && command.text.starts_with(['$', '`']) {
            // `$c`, `${:-source}`, `$(print source)`: any command, a
            // `source` among them.
            self.events.push(Event::Doubt(format!(
                "it cannot tell what command `{}` in {} runs",
                command.text, self.place
            )));
            for arg in &args {
                self.mention(&arg.text);
            }
            return;
        }
        match command.text.as_str() {
            "setopt" | "unsetopt" => {
                let on = command.text == "setopt";
                for arg in &args {
                    if let Some(items) = Self::variable(arg).and_then(|var| self.loop_items(var)) {
                        let items = items.to_vec();
                        for item in items {
                            self.set(&item, on, unconditional);
                        }
                    } else if arg.expands || arg.text.starts_with(['-', '+']) {
                        self.events.push(Event::Doubt(format!(
                            "it cannot tell which options `{} {}` in {} turns on",
                            command.text, arg.text, self.place
                        )));
                    } else {
                        self.set(&arg.text, on, unconditional);
                    }
                }
            }
            "set" => {
                let mut args = args.iter();
                while let Some(arg) = args.next() {
                    if matches!(arg.text.as_str(), "-o" | "+o")
                        && let Some(name) = args.next()
                    {
                        if name.expands {
                            self.events.push(Event::Doubt(format!(
                                "it cannot tell which options `set {} {}` in {} turns on",
                                arg.text, name.text, self.place
                            )));
                        } else {
                            self.set(&name.text, arg.text == "-o", unconditional);
                        }
                    } else {
                        self.mention(&arg.text);
                    }
                }
            }
            "source" | "." => {
                self.sources += 1;
                let mut args = args.into_iter();
                match args.next() {
                    Some(path) if path.text.ends_with(OH_MY_ZSH) => {
                        self.events.push(Event::OhMyZsh);
                    }
                    Some(path) => {
                        self.mention(&path.text);
                        self.events.push(Event::Source {
                            path,
                            unconditional,
                        });
                    }
                    None => self.events.push(Event::Doubt(format!(
                        "it cannot tell what `{}` in {} reads",
                        command.text, self.place
                    ))),
                }
                for arg in args {
                    self.mention(&arg.text);
                }
            }
            "eval" if args.iter().all(|arg| !arg.expands) => {
                // Its words are code the walk reads as zsh would run them.
                let text: Vec<&str> = args.iter().map(|arg| arg.text.as_str()).collect();
                let nested = walk_text(&text.join(" "), self.place);
                self.sources += nested.sources;
                self.evals += 1 + nested.evals;
                self.zdotdirs += nested.zdotdirs;
                self.may_stop |= nested.may_stop;
                let uncertain = !unconditional || nested.confused;
                for mut event in nested.events {
                    if uncertain
                        && let Event::Set { unconditional, .. }
                        | Event::Source { unconditional, .. }
                        | Event::Assign { unconditional, .. } = &mut event
                    {
                        *unconditional = false;
                    }
                    self.events.push(event);
                }
            }
            "return" | "exit" => self.may_stop = true,
            "export" | "typeset" | "declare" | "local" | "readonly" | "integer" => {
                for arg in &args {
                    self.assignment(arg, unconditional);
                }
            }
            _ => {
                self.mention(&command.text);
                for arg in &args {
                    self.mention(&arg.text);
                }
            }
        }
    }

    /// The events of `word` when it assigns `ZDOTDIR` or `XDG_CONFIG_HOME`,
    /// and its mentions.
    pub(super) fn assignment(&mut self, word: &Word, unconditional: bool) {
        let name = match word.text.split_once('=') {
            Some(("ZDOTDIR", _)) => "ZDOTDIR",
            Some(("XDG_CONFIG_HOME", _)) => "XDG_CONFIG_HOME",
            _ => {
                if word.text == "ZDOTDIR" {
                    // Exported or declared as it is.
                    self.zdotdirs += 1;
                }
                self.mention(&word.text);
                return;
            }
        };
        self.zdotdirs += zdotdir_writes(&word.text);
        self.mention_options(&word.text);
        let value = word.text[name.len() + 1..].to_string();
        self.events.push(Event::Assign {
            name,
            value: Word {
                text: value,
                expands: word.expands,
            },
            unconditional,
        });
    }
}
