// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What the walk notes of the list of the commands the check knows to be
//! harmless ([`super::super::known`]): each command none of its forms holds,
//! read past its precommands, and each parameter set that the list does not
//! let be, by an assignment, a builtin, a loop's variable or an expansion
//! that assigns (`${HISTNO::=1}`), as [`Event::Unlisted`], which the reader
//! judges where zsh may run it ([`super::super::reached`]).

use super::super::known::{self, Verdict};
use super::super::lexer::Word;
use super::super::option_words;
use super::command::{Run, assigned};
use super::{Event, Walker};

/// The parameters the expansions in `text`, a word of zsh code, set as zsh
/// expands them (`${NAME=x}`, `${NAME:=x}`, `${NAME::=x}`), past their
/// flags and the `=`, `~` and `^` that split it, take it as a pattern and
/// join it to what is around it (`${(L)NAME:=x}`, `${(AA)=options::=...}`).
fn assigning_expansions(text: &str) -> Vec<&str> {
    let mut found = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find("${") {
        rest = &rest[at + 2..];
        let inner = match rest.strip_prefix('(') {
            Some(flags) => flags.split_once(')').map_or("", |(_, after)| after),
            None => rest,
        };
        let inner = inner.trim_start_matches(['=', '~', '^']);
        let end = inner
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(inner.len());
        let (name, after) = inner.split_at(end);
        let assigns = after.starts_with("::=")
            || after.starts_with(":=")
            || (after.starts_with('=') && !after.starts_with("=="));
        if !name.is_empty() && assigns {
            found.push(name);
        }
    }
    found
}

impl Walker<'_> {
    /// Note the command `command` of `args`, run as `run` says, that the list
    /// of the commands the check knows to be harmless does not hold
    /// ([`known::command`], [`Event::Unlisted`]).
    pub(super) fn listed(&mut self, command: &Word, args: &[Word], run: &Run) {
        let function = self.function();
        let how = known::How {
            outside: run.outside,
            exec: run.exec,
            function: function.as_deref(),
        };
        // A loop's variable over items the walk lists stands for each of
        // them, as `setopt` reads it (`for o in a b; do setopt $o; done`).
        let mut given = Vec::new();
        for arg in args {
            match Self::variable(arg).and_then(|var| self.loop_items(var)) {
                Some(items) if matches!(command.text.as_str(), "setopt" | "unsetopt") => {
                    given.extend(items.iter().map(|item| Word {
                        text: item.clone(),
                        ..Word::default()
                    }));
                }
                _ => given.push(arg.clone()),
            }
        }
        let args = given.as_slice();
        let (name, why) = match known::command(&command.text, args, how) {
            Verdict::Known => return,
            Verdict::Named => (
                Some(command.text.clone()),
                known::outside_program(&command.text),
            ),
            Verdict::Unknown(why) => (None, why),
        };
        self.events.push(Event::Unlisted {
            certain: self.certain_command,
            chain: self.chain,
            alias: !run.unaliased && !command.quoted && command.quoted_at.is_none(),
            function,
            shown: known::shown_command(&command.text, args),
            name,
            words: !args.is_empty(),
            why,
        });
    }

    /// Note a doubt where `shown` sets the parameter `name` and the list does
    /// not let it be ([`known::parameter`]), as zsh may read it otherwise than
    /// the check does: one of the line editor's in a function (`HISTNO`), or
    /// one of zsh's own whose effect the check does not read (`histchars`).
    pub(super) fn listed_parameter(&mut self, name: &str, shown: &str) {
        let function = self.function();
        if let Some(why) = known::parameter(name, function.is_some()) {
            self.events.push(Event::Unlisted {
                function,
                shown: shown.to_string(),
                name: None,
                words: false,
                certain: false,
                chain: None,
                alias: false,
                why,
            });
        }
    }

    /// Note a doubt where the assignment `word` sets a parameter the list
    /// does not let be ([`Walker::listed_parameter`]), or an option by a name
    /// it does not hold (`options[errexit]=on`, [`known::option`]); and where
    /// it may turn `ALIASES` off ([`Event::AliasesOff`]): zsh turns an option
    /// on for the value `on` and off for `off` (`options[aliases]=off`,
    /// `options[noaliases]=on`), and changes none for any other, so a value
    /// an expansion makes or one added to may.
    pub(super) fn listed_assignment(&mut self, word: &Word) {
        let Some((target, value)) = word.text.split_once('=') else {
            return;
        };
        let name = assigned(target);
        if name != "options" {
            self.listed_parameter(name, &word.text);
            return;
        }
        let key = target
            .strip_suffix('+')
            .unwrap_or(target)
            .split_once('[')
            .and_then(|(_, key)| key.strip_suffix(']'));
        if let Some(plain) = key.and_then(option_words::aliases_option) {
            let off = word.expands
                || target.ends_with('+')
                || (plain && value == "off")
                || (!plain && value == "on");
            if off {
                self.events.push(Event::AliasesOff(format!(
                    "{} may turn ALIASES off (`{}`)",
                    self.place, word.text
                )));
            }
        }
        let why = match key {
            Some(key) => known::option(key),
            None => Some("it sets every option at once".to_string()),
        };
        if let Some(why) = why {
            self.events.push(Event::Unlisted {
                function: self.function(),
                shown: word.text.clone(),
                name: None,
                words: false,
                certain: false,
                chain: None,
                alias: false,
                why,
            });
        }
    }

    /// Note the parameters the expansions in `text`, a word of the file's
    /// code that zsh expands, set as zsh expands them and the list does not
    /// let be ([`assigning_expansions`]), and an option that turns `ALIASES`
    /// off by one (`${options[aliases]::=off}`, [`Event::AliasesOff`]).
    pub(super) fn listed_expansions(&mut self, text: &str) {
        for name in assigning_expansions(text) {
            self.listed_parameter(name, text);
            // `${(AA)=options::=aliases off}` sets every option at once.
            if name == "options" {
                self.every_option(text);
            }
        }
        if option_words::expansion_elements(text, "options")
            .iter()
            .any(|key| option_words::aliases_option(key).is_some())
        {
            self.events.push(Event::AliasesOff(format!(
                "{} may turn ALIASES off (`{text}`)",
                self.place
            )));
        }
    }

    /// Note a doubt where `shown` sets every option at once (`options=(...)`,
    /// `set -A options ...`).
    pub(super) fn every_option(&mut self, shown: &str) {
        self.events.push(Event::Unlisted {
            function: self.function(),
            shown: shown.to_string(),
            name: None,
            words: false,
            certain: false,
            chain: None,
            alias: false,
            why: "it sets every option at once".to_string(),
        });
    }
}
