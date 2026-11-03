// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The functions a file makes hooks, which zsh runs as each command is
//! entered or ends, or as keys are pressed, as the walk reads them:
//! `add-zsh-hook`, `add-zle-hook-widget` and the `zle` widgets.

use super::super::lexer::Word;
use super::{Event, Walker};

impl Walker<'_> {
    /// The events of an `add-zsh-hook` or a `zle -N` of `args`: the function
    /// it makes a hook, which zsh runs as commands are entered or end, or as
    /// a key is pressed ([`Event::Hook`]); one an expansion names is a doubt.
    pub(super) fn hook(&mut self, command: &str, args: &[Word]) {
        for arg in args {
            self.mention(&arg.text);
        }
        let words: Vec<&Word> = args
            .iter()
            .filter(|arg| !arg.text.starts_with('-'))
            .collect();
        let function = match command {
            // `add-zsh-hook hook function`, `add-zle-hook-widget hook widget`.
            "add-zsh-hook" | "add-zle-hook-widget" => words.get(1),
            // `zle -N widget [function]`.
            _ if args.first().is_some_and(|flag| flag.text == "-N") => {
                words.get(1).or(words.first())
            }
            _ => None,
        };
        match function {
            Some(function) if function.expands => self.events.push(Event::Doubt(format!(
                "it cannot tell which function `{command} ... {}` in {} makes a hook",
                function.text, self.place
            ))),
            Some(function) => {
                self.events.push(Event::Hook(function.text.clone()));
                // `add-zsh-hook` and `add-zle-hook-widget` autoload the
                // function they add, which zsh then loads from `fpath`
                // unless the files define it.
                let adds = !args
                    .iter()
                    .any(|arg| arg.text.starts_with('-') && arg.text.contains(['d', 'D', 'L']));
                if command != "zle" && adds {
                    self.events.push(Event::Autoload((*function).clone()));
                }
            }
            None => {}
        }
    }
}
