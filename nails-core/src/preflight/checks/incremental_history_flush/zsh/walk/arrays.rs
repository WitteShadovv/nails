// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The arrays a file assigns, as the walk reads them (`name=(items)`,
//! `name+=(items)`): the hook functions, aliases, functions, files and
//! options they set, the directories they put in `fpath`, and the literal
//! lists a later loop runs over.

use super::super::lexer::Word;
use super::{Event, HOOKS, Walker, command, fpath};

impl Walker<'_> {
    /// The events of an array's assignment, `name=(items)`, or of what
    /// appends to it, when `name` ends with `+`.
    pub(super) fn array(&mut self, name: String, items: Vec<Word>) {
        for item in &items {
            self.mention_word(item);
        }
        let (name, append) = match name.strip_suffix('+') {
            Some(name) => (name.to_string(), true),
            None => (name, false),
        };
        if name == "options" {
            self.every_option(&format!("{name}=(...)"));
        } else {
            self.listed_parameter(&name, &format!("{name}=(...)"));
        }
        // The functions zsh runs as hooks (`precmd_functions+=(name)`).
        if let Some(hook) = name.strip_suffix("_functions")
            && HOOKS.contains(&hook)
        {
            self.hooks += 1;
            for item in &items {
                self.hook_value(item);
            }
        }
        let functions = matches!(name.as_str(), "functions" | "dis_functions");
        let aliases = command::ALIAS_PARAMETERS.contains(&name.as_str());
        if functions || aliases {
            // Function bodies or alias values, each beside its name.
            self.function_params += usize::from(functions);
            self.alias_params += usize::from(aliases);
            self.events.push(Event::Doubt(format!(
                "it cannot tell what code `{name}=(...)` in {} gives",
                self.place
            )));
        }
        if name == "mapfile" {
            // zsh/mapfile writes each file its keys name.
            self.events.push(Event::Doubt(format!(
                "it cannot tell which files `mapfile=(...)` in {} writes",
                self.place
            )));
        }
        if name == "options"
            && let Some(item) = items.iter().find(|item| item.expands)
        {
            // An option whose name an expansion makes.
            self.events.push(Event::Doubt(format!(
                "it cannot tell which options `options=(... {} ...)` in {} sets",
                item.text, self.place
            )));
        }
        self.counted();
        if name == "FPATH" {
            // A scalar's value as an array: what zsh makes of it the check
            // cannot follow.
            self.fpaths += 1;
            self.events.push(Event::Fpath {
                dir: None,
                first: false,
                in_function: false,
            });
        } else if name == "fpath" {
            self.fpaths += 1;
            if append || !self.profiles_fpath(&items) {
                self.fpath_items(&items, append, fpath::Given::Array);
            }
        }
        let literal: Option<Vec<String>> = items
            .iter()
            .map(|item| (!item.expands).then(|| item.text.clone()))
            .collect();
        match literal {
            Some(literal)
                if self.pending.words.is_empty()
                    && self.certain(self.pending.after_condition, self.pending.piped) =>
            {
                if !append {
                    self.arrays.insert(name, literal);
                } else if let Some(known) = self.arrays.get_mut(&name) {
                    known.extend(literal);
                }
            }
            _ => {
                self.arrays.remove(&name);
            }
        }
    }
}
