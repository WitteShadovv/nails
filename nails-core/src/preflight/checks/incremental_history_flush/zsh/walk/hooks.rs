// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The functions a file makes hooks, which zsh runs as each command is
//! entered or ends, or as keys are pressed, as the walk reads them:
//! `add-zsh-hook`, `add-zle-hook-widget`, the `zle` widgets, the arrays of
//! hook functions, and a function copied to a hook's name.

use super::super::lexer::Word;
use super::{Event, HOOKS, Walker};

/// Whether `widget`, a widget's name as written, may be one zsh runs by its
/// name as each line is entered or edited (`zle-line-init`,
/// `zle-line-finish`): one that starts with `zle-`, or that an expansion
/// makes.
fn special_widget(widget: &Word) -> bool {
    widget.expands || widget.text.contains(['$', '`']) || widget.text.starts_with("zle-")
}

/// The words among `args`, the words after the builtin `command`, that name
/// a parameter it sets to a value it reads or makes: `print -v`'s and
/// `printf -v`'s, `read`'s and `getln`'s names, `vared`'s, `getopts`'s
/// second word, `zstyle -s`'s, `-a`'s, `-b`'s and `-g`'s, `zformat -f`'s and
/// `-a`'s, and `strftime -s`'s.
pub(super) fn targets<'a>(command: &str, args: &'a [Word]) -> Vec<&'a Word> {
    // The word after the flags whose last is `flag` (`-v`, `-rv`).
    let after = |flag: char| {
        args.iter()
            .position(|word| word.text.starts_with('-') && word.text.ends_with(flag))
            .and_then(|at| args.get(at + 1))
            .into_iter()
            .collect()
    };
    let names = || {
        args.iter()
            .filter(|word| !word.text.starts_with('-'))
            .collect()
    };
    match command {
        "print" | "printf" => after('v'),
        "read" | "getln" | "vared" => names(),
        "getopts" => args.get(1).into_iter().collect(),
        "zstyle" => match args.first().map(|flag| flag.text.as_str()) {
            Some("-s" | "-a" | "-b") => args.get(3).into_iter().collect(),
            Some("-g") => args.get(1).into_iter().collect(),
            _ => Vec::new(),
        },
        "zformat" => match args.first().map(|flag| flag.text.as_str()) {
            Some("-f" | "-a") => args.get(1).into_iter().collect(),
            _ => Vec::new(),
        },
        "strftime" => after('s'),
        _ => Vec::new(),
    }
}

/// Whether `name` is an array of the functions zsh runs as hooks
/// (`precmd_functions`).
pub(super) fn hook_array(name: &str) -> bool {
    name.strip_suffix("_functions")
        .is_some_and(|hook| HOOKS.contains(&hook))
}

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
        let flag = args.first().map(|flag| flag.text.as_str());
        let function = match command {
            // `add-zsh-hook hook function`, `add-zle-hook-widget hook widget`.
            "add-zsh-hook" | "add-zle-hook-widget" => words.get(1),
            // `zle -N widget [function]`.
            _ if flag == Some("-N") => words.get(1).or(words.first()),
            // `zle -C widget builtin function`: a completion widget, which
            // zsh runs as each line is entered when it is named for a hook
            // (`zle-line-finish`), and otherwise as a key bound to it is
            // pressed, as completion runs.
            _ if flag == Some("-C") => words
                .get(2)
                .filter(|_| words.first().is_none_or(|widget| special_widget(widget))),
            // `zle -F fd handler`: run as the descriptor has input.
            _ if flag.is_some_and(|flag| flag.starts_with("-F")) => {
                words.last().filter(|_| words.len() > 1)
            }
            _ => None,
        };
        if command == "zle"
            && flag == Some("-A")
            && words.get(1).is_some_and(|widget| special_widget(widget))
        {
            // `zle -A old zle-line-finish`: the widget runs as each line is
            // entered, with the function of another.
            let words: Vec<&str> = args.iter().map(|arg| arg.text.as_str()).collect();
            self.events.push(Event::Doubt(format!(
                "it cannot tell which function `zle {}` in {} makes run as each line is entered",
                words.join(" "),
                self.place
            )));
            return;
        }
        if command == "zle" && flag == Some("-U") {
            // `zle -U string`: what the string types runs as the line typed.
            for typed in args.iter().skip(1) {
                if typed.expands || typed.text.contains(['$', '`']) {
                    self.events.push(Event::Doubt(format!(
                        "it cannot tell what `zle -U {}` in {} types",
                        typed.text, self.place
                    )));
                } else {
                    let hook = format!("zle -U {}", typed.text);
                    self.events.push(Event::Hook(hook.clone()));
                    self.nested_in(&typed.text, false, Some(hook));
                }
            }
            return;
        }
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

    /// The events of `word`, a function a hook's array is given
    /// (`precmd_functions[1]=name`, `set -A precmd_functions name`): a hook,
    /// or a doubt when an expansion names it.
    pub(super) fn hook_value(&mut self, word: &Word) {
        if word.expands || word.text.contains(['$', '`']) {
            self.events.push(Event::Doubt(format!(
                "it cannot tell which function `{}` in {} makes a hook",
                word.text, self.place
            )));
        } else if !word.text.is_empty() {
            self.events.push(Event::Hook(word.text.clone()));
        }
    }

    /// The events of a `functions -c` of `args`, which copies a function to
    /// another name, whose code it then runs as that function: a call of the
    /// first by the second, so that it counts as a hook where the second is
    /// one; one an expansion names is a doubt.
    pub(super) fn copy_function(&mut self, args: &[Word]) {
        let names: Vec<&Word> = args
            .iter()
            .filter(|arg| !arg.text.starts_with('-'))
            .collect();
        match names.as_slice() {
            [from, to] if !from.expands && !to.expands => {
                self.events.push(Event::Define(to.text.clone()));
                self.events.push(Event::Call {
                    name: from.text.clone(),
                    args: Vec::new(),
                    function: Some(to.text.clone()),
                });
            }
            _ => {
                let words: Vec<&str> = args.iter().map(|arg| arg.text.as_str()).collect();
                self.events.push(Event::Doubt(format!(
                    "it cannot tell which function `functions {}` in {} copies to which",
                    words.join(" "),
                    self.place
                )));
            }
        }
    }
}
