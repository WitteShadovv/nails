// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The functions a file makes hooks, which zsh runs as each command is
//! entered or ends, or as keys are pressed, as the walk reads them:
//! `add-zsh-hook`, `add-zle-hook-widget`, the `zle` widgets, the arrays of
//! hook functions, and a function copied to a hook's name.

use super::super::lexer::Word;
use super::{Event, HOOKS, Input, Walker};

/// Whether `widget`, a widget's name as written, may be one zsh runs by its
/// name as each line is entered or edited (`zle-line-init`,
/// `zle-line-finish`): one that starts with `zle-`, or that an expansion
/// makes.
fn special_widget(widget: &Word) -> bool {
    widget.expands || widget.text.contains(['$', '`']) || widget.text.starts_with("zle-")
}

/// The builtin widgets that complete a word, which the stock `compinit`
/// makes run the completion functions in `fpath` (`_main_complete`), and
/// `menu-select` of zsh/complist.
const COMPLETION_WIDGETS: &[&str] = &[
    "accept-and-menu-complete",
    "complete-word",
    "delete-char-or-list",
    "expand-or-complete",
    "expand-or-complete-prefix",
    "list-choices",
    "menu-complete",
    "menu-expand-or-complete",
    "menu-select",
    "reverse-menu-complete",
];

/// Whether `widget`, a widget's name as written, may complete a word, which
/// runs completion functions the check does not read: one of
/// [`COMPLETION_WIDGETS`], by its name or its builtin's (`.complete-word`),
/// one whose name starts with `_`, as `compinit`'s and `compdef`'s do, or
/// one an expansion names.
pub(super) fn completes(widget: &Word) -> bool {
    let name = widget.text.strip_prefix('.').unwrap_or(&widget.text);
    widget.expands
        || widget.text.contains(['$', '`'])
        || name.starts_with('_')
        || COMPLETION_WIDGETS.contains(&name)
}

/// Whether `name` is an array of the functions zsh runs as hooks
/// (`precmd_functions`).
pub(super) fn hook_array(name: &str) -> bool {
    name.strip_suffix("_functions")
        .is_some_and(|hook| HOOKS.contains(&hook))
}

impl Walker<'_> {
    /// The events of an `add-zsh-hook`, an `add-zle-hook-widget` or a `zle`
    /// of `args`: the function it makes a hook, which zsh runs as commands
    /// are entered or end, or as a key is pressed ([`Event::Hook`]); one an
    /// expansion names is a doubt. Every widget's function is a hook, as a
    /// key bound to it may run it as a line is typed: `zle -N`'s, `zle -C`'s,
    /// which complete a word, a `zle -T` transformation's and `zle -F`'s,
    /// which run as zle prints and as a descriptor has input. A widget that
    /// completes a word ([`completes`]) run as a hook runs, or as a line is
    /// entered, runs completion functions the check does not read: a doubt.
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
            // `zle -C widget builtin function`, `zle -T transformation
            // function`.
            _ if matches!(flag, Some("-C" | "-T")) => words.last().filter(|_| words.len() > 1),
            // `zle -F fd handler`: run as the descriptor has input.
            _ if flag.is_some_and(|flag| flag.starts_with("-F")) => {
                words.last().filter(|_| words.len() > 1)
            }
            _ => None,
        };
        let line = || {
            args.iter()
                .map(|arg| arg.text.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        };
        if command == "add-zle-hook-widget" && words.get(1).is_some_and(|widget| completes(widget))
        {
            // The hook runs the widget as each line is entered.
            self.events.push(Event::Doubt(format!(
                "it cannot tell what the completion functions that `add-zle-hook-widget {}` in \
                 {} runs as each line is entered write",
                line(),
                self.place
            )));
            return;
        }
        if command == "zle"
            && flag == Some("-A")
            && (words.get(1).is_some_and(|widget| special_widget(widget))
                || words.first().is_some_and(|widget| completes(widget)))
        {
            // `zle -A old zle-line-finish`: the widget runs as each line is
            // entered, with the function of another; `zle -A complete-word
            // accept-line`: a key that enters a line completes a word.
            self.events.push(Event::Doubt(format!(
                "it cannot tell which function `zle {}` in {} makes run as each line is entered",
                line(),
                self.place
            )));
            return;
        }
        // The widget `zle` runs, past a `--` that ends its options.
        let run = match flag {
            Some("--") => args.get(1),
            Some(flag) if !flag.starts_with('-') => args.first(),
            _ => None,
        };
        if command == "zle"
            && let Some(widget) = run
            && completes(widget)
            && let Some(function) = self.function()
        {
            // `zle complete-word`, as a hook runs it.
            self.events.push(Event::HookDoubt {
                doubt: format!(
                    "it cannot tell what the completion functions that `zle {}` in `{function}` \
                     in {} runs write",
                    widget.text, self.place
                ),
                function,
            });
        }
        if command == "zle" && flag == Some("-U") {
            // `zle -U string`: what the string types runs as the line typed,
            // its control characters as keys (Tab, which completes a word).
            for typed in args.iter().skip(1) {
                if typed.expands
                    || typed.text.contains(['$', '`'])
                    || typed.text.chars().any(|c| c.is_control() && c != '\n')
                {
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
                    input: Input::None,
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
