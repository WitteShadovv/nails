// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The options a command turns on or off, as the walk reads it: a `setopt`
//! or an `unsetopt`, a `set`'s `-o` and `+o`, and an `emulate`'s mode and
//! its `-o`, `+o` and `-c`.

use super::super::backstop;
use super::super::lexer::Word;
use super::command::ALIAS_PARAMETERS;
use super::hooks::hook_array;
use super::{Event, Walker};

impl Walker<'_> {
    /// The events of a `setopt`-like command turning the options `word`
    /// names on (`on`), as brace expansion may make the word
    /// ([`backstop::options`]); none when it names others.
    pub(super) fn set(&mut self, word: &str, on: bool, unconditional: bool) {
        for (option, named_on) in backstop::options(word) {
            self.events.push(Event::Set {
                option,
                on: on == named_on,
                unconditional,
            });
        }
    }

    /// The events of a `setopt` or an `unsetopt` (`command`) of `args`.
    pub(super) fn setopt(&mut self, command: &str, args: &[Word], unconditional: bool) {
        let on = command == "setopt";
        for arg in args {
            if let Some(items) = Self::variable(arg).and_then(|var| self.loop_items(var)) {
                let items = items.to_vec();
                for item in items {
                    self.set(&item, on, unconditional);
                }
            } else if arg.expands || arg.text.starts_with(['-', '+']) {
                self.events.push(Event::Doubt(format!(
                    "it cannot tell which options `{command} {}` in {} turns on",
                    arg.text, self.place
                )));
            } else {
                self.set(&arg.text, on, unconditional);
            }
        }
    }

    /// The events of a `set` of `args`: the options `-o` and `+o` set, and
    /// the array `-A` and `+A` set, a hook's among them.
    pub(super) fn set_builtin(&mut self, args: &[Word], unconditional: bool) {
        let mut args = args.iter();
        // The values `-A` assigns an array, and the positional
        // parameters after `--`, set no option.
        let mut values = false;
        // The values are the functions of a hook.
        let mut hooks = false;
        while let Some(arg) = args.next() {
            if hooks {
                self.hook_value(arg);
            } else if arg.expands && !values {
                self.events.push(Event::Doubt(format!(
                    "it cannot tell which options `set {}` in {} turns on",
                    arg.text, self.place
                )));
            }
            if matches!(arg.text.as_str(), "-A" | "+A") && !values {
                values = true;
                // The array it sets, by a name an expansion may make.
                if let Some(name) = args.next() {
                    if name.expands || name.text.contains(['$', '`']) {
                        self.events.push(Event::Doubt(format!(
                            "it cannot tell which parameter `set {} {}` in {} sets",
                            arg.text, name.text, self.place
                        )));
                    } else if hook_array(&name.text) {
                        self.hooks += 1;
                        hooks = true;
                    } else if ALIAS_PARAMETERS.contains(&name.text.as_str())
                        || matches!(name.text.as_str(), "functions" | "dis_functions")
                    {
                        // Aliases or functions, each value beside its name.
                        self.alias_params += usize::from(!name.text.contains("functions"));
                        self.function_params += usize::from(name.text.contains("functions"));
                        self.events.push(Event::Doubt(format!(
                            "it cannot tell what code `set {} {} ...` in {} gives",
                            arg.text, name.text, self.place
                        )));
                    }
                    self.mention(&name.text);
                }
                continue;
            }
            values |= arg.text == "--";
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

    /// The events of an `emulate` of `args`: the options its `-o` and `+o`
    /// set, and the code its `-c` runs. An expansion among its words, which
    /// may be such an option or code, is a doubt.
    pub(super) fn emulate(&mut self, args: &[Word], unconditional: bool) {
        let place = self.place;
        let doubt = |what: &str| {
            Event::Doubt(format!(
                "it cannot tell what `emulate {what}` in {place} turns on"
            ))
        };
        // `-R` resets every option to the mode's defaults, and ksh's turns
        // SHARE_HISTORY on (zsh 5.9.1: `emulate -R ksh`, not `emulate ksh`).
        let mut reset = false;
        let mut mode = None;
        let mut args = args.iter();
        while let Some(arg) = args.next() {
            if arg.expands {
                self.events.push(doubt(&arg.text));
                continue;
            }
            if mode.is_none() {
                if let Some(flags) = arg.text.strip_prefix('-')
                    && !flags.is_empty()
                    && flags.chars().all(|c| c.is_ascii_alphabetic())
                    && !matches!(flags, "o" | "c")
                {
                    reset |= flags.contains('R');
                    continue;
                }
                if !arg.text.starts_with(['-', '+']) {
                    mode = Some(arg.text.clone());
                }
            }
            match arg.text.as_str() {
                "-o" | "+o" => match args.next() {
                    Some(name) if name.expands => {
                        let what = format!("{} {}", arg.text, name.text);
                        self.events.push(doubt(&what));
                    }
                    Some(name) => self.set(&name.text, arg.text == "-o", unconditional),
                    None => {}
                },
                "-c" => match args.next() {
                    Some(code) if code.expands => {
                        let what = format!("-c {}", code.text);
                        self.events.push(doubt(&what));
                    }
                    Some(code) => self.nested(&code.text, unconditional),
                    None => {}
                },
                _ => self.mention(&arg.text),
            }
        }
        if reset && mode.as_deref() == Some("ksh") {
            self.events.push(Event::Turns {
                option: 1,
                what: format!(
                    "{} runs `emulate -R ksh`, whose reset to ksh's defaults turns on",
                    self.place
                ),
            });
        }
    }
}
