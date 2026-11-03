// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The keys a file binds and the line a `bindkey -s` string types, as the
//! walk reads them: the string is read as a hook's code, and a widget that
//! completes a word bound to a key a line is typed with runs completion
//! functions the check does not read.

use super::super::lexer::Word;
use super::hooks::completes;
use super::strings::computed;
use super::{Event, Walker};

/// The line that the keys `text` types, a `bindkey -s` string as written,
/// as zsh reads it: `^M`, `^J`, `\r`, `\n`, `\C-m` and `\C-j` end a line,
/// another `^` or `\` escape is a key that edits the line, which types
/// nothing; `None` when it holds an escape key (`^[`, `\e`, `\M-`), which
/// may run a widget by its name, a key that completes a word as zsh binds it
/// (Tab, `^D` at the end of a line) or starts one that may (`^X`), or a
/// character given by its number.
fn typed_line(text: &str) -> Option<String> {
    let mut line = String::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '^' => match chars.next()? {
                'M' | 'm' | 'J' | 'j' => line.push('\n'),
                '[' | 'I' | 'i' | 'D' | 'd' | 'X' | 'x' => return None,
                _ => {}
            },
            '\\' => match chars.next()? {
                'n' | 'r' => line.push('\n'),
                // An escape key, Tab, or a character by its number.
                'e' | 'E' | 'M' | 'x' | 'u' | 'U' | 't' | '0'..='9' => return None,
                'C' => {
                    chars.next_if_eq(&'-');
                    match chars.next()? {
                        'm' | 'M' | 'j' | 'J' => line.push('\n'),
                        '[' | 'I' | 'i' | 'D' | 'd' | 'X' | 'x' => return None,
                        _ => {}
                    }
                }
                c if c.is_ascii_alphanumeric() => {}
                c => line.push(c),
            },
            // Tab itself.
            '\t' => return None,
            c => line.push(c),
        }
    }
    Some(line)
}

/// Whether `keys`, a key sequence as `bindkey` is given it, is one the
/// check takes the operator to press only to complete a word, as zsh binds
/// such keys: Tab, `^D` (which zsh binds to `delete-char-or-list`), or a
/// sequence that starts with `^X` or an escape (`^[`, `\e`, `\M-`), past
/// which no key types a command line.
fn completion_keys(keys: &str) -> bool {
    matches!(
        keys,
        "^I" | "^i" | "\\t" | "\t" | "\\C-i" | "\\C-I" | "^D" | "^d" | "\\C-d" | "\\C-D"
    ) || ["^X", "^x", "\\C-x", "\\C-X", "^[", "\\e", "\\E", "\\M-"]
        .iter()
        .any(|prefix| keys.len() > prefix.len() && keys.starts_with(prefix))
}

impl Walker<'_> {
    /// The events of a `bindkey` of `args`: with `-s`, the keys each string
    /// after a key types, which zsh reads as the line typed when the key is
    /// pressed, read as a hook's code (a line ends at `^M`, `^J`, `\r` or
    /// `\n`, and another escape is a key that moves or erases); with an
    /// expansion among its words, or an escape key (`^[`, `\e`) in a string,
    /// which may run a widget by its name, a doubt.
    pub(super) fn bindkey(&mut self, args: &[Word], unconditional: bool) {
        let mut flags = Vec::new();
        let mut strings = Vec::new();
        let mut words = args.iter();
        while let Some(arg) = words.next() {
            if strings.is_empty() && arg.text.starts_with('-') && arg.text.len() > 1 {
                if arg.text.contains('M') {
                    // The keymap it binds in.
                    words.next();
                }
                flags.push(arg.text.as_str());
                continue;
            }
            strings.push(arg);
        }
        let macros = flags.iter().any(|flag| flag.contains('s'));
        if !macros {
            for arg in args {
                self.mention(&arg.text);
            }
            // A widget that completes a word bound to a key typed as a line
            // is (Space, a letter, Enter) runs completion functions the check
            // does not read as each line is typed.
            let keymaps = flags
                .iter()
                .any(|flag| flag.contains(['A', 'N', 'l', 'L', 'r', 'd']));
            for pair in strings.chunks(2) {
                let [keys, widget] = pair else {
                    continue;
                };
                if !keymaps && completes(widget) && (computed(keys) || !completion_keys(&keys.text))
                {
                    self.events.push(Event::Doubt(format!(
                        "it cannot tell what the completion functions that `bindkey {} {}` in {} \
                         runs as a line is typed write",
                        keys.text, widget.text, self.place
                    )));
                }
            }
            return;
        }
        let place = self.place;
        let doubt = |text: &str| {
            Event::Doubt(format!(
                "it cannot tell what the keys `bindkey -s ... {text}` in {place} types run"
            ))
        };
        for pair in strings.chunks(2) {
            let [keys, typed] = pair else {
                continue;
            };
            if computed(keys) || computed(typed) {
                self.events.push(doubt(&typed.text));
                continue;
            }
            match typed_line(&typed.text) {
                Some(code) => {
                    let hook = format!("bindkey -s {} {}", keys.text, typed.text);
                    self.hooked(&code, unconditional, hook);
                }
                None => self.events.push(doubt(&typed.text)),
            }
        }
    }
}
