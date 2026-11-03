// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The keys a file binds and the lines that keys and code type, as the walk
//! reads them: the string a `bindkey -s` key types, which zsh reads as keys
//! typed, is read as a hook's code where it holds printable characters and
//! line ends alone, and so is what `print -z` puts in the line (`zle -U` is
//! read in [`super::hooks`]); what they type counts for the names the files
//! use too ([`Event::Typed`]). A widget that completes a word bound to a key
//! a line is typed with runs completion functions the check does not read.

use super::super::lexer::Word;
use super::hooks::completes;
use super::strings::computed;
use super::{Event, Walker};

/// The line that the keys `text` types, a `bindkey -s` string as written,
/// as zsh reads it: `^M`, `^J`, `\r`, `\n`, `\C-m`, `\C-j` and a line end
/// itself end a line, and any other printable character types itself;
/// `None` when it holds any other key, which moves, erases or runs a widget
/// (`^A`, `^H`, `\b`, Tab, an escape), or a character given by its number.
fn typed_line(text: &str) -> Option<String> {
    let mut line = String::new();
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        match c {
            '^' => match chars.next()? {
                'M' | 'm' | 'J' | 'j' => line.push('\n'),
                _ => return None,
            },
            '\\' => match chars.next()? {
                'n' | 'r' => line.push('\n'),
                'C' => {
                    let mut next = chars.next()?;
                    if next == '-' {
                        next = chars.next()?;
                    }
                    match next {
                        'm' | 'M' | 'j' | 'J' => line.push('\n'),
                        _ => return None,
                    }
                }
                c if c.is_ascii_alphanumeric() || c.is_control() => return None,
                c => line.push(c),
            },
            '\n' | '\r' => line.push('\n'),
            c if c.is_control() => return None,
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

/// Whether `keys`, a key sequence as `bindkey` is given it, starts with a
/// key a line is typed with: a printable character, which no `^` or escape
/// gives but `\\` and the like (an expansion may give any).
fn typed_key(keys: &Word) -> bool {
    let mut chars = keys.text.chars();
    computed(keys)
        || match chars.next() {
            Some('^') | None => false,
            Some('\\') => chars
                .next()
                .is_some_and(|c| !c.is_ascii_alphanumeric() && !c.is_control()),
            Some(c) => !c.is_control(),
        }
}

impl Walker<'_> {
    /// The events of a `bindkey` of `args`. With `-s`, the keys each string
    /// after a key types, which zsh reads as the line typed when the key is
    /// pressed, read as a hook's code ([`typed_line`]), in the keymap a line
    /// is typed in; any other string, one an expansion makes, and one bound
    /// in another keymap (`-a`, `-M vicmd`), is a doubt. A key a line is typed
    /// with bound otherwise than to `self-insert`, a key unbound, and a keymap
    /// made, linked or reset may change what such a string types
    /// ([`Event::Rebind`]).
    pub(super) fn bindkey(&mut self, args: &[Word], unconditional: bool) {
        let mut flags = Vec::new();
        let mut keymap = None;
        let mut strings = Vec::new();
        let mut words = args.iter();
        while let Some(arg) = words.next() {
            if strings.is_empty() && arg.text.starts_with('-') && arg.text.len() > 1 {
                if arg.text.contains('M') {
                    // The keymap it binds in.
                    keymap = words.next();
                }
                flags.push(arg.text.as_str());
                continue;
            }
            strings.push(arg);
        }
        let macros = flags.iter().any(|flag| flag.contains('s'));
        let keymaps = flags
            .iter()
            .any(|flag| flag.contains(['A', 'N', 'r', 'R', 'd', 'D']));
        if keymaps {
            self.events.push(Event::Rebind);
        }
        if !macros {
            for arg in args {
                self.mention(&arg.text);
            }
            // A widget that completes a word bound to a key typed as a line
            // is (Space, a letter, Enter) runs completion functions the check
            // does not read as each line is typed.
            let keymaps = keymaps || flags.iter().any(|flag| flag.contains(['l', 'L']));
            for pair in strings.chunks(2) {
                let [keys, widget] = pair else {
                    continue;
                };
                if !keymaps && typed_key(keys) && widget.text != "self-insert" {
                    self.events.push(Event::Rebind);
                }
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
        // A string bound in a keymap other than the one a line is typed in,
        // where keys are commands (vicmd).
        let other = flags.iter().any(|flag| flag.contains('a'))
            || keymap
                .is_some_and(|keymap| !matches!(keymap.text.as_str(), "main" | "emacs" | "viins"));
        for pair in strings.chunks(2) {
            let [keys, typed] = pair else {
                continue;
            };
            if typed_key(keys) {
                self.events.push(Event::Rebind);
            }
            if other || computed(keys) || computed(typed) {
                self.events.push(doubt(&typed.text));
                continue;
            }
            match typed_line(&typed.text) {
                Some(code) => {
                    let hook = format!("bindkey -s {} {}", keys.text, typed.text);
                    self.events.push(Event::Typed {
                        text: code.clone(),
                        keys: true,
                    });
                    self.hooked(&code, unconditional, hook);
                }
                None => self.events.push(doubt(&typed.text)),
            }
        }
    }

    /// The events of a `print -z` of `args`, which puts its words in the line
    /// zsh edits next as if typed: read as a hook's code where it holds no
    /// expansion and no escape `print` decodes (`\n`), a doubt otherwise.
    pub(super) fn print_line(&mut self, args: &[Word]) {
        let flags: String = args
            .iter()
            .take_while(|arg| arg.text.starts_with('-') && arg.text.len() > 1 && arg.text != "--")
            .map(|arg| arg.text.as_str())
            .collect();
        if !flags.contains('z') {
            return;
        }
        let words: Vec<&Word> = args
            .iter()
            .skip_while(|arg| arg.text.starts_with('-') && arg.text.len() > 1 && arg.text != "--")
            .skip_while(|arg| arg.text == "--")
            .collect();
        let text = words
            .iter()
            .map(|word| word.text.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        if words.iter().any(|word| computed(word))
            || flags.contains(['f', 'u', 'v', 'C'])
            || (!flags.contains(['r', 'R']) && text.contains('\\'))
            || text.chars().any(|c| c.is_control() && c != '\n')
        {
            self.events.push(Event::Doubt(format!(
                "it cannot tell what the line `print -z {text}` in {} types runs",
                self.place
            )));
            return;
        }
        self.events.push(Event::Typed {
            text: text.clone(),
            keys: false,
        });
        self.hooked(&text, false, format!("print -z {text}"));
    }
}

#[cfg(test)]
mod tests {
    use super::typed_line;

    #[test]
    fn a_bindkey_string_types_printable_characters_and_line_ends_alone() {
        assert_eq!(
            typed_line("^Jsetopt x^M\\r\\C-m\\C-J"),
            Some("\nsetopt x\n\n\n\n".to_string())
        );
        assert_eq!(typed_line("lfcd^M"), Some("lfcd\n".to_string()));
        assert_eq!(typed_line("a\\\\b\\'"), Some("a\\b'".to_string()));
        // A key that moves, erases, completes or runs a widget, an escape,
        // and a character by its number.
        for text in [
            "^Jhistory^Asetopt share^J",
            "^Jsetopt sharehistorx^Hy^J",
            "^Jfc -IX ^H^H^HAI^J",
            "x^?y",
            "x\\by",
            "x\\C-hy",
            "x\\C-?",
            "x\\ty",
            "x\ty",
            "x\u{8}y",
            "x^[y",
            "x\\ey",
            "x\\M-y",
            "x\\x41",
            "x\\101",
            "x^",
        ] {
            assert_eq!(typed_line(text), None, "{text:?}");
        }
    }
}
