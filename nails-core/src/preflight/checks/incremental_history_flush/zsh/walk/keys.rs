// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The keys a file binds and the lines that keys and code type, as the walk
//! reads them: the string a `bindkey -s` key types, which zsh reads as keys
//! typed, is read as a hook's code where it holds printable characters and
//! line ends alone, and so is what `print -z` puts in the line (`zle -U` is
//! read in [`super::hooks`]); what they type counts for the names the files
//! use too ([`Event::Typed`]). A key a line is typed with bound to another
//! widget, alone or in a range (`bindkey -R`), may change what such a line
//! types ([`Event::Rebind`]), and past a word an expansion makes that zsh may
//! drop or make several of, the check cannot tell keys from widgets.

use super::super::lexer::Word;
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

/// The options of a `bindkey` of `args`, as zsh reads them, and the words
/// past them, keys and what they are bound to.
struct Options<'a> {
    /// The letters of the options (`-RM main` holds `R` and `M`).
    letters: String,
    /// The keymap `-M` names, the rest of its word or the next word.
    keymap: Option<Word>,
    /// The words past the options.
    words: &'a [Word],
    /// A word of the options an expansion makes, which may hold any.
    computed: Option<&'a Word>,
    /// Whether `--` or `-` ended the options, so that no word past them is
    /// one.
    ended: bool,
}

/// The options of a `bindkey` of `args`, as zsh reads them: from each word
/// that starts with `-` up to the first that does not, or that is a `-` and
/// a digit; `--` and `-` end them and are dropped, and `-M` takes the rest of
/// its word, or the next word, as the keymap.
fn options(args: &[Word]) -> Options<'_> {
    let mut letters = String::new();
    let mut keymap = None;
    let mut computed_word = None;
    let mut ended = false;
    let mut at = 0;
    while let Some(arg) = args.get(at) {
        let Some(flags) = arg.text.strip_prefix('-') else {
            break;
        };
        if flags.starts_with(|c: char| c.is_ascii_digit()) {
            break;
        }
        at += 1;
        if flags.is_empty() || flags == "-" {
            ended = true;
            break;
        }
        if computed(arg) {
            computed_word.get_or_insert(arg);
        }
        match flags.split_once('M') {
            Some((before, rest)) => {
                letters.push_str(before);
                letters.push('M');
                keymap = if rest.is_empty() {
                    at += 1;
                    args.get(at - 1).cloned()
                } else {
                    Some(Word {
                        text: rest.to_string(),
                        expands: computed(arg),
                        quoted: arg.quoted,
                        bare: arg.bare,
                    })
                };
            }
            None => letters.push_str(flags),
        }
    }
    Options {
        letters,
        keymap,
        words: args.get(at..).unwrap_or_default(),
        computed: computed_word,
        ended,
    }
}

/// How many words zsh may make of a word of a command as it expands it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Count {
    /// One: one with no expansion, or whose expansions stand in double
    /// quotes with nothing that splits them there (`"$terminfo[kcuu1]"`).
    One,
    /// None or one: an element of a parameter outside quotes
    /// (`$terminfo[kcuu1]`, `${key[Up]}`), which zsh drops when it is empty,
    /// unless `SH_WORD_SPLIT` or `KSH_ARRAYS` split it or read it otherwise.
    AtMostOne,
    /// Any number: another expansion outside quotes (`$k`, `$k""`, `$(...)`),
    /// which may be an array or split, one that splits in quotes too
    /// (`"$@"`, `"${(f)x}"`, `"${=x}"`), and a glob or brace expansion
    /// outside quotes (`{' ',x}`, `*`).
    Any,
}

/// How many words zsh may make of `word` ([`Count`]).
fn count(word: &Word) -> Count {
    let text = word.text.as_str();
    let splits = word.expands
        && (text.contains('@')
            || text.contains("${(")
            || text.contains("${=")
            || text.contains("$="));
    if !word.bare && !splits {
        return Count::One;
    }
    // `$name[key]` or `${name[key]}`, its key a literal word.
    let element = |inner: &str| {
        inner
            .strip_suffix(']')
            .and_then(|inner| inner.split_once('['))
            .is_some_and(|(name, key)| {
                super::super::lexer::is_name(name)
                    && !key.is_empty()
                    && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            })
    };
    let braced = text
        .strip_prefix("${")
        .and_then(|inner| inner.strip_suffix('}'));
    if !splits && (text.strip_prefix('$').is_some_and(element) || braced.is_some_and(element)) {
        Count::AtMostOne
    } else {
        Count::Any
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
    /// ([`Event::Rebind`]). Options an expansion makes, which may be any, are
    /// a doubt; past `-l`, which lists keymaps, and the options that make,
    /// link, reset or unbind, no word binds a key to a widget, and with any
    /// other the words bind keys (a range of them with `-R`) to widgets
    /// ([`Walker::bind_widgets`]).
    pub(super) fn bindkey(&mut self, args: &[Word], unconditional: bool) {
        let options = options(args);
        if let Some(word) = options.computed {
            let words: Vec<&str> = args.iter().map(|arg| arg.text.as_str()).collect();
            self.events.push(Event::Doubt(format!(
                "it cannot tell what `bindkey {}` in {} binds, as an expansion makes its options \
                 `{}`",
                words.join(" "),
                self.place,
                word.text
            )));
            return;
        }
        let letters = options.letters.as_str();
        let macros = letters.contains('s');
        let keymaps = letters.contains(['A', 'N', 'r', 'd', 'D']);
        if keymaps || letters.contains('R') {
            self.events.push(Event::Rebind);
        }
        if !macros {
            for arg in args {
                self.mention(&arg.text);
            }
            if !keymaps && !letters.contains('l') {
                match options.words {
                    // zsh reads the options from the words an expansion makes
                    // too: `"$o"` may be `-R`, `-s` or `-`, which make the
                    // words after it ranges, strings that keys type, or keys
                    // and widgets in each other's places.
                    [first, _, _, ..] if !options.ended && computed(first) => {
                        let words: Vec<&str> = args.iter().map(|arg| arg.text.as_str()).collect();
                        self.events.push(Event::Rebind);
                        self.events.push(Event::Doubt(format!(
                            "it cannot tell what `bindkey {}` in {} binds, as `{}` may expand \
                             to its options",
                            words.join(" "),
                            self.place,
                            first.text
                        )));
                    }
                    words => self.bind_widgets(words, letters.contains('R')),
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
        let other = letters.contains('a')
            || options
                .keymap
                .as_ref()
                .is_some_and(|keymap| !matches!(keymap.text.as_str(), "main" | "emacs" | "viins"));
        let strings: Vec<&Word> = options.words.iter().collect();
        // A word zsh may drop or make several of (`{x,'...^M'}`) may move a
        // string into a key's place or a key into a string's.
        if let Some(word) = strings.iter().find(|word| count(word) != Count::One) {
            let words: Vec<&str> = args.iter().map(|arg| arg.text.as_str()).collect();
            self.events.push(Event::Rebind);
            self.events.push(Event::Doubt(format!(
                "it cannot tell which keys `bindkey {}` in {} binds to which strings, as `{}` may \
                 expand to no word or to several",
                words.join(" "),
                self.place,
                word.text
            )));
            return;
        }
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

    /// The events of the words `words` of a `bindkey` that binds keys to
    /// widgets, each key a range of keys with `ranges` (`-R`): a key a line
    /// is typed with bound to another widget than `self-insert` may change
    /// what typed keys do ([`Event::Rebind`]). zsh drops a word an expansion
    /// outside quotes makes when it is empty, so past one the check cannot
    /// tell keys from widgets, and any may be such a key; a word an expansion
    /// may make several words of ([`Count`]) is a doubt, as the check cannot
    /// tell what it binds. `SH_WORD_SPLIT` and `KSH_ARRAYS` may make several
    /// of an element too ([`Event::KeysSplit`]).
    fn bind_widgets(&mut self, words: &[Word], ranges: bool) {
        let all: Vec<&str> = words.iter().map(|word| word.text.as_str()).collect();
        let shown = || {
            format!(
                "bindkey{} {}",
                if ranges { " -R" } else { "" },
                all.join(" ")
            )
        };
        // The word an expansion makes that may be dropped, past which the
        // check cannot tell keys from widgets.
        let mut dropped: Option<&Word> = None;
        for (at, word) in words.iter().enumerate() {
            let count = count(word);
            if count == Count::Any {
                self.events.push(Event::Rebind);
                self.events.push(Event::Doubt(format!(
                    "it cannot tell which keys `{}` in {} binds to what, as `{}` may expand to \
                     no word or to several",
                    shown(),
                    self.place,
                    word.text
                )));
                return;
            }
            if count == Count::AtMostOne {
                self.events.push(Event::KeysSplit {
                    bindkey: shown(),
                    word: word.text.clone(),
                });
            }
            match dropped {
                Some(_) => self.events.push(Event::Rebind),
                None if at % 2 == 1 => {
                    let keys = &words[at - 1];
                    if (ranges || typed_key(keys)) && word.text != "self-insert" {
                        self.events.push(Event::Rebind);
                    }
                }
                None => {}
            }
            if count == Count::AtMostOne && dropped.is_none() {
                dropped = Some(word);
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
