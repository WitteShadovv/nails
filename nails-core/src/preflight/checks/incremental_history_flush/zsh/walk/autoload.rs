// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The functions a command marks to be autoloaded, as the walk reads it:
//! `autoload`, and `functions`, `typeset`, `declare` and `readonly` with the
//! options that mark a function so, read as zsh reads a builtin's options
//! ([`super::declare::options`]). `local`, `export`, `integer`, `float` and
//! `private` take no `-f`: zsh 5.9 to 5.9.2 refuse it.

use super::super::lexer::Word;
use super::declare::{options, unread_doubt};
use super::{Event, Walker};

/// What the words after `functions`, or a builtin of the `typeset` family,
/// mark to be autoloaded.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Marks<'a> {
    /// No function.
    None,
    /// The functions the words from this one on name, with the letters of
    /// the options before them but a `U` a `+` turns off.
    Names(usize, String),
    /// A word where its options may stand that an expansion, brace expansion
    /// or a glob may make any options of, or none, so that the word after it
    /// is one.
    Doubt(&'a Word),
}

/// What `args`, the words after `command` (`functions`, `typeset`,
/// `declare` or `readonly`), mark to be autoloaded, their options read as
/// zsh reads a builtin's ([`options`]): a function is autoloaded where a word
/// that starts with `-` holds `u` or `U`, for `functions` alone, and for the
/// others with an `f` in a word of either sign (`typeset -fu`, `readonly +f
/// -u`, `declare +g -fU`); `functions -x` with no word after it runs nothing.
pub(super) fn marks<'a>(command: &str, args: &'a [Word]) -> Marks<'a> {
    let options = options(command, args);
    if let Some(word) = options.unread {
        return Marks::Doubt(word);
    }
    let undefined = options.on('u') || options.on('U');
    if options.fails || !undefined || !(command == "functions" || options.has('f')) {
        return Marks::None;
    }
    let flags = options
        .letters
        .iter()
        .filter(|&&(letter, minus)| minus || letter != 'U')
        .map(|&(letter, _)| letter)
        .collect();
    Marks::Names(options.names, flags)
}

impl Walker<'_> {
    /// The events of a `functions` or a builtin of the `typeset` family
    /// (`command`) of `args` that marks the functions they name to be
    /// autoloaded ([`marks`]), as an `autoload` of them does; `false` when it
    /// marks none. One whose options an expansion may make (`typeset $o x`)
    /// is a doubt, and is read as one that marks none.
    pub(super) fn marked(&mut self, command: &str, args: &[Word]) -> bool {
        match marks(command, args) {
            Marks::Names(at, flags) => {
                for arg in &args[..at] {
                    self.mention_word(arg);
                }
                self.load(command, args, &flags, args[at..].to_vec());
                true
            }
            Marks::Doubt(word) => {
                let doubt = unread_doubt(command, args, word, self.place);
                self.events.push(Event::Doubt(doubt));
                false
            }
            Marks::None => false,
        }
    }

    /// The events of an `autoload`, or of the like (`command`), of `args`:
    /// each function it marks, by name or by the path of its file
    /// ([`Walker::load`]). One with `-X` loads the function whose code runs
    /// it, from the directory its word names or from `fpath`: a doubt.
    pub(super) fn autoload(&mut self, command: &str, args: &[Word]) {
        let mut flags = String::new();
        let mut names = Vec::new();
        let mut options = true;
        let mut caller = false;
        for arg in args {
            if options && !arg.expands && arg.text.len() > 1 && arg.text.starts_with(['-', '+']) {
                self.mention_word(arg);
                if arg.text == "--" {
                    options = false;
                } else if arg.text.starts_with('-') {
                    caller |= arg.text.contains('X');
                    flags.push_str(&arg.text);
                } else {
                    // A flag turned off is none zsh acts on.
                    flags.push_str(&arg.text.replace('U', ""));
                }
                continue;
            }
            options = false;
            names.push(arg.clone());
        }
        if caller {
            for name in &names {
                self.mention_word(name);
            }
            let words: Vec<&str> = args.iter().map(|arg| arg.text.as_str()).collect();
            self.events.push(Event::Doubt(format!(
                "it cannot tell which function `{command} {}` in {} loads, as -X loads the one \
                 whose code runs it, from the directory a word after it names or from fpath",
                words.join(" "),
                self.place
            )));
            return;
        }
        self.load(command, args, &flags, names);
    }

    /// The events of the functions `names` that `command` of `args`, with the
    /// letters `flags` among its options, marks to be autoloaded, by name or
    /// by the path of its file. Which functions it marks is a doubt with `-m`
    /// (patterns, which may name any function defined so far) or `-w`
    /// (compiled files).
    fn load(&mut self, command: &str, args: &[Word], flags: &str, mut names: Vec<Word>) {
        for name in &names {
            self.mention_word(name);
        }
        if flags.contains(['m', 'w']) {
            let words: Vec<&str> = std::iter::once(command)
                .chain(args.iter().map(|arg| arg.text.as_str()))
                .collect();
            self.events.push(Event::Doubt(format!(
                "it cannot tell which functions `{}` in {} loads",
                words.join(" "),
                self.place
            )));
            return;
        }
        // With `-d`, zsh looks for a function it cannot find at the path
        // given in fpath, by its name.
        if flags.contains('d') {
            let bases: Vec<Word> = names
                .iter()
                .filter_map(|name| {
                    let (_, base) = name.text.rsplit_once('/')?;
                    Some(Word {
                        text: base.to_string(),
                        expands: name.expands,
                        quoted: false,
                        bare: name.bare,
                    })
                })
                .collect();
            names.extend(bases);
        }
        // Without `-U` zsh expands aliases in the function's code as it
        // loads it.
        if !flags.contains('U') {
            self.events.extend(
                names
                    .iter()
                    .filter(|name| !name.expands)
                    .map(|name| Event::Expanding(name.text.clone())),
            );
        }
        let in_function = self.function().is_some();
        self.events.extend(
            names
                .into_iter()
                .map(|name| Event::Autoload(name, in_function)),
        );
    }
}
