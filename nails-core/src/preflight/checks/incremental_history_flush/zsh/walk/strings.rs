// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The code that zsh runs from a string a startup file holds: an alias's
//! value as it is used, a trap's, a `sched`'s and a `zstyle -e`'s, and a
//! prompt's when `PROMPT_SUBST` is on. A string the walk can read whole is
//! read as an `eval`'s words are; one with an expansion in it, which may make
//! any code, is a doubt.

use super::super::backstop::{FC_WRITES, is_fc_flag};
use super::super::lexer::{Token, Word, lex};
use super::{Event, Walker};

/// The commands that take the words after them as options, code, names or
/// paths, so that an alias whose value ends with one hands them the words it
/// is used with (`alias so=setopt`, then `so $o`).
const OPEN: &[&str] = &[
    "setopt",
    "unsetopt",
    "set",
    "emulate",
    "source",
    ".",
    "eval",
    "autoload",
    "functions",
    "typeset",
    "declare",
    "local",
    "readonly",
    "export",
    "integer",
    "float",
    "unset",
    "fc",
    "trap",
    "sched",
    "zstyle",
    "print",
    "printf",
    "read",
    "alias",
    "zmodload",
    "builtin",
    "command",
    "exec",
    "noglob",
    "nocorrect",
    "-",
    "time",
];

/// The name of the alias that `text` defines: `name` of `name=value`, or of
/// `aliases[name]=value`; `None` for a suffix or global alias, which zsh
/// expands elsewhere than as a command's name, and for a name that holds
/// what zsh may expand.
fn alias_name(text: &str) -> Option<&str> {
    let (target, _) = text.split_once('=')?;
    let name = match target.strip_prefix("aliases[") {
        Some(rest) => rest.strip_suffix(']')?,
        None if target.contains('[') => return None,
        None => target,
    };
    (!name.is_empty() && !name.contains(['$', '`', '\\', '\'', '"', '[', ']', '*', '?']))
        .then_some(name)
}

/// The parameters whose value zsh shows as a prompt, which `PROMPT_SUBST`
/// makes it expand, a command substitution and an assignment in an
/// expansion among it, as it shows them.
pub(super) const PROMPTS: &[&str] = &[
    "PS1", "PROMPT", "RPS1", "RPROMPT", "PS2", "PROMPT2", "RPS2", "RPROMPT2", "PS3", "PROMPT3",
    "PS4", "PROMPT4",
];

/// Whether `word`, a string of zsh code as the lexer gives it, holds an
/// expansion, which may make any code: a backquote, or a `$` before a name,
/// a `{`, a `(` or a special parameter, wherever quotes put it (not the `$`
/// of `PS1='$ '`).
fn computed(word: &Word) -> bool {
    let mut chars = word.text.chars().peekable();
    word.expands
        || std::iter::from_fn(|| chars.next().map(|c| (c, chars.peek().copied()))).any(
            |(c, next)| {
                c == '`'
                    || (c == '$'
                        && next.is_some_and(|next| {
                            next.is_ascii_alphanumeric() || "_{([#?!*@$-".contains(next)
                        }))
            },
        )
}

/// Whether `command`, the last command of an alias's value as written, is
/// an `fc` that writes nothing: `fc`, past the precommands that run it, with
/// words that hold no expansion and no flag that writes the history file
/// ([`FC_WRITES`]: `-A`, `-W`, `-P`), as `fc -l` or `fc -lnr -20` lists it.
fn listing_fc(command: &str) -> bool {
    let (tokens, flaws) = lex(command);
    let mut words = Vec::new();
    for token in tokens {
        match token {
            Token::Word(word) if !word.expands => words.push(word.text),
            _ => return false,
        }
    }
    let mut words = words
        .iter()
        .skip_while(|word| matches!(word.as_str(), "builtin" | "noglob" | "nocorrect" | "-"));
    flaws.is_empty()
        && words.next().is_some_and(|word| word == "fc")
        && words.all(|word| !is_fc_flag(word) || !word.contains(FC_WRITES))
}

impl Walker<'_> {
    /// The events of an `alias` of `args`: what each value runs, read as an
    /// `eval`'s words, where the walk can read it whole. One with an
    /// expansion is a doubt, and so is one that ends with a command that
    /// takes the words the alias is used with as code, options, names or
    /// paths ([`OPEN`]), or with a blank, after which zsh expands the next
    /// word as an alias too. An `fc` that writes nothing is no doubt in the
    /// value of an alias zsh expands only as a command's name
    /// ([`Event::FcAlias`]).
    pub(super) fn alias(&mut self, args: &[Word], unconditional: bool) {
        // `-g` and `-s` make an alias zsh expands elsewhere than as a
        // command's name; `-r` is the default, and `--` ends the flags.
        let mut regular = true;
        let mut flags = true;
        for arg in args {
            self.mention(&arg.text);
            if flags && arg.text.starts_with(['-', '+']) && !arg.text.contains('=') {
                flags = arg.text != "--";
                regular &= matches!(arg.text.as_str(), "--" | "-r");
                continue;
            }
            flags = false;
            if let Some((_, value)) = arg.text.split_once('=') {
                self.alias_value(&arg.text, value, arg, unconditional, regular);
            }
        }
    }

    /// The events of the value `value` an alias is given by the word `word`,
    /// as [`Walker::alias`] reads it; `regular` when zsh expands the alias
    /// only as a command's name.
    pub(super) fn alias_value(
        &mut self,
        text: &str,
        value: &str,
        word: &Word,
        unconditional: bool,
        regular: bool,
    ) {
        let doubt = |place: &str| {
            Event::Doubt(format!(
                "it cannot tell what the alias `{text}` in {place} runs where it is used"
            ))
        };
        if computed(word) {
            self.events.push(doubt(self.place));
            return;
        }
        self.nested(value, unconditional);
        // The command the words the alias is used with go to: its value's
        // last, past its assignments and precommands.
        let last = value
            .rsplit([';', '&', '|', '(', ')', '{', '}', '\n'])
            .next()
            .unwrap_or_default();
        let command = last.split_whitespace().find(|word| {
            !word.contains('=')
                && !matches!(
                    *word,
                    "builtin" | "command" | "noglob" | "nocorrect" | "exec" | "-" | "time"
                )
        });
        let name = alias_name(text);
        if value.ends_with(char::is_whitespace) {
            self.events.push(doubt(self.place));
        } else if let Some(name) = name.filter(|_| regular && listing_fc(last)) {
            // It hands its words to an `fc` that writes nothing as written,
            // but may write once used with more (`h -W`).
            self.events.push(Event::FcAlias {
                name: name.to_string(),
                text: text.to_string(),
            });
        } else if command.is_none_or(|command| OPEN.contains(&command)) {
            self.events.push(doubt(self.place));
        }
    }

    /// The events of a `trap` of `args`: the code it runs as the signal or
    /// the hook comes (`trap 'fc -AI' DEBUG`), read as an `eval`'s words,
    /// where the walk can read it whole; with an expansion, a doubt.
    pub(super) fn trap(&mut self, args: &[Word], unconditional: bool) {
        let mut args = args.iter().peekable();
        args.next_if(|arg| arg.text == "--");
        if let Some(code) = args.next() {
            if computed(code) {
                self.events.push(Event::Doubt(format!(
                    "it cannot tell what code `trap {}` in {} runs",
                    code.text, self.place
                )));
            } else if code.text != "-" {
                // zsh runs it as it would the TRAP... function of its signal.
                let signal = args
                    .peek()
                    .map(|signal| signal.text.as_str())
                    .filter(|signal| signal.chars().all(|c| c.is_ascii_alphanumeric()))
                    .unwrap_or_default();
                let outer = Some(format!("TRAP{signal}"));
                self.nested_in(&code.text, unconditional, outer);
            }
        }
        for arg in args {
            self.mention(&arg.text);
        }
    }

    /// The events of a `sched` of `args`: the command it runs at its time
    /// (`sched +60 fc -W`), read as an `eval`'s words, where the walk can
    /// read them whole; with an expansion, a doubt.
    pub(super) fn sched(&mut self, args: &[Word], unconditional: bool) {
        let mut args = args.iter().peekable();
        args.next_if(|arg| arg.text == "-o");
        // The time, or the number of an item to take away (`-2`).
        match args.next() {
            Some(time) if time.text.starts_with('-') => return,
            Some(time) if computed(time) => {}
            Some(_) => {}
            None => return,
        }
        let command: Vec<&Word> = args.collect();
        if command.iter().any(|word| computed(word)) {
            let words: Vec<&str> = command.iter().map(|word| word.text.as_str()).collect();
            self.events.push(Event::Doubt(format!(
                "it cannot tell what command `sched ... {}` in {} runs",
                words.join(" "),
                self.place
            )));
            return;
        }
        let words: Vec<&str> = command.iter().map(|word| word.text.as_str()).collect();
        self.nested(&words.join(" "), unconditional);
    }

    /// The events of a `zstyle` of `args`: with `-e`, the code each string
    /// after the pattern and the style is, which zsh runs as it looks the
    /// style up, read as an `eval`'s words where the walk can read it whole;
    /// with an expansion, a doubt. Any other `zstyle` sets data, whose words
    /// count for the options they name.
    pub(super) fn zstyle(&mut self, args: &[Word], unconditional: bool) {
        if args.first().is_none_or(|flag| flag.text != "-e") {
            for arg in args {
                self.mention(&arg.text);
            }
            return;
        }
        for (at, arg) in args.iter().enumerate().skip(1) {
            if at < 3 {
                self.mention(&arg.text);
            } else if computed(arg) {
                self.events.push(Event::Doubt(format!(
                    "it cannot tell what code `zstyle -e ... {}` in {} runs",
                    arg.text, self.place
                )));
            } else {
                self.nested(&arg.text, unconditional);
            }
        }
    }

    /// Note a prompt that zsh expands as it shows it when `PROMPT_SUBST` is
    /// on, `text` as written, when it holds an expansion or a command
    /// substitution: what that runs, an `fc` or an assignment to `options`
    /// among it, the check cannot follow ([`Event::Prompt`]).
    pub(super) fn prompt(&mut self, text: &str, value: &Word) {
        if computed(value) {
            self.events.push(Event::Prompt(format!(
                "it cannot follow the code that `{text}` in {} runs as zsh shows the prompt, as \
                 PROMPT_SUBST may be on",
                self.place
            )));
        }
    }
}
