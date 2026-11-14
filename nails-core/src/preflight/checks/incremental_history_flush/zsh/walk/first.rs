// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Whether zsh certainly runs the first command of a file before anything
//! can stop it there ([`super::Event::Assign`]'s `first`): zsh parses the
//! whole line a command stands on, and the rest of the construct that line
//! opens, before it runs any of it (Src/parse.c, `parse_event`), so a parse
//! error later on that line (`ZDOTDIR=~/.zd; then`, `ZDOTDIR=~/.zd }`, an
//! option a declaration does not take) stops the file with nothing on it run.
//! So the line must be one simple command the check reads as zsh parses it.

use super::super::lexer::{Token, Word, blank, is_name, lex};
use super::command::cannot_fail;

/// The commands that may start such a line beside an assignment: those that
/// declare parameters, which zsh 5.9 to 5.9.2 parse as reserved words that
/// take their assignments as assignments, and `unset`; after `builtin` or
/// `noglob` too.
const DECLARES: &[&str] = &["export", "typeset", "declare", "readonly", "local", "unset"];

/// Whether `word` is an assignment as written, quoted or not, to a name (not
/// `name+=` or an element), with a value whose expansion cannot fail
/// ([`cannot_fail`]). Whether it assigns, which a quote before its `=` may
/// keep it from (`"ZDOTDIR=x"`), the walk reads.
fn plain_assignment(word: &Word) -> bool {
    word.text
        .split_once('=')
        .is_some_and(|(target, value)| is_name(target) && cannot_fail(value))
}

/// Whether `word` is a parameter's name as written, no flag or expansion.
fn plain_name(word: &Word) -> bool {
    !word.expands && !word.bare && word.quoted_at.is_none() && is_name(&word.text)
}

/// Whether the first line of zsh code `text` that holds code, past lines
/// that are blank or a comment (their first character that is no space or
/// tab a `#`), is one simple command that zsh certainly parses as the check
/// reads it, with nothing after it on the line but a comment: one
/// assignment ([`plain_assignment`]), or one of [`DECLARES`] given only
/// such assignments and names, no flag among them. A line that a
/// backslash runs on, that holds an operator, a redirection, a quote or an
/// expansion that does not close, or any other word, is none.
pub(super) fn lone_first(text: &str) -> bool {
    let Some(line) = text.split('\n').find(|line| {
        let code = line.trim_start_matches(blank);
        !code.is_empty() && !code.starts_with('#')
    }) else {
        return false;
    };
    if line.ends_with('\\') {
        return false;
    }
    let (tokens, flaws) = lex(line);
    let words: Option<Vec<&Word>> = tokens
        .iter()
        .map(|token| match token {
            Token::Word(word) => Some(word),
            _ => None,
        })
        .collect();
    let Some(words) = words.filter(|_| flaws.is_empty()) else {
        return false;
    };
    let declares = words
        .iter()
        .skip_while(|word| plain_name(word) && matches!(word.text.as_str(), "builtin" | "noglob"))
        .collect::<Vec<_>>();
    match (words.as_slice(), declares.as_slice()) {
        ([only], _) => plain_assignment(only),
        (_, [first, rest @ ..]) => {
            plain_name(first)
                && DECLARES.contains(&first.text.as_str())
                && !rest.is_empty()
                && rest
                    .iter()
                    .all(|word| plain_assignment(word) || plain_name(word))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::lone_first;

    #[test]
    fn a_first_line_is_lone_when_it_is_one_assignment_or_declaration() {
        for text in [
            "ZDOTDIR=~/.zd\n",
            "# a comment\n\n  \t\nZDOTDIR=$HOME/.zd # and one\nsetopt x; then\n",
            "export ZDOTDIR=\"$HOME/.zd\"\n",
            "export XDG_CONFIG_HOME=~/.cfg PATH\n",
            "typeset ZDOTDIR=${XDG_CONFIG_HOME:-$HOME/.config}/zsh\n",
            "unset XDG_CONFIG_HOME\n",
            "builtin export ZDOTDIR=~/.zd\n",
            "export \"ZDOTDIR=$HOME/.zd\"\n",
            "\"ZDOTDIR=~/.zd\"\n",
            "ZDOTDIR=~/.zd\r\n",
            "ZDOTDIR=~/.zd",
        ] {
            assert!(lone_first(text), "{text:?}");
        }
        // zsh 5.9 to 5.9.2 run nothing on these lines, or may not.
        for text in [
            "ZDOTDIR=~/.zd; then\n",
            "ZDOTDIR=~/.zd;;\n",
            "ZDOTDIR=~/.zd; print >\n",
            "ZDOTDIR=~/.zd; f() \n",
            "ZDOTDIR=~/.zd }\n",
            "ZDOTDIR=~/.zd then\n",
            "ZDOTDIR=~/.zd &&\nsetopt x\n",
            "ZDOTDIR=~/.zd \\\n; then\n",
            "ZDOTDIR=~/.zd; :\n",
            "export ZDOTDIR=~/.zd }\n",
            "export -x ZDOTDIR=~/.zd\n",
            "export ZDOTDIR=~/.zd [\n",
            "export ZDOTDIR=$(print ~/.zd)\n",
            "ZDOTDIR=$ZD\n",
            "builtin ZDOTDIR=~/.zd\n",
            "ZDOTDIR+=x\n",
            "ZDOTDIR=~/.zd x\n",
            "ZDOTDIR='~/.zd\n",
            "eval ZDOTDIR=~/.zd\n",
            "\u{b}# ZDOTDIR=~/.zd\nZDOTDIR=~/.zd\n",
            "integer ZDOTDIR=1\n",
            "\n# nothing\n",
        ] {
            assert!(!lone_first(text), "{text:?}");
        }
    }
}
