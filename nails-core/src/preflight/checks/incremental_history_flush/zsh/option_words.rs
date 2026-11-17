// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What the lines of zsh code may do to the options that change how zsh
//! reads code, beside the words that name them ([`super::backstop`]): an
//! `emulate` that sets every option of a mode's list as the mode has it,
//! which may turn on one no file names, a `set` of an option's letter, and
//! the spellings of the option `ALIASES`, without which zsh puts no alias in
//! place of a name.

use super::backstop::{
    braces, code_lines, comment_line, is_write, named_in, names_any, whole_words,
};

/// Whether `text`, zsh code, may run an `emulate` of a mode whose first
/// letter past one `r` is among `modes`, as zsh picks a mode by it: past the
/// flags of an `emulate` (and the option after `-o` or `+o`), its first
/// word, or one an expansion, brace expansion or a glob makes, which may be
/// any; one with no such word may be any too, as an alias or a function may
/// give it the mode (`alias em=emulate`, then `em sh`). A line that is a
/// comment is left out. Such an `emulate` sets each option of the mode's
/// list as the mode has it (`emulate -l sh` lists them, `emulate -lR sh`
/// those `-R` sets): sh's, ksh's and csh's turn `GLOB_SUBST` on, sh's and
/// ksh's `SH_WORD_SPLIT`, `KSH_ARRAYS` and `ALIAS_FUNC_DEF`, sh's
/// `IGNORE_BRACES` and csh's `CSH_JUNKIE_QUOTES` and `CSH_JUNKIE_LOOPS`; with
/// `-R` every mode turns `RCS` and `GLOBAL_RCS` on, sh's and ksh's
/// `PROMPT_SUBST`, and ksh's `SHARE_HISTORY` (zsh 5.9 to 5.9.2). zsh picks
/// the mode by that letter: `c` csh's, `k` ksh's, `s` and `b` sh's (`emulate
/// bash`), any other zsh's.
pub(super) fn emulates(text: &str, modes: &[char]) -> bool {
    let part = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '/' | '-');
    code_lines(text).any(|line| {
        line.match_indices("emulate").any(|(at, found)| {
            if line[..at].chars().next_back().is_some_and(part)
                || line[at + found.len()..].chars().next().is_some_and(part)
            {
                return false;
            }
            let rest = line[at + found.len()..]
                .split([';', '&', '|', '(', ')', '`'])
                .next()
                .unwrap_or_default();
            let mut words = rest.split_whitespace();
            while let Some(word) = words.next() {
                let word = word.trim_matches(['\'', '"', '\\']);
                if matches!(word, "-o" | "+o") {
                    words.next();
                } else if !word.starts_with(['-', '+']) {
                    let mode = word.strip_prefix('r').unwrap_or(word);
                    return word.contains(['$', '`', '{', '*', '?', '['])
                        || mode.starts_with(modes);
                }
            }
            true
        })
    })
}

/// Whether `text`, zsh code, runs a `set`, a `setopt` or an `unsetopt` with
/// a word of flags that holds `letter`, an option's (`set -I` for
/// `IGNORE_BRACES`). A line that is a comment is left out.
pub(super) fn sets_letter(text: &str, letter: char) -> bool {
    code_lines(text).any(|line| {
        ["set", "setopt", "unsetopt"]
            .iter()
            .any(|command| whole_words(line, command) > 0)
            && line.split_whitespace().any(|word| {
                let word = word.trim_matches(['\'', '"', '\\']);
                word.len() > 1
                    && word.starts_with(['-', '+'])
                    && word[1..].chars().all(|c| c.is_ascii_alphanumeric())
                    && word.contains(letter)
            })
    })
}

/// Whether `text`, zsh code, runs an `emulate` of another mode than zsh's,
/// which may turn `SH_WORD_SPLIT` or `KSH_ARRAYS` on: past its flags (and
/// the option after `-o` or `+o`), its first word is not `zsh`. One with no
/// word after it in its line may be given any by an alias or a function
/// that runs it (`alias em=emulate`).
pub(super) fn emulates_other(text: &str) -> bool {
    code_lines(text).any(|line| {
        let part = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '/' | '-');
        line.match_indices("emulate").any(|(at, found)| {
            if line[..at].chars().next_back().is_some_and(part)
                || line[at + found.len()..].chars().next().is_some_and(part)
            {
                return false;
            }
            let rest = line[at + found.len()..]
                .split([';', '&', '|', '(', ')', '`'])
                .next()
                .unwrap_or_default();
            let mut words = rest.split_whitespace();
            while let Some(word) = words.next() {
                if matches!(word, "-o" | "+o") {
                    words.next();
                } else if !word.starts_with(['-', '+']) {
                    return word != "zsh";
                }
            }
            true
        })
    })
}

/// Whether `text`, zsh code, may turn `RCS` or `GLOBAL_RCS` on again, which
/// make a zsh started with `-f` or `-d` read the startup files it skips: a
/// word that names one of them, in either form and as [`options`] reads
/// words; a `set`, `setopt` or `unsetopt` with a word of flags that holds `f`
/// or `d`, the letters of `NO_RCS` and `NO_GLOBAL_RCS` (`set +f`); and an
/// `emulate`, as `emulate -R` sets every option as zsh starts with it. A line
/// that is a comment is left out.
pub(super) fn names_rcs(text: &str) -> bool {
    names_any(text, &["rcs", "globalrcs"])
        || text.lines().filter(|line| !comment_line(line)).any(|line| {
            let flags = ["set", "setopt", "unsetopt"]
                .iter()
                .any(|command| whole_words(line, command) > 0)
                && line.split_whitespace().any(|word| {
                    let word = word.trim_matches(['\'', '"', '\\']);
                    word.len() > 1
                        && word.starts_with(['-', '+'])
                        && word[1..].starts_with(|c: char| c.is_ascii_alphabetic())
                        && word.contains(['f', 'd'])
                });
            // A computed flag or name (`set +$x`), and an `exec`, which
            // may start another zsh without `-f`.
            let computed = ["set", "setopt", "unsetopt"].iter().any(|command| {
                line.match_indices(command).any(|(at, _)| {
                    whole_words(&line[at..], command) > 0 && line[at..].contains(['$', '`'])
                })
            });
            flags || computed || whole_words(line, "emulate") > 0 || whole_words(line, "exec") > 0
        })
}

/// Whether `word` names the option `ALIASES`, as zsh reads an option's name
/// (case and underscores aside): `Some(true)` for `aliases`, `Some(false)`
/// for its `no` form; `None` for any other word.
pub(super) fn aliases_option(word: &str) -> Option<bool> {
    let name: String = word
        .chars()
        .filter(|c| *c != '_')
        .collect::<String>()
        .to_lowercase();
    match name.as_str() {
        "aliases" => Some(true),
        "noaliases" => Some(false),
        _ => None,
    }
}

/// Whether `word`, the name of an option a command turns on (`on`) or off,
/// may turn `ALIASES` off, as brace expansion may make it (`unsetopt
/// ALIASES`, `setopt no_aliases`, `set -o noaliases`): a word brace expansion
/// makes too much of may.
pub(super) fn turns_aliases_off(word: &str, on: bool) -> bool {
    braces(word).is_none_or(|words| {
        words
            .iter()
            .any(|word| aliases_option(word).is_some_and(|plain| plain != on))
    })
}

/// How often `text` names the option `ALIASES` in a spelling other than
/// `aliases` alone, which names the parameter that holds the aliases as
/// well (`setopt NO_ALIASES`, `unsetopt Aliases`, `options[no_aliases]`),
/// as [`options`] reads words.
pub(super) fn aliases_mentions(text: &str) -> usize {
    let named = |part: &str| (part != "aliases" && aliases_option(part).is_some()).then_some(());
    let mut found = Vec::new();
    for chunk in text.split_whitespace() {
        match braces(chunk) {
            Some(words) => {
                for word in words {
                    named_in(&word, &named, &mut found);
                }
            }
            None => found.push(()),
        }
    }
    found.len()
}

/// The keys of the elements of the parameter `name` that an expansion in
/// `text`, a word of zsh code, assigns as zsh expands it
/// (`${options[aliases]::=off}`, `${(L)options[x]:=on}`), as written.
pub(super) fn expansion_elements(text: &str, name: &str) -> Vec<String> {
    let modifiers = ['#', '+', '=', '~', '^'];
    let opener = format!("{name}[");
    text.match_indices(&opener)
        .filter(|&(at, _)| {
            let mut before = text[..at].trim_end_matches(modifiers);
            if let Some(flagged) = before.strip_suffix(')')
                && let Some(open) = flagged.rfind("${(")
            {
                before = &flagged[..open + 2];
            }
            before.ends_with("${") && is_write(text, at, name.len())
        })
        .filter_map(|(at, found)| {
            let key = &text[at + found.len()..];
            let mut depth = 1usize;
            for (end, c) in key.char_indices() {
                match c {
                    '[' => depth += 1,
                    ']' => {
                        depth -= 1;
                        if depth == 0 {
                            return Some(key[..end].to_string());
                        }
                    }
                    _ => {}
                }
            }
            None
        })
        .collect()
}

/// Whether `text`, zsh code, may turn `PROMPT_SUBST` on, which makes zsh run
/// what a prompt holds as it shows it: it names the option, or its other name
/// `PROMPT_VARS` (zsh's alias for bash's), or runs an `emulate`, as sh's and
/// ksh's emulation turn it on.
pub(super) fn names_prompt_subst(text: &str) -> bool {
    names_any(text, &["promptsubst", "promptvars"])
        || text
            .lines()
            .filter(|line| !comment_line(line))
            .any(|line| whole_words(line, "emulate") > 0)
}
