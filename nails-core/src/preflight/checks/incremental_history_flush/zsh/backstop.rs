// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What a startup file's lines name, counted without the lexer and
//! wherever it stands: the options that write each command line to the
//! history file, `source`, a `.` with a word after it, `eval`, an alias that
//! stands for `.`, `autoload`, an `fc` that may write the history file, and
//! the `ZDOTDIR` and `fpath` settings. The walk counts the same as it reads
//! them as code it follows, and what the lines name beyond that is what it
//! did not follow: an option named there counts as on, an `fpath` setting
//! adds a directory the check cannot follow, and the rest is a doubt.
//!
//! Only a line whose first character that is not a blank is `#` is left out,
//! so an option a comment at the end of a line names counts as on too, and a
//! `source` or `eval` anywhere else than in a command the walk follows, as in
//! a string, an `echo`, an alias or a here-document, is a doubt.

use super::walk::option;

/// What the lines of a file name, outside the lines that are a comment.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct Named {
    /// Each of [`super::OPTIONS`], in any spelling and in its `no` form too.
    pub(super) options: [usize; 3],
    /// `source`, a `.` with a word after it, and a `.` an alias stands for.
    pub(super) sources: usize,
    /// `eval`.
    pub(super) evals: usize,
    /// `ZDOTDIR` where it is not read ([`zdotdir_writes`]).
    pub(super) zdotdirs: usize,
    /// `autoload`.
    pub(super) autoloads: usize,
    /// `fpath` and `FPATH` where they are not read ([`fpath_writes`]).
    pub(super) fpaths: usize,
    /// `fc` with a flag that writes the history file, or an expansion
    /// ([`fc_writes`]).
    pub(super) fcs: usize,
}

/// What the lines of zsh code `text` name.
pub(super) fn named(text: &str) -> Named {
    let mut named = Named::default();
    for line in text.lines() {
        if line.trim_start().starts_with('#') {
            continue;
        }
        for (at, _) in options(line) {
            named.options[at] += 1;
        }
        named.sources += whole_words(line, "source") + dot_words(line) + alias_dots(line);
        named.evals += whole_words(line, "eval");
        named.zdotdirs += zdotdir_writes(line);
        named.autoloads += whole_words(line, "autoload");
        named.fpaths += fpath_writes(line);
        named.fcs += fc_writes(line);
    }
    named
}

/// The flags of `fc` that write the history file: `-A` appends to it, `-W`
/// writes it, and `-P` writes the list it pops.
pub(super) const FC_WRITES: [char; 3] = ['A', 'W', 'P'];

/// Whether `word`, a word of an `fc` command with its quotes taken off, is
/// one of its flags: a `-` and a letter (`-AI`), not a number (`-10`).
pub(super) fn is_fc_flag(word: &str) -> bool {
    word.strip_prefix('-')
        .is_some_and(|flags| flags.starts_with(|c: char| c.is_ascii_alphabetic()))
}

/// How often an `fc` stands in `line` as a word of its own with a flag
/// after it that writes the history file ([`FC_WRITES`]), or an expansion
/// that may be one, before its options end or the command does.
fn fc_writes(line: &str) -> usize {
    let part = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '/' | '-');
    line.match_indices("fc")
        .filter(|&(at, found)| {
            let rest = &line[at + found.len()..];
            if line[..at].chars().next_back().is_some_and(part)
                || rest.chars().next().is_some_and(part)
            {
                return false;
            }
            let command = rest
                .split([';', '&', '|', '(', ')', '`', '}'])
                .next()
                .unwrap_or_default();
            for word in command.split_whitespace() {
                let word = word.replace(['\'', '"', '\\'], "");
                if word.contains('$') {
                    return true;
                }
                if !is_fc_flag(&word) {
                    return false;
                }
                if word.contains(FC_WRITES) {
                    return true;
                }
            }
            false
        })
        .count()
}

/// How often `word` stands in `line` as a word of its own: with no letter,
/// digit, `_`, `.`, `/` or `-` beside it.
fn whole_words(line: &str, word: &str) -> usize {
    let part = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '/' | '-');
    line.match_indices(word)
        .filter(|&(at, found)| {
            !line[..at].chars().next_back().is_some_and(part)
                && !line[at + found.len()..].chars().next().is_some_and(part)
        })
        .count()
}

/// How often a `.` stands in `line` as a word of its own, quotes and a
/// backslash around it taken off, with another word after it, as in
/// `. file`; not before an option or a `]]` (`find . -name`, `[[ -d . ]]`).
fn dot_words(line: &str) -> usize {
    line.split([';', '&', '|', '(', ')', '{', '}', '`'])
        .map(|piece| {
            let words: Vec<&str> = piece
                .split_whitespace()
                .map(|word| word.trim_matches(['\'', '"', '\\']))
                .collect();
            words
                .windows(2)
                .filter(|pair| {
                    pair[0] == "." && !pair[1].starts_with('-') && !matches!(pair[1], "]]" | "]")
                })
                .count()
        })
        .sum()
}

/// How often an alias in `line` stands for `.`, past the precommands before
/// it, its quotes and backslashes taken off (`alias s=.`, `alias s='. f'`,
/// `alias s='builtin .'`, `alias s=\.`, `aliases[s]=.`).
fn alias_dots(line: &str) -> usize {
    if whole_words(line, "alias") == 0 && !line.contains("aliases[") {
        return 0;
    }
    line.match_indices('=')
        .filter(|&(at, _)| {
            let value = line[at + 1..].replace(['\'', '"', '\\'], " ");
            value
                .split_whitespace()
                .find(|word| {
                    !matches!(
                        *word,
                        "builtin" | "command" | "noglob" | "nocorrect" | "exec" | "-"
                    )
                })
                .is_some_and(|word| word == "." || word.starts_with(".;"))
        })
        .count()
}

/// The options that `text` names, by their place in [`super::OPTIONS`], in
/// either form: in each word of it as brace expansion may make it
/// ([`braces`]), each part between characters that are no letter, digit or
/// `_`, and, after a `-` or `+`, what follows an `o` in the part, as
/// `set -oshare_history` takes it. A word that brace expansion makes too
/// much of names every option.
pub(super) fn options(text: &str) -> Vec<(usize, bool)> {
    let mut found = Vec::new();
    for chunk in text.split_whitespace() {
        match braces(chunk) {
            Some(words) => {
                for word in words {
                    named_in(&word, &option, &mut found);
                }
            }
            None => found.extend((0..super::OPTIONS.len()).map(|at| (at, true))),
        }
    }
    found
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
        || text
            .lines()
            .filter(|line| !line.trim_start().starts_with('#'))
            .any(|line| {
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
                flags
                    || computed
                    || whole_words(line, "emulate") > 0
                    || whole_words(line, "exec") > 0
            })
}

/// Whether `text`, a word of zsh code, names a history file: `$HISTFILE` or
/// an expansion of it, or a path whose last part holds `hist` in any case
/// (`~/.zsh_history`, `~/.histfile`, `of=$HOME/.zhistory`).
pub(super) fn history_path(text: &str) -> bool {
    let last = text.rsplit(['/', '=']).next().unwrap_or(text);
    text.contains("$HISTFILE")
        || text.contains("${HISTFILE")
        || last.to_lowercase().contains("hist")
}

/// Whether `text`, zsh code, names one of the options `wanted` (as zsh
/// compares names: lower case, without `_`), in either form and as
/// [`options`] reads words, outside a line that is a comment.
pub(super) fn names_any(text: &str, wanted: &[&str]) -> bool {
    let named = |word: &str| {
        let name: String = word
            .chars()
            .filter(|c| *c != '_')
            .collect::<String>()
            .to_lowercase();
        let name = name.strip_prefix("no").unwrap_or(&name);
        wanted.contains(&name).then_some(())
    };
    text.lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .any(|line| {
            line.split_whitespace().any(|chunk| match braces(chunk) {
                Some(words) => words.iter().any(|word| {
                    let mut found = Vec::new();
                    named_in(word, &named, &mut found);
                    !found.is_empty()
                }),
                None => true,
            })
        })
}

/// Whether `text`, zsh code, may turn `PROMPT_SUBST` on, which makes zsh run
/// what a prompt holds as it shows it: it names the option, or runs an
/// `emulate`, as sh's and ksh's emulation turn it on.
pub(super) fn names_prompt_subst(text: &str) -> bool {
    names_any(text, &["promptsubst"])
        || text
            .lines()
            .filter(|line| !line.trim_start().starts_with('#'))
            .any(|line| whole_words(line, "emulate") > 0)
}

/// Whether `text`, a word of zsh code, expands a parameter's value again,
/// which may run code or set a parameter (`${options[...]::=on}`): with the
/// `(e)` flag, with `(%%)`, which expands it in full as a prompt, or as a
/// pattern (`${~name}`, `$~name`), where a glob qualifier in the value runs
/// code. One `%` only expands a prompt's escapes (`${(%):-%~}`).
pub(super) fn reexpands(text: &str) -> bool {
    text.contains("${~")
        || text.contains("$~")
        || text.match_indices("${(").any(|(at, found)| {
            let flags = &text[at + found.len()..];
            flags
                .split(')')
                .next()
                .is_some_and(|flags| flags.contains('e') || flags.matches('%').count() > 1)
        })
}

/// Add what the parts of `word` name, as `named` reads a part, to `found`
/// ([`options`]).
fn named_in<T>(word: &str, named: &impl Fn(&str) -> Option<T>, found: &mut Vec<T>) {
    let mut start = None;
    for (at, c) in word
        .char_indices()
        .chain(std::iter::once((word.len(), ' ')))
    {
        let part = c.is_ascii_alphanumeric() || c == '_';
        match start {
            None if part => start = Some(at),
            Some(from) if !part => {
                let piece = &word[from..at];
                if let Some(hit) = named(piece) {
                    found.push(hit);
                } else if word[..from].ends_with(['-', '+']) {
                    // Flags, an `o` among them, and the option's name after it.
                    found.extend(
                        piece
                            .match_indices('o')
                            .find_map(|(o, _)| named(&piece[o + 1..])),
                    );
                }
                start = None;
            }
            _ => {}
        }
    }
}

/// The most words that brace expansion is followed into for one word of
/// code; one that makes more names every option ([`options`]).
const BRACE_LIMIT: usize = 1024;

/// What stands for the `{` and the `}` of a group that brace expansion
/// leaves as written, so that it is not expanded again.
const KEPT: (char, char) = ('\u{1}', '\u{2}');

/// The words that brace expansion may make of `word`, a word of zsh code as
/// written, as far as they may name an option, and more: each alternative of
/// a `{a,b}` list, and of a `{x..y}` range and, as `BRACE_CCL` makes it, of
/// a `{abc}` group (its ranges too, as in `{a-z}`) each character that an
/// option's name may hold ([`NAME_CHARS`]), beside the group as written.
/// `None` when that makes more than [`BRACE_LIMIT`].
pub(super) fn braces(word: &str) -> Option<Vec<String>> {
    let mut done = Vec::new();
    let mut todo = vec![word.to_string()];
    while let Some(word) = todo.pop() {
        match group(&word) {
            None => done.push(word),
            Some((open, close)) => {
                for alternative in alternatives(&word[open + 1..close]) {
                    todo.push(format!(
                        "{}{alternative}{}",
                        &word[..open],
                        &word[close + 1..]
                    ));
                }
            }
        }
        if done.len() + todo.len() > BRACE_LIMIT {
            return None;
        }
    }
    Some(done)
}

/// Where the first group that brace expansion expands in `word` opens and
/// closes: a `{` with its `}`, past a parameter's expansion (`${...}`).
fn group(word: &str) -> Option<(usize, usize)> {
    let bytes = word.as_bytes();
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'$' && bytes.get(at + 1) == Some(&b'{') {
            at = closing(bytes, at + 1).map_or(at + 2, |close| close + 1);
        } else if bytes[at] == b'{' {
            match closing(bytes, at) {
                Some(close) => return Some((at, close)),
                None => at += 1,
            }
        } else {
            at += 1;
        }
    }
    None
}

/// The `}` that closes the `{` at `open` in `bytes`, nested ones counted.
fn closing(bytes: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (at, &byte) in bytes.iter().enumerate().skip(open) {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(at);
                }
            }
            _ => {}
        }
    }
    None
}

/// The characters of the names of [`super::OPTIONS`] and of their `no`
/// form, in either case, and the `_` that zsh skips in a name: no other
/// character a group of brace expansion stands for can make a word name one.
const NAME_CHARS: &str = "incapedhstorymINCAPEDHSTORYM_";

/// What a group of brace expansion, `content` between its braces, may stand
/// for ([`braces`]).
fn alternatives(content: &str) -> Vec<String> {
    let mut parts = vec![String::new()];
    let mut depth = 0usize;
    for c in content.chars() {
        match c {
            '{' => depth += 1,
            '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                parts.push(String::new());
                continue;
            }
            _ => {}
        }
        parts.last_mut().expect("a part").push(c);
    }
    if parts.len() > 1 {
        return parts;
    }
    let mut alternatives = vec![format!("{}{content}{}", KEPT.0, KEPT.1)];
    let mut add = |from: char, to: char| {
        for c in from.min(to)..=from.max(to) {
            if NAME_CHARS.contains(c) && !alternatives.iter().any(|known| *known == c.to_string()) {
                alternatives.push(c.to_string());
            }
        }
    };
    // A range, `{a..e}` or `{1..9..2}`; one of numbers makes digits, which
    // no option's name holds.
    if let Some((from, to)) = content.split_once("..") {
        let to = to.split("..").next().unwrap_or_default();
        let one = |text: &str| {
            let mut chars = text.chars();
            chars.next().filter(|_| chars.next().is_none())
        };
        if let (Some(from), Some(to)) = (one(from), one(to)) {
            add(from, to);
            return alternatives;
        }
        if from.parse::<i64>().is_ok() && to.parse::<i64>().is_ok() {
            alternatives.push("0".to_string());
            return alternatives;
        }
    }
    let chars: Vec<char> = content.chars().collect();
    let mut at = 0;
    while at < chars.len() {
        if at + 2 < chars.len() && chars[at + 1] == '-' {
            add(chars[at], chars[at + 2]);
            at += 3;
        } else {
            add(chars[at], chars[at]);
            at += 1;
        }
    }
    alternatives
}

/// Whether `text`, a word of zsh code as written, holds a glob qualifier
/// that runs code as zsh expands the word: `e` and a delimiter around the
/// code (`*(e:'...':)`, `*(#qe'...')`), or `+` and a command (`*(+func)`).
/// What `$(( ))` holds is arithmetic, not a glob.
pub(super) fn qualifier_code(text: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    let mut at = 0;
    while at < chars.len() {
        if chars[at] == '$' && chars.get(at + 1) == Some(&'(') && chars.get(at + 2) == Some(&'(') {
            // Arithmetic: past its `))`.
            let mut depth = 0usize;
            at += 1;
            while at < chars.len() {
                match chars[at] {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
                at += 1;
            }
        } else if chars[at] == '(' && (at == 0 || chars[at - 1] != '$') {
            let rest = &chars[at + 1..];
            for (i, &c) in rest.iter().enumerate() {
                let next = rest.get(i + 1).copied();
                let code = match (c, next) {
                    ('e', Some(open)) if open.is_ascii_punctuation() && open != ')' => {
                        let close = match open {
                            '(' => ')',
                            '[' => ']',
                            '{' => '}',
                            '<' => '>',
                            other => other,
                        };
                        rest[i + 2..].contains(&close)
                    }
                    ('+', Some(name)) => name.is_ascii_alphabetic() || matches!(name, '_' | '{'),
                    _ => false,
                };
                if code {
                    return true;
                }
            }
        }
        at += 1;
    }
    false
}

/// How often `text` names `ZDOTDIR` otherwise than to read it ([`writes`]).
pub(super) fn zdotdir_writes(text: &str) -> usize {
    writes(text, "ZDOTDIR")
}

/// How often `text` names `fpath` or `FPATH` otherwise than to read it
/// ([`writes`]).
pub(super) fn fpath_writes(text: &str) -> usize {
    writes(text, "fpath") + writes(text, "FPATH")
}

/// How often `text` names the variable `name` otherwise than to read it:
/// anywhere but after `$` or `${` (with flags, as in `${(@)name}`, or a `#`,
/// `+`, `=`, `~` or `^` between), and in `${name=...}`, `${name:=...}` or
/// `${name::=...}`.
fn writes(text: &str, name: &str) -> usize {
    let part = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let modifiers = ['#', '+', '=', '~', '^'];
    text.match_indices(name)
        .filter(|&(at, found)| {
            let before = &text[..at];
            let after = &text[at + found.len()..];
            if before.chars().next_back().is_some_and(part)
                || after.chars().next().is_some_and(part)
            {
                return false;
            }
            let mut before = before.trim_end_matches(modifiers);
            if let Some(flagged) = before.strip_suffix(')')
                && let Some(open) = flagged.rfind("${(")
                && !flagged[open + 3..].contains(['}', '$', '\n'])
            {
                before = flagged[..open + 2].trim_end_matches(modifiers);
            }
            let braced = before.ends_with("${");
            let read = braced || before.ends_with('$');
            !read
                || (braced
                    && (after.starts_with('=')
                        || after.starts_with(":=")
                        || after.starts_with("::=")))
        })
        .count()
}
