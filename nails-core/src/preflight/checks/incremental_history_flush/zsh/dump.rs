// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The dump file that the stock `compinit` sources (`~/.zcompdump`), as the
//! stock `compdump` writes it: a first line that counts the files and names
//! zsh's version; the arrays of the completion system (`_comps=(`, ...,
//! each line a pair of quoted words); the completion widgets (`zle -C`) and
//! the keys bound to them (`bindkey`), every one named with a leading `_`;
//! `zmodload -i zsh/complist`; the completion functions it marks to be
//! autoloaded (`autoload -Uz _name ...`); and `_comp_assocs`. A file whose
//! every line is one of those holds data and marks alone. One with any
//! other line, edited by hand or written by another tool, is read as code.

/// The arrays `compdump` writes, each opened on a line of its own.
const ARRAYS: [&str; 5] = [
    "_comps=(",
    "_services=(",
    "_patcomps=(",
    "_postpatcomps=(",
    "_compautos=(",
];

/// Where a line of a dump file stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Between the parts.
    Top,
    /// In an array, before its `)`.
    Array,
    /// In the names of an `autoload` whose line ended with a backslash.
    Names,
}

/// Whether `name` is the name of a completion function or widget as
/// `compdump` writes one: a leading `_`, then letters, digits and the
/// punctuation of file names, nothing zsh expands.
fn completion_name(name: &str) -> bool {
    name.starts_with('_')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '+' | ':' | '@'))
}

/// The rest of `text` past a word in single quotes at its start, as `(qq)`
/// quotes one: `'...'`, a quote in it written `'\''`; `None` when it starts
/// with none.
fn quoted(text: &str) -> Option<&str> {
    let mut rest = text.strip_prefix('\'')?;
    loop {
        let end = rest.find('\'')?;
        rest = &rest[end + 1..];
        match rest.strip_prefix("\\''") {
            Some(more) => rest = more,
            None => return Some(rest),
        }
    }
}

/// Whether `line` is a pair of words in single quotes, as an array's line of
/// a dump file holds: `'key' 'value'`.
fn pair(line: &str) -> bool {
    quoted(line)
        .and_then(|rest| rest.strip_prefix(' '))
        .and_then(quoted)
        .is_some_and(str::is_empty)
}

/// Whether `line` holds words in single quotes alone, each after a blank.
fn quoted_words(mut line: &str) -> bool {
    while let Some(rest) = line.strip_prefix(' ') {
        match quoted(rest) {
            Some(rest) => line = rest,
            None => return false,
        }
    }
    line.is_empty()
}

/// Whether `line` is a `bindkey` of a dump file: a key sequence in single
/// quotes, as written with no quote in it, and the completion widget bound to
/// it. A binding of the keys that end a line (`^M`, `^J`) is none, as zsh
/// would run the widget as each line is entered.
fn binding(line: &str) -> bool {
    let Some(rest) = line.strip_prefix("bindkey '") else {
        return false;
    };
    let Some((keys, widget)) = rest.split_once("' ") else {
        return false;
    };
    !keys.is_empty()
        && !keys.contains(['\'', '\n'])
        && !matches!(keys, "^M" | "^J" | "\\r" | "\\n" | "\\C-m" | "\\C-j")
        && completion_name(widget)
}

/// Whether `line` is a `zle -C` of a dump file: a completion widget, the
/// builtin widget it behaves like (`.complete-word`), and the function it
/// runs, both names with a leading `_`.
fn widget(line: &str) -> bool {
    let words: Vec<&str> = line.split(' ').collect();
    matches!(
        words.as_slice(),
        ["zle", "-C", name, builtin, function]
            if completion_name(name)
                && completion_name(function)
                && builtin.strip_prefix('.').is_some_and(|builtin| {
                    !builtin.is_empty()
                        && builtin.chars().all(|c| c.is_ascii_lowercase() || c == '-')
                })
    )
}

/// The names `words` marks to be autoloaded, all completion functions;
/// `None` when one is no such name.
fn names<'a>(words: impl Iterator<Item = &'a str>) -> Option<Vec<String>> {
    words
        .map(|word| completion_name(word).then(|| word.to_string()))
        .collect()
}

/// The first line `compdump` writes: `#files: <count>\tversion: <version>`.
fn header(line: &str) -> bool {
    line.strip_prefix("#files: ")
        .and_then(|rest| rest.split_once("\tversion: "))
        .is_some_and(|(count, version)| {
            !count.is_empty()
                && count.chars().all(|c| c.is_ascii_digit())
                && !version.is_empty()
                && !version.contains(char::is_whitespace)
        })
}

/// The completion functions the dump file `text` marks to be autoloaded,
/// when each of its lines is one the stock `compdump` writes; `None` when a
/// line is any other.
pub(super) fn marks(text: &str) -> Option<Vec<String>> {
    let mut lines = text.lines();
    if !lines.next().is_some_and(header) {
        return None;
    }
    let mut marks = Vec::new();
    let mut state = State::Top;
    for line in lines {
        state = match state {
            State::Array if line == ")" => State::Top,
            State::Array if pair(line) => State::Array,
            State::Array => return None,
            State::Names => {
                let (words, more) = match line.strip_suffix(" \\") {
                    Some(words) => (words, true),
                    None => (line, false),
                };
                if !words.starts_with(' ') {
                    return None;
                }
                marks.extend(names(words.split_whitespace())?);
                if more { State::Names } else { State::Top }
            }
            State::Top if line.is_empty() || line == "zmodload -i zsh/complist" => State::Top,
            State::Top if line == "typeset -gUa _comp_assocs" => State::Top,
            State::Top if ARRAYS.contains(&line) => State::Array,
            State::Top if widget(line) || binding(line) => State::Top,
            State::Top => {
                if let Some(values) = line.strip_prefix("_comp_assocs=(") {
                    match values.strip_suffix(" )") {
                        Some(values) if quoted_words(values) => State::Top,
                        _ => return None,
                    }
                } else {
                    let rest = line.strip_prefix("autoload -Uz")?;
                    let (words, more) = match rest.strip_suffix(" \\") {
                        Some(words) => (words, true),
                        None => (rest, false),
                    };
                    if !words.is_empty() && !words.starts_with(' ') {
                        return None;
                    }
                    // The options `#autoload` gives a function come before
                    // its name (`autoload -Uz +X _call_program`).
                    let words = words.split_whitespace().skip_while(|word| {
                        word.len() > 1
                            && word.starts_with(['-', '+'])
                            && word[1..].chars().all(|c| c.is_ascii_alphabetic())
                    });
                    marks.extend(names(words)?);
                    if more { State::Names } else { State::Top }
                }
            }
        };
    }
    (state == State::Top).then_some(marks)
}

#[cfg(test)]
pub(super) mod tests {
    use super::marks;

    /// A dump file as the stock `compdump` of zsh 5.9.2 writes one, cut
    /// short.
    pub(in super::super) const DUMP: &str = "\
#files: 999\tversion: 5.9.2

_comps=(
'-' '_precommand'
'.' '_source'
'eval' '_precommand'
'it'\\''s' '_files'
)

_services=(
'bzcat' 'bunzip2'
)

_patcomps=(
'*/(init|rc[0-9S]#).d/*' '_init_d'
)

_postpatcomps=(
'(p[bgpn]m*|*top[bgpn]m)' '_pbm'
)

_compautos=(
'_call_program' '+X'
)

zle -C _bash_complete-word .complete-word _bash_completions
zle -C _history-complete-older .complete-word _history_complete_word
bindkey '^X^R' _read_comp
bindkey '^[~' _bash_complete-word

autoload -Uz _7zip _a2ps _a2utils _aap _abcde \\
            _absolute_command_paths _ack _acpi _acpitool _acroread \\
            _zstyle _ztodo _zypper
autoload -Uz +X _call_program

typeset -gUa _comp_assocs
_comp_assocs=( '' )
";

    #[test]
    fn a_dump_compdump_writes_holds_data_and_marks_alone() {
        assert_eq!(
            marks(DUMP),
            Some(
                [
                    "_7zip",
                    "_a2ps",
                    "_a2utils",
                    "_aap",
                    "_abcde",
                    "_absolute_command_paths",
                    "_ack",
                    "_acpi",
                    "_acpitool",
                    "_acroread",
                    "_zstyle",
                    "_ztodo",
                    "_zypper",
                    "_call_program",
                ]
                .map(str::to_string)
                .to_vec()
            )
        );
    }

    #[test]
    fn a_dump_with_any_other_line_is_code() {
        for (from, to) in [
            ("#files: 999", "#files: x"),
            ("'-' '_precommand'", "'-' '_precommand' 'x'"),
            ("'-' '_precommand'", "'-' \"_precommand\""),
            ("'-' '_precommand'", "'-' $x"),
            (")\n\n_services", ")\nsetopt share_history\n_services"),
            ("zle -C _bash_complete-word", "zle -N _bash_complete-word"),
            (
                "zle -C _history-complete-older .complete-word",
                "zle -C zle-line-init .complete-word",
            ),
            (
                ".complete-word _bash_completions",
                ".complete-word bash_completions",
            ),
            ("bindkey '^X^R' _read_comp", "bindkey '^M' _read_comp"),
            ("bindkey '^X^R' _read_comp", "bindkey '^X^R' accept-line"),
            ("bindkey '^X^R'", "bindkey -s '^X^R'"),
            ("_abcde \\\n", "_abcde\n"),
            ("_zstyle _ztodo _zypper", "_zstyle _ztodo $f"),
            ("_zstyle _ztodo _zypper", "_zstyle _ztodo zypper"),
            (
                "autoload -Uz +X _call_program",
                "autoload -Uz +X _call_program; source ~/x",
            ),
            ("autoload -Uz +X", "autoload -X"),
            ("_comp_assocs=( '' )", "_comp_assocs=( $x )"),
            ("typeset -gUa _comp_assocs", "typeset -gUa _comp_assocs x"),
            ("zmodload -i zsh/complist", "zmodload zsh/complist"),
        ] {
            let text = if from == "zmodload -i zsh/complist" {
                DUMP.replace("bindkey '^X^R'", &format!("{to}\nbindkey '^X^R'"))
            } else {
                assert!(DUMP.contains(from), "{from}");
                DUMP.replacen(from, to, 1)
            };
            assert_eq!(marks(&text), None, "{to}");
        }
        // The line that may open a part closes it too, at the end.
        assert_eq!(
            marks(&DUMP.replacen(")\n\n_services", "\n\n_services", 1)),
            None
        );
        assert_eq!(marks("_comps=(\n)\n"), None);
        assert_eq!(marks("#files: 1\tversion: 5.9.2\n_comps=(\n"), None);
        // `zmodload -i zsh/complist` is one compdump writes.
        let text = DUMP.replace("bindkey '^X^R'", "zmodload -i zsh/complist\nbindkey '^X^R'");
        assert!(marks(&text).is_some());
    }
}
