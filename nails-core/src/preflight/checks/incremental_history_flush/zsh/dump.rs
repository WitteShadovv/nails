// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The dump file that the stock `compinit` sources (`~/.zcompdump`), as the
//! stock `compdump` writes it: a first line that counts the files and names
//! zsh's version; the arrays of the completion system (`_comps=(`, ...,
//! each line a pair of quoted words); the completion widgets (`zle -C`) and
//! the keys bound to them (`bindkey`), every one named with a leading `_`;
//! `zmodload -i zsh/complist`; the completion functions it marks to be
//! autoloaded (`autoload -Uz _name ...`); and `_comp_assocs`. A file whose
//! every line is one of those holds data and marks alone, but for a key
//! bound to a widget otherwise than zsh's own completion functions bind
//! theirs ([`BINDINGS`]), which may be a key a line is typed with (Space,
//! Enter in any spelling). One with any other line, edited by hand or
//! written by another tool, is read as code.

/// The arrays `compdump` writes, each opened on a line of its own.
const ARRAYS: [&str; 5] = [
    "_comps=(",
    "_services=(",
    "_patcomps=(",
    "_postpatcomps=(",
    "_compautos=(",
];

/// The arrays of [`ARRAYS`] whose values are code that zsh's completion
/// system runs (`_dispatch` runs each with `eval`), which the stock
/// `compdump` writes as the names of completion functions alone, a
/// `_patcomps` one after the service it gives (`=service=_name`).
const RUN: [&str; 3] = ["_comps=(", "_patcomps=(", "_postpatcomps=("];

/// Where a line of a dump file stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Between the parts.
    Top,
    /// In an array, before its `)`; `run` when its values are code
    /// ([`RUN`]).
    Array { run: bool },
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
/// a dump file holds: `'key' 'value'`; with `run`, one whose value is the
/// name of a completion function, after a service in `=...=` or not, as the
/// stock `compdump` writes those of the arrays whose values are code
/// ([`RUN`]), and no other code.
fn pair(line: &str, run: bool) -> bool {
    let Some(value) = quoted(line).and_then(|rest| rest.strip_prefix(' ')) else {
        return false;
    };
    if !quoted(value).is_some_and(str::is_empty) {
        return false;
    }
    let value = &value[1..value.len() - 1];
    let function = match value
        .strip_prefix('=')
        .and_then(|rest| rest.split_once('='))
    {
        Some((service, function)) if completion_name(&format!("_{service}")) => function,
        Some(_) => return !run,
        None => value,
    };
    !run || completion_name(function)
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

/// The keys that zsh's own completion functions bind to their widgets
/// (their first lines, `#compdef -k` and `-K`), as `compdump` writes them:
/// a `^X` sequence or an escape and one key, none a line is typed with.
const BINDINGS: [(&str, &str); 15] = [
    ("^X^R", "_read_comp"),
    ("^X?", "_complete_debug"),
    ("^XC", "_correct_filename"),
    ("^Xa", "_expand_alias"),
    ("^Xc", "_correct_word"),
    ("^Xd", "_list_expansions"),
    ("^Xe", "_expand_word"),
    ("^Xh", "_complete_help"),
    ("^Xm", "_most_recent_file"),
    ("^Xn", "_next_tags"),
    ("^Xt", "_complete_tag"),
    ("^X~", "_bash_list-choices"),
    ("^[,", "_history-complete-newer"),
    ("^[/", "_history-complete-older"),
    ("^[~", "_bash_complete-word"),
];

/// Whether `line` is a `bindkey` of a dump file that binds keys the way
/// zsh's own completion functions do ([`BINDINGS`]). Any other binding may
/// be of a key a line is typed with (Space, a letter, Enter as `^M`, `^m`,
/// `\C-M` or `\015`), which runs the widget as the line is typed.
fn binding(line: &str) -> bool {
    BINDINGS
        .iter()
        .any(|(keys, widget)| line == format!("bindkey '{keys}' {widget}"))
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

/// The words of the dump file `text` that zsh runs as commands, one on each
/// line: the first word of each of its lines that starts with a letter
/// (`zle`, `bindkey`, `autoload`, `zmodload`, `typeset`).
pub(super) fn commands(text: &str) -> String {
    text.lines()
        .filter_map(|line| line.split(' ').next())
        .filter(|word| word.starts_with(|c: char| c.is_ascii_alphabetic()))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The completion functions the dump file `text` marks to be autoloaded,
/// when each of its lines is one the stock `compdump` writes; `None` when a
/// line is any other, and when the text holds a control character but a tab
/// or a newline, which compdump never writes and zsh may read otherwise
/// than the check does (a backslash before a carriage return quotes it, so
/// the newline after it ends the line).
pub(super) fn marks(text: &str) -> Option<Vec<String>> {
    if text
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\t' | '\n'))
    {
        return None;
    }
    let mut lines = text.split('\n');
    if !lines.next().is_some_and(header) {
        return None;
    }
    let mut marks = Vec::new();
    let mut state = State::Top;
    for line in lines {
        state = match state {
            State::Array { .. } if line == ")" => State::Top,
            State::Array { run } if pair(line, run) => State::Array { run },
            State::Array { .. } => return None,
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
            State::Top if ARRAYS.contains(&line) => State::Array {
                run: RUN.contains(&line),
            },
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
                    // The option `#autoload` gives a function comes before
                    // its name (`autoload -Uz +X _call_program`): `+X`, which
                    // loads it at once without running it, and no other
                    // (`-w` marks the functions of a compiled file).
                    let words = words.split_whitespace().skip_while(|word| *word == "+X");
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
            // Enter as bindkey also reads it, Space, and a key of zsh's own
            // bound to another widget.
            ("bindkey '^X^R' _read_comp", "bindkey '^m' _read_comp"),
            ("bindkey '^X^R' _read_comp", "bindkey '^j' _read_comp"),
            ("bindkey '^X^R' _read_comp", "bindkey '\\C-M' _read_comp"),
            ("bindkey '^X^R' _read_comp", "bindkey '\\015' _read_comp"),
            ("bindkey '^X^R' _read_comp", "bindkey '\\x0d' _read_comp"),
            ("bindkey '^X^R' _read_comp", "bindkey ' ' _read_comp"),
            ("bindkey '^X^R' _read_comp", "bindkey 'a' _read_comp"),
            ("bindkey '^X^R' _read_comp", "bindkey '^X^R' _evil"),
            ("bindkey '^X^R' _read_comp", "bindkey '^X^R'  _read_comp"),
            ("bindkey '^X^R'", "bindkey -s '^X^R'"),
            ("_abcde \\\n", "_abcde\n"),
            // A value of an array of code that is no name of a completion
            // function, which `_dispatch` runs with `eval`.
            ("'eval' '_precommand'", "'eval' 'print $BUFFER >> ~/.zl'"),
            ("'eval' '_precommand'", "'eval' 'precommand'"),
            ("'eval' '_precommand'", "'eval' '_precommand;x'"),
            ("'*/(init|rc[0-9S]#).d/*' '_init_d'", "'x*' '=s v=_init_d'"),
            ("'*/(init|rc[0-9S]#).d/*' '_init_d'", "'x*' '=svc=init_d'"),
            ("'(p[bgpn]m*|*top[bgpn]m)' '_pbm'", "'x*' '_p'\\''bm'"),
            ("_zstyle _ztodo _zypper", "_zstyle _ztodo $f"),
            ("_zstyle _ztodo _zypper", "_zstyle _ztodo zypper"),
            (
                "autoload -Uz +X _call_program",
                "autoload -Uz +X _call_program; source ~/x",
            ),
            ("autoload -Uz +X", "autoload -X"),
            ("autoload -Uz +X", "autoload -Uz -w"),
            ("autoload -Uz +X", "autoload -Uz +X -m"),
            ("autoload -Uz +X _call_program", "autoload -Uz +X precmd"),
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
        // A carriage return before a newline, which zsh keeps in a line (a
        // backslash before it quotes it, so the newline ends the line), and
        // any other control character but a tab, make it code.
        for text in [
            "#files: 1\tversion: 5.9.2\n\nautoload -Uz _a \\\r\n           _evil\n",
            "#files: 1\tversion: 5.9.2\n\nautoload -Uz _a _b \\\r\n           _evil _f\n",
            "#files: 1\tversion: 5.9.2\r\n\nautoload -Uz _a\n",
            "#files: 1\tversion: 5.9.2\n\nautoload -Uz _a\x0b_b\n",
            "#files: 1\tversion: 5.9.2\n\nautoload -Uz _a\0\n",
        ] {
            assert_eq!(marks(text), None, "{text:?}");
        }
        assert_eq!(
            marks("#files: 1\tversion: 5.9.2\n\nautoload -Uz _a \\\n           _b\n"),
            Some(vec!["_a".to_string(), "_b".to_string()])
        );
        // The line that may open a part closes it too, at the end.
        assert_eq!(
            marks(&DUMP.replacen(")\n\n_services", "\n\n_services", 1)),
            None
        );
        assert_eq!(marks("_comps=(\n)\n"), None);
        assert_eq!(marks("#files: 1\tversion: 5.9.2\n_comps=(\n"), None);
        // A pattern's completion after the service it gives, and a
        // service's name, are data.
        for (from, to) in [
            ("'*/(init|rc[0-9S]#).d/*' '_init_d'", "'x*' '=svc=_init_d'"),
            ("'bzcat' 'bunzip2'", "'bzcat' 'b z'"),
        ] {
            assert!(marks(&DUMP.replacen(from, to, 1)).is_some(), "{to}");
        }
        // `zmodload -i zsh/complist` is one compdump writes.
        let text = DUMP.replace("bindkey '^X^R'", "zmodload -i zsh/complist\nbindkey '^X^R'");
        assert!(marks(&text).is_some());
    }
}
