// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What zsh's arithmetic may set. zsh evaluates arithmetic in `(( ))`,
//! `$(( ))`, `let`, an array's subscript, `${x:offset}`, `[[ a -eq b ]]`,
//! `printf %d`, a `repeat` count, an integer's value and many more places
//! ([`super::walk`] finds them), and it reads an expansion there as
//! arithmetic again, and the value of each parameter it names too, so an
//! assignment in what either gives sets a parameter whose name no file
//! writes (`n='HOME=5'; (( n ))`). An expression the check takes as setting
//! nothing it cannot read holds numbers, operators, the names of the
//! parameters zsh keeps a number in ([`NUMERIC`]), a count or a test of a
//! parameter (`$#x`, `${+x}`), and subscripts of arrays whose keys are
//! strings; anything else is a doubt.

use super::walk::Arith;
use super::{Forms, Reader};
use crate::Filesystem;

/// The parameters zsh keeps a number in, whatever is assigned to them, as
/// zsh 5.9 has them: an expression may name them.
pub(super) const NUMERIC: &[&str] = &[
    "ARGC",
    "COLUMNS",
    "EGID",
    "ERRNO",
    "EUID",
    "GID",
    "HISTCMD",
    "HISTSIZE",
    "KEYTIMEOUT",
    "LINENO",
    "LINES",
    "LISTMAX",
    "MAILCHECK",
    "OPTIND",
    "PPID",
    "RANDOM",
    "SAVEHIST",
    "SECONDS",
    "SHLVL",
    "TTYIDLE",
    "UID",
    "ZLE_RPROMPT_INDENT",
    "ZSH_SUBSHELL",
];

/// The parameters zsh keeps a string in and reads as arithmetic each time
/// it uses them, as zsh 5.9 and its modules do (`getiparam`, `mathevali`):
/// the time it waits at a prompt and while it reads a line (`TMOUT`), between
/// two `periodic` hooks, the speed it draws at, the time and memory past
/// which it reports a command, how many directories `cd` keeps, how far menu
/// selection scrolls, and the times of `zsh/watch` and `zsh/zftp`. A value
/// other than a number, as a file sets it or the shell's environment holds it,
/// may run code each time (`TMOUT='a[$(cmd)]'`).
pub(super) const READ_AS_NUMBER: [&str; 9] = [
    "TMOUT",
    "PERIOD",
    "BAUD",
    "REPORTTIME",
    "REPORTMEMORY",
    "DIRSTACKSIZE",
    "MENUSCROLL",
    "LOGCHECK",
    "ZFTP_TMOUT",
];

/// Whether `value`, one a parameter of [`READ_AS_NUMBER`] holds, is a
/// number zsh reads as arithmetic without running anything: digits, a sign
/// before them, or nothing.
pub(super) fn plain_number(value: &str) -> bool {
    let digits = value.strip_prefix(['-', '+']).unwrap_or(value);
    value.is_empty() || (!digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()))
}

/// The arrays of zsh and its modules whose keys are strings: a subscript of
/// one is no arithmetic.
const KEYED: &[&str] = &[
    "aliases",
    "builtins",
    "commands",
    "dis_aliases",
    "dis_builtins",
    "dis_functions",
    "dis_galiases",
    "dis_patchars",
    "dis_reswords",
    "dis_saliases",
    "functions",
    "functions_source",
    "galiases",
    "history",
    "jobdirs",
    "jobstates",
    "jobtexts",
    "mapfile",
    "modules",
    "nameddirs",
    "options",
    "parameters",
    "reswords",
    "saliases",
    "sysparams",
    "termcap",
    "terminfo",
    "userdirs",
    "usergroups",
    "widgets",
    "zsh_eval_context",
];

/// Arrays of zsh's own whose keys are numbers, of which an index a pattern
/// finds is a number (`${precmd_functions[(I)f]}`).
const INDEXED: &[&str] = &[
    "argv",
    "cdpath",
    "chpwd_functions",
    "dirstack",
    "fignore",
    "fpath",
    "funcfiletrace",
    "funcsourcetrace",
    "funcstack",
    "functrace",
    "historywords",
    "mailpath",
    "manpath",
    "match",
    "mbegin",
    "mend",
    "module_path",
    "path",
    "periodic_functions",
    "pipestatus",
    "precmd_functions",
    "preexec_functions",
    "psvar",
    "reply",
    "signals",
    "zsh_directory_name_functions",
    "zshaddhistory_functions",
    "zshexit_functions",
];

/// What an expression holds that the check must know to tell what it
/// sets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Piece {
    /// A parameter it names, whose value zsh evaluates again unless it holds
    /// a number (`n`, `$n`).
    Name(String),
    /// A subscript of the array `name`, an expression unless its keys are
    /// strings.
    Keyed(String, String),
    /// An expansion whose value the check cannot know (`$1`, `$(cmd)`,
    /// `${x:-y}`).
    Opaque(String),
}

/// The pieces of the arithmetic expression `expr` as written ([`Piece`]).
pub(super) fn pieces(expr: &str) -> Vec<Piece> {
    let mut found = Vec::new();
    let chars: Vec<char> = expr.chars().collect();
    let mut at = 0;
    while at < chars.len() {
        let c = chars[at];
        if c == '$' {
            at = expansion(&chars, at, &mut found);
        } else if c == '`' {
            found.push(Piece::Opaque(chars[at..].iter().collect()));
            break;
        } else if c.is_ascii_digit()
            || (c == '.' && chars.get(at + 1).is_some_and(char::is_ascii_digit))
        {
            at = number(&chars, at);
        } else if c == '#' && chars.get(at + 1) == Some(&'#') {
            // A character's code (`##a`, `##\n`).
            at += 2;
            if chars.get(at) == Some(&'\\') {
                at += 1;
            }
            at += 1;
        } else if c == '[' && chars.get(at + 1) == Some(&'#') {
            // The base the result is shown in (`[#16]`).
            while at < chars.len() && chars[at] != ']' {
                at += 1;
            }
            at += 1;
        } else if c.is_ascii_alphabetic() || c == '_' {
            let start = at;
            while at < chars.len() && (chars[at].is_ascii_alphanumeric() || chars[at] == '_') {
                at += 1;
            }
            found.push(Piece::Name(chars[start..at].iter().collect()));
        } else {
            at += 1;
        }
    }
    found
}

/// Where the number that starts at `at` in `chars` ends: hex digits after
/// `0x`, digits and the digits of their base after a `#` (`16#ff`), or
/// digits, a fraction and an exponent (`1.5e+3`).
fn number(chars: &[char], at: usize) -> usize {
    let digits = |from: usize, digit: fn(&char) -> bool| {
        let mut end = from;
        while chars.get(end).is_some_and(digit) {
            end += 1;
        }
        end
    };
    if chars[at] == '0' && matches!(chars.get(at + 1), Some('x' | 'X')) {
        return digits(at + 2, char::is_ascii_hexdigit);
    }
    let mut end = digits(at, char::is_ascii_digit);
    if chars.get(end) == Some(&'#') {
        return digits(end + 1, |c: &char| c.is_ascii_alphanumeric() || *c == '_');
    }
    if chars.get(end) == Some(&'.') {
        end = digits(end + 1, char::is_ascii_digit);
    }
    if matches!(chars.get(end), Some('e' | 'E')) {
        let sign = usize::from(matches!(chars.get(end + 1), Some('+' | '-')));
        if chars.get(end + 1 + sign).is_some_and(char::is_ascii_digit) {
            end = digits(end + 1 + sign, char::is_ascii_digit);
        }
    }
    end
}

/// The index of the `close` that closes the `open` at `at` in `chars`,
/// nested ones counted and quoted ones not; the end when none does.
fn closing(chars: &[char], at: usize, open: char, close: char) -> usize {
    let mut depth = 0usize;
    let mut quote: Option<char> = None;
    let mut index = at;
    while index < chars.len() {
        let c = chars[index];
        match quote {
            Some(_) if c == '\\' => index += 1,
            Some(q) if c == q => quote = None,
            Some(_) => {}
            None if matches!(c, '\'' | '"') && open == '(' => quote = Some(c),
            None if c == open => depth += 1,
            None if c == close => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return index;
                }
            }
            None => {}
        }
        index += 1;
    }
    chars.len()
}

/// Read the expansion at `at` in `chars`, a `$`, into `found`; where the
/// expression goes on past it.
fn expansion(chars: &[char], at: usize, found: &mut Vec<Piece>) -> usize {
    let next = chars.get(at + 1).copied();
    let name_end = |from: usize| {
        let mut end = from;
        while end < chars.len() && (chars[end].is_ascii_alphanumeric() || chars[end] == '_') {
            end += 1;
        }
        end
    };
    match next {
        Some('(') if chars.get(at + 2) == Some(&'(') => {
            // Arithmetic in it, `$(( ))`.
            let end = closing(chars, at + 1, '(', ')');
            let inner: String = chars[(at + 3).min(end)..end.saturating_sub(1).max(at + 3)]
                .iter()
                .collect();
            found.extend(pieces(&inner));
            end + 1
        }
        Some('[') => {
            let end = closing(chars, at + 1, '[', ']');
            let inner: String = chars[(at + 2).min(end)..end].iter().collect();
            found.extend(pieces(&inner));
            end + 1
        }
        Some('(') => {
            // A command's output.
            let end = closing(chars, at + 1, '(', ')');
            found.push(Piece::Opaque(
                chars[at..(end + 1).min(chars.len())].iter().collect(),
            ));
            end + 1
        }
        Some('{') => {
            let end = closing(chars, at + 1, '{', '}');
            let inner: String = chars[(at + 2).min(end)..end].iter().collect();
            braced(&inner, found);
            end + 1
        }
        // A count or a test of a parameter, or of an element of an array.
        Some('#' | '+')
            if chars
                .get(at + 2)
                .is_some_and(|c| c.is_ascii_alphabetic() || *c == '_') =>
        {
            let end = name_end(at + 2);
            let name: String = chars[at + 2..end].iter().collect();
            if chars.get(end) == Some(&'[') {
                let close = closing(chars, end, '[', ']');
                let key: String = chars[end + 1..close.min(chars.len())].iter().collect();
                found.push(Piece::Keyed(name, key));
                return close + 1;
            }
            end
        }
        Some('#' | '?' | '$' | '!') => at + 2,
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {
            let end = name_end(at + 1);
            let name: String = chars[at + 1..end].iter().collect();
            if chars.get(end) == Some(&'[') {
                // An element's value, which zsh reads as arithmetic.
                let close = closing(chars, end, '[', ']');
                found.push(Piece::Opaque(
                    chars[at..(close + 1).min(chars.len())].iter().collect(),
                ));
                return close + 1;
            }
            found.push(Piece::Name(name));
            end
        }
        _ => {
            let end = (at + 2).min(chars.len());
            found.push(Piece::Opaque(chars[at..end].iter().collect()));
            end
        }
    }
}

/// Read what `${...}` holds, `inner`, into `found`: a count or a test of a
/// parameter or of an element (`${#x}`, `${+x[k]}`, `${#}`), a parameter's
/// value (`${x}`), or what the check cannot know.
fn braced(inner: &str, found: &mut Vec<Piece>) {
    if inner == "#" {
        return;
    }
    let (rest, counted) = match inner.strip_prefix(['#', '+']) {
        Some(rest) => (rest, true),
        None => (inner, false),
    };
    let end = rest
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(rest.len());
    let (name, after) = rest.split_at(end);
    let name_ok = name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_');
    if name_ok && after.is_empty() {
        if !counted {
            found.push(Piece::Name(name.to_string()));
        }
        return;
    }
    let key = after
        .strip_prefix('[')
        .and_then(|key| key.strip_suffix(']'));
    if name_ok
        && counted
        && let Some(key) = key
    {
        found.push(Piece::Keyed(name.to_string(), key.to_string()));
        return;
    }
    // An index a pattern finds in an array of zsh's own, a number; what the
    // pattern's expansions hold is evaluated all the same.
    if name_ok
        && INDEXED.contains(&name)
        && let Some(pattern) =
            key.and_then(|key| key.strip_prefix("(i)").or_else(|| key.strip_prefix("(I)")))
    {
        found.extend(nested(pattern));
        return;
    }
    found.push(Piece::Opaque(format!("${{{inner}}}")));
}

/// The pieces of the arithmetic the expansions in `key`, a subscript of an
/// array whose keys are strings, hold (`$(( ))`, `$[ ]`), which zsh
/// evaluates as it expands the key.
fn nested(key: &str) -> Vec<Piece> {
    let chars: Vec<char> = key.chars().collect();
    let mut found = Vec::new();
    let mut at = 0;
    while at < chars.len() {
        if chars[at] == '$' && matches!(chars.get(at + 1), Some('(' | '[')) {
            let mut inner = Vec::new();
            let next = expansion(&chars, at, &mut inner);
            if chars.get(at + 1) == Some(&'[') || chars.get(at + 2) == Some(&'(') {
                found.extend(inner);
            }
            at = next;
        } else {
            at += 1;
        }
    }
    found
}

/// The parts of `expr` that a `,` or a `;` outside parentheses, brackets
/// and braces part, which zsh evaluates one after another.
fn segments(expr: &str) -> Vec<&str> {
    let mut found = Vec::new();
    let mut depth = 0usize;
    let mut start = 0;
    for (at, c) in expr.char_indices() {
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            ',' | ';' if depth == 0 => {
                found.push(&expr[start..at]);
                start = at + 1;
            }
            _ => {}
        }
    }
    found.push(&expr[start..]);
    found
}

/// The parameter a part of an expression, `segment`, assigns with a plain
/// `=` outside parentheses (`i = 0`), and what it assigns; zsh reads no
/// value of it there.
fn plain_assignment(segment: &str) -> Option<(&str, &str)> {
    let bytes = segment.as_bytes();
    let mut depth = 0usize;
    for (at, &byte) in bytes.iter().enumerate() {
        match byte {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            b'=' if depth == 0 => {
                let before = at.checked_sub(1).map(|before| bytes[before]);
                if bytes.get(at + 1) == Some(&b'=')
                    || before.is_some_and(|before| b"=!<>+-*/%&|^".contains(&before))
                {
                    return None;
                }
                let name = segment[..at].trim();
                return (!name.is_empty()
                    && name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
                    && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
                .then(|| (name, &segment[at + 1..]));
            }
            _ => {}
        }
    }
    None
}

impl<F: Filesystem> Reader<'_, F> {
    /// Note a doubt for each arithmetic expression the files hold that may
    /// set a parameter whose name the check cannot read ([`super::arith`]):
    /// one that names a parameter that holds no number, or holds what the
    /// check cannot know. A subscript of an array whose keys are strings is
    /// none but for the arithmetic its expansions hold, and so is the value
    /// of an assignment to a parameter that holds no number. zsh keeps a
    /// number in the parameters of [`NUMERIC`] unless a file unsets one,
    /// which makes it a plain one, or may hide what they are (`local -h`),
    /// and in one a part of the expression before assigns (`i = 0, i++`); a
    /// plain `=` reads no value of what it assigns.
    pub(super) fn arithmetic(&mut self) {
        let hidden =
            self.texts.iter().any(Forms::hides_specials) || self.unset.iter().any(String::is_empty);
        for (expr, kind, place) in std::mem::take(&mut self.arith) {
            match &kind {
                Arith::Keyed(name) if self.keyed(name) => continue,
                Arith::Value(name)
                    if !NUMERIC.contains(&name.as_str())
                        && !READ_AS_NUMBER.contains(&name.as_str())
                        && !self.integers.contains(name) =>
                {
                    continue;
                }
                _ => {}
            }
            if let Arith::Value(name) = &kind
                && READ_AS_NUMBER.contains(&name.as_str())
            {
                // zsh reads it as arithmetic each time it uses it, past what
                // the check reads.
                if !plain_number(expr.trim()) {
                    self.doubt(format!(
                        "it cannot tell what code the value `{}` that {place} gives {name} runs, \
                         as zsh reads it as arithmetic each time it uses {name}",
                        expr.trim()
                    ));
                }
                continue;
            }
            if let Some(why) = self.judge(&expr, hidden) {
                self.doubt(format!(
                    "it cannot tell which parameters `{}` in {place} sets, as zsh reads {why} \
                     there as arithmetic, which may set one by a name the check cannot read",
                    expr.trim()
                ));
            }
        }
    }

    /// What in the expression `expr` zsh may read a value of that the check
    /// cannot know, as the warning names it; `None` when it reads none
    /// ([`Reader::arithmetic`]).
    fn judge(&self, expr: &str, hidden: bool) -> Option<String> {
        let mut assigned: Vec<&str> = Vec::new();
        for segment in segments(expr) {
            let (name, read) = match plain_assignment(segment) {
                Some((name, value)) => (Some(name), value),
                None => (None, segment),
            };
            let mut todo = pieces(read);
            while let Some(piece) = todo.pop() {
                match piece {
                    Piece::Name(name)
                        if assigned.contains(&name.as_str())
                            || (!hidden
                                && NUMERIC.contains(&name.as_str())
                                && !self.unset.contains(&name)) => {}
                    Piece::Keyed(name, key) if self.keyed(&name) => todo.extend(nested(&key)),
                    Piece::Keyed(_, key) => todo.extend(pieces(&key)),
                    Piece::Name(name) => return Some(format!("the value of `{name}`")),
                    Piece::Opaque(text) => return Some(format!("what `{text}` gives")),
                }
            }
            assigned.extend(name);
        }
        None
    }

    /// Whether the array `name` is one whose keys are strings: one of zsh's
    /// own ([`KEYED`]), or one a file declares so where no function makes it
    /// its own (`typeset -A key`) and no file unsets it, after which it may be
    /// a plain array.
    fn keyed(&self, name: &str) -> bool {
        KEYED.contains(&name)
            || (self.keyed_arrays.iter().any(|keyed| keyed == name)
                && !self
                    .unset
                    .iter()
                    .any(|unset| unset == name || unset.is_empty()))
    }
}

#[cfg(test)]
mod tests {
    use super::{Piece, pieces};

    #[test]
    fn an_expression_s_pieces_are_the_names_and_expansions_in_it() {
        assert_eq!(pieces("1 + 0x1f * 16#ff - 1.5e+3 + ##a + [#16] 2 + .5"), []);
        // A name past a number is read as one.
        assert_eq!(pieces("16#e+x"), [Piece::Name("x".to_string())]);
        assert_eq!(pieces("0xe+y"), [Piece::Name("y".to_string())]);
        assert_eq!(pieces("1e5+z"), [Piece::Name("z".to_string())]);
        assert_eq!(pieces("$#x + ${#y} + $+z + ${+w} + $# + $? + ${#}"), []);
        assert_eq!(
            pieces("${n}TY = 5"),
            [Piece::Name("n".to_string()), Piece::Name("TY".to_string())]
        );
        assert_eq!(
            pieces("$+commands[fzf] && ${+terminfo[smkx]}"),
            [
                Piece::Keyed("commands".to_string(), "fzf".to_string()),
                Piece::Keyed("terminfo".to_string(), "smkx".to_string())
            ]
        );
        assert_eq!(pieces("$(( EUID ))"), [Piece::Name("EUID".to_string())]);
        assert_eq!(
            pieces("$1 + $(x) + ${x:-1} + $a[1]"),
            [
                Piece::Opaque("$1".to_string()),
                Piece::Opaque("$(x)".to_string()),
                Piece::Opaque("${x:-1}".to_string()),
                Piece::Opaque("$a[1]".to_string())
            ]
        );
    }
}
