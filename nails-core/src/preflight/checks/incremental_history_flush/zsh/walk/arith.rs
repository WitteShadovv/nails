// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Where a file's code holds arithmetic, as the walk finds it
//! ([`Event::Arith`]): in its words, `$(( ))`, `$[ ]`, an array's subscript
//! (`${a[n]}`, `$a[n]`, `${+a[n]}`), an offset or a length (`${s:n:m}`), the
//! argument of a flag that takes a number (`${(l:n:)s}`) and the subscript
//! of a glob qualifier (`*([n])`); in its commands, `(( ))`, `let`, the
//! numbers `printf` and `print -f` format, the operands of `[[ a -eq b ]]`, the
//! counts of `shift`, `return`, `exit`, `break`, `continue` and `repeat`, the
//! timeouts and offsets of zsh/system, an array element a command sets by its
//! subscript (`a[n]=x`, `unset 'a[n]'`, `print -v 'a[n]'`), the value of an
//! assignment to a parameter that holds a number, and the value of one
//! declared to hold numbers at the top level (`integer n`), which zsh reads
//! as arithmetic as it declares it. What each sets the reader tells
//! ([`super::super::arith`]). The `((` and `$[` the tokens' texts hold are
//! counted, so that what the lines hold beyond them is a doubt.

use super::super::lexer::{Token, Word};
use super::command::assigned;
use super::names::{option_arguments, targets};
use super::{Arith, Event, Walker};

/// How many `((` and `$[` `text` holds.
pub(super) fn marks(text: &str) -> usize {
    text.matches("((").count() + text.matches("$[").count()
}

/// The arithmetic the texts of `tokens` hold, and how many `((` and `$[`
/// their texts hold ([`marks`]).
pub(super) fn of_tokens(tokens: &[Token]) -> (Vec<Event>, usize) {
    let mut events = Vec::new();
    let mut count = 0;
    for token in tokens {
        match token {
            Token::Word(word) => {
                count += marks(&word.text);
                if word.expands || word.text.contains('[') {
                    in_word(&word.text, &mut events);
                }
            }
            Token::Array(name, items) => {
                let name = name.strip_suffix('+').unwrap_or(name);
                for item in items {
                    count += marks(&item.text);
                    if item.expands {
                        in_word(&item.text, &mut events);
                    }
                    // An element given by its subscript (`a=([n]=1)`).
                    if let Some(key) = item
                        .text
                        .strip_prefix('[')
                        .and_then(|rest| rest.split_once("]="))
                        .map(|(key, _)| key)
                    {
                        events.extend(subscript(name, key));
                    }
                }
            }
            Token::Text(text) => {
                count += marks(text);
                if text.contains('$') {
                    in_text(&text.chars().collect::<Vec<_>>(), &mut events);
                }
            }
            Token::Arithmetic(text) => {
                count += marks(text);
                let inner = text
                    .strip_prefix("((")
                    .and_then(|text| text.strip_suffix("))"))
                    .unwrap_or(text);
                events.push(plain(inner));
            }
            _ => {}
        }
    }
    (events, count)
}

/// An expression zsh evaluates wherever it stands.
fn plain(text: &str) -> Event {
    Event::Arith {
        text: text.to_string(),
        kind: Arith::Plain,
    }
}

/// The index of the `close` that closes the `open` at `at` in `chars`,
/// nested ones counted; the end of `chars` when none does.
fn closing(chars: &[char], at: usize, open: char, close: char) -> usize {
    let mut depth = 0usize;
    for (index, &c) in chars.iter().enumerate().skip(at) {
        if c == open {
            depth += 1;
        } else if c == close {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return index;
            }
        }
    }
    chars.len()
}

/// The text of `chars` from `from` to `to`, each kept inside it.
fn slice(chars: &[char], from: usize, to: usize) -> String {
    chars[from.min(chars.len())..to.min(chars.len()).max(from.min(chars.len()))]
        .iter()
        .collect()
}

/// The arithmetic in `text`, a word of zsh code as the lexer gives it: in
/// its expansions ([`in_text`]), and the subscript of a glob qualifier at
/// its end (`*(om[1,n])`).
fn in_word(text: &str, events: &mut Vec<Event>) {
    let chars: Vec<char> = text.chars().collect();
    in_text(&chars, events);
    if text.ends_with(')')
        && let Some(open) = text.rfind('(')
        && !text[..open].ends_with('$')
    {
        let qualifier: Vec<char> = text[open..].chars().collect();
        let mut at = 0;
        while let Some(start) = qualifier[at..].iter().position(|c| *c == '[') {
            let start = at + start;
            let end = closing(&qualifier, start, '[', ']');
            events.push(plain(&slice(&qualifier, start + 1, end)));
            at = end + 1;
            if at >= qualifier.len() {
                break;
            }
        }
    }
}

/// The arithmetic in the expansions of `chars`: `$(( ))`, `$[ ]`, a
/// subscript of `$name[...]`, and what `${...}` holds ([`braced`]). What a
/// command substitution holds runs in a subshell, which sets nothing in the
/// shell.
fn in_text(chars: &[char], events: &mut Vec<Event>) {
    let mut at = 0;
    while at < chars.len() {
        match chars[at] {
            '\\' => at += 2,
            '`' => {
                at += 1;
                while at < chars.len() && chars[at] != '`' {
                    at += if chars[at] == '\\' { 2 } else { 1 };
                }
                at += 1;
            }
            '$' => match chars.get(at + 1) {
                Some('(') if chars.get(at + 2) == Some(&'(') => {
                    let end = closing(chars, at + 1, '(', ')');
                    events.push(plain(&slice(chars, at + 3, end.saturating_sub(1))));
                    at = end + 1;
                }
                Some('(') => at = closing(chars, at + 1, '(', ')') + 1,
                Some('[') => {
                    let end = closing(chars, at + 1, '[', ']');
                    events.push(plain(&slice(chars, at + 2, end)));
                    at = end + 1;
                }
                Some('{') => {
                    let end = closing(chars, at + 1, '{', '}');
                    let inner: Vec<char> = chars[(at + 2).min(end)..end].to_vec();
                    braced(&inner, events);
                    at = end + 1;
                }
                Some(c) if c.is_ascii_alphabetic() || *c == '_' => {
                    let mut end = at + 1;
                    while end < chars.len()
                        && (chars[end].is_ascii_alphanumeric() || chars[end] == '_')
                    {
                        end += 1;
                    }
                    if chars.get(end) == Some(&'[') {
                        let close = closing(chars, end, '[', ']');
                        keyed(&slice(chars, at + 1, end), chars, end + 1, close, events);
                        at = close + 1;
                    } else {
                        at = end;
                    }
                }
                _ => at += 1,
            },
            _ => at += 1,
        }
    }
}

/// The subscript `key` of the array `name`: arithmetic unless its keys are
/// strings, or a flag makes it a pattern (`(r)`, `(i)`).
fn subscript(name: &str, key: &str) -> Option<Event> {
    let pattern = key
        .strip_prefix('(')
        .and_then(|flagged| flagged.split_once(')'))
        .is_some_and(|(flags, _)| {
            !flags.is_empty()
                && flags
                    .chars()
                    .all(|c| matches!(c, 'r' | 'R' | 'i' | 'I' | 'k' | 'K' | 'e'))
        });
    (!pattern && !key.is_empty()).then(|| Event::Arith {
        text: key.to_string(),
        kind: Arith::Keyed(name.to_string()),
    })
}

/// Note the subscript `key` of the array `name` that `chars` hold from
/// `from` to `to`, and the arithmetic the expansions in it hold, which zsh
/// evaluates whatever the array's keys are (`${history[$((HISTCMD-1))]}`).
fn keyed(name: &str, chars: &[char], from: usize, to: usize, events: &mut Vec<Event>) {
    let key = slice(chars, from, to);
    events.extend(subscript(name, &key));
    in_text(
        &chars[from.min(chars.len())..to.min(chars.len()).max(from.min(chars.len()))],
        events,
    );
}

/// The arithmetic in what `${...}` holds, `inner`: the arguments of its
/// flags that take a number (`l:n:`, `r:n:`, `I:n:`), the subscript of the
/// parameter it names, an offset and a length (`${s:n:m}`, but not
/// `${s:-x}`), and what the expansions in the rest hold.
fn braced(inner: &[char], events: &mut Vec<Event>) {
    let mut at = 0;
    if inner.first() == Some(&'(') {
        let close = closing(inner, 0, '(', ')');
        let flags = &inner[1..close.min(inner.len())];
        let mut index = 0;
        while index < flags.len() {
            let flag = flags[index];
            let takes = matches!(flag, 'l' | 'r' | 'I' | 'j' | 's' | 'Z' | '_' | 'g');
            match flags.get(index + 1) {
                Some(&delimiter) if takes && !delimiter.is_ascii_alphanumeric() => {
                    let end = flags[index + 2..]
                        .iter()
                        .position(|c| *c == delimiter)
                        .map_or(flags.len(), |end| index + 2 + end);
                    if matches!(flag, 'l' | 'r' | 'I') {
                        events.push(plain(&slice(flags, index + 2, end)));
                    }
                    index = end + 1;
                    // The strings `l` and `r` take after their number.
                    while matches!(flag, 'l' | 'r') && flags.get(index) == Some(&delimiter) {
                        index = flags[index + 1..]
                            .iter()
                            .position(|c| *c == delimiter)
                            .map_or(flags.len(), |end| index + 2 + end);
                    }
                }
                _ => index += 1,
            }
        }
        at = close + 1;
    }
    while inner
        .get(at)
        .is_some_and(|c| matches!(c, '#' | '+' | '=' | '~' | '^'))
    {
        at += 1;
    }
    // A subscript of what a nested expansion gives (`${${(z)s}[n]}`), of an
    // array the check cannot name: arithmetic.
    if inner.get(at) == Some(&'$') && inner.get(at + 1) == Some(&'{') {
        let close = closing(inner, at + 1, '{', '}');
        braced(&inner[(at + 2).min(close)..close.min(inner.len())], events);
        if inner.get(close + 1) == Some(&'[') {
            let end = closing(inner, close + 1, '[', ']');
            events.push(plain(&slice(inner, close + 2, end)));
            at = end + 1;
        } else {
            at = close + 1;
        }
        in_text(&inner[at.min(inner.len())..], events);
        return;
    }
    let start = at;
    while at < inner.len() && (inner[at].is_ascii_alphanumeric() || inner[at] == '_') {
        at += 1;
    }
    let name = slice(inner, start, at);
    if !name.is_empty() && inner.get(at) == Some(&'[') {
        let close = closing(inner, at, '[', ']');
        keyed(&name, inner, at + 1, close, events);
        at = close + 1;
    }
    if !name.is_empty()
        && inner.get(at) == Some(&':')
        && inner
            .get(at + 1)
            .is_some_and(|c| c.is_ascii_digit() || c.is_whitespace() || matches!(c, '(' | '$'))
    {
        // `${s:offset}`, `${s:offset:length}`.
        let rest = &inner[at + 1..];
        let mut depth = 0usize;
        let mut from = 0;
        for (index, &c) in rest.iter().enumerate() {
            match c {
                '(' | '{' | '[' => depth += 1,
                ')' | '}' | ']' => depth = depth.saturating_sub(1),
                ':' if depth == 0 => {
                    events.push(plain(&slice(rest, from, index)));
                    from = index + 1;
                }
                _ => {}
            }
        }
        events.push(plain(&slice(rest, from, rest.len())));
        return;
    }
    in_text(&inner[at.min(inner.len())..], events);
}

/// Where the words `print` prints start among `args`, past its options and
/// the words the options that take one take (`-f format`, `-u 2`), and past
/// a `--` that ends them.
fn print_words(args: &[Word]) -> usize {
    let mut at = 0;
    while let Some(arg) = args.get(at) {
        at += 1;
        if arg.text == "--" {
            return at;
        }
        let Some(flags) = arg.text.strip_prefix('-').filter(|flags| !flags.is_empty()) else {
            return at - 1;
        };
        if let Some(taking) = flags.find(['C', 'f', 'u', 'v', 'x', 'X'])
            && taking + 1 == flags.len()
        {
            at += 1;
        }
    }
    at
}

/// The conversions of the `printf` format `format` that take a number, in
/// order, a `*` width or precision among them: `true` for one, `false` for
/// one that takes a string; `None` when an argument is named by its place
/// (`%1$d`), which may be any.
fn conversions(format: &str) -> Option<Vec<bool>> {
    let mut found = Vec::new();
    let mut chars = format.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '%' {
            continue;
        }
        if chars.next_if_eq(&'%').is_some() {
            continue;
        }
        loop {
            match chars.next() {
                Some('*') => found.push(true),
                Some('$') => return None,
                Some(c)
                    if c.is_ascii_digit()
                        || matches!(
                            c,
                            '.' | '-'
                                | '+'
                                | ' '
                                | '#'
                                | '0'
                                | 'l'
                                | 'h'
                                | 'L'
                                | 'q'
                                | 'j'
                                | 'z'
                                | 't'
                        ) => {}
                Some(c) => {
                    found.push(matches!(
                        c,
                        'd' | 'i'
                            | 'o'
                            | 'u'
                            | 'x'
                            | 'X'
                            | 'e'
                            | 'E'
                            | 'f'
                            | 'F'
                            | 'g'
                            | 'G'
                            | 'a'
                            | 'A'
                    ));
                    break;
                }
                None => break,
            }
        }
    }
    Some(found)
}

impl Walker<'_> {
    /// Note an arithmetic expression `text` of `kind`.
    pub(super) fn arith(&mut self, text: &str, kind: Arith) {
        if !text.is_empty() && !text.chars().all(|c| c.is_ascii_digit()) {
            self.events.push(Event::Arith {
                text: text.to_string(),
                kind,
            });
        }
    }

    /// Note the arithmetic of the command `command` with `args` ([the
    /// module](self)), and the subscripts of the parameters it sets by their
    /// names.
    pub(super) fn command_arithmetic(&mut self, command: &str, args: &[Word]) {
        let texts = |words: &[Word]| -> Vec<String> {
            words.iter().map(|word| word.text.clone()).collect()
        };
        let numbers: Vec<String> = match command {
            "let" => texts(args),
            "shift" | "return" | "exit" | "break" | "continue" => texts(args)
                .into_iter()
                .filter(|text| {
                    !text.starts_with('-')
                        || text.len() < 2
                        || text[1..].starts_with(|c: char| c.is_ascii_digit())
                })
                .collect(),
            "printf" | "print" => {
                let format = if command == "printf" {
                    let skip = usize::from(args.first().is_some_and(|arg| arg.text == "-v")) * 2;
                    let skip =
                        skip + usize::from(args.get(skip).is_some_and(|arg| arg.text == "--"));
                    args.get(skip).map(|format| (format.clone(), skip + 1))
                } else {
                    option_arguments(args, "CfuvxX", "f")
                        .into_iter()
                        .next()
                        .map(|format| (format, print_words(args)))
                };
                match format {
                    Some((format, rest)) => {
                        let values = texts(&args[rest.min(args.len())..]);
                        match conversions(&format.text).filter(|_| !format.expands) {
                            Some(kinds) if kinds.is_empty() => Vec::new(),
                            Some(kinds) => values
                                .into_iter()
                                .enumerate()
                                .filter(|(at, _)| kinds[at % kinds.len()])
                                .map(|(_, value)| value)
                                .collect(),
                            None => values,
                        }
                    }
                    None => Vec::new(),
                }
            }
            "[[" => {
                let mut found = Vec::new();
                for (at, arg) in args.iter().enumerate() {
                    if matches!(
                        arg.text.as_str(),
                        "-eq" | "-ne" | "-lt" | "-le" | "-gt" | "-ge"
                    ) {
                        found.extend(
                            at.checked_sub(1)
                                .and_then(|before| args.get(before))
                                .map(|word| word.text.clone()),
                        );
                        found.extend(args.get(at + 1).map(|word| word.text.clone()));
                    }
                    if arg.text == "-v"
                        && let Some(name) = args.get(at + 1)
                    {
                        self.subscripted(&name.text);
                    }
                }
                found
            }
            "sysread" => option_arguments(args, "ciost", "iost")
                .iter()
                .map(|word| word.text.clone())
                .collect(),
            "sysseek" => {
                let mut found = Vec::new();
                let mut words = args.iter();
                while let Some(word) = words.next() {
                    match word.text.as_str() {
                        "-w" => {
                            words.next();
                        }
                        "-u" => found.extend(words.next().map(|word| word.text.clone())),
                        _ => found.push(word.text.clone()),
                    }
                }
                found
            }
            "zsystem" if args.first().is_some_and(|sub| sub.text == "flock") => {
                option_arguments(&args[1..], "fit", "it")
                    .iter()
                    .map(|word| word.text.clone())
                    .collect()
            }
            "unset" => {
                for arg in args {
                    if arg.text.starts_with('-') {
                        if arg.text.contains('m') {
                            self.events.push(Event::Unset(String::new()));
                        }
                        continue;
                    }
                    let name = assigned(&arg.text);
                    self.events.push(Event::Unset(if arg.expands {
                        String::new()
                    } else {
                        name.to_string()
                    }));
                    self.subscripted(&arg.text);
                }
                Vec::new()
            }
            _ => Vec::new(),
        };
        for text in numbers {
            self.arith(&text, Arith::Plain);
        }
        for target in targets(command, args) {
            self.subscripted(&target.text);
        }
    }

    /// Note the subscript of `text`, a parameter's name with one
    /// (`a[n]`), which zsh reads as arithmetic unless the array's keys are
    /// strings.
    pub(super) fn subscripted(&mut self, text: &str) {
        let target = text.split_once('=').map_or(text, |(target, _)| target);
        let target = target.strip_suffix('+').unwrap_or(target);
        if let Some((name, key)) = target.split_once('[') {
            let key = key.strip_suffix(']').unwrap_or(key);
            if let Some(Event::Arith { text, kind }) = subscript(name, key) {
                self.arith(&text, kind);
            }
            let mut events = Vec::new();
            in_text(&key.chars().collect::<Vec<_>>(), &mut events);
            self.events.extend(events);
        }
    }

    /// Note the arithmetic of the assignment `word`: the subscript of the
    /// element it sets, and its value, which zsh reads as arithmetic where the
    /// parameter holds a number.
    pub(super) fn assignment_arithmetic(&mut self, word: &Word) {
        let Some((target, value)) = word.text.split_once('=') else {
            return;
        };
        self.subscripted(target);
        if !target.contains('[') {
            let name = assigned(target).to_string();
            self.arith(value, Arith::Value(name));
        }
    }

    /// Note what a `typeset` or the like (`command`) of `args` declares: an
    /// array whose keys are strings (`-A`), a parameter that holds numbers
    /// (`-i`, `-E`, `-F`, `integer`, `float`), whose value zsh reads as
    /// arithmetic as it declares one that is not local to the function it
    /// runs in, and those values assigned.
    pub(super) fn declared(&mut self, command: &str, args: &[Word]) {
        let flags: String = args
            .iter()
            .take_while(|arg| arg.text.starts_with(['-', '+']) && arg.text.len() > 1)
            .map(|arg| arg.text.as_str())
            .collect();
        let numeric = matches!(command, "integer" | "float") || flags.contains(['i', 'E', 'F']);
        let local = self.function().is_some() && command != "export" && !flags.contains('g');
        // One a function declares is its own: the name's keys elsewhere are
        // not strings for it.
        let keyed = flags.contains('A') && !local;
        for arg in args
            .iter()
            .skip_while(|arg| arg.text.starts_with(['-', '+']) && arg.text.len() > 1)
        {
            // The base or the precision of a number (`typeset -i 16 x`).
            if arg.text.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }
            let (target, value) = match arg.text.split_once('=') {
                Some((target, value)) => (target, Some(value)),
                None => (arg.text.as_str(), None),
            };
            let name = assigned(target).to_string();
            if keyed || numeric {
                self.events.push(Event::Declared {
                    name: name.clone(),
                    keyed,
                    numeric,
                });
            }
            match value {
                Some(value) if numeric => self.arith(value, Arith::Plain),
                None if numeric && !local => self.arith(&name, Arith::Old),
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Arith, Event, conversions, in_word};

    fn found(text: &str) -> Vec<(String, Arith)> {
        let mut events = Vec::new();
        in_word(text, &mut events);
        events
            .into_iter()
            .filter_map(|event| match event {
                Event::Arith { text, kind } if !text.is_empty() => Some((text, kind)),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn a_word_s_arithmetic_is_where_zsh_evaluates_it() {
        let plain = |text: &str| (text.to_string(), Arith::Plain);
        let keyed = |text: &str, name: &str| (text.to_string(), Arith::Keyed(name.to_string()));
        assert_eq!(found("$(( n ))x$[m]"), [plain(" n "), plain("m")]);
        assert_eq!(
            found("${a[n]}$b[m]${+c[k]}${#d[j]}"),
            [
                keyed("n", "a"),
                keyed("m", "b"),
                keyed("k", "c"),
                keyed("j", "d")
            ]
        );
        assert_eq!(
            found("${s:$o:m}${s: n}${s:(n)}${s:n}"),
            [plain("$o"), plain("m"), plain(" n"), plain("(n)")]
        );
        assert_eq!(
            found("${(l:n::0:)s}${(r.m.)s}${(I:k:)s#a}"),
            [plain("n"), plain("m"), plain("k")]
        );
        assert_eq!(found("*(om[1,n])"), [plain("1,n")]);
        assert_eq!(found("${x:-$(( n ))}"), [plain(" n ")]);
        // A default value, a modifier, a pattern's flags and a command's
        // output are none.
        assert_eq!(
            found("${s:-n}${s:h}${a[(r)x*]}$(( (n) ))"),
            [plain(" (n) ")]
        );
        assert_eq!(found("$(print $((n)))`a[1]`"), []);
        assert_eq!(found("${${(z)s}[n]}${${s}}"), [plain("n")]);
    }

    #[test]
    fn a_printf_format_s_conversions_say_which_arguments_are_numbers() {
        assert_eq!(
            conversions("%s %d %5.2f %c %*s %%"),
            Some(vec![false, true, true, false, true, false])
        );
        assert_eq!(conversions("%1$d"), None);
        assert_eq!(conversions("plain"), Some(Vec::new()));
    }
}
