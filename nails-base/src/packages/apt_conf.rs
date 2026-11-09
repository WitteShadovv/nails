// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! apt's configuration files (apt.conf(5)), read the way apt reads them.
//!
//! apt (Debian, Ubuntu) and the programs built on it, such as
//! unattended-upgrades, read their settings from `/etc/apt/apt.conf.d` and
//! `/etc/apt/apt.conf`. [`parse`] reads one file the way apt's
//! `ReadConfigFile()` does (apt-pkg/contrib/configuration.cc in apt 2.7 to
//! 3.2, which read it alike): a tab counts as eight spaces, `//` and `#` start
//! a comment outside a quoted string (but `#clear`, `#include` and
//! `#x-apt-configure-index` do not), `/* */` comments span lines, and a
//! statement ends at a `;`, a `{` or a `}` outside a quoted string. Each
//! statement is a tag, its value (quoted strings, or one word), and the scope
//! of the blocks around it. A file apt refuses is refused here, on the line
//! apt names, and so is a line NAILS does not read the way apt does: one
//! longer than [`MAX_LINE`] bytes, and one with a NUL byte in it, at which
//! apt stops reading the line.
//!
//! [`tags`] splits an item's name into the tags apt looks up, [`part_name`]
//! tells the files of a parts directory apt reads from those it skips, and
//! [`string_to_bool`] reads a value as apt's `FindB()` does. Names compare
//! without regard to ASCII case, as apt's do. The `apt_conf` fuzz target
//! drives the reader with hostile input.
//!
//! apt runs in the system's locale, and two of its choices follow it: which
//! files of a parts directory it reads (`isalpha()`), and which words it
//! takes for a boolean (`strcasecmp()`). Both are the same in every locale
//! for ASCII, so the reader keeps to ASCII's rules and says where a byte
//! beyond it leaves the choice to the locale: a [`PartName::ByLocale`], and a
//! value [`value_by_locale`] names. The structure of a file follows no
//! locale: apt's `isspace()` takes no byte beyond ASCII for a space in any
//! locale glibc builds on an ASCII charset.

/// The longest line, newline excluded, read the way apt reads it. apt reads a
/// line in pieces of 4095 bytes, its newline included, and when the last
/// piece of a line fills one exactly, it joins the next line to it. So a line
/// longer than this is refused rather than read wrong.
pub const MAX_LINE: usize = 4000;

/// One statement of a file, as apt applies it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Statement {
    /// The item `item` is set to `value` (apt's `Set()`).
    Set {
        /// The item's full name, its block scope included.
        item: Vec<u8>,
        /// The value, as apt keeps it.
        value: Vec<u8>,
        /// The line the statement ends on, counted from 1.
        line: usize,
    },
    /// `#clear <name>`: the item `name` loses its value and every item below
    /// it.
    Clear {
        /// The item cleared.
        name: Vec<u8>,
        /// The line, counted from 1.
        line: usize,
    },
    /// `#include <path>`: apt reads another file, or a directory of them, at
    /// this point.
    Include {
        /// The line, counted from 1.
        line: usize,
    },
    /// `#x-apt-configure-index <path>`: apt loads an index of option types,
    /// and stops reading the file when it cannot.
    ConfigureIndex {
        /// The line, counted from 1.
        line: usize,
    },
}

/// A file apt refuses, or one NAILS does not read the way apt does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyntaxError {
    /// The line apt names, or the one NAILS does not read, counted from 1.
    pub line: usize,
    /// What is wrong: apt's words where apt refuses the file, else what the
    /// line holds that NAILS does not read.
    pub reason: &'static str,
    /// Whether apt refuses the file there. Otherwise apt reads the line, but
    /// not in a way NAILS follows (see [`parse`]).
    pub by_apt: bool,
}

/// A file read whole.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    /// Its statements, in the order apt applies them.
    pub statements: Vec<Statement>,
    /// How many blocks are still open at its end. apt does not refuse a file
    /// that leaves one open.
    pub open_blocks: usize,
    /// Whether it ends inside a `/* */` comment, which apt does not refuse
    /// either.
    pub in_comment: bool,
}

/// `isspace()` in the C locale.
fn is_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// The first `needle` in `haystack` at or after `from`.
fn find(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    haystack
        .get(from..)?
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|at| at + from)
}

/// Whether `before` holds an odd number of double quotes: what follows it is
/// inside a quoted string.
fn quoted(before: &[u8]) -> bool {
    before.iter().filter(|&&byte| byte == b'"').count() % 2 != 0
}

/// `line` with its comments taken out, as apt does: `in_comment` says
/// whether a `/* */` comment from an earlier line is still open, and is set
/// for the next line.
fn strip_comments(mut line: &[u8], in_comment: &mut bool) -> Vec<u8> {
    if *in_comment {
        match find(line, b"*/", 0) {
            Some(end) => {
                line = &line[end + 2..];
                *in_comment = false;
            }
            None => return Vec::new(),
        }
    }
    // `//` outside a quoted string.
    let mut start = 0;
    while let Some(at) = find(line, b"//", start) {
        if quoted(&line[..at]) {
            start = at + 1;
            continue;
        }
        line = &line[..at];
        break;
    }
    // `#` outside a quoted string, unless it starts a directive.
    const DIRECTIVES: [&[u8]; 3] = [b"clear", b"include", b"x-apt-configure-index"];
    let mut start = 0;
    while let Some(at) = line[start..]
        .iter()
        .position(|&byte| byte == b'#')
        .map(|at| at + start)
    {
        if quoted(&line[..at])
            || DIRECTIVES
                .iter()
                .any(|directive| line[at + 1..].starts_with(directive))
        {
            start = at + 1;
            continue;
        }
        line = &line[..at];
        break;
    }
    // `/* */` outside a quoted string, possibly left open.
    let mut fragment = Vec::with_capacity(line.len());
    let mut start = 0;
    while let Some(at) = find(line, b"/*", start) {
        if quoted(&line[..at]) {
            start = at + 2;
            continue;
        }
        fragment.extend_from_slice(&line[..at]);
        match find(line, b"*/", at + 2) {
            None => {
                line = &[];
                *in_comment = true;
                break;
            }
            Some(end) => line = &line[end + 2..],
        }
        start = 0;
    }
    fragment.extend_from_slice(line);
    fragment
}

/// `bytes` up to its first NUL, as apt's C string functions see it.
fn c_str(bytes: &[u8]) -> &[u8] {
    match bytes.iter().position(|&byte| byte == 0) {
        Some(end) => &bytes[..end],
        None => bytes,
    }
}

/// `at` moved past the spaces there in `text`, as apt's `ParseQuoteWord()`
/// and `ParseCWord()` skip them first. [`Reader::statement`] calls neither at
/// a space, though: a statement starts with none, and a word is read up to
/// the white space after it, which is skipped too.
fn skip_spaces(text: &[u8], mut at: usize) -> usize {
    while at < text.len() && text[at] == b' ' {
        at += 1;
    }
    at
}

/// Where the first `close` after `open` in `text` is: where apt's
/// `ParseQuoteWord()` goes on from a `"` or a `[` (its `strchr()`).
fn closing(text: &[u8], open: usize, close: u8) -> Option<usize> {
    text[open + 1..]
        .iter()
        .position(|&byte| byte == close)
        .map(|at| open + 1 + at)
}

/// The word at `*pos` in `text`, as apt's `ParseQuoteWord()` reads it: up to
/// white space outside `"..."` and `[...]`, with the quotes dropped and each
/// `%xx` decoded. `*pos` moves past it and the white space after it; `None`
/// leaves it where it was.
fn parse_quote_word(text: &[u8], pos: &mut usize) -> Option<Vec<u8>> {
    let begin = *pos;
    let mut at = skip_spaces(text, begin);
    if at >= text.len() {
        return None;
    }
    while at < text.len() && !is_space(text[at]) {
        if text[at] == b'"' {
            at = closing(text, at, b'"')?;
        }
        if text[at] == b'[' {
            at = closing(text, at, b']')?;
        }
        at += 1;
    }
    let mut word = Vec::with_capacity(at - begin);
    let mut from = begin;
    while from != at {
        if text[from] == b'%'
            && from + 2 < at
            && text[from + 1].is_ascii_hexdigit()
            && text[from + 2].is_ascii_hexdigit()
        {
            let hex = |digit: u8| (digit as char).to_digit(16).unwrap_or(0) as u8;
            word.push(hex(text[from + 1]) << 4 | hex(text[from + 2]));
            from += 3;
            continue;
        }
        if text[from] != b'"' {
            word.push(text[from]);
        }
        from += 1;
    }
    while at < text.len() && is_space(text[at]) {
        at += 1;
    }
    *pos = at;
    Some(word)
}

/// The value at `*pos` in `text`, as apt's `ParseCWord()` reads it: quoted
/// strings and the white space between them, which becomes one space. Any
/// other character outside the quotes is no such value: `None`, and `*pos`
/// stays where it was.
fn parse_c_word(text: &[u8], pos: &mut usize) -> Option<Vec<u8>> {
    let begin = *pos;
    let mut at = skip_spaces(text, begin);
    if at >= text.len() {
        return None;
    }
    let mut word = Vec::new();
    while at < text.len() {
        if text[at] == b'"' {
            at += 1;
            while at < text.len() && text[at] != b'"' {
                word.push(text[at]);
                at += 1;
            }
            if at >= text.len() {
                return None;
            }
            at += 1;
            continue;
        }
        if at != begin && is_space(text[at]) && is_space(text[at - 1]) {
            at += 1;
            continue;
        }
        if !is_space(text[at]) {
            return None;
        }
        word.push(b' ');
        at += 1;
    }
    *pos = at;
    Some(word)
}

/// The parser's state across the lines of one file.
#[derive(Default)]
struct Reader {
    statements: Vec<Statement>,
    /// The statement read so far, over as many lines as it takes.
    pending: Vec<u8>,
    /// The scope of the enclosing blocks.
    parent: Vec<u8>,
    /// The scopes to go back to as each block closes.
    stack: Vec<Vec<u8>>,
}

impl Reader {
    /// Close the innermost block.
    fn leave_scope(&mut self) {
        self.parent = self.stack.pop().unwrap_or_default();
    }

    /// Read the statements of one line, comments taken out.
    fn read_fragment(&mut self, fragment: &[u8], line: usize) -> Result<(), SyntaxError> {
        let error = |reason| {
            Err(SyntaxError {
                line,
                reason,
                by_apt: true,
            })
        };
        let mut in_quote = false;
        let mut start = 0;
        for (at, &byte) in fragment.iter().enumerate() {
            if byte == b'"' {
                in_quote = !in_quote;
            }
            if in_quote || !matches!(byte, b'{' | b';' | b'}') {
                continue;
            }
            let mut from = start;
            while from < at && is_space(fragment[from]) {
                from += 1;
            }
            let mut to = at;
            while to > from && is_space(fragment[to - 1]) {
                to -= 1;
            }
            if !self.pending.is_empty() && to > from {
                self.pending.push(b' ');
            }
            self.pending.extend_from_slice(&fragment[from..to]);
            start = at + 1;
            if byte == b'{' && self.pending.is_empty() {
                return error("Block starts with no name.");
            }
            if self.pending.is_empty() {
                if byte == b'}' {
                    self.leave_scope();
                }
                continue;
            }
            self.statement(byte, line)?;
            self.pending.clear();
            if byte == b'}' {
                self.leave_scope();
            }
        }
        // What is left waits for the next line, stripped as apt's
        // _strstrip() strips it.
        let rest = &fragment[start..];
        let lead = rest
            .iter()
            .position(|&byte| byte != b' ' && byte != b'\t')
            .unwrap_or(rest.len());
        let rest = &rest[lead..];
        let trail = rest
            .iter()
            .rposition(|&byte| !matches!(byte, b' ' | b'\t' | b'\n' | b'\r'))
            .map_or(0, |last| last + 1);
        let rest = &rest[..trail];
        if !rest.is_empty() && !self.pending.is_empty() {
            self.pending.push(b' ');
        }
        self.pending.extend_from_slice(rest);
        Ok(())
    }

    /// Apply the pending statement, which `term` (`;`, `{` or `}`) ends.
    fn statement(&mut self, term: u8, line: usize) -> Result<(), SyntaxError> {
        let error = |reason| {
            Err(SyntaxError {
                line,
                reason,
                by_apt: true,
            })
        };
        let pending = std::mem::take(&mut self.pending);
        let text = c_str(&pending);
        let mut pos = 0;
        let Some(mut tag) = parse_quote_word(text, &mut pos) else {
            return error("Malformed tag");
        };
        let mut no_word = false;
        let word = match parse_c_word(text, &mut pos).or_else(|| parse_quote_word(text, &mut pos)) {
            Some(word) => word,
            None if term != b'{' => std::mem::take(&mut tag),
            None => {
                no_word = true;
                Vec::new()
            }
        };
        if pos != text.len() {
            return error("Extra junk after value");
        }
        if term == b'{' {
            self.stack.push(self.parent.clone());
            if !self.parent.is_empty() {
                self.parent.extend_from_slice(b"::");
            }
            self.parent.extend_from_slice(&std::mem::take(&mut tag));
        }
        let item = if self.parent.is_empty() {
            tag.clone()
        } else if term != b'{' || !tag.is_empty() {
            [self.parent.as_slice(), b"::", tag.as_slice()].concat()
        } else {
            self.parent.clone()
        };
        if let Some(directive) = tag.strip_prefix(b"#") {
            if !self.parent.is_empty() {
                return error("Directives can only be done at the top level");
            }
            self.statements.push(match directive {
                b"clear" => Statement::Clear { name: word, line },
                b"include" => Statement::Include { line },
                b"x-apt-configure-index" => Statement::ConfigureIndex { line },
                _ => return error("Unsupported directive"),
            });
        } else if tag.is_empty() && !no_word && word == b"#clear" {
            return error("clear directive requires an option tree as argument");
        } else if !no_word {
            self.statements.push(Statement::Set {
                item,
                value: word,
                line,
            });
        }
        Ok(())
    }
}

/// The statements of the configuration file `text`, as apt reads it, or why
/// apt refuses it, or the first line NAILS does not read the way apt does: a
/// line longer than [`MAX_LINE`] bytes, or one with a NUL byte in it.
pub fn parse(text: &[u8]) -> Result<Parsed, SyntaxError> {
    let mut reader = Reader::default();
    let mut in_comment = false;
    let mut line = 0;
    for raw in text.split(|&byte| byte == b'\n') {
        line += 1;
        if raw.len() > MAX_LINE {
            return Err(SyntaxError {
                line,
                reason: "more than 4000 bytes",
                by_apt: false,
            });
        }
        if raw.contains(&0) {
            return Err(SyntaxError {
                line,
                reason: "a NUL byte",
                by_apt: false,
            });
        }
        // apt drops the line's end (any \r and \n), counts a tab as eight
        // spaces, and strips the white space around the line.
        let end = raw
            .iter()
            .rposition(|&byte| byte != b'\r')
            .map_or(0, |last| last + 1);
        let mut expanded = Vec::with_capacity(end);
        for &byte in &raw[..end] {
            if byte == b'\t' {
                expanded.extend_from_slice(b"        ");
            } else {
                expanded.push(byte);
            }
        }
        let first = expanded
            .iter()
            .position(|&byte| !is_space(byte))
            .unwrap_or(expanded.len());
        let last = expanded
            .iter()
            .rposition(|&byte| !is_space(byte))
            .map_or(first, |last| last + 1);
        let fragment = strip_comments(&expanded[first..last], &mut in_comment);
        if fragment.is_empty() {
            continue;
        }
        reader.read_fragment(&fragment, line)?;
    }
    if !reader.pending.is_empty() {
        return Err(SyntaxError {
            line,
            reason: "Extra junk at end of file",
            by_apt: true,
        });
    }
    Ok(Parsed {
        statements: reader.statements,
        open_blocks: reader.stack.len(),
        in_comment,
    })
}

/// The tags apt looks an item up by: its name split at each `::`, the way
/// apt's `Configuration::Lookup()` splits it (a `::` right after another is
/// part of the next tag). `None` when a tag is empty: apt finds no item by an
/// empty tag, it makes a new one each time (a list item).
pub fn tags(name: &[u8]) -> Option<Vec<&[u8]>> {
    let name = c_str(name);
    let mut tags = Vec::new();
    let (mut start, mut at) = (0, 0);
    while at + 2 <= name.len() {
        if name[at] == b':' && name[at + 1] == b':' {
            tags.push(&name[start..at]);
            at += 2;
            start = at;
        }
        at += 1;
    }
    tags.push(&name[start..]);
    tags.iter().all(|tag| !tag.is_empty()).then_some(tags)
}

/// Whether the item `name` is `key` (its tags, ASCII case ignored), or, with
/// `or_above`, an item above it.
pub fn names(name: &[u8], key: &[&str], or_above: bool) -> bool {
    let Some(tags) = tags(name) else {
        return false;
    };
    let length_fits = if or_above {
        tags.len() <= key.len()
    } else {
        tags.len() == key.len()
    };
    length_fits
        && tags
            .iter()
            .zip(key)
            .all(|(tag, wanted)| tag.eq_ignore_ascii_case(wanted.as_bytes()))
}

/// What apt makes of a file of a configuration parts directory
/// (`apt.conf.d`) by its name ([`part_name`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartName {
    /// apt reads it.
    Read,
    /// apt skips it.
    Skipped,
    /// apt reads it in some locales and skips it in others: it would read it
    /// but for a byte beyond ASCII, which its `isalpha()` takes for a letter
    /// in some single-byte locales (`0xe9`, `é` in ISO-8859-1) and not in
    /// the C locale or a UTF-8 one.
    ByLocale,
}

/// What apt makes of the file `name` of a configuration parts directory
/// (`apt.conf.d`), by its name: `GetListOfFilesInDir()` with the extension
/// `conf` or none. It skips a name that starts with a dot, one with another
/// extension (`.bak`, `.dpkg-old`, `.disabled`), one with a character other
/// than a letter, a digit, `_`, `-`, `:` and `.` (`x~`), and one that ends
/// with a dot. Whether the file is a regular file is asked apart.
pub fn part_name(name: &[u8]) -> PartName {
    if name.is_empty() || name[0] == b'.' || name.last() == Some(&b'.') {
        return PartName::Skipped;
    }
    let extension = match name.iter().rposition(|&byte| byte == b'.') {
        Some(dot) => &name[dot + 1..],
        None => name,
    };
    if extension != name && extension != b"conf" {
        return PartName::Skipped;
    }
    let mut beyond_ascii = false;
    for &byte in name {
        if !byte.is_ascii() {
            beyond_ascii = true;
        } else if !(byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b':' | b'.')) {
            return PartName::Skipped;
        }
    }
    if beyond_ascii {
        PartName::ByLocale
    } else {
        PartName::Read
    }
}

/// What C's `strtol(text, &end, 0)` makes of the whole of `text`, on a
/// 64-bit `long`: `None` unless it reads every byte. It skips white space,
/// takes a sign, reads hexadecimal after `0x`, binary after `0b`, octal after
/// `0`, decimal otherwise, and saturates on overflow.
///
/// The `0b` is the 2023 C standard's, which glibc's `strtol()` reads since
/// 2.38 for a program that asks for it, as g++ does (its `_GNU_SOURCE`):
/// libapt-pkg imports that `strtol()` (`__isoc23_strtol`) on every release
/// NAILS supports, Debian 13 and Ubuntu 24.04 and 26.04. A `0b` with no
/// binary digit after it reads as 0 and stops at the `b`, as a `0x` with no
/// hex digit after it stops at the `x`: no number, either way.
fn strtol_whole(text: &[u8]) -> Option<i64> {
    let mut at = 0;
    while at < text.len() && is_space(text[at]) {
        at += 1;
    }
    let negative = match text.get(at) {
        Some(b'-') => {
            at += 1;
            true
        }
        Some(b'+') => {
            at += 1;
            false
        }
        _ => false,
    };
    let (radix, digits_at) = match (text.get(at), text.get(at + 1), text.get(at + 2)) {
        (Some(b'0'), Some(b'x' | b'X'), Some(digit)) if digit.is_ascii_hexdigit() => (16, at + 2),
        (Some(b'0'), Some(b'b' | b'B'), Some(b'0' | b'1')) => (2, at + 2),
        (Some(b'0'), _, _) => (8, at),
        _ => (10, at),
    };
    let digits = &text[digits_at..];
    let count = digits
        .iter()
        .take_while(|&&byte| (byte as char).is_digit(radix))
        .count();
    if count == 0 || digits_at + count != text.len() {
        return None;
    }
    let mut value: i128 = 0;
    for &byte in &digits[..count] {
        value = value * i128::from(radix) + i128::from((byte as char).to_digit(radix)?);
        value = value.min(i128::from(i64::MAX) + 1);
    }
    let value = if negative { -value } else { value };
    Some(value.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64)
}

/// The value `value` as apt's `Configuration::FindB()` reads it, `default`
/// when it says nothing: an empty value, or a word apt does not know.
///
/// apt reads a number first, with `strtol()` into an `int` (so `0x1`, `01`,
/// `0b1` and `4294967297` read as 1), and takes it when strtol() reads the
/// whole value and it is 0 or 1. Then it knows `no`, `false`, `without`, `off`,
/// `disable` and `yes`, `true`, `with`, `on`, `enable`, in any ASCII case,
/// comparing the value up to its first NUL byte (a `%00` in a word puts one
/// in). strtol() stops at that byte, so a value that holds one is never a
/// number.
pub fn string_to_bool(value: &[u8], default: bool) -> bool {
    if value.is_empty() {
        return default;
    }
    if !value.contains(&0)
        && let Some(number) = strtol_whole(value)
    {
        // apt keeps strtol()'s long in an int: the low 32 bits.
        match number as i32 {
            0 => return false,
            1 => return true,
            _ => {}
        }
    }
    let value = c_str(value);
    let is = |word: &str| value.eq_ignore_ascii_case(word.as_bytes());
    if ["no", "false", "without", "off", "disable"]
        .iter()
        .any(|word| is(word))
    {
        return false;
    }
    if ["yes", "true", "with", "on", "enable"]
        .iter()
        .any(|word| is(word))
    {
        return true;
    }
    default
}

/// Whether apt's reading of `value` as a boolean hangs on the system's
/// locale: a byte beyond ASCII before its first NUL. strtol() reads no number
/// in such a value, but `strcasecmp()` compares it with apt's words by the
/// locale's case rules, which can lowercase such a byte to an ASCII letter:
/// `İ` (`0xdd` in ISO-8859-9) to `i`, so that `W\xddTH` reads as `with` in
/// tr_TR.ISO-8859-9. [`string_to_bool`] reads by ASCII's rules alone, which
/// know no word with such a byte.
pub fn value_by_locale(value: &[u8]) -> bool {
    !c_str(value).is_ascii()
}

#[cfg(test)]
#[path = "apt_conf_tests.rs"]
mod tests;
