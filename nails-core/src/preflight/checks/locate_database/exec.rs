// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The commands an `ExecStart=` value runs, split as systemd splits them.
//!
//! systemd's `config_parse_exec()` reads the value word by word with
//! `extract_first_word()`, unquoting and unescaping each, then expands its
//! specifiers, and at the start of the command the service manager replaces
//! environment variables in the arguments. [`exec_commands`] follows it:
//!
//! - words are separated by blanks (space, tab, newline, carriage return). A
//!   `'` or `"` anywhere in a word quotes up to its partner, and a backslash
//!   escape is read inside and outside quotes as C reads it (`\n`, `\x41`,
//!   `\101`, `\u00e9`, `\s` for a space, ...).
//!   An escape systemd does not know keeps its backslash and the character
//!   after it, and so does a backslash that ends the value outside quotes:
//!   systemd logs "Ignoring unknown escape sequences" and reads the word
//!   again so. Only a quote without its partner, or a backslash that ends
//!   the value inside quotes, makes it refuse the line;
//! - a lone `;` ends one command and starts the next; `\;` is a `;` word;
//! - the first word may start with the prefixes `-`, `@`, `:`, `+`, `!` and
//!   `!!`. With `@` the second word is `argv[0]`; with `:` the arguments keep
//!   their `$`;
//! - `%%` is a `%`. Another specifier is expanded from the unit's own
//!   name and the host's, which NAILS does not do, so a command with one is
//!   [`ExecError::Unknown`];
//! - `$$` in an argument is a `$`. Another `$` names an environment variable,
//!   whose value NAILS does not know, so a command with one is
//!   [`ExecError::Unknown`] too, unless `:` keeps it.

/// One command of an `ExecStart=` value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecCommand {
    /// The program, as the value names it.
    pub program: Vec<u8>,
    /// The arguments after `argv[0]`.
    pub args: Vec<Vec<u8>>,
}

/// Why the commands of a value are not known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecError {
    /// systemd refuses the line, so the service does not start.
    Refused(String),
    /// What the command runs depends on something NAILS does not read.
    Unknown(String),
}

impl std::fmt::Display for ExecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecError::Refused(why) | ExecError::Unknown(why) => f.write_str(why),
        }
    }
}

/// systemd's `WHITESPACE`.
fn is_blank(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r')
}

/// The value of a hexadecimal digit.
fn hex(byte: u8) -> Option<u32> {
    char::from(byte).to_digit(16)
}

/// `cunescape_one()` on the bytes after a backslash: the bytes the escape
/// stands for and how many it takes, or `None` for one systemd refuses.
fn unescape(rest: &[u8]) -> Option<(Vec<u8>, usize)> {
    let first = *rest.first()?;
    let single = |byte: u8| Some((vec![byte], 1));
    match first {
        b'a' => single(0x07),
        b'b' => single(0x08),
        b'f' => single(0x0c),
        b'n' => single(b'\n'),
        b'r' => single(b'\r'),
        b't' => single(b'\t'),
        b'v' => single(0x0b),
        b'\\' | b'"' | b'\'' => single(first),
        b's' => single(b' '),
        b'x' => {
            let value = (hex(*rest.get(1)?)? << 4) | hex(*rest.get(2)?)?;
            // No NUL bytes.
            let byte = u8::try_from(value).ok().filter(|&byte| byte != 0)?;
            Some((vec![byte], 3))
        }
        b'u' | b'U' => {
            let digits = if first == b'u' { 4 } else { 8 };
            let mut value: u32 = 0;
            for at in 1..=digits {
                value = (value << 4) | hex(*rest.get(at)?)?;
            }
            // No NUL; `\U` takes only what systemd's unichar_is_valid()
            // takes, while `\u` encodes even a surrogate.
            if value == 0 || (first == b'U' && !unichar_is_valid(value)) {
                return None;
            }
            Some((encode_utf8(value), digits + 1))
        }
        b'0'..=b'7' => {
            let octal = |at: usize| {
                rest.get(at)
                    .filter(|byte| (b'0'..=b'7').contains(byte))
                    .map(|byte| u32::from(byte - b'0'))
            };
            let value = (octal(0)? << 6) | (octal(1)? << 3) | octal(2)?;
            let byte = u8::try_from(value).ok().filter(|&byte| byte != 0)?;
            Some((vec![byte], 3))
        }
        _ => None,
    }
}

/// systemd's `unichar_is_valid()`: a code point of Unicode that is no
/// surrogate and no noncharacter.
fn unichar_is_valid(c: u32) -> bool {
    c < 0x11_0000
        && (c & 0xFFFF_F800) != 0xD800
        && !(0xFDD0..=0xFDEF).contains(&c)
        && (c & 0xFFFE) != 0xFFFE
}

/// systemd's `utf8_encode_unichar()`: `c` in UTF-8, a surrogate's three
/// bytes included.
fn encode_utf8(c: u32) -> Vec<u8> {
    // Each byte below takes the bits the masks leave, so the casts lose
    // nothing.
    let byte = |bits: u32| (bits & 0xFF) as u8;
    match c {
        0..0x80 => vec![byte(c)],
        0x80..0x800 => vec![byte(0xC0 | (c >> 6)), byte(0x80 | (c & 0x3F))],
        0x800..0x1_0000 => vec![
            byte(0xE0 | (c >> 12)),
            byte(0x80 | ((c >> 6) & 0x3F)),
            byte(0x80 | (c & 0x3F)),
        ],
        _ => vec![
            byte(0xF0 | (c >> 18)),
            byte(0x80 | ((c >> 12) & 0x3F)),
            byte(0x80 | ((c >> 6) & 0x3F)),
            byte(0x80 | (c & 0x3F)),
        ],
    }
}

/// `extract_first_word()` with unquoting and C unescaping at `*at`: the next
/// word, or `None` at the end of the value.
fn next_word(value: &[u8], at: &mut usize) -> Result<Option<Vec<u8>>, ExecError> {
    while value.get(*at).is_some_and(|&byte| is_blank(byte)) {
        *at += 1;
    }
    if *at >= value.len() {
        return Ok(None);
    }
    let refuse = |why: &str| Err(ExecError::Refused(why.to_string()));
    let mut word = Vec::new();
    let mut quote: Option<u8> = None;
    while let Some(&byte) = value.get(*at) {
        *at += 1;
        match (quote, byte) {
            (_, 0) => return refuse("a NUL in the line"),
            (_, b'\\') => match (unescape(&value[*at..]), value.get(*at)) {
                (Some((bytes, taken)), _) => {
                    word.extend(bytes);
                    *at += taken;
                }
                (None, Some(0)) => return refuse("a NUL in the line"),
                // EXTRACT_UNESCAPE_RELAX: the backslash and the character
                // after it stay as they are.
                (None, Some(&next)) => {
                    word.extend([b'\\', next]);
                    *at += 1;
                }
                // A backslash that ends the value stays; inside quotes, the
                // quote without its partner is refused below.
                (None, None) => word.push(b'\\'),
            },
            (Some(open), _) if byte == open => quote = None,
            (Some(_), _) => word.push(byte),
            (None, b'\'' | b'"') => quote = Some(byte),
            (None, _) if is_blank(byte) => return Ok(Some(word)),
            (None, _) => word.push(byte),
        }
    }
    if quote.is_some() {
        return refuse("a quote without its partner");
    }
    Ok(Some(word))
}

/// Expand the specifiers of `word`: `%%` is a `%`, and any other is not
/// known here.
fn specifiers(word: Vec<u8>) -> Result<Vec<u8>, ExecError> {
    if !word.contains(&b'%') {
        return Ok(word);
    }
    let mut out = Vec::with_capacity(word.len());
    let mut bytes = word.into_iter();
    while let Some(byte) = bytes.next() {
        if byte != b'%' {
            out.push(byte);
            continue;
        }
        match bytes.next() {
            Some(b'%') => out.push(b'%'),
            _ => {
                return Err(ExecError::Unknown(
                    "it uses a specifier that NAILS does not expand".to_string(),
                ));
            }
        }
    }
    Ok(out)
}

/// Replace `$$` in an argument with `$`; any other `$` names a variable.
fn environment(word: Vec<u8>) -> Result<Vec<u8>, ExecError> {
    if !word.contains(&b'$') {
        return Ok(word);
    }
    let mut out = Vec::with_capacity(word.len());
    let mut bytes = word.into_iter();
    while let Some(byte) = bytes.next() {
        if byte != b'$' {
            out.push(byte);
            continue;
        }
        match bytes.next() {
            Some(b'$') => out.push(b'$'),
            _ => {
                return Err(ExecError::Unknown(
                    "it takes an argument from an environment variable".to_string(),
                ));
            }
        }
    }
    Ok(out)
}

/// The commands an `ExecStart=` value runs (see the [module docs](self)).
///
/// # Errors
///
/// [`ExecError::Refused`] for a value systemd refuses, and
/// [`ExecError::Unknown`] for one whose words depend on what NAILS does not
/// read.
pub fn exec_commands(value: &str) -> Result<Vec<ExecCommand>, ExecError> {
    let value = value.as_bytes();
    let mut at = 0;
    let mut commands = Vec::new();
    loop {
        let Some(first) = next_word(value, &mut at)? else {
            return Ok(commands);
        };
        if first == b";" {
            continue;
        }
        let (program, argv0_follows, keep_dollars) = strip_prefixes(&first);
        let program = specifiers(program.to_vec())?;
        let mut args = Vec::new();
        let mut argv0_pending = argv0_follows;
        loop {
            // A word ends with the blanks after it, so a `;` that ends the
            // command is looked for at the next word.
            while value.get(at).is_some_and(|&byte| is_blank(byte)) {
                at += 1;
            }
            let rest = &value[at..];
            let lone = |prefix: &[u8]| {
                rest.strip_prefix(prefix)
                    .is_some_and(|after| after.first().is_none_or(|&byte| is_blank(byte)))
            };
            if lone(b";") {
                // The next command starts with it, which skips it.
                break;
            }
            let word = if lone(b"\\;") {
                at += 2;
                b";".to_vec()
            } else {
                match next_word(value, &mut at)? {
                    Some(word) => word,
                    None => break,
                }
            };
            let word = specifiers(word)?;
            let word = if keep_dollars {
                word
            } else {
                environment(word)?
            };
            if std::mem::take(&mut argv0_pending) {
                continue;
            }
            args.push(word);
        }
        if argv0_pending {
            return Err(ExecError::Refused(
                "the @ prefix without the argv[0] it announces".to_string(),
            ));
        }
        commands.push(ExecCommand { program, args });
    }
}

/// The program after the prefixes of the first word, whether `@` announces
/// `argv[0]` as the next word, and whether `:` keeps the `$` of the
/// arguments.
fn strip_prefixes(first: &[u8]) -> (&[u8], bool, bool) {
    let (mut argv0, mut keep_dollars, mut ignore, mut privileged) = (false, false, false, false);
    let mut at = 0;
    while let Some(&byte) = first.get(at) {
        match byte {
            b'-' if !ignore => ignore = true,
            b'@' if !argv0 => argv0 = true,
            b':' if !keep_dollars => keep_dollars = true,
            b'+' | b'!' if !privileged => {
                privileged = true;
                if byte == b'!' && first.get(at + 1) == Some(&b'!') {
                    at += 1;
                }
            }
            _ => break,
        }
        at += 1;
    }
    (&first[at..], argv0, keep_dollars)
}

/// Whether `program` is an updatedb: its file name is `updatedb`, or
/// `updatedb.` and a suffix of letters, digits, `_`, `-` and `.`, as Debian's
/// `updatedb.plocate` and `updatedb.mlocate`. The kernel cuts a process's
/// `comm` to 15 bytes, so a cut name counts too. A word with a blank or
/// another character in it, such as the whole script of `sh -c`, is none.
pub fn is_updatedb(program: &[u8]) -> bool {
    let name = program
        .rsplit(|&byte| byte == b'/')
        .next()
        .unwrap_or(program);
    name == b"updatedb"
        || name.strip_prefix(b"updatedb.").is_some_and(|suffix| {
            !suffix.is_empty()
                && suffix
                    .iter()
                    .all(|&byte| byte.is_ascii_alphanumeric() || b"_-.".contains(&byte))
        })
}

/// Whether `text` names updatedb anywhere.
pub fn mentions_updatedb(text: &[u8]) -> bool {
    text.windows(8).any(|window| window == b"updatedb")
}

#[cfg(test)]
#[path = "exec_tests.rs"]
mod tests;
