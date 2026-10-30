// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! `/etc/updatedb.conf`, read as plocate's and mlocate's updatedb read it.
//!
//! The grammar is updatedb.conf(5)'s, and [`parse_updatedb_conf`] follows
//! `parse_updatedb_conf()` and its lexer `uc_lex()` in plocate's `conf.cpp`,
//! which plocate took from mlocate, whose updatedb reads the file the same
//! way. Both run in the C locale, so every class of byte below is ASCII's:
//!
//! - a line is `VARIABLE = "VALUE"`, with blanks between the tokens (what C's
//!   `isspace()` takes for one, the newline aside, which ends the line). An
//!   empty line is skipped, and a `#` outside a quoted value starts a comment
//!   that runs to the end of the line;
//! - the variables are `PRUNEFS`, `PRUNENAMES`, `PRUNEPATHS` and
//!   `PRUNE_BIND_MOUNTS`. Another name, a variable set twice, a missing `=` or
//!   quoted value, a value without its closing quote on the same line, data
//!   after the value, or a `PRUNE_BIND_MOUNTS` other than `0`, `no`, `1` or
//!   `yes` is an error ([`ConfError`]): updatedb stops before it scans
//!   anything;
//! - a value is split at blanks into its entries. updatedb hands the value on
//!   as a C string, so a NUL in it ends it there.
//!
//! A missing file is no error: updatedb then prunes nothing the file would
//! have named. The caller tells a missing file from one it cannot read.

/// A variable of `updatedb.conf`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Variable {
    /// `PRUNE_BIND_MOUNTS`: whether bind mounts are skipped.
    PruneBindMounts,
    /// `PRUNEFS`: filesystem types whose mounts are skipped.
    PruneFs,
    /// `PRUNENAMES`: directory names that are skipped.
    PruneNames,
    /// `PRUNEPATHS`: directory paths that are skipped.
    PrunePaths,
}

impl Variable {
    /// The name the file spells it with.
    pub fn name(self) -> &'static str {
        match self {
            Variable::PruneBindMounts => "PRUNE_BIND_MOUNTS",
            Variable::PruneFs => "PRUNEFS",
            Variable::PruneNames => "PRUNENAMES",
            Variable::PrunePaths => "PRUNEPATHS",
        }
    }

    fn index(self) -> usize {
        match self {
            Variable::PruneBindMounts => 0,
            Variable::PruneFs => 1,
            Variable::PruneNames => 2,
            Variable::PrunePaths => 3,
        }
    }
}

/// What `updatedb.conf` sets: every entry as the file writes it, in its
/// order. updatedb compares a `PRUNEFS` entry without ASCII case and the
/// others byte for byte.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpdatedbConf {
    /// `PRUNE_BIND_MOUNTS`, when the file sets it.
    pub prune_bind_mounts: Option<bool>,
    /// The `PRUNEFS` entries.
    pub prunefs: Vec<Vec<u8>>,
    /// The `PRUNENAMES` entries.
    pub prunenames: Vec<Vec<u8>>,
    /// The `PRUNEPATHS` entries.
    pub prunepaths: Vec<Vec<u8>>,
}

/// Why updatedb refuses the file, and the line it names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfError {
    /// The line, counted from 1.
    pub line: u32,
    /// What is wrong there.
    pub kind: ConfErrorKind,
}

/// What updatedb refuses in the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfErrorKind {
    /// A name that is not one of the variables.
    UnknownVariable(Vec<u8>),
    /// Something other than a name where a line starts.
    VariableExpected,
    /// A variable set a second time.
    AlreadyDefined(Variable),
    /// No `=` after the variable.
    EqualsExpected,
    /// No quoted value after the `=`.
    QuotedValueExpected,
    /// A quoted value without its closing quote on the same line.
    MissingClosingQuote,
    /// A `PRUNE_BIND_MOUNTS` value other than `0`, `no`, `1` or `yes`.
    InvalidBool(Vec<u8>),
    /// More after the quoted value than a comment.
    DataAfterValue,
}

impl std::fmt::Display for ConfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let line = self.line;
        match &self.kind {
            ConfErrorKind::UnknownVariable(name) => write!(
                f,
                "line {line} sets {}, which updatedb does not know",
                String::from_utf8_lossy(name)
            ),
            ConfErrorKind::VariableExpected => {
                write!(f, "line {line} does not start with a variable name")
            }
            ConfErrorKind::AlreadyDefined(variable) => {
                write!(f, "line {line} sets {} a second time", variable.name())
            }
            ConfErrorKind::EqualsExpected => {
                write!(f, "line {line} has no = after the variable name")
            }
            ConfErrorKind::QuotedValueExpected => {
                write!(f, "line {line} has no quoted value after the =")
            }
            ConfErrorKind::MissingClosingQuote => {
                write!(f, "the quoted value on line {line} is not closed")
            }
            ConfErrorKind::InvalidBool(value) => write!(
                f,
                "line {line} sets PRUNE_BIND_MOUNTS to {:?}, which is none of 0, no, 1 and yes",
                String::from_utf8_lossy(value)
            ),
            ConfErrorKind::DataAfterValue => {
                write!(f, "line {line} goes on after its quoted value")
            }
        }
    }
}

/// A token of `uc_lex()`.
enum Token<'a> {
    /// The end of the file.
    Eof,
    /// The end of a line, a comment's included.
    Eol,
    /// A name that is not a variable.
    Identifier(&'a [u8]),
    /// A variable's name.
    Variable(Variable),
    /// `=`.
    Equal,
    /// A quoted value, without its quotes.
    Quoted(&'a [u8]),
    /// Any other byte.
    Other,
}

/// C's `isspace()` in the C locale.
fn is_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// `uc_lex()` over the bytes of the file.
struct Lexer<'a> {
    bytes: &'a [u8],
    at: usize,
    /// The line the reading is on (`uc_current_line`).
    line: u32,
    /// The line the last token started on (`uc_line`).
    token_line: u32,
}

impl<'a> Lexer<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            at: 0,
            line: 1,
            token_line: 1,
        }
    }

    /// The next byte, consumed.
    fn getc(&mut self) -> Option<u8> {
        let byte = self.bytes.get(self.at).copied()?;
        self.at += 1;
        Some(byte)
    }

    fn next(&mut self) -> Result<Token<'a>, ConfError> {
        self.token_line = self.line;
        let first = loop {
            let Some(byte) = self.getc() else {
                return Ok(Token::Eof);
            };
            if byte == b'\n' || !is_space(byte) {
                break byte;
            }
        };
        match first {
            b'#' => {
                // A comment ends at its newline, which ends the line; one at
                // the end of the file ends the file.
                loop {
                    match self.getc() {
                        None => return Ok(Token::Eof),
                        Some(b'\n') => break,
                        Some(_) => {}
                    }
                }
                self.line += 1;
                Ok(Token::Eol)
            }
            b'\n' => {
                self.line += 1;
                Ok(Token::Eol)
            }
            b'=' => Ok(Token::Equal),
            b'"' => {
                let start = self.at;
                loop {
                    match self.getc() {
                        None | Some(b'\n') => {
                            return Err(ConfError {
                                line: self.token_line,
                                kind: ConfErrorKind::MissingClosingQuote,
                            });
                        }
                        Some(b'"') => return Ok(Token::Quoted(&self.bytes[start..self.at - 1])),
                        Some(_) => {}
                    }
                }
            }
            byte if byte.is_ascii_alphabetic() || byte == b'_' => {
                let start = self.at - 1;
                while self
                    .bytes
                    .get(self.at)
                    .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
                {
                    self.at += 1;
                }
                let word = &self.bytes[start..self.at];
                Ok(match word {
                    b"PRUNE_BIND_MOUNTS" => Token::Variable(Variable::PruneBindMounts),
                    b"PRUNEFS" => Token::Variable(Variable::PruneFs),
                    b"PRUNENAMES" => Token::Variable(Variable::PruneNames),
                    b"PRUNEPATHS" => Token::Variable(Variable::PrunePaths),
                    _ => Token::Identifier(word),
                })
            }
            _ => Ok(Token::Other),
        }
    }
}

/// The entries of a value: its runs of bytes between blanks, as
/// `var_add_values()` splits it.
fn entries(value: &[u8]) -> impl Iterator<Item = Vec<u8>> + '_ {
    value
        .split(|&byte| is_space(byte))
        .filter(|entry| !entry.is_empty())
        .map(<[u8]>::to_vec)
}

/// `parse_bool()`: `0` and `no` are false, `1` and `yes` true.
fn parse_bool(value: &[u8]) -> Option<bool> {
    match value {
        b"0" | b"no" => Some(false),
        b"1" | b"yes" => Some(true),
        _ => None,
    }
}

/// Read `updatedb.conf` as plocate's and mlocate's updatedb read it (see the
/// [module docs](self)).
///
/// # Errors
///
/// The first line updatedb refuses, with what it refuses there: updatedb
/// then stops before it scans anything.
pub fn parse_updatedb_conf(bytes: &[u8]) -> Result<UpdatedbConf, ConfError> {
    let mut lexer = Lexer::new(bytes);
    let mut conf = UpdatedbConf::default();
    let mut defined = [false; 4];
    let fail = |line, kind| Err(ConfError { line, kind });
    loop {
        let variable = match lexer.next()? {
            Token::Eof => return Ok(conf),
            Token::Eol => continue,
            Token::Variable(variable) => variable,
            Token::Identifier(name) => {
                return fail(
                    lexer.token_line,
                    ConfErrorKind::UnknownVariable(name.to_vec()),
                );
            }
            Token::Equal | Token::Quoted(_) | Token::Other => {
                return fail(lexer.token_line, ConfErrorKind::VariableExpected);
            }
        };
        if std::mem::replace(&mut defined[variable.index()], true) {
            return fail(lexer.token_line, ConfErrorKind::AlreadyDefined(variable));
        }
        if !matches!(lexer.next()?, Token::Equal) {
            return fail(lexer.token_line, ConfErrorKind::EqualsExpected);
        }
        let Token::Quoted(quoted) = lexer.next()? else {
            return fail(lexer.token_line, ConfErrorKind::QuotedValueExpected);
        };
        // updatedb hands the value on as a C string: a NUL ends it.
        let value = quoted.split(|&byte| byte == 0).next().unwrap_or_default();
        match variable {
            Variable::PruneBindMounts => match parse_bool(value) {
                Some(flag) => conf.prune_bind_mounts = Some(flag),
                None => {
                    return fail(lexer.token_line, ConfErrorKind::InvalidBool(value.to_vec()));
                }
            },
            Variable::PruneFs => conf.prunefs.extend(entries(value)),
            Variable::PruneNames => conf.prunenames.extend(entries(value)),
            Variable::PrunePaths => conf.prunepaths.extend(entries(value)),
        }
        match lexer.next()? {
            // At the end of the file the next call ends the reading.
            Token::Eol | Token::Eof => {}
            _ => return fail(lexer.token_line, ConfErrorKind::DataAfterValue),
        }
    }
}

#[cfg(test)]
#[path = "conf_tests.rs"]
mod tests;
