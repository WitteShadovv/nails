// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! How plocate's updatedb reads `/etc/updatedb.conf`: `uc_lex()`,
//! `parse_updatedb_conf()` and the end of `conf_prepare()` in plocate's
//! `conf.cpp`, written as the C reads its `FILE` one `getc_unlocked()` at a
//! time, with `ungetc()`, in the C locale.
//!
//! Where updatedb prints an error and exits, the model returns the line it
//! names and the message's first words.

/// What updatedb keeps of the file once `conf_prepare()` has finished its
/// lists: `PRUNEFS` in upper case, every list sorted and without
/// duplicates.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Conf {
    /// `conf_prune_bind_mounts`.
    pub prune_bind_mounts: bool,
    /// `conf_prunefs`.
    pub prunefs: Vec<Vec<u8>>,
    /// `conf_prunenames`.
    pub prunenames: Vec<Vec<u8>>,
    /// `conf_prunepaths`.
    pub prunepaths: Vec<Vec<u8>>,
}

/// The error updatedb exits with: the line it names, and what its message
/// starts with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exit {
    /// `uc_line`.
    pub line: u32,
    /// The message, up to its variable part.
    pub message: &'static str,
}

const EOF: i32 = -1;

/// The `FILE` updatedb reads.
struct File<'a> {
    bytes: &'a [u8],
    pos: usize,
    pushed: Option<i32>,
}

impl File<'_> {
    fn getc(&mut self) -> i32 {
        if let Some(c) = self.pushed.take() {
            return c;
        }
        match self.bytes.get(self.pos) {
            Some(&byte) => {
                self.pos += 1;
                i32::from(byte)
            }
            None => EOF,
        }
    }

    fn ungetc(&mut self, c: i32) {
        if c != EOF {
            self.pushed = Some(c);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Token {
    Eof,
    Eol,
    Identifier,
    Equal,
    Quoted,
    Other,
    PruneBindMounts,
    PruneFs,
    PruneNames,
    PrunePaths,
}

fn isspace(c: i32) -> bool {
    matches!(c, 0x20 | 0x09..=0x0d)
}

fn isalpha(c: i32) -> bool {
    matches!(c, 0x41..=0x5a | 0x61..=0x7a)
}

fn isalnum(c: i32) -> bool {
    isalpha(c) || matches!(c, 0x30..=0x39)
}

struct Lexer<'a> {
    file: File<'a>,
    uc_line: u32,
    uc_current_line: u32,
    uc_lex_buf: Vec<u8>,
}

impl Lexer<'_> {
    /// `uc_lex()`; `Err` where it exits.
    fn uc_lex(&mut self) -> Result<Token, Exit> {
        self.uc_lex_buf.clear();
        self.uc_line = self.uc_current_line;
        let mut c;
        loop {
            c = self.file.getc();
            if c == EOF {
                return Ok(Token::Eof);
            }
            if !(c != i32::from(b'\n') && isspace(c)) {
                break;
            }
        }
        if c == i32::from(b'#') {
            loop {
                c = self.file.getc();
                if c == EOF {
                    return Ok(Token::Eof);
                }
                if c == i32::from(b'\n') {
                    break;
                }
            }
        }
        if c == i32::from(b'\n') {
            self.uc_current_line += 1;
            return Ok(Token::Eol);
        }
        if c == i32::from(b'=') {
            return Ok(Token::Equal);
        }
        if c == i32::from(b'"') {
            loop {
                c = self.file.getc();
                if c == i32::from(b'"') {
                    return Ok(Token::Quoted);
                }
                if c == EOF || c == i32::from(b'\n') {
                    return Err(Exit {
                        line: self.uc_line,
                        message: "missing closing `\"'",
                    });
                }
                self.uc_lex_buf.push(c as u8);
            }
        }
        if !isalpha(c) && c != i32::from(b'_') {
            return Ok(Token::Other);
        }
        loop {
            self.uc_lex_buf.push(c as u8);
            c = self.file.getc();
            if !(c != EOF && (isalnum(c) || c == i32::from(b'_'))) {
                break;
            }
        }
        self.file.ungetc(c);
        Ok(match self.uc_lex_buf.as_slice() {
            b"PRUNE_BIND_MOUNTS" => Token::PruneBindMounts,
            b"PRUNEFS" => Token::PruneFs,
            b"PRUNENAMES" => Token::PruneNames,
            b"PRUNEPATHS" => Token::PrunePaths,
            _ => Token::Identifier,
        })
    }
}

/// `uc_lex_buf.c_str()`: the buffer up to its first NUL.
fn c_str(buf: &[u8]) -> &[u8] {
    match buf.iter().position(|&byte| byte == 0) {
        Some(nul) => &buf[..nul],
        None => buf,
    }
}

/// `var_add_values()`.
fn var_add_values(list: &mut Vec<Vec<u8>>, val: &[u8]) {
    let mut i = 0;
    loop {
        while i < val.len() && isspace(i32::from(val[i])) {
            i += 1;
        }
        if i == val.len() {
            break;
        }
        let start = i;
        loop {
            i += 1;
            if !(i < val.len() && !isspace(i32::from(val[i]))) {
                break;
            }
        }
        list.push(val[start..i].to_vec());
    }
}

/// `parse_bool()`.
fn parse_bool(dest: &mut bool, s: &[u8]) -> bool {
    match s {
        b"0" | b"no" => {
            *dest = false;
            true
        }
        b"1" | b"yes" => {
            *dest = true;
            true
        }
        _ => false,
    }
}

/// `parse_updatedb_conf()` on the file's bytes, then the finishing of the
/// lists in `conf_prepare()`.
pub fn parse_updatedb_conf(bytes: &[u8]) -> Result<Conf, Exit> {
    let mut lexer = Lexer {
        file: File {
            bytes,
            pos: 0,
            pushed: None,
        },
        uc_line: 0,
        uc_current_line: 1,
        uc_lex_buf: Vec::new(),
    };
    let mut conf = Conf::default();
    let mut had = [false; 4];
    let exit = |line, message| Err(Exit { line, message });
    'lines: loop {
        let token = lexer.uc_lex()?;
        let had_var = match token {
            Token::Eof => break 'lines,
            Token::Eol => continue,
            Token::PruneBindMounts => 0,
            Token::PruneFs => 1,
            Token::PruneNames => 2,
            Token::PrunePaths => 3,
            Token::Identifier => return exit(lexer.uc_line, "unknown variable"),
            _ => return exit(lexer.uc_line, "variable name expected"),
        };
        if had[had_var] {
            return exit(lexer.uc_line, "variable was already defined");
        }
        had[had_var] = true;
        let var_token = token;
        if lexer.uc_lex()? != Token::Equal {
            return exit(lexer.uc_line, "`=' expected after variable name");
        }
        if lexer.uc_lex()? != Token::Quoted {
            return exit(lexer.uc_line, "value in quotes expected after `='");
        }
        let value = c_str(&lexer.uc_lex_buf).to_vec();
        match var_token {
            Token::PruneBindMounts => {
                if !parse_bool(&mut conf.prune_bind_mounts, &value) {
                    return exit(lexer.uc_line, "invalid value of PRUNE_BIND_MOUNTS");
                }
            }
            Token::PruneFs => var_add_values(&mut conf.prunefs, &value),
            Token::PruneNames => var_add_values(&mut conf.prunenames, &value),
            _ => var_add_values(&mut conf.prunepaths, &value),
        }
        let mut token = lexer.uc_lex()?;
        if token != Token::Eol && token != Token::Eof {
            return exit(lexer.uc_line, "unexpected data after variable value");
        }
        while token != Token::Eol {
            if token == Token::Eof {
                break 'lines;
            }
            token = lexer.uc_lex()?;
        }
    }
    for fs in &mut conf.prunefs {
        fs.make_ascii_uppercase();
    }
    for list in [
        &mut conf.prunefs,
        &mut conf.prunenames,
        &mut conf.prunepaths,
    ] {
        list.sort();
        list.dedup();
    }
    Ok(conf)
}
