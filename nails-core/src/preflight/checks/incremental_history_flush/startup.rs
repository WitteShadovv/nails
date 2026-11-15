// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Reading a shell's startup files, and what bash's say about when it writes
//! its history; zsh's are read by [`super::zsh`].
//!
//! bash's files are read as a login shell and an interactive one read them,
//! together: `/etc/profile`, `/etc/bash.bashrc`, `/etc/bashrc`, then
//! `~/.bash_profile`, `~/.bash_login`, `~/.profile` and `~/.bashrc` in each
//! home the shell may run with. A line is read for the words a shell would
//! run, its comment dropped and its quotes taken off, and goes on in the next
//! one where what is left of it ends in a backslash. A comment starts at a
//! `#` that starts a word outside quotes, after a space or a tab (bash's
//! blanks) or an operator, and ends with its line, a backslash at its end
//! too, as in bash ([`uncommented`]).

use std::path::{Path, PathBuf};

use crate::Filesystem;

/// The most of a startup file the check reads: 4 MiB, more than any startup
/// file holds.
const READ_LIMIT: u64 = 4 << 20;

/// A setting that makes a shell write each command line to its history file
/// as it runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Write {
    /// The setting and where it is made, as the warning names them.
    pub what: String,
    /// Whether the shell writes a command line as it is entered, rather than
    /// once the command ends.
    pub entered: bool,
    /// Whether it is one of zsh's options, which the check counts as on
    /// wherever a file names it, a turn-off too.
    pub option: bool,
}

/// What the check read of a shell's startup files.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Scan {
    /// The settings found.
    pub writes: Vec<Write>,
    /// What the check could not follow, each as a clause of the warning
    /// (`it could not read ...`).
    pub doubts: Vec<String>,
    /// Whether the files a zsh started with `-f` or `-d` reads may turn
    /// `RCS` or `GLOBAL_RCS` on again, so that it reads what it would skip.
    pub reopened: bool,
    /// The doubts of the prompts that hold code zsh runs as it shows them,
    /// which hold when `PROMPT_SUBST` is on: the files do not turn it on,
    /// but a command line may.
    pub prompts: Vec<String>,
}

/// The text of the startup file at `path`, read through `fs`: `Ok(None)` when
/// nothing is there, `Err` naming the file and why when something is there
/// that the check cannot read. Its type and size are looked up first, which
/// changes no access time, so no FIFO or device is opened.
pub(super) fn read<F: Filesystem>(fs: &F, path: &Path) -> Result<Option<String>, String> {
    let unread = |why: String| format!("{} ({why})", path.display());
    let failed = |error: crate::NailsError| {
        unread(
            error
                .io_kind()
                .map_or_else(|| error.to_string(), |kind| kind.to_string()),
        )
    };
    match fs.inode(path) {
        Ok(None) => return Ok(None),
        Ok(Some(_)) => {}
        Err(error) => return Err(failed(error)),
    }
    match fs.is_regular_file(path) {
        Ok(true) => {}
        Ok(false) => return Err(unread("not a regular file".to_string())),
        Err(error) => return Err(failed(error)),
    }
    match fs.file_size(path) {
        Ok(size) if size > READ_LIMIT => {
            return Err(unread(format!(
                "{size} bytes, more than a startup file holds"
            )));
        }
        Ok(_) => {}
        Err(error) => return Err(failed(error)),
    }
    fs.read_file_bytes(path)
        .map(|bytes| Some(String::from_utf8_lossy(&bytes).into_owned()))
        .map_err(failed)
}

/// Where the reading of bash code is ([`uncommented`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Quote {
    None,
    /// In `'...'`, where nothing is escaped.
    Single,
    /// In `"..."`, where a backslash escapes the next character.
    Double,
    /// In `$'...'`, where a backslash escapes the next character.
    Ansi,
}

/// The delimiter of a here-document that `chars` gives past its `<<`, and
/// whether its lines may start with tabs (`<<-`), as bash reads it: the next
/// word, past blanks, its quotes and backslashes taken off; `None` for a
/// here-string (`<<<`) or where no word follows.
fn delimiter(chars: &mut std::iter::Peekable<std::str::Chars>) -> Option<(String, bool)> {
    if chars.peek() == Some(&'<') {
        return None;
    }
    let tabs = chars.next_if_eq(&'-').is_some();
    while chars.next_if(|c| matches!(c, ' ' | '\t')).is_some() {}
    let mut word = String::new();
    let mut quote: Option<char> = None;
    while let Some(&c) = chars.peek() {
        match (quote, c) {
            (Some(open), c) if c == open => quote = None,
            (Some(_), c) => word.push(c),
            (None, '\'' | '"') => quote = Some(c),
            (None, '\\') => {
                chars.next();
                word.extend(chars.peek().copied());
            }
            (None, ' ' | '\t' | '\n' | ';' | '&' | '|' | '<' | '>' | '(' | ')') => break,
            (None, c) => word.push(c),
        }
        chars.next();
    }
    (!word.is_empty()).then_some((word, tabs))
}

/// `text`, bash code, with its comments dropped as bash reads them: a `#`
/// that starts a word, at a line's start or after a space, a tab or an
/// operator, outside quotes (`'...'`, `"..."`, `$'...'`) and not escaped by a
/// backslash, starts one, which ends with its line, a backslash at its end
/// too. bash keeps any other white space in the word (a vertical tab, a
/// no-break space), so a `#` after one starts no comment. A here-document's
/// body is text, in which no `#` starts a comment and no quote opens one.
/// bash reads a startup file and what it sources as it reads a script, with
/// comments whatever `interactive_comments` holds.
fn uncommented(text: &str) -> String {
    let mut kept = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut quote = Quote::None;
    let mut previous: Option<char> = None;
    let mut bodies: Vec<(String, bool)> = Vec::new();
    while let Some(c) = chars.next() {
        match quote {
            Quote::Single if c == '\'' => quote = Quote::None,
            Quote::Double if c == '"' => quote = Quote::None,
            Quote::Ansi if c == '\'' => quote = Quote::None,
            Quote::Double | Quote::Ansi if c == '\\' => {
                kept.push(c);
                if let Some(next) = chars.next() {
                    kept.push(next);
                }
                previous = Some('\\');
                continue;
            }
            Quote::Single | Quote::Double | Quote::Ansi => {}
            Quote::None => match c {
                '\\' => {
                    kept.push(c);
                    if let Some(next) = chars.next() {
                        kept.push(next);
                    }
                    previous = Some('\\');
                    continue;
                }
                '\'' => quote = Quote::Single,
                '"' => quote = Quote::Double,
                '$' if chars.peek() == Some(&'\'') => {
                    kept.push(c);
                    kept.push('\'');
                    chars.next();
                    quote = Quote::Ansi;
                    previous = Some('\'');
                    continue;
                }
                '#' if previous.is_none_or(|p| {
                    matches!(p, '\n' | ' ' | '\t' | ';' | '&' | '|' | '(' | ')')
                }) =>
                {
                    while chars.next_if(|c| *c != '\n').is_some() {}
                    continue;
                }
                '<' if chars.peek() == Some(&'<') => {
                    kept.push(c);
                    kept.push('<');
                    chars.next();
                    let mut ahead = chars.clone();
                    if let Some(body) = delimiter(&mut ahead) {
                        bodies.push(body);
                    }
                    previous = Some('<');
                    continue;
                }
                '\n' if !bodies.is_empty() => {
                    kept.push(c);
                    // The bodies of the here-documents the line opened, in
                    // order, each to the line that is its delimiter.
                    for (word, tabs) in std::mem::take(&mut bodies) {
                        loop {
                            let mut line = String::new();
                            while let Some(next) = chars.next_if(|c| *c != '\n') {
                                line.push(next);
                            }
                            let ended = chars.next().is_some();
                            kept.push_str(&line);
                            if ended {
                                kept.push('\n');
                            }
                            let shown = if tabs {
                                line.trim_start_matches('\t')
                            } else {
                                line.as_str()
                            };
                            if shown == word || !ended {
                                break;
                            }
                        }
                    }
                    previous = Some('\n');
                    continue;
                }
                _ => {}
            },
        }
        kept.push(c);
        previous = Some(c);
    }
    kept
}

/// The words of a line of shell code, its comment dropped already
/// ([`uncommented`]) and its quotes, braces and backslashes taken off, split
/// at blanks and at `=`, with `;` standing for each place where a command can
/// end (`;`, `&`, `|`, parentheses and backquotes).
fn words(line: &str) -> Vec<String> {
    fn end(word: &mut String, words: &mut Vec<String>) {
        if !word.is_empty() {
            words.push(std::mem::take(word));
        }
    }
    let mut words = Vec::new();
    let mut word = String::new();
    for c in line.chars() {
        match c {
            '\'' | '"' | '\\' | '{' | '}' => {}
            ';' | '&' | '|' | '(' | ')' | '`' => {
                end(&mut word, &mut words);
                words.push(";".to_string());
            }
            c if c.is_whitespace() || c == '=' => end(&mut word, &mut words),
            c => word.push(c),
        }
    }
    end(&mut word, &mut words);
    words
}

/// The lines of bash code `text`, its comments dropped ([`uncommented`]),
/// each with the lines it goes on in: one that ends in a backslash goes on in
/// the next, as bash joins them; a comment ends with its line, as a backslash
/// in it escapes nothing.
fn joined_lines(text: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut open: Option<String> = None;
    for line in uncommented(text).split('\n') {
        let mut joined = open.take().unwrap_or_default();
        joined.push_str(line);
        match joined.strip_suffix('\\') {
            Some(rest) if rest.len() + 1 == joined.len() => open = Some(rest.to_string()),
            _ => lines.push(joined),
        }
    }
    lines.extend(open);
    lines
}

/// The history command a bash startup file's `text` runs from
/// `PROMPT_COMMAND`: `history -a` or `history -w`, when the file names
/// `PROMPT_COMMAND` and runs one of them anywhere, its lines joined as bash
/// joins them ([`joined_lines`]).
fn prompt_command_writes(text: &str) -> Option<&'static str> {
    let mut prompt_command = false;
    let mut found = None;
    for line in joined_lines(text) {
        let line = line.as_str();
        prompt_command |= line.contains("PROMPT_COMMAND");
        let words = words(line);
        for pair in words.windows(2) {
            if pair[0] == "history"
                && let Some(flags) = pair[1].strip_prefix('-')
            {
                if flags.contains('a') {
                    found.get_or_insert("history -a");
                } else if flags.contains('w') {
                    found.get_or_insert("history -w");
                }
            }
        }
    }
    found.filter(|_| prompt_command)
}

/// What bash's startup files below `/etc` and in `homes` turn on, through
/// `fs`.
pub(super) fn bash<F: Filesystem>(fs: &F, homes: &[PathBuf]) -> Scan {
    let mut scan = Scan::default();
    let system = ["/etc/profile", "/etc/bash.bashrc", "/etc/bashrc"].map(PathBuf::from);
    let user = homes.iter().flat_map(|home| {
        [".bash_profile", ".bash_login", ".profile", ".bashrc"].map(|file| home.join(file))
    });
    for path in system.into_iter().chain(user) {
        match read(fs, &path) {
            Ok(Some(text)) => {
                if let Some(command) = prompt_command_writes(&text) {
                    scan.writes.push(Write {
                        what: format!("{} runs `{command}` from PROMPT_COMMAND", path.display()),
                        entered: false,
                        option: false,
                    });
                }
            }
            Ok(None) => {}
            Err(why) => scan.doubts.push(format!("it could not read {why}")),
        }
    }
    scan
}
