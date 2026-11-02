// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Reading a shell's startup files, and what bash's say about when it writes
//! its history; zsh's are read by [`super::zsh`].
//!
//! bash's files are read as a login shell and an interactive one read them,
//! together: `/etc/profile`, `/etc/bash.bashrc`, `/etc/bashrc`, then
//! `~/.bash_profile`, `~/.bash_login`, `~/.profile` and `~/.bashrc` in each
//! home the shell may run with. A line ending in a backslash goes on in the
//! next one, and a line is read for the words a shell would run, its comment
//! dropped and its quotes taken off.

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
}

/// What the check read of a shell's startup files.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Scan {
    /// The settings found.
    pub writes: Vec<Write>,
    /// What the check could not follow, each as a clause of the warning
    /// (`it could not read ...`).
    pub doubts: Vec<String>,
    /// Whether NixOS's `programs.zsh` names a setting found, in the
    /// `/etc/zshrc` it writes.
    pub nixos: bool,
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
    if !fs.is_regular_file(path).unwrap_or(false) {
        return Err(unread("not a regular file".to_string()));
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

/// `line` without its comment: from a `#` that starts a word on.
fn code(line: &str) -> &str {
    let mut previous: Option<char> = None;
    for (at, c) in line.char_indices() {
        if c == '#'
            && previous
                .is_none_or(|p| p.is_whitespace() || matches!(p, ';' | '&' | '|' | '(' | ')'))
        {
            return &line[..at];
        }
        previous = Some(c);
    }
    line
}

/// The words of a line of shell code, its comment dropped and its quotes,
/// braces and backslashes taken off, split at blanks and at `=`, with `;`
/// standing for each place where a command can end (`;`, `&`, `|`,
/// parentheses and backquotes).
fn words(line: &str) -> Vec<String> {
    fn end(word: &mut String, words: &mut Vec<String>) {
        if !word.is_empty() {
            words.push(std::mem::take(word));
        }
    }
    let mut words = Vec::new();
    let mut word = String::new();
    for c in code(line).chars() {
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

/// The history command a bash startup file's `text` runs from
/// `PROMPT_COMMAND`: `history -a` or `history -w`, when the file names
/// `PROMPT_COMMAND` and runs one of them anywhere. A line ending in a
/// backslash goes on in the next one.
fn prompt_command_writes(text: &str) -> Option<&'static str> {
    let text = text.replace("\\\r\n", "").replace("\\\n", "");
    let mut prompt_command = false;
    let mut found = None;
    for line in text.lines() {
        prompt_command |= code(line).contains("PROMPT_COMMAND");
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
                    });
                }
            }
            Ok(None) => {}
            Err(why) => scan.doubts.push(format!("it could not read {why}")),
        }
    }
    scan
}
