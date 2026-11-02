// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What a shell's startup files say about when it writes its history.
//!
//! The files are read in the order the shell reads them, each stage's file in
//! `/etc` (and, for zsh, in `/etc/zsh`, where Debian's and Arch's zsh look)
//! before the user's own:
//!
//! - zsh: `zshenv`, `zprofile`, `zshrc` and `zlogin`, the user's as
//!   `$ZDOTDIR/.zshenv` and so on, `$ZDOTDIR` being the home unless a
//!   `zshenv` sets it;
//! - bash: `/etc/profile`, `/etc/bash.bashrc`, `/etc/bashrc`, then
//!   `~/.bash_profile`, `~/.bash_login`, `~/.profile` and `~/.bashrc`.
//!
//! A line is read for the words a shell would run, its comment dropped and its
//! quotes taken off; what runs only under a condition counts as run.

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
    /// What the check could not read, as the warning names it.
    pub doubts: Vec<String>,
}

/// The text of the startup file at `path`, read through `fs`: `Ok(None)` when
/// nothing is there, `Err` naming the file and why when something is there
/// that the check cannot read. Its type and size are looked up first, which
/// changes no access time, so no FIFO or device is opened.
fn read<F: Filesystem>(fs: &F, path: &Path) -> Result<Option<String>, String> {
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

/// The zsh options that write each command line to the history file as zsh
/// runs: the name as zsh compares it (lower case, without underscores), the
/// name the warning shows, and whether zsh writes a line as it is entered
/// (else once its command ends).
const ZSH_OPTIONS: [(&str, &str, bool); 3] = [
    ("incappendhistory", "INC_APPEND_HISTORY", true),
    ("sharehistory", "SHARE_HISTORY", true),
    ("incappendhistorytime", "INC_APPEND_HISTORY_TIME", false),
];

/// Oh My Zsh's loader, which turns `SHARE_HISTORY` on (its `lib/history.zsh`).
const OH_MY_ZSH: &str = "oh-my-zsh.sh";

/// What the zsh startup files read so far turn on.
struct ZshState<'a> {
    /// The home of the account zsh runs as.
    home: &'a Path,
    /// Where each of [`ZSH_OPTIONS`] was last turned on; `None` while off.
    options: [Option<String>; 3],
    /// The directory of the user's own startup files; `None` once a `zshenv`
    /// set it to something the check cannot follow.
    zdotdir: Option<PathBuf>,
    /// `XDG_CONFIG_HOME` as a startup file set it.
    xdg_config_home: Option<PathBuf>,
}

impl ZshState<'_> {
    /// Turn the option `word` names on or off (`on`), as `place` does:
    /// `share_history`, `SHAREHISTORY` and `no_share_history` are spellings
    /// zsh takes.
    fn set(&mut self, word: &str, on: bool, place: &str) {
        let name: String = word
            .chars()
            .filter(|c| *c != '_')
            .collect::<String>()
            .to_lowercase();
        let (name, on) = match name.strip_prefix("no") {
            Some(rest) if ZSH_OPTIONS.iter().any(|option| option.0 == rest) => (rest, !on),
            _ => (name.as_str(), on),
        };
        if let Some(at) = ZSH_OPTIONS.iter().position(|option| option.0 == name) {
            self.options[at] = on.then(|| place.to_string());
        }
    }

    /// Follow the settings of one startup file's `text`, which is at `place`.
    fn follow(&mut self, text: &str, place: &str, scan: &mut Scan) {
        for line in text.lines() {
            let words = words(line);
            let mut words = words.iter().map(String::as_str).peekable();
            while let Some(word) = words.next() {
                match word {
                    "setopt" | "unsetopt" => {
                        while let Some(option) = words.next_if(|word| *word != ";") {
                            if !option.starts_with(['-', '+']) {
                                self.set(option, word == "setopt", place);
                            }
                        }
                    }
                    "set" => {
                        while let Some(flag) = words.next_if(|word| *word != ";") {
                            if matches!(flag, "-o" | "+o")
                                && let Some(option) = words.next_if(|word| *word != ";")
                            {
                                self.set(option, flag == "-o", place);
                            }
                        }
                    }
                    "source" | "."
                        if words.peek().is_some_and(|file| file.ends_with(OH_MY_ZSH)) =>
                    {
                        let loader = format!("Oh My Zsh, which {place} loads,");
                        self.set("share_history", true, &loader);
                    }
                    _ => {}
                }
            }
            for (name, value) in assignments(line) {
                match name {
                    "XDG_CONFIG_HOME" => self.xdg_config_home = self.resolve(&value),
                    "ZDOTDIR" => {
                        self.zdotdir = self.resolve(&value);
                        if self.zdotdir.is_none() {
                            scan.doubts.push(format!(
                                "the startup files in the ZDOTDIR that {place} sets (`{value}`)"
                            ));
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    /// The directory `value` names, with `~`, `$HOME`, `$XDG_CONFIG_HOME` and
    /// `${XDG_CONFIG_HOME:-$HOME/.config}` in it; `None` when it names
    /// anything else the check cannot know, or no absolute path.
    fn resolve(&self, value: &str) -> Option<PathBuf> {
        let home = self.home.to_string_lossy();
        let config = self
            .xdg_config_home
            .as_ref()
            .map(|dir| dir.to_string_lossy().into_owned());
        let default_config = format!("{home}/.config");
        let mut value = value.to_string();
        for default in [
            "${XDG_CONFIG_HOME:-$HOME/.config}",
            "${XDG_CONFIG_HOME:-${HOME}/.config}",
            "${XDG_CONFIG_HOME:-~/.config}",
        ] {
            value = value.replace(default, config.as_deref().unwrap_or(&default_config));
        }
        for variable in ["${XDG_CONFIG_HOME}", "$XDG_CONFIG_HOME"] {
            if value.contains(variable) {
                value = value.replace(variable, config.as_deref()?);
            }
        }
        value = value.replace("${HOME}", &home).replace("$HOME", &home);
        if value == "~" || value.starts_with("~/") {
            value = format!("{home}{}", &value[1..]);
        }
        let path = PathBuf::from(value);
        let plain = !path.to_string_lossy().contains(['$', '`', '~']);
        (plain && path.is_absolute()).then_some(path)
    }
}

/// The variables a line of shell code assigns, with their values, quotes
/// taken off: `NAME=value` where a word starts, also after `export` and in
/// quotes (`export "NAME=value"`).
fn assignments(line: &str) -> Vec<(&str, String)> {
    let code = code(line);
    let mut found = Vec::new();
    let mut rest = code;
    while let Some(at) = rest.find('=') {
        let before = &rest[..at];
        let name_at = before
            .char_indices()
            .rev()
            .find(|(_, c)| !(c.is_ascii_alphanumeric() || *c == '_'))
            .map_or(0, |(at, c)| at + c.len_utf8());
        let name = &before[name_at..];
        let starts_a_word = before[..name_at]
            .chars()
            .next_back()
            .is_none_or(|c| c.is_whitespace() || matches!(c, ';' | '&' | '|' | '(' | '"' | '\''));
        let after = &rest[at + 1..];
        let (value, len) = value(after);
        if starts_a_word && !name.is_empty() {
            found.push((name, value));
        }
        rest = &after[len.min(after.len())..];
    }
    found
}

/// The value at the start of `text`, as a shell word: up to a blank or `;`
/// outside quotes, its quotes taken off. Returns the value and how many bytes
/// of `text` it took.
fn value(text: &str) -> (String, usize) {
    let mut value = String::new();
    let mut quote = None;
    for (at, c) in text.char_indices() {
        match (quote, c) {
            (None, '\'' | '"') => quote = Some(c),
            (Some(open), c) if c == open => quote = None,
            (None, c) if c.is_whitespace() || c == ';' => return (value, at),
            (_, c) => value.push(c),
        }
    }
    (value, text.len())
}

/// What zsh's startup files below `/etc` and in `home` turn on, through `fs`.
pub(super) fn zsh<F: Filesystem>(fs: &F, home: &Path) -> Scan {
    let mut scan = Scan::default();
    let mut state = ZshState {
        home,
        options: Default::default(),
        zdotdir: Some(home.to_path_buf()),
        xdg_config_home: None,
    };
    let follow = |state: &mut ZshState, path: PathBuf, scan: &mut Scan| match read(fs, &path) {
        Ok(Some(text)) => state.follow(&text, &path.to_string_lossy(), scan),
        Ok(None) => {}
        Err(why) => scan.doubts.push(why),
    };
    for stage in ["zshenv", "zprofile", "zshrc", "zlogin"] {
        for dir in ["/etc", "/etc/zsh"] {
            follow(&mut state, Path::new(dir).join(stage), &mut scan);
        }
        // The user's own, from where the files read so far put ZDOTDIR.
        if let Some(dir) = state.zdotdir.clone() {
            follow(&mut state, dir.join(format!(".{stage}")), &mut scan);
        }
    }
    for ((_, shown, entered), place) in ZSH_OPTIONS.iter().zip(state.options) {
        if let Some(place) = place {
            scan.writes.push(Write {
                what: format!("{place} sets {shown}"),
                entered: *entered,
            });
        }
    }
    scan
}

/// The history command a bash startup file's `text` runs from
/// `PROMPT_COMMAND`: `history -a` or `history -w`, when the file names
/// `PROMPT_COMMAND` and runs one of them anywhere.
fn prompt_command_writes(text: &str) -> Option<&'static str> {
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

/// What bash's startup files below `/etc` and in `home` turn on, through `fs`.
pub(super) fn bash<F: Filesystem>(fs: &F, home: &Path) -> Scan {
    let mut scan = Scan::default();
    let system = ["/etc/profile", "/etc/bash.bashrc", "/etc/bashrc"].map(PathBuf::from);
    let user = [".bash_profile", ".bash_login", ".profile", ".bashrc"].map(|file| home.join(file));
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
            Err(why) => scan.doubts.push(why),
        }
    }
    scan
}
