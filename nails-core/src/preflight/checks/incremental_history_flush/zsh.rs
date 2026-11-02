// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! When zsh's startup files turn on the options that write each command line
//! to the history file as zsh runs, read in zsh's order and failing closed on
//! what the check cannot follow.
//!
//! zsh reads `zshenv`, then `zprofile` for a login shell, `zshrc` for an
//! interactive one and `zlogin` for a login shell: each stage's file in `/etc`
//! or in `/etc/zsh` (where Debian's and Arch's zsh look), then the user's own
//! in `$ZDOTDIR`, which is the home unless a file read so far sets it. A file
//! that a startup file sources is read where it is sourced, when its path
//! resolves. A zsh runs with one home, which `~` and `$HOME` name, so for a
//! shell that may run with several (a root shell with the operator's), the
//! files are read for each, and an option counts as on when it is on with
//! any.
//!
//! An option counts as on where a `setopt` turns it on (or an `unsetopt` of
//! its `no` form, or `set -o`), wherever that is, and where any other word
//! outside a comment names it without a `no` prefix: in an array, a string,
//! an alias or a test. It counts as off again only where an `unsetopt` turns
//! it off (or a `setopt` of its `no` form, or `set +o`) unconditionally at the
//! top level of a file zsh certainly reads: the one file of its stage that zsh
//! can read (not one of both in `/etc` and in `/etc/zsh`, nor one of several
//! `ZDOTDIR`s), not in a condition, a function (an anonymous one
//! included), a subshell, a pipeline or the background (a group or loop
//! followed by `&` or `|` too), not after `&&` or `||`, not in a loop over
//! something the check cannot list, not after a `return` or `exit` in the
//! file, and not in a `zprofile` or `zlogin` of a shell that may not be a
//! login shell. A turn-off anywhere else counts as a mention, which turns the
//! option on, and so does a word in a here-document's body, which is text, not
//! code. A loop over a list the check can read, as Home Manager writes
//! `for opt in "${set_opts[@]}"; do setopt "$opt"; done` after a literal
//! `set_opts=(...)`, is read item by item. A `setopt` with an expansion it
//! cannot list, a `source` without a path or with one it cannot resolve (a
//! process substitution among them), a `ZDOTDIR` it cannot follow, one set
//! otherwise than by an assignment (`${ZDOTDIR:=...}`), a quote, an
//! expansion or a here-document that runs to the end of the file without
//! closing, and an expansion that holds what the check cannot read as zsh
//! does (a `case` in a `$(...)`, a `${ command }`) are doubts. A `<<` in an
//! arithmetic command, `(( ... ))`, is a shift, not a here-document, a `)` or
//! `}` in quotes closes no expansion, a `\'` does not end a `$'...'`, and the
//! here-documents and comments of a `$(...)` are read as text, as at the top
//! level. Beside the code, the lines of each file are counted for what they
//! name ([`backstop`]): an option named beyond what the code names counts as
//! on, and a `source`, `.` or `ZDOTDIR` setting beyond what the walk read is
//! a doubt.

mod backstop;
mod lexer;
mod walk;

use super::startup::{Scan, Write, read};
use crate::Filesystem;
use lexer::Word;
#[cfg(test)]
use lexer::{End, Token, tokens};
use std::path::{Path, PathBuf};
use walk::{Event, events};

/// The zsh options that write each command line to the history file as zsh
/// runs: the name as zsh compares it (lower case, without underscores), the
/// name the warning shows, and whether zsh writes a line as it is entered
/// (else once its command ends).
const OPTIONS: [(&str, &str, bool); 3] = [
    ("incappendhistory", "INC_APPEND_HISTORY", true),
    ("sharehistory", "SHARE_HISTORY", true),
    ("incappendhistorytime", "INC_APPEND_HISTORY_TIME", false),
];

/// Oh My Zsh's loader, which turns `SHARE_HISTORY` on (its `lib/history.zsh`).
const OH_MY_ZSH: &str = "oh-my-zsh.sh";

/// How many files deep sourced files are followed.
const SOURCE_DEPTH: usize = 8;

/// What the check knows of how a zsh was started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Start {
    /// Whether it is a login shell, which reads `zprofile` and `zlogin`;
    /// `None` when the check cannot tell.
    pub login: Option<bool>,
    /// Whether it reads every startup file, as it does without `-f` or `-d`.
    pub every_file: bool,
}

impl Start {
    /// How the zsh started as `argv` reads its startup files: a login shell
    /// when `argv[0]` starts with `-` or with `-l` or `--login`, and not every
    /// file with `-f`, `-d`, `--no-rcs` or `--no-global-rcs`.
    pub(super) fn of(argv: &[String]) -> Self {
        let mut start = Self {
            login: Some(argv.first().is_some_and(|zero| zero.starts_with('-'))),
            every_file: true,
        };
        for arg in argv.iter().skip(1).map(String::as_str) {
            if matches!(arg, "-" | "--") || !arg.starts_with(['-', '+']) {
                break;
            }
            if let Some(long) = arg.strip_prefix("--") {
                let long = long.replace(['-', '_'], "").to_lowercase();
                match long.as_str() {
                    "login" => start.login = Some(true),
                    "norcs" | "noglobalrcs" => start.every_file = false,
                    _ => {}
                }
            } else if arg.starts_with('-') {
                start.login = Some(start.login == Some(true) || arg.contains('l'));
                start.every_file &= !arg.contains(['f', 'd']);
            }
        }
        start
    }
}

/// What the zsh startup files read so far set.
struct Reader<'a, F: Filesystem> {
    fs: &'a F,
    /// The home the shell runs with, if it has one.
    home: Option<&'a Path>,
    /// Where each of [`OPTIONS`] was last turned on; `None` while off.
    options: [Option<String>; 3],
    /// The directories the user's own startup files may be in; empty once a
    /// file set `ZDOTDIR` to something the check cannot follow.
    zdotdirs: Vec<PathBuf>,
    /// What `XDG_CONFIG_HOME` may be as the files read so far set it: each
    /// value as written, `None` while unset.
    xdg_config_homes: Vec<Option<String>>,
    /// The files being followed, outermost first.
    stack: Vec<PathBuf>,
    scan: Scan,
}

impl<F: Filesystem> Reader<'_, F> {
    /// The paths `value` may name: one for each value `XDG_CONFIG_HOME` may
    /// have, each different one once; `None` when one of them is no path the
    /// check can know.
    fn resolve(&self, value: &Word) -> Option<Vec<PathBuf>> {
        let mut paths = Vec::new();
        for config in &self.xdg_config_homes {
            let path = self.resolve_in(value, config.as_deref())?;
            if !paths.contains(&path) {
                paths.push(path);
            }
        }
        (!paths.is_empty()).then_some(paths)
    }

    /// The path `value` names with `XDG_CONFIG_HOME` set to `config` as
    /// written, or unset: with `~`, `$HOME`, `$ZDOTDIR`, `$XDG_CONFIG_HOME`
    /// and their `${...:-...}` defaults in it; `None` when it names anything
    /// else the check cannot know, or no absolute path.
    fn resolve_in(&self, value: &Word, config: Option<&str>) -> Option<PathBuf> {
        let home = self.home?.to_string_lossy().into_owned();
        let default_config = format!("{home}/.config");
        let config = config.map(str::to_string);
        let zdotdir = match self.zdotdirs.as_slice() {
            [one] => Some(one.to_string_lossy().into_owned()),
            _ => None,
        };
        let mut text = value.text.clone();
        if value.expands {
            for (pattern, with) in [
                (
                    "${XDG_CONFIG_HOME:-$HOME/.config}",
                    config.clone().or(Some(default_config.clone())),
                ),
                (
                    "${XDG_CONFIG_HOME:-${HOME}/.config}",
                    config.clone().or(Some(default_config.clone())),
                ),
                (
                    "${XDG_CONFIG_HOME:-~/.config}",
                    config.clone().or(Some(default_config)),
                ),
                ("${ZDOTDIR:-$HOME}", zdotdir.clone()),
                ("${ZDOTDIR:-${HOME}}", zdotdir.clone()),
                ("${ZDOTDIR:-~}", zdotdir.clone()),
                ("${XDG_CONFIG_HOME}", config.clone()),
                ("$XDG_CONFIG_HOME", config),
                ("${ZDOTDIR}", zdotdir.clone()),
                ("$ZDOTDIR", zdotdir),
                ("${HOME}", Some(home.clone())),
                ("$HOME", Some(home.clone())),
            ] {
                if text.contains(pattern) {
                    text = text.replace(pattern, &with?);
                }
            }
        }
        if text == "~" || text.starts_with("~/") {
            text = format!("{home}{}", &text[1..]);
        }
        let path = PathBuf::from(text);
        let plain = !path.to_string_lossy().contains(['$', '`', '~']);
        (plain && path.is_absolute()).then_some(path)
    }

    /// Read the startup file at `path` and follow what it sets; `certain`
    /// when zsh certainly runs it whole.
    fn file(&mut self, path: &Path, certain: bool) {
        if self.stack.iter().any(|open| open == path) {
            return;
        }
        let text = match read(self.fs, path) {
            Ok(Some(text)) => text,
            Ok(None) => return,
            Err(why) => {
                self.scan.doubts.push(format!("it could not read {why}"));
                return;
            }
        };
        if self.stack.len() >= SOURCE_DEPTH {
            self.scan.doubts.push(format!(
                "it follows sourced files {SOURCE_DEPTH} deep, not on to {}",
                path.display()
            ));
            return;
        }
        let place = path.to_string_lossy().into_owned();
        let (events, confused) = events(&text, &place);
        self.stack.push(path.to_path_buf());
        for event in events {
            self.apply(event, &place, certain && !confused);
        }
        self.stack.pop();
    }

    /// Apply one event of the file at `place`; `certain` when zsh certainly
    /// runs the file whole and the check followed its structure.
    fn apply(&mut self, event: Event, place: &str, certain: bool) {
        match event {
            Event::Set {
                option,
                on: false,
                unconditional: true,
            } if certain => self.options[option] = None,
            Event::Set { option, .. } | Event::Mention(option) => {
                self.options[option] = Some(place.to_string());
            }
            Event::Unread(option) => {
                self.options[option] = Some(format!(
                    "a line of {place} that the check cannot read as code"
                ));
            }
            Event::OhMyZsh => {
                self.options[1] = Some(format!("Oh My Zsh, which {place} loads,"));
            }
            Event::Doubt(doubt) => self.scan.doubts.push(doubt),
            Event::Source {
                path,
                unconditional,
            } => match self.resolve(&path) {
                Some(files) => {
                    let one = files.len() == 1;
                    for file in files {
                        self.file(&file, certain && unconditional && one);
                    }
                }
                None => self.scan.doubts.push(format!(
                    "it cannot follow the file {place} sources as `{}`",
                    path.text
                )),
            },
            Event::Assign {
                name,
                value,
                unconditional,
            } => {
                if name == "XDG_CONFIG_HOME" {
                    let config = Some(value.text);
                    if certain && unconditional {
                        self.xdg_config_homes = vec![config];
                    } else if !self.xdg_config_homes.contains(&config) {
                        self.xdg_config_homes.push(config);
                    }
                    return;
                }
                match self.resolve(&value) {
                    Some(dirs) if certain && unconditional => self.zdotdirs = dirs,
                    Some(dirs) => {
                        for dir in dirs {
                            if !self.zdotdirs.contains(&dir) {
                                self.zdotdirs.push(dir);
                            }
                        }
                    }
                    None => {
                        if certain && unconditional {
                            // zsh reads the user's files somewhere else now.
                            self.zdotdirs.clear();
                        }
                        self.scan.doubts.push(format!(
                            "it cannot follow the ZDOTDIR that {place} sets (`{}`)",
                            value.text
                        ));
                    }
                }
            }
        }
    }
}

/// What zsh's startup files below `/etc` and in `homes` turn on, read
/// through `fs`, for a zsh started as `start` says. A zsh runs with one home,
/// where it reads the user's files and which `~` and `$HOME` name, so the
/// files are read for each of `homes` the shell may run with, and an option
/// counts as on when it is on with any of them.
pub(super) fn zsh<F: Filesystem>(fs: &F, homes: &[PathBuf], start: Start) -> Scan {
    let homes: Vec<Option<&Path>> = if homes.is_empty() {
        vec![None]
    } else {
        homes.iter().map(|home| Some(home.as_path())).collect()
    };
    let mut scan = Scan::default();
    for home in homes {
        let one = in_home(fs, home, start);
        for write in one.writes {
            if !scan.writes.contains(&write) {
                scan.writes.push(write);
            }
        }
        for doubt in one.doubts {
            if !scan.doubts.contains(&doubt) {
                scan.doubts.push(doubt);
            }
        }
    }
    scan
}

/// What zsh's startup files below `/etc` and in `home` turn on, for a zsh
/// that runs with `home`.
fn in_home<F: Filesystem>(fs: &F, home: Option<&Path>, start: Start) -> Scan {
    let mut reader = Reader {
        fs,
        home,
        options: Default::default(),
        zdotdirs: home.map(Path::to_path_buf).into_iter().collect(),
        xdg_config_homes: vec![None],
        stack: Vec::new(),
        scan: Scan::default(),
    };
    for stage in ["zshenv", "zprofile", "zshrc", "zlogin"] {
        let login_stage = matches!(stage, "zprofile" | "zlogin");
        if login_stage && start.login == Some(false) {
            continue;
        }
        // Read whole only by a zsh that certainly reads it, and a file only
        // when it is the one zsh can read for this stage: a zsh reads its
        // stage's file in /etc or in /etc/zsh, as it was built, and the
        // user's in one ZDOTDIR.
        let certain = start.every_file && (!login_stage || start.login == Some(true));
        let system = ["/etc", "/etc/zsh"].map(|dir| Path::new(dir).join(stage));
        let present = system
            .iter()
            .filter(|path| !matches!(fs.inode(path), Ok(None)))
            .count();
        for path in &system {
            reader.file(path, certain && present == 1);
        }
        // The user's own, from where the files read so far put ZDOTDIR.
        let dirs = reader.zdotdirs.clone();
        for dir in &dirs {
            reader.file(&dir.join(format!(".{stage}")), certain && dirs.len() == 1);
        }
    }
    let mut scan = reader.scan;
    for ((_, shown, entered), place) in OPTIONS.iter().zip(reader.options) {
        if let Some(place) = place {
            scan.writes.push(Write {
                what: format!("{place} sets {shown}"),
                entered: *entered,
            });
        }
    }
    scan
}

#[cfg(test)]
#[path = "zsh_tests.rs"]
mod tests;
