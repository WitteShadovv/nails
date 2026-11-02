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
//!
//! A `.zshrc` whose last commands are plain `unsetopt`s that turn all three
//! options off settles every doubt before it, as zsh runs it top to bottom,
//! except one about `ZDOTDIR`, one about code read before `.zshrc`, which may
//! move `ZDOTDIR` and so the `.zshrc` zsh reads, and one about what zsh reads
//! after `.zshrc`; and none at all when a file zsh reads holds what may undo
//! the line or stop zsh before it ([`backstop::blocker`]).

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

/// When zsh reads a startup file, by `.zshrc`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// `zshenv` or `zprofile`, where `ZDOTDIR` can still move.
    Before,
    Rc,
    /// `zlogin`.
    After,
}

/// Where a `.zshrc` ended with a plain `unsetopt` of every option: how many
/// doubts came before it, and the options as it left them.
struct Settle {
    doubts: usize,
    options: [Option<String>; 3],
}

/// What a doubt is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// Code that may do anything.
    Code,
    /// Which options a `setopt` turns on.
    Options,
    Zdotdir,
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
    /// The stage whose files are being read.
    stage: Stage,
    /// The doubts so far, each with whether turning the options off at the
    /// end of `.zshrc` does not settle it.
    doubts: Vec<(String, bool)>,
    /// Where the user's `.zshrc` ended turning every option off.
    settle: Option<Settle>,
    /// What in a file read keeps that from settling the doubts before it.
    blocked: Option<String>,
}

impl<F: Filesystem> Reader<'_, F> {
    /// Note a doubt about `kind`. Turning the options off at the end of
    /// `.zshrc` settles one about the options, and one about code in
    /// `.zshrc`, but none about `ZDOTDIR`, about code before `.zshrc`, which
    /// may move `ZDOTDIR` and so the `.zshrc` zsh reads, or about what zsh
    /// reads after it.
    fn doubt(&mut self, text: String, kind: Kind) {
        let lasting = match kind {
            Kind::Zdotdir => true,
            Kind::Code => self.stage != Stage::Rc,
            Kind::Options => self.stage == Stage::After,
        };
        self.doubts.push((text, lasting));
    }

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
                self.doubt(format!("it could not read {why}"), Kind::Code);
                return;
            }
        };
        if self.stack.len() >= SOURCE_DEPTH {
            self.doubt(
                format!(
                    "it follows sourced files {SOURCE_DEPTH} deep, not on to {}",
                    path.display()
                ),
                Kind::Code,
            );
            return;
        }
        let place = path.to_string_lossy().into_owned();
        let read = events(&text, &place);
        self.stack.push(path.to_path_buf());
        for event in read.events {
            self.apply(event, &place, certain && !read.confused);
        }
        self.stack.pop();
        if self.blocked.is_none() {
            self.blocked = if read.confused || read.flawed {
                Some(format!(
                    "the check cannot follow all of {place}, which may stop before the line runs"
                ))
            } else {
                backstop::blocker(&text, &place)
            };
        }
        if certain
            && !read.confused
            && read.ends_off
            && self.stage == Stage::Rc
            && self.stack.is_empty()
            && path.file_name().is_some_and(|name| name == ".zshrc")
        {
            // zsh runs a file top to bottom: whatever came before, the
            // options are off once its last commands ran, unless something
            // [`Reader::blocked`] names keeps them from it.
            self.settle = Some(Settle {
                doubts: self.doubts.len(),
                options: self.options.clone(),
            });
        }
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
            Event::Doubt(doubt) => self.doubt(doubt, Kind::Code),
            Event::OptionDoubt(doubt) => self.doubt(doubt, Kind::Options),
            Event::ZdotdirDoubt(doubt) => self.doubt(doubt, Kind::Zdotdir),
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
                None => self.doubt(
                    format!(
                        "it cannot follow the file {place} sources as `{}`",
                        path.text
                    ),
                    Kind::Code,
                ),
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
                        self.doubt(
                            format!(
                                "it cannot follow the ZDOTDIR that {place} sets (`{}`)",
                                value.text
                            ),
                            Kind::Zdotdir,
                        );
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
        scan.lasting |= one.lasting;
        if scan.blocked.is_none() {
            scan.blocked = one.blocked;
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
        stage: Stage::Before,
        doubts: Vec::new(),
        settle: None,
        blocked: None,
    };
    for stage in ["zshenv", "zprofile", "zshrc", "zlogin"] {
        let login_stage = matches!(stage, "zprofile" | "zlogin");
        if login_stage && start.login == Some(false) {
            continue;
        }
        reader.stage = match stage {
            "zshrc" => Stage::Rc,
            "zlogin" => Stage::After,
            _ => Stage::Before,
        };
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
    if let Some(settle) = reader.settle.take()
        && reader.blocked.is_none()
    {
        // Every doubt before the line is settled but one it cannot settle,
        // and an option on there is off.
        let mut at = 0;
        reader.doubts.retain(|(_, lasting)| {
            at += 1;
            *lasting || at > settle.doubts
        });
        for (option, then) in reader.options.iter_mut().zip(settle.options) {
            if then.is_some() && *option == then {
                *option = None;
            }
        }
    }
    let mut scan = Scan {
        lasting: reader.doubts.iter().any(|(_, lasting)| *lasting),
        blocked: if reader.doubts.is_empty() {
            None
        } else {
            reader.blocked
        },
        doubts: reader.doubts.into_iter().map(|(doubt, _)| doubt).collect(),
        ..Scan::default()
    };
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
