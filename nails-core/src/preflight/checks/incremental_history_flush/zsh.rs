// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Whether zsh's startup files name the options that write each command
//! line to the history file as zsh runs, or hold an `fc` that writes it,
//! read in zsh's order and failing closed on what the check cannot follow.
//!
//! zsh reads `zshenv`, then `zprofile` for a login shell, `zshrc` for an
//! interactive one and `zlogin` for a login shell: each stage's file in `/etc`
//! or in `/etc/zsh` (where Debian's and Arch's zsh look), then the user's own
//! in `$ZDOTDIR`, which is the home unless a file read so far sets it. A zsh
//! started with `-f` reads `/etc/zshenv` alone, and one started with `-d` no
//! other file in `/etc` ([`Start`]), unless a file read so far names `RCS` or
//! `GLOBAL_RCS`, which may turn them on again ([`backstop::names_rcs`]). The
//! options its command line turns on count too ([`CommandLine`]). A file that a
//! startup file sources is read where it is sourced, when its path resolves. A
//! zsh runs with one home, which `~` and `$HOME` name, so for a shell that may
//! run with several (a root shell with the operator's), the files are read for
//! each.
//!
//! A function the files autoload is read from its file: the one they name by
//! its path, or the one of its name in each directory they add to `fpath`
//! and in those `fpath` starts with when the check knows them ([`Install`]),
//! where zsh looks for it as it first runs it. Once one is autoloaded, a
//! directory added that the check cannot follow is a doubt, and, where it does
//! not know where `fpath` starts, so is a function that no directory put in
//! front of `fpath` holds, which zsh then finds in a directory it was built
//! with or one `FPATH` names. A stock function of zsh's own is read for what
//! its code does ([`stock`]): `compinit` and `promptinit` mark functions that
//! zsh runs only when they are run by name, as hooks or, for completion
//! functions, as a word is completed, which the check reads where the files
//! run them. zsh runs compiled code in place of a file, or of a
//! directory's functions, when a `.zwc` is beside it, and the check cannot read
//! that code, so such a `.zwc` is a doubt, and so is a path zsh expands into
//! others (a glob, `{a,b}`).
//!
//! An option counts as on wherever a file zsh reads names it, outside a line
//! that is a comment, in either form: a `setopt` or an `unsetopt`, an array, a
//! string, an alias, a test, a here-document's body or a comment at the end of
//! a line, as brace expansion may make the word, and after an `o` among flags
//! (`set -oshare_history`). An `fc` with a flag that writes the history file
//! (`-A`, `-W`, `-P`) counts as such a write wherever it stands, as a hook may
//! run it after every command, and so does a redirection to the history file
//! and, in a hook, a word that names it, while a redirection there whose target
//! an expansion makes is a doubt. An `emulate -R ksh` turns `SHARE_HISTORY` on,
//! as ksh's defaults hold it. No turn-off counts: zsh can end with the option
//! on after one, through a redefined `unsetopt`, a trap or a hook, a plugin
//! loaded later or an error that stops the file before the line, and no reading
//! of the files shows that it holds. A `setopt` with an expansion the check
//! cannot list, an option whose name an expansion makes (`options[$o]=on`,
//! `emulate -o $o`, `read -A options`, a `typeset` of a parameter whose name
//! does), a glob qualifier that runs code (`*(e:...:)`, `*(+func)`), an
//! expansion that reads a parameter's value again (`${(e)x}`, `${~x}`,
//! `GLOB_SUBST`), code in a string zsh runs that an expansion makes (an alias's
//! value, a trap's, a `sched`'s, a `zstyle -e`'s, a prompt's where
//! `PROMPT_SUBST` may be on), an alias that hands the words it is used with to
//! a command that reads them as code, options, names or paths
//! (`alias so=setopt`), a `source` without a path or with one it cannot resolve
//! (a process substitution among them), a `ZDOTDIR` it cannot follow, one set
//! otherwise than by an assignment (`${ZDOTDIR:=...}`), a quote, an expansion
//! or a here-document that runs to the end of the file without closing, and an
//! expansion that holds what the check cannot read as zsh does (a `case` in a
//! `$(...)`, a `${ command }`) are doubts. Beside the code, the lines of each
//! file are counted for what they name ([`backstop`]): an option named beyond
//! what the code names counts as on, an `fpath` setting beyond what the walk
//! read adds a directory the check cannot follow, and a `source`, `.`, `eval`,
//! `autoload`, `fc` or `ZDOTDIR` setting beyond that is a doubt. The structure
//! of the code still decides which `ZDOTDIR` zsh reads its files in.

mod backstop;
mod dump;
mod install;
mod lexer;
mod stock;
mod walk;

use super::startup::{Scan, Write, read};
use crate::Filesystem;
pub(super) use install::{ENVIRONMENT, Install};
use install::{known_lines, plain_profile};
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

/// What makes zsh expand a path into others: a glob, a qualifier or brace
/// expansion.
const GLOB: [char; 9] = ['*', '?', '[', '<', '(', '|', '{', '^', '#'];

/// What the check knows of how a zsh was started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Start {
    /// Whether it is a login shell, which reads `zprofile` and `zlogin`;
    /// `None` when the check cannot tell.
    pub login: Option<bool>,
    /// Whether it reads more than `zshenv` in `/etc`, as it does without
    /// `-f` (zsh's `RCS` option).
    pub rcs: bool,
    /// Whether it reads the files in `/etc` other than `zshenv`, as it does
    /// without `-d` (zsh's `GLOBAL_RCS` option).
    pub global_rcs: bool,
}

impl Start {
    /// How the zsh started as `argv` reads its startup files
    /// ([`CommandLine::of`]).
    pub(super) fn of(argv: &[String]) -> Self {
        CommandLine::of(argv).start
    }
}

/// What the command line of a zsh tells: how it reads its startup files,
/// which of [`OPTIONS`] it turns on, and what the check cannot tell of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CommandLine {
    pub start: Start,
    /// For each of [`OPTIONS`], whether the command line turns it on, as the
    /// last word that names it says; `None` when none does.
    pub on: [Option<bool>; 3],
    /// What the check cannot tell of it, each as a clause of the warning.
    pub doubts: Vec<String>,
    /// Whether it turns `PROMPT_SUBST` on, which makes zsh run what a prompt
    /// holds as it shows it.
    pub prompt_subst: bool,
}

impl CommandLine {
    /// What the command line `argv` of a zsh tells, read as zsh reads it: a
    /// login shell when `argv[0]` starts with `-` or with `-l`, `--login` or
    /// `-o login`; only `/etc/zshenv` with `-f`, `--no-rcs`, `-o norcs` or
    /// `+o rcs`; none of the other files in `/etc` with `-d`,
    /// `--no-global-rcs`, `-o noglobalrcs` or `+o globalrcs`; an option by
    /// `-o name`, `+o name`, `-oname`, `-xo name`, `--long-name` or
    /// `+-long-name`. A zsh that emulates sh or ksh, as it does when the name
    /// it runs under starts with `s` or `k` (past a `-` and an `r`) or with
    /// `--emulate sh`, reads other startup files, which is a doubt, and so is
    /// an `-o` that names no option.
    pub(super) fn of(argv: &[String]) -> Self {
        let mut line = Self {
            start: Start {
                login: Some(argv.first().is_some_and(|zero| zero.starts_with('-'))),
                rcs: true,
                global_rcs: true,
            },
            on: [None; 3],
            doubts: Vec::new(),
            prompt_subst: false,
        };
        if let Some(zero) = argv.first() {
            let name = Path::new(zero)
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            let name = name.trim_start_matches('-');
            if name
                .strip_prefix('r')
                .unwrap_or(name)
                .starts_with(['s', 'k'])
            {
                line.emulated(zero);
            }
        }
        let mut args = argv.iter().skip(1).map(String::as_str);
        while let Some(arg) = args.next() {
            if matches!(arg, "-" | "--") || !arg.starts_with(['-', '+']) {
                break;
            }
            if let Some(mode) = arg.strip_prefix("--emulate") {
                let mode = match mode.strip_prefix('=') {
                    Some(mode) => Some(mode),
                    None if mode.is_empty() => args.next(),
                    None => None,
                };
                if mode != Some("zsh") {
                    line.emulated(arg);
                }
            } else if let Some(long) = arg.strip_prefix("--") {
                line.option(long, true);
            } else if let Some(long) = arg.strip_prefix("+-") {
                line.option(long, false);
            } else {
                let on = arg.starts_with('-');
                for (at, flag) in arg.char_indices().skip(1) {
                    match flag {
                        'l' => line.start.login = Some(on),
                        'f' => line.start.rcs = !on,
                        'd' => line.start.global_rcs = !on,
                        'o' => {
                            let rest = &arg[at + 1..];
                            match if rest.is_empty() {
                                args.next()
                            } else {
                                Some(rest)
                            } {
                                Some(name) => line.option(name, on),
                                None => line.doubts.push(format!(
                                    "it cannot tell what `{arg}` on its command line turns on"
                                )),
                            }
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }
        line
    }

    /// Note that the zsh emulates sh or ksh, as `word` on its command line
    /// makes it.
    fn emulated(&mut self, word: &str) {
        self.doubts.push(format!(
            "it cannot tell what a zsh started with `{word}` on its command line reads, as zsh \
             then emulates sh or ksh and reads their startup files"
        ));
    }

    /// Set the option `name` (`no_rcs`, `GLOBAL_RCS`, `share-history`, ...)
    /// on, or off.
    fn option(&mut self, name: &str, on: bool) {
        let name = name.replace(['-', '_'], "").to_lowercase();
        let known = |name: &str| {
            matches!(name, "rcs" | "globalrcs" | "login") || walk::option(name).is_some()
        };
        let (name, on) = match name.strip_prefix("no") {
            Some(rest) if known(rest) => (rest.to_string(), !on),
            _ => (name, on),
        };
        match name.as_str() {
            "login" => self.start.login = Some(on),
            "rcs" => self.start.rcs = on,
            "globalrcs" => self.start.global_rcs = on,
            "promptsubst" => self.prompt_subst |= on,
            "globsubst" if on => self.doubts.push(
                "it cannot tell what code zsh runs from the values it expands as patterns, as its \
                 command line turns GLOB_SUBST on, which makes a glob qualifier in a value run"
                    .to_string(),
            ),
            other => {
                if let Some((at, true)) = walk::option(other) {
                    self.on[at] = Some(on);
                }
            }
        }
    }

    /// What the command line turns on that writes each command line as zsh
    /// runs.
    pub(super) fn writes(&self) -> Vec<Write> {
        OPTIONS
            .iter()
            .zip(self.on)
            .filter(|(_, on)| *on == Some(true))
            .map(|((_, shown, entered), _)| Write {
                what: format!("its command line turns on {shown}"),
                entered: *entered,
                option: false,
            })
            .collect()
    }
}

/// What the zsh startup files read so far set.
struct Reader<'a, F: Filesystem> {
    fs: &'a F,
    /// The home the shell runs with, if it has one.
    home: Option<&'a Path>,
    /// For each of [`OPTIONS`], what last named it, as the warning tells it
    /// (`/etc/zshrc names`); `None` while nothing has.
    options: [Option<String>; 3],
    /// The directories the user's own startup files may be in; empty once a
    /// file set `ZDOTDIR` to something the check cannot follow.
    zdotdirs: Vec<PathBuf>,
    /// What `XDG_CONFIG_HOME` may be as the files read so far set it: each
    /// value as written, `None` while unset.
    xdg_config_homes: Vec<Option<String>>,
    /// The files being followed, outermost first.
    stack: Vec<PathBuf>,
    /// The directories the files read add to `fpath`, and whether zsh looks
    /// in one before the directories it was built with ([`Event::Fpath`]),
    /// or the doubt that one the check cannot follow is, should they
    /// autoload a function.
    fpath: Vec<Result<(PathBuf, bool), String>>,
    /// The functions the files read autoload by name.
    autoloads: Vec<String>,
    /// What writes the history file otherwise than the options, as the
    /// warning names it (`/etc/zshrc names \`fc -AI\``).
    fc: Vec<String>,
    /// The functions the files make hooks ([`Event::Hook`]).
    hooks: Vec<String>,
    /// What writes the history file or may, should the function it is in be
    /// a hook: the function, and the write or the doubt it is then.
    in_functions: Vec<(String, Result<String, String>)>,
    /// What the check could not follow.
    doubts: Vec<String>,
    /// Whether a file read may turn `RCS` or `GLOBAL_RCS` on again
    /// ([`backstop::names_rcs`]).
    rcs: bool,
    /// Whether a file read may turn `PROMPT_SUBST` on
    /// ([`backstop::names_prompt_subst`]).
    prompt_subst: bool,
    /// The doubts of the prompts that hold code zsh runs as it shows them
    /// when `PROMPT_SUBST` is on ([`Event::Prompt`]).
    prompts: Vec<String>,
    /// What the check knows of the zsh program and its environment.
    install: &'a Install,
    /// The Nix profiles `NIX_PROFILES` may name, as the environment and the
    /// files read set it; `None` when the check cannot tell.
    profiles: Option<Vec<String>>,
    /// The directories added under each Nix profile
    /// ([`Event::ProfileFpath`]): as written, past the profile, whether in
    /// front, and where.
    profile_fpath: Vec<(String, String, bool, String)>,
    /// Where a file read may set `TTY` ([`backstop::names_tty_write`]).
    tty_set: Option<String>,
    /// Where a file read as code names `_compdir`, which picks the
    /// directory whose own the stock `compaudit` may put in `fpath`.
    compdir: Option<String>,
    /// Whether a file read may set `ZSH_VERSION`.
    version_set: bool,
    /// Whether a file read may set `HOME`, `USER` or `XDG_STATE_HOME`,
    /// with which NixOS's `set-environment` writes `NIX_PROFILES`.
    profile_vars_set: bool,
    /// The functions the files autoload without `-U`
    /// ([`Event::Expanding`]).
    expanding: Vec<String>,
    /// The functions that redirect output to `$TTY`, and where: the
    /// terminal, while no file sets `TTY`.
    terminals: Vec<(String, String)>,
    /// The aliases that stand for an `fc` that writes nothing
    /// ([`Event::FcAlias`]): their names, as written, and where.
    fc_aliases: Vec<(String, String, String)>,
    /// The text of each file read, for the names its lines use.
    texts: Vec<String>,
    /// The commands the files run by name ([`Event::Call`]), and where.
    calls: Vec<(String, Vec<Word>, String)>,
    /// The stock functions of zsh's own the files autoload ([`Stock`]):
    /// `compinit`, `compaudit` and `promptinit`.
    compinit: bool,
    compaudit: bool,
    promptinit: bool,
    /// The completion functions a dump file marks to be autoloaded.
    dump_marks: Vec<String>,
    /// The dump files read, and the directories `compaudit` was looked at
    /// for.
    dumps: Vec<PathBuf>,
    audited: Vec<PathBuf>,
}

impl<F: Filesystem> Reader<'_, F> {
    /// Note a doubt, once.
    fn doubt(&mut self, text: String) {
        if !self.doubts.contains(&text) {
            self.doubts.push(text);
        }
    }

    /// Note a doubt when zsh may run compiled code at `path`, which the
    /// check cannot read: zsh runs a file's `.zwc` in its place when it is
    /// newer or the file is missing, and an `fpath` directory's when it holds
    /// the function.
    fn compiled(&mut self, path: &Path) {
        match self.fs.inode(path) {
            Ok(None) => {}
            Ok(Some(_)) => self.doubt(format!(
                "it cannot read the compiled code in {} that zsh may run",
                path.display()
            )),
            Err(error) => self.doubt(format!(
                "it could not read {} ({})",
                path.display(),
                error
                    .io_kind()
                    .map_or_else(|| error.to_string(), |kind| kind.to_string())
            )),
        }
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
        let plain = !text.contains(['$', '`', '~']) && !text.contains(GLOB);
        let path = PathBuf::from(text);
        (plain && path.is_absolute()).then_some(path)
    }

    /// The text of the file at `path`, unless it is being followed already,
    /// nothing is there, or the check cannot read it, which is a doubt; zsh
    /// may run compiled code in its place, which is a doubt too.
    fn text(&mut self, path: &Path) -> Option<String> {
        if self.stack.iter().any(|open| open == path) {
            return None;
        }
        self.compiled(&zwc(path));
        let text = match read(self.fs, path) {
            Ok(Some(text)) => text,
            Ok(None) => return None,
            Err(why) => {
                self.doubt(format!("it could not read {why}"));
                return None;
            }
        };
        if self.stack.len() >= SOURCE_DEPTH {
            self.doubt(format!(
                "it follows sourced files {SOURCE_DEPTH} deep, not on to {}",
                path.display()
            ));
            return None;
        }
        Some(text)
    }

    /// Note what the lines of `text`, the file at `place`, may set that the
    /// check reads beside its code: `TTY`, `ZSH_VERSION`, the names the
    /// files use.
    fn lines(&mut self, text: &str, place: &str) {
        if self.tty_set.is_none() && backstop::names_tty_write(text) {
            self.tty_set = Some(place.to_string());
        }
        self.version_set |= backstop::names_write(text, "ZSH_VERSION");
        // What NixOS's set-environment writes NIX_PROFILES with.
        self.profile_vars_set |= ["HOME", "USER", "XDG_STATE_HOME"]
            .iter()
            .any(|name| backstop::names_write(text, name));
        self.texts.push(text.to_string());
    }

    /// Read the startup file at `path` and follow what it sets; `certain`
    /// when zsh certainly runs it whole.
    fn file(&mut self, path: &Path, certain: bool) {
        if let Some(text) = self.text(path) {
            self.code(path, &text, certain);
        }
    }

    /// Follow what `text`, the code of the file at `path`, sets; `certain`
    /// when zsh certainly runs it whole.
    fn code(&mut self, path: &Path, text: &str, certain: bool) {
        let text = known_lines(path, text);
        let text = text.as_ref();
        self.rcs |= backstop::names_rcs(text);
        self.prompt_subst |= backstop::names_prompt_subst(text);
        let place = path.to_string_lossy().into_owned();
        self.lines(text, &place);
        if self.compdir.is_none() && backstop::uses(text, "_compdir") > 0 {
            self.compdir = Some(place.clone());
        }
        if backstop::names_any(text, &["globsubst"]) {
            self.doubt(format!(
                "it cannot tell what code zsh runs from the values it expands as patterns, as \
                 {place} names GLOB_SUBST, which makes a glob qualifier in a value run"
            ));
        }
        let read = events(text, &place);
        self.stack.push(path.to_path_buf());
        for event in read.events {
            self.apply(event, &place, certain && !read.confused);
        }
        self.stack.pop();
    }

    /// Mark the function `name` to be read as one the files autoload.
    fn autoload_name(&mut self, name: &str) {
        if !self.autoloads.iter().any(|known| known == name) {
            self.autoloads.push(name.to_string());
        }
    }

    /// Apply one event of the file at `place`; `certain` when zsh certainly
    /// runs the file whole and the check followed its structure.
    fn apply(&mut self, event: Event, place: &str, certain: bool) {
        match event {
            // A turn-off names the option as much as a turn-on: no reading
            // of the files can show that it holds.
            Event::Set { option, .. } | Event::Mention(option) | Event::Unread(option) => {
                self.options[option] = Some(format!("{place} names"));
            }
            Event::OhMyZsh => {
                self.options[1] = Some(format!("Oh My Zsh, which {place} loads, sets"));
            }
            Event::Doubt(doubt) => self.doubt(doubt),
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
                None => self.doubt(format!(
                    "it cannot follow the file {place} sources as `{}`",
                    path.text
                )),
            },
            Event::Assign {
                name: "NIX_PROFILES",
                value,
                ..
            } => self.nix_profiles(&value),
            Event::ProfilesUnknown => self.profiles = None,
            Event::Expanding(name) => {
                if !self.expanding.contains(&name) {
                    self.expanding.push(name);
                }
            }
            Event::ProfileFpath {
                written,
                rest,
                first,
            } => self
                .profile_fpath
                .push((written, rest, first, place.to_string())),
            Event::FcAlias { name, text } => {
                self.fc_aliases.push((name, text, place.to_string()));
            }
            Event::Call { name, args } => self.calls.push((name, args, place.to_string())),
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
                        self.doubt(format!(
                            "it cannot follow the ZDOTDIR that {place} sets (`{}`)",
                            value.text
                        ));
                    }
                }
            }
            Event::Fpath {
                dir: Some(dir),
                first,
            } => match self.resolve(&dir) {
                Some(dirs) => {
                    for dir in dirs {
                        let entry = Ok((dir, first));
                        if !self.fpath.contains(&entry) {
                            self.fpath.push(entry);
                        }
                    }
                }
                None => self.fpath.push(Err(format!(
                    "it cannot follow the directory that {place} adds to fpath as `{}`, where \
                     zsh looks for the functions the files autoload",
                    dir.text
                ))),
            },
            Event::Fpath { dir: None, .. } => self.fpath.push(Err(format!(
                "it cannot follow what a line of {place} may add to fpath, where zsh looks \
                 for the functions the files autoload"
            ))),
            Event::Autoload(function) => self.autoload(function, place),
            Event::Fc(command) => {
                let what = format!("{place} names `{command}`");
                if !self.fc.contains(&what) {
                    self.fc.push(what);
                }
            }
            Event::Prompt(doubt) => {
                if !self.prompts.contains(&doubt) {
                    self.prompts.push(doubt);
                }
            }
            Event::Turns { option, what } => self.options[option] = Some(what),
            Event::Redirect {
                target,
                function,
                computed,
            } => {
                if backstop::history_path(&target) {
                    let what = format!("{place} redirects output to `{target}`");
                    if !self.fc.contains(&what) {
                        self.fc.push(what);
                    }
                } else if computed && let Some(function) = function {
                    if matches!(target.as_str(), "$TTY" | "${TTY}") {
                        // The terminal zsh runs on, unless code sets TTY.
                        self.terminals.push((function, place.to_string()));
                        return;
                    }
                    let doubt = format!(
                        "it cannot tell where the output that `{function}` in {place} \
                         redirects to `{target}` goes, which may be the history file"
                    );
                    self.in_functions.push((function, Err(doubt)));
                }
            }
            Event::Names { word, function } => {
                let what = format!("{place} names `{word}` in `{function}`");
                self.in_functions.push((function, Ok(what)));
            }
            Event::Hook(name) => {
                if !self.hooks.contains(&name) {
                    self.hooks.push(name);
                }
            }
        }
    }

    /// Note the function `function` that the file at `place` autoloads: by
    /// name, to be looked for where the files add to `fpath`, or by the path
    /// of its file, which is read at once.
    fn autoload(&mut self, function: Word, place: &str) {
        if function.text.contains('/') {
            match self.resolve(&function) {
                Some(files) => {
                    for file in files {
                        self.file(&file, false);
                    }
                }
                None => self.doubt(format!(
                    "it cannot follow the function file that {place} autoloads as `{}`",
                    function.text
                )),
            }
        } else if function.expands || function.text.contains(GLOB) {
            self.doubt(format!(
                "it cannot tell which function `{}` in {place} autoloads",
                function.text
            ));
        } else if !self.autoloads.contains(&function.text) {
            self.autoloads.push(function.text);
        }
    }

    /// Read the files of the functions the files read autoload by name in
    /// each directory they add to `fpath`, where zsh looks for them as they
    /// first run, and in those zsh's `fpath` starts with when the check
    /// knows them ([`Install::fpath`]), until those files add no more, and
    /// what the stock functions among them read and mark
    /// ([`Reader::marked`]). Once a function is autoloaded, a directory the
    /// check cannot follow is a doubt. When the check does not know where
    /// zsh's `fpath` starts, so is a function that no directory zsh looks in
    /// first holds: zsh then finds it in a directory the files do not add,
    /// one it was built with or one `FPATH` names in its environment.
    fn autoloaded(&mut self) {
        let mut looked: Vec<PathBuf> = Vec::new();
        let mut digests: Vec<PathBuf> = Vec::new();
        let mut found: Vec<String> = Vec::new();
        loop {
            let before = (looked.len(), self.autoloads.len(), self.fpath.len());
            self.profile_dirs();
            self.marked();
            self.audit();
            for entry in self.fpath.clone() {
                let (dir, first) = match entry {
                    Ok(entry) => entry,
                    Err(doubt) => {
                        if !self.autoloads.is_empty() && !self.doubts.contains(&doubt) {
                            self.doubt(doubt);
                        }
                        continue;
                    }
                };
                for name in self.autoloads.clone() {
                    let path = dir.join(&name);
                    if first
                        && !found.contains(&name)
                        && matches!(self.fs.inode(&path), Ok(Some(_)))
                    {
                        found.push(name.clone());
                    }
                    if looked.contains(&path) {
                        continue;
                    }
                    looked.push(path.clone());
                    if !digests.contains(&dir) {
                        digests.push(dir.clone());
                        self.compiled(&zwc(&dir));
                    }
                    self.function(&path, &name);
                }
            }
            if (looked.len(), self.autoloads.len(), self.fpath.len()) == before {
                break;
            }
        }
        if self.install.fpath.is_some() {
            // zsh looks in no directory the check does not read: a function
            // none holds is one zsh cannot load either.
            return;
        }
        let unfound: Vec<String> = self
            .autoloads
            .iter()
            .filter(|name| !found.contains(name))
            .map(|name| format!("`{name}`"))
            .collect();
        if let Some((last, rest)) = unfound.split_last() {
            let names = if rest.is_empty() {
                last.clone()
            } else {
                format!("{} and {last}", rest.join(", "))
            };
            self.doubt(format!(
                "it cannot read the functions the files autoload that no directory they put in \
                 front of fpath holds ({names}), which zsh then finds in one it was built with \
                 or one FPATH names"
            ));
        }
    }
}

/// The path of the compiled form zsh looks for beside `path`: `path.zwc`.
fn zwc(path: &Path) -> PathBuf {
    let mut zwc = path.as_os_str().to_os_string();
    zwc.push(".zwc");
    PathBuf::from(zwc)
}

/// What zsh's startup files below `/etc` and in `homes` turn on, read
/// through `fs`, for a zsh started as `start` says. A zsh runs with one home,
/// where it reads the user's files and which `~` and `$HOME` name, so the
/// files are read for each of `homes` the shell may run with, and an option
/// counts as on when it is on with any of them.
pub(super) fn zsh<F: Filesystem>(
    fs: &F,
    homes: &[PathBuf],
    start: Start,
    install: &Install,
) -> Scan {
    let homes: Vec<Option<&Path>> = if homes.is_empty() {
        vec![None]
    } else {
        homes.iter().map(|home| Some(home.as_path())).collect()
    };
    let mut scan = Scan::default();
    for home in homes {
        let one = in_home(fs, home, start, install);
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
        scan.reopened |= one.reopened;
        for prompt in one.prompts {
            if !scan.prompts.contains(&prompt) {
                scan.prompts.push(prompt);
            }
        }
    }
    scan
}

/// What zsh's startup files below `/etc` and in `home` turn on, for a zsh
/// that runs with `home`.
fn in_home<F: Filesystem>(fs: &F, home: Option<&Path>, start: Start, install: &Install) -> Scan {
    // The profiles the environment names, as `${(z)NIX_PROFILES}` splits
    // them; none the check can tell when the environment holds what zsh
    // splits otherwise.
    let profiles = install.env.as_ref().and_then(|env| {
        let words: Vec<String> = env
            .nix_profiles
            .as_deref()
            .unwrap_or_default()
            .split_whitespace()
            .map(str::to_string)
            .collect();
        words
            .iter()
            .all(|word| plain_profile(word))
            .then_some(words)
    });
    let mut reader = Reader {
        fs,
        home,
        options: Default::default(),
        zdotdirs: home.map(Path::to_path_buf).into_iter().collect(),
        xdg_config_homes: vec![None],
        stack: Vec::new(),
        fpath: install
            .fpath
            .iter()
            .flatten()
            .map(|dir| Ok((dir.clone(), false)))
            .collect(),
        autoloads: Vec::new(),
        fc: Vec::new(),
        hooks: Vec::new(),
        in_functions: Vec::new(),
        doubts: Vec::new(),
        rcs: false,
        prompt_subst: false,
        prompts: Vec::new(),
        install,
        profiles,
        profile_fpath: Vec::new(),
        tty_set: None,
        compdir: None,
        version_set: false,
        profile_vars_set: false,
        expanding: Vec::new(),
        terminals: Vec::new(),
        fc_aliases: Vec::new(),
        texts: Vec::new(),
        calls: Vec::new(),
        compinit: false,
        compaudit: false,
        promptinit: false,
        dump_marks: Vec::new(),
        dumps: Vec::new(),
        audited: Vec::new(),
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
        // Without `RCS`, zsh reads /etc's zshenv and nothing after it;
        // without `GLOBAL_RCS`, no other file in /etc; a file read so far
        // may turn them on again.
        if !(start.rcs || reader.rcs) && stage != "zshenv" {
            break;
        }
        let certain = !login_stage || start.login == Some(true);
        if start.global_rcs || reader.rcs || stage == "zshenv" {
            let system = ["/etc", "/etc/zsh"].map(|dir| Path::new(dir).join(stage));
            let present = system
                .iter()
                .filter(|path| !matches!(fs.inode(path), Ok(None)))
                .count();
            for path in &system {
                reader.file(path, certain && present == 1);
            }
        }
        if !(start.rcs || reader.rcs) {
            break;
        }
        // The user's own, from where the files read so far put ZDOTDIR.
        let dirs = reader.zdotdirs.clone();
        for dir in &dirs {
            reader.file(&dir.join(format!(".{stage}")), certain && dirs.len() == 1);
        }
    }
    reader.autoloaded();
    // A redirection to $TTY writes to the terminal, unless a file sets TTY.
    if let Some(set) = reader.tty_set.clone() {
        for (function, place) in std::mem::take(&mut reader.terminals) {
            let doubt = format!(
                "it cannot tell where the output that `{function}` in {place} redirects to \
                 `$TTY` goes, as {set} may set TTY to name the history file"
            );
            reader.in_functions.push((function, Err(doubt)));
        }
    }
    // An alias for an fc that writes nothing hands it the words it is used
    // with: harmless while no file uses its name but where it is defined.
    let mut aliases = std::mem::take(&mut reader.fc_aliases);
    aliases.sort();
    aliases.dedup();
    for (name, text, place) in &aliases {
        // Each definition names it as often as its own words do; one
        // written twice alike counts once, so the second is a use.
        let defined: usize = aliases
            .iter()
            .filter(|(other, ..)| other == name)
            .map(|(_, text, _)| backstop::uses(text, name))
            .sum();
        let named: usize = reader
            .texts
            .iter()
            .map(|file| backstop::uses(file, name))
            .sum::<usize>();
        if named > defined {
            reader.doubt(format!(
                "it cannot tell what the alias `{text}` in {place} runs where it is used, as zsh \
                 hands the fc it stands for the words after it"
            ));
        }
    }
    // What a function holds counts where zsh runs it as a hook: by its name
    // (`preexec`, `TRAPDEBUG`) or as the files make it one.
    for (function, found) in std::mem::take(&mut reader.in_functions) {
        let hook = walk::HOOKS.contains(&function.as_str())
            || function.starts_with("TRAP")
            || reader.hooks.contains(&function);
        match found {
            Ok(write) if hook && !reader.fc.contains(&write) => reader.fc.push(write),
            Err(doubt) if hook => reader.doubt(doubt),
            _ => {}
        }
    }
    // A prompt's code runs only when PROMPT_SUBST is on; whether a command
    // line turns it on, the check reads beside the files.
    let mut doubts = reader.doubts;
    let mut prompts = Vec::new();
    if reader.prompt_subst {
        doubts.extend(reader.prompts);
    } else {
        prompts = reader.prompts;
    }
    let mut scan = Scan {
        doubts,
        prompts,
        reopened: reader.rcs && !(start.rcs && start.global_rcs),
        ..Scan::default()
    };
    for ((_, shown, entered), named) in OPTIONS.iter().zip(reader.options) {
        if let Some(named) = named {
            scan.writes.push(Write {
                what: format!("{named} {shown}"),
                entered: *entered,
                option: true,
            });
        }
    }
    // A hook may run it as each line is entered (`preexec`).
    scan.writes.extend(reader.fc.into_iter().map(|what| Write {
        what,
        entered: true,
        option: false,
    }));
    scan
}

#[cfg(test)]
#[path = "zsh_tests.rs"]
mod tests;
