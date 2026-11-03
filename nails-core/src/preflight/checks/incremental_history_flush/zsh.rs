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
//! with or one `FPATH` names; an element of `fpath` that is empty, or that
//! `SH_WORD_SPLIT` or `KSH_ARRAYS` may change, is one the check cannot follow.
//! A stock function of zsh's own is read for what
//! its code does ([`stock`]): `compinit` and `promptinit` mark functions that
//! zsh runs only when they are run by name, as hooks or, for completion
//! functions, as a word is completed, which the check reads where the files
//! run them. NixOS's dircolors line in `/etc/zshrc` is left out while nothing
//! that runs before it may change what it runs ([`shadows`]). zsh runs
//! compiled code in place of a file, or of a
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
//! and, in a hook, a word that names it, while a redirection there to any other
//! file but a device, which may be the one `HISTFILE` names, or whose target an
//! expansion makes, is a doubt ([`runs`]). An `emulate -R ksh` turns `SHARE_HISTORY` on,
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
//! `$(...)`, a `${ command }`) are doubts, and so are arithmetic that may set
//! a parameter by a name the check cannot read ([`arith`]), a global alias
//! the code uses, which zsh puts in place of that word, a file the code may
//! make or write before zsh reads it, and a program a hook runs where a hook
//! may give it the command line in its environment ([`made`]). Beside the
//! code, the lines of each
//! file are counted for what they name ([`backstop`]): an option named beyond
//! what the code names counts as on, an `fpath` setting beyond what the walk
//! read adds a directory the check cannot follow, and a `source`, `.`, `eval`,
//! `autoload`, `fc` or `ZDOTDIR` setting beyond that is a doubt. The structure
//! of the code still decides which `ZDOTDIR` zsh reads its files in.

mod arith;
mod backstop;
mod builtins;
mod command_line;
mod dump;
mod functions;
mod install;
mod lexer;
mod made;
mod runs;
mod shadows;
mod stock;
mod walk;

use super::startup::{Scan, Write, read};
use crate::Filesystem;
use backstop::Forms;
pub(super) use command_line::{CommandLine, Start};
#[cfg(test)]
pub(super) use install::tests::seed_coreutils;
pub(super) use install::{ENVIRONMENT, Install, LOADER};
use install::{dircolors_split, profile_words};
use lexer::Word;
#[cfg(test)]
use lexer::{End, Token, tokens};
use shadows::{Changer, Snapshot};
use std::path::{Path, PathBuf};
use walk::{Event, Input, Read, events};

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
    /// Every directory `ZDOTDIR` may have named as the files were read, and
    /// whether it named one the check cannot follow: `compinit` reads its
    /// dump file in the one in force as it runs.
    zdotdirs_seen: Vec<PathBuf>,
    zdotdir_lost: bool,
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
    /// The redirections to a device or the terminal (`/dev/tty`, `$TTY`):
    /// the function they are in, or none for an `exec` that keeps one open,
    /// the target as written, and where. Each writes no file while no global
    /// alias may stand for it and no file sets `TTY`.
    devices: Vec<(Option<String>, String, String)>,
    /// The words the global aliases the files define stand for, as written,
    /// and each one's definition (its name, the word that defines it and
    /// where), which runs where a word of the code is its name.
    global_aliases: Vec<String>,
    global_alias_defs: Vec<(String, String, String)>,
    /// The forms of the dump files read as data, whose words but the quoted
    /// ones a global alias may stand for.
    dump_texts: Vec<Forms>,
    /// The lines keys type as zsh reads them (`bindkey -s`, `zle -U`), and
    /// where, and where a file first binds a key a line is typed with or
    /// changes a keymap, which may make them type others.
    typed_keys: Vec<(String, String)>,
    rebound: Option<String>,
    /// The arithmetic the files hold, of each kind and where
    /// ([`Event::Arith`]); the parameters they declare to hold numbers and
    /// the arrays whose keys are strings; and the parameters they unset, an
    /// empty name for one an expansion or a pattern names.
    arith: Vec<(String, walk::Arith, String)>,
    integers: Vec<String>,
    keyed_arrays: Vec<String>,
    unset: Vec<String>,
    /// The files the check would read that are not there now, and the
    /// words the files source and test, the paths of the functions they
    /// autoload among them, and give compinit after `-d` ([`Reader::made`]).
    missing: Vec<(PathBuf, usize)>,
    read_files: Vec<(PathBuf, usize)>,
    known_files: Vec<String>,
    compinit_dumps: Vec<String>,
    /// The writes to a path an expansion makes (`cp ~/.src $f`, `> $f`):
    /// its last part, what the warning names, where in the files read it is
    /// and the function it is in; the commands the files run where no
    /// function does, and where; and how many events were applied so far,
    /// which orders them ([`Reader::made`]).
    writes: Vec<(String, String, usize, Option<String>)>,
    top_calls: Vec<(String, usize)>,
    order: usize,
    /// The parameters a function sets to what an expansion makes: the
    /// function, the parameter, whether it is the function's own, and where
    /// ([`Event::Computed`]).
    computed: Vec<(String, String, bool, String)>,
    /// The aliases that stand for an `fc` that writes nothing
    /// ([`Event::FcAlias`]): their names, as written, and where.
    fc_aliases: Vec<(String, String, String)>,
    /// The forms of the text of each file read, for the names its lines use
    /// ([`Forms`]), and which of them are the code of a stock function,
    /// which makes no file the check would read before zsh reads it.
    texts: Vec<Forms>,
    stock_texts: Vec<usize>,
    /// The functions and regular aliases the files define
    /// ([`Event::Define`]).
    defined: Vec<String>,
    /// The commands a function runs with a word an expansion makes, or that
    /// read what the shell's code may make the command line, and where: in a
    /// hook, one that is no function may write the file the word names
    /// (`tee -a $f`), or what it reads (`print -r -- "$1" | tee -a file`).
    computed_calls: Vec<(String, String, String, runs::Fed)>,
    /// The commands the files run by name ([`Event::Call`]), and where.
    calls: Vec<(String, Vec<Word>, String)>,
    /// Each function the files define and a command it runs by name.
    edges: Vec<(String, String)>,
    /// The stock functions of zsh's own the files autoload ([`Stock`]):
    /// `compinit`, `compaudit` and `promptinit`.
    compinit: bool,
    compaudit: bool,
    promptinit: bool,
    /// The completion functions a dump file marks to be autoloaded.
    dump_marks: Vec<String>,
    /// The dump files read, the directories `compaudit` was looked at for,
    /// and those whose completion functions' first lines were read.
    dumps: Vec<PathBuf>,
    audited: Vec<PathBuf>,
    first_lines_read: Vec<PathBuf>,
    /// What the files read may change what a later command runs with
    /// ([`Changer`]), what of it came before each dircolors line of NixOS's
    /// `/etc/zshrc` taken as known ([`Snapshot`]), and how many were noted
    /// once the startup files were read.
    changers: Vec<Changer>,
    dircolors: Vec<Snapshot>,
    startup_changers: usize,
    /// The function whose code each file being followed is, outermost
    /// first, beside [`Reader::stack`].
    outers: Vec<Option<String>>,
    /// Each function and one it autoloads, which runs as it runs.
    autoloaded_by: Vec<(String, String)>,
    /// Where a file read may turn `SH_WORD_SPLIT` or `KSH_ARRAYS` on, and
    /// the elements of `fpath` they may change ([`Event::FpathSplits`]), as
    /// written and where.
    word_split: Option<String>,
    fpath_splits: Vec<(String, String)>,
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
            Ok(Some(text)) => {
                self.missing(path, true);
                text
            }
            Ok(None) => {
                self.missing(path, false);
                return None;
            }
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
    /// check reads beside its code, in any form zsh may read their words in
    /// ([`Forms`]): `TTY`, `ZSH_VERSION`, `HOME`, `_compdir`, the names the
    /// files use.
    fn lines(&mut self, text: &str, place: &str) -> Forms {
        let forms = Forms::of(text);
        if self.tty_set.is_none() && forms.writes("TTY") > 0 {
            self.tty_set = Some(place.to_string());
        }
        self.version_set |= forms.writes("ZSH_VERSION") > 0;
        // What NixOS's set-environment writes NIX_PROFILES with.
        self.profile_vars_set |= ["HOME", "USER", "XDG_STATE_HOME"]
            .iter()
            .any(|name| forms.writes(name) > 0);
        if forms.writes("HOME") > 0 {
            self.doubt(format!(
                "it cannot follow the HOME that {place} may set, which changes where zsh reads \
                 the user's startup files and the dump file compinit sources"
            ));
        }
        if self.compdir.is_none() && forms.uses("_compdir") > 0 {
            self.compdir = Some(place.to_string());
        }
        // Parameters whose values zsh runs or loads code from: the messages
        // MAILPATH names, which it expands before a prompt, the command it
        // runs for a redirection with none, and the directories it loads its
        // modules from.
        for (names, what) in [
            (
                ["MAILPATH", "mailpath"],
                "the mail messages it sets, which zsh expands before a prompt",
            ),
            (
                ["NULLCMD", "READNULLCMD"],
                "the command it sets, which zsh runs for a redirection that has none",
            ),
            (
                ["module_path", "MODULE_PATH"],
                "the modules zsh may load from where it sets them, whose code it cannot read",
            ),
        ] {
            if names.iter().any(|name| forms.writes(name) > 0) {
                self.doubt(format!(
                    "it cannot tell what code runs from {} in {place}, as it cannot read {what}",
                    names[0]
                ));
            }
        }
        self.texts.push(forms.clone());
        forms
    }

    /// Read the startup file at `path` and follow what it sets; `certain`
    /// when zsh certainly runs it whole.
    fn file(&mut self, path: &Path, certain: bool) {
        self.file_in(path, certain, None);
    }

    /// Read the file at `path` that runs as the code of the function `outer`
    /// when in one, and follow what it sets ([`Reader::file`]).
    fn file_in(&mut self, path: &Path, certain: bool, outer: Option<String>) {
        if let Some(text) = self.text(path) {
            self.code_in(path, &text, certain, outer);
        }
    }

    /// Follow what `text`, the code of the file at `path` that runs as the
    /// code of the function `outer` when in one, sets; `certain` when zsh
    /// certainly runs it whole. In NixOS's `/etc/zshrc`, as zsh reads it at
    /// the top, the `eval` of what dircolors prints is left out
    /// ([`dircolors_split`]): the lines before it are read first, what they
    /// and the files read so far may change it with is noted
    /// ([`Snapshot`]), then the rest; one that does not close its structure
    /// before the line is read whole.
    fn code_in(&mut self, path: &Path, text: &str, certain: bool, outer: Option<String>) {
        let place = path.to_string_lossy().into_owned();
        if outer.is_none()
            && self.stack.is_empty()
            && let Some((before, program, after)) = dircolors_split(self.fs, path, text)
        {
            let first = events(before, &place, None);
            if !first.confused {
                let stops = first.may_stop;
                self.piece(path, before, first, certain, None);
                self.snapshot(&place, program);
                let second = events(after, &place, None);
                self.piece(path, after, second, certain && !stops, None);
                return;
            }
        }
        let read = events(text, &place, outer.clone());
        self.piece(path, text, read, certain, outer);
    }

    /// Follow what `text`, the code of the file at `path` or a piece of it
    /// that runs as the code of the function `outer` when in one, sets, as
    /// `read` reads it; `certain` when zsh certainly runs it whole.
    fn piece(&mut self, path: &Path, text: &str, read: Read, certain: bool, outer: Option<String>) {
        self.rcs |= backstop::names_rcs(text);
        self.prompt_subst |= backstop::names_prompt_subst(text);
        let place = path.to_string_lossy().into_owned();
        let forms = self.lines(text, &place);
        self.shadows(&forms, &place, outer.as_deref());
        if backstop::names_any(text, &["globsubst"]) {
            self.doubt(format!(
                "it cannot tell what code zsh runs from the values it expands as patterns, as \
                 {place} names GLOB_SUBST, which makes a glob qualifier in a value run"
            ));
        }
        if self.word_split.is_none() && forms.word_split() {
            self.word_split = Some(place.clone());
        }
        self.stack.push(path.to_path_buf());
        self.outers.push(outer);
        for event in read.events {
            self.apply(event, &place, certain && !read.confused);
        }
        self.outers.pop();
        self.stack.pop();
    }

    /// Note `dirs` among the directories `ZDOTDIR` may have named.
    fn seen(&mut self, dirs: &[PathBuf]) {
        for dir in dirs {
            if !self.zdotdirs_seen.contains(dir) {
                self.zdotdirs_seen.push(dir.clone());
            }
        }
    }

    /// Mark the function `name` to be read as one the files autoload, which
    /// the function `by` autoloads as it runs when it does.
    fn autoload_name(&mut self, name: &str, by: Option<&str>) {
        if !self.autoloads.iter().any(|known| known == name) {
            self.autoloads.push(name.to_string());
        }
        if let Some(by) = by {
            let edge = (by.to_string(), name.to_string());
            if !self.autoloaded_by.contains(&edge) {
                self.autoloaded_by.push(edge);
            }
        }
    }

    /// Apply one event of the file at `place`; `certain` when zsh certainly
    /// runs the file whole and the check followed its structure.
    fn apply(&mut self, event: Event, place: &str, certain: bool) {
        self.order += 1;
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
                function,
            } => {
                self.known_files.push(path.text.clone());
                match self.resolve(&path) {
                    Some(files) => {
                        let one = files.len() == 1;
                        for file in files {
                            // Sourced in a function, its code runs as that one's.
                            self.file_in(&file, certain && unconditional && one, function.clone());
                        }
                    }
                    None => self.doubt(format!(
                        "it cannot follow the file {place} sources as `{}`",
                        path.text
                    )),
                }
            }
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
            Event::Call {
                name,
                args,
                function,
                input,
            } => self.call(name, args, function, input, place),
            Event::Define(name) => {
                self.shadow_function(&name, place, "defines");
                if !self.defined.contains(&name) {
                    self.defined.push(name);
                }
            }
            Event::HookDoubt { function, doubt } => self.in_functions.push((function, Err(doubt))),
            event @ (Event::GlobalAlias { .. }
            | Event::FpathSplits(_)
            | Event::Typed { .. }
            | Event::Rebind
            | Event::Arith { .. }
            | Event::Declared { .. }
            | Event::Unset(_)
            | Event::Tested(_)
            | Event::Computed { .. }) => self.note(event, place),
            Event::Assign {
                name,
                value,
                unconditional,
            } => self.assign(name, value, certain && unconditional, place),
            Event::Fpath {
                dir: Some(dir),
                first,
            } => match self.resolve(&dir) {
                // A `:` in it parts it in two where FPATH's value is set from
                // FPATH again (`FPATH=$FPATH:/x`).
                Some(dirs) if !dirs.iter().any(|dir| dir.to_string_lossy().contains(':')) => {
                    for dir in dirs {
                        let entry = Ok((dir, first));
                        if !self.fpath.contains(&entry) {
                            self.fpath.push(entry);
                        }
                    }
                }
                _ => self.fpath.push(Err(format!(
                    "it cannot follow the directory that {place} adds to fpath as `{}`, where \
                     zsh looks for the functions the files autoload",
                    dir.text
                ))),
            },
            Event::Fpath { dir: None, .. } => self.fpath.push(Err(format!(
                "it cannot follow what a line of {place} may add to fpath, where zsh looks \
                 for the functions the files autoload"
            ))),
            Event::Autoload(function) => {
                if function.text.contains('/') {
                    self.known_files.push(function.text.clone());
                }
                let name = function
                    .text
                    .rsplit('/')
                    .next()
                    .unwrap_or_default()
                    .to_string();
                self.shadow_function(&name, place, "autoloads");
                if let Some(Some(outer)) = self.outers.last()
                    && !function.text.contains('/')
                {
                    let edge = (outer.clone(), name);
                    if !self.autoloaded_by.contains(&edge) {
                        self.autoloaded_by.push(edge);
                    }
                }
                self.autoload(function, place);
            }
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
                kept,
            } => self.redirect(&target, function, computed, kept, place),
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

    /// Note that the file at `place` runs the command `name` with `args`, in
    /// the function `function` when in one, reading `input`
    /// ([`Event::Call`]).
    fn call(
        &mut self,
        name: String,
        args: Vec<Word>,
        function: Option<String>,
        input: Input,
        place: &str,
    ) {
        if made::creates(&name) {
            for arg in args.iter().filter(|arg| !arg.text.starts_with('-')) {
                let what = format!("`{name}` in {place} writes to `{}`", arg.text);
                self.makes(&arg.text, what, function.clone());
            }
        }
        if function.is_none() {
            self.top_calls.push((name.clone(), self.order));
        }
        if let Some(function) = function {
            let fed = if args.iter().any(|arg| arg.expands) {
                Some(runs::Fed::Word)
            } else {
                match input {
                    Input::None => None,
                    Input::Computed => Some(runs::Fed::Input),
                    Input::Piped(feeders) => Some(runs::Fed::Pipe(feeders)),
                }
            };
            if let Some(fed) = fed {
                self.computed_calls
                    .push((function.clone(), name.clone(), place.to_string(), fed));
            }
            if !self.edges.contains(&(function.clone(), name.clone())) {
                self.edges.push((function, name.clone()));
            }
        }
        self.calls.push((name, args, place.to_string()));
    }

    /// Note what the file at `place` defines, declares, tests or types that
    /// the check counts once the files are read: a global alias, an element
    /// given `fpath` that may split, a line keys type, a key bound, an
    /// arithmetic expression, a parameter declared, unset or set in a
    /// function, a file a test asks about.
    fn note(&mut self, event: Event, place: &str) {
        match event {
            Event::GlobalAlias { name, text } => {
                let definition = (name.clone(), text, place.to_string());
                if !self.global_alias_defs.contains(&definition) {
                    self.global_alias_defs.push(definition);
                }
                // It stands for any word of a later command, as zsh reads it.
                self.shadow(format!("{place} defines the global alias `{name}`"));
                if !self.global_aliases.contains(&name) {
                    self.global_aliases.push(name);
                }
            }
            Event::FpathSplits(text) => self.fpath_splits.push((text, place.to_string())),
            Event::Typed { text, keys } => {
                // What it types counts for the names the files use.
                self.lines(&text, place);
                if keys {
                    self.typed_keys.push((text, place.to_string()));
                }
            }
            Event::Rebind => {
                if self.rebound.is_none() {
                    self.rebound = Some(place.to_string());
                }
            }
            Event::Arith { text, kind } => {
                let entry = (text, kind, place.to_string());
                if !self.arith.contains(&entry) {
                    self.arith.push(entry);
                }
            }
            Event::Declared {
                name,
                keyed,
                numeric,
            } => {
                if keyed && !self.keyed_arrays.contains(&name) {
                    self.keyed_arrays.push(name.clone());
                }
                if numeric && !self.integers.contains(&name) {
                    self.integers.push(name);
                }
            }
            Event::Unset(name) => {
                if !self.unset.contains(&name) {
                    self.unset.push(name);
                }
            }
            Event::Tested(word) => self.known_files.push(word),
            Event::Computed {
                function,
                name,
                local,
            } => self
                .computed
                .push((function, name, local, place.to_string())),
            _ => {}
        }
    }

    /// Note the value `value` a file at `place` gives `ZDOTDIR` or
    /// `XDG_CONFIG_HOME` (`name`); `certain` when the assignment certainly
    /// runs.
    fn assign(&mut self, name: &str, value: Word, certain: bool, place: &str) {
        if name == "XDG_CONFIG_HOME" {
            let config = Some(value.text);
            if certain {
                self.xdg_config_homes = vec![config];
            } else if !self.xdg_config_homes.contains(&config) {
                self.xdg_config_homes.push(config);
            }
            return;
        }
        match self.resolve(&value) {
            Some(dirs) if certain => {
                self.seen(&dirs);
                self.zdotdirs = dirs;
            }
            Some(dirs) => {
                self.seen(&dirs);
                for dir in dirs {
                    if !self.zdotdirs.contains(&dir) {
                        self.zdotdirs.push(dir);
                    }
                }
            }
            None => {
                self.zdotdir_lost = true;
                if certain {
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
    let mut scan = Scan::default();
    // A zsh runs with the home its environment names, when the check reads
    // it; one that is not its account's is a home it does not read.
    let homes: Vec<PathBuf> = match install.env.as_ref().and_then(|env| env.home.as_deref()) {
        Some(home) if homes.iter().any(|known| known == Path::new(home)) => {
            vec![PathBuf::from(home)]
        }
        Some(home) => {
            scan.doubts.push(format!(
                "it cannot tell what the user's startup files hold, as the shell's environment \
                 sets HOME to `{home}`, a home the check does not read"
            ));
            homes.to_vec()
        }
        None => homes.to_vec(),
    };
    if install
        .env
        .as_ref()
        .is_some_and(|env| env.mailpath.is_some())
    {
        scan.doubts.push(
            "it cannot tell what code the mail messages that MAILPATH in the shell's \
             environment names run, which zsh expands before a prompt"
                .to_string(),
        );
    }
    let homes: Vec<Option<&Path>> = if homes.is_empty() {
        vec![None]
    } else {
        homes.iter().map(|home| Some(home.as_path())).collect()
    };
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
    let env = install.env.as_ref();
    // The profiles the environment names, as `${(z)NIX_PROFILES}` splits
    // them; none the check can tell when the environment holds what zsh
    // splits otherwise.
    let profiles =
        env.and_then(|env| profile_words(env.nix_profiles.as_deref().unwrap_or_default()));
    // Where the user's files are: the ZDOTDIR the environment holds, when it
    // holds one, else the home.
    let mut doubts = Vec::new();
    let zdotdirs: Vec<PathBuf> = match env.and_then(|env| env.zdotdir.as_deref()) {
        Some(dir) if Path::new(dir).is_absolute() => vec![PathBuf::from(dir)],
        Some(dir) => {
            doubts.push(format!(
                "it cannot follow the ZDOTDIR that the shell's environment holds (`{dir}`)"
            ));
            Vec::new()
        }
        None => home.map(Path::to_path_buf).into_iter().collect(),
    };
    let mut reader = Reader {
        fs,
        home,
        options: Default::default(),
        zdotdir_lost: zdotdirs.is_empty(),
        zdotdirs_seen: zdotdirs.clone(),
        zdotdirs,
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
        doubts,
        rcs: false,
        prompt_subst: false,
        prompts: Vec::new(),
        install,
        profiles,
        profile_fpath: Vec::new(),
        tty_set: None,
        compdir: env
            .and_then(|env| env.compdir.as_ref())
            .map(|_| "the shell's environment".to_string()),
        version_set: false,
        profile_vars_set: false,
        expanding: Vec::new(),
        devices: Vec::new(),
        global_aliases: Vec::new(),
        global_alias_defs: Vec::new(),
        dump_texts: Vec::new(),
        typed_keys: Vec::new(),
        rebound: None,
        arith: Vec::new(),
        integers: Vec::new(),
        keyed_arrays: Vec::new(),
        unset: Vec::new(),
        missing: Vec::new(),
        read_files: Vec::new(),
        known_files: Vec::new(),
        compinit_dumps: Vec::new(),
        writes: Vec::new(),
        top_calls: Vec::new(),
        order: 0,
        computed: Vec::new(),
        fc_aliases: Vec::new(),
        texts: Vec::new(),
        stock_texts: Vec::new(),
        defined: Vec::new(),
        computed_calls: Vec::new(),
        calls: Vec::new(),
        edges: Vec::new(),
        compinit: false,
        compaudit: false,
        promptinit: false,
        dump_marks: Vec::new(),
        dumps: Vec::new(),
        audited: Vec::new(),
        first_lines_read: Vec::new(),
        changers: Vec::new(),
        dircolors: Vec::new(),
        startup_changers: 0,
        outers: Vec::new(),
        autoloaded_by: Vec::new(),
        word_split: None,
        fpath_splits: Vec::new(),
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
            if stage == "zshenv" && !matches!(fs.inode(Path::new("/etc/NIXOS")), Ok(None)) {
                // The zshenv nixpkgs builds into zsh reads, on NixOS,
                // /etc/set-environment when /etc/zshenv is missing, and
                // /etc/zshenv.local after either.
                if matches!(fs.inode(Path::new("/etc/zshenv")), Ok(None)) {
                    reader.file(Path::new("/etc/set-environment"), false);
                }
                reader.file(Path::new("/etc/zshenv.local"), false);
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
    reader.startup_changers = reader.changers.len();
    reader.autoloaded();
    reader.runs();
    reader.arithmetic();
    reader.made();
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
