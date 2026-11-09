// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Where zsh finds the programs that its own completion functions run as you
//! complete a word, once the files autoload its stock `compinit`. Some of
//! those functions run what such a program prints as code: `_comp_locale`
//! evaluates the `LC_CTYPE` line that `locale` prints, which `_call_program`
//! runs for `ls <Tab>` among others, `_apt` what `apt-config` prints, `_npm`
//! what `npm` prints, and `_rubber`, `_ecasound` (`grep`, `awk`), `_ant` and
//! macOS's `_retrieve_mac_apps` (`sysctl`) the like. So a program of the
//! operator's own that zsh finds by such a name may make it run any code.
//! Where compinit runs, a directory of `PATH` that holds a program (any file
//! but a directory) and is neither a system directory ([`SYSTEM_DIRS`]) nor
//! one that leads into the Nix store is a doubt, and so is one the check
//! cannot read, one named relative to the directory zsh runs in (an empty
//! element, `.`, `bin`, a `~` a quote keeps), a change of `PATH` it cannot
//! follow, and a program that a `hash` or the `commands` parameter names for
//! a command, which zsh runs by that name wherever it is. `PATH` is read from
//! the shell's environment and from each directory the files put in it,
//! wherever they do, as zsh may look in any of them as you complete a word.

use super::backstop::{is_write, whole_words, writes};
use super::completion::shown;
use super::paths::replace_parameter;
use super::walk::PathChange;
use super::{Reader, Word};
use crate::Filesystem;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

/// The directories of the system's own programs, which the check takes for
/// harmless where zsh finds a program in one: `/usr/bin`, `/bin`,
/// `/usr/sbin`, `/sbin`, and NixOS's `/run/wrappers/bin`, which holds the
/// wrappers of its setuid programs.
pub(super) const SYSTEM_DIRS: [&str; 5] = [
    "/usr/bin",
    "/bin",
    "/usr/sbin",
    "/sbin",
    "/run/wrappers/bin",
];

/// What zsh's own completion functions do with the programs of a directory
/// zsh looks in, as the doubts say it.
const RUN: &str = "whose programs zsh's own completion functions may run as you complete a \
                   word, reading what some print as code (`_comp_locale` reads what `locale` \
                   prints)";

/// Whether `dir` is one of [`SYSTEM_DIRS`], as zsh looks in it: a `/` at
/// its end or twice, and a `.` part, change nothing; a `..` may.
fn system_dir(dir: &Path) -> bool {
    SYSTEM_DIRS
        .iter()
        .any(|system| dir.components().eq(Path::new(system).components()))
}

/// `part`, an element of the shell's environment's `PATH` that names no
/// absolute directory, as a doubt names it.
fn relative(part: &str) -> String {
    if part.is_empty() {
        "an empty element, which names the directory zsh runs in".to_string()
    } else {
        format!("`{part}`, a directory relative to the one zsh runs in")
    }
}

/// How often `text` names `PATH` otherwise than to read it ([`writes`]), and
/// `path`, a word that paths and styles hold too (`~/path/x`,
/// `cache-path`), where it may be the parameter's name ([`name_writes`]).
pub(super) fn path_writes(text: &str) -> usize {
    writes(text, "PATH") + name_writes(text, "path")
}

/// How often `text` names `hash` as a word of its own ([`whole_words`]),
/// which may name the program zsh runs for a command (`hash locale=...`),
/// and `commands`, zsh's table of them, where it may be the parameter's name
/// ([`name_writes`]).
pub(super) fn hash_writes(text: &str) -> usize {
    whole_words(text, "hash") + name_writes(text, "commands")
}

/// How often `text` names the parameter `name`, a word that paths, styles
/// and other words hold too, otherwise than to read it ([`is_write`]) where
/// it may be that parameter's name: after nothing, a blank, a quote, a
/// backslash, a `;`, a `&`, a `|`, a `(`, a `)` (of `${(A)name::=...}`), a
/// `{` (of `${name::=...}`), a `}`, a `!`, a `,` (of a brace expansion's
/// list), a backquote or the letters of an option (`-vname`), and before
/// nothing, a blank, a quote, a backslash, a subscript, an `=`, a `+`, a `:`,
/// a `;`, a `&`, a `|`, a `)`, a `}`, a `,` or a backquote.
fn name_writes(text: &str, name: &str) -> usize {
    text.match_indices(name)
        .filter(|&(at, found)| {
            let before = text[..at].chars().next_back();
            let after = text[at + found.len()..].chars().next();
            before.is_none_or(|c| {
                c.is_whitespace() || c.is_ascii_alphabetic() || "'\"\\;&|(){}!,`".contains(c)
            }) && after.is_none_or(|c| c.is_whitespace() || "'\"\\[=+:;&|)},`".contains(c))
                && is_write(text, at, found.len())
        })
        .count()
}

impl<F: Filesystem> Reader<'_, F> {
    /// Note what the file at `place` does to where zsh finds the programs it
    /// runs by name ([`PathChange`]), which counts where compinit runs.
    pub(super) fn path_change(&mut self, change: PathChange, place: &str) {
        let doubt = match change {
            PathChange::Dir(dir) => {
                self.path_dir(&dir, place);
                return;
            }
            PathChange::Splits(text) => {
                self.path_splits.push((text, place.to_string()));
                return;
            }
            PathChange::Unfollowed(text) => {
                format!("it cannot follow the change of PATH that `{text}` in {place} makes, {RUN}")
            }
            PathChange::Hashed(text) => format!(
                "it cannot tell what the program prints that `{text}` in {place} names for a \
                 command, which zsh then runs by that name wherever it is, and zsh's own \
                 completion functions may run as you complete a word, reading what some print as \
                 code"
            ),
            PathChange::Unread => format!(
                "it cannot follow a change of PATH, or of the program zsh runs for a command, \
                 that a line of {place} may make, {RUN}"
            ),
        };
        let entry = Err(doubt);
        if !self.path.contains(&entry) {
            self.path.push(entry);
        }
    }

    /// Note the directory `dir`, as written, that the file at `place` puts in
    /// `PATH`, which [`Reader::path_dirs`] resolves once the files are read.
    /// A `~` that a quote or a backslash may keep as written (`"~/bin"`,
    /// `\~/bin`) names a directory relative to the one zsh runs in, not the
    /// home.
    fn path_dir(&mut self, dir: &Word, place: &str) {
        let literal = dir.text.starts_with('~')
            && (dir.quoted || self.escaped_tildes.last().copied().unwrap_or(true));
        let entry = (dir.clone(), place.to_string(), literal);
        if !self.path_words.contains(&entry) {
            self.path_words.push(entry);
        }
    }

    /// The directories the files put in `PATH` ([`Reader::path_dir`]), each
    /// one a word may name ([`Reader::resolve`]) with `$USER` and
    /// `$XDG_STATE_HOME` in it as the shell runs with them, as NixOS's
    /// `set-environment` writes them, or the doubt that one the check cannot
    /// follow is: one named relative to the directory zsh runs in, one
    /// holding `$ZDOTDIR` or `$XDG_CONFIG_HOME`, which the files may set to
    /// another as zsh runs, and any other expansion.
    fn path_dirs(&mut self) {
        for (word, place, literal) in std::mem::take(&mut self.path_words) {
            let resolved = if literal
                || word.text.contains("ZDOTDIR")
                || word.text.contains("XDG_CONFIG_HOME")
            {
                None
            } else {
                self.with_session(&word)
                    .and_then(|word| self.resolve(&word))
            };
            let entries: Vec<Result<PathBuf, String>> = match resolved {
                Some(dirs) => dirs.into_iter().map(Ok).collect(),
                None => vec![Err(format!(
                    "it cannot follow the directory that {place} puts in PATH as `{}`, {RUN}",
                    word.text
                ))],
            };
            for entry in entries {
                if !self.path.contains(&entry) {
                    self.path.push(entry);
                }
            }
        }
    }

    /// `word` with `$USER` and `$XDG_STATE_HOME` in it as the shell's
    /// environment holds them, each empty where it holds none, as zsh
    /// expands them; `None` where the check does not know that environment
    /// or a file read may set either.
    fn with_session(&self, word: &Word) -> Option<Word> {
        if !word.expands {
            return Some(word.clone());
        }
        let mut text = word.text.clone();
        for name in ["USER", "XDG_STATE_HOME"] {
            let forms = [format!("${{{name}}}"), format!("${name}")];
            if !forms.iter().any(|form| text.contains(form.as_str())) {
                continue;
            }
            let env = self
                .install
                .env
                .as_ref()
                .filter(|_| !self.profile_vars_set)?;
            let value = match name {
                "USER" => env.user.clone(),
                _ => env.xdg_state_home.clone(),
            }
            .unwrap_or_default();
            for form in &forms {
                text = replace_parameter(&text, form, &value);
            }
        }
        Some(Word {
            text,
            ..word.clone()
        })
    }

    /// Note a doubt for each directory zsh may look in for a program that its
    /// own completion functions run, and whose output some run as code
    /// ([`super::programs`]), once the files autoload the stock `compinit`:
    /// those `PATH` names in the shell's environment and those the files put
    /// in it.
    pub(super) fn own_programs(&mut self) {
        self.path_dirs();
        self.loaded_programs();
        let mut dirs: Vec<PathBuf> = Vec::new();
        match self.install.env.as_ref().map(|env| env.path.clone()) {
            None => self.doubt(format!(
                "it cannot tell which directories PATH names, as it does not know the shell's \
                 environment, {RUN}"
            )),
            Some(None) => self.doubt(format!(
                "it cannot tell which directories PATH names, as the shell's environment holds \
                 none and zsh then takes the one it was built with, {RUN}"
            )),
            Some(Some(value)) => {
                for part in value.split(':') {
                    if part.contains('\u{fffd}') {
                        // A name that is no UTF-8, which the check cannot
                        // name as zsh looks in it.
                        self.doubt(format!(
                            "it cannot tell which programs zsh finds by PATH in the shell's \
                             environment, as it holds a directory whose name is no UTF-8 \
                             (`{part}`), {RUN}"
                        ));
                    } else if Path::new(part).is_absolute() {
                        let dir = PathBuf::from(part);
                        if !dirs.contains(&dir) {
                            dirs.push(dir);
                        }
                    } else {
                        self.doubt(format!(
                            "it cannot tell which programs zsh finds by PATH in the shell's \
                             environment, as it holds {}, {RUN}",
                            relative(part)
                        ));
                    }
                }
            }
        }
        if let Some(place) = self.word_split.clone() {
            for (text, at) in std::mem::take(&mut self.path_splits) {
                self.doubt(format!(
                    "it cannot follow the directories that `{text}` gives PATH in {at}, as {place} \
                     may turn SH_WORD_SPLIT or KSH_ARRAYS on, which split them or keep the first, \
                     {RUN}"
                ));
            }
        }
        for entry in std::mem::take(&mut self.path) {
            match entry {
                Ok(dir) => {
                    if !dirs.contains(&dir) {
                        dirs.push(dir);
                    }
                }
                Err(doubt) => self.doubt(doubt),
            }
        }
        for dir in dirs {
            self.programs_in(&dir);
        }
    }

    /// Note a doubt where the shell's environment or a file read may make any
    /// program print other code than its own, a program of the system's
    /// among them, whose output zsh's own completion functions may run as
    /// code: by a variable of the dynamic loader, which loads code of the
    /// operator's own into it (`LD_PRELOAD`), or by `ARGV0`, the name zsh
    /// gives every program it runs, which picks the program a multi-call
    /// program runs. zsh 5.9.2 ran the `LC_CTYPE` line that `locale` printed
    /// with an `LD_PRELOAD` of the operator's own, from `.zshrc` or from the
    /// environment, as Tab completed `ls marker-one `.
    fn loaded_programs(&mut self) {
        let env = self.install.env.as_ref();
        let why = if env.is_some_and(|env| env.loader) {
            Some(
                "the shell's environment sets a variable of the dynamic loader (`LD_...`)"
                    .to_string(),
            )
        } else if env.is_some_and(|env| env.argv0.is_some()) {
            Some(
                "the shell's environment sets ARGV0, the name zsh gives every program it runs"
                    .to_string(),
            )
        } else {
            self.loader_set.as_ref().map(|place| {
                format!("{place} sets a variable of the dynamic loader (`LD_...`) or ARGV0")
            })
        };
        if let Some(why) = why {
            self.doubt(format!(
                "it cannot tell what the programs that zsh's own completion functions run as you \
                 complete a word print, as {why}, which may make any of them print code of the \
                 operator's own, and some of those functions read what a program prints as code \
                 (`_comp_locale` reads what `locale` prints)"
            ));
        }
    }

    /// Note a doubt where `dir`, a directory of `PATH`, holds a program, any
    /// file but a directory, and is neither one of [`SYSTEM_DIRS`] nor one
    /// that leads into the Nix store, or where the check cannot read it; one
    /// that is not there holds none.
    fn programs_in(&mut self, dir: &Path) {
        if system_dir(dir) {
            return;
        }
        let could_not = |error: crate::NailsError| {
            format!(
                "it could not read the directory {} of PATH ({}), {RUN}",
                dir.display(),
                error
                    .io_kind()
                    .map_or_else(|| error.to_string(), |kind| kind.to_string())
            )
        };
        let gone = |error: &crate::NailsError| {
            matches!(
                error.io_kind(),
                Some(ErrorKind::NotFound | ErrorKind::NotADirectory)
            )
        };
        let real = match self.fs.canonicalize(dir) {
            Ok(real) if real.starts_with("/nix/store") || system_dir(&real) => return,
            Ok(real) => real,
            Err(error) if gone(&error) => return,
            Err(error) => {
                let doubt = could_not(error);
                self.doubt(doubt);
                return;
            }
        };
        match self.fs.list_directory(&real) {
            Ok(entries) => {
                let mut names: Vec<String> = entries
                    .iter()
                    .filter(|entry| !matches!(self.fs.is_directory(entry), Ok(true)))
                    .filter_map(|entry| entry.file_name())
                    .map(|name| name.to_string_lossy().into_owned())
                    .collect();
                names.sort();
                if !names.is_empty() {
                    self.doubt(format!(
                        "it cannot tell what the programs in {} print ({}), as that directory of \
                         PATH is neither a system directory nor one that leads into the Nix store, \
                         and zsh's own completion functions may run them as you complete a word, \
                         reading what some print as code (`_comp_locale` reads what `locale` \
                         prints)",
                        dir.display(),
                        shown(&names)
                    ));
                }
            }
            Err(error) if gone(&error) => {}
            Err(error) => {
                let doubt = could_not(error);
                self.doubt(doubt);
            }
        }
    }
}
