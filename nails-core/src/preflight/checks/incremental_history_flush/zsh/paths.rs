// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The paths the files name, as the check resolves them: with `~`, `$HOME`,
//! `$ZDOTDIR` and `$XDG_CONFIG_HOME` in them, and the directories `ZDOTDIR`
//! and `XDG_CONFIG_HOME` may name as the files set them. Each of the two is
//! a set of values it may hold ([`Candidates`]), and a path that names one is
//! read for each of them. `XDG_CONFIG_HOME` may always be empty too, which
//! `${XDG_CONFIG_HOME:-$HOME/.config}` takes as its default, as a write the
//! walk does not follow may make it so (`typeset -a XDG_CONFIG_HOME`, a
//! declaration in an anonymous function); and where the check does not know
//! the shell's environment, it may hold any value, which no path that names
//! it can be read for. An assignment the walk reads as certain holds for the
//! rest of its file, but once the file ends, the values from before the file
//! and each one it gave on the way may hold too: zsh stops reading a file at
//! an error (an unset parameter under `NO_UNSET`, a read-only one, a bad
//! subscript), which may come before the assignment. Code that runs as a
//! function runs after the files define it, so the paths it sources, and
//! those any code adds to `fpath` or autoloads by path, are read for every
//! value the files ever give either parameter, those they give later among
//! them ([`Reader::late`]).

use super::{GLOB, Reader, Word};
use crate::Filesystem;
use std::path::{Path, PathBuf};

/// The values `ZDOTDIR` and `XDG_CONFIG_HOME` may hold.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Candidates {
    /// Each value `ZDOTDIR` may hold, `None` where it is unset, as zsh then
    /// reads the user's files in the home and expands `$ZDOTDIR` to nothing;
    /// none once a file sets it to what the check cannot follow.
    pub(super) zdotdirs: Vec<Option<PathBuf>>,
    /// Each value `XDG_CONFIG_HOME` may hold as written, `None` where it is
    /// unset or empty; and whether it may hold one that an environment the
    /// check does not know gives.
    pub(super) xdg: Vec<Option<String>>,
    pub(super) xdg_unknown: bool,
}

impl Candidates {
    /// Add each value of `other` that `self` lacks.
    pub(super) fn union(&mut self, other: &Self) {
        add_all(&mut self.zdotdirs, other.zdotdirs.iter().cloned());
        add_all(&mut self.xdg, other.xdg.iter().cloned());
        self.xdg_unknown |= other.xdg_unknown;
    }
}

/// Add each of `values` that `to` lacks.
fn add_all<T: PartialEq>(to: &mut Vec<T>, values: impl IntoIterator<Item = T>) {
    for value in values {
        if !to.contains(&value) {
            to.push(value);
        }
    }
}

/// What a file being followed gave `ZDOTDIR` and `XDG_CONFIG_HOME` so far,
/// and whether it set each where zsh cannot have stopped it before
/// ([`super::Event::Assign`]).
#[derive(Debug, Default)]
pub(super) struct Given {
    values: Candidates,
    zdotdir_first: bool,
    xdg_first: bool,
}

/// A path code that may run later names, read again once the files are
/// read ([`Reader::late`]): a file the function `function` sources, a
/// directory added to `fpath` (in front where `first`), a function's file
/// autoloaded by its path; and where.
#[derive(Debug, Clone)]
pub(super) enum Late {
    Source(Word, Option<String>, String),
    Fpath(Word, bool, String),
    Autoload(Word, String),
}

impl<F: Filesystem> Reader<'_, F> {
    /// The paths `value` may name for the values `ZDOTDIR` and
    /// `XDG_CONFIG_HOME` may hold now, each different one once; `None` when
    /// one of them is no path the check can know.
    pub(super) fn resolve(&self, value: &Word) -> Option<Vec<PathBuf>> {
        self.resolve_for(value, &self.values)
    }

    /// The paths `value` may name for every value the files ever give
    /// `ZDOTDIR` and `XDG_CONFIG_HOME`, as code that runs as a function may
    /// run with any of them ([`Reader::resolve`]).
    pub(super) fn resolve_ever(&self, value: &Word) -> Option<Vec<PathBuf>> {
        self.resolve_for(value, &self.ever)
    }

    /// The paths `value` may name for the values of `values`.
    fn resolve_for(&self, value: &Word, values: &Candidates) -> Option<Vec<PathBuf>> {
        let xdg = value.text.contains("XDG_CONFIG_HOME");
        if xdg && values.xdg_unknown {
            return None;
        }
        let zdot = value.text.contains("ZDOTDIR");
        let configs: &[Option<String>] = if xdg { &values.xdg } else { &[None] };
        let dirs: &[Option<PathBuf>] = if zdot { &values.zdotdirs } else { &[None] };
        let mut paths = Vec::new();
        for config in configs {
            for dir in dirs {
                let path = self.resolve_in(value, config.as_deref(), dir.as_deref())?;
                add_all(&mut paths, [path]);
            }
        }
        (!paths.is_empty()).then_some(paths)
    }

    /// The path `value` names with `XDG_CONFIG_HOME` set to `config` as
    /// written, or unset, and `ZDOTDIR` to `zdotdir`, or unset: with `~`,
    /// `$HOME`, `$ZDOTDIR`, `$XDG_CONFIG_HOME` and their `${...:-...}`
    /// defaults in it, an unset or empty one expanding to nothing, as zsh
    /// expands it (`$ZDOTDIR/x` is `/x`), and a `$HOME` that a letter, a digit
    /// or a `_` follows being another parameter (`$HOMEBREW`), but no `~` a
    /// value gives it; `None` when it
    /// names anything else the check cannot know, a modifier or a subscript on
    /// one of them among it (`$HOME:a`, `$ZDOTDIR:h`), or no absolute path.
    fn resolve_in(
        &self,
        value: &Word,
        config: Option<&str>,
        zdotdir: Option<&Path>,
    ) -> Option<PathBuf> {
        let home = self.home?.to_string_lossy().into_owned();
        // `:-` puts the default in place of an empty value too.
        let default_config = config
            .filter(|config| !config.is_empty())
            .map_or_else(|| format!("{home}/.config"), str::to_string);
        let config = config.unwrap_or_default().to_string();
        let zdotdir = zdotdir.map(|dir| dir.to_string_lossy().into_owned());
        let default_zdotdir = zdotdir.clone().unwrap_or_else(|| home.clone());
        let zdotdir = zdotdir.unwrap_or_default();
        let mut text = value.text.clone();
        if value.expands {
            for (pattern, with) in [
                ("${XDG_CONFIG_HOME:-$HOME/.config}", &default_config),
                ("${XDG_CONFIG_HOME:-${HOME}/.config}", &default_config),
                ("${XDG_CONFIG_HOME:-~/.config}", &default_config),
                ("${ZDOTDIR:-$HOME}", &default_zdotdir),
                ("${ZDOTDIR:-${HOME}}", &default_zdotdir),
                ("${ZDOTDIR:-~}", &default_zdotdir),
                ("${XDG_CONFIG_HOME}", &config),
                ("$XDG_CONFIG_HOME", &config),
                ("${ZDOTDIR}", &zdotdir),
                ("$ZDOTDIR", &zdotdir),
                ("${HOME}", &home),
                ("$HOME", &home),
            ] {
                if text.contains(pattern) {
                    text = replace_parameter(&text, pattern, with);
                }
            }
        }
        // A `~` the value starts with is the home; one a parameter's value
        // gives stays as it is, as zsh expands no `~` in it (`$XDG_CONFIG_HOME`
        // holding `~/.cfg` names `~/.cfg` below the working directory).
        if (value.text == "~" || value.text.starts_with("~/"))
            && (text == "~" || text.starts_with("~/"))
        {
            text = format!("{home}{}", &text[1..]);
        }
        let plain = !text.contains(['$', '`', '~']) && !text.contains(GLOB);
        let path = PathBuf::from(text);
        (plain && path.is_absolute()).then_some(path)
    }

    /// Read the user's file of the stage `stage` (`zshrc`) from each place
    /// `ZDOTDIR` may put it in: where zsh reads the one there, `ZDOTDIR`
    /// holds that place, or is unset for the home's, and where an `emulate`
    /// of sh's mode may last, the home's with `ZDOTDIR` as it is; `certain`
    /// when zsh certainly reads the stage's file. The home's first, so the
    /// warning names a file of a place the files set.
    pub(super) fn user_files(&mut self, stage: &str, certain: bool) {
        let before = self.values.zdotdirs.clone();
        let mut dirs = before.clone();
        dirs.sort_by_key(Option::is_some);
        let mut after: Vec<Option<PathBuf>> = Vec::new();
        let mut read: Vec<PathBuf> = Vec::new();
        for dir in dirs {
            self.values.zdotdirs = vec![dir.clone()];
            if let Some(path) = dir
                .as_deref()
                .or(self.home)
                .map(|dir| dir.join(format!(".{stage}")))
                && !read.contains(&path)
            {
                read.push(path.clone());
                self.file(&path, certain);
            }
            add_all(&mut after, std::mem::take(&mut self.values.zdotdirs));
        }
        // In sh's or ksh's mode zsh reads the home's file in place of the
        // one in ZDOTDIR, which keeps what it held
        // ([`super::reading::emulates_sh`]).
        if self.sh_mode
            && let Some(path) = self.home.map(|home| home.join(format!(".{stage}")))
            && !read.contains(&path)
        {
            self.values.zdotdirs = before;
            self.file(&path, false);
            add_all(&mut after, std::mem::take(&mut self.values.zdotdirs));
        }
        self.values.zdotdirs = after;
    }

    /// Start following a file: what `ZDOTDIR` and `XDG_CONFIG_HOME` may
    /// hold before it ([`Reader::end_file`]).
    pub(super) fn start_file(&mut self) -> Candidates {
        self.given.push(Given::default());
        self.values.clone()
    }

    /// End following a file, before which `ZDOTDIR` and `XDG_CONFIG_HOME`
    /// held `before`: zsh may not have read it, or stopped it at an error
    /// before any of its assignments, so each value from before it may hold
    /// too, but for one a file zsh certainly reads set before anything that
    /// may stop it, and so may each it gave.
    pub(super) fn end_file(&mut self, mut before: Candidates) {
        let given = self.given.pop().unwrap_or_default();
        if given.zdotdir_first {
            before.zdotdirs.clear();
        }
        if given.xdg_first {
            before.xdg.clear();
            before.xdg_unknown = false;
        }
        self.values.union(&before);
        self.values.union(&given.values);
        if let Some(outer) = self.given.last_mut() {
            outer.values.union(&given.values);
        }
    }

    /// Note the value `value` a file at `place` gives `ZDOTDIR` or
    /// `XDG_CONFIG_HOME` (`name`), or that it takes `XDG_CONFIG_HOME` away
    /// (`None`), after which `${XDG_CONFIG_HOME:-...}` is its default; of
    /// `how`, whether the assignment certainly runs where the file runs to
    /// it, which makes it the one value for the rest of the file, and
    /// whether it certainly runs, in a file zsh certainly reads, first, where
    /// zsh cannot have stopped the file before it ([`super::Event::Assign`]).
    pub(super) fn assign(
        &mut self,
        name: &str,
        value: Option<Word>,
        how: (bool, bool),
        place: &str,
    ) {
        let (certain, first) = how;
        if name == "XDG_CONFIG_HOME" {
            // Each path it may name as it is set, from what it was before
            // (`${XDG_CONFIG_HOME:-$HOME/.config}`), else the value as
            // written.
            let configs: Vec<Option<String>> = match value {
                None => vec![None],
                Some(value) => match self.resolve(&value) {
                    Some(paths) => paths
                        .iter()
                        .map(|path| Some(path.to_string_lossy().into_owned()))
                        .collect(),
                    None => vec![Some(value.text)],
                },
            };
            if certain {
                self.values.xdg.clear();
                self.values.xdg_unknown = false;
            }
            add_all(&mut self.values.xdg, configs.iter().cloned());
            // Empty, its default, beside whatever the files set.
            add_all(&mut self.values.xdg, [None]);
            if let Some(given) = self.given.last_mut() {
                add_all(&mut given.values.xdg, configs.iter().cloned());
                given.xdg_first |= certain && first;
            }
            add_all(&mut self.ever.xdg, configs);
            return;
        }
        // The walk takes ZDOTDIR away nowhere: a line that does is a doubt.
        let Some(value) = value.filter(|_| name == "ZDOTDIR") else {
            return;
        };
        match self.resolve(&value) {
            Some(dirs) => {
                let dirs: Vec<Option<PathBuf>> = dirs.into_iter().map(Some).collect();
                if certain {
                    self.values.zdotdirs.clear();
                }
                add_all(&mut self.values.zdotdirs, dirs.iter().cloned());
                if let Some(given) = self.given.last_mut() {
                    add_all(&mut given.values.zdotdirs, dirs.iter().cloned());
                    given.zdotdir_first |= certain && first;
                }
                add_all(&mut self.ever.zdotdirs, dirs);
            }
            None => {
                if certain {
                    // zsh reads the user's files somewhere else now.
                    self.values.zdotdirs.clear();
                }
                self.doubt(format!(
                    "it cannot follow the ZDOTDIR that {place} sets (`{}`)",
                    value.text
                ));
            }
        }
    }

    /// Read the file the file at `place` sources as `path`, in the function
    /// `function` when in one, whose code it then runs as that one's;
    /// `certain` when zsh certainly runs the `source`. Sourced in a function,
    /// it is read for every value the files ever give `ZDOTDIR` and
    /// `XDG_CONFIG_HOME`, as the function runs later ([`Reader::late`]).
    pub(super) fn source(
        &mut self,
        path: &Word,
        certain: bool,
        function: Option<String>,
        place: &str,
    ) {
        self.known_files.push(path.text.clone());
        let later = function.is_some() || self.in_function_code();
        let files = if later {
            let late = Late::Source(path.clone(), function.clone(), place.to_string());
            self.late.push(late);
            self.resolve_ever(path)
        } else {
            self.resolve(path)
        };
        match files {
            Some(files) => {
                let one = files.len() == 1 && !later;
                for file in files {
                    self.file_in(&file, certain && one, function.clone());
                }
            }
            None => self.doubt(format!(
                "it cannot follow the file {place} sources as `{}`",
                path.text
            )),
        }
    }

    /// Read again what code that may run later names ([`Late`]), for every
    /// value the files ever gave `ZDOTDIR` and `XDG_CONFIG_HOME`, those they
    /// gave after it among them: what a function sources, a directory a
    /// function adds to `fpath` and a function's file it autoloads by its
    /// path, as zsh looks them up where the function runs. A path that is not
    /// read yet is read now, until that reads no more; one the check cannot
    /// follow for one of those values is a doubt. Whether it read or added
    /// anything.
    pub(super) fn late(&mut self) -> bool {
        let mut any = false;
        loop {
            let size = |reader: &Self| {
                (
                    reader.ever.clone(),
                    reader.read_files.len() + reader.missing.len(),
                    reader.fpath.len(),
                    reader.late.len(),
                )
            };
            let before = size(self);
            for late in self.late.clone() {
                match late {
                    Late::Source(path, function, place) => match self.resolve_ever(&path) {
                        Some(files) => {
                            for file in files {
                                if !self.has_read(&file) {
                                    self.file_in(&file, false, function.clone());
                                }
                            }
                        }
                        None => self.doubt(format!(
                            "it cannot follow the file {place} sources as `{}`",
                            path.text
                        )),
                    },
                    Late::Fpath(dir, first, place) => self.fpath_dir(&dir, first, &place, true),
                    Late::Autoload(function, place) => {
                        self.autoload_path(&function, &place, true);
                    }
                }
            }
            if size(self) == before {
                return any;
            }
            any = true;
        }
    }

    /// Whether the check read, or looked for and did not find, the file at
    /// `path`.
    pub(super) fn has_read(&self, path: &Path) -> bool {
        self.read_files
            .iter()
            .chain(&self.missing)
            .any(|(read, _)| read == path)
    }
}

/// `text` with each `pattern`, a parameter's expansion as written (`$HOME`,
/// `${HOME}`), put as `with`, but where a letter, a digit or a `_` follows a
/// `$name` form, which makes it another parameter's name (`$HOMEBREW`), or a
/// `:` or a `[`, with which zsh applies a modifier (`$HOME:a`, `$HOME:h`) or
/// a subscript (`$HOME[1,-1]`) to the value: it stays as written, a path the
/// check cannot know.
fn replace_parameter(text: &str, pattern: &str, with: &str) -> String {
    let braced = pattern.ends_with('}');
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find(pattern) {
        let after = &rest[at + pattern.len()..];
        out.push_str(&rest[..at]);
        if braced
            || !after
                .starts_with(|c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | ':' | '['))
        {
            out.push_str(with);
        } else {
            out.push_str(pattern);
        }
        rest = after;
    }
    out.push_str(rest);
    out
}
