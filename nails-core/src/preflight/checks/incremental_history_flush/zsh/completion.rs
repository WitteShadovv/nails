// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What zsh may run as you complete a word (Tab, `^D`) that is no code of
//! zsh's own, once the files autoload its stock `compinit`. The check takes
//! the completion functions zsh ships for harmless, and those packages put in
//! the Nix profiles too, which `fpath` names in front of zsh's own on NixOS,
//! without reading either. So it doubts what may make zsh run code of the
//! files' own instead: a completion function, a file whose name starts with
//! `_`, in any other directory of `fpath` (`fpath=(~/zc $fpath)`), which
//! `compinit` marks to be autoloaded, and a file there named like one of
//! zsh's own functions (`compinstall`), which zsh may load in its place; a
//! completer, a completion widget's function or a `compdef`'s that is no
//! function of zsh's own, or that the files define or autoload from a file of
//! their own in place of one (`zstyle ':completion:*' completer _w`,
//! `zle -C w complete-word _w`, `compdef _w cmd`), or is code
//! (`compdef '...' cmd`); a file that sets a parameter the completion system
//! runs code or functions from, or the options it completes with
//! (`_comps[cmd]=...`, `comppostfuncs`, `compcontext`, `_comp_options`); and a
//! style whose value zsh's own completion functions may run as code
//! ([`super::walk::Event::Style`]). Every function of the files' own counts
//! as a hook there, as zsh's own completion functions run commands by name
//! as you complete a word, the one you complete among them (`ls --help` for
//! `ls <Tab>`), and functions whose names start with `_`. Without `compinit`
//! too, `compctl` and bash's `complete` (`bashcompinit`) name what zsh runs
//! as you complete a word in words the check does not read: a doubt.

use super::backstop::Forms;
use super::walk::PROFILE_DIRS;
use super::{Reader, Word};
use crate::Filesystem;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

/// The parameters of zsh's completion system that hold code it runs, or
/// pick it, as you complete a word: the completion of each command and
/// pattern, which `_dispatch` runs with `eval`, the service each command is
/// completed as, the flags of the functions marked to be autoloaded, the
/// functions `_main_complete` runs before and after it completes, the code
/// it runs first, the context `_complete` completes in instead, whose action
/// it runs with `eval`, the function `_tags` sorts the tags with, and the
/// options it completes with, which may make it expand an alias in the code
/// it runs with `eval` (`aliases`): all of them but `_comp_options+=(globdots)`,
/// with which it completes the files whose names start with a dot.
const PARAMETERS: [&str; 11] = [
    "_comps",
    "_patcomps",
    "_postpatcomps",
    "_services",
    "_compautos",
    "compprefuncs",
    "comppostfuncs",
    "_comp_setup",
    "compcontext",
    "_sort_tags",
    "_comp_options",
];

/// How many of a directory's completion functions a doubt names.
const SHOWN: usize = 3;

/// What the files hold that zsh's completion system may run, as they are
/// read ([`Reader::completions`]).
#[derive(Debug, Default)]
pub(super) struct Seen {
    /// The functions named where the completion system runs them, as
    /// written, what names each and where
    /// ([`super::walk::Event::Completes`]).
    names: Vec<(Word, String, String)>,
    /// The parameters of [`PARAMETERS`] a file sets, and where.
    parameters: Vec<(&'static str, String)>,
    /// The doubts of the styles the files set ([`super::walk::Event::Style`]).
    styles: Vec<String>,
    /// The functions the files define by name, each beside the file that
    /// defines it, and those they autoload, each beside its file
    /// ([`super::walk::Event::Function`]).
    functions: Vec<(String, PathBuf)>,
}

impl Seen {
    /// Note `function`, which `what` in the file at `place` gives the
    /// completion system to run.
    pub(super) fn completes(&mut self, function: Word, what: String, place: &str) {
        self.names.push((function, what, place.to_string()));
    }

    /// Note the parameters of [`PARAMETERS`] that `forms`, of the file at
    /// `place` whose code is `text`, name otherwise than to read them, in any
    /// form zsh may read a word in, beyond the lines of `text` that are
    /// `_comp_options+=(globdots)` alone.
    pub(super) fn parameters(&mut self, text: &str, forms: &Forms, place: &str) {
        for name in PARAMETERS {
            let entry = (name, place.to_string());
            let allowed = if name == "_comp_options" {
                text.lines().filter(|line| globdots(line)).count()
            } else {
                0
            };
            if forms.writes(name) > allowed && !self.parameters.contains(&entry) {
                self.parameters.push(entry);
            }
        }
    }

    /// Note `doubt`, of a style a file sets ([`super::walk::Event::Style`]).
    pub(super) fn style(&mut self, doubt: String) {
        if !self.styles.contains(&doubt) {
            self.styles.push(doubt);
        }
    }

    /// Note the function `name` that the file at `place` defines, or whose
    /// code it is, autoloaded.
    pub(super) fn function(&mut self, name: String, place: &str) {
        let entry = (name, PathBuf::from(place));
        if !self.functions.contains(&entry) {
            self.functions.push(entry);
        }
    }
}

/// Whether `line` adds no option but `GLOB_DOTS` to those zsh's completion
/// system completes with: `_comp_options+=(globdots)`, in any of the
/// option's spellings, alone on the line.
fn globdots(line: &str) -> bool {
    line.trim()
        .strip_prefix("_comp_options+=(")
        .and_then(|rest| rest.strip_suffix(')'))
        .is_some_and(|option| {
            let option: String = option.trim().chars().filter(|c| *c != '_').collect();
            option.eq_ignore_ascii_case("globdots")
        })
}

/// The word a `compdef` of `args` gives the completion system to run, as
/// the stock `compinit`'s `compdef` reads its words: past its options, which
/// its `getopts anpPkKde` takes from the words that start with `-` or `+` up
/// to a lone `-` or a `--` (a `+` one sets none of them), the first word,
/// unless it deletes (`-d`) or, without `-e`, maps commands to another's
/// completion (`cmd=service`). `Err` with a word up to it that an expansion,
/// brace expansion or a glob may make other words of.
fn compdef_function(args: &[Word]) -> Result<Option<&Word>, &Word> {
    let mut flags = String::new();
    let mut words = args.iter();
    let function = loop {
        let Some(word) = words.next() else {
            return Ok(None);
        };
        if word.expands || word.bare {
            return Err(word);
        }
        if word.text == "--" {
            break words.next();
        }
        match (word.text.strip_prefix('-'), word.text.strip_prefix('+')) {
            (Some(letters), _) if !letters.is_empty() => flags.push_str(letters),
            (_, Some(letters)) if !letters.is_empty() => {}
            _ => break Some(word),
        }
    };
    match function {
        Some(word) if word.expands || word.bare => Err(word),
        Some(word) if !flags.contains('d') && (flags.contains('e') || !word.text.contains('=')) => {
            Ok(Some(word))
        }
        _ => Ok(None),
    }
}

/// `names`, each in backquotes, the first [`SHOWN`] of them and how many
/// more.
fn shown(names: &[String]) -> String {
    let listed: Vec<String> = names
        .iter()
        .take(SHOWN)
        .map(|name| format!("`{name}`"))
        .collect();
    match names.len().saturating_sub(SHOWN) {
        0 => listed.join(", "),
        more => format!("{} and {more} more", listed.join(", ")),
    }
}

impl<F: Filesystem> Reader<'_, F> {
    /// Note what zsh may run as you complete a word that is no code of
    /// zsh's own ([`super::completion`]), once the files are read.
    pub(super) fn completions(&mut self) {
        for (name, args, place) in self.calls.clone() {
            if matches!(name.as_str(), "compctl" | "complete") {
                let words: Vec<&str> = args.iter().map(|arg| arg.text.as_str()).collect();
                self.doubt(format!(
                    "it cannot tell what `{name} {}` in {place} makes zsh run as you complete a \
                     word",
                    words.join(" ")
                ));
            }
        }
        if !self.compinit {
            return;
        }
        let stock = self.stock_names();
        self.own_completion_dirs(&stock);
        // The functions of the files' own: those they define, and those they
        // autoload from a file outside zsh's own directory and the Nix
        // profiles'.
        let own: Vec<String> = std::mem::take(&mut self.completion.functions)
            .into_iter()
            .filter(|(_, file)| !file.parent().is_some_and(|dir| self.exempt(dir)))
            .map(|(name, _)| name)
            .collect();
        let mut named = std::mem::take(&mut self.completion.names);
        for (name, args, place) in self.calls.clone() {
            if name != "compdef" {
                continue;
            }
            let words: Vec<&str> = args.iter().map(|arg| arg.text.as_str()).collect();
            let what = format!("compdef {}", words.join(" "));
            match compdef_function(&args) {
                Ok(Some(function)) => named.push((function.clone(), what, place)),
                Ok(None) => {}
                Err(word) => self.doubt(format!(
                    "it cannot tell which function `{what}` in {place} makes zsh run as you \
                     complete a word, as zsh may expand `{}` into other words",
                    word.text
                )),
            }
        }
        for (function, what, place) in named {
            if function.expands || function.bare {
                self.doubt(format!(
                    "it cannot tell which function `{what}` in {place} makes zsh run as you \
                     complete a word"
                ));
            } else if !stock.contains(&function.text)
                || self.defined.contains(&function.text)
                || own.contains(&function.text)
            {
                self.doubt(format!(
                    "it cannot tell what `{}`, which `{what}` in {place} makes zsh run as you \
                     complete a word, writes, as it is no completion function of zsh's own",
                    function.text
                ));
            }
        }
        // zsh's own completion functions run commands by name as you complete
        // a word, the one you complete among them (`_ls` runs `ls --help`),
        // and functions by names that start with `_`, so a function of the
        // files' own may run there as a hook would.
        for name in own {
            if !self.hooks.contains(&name) {
                self.hooks.push(name);
            }
        }
        for doubt in std::mem::take(&mut self.completion.styles) {
            self.doubt(doubt);
        }
        for (name, place) in std::mem::take(&mut self.completion.parameters) {
            self.doubt(format!(
                "it cannot tell what {place} makes zsh run as you complete a word, as it sets \
                 `{name}`, which zsh's completion system runs code or functions from"
            ));
        }
    }

    /// The names of the files in zsh's own function directory
    /// ([`super::Install::functions`]), its completion functions among them;
    /// none when the check cannot tell where that is, or read it.
    fn stock_names(&self) -> Vec<String> {
        let Some(dir) = self.install.functions.as_ref() else {
            return Vec::new();
        };
        self.fs
            .list_directory(dir)
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(|entry| entry.file_name()?.to_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Note a doubt for each directory of `fpath` that is neither zsh's own
    /// nor a Nix profile's ([`Reader::exempt`]) and holds a completion
    /// function, a file whose name starts with `_`, which `compinit` marks to
    /// be autoloaded and zsh then runs as you complete a word (a `#compdef`
    /// first line names the commands it completes) or in place of one of
    /// zsh's own of its name, or a file named like one of zsh's own functions
    /// (`stock`, `compinstall`, `zmv`), which zsh may load in its place where
    /// its own code runs that one by name, and for each such directory the
    /// check could not read.
    fn own_completion_dirs(&mut self, stock: &[String]) {
        let mut dirs: Vec<PathBuf> = Vec::new();
        for entry in &self.fpath {
            if let Ok((dir, _)) = entry
                && !dirs.contains(dir)
                && !self.exempt(dir)
            {
                dirs.push(dir.clone());
            }
        }
        for dir in dirs {
            match self.fs.list_directory(&dir) {
                Ok(entries) => {
                    let mut names: Vec<String> = entries
                        .iter()
                        .filter_map(|entry| entry.file_name())
                        .filter(|name| name.as_encoded_bytes().starts_with(b"_"))
                        .map(|name| name.to_string_lossy().into_owned())
                        .collect();
                    let mut shadows: Vec<String> = entries
                        .iter()
                        .filter_map(|entry| entry.file_name()?.to_str())
                        .filter(|name| {
                            !name.starts_with('_') && stock.iter().any(|own| own == name)
                        })
                        .map(str::to_string)
                        .collect();
                    names.sort();
                    shadows.sort();
                    if !names.is_empty() {
                        self.doubt(format!(
                            "it cannot tell what the completion functions in {} write ({}), \
                             which zsh runs as you complete a word once compinit marks them, as \
                             that directory of fpath is neither zsh's own nor a Nix profile's",
                            dir.display(),
                            shown(&names)
                        ));
                    }
                    if !shadows.is_empty() {
                        self.doubt(format!(
                            "it cannot tell what the functions in {} write ({}), which zsh may \
                             run in place of zsh's own of their names where its own code runs \
                             one by name, as that directory of fpath is neither zsh's own nor a \
                             Nix profile's",
                            dir.display(),
                            shown(&shadows)
                        ));
                    }
                }
                Err(error)
                    if matches!(
                        error.io_kind(),
                        Some(ErrorKind::NotFound | ErrorKind::NotADirectory)
                    ) => {}
                Err(error) => self.doubt(format!(
                    "it could not read the directory {} of fpath ({}), where compinit may find \
                     completion functions that zsh runs as you complete a word",
                    dir.display(),
                    error
                        .io_kind()
                        .map_or_else(|| error.to_string(), |kind| kind.to_string())
                )),
            }
        }
    }

    /// Whether `dir`, a directory of `fpath`, is zsh's own function
    /// directory or one of a Nix profile that NixOS's `/etc/zshenv` puts in
    /// `fpath` ([`PROFILE_DIRS`]), of a profile `NIX_PROFILES` names, that
    /// leads into the Nix store: the completion functions there are zsh's own
    /// or those packages put there.
    fn exempt(&self, dir: &Path) -> bool {
        if self.install.functions.as_deref() == Some(dir) {
            return true;
        }
        let Some(profiles) = self.profiles.as_ref() else {
            return false;
        };
        let version = self
            .install
            .version
            .as_deref()
            .filter(|_| !self.version_set);
        let profile = profiles.iter().any(|profile| {
            PROFILE_DIRS.iter().any(|rest| {
                let rest = version.map_or_else(
                    || (*rest).to_string(),
                    |version| rest.replace("$ZSH_VERSION", version),
                );
                !rest.contains('$') && Path::new(&format!("{profile}{rest}")) == dir
            })
        });
        profile
            && self
                .fs
                .canonicalize(dir)
                .is_ok_and(|real| real.starts_with("/nix/store"))
    }
}
