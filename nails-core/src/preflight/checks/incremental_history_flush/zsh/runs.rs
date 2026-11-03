// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What the code the files define does as zsh runs it, once every file is
//! read: where the redirections the files make write, what the functions
//! zsh runs as hooks write or may write, and where the aliases the files
//! define are used.

use super::{Forms, Reader, Word, backstop, builtins, walk};
use crate::Filesystem;

/// The commands that print what they read and write no file but where a
/// word names one (`sort -o file`), as a global alias feeds them
/// (`alias -g G='| grep'`).
const FILTERS: &[&str] = &[
    "grep", "egrep", "fgrep", "rg", "ag", "less", "more", "most", "head", "tail", "sort", "uniq",
    "wc", "cut", "tr", "column", "fmt", "fold", "nl", "cat", "bat", "jq", "yq", "tac", "rev",
    "xclip", "xsel", "wl-copy", "pbcopy",
];

/// Whether a word of `args`, the words the command `command` is given, may
/// name a file it writes: one an expansion makes or a path (`~/.zlog`,
/// `of=/x`), and for a command that is no filter ([`FILTERS`]) any word but
/// an option (`tee zlog`).
pub(super) fn names_file(command: &str, args: &[Word]) -> bool {
    let filter = FILTERS.contains(&command);
    args.iter().any(|arg| {
        arg.expands
            || arg.text.contains('/')
            || arg.text.starts_with('~')
            || (!filter && !arg.text.starts_with('-'))
    })
}

/// How a command a function runs may write what the shell's code gives it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Fed {
    /// An expansion makes a word it is given, which may name the history
    /// file (`tee -a $f`).
    Word,
    /// It reads what an expansion makes ([`walk::Input::Computed`]).
    Input,
    /// It reads what the commands before it in its pipeline write, each
    /// one's name and whether an expansion makes a word of it
    /// ([`walk::Input::Piped`]).
    Pipe(Vec<(String, bool)>),
}

/// Whether `target`, a redirection's target as written, is a device that
/// is no file: the terminal (`/dev/tty`, `$TTY`), nothing (`/dev/null`), or
/// a descriptor the shell has open (`/dev/stderr`, `/dev/fd/2`).
fn device(target: &str) -> bool {
    let descriptor = |rest: Option<&str>| {
        rest.is_some_and(|rest| !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()))
    };
    matches!(
        target,
        "/dev/null" | "/dev/tty" | "/dev/stdout" | "/dev/stderr" | "/dev/stdin" | "$TTY" | "${TTY}"
    ) || descriptor(target.strip_prefix("/dev/fd/"))
        || descriptor(target.strip_prefix("/proc/self/fd/"))
}

impl<F: Filesystem> Reader<'_, F> {
    /// Note a redirection to `target`, as written, in the function `function`
    /// when in one, by the file at `place`: one to the history file by its
    /// name writes it; one to a device writes no file while no global alias
    /// may stand for it, nor `$TTY` while no file sets `TTY`
    /// ([`Reader::devices`]). One whose target an expansion makes
    /// (`computed`), or that is any other file, which may be the history file
    /// (one `HISTFILE` names, a link to it), is a doubt where an `exec` keeps
    /// it open (`kept`), as a hook may write to the descriptor, and where a
    /// hook makes it.
    pub(super) fn redirect(
        &mut self,
        target: &str,
        function: Option<String>,
        computed: bool,
        kept: bool,
        place: &str,
    ) {
        if backstop::history_path(target) {
            let what = format!("{place} redirects output to `{target}`");
            if !self.fc.contains(&what) {
                self.fc.push(what);
            }
            return;
        }
        let terminal = matches!(target, "$TTY" | "${TTY}");
        if device(target) && !(kept && terminal) {
            if kept || function.is_some() {
                self.devices.push((
                    function.filter(|_| !kept),
                    target.to_string(),
                    place.to_string(),
                ));
            }
            return;
        }
        if kept {
            self.doubt(format!(
                "it cannot tell where the descriptor that `exec` in {place} opens to `{target}` \
                 goes, which may be the history file a hook writes each command line to"
            ));
        } else if let Some(function) = function {
            let doubt = if computed {
                format!(
                    "it cannot tell where the output that `{function}` in {place} redirects to \
                     `{target}` goes, which may be the history file"
                )
            } else {
                format!(
                    "it cannot tell whether `{target}`, which `{function}` in {place} redirects \
                     output to, is the history file (a file HISTFILE names, or a link to it)"
                )
            };
            self.in_functions.push((function, Err(doubt)));
        }
    }

    /// Whether a function named `function` is one zsh runs as a hook: by its
    /// name (`preexec`, `TRAPDEBUG`), as the dispatcher that the stock
    /// `add-zle-hook-widget` runs as each line is entered (`azhw:...`), as
    /// the files make it one or a hook runs it (`hooked`), or as it is named
    /// like a builtin, which zsh's own code runs as each line is entered
    /// (`zstyle`, `zle`).
    fn is_hook(function: &str, hooked: &[String]) -> bool {
        walk::HOOKS.contains(&function)
            || builtins::builtin(function)
            || function.starts_with("TRAP")
            || function.starts_with("azhw:")
            || hooked.iter().any(|hook| hook == function)
    }

    /// Note what runs as zsh runs: a redirection to a device a global alias
    /// may stand for, or to `$TTY` where a file may set `TTY`; an alias for an
    /// `fc` that writes nothing where a file uses it; what the functions zsh
    /// runs as hooks write or may write; and what may change NixOS's
    /// dircolors line ([`Reader::dircolors_doubts`]).
    pub(super) fn runs(&mut self) {
        // A redirection to a device writes no file, unless a global alias
        // stands for its target, or a file sets TTY.
        for (function, target, place) in std::mem::take(&mut self.devices) {
            let terminal = matches!(target.as_str(), "$TTY" | "${TTY}");
            let why = if let Some(set) = self.tty_set.clone().filter(|_| terminal) {
                format!("{set} may set TTY to name the history file")
            } else if let Some(alias) = self
                .global_aliases
                .iter()
                .find(|alias| alias.is_empty() || **alias == target)
            {
                format!("a file defines the global alias `{alias}`, which may stand for it")
            } else {
                continue;
            };
            let doubt = format!(
                "it cannot tell where the output that {} in {place} redirects to `{target}` \
                 goes, as {why}",
                function
                    .as_ref()
                    .map_or_else(|| "`exec`".to_string(), |function| format!("`{function}`"))
            );
            match function {
                Some(function) => self.in_functions.push((function, Err(doubt))),
                None => self.doubt(doubt),
            }
        }
        // An alias for an fc that writes nothing hands it the words it is used
        // with: harmless while no file uses its name but where it is defined.
        let mut aliases = std::mem::take(&mut self.fc_aliases);
        aliases.sort();
        aliases.dedup();
        for (name, text, place) in &aliases {
            // Each definition names it as often as its own words do; one
            // written twice alike counts once, so the second is a use.
            let defined: usize = aliases
                .iter()
                .filter(|(other, ..)| other == name)
                .map(|(_, text, _)| Forms::of(text).uses(name))
                .sum();
            let named: usize = self
                .texts
                .iter()
                .map(|forms| forms.uses(name))
                .sum::<usize>();
            if named > defined {
                self.doubt(format!(
                    "it cannot tell what the alias `{text}` in {place} runs where it is used, as zsh \
                     hands the fc it stands for the words after it"
                ));
            }
        }
        // What a function holds counts where zsh runs it as a hook: by its name,
        // as the files make it one, as a hook runs it, or as it is named like a
        // builtin.
        let mut hooked = self.hooks.clone();
        loop {
            let before = hooked.len();
            for (caller, callee) in &self.edges {
                if Self::is_hook(caller, &hooked) && !Self::is_hook(callee, &hooked) {
                    hooked.push(callee.clone());
                }
            }
            if hooked.len() == before {
                break;
            }
        }
        for (function, found) in std::mem::take(&mut self.in_functions) {
            let hook = Self::is_hook(&function, &hooked);
            match found {
                Ok(write) if hook && !self.fc.contains(&write) => self.fc.push(write),
                Err(doubt) if hook => self.doubt(doubt),
                _ => {}
            }
        }
        // A command a hook runs with a word an expansion makes may write the
        // file that word names (`tee -a $f`), and one that reads what the
        // shell's code gives it may write that, the command line among it
        // (`print -r -- "$1" | tee -a file`), unless it is a function or an
        // alias the check reads, or a builtin that writes no file.
        for (function, command, place, fed, names_file) in std::mem::take(&mut self.computed_calls)
        {
            if !Self::is_hook(&function, &hooked)
                || self.defined.contains(&command)
                || self.autoloads.contains(&command)
                || builtins::quiet(&command)
            {
                continue;
            }
            // A global alias's value that feeds a command what comes before
            // the alias where it is used (`alias -g G='| grep'`) runs as a
            // hook only where a hook uses it: one that writes to a file a word
            // names (`| tee -a file`) may write the command line there.
            if function.starts_with("alias ") && fed != Fed::Word && !names_file {
                continue;
            }
            let what = match fed {
                Fed::Word => {
                    "as an expansion makes a word it is given, which may name the \
                              history file"
                }
                Fed::Pipe(feeders) if !self.carries(&feeders) => continue,
                Fed::Input | Fed::Pipe(_) => {
                    "as it reads what the shell gives it, which may \
                                             be the command line"
                }
            };
            self.doubt(format!(
                "it cannot tell what `{command}` in `{function}` in {place} writes, {what}"
            ));
        }
        self.dircolors_doubts();
    }

    /// Whether the commands that feed a pipeline, `feeders`, each one's name
    /// and whether an expansion makes a word of it, may write the command
    /// line into it: one an expansion makes a word of (`print -r -- "$1"`),
    /// an `fc` or a `history` that lists the history, a function or an alias
    /// the files define, which may print anything; any when the check does
    /// not know them (none listed). A command the files do not define given
    /// only words as written writes nothing of the command line.
    fn carries(&self, feeders: &[(String, bool)]) -> bool {
        feeders.is_empty()
            || feeders.iter().any(|(name, expands)| {
                *expands
                    || matches!(name.as_str(), "fc" | "history" | "r")
                    || self.defined.contains(name)
                    || self.autoloads.contains(name)
            })
    }
}
