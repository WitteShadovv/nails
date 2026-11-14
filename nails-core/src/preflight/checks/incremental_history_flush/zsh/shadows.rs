// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What may change what NixOS's dircolors line in `/etc/zshrc` runs,
//! `eval "$(/nix/store/<hash>-coreutils-<version>/bin/dircolors -b)"`, which
//! the check reads as harmless ([`super::install::dircolors_split`]) only
//! while nothing that runs before it may change what it runs: an alias of
//! any kind, which zsh expands in its words and in what `eval` reads; a
//! function named `eval`, `export` or like its program, or one whose name an
//! expansion makes; a `TRAP...` function or a `trap`, which zsh runs inside
//! the command substitution and whose output `eval` then reads; a
//! `disable`, after which `eval` may be another command; and an `LD_`
//! variable of the dynamic loader or `ARGV0`, the name zsh gives every program
//! it runs, which picks the program a multi-call coreutils runs, each set by
//! a file or held by the shell's environment, which may make the program
//! print other code. And what may change what a builtin runs by which the walk
//! reads a setting ([`SETTERS`]): a function or a regular alias of its name,
//! and a `disable` of it, are doubts wherever the files read define them.

use super::Reader;
use super::backstop::Forms;
use super::walk::may_expand;
use crate::Filesystem;

/// What a file read may change what a later command runs with: what the
/// warning names, the function named when it defines or autoloads one, and
/// the function whose code the file is, when it is one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Changer {
    what: String,
    function: Option<String>,
    outer: Option<String>,
}

/// What came before a dircolors line the check took as known: how many
/// changers, autoloaded functions, commands run by name and hooks the files
/// read had noted, where the line is, and the program it runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Snapshot {
    changers: usize,
    autoloads: usize,
    calls: usize,
    hooks: usize,
    place: String,
    program: String,
}

/// The builtins and precommands by which the walk reads a parameter as set,
/// declared or taken away (`export ZDOTDIR=...`, `unset XDG_CONFIG_HOME`) or a
/// file as sourced. A regular alias of such a name runs in its place (`alias
/// export=:`, zsh 5.9 to 5.9.2 then set nothing), and so does a function of a
/// name that is no reserved word, or one `disable -r` takes away (`unset() {
/// }`, `source() { }`), and after a `disable` of it zsh runs what PATH finds,
/// so the setting the walk read need not happen.
const SETTERS: &[&str] = &[
    "typeset",
    "export",
    "declare",
    "local",
    "readonly",
    "integer",
    "float",
    "private",
    "unset",
    "source",
    ".",
    "builtin",
    "command",
    "noglob",
    "nocorrect",
    "exec",
    "time",
];

/// Whether a function named `name` changes what the dircolors line that
/// runs `program` runs: one named `eval` or `export`, which it runs, or
/// like `program`, a `TRAP...` function, which zsh may run in its command
/// substitution, or one zsh may expand into another (`$n`, `{a,b}`, a glob,
/// `=dircolors`), which may be any.
fn changes(name: &str, program: &str) -> bool {
    matches!(name, "eval" | "export")
        || name == program
        || name.starts_with("TRAP")
        || may_expand(name)
}

impl<F: Filesystem> Reader<'_, F> {
    /// Note what the forms of a file's code at `place`, the code of the
    /// function `outer` when it is one, may change what a later command runs
    /// with ([`super::shadows`]): an alias, a `disable`, a `trap` and an `LD_`
    /// variable they set.
    pub(super) fn shadows(&mut self, forms: &Forms, place: &str, outer: Option<&str>) {
        for what in forms.shadows() {
            self.changers.push(Changer {
                what: format!("{place} {what}"),
                function: None,
                outer: outer.map(str::to_string),
            });
        }
    }

    /// Note a doubt where `what` (`/etc/zshenv defines a function or an
    /// alias`) is named `name`, like a builtin by which the walk reads a
    /// setting ([`SETTERS`]), or where an expansion may make the name, as it
    /// then runs in that builtin's place.
    pub(super) fn shadow_setter(&mut self, name: &str, what: &str) {
        if SETTERS.contains(&name) || may_expand(name) {
            self.doubt(format!(
                "it cannot tell what the files set where they run `{name}`, as {what} `{name}`, \
                 which zsh runs in place of the builtin of that name"
            ));
        }
    }

    /// Note a doubt where a `disable` at `place` may take away a builtin by
    /// which the walk reads a setting ([`SETTERS`]), the patterns of its names
    /// `patterns`, as zsh then runs what PATH finds by that name.
    pub(super) fn disable_setters(&mut self, patterns: &[String], place: &str) {
        let names: Vec<&str> = SETTERS
            .iter()
            .copied()
            .filter(|name| {
                patterns
                    .iter()
                    .any(|pattern| super::walk::may_match(pattern, name))
            })
            .collect();
        if !names.is_empty() {
            self.doubt(format!(
                "it cannot tell what the files set where they run `{}`, as a `disable` in \
                 {place} may take that builtin away, after which zsh runs what PATH finds by its \
                 name",
                names.join("`, `")
            ));
        }
    }

    /// Note `what`, which a file read defines, as what may change what any
    /// later command runs.
    pub(super) fn shadow(&mut self, what: String) {
        let outer = self.outers.last().cloned().flatten();
        self.changers.push(Changer {
            what,
            function: None,
            outer,
        });
    }

    /// Note the function `name` that the file at `place` defines or
    /// autoloads (`verb`), which may change what a later command runs.
    pub(super) fn shadow_function(&mut self, name: &str, place: &str, verb: &str) {
        let outer = self.outers.last().cloned().flatten();
        self.changers.push(Changer {
            what: format!("{place} {verb} the function `{name}`"),
            function: Some(name.to_string()),
            outer,
        });
    }

    /// Note that the dircolors line of the file at `place`, which runs
    /// `program`, comes next: what the files read so far noted runs before
    /// it.
    pub(super) fn snapshot(&mut self, place: &str, program: String) {
        self.dircolors.push(Snapshot {
            changers: self.changers.len(),
            autoloads: self.autoloads.len(),
            calls: self.calls.len(),
            hooks: self.hooks.len(),
            place: place.to_string(),
            program,
        });
    }

    /// The functions that may run before the dircolors line `snapshot`
    /// says came next: those autoloaded, run by name or made hooks before
    /// it, and those each of them runs or autoloads, as far as they go.
    fn run_before(&self, snapshot: &Snapshot) -> Vec<String> {
        let mut before: Vec<String> = self.autoloads[..snapshot.autoloads]
            .iter()
            .chain(self.calls[..snapshot.calls].iter().map(|(name, ..)| name))
            .chain(&self.hooks[..snapshot.hooks])
            .cloned()
            .collect();
        loop {
            let known = before.len();
            for (caller, callee) in self.edges.iter().chain(&self.autoloaded_by) {
                if before.contains(caller) && !before.contains(callee) {
                    before.push(callee.clone());
                }
            }
            if before.len() == known {
                return before;
            }
        }
    }

    /// Note a doubt for each dircolors line the check took as known that
    /// what runs before it may change ([`super::shadows`]): what the files
    /// read before it noted, and what the files of the functions that may
    /// run before it, which the check reads once the startup files are,
    /// noted.
    pub(super) fn dircolors_doubts(&mut self) {
        // What the shell's environment holds that may change what any program
        // it runs prints: ARGV0, the name zsh gives it, which picks the
        // program a multi-call coreutils runs, and a variable of the dynamic
        // loader; one the check does not know may hold either.
        let env = self.install.env.as_ref();
        let environment = match env {
            None => Some("the check does not know the shell's environment, which may set ARGV0"),
            Some(env) if env.argv0.is_some() => {
                Some("the shell's environment sets ARGV0, which names the program coreutils runs")
            }
            Some(env) if env.loader => {
                Some("the shell's environment sets a variable of the dynamic loader (`LD_...`)")
            }
            Some(_) => None,
        };
        for snapshot in self.dircolors.clone() {
            if let Some(why) = environment {
                self.doubt(format!(
                    "it cannot tell what the `eval` of what dircolors prints in {} runs, as {why}",
                    snapshot.place
                ));
                continue;
            }
            let before = self.run_before(&snapshot);
            let found = self.changers.iter().enumerate().find(|(at, changer)| {
                let runs_before = *at < snapshot.changers
                    || (*at >= self.startup_changers
                        && changer
                            .outer
                            .as_ref()
                            .is_none_or(|outer| before.contains(outer)));
                runs_before
                    && changer
                        .function
                        .as_ref()
                        .is_none_or(|name| changes(name, &snapshot.program))
            });
            if let Some((_, changer)) = found {
                let doubt = format!(
                    "it cannot tell what the `eval` of what dircolors prints in {} runs, as {} \
                     before it, which may change what it runs",
                    snapshot.place, changer.what
                );
                self.doubt(doubt);
            }
        }
    }
}
