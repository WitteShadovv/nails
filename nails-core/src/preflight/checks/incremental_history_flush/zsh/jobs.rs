// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The jobs the files start that may run on after the startup files
//! ([`walk::Event::Job`]), judged once the files are read: zsh ends on a
//! signal such a job sends it later (`SIGHUP`, `SIGALRM`, Src/signals.c) and
//! writes its history file as it ends, the lines typed so far in it. A job is
//! a doubt where its code may signal the shell, or where it runs a command by
//! a name that may be an outside program, which may signal its parent, the
//! shell, or start what does: neither a builtin of zsh's that a file does not
//! disable, one of a module zsh does not load as its name is first run aside
//! ([`builtins::unloaded`]), nor a function or an alias the files define or
//! autoload whose code, and that of each it runs, holds none of that. One
//! that may run in place of a disabled builtin is such a program
//! ([`Reader::outside`]).

use super::{Reader, Word, builtins, walk};
use crate::Filesystem;

/// A job the files start, as the reader keeps it: what names it in a
/// warning, the commands it runs by name, each with its words and whether it
/// runs as an outside program, and what in it may signal the shell
/// ([`walk::Event::Job`]).
pub(super) type Job = (String, Vec<(String, Vec<Word>, bool)>, Vec<String>);

/// The builtins that run a program or a shell of their own: `zpty`'s
/// command, and the copy of the shell `clone` starts on another terminal.
const STARTERS: &[&str] = &["zpty", "clone"];

impl<F: Filesystem> Reader<'_, F> {
    /// Note a doubt for each job the files start whose code may signal the
    /// shell ([the module](self)).
    pub(super) fn jobs(&mut self) {
        for (what, calls, stops) in std::mem::take(&mut self.jobs) {
            let why = stops.into_iter().next().or_else(|| {
                calls
                    .iter()
                    .find_map(|(name, _, outside)| self.may_signal(name, *outside, &mut Vec::new()))
            });
            if let Some(why) = why {
                self.doubt(format!(
                    "it cannot tell whether zsh writes the history file as it ends by itself, as \
                     {what} may run on after the startup files and signal the shell, on which zsh \
                     ends and writes the file: {why}"
                ));
            }
        }
    }

    /// Why the command `name` a job runs, as an outside program where
    /// `outside`, may signal the shell, as a doubt says it; `None` when it
    /// cannot ([the module](self)). `seen` holds the functions on the way,
    /// whose code is read once.
    fn may_signal(&self, name: &str, outside: bool, seen: &mut Vec<String>) -> Option<String> {
        let program = || {
            Some(format!(
                "`{name}` may be an outside program, which may signal its parent, the shell"
            ))
        };
        if outside || self.outside(name) {
            return program();
        }
        if self.defined.iter().any(|known| known == name)
            || self.autoloads.iter().any(|known| known == name)
        {
            if seen.iter().any(|known| known == name) {
                return None;
            }
            seen.push(name.to_string());
            if self.ends_in.iter().any(|function| function == name) {
                return Some(format!(
                    "`{name}` runs what may end the shell or signal its process"
                ));
            }
            let callees: Vec<String> = self
                .edges
                .iter()
                .filter(|(caller, _)| caller == name)
                .map(|(_, callee)| callee.clone())
                .collect();
            return callees
                .iter()
                .find_map(|callee| self.may_signal(callee, false, seen));
        }
        let harmless = walk::STOCK_NAMES.contains(&name)
            || ((builtins::builtin(name) || builtins::quiet(name))
                && !builtins::unloaded(name)
                && !STARTERS.contains(&name));
        if harmless { None } else { program() }
    }
}
