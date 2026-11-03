// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What the code the files define does as zsh runs it, once every file is
//! read: what the functions zsh runs as hooks write, and where the aliases
//! the files define are used.

use super::{Reader, backstop, walk};
use crate::Filesystem;

impl<F: Filesystem> Reader<'_, F> {
    /// Note what runs as zsh runs: a redirection to `$TTY` where a file may
    /// set `TTY`, an alias for an `fc` that writes nothing where a file uses
    /// it, and what the functions zsh runs as hooks write or may write.
    pub(super) fn runs(&mut self) {
        // A redirection to $TTY writes to the terminal, unless a file sets TTY.
        if let Some(set) = self.tty_set.clone() {
            for (function, place) in std::mem::take(&mut self.terminals) {
                let doubt = format!(
                    "it cannot tell where the output that `{function}` in {place} redirects to \
                     `$TTY` goes, as {set} may set TTY to name the history file"
                );
                self.in_functions.push((function, Err(doubt)));
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
                .map(|(_, text, _)| backstop::uses(text, name))
                .sum();
            let named: usize = self
                .texts
                .iter()
                .map(|file| backstop::uses(file, name))
                .sum::<usize>();
            if named > defined {
                self.doubt(format!(
                    "it cannot tell what the alias `{text}` in {place} runs where it is used, as zsh \
                     hands the fc it stands for the words after it"
                ));
            }
        }
        // What a function holds counts where zsh runs it as a hook: by its name
        // (`preexec`, `TRAPDEBUG`), as the files make it one, or as a hook runs
        // it.
        let is_hook = |function: &str, hooked: &[String]| {
            walk::HOOKS.contains(&function)
                || function.starts_with("TRAP")
                || hooked.iter().any(|hook| hook == function)
        };
        let mut hooked = self.hooks.clone();
        loop {
            let before = hooked.len();
            for (caller, callee) in &self.edges {
                if is_hook(caller, &hooked) && !is_hook(callee, &hooked) {
                    hooked.push(callee.clone());
                }
            }
            if hooked.len() == before {
                break;
            }
        }
        for (function, found) in std::mem::take(&mut self.in_functions) {
            let hook = is_hook(&function, &hooked);
            match found {
                Ok(write) if hook && !self.fc.contains(&write) => self.fc.push(write),
                Err(doubt) if hook => self.doubt(doubt),
                _ => {}
            }
        }
    }
}
