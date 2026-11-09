// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What zsh may run as you complete a word (Tab, `^D`) that the check does
//! not read. A function named `compinit` that zsh may load, whatever its
//! bytes, starts zsh's completion system, whose own functions run what
//! programs print as code (`_comp_locale` evaluates what `locale` prints,
//! `_npm` what `npm` prints), parse the help that programs print into the
//! code they run (`_arguments --`), and run code from the specifications,
//! styles, parameters and files they read. Which programs and settings may
//! change what those functions run, tools every system has among them (`tar`
//! through `LANGUAGE`, `bash` through `BASH_ENV`), cannot all be listed, so
//! wherever zsh may load one, it is a doubt. Without `compinit` too,
//! `compctl` and bash's `complete` (`bashcompinit`) name what zsh runs as you
//! complete a word in words the check does not read: a doubt.

use super::Reader;
use crate::Filesystem;

impl<F: Filesystem> Reader<'_, F> {
    /// Note that zsh may load a `compinit` the files autoload, which starts
    /// its completion system ([`super::completion`]).
    pub(super) fn completion_system(&mut self) {
        self.doubt(
            "it cannot tell what zsh runs as you complete a word, as the files autoload \
             compinit, which starts zsh's completion system, whose own functions run what \
             programs print as code, and the programs and settings that may change what they \
             print cannot all be listed"
                .to_string(),
        );
    }

    /// Note a doubt for each `compctl` and `complete` the files run, which
    /// name what zsh runs as you complete a word ([`super::completion`]).
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
    }
}
