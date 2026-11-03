// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The descriptors a file's code keeps open or writes to, as the walk reads
//! them: `sysopen` to write and `zsystem flock` keep one open on a file, and
//! `zsocket` and `ztcp` one to another process, which a hook may write each
//! command line to; in a function, a write to a descriptor above 2
//! (`print -u 7`, `>&7`) goes to whatever file the shell has open there.

use super::super::lexer::Word;
use super::names::{computed, option_arguments};
use super::{Event, Walker};

impl Walker<'_> {
    /// The events of a `sysopen` of `args` (zsh/system): one that opens its
    /// file to write (`-w`, `-a`) keeps the descriptor open as `exec 3>>file`
    /// does, which a hook may write each command line to.
    pub(super) fn sysopen(&mut self, args: &[Word]) {
        let mut writes = false;
        let mut words = args.iter();
        let mut file = None;
        while let Some(word) = words.next() {
            match word.text.strip_prefix('-') {
                Some(flags) if !flags.is_empty() && !word.expands => {
                    writes |= flags.contains(['w', 'a']);
                    // `-u`, `-o` and `-m` take the word after them, unless
                    // the rest of theirs.
                    if let Some(at) = flags.find(['u', 'o', 'm'])
                        && at + 1 == flags.len()
                    {
                        words.next();
                    }
                }
                Some(_) => writes = true,
                None => file = Some(word),
            }
            if word.expands {
                writes = true;
            }
        }
        if let Some(file) = file.filter(|_| writes) {
            self.kept(file);
        }
    }

    /// Note that the code keeps a descriptor open on the file `file` names,
    /// which a hook may write each command line to.
    fn kept(&mut self, file: &Word) {
        self.events.push(Event::Redirect {
            computed: computed(file),
            function: self.function(),
            target: file.text.clone(),
            kept: true,
        });
    }

    /// The events of a `zsystem` of `args` (zsh/system): `zsystem flock`
    /// opens the file it names, its last word, and keeps the descriptor,
    /// unless `-u` unlocks one.
    pub(super) fn zsystem(&mut self, args: &[Word]) {
        for arg in args {
            self.mention(&arg.text);
        }
        if args.first().is_none_or(|sub| sub.text != "flock")
            || args[1..]
                .iter()
                .any(|arg| arg.text.starts_with('-') && arg.text.contains('u'))
        {
            return;
        }
        if let Some(file) = args[1..].last().filter(|file| !file.text.starts_with('-')) {
            self.kept(file);
        }
    }

    /// The events of a `zsocket` or `ztcp` (`command`) of `args`, which
    /// open a connection to another process and keep its descriptor: what a
    /// hook writes to it, that process may write to any file.
    pub(super) fn connection(&mut self, command: &str, args: &[Word]) {
        for arg in args {
            self.mention(&arg.text);
        }
        let words: Vec<&str> = args.iter().map(|arg| arg.text.as_str()).collect();
        self.events.push(Event::Doubt(format!(
            "it cannot tell where the connection that `{command} {}` in {} opens goes, which a \
             hook may write each command line to",
            words.join(" "),
            self.place
        )));
    }

    /// In a function, note the descriptor `print -u` writes to among `args`
    /// when it is not standard output or error: it may be any file the
    /// shell has open, which a hook may write each command line to.
    pub(super) fn print_descriptor(&mut self, args: &[Word]) {
        let Some(function) = self.function() else {
            return;
        };
        for descriptor in option_arguments(args, "CfuvxX", "u") {
            if computed(&descriptor) || !matches!(descriptor.text.as_str(), "1" | "2") {
                self.events.push(Event::HookDoubt {
                    doubt: format!(
                        "it cannot tell where the descriptor `{}` that `print -u` in `{function}` \
                         in {} writes to goes, which may be any file the shell has open",
                        descriptor.text, self.place
                    ),
                    function: function.clone(),
                });
            }
        }
    }

    /// Note a redirection that duplicates the descriptor `target`, a number,
    /// for output (`>&7`): one above 2 may be any file the shell has open,
    /// which a hook may write each command line to, in a function and where
    /// an `exec` keeps it (`kept`) for every command after it.
    pub(super) fn duplicated(&mut self, target: &str, kept: bool) {
        if target.parse::<u64>().is_ok_and(|fd| fd < 3) {
            return;
        }
        if kept {
            self.events.push(Event::Doubt(format!(
                "it cannot tell where the descriptor `{target}` that `exec` in {} sends output \
                 to goes, which may be the history file a hook writes each command line to",
                self.place
            )));
        } else if let Some(function) = self.function() {
            self.events.push(Event::HookDoubt {
                doubt: format!(
                    "it cannot tell where the descriptor `{target}` that `{function}` in {} \
                     writes to goes, which may be any file the shell has open",
                    self.place
                ),
                function,
            });
        }
    }
}
