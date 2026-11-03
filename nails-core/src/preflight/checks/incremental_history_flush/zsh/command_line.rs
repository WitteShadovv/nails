// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What the command line of a zsh tells: how it reads its startup files
//! ([`Start`]), the options it turns on, and what the check cannot tell of
//! it ([`CommandLine`]).

use super::super::startup::Write;
use super::{OPTIONS, walk};
use std::path::Path;

/// What the check knows of how a zsh was started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in super::super) struct Start {
    /// Whether it is a login shell, which reads `zprofile` and `zlogin`;
    /// `None` when the check cannot tell.
    pub login: Option<bool>,
    /// Whether it reads more than `zshenv` in `/etc`, as it does without
    /// `-f` (zsh's `RCS` option).
    pub rcs: bool,
    /// Whether it reads the files in `/etc` other than `zshenv`, as it does
    /// without `-d` (zsh's `GLOBAL_RCS` option).
    pub global_rcs: bool,
}

impl Start {
    /// How the zsh started as `argv` reads its startup files
    /// ([`CommandLine::of`]).
    pub(in super::super) fn of(argv: &[String]) -> Self {
        CommandLine::of(argv).start
    }
}

/// What the command line of a zsh tells: how it reads its startup files,
/// which of [`OPTIONS`] it turns on, and what the check cannot tell of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in super::super) struct CommandLine {
    pub start: Start,
    /// For each of [`OPTIONS`], whether the command line turns it on, as the
    /// last word that names it says; `None` when none does.
    pub on: [Option<bool>; 3],
    /// What the check cannot tell of it, each as a clause of the warning.
    pub doubts: Vec<String>,
    /// Whether it turns `PROMPT_SUBST` on, which makes zsh run what a prompt
    /// holds as it shows it.
    pub prompt_subst: bool,
}

impl CommandLine {
    /// What the command line `argv` of a zsh tells, read as zsh reads it: a
    /// login shell when `argv[0]` starts with `-` or with `-l`, `--login` or
    /// `-o login`; only `/etc/zshenv` with `-f`, `--no-rcs`, `-o norcs` or
    /// `+o rcs`; none of the other files in `/etc` with `-d`,
    /// `--no-global-rcs`, `-o noglobalrcs` or `+o globalrcs`; an option by
    /// `-o name`, `+o name`, `-oname`, `-xo name`, `--long-name` or
    /// `+-long-name`. A zsh that emulates sh or ksh, as it does when the name
    /// it runs under starts with `s` or `k` (past a `-` and an `r`) or with
    /// `--emulate sh`, reads other startup files, which is a doubt, and so is
    /// an `-o` that names no option.
    pub(in super::super) fn of(argv: &[String]) -> Self {
        let mut line = Self {
            start: Start {
                login: Some(argv.first().is_some_and(|zero| zero.starts_with('-'))),
                rcs: true,
                global_rcs: true,
            },
            on: [None; 3],
            doubts: Vec::new(),
            prompt_subst: false,
        };
        if let Some(zero) = argv.first() {
            let name = Path::new(zero)
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            let name = name.trim_start_matches('-');
            if name
                .strip_prefix('r')
                .unwrap_or(name)
                .starts_with(['s', 'k'])
            {
                line.emulated(zero);
            }
        }
        let mut args = argv.iter().skip(1).map(String::as_str);
        while let Some(arg) = args.next() {
            if matches!(arg, "-" | "--") || !arg.starts_with(['-', '+']) {
                break;
            }
            if let Some(mode) = arg.strip_prefix("--emulate") {
                let mode = match mode.strip_prefix('=') {
                    Some(mode) => Some(mode),
                    None if mode.is_empty() => args.next(),
                    None => None,
                };
                if mode != Some("zsh") {
                    line.emulated(arg);
                }
            } else if let Some(long) = arg.strip_prefix("--") {
                line.option(long, true);
            } else if let Some(long) = arg.strip_prefix("+-") {
                line.option(long, false);
            } else {
                let on = arg.starts_with('-');
                for (at, flag) in arg.char_indices().skip(1) {
                    match flag {
                        'l' => line.start.login = Some(on),
                        'f' => line.start.rcs = !on,
                        'd' => line.start.global_rcs = !on,
                        'y' if on => line.option("shwordsplit", true),
                        'o' => {
                            let rest = &arg[at + 1..];
                            match if rest.is_empty() {
                                args.next()
                            } else {
                                Some(rest)
                            } {
                                Some(name) => line.option(name, on),
                                None => line.doubts.push(format!(
                                    "it cannot tell what `{arg}` on its command line turns on"
                                )),
                            }
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }
        line
    }

    /// Note that the zsh emulates sh or ksh, as `word` on its command line
    /// makes it.
    fn emulated(&mut self, word: &str) {
        self.doubts.push(format!(
            "it cannot tell what a zsh started with `{word}` on its command line reads, as zsh \
             then emulates sh or ksh and reads their startup files"
        ));
    }

    /// Set the option `name` (`no_rcs`, `GLOBAL_RCS`, `share-history`, ...)
    /// on, or off.
    fn option(&mut self, name: &str, on: bool) {
        let name = name.replace(['-', '_'], "").to_lowercase();
        let known = |name: &str| {
            matches!(name, "rcs" | "globalrcs" | "login") || walk::option(name).is_some()
        };
        let (name, on) = match name.strip_prefix("no") {
            Some(rest) if known(rest) => (rest.to_string(), !on),
            _ => (name, on),
        };
        match name.as_str() {
            "login" => self.start.login = Some(on),
            "rcs" => self.start.rcs = on,
            "globalrcs" => self.start.global_rcs = on,
            "promptsubst" => self.prompt_subst |= on,
            "globsubst" if on => self.doubts.push(
                "it cannot tell what code zsh runs from the values it expands as patterns, as its \
                 command line turns GLOB_SUBST on, which makes a glob qualifier in a value run"
                    .to_string(),
            ),
            "shwordsplit" | "ksharrays" if on => self.doubts.push(format!(
                "it cannot tell where zsh looks for the functions the files autoload, as its \
                 command line turns {} on, which may change the directories an expansion gives \
                 fpath",
                if name == "ksharrays" {
                    "KSH_ARRAYS"
                } else {
                    "SH_WORD_SPLIT"
                }
            )),
            other => {
                if let Some((at, true)) = walk::option(other) {
                    self.on[at] = Some(on);
                }
            }
        }
    }

    /// What the command line turns on that writes each command line as zsh
    /// runs.
    pub(in super::super) fn writes(&self) -> Vec<Write> {
        OPTIONS
            .iter()
            .zip(self.on)
            .filter(|(_, on)| *on == Some(true))
            .map(|((_, shown, entered), _)| Write {
                what: format!("its command line turns on {shown}"),
                entered: *entered,
                option: false,
            })
            .collect()
    }
}
