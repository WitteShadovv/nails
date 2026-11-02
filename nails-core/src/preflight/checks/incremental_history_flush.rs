// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Incremental shell-history flush pre-flight check.
//!
//! Warns, never fails. Activation SIGKILLs the decoy's interactive shells, so
//! a shell that writes its history only when it ends never writes the decoy
//! commands ([`nails_teardown::shells`]). A shell that writes each command
//! line to its history file as it runs has written them before activation
//! starts, and no kill takes that back: zsh with `INC_APPEND_HISTORY` or
//! `SHARE_HISTORY` as each line is entered, and with `INC_APPEND_HISTORY_TIME`
//! once each command ends, bash with `history -a` or `history -w` in
//! `PROMPT_COMMAND` at the next prompt, and fish, unless it runs in private
//! mode, as it starts each command. Refusing the activation would take none
//! of those lines back, and with a shell that writes once a command ends it
//! would add one: the refused activation ends, and its command line is written
//! then. So the check warns, and names the shell and the setting.
//!
//! It reads the settings of one shell: the one the running command was typed
//! into, as its process tree shows ([`InspectedShell::typed`]), else the
//! operator's login shell ([`InspectedShell::login`]). Of that shell it reads
//! the startup files in `/etc` and in the home of the account the shell runs
//! as ([`startup`], and [`zsh`], which follows zsh's files as zsh runs them
//! and fails closed on what it cannot follow), through the [`Filesystem`]
//! seam: as root a read changes no file's access time, but a link on the way
//! to one is followed and its access time can change. It never reads a history
//! file. What it cannot read or follow makes it warn that it cannot tell. It
//! knows the settings of bash, zsh and fish, and that dash keeps no history
//! file; of any other shell it warns that it cannot tell. It does not see a
//! setting typed into the shell, one a plugin manager or an `eval` makes, or
//! one in the files of a shell started with others (`--rcfile`, a `ZDOTDIR`
//! from its environment).

mod startup;
mod zsh;

use std::path::{Path, PathBuf};

use super::super::{CheckResult, PreFlightCheck};
use crate::{Filesystem, Result, TargetUser};

/// How the check found the shell whose settings it reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellOrigin {
    /// The command running the check was typed into it.
    Typed,
    /// It is the operator's login shell, as the passwd database names it.
    Login,
}

impl ShellOrigin {
    /// The shell's part, as a message names it.
    fn describe(self) -> &'static str {
        match self {
            Self::Typed => "the shell this command was typed into",
            Self::Login => "the operator's login shell",
        }
    }
}

/// The shell whose history settings the check reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectedShell {
    /// The file name of its program: `zsh`, `bash`, `fish`, ...
    pub program: String,
    /// The home of the account it runs as, which holds its own startup files.
    pub home: PathBuf,
    /// Its command line; empty for a login shell, which may not run now.
    pub argv: Vec<String>,
    /// How the check found it.
    pub origin: ShellOrigin,
}

impl InspectedShell {
    /// The operator's login shell.
    pub fn login(operator: &TargetUser) -> Self {
        Self {
            program: file_name(&operator.shell),
            home: operator.home().to_path_buf(),
            argv: Vec::new(),
            origin: ShellOrigin::Login,
        }
    }

    /// The interactive shell the running command was typed into, as `/proc`
    /// shows it ([`nails_teardown::proc::Invocation`]), with the home of the
    /// account it runs as: `operator`'s, or the passwd database's for another
    /// account, such as root's for a shell that `sudo -i` opened. `None` when
    /// the command was not typed into a shell, when the shell's account or its
    /// home cannot be found, and in a test, which never reads the host's
    /// processes.
    pub fn typed(operator: Option<&TargetUser>) -> Option<Self> {
        use nails_teardown::proc;
        if crate::runtime_safety::should_skip_host_interaction() {
            return None;
        }
        let pid = proc::Invocation::current().shell?;
        let uid = proc::uid(pid)?;
        let home = match operator {
            Some(operator) if operator.uid == uid => operator.home().to_path_buf(),
            _ => {
                nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
                    .ok()
                    .flatten()?
                    .dir
            }
        };
        Some(Self {
            program: program(pid)?,
            home,
            argv: proc::cmdline(pid),
            origin: ShellOrigin::Typed,
        })
    }
}

/// The file name of the program `pid` runs, as its `/proc/<pid>/exe` link
/// names it, so a shell started through a link (`/bin/sh`) is named for the
/// shell it is; else its process name.
fn program(pid: u32) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|exe| file_name(&exe))
        .or_else(|| nails_teardown::proc::comm(pid))
}

/// The file name of `path`, without the ` (deleted)` the kernel adds to the
/// link of a program whose file was replaced.
fn file_name(path: &Path) -> String {
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    name.strip_suffix(" (deleted)").unwrap_or(&name).to_string()
}

/// How the check reads a shell's history settings, by the name of its
/// program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Bash,
    Zsh,
    Fish,
    /// A shell that keeps no history file: dash.
    NoHistory,
    /// A shell whose settings the check does not know.
    Unknown,
}

fn kind(program: &str) -> Kind {
    match nails_teardown::shells::unwrapped(program) {
        "bash" | "rbash" => Kind::Bash,
        "zsh" => Kind::Zsh,
        "fish" => Kind::Fish,
        "dash" => Kind::NoHistory,
        _ => Kind::Unknown,
    }
}

/// What a write after every command means for the decoy commands.
const ON_DISK: &str = "the commands typed in it are on the decoy disk once it writes them, and \
                       killing the shells at activation cannot take them back";

/// Reports when the shell the decoy commands are typed into writes each
/// command line to its history file as it runs.
#[derive(Debug, Clone, Default)]
pub struct IncrementalHistoryFlushCheck {
    /// The shell whose settings the check reads. `None` when neither a typed
    /// shell nor the operator could be found, in which case the check reports
    /// a skipped Pass.
    shell: Option<InspectedShell>,
}

impl IncrementalHistoryFlushCheck {
    /// Create a check that reads the settings of `shell`.
    pub fn new(shell: InspectedShell) -> Self {
        Self { shell: Some(shell) }
    }

    /// Create a check that reports Pass without inspecting anything, used when
    /// no shell could be found.
    pub fn disabled() -> Self {
        Self { shell: None }
    }
}

/// The result for `shell`, whose startup files `fs` holds.
fn judge<F: Filesystem>(fs: &F, shell: &InspectedShell) -> CheckResult {
    let program = nails_teardown::shells::unwrapped(&shell.program);
    let origin = shell.origin.describe();
    let homes = std::slice::from_ref(&shell.home);
    let start = match shell.origin {
        ShellOrigin::Typed => zsh::Start::of(&shell.argv),
        ShellOrigin::Login => zsh::Start {
            login: None,
            every_file: true,
        },
    };
    let (scan, settings, remedy) = match kind(program) {
        Kind::Zsh => (
            zsh::zsh(fs, homes, start),
            "turns on INC_APPEND_HISTORY, INC_APPEND_HISTORY_TIME or SHARE_HISTORY",
            "Type the decoy commands in a zsh that saves no history (run `unset HISTFILE` in \
             it first), or turn the option off for that zsh (`unsetopt` it at the end of its \
             .zshrc).",
        ),
        Kind::Bash => (
            startup::bash(fs, homes),
            "runs `history -a` or `history -w` from PROMPT_COMMAND",
            "Type the decoy commands in a bash whose history is off (run `set +o history` in \
             it first), or take `history -a` and `history -w` out of PROMPT_COMMAND.",
        ),
        Kind::Fish if nails_teardown::shells::fish_is_private(&shell.argv) => {
            return CheckResult::Pass(format!(
                "{program} ({origin}) runs in private mode and writes no history"
            ));
        }
        Kind::Fish => {
            return CheckResult::Warn(format!(
                "{program}, {origin}, writes each command line to its history file as it \
                 starts the command, unless it runs in private mode. So {ON_DISK}. Type the \
                 decoy commands in a fish started as `fish --private`."
            ));
        }
        Kind::NoHistory => {
            return CheckResult::Pass(format!("{program} ({origin}) keeps no history file"));
        }
        Kind::Unknown => {
            return CheckResult::Warn(format!(
                "NAILS reads the history settings of bash, zsh and fish only, so it cannot \
                 tell whether {program}, {origin}, writes each command line to a history file \
                 as it runs, as the Korn shells, yash, nu and elvish can. If it does, {ON_DISK}. \
                 Type the decoy commands in a shell whose history is off."
            ));
        }
    };
    let doubts = (!scan.doubts.is_empty()).then(|| scan.doubts.join("; "));
    if scan.writes.is_empty() {
        return match doubts {
            None => CheckResult::Pass(format!(
                "{program} ({origin}): no startup file the check reads {settings}"
            )),
            Some(doubts) => CheckResult::Warn(format!(
                "The check cannot tell whether {program}, {origin}, writes each command line to \
                 its history file as it runs: {doubts}. If it does, {ON_DISK}."
            )),
        };
    }
    let when = if scan.writes.iter().any(|write| write.entered) {
        "as you enter it"
    } else {
        "once the command ends"
    };
    let what: Vec<&str> = scan
        .writes
        .iter()
        .map(|write| write.what.as_str())
        .collect();
    let unread = doubts
        .map(|doubts| format!(" Beyond that, {doubts}."))
        .unwrap_or_default();
    CheckResult::Warn(format!(
        "{program}, {origin}, writes each command line to its history file {when}: {}. So \
         {ON_DISK}. {remedy}{unread}",
        what.join("; ")
    ))
}

impl<F: Filesystem> PreFlightCheck<F> for IncrementalHistoryFlushCheck {
    fn name(&self) -> &'static str {
        "incremental-history-flush"
    }

    fn description(&self) -> &'static str {
        "Reports shell settings that write each command to the history file as it runs"
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        Ok(match self.shell.as_ref() {
            Some(shell) => judge(fs, shell),
            None => CheckResult::Pass(
                "Target user could not be resolved; shell history-flush settings were not \
                 inspected"
                    .into(),
            ),
        })
    }
}

#[cfg(test)]
mod tests;
