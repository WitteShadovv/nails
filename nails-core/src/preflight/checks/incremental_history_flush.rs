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
//! It reads the settings of the shell the running command was typed into, as
//! its process tree shows ([`InspectedShell::typed`]). When it can only tell
//! the shell the command was likely typed into, it reads that one's and every
//! other shell's it knows; when it finds none (the command ran from a window,
//! through `run0`, or the like), it reads the settings of every shell it
//! knows, bash, zsh and the operator's login shell, and fish's when the
//! operator's home has its configuration ([`InspectedShell::login`]). Of a
//! shell it reads the startup files in
//! `/etc` and in the home of the account the shell runs as, and in the
//! operator's home when that is another ([`startup`], [`zsh`]), through the
//! [`Filesystem`] seam: as root a read changes no file's access time, but a
//! link on the way to one is followed and its access time can change. It never
//! reads a history file. What it cannot read or follow makes it warn that it
//! cannot tell. It knows the settings of bash, zsh and fish, and that dash
//! keeps no history file; of any other shell it warns that it cannot tell. It
//! does not see a setting typed into the shell, one a plugin manager or an
//! `eval` makes, or one in the files of a shell started with others
//! (`--rcfile`, a `ZDOTDIR` from its environment).

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
    /// The command was likely typed into it: the nearest interactive shell
    /// on the command's terminal, with the command in its foreground
    /// ([`nails_teardown::proc::TypingShell::Likely`]). The check reads
    /// every shell it knows besides.
    Likely,
    /// No typed shell was found: it is the operator's login shell, and the
    /// check reads every shell it knows besides.
    Login,
}

/// The shell whose history settings the check reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectedShell {
    /// The file name of its program: `zsh`, `bash`, `fish`, ...
    pub program: String,
    /// The homes it may run with: the home of the account it runs as first,
    /// then the operator's when that is another.
    pub homes: Vec<PathBuf>,
    /// Its command line; empty for a login shell, which may not run now.
    pub argv: Vec<String>,
    /// How the check found it.
    pub origin: ShellOrigin,
    /// The program of the operator's login shell, read beside a shell the
    /// command was only likely typed into.
    pub login: Option<String>,
}

impl InspectedShell {
    /// The operator's login shell, read when no typed shell is found.
    pub fn login(operator: &TargetUser) -> Self {
        Self {
            program: file_name(&operator.shell),
            homes: vec![operator.home().to_path_buf()],
            argv: Vec::new(),
            origin: ShellOrigin::Login,
            login: None,
        }
    }

    /// The interactive shell the running command was typed into, as `/proc`
    /// shows it ([`nails_teardown::proc::typing_shell`]), with the home of
    /// the account it runs as and, for another account than `operator`'s
    /// (root's, for a shell `sudo -i` or `sudo -s` opened), `operator`'s home
    /// too, which such a shell can run with. A shell the command was only
    /// likely typed into is [`ShellOrigin::Likely`]. `None` when the command
    /// was not typed into a shell, when the shell's account cannot be found,
    /// and in a test, which never reads the host's processes.
    pub fn typed(operator: Option<&TargetUser>) -> Option<Self> {
        use nails_teardown::proc::{self, TypingShell};
        if crate::runtime_safety::should_skip_host_interaction() {
            return None;
        }
        let (pid, origin) = match proc::typing_shell(std::process::id(), proc::Node::read)? {
            TypingShell::Certain(pid) => (pid, ShellOrigin::Typed),
            TypingShell::Likely(pid) => (pid, ShellOrigin::Likely),
        };
        let uid = proc::uid(pid)?;
        let homes = match operator {
            Some(operator) if operator.uid == uid => vec![operator.home().to_path_buf()],
            _ => {
                let own = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
                    .ok()
                    .flatten()?
                    .dir;
                let mut homes = vec![own];
                homes.extend(operator.map(|operator| operator.home().to_path_buf()));
                homes
            }
        };
        let exe = std::fs::read_link(format!("/proc/{pid}/exe")).ok();
        Some(Self {
            program: program_name(exe.as_deref(), proc::comm(pid))?,
            homes,
            argv: proc::cmdline(pid),
            origin,
            login: operator
                .filter(|_| origin == ShellOrigin::Likely)
                .map(|operator| file_name(&operator.shell)),
        })
    }
}

/// The name a shell's process is known by: the file name of the program its
/// `/proc/<pid>/exe` link names (`exe`) when that is a shell's, so a shell
/// started through a link (`/bin/sh`) is named for the shell it is, else its
/// process name (`comm`), so xonsh, which Python runs, is named xonsh.
fn program_name(exe: Option<&Path>, comm: Option<String>) -> Option<String> {
    exe.map(file_name)
        .filter(|name| nails_teardown::shells::shell_syntax(name).is_some())
        .or(comm)
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

/// One shell to judge: its program, its homes, how zsh would read its files,
/// and its part, as a message names it.
struct Judged<'a> {
    program: &'a str,
    homes: &'a [PathBuf],
    argv: &'a [String],
    zsh: zsh::Start,
    part: &'a str,
}

/// The result for one shell, whose startup files `fs` holds.
fn judge_one<F: Filesystem>(fs: &F, shell: &Judged) -> CheckResult {
    let program = nails_teardown::shells::unwrapped(shell.program);
    let part = shell.part;
    let (scan, settings, remedy) = match kind(program) {
        Kind::Zsh => (
            zsh::zsh(fs, shell.homes, shell.zsh),
            "turns on INC_APPEND_HISTORY, INC_APPEND_HISTORY_TIME or SHARE_HISTORY",
            format!(
                "Type the decoy commands in a zsh that saves no history (run `unset HISTFILE` \
                 in it first), or turn the option off for that zsh (`unsetopt` it at the end \
                 of {}).",
                if shell.homes.len() > 1 {
                    "the .zshrc in each home it can run with"
                } else {
                    "its .zshrc"
                }
            ),
        ),
        Kind::Bash => (
            startup::bash(fs, shell.homes),
            "runs `history -a` or `history -w` from PROMPT_COMMAND",
            "Type the decoy commands in a bash whose history is off (run `set +o history` in \
             it first), or take `history -a` and `history -w` out of PROMPT_COMMAND."
                .to_string(),
        ),
        Kind::Fish if nails_teardown::shells::fish_is_private(shell.argv) => {
            return CheckResult::Pass(format!(
                "{program} ({part}) runs in private mode and writes no history"
            ));
        }
        Kind::Fish => {
            return CheckResult::Warn(format!(
                "{program}, {part}, writes each command line to its history file as it starts \
                 the command, unless it runs in private mode. So {ON_DISK}. Type the decoy \
                 commands in a fish started as `fish --private`."
            ));
        }
        Kind::NoHistory => {
            return CheckResult::Pass(format!("{program} ({part}) keeps no history file"));
        }
        Kind::Unknown => {
            return CheckResult::Warn(format!(
                "NAILS reads the history settings of bash, zsh and fish only, so it cannot \
                 tell whether {program}, {part}, writes each command line to a history file as \
                 it runs, as the Korn shells, yash, nu and elvish can. If it does, {ON_DISK}. \
                 Type the decoy commands in a shell whose history is off."
            ));
        }
    };
    let doubts = (!scan.doubts.is_empty()).then(|| scan.doubts.join("; "));
    if scan.writes.is_empty() {
        return match doubts {
            None => CheckResult::Pass(format!(
                "{program} ({part}): no startup file the check reads {settings}"
            )),
            Some(doubts) => CheckResult::Warn(format!(
                "The check cannot tell whether {program}, {part}, writes each command line to \
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
        "{program}, {part}, writes each command line to its history file {when}: {}. So \
         {ON_DISK}. {remedy}{unread}",
        what.join("; ")
    ))
}

/// The result for `shell`, whose startup files `fs` holds.
fn judge<F: Filesystem>(fs: &F, shell: &InspectedShell) -> CheckResult {
    match shell.origin {
        ShellOrigin::Typed => judge_one(
            fs,
            &Judged {
                program: &shell.program,
                homes: &shell.homes,
                argv: &shell.argv,
                zsh: zsh::Start::of(&shell.argv),
                part: "the shell this command was typed into",
            },
        ),
        ShellOrigin::Likely => {
            let mut first = vec![unsure(
                &shell.program,
                &shell.homes,
                "the shell this command was likely typed into",
            )];
            first.extend(
                shell
                    .login
                    .as_deref()
                    .filter(|login| !same_shell(login, &shell.program))
                    .map(|login| unsure(login, &shell.homes, "the operator's login shell")),
            );
            let program = nails_teardown::shells::unwrapped(&shell.program);
            every_shell(
                fs,
                first,
                &format!(
                    "This command was likely typed into {program}, but the check cannot be sure \
                     of it, so it read the startup files of every shell it knows"
                ),
            )
        }
        ShellOrigin::Login => every_shell(
            fs,
            vec![unsure(
                &shell.program,
                &shell.homes,
                "the operator's login shell",
            )],
            "This command was not typed into a shell the check can see, so it read the startup \
             files of every shell it knows",
        ),
    }
}

/// `program`, which the decoy commands may have been typed into, read as any
/// shell the operator may use: no command line tells how it started, so zsh
/// is taken to read every startup file it may read.
fn unsure<'a>(program: &'a str, homes: &'a [PathBuf], part: &'a str) -> Judged<'a> {
    Judged {
        program,
        homes,
        argv: &[],
        zsh: zsh::Start {
            login: None,
            every_file: true,
        },
        part,
    }
}

/// Whether the check reads `a` and `b` alike: the same program, or two it
/// reads the settings of the same way.
fn same_shell(a: &str, b: &str) -> bool {
    let unwrapped = nails_teardown::shells::unwrapped;
    unwrapped(a) == unwrapped(b) || (kind(a) == kind(b) && kind(a) != Kind::Unknown)
}

/// The result for the shells `first`, then bash, zsh and, when one of their
/// homes has its configuration, fish, each that `first` does not hold already;
/// `preface` says why the check reads them all.
fn every_shell<F: Filesystem>(fs: &F, first: Vec<Judged>, preface: &str) -> CheckResult {
    let homes = first.first().map_or(&[][..], |shell| shell.homes);
    let has_fish = homes
        .iter()
        .any(|home| fs.path_exists(&home.join(".config/fish")).unwrap_or(false));
    let mut shells = first;
    for other in ["bash", "zsh", "fish"] {
        let known = shells.iter().any(|shell| same_shell(shell.program, other));
        if !known && (other != "fish" || has_fish) {
            shells.push(unsure(other, homes, "a shell the operator may use"));
        }
    }
    let results: Vec<CheckResult> = shells.iter().map(|shell| judge_one(fs, shell)).collect();
    let warnings: Vec<&str> = results
        .iter()
        .filter(|result| matches!(result, CheckResult::Warn(_)))
        .map(CheckResult::message)
        .collect();
    if warnings.is_empty() {
        let passes: Vec<&str> = results.iter().map(CheckResult::message).collect();
        CheckResult::Pass(format!("{preface}: {}", passes.join("; ")))
    } else {
        CheckResult::Warn(format!("{preface}. {}", warnings.join(" ")))
    }
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
