// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Killing interactive shells before a soft-reboot.
//!
//! An interactive shell keeps its history in memory and writes it out when it
//! exits, and stopping a login session sends it SIGHUP, on which bash and zsh
//! write. `activate` therefore SIGKILLs every interactive shell (root's
//! included) on the decoy right before it asks logind for the soft-reboot,
//! again while logind holds it back and once more when PID 1 holds its job, so
//! the activation command never reaches a decoy history file, and `emergency`
//! does the same before the way back or the power-off. Both kill them the
//! newest first, as one shell's death can hang up another
//! ([`kill_interactive_shells_newest_first`]). A SIGKILLed shell runs no
//! handler and writes nothing. A shell counts as interactive when it reads its
//! commands from a terminal ([`shell_is_interactive`]). Non-interactive shells
//! (a service's script, an `sh -c` wrapper, a pipeline subshell) keep no
//! history and are left alone.

use crate::proc::{self, ProcessHandle};

/// How a shell's command line is read: which options take a value, and which
/// make the shell run the commands it is given instead of reading them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Syntax {
    /// bash and the shells whose options follow the POSIX shell's: `-c` runs
    /// the first operand, `-s` reads the commands from standard input and
    /// passes the operands to them, `-i` or `--interactive` forces interactive
    /// mode, a lone `-` or `--` ends the options, and `-o`, `+o`, `-O`, `+O`,
    /// `--rcfile`, `--init-file`, yash's `--profile` and zsh's `--emulate`
    /// take the next word as their value.
    Posix,
    /// fish, whose options are read the way `getopt_long` reads them: `-c` or
    /// `--command` runs its value, `-C` or `--init-command` runs its value
    /// before fish reads the terminal, and `-d`, `-o`, `-p`, `-f`, `-D` and
    /// their long forms take a value too, the rest of the word or the next
    /// one.
    Fish,
}

/// Process names treated as shells, with the syntax of each one's command
/// line.
pub const SHELL_NAMES: &[(&str, Syntax)] = &[
    ("bash", Syntax::Posix),
    ("zsh", Syntax::Posix),
    ("fish", Syntax::Fish),
    ("sh", Syntax::Posix),
    ("dash", Syntax::Posix),
    ("ksh", Syntax::Posix),
    ("tcsh", Syntax::Posix),
];

/// The syntax of the shell whose process is named `comm`; `None` when it is no
/// shell.
pub fn shell_syntax(comm: &str) -> Option<Syntax> {
    SHELL_NAMES
        .iter()
        .find(|(name, _)| *name == comm)
        .map(|&(_, syntax)| syntax)
}

/// What a shell's command line says about where its commands come from.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Startup {
    /// It runs a command string it is given (`-c`).
    command: bool,
    /// It names a script to run.
    script: bool,
    /// It forces interactive mode (`-i`, `--interactive`).
    forced: bool,
}

/// Whether a shell is interactive: whether it reads its commands from a
/// terminal. Its command line, read by `syntax`, runs no command string and
/// names no script, and its standard input is a terminal (`stdin_tty`); or it
/// forces interactive mode and runs no command string. `argv[0]` is ignored.
///
/// Each shell's own rule asks for one more terminal: bash, the Korn shells
/// and yash for standard error, dash and ash for standard output, zsh and fish
/// for none. Standard input alone covers them all, so a shell started with its
/// errors sent elsewhere, as `zsh 2>/dev/null`, counts. So does a shell that
/// reads a terminal without being interactive by its own rule, as
/// `bash 2>/dev/null` does: such a shell keeps no history, and killing it
/// costs only the shell, which the switch or the power-off ends anyway.
pub fn shell_is_interactive(syntax: Syntax, argv: &[String], stdin_tty: bool) -> bool {
    let args = argv.get(1..).unwrap_or_default();
    let startup = match syntax {
        Syntax::Posix => posix(args),
        Syntax::Fish => fish(args),
    };
    !startup.command && (startup.forced || (!startup.script && stdin_tty))
}

/// The command line of a shell of [`Syntax::Posix`], past `argv[0]`.
fn posix(args: &[String]) -> Startup {
    let mut startup = Startup::default();
    let mut read_stdin = false;
    let mut args = args.iter().map(String::as_str);
    while let Some(arg) = args.next() {
        if matches!(arg, "-" | "+" | "--") {
            startup.script = !read_stdin && args.next().is_some();
            break;
        }
        if let Some(long) = arg.strip_prefix("--") {
            match long {
                "rcfile" | "init-file" | "profile" | "emulate" => {
                    args.next();
                }
                "interactive" => startup.forced = true,
                _ => {}
            }
            continue;
        }
        if let Some(flags) = arg.strip_prefix(['-', '+']) {
            for flag in flags.chars() {
                match flag {
                    'c' => startup.command = true,
                    'i' => startup.forced = true,
                    's' => read_stdin = true,
                    _ => {}
                }
            }
            if flags.ends_with(['o', 'O']) {
                args.next();
            }
            continue;
        }
        startup.script = !read_stdin;
        break;
    }
    startup
}

/// The command line of fish ([`Syntax::Fish`]), past `argv[0]`.
fn fish(args: &[String]) -> Startup {
    /// The one-letter options that take a value.
    const SHORT_VALUE: &str = "cCdoDfp";
    /// The long options that take a value.
    const LONG_VALUE: &[&str] = &[
        "command",
        "init-command",
        "debug",
        "debug-output",
        "debug-stack-frames",
        "features",
        "profile",
        "profile-startup",
    ];
    let mut startup = Startup::default();
    let mut args = args.iter().map(String::as_str);
    while let Some(arg) = args.next() {
        if arg == "--" {
            startup.script = args.next().is_some();
            break;
        }
        if let Some(long) = arg.strip_prefix("--") {
            let (name, inline) = match long.split_once('=') {
                Some((name, _)) => (name, true),
                None => (long, false),
            };
            match name {
                "command" => startup.command = true,
                "interactive" => startup.forced = true,
                _ => {}
            }
            if !inline && LONG_VALUE.contains(&name) {
                args.next();
            }
            continue;
        }
        if let Some(flags) = arg.strip_prefix('-').filter(|flags| !flags.is_empty()) {
            for (at, flag) in flags.char_indices() {
                match flag {
                    'c' => startup.command = true,
                    'i' => startup.forced = true,
                    _ => {}
                }
                if SHORT_VALUE.contains(flag) {
                    // The value is the rest of the word, or else the next one.
                    if at + flag.len_utf8() == flags.len() {
                        args.next();
                    }
                    break;
                }
            }
            continue;
        }
        startup.script = true;
        break;
    }
    startup
}

/// Whether `pid` is an interactive shell.
pub fn is_interactive_shell(pid: u32) -> bool {
    proc::comm(pid)
        .and_then(|comm| shell_syntax(&comm))
        .is_some_and(|syntax| {
            shell_is_interactive(syntax, &proc::cmdline(pid), proc::fd_is_terminal(pid, 0))
        })
}

/// SIGKILL every interactive shell, the newest first, and return the pids
/// signalled in that order. An activation calls it right before it asks
/// logind for the soft-reboot and again until PID 1 holds the job, and an
/// emergency right before it starts the way back or a power action.
///
/// A shell that leads its terminal's session hangs up the terminal's
/// foreground job as it dies, and a console such as tty1 hangs up whole. A
/// login shell on tty1 that started a compositor or an X server in the
/// foreground ends it that way, and with it every terminal window on it: the
/// kernel hangs up each window's pseudo-terminal and sends the shell in it
/// SIGHUP, on which bash writes its history. A shell started at a prompt
/// (`bash`, `su`, `nix-shell`) gets the SIGHUP as the prompt's foreground
/// job, and one that `sudo -i` started gets it from `sudo`, which passes it
/// on. Were the login shell killed first, such a shell, the one the
/// activation was typed into among them, could write its history before its
/// own SIGKILL came. An emergency typed into such a shell is the same.
///
/// What the kernel sends as a shell dies reaches only processes started after
/// it: SIGHUP to its terminal's foreground job when it leads its session, the
/// hangup of a pseudo-terminal once the last process holding its master
/// ends, SIGHUP to a stopped process group it orphans. What those end in
/// turn, a desktop's windows and the shells in them, started after it too.
/// So every interactive shell is found first and then SIGKILLed before each
/// older one, back to back: when a shell dies, every shell those paths reach
/// has its SIGKILL already, and a shell sent SIGKILL runs no handler any
/// more. Shells that started in the same clock tick go by pid, the higher
/// first.
///
/// An older process that ends shells as a newer one goes is the exception: a
/// terminal multiplexer that ends a session when its last client goes (tmux
/// with `destroy-unattached` or `exit-unattached`, screen with
/// `autodetach off`, zellij with `on_force_close "quit"`) sends the shells in
/// its panes, older ones among them, SIGHUP as the shell that ran its last
/// client dies. There the order only narrows the race.
pub fn kill_interactive_shells_newest_first() -> Vec<u32> {
    let own = std::process::id();
    let mut shells: Vec<ProcessHandle> = proc::pids()
        .into_iter()
        .filter(|&pid| pid != 1 && pid != own && is_interactive_shell(pid))
        .filter_map(ProcessHandle::open)
        .collect();
    shells.sort_by_key(|shell| std::cmp::Reverse((shell.start_time(), shell.pid())));
    shells
        .iter()
        .filter(|shell| shell.kill())
        .map(ProcessHandle::pid)
        .collect()
}

#[cfg(test)]
#[path = "shells_tests.rs"]
mod tests;
