// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Killing interactive shells before a soft-reboot.
//!
//! An interactive shell keeps its history in memory and writes it out when it
//! exits, and stopping a login session sends it SIGHUP, on which bash writes.
//! `activate` therefore SIGKILLs every interactive shell (root's included) on
//! the decoy right before it asks logind for the soft-reboot, again while
//! logind holds it back and once more when PID 1 holds its job, so the
//! activation command never reaches a decoy history file, and `emergency` does
//! the same before the way back or the power-off. Both kill them the newest
//! first, as one shell's death can hang up another
//! ([`kill_interactive_shells_newest_first`]). A SIGKILLed shell runs no
//! handler and writes nothing. Non-interactive shells (a service's script, an
//! `sh -c` wrapper, a pipeline subshell) keep no history and are left alone.

use crate::proc::{self, ProcessHandle};

/// Process names treated as shells.
pub const SHELL_NAMES: &[&str] = &["bash", "zsh", "fish", "sh", "dash", "ksh", "tcsh"];

/// Whether a shell is interactive by the shell's own rules (bash's, which zsh,
/// ksh and fish share in substance): `-c` or a script argument means not
/// interactive, `-i` forces it, otherwise it is interactive exactly when stdin
/// and stderr are terminals. `argv[0]` is ignored.
pub fn shell_is_interactive(argv: &[String], stdin_tty: bool, stderr_tty: bool) -> bool {
    let mut forced = false;
    let mut read_stdin = false;
    let mut args = argv.iter().skip(1);
    while let Some(arg) = args.next() {
        let arg = arg.as_str();
        if arg == "--" {
            break;
        }
        if let Some(long) = arg.strip_prefix("--") {
            if matches!(long, "rcfile" | "init-file") {
                args.next();
            }
            continue;
        }
        if let Some(flags) = arg.strip_prefix(['-', '+'])
            && !flags.is_empty()
        {
            for flag in flags.chars() {
                match flag {
                    'c' => return false,
                    'i' => forced = true,
                    's' => read_stdin = true,
                    _ => {}
                }
            }
            if flags.ends_with(['o', 'O']) {
                args.next();
            }
            continue;
        }
        if !read_stdin {
            return forced;
        }
        break;
    }
    forced || (stdin_tty && stderr_tty)
}

/// Whether `pid` is an interactive shell.
pub fn is_interactive_shell(pid: u32) -> bool {
    proc::comm(pid).is_some_and(|comm| SHELL_NAMES.contains(&comm.as_str()))
        && shell_is_interactive(
            &proc::cmdline(pid),
            proc::fd_is_terminal(pid, 0),
            proc::fd_is_terminal(pid, 2),
        )
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
