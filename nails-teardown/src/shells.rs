// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Killing interactive shells before the overlays come down.
//!
//! An interactive shell keeps its history in memory and writes it out when it
//! exits. Once the overlays are gone its history file is on the decoy, so every
//! interactive shell (root's included) is SIGKILLed before the unmount: a
//! SIGKILLed shell runs no handler and writes nothing. Non-interactive shells
//! (a service's script, an `sh -c` wrapper, a pipeline subshell) keep no
//! history and are left alone, as is the teardown's own invocation, whose shell
//! is killed last, after the output is written ([`kill_invoking_shells`]).

use crate::proc::{self, Invocation, ProcessHandle};

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

/// Whether `pid` runs in one of the `spared_units` (system services named by
/// the caller whose shells must survive).
fn in_spared_unit(pid: u32, spared_units: &[String]) -> bool {
    !spared_units.is_empty()
        && proc::cgroup(pid)
            .and_then(|c| crate::cgroup::service_unit_from_cgroup(&c))
            .is_some_and(|unit| spared_units.iter().any(|s| s == &unit))
}

/// SIGKILL every interactive shell outside `invocation` and `spared_units`.
/// Returns handles on the shells signalled, to wait for their exit.
pub fn kill_interactive_shells(
    invocation: &Invocation,
    spared_units: &[String],
) -> Vec<ProcessHandle> {
    let mut killed = Vec::new();
    for pid in proc::pids() {
        let stat = proc::stat(pid);
        if pid == 1 || invocation.contains(pid, stat.as_ref()) || !is_interactive_shell(pid) {
            continue;
        }
        if in_spared_unit(pid, spared_units) {
            continue;
        }
        if let Some(handle) = ProcessHandle::open(pid)
            && handle.kill()
        {
            killed.push(handle);
        }
    }
    killed
}

/// SIGKILL the interactive shells of this process's own invocation: its
/// ancestry and session. Emergency calls it as its very last step, after every
/// line of output is flushed. Only shells die, so `sudo` and a pipe reader keep
/// relaying what was already written.
pub fn kill_invoking_shells(spared_units: &[String]) -> Vec<u32> {
    let invocation = Invocation::current();
    let own = std::process::id();
    let mut killed = Vec::new();
    for pid in proc::pids() {
        if pid == own {
            continue;
        }
        let stat = proc::stat(pid);
        let in_invocation = invocation.ancestry.contains(&pid)
            || (invocation.sid != 0 && stat.is_some_and(|s| s.sid == invocation.sid));
        if !in_invocation || !is_interactive_shell(pid) || in_spared_unit(pid, spared_units) {
            continue;
        }
        if ProcessHandle::open(pid).is_some_and(|h| h.kill()) {
            killed.push(pid);
        }
    }
    killed
}

/// SIGKILL every interactive shell, the invocation's own last. Called just
/// before a soft-reboot or power action is enqueued: stopping a login session
/// sends its shells SIGHUP, on which bash writes its history.
pub fn kill_all_interactive_shells(spared_units: &[String]) {
    let invocation = Invocation::current();
    let _ = kill_interactive_shells(&invocation, spared_units);
    let _ = kill_invoking_shells(spared_units);
}

#[cfg(test)]
mod tests {
    use super::shell_is_interactive;

    fn argv(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| w.to_string()).collect()
    }

    #[test]
    fn a_command_string_or_script_is_never_interactive() {
        assert!(!shell_is_interactive(
            &argv(&["bash", "-c", "x"]),
            true,
            true
        ));
        assert!(!shell_is_interactive(
            &argv(&["sh", "-lc", "x"]),
            true,
            true
        ));
        assert!(!shell_is_interactive(
            &argv(&["bash", "script.sh"]),
            true,
            true
        ));
        assert!(!shell_is_interactive(
            &argv(&["bash", "-o", "posix", "script.sh"]),
            true,
            true
        ));
    }

    #[test]
    fn a_terminal_shell_or_a_forced_one_is_interactive() {
        assert!(shell_is_interactive(&argv(&["-bash"]), true, true));
        assert!(shell_is_interactive(&argv(&["bash", "-l"]), true, true));
        assert!(!shell_is_interactive(&argv(&["bash"]), false, true));
        assert!(shell_is_interactive(&argv(&["bash", "-i"]), false, false));
        assert!(shell_is_interactive(
            &argv(&["bash", "--rcfile", "x", "-s"]),
            true,
            true
        ));
    }
}
