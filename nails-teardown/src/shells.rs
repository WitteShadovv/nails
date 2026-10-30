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
//! the same before the way back or the power-off. A SIGKILLed shell runs no handler and writes
//! nothing. Non-interactive shells
//! (a service's script, an `sh -c` wrapper, a pipeline subshell) keep no
//! history and are left alone. The shells of the teardown's own invocation (its
//! ancestors and those in its session) die last ([`kill_invoking_shells`]).

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

/// SIGKILL every interactive shell but those `invocation` was started from
/// ([`Invocation::is_invoking`]) and those in `spared_units`. Returns handles
/// on the shells signalled, to wait for their exit.
pub fn kill_interactive_shells(
    invocation: &Invocation,
    spared_units: &[String],
) -> Vec<ProcessHandle> {
    let mut killed = Vec::new();
    for pid in proc::pids() {
        let stat = proc::stat(pid);
        if pid == 1 || invocation.is_invoking(pid, stat.as_ref()) || !is_interactive_shell(pid) {
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

/// SIGKILL the interactive shells this process was started from: those among
/// its ancestors and in its session. [`kill_all_interactive_shells`] calls it
/// once every other interactive shell is gone. A shell that leads its
/// terminal's session hangs up the terminal's foreground job as it dies:
/// `sudo` passes the SIGHUP on to its command, which the emergency ignores,
/// and a pipe reader there that does not ignore it ends.
pub fn kill_invoking_shells(spared_units: &[String]) -> Vec<u32> {
    let invocation = Invocation::current();
    let own = std::process::id();
    let mut killed = Vec::new();
    for pid in proc::pids() {
        if pid == own {
            continue;
        }
        let stat = proc::stat(pid);
        if !invocation.is_invoking(pid, stat.as_ref())
            || !is_interactive_shell(pid)
            || in_spared_unit(pid, spared_units)
        {
            continue;
        }
        if ProcessHandle::open(pid).is_some_and(|h| h.kill()) {
            killed.push(pid);
        }
    }
    killed
}

/// SIGKILL every interactive shell, the invocation's own last. Called just
/// before a soft-reboot or power action is asked for (and, by an activation,
/// until PID 1 holds its job): stopping a login session sends its shells
/// SIGHUP, on which bash writes its history.
pub fn kill_all_interactive_shells(spared_units: &[String]) {
    let invocation = Invocation::current();
    let _ = kill_interactive_shells(&invocation, spared_units);
    let _ = kill_invoking_shells(spared_units);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

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

    /// Spawn `program args` and wait until its comm reads `comm` (a `setsid`
    /// wrapper execs the shell only after `spawn` returns) and it sleeps, done
    /// starting up. Its stdin stays open so an interactive shell blocks
    /// reading it.
    fn spawn_as(comm: &str, program: &str, args: &[&str]) -> Child {
        let child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {program}: {e}"));
        let deadline = Instant::now() + Duration::from_secs(5);
        while proc::comm(child.id()).as_deref() != Some(comm)
            || proc::stat(child.id()).map(|s| s.state) != Some('S')
        {
            assert!(
                Instant::now() < deadline,
                "{program} never settled as {comm}: {:?}",
                proc::stat(child.id())
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        child
    }

    /// Whether `child` was SIGKILLed, waiting for it to go.
    fn was_killed(child: &mut Child) -> bool {
        child.wait().unwrap().signal() == Some(libc::SIGKILL)
    }

    /// Whether `child` still runs; it is killed and reaped either way.
    fn still_running(mut child: Child) -> bool {
        let running = child.try_wait().unwrap().is_none();
        let _ = child.kill();
        let _ = child.wait();
        running
    }

    /// Run `body` as PID 1 of a fresh user, mount and PID namespace with its
    /// own `/proc` (through `unshare`), so the shell killers see and can
    /// signal only the processes the test spawns. `test` is the libtest name.
    ///
    /// A host where `unshare` cannot create the namespaces skips, unless
    /// `NAILS_REQUIRE_USERNS=1` (set by the CI job that must run these).
    fn in_pid_namespace(test: &str, body: impl FnOnce()) {
        const CHILD_ENV: &str = "NAILS_TEARDOWN_PID_NS_CHILD";
        if std::env::var_os(CHILD_ENV).is_some_and(|name| name == test) {
            // Never let a killer loose on the host's processes.
            assert_eq!(std::process::id(), 1, "the body must run as PID 1");
            // Lead a session of our own, so the shells spawned below belong
            // to this invocation unless they call setsid themselves.
            rustix::process::setsid().expect("setsid");
            body();
            return;
        }
        let output = Command::new("unshare")
            .args([
                "--user",
                "--map-root-user",
                "--pid",
                "--fork",
                "--mount-proc",
                "--",
            ])
            .arg(std::env::current_exe().unwrap())
            .args([test, "--exact", "--nocapture", "--test-threads", "1"])
            .env(CHILD_ENV, test)
            .stdin(Stdio::null())
            .output();
        let required = std::env::var("NAILS_REQUIRE_USERNS").as_deref() == Ok("1");
        let output = match output {
            Ok(output) => output,
            Err(e) => {
                assert!(!required, "cannot run unshare: {e}");
                eprintln!("skipped {test}: cannot run unshare ({e})");
                return;
            }
        };
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.starts_with("unshare:") {
            assert!(!required, "cannot create the namespaces: {stderr}");
            eprintln!("skipped {test}: {stderr}");
            return;
        }
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "{test} failed in its PID namespace\n{stdout}\n{stderr}"
        );
    }

    #[test]
    fn a_live_interactive_shell_is_told_from_a_script_and_a_non_shell() {
        // In a session of its own: under a terminal, an interactive shell in
        // the test's background process group would be stopped (SIGTTOU).
        let shell = spawn_as("sh", "setsid", &["sh", "-i"]);
        let script = spawn_as("sh", "sh", &["-c", "sleep 30; :"]);
        let other = spawn_as("sleep", "sleep", &["30"]);

        let verdicts = [
            is_interactive_shell(shell.id()),
            is_interactive_shell(script.id()),
            is_interactive_shell(other.id()),
        ];
        for child in [shell, script, other] {
            still_running(child);
        }

        assert_eq!(verdicts, [true, false, false]);
    }

    #[test]
    fn the_invocation_s_shells_are_killed_last_and_scripts_never() {
        in_pid_namespace(
            "shells::tests::the_invocation_s_shells_are_killed_last_and_scripts_never",
            || {
                let mut own = spawn_as("sh", "sh", &["-i"]);
                let mut foreign = spawn_as("sh", "setsid", &["sh", "-i"]);
                let script = spawn_as("sh", "setsid", &["sh", "-c", "sleep 30; :"]);
                let spared = ["unrelated.service".to_string()];

                // First every shell outside the invocation...
                let killed = kill_interactive_shells(&Invocation::current(), &spared);
                let pids: Vec<u32> = killed.iter().map(ProcessHandle::pid).collect();
                assert_eq!(pids, vec![foreign.id()]);
                assert!(was_killed(&mut foreign));
                assert_eq!(own.try_wait().unwrap(), None, "the own shell waits");

                // ...then, last, the invocation's own.
                assert_eq!(kill_invoking_shells(&spared), vec![own.id()]);
                assert!(was_killed(&mut own));
                assert!(still_running(script), "a script keeps no history");
            },
        );
    }

    #[test]
    fn every_interactive_shell_is_killed_before_a_soft_reboot() {
        in_pid_namespace(
            "shells::tests::every_interactive_shell_is_killed_before_a_soft_reboot",
            || {
                let mut own = spawn_as("sh", "sh", &["-i"]);
                let mut foreign = spawn_as("sh", "setsid", &["sh", "-i"]);
                let script = spawn_as("sh", "sh", &["-c", "sleep 30; :"]);

                kill_all_interactive_shells(&[]);

                assert!(was_killed(&mut own));
                assert!(was_killed(&mut foreign));
                assert!(still_running(script));
            },
        );
    }
}
