// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Killing interactive shells before a soft-reboot.
//!
//! An interactive shell keeps its history in memory and writes it out when it
//! exits, and stopping a login session sends it SIGHUP, on which bash writes.
//! `activate` therefore SIGKILLs every interactive shell (root's included) on
//! the decoy, the newest first ([`kill_interactive_shells_newest_first`]),
//! right before it asks logind for the soft-reboot, again while logind holds
//! it back and once more when PID 1 holds its job, so the activation command
//! never reaches a decoy history file. `emergency` kills them before the way
//! back or the power-off ([`kill_all_interactive_shells`]). A SIGKILLed shell
//! runs no handler and writes
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

/// SIGKILL every interactive shell, the invocation's own last. An emergency
/// calls it right before it starts the way back or a power action: stopping
/// a login session sends its shells SIGHUP, on which bash writes its history.
pub fn kill_all_interactive_shells(spared_units: &[String]) {
    let invocation = Invocation::current();
    let _ = kill_interactive_shells(&invocation, spared_units);
    let _ = kill_invoking_shells(spared_units);
}

/// SIGKILL every interactive shell, the newest first, and return the pids
/// signalled in that order. An activation calls it right before it asks
/// logind for the soft-reboot, and again until PID 1 holds the job.
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
/// own SIGKILL came.
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

    /// Make the next process of this PID namespace get `pid + 1`.
    fn set_last_pid(pid: u32) {
        std::fs::write("/proc/sys/kernel/ns_last_pid", pid.to_string()).expect("write ns_last_pid");
    }

    /// Wait until a process started now gets a later start time than `pid`
    /// did: `/proc/<pid>/stat` counts hundredths of a second of the boot clock.
    fn wait_for_a_later_tick(pid: u32) {
        let started = proc::stat(pid).expect("stat").start_time;
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
            let ticks = u64::try_from(now.tv_sec).unwrap() * 100
                + u64::try_from(now.tv_nsec).unwrap() / 10_000_000;
            if ticks > started {
                return;
            }
            assert!(Instant::now() < deadline, "the boot clock stands still");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// Wait for the one bash whose stat passes `pick` to settle, waiting for
    /// input, and return its pid.
    fn settled_bash(pick: impl Fn(&proc::Stat) -> bool) -> u32 {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let found = proc::pids().into_iter().find(|&pid| {
                proc::comm(pid).as_deref() == Some("bash")
                    && proc::stat(pid).is_some_and(|stat| stat.state == 'S' && pick(&stat))
            });
            if let Some(pid) = found {
                return pid;
            }
            assert!(Instant::now() < deadline, "no bash settled");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Write `line` to the console, as typed on its keyboard.
    fn type_into(console: &mut Child, line: &str) {
        use std::io::Write;
        let keyboard = console.stdin.as_mut().expect("keyboard");
        keyboard.write_all(line.as_bytes()).expect("type");
        keyboard.flush().expect("type");
    }

    /// A login shell on a console (a pseudo-terminal that `script` holds,
    /// typed into through its stdin) with a second interactive bash in its
    /// foreground, as `bash`, `su` or `nix-shell` typed at a prompt start one.
    /// The inner shell has run a typed line, so it has history to write; both
    /// write theirs to `history`. Returns the console and the login and the
    /// inner shell's pids.
    fn console_with_a_shell_in_its_foreground(history: &std::path::Path) -> (Child, u32, u32) {
        let mut console = Command::new("script")
            .args(["-qfec", "exec bash --norc --noprofile -i", "/dev/null"])
            .env_remove("SHELL")
            .env("HISTFILE", history)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn script");
        let script = console.id();
        let login = settled_bash(|stat| stat.ppid == script);
        type_into(&mut console, "bash --norc --noprofile -i\n");
        let inner = settled_bash(|stat| stat.ppid == login);
        let typed = history.with_extension("typed");
        type_into(&mut console, &format!("touch {}\n", typed.display()));
        let deadline = Instant::now() + Duration::from_secs(5);
        while !typed.exists() {
            assert!(Instant::now() < deadline, "the inner shell ran nothing");
            std::thread::sleep(Duration::from_millis(5));
        }
        (console, login, inner)
    }

    #[test]
    fn a_dying_login_shell_makes_its_foreground_shell_write_history() {
        in_pid_namespace(
            "shells::tests::a_dying_login_shell_makes_its_foreground_shell_write_history",
            || {
                let dir = tempfile::tempdir().expect("tempdir");
                let history = dir.path().join("history");
                let (mut console, login, inner) = console_with_a_shell_in_its_foreground(&history);
                let inner = ProcessHandle::open(inner).expect("inner shell");

                // The login shell leads the console's session: as it dies,
                // the console's foreground job, the inner shell, gets SIGHUP.
                assert!(ProcessHandle::open(login).is_some_and(|login| login.kill()));
                let deadline = Instant::now() + Duration::from_secs(5);
                assert!(proc::await_exit(&[inner], deadline).is_empty());

                let written = std::fs::read_to_string(&history).unwrap_or_default();
                assert!(written.contains("touch"), "no history written: {written:?}");
                let _ = console.kill();
                let _ = console.wait();
            },
        );
    }

    #[test]
    fn shells_die_newest_first_so_no_dying_shell_hangs_up_a_live_one() {
        in_pid_namespace(
            "shells::tests::shells_die_newest_first_so_no_dying_shell_hangs_up_a_live_one",
            || {
                let dir = tempfile::tempdir().expect("tempdir");
                let history = dir.path().join("history");
                let (mut console, login, inner) = console_with_a_shell_in_its_foreground(&history);
                let shells = [login, inner].map(|pid| ProcessHandle::open(pid).expect("shell"));

                assert_eq!(kill_interactive_shells_newest_first(), vec![inner, login]);

                let deadline = Instant::now() + Duration::from_secs(5);
                assert!(proc::await_exit(&shells, deadline).is_empty());
                assert!(
                    !history.exists(),
                    "a killed shell wrote its history: {:?}",
                    std::fs::read_to_string(&history)
                );
                let _ = console.kill();
                let _ = console.wait();
            },
        );
    }

    #[test]
    fn the_newest_shell_dies_first_whatever_its_pid() {
        in_pid_namespace(
            "shells::tests::the_newest_shell_dies_first_whatever_its_pid",
            || {
                // The older shell gets the higher pid.
                set_last_pid(5000);
                let mut older = spawn_as("sh", "setsid", &["sh", "-i"]);
                wait_for_a_later_tick(older.id());
                set_last_pid(100);
                let mut newer = spawn_as("sh", "setsid", &["sh", "-i"]);
                assert!(newer.id() < older.id());
                let script = spawn_as("sh", "setsid", &["sh", "-c", "sleep 30; :"]);

                assert_eq!(
                    kill_interactive_shells_newest_first(),
                    vec![newer.id(), older.id()]
                );
                assert!(was_killed(&mut newer));
                assert!(was_killed(&mut older));
                assert!(still_running(script), "a script keeps no history");
            },
        );
    }
}
