// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

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
        // Lead a session of our own, without a terminal: no shell spawned
        // below reaches the terminal the tests run from.
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
