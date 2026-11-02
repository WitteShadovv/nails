// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn argv(words: &[&str]) -> Vec<String> {
    words.iter().map(|w| w.to_string()).collect()
}

/// Whether a shell of `syntax` started as `words` counts as interactive, with
/// its standard input on a terminal or not.
fn interactive(syntax: Syntax, words: &[&str], stdin_tty: bool) -> bool {
    shell_is_interactive(syntax, &argv(words), stdin_tty)
}

#[test]
fn a_command_string_or_script_is_never_interactive() {
    for words in [
        &["bash", "-c", "x"][..],
        &["sh", "-lc", "x"],
        &["bash", "-i", "-c", "x"],
        &["bash", "script.sh"],
        &["bash", "-o", "posix", "script.sh"],
        &["bash", "--rcfile", "x", "script.sh"],
        &["bash", "--init-file", "x", "script.sh"],
        &["bash", "--rcfile=x", "script.sh"],
        &["bash", "-O", "extglob", "script.sh"],
        &["bash", "--", "script.sh"],
        &["sh", "-", "script.sh"],
        &["zsh", "+", "script.sh"],
        &["zsh", "--emulate", "sh", "script.sh"],
        &["yash", "--profile", "p", "script.sh"],
    ] {
        assert!(!interactive(Syntax::Posix, words, true), "{words:?}");
    }
}

#[test]
fn a_shell_reading_a_terminal_or_a_forced_one_is_interactive() {
    for words in [
        &["-bash"][..],
        &["bash", "-l"],
        &["bash", "--rcfile", "x", "-s"],
        &["bash", "-s", "arg"],
        &["bash", "-s", "--", "arg"],
        &["bash", "--init-file", "x"],
        &["bash", "+O", "extglob"],
        &["bash", "--"],
        &["zsh", "-"],
        &["zsh", "+"],
        &["zsh", "--emulate", "sh"],
        &["yash", "--profile", "p"],
    ] {
        assert!(interactive(Syntax::Posix, words, true), "{words:?}");
    }
    assert!(!interactive(Syntax::Posix, &["bash"], false));
    assert!(interactive(Syntax::Posix, &["bash", "-i"], false));
    assert!(interactive(Syntax::Posix, &["zsh", "--interactive"], false));
    assert!(
        interactive(Syntax::Posix, &["sh", "-i", "-m", "job.sh"], false),
        "a forced shell reads its script interactively"
    );
}

#[test]
fn fish_reads_the_terminal_after_an_init_command_but_not_with_a_command() {
    for words in [
        &["fish"][..],
        &["-fish"],
        &["fish", "-l"],
        &["fish", "-C", "set -g x 1"],
        &["fish", "-Cset -g x 1"],
        &["fish", "--init-command", "set -g x 1"],
        &["fish", "--init-command=set -g x 1"],
        &["fish", "-d", "history", "-o", "/tmp/log"],
        &["fish", "--debug", "history"],
        &["fish", "-P", "--features", "qmark-noglob"],
        &[
            "fish",
            "-D",
            "3",
            "-p",
            "/tmp/profile",
            "-f",
            "qmark-noglob",
        ],
        &[
            "fish",
            "--debug-output",
            "/tmp/log",
            "--debug-stack-frames",
            "3",
            "--profile",
            "/tmp/profile",
            "--profile-startup",
            "/tmp/startup",
        ],
        &["fish", "-iPl"],
    ] {
        assert!(interactive(Syntax::Fish, words, true), "{words:?}");
    }
    for words in [
        &["fish", "-c", "echo"][..],
        &["fish", "-cecho"],
        &["fish", "-lc", "echo"],
        &["fish", "--command", "echo"],
        &["fish", "--command=echo"],
        &["fish", "-i", "-c", "echo"],
        &["fish", "script.fish"],
        &["fish", "-d", "history", "script.fish"],
        &["fish", "--init-command=set -g x 1", "script.fish"],
        &["fish", "--private", "script.fish"],
        &["fish", "--", "script.fish"],
        &["fish", "-"],
    ] {
        assert!(!interactive(Syntax::Fish, words, true), "{words:?}");
    }
    assert!(!interactive(Syntax::Fish, &["fish"], false));
    assert!(interactive(Syntax::Fish, &["fish", "-i"], false));
    assert!(interactive(
        Syntax::Fish,
        &["fish", "--interactive", "script.fish"],
        false
    ));
}

#[test]
fn a_private_fish_is_told_by_its_command_line() {
    for words in [
        &["fish", "-P"][..],
        &["fish", "--private"],
        &["fish", "-lP"],
        &["fish", "-d", "history", "-P"],
        &["fish", "--debug", "history", "--private", "-l"],
    ] {
        assert!(fish_is_private(&argv(words)), "{words:?}");
    }
    for words in [
        &["fish"][..],
        &["-fish", "-l"],
        &["fish", "-d", "P"],
        &["fish", "-dP"],
        &["fish", "-C", "-P"],
        &["fish", "script.fish", "-P"],
        &["fish", "--", "-P"],
    ] {
        assert!(!fish_is_private(&argv(words)), "{words:?}");
    }
}

#[test]
fn nu_reads_the_terminal_unless_it_runs_commands_or_a_script() {
    for words in [
        &["nu"][..],
        &["-nu"],
        &["nu", "-l"],
        &["nu", "-e", "print hi"],
        &["nu", "--execute", "print hi"],
        &["nu", "--config", "c.nu", "--env-config", "e.nu"],
        &["nu", "-n", "--no-history", "-t", "4"],
        &["nu", "--log-level", "info", "-I", "/lib", "-m", "light"],
    ] {
        assert!(interactive(Syntax::Nu, words, true), "{words:?}");
    }
    for words in [
        &["nu", "-c", "ls"][..],
        &["nu", "--commands", "ls"],
        &["nu", "-i", "-c", "ls"],
        &["nu", "script.nu"],
        &["nu", "--config", "c.nu", "script.nu"],
        &["nu", "-e", "print hi", "script.nu"],
    ] {
        assert!(!interactive(Syntax::Nu, words, true), "{words:?}");
    }
    assert!(!interactive(Syntax::Nu, &["nu"], false));
    assert!(interactive(Syntax::Nu, &["nu", "--interactive"], false));
}

#[test]
fn elvish_reads_the_terminal_unless_it_runs_code_or_a_script() {
    for words in [
        &["elvish"][..],
        &["elvish", "-norc"],
        &["elvish", "--norc"],
        &["elvish", "-rc", "/etc/rc.elv"],
        &["elvish", "-rc=/etc/rc.elv"],
        &["elvish", "-log", "/tmp/log", "-deprecation-level", "20"],
        &["elvish", "-c=false"],
        &["elvish", "--"],
    ] {
        assert!(interactive(Syntax::Elvish, words, true), "{words:?}");
    }
    for words in [
        &["elvish", "-c", "echo"][..],
        &["elvish", "--c", "echo"],
        &["elvish", "-c=true", "echo"],
        &["elvish", "script.elv"],
        &["elvish", "-rc", "/etc/rc.elv", "script.elv"],
        &["elvish", "-norc", "script.elv"],
        &["elvish", "--", "script.elv"],
        &["elvish", "-"],
    ] {
        assert!(!interactive(Syntax::Elvish, words, true), "{words:?}");
    }
    assert!(!interactive(Syntax::Elvish, &["elvish"], false));
}

#[test]
fn xonsh_s_options_follow_its_interpreter_and_its_path() {
    for words in [
        &["/usr/bin/python3", "/usr/bin/xonsh"][..],
        &["/usr/bin/python3", "-sP", "/usr/bin/xonsh", "--login"],
        &[
            "/nix/store/x-python3/bin/python3.13",
            "/nix/store/y-xonsh/bin/.xonsh-wrapped",
        ],
        &["python3", "/usr/bin/xonsh", "--rc", "a.xsh", "b.xsh"],
        &["python3", "/usr/bin/xonsh", "-DXONSH_DEBUG=1"],
        &[
            "python3",
            "/usr/bin/xonsh",
            "-D",
            "XONSH_DEBUG=1",
            "--shell-type",
            "readline",
        ],
        &["python3", "/usr/bin/xonsh", "--no-rc", "-l"],
    ] {
        assert!(interactive(Syntax::Xonsh, words, true), "{words:?}");
    }
    for words in [
        &["python3", "/usr/bin/xonsh", "-c", "echo"][..],
        &["python3", "/usr/bin/xonsh", "-cecho"],
        &["python3", "/usr/bin/xonsh", "script.xsh"],
        &[
            "python3",
            "/usr/bin/xonsh",
            "--rc",
            "a.xsh",
            "--",
            "script.xsh",
        ],
        &[
            "python3",
            "/usr/bin/xonsh",
            "--shell-type",
            "readline",
            "script.xsh",
        ],
    ] {
        assert!(!interactive(Syntax::Xonsh, words, true), "{words:?}");
    }
    assert!(interactive(
        Syntax::Xonsh,
        &["python3", "/usr/bin/xonsh", "-i", "script.xsh"],
        false
    ));
}

#[test]
fn the_common_shells_are_shells_under_their_own_names() {
    for (name, syntax) in [
        ("sh", Syntax::Posix),
        ("bash", Syntax::Posix),
        ("rbash", Syntax::Posix),
        ("dash", Syntax::Posix),
        ("ash", Syntax::Posix),
        ("ksh", Syntax::Posix),
        ("ksh93", Syntax::Posix),
        ("rksh", Syntax::Posix),
        ("mksh", Syntax::Posix),
        ("lksh", Syntax::Posix),
        ("oksh", Syntax::Posix),
        ("loksh", Syntax::Posix),
        ("pdksh", Syntax::Posix),
        ("yash", Syntax::Posix),
        ("zsh", Syntax::Posix),
        ("tcsh", Syntax::Posix),
        ("csh", Syntax::Posix),
        ("fish", Syntax::Fish),
        ("nu", Syntax::Nu),
        ("elvish", Syntax::Elvish),
        ("xonsh", Syntax::Xonsh),
    ] {
        assert_eq!(shell_syntax(name), Some(syntax), "{name}");
        let wrapped = format!(".{name}-wrapped");
        assert_eq!(shell_syntax(&wrapped), Some(syntax), "{wrapped}");
    }
    for (name, syntax) in SHELL_NAMES {
        assert_eq!(shell_syntax(name), Some(*syntax), "{name}");
    }
    for name in [
        "sudo",
        "nails",
        "script",
        "bashbug",
        "zsh-newuser",
        "nu_plugin_query",
        "python3",
        "",
        "xonsh-wrapped",
        ".xonsh",
        ".-wrapped",
    ] {
        assert_eq!(shell_syntax(name), None, "{name}");
    }
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

/// Wait for the one process named `comm` whose stat passes `pick` to settle,
/// waiting for input, and return its pid.
fn settled(comm: &str, pick: impl Fn(&proc::Stat) -> bool) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let found = proc::pids().into_iter().find(|&pid| {
            proc::comm(pid).as_deref() == Some(comm)
                && proc::stat(pid).is_some_and(|stat| stat.state == 'S' && pick(&stat))
        });
        if let Some(pid) = found {
            return pid;
        }
        assert!(Instant::now() < deadline, "no {comm} settled");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// `program` on `PATH`, as a path.
fn on_path(program: &str) -> Option<std::path::PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join(program))
        .find(|path| path.is_file())
}

/// Whether `program` is on `PATH`.
fn installed(program: &str) -> bool {
    on_path(program).is_some()
}

/// Give the shells `command` starts `home` as their home and their only
/// configuration: an empty `.zshrc` there, so zsh asks no new user's
/// questions, and no other startup file, history file or directory of the
/// caller's.
fn in_home(command: &mut Command, home: &std::path::Path) {
    std::fs::write(home.join(".zshrc"), "").expect("write .zshrc");
    command
        .env("HOME", home)
        .env("ZDOTDIR", home)
        .env("TERM", "dumb")
        .env_remove("SHELL")
        .env_remove("ENV")
        .env_remove("BASH_ENV")
        .env_remove("HISTFILE")
        .env_remove("SAVEHIST");
    for xdg in [
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_STATE_HOME",
        "XDG_CACHE_HOME",
    ] {
        command.env_remove(xdg);
    }
}

/// Start `command` with `sh -c` on a terminal of its own, a pseudo-terminal
/// that `script` holds, its shells at home in `home` ([`in_home`]), and
/// return `script` and the pid of its child named `comm` once that waits for
/// input.
fn on_a_terminal(comm: &str, command: &str, home: &std::path::Path) -> (Child, u32) {
    let mut script = Command::new("script");
    script
        .args(["-qfec", command, "/dev/null"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    in_home(&mut script, home);
    let console = script.spawn().expect("spawn script");
    let id = console.id();
    let shell = settled(comm, |stat| stat.ppid == id);
    (console, shell)
}

#[test]
fn a_shell_reading_a_terminal_counts_whatever_its_other_descriptors() {
    let home = tempfile::tempdir().expect("tempdir");
    for (comm, command) in [
        // Interactive by zsh's rule and fish's, which ask for nothing else.
        ("zsh", "exec zsh -d 2>/dev/null"),
        ("fish", "exec fish -N -C 'set -g x 1' 2>/dev/null"),
        // Not interactive by bash's, which asks for standard error too: it
        // keeps no history, and counting it costs nothing.
        ("bash", "exec bash --norc --noprofile 2>/dev/null"),
    ] {
        if !installed(comm) {
            eprintln!("skipped {command}: no {comm} on PATH");
            continue;
        }
        let (console, shell) = on_a_terminal(comm, command, home.path());
        let seen = (
            proc::fd_is_terminal(shell, 0),
            proc::fd_is_terminal(shell, 2),
            is_interactive_shell(shell),
        );
        still_running(console);
        assert_eq!(seen, (true, false, true), "{command}");
    }
}

#[test]
fn a_shell_started_through_a_link_counts_under_the_link_s_name() {
    let Some(bash) = on_path("bash") else {
        eprintln!("skipped: no bash on PATH");
        return;
    };
    let home = tempfile::tempdir().expect("tempdir");
    let rbash = home.path().join("rbash");
    std::os::unix::fs::symlink(bash, &rbash).expect("link rbash to bash");
    let command = format!("exec {} --norc --noprofile", rbash.display());
    let (console, shell) = on_a_terminal("rbash", &command, home.path());
    let seen = is_interactive_shell(shell);
    still_running(console);
    assert!(seen, "rbash is bash under the name rbash");
}

/// Write `line` to the console, as typed on its keyboard.
fn type_into(console: &mut Child, line: &str) {
    use std::io::Write;
    let keyboard = console.stdin.as_mut().expect("keyboard");
    keyboard.write_all(line.as_bytes()).expect("type");
    keyboard.flush().expect("type");
}

/// A second shell typed at the console's prompt: the line that starts it and
/// the name of its process.
#[derive(Clone, Copy)]
struct Inner {
    line: &'static str,
    comm: &'static str,
}

/// bash, as `bash`, `su` or `nix-shell` typed at a prompt start one.
const BASH: Inner = Inner {
    line: "bash --norc --noprofile -i\n",
    comm: "bash",
};

/// zsh with its errors sent elsewhere: interactive all the same, as zsh asks
/// only for a terminal on its standard input.
const ZSH: Inner = Inner {
    line: "zsh -d 2>/dev/null\n",
    comm: "zsh",
};

/// A login shell on a console (a pseudo-terminal that `script` holds,
/// typed into through its stdin) with the `inner` shell in its foreground.
/// The inner shell has run a typed line, so it has history to write; both
/// write theirs to `history`, and keep their home beside it. Returns the
/// console and the login and the inner shell's pids, or `None`, saying so,
/// when the inner shell is not installed.
fn console_with_a_shell_in_its_foreground(
    history: &std::path::Path,
    inner: Inner,
) -> Option<(Child, u32, u32)> {
    if !installed(inner.comm) {
        eprintln!("skipped {}: not on PATH", inner.comm);
        return None;
    }
    let mut script = Command::new("script");
    script
        .args(["-qfec", "exec bash --norc --noprofile -i", "/dev/null"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    in_home(&mut script, history.parent().expect("a directory"));
    script.env("HISTFILE", history).env("SAVEHIST", "100");
    let mut console = script.spawn().expect("spawn script");
    let id = console.id();
    let login = settled("bash", |stat| stat.ppid == id);
    type_into(&mut console, inner.line);
    let inner = settled(inner.comm, |stat| stat.ppid == login);
    let typed = history.with_extension("typed");
    type_into(&mut console, &format!("touch {}\n", typed.display()));
    let deadline = Instant::now() + Duration::from_secs(5);
    while !typed.exists() {
        assert!(Instant::now() < deadline, "the inner shell ran nothing");
        std::thread::sleep(Duration::from_millis(5));
    }
    Some((console, login, inner))
}

#[test]
fn a_dying_login_shell_makes_its_foreground_shell_write_history() {
    in_pid_namespace(
        "shells::tests::a_dying_login_shell_makes_its_foreground_shell_write_history",
        || {
            for shell in [BASH, ZSH] {
                let dir = tempfile::tempdir().expect("tempdir");
                let history = dir.path().join("history");
                let Some((mut console, login, inner)) =
                    console_with_a_shell_in_its_foreground(&history, shell)
                else {
                    continue;
                };
                let inner = ProcessHandle::open(inner).expect("inner shell");

                // The login shell leads the console's session: as it dies,
                // the console's foreground job, the inner shell, gets SIGHUP.
                assert!(ProcessHandle::open(login).is_some_and(|login| login.kill()));
                let deadline = Instant::now() + Duration::from_secs(5);
                assert!(proc::await_exit(&[inner], deadline).is_empty());

                let written = std::fs::read_to_string(&history).unwrap_or_default();
                assert!(
                    written.contains("touch"),
                    "{} wrote no history: {written:?}",
                    shell.comm
                );
                let _ = console.kill();
                let _ = console.wait();
            }
        },
    );
}

#[test]
fn shells_die_newest_first_so_no_dying_shell_hangs_up_a_live_one() {
    in_pid_namespace(
        "shells::tests::shells_die_newest_first_so_no_dying_shell_hangs_up_a_live_one",
        || {
            for shell in [BASH, ZSH] {
                let dir = tempfile::tempdir().expect("tempdir");
                let history = dir.path().join("history");
                let Some((mut console, login, inner)) =
                    console_with_a_shell_in_its_foreground(&history, shell)
                else {
                    continue;
                };
                let shells = [login, inner].map(|pid| ProcessHandle::open(pid).expect("shell"));

                assert_eq!(
                    kill_interactive_shells_newest_first(),
                    vec![inner, login],
                    "{}",
                    shell.comm
                );

                let deadline = Instant::now() + Duration::from_secs(5);
                assert!(proc::await_exit(&shells, deadline).is_empty());
                assert!(
                    !history.exists(),
                    "a killed {} wrote its history: {:?}",
                    shell.comm,
                    std::fs::read_to_string(&history)
                );
                let _ = console.kill();
                let _ = console.wait();
            }
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
