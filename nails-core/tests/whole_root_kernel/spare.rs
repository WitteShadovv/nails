// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Whom the emergency's kill spares, on trees of real processes.
//!
//! A desktop shell stand-in leads a session and a process group of its own, as
//! a unit's main process does, and starts as its direct children, in both: an
//! app, a window with the helper the window starts, and a terminal (util-linux
//! `script`, which holds a pseudo-terminal) with an interactive shell on it.
//! A second window leads a session of its own, as an app unit does. Into the
//! shell goes the job: `sudo nails emergency | less` in the background, with
//! `script` as the `sudo`-like middle, which runs the command on a
//! pseudo-terminal of its own under a monitor that leads a session there and
//! gives the command a process group of its own, as `sudo` does; or
//! `nails emergency | cat` in the foreground.
//!
//! Each test runs as PID 1 of a PID namespace of its own
//! ([`Rerun::in_pid_ns`]), so every process it reads or signals is one it
//! started. The kill is the emergency's own in the cgroup it shares with what
//! it spares ([`kill::kill_unspared`] over [`kill::spared_pids`]): here every
//! process shares the test's cgroup. Killing the shell first stands for the
//! shell kill before the switch; the emergency stand-in is this test binary
//! with the hot path's signal dispositions. A terminal ends once its shell
//! has, as `script` does.

use nails_core::test_path;
use nails_core::test_support::{Rerun, ScratchTmpfs, skip_host};
use nails_teardown::proc::{self, Invocation, ProcessHandle};
use nails_teardown::whole_root::kill;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Set for the emergency stand-in: the directory of the tree.
const ROLE_ENV: &str = "NAILS_SPARE_ROLE_DIR";

/// What the emergency stand-in writes once it is told to: its report.
const REPORT: &str = "emergency report line";

/// How long a process of the tree may take to appear, settle or go.
const WAIT: Duration = Duration::from_secs(30);

/// The desktop shell stand-in: an app, a window with its helper, a window
/// leading a session of its own with its helper, and a terminal running an
/// interactive shell on the job script.
const DESKTOP: &str = r#"d=$1
sleep 600 &
echo $! > "$d/app.pid"
sh "$d/window.sh" "$d" window helper &
setsid sh "$d/window.sh" "$d" window2 helper2 &
script -qfc "exec sh -i -m '$d/job.sh' '$d'" /dev/null < "$d/hold" > /dev/null 2>&1 &
echo $! > "$d/terminal.pid"
echo $$ > "$d/desktop.pid"
wait
"#;

/// A window and the helper it starts as its child.
const WINDOW: &str = r#"d=$1
echo $$ > "$d/$2.pid"
sleep 600 &
echo $! > "$d/$3.pid"
wait
"#;

/// The interactive shell's input. `sudo` is `script` running the command
/// under a monitor (`sh -c` with job control, so the command gets a process
/// group of its own) on a pseudo-terminal of its own, a job in the
/// background: the shell's death sends SIGHUP to the job in the foreground, on
/// which `script`, unlike `sudo`, ends its command. `direct` is nails with its
/// pipe reader, a job in the foreground.
const JOB: &str = r#"d=$1
echo $$ > "$d/shell.pid"
stand_in="'$ROLE' '$ROLE_TEST' --exact --nocapture --test-threads 1"
reader='echo $$ > "$1/reader.pid"; exec cat > "$1/reader.out"'
case $JOB in
sudo)
    script -qfc "set -m; echo \$\$ > '$d/monitor.pid'; $stand_in; :" /dev/null < "$d/hold" \
        | sh -c "$reader" sh "$d" &
    ;;
direct)
    "$ROLE" "$ROLE_TEST" --exact --nocapture --test-threads 1 | sh -c "$reader" sh "$d"
    ;;
esac
sleep 600
"#;

/// A tree of processes below a desktop shell stand-in, in a scratch tmpfs.
struct Tree {
    dir: ScratchTmpfs,
    /// Keeps the terminals' input open, so neither reads its end.
    _hold: std::fs::File,
    desktop: Child,
}

impl Tree {
    /// Start the desktop with the interactive shell running `job` (`sudo`,
    /// `direct`, or anything else for none).
    fn start(job: &str) -> Self {
        // Every kill here takes every process but this one: never let it
        // loose outside a PID namespace of the test's own.
        assert_eq!(std::process::id(), 1, "the tree must be built as PID 1");
        let Some(shell) = on_path("sh") else {
            skip_host("no sh on PATH");
        };
        if on_path("script").is_none() || on_path("setsid").is_none() {
            skip_host("util-linux's script and setsid are not on PATH");
        }
        let dir = ScratchTmpfs::new("");
        for (name, text) in [
            ("desktop.sh", DESKTOP),
            ("window.sh", WINDOW),
            ("job.sh", JOB),
        ] {
            std::fs::write(dir.path().join(name), text).unwrap();
        }
        nix::unistd::mkfifo(
            &dir.path().join("hold"),
            nix::sys::stat::Mode::from_bits_truncate(0o600),
        )
        .expect("make a fifo");
        let hold = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(dir.path().join("hold"))
            .expect("open the terminals' input");
        let desktop = Command::new("setsid")
            .arg("sh")
            .arg(dir.path().join("desktop.sh"))
            .arg(dir.path())
            .env("SHELL", &shell)
            .env("HOME", dir.path())
            .env("HISTFILE", "/dev/null")
            .env_remove("ENV")
            .env("JOB", job)
            .env("ROLE", std::env::current_exe().unwrap())
            .env("ROLE_TEST", test_path!(emergency_stand_in))
            .env(ROLE_ENV, dir.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start the desktop stand-in");
        Self {
            dir,
            _hold: hold,
            desktop,
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// The pid the process `name` wrote, once it has.
    fn pid(&self, name: &str) -> u32 {
        let path = self.path(&format!("{name}.pid"));
        wait_until(&format!("{name} to start"), || {
            std::fs::read_to_string(&path)
                .ok()
                .and_then(|text| text.trim().parse().ok())
        })
    }

    /// The pids of `names`.
    fn pids<const N: usize>(&self, names: [&str; N]) -> [u32; N] {
        names.map(|name| self.pid(name))
    }

    /// Let the emergency stand-in write its report, and read back how its
    /// writes to standard output and standard error ended.
    fn report(&self) -> String {
        std::fs::write(self.path("go"), "").unwrap();
        let done = self.path("emergency.done");
        wait_until("the emergency stand-in to finish its report", || {
            std::fs::read_to_string(&done).ok()
        })
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        // Every process but this one, so none writes into the scratch tmpfs
        // while it goes.
        kill::kill_unspared(others(), &[]);
        let _ = self.desktop.wait();
    }
}

/// Every process of the PID namespace but this one, its PID 1.
fn others() -> Vec<u32> {
    assert_eq!(
        std::process::id(),
        1,
        "only PID 1 of the test's namespace kills"
    );
    proc::pids().into_iter().filter(|&pid| pid != 1).collect()
}

/// `program` on `PATH`, as an absolute path.
fn on_path(program: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join(program))
        .find(|path| path.is_file())
}

/// Poll `f` until it gives a value, at most [`WAIT`]; panic naming `what`.
fn wait_until<T>(what: &str, mut f: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + WAIT;
    loop {
        if let Some(value) = f() {
            return value;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Whether `pid` still runs (a zombie has ended).
fn alive(pid: u32) -> bool {
    proc::stat(pid).is_some_and(|s| s.state != 'Z' && s.state != 'X')
}

/// Wait until `pid` has ended.
fn gone(pid: u32) {
    wait_until(&format!("{pid} to end"), || (!alive(pid)).then_some(()));
}

/// Whether `pid` is a process of the tree that `invocation` spares.
fn spares(invocation: &Invocation, pid: u32) -> bool {
    invocation.contains(pid, proc::stat(pid).as_ref())
}

/// The kill the emergency runs in its own cgroup, over every process here but
/// this one. Returns the pids it killed.
fn kill_all_but(invocation: &Invocation) -> Vec<u32> {
    let spare = kill::spared_pids(invocation);
    kill::kill_unspared(others(), &spare)
}

/// SIGKILL `pid`, as the shell kill before the switch does, and wait for it.
fn kill_now(pid: u32) {
    assert!(others().contains(&pid), "{pid} is no process of the tree");
    assert!(
        ProcessHandle::open(pid).is_some_and(|handle| handle.kill()),
        "{pid} could not be killed"
    );
    gone(pid);
}

/// The emergency stand-in: with the hot path's signal dispositions, it tells
/// the tree its pid, waits to be told to go, writes its report to standard
/// output and standard error, and records how each write ended. Run as a test
/// on its own, it does nothing.
#[test]
fn emergency_stand_in() {
    let Some(dir) = std::env::var_os(ROLE_ENV).map(PathBuf::from) else {
        return;
    };
    nails_teardown::whole_root::tools::survive_session_stop();
    std::fs::write(dir.join("emergency.pid"), std::process::id().to_string()).unwrap();
    wait_until("the go", || dir.join("go").exists().then_some(()));
    let out = writeln!(std::io::stdout(), "{REPORT}").and_then(|()| std::io::stdout().flush());
    let err = writeln!(std::io::stderr(), "{REPORT}");
    let ended = |result: std::io::Result<()>| match result {
        Ok(()) => "written".to_string(),
        Err(e) => format!("os error {}", e.raw_os_error().unwrap_or(0)),
    };
    std::fs::write(
        dir.join("emergency.done"),
        format!("{}\n{}\n", ended(out), ended(err)),
    )
    .unwrap();
}

#[test]
fn a_window_s_helper_spares_itself_alone() {
    let _ = Rerun::new(test_path!(a_window_s_helper_spares_itself_alone))
        .in_pid_ns()
        .run(|| {
            let tree = Tree::start("none");
            let [
                desktop,
                app,
                window,
                helper,
                window2,
                helper2,
                terminal,
                shell,
            ] = tree.pids([
                "desktop", "app", "window", "helper", "window2", "helper2", "terminal", "shell",
            ]);
            let everyone = [
                desktop, app, window, helper, window2, helper2, terminal, shell,
            ];

            let invocation = Invocation::of(helper);
            assert_eq!(invocation.chain, [helper]);
            assert!(invocation.ancestry.starts_with(&[helper, window, desktop]));
            for pid in everyone {
                assert_eq!(spares(&invocation, pid), pid == helper, "{pid}");
            }
            // A window leading a session of its own, as an app unit does,
            // spares its helper alone too.
            let in_its_own = Invocation::of(helper2);
            for pid in everyone {
                assert_eq!(spares(&in_its_own, pid), pid == helper2, "{pid}");
            }

            let killed = kill_all_but(&invocation);
            assert!(killed.contains(&desktop), "{killed:?}");
            assert!(!killed.contains(&helper), "{killed:?}");
            for pid in everyone.into_iter().filter(|&pid| pid != helper) {
                gone(pid);
            }
            assert!(alive(helper));
        });
}

#[test]
fn a_background_job_keeps_its_sudo_chain_and_its_pipe_reader() {
    let _ = Rerun::new(test_path!(
        a_background_job_keeps_its_sudo_chain_and_its_pipe_reader
    ))
    .in_pid_ns()
    .run(|| {
        let tree = Tree::start("sudo");
        let [
            emergency,
            monitor,
            reader,
            shell,
            terminal,
            desktop,
            app,
            window,
            helper,
        ] = tree.pids([
            "emergency",
            "monitor",
            "reader",
            "shell",
            "terminal",
            "desktop",
            "app",
            "window",
            "helper",
        ]);
        let sudo = proc::stat(monitor).unwrap().ppid;
        assert_eq!(proc::stat(sudo).unwrap().ppid, shell);
        // As under `sudo`, the command leads a process group of its own.
        assert_eq!(proc::stat(emergency).unwrap().pgid, emergency);

        // Read, as the hot path reads it, before the shell is killed.
        let invocation = Invocation::of(emergency);
        assert_eq!(invocation.chain, [emergency, monitor, sudo]);
        for pid in [emergency, monitor, sudo, reader] {
            assert!(spares(&invocation, pid), "{pid}");
        }
        for pid in [shell, terminal, desktop, app, window, helper] {
            assert!(!spares(&invocation, pid), "{pid}");
        }

        // The shell's death takes its terminal from the job: read after it,
        // the chain would hold nails alone.
        kill_now(shell);
        assert_eq!(Invocation::of(emergency).chain, [emergency]);

        let killed = kill_all_but(&invocation);
        assert!(killed.contains(&desktop), "{killed:?}");
        for pid in [terminal, desktop, app, window, helper] {
            gone(pid);
        }
        for pid in [emergency, monitor, sudo, reader] {
            assert!(alive(pid), "{pid}");
        }

        // The report still reaches the pipe reader of the job in the
        // background, through `sudo`.
        assert_eq!(tree.report(), "written\nwritten\n");
        let out = tree.path("reader.out");
        wait_until("the report at the pipe reader", || {
            let text = std::fs::read_to_string(&out).unwrap_or_default();
            (text.matches(REPORT).count() == 2).then_some(())
        });
    });
}

#[test]
fn a_foreground_reader_ends_at_the_shell_kill_and_the_emergency_runs_on() {
    let _ = Rerun::new(test_path!(
        a_foreground_reader_ends_at_the_shell_kill_and_the_emergency_runs_on
    ))
    .in_pid_ns()
    .run(|| {
        let tree = Tree::start("direct");
        let [emergency, reader, shell, terminal] =
            tree.pids(["emergency", "reader", "shell", "terminal"]);
        assert_eq!(proc::stat(emergency).unwrap().ppid, shell);

        // The job leads its own process group, its reader in it.
        let invocation = Invocation::of(emergency);
        assert_eq!(invocation.chain, [emergency]);
        assert!(spares(&invocation, reader));

        // The shell's death sends the job in the foreground SIGHUP: the
        // reader ends there, before any kill, and the stand-in runs on.
        kill_now(shell);
        gone(reader);
        assert!(alive(emergency));
        kill_all_but(&invocation);
        gone(terminal);
        assert!(alive(emergency));

        // Its report meets a pipe without a reader and a terminal that has
        // gone: both writes fail, and the stand-in runs on to its end, which
        // no signal brings.
        assert_eq!(
            tree.report(),
            format!(
                "os error {}\nos error {}\n",
                nix::libc::EPIPE,
                nix::libc::EIO
            )
        );
        let out = std::fs::read_to_string(tree.path("reader.out")).unwrap_or_default();
        assert!(!out.contains(REPORT), "{out}");
        let pid = nix::unistd::Pid::from_raw(i32::try_from(emergency).unwrap());
        let ended = wait_until("the stand-in to end", || {
            match nix::sys::wait::waitpid(pid, Some(nix::sys::wait::WaitPidFlag::WNOHANG)) {
                Ok(nix::sys::wait::WaitStatus::StillAlive) => None,
                other => Some(other),
            }
        });
        assert!(
            matches!(ended, Ok(nix::sys::wait::WaitStatus::Exited(..))),
            "{ended:?}"
        );
    });
}
