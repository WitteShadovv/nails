// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! `nails gui` through the real binary: the gate that refuses before any
//! window starts, the operator it drops the window to, and the window and its
//! helper talking from the hello handshake on, detached from the launcher.
//!
//! Each test lays out a bundle the way a hidden volume holds one: the engine
//! (a link to the binary under test) and, beside it, `gui/bin/session`,
//! here a shell script that plays the window and records what it got (or a
//! link to the shell itself, whose command line is the one it was given). The
//! launcher runs without root (the test build does not enforce the root gate)
//! as the operator itself, so the drop is to the account it already has; its
//! checks still run. The operator's runtime directory is a private directory
//! on `/dev/shm`, a tmpfs, as `/run/user/<uid>` is.

#![cfg(feature = "gui")]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

use nails_api::protocol::{ErrorCode, Frame, Hello, Op, PROTOCOL_VERSION, Request};
use serde_json::Value;

/// How long a test waits for the window or the helper.
const PATIENCE: Duration = Duration::from_secs(30);

/// A bundle on disk and the directories around it.
struct Bundle {
    dir: tempfile::TempDir,
    runtime_base: tempfile::TempDir,
}

impl Bundle {
    /// A bundle whose window runs `script`, a shell body in which `$out` is
    /// the directory the test reads (`None`: no window installed).
    fn new(script: Option<&str>) -> Self {
        let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
        let engine = dir.path().join("nails");
        let binary = assert_cmd::cargo::cargo_bin!("nails");
        if std::fs::hard_link(binary, &engine).is_err() {
            std::fs::copy(binary, &engine).unwrap();
        }
        std::fs::create_dir(dir.path().join("out")).unwrap();
        if let Some(script) = script {
            let bin = dir.path().join("gui/bin");
            std::fs::create_dir_all(&bin).unwrap();
            let program = bin.join("session");
            let out = dir.path().join("out");
            std::fs::write(
                &program,
                format!("#!/bin/sh\nout='{}'\n{script}", out.display()),
            )
            .unwrap();
            std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let config = dir.path().join("nails.toml");
        let root = dir.path().join("hidden-volume");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(
            &config,
            format!(
                "hidden_volume_root = {:?}\nstate_file_path = {:?}\nshow_opsec_reminders = false\n",
                root.display().to_string(),
                root.join("state.json").display().to_string()
            ),
        )
        .unwrap();
        let runtime_base = tempfile::tempdir_in("/dev/shm").unwrap();
        let runtime = runtime_base.path().join(uid().to_string());
        std::fs::create_dir(&runtime).unwrap();
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self { dir, runtime_base }
    }

    /// A bundle whose window is the shell itself, reading the pair as its
    /// script: a program of its own, not a script, so its command line is
    /// the one the launcher gave it.
    fn with_shell_window() -> Self {
        let bundle = Self::new(None);
        let bin = bundle.dir.path().join("gui/bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::os::unix::fs::symlink("/bin/sh", bin.join("session")).unwrap();
        bundle
    }

    fn engine(&self) -> PathBuf {
        self.dir.path().join("nails")
    }

    fn out(&self, name: &str) -> PathBuf {
        self.dir.path().join("out").join(name)
    }

    fn runtime(&self) -> PathBuf {
        self.runtime_base.path().join(uid().to_string())
    }

    /// `nails --json gui` from a clean environment of `vars`, as pkexec
    /// leaves one: `PKEXEC_UID` names the operator, `SUDO_UID` (which pkexec
    /// of polkit 127 and later sets too) names root.
    fn launch(&self, vars: &[(&str, &str)]) -> (i32, Value) {
        self.launch_with(&self.dir.path().join("nails.toml"), None, vars)
    }

    /// [`launch`](Self::launch) with `--config config`, from the working
    /// directory `cwd` when given.
    fn launch_with(
        &self,
        config: &Path,
        cwd: Option<&Path>,
        vars: &[(&str, &str)],
    ) -> (i32, Value) {
        let mut command = Command::new(self.engine());
        if let Some(cwd) = cwd {
            command.current_dir(cwd);
        }
        let output: Output = command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("PKEXEC_UID", uid().to_string())
            .env("SUDO_UID", "0")
            .env("NAILS_TEST_USER_RUNTIME_BASE", self.runtime_base.path())
            .env("XDG_CURRENT_DESKTOP", "TEST")
            .env("SESSION_MANAGER", "local/host:@/tmp/.ICE-unix/1")
            .env("SOME_SECRET", "not-for-the-window")
            .envs(vars.iter().copied())
            .arg("--no-log-file")
            .arg("--config")
            .arg(config)
            .args(["--json", "gui"])
            .output()
            .expect("run the launcher");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let envelope = serde_json::from_str(stdout.trim())
            .unwrap_or_else(|e| panic!("not one envelope ({e}): {stdout}"));
        (output.status.code().unwrap_or(-1), envelope)
    }

    /// Wait until the window has written `name`.
    fn wait_for(&self, name: &str) {
        let start = Instant::now();
        while !self.out(name).exists() {
            assert!(start.elapsed() < PATIENCE, "the window never wrote {name}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn frame(&self, name: &str) -> Frame {
        let line = std::fs::read_to_string(self.out(name)).unwrap();
        serde_json::from_str(line.trim()).unwrap_or_else(|e| panic!("{e}: {line}"))
    }
}

fn uid() -> u32 {
    nix::unistd::getuid().as_raw()
}

fn ours() -> Hello {
    Hello {
        protocol: PROTOCOL_VERSION,
        engine: env!("CARGO_PKG_VERSION").to_string(),
    }
}

fn hello_line(engine: &str) -> String {
    Request {
        v: PROTOCOL_VERSION,
        id: 1,
        op: Op::Hello(Hello {
            protocol: PROTOCOL_VERSION,
            engine: engine.to_string(),
        }),
    }
    .to_line()
}

/// A window that takes the helper's hello, answers with its own, then waits
/// for the test's go and asks for the status.
fn greeting_window() -> String {
    let status = Request {
        v: PROTOCOL_VERSION,
        id: 2,
        op: Op::Status,
    }
    .to_line();
    format!(
        "echo $$ > \"$out/pid.part\" && mv \"$out/pid.part\" \"$out/pid\"\n\
         read -r line; printf '%s\\n' \"$line\" > \"$out/helper-hello\"\n\
         printf '%s\\n' '{hello}' >&0\n\
         read -r line; printf '%s\\n' \"$line\" > \"$out/hello-answer\"\n\
         : > \"$out/greeted\"\n\
         n=0; while [ ! -e \"$out/go\" ]; do n=$((n+1)); [ $n -lt 600 ] || exit 1; sleep 0.05; done\n\
         printf '%s\\n' '{status}' >&0\n\
         read -r line; printf '%s\\n' \"$line\" > \"$out/status-answer\"\n\
         : > \"$out/done\"\n",
        hello = hello_line(&ours().engine),
    )
}

/// Fields 6 (session) and 7 (controlling terminal) of `/proc/<pid>/stat`.
fn session_and_tty(pid: u32) -> (u32, i64) {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let after_comm = &stat[stat.rfind(')').unwrap() + 2..];
    let fields: Vec<&str> = after_comm.split(' ').collect();
    // After the comm: state, ppid, pgrp, session, tty_nr.
    (fields[3].parse().unwrap(), fields[4].parse().unwrap())
}

/// The value of `key:` in `/proc/<pid>/status`.
fn status_field(pid: u32, key: &str) -> String {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    status
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{key}:")))
        .map(|value| value.split_whitespace().collect::<Vec<_>>().join(" "))
        .unwrap_or_else(|| panic!("no {key} in the status of {pid}"))
}

/// The names in `/proc/<pid>/environ`, sorted. Only names: the values stay
/// out of any failure message.
fn environment_names(pid: u32) -> Vec<String> {
    let environ = std::fs::read(format!("/proc/{pid}/environ")).unwrap();
    let mut names: Vec<String> = environ
        .split(|b| *b == 0)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            let name = entry.split(|b| *b == b'=').next().unwrap_or_default();
            String::from_utf8_lossy(name).into_owned()
        })
        .collect();
    names.sort();
    names
}

fn environment_value(pid: u32, key: &str) -> Option<String> {
    let environ = std::fs::read(format!("/proc/{pid}/environ")).unwrap();
    environ.split(|b| *b == 0).find_map(|entry| {
        let text = String::from_utf8_lossy(entry);
        text.strip_prefix(&format!("{key}=")).map(str::to_string)
    })
}

/// Whether `pid` has ended (gone, or a zombie no one reaped yet).
fn ended(pid: u32) -> bool {
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Err(_) => true,
        Ok(stat) => stat[stat.rfind(')').unwrap() + 2..].starts_with('Z'),
    }
}

fn wait_until_ended(pid: u32) {
    let start = Instant::now();
    while !ended(pid) {
        assert!(start.elapsed() < PATIENCE, "process {pid} never ended");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The helper and the window a launch started. They outlive the launcher by
/// design, so a test that fails halfway must not leave them behind: dropping
/// this kills each one still running from `bundle`'s directory.
struct Started {
    helper: u32,
    window: u32,
    marker: String,
}

impl Started {
    fn from(bundle: &Bundle, envelope: &Value) -> Self {
        let pid = |key: &str| {
            u32::try_from(
                envelope["data"][key]
                    .as_u64()
                    .unwrap_or_else(|| panic!("{envelope}")),
            )
            .unwrap()
        };
        Self {
            helper: pid("helper_pid"),
            window: pid("window_pid"),
            marker: bundle.dir.path().display().to_string(),
        }
    }
}

impl Drop for Started {
    fn drop(&mut self) {
        for pid in [self.window, self.helper] {
            // Only a process that still runs from this bundle: never one that
            // took over the number after it ended.
            let ours = std::fs::read(format!("/proc/{pid}/cmdline"))
                .is_ok_and(|cmdline| String::from_utf8_lossy(&cmdline).contains(&self.marker));
            if ours && let Ok(pid) = i32::try_from(pid) {
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(pid),
                    nix::sys::signal::Signal::SIGKILL,
                );
            }
        }
    }
}

#[test]
fn the_window_and_its_helper_talk_detached_and_outlive_a_hangup() {
    let bundle = Bundle::new(Some(&greeting_window()));
    let (exit, envelope) = bundle.launch(&[("NAILS_TEST_ADMIT_WINDOW", "1")]);
    assert_eq!(exit, 0, "{envelope}");
    assert_eq!(envelope["command"], "gui");
    let started = Started::from(&bundle, &envelope);
    let (helper, window) = (started.helper, started.window);

    // The handshake, end to end: the helper's hello first, then its answer
    // to the window's. The launcher ran with PKEXEC_UID set and gave its
    // helper --config and --no-log-file, so the helper greets only because it
    // was not taken for one that pkexec started itself.
    bundle.wait_for("greeted");
    match bundle.frame("helper-hello") {
        Frame::Hello(hello) => assert_eq!(hello, ours()),
        other => panic!("the helper's first frame is {other:?}"),
    }
    match bundle.frame("hello-answer") {
        Frame::Result { id: 1, exit: 0, .. } => {}
        other => panic!("the hello was answered with {other:?}"),
    }
    let pid: u32 = std::fs::read_to_string(bundle.out("pid"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert_eq!(pid, window);

    // Each leads a session of its own, without a controlling terminal.
    for process in [helper, window] {
        assert_eq!(session_and_tty(process), (process, 0), "process {process}");
    }

    // The window runs as the operator pkexec named, with no way back to
    // privileges, in its own directory in the runtime directory. (The
    // supplementary groups go only in a drop from root, which this
    // unprivileged run does not make.)
    let me = uid().to_string();
    assert_eq!(
        status_field(window, "Uid"),
        [me.as_str(); 4].join(" "),
        "the window runs as PKEXEC_UID, not SUDO_UID"
    );
    assert_eq!(status_field(window, "NoNewPrivs"), "1");
    let names = environment_names(window);
    for left_out in ["SESSION_MANAGER", "SOME_SECRET", "PKEXEC_UID", "SUDO_UID"] {
        assert!(
            !names.iter().any(|n| n == left_out),
            "{left_out} reached the window: {names:?}"
        );
    }
    assert!(
        names.iter().any(|n| n == "XDG_CURRENT_DESKTOP"),
        "{names:?}"
    );
    let home = PathBuf::from(environment_value(window, "HOME").unwrap());
    assert_eq!(home.parent(), Some(bundle.runtime().as_path()));
    assert!(home.is_dir());
    assert_eq!(
        environment_value(window, "XDG_RUNTIME_DIR").map(PathBuf::from),
        Some(bundle.runtime())
    );
    // (The helper's descriptors cannot be read: it is not dumpable.)
    for fd in [1, 2] {
        assert_eq!(
            std::fs::read_link(format!("/proc/{window}/fd/{fd}")).unwrap(),
            Path::new("/dev/null"),
            "fd {fd} of the window"
        );
    }
    let window_pipe = std::fs::read_link(format!("/proc/{window}/fd/0")).unwrap();
    assert!(
        window_pipe.to_string_lossy().starts_with("socket:"),
        "{window_pipe:?}"
    );

    // A hangup does not end the helper: it still answers afterwards.
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(i32::try_from(helper).unwrap()),
        nix::sys::signal::Signal::SIGHUP,
    )
    .unwrap();
    std::thread::sleep(Duration::from_millis(200));
    assert!(!ended(helper), "a hangup ended the helper");
    std::fs::write(bundle.out("go"), "").unwrap();
    bundle.wait_for("done");
    match bundle.frame("status-answer") {
        Frame::Result {
            id: 2, envelope, ..
        } => assert_eq!(envelope["command"], "status"),
        other => panic!("the status was answered with {other:?}"),
    }

    // The window ended and closed its end: the helper ends too.
    wait_until_ended(helper);
}

#[test]
fn a_window_of_another_release_is_refused_and_its_helper_ends() {
    let script = format!(
        "read -r line\n\
         printf '%s\\n' '{hello}' >&0\n\
         read -r line; printf '%s\\n' \"$line\" > \"$out/hello-answer\"\n\
         if read -r line; then echo more > \"$out/after\"; else echo eof > \"$out/after\"; fi\n\
         : > \"$out/done\"\n",
        hello = hello_line("0.0.0-another"),
    );
    let bundle = Bundle::new(Some(&script));
    let (exit, envelope) = bundle.launch(&[("NAILS_TEST_ADMIT_WINDOW", "1")]);
    assert_eq!(exit, 0, "{envelope}");
    let started = Started::from(&bundle, &envelope);
    let helper = started.helper;
    bundle.wait_for("done");
    match bundle.frame("hello-answer") {
        Frame::Error { error, .. } => assert_eq!(error.code, ErrorCode::Handshake),
        other => panic!("a hello of another release was answered with {other:?}"),
    }
    assert_eq!(
        std::fs::read_to_string(bundle.out("after")).unwrap().trim(),
        "eof",
        "the helper closed the pipe after refusing the hello"
    );
    wait_until_ended(helper);
}

/// A relative `--config` names the file the launcher read for the helper as
/// well, which starts in `/`: the window asks for the configuration's path
/// and gets the launcher's, found.
#[test]
fn a_relative_configuration_is_the_helpers_too() {
    let ask = Request {
        v: PROTOCOL_VERSION,
        id: 2,
        op: Op::ConfigPath,
    }
    .to_line();
    let window = format!(
        "read -r line\n\
         printf '%s\\n' '{hello}' >&0\n\
         read -r line\n\
         printf '%s\\n' '{ask}' >&0\n\
         read -r line; printf '%s\\n' \"$line\" > \"$out/config-path\"\n\
         : > \"$out/done\"\n",
        hello = hello_line(&ours().engine),
    );
    let bundle = Bundle::new(Some(&window));
    let (exit, envelope) = bundle.launch_with(
        Path::new("nails.toml"),
        Some(bundle.dir.path()),
        &[("NAILS_TEST_ADMIT_WINDOW", "1")],
    );
    assert_eq!(exit, 0, "{envelope}");
    let _started = Started::from(&bundle, &envelope);
    bundle.wait_for("done");
    match bundle.frame("config-path") {
        Frame::Result {
            id: 2,
            exit: 0,
            envelope,
        } => {
            let expected = bundle.dir.path().join("nails.toml");
            assert_eq!(envelope["data"]["path"], expected.display().to_string());
            assert_eq!(envelope["data"]["exists"], true, "{envelope}");
        }
        other => panic!("the path was answered with {other:?}"),
    }
}

#[test]
fn the_decoy_gate_refuses_before_any_window_starts_and_says_why() {
    let bundle = Bundle::new(Some("echo started > \"$out/started\"\n"));
    let (exit, envelope) = bundle.launch(&[]);
    // No test host passes the decoy gate: no desktop is admitted yet, and
    // the host's journal may persist besides.
    assert!(exit == 8 || exit == 4, "exit {exit}: {envelope}");
    let code = envelope["error"]["code"].as_str().unwrap();
    assert!(
        ["desktop_untested", "decoy_persistent"].contains(&code),
        "{envelope}"
    );
    let message = envelope["error"]["message"].as_str().unwrap();
    assert!(
        message.contains("The window has not been tested on this desktop (TEST) yet"),
        "{message}"
    );
    let activate = format!("Use: sudo {} activate", bundle.engine().display());
    assert!(message.ends_with(&activate), "{message}");
    std::thread::sleep(Duration::from_millis(200));
    assert!(!bundle.out("started").exists(), "a window started");
    let entries = std::fs::read_dir(bundle.runtime()).unwrap().count();
    assert_eq!(entries, 0, "the refused launch made a directory");
}

#[test]
fn the_window_never_runs_as_root_and_needs_its_program() {
    let bundle = Bundle::new(None);
    let (exit, envelope) = bundle.launch(&[("PKEXEC_UID", "0"), ("NAILS_TEST_ADMIT_WINDOW", "1")]);
    assert_eq!(exit, 3, "{envelope}");
    assert_eq!(envelope["error"]["code"], "operator_is_root");

    let (exit, envelope) = bundle.launch(&[("NAILS_TEST_ADMIT_WINDOW", "1")]);
    assert_eq!(exit, 1, "{envelope}");
    assert_eq!(envelope["error"]["code"], "window_missing");
}

#[test]
fn the_window_starts_by_its_name_alone() {
    let bundle = Bundle::with_shell_window();
    let (exit, envelope) = bundle.launch(&[("NAILS_TEST_ADMIT_WINDOW", "1")]);
    assert_eq!(exit, 0, "{envelope}");
    let started = Started::from(&bundle, &envelope);
    let (helper, window) = (started.helper, started.window);
    // The window's whole command line is its name: no path for a log that
    // quotes it, dbus-daemon's at an activation the window starts, say.
    let cmdline = std::fs::read(format!("/proc/{window}/cmdline"));
    let comm = std::fs::read_to_string(format!("/proc/{window}/comm"));
    // The shell reads the pair for commands until it ends: end it here,
    // after the reads, so a failed assertion leaves nothing behind.
    if comm.is_ok_and(|comm| comm.trim_end() == "session") {
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(i32::try_from(window).unwrap()),
            nix::sys::signal::Signal::SIGKILL,
        );
    }
    assert_eq!(cmdline.unwrap(), b"session\0", "the window's command line");
    // Its end closed with it: the helper ends too.
    wait_until_ended(helper);
}
