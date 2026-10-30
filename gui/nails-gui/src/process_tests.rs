// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

use std::ffi::OsStr;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use super::*;
use crate::worker::Connect;

/// The variable that tells a test binary started by [`in_child`] which test
/// it runs as the child.
const CHILD: &str = "NAILS_GUI_TEST_CHILD";

/// How long a child test may take before it is ended and the test fails.
const LIMIT: Duration = Duration::from_secs(60);

/// Whether this run of `test` is the child [`in_child`] started.
fn is_child(test: &str) -> bool {
    std::env::var_os(CHILD).as_deref() == Some(OsStr::new(test))
}

/// Run `test` again in a process of its own, with `vars` added, and return
/// its exit status: what a test changes for its whole process (a limit, the
/// dumpable flag) or what replaces the process (`exec`) stays in that child.
fn in_child(test: &str, vars: &[(&str, &OsStr)]) -> std::process::ExitStatus {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([test, "--exact", "--nocapture", "--test-threads=1"])
        .env(CHILD, test)
        .envs(vars.iter().copied())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("the test binary starts again");
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().expect("the child can be waited for") {
            return status;
        }
        if started.elapsed() > LIMIT {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the child of {test} did not end within {LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// A private directory of its own on `/dev/shm`, a tmpfs, as logind's
/// `/run/user/<uid>` is; removed when it is dropped.
struct Runtime(PathBuf);

impl Runtime {
    fn new() -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let dir = Path::new("/dev/shm").join(format!(
            "nails-gui-runtime-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir(&dir).expect("a directory on /dev/shm");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn env(pairs: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
    pairs
        .iter()
        .map(|(key, value)| (OsString::from(key), OsString::from(value)))
        .collect()
}

/// What a desktop hands a program its menu entry starts: the session's whole
/// environment.
fn desktop() -> Vec<(OsString, OsString)> {
    env(&[
        ("HOME", "/home/operator"),
        ("USER", "operator"),
        ("SHELL", "/bin/bash"),
        ("PATH", "/home/operator/bin:/usr/bin"),
        ("LD_PRELOAD", "/nonexistent/preload.so"),
        ("SESSION_MANAGER", "local/host:@/tmp/.ICE-unix/1"),
        ("SLINT_DEBUG_PERFORMANCE", "refresh_lazy"),
        ("SOME_SECRET", "not-for-the-window"),
        ("DISPLAY", ":0"),
        ("LANG", "C.UTF-8"),
        ("XDG_CURRENT_DESKTOP", "GNOME"),
    ])
}

fn uid() -> u32 {
    rustix::process::getuid().as_raw()
}

/// The `NoNewPrivs:` line of this test process, which a child it starts
/// inherits: 0 unless whatever runs the tests set it.
fn inherited_no_new_privs() -> String {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find(|line| line.starts_with("NoNewPrivs:"))
        .unwrap()
        .to_string()
}

#[test]
fn the_thread_takes_the_neutral_name() {
    // A test runs on a thread of its own, which the name is given to alone:
    // nothing else of the test binary changes its name.
    name_neutrally().unwrap();
    let comm = std::fs::read_to_string("/proc/thread-self/comm").unwrap();
    assert_eq!(comm.trim_end(), "session");
    let child = std::thread::spawn(|| std::fs::read_to_string("/proc/thread-self/comm"))
        .join()
        .unwrap()
        .unwrap();
    assert_eq!(
        child.trim_end(),
        "session",
        "a thread started afterwards inherits it"
    );
}

#[test]
fn the_window_turns_off_core_dumps_dumping_and_new_privileges() {
    const TEST: &str = "process::tests::the_window_turns_off_core_dumps_dumping_and_new_privileges";
    if !is_child(TEST) {
        assert!(in_child(TEST, &[]).success(), "the child's checks failed");
        return;
    }
    use rustix::process::{DumpableBehavior, Resource, Rlimit, dumpable_behavior, getrlimit};
    limit().unwrap();
    assert_eq!(
        getrlimit(Resource::Core),
        Rlimit {
            current: Some(0),
            maximum: Some(0)
        }
    );
    assert_eq!(dumpable_behavior().unwrap(), DumpableBehavior::NotDumpable);
    assert!(rustix::thread::no_new_privs().unwrap());
}

#[test]
fn the_desktops_environment_is_not_the_allowlists_and_the_allowlists_own_is() {
    let runtime = Runtime::new();
    let own = runtime.path().join("0011223344556677");
    let _bus = UnixListener::bind(runtime.path().join("bus")).unwrap();
    assert!(!runs_on_allowlist(&desktop(), runtime.path()));

    let allowlisted = window_env::vars(pairs(&desktop()), runtime.path(), &own);
    assert!(runs_on_allowlist(&allowlisted, runtime.path()));

    // A variable more, or a home elsewhere, is not the allowlist's own.
    let mut more = allowlisted.clone();
    more.push((OsString::from("LD_PRELOAD"), OsString::from("/x.so")));
    assert!(!runs_on_allowlist(&more, runtime.path()));
    let elsewhere = window_env::vars(pairs(&desktop()), runtime.path(), Path::new("/tmp/own"));
    assert!(!runs_on_allowlist(&elsewhere, runtime.path()));
    let homeless: Vec<(OsString, OsString)> = allowlisted
        .iter()
        .filter(|(key, _)| key != "HOME")
        .cloned()
        .collect();
    assert!(!runs_on_allowlist(&homeless, runtime.path()));
}

#[test]
fn a_runtime_directory_the_window_may_not_use_starts_nothing() {
    let runtime = Runtime::new();
    std::fs::set_permissions(runtime.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let restart = Restart {
        program: Path::new("/nonexistent/session"),
        args: &[],
        input: b"/mnt/data/nails",
    };
    let refused = restart_on_allowlist(runtime.path(), uid(), &restart, &desktop()).unwrap_err();
    assert!(
        refused.ends_with("cannot be used: other accounts can reach it (mode 755)"),
        "{refused}"
    );
    let missing = runtime.path().join("missing");
    let refused = restart_on_allowlist(&missing, uid(), &restart, &desktop()).unwrap_err();
    assert!(refused.starts_with(&format!("{} cannot be used: ", missing.display())));
    // Nothing was made in either.
    assert_eq!(std::fs::read_dir(runtime.path()).unwrap().count(), 0);
}

/// The script the menu entry's start is replaced by in the test below: it
/// records, into `out`, what the process it now is got. Each fact is read in
/// a command substitution, before anything is redirected to `out`, so the
/// shell's own standard streams are the ones it was started with; its
/// standard input last, read to its end.
fn recorder(out: &Path) -> String {
    format!(
        "f0=$(readlink /proc/$$/fd/0)\n\
         f1=$(readlink /proc/$$/fd/1)\n\
         f2=$(readlink /proc/$$/fd/2)\n\
         d=$(pwd)\n\
         n=$(grep '^NoNewPrivs:' /proc/$$/status)\n\
         c=$(ulimit -c)\n\
         h=$(ulimit -Hc)\n\
         e=$(env | sed 's/=.*//' | tr '\\n' ' ')\n\
         a=$(tr '\\0' '\\n' < /proc/$$/cmdline | head -n 1)\n\
         i=$(cat)\n\
         printf '%s\\n' \"$f0\" \"$f1\" \"$f2\" \"$d\" \"$n\" \"$c\" \"$h\" \"HOME=$HOME\" \"$e\" \
         \"$a\" \"$i\" > '{}'\n",
        out.display()
    )
}

#[test]
fn a_menu_entrys_start_runs_again_on_the_allowlist_without_core_dumps() {
    const TEST: &str =
        "process::tests::a_menu_entrys_start_runs_again_on_the_allowlist_without_core_dumps";
    if is_child(TEST) {
        // The child: the start that a menu entry made, which replaces itself
        // with the recorder, standing in for the window's program.
        let runtime = PathBuf::from(std::env::var_os("NAILS_GUI_TEST_RUNTIME").unwrap());
        let out = PathBuf::from(std::env::var_os("NAILS_GUI_TEST_OUT").unwrap());
        let args = [OsString::from("-c"), OsString::from(recorder(&out))];
        let restart = Restart {
            program: Path::new("/bin/sh"),
            args: &args,
            input: b"/mnt/data/nails",
        };
        let error = restart_on_allowlist(&runtime, uid(), &restart, &desktop());
        panic!("the start did not run again: {error:?}");
    }
    let runtime = Runtime::new();
    let out = runtime.path().join("recorded");
    let status = in_child(
        TEST,
        &[
            ("NAILS_GUI_TEST_RUNTIME", runtime.path().as_os_str()),
            ("NAILS_GUI_TEST_OUT", out.as_os_str()),
        ],
    );
    assert!(status.success(), "the recorder ended with {status}");
    let recorded = std::fs::read_to_string(&out).unwrap();
    let lines: Vec<&str> = recorded.lines().collect();
    // Its input is the pipe that holds the engine, its output /dev/null. No
    // core dumps, but no_new_privs not yet: the window starts pkexec before
    // it sets that.
    assert!(lines[0].starts_with("pipe:"), "{recorded}");
    let no_new_privs = inherited_no_new_privs();
    assert_eq!(
        lines[1..7],
        [
            "/dev/null",
            "/dev/null",
            "/",
            no_new_privs.as_str(),
            "0",
            "0"
        ],
        "its streams, its directory and its limits: {recorded}"
    );
    // Started by the window's name alone, with the engine on its input.
    assert_eq!(lines[9..11], ["session", "/mnt/data/nails"], "{recorded}");
    // Its home is a fresh directory of its own in the runtime directory.
    let home = lines[7].strip_prefix("HOME=").unwrap();
    let home = Path::new(home);
    assert_eq!(home.parent(), Some(runtime.path()), "{recorded}");
    let mode = std::fs::metadata(home).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);
    // The allowlist and nothing else: the desktop's variables are gone.
    // A shell exports a few variables of its own.
    let mut names: Vec<&str> = lines[8]
        .split_whitespace()
        .filter(|name| !["PWD", "OLDPWD", "SHLVL", "_"].contains(name))
        .collect();
    names.sort_unstable();
    let mut expected: Vec<String> = window_env::vars(pairs(&desktop()), runtime.path(), home)
        .into_iter()
        .map(|(key, _)| key.to_string_lossy().into_owned())
        .collect();
    expected.sort();
    assert_eq!(names, expected, "{recorded}");
    for gone in [
        "USER",
        "SHELL",
        "LD_PRELOAD",
        "SESSION_MANAGER",
        "SOME_SECRET",
    ] {
        assert!(!names.contains(&gone), "{gone} reached the window");
    }
}

/// A directory of its own for a stand-in program; removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("nails-gui-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn pkexec_starts_before_the_window_sets_no_new_privs() {
    const TEST: &str = "process::tests::pkexec_starts_before_the_window_sets_no_new_privs";
    if is_child(TEST) {
        // The order of a menu entry's start: pkexec, then the limits.
        let pkexec = PathBuf::from(std::env::var_os("NAILS_GUI_TEST_PKEXEC").unwrap());
        let connect = Connect::pkexec(Ok(pkexec), Path::new("/mnt/data/nails"));
        limit().unwrap();
        assert!(rustix::thread::no_new_privs().unwrap());
        let (mut child, stream) = match connect {
            Connect::Pkexec { child, stream } => (child, stream),
            other => panic!("pkexec did not start: {other:?}"),
        };
        drop(stream);
        let started = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            assert!(started.elapsed() < LIMIT, "pkexec did not end");
            std::thread::sleep(Duration::from_millis(20));
        };
        assert!(status.success(), "{status}");
        return;
    }
    let scratch = Scratch::new("pkexec-order");
    let out = scratch.0.join("recorded");
    let pkexec = scratch.0.join("pkexec");
    std::fs::write(
        &pkexec,
        format!(
            "#!/bin/sh\ngrep '^NoNewPrivs:' /proc/$$/status > '{}'\n",
            out.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&pkexec, std::fs::Permissions::from_mode(0o755)).unwrap();
    let status = in_child(TEST, &[("NAILS_GUI_TEST_PKEXEC", pkexec.as_os_str())]);
    assert!(status.success(), "the child's checks failed: {status}");
    // pkexec ran as the window would start it: without no_new_privs, so its
    // set-user-ID bit counts.
    assert_eq!(
        std::fs::read_to_string(&out).unwrap().trim_end(),
        inherited_no_new_privs()
    );
}

#[test]
fn a_menu_entrys_start_again_names_no_path_on_its_command_line() {
    assert_eq!(RESTART_ARGS, ["--engine", "-"]);
    assert!(RESTART_ARGS.iter().all(|arg| !arg.contains('/')));
    // The engine comes whole on standard input instead.
    assert_eq!(
        read_engine(&b"/mnt/data/nails"[..]),
        Ok(PathBuf::from("/mnt/data/nails"))
    );
    assert_eq!(
        read_engine(&[b'a'; 4096][..]).map(|engine| engine.as_os_str().len()),
        Ok(4096)
    );
    assert_eq!(
        read_engine(&b""[..]),
        Err("no engine came on standard input".to_string())
    );
    assert_eq!(
        read_engine(&[b'a'; 4097][..]),
        Err("the engine on standard input is longer than a path".to_string())
    );
    // One longer than a path is never handed over.
    let runtime = Runtime::new();
    let restart = Restart {
        program: Path::new("/nonexistent/session"),
        args: &[],
        input: &[b'a'; 4097],
    };
    let refused = restart_on_allowlist(runtime.path(), uid(), &restart, &desktop()).unwrap_err();
    assert_eq!(
        refused,
        "the window could not hand itself its engine: its path is too long"
    );
    assert_eq!(std::fs::read_dir(runtime.path()).unwrap().count(), 0);
}
