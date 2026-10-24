// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Real-kernel test support: run a test body in a re-executed child process,
//! optionally inside a fresh, unprivileged user + mount namespace.
//!
//! The mocks cannot show what the kernel does: which device an overlay reports
//! for its files, what `/proc/<pid>/fdinfo` says about an fd opened before a
//! mount, whether a read bumps an access time, what a write to a closed pipe
//! returns. These helpers let an ordinary `cargo test` ask the kernel directly,
//! with no root and no effect on the host.
//!
//! [`Rerun`] spawns the current test binary again, filtered to the one calling
//! test (`--exact`), and marks the child through [`CHILD_ENV`]. In the child the
//! same test function calls [`Rerun::run`] again, which now runs the body. With
//! [`Rerun::in_user_mount_ns`] the child is moved into a new user namespace (the
//! caller's uid and gid mapped to 0) and a new mount namespace *before* `exec`,
//! while it is still single-threaded, as `unshare(CLONE_NEWUSER)` requires. Its
//! root mount is then made recursively private, so every mount the body makes
//! (tmpfs, overlay, bind) is invisible to the host and disappears when the child
//! exits, even after a panic.
//!
//! Re-executing instead of forking keeps the child a fresh process: no other
//! test thread can be holding a lock at the moment of the fork, and the same
//! pattern works under libtest and nextest alike.
//!
//! A host that cannot create the namespaces (user namespaces disabled, or
//! Ubuntu's `kernel.apparmor_restrict_unprivileged_userns=1`, which grants the
//! namespace no capabilities) yields [`Outcome::Skipped`] with the reason, so the
//! test passes vacuously there. Setting [`REQUIRE_USERNS_ENV`] to `1` turns that
//! skip into a failure; CI sets it in the job that must exercise these tests. A
//! test that also needs something no CI runner has (a delegated cgroup, a NixOS
//! store) ends with [`skip_host`] instead, which that variable leaves a skip.
//!
//! [`write_executable`] writes a stub tool, a script or a copied program that a
//! test then runs, without this process ever holding the file open for writing
//! (see there). It lives in `nails_teardown::test_support`, so that the crate
//! below this one can use it too, and is re-exported here.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub use nails_teardown::test_support::write_executable;

/// Environment variable naming the test the re-executed child must run.
pub const CHILD_ENV: &str = "NAILS_TEST_CHILD";

/// Set to `1` to fail, instead of skip, when no user namespace is available.
pub const REQUIRE_USERNS_ENV: &str = "NAILS_REQUIRE_USERNS";

/// Exit status of a child that found no usable namespace (the automake "skip").
const SKIP_EXIT: i32 = 77;

/// Exit status of a child that lacks a host prerequisite other than namespaces.
const HOST_SKIP_EXIT: i32 = 78;

/// Prefix of the line a skipping child prints on stderr, followed by the reason.
const SKIP_MARKER: &str = "NAILS_TEST_SKIP: ";

/// The libtest name of the test function `$f`, for [`Rerun::new`].
///
/// libtest names a test by its module path without the crate name: a function at
/// the top of an integration test file is just `f`, one in a library module is
/// `module::tests::f`.
#[macro_export]
macro_rules! test_path {
    ($f:ident) => {{
        let full = concat!(module_path!(), "::", stringify!($f));
        full.split_once("::").map_or(full, |(_, rest)| rest)
    }};
}

/// How a [`Rerun`] ended, seen from the calling test.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "a skipped real-kernel test asserted nothing"]
pub enum Outcome {
    /// The body ran (in this process, when this is the child) and passed.
    Ran,
    /// The host could not provide the namespaces, or a prerequisite the body
    /// probes; the body did not run.
    Skipped(String),
}

/// A re-execution of the calling test in a child process. See the module docs.
pub struct Rerun<'a> {
    test_path: &'a str,
    user_mount_ns: bool,
    cgroup_ns: bool,
    pid_ns: bool,
    stderr: Option<Stdio>,
}

/// Set in the PID-namespace child (see [`Rerun::in_pid_ns`]) so it runs the
/// body instead of spawning another.
const PID1_ENV: &str = "NAILS_TEST_PID1";

impl<'a> Rerun<'a> {
    /// Re-run the test named `test_path` (use [`test_path!`]).
    pub fn new(test_path: &'a str) -> Self {
        Self {
            test_path,
            user_mount_ns: false,
            cgroup_ns: false,
            pid_ns: false,
            stderr: None,
        }
    }

    /// Run the child in a fresh user + mount namespace, as uid 0 inside it.
    pub fn in_user_mount_ns(mut self) -> Self {
        self.user_mount_ns = true;
        self
    }

    /// Also give the child its own cgroup namespace, rooted at the caller's
    /// cgroup, so a cgroup2 mounted inside sees (and may create cgroups in) only
    /// the caller's delegated subtree. Implies [`in_user_mount_ns`](Self::in_user_mount_ns).
    pub fn in_cgroup_ns(mut self) -> Self {
        self.user_mount_ns = true;
        self.cgroup_ns = true;
        self
    }

    /// Run the body as PID 1 of a new PID namespace with its own `/proc`, so
    /// it sees (and can signal) no process outside the test. Implies
    /// [`in_user_mount_ns`](Self::in_user_mount_ns).
    pub fn in_pid_ns(mut self) -> Self {
        self.user_mount_ns = true;
        self.pid_ns = true;
        self
    }

    /// Give the child this stderr instead of a pipe the parent reads.
    ///
    /// The child's own failure output then goes there too, so a failure is
    /// reported by exit status only.
    pub fn stderr(mut self, stderr: Stdio) -> Self {
        self.stderr = Some(stderr);
        self
    }

    /// In the child, run `body`; in the parent, spawn the child and judge it.
    ///
    /// # Panics
    ///
    /// In the parent, when the child fails, cannot be spawned for a reason other
    /// than missing namespace support, or skips (other than through
    /// [`skip_host`]) while [`REQUIRE_USERNS_ENV`] is set.
    pub fn run(self, body: impl FnOnce()) -> Outcome {
        if std::env::var_os(CHILD_ENV).is_some_and(|name| name == self.test_path) {
            if self.user_mount_ns {
                make_mounts_private_or_skip();
            }
            if self.pid_ns && std::env::var_os(PID1_ENV).is_none() {
                std::process::exit(run_as_pid1());
            }
            // A skip unwinds out of the body, so its temp dirs and scratch
            // mounts are dropped before the child exits.
            if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)) {
                match payload.downcast::<Skip>() {
                    Ok(skip) => exit_skipped(&skip.reason, skip.host),
                    Err(panic) => std::panic::resume_unwind(panic),
                }
            }
            return Outcome::Ran;
        }
        let test_path = self.test_path;
        let (outcome, host_skip) = self.spawn_and_wait();
        if let Outcome::Skipped(reason) = &outcome {
            assert!(
                host_skip || std::env::var(REQUIRE_USERNS_ENV).as_deref() != Ok("1"),
                "{REQUIRE_USERNS_ENV}=1 but the test was skipped: {reason}"
            );
            eprintln!("skipped {test_path}: {reason}");
        }
        outcome
    }

    /// The child's outcome, and whether a skip came from [`skip_host`].
    fn spawn_and_wait(self) -> (Outcome, bool) {
        let exe = std::env::current_exe().expect("locate the running test binary");
        let mut cmd = Command::new(exe);
        cmd.args([
            self.test_path,
            "--exact",
            "--include-ignored",
            "--nocapture",
        ])
        .args(["--test-threads", "1"])
        .env(CHILD_ENV, self.test_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped());
        let captures_stderr = self.stderr.is_none();
        cmd.stderr(self.stderr.unwrap_or_else(Stdio::piped));
        if self.user_mount_ns {
            enter_user_mount_ns_before_exec(&mut cmd, self.cgroup_ns);
        }

        let mut child = match cmd.spawn() {
            Ok(child) => child,
            Err(err) if self.user_mount_ns && is_namespace_refusal(&err) => {
                return (
                    Outcome::Skipped(format!(
                        "cannot create a user + mount namespace ({err}); user namespaces \
                         are unavailable to this process"
                    )),
                    false,
                );
            }
            Err(err) => panic!("spawn the child test process: {err}"),
        };
        // Drain stderr on a thread so a chatty child cannot deadlock on a full pipe.
        let stderr_reader = child.stderr.take().map(|mut pipe| {
            std::thread::spawn(move || {
                let mut text = String::new();
                let _ = pipe.read_to_string(&mut text);
                text
            })
        });
        let mut stdout = String::new();
        if let Some(mut pipe) = child.stdout.take() {
            let _ = pipe.read_to_string(&mut stdout);
        }
        let status = child.wait().expect("wait for the child test process");
        let stderr = stderr_reader
            .map(|t| t.join().unwrap_or_default())
            .unwrap_or_default();

        if let Some(code @ (SKIP_EXIT | HOST_SKIP_EXIT)) = status.code() {
            let reason = stderr
                .lines()
                .find_map(|line| line.strip_prefix(SKIP_MARKER))
                .unwrap_or("the child reported no reason");
            return (Outcome::Skipped(reason.to_string()), code == HOST_SKIP_EXIT);
        }
        assert!(
            status.success(),
            "child test {} failed with {status}{}\n--- child stdout ---\n{stdout}\n--- child stderr ---\n{stderr}",
            self.test_path,
            if captures_stderr {
                ""
            } else {
                " (its stderr was redirected)"
            },
        );
        // A child that matched no test also exits 0; make sure the body ran.
        assert!(
            stdout.contains("1 passed"),
            "child test {} did not run exactly one test (is the test path right?)\n{stdout}",
            self.test_path
        );
        (Outcome::Ran, false)
    }
}

/// Whether a spawn error is the kernel refusing the namespaces, not a bug.
fn is_namespace_refusal(err: &std::io::Error) -> bool {
    use nix::errno::Errno;
    err.raw_os_error().is_some_and(|code| {
        [
            Errno::EPERM,
            Errno::EACCES,
            Errno::EINVAL,
            Errno::ENOSPC,
            Errno::EUSERS,
            Errno::ENOSYS,
        ]
        .iter()
        .any(|errno| *errno as i32 == code)
    })
}

/// Arrange for `cmd`'s child to unshare a user and a mount namespace and map the
/// caller's ids to root, between `fork` and `exec`.
fn enter_user_mount_ns_before_exec(cmd: &mut Command, cgroup_ns: bool) {
    use std::os::unix::process::CommandExt;

    // Formatted here, in the parent: the pre-exec hook must not allocate.
    let uid_map = format!("0 {} 1\n", nix::unistd::getuid());
    let gid_map = format!("0 {} 1\n", nix::unistd::getgid());
    let hook = move || -> std::io::Result<()> {
        use nix::sched::{CloneFlags, unshare};
        let mut flags = CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNS;
        if cgroup_ns {
            flags |= CloneFlags::CLONE_NEWCGROUP;
        }
        unshare(flags)?;
        // setgroups must be denied before an unprivileged gid_map write. Kernels
        // older than 3.19 lack the file and need no denial.
        match write_proc(c"/proc/self/setgroups", b"deny") {
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            other => other?,
        }
        write_proc(c"/proc/self/uid_map", uid_map.as_bytes())?;
        write_proc(c"/proc/self/gid_map", gid_map.as_bytes())
    };
    #[allow(unsafe_code)]
    // SAFETY: the hook runs in the forked child before exec. It only makes the
    // unshare(2), open(2), write(2) and close(2) system calls on borrowed,
    // pre-formatted data: no allocation, no lock, nothing async-signal-unsafe.
    unsafe {
        cmd.pre_exec(hook);
    }
}

/// Write `data` to a `/proc` control file with raw system calls.
fn write_proc(path: &std::ffi::CStr, data: &[u8]) -> std::io::Result<()> {
    use rustix::fs::{Mode, OFlags, open};
    let fd = open(path, OFlags::WRONLY | OFlags::CLOEXEC, Mode::empty())?;
    let written = rustix::io::write(&fd, data)?;
    if written == data.len() {
        Ok(())
    } else {
        Err(std::io::Error::from(std::io::ErrorKind::WriteZero))
    }
}

/// The payload a skip unwinds the body with; [`Rerun::run`] catches it.
struct Skip {
    reason: String,
    host: bool,
}

/// End the re-executed child's body as skipped, with `reason` on stderr: for a
/// namespace prerequisite only the body can probe (mounting cgroup2, say).
/// Call it on the body's own thread; it unwinds, so everything the body holds
/// is dropped (and its temp dirs removed) before the child exits.
pub fn skip(reason: &str) -> ! {
    std::panic::resume_unwind(Box::new(Skip {
        reason: reason.to_string(),
        host: false,
    }))
}

/// Like [`skip`], for a prerequisite of the host rather than of the namespaces
/// (a delegated cgroup, a NixOS store): [`REQUIRE_USERNS_ENV`] does not turn
/// this skip into a failure, since no CI runner provides it.
pub fn skip_host(reason: &str) -> ! {
    std::panic::resume_unwind(Box::new(Skip {
        reason: reason.to_string(),
        host: true,
    }))
}

/// Exit the child as skipped, with `reason` on stderr.
fn exit_skipped(reason: &str, host: bool) -> ! {
    eprintln!("{SKIP_MARKER}{reason}");
    std::process::exit(if host { HOST_SKIP_EXIT } else { SKIP_EXIT });
}

/// In the namespaced child: re-execute this test binary, with the same
/// arguments, as PID 1 of a new PID and mount namespace whose `/proc` is
/// mounted first, and return its exit status.
#[allow(unsafe_code)]
fn run_as_pid1() -> i32 {
    use nix::sched::CloneFlags;
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let exe = CString::new(
        std::env::current_exe()
            .expect("locate the test binary")
            .as_os_str()
            .as_bytes(),
    )
    .expect("a test binary path without NUL");
    let args: Vec<CString> = std::env::args_os()
        .map(|a| CString::new(a.as_bytes()).expect("an argument without NUL"))
        .collect();
    let env: Vec<CString> = std::env::vars_os()
        .map(|(k, v)| {
            let mut pair = k.as_bytes().to_vec();
            pair.push(b'=');
            pair.extend_from_slice(v.as_bytes());
            CString::new(pair).expect("an environment entry without NUL")
        })
        .chain(std::iter::once(
            CString::new(format!("{PID1_ENV}=1")).expect("a literal"),
        ))
        .collect();
    let mut argv: Vec<*const nix::libc::c_char> = args.iter().map(|a| a.as_ptr()).collect();
    argv.push(std::ptr::null());
    let mut envp: Vec<*const nix::libc::c_char> = env.iter().map(|e| e.as_ptr()).collect();
    envp.push(std::ptr::null());
    let mut stack = vec![0u8; 256 * 1024];
    let child = move || -> isize {
        // SAFETY: raw syscalls on data prepared before the clone, then exec or
        // exit; nothing that takes a lock or allocates.
        unsafe {
            if nix::libc::mount(
                c"proc".as_ptr(),
                c"/proc".as_ptr(),
                c"proc".as_ptr(),
                0,
                std::ptr::null(),
            ) != 0
            {
                nix::libc::_exit(SKIP_EXIT);
            }
            nix::libc::execve(exe.as_ptr(), argv.as_ptr(), envp.as_ptr());
            nix::libc::_exit(127)
        }
    };
    // SAFETY: the callback only makes async-signal-safe calls (see above), and
    // the stack outlives it: the child execs or exits at once.
    let pid = match unsafe {
        nix::sched::clone(
            Box::new(child),
            &mut stack,
            CloneFlags::CLONE_NEWPID | CloneFlags::CLONE_NEWNS,
            Some(nix::libc::SIGCHLD),
        )
    } {
        Ok(pid) => pid,
        Err(errno) => exit_skipped(&format!("cannot create a PID namespace ({errno})"), false),
    };
    match nix::sys::wait::waitpid(pid, None) {
        Ok(nix::sys::wait::WaitStatus::Exited(_, code)) => code,
        _ => 1,
    }
}

/// In the namespaced child: make every mount private, or skip when the
/// namespace carries no mount capability.
fn make_mounts_private_or_skip() {
    use nix::mount::{MsFlags, mount};
    if let Err(errno) = mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    ) {
        eprintln!(
            "{SKIP_MARKER}the user namespace grants no mount capability ({errno}); on \
             Ubuntu 24.04 set kernel.apparmor_restrict_unprivileged_userns=0"
        );
        std::process::exit(SKIP_EXIT);
    }
}

/// A fresh tmpfs on a temporary directory, for use inside the namespaced child.
///
/// overlayfs needs its upper and work layers on a filesystem it accepts as an
/// upper, and an atime test needs a filesystem whose atime policy it controls;
/// a private tmpfs gives both, whatever backs the host's temp directory. Drop
/// detaches the tmpfs before the directory is removed, so nothing is left in
/// `TMPDIR` even when the body panics.
pub struct ScratchTmpfs {
    dir: tempfile::TempDir,
}

impl ScratchTmpfs {
    /// Mount a tmpfs with the given extra options (`""` for none).
    ///
    /// # Panics
    ///
    /// When the mount fails; call it only inside [`Rerun::in_user_mount_ns`].
    pub fn new(options: &str) -> Self {
        Self::with_flags(nix::mount::MsFlags::empty(), options)
    }

    /// Mount a tmpfs where every read updates the access time.
    ///
    /// # Panics
    ///
    /// As [`ScratchTmpfs::new`].
    pub fn strictatime() -> Self {
        Self::with_flags(nix::mount::MsFlags::MS_STRICTATIME, "")
    }

    fn with_flags(flags: nix::mount::MsFlags, options: &str) -> Self {
        let dir = tempfile::tempdir().expect("create the scratch mount point");
        let data = if options.is_empty() {
            "mode=0755".to_string()
        } else {
            format!("mode=0755,{options}")
        };
        nix::mount::mount(
            Some("tmpfs"),
            dir.path(),
            Some("tmpfs"),
            flags,
            Some(data.as_str()),
        )
        .expect("mount the scratch tmpfs (only inside a user + mount namespace)");
        Self { dir }
    }

    /// The tmpfs root.
    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    /// `rel` under the tmpfs root, created as a directory.
    pub fn mkdir(&self, rel: &str) -> PathBuf {
        let path = self.dir.path().join(rel);
        std::fs::create_dir_all(&path).expect("create a scratch directory");
        path
    }
}

impl Drop for ScratchTmpfs {
    fn drop(&mut self) {
        // Detach whatever a test stacked on the tmpfs too (an overlay, say):
        // the directory can be removed only once nothing is mounted on it.
        for _ in 0..16 {
            if nix::mount::umount2(self.dir.path(), nix::mount::MntFlags::MNT_DETACH).is_err() {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Outcome, Rerun, ScratchTmpfs};

    #[test]
    fn child_runs_the_body_in_a_user_namespace_as_root() {
        let outcome = Rerun::new(crate::test_path!(
            child_runs_the_body_in_a_user_namespace_as_root
        ))
        .in_user_mount_ns()
        .run(|| {
            assert!(
                nix::unistd::getuid().is_root(),
                "uid 0 inside the namespace"
            );
            let scratch = ScratchTmpfs::new("size=1M");
            std::fs::write(scratch.path().join("probe"), b"ok").unwrap();
            let mounts = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
            assert!(
                mounts.contains(&scratch.path().display().to_string()),
                "the scratch tmpfs is listed in this namespace's mountinfo"
            );
        });
        assert!(matches!(outcome, Outcome::Ran | Outcome::Skipped(_)));
    }

    #[test]
    fn plain_rerun_needs_no_namespace() {
        let outcome = Rerun::new(crate::test_path!(plain_rerun_needs_no_namespace)).run(|| {
            assert_eq!(
                std::env::var(super::CHILD_ENV).as_deref(),
                Ok("test_support::tests::plain_rerun_needs_no_namespace")
            );
        });
        assert_eq!(outcome, Outcome::Ran);
    }

    #[test]
    fn a_skip_drops_what_the_body_holds_before_the_child_exits() {
        // The parent's pid names a directory both processes find.
        fn shared(pid: u32) -> std::path::PathBuf {
            std::env::temp_dir().join(format!("nails-skip-drop-{pid}"))
        }
        struct RemoveOnDrop(std::path::PathBuf);
        impl Drop for RemoveOnDrop {
            fn drop(&mut self) {
                std::fs::remove_file(&self.0).unwrap();
            }
        }
        let dir = shared(std::process::id());

        let outcome = Rerun::new(crate::test_path!(
            a_skip_drops_what_the_body_holds_before_the_child_exits
        ))
        .run(|| {
            let dir = shared(std::os::unix::process::parent_id());
            std::fs::create_dir(&dir).unwrap();
            std::fs::write(dir.join("kept"), "").unwrap();
            std::fs::write(dir.join("dropped"), "").unwrap();
            let _guard = RemoveOnDrop(dir.join("dropped"));
            super::skip_host("dropping on the way out");
        });

        let kept = dir.join("kept").exists();
        let dropped = !dir.join("dropped").exists();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(
            outcome,
            Outcome::Skipped("dropping on the way out".to_string())
        );
        assert!(kept, "the body ran");
        assert!(dropped, "the skip dropped the body's guard");
    }

    /// CI runs this with `NAILS_REQUIRE_USERNS=1`, which must leave a host skip a skip.
    #[test]
    fn a_host_skip_is_reported_as_a_skip() {
        let outcome = Rerun::new(crate::test_path!(a_host_skip_is_reported_as_a_skip))
            .run(|| super::skip_host("no such thing on this host"));
        assert_eq!(
            outcome,
            Outcome::Skipped("no such thing on this host".to_string())
        );
    }
}
