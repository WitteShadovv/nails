// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Research proof of concept for ADR 0007 (emergency architecture).
//!
//! These tests drive the real kernel, not a mock, to check the three kernel
//! mechanisms the ADR leans on:
//!
//! 1. `cgroup.kill` on a dedicated cgroup kills every process in it at once,
//!    including a stopped one, one that ignores `SIGTERM`, one that daemonised
//!    away from its parent and a parent that keeps forking. Once
//!    `cgroup.events` reports `populated 0`, a *non-lazy* `umount2` of the
//!    overlay succeeds, and the overlay's upper layer is provably no longer held
//!    by any overlay superblock. A process in a sibling cgroup (the stand-in for
//!    the graphical session) is untouched.
//! 2. `MNT_DETACH` alone removes the overlay from the mount table but releases
//!    nothing: a process holding a file keeps reading hidden data through the
//!    detached mount, and the upper layer stays pinned until that process dies.
//! 3. An overlay mounted inside a private mount namespace never shows up in the
//!    outer mount table, and killing the namespace's processes through their
//!    cgroup frees the namespace and the overlay with it.
//!
//! "The upper layer is no longer held" is checked with overlayfs itself: with
//! `index=on`, overlayfs refuses to mount an upper directory that a live overlay
//! superblock still uses (`EBUSY`). A probe mount that succeeds is the kernel
//! saying that no overlay instance, attached or detached, still pins the upper.
//! On a real host that is the condition for the hidden volume's device-mapper
//! device to close.
//!
//! Every test re-executes this test binary inside fresh, unprivileged user,
//! mount and cgroup namespaces, so nothing is mounted on the host and no root is
//! needed where unprivileged user namespaces are allowed. Run them with:
//!
//! ```sh
//! cargo test -p nails-core --test research_emergency_kernel -- --ignored --nocapture
//! ```
//!
//! A host that refuses unprivileged user namespaces (AppArmor on ubuntu-24.04)
//! or does not delegate the caller's cgroup prints `RESEARCH-SKIP` and passes;
//! set `NAILS_RESEARCH_REQUIRE_NS=1` to turn a skip into a failure, or run the
//! binary under `sudo`. They are `#[ignore]`d because they spawn real processes,
//! need namespaces, and exist to back a design decision rather than to guard a
//! shipped code path.

use nix::errno::Errno;
use nix::libc;
use nix::mount::{MntFlags, MsFlags, mount, umount2};
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Set in the re-executed child to the name of the scenario it must run.
const CHILD_ENV: &str = "NAILS_RESEARCH_NS_CHILD";
/// Turns every skip into a failure (for a VM or CI lane that must prove it).
const REQUIRE_ENV: &str = "NAILS_RESEARCH_REQUIRE_NS";
/// Marker the child prints when a prerequisite is missing.
const SKIP_MARKER: &str = "RESEARCH-SKIP";

/// How long a killed cgroup may take to report `populated 0`.
const KILL_DEADLINE: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// Namespace re-exec harness
// ---------------------------------------------------------------------------

/// Returns `true` when this process is the namespaced child that must run the
/// scenario `name`. Otherwise re-executes the test binary for `name` inside new
/// user, mount and cgroup namespaces, asserts it passed, and returns `false`.
fn in_namespace_child(name: &str) -> bool {
    if std::env::var(CHILD_ENV).as_deref() == Ok(name) {
        return true;
    }

    let exe = std::env::current_exe().expect("locate the test binary");
    let mut cmd = Command::new(exe);
    cmd.args([
        name,
        "--exact",
        "--ignored",
        "--nocapture",
        "--test-threads=1",
    ])
    .env(CHILD_ENV, name)
    .stdin(Stdio::null());
    enter_user_mount_cgroup_namespaces(&mut cmd);

    let output = match cmd.output() {
        Ok(output) => output,
        Err(e) => {
            skip_or_fail(&format!("cannot create user+mount+cgroup namespaces: {e}"));
            return false;
        }
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("--- namespaced child `{name}` ---\n{stdout}{stderr}--- end `{name}` ---");
    assert!(
        output.status.success(),
        "namespaced scenario `{name}` failed: {}",
        output.status
    );
    false
}

fn skip_or_fail(reason: &str) {
    if std::env::var_os(REQUIRE_ENV).is_some() {
        panic!("{SKIP_MARKER} not allowed ({REQUIRE_ENV} is set): {reason}");
    }
    eprintln!("{SKIP_MARKER}: {reason}");
}

/// Make the spawned child unshare user, mount and cgroup namespaces and map the
/// caller's uid/gid to root inside, before it executes.
#[allow(unsafe_code)]
fn enter_user_mount_cgroup_namespaces(cmd: &mut Command) {
    let uid_map = format!("0 {} 1", nix::unistd::getuid().as_raw());
    let gid_map = format!("0 {} 1", nix::unistd::getgid().as_raw());
    // SAFETY: the closure runs between fork and exec in a single-threaded child.
    // It only makes raw syscalls on data prepared before the fork (no
    // allocation, no locks), which is async-signal-safe.
    unsafe {
        cmd.pre_exec(move || {
            if libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS | libc::CLONE_NEWCGROUP) != 0 {
                return Err(io::Error::last_os_error());
            }
            write_raw(c"/proc/self/setgroups", b"deny")?;
            write_raw(c"/proc/self/uid_map", uid_map.as_bytes())?;
            write_raw(c"/proc/self/gid_map", gid_map.as_bytes())?;
            Ok(())
        });
    }
}

/// `open` + `write` + `close` with no allocation, for use after `fork`.
#[allow(unsafe_code)]
fn write_raw(path: &CStr, data: &[u8]) -> io::Result<()> {
    // SAFETY: plain syscalls on a valid C string and buffer.
    unsafe {
        let fd = libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let written = libc::write(fd, data.as_ptr().cast(), data.len());
        let err = io::Error::last_os_error();
        libc::close(fd);
        if written != data.len() as isize {
            return Err(err);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Fixture: a tmpfs "hidden volume", a lower tree and an overlay
// ---------------------------------------------------------------------------

/// A stand-in for one NAILS overlay: the decoy `lower`, a tmpfs at `hidden`
/// playing the hidden volume (upper and work live on it), and the mount point.
struct Fixture {
    _temp: tempfile::TempDir,
    base: PathBuf,
    lower: PathBuf,
    hidden: PathBuf,
    merged: PathBuf,
    probes: std::cell::Cell<u32>,
}

impl Fixture {
    fn new() -> Self {
        // Inside a namespace whose mounts were copied from the host, make every
        // mount private so nothing propagates back out.
        mount(
            None::<&str>,
            "/",
            None::<&str>,
            MsFlags::MS_REC | MsFlags::MS_PRIVATE,
            None::<&str>,
        )
        .expect("make the namespace's mounts private");

        let temp = tempfile::tempdir().expect("temp dir");
        let base = temp.path().to_path_buf();
        let lower = base.join("lower");
        let hidden = base.join("hidden");
        let merged = base.join("merged");
        for dir in [&lower, &hidden, &merged] {
            std::fs::create_dir(dir).expect("create fixture dir");
        }
        std::fs::write(lower.join("decoy.txt"), "decoy\n").expect("write lower file");
        mount(
            Some("tmpfs"),
            &hidden,
            Some("tmpfs"),
            MsFlags::empty(),
            Some("size=64m"),
        )
        .expect("mount the stand-in hidden volume");
        for dir in ["upper", "work"] {
            std::fs::create_dir(hidden.join(dir)).expect("create upper/work");
        }
        Self {
            _temp: temp,
            base,
            lower,
            hidden,
            merged,
            probes: std::cell::Cell::new(0),
        }
    }

    fn overlay_options(&self, workdir: &Path) -> String {
        format!(
            "lowerdir={},upperdir={},workdir={},index=on",
            self.lower.display(),
            self.hidden.join("upper").display(),
            workdir.display()
        )
    }

    /// Mount the overlay at `merged` in the current mount namespace.
    fn mount_overlay(&self) {
        mount(
            Some("overlay"),
            &self.merged,
            Some("overlay"),
            MsFlags::empty(),
            Some(self.overlay_options(&self.hidden.join("work")).as_str()),
        )
        .expect("mount overlay (needs overlayfs in user namespaces, Linux 5.11+)");
    }

    /// True when no overlay superblock (attached, lazily detached, or in another
    /// mount namespace) still uses the upper directory. Proven by mounting a
    /// second `index=on` overlay on the same upper: overlayfs refuses that with
    /// `EBUSY` while the upper is in use.
    fn upper_released(&self) -> bool {
        let n = self.probes.get() + 1;
        self.probes.set(n);
        let work = self.hidden.join(format!("probe-work-{n}"));
        let target = self.base.join(format!("probe-{n}"));
        std::fs::create_dir(&work).expect("probe workdir");
        std::fs::create_dir(&target).expect("probe target");
        let options = self.overlay_options(&work);
        match mount(
            Some("overlay"),
            &target,
            Some("overlay"),
            MsFlags::empty(),
            Some(options.as_str()),
        ) {
            Ok(()) => {
                umount2(&target, MntFlags::empty()).expect("unmount the probe overlay");
                true
            }
            Err(Errno::EBUSY) => false,
            Err(e) => panic!("unexpected probe mount error: {e}"),
        }
    }

    /// Poll [`upper_released`](Self::upper_released) for up to `deadline`:
    /// mount-namespace teardown finishes asynchronously after the last task.
    fn wait_upper_released(&self, deadline: Duration) -> Option<Duration> {
        let start = Instant::now();
        loop {
            if self.upper_released() {
                return Some(start.elapsed());
            }
            if start.elapsed() > deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// The lower tree must be byte-identical to what the fixture created: every
    /// hidden write lands in the upper, never on the decoy.
    fn assert_lower_untouched(&self) {
        let mut names: Vec<_> = std::fs::read_dir(&self.lower)
            .expect("read lower")
            .map(|e| e.expect("entry").file_name())
            .collect();
        names.sort();
        assert_eq!(names, vec![std::ffi::OsString::from("decoy.txt")]);
        assert_eq!(
            std::fs::read_to_string(self.lower.join("decoy.txt")).unwrap(),
            "decoy\n"
        );
    }
}

/// Whether `path` is a mount point in this process's mount table.
fn in_mount_table(mountinfo: &str, path: &Path) -> bool {
    let wanted = path.to_string_lossy();
    mountinfo
        .lines()
        .any(|line| line.split(' ').nth(4) == Some(wanted.as_ref()))
}

fn own_mountinfo() -> String {
    std::fs::read_to_string("/proc/self/mountinfo").expect("read mountinfo")
}

// ---------------------------------------------------------------------------
// cgroup v2 helpers
// ---------------------------------------------------------------------------

/// A cgroup created under the namespace's cgroup root. Dropping it kills any
/// leftover process and removes the directory, so a failed assertion never
/// leaves processes behind.
struct Cgroup {
    path: PathBuf,
}

/// Mount cgroup2 inside the private mount namespace. Returns `None` (after
/// printing a skip) when the caller's cgroup is not delegated to it.
fn mount_cgroup_root(fx: &Fixture) -> Option<PathBuf> {
    let root = fx.base.join("cgroup");
    std::fs::create_dir(&root).expect("cgroup mount point");
    if let Err(e) = mount(
        Some("none"),
        &root,
        Some("cgroup2"),
        MsFlags::empty(),
        None::<&str>,
    ) {
        skip_or_fail(&format!("cannot mount cgroup2 in the namespace: {e}"));
        return None;
    }
    let probe = root.join("nails-research-probe");
    if let Err(e) = std::fs::create_dir(&probe) {
        skip_or_fail(&format!(
            "the caller's cgroup is not delegated (mkdir: {e})"
        ));
        return None;
    }
    std::fs::remove_dir(&probe).expect("remove probe cgroup");
    Some(root)
}

impl Cgroup {
    /// A child cgroup named after `name` and this process. Every scenario runs
    /// in its own namespaced child process, but all of them share the caller's
    /// delegated cgroup, so a bare name collides when the harness runs them in
    /// parallel.
    fn create(root: &Path, name: &str) -> Self {
        let path = root.join(format!("{name}-{}", std::process::id()));
        std::fs::create_dir(&path).expect("create cgroup");
        Self { path }
    }

    /// Open `cgroup.procs` so a child can join this cgroup from `pre_exec`.
    fn procs_file(&self) -> File {
        File::options()
            .write(true)
            .open(self.path.join("cgroup.procs"))
            .expect("open cgroup.procs")
    }

    fn pids(&self) -> Vec<u32> {
        std::fs::read_to_string(self.path.join("cgroup.procs"))
            .unwrap_or_default()
            .lines()
            .filter_map(|l| l.trim().parse().ok())
            .collect()
    }

    fn populated(&self) -> bool {
        std::fs::read_to_string(self.path.join("cgroup.events"))
            .expect("read cgroup.events")
            .lines()
            .any(|l| l == "populated 1")
    }

    /// SIGKILL every process in the cgroup tree, atomically with respect to
    /// concurrent forks.
    fn kill(&self) -> io::Result<()> {
        std::fs::write(self.path.join("cgroup.kill"), "1")
    }

    /// Wait until `cgroup.events` reports `populated 0`.
    fn wait_unpopulated(&self, deadline: Duration) -> Option<Duration> {
        let start = Instant::now();
        while self.populated() {
            if start.elapsed() > deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        Some(start.elapsed())
    }
}

impl Drop for Cgroup {
    fn drop(&mut self) {
        let _ = self.kill();
        let _ = self.wait_unpopulated(KILL_DEADLINE);
        let _ = std::fs::remove_dir(&self.path);
    }
}

/// Spawn `sh -c script` with `cwd`, joined to `cgroup` before it executes, so
/// it and every descendant start inside that cgroup.
#[allow(unsafe_code)]
fn spawn_in_cgroup(cgroup: &Cgroup, cwd: &Path, script: &str, stdin: Stdio) -> Child {
    let procs = cgroup.procs_file();
    let fd = procs.as_raw_fd();
    let mut cmd = Command::new("sh");
    cmd.arg("-c")
        .arg(script)
        .current_dir(cwd)
        .stdin(stdin)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: a single raw write to an fd opened before the fork.
    unsafe {
        cmd.pre_exec(move || {
            if libc::write(fd, b"0".as_ptr().cast(), 1) != 1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = cmd.spawn().expect("spawn a process in the cgroup");
    drop(procs);
    child
}

fn is_running(child: &mut Child) -> bool {
    matches!(child.try_wait(), Ok(None))
}

// ---------------------------------------------------------------------------
// pidfd helpers (race-free signalling of a single process)
// ---------------------------------------------------------------------------

#[allow(unsafe_code)]
fn pidfd_open(pid: u32) -> io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;
    // SAFETY: pidfd_open(2) with flags 0 returns a new fd or -1.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the kernel just returned this fd and nothing else owns it.
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd as i32) })
}

#[allow(unsafe_code)]
fn pidfd_kill(pidfd: &std::os::fd::OwnedFd) -> io::Result<()> {
    // SAFETY: pidfd_send_signal(2) on a pidfd we own, no siginfo, flags 0.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            libc::SIGKILL,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Scenario 1: cgroup.kill releases a live overlay, sparing the "desktop"
// ---------------------------------------------------------------------------

const CGROUP_KILL: &str = "cgroup_kill_releases_a_live_overlay";

#[test]
#[ignore = "research: needs unprivileged user, mount and cgroup namespaces"]
fn cgroup_kill_releases_a_live_overlay() {
    if !in_namespace_child(CGROUP_KILL) {
        return;
    }
    let fx = Fixture::new();
    let Some(cg_root) = mount_cgroup_root(&fx) else {
        return;
    };
    fx.mount_overlay();
    std::fs::write(fx.merged.join("hidden-note.txt"), "hidden\n").expect("hidden write");

    let hidden = Cgroup::create(&cg_root, "hidden-session");
    let desktop = Cgroup::create(&cg_root, "desktop");

    // Hidden-session processes, each pinning the overlay a different way.
    let note = || Stdio::from(File::open(fx.merged.join("hidden-note.txt")).expect("open note"));
    let mut direct = vec![
        // cwd inside the overlay
        spawn_in_cgroup(&hidden, &fx.merged, "exec sleep 600", Stdio::null()),
        // open fd on a hidden file
        spawn_in_cgroup(&hidden, &fx.base, "exec sleep 600", note()),
        // ignores SIGTERM and keeps writing into the overlay
        spawn_in_cgroup(
            &hidden,
            &fx.merged,
            "trap '' TERM; while :; do echo x >> writer.log; sleep 0.01; done",
            Stdio::null(),
        ),
        // will be SIGSTOPped below
        spawn_in_cgroup(&hidden, &fx.merged, "exec sleep 600", Stdio::null()),
        // daemonises away from its parent (setsid + reparenting), then exits
        spawn_in_cgroup(
            &hidden,
            &fx.merged,
            "setsid sh -c 'exec sleep 600' </dev/null >/dev/null 2>&1 & exit 0",
            Stdio::null(),
        ),
        // keeps forking while the kill lands
        spawn_in_cgroup(
            &hidden,
            &fx.merged,
            "i=0; while [ $i -lt 1000 ]; do sleep 600 & i=$((i+1)); done; wait",
            Stdio::null(),
        ),
    ];
    // The graphical session stand-in: outside the hidden cgroup, not on the overlay.
    let mut desktop_proc = spawn_in_cgroup(&desktop, &fx.base, "exec sleep 600", Stdio::null());

    std::thread::sleep(Duration::from_millis(300));
    let stopped = direct[3].id() as i32;
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(stopped),
        nix::sys::signal::Signal::SIGSTOP,
    )
    .expect("SIGSTOP a hidden process");

    // Preconditions: the overlay is pinned and the upper is in use.
    assert_eq!(
        umount2(&fx.merged, MntFlags::empty()),
        Err(Errno::EBUSY),
        "the hidden processes must pin the overlay before the kill"
    );
    assert!(!fx.upper_released(), "the live overlay must hold the upper");
    let victims = hidden.pids().len();

    // --- the emergency step under test ---
    let start = Instant::now();
    hidden.kill().expect("write cgroup.kill");
    let drained = hidden
        .wait_unpopulated(KILL_DEADLINE)
        .expect("the hidden cgroup must drain after cgroup.kill");
    umount2(&fx.merged, MntFlags::empty())
        .expect("a non-lazy unmount must succeed once the cgroup is empty");
    let unmounted = start.elapsed();
    // --- end ---

    assert!(
        fx.upper_released(),
        "no overlay superblock may still hold the upper"
    );
    assert!(!in_mount_table(&own_mountinfo(), &fx.merged));
    assert!(
        is_running(&mut desktop_proc),
        "the desktop cgroup must be untouched"
    );
    fx.assert_lower_untouched();
    for child in &mut direct {
        let _ = child.wait();
    }

    eprintln!(
        "PoC cgroup.kill: {victims} processes at kill time; cgroup drained in {:.1} ms; \
         overlay unmounted (non-lazy) {:.1} ms after the kill",
        drained.as_secs_f64() * 1e3,
        unmounted.as_secs_f64() * 1e3
    );
    let _ = desktop_proc.kill();
    let _ = desktop_proc.wait();
}

// ---------------------------------------------------------------------------
// Scenario 2: MNT_DETACH alone hides the overlay but releases nothing
// ---------------------------------------------------------------------------

const LAZY_DETACH: &str = "lazy_detach_alone_keeps_the_hidden_volume_pinned";

#[test]
#[ignore = "research: needs unprivileged user and mount namespaces"]
fn lazy_detach_alone_keeps_the_hidden_volume_pinned() {
    if !in_namespace_child(LAZY_DETACH) {
        return;
    }
    let fx = Fixture::new();
    fx.mount_overlay();
    std::fs::write(fx.merged.join("hidden-note.txt"), "hidden\n").expect("hidden write");

    let note = File::open(fx.merged.join("hidden-note.txt")).expect("open note");
    let mut holder = Command::new("sleep")
        .arg("600")
        .current_dir(&fx.base)
        .stdin(Stdio::from(note))
        .spawn()
        .expect("spawn holder");
    std::thread::sleep(Duration::from_millis(100));

    assert_eq!(umount2(&fx.merged, MntFlags::empty()), Err(Errno::EBUSY));
    umount2(&fx.merged, MntFlags::MNT_DETACH).expect("lazy detach always succeeds");

    // An observer reading the mount table sees nothing ...
    assert!(!in_mount_table(&own_mountinfo(), &fx.merged));
    // ... but the holder still reads hidden data through the detached mount ...
    let leaked = std::fs::read_to_string(format!("/proc/{}/fd/0", holder.id()))
        .expect("read through the holder's fd");
    assert_eq!(
        leaked, "hidden\n",
        "a detached overlay keeps serving hidden data"
    );
    // ... and the upper (the hidden volume) stays pinned.
    assert!(
        !fx.upper_released(),
        "MNT_DETACH must not release the upper"
    );

    // Killing the holder (via a pidfd, immune to pid reuse) releases it.
    let pidfd = pidfd_open(holder.id()).expect("pidfd_open (Linux 5.3+)");
    pidfd_kill(&pidfd).expect("pidfd_send_signal");
    let _ = holder.wait();
    let released = fx
        .wait_upper_released(Duration::from_secs(2))
        .expect("the upper is released once the last holder is gone");
    eprintln!(
        "PoC MNT_DETACH: mount table clean at once; hidden data readable until the holder \
         died; upper released {:.1} ms after the kill",
        released.as_secs_f64() * 1e3
    );
}

// ---------------------------------------------------------------------------
// Scenario 3: an overlay inside a private mount namespace dies with it
// ---------------------------------------------------------------------------

const MOUNT_NS: &str = "killing_a_private_mount_namespace_releases_its_overlay";

#[test]
#[ignore = "research: needs unprivileged user, mount and cgroup namespaces"]
#[allow(unsafe_code)]
fn killing_a_private_mount_namespace_releases_its_overlay() {
    if !in_namespace_child(MOUNT_NS) {
        return;
    }
    let fx = Fixture::new();
    let Some(cg_root) = mount_cgroup_root(&fx) else {
        return;
    };
    let session = Cgroup::create(&cg_root, "hidden-session");

    // The session leader joins the cgroup, unshares a mount namespace, mounts
    // the overlay only there, then starts two holders inside it.
    let procs = session.procs_file();
    let procs_fd = procs.as_raw_fd();
    let root = CString::new("/").unwrap();
    let overlay = CString::new("overlay").unwrap();
    let target = CString::new(fx.merged.to_str().unwrap()).unwrap();
    let options = CString::new(fx.overlay_options(&fx.hidden.join("work"))).unwrap();
    let mut cmd = Command::new("sh");
    cmd.arg("-c")
        .arg(format!(
            "sleep 600 < {m}/hidden-note.txt & cd {m} && exec sleep 600",
            m = fx.merged.display()
        ))
        .current_dir(&fx.base)
        .stdin(Stdio::null());
    // SAFETY: raw syscalls on data prepared before the fork.
    unsafe {
        cmd.pre_exec(move || {
            if libc::write(procs_fd, b"0".as_ptr().cast(), 1) != 1
                || libc::unshare(libc::CLONE_NEWNS) != 0
                || libc::mount(
                    std::ptr::null(),
                    root.as_ptr(),
                    std::ptr::null(),
                    libc::MS_REC | libc::MS_PRIVATE,
                    std::ptr::null(),
                ) != 0
                || libc::mount(
                    overlay.as_ptr(),
                    target.as_ptr(),
                    overlay.as_ptr(),
                    0,
                    options.as_ptr().cast(),
                ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            // Seed a hidden file before the shell opens it.
            let path = c"hidden-note.txt";
            if libc::chdir(target.as_ptr()) != 0 {
                return Err(io::Error::last_os_error());
            }
            let fd = libc::open(
                path.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_CLOEXEC,
                0o600,
            );
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            libc::write(fd, b"hidden\n".as_ptr().cast(), 7);
            libc::close(fd);
            Ok(())
        });
    }
    let mut leader = cmd.spawn().expect("spawn the namespaced session leader");
    drop(procs);
    std::thread::sleep(Duration::from_millis(300));

    let inner = std::fs::read_to_string(format!("/proc/{}/mountinfo", leader.id()))
        .expect("read the leader's mountinfo");
    assert!(
        in_mount_table(&inner, &fx.merged),
        "overlay is mounted inside the namespace"
    );
    assert!(
        !in_mount_table(&own_mountinfo(), &fx.merged),
        "the outer mount table never shows the namespaced overlay"
    );
    let ns = std::fs::read_link(format!("/proc/{}/ns/mnt", leader.id())).expect("ns link");
    assert_ne!(ns, std::fs::read_link("/proc/self/ns/mnt").unwrap());
    assert!(
        !fx.upper_released(),
        "the namespaced overlay holds the upper"
    );

    let start = Instant::now();
    session.kill().expect("write cgroup.kill");
    session
        .wait_unpopulated(KILL_DEADLINE)
        .expect("the session cgroup must drain");
    let _ = leader.wait();
    let released = fx
        .wait_upper_released(Duration::from_secs(2))
        .expect("the namespace and its overlay must be freed after the kill");
    let total = start.elapsed();

    // No surviving process is still in that mount namespace.
    let survivors = std::fs::read_dir("/proc")
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().parse::<u32>().is_ok())
        .filter(|e| std::fs::read_link(e.path().join("ns/mnt")).ok().as_ref() == Some(&ns))
        .count();
    assert_eq!(survivors, 0);
    fx.assert_lower_untouched();
    eprintln!(
        "PoC mount namespace: invisible in the outer mount table; upper released {:.1} ms \
         after cgroup.kill (probe wait {:.1} ms)",
        total.as_secs_f64() * 1e3,
        released.as_secs_f64() * 1e3
    );
}
