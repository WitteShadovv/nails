// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! cgroup v2: killing a whole unit at once and waiting for it to empty.
//!
//! On a systemd host every service has its own cgroup. Writing `1` to its
//! `cgroup.kill` (Linux 5.14) SIGKILLs every process in it atomically, racing
//! forkers and migrations included, with no pid list to go stale and without
//! touching any file on the hidden filesystem. Completion is visible in
//! `cgroup.events` (`populated 0`). A task in uninterruptible sleep keeps the
//! cgroup populated until its sleep ends, so the wait is bounded.
//!
//! On a kernel without `cgroup.kill` the fallback reads `cgroup.procs` and
//! SIGKILLs each process through a pidfd, a few rounds to catch forks. It never
//! freezes (ADR 0004).

use crate::proc::ProcessHandle;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Where the unified cgroup hierarchy is mounted on a systemd host.
pub const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// The cgroup v2 path (`/system.slice/foo.service`) in a `/proc/<pid>/cgroup`
/// body; `None` on a v1-only host.
pub fn v2_path(content: &str) -> Option<String> {
    content
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .map(str::to_string)
}

/// The cgroup v2 path of this process.
pub fn own_path() -> Option<String> {
    v2_path(&std::fs::read_to_string("/proc/self/cgroup").ok()?)
}

/// The system service a cgroup path belongs to, as `(unit, unit cgroup path)`:
/// a `.service` below `system.slice`. Never one below `user.slice` (the
/// operator's user manager or a session) and never the display manager.
pub fn service_of(path: &str) -> Option<(String, String)> {
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if segments.contains(&"user.slice") {
        return None;
    }
    let slice = segments.iter().position(|s| *s == "system.slice")?;
    let offset = segments[slice + 1..]
        .iter()
        .position(|s| s.ends_with(".service") && s.len() > ".service".len())?;
    let index = slice + 1 + offset;
    let unit = segments[index];
    if unit == "display-manager.service" || unit.starts_with("user@") {
        return None;
    }
    Some((
        unit.to_string(),
        format!("/{}", segments[..=index].join("/")),
    ))
}

/// The service unit `content` (a `/proc/<pid>/cgroup` body, v2 or v1) places a
/// process in.
pub fn service_unit_from_cgroup(content: &str) -> Option<String> {
    content.lines().find_map(|line| {
        let path = line.splitn(3, ':').nth(2)?;
        service_of(path).map(|(unit, _)| unit)
    })
}

/// Whether killing the cgroup `target` would kill the process in `own`: it is
/// the same cgroup or an ancestor of it. The teardown never kills itself.
pub fn contains(target: &str, own: &str) -> bool {
    let target = target.trim_end_matches('/');
    own == target || own.starts_with(&format!("{target}/")) || target.is_empty()
}

/// The directory of cgroup `path` in the hierarchy mounted at `root`.
pub fn dir(root: &Path, path: &str) -> PathBuf {
    root.join(path.trim_start_matches('/'))
}

/// How a cgroup was killed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KillMethod {
    /// `cgroup.kill`.
    Atomic,
    /// `cgroup.procs` and a pidfd SIGKILL per process (Linux before 5.14).
    PerProcess,
}

/// SIGKILL every process in the cgroup at `dir`. The per-process fallback
/// skips `spare` (the caller has already refused a cgroup holding one of them
/// for the atomic kill).
pub fn kill(dir: &Path, spare: &[u32]) -> std::io::Result<KillMethod> {
    match std::fs::write(dir.join("cgroup.kill"), "1") {
        Ok(()) => Ok(KillMethod::Atomic),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && dir.is_dir() => {
            for _ in 0..3 {
                let handles: Vec<ProcessHandle> = procs(dir)
                    .into_iter()
                    .filter(|pid| !spare.contains(pid))
                    .filter_map(ProcessHandle::open)
                    .collect();
                if handles.is_empty() {
                    break;
                }
                for handle in &handles {
                    handle.kill();
                }
            }
            Ok(KillMethod::PerProcess)
        }
        Err(e) => Err(e),
    }
}

/// The pids in the cgroup at `dir` (and below it).
pub fn procs(dir: &Path) -> Vec<u32> {
    let mut pids: Vec<u32> = std::fs::read_to_string(dir.join("cgroup.procs"))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.trim().parse().ok())
        .collect();
    if let Ok(children) = std::fs::read_dir(dir) {
        for child in children.flatten() {
            if child.file_type().is_ok_and(|t| t.is_dir()) {
                pids.extend(procs(&child.path()));
            }
        }
    }
    pids
}

/// Whether the cgroup at `dir` still holds a process. A cgroup that is gone
/// (systemd removed it once empty) is empty.
pub fn populated(dir: &Path) -> bool {
    std::fs::read_to_string(dir.join("cgroup.events"))
        .map(|events| events.lines().any(|l| l == "populated 1"))
        .unwrap_or(false)
}

/// Wait until every cgroup in `dirs` is empty or `budget` runs out. Returns the
/// ones still populated, for the report.
pub fn await_empty(dirs: &[PathBuf], budget: Duration) -> Vec<PathBuf> {
    let deadline = Instant::now() + budget;
    loop {
        let full: Vec<PathBuf> = dirs.iter().filter(|d| populated(d)).cloned().collect();
        if full.is_empty() || Instant::now() >= deadline {
            return full;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_system_service_resolves_to_its_unit_and_cgroup() {
        assert_eq!(
            service_of("/system.slice/worker.service/payload"),
            Some((
                "worker.service".to_string(),
                "/system.slice/worker.service".to_string()
            ))
        );
        assert_eq!(
            service_of("/system.slice/system-getty.slice/getty@tty1.service").map(|s| s.1),
            Some("/system.slice/system-getty.slice/getty@tty1.service".to_string())
        );
        assert_eq!(
            service_unit_from_cgroup("1:name=systemd:/system.slice/worker.service\n").as_deref(),
            Some("worker.service")
        );
    }

    #[test]
    fn the_graphical_session_and_user_units_are_never_services_to_kill() {
        for path in [
            "/system.slice/display-manager.service",
            "/user.slice/user-1000.slice/user@1000.service/app.slice/app.service",
            "/user.slice/user-1000.slice/session-2.scope",
            "/system.slice/user@1000.service",
            "/init.scope",
            "/system.slice/foo.scope",
            "/system.slice/.service",
        ] {
            assert_eq!(service_of(path), None, "{path}");
        }
    }

    #[test]
    fn a_cgroup_holding_the_teardown_is_never_killed() {
        let own = "/system.slice/nails-emergency-test.service";
        assert!(contains("/system.slice/nails-emergency-test.service", own));
        assert!(contains("/system.slice", own));
        assert!(contains("/", own));
        assert!(!contains("/system.slice/worker.service", own));
        assert!(!contains("/system.slice/nails-emergency", own));
    }

    #[test]
    fn the_v2_path_is_read_from_the_unified_line() {
        assert_eq!(
            v2_path("12:pids:/x\n0::/system.slice/a.service\n").as_deref(),
            Some("/system.slice/a.service")
        );
        assert_eq!(v2_path("12:pids:/x\n"), None);
    }
}
