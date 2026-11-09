// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The decoy's running shutdown helper of unattended-upgrades, as the kernel
//! and systemd show it: its processes, when it started, and the
//! `APT_CONFIG` it runs with.
//!
//! Its processes are those of its unit's cgroup
//! (`/sys/fs/cgroup/system.slice/unattended-upgrades.service/cgroup.procs`).
//! The helper read apt's configuration when it started, which was after the
//! unit's invocation marker came to be (systemd makes it before it starts the
//! process) and after each of its processes started (the boot time of
//! `/proc/stat` and the clock ticks of `/proc/<pid>/stat`). The earliest of
//! these times is taken: a step of the system clock after the start moves
//! the boot time `/proc/stat` gives with it, and leaves the marker's time as
//! it was, so whichever way the clock was set, one of them is no later than
//! the helper's read in the clock the files' change times were written in.
//!
//! apt reads the file `APT_CONFIG` names first, before every other file of
//! its configuration, however the variable came to the helper: from PID 1's
//! environment, the unit, or `systemctl set-environment`. Of each process's
//! environment, `/proc/<pid>/environ`, which only root may read, that one
//! variable is kept; the rest is dropped as it is read and never shown. A
//! read that fails without root the way the kernel keeps another user's
//! process from all but root is a doubt of its own ([`Doubt::needs_root`]),
//! which a run as root does not have: refused (`EACCES`, or `EPERM` with
//! `/proc` mounted `hidepid=noaccess`), or hidden as if the process were gone
//! (`ENOENT`, with `hidepid=invisible` or `ptraceable`).
//!
//! Every read is a read of a file or a lookup; nothing is written.

use super::{APT, PARTS, UNIT};
use crate::Filesystem;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Why NAILS cannot tell what the decoy's running helper reads first.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Doubt {
    /// The reason, as the texts say it.
    pub(super) why: String,
    /// The kernel refused to show the helper's environment, or hid it, as it
    /// does to everyone but root: a run as root can tell.
    pub(super) needs_root: bool,
}

impl From<String> for Doubt {
    fn from(why: String) -> Self {
        Self {
            why,
            needs_root: false,
        }
    }
}

/// The cgroup of the helper's unit, relative to the root.
const CGROUP: &str = "sys/fs/cgroup/system.slice";

/// The marker systemd makes for the helper's unit when it starts it,
/// relative to the root (see [`super::loggers::INVOCATION_DIR`]).
const MARKER: &str = "run/systemd/units/invocation:unattended-upgrades.service";

/// The clock ticks a second in which `/proc/<pid>/stat` gives a process's
/// start (`USER_HZ`, what `sysconf(_SC_CLK_TCK)` returns): 100 on every
/// architecture NAILS builds for.
const TICKS_PER_SECOND: u64 = 100;

/// The variable that names the file apt reads first.
const APT_CONFIG: &[u8] = b"APT_CONFIG";

/// The processes of the helper's unit under `root`.
pub(super) fn processes<F: Filesystem>(fs: &F, root: &Path) -> Result<Vec<u32>, String> {
    let shown = format!("/{CGROUP}/{UNIT}/cgroup.procs");
    let listed = fs
        .read_file_content(&root.join(CGROUP).join(UNIT).join("cgroup.procs"))
        .map_err(|e| format!("the processes of {UNIT} cannot be listed: {shown} ({e})"))?;
    let mut pids = Vec::new();
    for line in listed.lines().filter(|line| !line.trim().is_empty()) {
        let pid = line
            .trim()
            .parse::<u32>()
            .map_err(|_| format!("{shown} lists {line:?}, which is no process number"))?;
        pids.push(pid);
    }
    if pids.is_empty() {
        return Err(format!("{shown} lists no process of {UNIT}"));
    }
    Ok(pids)
}

/// The value of `APT_CONFIG` in an environment block as
/// `/proc/<pid>/environ` holds it, `NAME=value` entries each ended by a NUL:
/// the first entry of that name, as `getenv()` takes it, and `None` when
/// there is none or it is empty, which apt takes for none.
pub(super) fn apt_config_of(environ: &[u8]) -> Option<Vec<u8>> {
    environ
        .split(|byte| *byte == 0)
        .find_map(|entry| {
            entry
                .strip_prefix(APT_CONFIG)
                .and_then(|rest| rest.strip_prefix(b"="))
        })
        .filter(|value| !value.is_empty())
        .map(<[u8]>::to_vec)
}

/// What a caller that is root (`as_root`) or not makes of a read of the
/// helper's environment that failed with `kind`: the words that say only
/// root can read it, where only root can. Without root the kernel refuses it
/// (`EACCES`, or `EPERM` where `/proc` is mounted `hidepid=noaccess`) or
/// hides the process as if it were gone (`ENOENT`, where `/proc` is mounted
/// `hidepid=invisible` or `ptraceable`). A process gone since its unit's
/// cgroup was listed reads as gone as well, which a run as root then tells.
fn only_root(kind: Option<std::io::ErrorKind>, as_root: bool) -> Option<&'static str> {
    if as_root {
        return None;
    }
    match kind? {
        std::io::ErrorKind::PermissionDenied => Some("; only root can read it"),
        std::io::ErrorKind::NotFound => {
            Some("; where /proc hides other users' processes, only root can read it")
        }
        _ => None,
    }
}

/// The `APT_CONFIG` the helper's processes `pids` run with under `root`:
/// `None` when none sets it. Processes that set it apart leave it unknown,
/// and so does an environment NAILS cannot read: only root may, so a read
/// without root that the kernel refuses or hides says so.
pub(super) fn apt_config<F: Filesystem>(
    fs: &F,
    root: &Path,
    pids: &[u32],
) -> Result<Option<Vec<u8>>, Doubt> {
    let as_root = nix::unistd::geteuid().is_root();
    let mut found: Option<Option<Vec<u8>>> = None;
    for pid in pids {
        let environ = fs
            .read_file_bytes(&root.join(format!("proc/{pid}/environ")))
            .map_err(|e| {
                let root_can = only_root(e.io_kind(), as_root);
                Doubt {
                    why: format!(
                        "the environment of {UNIT} (PID {pid}), where apt takes APT_CONFIG from, \
                         cannot be read ({e}){}",
                        root_can.unwrap_or_default()
                    ),
                    needs_root: root_can.is_some(),
                }
            })?;
        // Only the one variable is kept: the block is dropped here.
        let value = apt_config_of(&environ);
        drop(environ);
        match &found {
            Some(seen) if *seen != value => {
                return Err(format!(
                    "the processes of {UNIT} run with different values of APT_CONFIG"
                )
                .into());
            }
            Some(_) => {}
            None => found = Some(value),
        }
    }
    Ok(found.flatten())
}

/// The boot time `/proc/stat` gives, in whole seconds since the epoch.
fn boot_time(stat: &str) -> Option<u64> {
    stat.lines()
        .find_map(|line| line.strip_prefix("btime "))
        .and_then(|value| value.trim().parse().ok())
}

/// The earliest time the helper, its processes `pids` under `root`, can have
/// read apt's configuration at its start (see the [module docs](self)).
pub(super) fn started<F: Filesystem>(
    fs: &F,
    root: &Path,
    pids: &[u32],
) -> Result<SystemTime, String> {
    let mut earliest = None::<SystemTime>;
    let mut take = |time: SystemTime| {
        earliest = Some(earliest.map_or(time, |seen| seen.min(time)));
    };
    let marker = root.join(MARKER);
    let doubt = |e| format!("when {UNIT} started cannot be read: /{MARKER} ({e})");
    if fs.is_symlink(&marker).map_err(doubt)? {
        take(fs.change_time(&marker).map_err(doubt)?);
    }
    let stat = fs
        .read_file_content(&root.join("proc/stat"))
        .map_err(|e| format!("when {UNIT} started cannot be read: /proc/stat ({e})"))?;
    let boot = boot_time(&stat)
        .ok_or_else(|| format!("when {UNIT} started cannot be read: /proc/stat has no btime"))?;
    for pid in pids {
        let shown = format!("/proc/{pid}/stat");
        let process = fs
            .read_file_content(&root.join(format!("proc/{pid}/stat")))
            .map_err(|e| format!("when {UNIT} started cannot be read: {shown} ({e})"))?;
        let ticks = nails_teardown::proc::parse_stat(&process)
            .ok_or_else(|| format!("when {UNIT} started cannot be read: {shown} is not one"))?
            .start_time;
        let since_boot = Duration::from_secs(ticks / TICKS_PER_SECOND)
            + Duration::from_nanos(ticks % TICKS_PER_SECOND * (1_000_000_000 / TICKS_PER_SECOND));
        take(UNIX_EPOCH + Duration::from_secs(boot) + since_boot);
    }
    earliest.ok_or_else(|| format!("when {UNIT} started cannot be read"))
}

/// Whether a file or directory that changed at `changed` may have changed
/// after the helper read it at a start no earlier than `started`: a change
/// in the same second or later counts, as a filesystem may keep its change
/// times to the second.
pub(super) fn changed_since(changed: SystemTime, started: SystemTime) -> bool {
    let seconds = |time: SystemTime| {
        time.duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_secs())
    };
    seconds(changed) >= seconds(started)
}

/// The file `APT_CONFIG` names, relative to the root, as the helper reads
/// it: an absolute path. A relative one, which the helper reads from its
/// working directory, is left to the caller as unknown.
pub(super) fn apt_config_path(value: &[u8]) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    let path = Path::new(std::ffi::OsStr::from_bytes(value));
    path.strip_prefix("/").ok().map(Path::to_path_buf)
}

/// What of apt's configuration under `root` changed since `started`, when
/// the decoy's helper read it at its start, as the helper keeps what it read
/// then: one of the files it reads now and the links among them that lead to
/// no file now (`read`), `/etc/apt` (where the main file lies),
/// `/etc/apt/apt.conf.d`, or the directory that holds the file at
/// `apt_config` that the helper's `APT_CONFIG` names (relative to `root`),
/// or one of them reached through a symbolic link, whose change NAILS does
/// not follow. A directory swapped into place replaces the files below it
/// without changing their own change times, which is why each directory
/// that holds one is compared too. `None` when nothing did.
pub(super) fn changed_since_start<F: Filesystem>(
    fs: &F,
    root: &Path,
    read: &[PathBuf],
    apt_config: Option<&Path>,
    started: SystemTime,
) -> Result<Option<String>, String> {
    let real_root = fs
        .canonicalize(root)
        .map_err(|e| format!("/ cannot be looked up ({e})"))?;
    let mut dirs = vec![root.join(APT), root.join(PARTS)];
    // The root itself is left out: it cannot be swapped, and a file in it
    // that is replaced changes its own change time.
    if let Some(holder) = apt_config
        .and_then(Path::parent)
        .filter(|holder| !holder.as_os_str().is_empty())
    {
        dirs.push(root.join(holder));
    }
    for path in dirs.iter().chain(read) {
        let rel = path.strip_prefix(root).unwrap_or(path);
        let shown = format!("/{}", rel.display());
        let doubt = |e| format!("{shown} cannot be looked up ({e})");
        // A link that leads to no file now is skipped by apt at the signal,
        // while what it led to at the start may still count.
        let linked = fs.is_symlink(path).map_err(doubt)?
            || fs.canonicalize(path).map_err(doubt)? != real_root.join(rel);
        if linked {
            return Ok(Some(format!(
                "{shown} is reached through a symbolic link, so NAILS cannot tell whether what \
                 it leads to changed after the helper started"
            )));
        }
        let changed = fs
            .change_time(path)
            .map_err(|e| format!("when {shown} changed cannot be read ({e})"))?;
        if changed_since(changed, started) {
            return Ok(Some(format!("{shown} changed after the helper started")));
        }
    }
    Ok(None)
}

/// What the decoy's running helper reads first, the file its `APT_CONFIG`
/// names, relative to `root`: `None` when it runs with none, an error when
/// NAILS cannot tell. The helper's processes come with it, for when it
/// started.
pub(super) fn running<F: Filesystem>(
    fs: &F,
    root: &Path,
) -> Result<(Vec<u32>, Option<PathBuf>), Doubt> {
    let pids = processes(fs, root)?;
    let apt_config = match apt_config(fs, root, &pids)? {
        None => None,
        Some(value) => Some(apt_config_path(&value).ok_or_else(|| {
            format!(
                "the helper's APT_CONFIG names {}, a relative path, which it reads from its \
                 working directory, which NAILS does not follow",
                String::from_utf8_lossy(&value)
            )
        })?),
    };
    Ok((pids, apt_config))
}

#[cfg(test)]
#[path = "helper_tests.rs"]
mod tests;
