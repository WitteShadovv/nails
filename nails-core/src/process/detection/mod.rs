//! Process Detection
//!
//! Detects processes using target directories by parsing the `/proc` filesystem.
//!
//! # Detection Strategy
//!
//! An overlay only redirects *new* path lookups. A process that opened a file,
//! `cwd`'d into a directory or memory-mapped a file *before* the mount keeps
//! resolving the original inode and keeps writing to the decoy lower tree. So the
//! detector does not ask merely "does this process touch the target?" — it asks
//! "can this process still *write* to the decoy through a reference it already
//! holds?". The indicators are:
//! 1. **Current working directory (`cwd`)** inside the target.
//! 2. **Root (`/proc/<pid>/root`)** inside the target (a chroot writer).
//! 3. **A writable open fd** (`O_WRONLY`/`O_RDWR`/`O_APPEND`, read from
//!    `/proc/<pid>/fdinfo`) or a **directory fd** inside the target.
//! 4. **A shared, writable mapping** (`rw-s`) of a file inside the target.
//!
//! Read-only fds and private/read-only mappings are recorded too, but they do not
//! let the process write to the decoy, so a process that holds *only* those is a
//! read-only consumer rather than a blocking writer.
//!
//! # Scanning once
//!
//! Activation overlays many targets. Rather than walk `/proc` once per target, a
//! [`ProcSnapshot`] walks it once, reads each process's `cwd`, `root`, fds and
//! maps, and then answers [`ProcSnapshot::processes_using`] for any number of
//! targets purely in memory. [`detect_processes_using`] is a thin wrapper that
//! captures a snapshot and queries a single target.
//!
//! # Example
//!
//! ```no_run
//! use nails_core::process::detection::detect_processes_using;
//! use std::path::Path;
//!
//! let blocking = detect_processes_using(Path::new("/home"))?;
//! for proc in blocking {
//!     println!("Process {} (PID {}) is using /home", proc.name, proc.pid);
//! }
//! # Ok::<(), nails_core::NailsError>(())
//! ```

use crate::error::{NailsError, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// Information about a process using a target directory
///
/// Contains all metadata needed to classify and restart the process. The
/// capability flags distinguish a process that can still *write* to the decoy
/// (`cwd`/`root` in target, a writable or directory fd, a shared-writable
/// mapping) from one that only holds read-only references.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    /// Process ID
    pub pid: u32,
    /// Process name (from `/proc/{pid}/comm`)
    pub name: String,
    /// Full command line (from `/proc/{pid}/cmdline`)
    pub cmdline: String,
    /// Current working directory
    pub cwd: PathBuf,
    /// Process has `cwd` in target directory
    pub has_cwd_in_target: bool,
    /// Process has any open file descriptor (read-only or writable) in target
    pub has_open_fds_in_target: bool,
    /// Process has a writable fd (`O_WRONLY`/`O_RDWR`/`O_APPEND`) in target
    pub has_writable_fd_in_target: bool,
    /// Process has a directory fd in target (blocks the overlay mount)
    pub has_dir_fd_in_target: bool,
    /// Process has any memory-mapped file from target directory
    pub has_mmap_in_target: bool,
    /// Process has a shared, writable (`rw-s`) mapping of a file in target
    pub has_shared_write_map_in_target: bool,
    /// Process root (`/proc/{pid}/root`) is inside the target (a chroot writer)
    pub has_root_in_target: bool,
    /// Process cannot be verified against the host namespace: it is chrooted or
    /// lives in a different mount namespace than PID 1, so whether it writes to
    /// the decoy lower tree cannot be determined from the host's view of the
    /// paths. Such a process is reported rather than silently trusted.
    pub is_unverifiable_writer: bool,
    /// Systemd service name (if applicable)
    pub service_name: Option<String>,
    /// Process is attached to a controlling terminal (stdin/stdout/stderr points
    /// at a tty or pty).
    ///
    /// An interactive process is almost always a program a user is working in
    /// (a shell, an editor, `tail -f`). Terminating it by signal loses their
    /// work without warning, so activation refuses to force-terminate an
    /// interactive, non-service process unless the operator opts in.
    pub is_interactive: bool,
}

impl ProcessInfo {
    /// Whether the process can still write to the decoy lower tree through a
    /// reference it already holds: `cwd` or root inside the target, a writable or
    /// directory fd, or a shared-writable mapping. A process that is only an
    /// unverifiable writer is treated as write-blocking too, because its access
    /// cannot be ruled out.
    pub fn is_write_blocking(&self) -> bool {
        self.has_cwd_in_target
            || self.has_root_in_target
            || self.has_writable_fd_in_target
            || self.has_dir_fd_in_target
            || self.has_shared_write_map_in_target
            || self.is_unverifiable_writer
    }

    /// Whether the process holds only read-only references to the target (an
    /// open fd or a private/read-only mapping) and cannot write to the decoy
    /// through them. These are safe to leave running.
    pub fn is_read_only_consumer(&self) -> bool {
        (self.has_open_fds_in_target || self.has_mmap_in_target) && !self.is_write_blocking()
    }
}

/// Strip the kernel's `" (deleted)"` suffix from a resolved `/proc` link or maps
/// path, so an unlinked-but-open file still matches its directory.
fn strip_deleted(path: &str) -> &str {
    path.strip_suffix(" (deleted)").unwrap_or(path)
}

/// A single open file descriptor of a process, resolved against the host view.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FdRef {
    /// The path the fd resolves to (with any `" (deleted)"` suffix stripped).
    path: PathBuf,
    /// The fd was opened for writing (`O_WRONLY`/`O_RDWR`/`O_APPEND`).
    writable: bool,
    /// The fd refers to a directory (holds the directory open).
    is_dir: bool,
}

/// A single memory mapping of a process, resolved against the host view.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MapRef {
    /// The mapped file path (with any `" (deleted)"` suffix stripped).
    path: PathBuf,
    /// The mapping is shared and writable (`rw-s`): writes reach the backing file.
    shared_write: bool,
}

/// Everything read about one process in a single `/proc` walk, so any number of
/// targets can be classified against it without touching the filesystem again.
#[derive(Debug, Clone)]
struct ProcEntry {
    pid: u32,
    name: String,
    cmdline: String,
    cwd: Option<PathBuf>,
    root: Option<PathBuf>,
    fds: Vec<FdRef>,
    maps: Vec<MapRef>,
    service_name: Option<String>,
    is_interactive: bool,
    /// The process lives in a different mount namespace than PID 1, or is
    /// chrooted; its path references cannot be verified against the host.
    unverifiable: bool,
}

impl ProcEntry {
    /// Classify this process against a single target, returning its
    /// [`ProcessInfo`] when it references the target in any way, or `None`.
    fn info_for(&self, target: &Path) -> Option<ProcessInfo> {
        let has_cwd_in_target = self
            .cwd
            .as_deref()
            .is_some_and(|cwd| cwd.starts_with(target));
        // Root is "/" for an unconfined process; that only matches target "/".
        let has_root_in_target = self
            .root
            .as_deref()
            .is_some_and(|root| root != Path::new("/") && root.starts_with(target));

        let mut has_open_fds_in_target = false;
        let mut has_writable_fd_in_target = false;
        let mut has_dir_fd_in_target = false;
        for fd in &self.fds {
            if fd.path.starts_with(target) {
                has_open_fds_in_target = true;
                has_writable_fd_in_target |= fd.writable;
                has_dir_fd_in_target |= fd.is_dir;
            }
        }

        let mut has_mmap_in_target = false;
        let mut has_shared_write_map_in_target = false;
        for map in &self.maps {
            if map.path.starts_with(target) {
                has_mmap_in_target = true;
                has_shared_write_map_in_target |= map.shared_write;
            }
        }

        let references_target =
            has_cwd_in_target || has_root_in_target || has_open_fds_in_target || has_mmap_in_target;
        if !references_target {
            return None;
        }

        Some(ProcessInfo {
            pid: self.pid,
            name: self.name.clone(),
            cmdline: self.cmdline.clone(),
            cwd: self.cwd.clone().unwrap_or_default(),
            has_cwd_in_target,
            has_open_fds_in_target,
            has_writable_fd_in_target,
            has_dir_fd_in_target,
            has_mmap_in_target,
            has_shared_write_map_in_target,
            has_root_in_target,
            is_unverifiable_writer: self.unverifiable,
            service_name: self.service_name.clone(),
            is_interactive: self.is_interactive,
        })
    }
}

/// A one-shot view of the processes on the host, captured by a single walk of
/// `/proc`. Classify any number of overlay targets against it with
/// [`ProcSnapshot::processes_using`] without re-reading `/proc` per target.
#[derive(Debug, Clone)]
pub struct ProcSnapshot {
    entries: Vec<ProcEntry>,
}

impl ProcSnapshot {
    /// Walk `/proc` once and read each process's `cwd`, `root`, fds and maps.
    ///
    /// Returns an empty snapshot in test/test-like runtimes (where touching the
    /// host `/proc` must be avoided).
    pub fn capture() -> Result<Self> {
        if crate::runtime_safety::should_skip_host_interaction() {
            tracing::debug!("Skipping host /proc snapshot in test/test-like runtime");
            return Ok(Self {
                entries: Vec::new(),
            });
        }

        let host_mnt_ns = read_mnt_ns(Path::new("/proc/1"));
        let mut entries = Vec::new();
        for (pid, proc_path) in scan_processes()? {
            if let Some(entry) = read_proc_entry(&proc_path, pid, host_mnt_ns.as_deref()) {
                entries.push(entry);
            }
        }
        Ok(Self { entries })
    }

    /// The processes that reference `target` in any way, classified against the
    /// capability flags recorded at capture time.
    pub fn processes_using(&self, target: &Path) -> Vec<ProcessInfo> {
        self.entries
            .iter()
            .filter_map(|entry| entry.info_for(target))
            .collect()
    }
}

/// Detect all processes using a target directory
///
/// Captures a [`ProcSnapshot`] and queries it for a single `target`. Callers that
/// inspect several targets should capture one snapshot and call
/// [`ProcSnapshot::processes_using`] per target to avoid re-walking `/proc`.
///
/// # Arguments
///
/// * `target` - Directory path to check (e.g., `/home`, `/etc`, `/nix/store`)
///
/// # Returns
///
/// * `Ok(Vec<ProcessInfo>)` - List of processes using the target directory
/// * `Err(NailsError)` - If `/proc` parsing fails
///
/// # Example
///
/// ```no_run
/// use nails_core::process::detection::detect_processes_using;
/// use std::path::Path;
///
/// let blocking = detect_processes_using(Path::new("/home"))?;
/// println!("Found {} processes using /home", blocking.len());
/// # Ok::<(), nails_core::NailsError>(())
/// ```
pub fn detect_processes_using(target: &Path) -> Result<Vec<ProcessInfo>> {
    Ok(ProcSnapshot::capture()?.processes_using(target))
}

/// Detect the terminal-attached processes using any of `targets`, in one pass
/// over `/proc`.
///
/// Returns one `(target, process)` pair per target a process uses. Activation
/// runs this before mounting anything so it can refuse up front when it would
/// otherwise have to force-terminate a program a user is working in.
pub fn detect_interactive_processes_using(
    targets: &[PathBuf],
) -> Result<Vec<(PathBuf, ProcessInfo)>> {
    if targets.is_empty() || crate::runtime_safety::should_skip_host_interaction() {
        return Ok(Vec::new());
    }

    let snapshot = ProcSnapshot::capture()?;
    let mut found = Vec::new();
    for entry in &snapshot.entries {
        if !entry.is_interactive {
            continue;
        }
        for target in targets {
            if let Some(info) = entry.info_for(target) {
                found.push((target.clone(), info));
            }
        }
    }

    Ok(found)
}

/// List the `/proc/<pid>` entries to inspect, leaving out this process and its
/// ancestors.
///
/// Excluding the own process tree prevents nails from killing itself (e.g. the
/// sudo that invoked nails, or the NixOS test-driver control channel in VM
/// tests).
fn scan_processes() -> Result<Vec<(u32, PathBuf)>> {
    let exclude_pids = collect_ancestor_pids();

    let proc_dir = Path::new("/proc");
    if !proc_dir.exists() {
        return Err(NailsError::ConfigError(
            "/proc filesystem not available. This is required for process detection. \
             Ensure you're running on Linux with /proc mounted."
                .to_string(),
        ));
    }

    let mut processes = Vec::new();
    for entry in fs::read_dir(proc_dir)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let pid_str = file_name.to_string_lossy();

        // Skip non-PID entries (e.g., "cpuinfo", "meminfo")
        if !pid_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }

        let pid: u32 = match pid_str.parse() {
            Ok(p) => p,
            Err(_) => continue, // Skip invalid PIDs
        };

        if exclude_pids.contains(&pid) {
            continue;
        }

        processes.push((pid, proc_dir.join(&file_name)));
    }

    Ok(processes)
}

/// Read every reference a process holds from its `/proc/<pid>` directory.
///
/// `host_mnt_ns` is PID 1's mount namespace link target, used to flag a process
/// in a different mount namespace as an unverifiable writer. An unreadable
/// process still yields an entry (with empty references), so it is simply never
/// matched against a target rather than aborting the whole snapshot.
fn read_proc_entry(proc_path: &Path, pid: u32, host_mnt_ns: Option<&str>) -> Option<ProcEntry> {
    let cwd = read_link_stripped(&proc_path.join("cwd"));
    let root = read_link_stripped(&proc_path.join("root"));
    let fds = read_fds(proc_path);
    let maps = read_maps(proc_path);

    let chrooted = root.as_deref().is_some_and(|root| root != Path::new("/"));
    let foreign_ns = match (host_mnt_ns, read_mnt_ns(proc_path)) {
        (Some(host), Some(ours)) => host != ours,
        _ => false,
    };

    Some(ProcEntry {
        pid,
        name: read_comm(proc_path).unwrap_or_else(|_| "unknown".to_string()),
        cmdline: read_cmdline(proc_path).unwrap_or_default(),
        cwd,
        root,
        fds,
        maps,
        service_name: extract_service_name(proc_path).ok().flatten(),
        is_interactive: check_interactive(proc_path),
        unverifiable: chrooted || foreign_ns,
    })
}

/// Collect the current process PID and all ancestor PIDs up to PID 1.
///
/// Walks the process tree via `/proc/{pid}/stat` to find PPIDs.
/// Returns a set containing the current PID and all parent PIDs.
fn collect_ancestor_pids() -> std::collections::HashSet<u32> {
    let mut pids = std::collections::HashSet::new();
    let mut current = std::process::id();

    loop {
        pids.insert(current);
        if current <= 1 {
            break;
        }
        match read_ppid(current) {
            Some(ppid) if ppid != current => {
                current = ppid;
            }
            _ => break,
        }
    }

    pids
}

/// Read the parent PID from `/proc/{pid}/stat`.
///
/// The stat file format has PPID as the 4th field. We parse carefully
/// because the process name (field 2) can contain spaces and parentheses.
fn read_ppid(pid: u32) -> Option<u32> {
    let stat_path = format!("/proc/{}/stat", pid);
    let content = fs::read_to_string(stat_path).ok()?;

    // Field 2 (comm) is enclosed in parentheses and may contain spaces/parens.
    // Find the last ')' to skip past it, then parse field 4 (PPID).
    let after_comm = content.rfind(')')? + 1;
    let remainder = &content[after_comm..];
    let fields: Vec<&str> = remainder.split_whitespace().collect();

    // fields[0] = state, fields[1] = ppid
    if fields.len() >= 2 {
        fields[1].parse().ok()
    } else {
        None
    }
}

/// Read a `/proc` symlink and strip any `" (deleted)"` suffix, returning `None`
/// when the link cannot be read.
fn read_link_stripped(link: &Path) -> Option<PathBuf> {
    let resolved = fs::read_link(link).ok()?;
    Some(PathBuf::from(strip_deleted(&resolved.to_string_lossy())))
}

/// Read the mount-namespace link target of a process (`/proc/<pid>/ns/mnt`).
fn read_mnt_ns(proc_path: &Path) -> Option<String> {
    fs::read_link(proc_path.join("ns/mnt"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

/// Read every open fd of a process, resolving each to a path and reading its
/// open flags from `/proc/<pid>/fdinfo/<fd>` to decide whether it is writable.
fn read_fds(proc_path: &Path) -> Vec<FdRef> {
    let fd_dir = proc_path.join("fd");
    let Ok(entries) = fs::read_dir(&fd_dir) else {
        return Vec::new();
    };

    let mut fds = Vec::new();
    for entry in entries.flatten() {
        let Ok(resolved) = fs::read_link(entry.path()) else {
            continue;
        };
        let path = PathBuf::from(strip_deleted(&resolved.to_string_lossy()));
        let fd_name = entry.file_name();
        let writable = fd_is_writable(proc_path, &fd_name.to_string_lossy());
        // A directory fd follows the symlink to a real directory; a deleted
        // target fails to stat and is treated as a non-directory.
        let is_dir = fs::metadata(entry.path())
            .map(|m| m.is_dir())
            .unwrap_or(false);
        fds.push(FdRef {
            path,
            writable,
            is_dir,
        });
    }
    fds
}

/// Octal open flags. Writability is the access mode in the low two bits
/// (`O_WRONLY`=1, `O_RDWR`=2) plus `O_APPEND`.
const O_ACCMODE: u64 = 0o3;
const O_WRONLY: u64 = 0o1;
const O_RDWR: u64 = 0o2;
const O_APPEND: u64 = 0o2000;

/// Whether an fd was opened for writing, read from `/proc/<pid>/fdinfo/<fd>`.
///
/// The `flags:` line holds the octal open flags. An fd counts as writable when
/// its access mode is `O_WRONLY`/`O_RDWR` or it carries `O_APPEND`. When fdinfo
/// cannot be read the fd is treated as writable, failing safe (a potential
/// writer is reported rather than silently trusted).
fn fd_is_writable(proc_path: &Path, fd_name: &str) -> bool {
    let fdinfo = proc_path.join("fdinfo").join(fd_name);
    let Ok(content) = fs::read_to_string(&fdinfo) else {
        return true;
    };
    match parse_fdinfo_flags(&content) {
        Some(flags) => {
            let access = flags & O_ACCMODE;
            access == O_WRONLY || access == O_RDWR || (flags & O_APPEND) != 0
        }
        None => true,
    }
}

/// Parse the octal `flags:` value out of an fdinfo file's contents.
fn parse_fdinfo_flags(content: &str) -> Option<u64> {
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("flags:") {
            return u64::from_str_radix(rest.trim(), 8).ok();
        }
    }
    None
}

/// Check whether a process is attached to a controlling terminal.
///
/// A process counts as interactive when any of its standard streams (fd 0, 1 or
/// 2) resolves to a terminal device (`/dev/pts/*`, `/dev/tty*` or `/dev/console`).
/// This is the signal that a user is working in the program, so activation must
/// not force-terminate it without consent.
fn check_interactive(proc_path: &Path) -> bool {
    let fd_dir = proc_path.join("fd");
    for fd in ["0", "1", "2"] {
        if let Ok(link) = fs::read_link(fd_dir.join(fd))
            && is_terminal_device(&link)
        {
            return true;
        }
    }
    false
}

/// Whether a resolved fd path points at a terminal device node.
fn is_terminal_device(path: &Path) -> bool {
    let text = path.to_string_lossy();
    text.starts_with("/dev/pts/") || text.starts_with("/dev/tty") || text == "/dev/console"
}

/// Read every file-backed memory mapping of a process from `/proc/<pid>/maps`,
/// recording whether each is a shared, writable mapping.
fn read_maps(proc_path: &Path) -> Vec<MapRef> {
    let maps_file = proc_path.join("maps");
    let Ok(contents) = fs::read_to_string(&maps_file) else {
        return Vec::new();
    };

    let mut maps = Vec::new();
    for line in contents.lines() {
        // maps format: address perms offset dev inode pathname
        // Example: 7f1234-7f5678 rw-s 00000000 08:01 12345 /home/user/db
        // The pathname is everything after the fifth field, so file names with
        // spaces survive; pseudo-paths like "[heap]" are skipped.
        let mut parts = line.splitn(6, char::is_whitespace);
        let (_addr, perms, _offset, _dev, _inode, pathname) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        );
        let (Some(perms), Some(pathname)) = (perms, pathname) else {
            continue;
        };
        let pathname = pathname.trim_start();
        if pathname.is_empty() || pathname.starts_with('[') {
            continue;
        }
        let shared_write = map_is_shared_write(perms);
        maps.push(MapRef {
            path: PathBuf::from(strip_deleted(pathname)),
            shared_write,
        });
    }
    maps
}

/// Whether a maps `perms` field describes a shared, writable mapping (`rw-s`):
/// writes through it reach the backing file in the decoy. A private mapping
/// (`rw-p`) copies on write and never touches the lower tree.
fn map_is_shared_write(perms: &str) -> bool {
    let bytes = perms.as_bytes();
    let writable = bytes.get(1) == Some(&b'w');
    let shared = bytes.get(3) == Some(&b's');
    writable && shared
}

/// Read process name from `/proc/{pid}/comm`
fn read_comm(proc_path: &Path) -> Result<String> {
    let comm_path = proc_path.join("comm");
    let content = fs::read_to_string(comm_path)?;
    Ok(content.trim().to_string())
}

/// Read full command line from `/proc/{pid}/cmdline`
fn read_cmdline(proc_path: &Path) -> Result<String> {
    let cmdline_path = proc_path.join("cmdline");
    let bytes = fs::read(cmdline_path)?;

    // cmdline is null-separated, convert to space-separated
    let cmdline = bytes
        .split(|&b| b == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).to_string())
        .collect::<Vec<_>>()
        .join(" ");

    Ok(cmdline)
}

/// Extract the systemd *system* unit a process belongs to from
/// `/proc/{pid}/cgroup`, if any.
///
/// Only a unit rooted under `/system.slice/` is returned; see
/// [`system_unit_from_cgroup_line`] for why a user unit must not be.
fn extract_service_name(proc_path: &Path) -> Result<Option<String>> {
    let cgroup_path = proc_path.join("cgroup");
    let Ok(content) = fs::read_to_string(cgroup_path) else {
        return Ok(None);
    };

    Ok(content
        .lines()
        .find_map(system_unit_from_cgroup_line)
        .map(str::to_string))
}

/// The systemd *system* unit a single cgroup line maps to, if any.
///
/// The cgroup path is the field after the last `:` (cgroup v2 writes `0::/…`,
/// v1 writes `N:controller:/…`). A unit is returned only when that path is
/// rooted under a `system.slice` segment and its leaf is a `.service`.
///
/// A user unit — anything under `user.slice` / `user@<uid>.service`, e.g.
/// `pipewire.service` beneath `user@1000.service` — deliberately yields `None`.
/// The result feeds `systemctl stop <unit>` against the *system* manager, so
/// mapping a user unit here would stop it system-wide for every user; returning
/// `None` instead routes that process to signal-based termination, which is the
/// correct handling for a per-user process.
pub(crate) fn system_unit_from_cgroup_line(line: &str) -> Option<&str> {
    let path = line.rsplit(':').next().unwrap_or(line);
    let unit = path.rsplit('/').next()?.strip_suffix(".service")?;
    if unit.is_empty() {
        return None;
    }
    path.split('/')
        .any(|segment| segment == "system.slice")
        .then_some(unit)
}

#[cfg(test)]
mod tests;
