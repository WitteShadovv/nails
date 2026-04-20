//! Process Detection
//!
//! Detects processes using target directories by parsing the `/proc` filesystem.
//!
//! # Detection Strategy
//!
//! The detection algorithm checks three indicators that a process is using a directory:
//! 1. **Current working directory (`cwd`)**: Process has `cwd` in target
//! 2. **Open file descriptors (`fd`)**: Process has open files in target
//! 3. **Memory mappings (`maps`)**: Process has memory-mapped files from target
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
/// Contains all metadata needed to classify and restart the process.
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
    /// Process has open file descriptors in target directory
    pub has_open_fds_in_target: bool,
    /// Process has memory-mapped files from target directory
    pub has_mmap_in_target: bool,
    /// Systemd service name (if applicable)
    pub service_name: Option<String>,
}

/// Detect all processes using a target directory
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
    if crate::runtime_safety::should_skip_host_interaction() {
        tracing::debug!(
            target = %target.display(),
            "Skipping host /proc process detection in test/test-like runtime"
        );
        return Ok(Vec::new());
    }

    let mut blocking = Vec::new();

    // Build set of PIDs to exclude: current process and all ancestors.
    // This prevents nails from killing its own process tree (e.g., the sudo
    // that invoked nails, or the NixOS test-driver control channel in VM tests).
    let exclude_pids = collect_ancestor_pids();

    // Iterate over /proc entries
    let proc_dir = Path::new("/proc");
    if !proc_dir.exists() {
        return Err(NailsError::ConfigError(
            "/proc filesystem not available. This is required for process detection. \
             Ensure you're running on Linux with /proc mounted."
                .to_string(),
        ));
    }

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

        // Skip our own process tree to avoid killing ourselves
        if exclude_pids.contains(&pid) {
            continue;
        }

        let proc_path = proc_dir.join(&file_name);

        // Check if process is using target directory
        let (has_cwd, cwd) = check_cwd_in_target(&proc_path, target);
        let has_open_fds = check_fds_in_target(&proc_path, target);
        let has_mmap = check_maps_in_target(&proc_path, target);

        if has_cwd || has_open_fds || has_mmap {
            // Process is using target - collect full info
            let name = read_comm(&proc_path).unwrap_or_else(|_| "unknown".to_string());

            let cmdline = read_cmdline(&proc_path).unwrap_or_else(|_| String::new());
            let service_name = extract_service_name(&proc_path).ok().flatten();

            let info = ProcessInfo {
                pid,
                name,
                cmdline,
                cwd,
                has_cwd_in_target: has_cwd,
                has_open_fds_in_target: has_open_fds,
                has_mmap_in_target: has_mmap,
                service_name,
            };

            blocking.push(info);
        }
    }

    Ok(blocking)
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

/// Check if process current working directory is in target
fn check_cwd_in_target(proc_path: &Path, target: &Path) -> (bool, PathBuf) {
    let cwd_link = proc_path.join("cwd");
    match fs::read_link(&cwd_link) {
        Ok(cwd) => {
            let in_target = cwd.starts_with(target);
            (in_target, cwd)
        }
        Err(_) => (false, PathBuf::new()),
    }
}

/// Check if process has open file descriptors in target
fn check_fds_in_target(proc_path: &Path, target: &Path) -> bool {
    let fd_dir = proc_path.join("fd");
    let Ok(entries) = fs::read_dir(&fd_dir) else {
        return false;
    };

    for entry in entries.flatten() {
        if let Ok(fd_target) = fs::read_link(entry.path())
            && fd_target.starts_with(target)
        {
            return true;
        }
    }

    false
}

/// Check if process has memory-mapped files from target
fn check_maps_in_target(proc_path: &Path, target: &Path) -> bool {
    let maps_file = proc_path.join("maps");
    let Ok(contents) = fs::read_to_string(&maps_file) else {
        return false;
    };

    let target_str = target.to_string_lossy();

    for line in contents.lines() {
        // maps format: address perms offset dev inode pathname
        // Example: 7f1234-7f5678 r-xp 00000000 08:01 12345 /home/user/lib.so
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 6 {
            let pathname = parts[5];
            if pathname.starts_with(target_str.as_ref()) {
                return true;
            }
        }
    }

    false
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

/// Extract systemd service name from `/proc/{pid}/cgroup`
fn extract_service_name(proc_path: &Path) -> Result<Option<String>> {
    let cgroup_path = proc_path.join("cgroup");
    let Ok(content) = fs::read_to_string(cgroup_path) else {
        return Ok(None);
    };

    // Parse cgroup format: "0::/system.slice/journald.service"
    for line in content.lines() {
        if let Some(service) = line.rsplit('/').next()
            && service.ends_with(".service")
        {
            let name = service.trim_end_matches(".service").to_string();
            return Ok(Some(name));
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests;
