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
    let mut blocking = Vec::new();

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
mod tests {
    use super::*;

    #[test]
    fn test_processinfo_struct() {
        // Verify ProcessInfo can be constructed with all fields
        let info = ProcessInfo {
            pid: 1234,
            name: "firefox".to_string(),
            cmdline: "/usr/bin/firefox".to_string(),
            cwd: PathBuf::from("/home/user"),
            has_cwd_in_target: true,
            has_open_fds_in_target: false,
            has_mmap_in_target: true,
            service_name: None,
        };

        assert_eq!(info.pid, 1234);
        assert_eq!(info.name, "firefox");
        assert!(info.has_cwd_in_target);
        assert!(!info.has_open_fds_in_target);
        assert!(info.has_mmap_in_target);
        assert_eq!(info.service_name, None);
    }

    #[test]
    fn test_processinfo_with_systemd_service() {
        let info = ProcessInfo {
            pid: 234,
            name: "systemd-journald".to_string(),
            cmdline: "/usr/lib/systemd/systemd-journald".to_string(),
            cwd: PathBuf::from("/"),
            has_cwd_in_target: false,
            has_open_fds_in_target: true,
            has_mmap_in_target: false,
            service_name: Some("systemd-journald".to_string()),
        };

        assert_eq!(info.service_name, Some("systemd-journald".to_string()));
    }

    #[test]
    fn test_extract_service_name_from_cgroup() {
        // Create a temporary test file simulating /proc/{pid}/cgroup
        let temp_dir = tempfile::tempdir().unwrap();
        let cgroup_path = temp_dir.path().join("cgroup");

        // Write cgroup content
        fs::write(&cgroup_path, "0::/system.slice/systemd-journald.service\n").unwrap();

        // Test extraction
        let proc_path = temp_dir.path();
        let service_name = extract_service_name(proc_path).unwrap();
        assert_eq!(service_name, Some("systemd-journald".to_string()));
    }

    #[test]
    fn test_extract_service_name_no_service() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cgroup_path = temp_dir.path().join("cgroup");

        // Write cgroup content without service
        fs::write(&cgroup_path, "0::/user.slice/user-1000.slice\n").unwrap();

        let proc_path = temp_dir.path();
        let service_name = extract_service_name(proc_path).unwrap();
        assert_eq!(service_name, None);
    }

    #[test]
    fn test_read_comm() {
        let temp_dir = tempfile::tempdir().unwrap();
        let comm_path = temp_dir.path().join("comm");

        fs::write(&comm_path, "firefox\n").unwrap();

        let name = read_comm(temp_dir.path()).unwrap();
        assert_eq!(name, "firefox");
    }

    #[test]
    fn test_read_cmdline() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cmdline_path = temp_dir.path().join("cmdline");

        // Null-separated command line
        let cmdline_bytes = b"/usr/bin/firefox\0--profile\0/home/user/.firefox\0";
        fs::write(&cmdline_path, cmdline_bytes).unwrap();

        let cmdline = read_cmdline(temp_dir.path()).unwrap();
        assert_eq!(cmdline, "/usr/bin/firefox --profile /home/user/.firefox");
    }

    #[test]
    fn test_check_cwd_in_target() {
        // Note: This test requires actual /proc filesystem with symlinks
        // We'll test the logic with a real process or skip if unavailable

        // Test with a path that doesn't exist (should return false)
        let proc_path = PathBuf::from("/proc/99999999"); // Unlikely PID
        let target = Path::new("/home");

        let (in_target, _cwd) = check_cwd_in_target(&proc_path, target);
        assert!(!in_target);
    }

    #[test]
    fn test_check_fds_in_target() {
        // Test with non-existent process
        let proc_path = PathBuf::from("/proc/99999999");
        let target = Path::new("/home");

        let has_fds = check_fds_in_target(&proc_path, target);
        assert!(!has_fds);
    }

    #[test]
    fn test_check_maps_in_target() {
        let temp_dir = tempfile::tempdir().unwrap();
        let maps_path = temp_dir.path().join("maps");

        // Simulate maps file content
        let maps_content = "\
7f1234567000-7f1234568000 r-xp 00000000 08:01 12345 /home/user/lib.so
7f1234568000-7f1234569000 r--p 00001000 08:01 12345 /home/user/lib.so
7f1234569000-7f123456a000 rw-p 00002000 08:01 12345 /home/user/lib.so
";
        fs::write(&maps_path, maps_content).unwrap();

        let has_mmap = check_maps_in_target(temp_dir.path(), Path::new("/home"));
        assert!(has_mmap);

        let has_mmap_other = check_maps_in_target(temp_dir.path(), Path::new("/etc"));
        assert!(!has_mmap_other);
    }

    #[test]
    fn test_detect_processes_using_returns_empty_for_nonexistent_target() {
        // Test detection against a target that no processes are using
        // This verifies the function doesn't panic and returns empty list
        let result = detect_processes_using(Path::new("/nonexistent-directory-xyz123"));
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }
}
