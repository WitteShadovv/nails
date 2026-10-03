//! System operations: NAILS process detection.
//!
//! Swap posture is classified per device by
//! [`crate::preflight::classify_swap`], which reads `/proc/swaps` and the
//! relevant `/sys` entries through the [`crate::Filesystem`] trait.

use crate::Result;
use crate::filesystem::ProcessMatch;
use std::collections::HashSet;
use std::path::Path;

pub(super) fn nails_process_running() -> Result<bool> {
    let proc_path = Path::new("/proc");
    let excluded_pids = collect_ancestor_pids();

    if !proc_path.exists() {
        return Ok(false);
    }

    if let Ok(entries) = std::fs::read_dir(proc_path) {
        for entry in entries.flatten() {
            let entry_path = entry.path();
            let pid_dir = entry_path.file_name().and_then(|n| n.to_str());

            if pid_dir.is_some_and(|p| p.chars().all(|c| c.is_ascii_digit())) {
                let pid = match pid_dir.and_then(|p| p.parse::<u32>().ok()) {
                    Some(pid) => pid,
                    None => continue,
                };

                if excluded_pids.contains(&pid) {
                    continue;
                }

                let cmdline_path = entry_path.join("cmdline");

                if let Ok(cmdline_bytes) = std::fs::read(&cmdline_path) {
                    let cmdline = String::from_utf8_lossy(&cmdline_bytes).replace('\0', " ");
                    if cmdline.to_lowercase().contains("nails") {
                        return Ok(true);
                    }
                }
            }
        }
    }

    Ok(false)
}

pub(super) fn nails_process_matches() -> Result<Vec<ProcessMatch>> {
    let proc_path = Path::new("/proc");
    let excluded_pids = collect_ancestor_pids();
    let mut matches = Vec::new();

    if !proc_path.exists() {
        return Ok(matches);
    }

    // The inode of the running binary. A process whose `/proc/<pid>/exe`
    // resolves to the same inode is unambiguously the NAILS binary, regardless
    // of how it was invoked, so that is the strongest signal we can get.
    let own_exe_inode = exe_inode(Path::new("/proc/self/exe"));

    let Ok(entries) = std::fs::read_dir(proc_path) else {
        return Ok(matches);
    };

    for entry in entries.flatten() {
        let entry_path = entry.path();
        let Some(pid) = entry_path
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| name.chars().all(|c| c.is_ascii_digit()))
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };

        if excluded_pids.contains(&pid) {
            continue;
        }

        let Ok(cmdline_bytes) = std::fs::read(entry_path.join("cmdline")) else {
            continue;
        };
        let cmdline = String::from_utf8_lossy(&cmdline_bytes);
        let args: Vec<&str> = cmdline.split('\0').filter(|s| !s.is_empty()).collect();

        // Strong match 1: the process executable is this very binary (same
        // inode), which no unrelated command that merely mentions "nails" shares.
        let exe_matches =
            own_exe_inode.is_some() && exe_inode(&entry_path.join("exe")) == own_exe_inode;

        // Strong match 2: argv[0]'s basename is exactly `nails`.
        let argv0_is_nails = args
            .first()
            .map(|arg| Path::new(arg).file_name().and_then(|n| n.to_str()) == Some("nails"))
            .unwrap_or(false);

        if exe_matches || argv0_is_nails {
            matches.push(ProcessMatch {
                pid,
                strong: true,
                detail: if exe_matches {
                    format!("pid {pid} runs the NAILS binary")
                } else {
                    format!("pid {pid} was invoked as `nails`")
                },
            });
            continue;
        }

        // Weak match: "nails" appears somewhere on the command line. This also
        // fires on an editor or a `grep` run against a NAILS file, so it is
        // reported as information only.
        if cmdline.replace('\0', " ").to_lowercase().contains("nails") {
            matches.push(ProcessMatch {
                pid,
                strong: false,
                detail: format!("pid {pid} command line references \"nails\""),
            });
        }
    }

    Ok(matches)
}

/// The inode number of the file `exe_link` resolves to, or `None` when it cannot
/// be read (the process exited, or we lack permission to follow its `exe` link).
fn exe_inode(exe_link: &Path) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(exe_link).ok().map(|meta| meta.ino())
}

fn collect_ancestor_pids() -> HashSet<u32> {
    let mut pids = HashSet::new();
    let mut current = std::process::id();

    loop {
        pids.insert(current);
        if current <= 1 {
            break;
        }

        match read_ppid(current) {
            Some(ppid) if ppid != current => current = ppid,
            _ => break,
        }
    }

    pids
}

fn read_ppid(pid: u32) -> Option<u32> {
    let stat_path = format!("/proc/{pid}/stat");
    let content = std::fs::read_to_string(stat_path).ok()?;
    let after_comm = content.rfind(')')? + 1;
    let remainder = &content[after_comm..];
    let fields: Vec<&str> = remainder.split_whitespace().collect();

    if fields.len() >= 2 {
        fields[1].parse().ok()
    } else {
        None
    }
}
