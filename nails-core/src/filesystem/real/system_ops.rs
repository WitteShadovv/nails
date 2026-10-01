//! System operations: swap detection and NAILS process detection.

use crate::Result;
use std::collections::HashSet;
use std::path::Path;

pub(super) fn swap_is_enabled() -> Result<bool> {
    let swaps = std::fs::read_to_string("/proc/swaps")?;
    Ok(swaps.lines().count() > 1)
}

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
