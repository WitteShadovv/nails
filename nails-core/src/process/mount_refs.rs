// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Which mount a process's references really live on, by mount id.
//!
//! A path string cannot tell a reference *inside* an overlay from one on the
//! decoy directory the overlay is mounted over, and `st_dev` cannot either:
//! overlayfs reports the overlay's own anonymous device only for directories,
//! while a non-directory file reports the device of the layer it lives in (the
//! hidden upper or the decoy lower). A process holding only a file open on an
//! overlay therefore looked like a decoy process. The mount id does not lie: a
//! file descriptor's `mnt_id` (`/proc/<pid>/fdinfo/<n>`) is the id of the mount
//! it was opened through, and the cwd, root and memory-mapped files resolve the
//! same way when they are opened `O_PATH` through their `/proc` magic links.
//!
//! Mount ids are unique system-wide but only meaningful within the mount
//! namespace they were read from, so the ids to compare against come from
//! `/proc/self/mountinfo` and the comparison is made only for processes in the
//! same mount namespace; a process in another namespace is the caller's to
//! treat fail-safe.

use std::collections::HashSet;
use std::path::Path;

/// Parse the `mnt_id:` value of a `/proc/<pid>/fdinfo/<n>` body.
pub(crate) fn parse_fdinfo_mnt_id(content: &str) -> Option<i32> {
    content
        .lines()
        .find_map(|line| line.strip_prefix("mnt_id:"))
        .and_then(|rest| rest.trim().parse().ok())
}

/// The mount id of whatever `path` resolves to, following `/proc` magic links:
/// opened `O_PATH` (no read access, no side effects on the object, no atime
/// update) and read back from this process's own fdinfo.
pub(crate) fn path_mount_id(path: &Path) -> Option<i32> {
    use nix::fcntl::OFlag;
    use std::os::fd::AsRawFd;
    let fd = nix::fcntl::open(
        path,
        OFlag::O_PATH | OFlag::O_CLOEXEC,
        nix::sys::stat::Mode::empty(),
    )
    .ok()?;
    let fdinfo = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", fd.as_raw_fd())).ok()?;
    parse_fdinfo_mnt_id(&fdinfo)
}

/// The `start-end` address ranges of a `/proc/<pid>/maps` body whose mapping is
/// shared and writable (`rw?s`) and backed by a file — the mappings through
/// which a process can write to a file without holding a descriptor.
pub(crate) fn shared_writable_map_ranges(maps: &str) -> Vec<String> {
    maps.lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let range = fields.next()?;
            let perms = fields.next()?;
            let _offset = fields.next()?;
            let _dev = fields.next()?;
            let inode = fields.next()?;
            let perms = perms.as_bytes();
            let shared_writable = perms.len() == 4 && perms[1] == b'w' && perms[3] == b's';
            (shared_writable && inode != "0").then(|| range.to_string())
        })
        .collect()
}

/// Whether any reference of `pid` lives on one of the mounts in `mount_ids`:
/// its cwd, its root, any open file descriptor, or any shared-writable file
/// mapping. A vanished process or an unreadable entry contributes no match.
pub(crate) fn process_references_mounts(pid: u32, mount_ids: &HashSet<i32>) -> bool {
    if mount_ids.is_empty() {
        return false;
    }
    let base = format!("/proc/{pid}");
    let on_mount = |id: Option<i32>| id.is_some_and(|id| mount_ids.contains(&id));

    if ["cwd", "root"]
        .iter()
        .any(|link| on_mount(path_mount_id(Path::new(&format!("{base}/{link}")))))
    {
        return true;
    }

    if let Ok(entries) = std::fs::read_dir(format!("{base}/fdinfo")) {
        for entry in entries.flatten() {
            if let Ok(fdinfo) = std::fs::read_to_string(entry.path())
                && on_mount(parse_fdinfo_mnt_id(&fdinfo))
            {
                return true;
            }
        }
    }

    if let Ok(maps) = std::fs::read_to_string(format!("{base}/maps")) {
        for range in shared_writable_map_ranges(&maps) {
            if on_mount(path_mount_id(Path::new(&format!(
                "{base}/map_files/{range}"
            )))) {
                return true;
            }
        }
    }
    false
}

/// Whether `pid` shares this process's mount namespace, so mount ids read from
/// `/proc/self/mountinfo` are meaningful for its references. `false` when either
/// namespace link cannot be read.
pub(crate) fn same_mount_namespace(pid: u32) -> bool {
    match (
        std::fs::read_link("/proc/self/ns/mnt"),
        std::fs::read_link(format!("/proc/{pid}/ns/mnt")),
    ) {
        (Ok(own), Ok(theirs)) => own == theirs,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// The mount id of the mount that holds `path`, from this process's own
    /// mountinfo: the longest mount point that prefixes the canonical path.
    fn mount_id_holding(path: &Path) -> i32 {
        let canonical = std::fs::canonicalize(path).unwrap();
        let entries = crate::filesystem::read_mountinfo().unwrap();
        entries
            .iter()
            .filter(|entry| canonical.starts_with(&entry.mount_point))
            .max_by_key(|entry| entry.mount_point.as_os_str().len())
            .map(|entry| entry.mount_id)
            .unwrap()
    }

    #[test]
    fn fdinfo_mount_id_is_parsed() {
        assert_eq!(
            parse_fdinfo_mnt_id("pos:\t0\nflags:\t02\nmnt_id:\t42\n"),
            Some(42)
        );
        assert_eq!(parse_fdinfo_mnt_id("flags:\t02\n"), None);
        assert_eq!(parse_fdinfo_mnt_id("mnt_id:\tx\n"), None);
    }

    #[test]
    fn only_shared_writable_file_mappings_are_listed() {
        let maps = "\
7f00-7f10 rw-s 00000000 fd:01 1234 /home/u/db.sqlite-shm
7f10-7f20 r--s 00000000 fd:01 1235 /home/u/ro
7f20-7f30 rw-p 00000000 fd:01 1236 /lib/libc.so
7f30-7f40 rw-s 00000000 00:01 0 /dev/zero (deleted)
";
        assert_eq!(
            shared_writable_map_ranges(maps),
            vec!["7f00-7f10".to_string()]
        );
    }

    #[test]
    fn a_process_holding_only_a_file_open_is_found_by_mount_id() {
        // A real child process holds a file open for writing in a temp dir and
        // has its cwd elsewhere: the mount-id scan must find it through the fd,
        // whatever device the file itself reports.
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("held");
        std::fs::File::create(&file).unwrap();
        let mut child = std::process::Command::new("sh")
            .arg("-c")
            .arg("exec 3>>\"$1\"; read _")
            .arg("sh")
            .arg(&file)
            .current_dir("/")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        // Give the shell a moment to open the descriptor.
        let ids: HashSet<i32> = [mount_id_holding(dir.path())].into();
        let pid = child.id();
        let mut found = false;
        for _ in 0..100 {
            if process_references_mounts(pid, &ids) {
                found = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let unrelated: HashSet<i32> = [i32::MAX].into();
        let spared = !process_references_mounts(pid, &unrelated);
        child.stdin.take().unwrap().write_all(b"\n").unwrap();
        child.wait().unwrap();
        assert!(found, "the open file descriptor must match its mount id");
        assert!(spared, "a mount the process does not touch must not match");
    }

    #[test]
    fn the_cwd_is_resolved_by_mount_id() {
        let dir = tempfile::tempdir().unwrap();
        let mut child = std::process::Command::new("sh")
            .arg("-c")
            .arg("read _")
            .current_dir(dir.path())
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let ids: HashSet<i32> = [mount_id_holding(dir.path())].into();
        let found = process_references_mounts(child.id(), &ids);
        child.stdin.take().unwrap().write_all(b"\n").unwrap();
        child.wait().unwrap();
        assert!(found);
        assert!(same_mount_namespace(std::process::id()));
    }
}
