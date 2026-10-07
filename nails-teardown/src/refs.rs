// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Which processes can still write through a NAILS mount, judged by mount id.
//!
//! A path string cannot tell a reference inside an overlay from one on the decoy
//! directory beneath it, and `st_dev` cannot either (an overlay's regular files
//! report their layer's device). The mount id does not lie: an fd's `mnt_id` in
//! `/proc/<pid>/fdinfo/<n>` is the mount it was opened through, and the cwd,
//! root and mapped files resolve the same way when their `/proc` magic links
//! are opened `O_PATH` and read back from this process's own fdinfo.
//!
//! None of this calls into the overlay or the hidden filesystem: an `O_PATH`
//! open of a magic link takes the path the kernel already holds, and fdinfo is a
//! procfs read. A dead hidden device therefore cannot block the scan, unlike a
//! `stat()` through `/proc/<pid>/fd/<n>`.

use std::collections::HashSet;
use std::path::Path;

/// `O_ACCMODE` and the flags that make an fd a write path.
const O_ACCMODE: u32 = 0o3;
const O_APPEND: u32 = 0o2000;
const O_DIRECTORY: u32 = 0o200000;
const O_PATH: u32 = 0o10000000;

/// The `mnt_id:` and `flags:` (octal) of a `/proc/<pid>/fdinfo/<n>` body.
pub fn parse_fdinfo(content: &str) -> (Option<i32>, Option<u32>) {
    let mut mnt_id = None;
    let mut flags = None;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("mnt_id:") {
            mnt_id = rest.trim().parse().ok();
        } else if let Some(rest) = line.strip_prefix("flags:") {
            flags = u32::from_str_radix(rest.trim(), 8).ok();
        }
    }
    (mnt_id, flags)
}

/// Whether an fd with these open flags can write: opened for writing or
/// appending, or a directory (or `O_PATH`) handle through which `openat` can
/// create files.
pub fn fd_flags_can_write(flags: u32) -> bool {
    flags & O_ACCMODE != 0 || flags & (O_APPEND | O_DIRECTORY | O_PATH) != 0
}

/// The mount id of whatever `path` resolves to, following `/proc` magic links:
/// opened `O_PATH` (no access to the object, no atime update) and read back from
/// this process's own fdinfo.
pub fn path_mount_id(path: &Path) -> Option<i32> {
    use rustix::fs::{Mode, OFlags, open};
    use std::os::fd::AsRawFd;
    let fd = open(path, OFlags::PATH | OFlags::CLOEXEC, Mode::empty()).ok()?;
    let fdinfo = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", fd.as_raw_fd())).ok()?;
    parse_fdinfo(&fdinfo).0
}

/// The address ranges of a `/proc/<pid>/maps` body whose mapping is shared,
/// writable and file-backed: a way to write a file without holding an fd.
pub fn shared_writable_map_ranges(maps: &str) -> Vec<String> {
    maps.lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let range = fields.next()?;
            let perms = fields.next()?.as_bytes();
            let _offset = fields.next()?;
            let _dev = fields.next()?;
            let inode = fields.next()?;
            (perms.len() == 4 && perms[1] == b'w' && perms[3] == b's' && inode != "0")
                .then(|| range.to_string())
        })
        .collect()
}

/// Whether `pid` can write through one of the mounts in `mount_ids`: its cwd or
/// root is on one, an fd that can write is open on one, or a shared writable
/// mapping is backed by one. A read-only consumer (a file open for reading, an
/// executable mapped from the overlay) is not, as before this crate existed:
/// it cannot dirty the decoy after the detach.
pub fn writes_through(pid: u32, mount_ids: &HashSet<i32>) -> bool {
    if mount_ids.is_empty() {
        return false;
    }
    let on = |id: Option<i32>| id.is_some_and(|id| mount_ids.contains(&id));
    let base = format!("/proc/{pid}");
    if ["cwd", "root"]
        .iter()
        .any(|link| on(path_mount_id(Path::new(&format!("{base}/{link}")))))
    {
        return true;
    }
    if let Ok(entries) = std::fs::read_dir(format!("{base}/fdinfo")) {
        for entry in entries.flatten() {
            if let Ok(fdinfo) = std::fs::read_to_string(entry.path()) {
                let (id, flags) = parse_fdinfo(&fdinfo);
                if on(id) && flags.is_some_and(fd_flags_can_write) {
                    return true;
                }
            }
        }
    }
    if let Ok(maps) = std::fs::read_to_string(format!("{base}/maps")) {
        for range in shared_writable_map_ranges(&maps) {
            if on(path_mount_id(Path::new(&format!(
                "{base}/map_files/{range}"
            )))) {
                return true;
            }
        }
    }
    false
}

/// The mount namespace of `pid`, by inode of its `ns/mnt` link target.
pub fn mount_namespace_of(pid: u32) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/ns/mnt"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    #[test]
    fn fdinfo_mount_id_and_flags_are_parsed() {
        let (id, flags) = parse_fdinfo("pos:\t0\nflags:\t02100001\nmnt_id:\t42\nino:\t7\n");
        assert_eq!(id, Some(42));
        assert!(fd_flags_can_write(flags.unwrap()));
        let (_, read_only) = parse_fdinfo("pos:\t0\nflags:\t02100000\nmnt_id:\t42\n");
        assert!(!fd_flags_can_write(read_only.unwrap()));
        let (_, dir) = parse_fdinfo("flags:\t02200000\nmnt_id:\t42\n");
        assert!(fd_flags_can_write(dir.unwrap()));
    }

    #[test]
    fn only_shared_writable_file_mappings_are_write_paths() {
        let maps = "\
7f00-7f10 rw-s 00000000 08:01 1234 /tmp/shm
7f10-7f20 rw-p 00000000 08:01 1235 /tmp/private
7f20-7f30 r--s 00000000 08:01 1236 /tmp/ro
7f30-7f40 rw-s 00000000 00:00 0 [anon]
";
        assert_eq!(shared_writable_map_ranges(maps), vec!["7f00-7f10"]);
    }

    /// The mount id of the mount holding `path`, from this process's mountinfo.
    fn mount_id_holding(path: &Path) -> i32 {
        let canonical = std::fs::canonicalize(path).unwrap();
        crate::mountinfo::read_mountinfo()
            .unwrap()
            .into_iter()
            .filter(|e| canonical.starts_with(&e.mount_point))
            .max_by_key(|e| e.mount_point.as_os_str().len())
            .unwrap()
            .mount_id
    }

    #[test]
    fn a_child_writing_a_file_is_found_by_mount_id_and_a_reader_is_not() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        std::fs::File::create(&file)
            .unwrap()
            .write_all(b"x")
            .unwrap();
        let ids: HashSet<i32> = [mount_id_holding(dir.path())].into();

        let spawn = |stdin: std::fs::File| {
            // cwd and root elsewhere (procfs is its own mount), no other fds.
            std::process::Command::new("sleep")
                .arg("30")
                .current_dir("/proc")
                .stdin(stdin)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap()
        };
        let writer = std::fs::OpenOptions::new()
            .append(true)
            .custom_flags(0)
            .open(&file)
            .unwrap();
        let mut child = spawn(writer);
        assert!(writes_through(child.id(), &ids));
        let _ = child.kill();
        let _ = child.wait();

        let mut child = spawn(std::fs::File::open(&file).unwrap());
        if mount_id_holding(Path::new("/")) != mount_id_holding(dir.path()) {
            assert!(!writes_through(child.id(), &ids));
        }
        let _ = child.kill();
        let _ = child.wait();
    }
}
