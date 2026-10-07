// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Reads that leave access times alone.
//!
//! Under the default `relatime` mount option the kernel still updates a file's or
//! directory's atime when it is older than its mtime or more than a day old, so
//! every read NAILS makes of the decoy would stamp the inode with the time of the
//! hidden session. Each read here opens with `O_NOATIME` instead, falling back to
//! a plain open when the kernel refuses the flag because the caller neither owns
//! the inode nor holds `CAP_FOWNER` (`EPERM`). Root always holds `CAP_FOWNER`, so
//! the fallback only applies to unprivileged runs, which cannot avoid the update.

use std::ffi::OsString;
use std::io::{self, Read};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// How [`open_noatime`] treats the final path component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OpenKind {
    /// A directory (`O_DIRECTORY`), following a symlink to it.
    Directory,
    /// A file, following a symlink to it (the plain `open(2)` behaviour).
    File,
    /// A file that must not be a symlink (`O_NOFOLLOW`), so a race cannot
    /// redirect the read.
    FileNoFollow,
}

/// Open `path` read-only with `O_NOATIME`, retrying without it on `EPERM`.
pub(crate) fn open_noatime(path: &Path, kind: OpenKind) -> io::Result<OwnedFd> {
    use rustix::fs::{Mode, OFlags, open};

    let mut base = OFlags::RDONLY | OFlags::CLOEXEC;
    match kind {
        OpenKind::Directory => base |= OFlags::DIRECTORY,
        OpenKind::File => {}
        OpenKind::FileNoFollow => base |= OFlags::NOFOLLOW,
    }

    match open(path, base | OFlags::NOATIME, Mode::empty()) {
        Ok(fd) => Ok(fd),
        // O_NOATIME needs file ownership or CAP_FOWNER; retry without it.
        Err(rustix::io::Errno::PERM) => open(path, base, Mode::empty()).map_err(io::Error::from),
        Err(e) => Err(io::Error::from(e)),
    }
}

/// Read a whole file as UTF-8 without updating its access time.
pub(super) fn read_to_string_noatime(path: &Path) -> io::Result<String> {
    let mut file = std::fs::File::from(open_noatime(path, OpenKind::File)?);
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    Ok(content)
}

/// One directory entry from [`read_dir_noatime`].
#[derive(Debug, Clone)]
pub(crate) struct NoatimeEntry {
    /// The entry's name within the directory.
    pub name: OsString,
    /// The entry type from `d_type`; `None` when the filesystem does not report
    /// it, in which case the caller falls back to `lstat`.
    pub file_type: Option<EntryType>,
}

/// The `d_type` of a directory entry, reduced to what callers branch on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EntryType {
    /// A directory.
    Directory,
    /// A regular file.
    File,
    /// A symbolic link.
    Symlink,
    /// A FIFO, socket or device node.
    Other,
}

/// List `dir` without updating its access time, skipping `.` and `..`.
pub(crate) fn read_dir_noatime(dir: &Path) -> io::Result<Vec<NoatimeEntry>> {
    use rustix::fs::FileType;

    let fd = open_noatime(dir, OpenKind::Directory)?;
    let dir_iter = rustix::fs::Dir::new(fd).map_err(io::Error::from)?;
    let mut entries = Vec::new();
    for entry in dir_iter {
        let entry = entry.map_err(io::Error::from)?;
        let raw = entry.file_name().to_bytes();
        if raw == b"." || raw == b".." {
            continue;
        }
        let file_type = match entry.file_type() {
            FileType::Directory => Some(EntryType::Directory),
            FileType::RegularFile => Some(EntryType::File),
            FileType::Symlink => Some(EntryType::Symlink),
            FileType::Unknown => None,
            _ => Some(EntryType::Other),
        };
        entries.push(NoatimeEntry {
            name: std::ffi::OsStr::from_bytes(raw).to_os_string(),
            file_type,
        });
    }
    Ok(entries)
}

impl NoatimeEntry {
    /// The entry type, from `d_type` or, when the filesystem left it unknown,
    /// from an `lstat` of `parent/name` (which never touches the atime).
    pub(crate) fn resolved_type(&self, parent: &Path) -> io::Result<EntryType> {
        if let Some(file_type) = self.file_type {
            return Ok(file_type);
        }
        let file_type = std::fs::symlink_metadata(parent.join(&self.name))?.file_type();
        Ok(if file_type.is_dir() {
            EntryType::Directory
        } else if file_type.is_file() {
            EntryType::File
        } else if file_type.is_symlink() {
            EntryType::Symlink
        } else {
            EntryType::Other
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;
    use std::time::{Duration, SystemTime};

    /// Backdate `path`'s atime well behind its mtime, so `relatime` would update
    /// it on the next read.
    fn backdate_atime(path: &Path) {
        let old = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
        let file = std::fs::File::open(path).unwrap();
        file.set_times(std::fs::FileTimes::new().set_accessed(old))
            .unwrap();
    }

    fn atime(path: &Path) -> (i64, i64) {
        let meta = std::fs::metadata(path).unwrap();
        (meta.atime(), meta.atime_nsec())
    }

    /// Whether the filesystem holding `dir` records atime updates at all; under
    /// `noatime` the comparison below would prove nothing.
    fn records_atime(dir: &Path) -> bool {
        let probe = dir.join("probe");
        std::fs::write(&probe, b"probe").unwrap();
        backdate_atime(&probe);
        let before = atime(&probe);
        let _ = std::fs::read(&probe).unwrap();
        atime(&probe) != before
    }

    #[test]
    fn reads_and_listings_leave_atime_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        if !records_atime(dir.path()) {
            eprintln!("skipping: the temp filesystem does not record atime updates");
            return;
        }

        let file = dir.path().join("decoy.txt");
        std::fs::write(&file, b"decoy content").unwrap();
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("inner"), b"x").unwrap();
        backdate_atime(&file);
        backdate_atime(&sub);
        let (file_before, sub_before) = (atime(&file), atime(&sub));

        assert_eq!(read_to_string_noatime(&file).unwrap(), "decoy content");
        let names: Vec<_> = read_dir_noatime(&sub)
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(names, vec![OsString::from("inner")]);

        assert_eq!(atime(&file), file_before, "file atime must not change");
        assert_eq!(atime(&sub), sub_before, "directory atime must not change");
    }

    #[test]
    fn real_filesystem_reads_leave_atime_unchanged() {
        use crate::{Filesystem, RealFilesystem};

        let dir = tempfile::tempdir().unwrap();
        if !records_atime(dir.path()) {
            eprintln!("skipping: the temp filesystem does not record atime updates");
            return;
        }
        let tree = dir.path().join("tree");
        std::fs::create_dir(&tree).unwrap();
        let file = tree.join("os-release");
        std::fs::write(&file, b"ID=decoy\n").unwrap();
        backdate_atime(&file);
        backdate_atime(&tree);
        let (file_before, tree_before) = (atime(&file), atime(&tree));

        let fs = RealFilesystem;
        assert_eq!(fs.read_file_content(&file).unwrap(), "ID=decoy\n");
        assert_eq!(fs.list_directory(&tree).unwrap(), vec![file.clone()]);
        assert_eq!(
            fs.scan_files_with_pattern(&tree, "release")
                .unwrap()
                .matches,
            vec![file.clone()]
        );

        assert_eq!(atime(&file), file_before, "file atime must not change");
        assert_eq!(atime(&tree), tree_before, "directory atime must not change");
    }

    #[test]
    fn a_symlinked_file_is_followed_unless_nofollow() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::write(&target, b"via link").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        assert_eq!(read_to_string_noatime(&link).unwrap(), "via link");
        assert!(open_noatime(&link, OpenKind::FileNoFollow).is_err());
    }

    #[test]
    fn listing_reports_entry_types() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("d")).unwrap();
        std::fs::write(dir.path().join("f"), b"").unwrap();
        std::os::unix::fs::symlink("f", dir.path().join("l")).unwrap();

        let mut found: Vec<(String, EntryType)> = read_dir_noatime(dir.path())
            .unwrap()
            .into_iter()
            .map(|e| {
                let kind = e.resolved_type(dir.path()).unwrap();
                (e.name.to_string_lossy().into_owned(), kind)
            })
            .collect();
        found.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            found,
            vec![
                ("d".to_string(), EntryType::Directory),
                ("f".to_string(), EntryType::File),
                ("l".to_string(), EntryType::Symlink),
            ]
        );
    }

    #[test]
    fn a_missing_path_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing");
        assert_eq!(
            read_to_string_noatime(&missing).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            read_dir_noatime(&missing).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }
}
