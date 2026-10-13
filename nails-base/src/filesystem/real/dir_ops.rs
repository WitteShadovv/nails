// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Directory listing, enumeration, copy, size, and submount operations.

use super::noatime::{OpenKind, open_noatime, read_dir_noatime};
use crate::{NailsError, Result};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub(super) fn list_directory(dir: &Path) -> Result<Vec<PathBuf>> {
    let entries = read_dir_noatime(dir).map_err(|e| {
        NailsError::io(
            dir,
            std::io::Error::new(
                e.kind(),
                format!("Failed to read directory {}: {}", dir.display(), e),
            ),
        )
    })?;

    Ok(entries.into_iter().map(|e| dir.join(e.name)).collect())
}

pub(super) fn modified_time(path: &Path) -> Result<chrono::DateTime<chrono::Utc>> {
    let metadata = std::fs::metadata(path).map_err(|e| {
        NailsError::io(
            path,
            std::io::Error::new(
                e.kind(),
                format!("Failed to get metadata for {}: {}", path.display(), e),
            ),
        )
    })?;

    let modified = metadata.modified().map_err(|e| {
        NailsError::io(
            path,
            std::io::Error::new(
                e.kind(),
                format!(
                    "Failed to get modification time for {}: {}",
                    path.display(),
                    e
                ),
            ),
        )
    })?;

    let datetime: chrono::DateTime<chrono::Utc> = modified.into();
    Ok(datetime)
}

/// Copy the contents of `src` into `dst`, atime-safe and in-process.
///
/// This replaces the former `cp -a` child process. Like `cp -a` it keeps modes,
/// ownership, timestamps, symlinks, hard links, special files and extended
/// attributes, but unlike `cp -a` it opens every source for reading with
/// `O_NOATIME`, so snapshotting a decoy tree (the vfat `/boot` pivot) never
/// updates the lower files' access times — a forensic tell `cp` would leave.
///
/// `O_NOATIME` requires owning the file (or `CAP_FOWNER`); for a source the
/// caller does not own the open falls back to a plain read, which is still
/// correct, only not atime-preserving for that one file. Ownership, xattrs and
/// timestamp restoration on the destination are best-effort: a vfat lower (the
/// only filesystem that takes this path) carries none of them, and a tmpfs that
/// rejects a `user.*` xattr must not fail the snapshot.
pub(super) fn copy_tree(src: &Path, dst: &Path) -> Result<()> {
    let mut hard_links: HashMap<(u64, u64), PathBuf> = HashMap::new();
    copy_dir_contents(src, dst, &mut hard_links).map_err(|err| {
        NailsError::io(
            src,
            io::Error::new(
                err.kind(),
                format!(
                    "atime-safe copy of {}/. into {} failed: {}",
                    src.display(),
                    dst.display(),
                    err
                ),
            ),
        )
    })
}

/// Recursively copy the entries of `src_dir` into the already-existing `dst_dir`.
fn copy_dir_contents(
    src_dir: &Path,
    dst_dir: &Path,
    hard_links: &mut HashMap<(u64, u64), PathBuf>,
) -> io::Result<()> {
    for entry in read_dir_noatime(src_dir)? {
        let name = entry.name;
        let src = src_dir.join(&name);
        let dst = dst_dir.join(&name);
        let meta = std::fs::symlink_metadata(&src)?;
        let file_type = meta.file_type();

        if file_type.is_dir() {
            match std::fs::create_dir(&dst) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
            copy_dir_contents(&src, &dst, hard_links)?;
            // Apply the directory's own metadata AFTER its children exist, so
            // creating them does not bump the mtime we are about to restore.
            apply_metadata(&src, &dst, &meta, false);
        } else if file_type.is_symlink() {
            let target = std::fs::read_link(&src)?;
            std::os::unix::fs::symlink(&target, &dst)?;
            apply_metadata(&src, &dst, &meta, true);
        } else if file_type.is_file() {
            // A file reached through several hard links is copied once and then
            // hard-linked, so the destination preserves the link structure.
            let key = (meta.dev(), meta.ino());
            if meta.nlink() > 1
                && let Some(first) = hard_links.get(&key)
            {
                std::fs::hard_link(first, &dst)?;
                continue;
            }
            copy_file_noatime(&src, &dst)?;
            apply_metadata(&src, &dst, &meta, false);
            if meta.nlink() > 1 {
                hard_links.insert(key, dst);
            }
        } else {
            // FIFO, socket or device node: recreate it with mknod, best-effort.
            copy_special_file(&dst, &meta, &file_type);
            apply_metadata(&src, &dst, &meta, false);
        }
    }
    Ok(())
}

/// Copy one regular file's contents, reading the source with `O_NOATIME`.
fn copy_file_noatime(src: &Path, dst: &Path) -> io::Result<()> {
    let fd = open_noatime(src, OpenKind::FileNoFollow)?;
    let mut reader = std::fs::File::from(fd);
    let mut writer = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dst)?;
    io::copy(&mut reader, &mut writer)?;
    Ok(())
}

/// Recreate a FIFO, socket or device node. Best-effort: a snapshot target that
/// cannot hold one (or a caller without privilege for a device node) is skipped
/// rather than failing the whole snapshot.
fn copy_special_file(dst: &Path, meta: &std::fs::Metadata, file_type: &std::fs::FileType) {
    use nix::sys::stat::{Mode, SFlag, mknod};

    let kind = if file_type.is_fifo() {
        SFlag::S_IFIFO
    } else if file_type.is_socket() {
        SFlag::S_IFSOCK
    } else if file_type.is_char_device() {
        SFlag::S_IFCHR
    } else if file_type.is_block_device() {
        SFlag::S_IFBLK
    } else {
        return;
    };
    let perm = Mode::from_bits_truncate(meta.mode() & 0o7777);
    let _ = mknod(dst, kind, perm, meta.rdev());
}

/// Apply mode, ownership, extended attributes and timestamps from `src`'s
/// metadata onto `dst`. Ownership, xattrs and timestamps are best-effort; the
/// mode is only applied to non-symlinks (a symlink's own mode is fixed). The
/// timestamps are set last so no earlier step overwrites the restored atime.
fn apply_metadata(src: &Path, dst: &Path, meta: &std::fs::Metadata, is_symlink: bool) {
    if !is_symlink {
        let _ =
            std::fs::set_permissions(dst, std::fs::Permissions::from_mode(meta.mode() & 0o7777));
    }
    restore_ownership(dst, meta, is_symlink);
    copy_xattrs(src, dst);
    restore_times(dst, meta, is_symlink);
}

fn restore_ownership(dst: &Path, meta: &std::fs::Metadata, is_symlink: bool) {
    use nix::fcntl::{AT_FDCWD, AtFlags};
    use nix::unistd::{Gid, Uid, fchownat};

    let flag = if is_symlink {
        AtFlags::AT_SYMLINK_NOFOLLOW
    } else {
        AtFlags::empty()
    };
    let _ = fchownat(
        AT_FDCWD,
        dst,
        Some(Uid::from_raw(meta.uid())),
        Some(Gid::from_raw(meta.gid())),
        flag,
    );
}

fn restore_times(dst: &Path, meta: &std::fs::Metadata, is_symlink: bool) {
    use nix::fcntl::AT_FDCWD;
    use nix::sys::stat::{UtimensatFlags, utimensat};
    use nix::sys::time::TimeSpec;

    let atime = TimeSpec::new(meta.atime(), meta.atime_nsec() as _);
    let mtime = TimeSpec::new(meta.mtime(), meta.mtime_nsec() as _);
    let flag = if is_symlink {
        UtimensatFlags::NoFollowSymlink
    } else {
        UtimensatFlags::FollowSymlink
    };
    let _ = utimensat(AT_FDCWD, dst, &atime, &mtime, flag);
}

/// Copy every extended attribute from `src` to `dst`, following no symlinks.
/// Best-effort: a filesystem without xattr support or one that rejects a name is
/// silently skipped.
fn copy_xattrs(src: &Path, dst: &Path) {
    // A zero-length buffer turns the list/get calls into a size query.
    let mut empty: [u8; 0] = [];
    let Ok(size) = rustix::fs::llistxattr(src, &mut empty[..]) else {
        return;
    };
    if size == 0 {
        return;
    }
    let mut names = vec![0u8; size];
    let Ok(written) = rustix::fs::llistxattr(src, &mut names[..]) else {
        return;
    };
    names.truncate(written);

    for name in names.split(|b| *b == 0).filter(|n| !n.is_empty()) {
        let name = OsStr::from_bytes(name);
        let Ok(vsize) = rustix::fs::lgetxattr(src, name, &mut empty[..]) else {
            continue;
        };
        let mut value = vec![0u8; vsize];
        let Ok(vwritten) = rustix::fs::lgetxattr(src, name, &mut value[..]) else {
            continue;
        };
        value.truncate(vwritten);
        let _ = rustix::fs::lsetxattr(dst, name, &value, rustix::fs::XattrFlags::empty());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    use std::fs;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn copy_tree_errors_when_the_source_is_missing() {
        let temp_dir = tempfile::tempdir().unwrap();
        let dst = temp_dir.path().join("dst");
        fs::create_dir_all(&dst).unwrap();

        let err = copy_tree(&temp_dir.path().join("nope"), &dst).unwrap_err();
        assert!(matches!(err, NailsError::IoError { .. }), "got {err:?}");
    }

    #[test]
    fn copy_tree_copies_nested_content_and_directory_metadata() {
        let temp_dir = tempfile::tempdir().unwrap();
        let src = temp_dir.path().join("src");
        let dst = temp_dir.path().join("dst");
        fs::create_dir_all(src.join("sub")).unwrap();
        fs::create_dir_all(&dst).unwrap();
        fs::write(src.join("sub/deep.txt"), "deep").unwrap();
        fs::set_permissions(src.join("sub"), fs::Permissions::from_mode(0o750)).unwrap();

        copy_tree(&src, &dst).unwrap();

        assert_eq!(
            fs::read_to_string(dst.join("sub/deep.txt")).unwrap(),
            "deep"
        );
        assert_eq!(
            fs::symlink_metadata(dst.join("sub"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o750
        );
    }

    #[test]
    fn copy_tree_does_not_update_the_source_access_time() {
        // tmpfs is usually relatime, which only bumps atime when it is older than
        // mtime; set atime well before mtime so a non-O_NOATIME read WOULD update
        // it, making this a real regression guard rather than a relatime no-op.
        let temp_dir = tempfile::tempdir().unwrap();
        let src = temp_dir.path().join("src");
        let dst = temp_dir.path().join("dst");
        fs::create_dir_all(&src).unwrap();
        fs::create_dir_all(&dst).unwrap();
        let file = src.join("secret.txt");
        fs::write(&file, "watch my atime").unwrap();

        let old_atime = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000);
        let mtime = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(2_000_000);
        let handle = fs::File::options().write(true).open(&file).unwrap();
        handle
            .set_times(
                fs::FileTimes::new()
                    .set_accessed(old_atime)
                    .set_modified(mtime),
            )
            .unwrap();
        drop(handle);
        let before = fs::metadata(&file).unwrap().accessed().unwrap();

        copy_tree(&src, &dst).unwrap();

        let after = fs::metadata(&file).unwrap().accessed().unwrap();
        assert_eq!(
            before, after,
            "O_NOATIME read must leave the source access time untouched"
        );
        // And the content still copied.
        assert_eq!(
            fs::read_to_string(dst.join("secret.txt")).unwrap(),
            "watch my atime"
        );
    }

    #[test]
    fn copy_tree_preserves_extended_attributes_when_supported() {
        use rustix::fs::XattrFlags;

        let temp_dir = tempfile::tempdir().unwrap();
        let src = temp_dir.path().join("src");
        let dst = temp_dir.path().join("dst");
        fs::create_dir_all(&src).unwrap();
        fs::create_dir_all(&dst).unwrap();
        let file = src.join("a.txt");
        fs::write(&file, "a").unwrap();

        // Some tmpfs configurations reject user.* xattrs; self-skip if so.
        if rustix::fs::lsetxattr(&file, "user.nails.test", b"v", XattrFlags::empty()).is_err() {
            return;
        }

        copy_tree(&src, &dst).unwrap();

        let mut buf = [0u8; 16];
        let n = rustix::fs::lgetxattr(dst.join("a.txt"), "user.nails.test", &mut buf[..]).unwrap();
        assert_eq!(&buf[..n], b"v");
    }

    #[test]
    fn copy_tree_preserves_symlinks_modes_timestamps_and_hard_links() {
        let temp_dir = tempfile::tempdir().unwrap();
        let src = temp_dir.path().join("src");
        let dst = temp_dir.path().join("dst");
        fs::create_dir_all(&src).unwrap();
        fs::create_dir_all(&dst).unwrap();
        let file = src.join("a.txt");
        fs::write(&file, "a").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o640)).unwrap();
        let mtime = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000);
        fs::File::options()
            .write(true)
            .open(&file)
            .unwrap()
            .set_modified(mtime)
            .unwrap();
        fs::hard_link(&file, src.join("b.txt")).unwrap();
        symlink("a.txt", src.join("link")).unwrap();

        copy_tree(&src, &dst).unwrap();

        let copied = fs::symlink_metadata(dst.join("a.txt")).unwrap();
        assert_eq!(copied.permissions().mode() & 0o7777, 0o640);
        assert_eq!(copied.modified().unwrap(), mtime);
        // The destination atime/mtime are restored from the source (cp -a parity).
        assert_eq!(
            copied.accessed().unwrap(),
            fs::symlink_metadata(&file).unwrap().accessed().unwrap()
        );
        assert_eq!(
            fs::symlink_metadata(dst.join("b.txt")).unwrap().ino(),
            copied.ino()
        );
        assert!(fs::symlink_metadata(dst.join("link")).unwrap().is_symlink());
        assert_eq!(fs::read_link(dst.join("link")).unwrap(), Path::new("a.txt"));
    }

    #[test]
    fn copy_tree_accepts_source_paths_that_are_not_utf8() {
        let temp_dir = tempfile::tempdir().unwrap();
        let src = temp_dir.path().join(OsStr::from_bytes(b"src-\xff"));
        let dst = temp_dir.path().join("dst");
        fs::create_dir_all(&src).unwrap();
        fs::create_dir_all(&dst).unwrap();
        fs::write(src.join("a.txt"), "a").unwrap();

        copy_tree(&src, &dst).unwrap();

        assert_eq!(fs::read_to_string(dst.join("a.txt")).unwrap(), "a");
    }
}
