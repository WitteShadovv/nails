//! File and path operations for RealFilesystem.

use super::RealFilesystem;
use crate::filesystem::{DiskUsage, Filesystem};
use crate::target_user::TargetUser;
use crate::{NailsError, Result};
use std::path::{Path, PathBuf};

pub(super) fn path_exists(path: &Path) -> Result<bool> {
    Ok(path.exists())
}

pub(super) fn is_directory(path: &Path) -> Result<bool> {
    Ok(path.is_dir())
}

pub(super) fn device_id(path: &Path) -> Result<u64> {
    use std::os::unix::fs::MetadataExt;
    // `metadata` follows symlinks, which is what we want: the attach gate asks
    // about the filesystem the path resolves to, not about a link inode.
    std::fs::metadata(path)
        .map(|meta| meta.dev())
        .map_err(NailsError::IoError)
}

pub(super) fn is_symlink(path: &Path) -> Result<bool> {
    Ok(path.is_symlink())
}

pub(super) fn supports_symlinks(dir: &Path) -> Result<bool> {
    let probe = dir.join(".nails_symlink_probe");
    let _ = std::fs::remove_file(&probe);
    match std::os::unix::fs::symlink(&probe, &probe) {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe);
            Ok(true)
        }
        Err(e) => {
            let _ = std::fs::remove_file(&probe);
            match e.raw_os_error() {
                Some(1) | Some(95) => Ok(false),
                _ => Err(NailsError::IoError(e)),
            }
        }
    }
}

pub(super) fn create_symlink(target: &Path, link: &Path) -> Result<()> {
    if link.is_symlink() {
        let existing_target = std::fs::read_link(link).map_err(NailsError::IoError)?;
        if existing_target == target {
            return Ok(());
        }
        return Err(NailsError::IoError(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "Symlink at {} already exists pointing to a different target",
                link.display()
            ),
        )));
    }
    if link.exists() {
        return Err(NailsError::IoError(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!("Path already exists (not a symlink) at {}", link.display()),
        )));
    }
    std::os::unix::fs::symlink(target, link).map_err(NailsError::IoError)
}

pub(super) fn disk_usage(path: &Path) -> Result<DiskUsage> {
    let stat = nix::sys::statvfs::statvfs(path)
        .map_err(|e| NailsError::IoError(std::io::Error::other(e.to_string())))?;
    let fragment_size = stat.fragment_size();
    Ok(DiskUsage {
        total: stat.blocks() * fragment_size,
        available: stat.blocks_available() * fragment_size,
    })
}

pub(super) fn create_directory(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)?;
    Ok(())
}

pub(super) fn set_permissions(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

pub(super) fn get_permissions(path: &Path) -> Result<u32> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)?.permissions().mode();
    Ok(mode & 0o7777)
}

pub(super) fn is_readable(path: &Path) -> Result<bool> {
    Ok(std::fs::File::open(path).is_ok())
}

pub(super) fn is_writable(path: &Path) -> Result<bool> {
    if path.is_dir() {
        let test_path = path.join(".nails_write_test");
        match std::fs::File::create(&test_path) {
            Ok(_) => {
                std::fs::remove_file(&test_path)?;
                Ok(true)
            }
            Err(_) => Ok(false),
        }
    } else {
        Ok(std::fs::OpenOptions::new().append(true).open(path).is_ok())
    }
}

pub(super) fn read_file_content(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).map_err(|e| {
        NailsError::IoError(std::io::Error::new(
            e.kind(),
            format!("Failed to read file {}: {}", path.display(), e),
        ))
    })
}

pub(super) fn write_file_content(path: &Path, content: &str) -> Result<()> {
    use std::io::Write;

    let temp_path = path.with_extension("tmp");

    let mut temp_file = std::fs::File::create(&temp_path).map_err(|e| {
        NailsError::IoError(std::io::Error::new(
            e.kind(),
            format!("Failed to create temp file {}: {}", temp_path.display(), e),
        ))
    })?;

    temp_file.write_all(content.as_bytes()).map_err(|e| {
        NailsError::IoError(std::io::Error::new(
            e.kind(),
            format!(
                "Failed to write to temp file {}: {}",
                temp_path.display(),
                e
            ),
        ))
    })?;

    temp_file.sync_all().map_err(|e| {
        NailsError::IoError(std::io::Error::new(
            e.kind(),
            format!("Failed to sync temp file {}: {}", temp_path.display(), e),
        ))
    })?;

    std::fs::rename(&temp_path, path).map_err(|e| {
        NailsError::IoError(std::io::Error::new(
            e.kind(),
            format!(
                "Failed to rename {} to {}: {}",
                temp_path.display(),
                path.display(),
                e
            ),
        ))
    })?;

    Ok(())
}

/// Symlink-safe, correctly-owned write of a file in a user-owned home path.
///
/// See [`crate::filesystem::Filesystem::write_user_file`] for the contract. The
/// implementation closes CWE-59 at the point of the open rather than after it:
/// the destination and every component of its parent chain are resolved with
/// symlink resolution disabled, the payload is written to a uniquely named temp
/// created `O_CREAT | O_EXCL | O_NOFOLLOW` relative to the parent's directory fd,
/// and the temp is renamed over the destination. There is no predictable
/// sibling name for an attacker to pre-plant, and the rename replaces a symlink
/// sitting at the destination name instead of following it.
pub(super) fn write_user_file(
    path: &Path,
    content: &str,
    user: &TargetUser,
    default_mode: u32,
) -> Result<()> {
    use nix::fcntl::{AtFlags, OFlag, OpenHow, ResolveFlag, openat2, renameat};
    use nix::sys::stat::{Mode, fchmod, fstatat};
    use nix::unistd::{Gid, Uid, UnlinkatFlags, fchown, unlinkat};
    use std::io::Write;

    let parent = path.parent().ok_or_else(|| {
        NailsError::IoError(std::io::Error::other(format!(
            "Refusing to write user file with no parent directory: {}",
            path.display()
        )))
    })?;
    let file_name = path.file_name().ok_or_else(|| {
        NailsError::IoError(std::io::Error::other(format!(
            "Refusing to write user file with no file name: {}",
            path.display()
        )))
    })?;

    // Ensure the parent chain exists and every directory NAILS creates is owned
    // by the target user with private (0700) permissions.
    create_user_dir_all(parent, user)?;

    // Anchor every subsequent operation at a directory fd whose path resolved
    // without traversing any symlink. After this open the parent cannot be
    // swapped out from under the write.
    let dir_fd = open_dir_no_symlinks(parent)?;

    // Preserve an existing file's owner and mode; a new file takes the target
    // user's numeric ids and the caller's default mode.
    let (uid, gid, mode) = match fstatat(&dir_fd, file_name, AtFlags::AT_SYMLINK_NOFOLLOW) {
        Ok(st) => (st.st_uid, st.st_gid, st.st_mode & 0o7777),
        Err(nix::errno::Errno::ENOENT) => (user.uid, user.gid, default_mode & 0o7777),
        Err(e) => {
            return Err(NailsError::IoError(std::io::Error::other(format!(
                "Failed to stat {} before writing: {}",
                path.display(),
                e
            ))));
        }
    };

    let create_how = OpenHow::new()
        .flags(
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        )
        .mode(Mode::from_bits_truncate(mode))
        .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS | ResolveFlag::RESOLVE_BENEATH);

    // Create the temp under a unique name beneath the parent dir fd.
    let mut temp_name = String::new();
    let mut last_err: Option<nix::errno::Errno> = None;
    let mut temp_fd = None;
    for _ in 0..8 {
        let candidate = unique_temp_name();
        match openat2(&dir_fd, candidate.as_str(), create_how) {
            Ok(fd) => {
                temp_name = candidate;
                temp_fd = Some(fd);
                break;
            }
            Err(nix::errno::Errno::EEXIST) => {
                last_err = Some(nix::errno::Errno::EEXIST);
                continue;
            }
            Err(e) => {
                return Err(NailsError::IoError(std::io::Error::other(format!(
                    "Failed to create temp file in {}: {}",
                    parent.display(),
                    e
                ))));
            }
        }
    }
    let temp_fd = temp_fd.ok_or_else(|| {
        NailsError::IoError(std::io::Error::other(format!(
            "Failed to create a unique temp file in {} ({:?})",
            parent.display(),
            last_err
        )))
    })?;

    // Everything below must clean up the temp on failure so a half-written file
    // is never left behind in the user's home.
    let outcome = (|| -> Result<()> {
        let mut file = std::fs::File::from(temp_fd);
        file.write_all(content.as_bytes()).map_err(|e| {
            NailsError::IoError(std::io::Error::new(
                e.kind(),
                format!("Failed to write temp file for {}: {}", path.display(), e),
            ))
        })?;
        file.sync_all().map_err(|e| {
            NailsError::IoError(std::io::Error::new(
                e.kind(),
                format!("Failed to sync temp file for {}: {}", path.display(), e),
            ))
        })?;

        // Ownership is skipped in test/test-like runtimes, where the process may
        // lack the privilege to chown to another account. This mirrors the
        // guard the notification writer uses for the same reason.
        if !crate::runtime_safety::should_skip_host_interaction() {
            fchown(&file, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid))).map_err(|e| {
                NailsError::IoError(std::io::Error::other(format!(
                    "Failed to set ownership {uid}:{gid} on {}: {e}",
                    path.display()
                )))
            })?;
        }

        // Set the mode explicitly so the process umask cannot alter it.
        fchmod(&file, Mode::from_bits_truncate(mode)).map_err(|e| {
            NailsError::IoError(std::io::Error::other(format!(
                "Failed to set mode {mode:o} on {}: {e}",
                path.display()
            )))
        })?;

        renameat(&dir_fd, temp_name.as_str(), &dir_fd, file_name).map_err(|e| {
            NailsError::IoError(std::io::Error::other(format!(
                "Failed to move temp file into place at {}: {e}",
                path.display()
            )))
        })?;
        Ok(())
    })();

    if outcome.is_err() {
        let _ = unlinkat(&dir_fd, temp_name.as_str(), UnlinkatFlags::NoRemoveDir);
    }

    outcome
}

/// Open `dir` as a directory fd whose path contains no symlinked component.
///
/// Uses `openat2` with `RESOLVE_NO_SYMLINKS`, so a symlink anywhere in `dir`'s
/// path (for example a pre-planted `~/.config` pointing elsewhere) is refused
/// with `ELOOP` rather than silently followed. The anchor fd is required by the
/// wrapper but is ignored for the absolute path passed here.
fn open_dir_no_symlinks(dir: &Path) -> Result<std::os::fd::OwnedFd> {
    use nix::fcntl::{OFlag, OpenHow, ResolveFlag, openat2};

    let anchor = std::fs::File::open("/").map_err(|e| {
        NailsError::IoError(std::io::Error::new(
            e.kind(),
            format!("Failed to open / to anchor directory resolution: {e}"),
        ))
    })?;
    let how = OpenHow::new()
        .flags(OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC)
        .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS);
    openat2(&anchor, dir, how).map_err(|e| {
        NailsError::IoError(std::io::Error::other(format!(
            "Refusing to write into {}: its path is not resolvable without symlinks ({e})",
            dir.display()
        )))
    })
}

/// Create `dir` and any missing ancestors, leaving every directory NAILS creates
/// owned by `user` and mode 0700. Refuses to descend through a symlinked
/// component so a planted symlink cannot redirect directory creation.
fn create_user_dir_all(dir: &Path, user: &TargetUser) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    match std::fs::symlink_metadata(dir) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(NailsError::IoError(std::io::Error::other(format!(
                "Refusing to write under symlinked directory {}",
                dir.display()
            ))));
        }
        Ok(meta) if meta.is_dir() => return Ok(()),
        Ok(_) => {
            return Err(NailsError::IoError(std::io::Error::other(format!(
                "Parent path {} exists and is not a directory",
                dir.display()
            ))));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(NailsError::IoError(std::io::Error::new(
                e.kind(),
                format!("Failed to stat {}: {e}", dir.display()),
            )));
        }
    }

    // Walk up to the first existing ancestor, recording the missing ones.
    let mut missing = Vec::new();
    let mut cursor = dir;
    loop {
        match std::fs::symlink_metadata(cursor) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(NailsError::IoError(std::io::Error::other(format!(
                    "Refusing to create directories under symlinked path {}",
                    cursor.display()
                ))));
            }
            Ok(_) => break,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                missing.push(cursor.to_path_buf());
                match cursor.parent() {
                    Some(parent) => cursor = parent,
                    None => break,
                }
            }
            Err(e) => {
                return Err(NailsError::IoError(std::io::Error::new(
                    e.kind(),
                    format!("Failed to stat {}: {e}", cursor.display()),
                )));
            }
        }
    }

    for new_dir in missing.iter().rev() {
        match std::fs::create_dir(new_dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(NailsError::IoError(std::io::Error::new(
                    e.kind(),
                    format!("Failed to create directory {}: {e}", new_dir.display()),
                )));
            }
        }

        if let Err(e) = std::fs::set_permissions(new_dir, std::fs::Permissions::from_mode(0o700)) {
            tracing::warn!(
                dir = %new_dir.display(),
                error = %e,
                "Failed to set mode on created directory (non-fatal)"
            );
        }

        if !crate::runtime_safety::should_skip_host_interaction() {
            std::os::unix::fs::chown(new_dir, Some(user.uid), Some(user.gid)).map_err(|e| {
                NailsError::IoError(std::io::Error::new(
                    e.kind(),
                    format!(
                        "Failed to set ownership {}:{} on {}: {e}",
                        user.uid,
                        user.gid,
                        new_dir.display()
                    ),
                ))
            })?;
        }
    }

    Ok(())
}

/// A process-unique temp file name. The write path creates it with `O_EXCL`, so
/// a residual collision only costs a retry; uniqueness here just keeps retries
/// rare and the name unpredictable.
fn unique_temp_name() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(".nails-tmp.{}.{}.{}", std::process::id(), nanos, seq)
}

pub(super) fn find_files_with_pattern(
    fs: &RealFilesystem,
    dir: &Path,
    pattern: &str,
) -> Result<Vec<PathBuf>> {
    let mut matching_files = Vec::new();

    if !dir.exists() || !dir.is_dir() {
        return Ok(matching_files);
    }

    let entries = std::fs::read_dir(dir).map_err(|e| {
        NailsError::IoError(std::io::Error::new(
            e.kind(),
            format!("Failed to read directory {}: {}", dir.display(), e),
        ))
    })?;

    for entry in entries.flatten() {
        let path = entry.path();

        if path.is_dir() {
            matching_files.extend(fs.find_files_with_pattern(&path, pattern)?);
        } else if path.is_file()
            && let Some(filename) = path.file_name()
            && filename
                .to_string_lossy()
                .to_lowercase()
                .contains(&pattern.to_lowercase())
        {
            matching_files.push(path);
        }
    }

    Ok(matching_files)
}

pub(super) fn file_size(path: &Path) -> Result<u64> {
    let metadata = std::fs::metadata(path).map_err(|e| {
        NailsError::IoError(std::io::Error::new(
            e.kind(),
            format!("Failed to get file size for {}: {}", path.display(), e),
        ))
    })?;
    Ok(metadata.len())
}

pub(super) fn rename_file(from: &Path, to: &Path) -> Result<()> {
    std::fs::rename(from, to).map_err(|e| {
        NailsError::IoError(std::io::Error::new(
            e.kind(),
            format!(
                "Failed to rename {} to {}: {}",
                from.display(),
                to.display(),
                e
            ),
        ))
    })
}

pub(super) fn remove_file(path: &Path) -> Result<()> {
    std::fs::remove_file(path).map_err(|e| {
        NailsError::IoError(std::io::Error::new(
            e.kind(),
            format!("Failed to remove file {}: {}", path.display(), e),
        ))
    })
}

pub(super) fn remove_directory(path: &Path) -> Result<()> {
    std::fs::remove_dir(path).map_err(|e| {
        NailsError::IoError(std::io::Error::new(
            e.kind(),
            format!("Failed to remove directory {}: {}", path.display(), e),
        ))
    })
}

pub(super) fn remove_dir_all(path: &Path) -> Result<()> {
    std::fs::remove_dir_all(path).map_err(|e| {
        NailsError::IoError(std::io::Error::new(
            e.kind(),
            format!("Failed to remove directory {}: {}", path.display(), e),
        ))
    })
}

pub(super) fn secure_delete(fs: &RealFilesystem, path: &Path) -> Result<()> {
    use std::io::Write;

    let file_size = fs.file_size(path)?;

    if file_size == 0 {
        return fs.remove_file(path);
    }

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|e| {
            NailsError::IoError(std::io::Error::new(
                e.kind(),
                format!(
                    "Failed to open file for secure deletion {}: {}",
                    path.display(),
                    e
                ),
            ))
        })?;

    const BUFFER_SIZE: usize = 64 * 1024;
    let zeros = vec![0u8; BUFFER_SIZE];

    // Pass 1: Overwrite with zeros
    let mut remaining = file_size as usize;
    while remaining > 0 {
        let to_write = remaining.min(BUFFER_SIZE);
        file.write_all(&zeros[..to_write]).map_err(|e| {
            NailsError::IoError(std::io::Error::new(
                e.kind(),
                format!(
                    "Failed to overwrite file with zeros {}: {}",
                    path.display(),
                    e
                ),
            ))
        })?;
        remaining -= to_write;
    }
    file.sync_all().map_err(NailsError::IoError)?;

    // Pass 2: Overwrite with random data from /dev/urandom
    use std::io::{Read, Seek};
    file.seek(std::io::SeekFrom::Start(0))
        .map_err(NailsError::IoError)?;

    let mut urandom = std::fs::File::open("/dev/urandom").map_err(|e| {
        NailsError::IoError(std::io::Error::new(
            e.kind(),
            format!("Failed to open /dev/urandom for secure deletion: {}", e),
        ))
    })?;

    let mut random_buf = vec![0u8; BUFFER_SIZE];
    remaining = file_size as usize;
    while remaining > 0 {
        let to_write = remaining.min(BUFFER_SIZE);
        urandom
            .read_exact(&mut random_buf[..to_write])
            .map_err(|e| {
                NailsError::IoError(std::io::Error::new(
                    e.kind(),
                    format!("Failed to read random data from /dev/urandom: {}", e),
                ))
            })?;
        file.write_all(&random_buf[..to_write]).map_err(|e| {
            NailsError::IoError(std::io::Error::new(
                e.kind(),
                format!(
                    "Failed to overwrite file with random data {}: {}",
                    path.display(),
                    e
                ),
            ))
        })?;
        remaining -= to_write;
    }
    file.sync_all().map_err(NailsError::IoError)?;

    // Pass 3: Overwrite with zeros again
    file.seek(std::io::SeekFrom::Start(0))
        .map_err(NailsError::IoError)?;

    remaining = file_size as usize;
    while remaining > 0 {
        let to_write = remaining.min(BUFFER_SIZE);
        file.write_all(&zeros[..to_write]).map_err(|e| {
            NailsError::IoError(std::io::Error::new(
                e.kind(),
                format!(
                    "Failed to overwrite file with zeros (final pass) {}: {}",
                    path.display(),
                    e
                ),
            ))
        })?;
        remaining -= to_write;
    }
    file.sync_all().map_err(NailsError::IoError)?;

    drop(file);
    fs.remove_file(path)
}

pub(super) fn secure_delete_dir_all(fs: &RealFilesystem, path: &Path) -> Result<()> {
    if path.is_dir() {
        for entry in std::fs::read_dir(path).map_err(|e| {
            NailsError::IoError(std::io::Error::new(
                e.kind(),
                format!("Failed to read directory {}: {}", path.display(), e),
            ))
        })? {
            let entry = entry.map_err(NailsError::IoError)?;
            let entry_path = entry.path();

            if entry_path.is_dir() {
                fs.secure_delete_dir_all(&entry_path)?;
            } else {
                fs.secure_delete(&entry_path)?;
            }
        }

        std::fs::remove_dir(path).map_err(|e| {
            NailsError::IoError(std::io::Error::new(
                e.kind(),
                format!("Failed to remove directory {}: {}", path.display(), e),
            ))
        })?;
    }

    Ok(())
}

#[cfg(test)]
mod write_user_file_tests {
    use super::*;
    use crate::target_user::TargetUser;
    use std::os::unix::fs::PermissionsExt;

    fn test_user() -> TargetUser {
        // Ownership is skipped under the test runtime, so the ids never have to
        // match a real passwd entry.
        TargetUser::for_test(1000, 100, "operator", "/home/operator", "/bin/bash")
    }

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
    }

    #[test]
    fn planted_tmp_sibling_symlink_cannot_redirect_the_write() {
        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path();

        // A sensitive file the attacker wants root to clobber, plus the
        // predictable sibling symlink the old implementation would have opened.
        let sentinel = base.join("sentinel");
        std::fs::write(&sentinel, "SECRET").unwrap();
        let target = base.join("foo");
        std::os::unix::fs::symlink(&sentinel, base.join("foo.tmp")).unwrap();

        write_user_file(&target, "payload", &test_user(), 0o600).unwrap();

        // The sentinel the sibling pointed at is untouched.
        assert_eq!(std::fs::read_to_string(&sentinel).unwrap(), "SECRET");
        // The destination is a real file with our content and mode, not a link.
        assert!(
            !std::fs::symlink_metadata(&target)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "payload");
        assert_eq!(mode_of(&target), 0o600);
    }

    #[test]
    fn write_into_symlinked_parent_is_refused() {
        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path();

        let real = base.join("real");
        std::fs::create_dir(&real).unwrap();
        let link = base.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let err = write_user_file(&link.join("file"), "payload", &test_user(), 0o644);
        assert!(
            err.is_err(),
            "expected refusal writing through a symlinked parent"
        );
        // Nothing leaked into the symlink's real target.
        assert!(!real.join("file").exists());
    }

    #[test]
    fn creates_missing_parents_private_and_writes_default_mode() {
        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path();

        let target = base.join("a/b/c.txt");
        write_user_file(&target, "hello", &test_user(), 0o644).unwrap();

        assert_eq!(std::fs::read_to_string(&target).unwrap(), "hello");
        assert_eq!(mode_of(&target), 0o644);
        assert_eq!(mode_of(&base.join("a")), 0o700);
        assert_eq!(mode_of(&base.join("a/b")), 0o700);
    }

    #[test]
    fn existing_file_keeps_its_mode() {
        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path();
        let target = base.join("keep");

        write_user_file(&target, "first", &test_user(), 0o600).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o640)).unwrap();

        // A second write with a different default must not reset the mode.
        write_user_file(&target, "second", &test_user(), 0o600).unwrap();

        assert_eq!(std::fs::read_to_string(&target).unwrap(), "second");
        assert_eq!(mode_of(&target), 0o640);
    }
}
