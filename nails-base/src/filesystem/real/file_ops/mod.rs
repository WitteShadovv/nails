// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! File and path operations for RealFilesystem.

use super::RealFilesystem;
use super::noatime::EntryType;
use crate::filesystem::{DiskUsage, Filesystem, PatternScan};
use crate::{IoResultExt, NailsError, Result};
use std::path::{Path, PathBuf};

mod secure_delete;
mod user_write;

pub(super) use secure_delete::{secure_delete, secure_delete_dir_all};
pub(super) use user_write::write_user_file;

pub(super) fn path_exists(path: &Path) -> Result<bool> {
    Ok(path.exists())
}

pub(super) fn is_directory(path: &Path) -> Result<bool> {
    Ok(path.is_dir())
}

pub(super) fn is_regular_file(path: &Path) -> Result<bool> {
    // `stat` reads the type without opening the file: a FIFO cannot block
    // it, and no device is opened.
    Ok(path.is_file())
}

pub(super) fn device_id(path: &Path) -> Result<u64> {
    use std::os::unix::fs::MetadataExt;
    // `metadata` follows symlinks, which is what we want: the attach gate asks
    // about the filesystem the path resolves to, not about a link inode.
    std::fs::metadata(path).map(|meta| meta.dev()).at_path(path)
}

pub(super) fn is_symlink(path: &Path) -> Result<bool> {
    Ok(path.is_symlink())
}

pub(super) fn is_overlay_whiteout(path: &Path) -> Result<bool> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    Ok(std::fs::symlink_metadata(path)
        .is_ok_and(|meta| meta.file_type().is_char_device() && meta.rdev() == 0))
}

pub(super) fn canonicalize(path: &Path) -> Result<PathBuf> {
    std::fs::canonicalize(path).at_path(path)
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
                _ => Err(NailsError::io(&probe, e)),
            }
        }
    }
}

pub(super) fn create_symlink(target: &Path, link: &Path) -> Result<()> {
    if link.is_symlink() {
        let existing_target = std::fs::read_link(link).at_path(link)?;
        if existing_target == target {
            return Ok(());
        }
        return Err(NailsError::io(
            link,
            std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!(
                    "Symlink at {} already exists pointing to a different target",
                    link.display()
                ),
            ),
        ));
    }
    if link.exists() {
        return Err(NailsError::io(
            link,
            std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("Path already exists (not a symlink) at {}", link.display()),
            ),
        ));
    }
    std::os::unix::fs::symlink(target, link).at_path(link)
}

pub(super) fn disk_usage(path: &Path) -> Result<DiskUsage> {
    let stat = nix::sys::statvfs::statvfs(path)
        .map_err(|e| NailsError::io(path, std::io::Error::from(e)))?;
    let fragment_size = stat.fragment_size();
    Ok(DiskUsage {
        total: stat.blocks() * fragment_size,
        available: stat.blocks_available() * fragment_size,
    })
}

pub(super) fn create_directory(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path).at_path(path)
}

pub(super) fn set_permissions(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(path, perms).at_path(path)
}

pub(super) fn get_permissions(path: &Path) -> Result<u32> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path).at_path(path)?.permissions().mode();
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
                std::fs::remove_file(&test_path).at_path(&test_path)?;
                Ok(true)
            }
            Err(_) => Ok(false),
        }
    } else {
        Ok(std::fs::OpenOptions::new().append(true).open(path).is_ok())
    }
}

/// Read a file as UTF-8 without updating its access time, so NAILS's own reads
/// of decoy files leave no session-time atime on them (the symlinks a lookup
/// follows on the way are not covered; see the `noatime` module).
pub(super) fn read_file_content(path: &Path) -> Result<String> {
    super::noatime::read_to_string_noatime(path).map_err(|e| {
        NailsError::io(
            path,
            std::io::Error::new(
                e.kind(),
                format!("Failed to read file {}: {}", path.display(), e),
            ),
        )
    })
}

/// Read a file's raw bytes without updating its access time, as
/// [`read_file_content`] reads text.
pub(super) fn read_file_bytes(path: &Path) -> Result<Vec<u8>> {
    super::noatime::read_to_end_noatime(path).map_err(|e| {
        NailsError::io(
            path,
            std::io::Error::new(
                e.kind(),
                format!("Failed to read file {}: {}", path.display(), e),
            ),
        )
    })
}

pub(super) fn write_file_content(path: &Path, content: &str) -> Result<()> {
    use std::io::Write;

    let temp_path = path.with_extension("tmp");

    let mut temp_file = std::fs::File::create(&temp_path).map_err(|e| {
        NailsError::io(
            &temp_path,
            std::io::Error::new(
                e.kind(),
                format!("Failed to create temp file {}: {}", temp_path.display(), e),
            ),
        )
    })?;

    temp_file.write_all(content.as_bytes()).map_err(|e| {
        NailsError::io(
            &temp_path,
            std::io::Error::new(
                e.kind(),
                format!(
                    "Failed to write to temp file {}: {}",
                    temp_path.display(),
                    e
                ),
            ),
        )
    })?;

    temp_file.sync_all().map_err(|e| {
        NailsError::io(
            &temp_path,
            std::io::Error::new(
                e.kind(),
                format!("Failed to sync temp file {}: {}", temp_path.display(), e),
            ),
        )
    })?;

    std::fs::rename(&temp_path, path).map_err(|e| {
        NailsError::io(
            &temp_path,
            std::io::Error::new(
                e.kind(),
                format!(
                    "Failed to rename {} to {}: {}",
                    temp_path.display(),
                    path.display(),
                    e
                ),
            ),
        )
    })?;

    Ok(())
}

/// Overwrite an existing file's contents in place on the same inode.
///
/// See [`crate::filesystem::Filesystem::overwrite_file_in_place`] for the
/// contract. The parent directory is resolved through [`SafeRoot`] (symlink
/// resolution disabled), the file is opened `O_RDWR | O_NOFOLLOW` without
/// `O_CREAT` — a missing file is reported rather than created — truncated to
/// zero, and rewritten. No temp file and no rename, so the inode, owner and mode
/// are preserved and the old content is not left behind under a sibling name.
pub(super) fn overwrite_file_in_place(path: &Path, content: &str) -> Result<()> {
    use std::io::Write;

    let parent = path.parent().ok_or_else(|| {
        NailsError::io(
            path,
            std::io::Error::other(format!(
                "Refusing to overwrite a file with no parent directory: {}",
                path.display()
            )),
        )
    })?;
    let file_name = path.file_name().ok_or_else(|| {
        NailsError::io(
            path,
            std::io::Error::other(format!(
                "Refusing to overwrite a path with no file name: {}",
                path.display()
            )),
        )
    })?;

    // Open the existing file beneath the symlink-safe parent root without
    // `O_CREAT`: a missing file is reported rather than created, so the opt-in
    // edit never plants a decoy history file that was not already there. The
    // existing inode, owner and mode are preserved, and `O_NOFOLLOW` refuses a
    // symlink planted at the final component.
    let root = crate::filesystem::SafeRoot::open(parent)?;
    let mut file = root.open_rw_existing(Path::new(file_name))?;

    // Truncate on the same inode, then rewrite — no temp file, no rename.
    file.set_len(0).map_err(|e| {
        NailsError::io(
            path,
            std::io::Error::new(
                e.kind(),
                format!("Failed to truncate {}: {}", path.display(), e),
            ),
        )
    })?;
    file.write_all(content.as_bytes()).map_err(|e| {
        NailsError::io(
            path,
            std::io::Error::new(
                e.kind(),
                format!("Failed to rewrite {}: {}", path.display(), e),
            ),
        )
    })?;
    file.sync_all().map_err(|e| {
        NailsError::io(
            path,
            std::io::Error::new(
                e.kind(),
                format!("Failed to sync {}: {}", path.display(), e),
            ),
        )
    })?;

    Ok(())
}

/// A process-unique temp file name. The write path creates it with `O_EXCL`, so
/// a residual collision only costs a retry; uniqueness here just keeps retries
/// rare and the name unpredictable.
///
/// Shared with [`crate::filesystem::safe_path`], whose atomic write under the
/// hidden root uses the same `O_EXCL`-guarded temp-then-rename pattern.
pub(crate) fn unique_temp_name() -> String {
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

    let entries = super::noatime::read_dir_noatime(dir).map_err(|e| {
        NailsError::io(
            dir,
            std::io::Error::new(
                e.kind(),
                format!("Failed to read directory {}: {}", dir.display(), e),
            ),
        )
    })?;

    for entry in entries {
        let path = dir.join(&entry.name);

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

pub(super) fn scan_files_with_pattern(dir: &Path, pattern: &str) -> Result<PatternScan> {
    let mut scan = PatternScan::default();
    scan_files_tolerant(dir, &pattern.to_lowercase(), &mut scan);
    Ok(scan)
}

/// Walk `dir` recursively, collecting files whose name contains `pattern` and
/// recording directories that cannot be read instead of failing on them.
///
/// `pattern` is already lowercased by the caller. A directory that cannot be
/// opened (permission denied, or a race that removes it mid-walk) is appended to
/// [`PatternScan::unreadable`] and skipped, so an unprivileged scan of `/tmp`
/// never aborts on a `systemd-private-*` directory owned by another service.
fn scan_files_tolerant(dir: &Path, pattern: &str, scan: &mut PatternScan) {
    if !dir.is_dir() {
        return;
    }

    let entries = match super::noatime::read_dir_noatime(dir) {
        Ok(entries) => entries,
        Err(_) => {
            scan.unreadable.push(dir.to_path_buf());
            return;
        }
    };

    for entry in entries {
        let path = dir.join(&entry.name);
        // The entry type comes from `d_type` (an `lstat` only when the filesystem
        // leaves it unknown) and does not follow symlinks, so a symlinked
        // directory is never recursed into.
        match entry.resolved_type(dir) {
            Ok(EntryType::Directory) => scan_files_tolerant(&path, pattern, scan),
            Ok(EntryType::File) => {
                if let Some(name) = path.file_name()
                    && name.to_string_lossy().to_lowercase().contains(pattern)
                {
                    scan.matches.push(path);
                }
            }
            _ => {}
        }
    }
}

pub(super) fn file_size(path: &Path) -> Result<u64> {
    let metadata = std::fs::metadata(path).map_err(|e| {
        NailsError::io(
            path,
            std::io::Error::new(
                e.kind(),
                format!("Failed to get file size for {}: {}", path.display(), e),
            ),
        )
    })?;
    Ok(metadata.len())
}

pub(super) fn rename_file(from: &Path, to: &Path) -> Result<()> {
    std::fs::rename(from, to).map_err(|e| {
        NailsError::io(
            from,
            std::io::Error::new(
                e.kind(),
                format!(
                    "Failed to rename {} to {}: {}",
                    from.display(),
                    to.display(),
                    e
                ),
            ),
        )
    })
}

pub(super) fn remove_file(path: &Path) -> Result<()> {
    std::fs::remove_file(path).map_err(|e| {
        NailsError::io(
            path,
            std::io::Error::new(
                e.kind(),
                format!("Failed to remove file {}: {}", path.display(), e),
            ),
        )
    })
}

pub(super) fn remove_directory(path: &Path) -> Result<()> {
    std::fs::remove_dir(path).map_err(|e| {
        NailsError::io(
            path,
            std::io::Error::new(
                e.kind(),
                format!("Failed to remove directory {}: {}", path.display(), e),
            ),
        )
    })
}

pub(super) fn remove_dir_all(path: &Path) -> Result<()> {
    std::fs::remove_dir_all(path).map_err(|e| {
        NailsError::io(
            path,
            std::io::Error::new(
                e.kind(),
                format!("Failed to remove directory {}: {}", path.display(), e),
            ),
        )
    })
}
