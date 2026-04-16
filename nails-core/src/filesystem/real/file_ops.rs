//! File and path operations for RealFilesystem.

use super::RealFilesystem;
use crate::filesystem::Filesystem;
use crate::{NailsError, Result};
use std::path::{Path, PathBuf};

pub(super) fn path_exists(path: &Path) -> Result<bool> {
    Ok(path.exists())
}

pub(super) fn is_directory(path: &Path) -> Result<bool> {
    Ok(path.is_dir())
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

pub(super) fn get_free_space(path: &Path) -> Result<u64> {
    let stat = nix::sys::statvfs::statvfs(path)
        .map_err(|e| NailsError::IoError(std::io::Error::other(e.to_string())))?;
    Ok(stat.blocks_available() * stat.fragment_size())
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
