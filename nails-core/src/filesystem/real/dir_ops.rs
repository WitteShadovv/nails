//! Directory listing, enumeration, copy, size, and submount operations.

use crate::{NailsError, Result};
use std::path::{Path, PathBuf};

pub(super) fn list_directory(dir: &Path) -> Result<Vec<PathBuf>> {
    let entries = std::fs::read_dir(dir).map_err(|e| {
        NailsError::IoError(std::io::Error::new(
            e.kind(),
            format!("Failed to read directory {}: {}", dir.display(), e),
        ))
    })?;

    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| {
            NailsError::IoError(std::io::Error::new(
                e.kind(),
                format!("Failed to read directory entry in {}: {}", dir.display(), e),
            ))
        })?;
        paths.push(entry.path());
    }

    Ok(paths)
}

pub(super) fn enumerate_root_directories() -> Result<Vec<PathBuf>> {
    let root = Path::new("/");

    let entries = std::fs::read_dir(root).map_err(|e| {
        NailsError::IoError(std::io::Error::new(
            e.kind(),
            format!("Failed to read /: {}", e),
        ))
    })?;

    let mut directories = Vec::new();

    for entry in entries {
        let entry = entry.map_err(|e| {
            NailsError::IoError(std::io::Error::new(
                e.kind(),
                format!("Failed to read directory entry: {}", e),
            ))
        })?;
        let path = entry.path();

        let metadata = std::fs::symlink_metadata(&path).map_err(|e| {
            NailsError::IoError(std::io::Error::new(
                e.kind(),
                format!("Failed to get metadata for {}: {}", path.display(), e),
            ))
        })?;

        // Skip symlinks (even if they point to directories)
        if metadata.is_symlink() {
            tracing::debug!(
                "Skipping symlink: {} -> {:?}",
                path.display(),
                std::fs::read_link(&path)
            );
            continue;
        }

        if !metadata.is_dir() {
            continue;
        }

        // Skip /run/nails directory (Story 14.10, Issue 6)
        if path.starts_with("/run/nails") {
            tracing::debug!("Skipping NAILS runtime directory: {}", path.display());
            continue;
        }

        directories.push(path);
    }

    // Sort alphabetically for consistent mount order (Story 14.10)
    directories.sort();

    Ok(directories)
}

pub(super) fn read_directory(path: &Path) -> Result<Vec<std::fs::DirEntry>> {
    let entries = std::fs::read_dir(path).map_err(|e| {
        NailsError::IoError(std::io::Error::new(
            e.kind(),
            format!("Failed to read directory {}: {}", path.display(), e),
        ))
    })?;

    let mut result = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| {
            NailsError::IoError(std::io::Error::new(
                e.kind(),
                format!(
                    "Failed to read directory entry in {}: {}",
                    path.display(),
                    e
                ),
            ))
        })?;
        result.push(entry);
    }

    Ok(result)
}

pub(super) fn modified_time(path: &Path) -> Result<chrono::DateTime<chrono::Utc>> {
    let metadata = std::fs::metadata(path).map_err(|e| {
        NailsError::IoError(std::io::Error::new(
            e.kind(),
            format!("Failed to get metadata for {}: {}", path.display(), e),
        ))
    })?;

    let modified = metadata.modified().map_err(|e| {
        NailsError::IoError(std::io::Error::new(
            e.kind(),
            format!(
                "Failed to get modification time for {}: {}",
                path.display(),
                e
            ),
        ))
    })?;

    let datetime: chrono::DateTime<chrono::Utc> = modified.into();
    Ok(datetime)
}

pub(super) fn copy_tree(src: &Path, dst: &Path) -> Result<()> {
    let src_str = src.to_str().ok_or_else(|| {
        NailsError::IoError(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Invalid UTF-8 in source path: {}", src.display()),
        ))
    })?;

    let output = std::process::Command::new("cp")
        .args(["-a", &format!("{}/.", src_str)])
        .arg(dst)
        .output()
        .map_err(|e| {
            NailsError::IoError(std::io::Error::new(
                e.kind(),
                format!(
                    "Failed to run cp -a {}/. {}: {}",
                    src.display(),
                    dst.display(),
                    e
                ),
            ))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(NailsError::IoError(std::io::Error::other(format!(
            "cp -a {}/. {} failed: {}",
            src.display(),
            dst.display(),
            stderr.trim()
        ))));
    }

    Ok(())
}

pub(super) fn get_directory_size(path: &Path) -> Result<u64> {
    let path_str = path.to_str().ok_or_else(|| {
        NailsError::IoError(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Invalid UTF-8 in path: {}", path.display()),
        ))
    })?;

    let output = std::process::Command::new("du")
        .args(["-sb", path_str])
        .output()
        .map_err(|e| {
            NailsError::IoError(std::io::Error::new(
                e.kind(),
                format!("Failed to run du -sb {}: {}", path.display(), e),
            ))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(NailsError::IoError(std::io::Error::other(format!(
            "du -sb {} failed: {}",
            path.display(),
            stderr.trim()
        ))));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let size_str = stdout.split_whitespace().next().ok_or_else(|| {
        NailsError::IoError(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("du -sb {} returned empty output", path.display()),
        ))
    })?;

    size_str.parse::<u64>().map_err(|e| {
        NailsError::IoError(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Failed to parse du output '{}': {}", size_str, e),
        ))
    })
}

pub(super) fn find_submount_sources(target: &Path) -> Result<Vec<(PathBuf, PathBuf)>> {
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo")?;
    let canonical_target = target
        .canonicalize()
        .unwrap_or_else(|_| target.to_path_buf());
    Ok(super::submount::parse_submount_sources(
        &mountinfo,
        &canonical_target,
    ))
}
