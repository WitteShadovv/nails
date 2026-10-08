// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Multi-pass overwrite-then-remove secure deletion.

use super::RealFilesystem;
use crate::filesystem::Filesystem;
use crate::{IoResultExt, NailsError, Result};
use std::path::Path;

pub(in crate::filesystem::real) fn secure_delete(fs: &RealFilesystem, path: &Path) -> Result<()> {
    use std::io::Write;

    let file_size = fs.file_size(path)?;

    if file_size == 0 {
        return fs.remove_file(path);
    }

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|e| {
            NailsError::io(
                path,
                std::io::Error::new(
                    e.kind(),
                    format!(
                        "Failed to open file for secure deletion {}: {}",
                        path.display(),
                        e
                    ),
                ),
            )
        })?;

    const BUFFER_SIZE: usize = 64 * 1024;
    let zeros = vec![0u8; BUFFER_SIZE];

    // Pass 1: Overwrite with zeros
    let mut remaining = file_size as usize;
    while remaining > 0 {
        let to_write = remaining.min(BUFFER_SIZE);
        file.write_all(&zeros[..to_write]).map_err(|e| {
            NailsError::io(
                path,
                std::io::Error::new(
                    e.kind(),
                    format!(
                        "Failed to overwrite file with zeros {}: {}",
                        path.display(),
                        e
                    ),
                ),
            )
        })?;
        remaining -= to_write;
    }
    file.sync_all().at_path(path)?;

    // Pass 2: Overwrite with random data from /dev/urandom
    use std::io::{Read, Seek};
    file.seek(std::io::SeekFrom::Start(0)).at_path(path)?;

    let mut urandom = std::fs::File::open("/dev/urandom").map_err(|e| {
        NailsError::io(
            "/dev/urandom",
            std::io::Error::new(
                e.kind(),
                format!("Failed to open /dev/urandom for secure deletion: {}", e),
            ),
        )
    })?;

    let mut random_buf = vec![0u8; BUFFER_SIZE];
    remaining = file_size as usize;
    while remaining > 0 {
        let to_write = remaining.min(BUFFER_SIZE);
        urandom
            .read_exact(&mut random_buf[..to_write])
            .map_err(|e| {
                NailsError::io(
                    "/dev/urandom",
                    std::io::Error::new(
                        e.kind(),
                        format!("Failed to read random data from /dev/urandom: {}", e),
                    ),
                )
            })?;
        file.write_all(&random_buf[..to_write]).map_err(|e| {
            NailsError::io(
                path,
                std::io::Error::new(
                    e.kind(),
                    format!(
                        "Failed to overwrite file with random data {}: {}",
                        path.display(),
                        e
                    ),
                ),
            )
        })?;
        remaining -= to_write;
    }
    file.sync_all().at_path(path)?;

    // Pass 3: Overwrite with zeros again
    file.seek(std::io::SeekFrom::Start(0)).at_path(path)?;

    remaining = file_size as usize;
    while remaining > 0 {
        let to_write = remaining.min(BUFFER_SIZE);
        file.write_all(&zeros[..to_write]).map_err(|e| {
            NailsError::io(
                path,
                std::io::Error::new(
                    e.kind(),
                    format!(
                        "Failed to overwrite file with zeros (final pass) {}: {}",
                        path.display(),
                        e
                    ),
                ),
            )
        })?;
        remaining -= to_write;
    }
    file.sync_all().at_path(path)?;

    drop(file);
    fs.remove_file(path)
}

pub(in crate::filesystem::real) fn secure_delete_dir_all(
    fs: &RealFilesystem,
    path: &Path,
) -> Result<()> {
    if path.is_dir() {
        for entry in std::fs::read_dir(path).map_err(|e| {
            NailsError::io(
                path,
                std::io::Error::new(
                    e.kind(),
                    format!("Failed to read directory {}: {}", path.display(), e),
                ),
            )
        })? {
            let entry = entry.at_path(path)?;
            let entry_path = entry.path();

            if entry_path.is_dir() {
                fs.secure_delete_dir_all(&entry_path)?;
            } else {
                fs.secure_delete(&entry_path)?;
            }
        }

        std::fs::remove_dir(path).map_err(|e| {
            NailsError::io(
                path,
                std::io::Error::new(
                    e.kind(),
                    format!("Failed to remove directory {}: {}", path.display(), e),
                ),
            )
        })?;
    }

    Ok(())
}
