// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The decoy's files, as the locate-database check reads them: nothing is
//! written, a file is opened only once it is seen to be a regular file of a
//! sane size, with `O_NOATIME` (the filesystem's reads), and none is read, nor
//! a directory listed, where its links lead onto the hidden volume.

use crate::Filesystem;
use std::path::{Path, PathBuf};

/// The largest file read: far beyond any real configuration, unit or cron
/// job.
const MAX_FILE_BYTES: u64 = 1 << 20;

/// What a decoy path holds, as [`DecoyFiles::read`] reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecoyFile {
    /// Nothing, or a link to nothing.
    Absent,
    /// A link to `/dev/null`.
    Null,
    /// A regular file's bytes.
    Text(Vec<u8>),
    /// Something NAILS does not read, for this reason.
    Unread(String),
}

/// The decoy's files under `root`, read without writing, without changing an
/// access time and without following a link onto the hidden volume.
pub struct DecoyFiles<'a, F: Filesystem> {
    fs: &'a F,
    root: &'a Path,
    hidden: &'a [PathBuf],
}

impl<'a, F: Filesystem> DecoyFiles<'a, F> {
    /// Read under `root`; `hidden` are the hidden volume's locations, resolved.
    pub fn new(fs: &'a F, root: &'a Path, hidden: &'a [PathBuf]) -> Self {
        Self { fs, root, hidden }
    }

    /// The root the decoy is read under.
    pub fn root(&self) -> &Path {
        self.root
    }

    /// `path`, a path under the root, as the decoy names it.
    pub fn shown(&self, path: &Path) -> String {
        Path::new("/")
            .join(path.strip_prefix(self.root).unwrap_or(path))
            .display()
            .to_string()
    }

    /// Whether `path`, resolved, lies on the hidden volume.
    fn onto_hidden(&self, path: &Path) -> bool {
        self.fs
            .canonicalize(path)
            .is_ok_and(|target| self.hidden.iter().any(|hidden| target.starts_with(hidden)))
    }

    /// What `path` holds. A FIFO or device is never opened: the first would
    /// block the read and the second can be read without end.
    pub fn read(&self, path: &Path) -> DecoyFile {
        let shown = path.display();
        if self.fs.is_regular_file(path).unwrap_or(false) {
            if self.onto_hidden(path) {
                return DecoyFile::Unread(format!("{shown} leads onto the hidden volume"));
            }
            if self
                .fs
                .file_size(path)
                .is_ok_and(|size| size > MAX_FILE_BYTES)
            {
                return DecoyFile::Unread(format!("{shown} is larger than 1 MiB"));
            }
            return match self.fs.read_file_bytes(path) {
                Ok(bytes) if bytes.len() as u64 <= MAX_FILE_BYTES => DecoyFile::Text(bytes),
                Ok(_) => DecoyFile::Unread(format!("{shown} is larger than 1 MiB")),
                Err(e) => match e.io_kind() {
                    Some(std::io::ErrorKind::NotFound) => DecoyFile::Absent,
                    Some(std::io::ErrorKind::PermissionDenied) => DecoyFile::Unread(format!(
                        "NAILS cannot read {shown}; run the command again with sudo"
                    )),
                    _ => DecoyFile::Unread(format!("NAILS cannot read {shown} ({e})")),
                },
            };
        }
        if self.fs.path_exists(path).unwrap_or(true) {
            if self
                .fs
                .canonicalize(path)
                .is_ok_and(|target| target == Path::new("/dev/null"))
            {
                return DecoyFile::Null;
            }
            return DecoyFile::Unread(format!("{shown} is not a regular file"));
        }
        match self.fs.canonicalize(path) {
            Err(e) if e.io_kind() == Some(std::io::ErrorKind::PermissionDenied) => {
                DecoyFile::Unread(format!(
                    "NAILS cannot look up {shown}; run the command again with sudo"
                ))
            }
            Err(e) if e.io_kind() != Some(std::io::ErrorKind::NotFound) => {
                DecoyFile::Unread(format!("NAILS cannot follow {shown} ({e})"))
            }
            _ => DecoyFile::Absent,
        }
    }

    /// The entries of directory `dir`; none when it is missing or no
    /// directory.
    ///
    /// # Errors
    ///
    /// Why NAILS cannot list it: it may not, the listing fails, or the
    /// directory lies on the hidden volume.
    pub fn list(&self, dir: &Path) -> Result<Vec<PathBuf>, String> {
        if self.onto_hidden(dir) {
            return Err(format!("{} leads onto the hidden volume", dir.display()));
        }
        match self.fs.list_directory(dir) {
            Ok(entries) => Ok(entries),
            Err(e) => match e.io_kind() {
                Some(std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory) => {
                    Ok(Vec::new())
                }
                Some(std::io::ErrorKind::PermissionDenied) => Err(format!(
                    "NAILS cannot list {}; run the command again with sudo",
                    dir.display()
                )),
                _ => Err(format!("NAILS cannot list {} ({e})", dir.display())),
            },
        }
    }
}

#[cfg(test)]
#[path = "files_tests.rs"]
mod tests;
