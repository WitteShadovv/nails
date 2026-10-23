// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Read-only access to a raw block device or disk image.
//!
//! [`RawSource::open`] opens with `O_RDONLY | O_NOATIME | O_CLOEXEC` (falling
//! back without `O_NOATIME` only where the kernel refuses it), never mounts,
//! and offers positioned reads. Before reading it drops the clean cached pages
//! of the source (`posix_fadvise(DONTNEED)`), so a scan sees what is on the
//! device now rather than what an earlier scan cached, and it drops them again
//! when it is done so a large scan does not evict the page cache.

use crate::filesystem::real::{OpenKind, open_noatime};
use std::fs::File;
use std::io;
use std::os::unix::fs::{FileExt, FileTypeExt};
use std::path::{Path, PathBuf};

/// What kind of object a [`RawSource`] reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    /// A block device node.
    BlockDevice,
    /// A regular file (a disk image), possibly sparse.
    Image,
}

/// A raw device or image opened read-only.
#[derive(Debug)]
pub struct RawSource {
    path: PathBuf,
    file: File,
    size: u64,
    kind: SourceKind,
}

impl RawSource {
    /// Open `path` read-only without updating its access time.
    ///
    /// # Errors
    ///
    /// Fails when the path cannot be opened, is neither a block device nor a
    /// regular file, or its size cannot be read.
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = File::from(open_noatime(path, OpenKind::File)?);
        let meta = file.metadata()?;
        let file_type = meta.file_type();
        let kind = if file_type.is_block_device() {
            SourceKind::BlockDevice
        } else if file_type.is_file() {
            SourceKind::Image
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{} is neither a block device nor a regular file",
                    path.display()
                ),
            ));
        };
        // A block device reports st_size 0; its size is where SEEK_END lands.
        let size = match kind {
            SourceKind::Image => meta.len(),
            SourceKind::BlockDevice => {
                rustix::fs::seek(&file, rustix::fs::SeekFrom::End(0)).map_err(io::Error::from)?
            }
        };
        let source = Self {
            path: path.to_path_buf(),
            file,
            size,
            kind,
        };
        source.drop_cache();
        Ok(source)
    }

    /// A source over the image at `path` opened write-only, so every read of
    /// it fails: lets a test drive a read error through code that reads one.
    #[cfg(test)]
    pub(crate) fn unreadable(path: &Path) -> io::Result<Self> {
        let file = std::fs::OpenOptions::new().write(true).open(path)?;
        let size = file.metadata()?.len();
        Ok(Self {
            path: path.to_path_buf(),
            file,
            size,
            kind: SourceKind::Image,
        })
    }

    /// The path that was opened.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Size in bytes.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Whether this is a block device or an image file.
    pub fn kind(&self) -> SourceKind {
        self.kind
    }

    /// Read up to `buf.len()` bytes at `offset`, returning how many were read
    /// (fewer only at the end of the source).
    ///
    /// # Errors
    ///
    /// Propagates a read error.
    pub fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        let mut filled = 0;
        while filled < buf.len() {
            match self
                .file
                .read_at(&mut buf[filled..], offset + filled as u64)
            {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                Err(err) => return Err(err),
            }
        }
        Ok(filled)
    }

    /// The byte ranges that hold data. A sparse image's holes read as zeros
    /// and cannot hold a token, so a scan may skip them; a block device, or a
    /// filesystem without `SEEK_DATA`, is one range covering everything.
    pub fn data_extents(&self) -> Vec<(u64, u64)> {
        use rustix::fs::{SeekFrom, seek};
        if self.kind == SourceKind::BlockDevice || self.size == 0 {
            return if self.size == 0 {
                Vec::new()
            } else {
                vec![(0, self.size)]
            };
        }
        let mut extents = Vec::new();
        let mut offset = 0u64;
        while offset < self.size {
            let start = match seek(&self.file, SeekFrom::Data(offset)) {
                Ok(start) => start,
                Err(rustix::io::Errno::NXIO) => break,
                Err(_) => return vec![(0, self.size)],
            };
            let end = match seek(&self.file, SeekFrom::Hole(start)) {
                Ok(end) => end.min(self.size),
                Err(_) => return vec![(0, self.size)],
            };
            if end <= start {
                break;
            }
            extents.push((start, end));
            offset = end;
        }
        extents
    }

    /// Ask the kernel to drop the clean cached pages of this source.
    /// Best-effort: a refusal only means a scan may read cached pages.
    pub fn drop_cache(&self) {
        let _ = rustix::fs::fadvise(&self.file, 0, None, rustix::fs::Advice::DontNeed);
    }
}

impl Drop for RawSource {
    fn drop(&mut self) {
        self.drop_cache();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek, SeekFrom, Write};

    #[test]
    fn an_image_reads_back_and_reports_its_size() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("disk.img");
        std::fs::write(&path, b"0123456789").unwrap();

        let source = RawSource::open(&path).unwrap();
        assert_eq!(source.kind(), SourceKind::Image);
        assert_eq!(source.size(), 10);
        let mut buf = [0u8; 4];
        assert_eq!(source.read_at(&mut buf, 3).unwrap(), 4);
        assert_eq!(&buf, b"3456");
        assert_eq!(source.read_at(&mut buf, 8).unwrap(), 2);
    }

    #[test]
    fn a_sparse_image_skips_its_holes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sparse.img");
        let mut file = File::create(&path).unwrap();
        file.set_len(64 << 20).unwrap();
        file.seek(SeekFrom::Start(32 << 20)).unwrap();
        file.write_all(&[0xAA; 4096]).unwrap();
        file.sync_all().unwrap();

        let source = RawSource::open(&path).unwrap();
        let extents = source.data_extents();
        let covered: u64 = extents.iter().map(|(start, end)| end - start).sum();
        assert!(
            extents
                .iter()
                .any(|(start, end)| *start <= 32 << 20 && *end >= (32 << 20) + 4096),
            "the written block must be inside an extent: {extents:?}"
        );
        // On a filesystem with SEEK_HOLE the extents cover far less than the
        // whole image; without it they cover everything, which is still correct.
        assert!(covered <= 64 << 20);
    }

    #[test]
    fn a_directory_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let err = RawSource::open(dir.path()).unwrap_err();
        assert!(err.kind() == io::ErrorKind::InvalidInput || err.raw_os_error().is_some());
    }

    #[test]
    fn opening_never_writes_or_touches_the_atime() {
        use std::os::unix::fs::MetadataExt;
        use std::time::{Duration, SystemTime};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("disk.img");
        std::fs::write(&path, vec![7u8; 8192]).unwrap();
        let old = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
        File::open(&path)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_accessed(old))
            .unwrap();
        let before = std::fs::metadata(&path).unwrap();

        let source = RawSource::open(&path).unwrap();
        let mut buf = vec![0u8; 8192];
        source.read_at(&mut buf, 0).unwrap();
        drop(source);

        let after = std::fs::metadata(&path).unwrap();
        assert_eq!(after.atime(), before.atime(), "the read updated the atime");
        assert_eq!(after.mtime(), before.mtime());
        assert_eq!(after.len(), before.len());
    }
}
