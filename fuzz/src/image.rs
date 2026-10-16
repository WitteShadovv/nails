// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! A disk image in an anonymous memory file.
//!
//! The forensic readers take a [`RawSource`], which opens a path: the device
//! or image an examiner points them at. The image here is a memfd, opened
//! through its `/proc/self/fd` link, so the targets drive the product's own
//! reads (positioned reads, `SEEK_DATA` and `SEEK_HOLE`) without a disk: the
//! memory file lives in RAM, and its holes read as zeros like a sparse
//! image's.

use nails_forensics::forensic::RawSource;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::path::PathBuf;

/// The page size of the memory file: its holes start and end on it.
pub const PAGE: u64 = 4096;

/// One memory file, reused for every input of a run.
pub struct MemImage {
    file: File,
    path: PathBuf,
}

impl MemImage {
    /// A new, empty memory file.
    ///
    /// # Panics
    ///
    /// When the kernel refuses `memfd_create`, which no fuzzing host does.
    pub fn new() -> Self {
        let fd = rustix::fs::memfd_create("nails-fuzz-image", rustix::fs::MemfdFlags::CLOEXEC)
            .expect("memfd_create");
        let file = File::from(fd);
        let path = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
        Self { file, path }
    }

    /// Replace the image with `size` bytes that are holes everywhere but at
    /// `chunks`, each written at its offset, and open it as a source.
    ///
    /// # Panics
    ///
    /// When the memory file cannot be resized, written or opened.
    pub fn load(&self, size: u64, chunks: &[(u64, &[u8])]) -> RawSource {
        // Truncating to zero first drops every page the last input wrote.
        self.file.set_len(0).expect("truncate the image");
        self.file.set_len(size).expect("size the image");
        for (offset, bytes) in chunks {
            self.file
                .write_all_at(bytes, *offset)
                .expect("write the image");
        }
        RawSource::open(&self.path).expect("open the image")
    }
}

impl Default for MemImage {
    fn default() -> Self {
        Self::new()
    }
}
