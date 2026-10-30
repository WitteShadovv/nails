// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What a system's package database says is installed.
//!
//! Three package managers keep the record NAILS reads:
//!
//! - dpkg (Debian, Ubuntu) keeps one stanza per package in
//!   `/var/lib/dpkg/status` ([`dpkg::parse_status`]), and each package's own
//!   files in `/var/lib/dpkg/info`, named after the package
//!   ([`dpkg::info_owner`]);
//! - pacman (Arch Linux) keeps one `<name>-<version>-<release>` directory per
//!   installed package in `/var/lib/pacman/local` ([`pacman::parse_entry`]);
//! - rpm (Fedora) keeps a SQLite database, whose table of packages NAILS
//!   reads with its own reader ([`sqlite`]): each package's name, version,
//!   architecture and files ([`rpm::read_packages`]).
//!
//! Each of them holds whatever the decoy's disk holds, or what a hidden
//! session wrote, so the parsers take any input: a line, a stanza or an entry
//! they cannot read is left out, never an error. rpm's database is read
//! whole or not at all: a header or a page it cannot read is an error, and so
//! is a database larger than rpm keeps or one whose packages would take more
//! memory than any of rpm's do ([`rpm::read_packages`]). The
//! `dpkg_status`, `pacman_local` and `rpmdb` fuzz targets drive them with
//! hostile input.
//!
//! # Reading without a trace
//!
//! The readers here go through the [`Filesystem`](crate::Filesystem) seam,
//! whose real reads open a file or a directory with `O_NOATIME`, so reading
//! the decoy's database leaves its access times alone, and whose metadata
//! reads (`stat`, `lstat`) never change one. The kernel grants `O_NOATIME` on
//! a file the caller does not own only to a caller with `CAP_FOWNER` (root);
//! for anyone else the real read falls back to a plain open, which does update
//! the access time. A caller that is not root therefore must not read the
//! decoy's database at all: the cryptsetup advice and the `package-drift`
//! check skip what they would read instead.

pub mod dpkg;
pub mod pacman;
pub mod rpm;
pub mod sqlite;

use crate::{Filesystem, NailsError, Result};
use std::path::Path;

/// The most of a package database file a reader takes in, 64 MiB: dpkg's
/// `status` file of a desktop with a few thousand packages is a few MiB, so a
/// file this large is not one dpkg wrote, and reading it whole could exhaust
/// the memory of the activation that reads it.
pub const READ_LIMIT: u64 = 64 << 20;

/// Whether `error` says the path, or a directory on its way, does not exist.
fn missing(error: &NailsError) -> bool {
    matches!(
        error.io_kind(),
        Some(std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory)
    )
}

/// The bytes of the file at `path`, read through `fs`: `None` when there is
/// no such file, an error when it holds more than [`READ_LIMIT`] bytes or
/// cannot be read. Its size is looked up first, which changes no access time.
pub fn read_bounded<F: Filesystem>(fs: &F, path: &Path) -> Result<Option<Vec<u8>>> {
    let size = match fs.file_size(path) {
        Ok(size) => size,
        Err(e) if missing(&e) => return Ok(None),
        Err(e) => return Err(e),
    };
    if size > READ_LIMIT {
        return Err(NailsError::io(
            path,
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{size} bytes, more than a package database holds ({READ_LIMIT})"),
            ),
        ));
    }
    match fs.read_file_bytes(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if missing(&e) => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests;
