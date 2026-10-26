// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! rpm's database of installed packages (Fedora).
//!
//! rpm keeps its database in SQLite, `rpmdb.sqlite`, at
//! `/usr/lib/sysimage/rpm` since Fedora 36 and at `/var/lib/rpm` before, which
//! Fedora keeps as a link to the new place. NAILS does not read SQLite: all it
//! knows of the database is the file's size and when it was last written, a
//! [`Stamp`], which `stat` gives without changing an access time.

use crate::{Filesystem, Result};
use std::path::Path;
use std::time::SystemTime;

/// Where rpm keeps its database, relative to the root, in the order they are
/// tried: the place since Fedora 36, then the one before.
pub const DATABASES: [&str; 2] = [
    "usr/lib/sysimage/rpm/rpmdb.sqlite",
    "var/lib/rpm/rpmdb.sqlite",
];

/// What is known of rpm's database without reading it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stamp {
    /// Its size in bytes.
    pub size: u64,
    /// When it was last written.
    pub modified: SystemTime,
}

/// The stamp of the file at `path`, looked up through `fs`: `None` when there
/// is no such file.
pub fn stamp<F: Filesystem>(fs: &F, path: &Path) -> Result<Option<Stamp>> {
    let size = match fs.file_size(path) {
        Ok(size) => size,
        Err(e) if super::missing(&e) => return Ok(None),
        Err(e) => return Err(e),
    };
    Ok(Some(Stamp {
        size,
        modified: fs.modified_time(path)?,
    }))
}

/// rpm's database below `root`: the first of [`DATABASES`] that is a regular
/// file there with no symbolic link on its way, and its stamp. `None` when
/// there is none.
///
/// A path with a link on its way is passed over, so the lookup follows no
/// link, whose access time a lookup would change, and the link Fedora keeps
/// at the old place is not taken for a second database.
pub fn locate<F: Filesystem>(fs: &F, root: &Path) -> Result<Option<(&'static str, Stamp)>> {
    'databases: for database in DATABASES {
        let mut path = root.to_path_buf();
        for component in Path::new(database).components() {
            path.push(component);
            if fs.is_symlink(&path)? {
                continue 'databases;
            }
        }
        if !fs.is_regular_file(&path)? {
            continue;
        }
        if let Some(stamp) = stamp(fs, &path)? {
            return Ok(Some((database, stamp)));
        }
    }
    Ok(None)
}
