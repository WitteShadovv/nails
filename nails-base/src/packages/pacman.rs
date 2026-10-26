// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! pacman's database of installed packages (Arch Linux).
//!
//! `/var/lib/pacman/local` holds one directory per installed package, named
//! `<name>-<version>-<release>` (the version may start with an `<epoch>:`),
//! with the package's `desc`, `files` and `mtree` in it. pacman knows a
//! package by that name: libalpm's `_alpm_splitname()` (lib/libalpm/util.c)
//! splits it at its last two hyphens, since a package's name may hold hyphens
//! and its version and release may not, and [`parse_entry`] splits it the
//! same way. A name it cannot split, such as the database's own
//! `ALPM_DB_VERSION`, is no package.

use crate::{Filesystem, Result};
use std::path::Path;

/// pacman's database of installed packages, relative to the root.
pub const LOCAL: &str = "var/lib/pacman/local";

/// One package of pacman's database.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Package {
    /// The package's name (`linux-firmware`).
    pub name: String,
    /// Its version and release, with the epoch when it has one
    /// (`1:20260910.1234-1`).
    pub version: String,
}

impl Package {
    /// The name of the package's entry in the database.
    pub fn entry(&self) -> String {
        format!("{}-{}", self.name, self.version)
    }
}

/// The package the database entry `entry` holds, split as libalpm splits it
/// (see the [module docs](self)): `None` when `entry` has fewer than two
/// hyphens or starts with the one that would end the name. As libalpm does,
/// everything from a `/` on is left out.
pub fn parse_entry(entry: &str) -> Option<Package> {
    let entry = entry.split('/').next().unwrap_or_default();
    let release = entry.rfind('-')?;
    let version = entry[..release].rfind('-')?;
    if version == 0 {
        return None;
    }
    Some(Package {
        name: entry[..version].to_string(),
        version: entry[version + 1..].to_string(),
    })
}

/// The packages of pacman's database below `root` ([`read_local_dir`] of its
/// [`LOCAL`]).
pub fn read_local<F: Filesystem>(fs: &F, root: &Path) -> Result<Option<Vec<Package>>> {
    read_local_dir(fs, &root.join(LOCAL))
}

/// The packages of the pacman database directory `dir`, listed through `fs`
/// (see the [parent module](super) on access times), in the listing's order:
/// `None` when there is no such directory. Only the entries' names are read,
/// and an entry whose name is not UTF-8 or does not split is left out.
pub fn read_local_dir<F: Filesystem>(fs: &F, dir: &Path) -> Result<Option<Vec<Package>>> {
    let entries = match fs.list_directory(dir) {
        Ok(entries) => entries,
        Err(e) if super::missing(&e) => return Ok(None),
        Err(e) => return Err(e),
    };
    Ok(Some(
        entries
            .iter()
            .filter_map(|entry| entry.file_name()?.to_str())
            .filter_map(parse_entry)
            .collect(),
    ))
}
