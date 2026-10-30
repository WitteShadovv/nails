// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! rpm's database of installed packages (Fedora).
//!
//! rpm keeps its database in SQLite, `rpmdb.sqlite`, at
//! `/usr/lib/sysimage/rpm` since Fedora 36 and at `/var/lib/rpm` before, which
//! Fedora keeps as a link to the new place. rpm runs it in WAL mode and keeps
//! the log, `rpmdb.sqlite-wal`, next to it, empty once a transaction is
//! checkpointed. Its table `Packages` holds one row per installed package,
//! `(hnum INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL)`, whose blob
//! is the package's header as rpm's `headerExport()` writes it: the number of
//! index entries and the size of the data, both 32-bit big-endian, then the
//! entries, sixteen bytes each (tag, type, offset into the data, count), then
//! the data.
//!
//! NAILS reads the table with its own reader ([`super::sqlite`]), the file
//! and the log through the [`Filesystem`] seam, and of each header the tags
//! it judges by: the package's name, epoch, version, release and
//! architecture, and the files it installed (their paths, flags, modes and
//! states). A header it cannot read makes the database unreadable: rpm itself
//! would not trust such a database either.
//!
//! The database is read one row at a time, and of each row only the package
//! is kept, within a [`Budget`] of memory that the packages of both databases
//! one judgement reads share. A database or log larger than [`FILE_LIMIT`], a
//! row larger than the largest header rpm writes, and packages that need more
//! than the budget make the database unreadable too, as a page that does not
//! hold does: none of them is one rpm keeps.

mod header;

use super::sqlite::{self, Database, Pages, Value};
use crate::{Filesystem, NailsError, Result};
use header::HEADER_MAX;
#[cfg(test)]
use header::{kind, tag};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Where rpm keeps its database, relative to the root, in the order they are
/// tried: the place since Fedora 36, then the one before.
pub const DATABASES: [&str; 2] = [
    "usr/lib/sysimage/rpm/rpmdb.sqlite",
    "var/lib/rpm/rpmdb.sqlite",
];

/// The suffix of the database's write-ahead log.
pub const WAL: &str = "-wal";

/// The suffix of the rollback journal SQLite keeps instead when it cannot
/// run in WAL mode.
pub const JOURNAL: &str = "-journal";

/// The table of installed packages.
const PACKAGES: &str = "Packages";

/// The most bytes of rpm's database file, or of its log, the reader takes
/// on, 4 GiB. rpm's database of a desktop holds a few hundred MiB, more after
/// many updates, since SQLite does not give back the room of what it
/// deleted, and its log grows by a whole transaction until rpm copies it into
/// the database at the end: a larger file is not one rpm keeps outside a
/// transaction stopped half way, and reading it would take long.
pub const FILE_LIMIT: u64 = 4 << 30;

/// The largest row of rpm's table of packages: the largest header rpm
/// writes, and the record's header before it (its size and two serial
/// types, eleven bytes at most).
const ROW_MAX: usize = HEADER_MAX + 16;

/// The memory the packages of one judgement's two databases may take, 256
/// MiB: a desktop's database lists a few hundred thousand files, which take
/// some tens of MiB here, about 64 bytes each.
pub const KEPT_LIMIT: usize = 256 << 20;

/// A file's flag: a configuration file (`RPMFILE_CONFIG`, bit 0).
pub const CONFIG: u32 = 0x01;
/// A file's flag: one rpm lists but does not install (`RPMFILE_GHOST`, bit
/// 6).
pub const GHOST: u32 = 0x40;
/// A file's state: installed by the package and still its own
/// (`RPMFILE_STATE_NORMAL`).
pub const NORMAL: u8 = 0;
/// The type bits of a file's mode, and those of a directory.
const S_IFMT: u16 = 0o170_000;
const S_IFDIR: u16 = 0o040_000;

/// What is known of rpm's database without reading it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stamp {
    /// Its size in bytes.
    pub size: u64,
    /// When it was last written.
    pub modified: SystemTime,
}

/// What the packages read from rpm's databases may still take in memory:
/// what a package keeps is taken from it before it is copied out of its
/// header, each string as the allocator holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    /// What it started with, in bytes.
    total: usize,
    /// What is left of it, in bytes.
    left: usize,
}

impl Budget {
    /// A budget of `bytes`.
    pub const fn new(bytes: usize) -> Self {
        Self {
            total: bytes,
            left: bytes,
        }
    }

    /// What it has left, in bytes.
    pub fn left(&self) -> usize {
        self.left
    }

    /// Take `bytes` from it, or say that the packages need more.
    fn take(&mut self, bytes: usize) -> std::result::Result<(), String> {
        self.left = self.left.checked_sub(bytes).ok_or_else(|| {
            format!(
                "packages that need more than the {} bytes of memory NAILS keeps for rpm's \
                 databases",
                self.total
            )
        })?;
        Ok(())
    }

    /// `text` as a string of its own, taken from the budget first.
    fn copy(&mut self, text: &str) -> std::result::Result<Box<str>, String> {
        self.take(Self::allocation(text.len()))?;
        Ok(text.into())
    }

    /// About what the allocator holds for a string of `len` bytes: its bytes
    /// and a word of its own, rounded up to sixteen. An empty string holds
    /// nothing.
    fn allocation(len: usize) -> usize {
        if len == 0 {
            0
        } else {
            (len + 8).next_multiple_of(16)
        }
    }
}

impl Default for Budget {
    /// A budget of [`KEPT_LIMIT`].
    fn default() -> Self {
        Self::new(KEPT_LIMIT)
    }
}

/// One file of a package.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct File {
    /// The index of its directory among its package's
    /// [`dirs`](Package::dirs).
    pub dir: u32,
    /// Its name in that directory.
    pub name: Box<str>,
    /// Its `RPMFILE_*` flags.
    pub flags: u32,
    /// Its mode.
    pub mode: u16,
    /// Its state, [`NORMAL`] when the header records none.
    pub state: u8,
}

impl File {
    /// The file `name` in the directory of index `dir`, with no flag, a plain
    /// file's mode of none and the state [`NORMAL`].
    fn new(dir: u32, name: Box<str>) -> Self {
        Self {
            dir,
            name,
            flags: 0,
            mode: 0,
            state: NORMAL,
        }
    }

    /// Whether the package installed the file as it is and keeps it: not a
    /// directory, which other packages share, nor a configuration file, which
    /// the operator edits, nor one rpm lists without installing it (a ghost,
    /// one another package replaced, one left out).
    pub fn is_own(&self) -> bool {
        self.flags & CONFIG == 0
            && self.flags & GHOST == 0
            && self.mode & S_IFMT != S_IFDIR
            && self.state == NORMAL
    }
}

/// One package rpm's database records.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Package {
    /// Its name.
    pub name: String,
    /// Its architecture, which a public key rpm records as a package lacks.
    pub arch: Option<String>,
    /// Its epoch, when it has one.
    pub epoch: Option<u32>,
    /// Its version.
    pub version: String,
    /// Its release.
    pub release: String,
    /// The directories its files are in, as its header records them: each
    /// absolute and ending in `/`, as rpm writes them.
    pub dirs: Vec<Box<str>>,
    /// Its files.
    pub files: Vec<File>,
}

impl Package {
    /// Its version as rpm writes it: `[epoch:]version-release`.
    pub fn evr(&self) -> String {
        match self.epoch {
            Some(epoch) => format!("{epoch}:{}-{}", self.version, self.release),
            None => format!("{}-{}", self.version, self.release),
        }
    }

    /// Whether it is a public key rpm records as the package `gpg-pubkey`,
    /// which installs no file.
    pub fn is_key(&self) -> bool {
        self.name == "gpg-pubkey" && self.arch.is_none()
    }

    /// The path of `file`, one of its files, as its header records it: its
    /// directory and its name.
    pub fn path(&self, file: &File) -> String {
        let dir = self.dirs.get(file.dir as usize).map_or("", |dir| dir);
        format!("{dir}{}", file.name)
    }
}

/// The package the header `blob` records, or why it cannot be read.
pub fn parse_header(blob: &[u8]) -> std::result::Result<Package, String> {
    header::parse(blob, &mut Budget::default())
}

/// The packages of the database `database`, in the order of its table, or
/// why they cannot be read, with what they keep taken from `budget`.
pub fn packages(
    database: &Database<'_>,
    budget: &mut Budget,
) -> std::result::Result<Vec<Package>, String> {
    let root = database
        .table_root(PACKAGES)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("no table {PACKAGES}"))?;
    let mut packages = Vec::new();
    let stopped = database
        .each_row(root, |row| {
            let package = match row.values.get(1) {
                Some(Value::Blob(blob)) => {
                    header::parse(blob, budget).map_err(|e| format!("package {}: {e}", row.rowid))
                }
                _ => Err(format!("package {} has no header", row.rowid)),
            };
            match package {
                Ok(package) => {
                    packages.push(package);
                    ControlFlow::Continue(())
                }
                Err(e) => ControlFlow::Break(e),
            }
        })
        .map_err(|e| e.to_string())?;
    match stopped {
        Some(e) => Err(e),
        None => Ok(packages),
    }
}

/// The packages of the database in `file` with its log `wal`, as bytes,
/// within a [`Budget`] of [`KEPT_LIMIT`].
pub fn parse_database(
    file: &[u8],
    wal: Option<&[u8]>,
) -> std::result::Result<Vec<Package>, String> {
    let database = Database::open(&file, wal.as_ref().map(|wal| wal as &dyn Pages))
        .map_err(|e| e.to_string())?
        .with_payload_limit(ROW_MAX);
    packages(&database, &mut Budget::default())
}

/// The size of the pieces [`Source`] reads a file in.
const CHUNK: usize = 1 << 18;

/// How many pieces [`Source`] keeps.
const CHUNKS: usize = 64;

/// A file read through the [`Filesystem`] seam, in pieces of [`CHUNK`] bytes
/// a few of which it keeps.
struct Source<'a, F: Filesystem> {
    fs: &'a F,
    path: &'a Path,
    len: u64,
    chunks: RefCell<BTreeMap<u64, Vec<u8>>>,
}

impl<F: Filesystem> Source<'_, F> {
    fn chunk(&self, index: u64) -> sqlite::Result<Vec<u8>> {
        if let Some(chunk) = self.chunks.borrow().get(&index) {
            return Ok(chunk.clone());
        }
        let offset = index * CHUNK as u64;
        let len = (self.len - offset).min(CHUNK as u64) as usize;
        let chunk = self
            .fs
            .read_file_range(self.path, offset, len)
            .map_err(|e| sqlite::Error::Read(e.to_string()))?;
        if chunk.len() != len {
            return Err(sqlite::Error::Read(format!(
                "{} is shorter than it was",
                self.path.display()
            )));
        }
        let mut chunks = self.chunks.borrow_mut();
        if chunks.len() >= CHUNKS {
            chunks.clear();
        }
        chunks.insert(index, chunk.clone());
        Ok(chunk)
    }
}

impl<F: Filesystem> Pages for Source<'_, F> {
    fn len(&self) -> u64 {
        self.len
    }

    fn read(&self, offset: u64, len: usize) -> sqlite::Result<Vec<u8>> {
        offset
            .checked_add(len as u64)
            .filter(|end| *end <= self.len)
            .ok_or_else(|| {
                sqlite::Error::Read(format!("{len} bytes at {offset} lie past the end"))
            })?;
        let mut bytes = Vec::with_capacity(len);
        while bytes.len() < len {
            let at = offset + bytes.len() as u64;
            let index = at / CHUNK as u64;
            let chunk = self.chunk(index)?;
            let from = (at % CHUNK as u64) as usize;
            let take = chunk.len().saturating_sub(from).min(len - bytes.len());
            if take == 0 {
                return Err(sqlite::Error::Read(format!(
                    "{} has no byte at {at}",
                    self.path.display()
                )));
            }
            bytes.extend_from_slice(&chunk[from..][..take]);
        }
        Ok(bytes)
    }
}

/// The files of one view of a database: the database, and its log and its
/// rollback journal when the view has them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Files {
    /// The database file.
    pub database: PathBuf,
    /// Its write-ahead log.
    pub wal: Option<PathBuf>,
    /// Its rollback journal.
    pub journal: Option<PathBuf>,
}

impl Files {
    /// The files next to `database`, each counted when it exists. A lookup
    /// of each is a `stat`, which changes no access time.
    pub fn beside<F: Filesystem>(fs: &F, database: &Path) -> Result<Self> {
        let next = |suffix: &str| -> Result<Option<PathBuf>> {
            let mut name = database.as_os_str().to_os_string();
            name.push(suffix);
            let path = PathBuf::from(name);
            Ok(stamp(fs, &path)?.map(|_| path))
        };
        Ok(Self {
            database: database.to_path_buf(),
            wal: next(WAL)?,
            journal: next(JOURNAL)?,
        })
    }

    /// The stamps of the files, to tell whether one was written while it was
    /// read.
    fn stamps<F: Filesystem>(&self, fs: &F) -> Result<[Option<Stamp>; 3]> {
        let of = |path: Option<&PathBuf>| match path {
            Some(path) => stamp(fs, path),
            None => Ok(None),
        };
        Ok([
            of(Some(&self.database))?,
            of(self.wal.as_ref())?,
            of(self.journal.as_ref())?,
        ])
    }
}

/// An error about `path` of the kind `kind`.
fn error(path: &Path, kind: std::io::ErrorKind, reason: String) -> NailsError {
    NailsError::io(path, std::io::Error::new(kind, reason))
}

/// The packages the database `files` hold, read through `fs` (see the
/// [parent module](super) on access times), with what they keep taken from
/// `budget`. An error when they cannot be read, when the database or its log
/// holds more than [`FILE_LIMIT`] bytes, when a rollback journal that is not
/// empty says a transaction was stopped half way (SQLite would roll it back
/// first), or when a file is written while it is read, twice in a row.
pub fn read_packages<F: Filesystem>(
    fs: &F,
    files: &Files,
    budget: &mut Budget,
) -> Result<Vec<Package>> {
    let mut last = None;
    for _ in 0..2 {
        let before = files.stamps(fs)?;
        if let [_, _, Some(journal)] = before
            && journal.size > 0
        {
            return Err(error(
                &files.database,
                std::io::ErrorKind::InvalidData,
                "an rpm transaction was stopped half way and left its rollback journal".to_string(),
            ));
        }
        let Some(database) = before[0] else {
            return Err(error(
                &files.database,
                std::io::ErrorKind::NotFound,
                "no such file".to_string(),
            ));
        };
        for (path, stamp) in [
            (Some(&files.database), before[0]),
            (files.wal.as_ref(), before[1]),
        ] {
            if let (Some(path), Some(stamp)) = (path, stamp)
                && stamp.size > FILE_LIMIT
            {
                return Err(error(
                    path,
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "{} bytes, more than rpm keeps in its database or its log ({FILE_LIMIT})",
                        stamp.size
                    ),
                ));
            }
        }
        let main = Source {
            fs,
            path: &files.database,
            len: database.size,
            chunks: RefCell::new(BTreeMap::new()),
        };
        let wal = match (&files.wal, before[1]) {
            (Some(path), Some(stamp)) => Some(Source {
                fs,
                path,
                len: stamp.size,
                chunks: RefCell::new(BTreeMap::new()),
            }),
            _ => None,
        };
        // A read that is thrown away gives back what it took.
        let mut kept = *budget;
        let read = Database::open(&main, wal.as_ref().map(|wal| wal as &dyn Pages))
            .map_err(|e| e.to_string())
            .and_then(|database| packages(&database.with_payload_limit(ROW_MAX), &mut kept));
        if files.stamps(fs)? != before {
            last = Some(error(
                &files.database,
                std::io::ErrorKind::Interrupted,
                "rpm wrote its database while it was read".to_string(),
            ));
            continue;
        }
        *budget = kept;
        return read
            .map_err(|reason| error(&files.database, std::io::ErrorKind::InvalidData, reason));
    }
    Err(last.expect("the loop sets it before it goes round again"))
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

#[cfg(test)]
#[path = "rpm_tests.rs"]
mod tests;
