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
//! states). A header it cannot read makes the database unreadable: rpm
//! itself would not trust such a database either.

use super::sqlite::{self, Database, Pages, Value};
use crate::{Filesystem, NailsError, Result};
use std::cell::RefCell;
use std::collections::BTreeMap;
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

/// The most index entries and data bytes rpm allows a header
/// (`HEADER_TAGS_MAX`, `HEADER_DATA_MAX` in lib/header_internal.h), each one
/// less than a power of two, so a size within it has no bit outside it.
const TAGS_MAX: usize = 0xffff;
const DATA_MAX: usize = 0x0fff_ffff;

/// The tags read (lib/rpmtag.h).
mod tag {
    pub const NAME: u32 = 1000;
    pub const VERSION: u32 = 1001;
    pub const RELEASE: u32 = 1002;
    pub const EPOCH: u32 = 1003;
    pub const ARCH: u32 = 1022;
    pub const OLDFILENAMES: u32 = 1027;
    pub const FILESTATES: u32 = 1029;
    pub const FILEMODES: u32 = 1030;
    pub const FILEFLAGS: u32 = 1037;
    pub const DIRINDEXES: u32 = 1116;
    pub const BASENAMES: u32 = 1117;
    pub const DIRNAMES: u32 = 1118;
}

/// The types read (`rpmTagType`).
mod kind {
    pub const CHAR: u32 = 1;
    pub const INT8: u32 = 2;
    pub const INT16: u32 = 3;
    pub const INT32: u32 = 4;
    pub const STRING: u32 = 6;
    pub const STRING_ARRAY: u32 = 8;
    pub const I18NSTRING: u32 = 9;
}

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

/// One file of a package.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct File {
    /// Its absolute path.
    pub path: String,
    /// Its `RPMFILE_*` flags.
    pub flags: u32,
    /// Its mode.
    pub mode: u16,
    /// Its state, [`NORMAL`] when the header records none.
    pub state: u8,
}

impl File {
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
}

/// One index entry of a header.
#[derive(Clone, Copy)]
struct Entry {
    kind: u32,
    offset: usize,
    count: usize,
}

/// A header being read: its entries by tag and its data.
struct Header<'a> {
    entries: BTreeMap<u32, Entry>,
    data: &'a [u8],
}

fn bad<T>(reason: impl Into<String>) -> std::result::Result<T, String> {
    Err(reason.into())
}

fn be32(bytes: &[u8], at: usize) -> Option<u32> {
    let b = bytes.get(at..at.checked_add(4)?)?;
    Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

impl<'a> Header<'a> {
    fn parse(blob: &'a [u8]) -> std::result::Result<Self, String> {
        let (Some(il), Some(dl)) = (be32(blob, 0), be32(blob, 4)) else {
            return bad("a header shorter than its sizes");
        };
        let (il, dl) = (il as usize, dl as usize);
        if il == 0 || il & !TAGS_MAX != 0 || dl & !DATA_MAX != 0 {
            return bad("a header of a size rpm does not write");
        }
        let start = 8 + 16 * il;
        let Some(data) = blob.get(start..start + dl) else {
            return bad("a header shorter than its sizes");
        };
        let mut entries = BTreeMap::new();
        for i in 0..il {
            let at = 8 + 16 * i;
            let field = |n: usize| be32(blob, at + 4 * n).unwrap_or_default();
            let entry = Entry {
                kind: field(1),
                offset: field(2) as usize,
                count: field(3) as usize,
            };
            if entry.offset > dl {
                return bad("a header entry past its data");
            }
            entries.entry(field(0)).or_insert(entry);
        }
        Ok(Self { entries, data })
    }

    /// The strings of `tag`: `None` when the header has no such tag.
    fn strings(&self, tag: u32) -> std::result::Result<Option<Vec<String>>, String> {
        let Some(entry) = self.entries.get(&tag).copied() else {
            return Ok(None);
        };
        if !matches!(
            entry.kind,
            kind::STRING | kind::STRING_ARRAY | kind::I18NSTRING
        ) {
            return bad(format!("tag {tag} is no string"));
        }
        // A plain string counts once, whatever the entry says.
        let count = if entry.kind == kind::STRING {
            1
        } else {
            entry.count
        };
        // Each string takes a byte at least, so a count past the data ends
        // at the data's end.
        let mut at = entry.offset;
        let mut strings = Vec::new();
        for _ in 0..count {
            let rest = self.data.get(at..).unwrap_or_default();
            let Some(end) = rest.iter().position(|&byte| byte == 0) else {
                return bad(format!("a string of tag {tag} runs past its data"));
            };
            let text = std::str::from_utf8(&rest[..end])
                .map_err(|_| format!("a string of tag {tag} is not UTF-8"))?;
            strings.push(text.to_string());
            at += end + 1;
        }
        Ok(Some(strings))
    }

    /// The one string of `tag`.
    fn string(&self, tag: u32) -> std::result::Result<Option<String>, String> {
        Ok(self
            .strings(tag)?
            .and_then(|strings| strings.into_iter().next()))
    }

    /// The integers of `tag`, of the width its type gives: `None` when the
    /// header has no such tag.
    fn integers(&self, tag: u32) -> std::result::Result<Option<Vec<u32>>, String> {
        let Some(entry) = self.entries.get(&tag).copied() else {
            return Ok(None);
        };
        let width = match entry.kind {
            kind::CHAR | kind::INT8 => 1,
            kind::INT16 => 2,
            kind::INT32 => 4,
            _ => return bad(format!("tag {tag} is no integer")),
        };
        let bytes = entry
            .count
            .checked_mul(width)
            .and_then(|len| self.data.get(entry.offset..entry.offset.checked_add(len)?))
            .ok_or_else(|| format!("tag {tag} runs past its data"))?;
        Ok(Some(
            bytes
                .chunks_exact(width)
                .map(|b| match b {
                    [byte] => u32::from(*byte),
                    [high, low] => u32::from(u16::from_be_bytes([*high, *low])),
                    [a, b, c, d] => u32::from_be_bytes([*a, *b, *c, *d]),
                    _ => unreachable!("a width of 1, 2 or 4"),
                })
                .collect(),
        ))
    }

    /// The files: each path with its flags, mode and state, which a header
    /// without them gives as none, a plain file and [`NORMAL`].
    fn files(&self) -> std::result::Result<Vec<File>, String> {
        let paths = match self.strings(tag::BASENAMES)? {
            Some(basenames) => {
                let dirnames = self.strings(tag::DIRNAMES)?.unwrap_or_default();
                let indexes = self.integers(tag::DIRINDEXES)?.unwrap_or_default();
                if indexes.len() != basenames.len() {
                    return bad("as many directory indexes as file names");
                }
                basenames
                    .iter()
                    .zip(&indexes)
                    .map(|(base, &index)| {
                        dirnames
                            .get(index as usize)
                            .map(|dir| format!("{dir}{base}"))
                            .ok_or_else(|| "a directory index past the directories".to_string())
                    })
                    .collect::<std::result::Result<Vec<_>, _>>()?
            }
            None => self.strings(tag::OLDFILENAMES)?.unwrap_or_default(),
        };
        let per_file = |tag: u32| -> std::result::Result<Vec<u32>, String> {
            match self.integers(tag)? {
                None => Ok(vec![0; paths.len()]),
                Some(values) if values.len() == paths.len() => Ok(values),
                Some(_) => bad(format!("tag {tag} has not one value per file")),
            }
        };
        let (flags, modes, states) = (
            per_file(tag::FILEFLAGS)?,
            per_file(tag::FILEMODES)?,
            per_file(tag::FILESTATES)?,
        );
        Ok(paths
            .into_iter()
            .enumerate()
            .map(|(i, path)| File {
                path,
                flags: flags[i],
                mode: modes[i] as u16,
                state: states[i] as u8,
            })
            .collect())
    }
}

/// The package the header `blob` records, or why it cannot be read.
pub fn parse_header(blob: &[u8]) -> std::result::Result<Package, String> {
    let header = Header::parse(blob)?;
    let required = |tag: u32, what: &str| -> std::result::Result<String, String> {
        header
            .string(tag)?
            .ok_or_else(|| format!("a header without its {what}"))
    };
    let epoch = match header.integers(tag::EPOCH)? {
        Some(values) => values.first().copied(),
        None => None,
    };
    Ok(Package {
        name: required(tag::NAME, "name")?,
        arch: header.string(tag::ARCH)?,
        epoch,
        version: required(tag::VERSION, "version")?,
        release: required(tag::RELEASE, "release")?,
        files: header.files()?,
    })
}

/// The packages of the database `database`, in the order of its table, or
/// why they cannot be read.
pub fn packages(database: &Database<'_>) -> std::result::Result<Vec<Package>, String> {
    let root = database
        .table_root(PACKAGES)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("no table {PACKAGES}"))?;
    database
        .rows(root)
        .map_err(|e| e.to_string())?
        .iter()
        .map(|row| match row.values.get(1) {
            Some(Value::Blob(blob)) => {
                parse_header(blob).map_err(|e| format!("package {}: {e}", row.rowid))
            }
            _ => bad(format!("package {} has no header", row.rowid)),
        })
        .collect()
}

/// The packages of the database in `file` with its log `wal`, as bytes.
pub fn parse_database(
    file: &[u8],
    wal: Option<&[u8]>,
) -> std::result::Result<Vec<Package>, String> {
    let database = Database::open(&file, wal.as_ref().map(|wal| wal as &dyn Pages))
        .map_err(|e| e.to_string())?;
    packages(&database)
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
/// [parent module](super) on access times). An error when they cannot be
/// read, when a rollback journal that is not empty says a transaction was
/// stopped half way (SQLite would roll it back first), or when a file is
/// written while it is read, twice in a row.
pub fn read_packages<F: Filesystem>(fs: &F, files: &Files) -> Result<Vec<Package>> {
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
        let read = Database::open(&main, wal.as_ref().map(|wal| wal as &dyn Pages))
            .map_err(|e| e.to_string())
            .and_then(|database| packages(&database));
        if files.stamps(fs)? != before {
            last = Some(error(
                &files.database,
                std::io::ErrorKind::Interrupted,
                "rpm wrote its database while it was read".to_string(),
            ));
            continue;
        }
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
