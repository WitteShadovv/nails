// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The rows of a table of a SQLite database file, read without SQLite.
//!
//! rpm keeps its database in SQLite. NAILS reads it without linking SQLite,
//! whose own reads of the file would change its access time and could write
//! next to it (a `-shm` file, a recovered journal): [`Database`] reads the
//! pages it needs through a [`Pages`] source, which the caller backs with
//! reads that leave access times alone, and never writes. It reads what the
//! [file format](https://www.sqlite.org/fileformat2.html) says a table holds:
//!
//! - the database header (page size, the bytes each page reserves, the text
//!   encoding);
//! - the write-ahead log, when one is given: SQLite in WAL mode (as rpm runs
//!   it) writes a transaction to `<db>-wal` first and copies it into the
//!   database only at a checkpoint, so the log's committed frames are part of
//!   the database. A frame counts as the recovery of `sqlite3WalRecover`
//!   counts it: its salts are the log header's and its checksum, carried on
//!   from the frame before, holds; the frames up to the last such frame that
//!   ends a transaction are committed, and of those the last frame of a page
//!   is the page;
//! - `sqlite_schema`, the table on page 1 that names every table and its
//!   root page;
//! - a table's b-tree, interior and leaf pages, each leaf cell's record and
//!   the overflow pages its payload goes on in.
//!
//! The file is whatever the decoy's disk or a hidden session holds, so every
//! read is checked: a page out of the file, a page the walk has already been
//! to (a loop), a cell or a record that does not fit, and an encoding other
//! than UTF-8 are errors, never a panic. The `rpmdb` fuzz target drives it
//! with hostile input.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// The sixteen bytes a SQLite database file starts with.
const MAGIC: &[u8; 16] = b"SQLite format 3\0";

/// The size of the database header on page 1.
const HEADER: usize = 100;

/// The size of the write-ahead log's header, and of each frame's.
const WAL_HEADER: usize = 32;
const FRAME_HEADER: usize = 24;

/// Why a database cannot be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The source could not give the bytes asked for.
    Read(String),
    /// The file is not a SQLite database the format allows, for the reason
    /// given.
    Malformed(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Read(reason) => write!(f, "{reason}"),
            Error::Malformed(reason) => write!(f, "not a SQLite database NAILS can read: {reason}"),
        }
    }
}

impl std::error::Error for Error {}

/// A result of this module.
pub type Result<T> = std::result::Result<T, Error>;

fn malformed<T>(reason: impl Into<String>) -> Result<T> {
    Err(Error::Malformed(reason.into()))
}

/// Where the bytes of a file come from: the database file, or its
/// write-ahead log.
pub trait Pages {
    /// The file's size in bytes.
    fn len(&self) -> u64;

    /// Whether the file holds no byte.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// `len` bytes from `offset` on, all of which lie in the file.
    fn read(&self, offset: u64, len: usize) -> Result<Vec<u8>>;
}

/// The bytes at `offset` of `bytes`, `len` of them.
fn slice(bytes: &[u8], offset: u64, len: usize) -> Result<Vec<u8>> {
    usize::try_from(offset)
        .ok()
        .and_then(|start| bytes.get(start..start.checked_add(len)?))
        .map(<[u8]>::to_vec)
        .ok_or_else(|| Error::Read(format!("{len} bytes at {offset} lie past the end")))
}

impl Pages for &[u8] {
    fn len(&self) -> u64 {
        <[u8]>::len(self) as u64
    }

    fn read(&self, offset: u64, len: usize) -> Result<Vec<u8>> {
        slice(self, offset, len)
    }
}

impl Pages for Vec<u8> {
    fn len(&self) -> u64 {
        self.as_slice().len() as u64
    }

    fn read(&self, offset: u64, len: usize) -> Result<Vec<u8>> {
        slice(self, offset, len)
    }
}

/// One value of a record.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// `NULL`.
    Null,
    /// An integer.
    Integer(i64),
    /// A floating point number.
    Real(f64),
    /// Text, as UTF-8.
    Text(String),
    /// A blob.
    Blob(Vec<u8>),
}

/// One row of a table: its rowid and its columns' values.
#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    /// The rowid (an `INTEGER PRIMARY KEY` column is stored as `NULL` in the
    /// record and is this).
    pub rowid: i64,
    /// The record's values, in column order.
    pub values: Vec<Value>,
}

/// The committed frames of a log (page number to the offset of its data),
/// the log's page size and the database's size in pages after its last
/// committed transaction.
type Frames = (BTreeMap<u32, u64>, Option<usize>, Option<u32>);

/// A database file and its write-ahead log, read page by page.
pub struct Database<'a> {
    file: &'a dyn Pages,
    wal: Option<&'a dyn Pages>,
    page_size: usize,
    usable: usize,
    pages: u32,
    /// The committed frames of the log: page number to the offset of its
    /// page data in the log.
    frames: BTreeMap<u32, u64>,
}

impl fmt::Debug for Database<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Database")
            .field("page_size", &self.page_size)
            .field("pages", &self.pages)
            .field("frames", &self.frames.len())
            .finish_non_exhaustive()
    }
}

/// The page size a header's two bytes give: a power of two from 512 to
/// 65536, which the value 1 stands for.
fn page_size(raw: u32) -> Option<usize> {
    let size = if raw == 1 { 65536 } else { raw };
    ((512..=65536).contains(&size) && size.is_power_of_two()).then_some(size as usize)
}

fn be16(bytes: &[u8], at: usize) -> Result<u16> {
    bytes
        .get(at..at + 2)
        .map(|b| u16::from_be_bytes([b[0], b[1]]))
        .ok_or_else(|| Error::Malformed(format!("no 2 bytes at {at}")))
}

fn be32(bytes: &[u8], at: usize) -> Result<u32> {
    bytes
        .get(at..at + 4)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or_else(|| Error::Malformed(format!("no 4 bytes at {at}")))
}

/// The varint at `at` and the bytes it takes: up to eight bytes of seven
/// bits each, high bit first, and a ninth of eight bits.
fn varint(bytes: &[u8], at: usize) -> Result<(u64, usize)> {
    let mut value: u64 = 0;
    for i in 0..9 {
        let Some(&byte) = bytes.get(at + i) else {
            return malformed(format!("a varint at {at} runs past its page"));
        };
        if i == 8 {
            return Ok(((value << 8) + u64::from(byte), 9));
        }
        value = (value << 7) + u64::from(byte & 0x7f);
        if byte & 0x80 == 0 {
            return Ok((value, i + 1));
        }
    }
    unreachable!("the ninth byte returns")
}

/// The WAL checksum of `data` (a multiple of eight bytes), carried on from
/// `sum`, its words read big-endian when `big`.
fn checksum(sum: (u32, u32), data: &[u8], big: bool) -> (u32, u32) {
    let (mut s0, mut s1) = sum;
    let (pairs, _) = data.as_chunks::<8>();
    for pair in pairs {
        let word = |b: &[u8]| {
            let b = [b[0], b[1], b[2], b[3]];
            if big {
                u32::from_be_bytes(b)
            } else {
                u32::from_le_bytes(b)
            }
        };
        s0 = s0.wrapping_add(word(&pair[..4])).wrapping_add(s1);
        s1 = s1.wrapping_add(word(&pair[4..])).wrapping_add(s0);
    }
    (s0, s1)
}

impl<'a> Database<'a> {
    /// The database in `file`, with its write-ahead log `wal` when there is
    /// one: an empty or missing log holds nothing, as SQLite reads it.
    pub fn open(file: &'a dyn Pages, wal: Option<&'a dyn Pages>) -> Result<Self> {
        let wal = wal.filter(|wal| !wal.is_empty());
        let header = if file.len() >= HEADER as u64 {
            Some(file.read(0, HEADER)?)
        } else if file.is_empty() {
            None
        } else {
            return malformed("shorter than its header");
        };
        let mut page_size_found = None;
        let mut reserved = 0;
        if let Some(header) = &header {
            if &header[..16] != MAGIC {
                return malformed("no SQLite header");
            }
            page_size_found = Some(
                page_size(u32::from(be16(header, 16)?))
                    .ok_or_else(|| Error::Malformed("a page size SQLite does not use".into()))?,
            );
            reserved = usize::from(header[20]);
            let encoding = be32(header, 56)?;
            if encoding > 1 {
                return malformed("text that is not UTF-8");
            }
        }
        let (frames, wal_page_size, wal_pages) = match wal {
            Some(wal) => Self::frames(wal)?,
            None => (BTreeMap::new(), None, None),
        };
        let page_size = match (page_size_found, wal_page_size) {
            (Some(file), Some(wal)) if file != wal && !frames.is_empty() => {
                return malformed("the write-ahead log has another page size");
            }
            (Some(size), _) | (None, Some(size)) => size,
            (None, None) => return malformed("an empty file"),
        };
        let usable = page_size
            .checked_sub(reserved)
            .filter(|usable| *usable >= 480)
            .ok_or_else(|| Error::Malformed("pages reserve too many bytes".into()))?;
        let pages = match wal_pages {
            Some(pages) => pages,
            None => u32::try_from(file.len() / page_size as u64)
                .map_err(|_| Error::Malformed("more pages than SQLite allows".into()))?,
        };
        let database = Self {
            file,
            wal,
            page_size,
            usable,
            pages,
            frames,
        };
        if header.is_none() {
            // The log alone holds page 1: its header must be SQLite's.
            let first = database.page(1)?;
            if &first[..16] != MAGIC {
                return malformed("no SQLite header");
            }
        }
        Ok(database)
    }

    /// The committed frames of the log `wal`, its page size and the
    /// database's size in pages after its last committed transaction (see
    /// the [module docs](self)). A log whose header does not hold has no
    /// frame.
    fn frames(wal: &dyn Pages) -> Result<Frames> {
        let none = Ok((BTreeMap::new(), None, None));
        if wal.len() < WAL_HEADER as u64 {
            return none;
        }
        let header = wal.read(0, WAL_HEADER)?;
        let magic = be32(&header, 0)?;
        if magic & !1 != 0x377f_0682 || be32(&header, 4)? != 3_007_000 {
            return none;
        }
        let big = magic & 1 == 1;
        let Some(size) = page_size(be32(&header, 8)?) else {
            return none;
        };
        let salts = (be32(&header, 16)?, be32(&header, 20)?);
        let mut sum = checksum((0, 0), &header[..24], big);
        if sum != (be32(&header, 24)?, be32(&header, 28)?) {
            return none;
        }
        let mut committed = BTreeMap::new();
        let mut pending = BTreeMap::new();
        let mut pages = None;
        let frame = (FRAME_HEADER + size) as u64;
        let mut offset = WAL_HEADER as u64;
        while offset + frame <= wal.len() {
            let bytes = wal.read(offset, frame as usize)?;
            let number = be32(&bytes, 0)?;
            let commit = be32(&bytes, 4)?;
            if number == 0 || (be32(&bytes, 8)?, be32(&bytes, 12)?) != salts {
                break;
            }
            sum = checksum(sum, &bytes[..8], big);
            sum = checksum(sum, &bytes[FRAME_HEADER..], big);
            if sum != (be32(&bytes, 16)?, be32(&bytes, 20)?) {
                break;
            }
            pending.insert(number, offset + FRAME_HEADER as u64);
            if commit != 0 {
                committed.append(&mut pending);
                pages = Some(commit);
            }
            offset += frame;
        }
        Ok((committed, Some(size), pages))
    }

    /// The bytes of page `number` (from 1), from the log when it holds the
    /// page.
    fn page(&self, number: u32) -> Result<Vec<u8>> {
        if number == 0 || number > self.pages {
            return malformed(format!("page {number} lies outside the database"));
        }
        if let (Some(wal), Some(&offset)) = (self.wal, self.frames.get(&number)) {
            return wal.read(offset, self.page_size);
        }
        let offset = u64::from(number - 1) * self.page_size as u64;
        if offset + self.page_size as u64 > self.file.len() {
            return malformed(format!("page {number} lies past the end of the file"));
        }
        self.file.read(offset, self.page_size)
    }

    /// The root page of the table `name`, as `sqlite_schema` names it:
    /// `None` when there is no such table.
    pub fn table_root(&self, name: &str) -> Result<Option<u32>> {
        for row in self.rows(1)? {
            let is_table = matches!(row.values.first(), Some(Value::Text(kind)) if kind == "table");
            let named = matches!(row.values.get(1), Some(Value::Text(table)) if table == name);
            if !(is_table && named) {
                continue;
            }
            // A virtual table's row names no page (0).
            return match row.values.get(3) {
                Some(Value::Integer(root)) => u32::try_from(*root)
                    .ok()
                    .filter(|root| *root != 0)
                    .map(Some)
                    .ok_or_else(|| Error::Malformed(format!("table {name} has no root page"))),
                _ => malformed(format!("table {name} has no root page")),
            };
        }
        Ok(None)
    }

    /// Every row of the table whose b-tree starts at page `root`, in rowid
    /// order.
    pub fn rows(&self, root: u32) -> Result<Vec<Row>> {
        let mut rows = Vec::new();
        let mut seen = BTreeSet::new();
        let mut stack = vec![root];
        // Children are pushed right to left, so the leftmost is walked first.
        while let Some(number) = stack.pop() {
            if !seen.insert(number) {
                return malformed(format!("page {number} is reached twice"));
            }
            let page = self.page(number)?;
            let start = if number == 1 { HEADER } else { 0 };
            let kind = *page
                .get(start)
                .ok_or_else(|| Error::Malformed("an empty page".into()))?;
            let cells = usize::from(be16(&page, start + 3)?);
            match kind {
                0x05 => {
                    let header = start + 12;
                    let mut children = Vec::with_capacity(cells + 1);
                    for i in 0..cells {
                        let at = usize::from(be16(&page, header + 2 * i)?);
                        children.push(be32(&page, at)?);
                    }
                    children.push(be32(&page, start + 8)?);
                    stack.extend(children.into_iter().rev());
                }
                0x0d => {
                    let header = start + 8;
                    for i in 0..cells {
                        let at = usize::from(be16(&page, header + 2 * i)?);
                        rows.push(self.leaf_cell(&page, at, &mut seen)?);
                    }
                }
                other => return malformed(format!("page {number} is no table page ({other})")),
            }
        }
        Ok(rows)
    }

    /// The row of the table leaf cell at `at` of `page`, its payload read on
    /// through its overflow pages, each added to `seen`.
    fn leaf_cell(&self, page: &[u8], at: usize, seen: &mut BTreeSet<u32>) -> Result<Row> {
        let (size, used) = varint(page, at)?;
        let (rowid, used_rowid) = varint(page, at + used)?;
        let start = at + used + used_rowid;
        let size = usize::try_from(size)
            .ok()
            .filter(|size| *size <= self.pages as usize * self.usable)
            .ok_or_else(|| Error::Malformed("a payload larger than the database".into()))?;
        let usable = self.usable;
        let max_local = usable - 35;
        let local = if size <= max_local {
            size
        } else {
            let min_local = (usable - 12) * 32 / 255 - 23;
            let k = min_local + (size - min_local) % (usable - 4);
            if k <= max_local { k } else { min_local }
        };
        let end = start + local;
        if end > usable.min(page.len()) {
            return malformed("a cell runs past its page");
        }
        let mut payload = page[start..end].to_vec();
        if local < size {
            let mut next = be32(page, end)?;
            while payload.len() < size {
                if !seen.insert(next) {
                    return malformed(format!("overflow page {next} is reached twice"));
                }
                let overflow = self.page(next)?;
                let take = (size - payload.len()).min(usable - 4);
                payload.extend_from_slice(&overflow[4..4 + take]);
                next = be32(&overflow, 0)?;
            }
        }
        Ok(Row {
            rowid: rowid as i64,
            values: record(&payload)?,
        })
    }
}

/// The values of the record `payload`.
pub fn record(payload: &[u8]) -> Result<Vec<Value>> {
    let (header_size, mut at) = varint(payload, 0)?;
    let header_size = usize::try_from(header_size)
        .ok()
        .filter(|size| *size <= payload.len() && *size >= at)
        .ok_or_else(|| Error::Malformed("a record header larger than its record".into()))?;
    let mut body = header_size;
    let mut values = Vec::new();
    while at < header_size {
        let (serial, used) = varint(&payload[..header_size], at)?;
        at += used;
        let width = match serial {
            0 | 8 | 9 => 0,
            1..=4 => serial as usize,
            5 => 6,
            6 | 7 => 8,
            10 | 11 => return malformed("a reserved serial type"),
            n => ((n - 12) / 2) as usize,
        };
        let bytes = payload
            .get(body..body.saturating_add(width))
            .ok_or_else(|| Error::Malformed("a value runs past its record".into()))?;
        body += width;
        // A big-endian two's complement integer of `bytes.len()` bytes,
        // widened to eight with its sign.
        let integer = |bytes: &[u8]| {
            let sign = if bytes.first().is_some_and(|b| b & 0x80 != 0) {
                0xff
            } else {
                0
            };
            let mut wide = [sign; 8];
            wide[8 - bytes.len()..].copy_from_slice(bytes);
            i64::from_be_bytes(wide)
        };
        values.push(match serial {
            0 => Value::Null,
            8 => Value::Integer(0),
            9 => Value::Integer(1),
            1..=6 => Value::Integer(integer(bytes)),
            7 => Value::Real(f64::from_bits(integer(bytes) as u64)),
            n if n % 2 == 0 => Value::Blob(bytes.to_vec()),
            _ => Value::Text(
                String::from_utf8(bytes.to_vec())
                    .map_err(|_| Error::Malformed("text that is not UTF-8".into()))?,
            ),
        });
    }
    if body != payload.len() {
        return malformed("a record longer than its values");
    }
    Ok(values)
}

#[cfg(test)]
#[path = "sqlite_tests.rs"]
mod tests;
