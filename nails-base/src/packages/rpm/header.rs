// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! rpm's header of one package, as `headerExport()` writes it.
//!
//! The header is whatever a database on the decoy or in a hidden session
//! holds, so its strings and integers are read where they lie, one at a time,
//! and only what [`Package`] keeps is copied out, each piece taken from a
//! [`Budget`] before it is. A file's path is its directory and its name, the
//! directory kept once for all of its files, as the header keeps it: one
//! header of a few hundred KiB lists hundreds of thousands of files.

use super::{Budget, File, Package};
use std::collections::BTreeMap;

/// The most index entries and data bytes rpm allows a header
/// (`HEADER_TAGS_MAX`, `HEADER_DATA_MAX` in lib/header_internal.h), each one
/// less than a power of two, so a size within it has no bit outside it.
pub(super) const TAGS_MAX: usize = 0xffff;
pub(super) const DATA_MAX: usize = 0x0fff_ffff;

/// The largest header rpm writes: its two sizes, its index entries and its
/// data.
pub(super) const HEADER_MAX: usize = 8 + 16 * TAGS_MAX + DATA_MAX;

/// The tags read (lib/rpmtag.h).
pub(super) mod tag {
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
pub(super) mod kind {
    pub const CHAR: u32 = 1;
    pub const INT8: u32 = 2;
    pub const INT16: u32 = 3;
    pub const INT32: u32 = 4;
    pub const STRING: u32 = 6;
    pub const STRING_ARRAY: u32 = 8;
    pub const I18NSTRING: u32 = 9;
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

/// The strings of an entry, read where they lie one after the other.
struct Strings<'a> {
    tag: u32,
    rest: &'a [u8],
    left: usize,
}

impl Strings<'_> {
    /// How many strings the entry says it holds and are not read yet.
    fn len(&self) -> usize {
        self.left
    }
}

impl<'a> Iterator for Strings<'a> {
    type Item = std::result::Result<&'a str, String>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.left == 0 {
            return None;
        }
        self.left -= 1;
        let Some(end) = self.rest.iter().position(|&byte| byte == 0) else {
            self.left = 0;
            return Some(bad(format!(
                "a string of tag {} runs past its data",
                self.tag
            )));
        };
        let (text, rest) = (&self.rest[..end], &self.rest[end + 1..]);
        self.rest = rest;
        Some(
            std::str::from_utf8(text)
                .map_err(|_| format!("a string of tag {} is not UTF-8", self.tag)),
        )
    }
}

/// The integers of an entry, each of the width its type gives.
struct Integers<'a> {
    bytes: &'a [u8],
    width: usize,
}

impl Integers<'_> {
    fn len(&self) -> usize {
        self.bytes.len() / self.width
    }

    fn first(&self) -> Option<u32> {
        (self.len() != 0).then(|| self.get(0))
    }

    /// The integer at `index`, which is less than [`Self::len`].
    fn get(&self, index: usize) -> u32 {
        match &self.bytes[index * self.width..][..self.width] {
            [byte] => u32::from(*byte),
            [high, low] => u32::from(u16::from_be_bytes([*high, *low])),
            [a, b, c, d] => u32::from_be_bytes([*a, *b, *c, *d]),
            _ => unreachable!("a width of 1, 2 or 4"),
        }
    }
}

/// A package's files as its header lists them.
#[derive(Default)]
struct Listing {
    dirs: Vec<Box<str>>,
    files: Vec<File>,
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

    /// The strings of `tag`: `None` when the header has no such tag. Each
    /// takes a byte at least, so an entry that says it holds more strings than
    /// it has bytes left runs past its data.
    fn strings(&self, tag: u32) -> std::result::Result<Option<Strings<'a>>, String> {
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
        let rest = self.data.get(entry.offset..).unwrap_or_default();
        if count > rest.len() {
            return bad(format!("a string of tag {tag} runs past its data"));
        }
        Ok(Some(Strings {
            tag,
            rest,
            left: count,
        }))
    }

    /// The one string of `tag`.
    fn string(&self, tag: u32) -> std::result::Result<Option<String>, String> {
        match self.strings(tag)?.and_then(|mut strings| strings.next()) {
            Some(text) => Ok(Some(text?.to_string())),
            None => Ok(None),
        }
    }

    /// The integers of `tag`, of the width its type gives: `None` when the
    /// header has no such tag.
    fn integers(&self, tag: u32) -> std::result::Result<Option<Integers<'a>>, String> {
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
        Ok(Some(Integers { bytes, width }))
    }

    /// The integers of `tag`, one for each of `files` files: `None` when the
    /// header has no such tag.
    fn per_file(
        &self,
        tag: u32,
        files: usize,
    ) -> std::result::Result<Option<Integers<'a>>, String> {
        match self.integers(tag)? {
            Some(values) if values.len() != files => {
                bad(format!("tag {tag} has not one value per file"))
            }
            values => Ok(values),
        }
    }

    /// The files: each one's directory and name, with its flags, mode and
    /// state, which a header without them gives as none, a plain file and
    /// [`NORMAL`](super::NORMAL). What is kept is taken from `budget` before
    /// it is copied out.
    fn files(&self, budget: &mut Budget) -> std::result::Result<Listing, String> {
        let mut listing = Listing::default();
        match self.strings(tag::BASENAMES)? {
            Some(basenames) => {
                let dirnames = self.strings(tag::DIRNAMES)?;
                let indexes = self.integers(tag::DIRINDEXES)?;
                let count = basenames.len();
                if indexes.as_ref().map_or(0, Integers::len) != count {
                    return bad("as many directory indexes as file names");
                }
                if let Some(dirnames) = dirnames {
                    budget.take(dirnames.len() * size_of::<Box<str>>())?;
                    listing.dirs.reserve_exact(dirnames.len());
                    for dir in dirnames {
                        listing.dirs.push(budget.copy(dir?)?);
                    }
                }
                budget.take(count * size_of::<File>())?;
                listing.files.reserve_exact(count);
                for (i, name) in basenames.enumerate() {
                    let name = name?;
                    let dir = indexes.as_ref().map_or(0, |indexes| indexes.get(i));
                    if dir as usize >= listing.dirs.len() {
                        return bad("a directory index past the directories");
                    }
                    listing.files.push(File::new(dir, budget.copy(name)?));
                }
            }
            None => {
                if let Some(paths) = self.strings(tag::OLDFILENAMES)? {
                    budget.take(paths.len() * size_of::<File>())?;
                    listing.files.reserve_exact(paths.len());
                    for path in paths {
                        let path = path?;
                        let (dir, name) = path.split_at(path_dir(path));
                        // rpm lists a package's files in order, so the files
                        // of one directory follow one another.
                        if listing.dirs.last().is_none_or(|last| **last != *dir) {
                            budget.take(size_of::<Box<str>>())?;
                            listing.dirs.push(budget.copy(dir)?);
                        }
                        let index = (listing.dirs.len() - 1) as u32;
                        listing.files.push(File::new(index, budget.copy(name)?));
                    }
                }
            }
        }
        let count = listing.files.len();
        let flags = self.per_file(tag::FILEFLAGS, count)?;
        let modes = self.per_file(tag::FILEMODES, count)?;
        let states = self.per_file(tag::FILESTATES, count)?;
        for (i, file) in listing.files.iter_mut().enumerate() {
            let at =
                |values: &Option<Integers<'_>>| values.as_ref().map_or(0, |values| values.get(i));
            file.flags = at(&flags);
            file.mode = at(&modes) as u16;
            file.state = at(&states) as u8;
        }
        Ok(listing)
    }
}

/// Where the directory of `path` ends in it: after its last `/`, none for a
/// path without one.
fn path_dir(path: &str) -> usize {
    path.rfind('/').map_or(0, |at| at + 1)
}

/// The package the header `blob` records, or why it cannot be read, with
/// what it keeps taken from `budget`.
pub(super) fn parse(blob: &[u8], budget: &mut Budget) -> std::result::Result<Package, String> {
    let header = Header::parse(blob)?;
    let required = |tag: u32, what: &str| -> std::result::Result<String, String> {
        header
            .string(tag)?
            .ok_or_else(|| format!("a header without its {what}"))
    };
    let epoch = header
        .integers(tag::EPOCH)?
        .and_then(|values| values.first());
    let name = required(tag::NAME, "name")?;
    let arch = header.string(tag::ARCH)?;
    let version = required(tag::VERSION, "version")?;
    let release = required(tag::RELEASE, "release")?;
    budget.take(size_of::<Package>())?;
    for text in [&name, &version, &release].into_iter().chain(arch.as_ref()) {
        budget.take(Budget::allocation(text.len()))?;
    }
    let listing = header.files(budget)?;
    Ok(Package {
        name,
        arch,
        epoch,
        version,
        release,
        dirs: listing.dirs,
        files: listing.files,
    })
}
