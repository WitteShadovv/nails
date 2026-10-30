// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! How systemd finds a unit: the unit directories of the system manager in
//! their order, below the next root and below `/run`, a unit's file and its
//! drop-ins read as systemd loads them ([`UnitDirs::load`]), and the names a
//! directory of units or links lists ([`UnitDirs::list`]).
//!
//! A lookup that fails for another reason than that nothing is there (a loop
//! of links, a directory NAILS may not search) does not count as nothing:
//! systemd, which reads the same paths as root, may read what NAILS cannot.
//! Such a unit is [`Load::Unreadable`], and such a directory [`Unlisted`].

use super::unit_file::{self, UnitFile};
use crate::session::policy::Decision;
use nails_teardown::whole_root::nextroot::{
    canonical_in_root, list_in_root, read_in_root, regular_file_in_root,
};
use std::io;
use std::path::{Path, PathBuf};

/// Where a unit directory lives: in the next root, or in `/run`, which the
/// soft-reboot carries into the hidden session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Base {
    /// Below the root.
    Root,
    /// Below `/run`.
    Run,
}

/// systemd's unit directories for the system manager, highest priority
/// first.
const UNIT_DIRS: &[(Base, &str)] = &[
    (Base::Root, "etc/systemd/system.control"),
    (Base::Run, "systemd/system.control"),
    (Base::Run, "systemd/generator.early"),
    (Base::Root, "etc/systemd/system"),
    (Base::Run, "systemd/system"),
    (Base::Run, "systemd/generator"),
    (Base::Root, "usr/local/lib/systemd/system"),
    (Base::Root, "usr/lib/systemd/system"),
    (Base::Root, "lib/systemd/system"),
    (Base::Run, "systemd/generator.late"),
];

/// The largest unit file or drop-in read; a larger one counts as one that
/// cannot be read.
const MAX_UNIT_FILE: usize = 4 * 1024 * 1024;

/// Whether a lookup failed because nothing is there: the path, or a
/// directory on the way, does not exist.
fn missing(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
    )
}

/// The unit directories of a root and of `/run`.
#[derive(Debug, Clone, Copy)]
pub struct UnitDirs<'a> {
    /// The root whose unit files the hidden systemd reads: the next root.
    pub root: &'a Path,
    /// The `/run` the soft-reboot carries.
    pub run: &'a Path,
}

/// A directory of units or links that NAILS cannot list: the hidden systemd
/// may start units linked there that NAILS never decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unlisted {
    /// The directory, as the root it is in sees it (`/run/...` for one below
    /// `/run`).
    pub dir: PathBuf,
    /// Why it cannot be listed.
    pub error: String,
}

impl Unlisted {
    /// The refusal of the entry: no safe decision without the units.
    pub fn refusal(&self) -> Decision {
        Decision::Refuse {
            target: self.dir.clone(),
            reason: format!("NAILS cannot list this unit directory: {}", self.error),
        }
    }
}

/// Whether `base` and `dir` name a directory generators write to.
fn generator_dir(base: Base, dir: &str) -> bool {
    base == Base::Run && dir.starts_with("systemd/generator")
}

/// How systemd would load a unit, as far as NAILS can tell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Load {
    /// Its first file is a link to `/dev/null`, or empty: the decoy masks it.
    Masked,
    /// No unit directory has it.
    Missing,
    /// A file of it cannot be read, or systemd refuses it.
    Unreadable,
    /// It loads.
    Loaded {
        /// Its assignments, its drop-ins' after its file's.
        unit: UnitFile,
        /// Whether its file is in a generator directory: a generator made
        /// it.
        generated: bool,
    },
}

impl UnitDirs<'_> {
    /// The base and the path below it of `dir` joined with `name`.
    fn locate(&self, base: Base, dir: &str, name: &str) -> (&Path, PathBuf) {
        let root = match base {
            Base::Root => self.root,
            Base::Run => self.run,
        };
        (root, Path::new("/").join(dir).join(name))
    }

    /// The names in `name` of every unit directory, the directories in
    /// priority order and the names of each sorted. `Err` names the first
    /// one that is there but cannot be listed.
    pub(super) fn list(&self, name: &str) -> Result<Vec<String>, Unlisted> {
        let mut names = Vec::new();
        for &(base, dir) in UNIT_DIRS {
            let (root, path) = self.locate(base, dir, name);
            let mut here: Vec<String> = match list_in_root(root, &path) {
                Ok(entries) => entries
                    .into_iter()
                    .filter_map(|entry| entry.into_string().ok())
                    .collect(),
                Err(e) if missing(&e) => continue,
                Err(e) => {
                    let dir = match base {
                        Base::Root => path,
                        Base::Run => {
                            Path::new("/run").join(path.strip_prefix("/").unwrap_or(&path))
                        }
                    };
                    return Err(Unlisted {
                        dir,
                        error: e.to_string(),
                    });
                }
            };
            here.sort();
            names.extend(here);
        }
        Ok(names)
    }

    /// The file at `path` below `root`: `Ok(None)` when there is none, `Err`
    /// when it is not a regular file or cannot be read. A FIFO would block
    /// the read, and a link to a device such as `/dev/zero` never end it.
    fn read_file(root: &Path, path: &Path) -> Result<Option<Vec<u8>>, ()> {
        match regular_file_in_root(root, path) {
            Ok(true) => {}
            Err(e) if missing(&e) => return Ok(None),
            Ok(false) | Err(_) => return Err(()),
        }
        match read_in_root(root, path) {
            Ok(bytes) if bytes.len() <= MAX_UNIT_FILE => Ok(Some(bytes)),
            Err(e) if missing(&e) => Ok(None),
            _ => Err(()),
        }
    }

    /// The unit `name` as systemd loads it: the first unit directory that
    /// has it, then its own drop-ins (`<name>.d/*.conf`), each name from the
    /// first directory that has it, in the order of their names.
    pub(super) fn load(&self, name: &str) -> Load {
        let mut fragment = None;
        for &(base, dir) in UNIT_DIRS {
            let (root, path) = self.locate(base, dir, name);
            if canonical_in_root(root, &path) == Path::new("/dev/null") {
                return Load::Masked;
            }
            match Self::read_file(root, &path) {
                Ok(Some(bytes)) => {
                    fragment = Some((bytes, generator_dir(base, dir)));
                    break;
                }
                Ok(None) => {}
                Err(()) => return Load::Unreadable,
            }
        }
        let Some((fragment, generated)) = fragment else {
            return Load::Missing;
        };
        if fragment.is_empty() {
            return Load::Masked;
        }
        let mut dropins: Vec<(String, Base, &str)> = Vec::new();
        for &(base, dir) in UNIT_DIRS {
            let (root, path) = self.locate(base, dir, &format!("{name}.d"));
            let entries = match list_in_root(root, &path) {
                Ok(entries) => entries,
                Err(e) if missing(&e) => continue,
                Err(_) => return Load::Unreadable,
            };
            for entry in entries {
                let Some(entry) = entry.to_str() else {
                    continue;
                };
                if entry.ends_with(".conf") && !dropins.iter().any(|(seen, ..)| seen == entry) {
                    dropins.push((entry.to_string(), base, dir));
                }
            }
        }
        dropins.sort_by(|a, b| a.0.cmp(&b.0));
        let mut texts = vec![fragment];
        for (file, base, dir) in dropins {
            let (root, path) = self.locate(base, dir, &format!("{name}.d/{file}"));
            if canonical_in_root(root, &path) == Path::new("/dev/null") {
                continue;
            }
            match Self::read_file(root, &path) {
                Ok(Some(bytes)) => texts.push(bytes),
                Ok(None) => {}
                Err(()) => return Load::Unreadable,
            }
        }
        let mut unit = UnitFile::default();
        for text in texts {
            match unit_file::parse(&text) {
                Ok(file) => unit.extend(file),
                Err(_) => return Load::Unreadable,
            }
        }
        Load::Loaded { unit, generated }
    }
}
