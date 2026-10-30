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
use std::ffi::OsString;
use std::io;
use std::os::unix::ffi::OsStrExt;
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

/// The names whose drop-in directories (`<name>.d`) apply to the unit
/// `name`, in the order systemd's `unit_file_find_dirs()` walks them: the
/// name itself; for an instance (`systemd-fsck@dev-vdb1.service`) its
/// template's names (`systemd-fsck@.service`, and what follows from that);
/// then, while what is left before the instance or the type holds a dash
/// that is not its first byte, the names of the name cut after its last
/// dash, the instance kept (`srv-data-old.mount`, `srv-data-.mount`,
/// `srv-.mount`; `systemd-@dev-vdb1.service`).
pub(super) fn dropin_stems(name: &str) -> Vec<String> {
    let mut stems = Vec::new();
    find_stems(name, &mut stems);
    stems
}

/// [`dropin_stems`] of `name`, added to `stems`.
fn find_stems(name: &str, stems: &mut Vec<String>) {
    stems.push(name.to_string());
    let Some((body, kind)) = name.rsplit_once('.') else {
        return;
    };
    let (prefix, instance) = match body.split_once('@') {
        Some((prefix, instance)) => (prefix, Some(instance).filter(|i| !i.is_empty())),
        None => (body, None),
    };
    if instance.is_some() {
        find_stems(&format!("{prefix}@.{kind}"), stems);
    }
    // A prefix that ends in a dash loses it once, so the walk goes on to the
    // dash before it.
    let rest = prefix.strip_suffix('-').unwrap_or(prefix);
    let Some(dash) = rest.rfind('-').filter(|&dash| dash > 0) else {
        return;
    };
    let cut = &rest[..=dash];
    find_stems(
        &match instance {
            Some(instance) => format!("{cut}@{instance}.{kind}"),
            None => format!("{cut}.{kind}"),
        },
        stems,
    );
}

/// Whether `base` and `dir` name a directory generators write to.
fn generator_dir(base: Base, dir: &str) -> bool {
    base == Base::Run && dir.starts_with("systemd/generator")
}

/// A drop-in of a unit, as systemd finds it ([`UnitDirs::dropins`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Dropin {
    /// Its file name, which orders it among the unit's drop-ins.
    pub(super) name: OsString,
    /// Where its drop-in directory comes in the order systemd searches them:
    /// the directory that comes first gives a name its file.
    pub(super) rank: usize,
    /// The root its unit directory is below.
    base: Base,
    /// Its unit directory.
    dir: &'static str,
    /// Its drop-in directory there (`srv-data.mount.d`).
    sub: String,
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
        Ok(self
            .list_marked(name)?
            .into_iter()
            .map(|(name, _)| name)
            .collect())
    }

    /// [`Self::list`], each name with whether its unit directory is one a
    /// generator writes to.
    pub(super) fn list_marked(&self, name: &str) -> Result<Vec<(String, bool)>, Unlisted> {
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
            names.extend(
                here.into_iter()
                    .map(|name| (name, generator_dir(base, dir))),
            );
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

    /// The drop-in directories of the unit `name` in the order systemd's
    /// `unit_file_find_dropin_paths()` searches them: in each unit directory
    /// `<name>.d` and those of the names [`dropin_stems`] gives, then in each
    /// unit directory the directory of its type (`mount.d`).
    fn dropin_dirs(name: &str) -> Vec<(Base, &'static str, String)> {
        let stems = dropin_stems(name);
        let mut searched = Vec::new();
        for &(base, dir) in UNIT_DIRS {
            for stem in &stems {
                searched.push((base, dir, format!("{stem}.d")));
            }
        }
        if let Some((_, kind)) = name.rsplit_once('.') {
            for &(base, dir) in UNIT_DIRS {
                searched.push((base, dir, format!("{kind}.d")));
            }
        }
        searched
    }

    /// Where the skip drop-in of the unit `name` comes in the order systemd
    /// searches its drop-in directories ([`Self::dropin_dirs`]): `<name>.d`
    /// below `/run/systemd/system`.
    pub(super) fn runtime_rank(name: &str) -> usize {
        let own = format!("{name}.d");
        Self::dropin_dirs(name)
            .iter()
            .position(|(base, dir, sub)| {
                *base == Base::Run && *dir == "systemd/system" && *sub == own
            })
            .unwrap_or(usize::MAX)
    }

    /// The drop-ins of the unit `name` systemd applies, in the order of
    /// their names: each file of its drop-in directories ([`Self::dropin_dirs`])
    /// whose name ends in `.conf`, as bytes, each name from the first
    /// directory that has it. A hidden name, which begins with a dot, is not
    /// one, as systemd skips it. `Err` when a drop-in directory is there but
    /// cannot be listed.
    pub(super) fn dropins(&self, name: &str) -> Result<Vec<Dropin>, ()> {
        let mut found: Vec<Dropin> = Vec::new();
        for (rank, (base, dir, sub)) in Self::dropin_dirs(name).into_iter().enumerate() {
            let (root, path) = self.locate(base, dir, &sub);
            let entries = match list_in_root(root, &path) {
                Ok(entries) => entries,
                Err(e) if missing(&e) => continue,
                Err(_) => return Err(()),
            };
            for entry in entries {
                let bytes = entry.as_bytes();
                if bytes.ends_with(b".conf")
                    && !bytes.starts_with(b".")
                    && !found.iter().any(|seen| seen.name == entry)
                {
                    found.push(Dropin {
                        name: entry,
                        rank,
                        base,
                        dir,
                        sub: sub.clone(),
                    });
                }
            }
        }
        found.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
        Ok(found)
    }

    /// The text of `dropin`: `Ok(None)` for one that masks its name (a link
    /// to `/dev/null`) or is gone by now, `Err` for one that cannot be read.
    pub(super) fn read_dropin(&self, dropin: &Dropin) -> Result<Option<Vec<u8>>, ()> {
        let (root, dir) = self.locate(dropin.base, dropin.dir, &dropin.sub);
        let path = dir.join(&dropin.name);
        if canonical_in_root(root, &path) == Path::new("/dev/null") {
            return Ok(None);
        }
        Self::read_file(root, &path)
    }

    /// The unit `name` as systemd loads it: the first unit directory that
    /// has it, then its drop-ins ([`Self::dropins`]).
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
        let Ok(dropins) = self.dropins(name) else {
            return Load::Unreadable;
        };
        let mut texts = vec![fragment];
        for dropin in &dropins {
            match self.read_dropin(dropin) {
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
