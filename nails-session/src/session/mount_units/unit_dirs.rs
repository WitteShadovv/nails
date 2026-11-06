// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! How systemd finds a unit: the unit directories of the system manager in
//! their order, below the next root and below `/run`, a unit's file and its
//! drop-ins read as systemd loads them ([`UnitDirs::load`]), the names a
//! directory of units or links lists ([`UnitDirs::list`]), and the unit an
//! alias link makes a name stand for ([`UnitDirs::alias_of`]).
//!
//! A lookup that fails for another reason than that nothing is there (a loop
//! of links, a directory NAILS may not search) does not count as nothing:
//! systemd, which reads the same paths as root, may read what NAILS cannot.
//! Such a unit is [`Load::Unreadable`], and such a directory [`Unlisted`].
//!
//! A check that reads the running system asks the automount guard before
//! each lookup ([`UnitDirs::guard`]): a lookup it does not make counts as one
//! that failed, so a unit directory behind an automount point that nothing is
//! mounted on yet is [`Unlisted`], with the guard's reason.

use super::unit_file::{self, UnitFile};
use crate::filesystem::automount::Lookup;
use crate::session::policy::Decision;
use nails_teardown::whole_root::nextroot::{
    canonical_in_root, list_in_root, read_in_root, read_link_in_root, regular_file_in_root,
};
use std::ffi::OsString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

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
    /// The automount guard each lookup is asked of first, for a check that
    /// reads the running system; `None` at entry, which reads the next root.
    pub guard: Option<Guard<'a>>,
}

/// The automount guard of a check that makes its lookups itself: it tells,
/// for the path a lookup reaches on the running system and how the lookup
/// treats its end, whether it may be made, as
/// [`Guarded::ask`](crate::filesystem::automount::Guarded::ask) does, and
/// keeps each lookup it does not make in that view's ledger. `Ok(None)` when
/// the lookup may be made; `Ok(Some(point))` when it only resolves a path
/// that ends at the direct automount point `point`, which is answered
/// without a lookup; `Err` with why it is not made.
#[derive(Clone, Copy)]
pub struct Guard<'a>(pub &'a dyn Fn(&Path, Lookup) -> crate::Result<Option<PathBuf>>);

impl std::fmt::Debug for Guard<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Guard")
    }
}

impl Guard<'_> {
    /// Ask about a lookup of `path` below `root`, made as `lookup`.
    pub fn ask(&self, root: &Path, path: &Path, lookup: Lookup) -> crate::Result<Option<PathBuf>> {
        (self.0)(&root.join(path.strip_prefix("/").unwrap_or(path)), lookup)
    }
}

/// How a read of a unit directory, a unit file or a drop-in treats its end:
/// it opens what is there.
const ENTERS: Lookup = Lookup::Enters { follow: true };

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

/// The template of the instance `name` (`systemd-fsck@.service` for
/// `systemd-fsck@dev-vdb1.service`), with the instance (`dev-vdb1`); `None`
/// for a name that is no instance.
pub(super) fn template_of(name: &str) -> Option<(String, &str)> {
    let (stem, kind) = name.rsplit_once('.')?;
    let (prefix, instance) = stem.split_once('@')?;
    (!instance.is_empty()).then(|| (format!("{prefix}@.{kind}"), instance))
}

/// The instance `instance` of the template `template` (`bar@x.service` for
/// `bar@.service` and `x`); `None` for a name that is no template.
pub(super) fn instance_of(template: &str, instance: &str) -> Option<String> {
    let (prefix, kind) = template.split_once("@.")?;
    Some(format!("{prefix}@{instance}.{kind}"))
}

/// Whether a link named `name` to a unit file named `file` can make `name`
/// an alias of `file`, as systemd lets one: both of one type, and both
/// templates or neither.
fn alias_fits(name: &str, file: &str) -> bool {
    let kind = |n: &str| n.rsplit_once('.').map(|(_, kind)| kind.to_string());
    let template = |n: &str| {
        n.rsplit_once('.')
            .is_some_and(|(stem, _)| stem.ends_with('@'))
    };
    file != name
        && nails_teardown::whole_root::runtime_units::valid_unit_name(file)
        && kind(file) == kind(name)
        && template(file) == template(name)
}

/// `path` with its `.` and `..` components resolved by their text.
fn lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(part) => out.push(part),
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
        }
    }
    out
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

    /// Ask the guard, if there is one, about a lookup of `path` below
    /// `root` made as `lookup` ([`Guard::ask`]).
    fn ask(&self, root: &Path, path: &Path, lookup: Lookup) -> crate::Result<Option<PathBuf>> {
        match self.guard {
            Some(guard) => guard.ask(root, path, lookup),
            None => Ok(None),
        }
    }

    /// The names in the directory `path` below `root`: `None` when there is
    /// none; why not, when it is there but cannot be listed, or the guard
    /// does not look it up.
    fn names_in(&self, root: &Path, path: &Path) -> Result<Option<Vec<OsString>>, String> {
        self.ask(root, path, ENTERS).map_err(|e| e.to_string())?;
        match list_in_root(root, path) {
            Ok(entries) => Ok(Some(entries)),
            Err(e) if missing(&e) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    /// Whether the entry at `path` below `root` is a mask: a link to
    /// `/dev/null`. `Err` when the guard does not resolve it; a direct
    /// automount point at its end is a directory, never a mask.
    fn masks(&self, root: &Path, path: &Path) -> Result<bool, ()> {
        match self.ask(root, path, Lookup::Resolves { follow: true }) {
            Ok(None) => Ok(canonical_in_root(root, path) == Path::new("/dev/null")),
            Ok(Some(_)) => Ok(false),
            Err(_) => Err(()),
        }
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

    /// The units linked in the `kind` directories (`requires`, `wants`,
    /// `upholds`) that systemd reads for the unit `name`: `<name>.<kind>` and
    /// those of the names [`dropin_stems`] gives in each unit directory, then
    /// `<type>.<kind>` in each, each name once. `Err` names the first
    /// directory that is there but cannot be listed.
    pub(super) fn links(&self, name: &str, kind: &str) -> Result<Vec<String>, Unlisted> {
        let mut dirs: Vec<String> = dropin_stems(name)
            .into_iter()
            .map(|stem| format!("{stem}.{kind}"))
            .collect();
        if let Some((_, unit_kind)) = name.rsplit_once('.') {
            dirs.push(format!("{unit_kind}.{kind}"));
        }
        let mut units: Vec<String> = Vec::new();
        for dir in dirs {
            for unit in self.list(&dir)? {
                if !units.contains(&unit) {
                    units.push(unit);
                }
            }
        }
        Ok(units)
    }

    /// [`Self::list`], each name with whether its unit directory is one a
    /// generator writes to.
    pub(super) fn list_marked(&self, name: &str) -> Result<Vec<(String, bool)>, Unlisted> {
        let mut names = Vec::new();
        for &(base, dir) in UNIT_DIRS {
            let (root, path) = self.locate(base, dir, name);
            let mut here: Vec<String> = match self.names_in(root, &path) {
                Ok(Some(entries)) => entries
                    .into_iter()
                    .filter_map(|entry| entry.into_string().ok())
                    .collect(),
                Ok(None) => continue,
                Err(error) => {
                    let dir = match base {
                        Base::Root => path,
                        Base::Run => {
                            Path::new("/run").join(path.strip_prefix("/").unwrap_or(&path))
                        }
                    };
                    return Err(Unlisted { dir, error });
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
    /// when it is not a regular file, cannot be read, or the guard does not
    /// look it up. A FIFO would block the read, and a link to a device such
    /// as `/dev/zero` never end it.
    fn read_file(&self, root: &Path, path: &Path) -> Result<Option<Vec<u8>>, ()> {
        if self.ask(root, path, ENTERS).is_err() {
            return Err(());
        }
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
            let entries = match self.names_in(root, &path) {
                Ok(Some(entries)) => entries,
                Ok(None) => continue,
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
        if self.masks(root, &path)? {
            return Ok(None);
        }
        self.read_file(root, &path)
    }

    /// The unit `name` as systemd loads it: the first unit directory that
    /// has it, or for an instance (`systemd-fsck@dev-vdb1.service`) that has
    /// neither it nor a mask of it, the first that has its template
    /// (`systemd-fsck@.service`); then its drop-ins ([`Self::dropins`]).
    pub(super) fn load(&self, name: &str) -> Load {
        match self.load_as(name, name, true) {
            Load::Missing => match template_of(name) {
                Some((template, _)) => self.load_as(name, &template, true),
                None => Load::Missing,
            },
            load => load,
        }
    }

    /// [`Self::load`] of a unit systemd loads without a file of its own too,
    /// from its drop-ins: a device or a slice. One with neither is
    /// [`Load::Missing`].
    pub(super) fn load_bare(&self, name: &str) -> Load {
        self.load_as(name, name, false)
    }

    /// [`Self::load`] of the unit `name` from the file of `file`: `name` or
    /// its template. Without one, a unit that needs none (`!needs_file`)
    /// loads from its drop-ins.
    fn load_as(&self, name: &str, file: &str, needs_file: bool) -> Load {
        let mut fragment = None;
        for &(base, dir) in UNIT_DIRS {
            let (root, path) = self.locate(base, dir, file);
            match self.masks(root, &path) {
                Ok(true) => return Load::Masked,
                Ok(false) => {}
                Err(()) => return Load::Unreadable,
            }
            match self.read_file(root, &path) {
                Ok(Some(bytes)) => {
                    fragment = Some((bytes, generator_dir(base, dir)));
                    break;
                }
                Ok(None) => {}
                Err(()) => return Load::Unreadable,
            }
        }
        let (mut texts, generated) = match fragment {
            Some((fragment, _)) if fragment.is_empty() => return Load::Masked,
            Some((fragment, generated)) => (vec![fragment], generated),
            None if needs_file => return Load::Missing,
            None => (Vec::new(), false),
        };
        let Ok(dropins) = self.dropins(name) else {
            return Load::Unreadable;
        };
        for dropin in &dropins {
            match self.read_dropin(dropin) {
                Ok(Some(bytes)) => texts.push(bytes),
                Ok(None) => {}
                Err(()) => return Load::Unreadable,
            }
        }
        if texts.is_empty() {
            return Load::Missing;
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

    /// The system's path of the unit directory `dir` below `base`
    /// (`/run/systemd/system` for one below `/run`).
    fn system_path(base: Base, dir: &str) -> PathBuf {
        match base {
            Base::Root => Path::new("/").join(dir),
            Base::Run => Path::new("/run").join(dir),
        }
    }

    /// The unit the name `name` also names, as the first unit directory with
    /// an entry `name` makes it an alias (systemd's
    /// `unit_file_build_name_map()`): a link there to a unit file of another
    /// name of the same type ([`alias_fits`]). With whether systemd takes the
    /// link for an alias for sure (`true`): its target, read from the link's
    /// own directory, lies right in one of the unit directories. One whose
    /// target lies elsewhere systemd may take for a linked unit file under
    /// the link's own name (`false`). An instance with no entry of its own
    /// follows its template's link (`bar@x.service` for `foo@x.service` when
    /// `foo@.service` links to `bar@.service`). `Ok(None)` for a file, a
    /// link that makes no alias (a mask, a unit of the same name) and no
    /// entry; `Err` when an entry cannot be read.
    pub(super) fn alias_of(&self, name: &str) -> Result<Option<(String, bool)>, ()> {
        if let Some(found) = self.link_of(name)? {
            return Ok(found);
        }
        let Some((template, instance)) = template_of(name) else {
            return Ok(None);
        };
        Ok(self
            .link_of(&template)?
            .flatten()
            .and_then(|(aliased, sure)| Some((instance_of(&aliased, instance)?, sure))))
    }

    /// For the first unit directory with an entry `name`, the unit that entry
    /// makes `name` an alias of, if any ([`Self::alias_of`]); `None` when no
    /// unit directory has one.
    fn link_of(&self, name: &str) -> Result<Option<Option<(String, bool)>>, ()> {
        for &(base, dir) in UNIT_DIRS {
            let (root, path) = self.locate(base, dir, name);
            match self.ask(root, &path, Lookup::Resolves { follow: false }) {
                Ok(None) => {}
                // An automount point is a directory, never a link.
                Ok(Some(_)) => return Ok(Some(None)),
                Err(_) => return Err(()),
            }
            let target = match read_link_in_root(root, &path) {
                Ok(target) => target,
                Err(e) if missing(&e) => continue,
                // A file, not a link: the unit's own.
                Err(e) if e.kind() == io::ErrorKind::InvalidInput => return Ok(Some(None)),
                Err(_) => return Err(()),
            };
            let Some(file) = target.file_name().and_then(|file| file.to_str()) else {
                return Ok(Some(None));
            };
            if !alias_fits(name, file) {
                return Ok(Some(None));
            }
            let at = lexical(&Self::system_path(base, dir).join(&target));
            let sure = at.parent().is_some_and(|parent| {
                UNIT_DIRS
                    .iter()
                    .any(|&(base, dir)| Self::system_path(base, dir) == parent)
            });
            return Ok(Some(Some((file.to_string(), sure))));
        }
        Ok(None)
    }

    /// The unit names with a directory of links or drop-ins of their own in
    /// a unit directory (`<name>.wants`, `.requires`, `.upholds`, `.d`), each
    /// once: an alias among them adds what is there to the unit it names.
    /// `Err` names a unit directory that cannot be listed.
    pub(super) fn named_dirs(&self) -> Result<Vec<String>, Unlisted> {
        let mut names: Vec<String> = Vec::new();
        for entry in self.list("")? {
            let stem = [".wants", ".requires", ".upholds", ".d"]
                .iter()
                .find_map(|suffix| entry.strip_suffix(suffix));
            if let Some(stem) = stem
                && stem.contains('.')
                && !names.iter().any(|seen| seen == stem)
            {
                names.push(stem.to_string());
            }
        }
        Ok(names)
    }
}
