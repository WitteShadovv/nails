// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The decoy's mount, swap and automount units outside its fstab.
//!
//! The hidden systemd starts every unit a target pulls in, not only those
//! its fstab generator makes: a mount unit installed for a target
//! (`/etc/systemd/system/local-fs.target.wants/srv-x.mount`, NixOS's
//! `systemd.mounts`), a swap unit (zram-generator's `dev-zram0.swap`), an
//! automount (systemd's GPT auto-generator's `efi.automount`,
//! `proc-sys-fs-binfmt_misc.automount`), the mounts the fstab generator makes
//! from the kernel command line (`systemd.mount-extra=`). The fstab policy
//! ([`super::policy`]) never saw them: in the hidden root such a unit could
//! mount a decoy disk read-write or swap onto one, and a decoy filesystem the
//! decoy has mounted now would be missing from the hidden session.
//!
//! [`read`] finds every unit with a `.mount`, `.swap` or `.automount` suffix
//! linked into a target's `.wants` or `.requires` directory, in the unit
//! directories of the next root (`/etc/systemd/system`,
//! `/usr/local/lib/systemd/system`, `/usr/lib/systemd/system`,
//! `/lib/systemd/system`) and of `/run` (`/run/systemd/system` and the
//! generator directories the decoy's start filled), less those the fstab
//! generator made from `/etc/fstab` (`SourcePath=/etc/fstab`), which the
//! fstab policy decides. Each is read from the first unit directory in
//! systemd's order that has it, with its own drop-ins
//! ([`unit_file`]); a `.requires` link says a target requires it.
//!
//! [`decide`] gives each the decision an fstab line with its source, mount
//! point, type and options would get ([`policy::decide_units`]): a
//! filesystem the decoy has mounted now is bound read-only or overlaid, one
//! not mounted now is skipped or masked, RAM and kernel filesystems are left
//! to the hidden systemd. The mount point and a swap's device are the ones
//! the unit's name stands for, as systemd refuses a unit whose `Where=` or
//! `What=` does not match its name; a filesystem mounted now is judged by the
//! decoy's mount table. A zram swap is left to the hidden systemd: it is RAM,
//! unless the decoy's zram device has a backing device, which the `swap`
//! check refuses as well. The automount of a filesystem put in place is kept
//! off, as for an fstab line. A unit the decoy masks is left alone, and one
//! whose files cannot be read, or that NAILS cannot resolve, is masked.
//!
//! A unit skipped in the hidden session starts what it requires and wants
//! before its condition is tested: [`pulled_in`] names those that act on its
//! device or file (its fsck, makefs, mkswap, growfs, pcrfs, validatefs and
//! quota units, and NixOS's `mkswap-<name>.service`), from its unit files
//! and its own `.wants` and `.requires` directories, so they are skipped
//! with it. The generators run again in the hidden session; what they made in
//! the decoy is taken as what they make there.

pub mod unit_file;

use super::fstab::{FstabEntry, escape_path};
use super::policy::{self, Decision, Present, Units};
use nails_teardown::mountinfo::MountEntry;
use nails_teardown::whole_root::nextroot::{
    canonical_in_root, exists_in_root, is_file_in_root, list_in_root, read_in_root,
};
use nails_teardown::whole_root::plan::Skip;
use nails_teardown::whole_root::runtime_units::valid_unit_name;
use std::path::{Path, PathBuf};
use unit_file::{UnitFile, without_specifiers};

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

/// What the fstab generator writes as `SourcePath=` of a unit it made from
/// the fstab.
const FSTAB_SOURCE: &str = "/etc/fstab";

/// The units that act on the device or file of the mount or swap that pulls
/// them in: the instances of systemd's templates, by their prefix.
const DEVICE_UNIT_TEMPLATES: &[&str] = &[
    "systemd-fsck@",
    "systemd-makefs@",
    "systemd-mkswap@",
    "systemd-growfs@",
    "systemd-pcrfs@",
    "systemd-validatefs@",
    "systemd-quotacheck@",
    "quotaon@",
];

/// The prefix of NixOS's service that formats a swap file or partition
/// before its swap unit starts.
const NIXOS_MKSWAP: &str = "mkswap-";

/// The unit directories of a root and of `/run`.
#[derive(Debug, Clone, Copy)]
pub struct UnitDirs<'a> {
    /// The root whose unit files the hidden systemd reads: the next root.
    pub root: &'a Path,
    /// The `/run` the soft-reboot carries.
    pub run: &'a Path,
}

impl UnitDirs<'_> {
    /// The base and the path below it of `dir` joined with `name`.
    fn locate(&self, base: Base, dir: &str, name: &str) -> (&Path, PathBuf) {
        let base = match base {
            Base::Root => self.root,
            Base::Run => self.run,
        };
        (base, Path::new("/").join(dir).join(name))
    }

    /// The names in `name` of every unit directory, the directories in
    /// priority order and the names of each sorted.
    fn list(&self, name: &str) -> Vec<String> {
        let mut names = Vec::new();
        for &(base, dir) in UNIT_DIRS {
            let (base, path) = self.locate(base, dir, name);
            let mut here: Vec<String> = list_in_root(base, &path)
                .unwrap_or_default()
                .into_iter()
                .filter_map(|entry| entry.into_string().ok())
                .collect();
            here.sort();
            names.extend(here);
        }
        names
    }

    /// The file at `path` below `base`: `Ok(None)` when there is none, `Err`
    /// when it is not a regular file or cannot be read. A FIFO would block
    /// the read, and a link to a device such as `/dev/zero` never end it.
    fn read_file(base: &Path, path: &Path) -> Result<Option<Vec<u8>>, ()> {
        if !exists_in_root(base, path) {
            return Ok(None);
        }
        if !is_file_in_root(base, path) {
            return Err(());
        }
        match read_in_root(base, path) {
            Ok(bytes) if bytes.len() <= MAX_UNIT_FILE => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            _ => Err(()),
        }
    }

    /// The unit `name` as systemd loads it: the first unit directory that
    /// has it, then its own drop-ins (`<name>.d/*.conf`), each name from the
    /// first directory that has it, in the order of their names.
    fn load(&self, name: &str) -> Load {
        let mut fragment = None;
        for &(base, dir) in UNIT_DIRS {
            let (base, path) = self.locate(base, dir, name);
            if canonical_in_root(base, &path) == Path::new("/dev/null") {
                return Load::Masked;
            }
            match Self::read_file(base, &path) {
                Ok(Some(bytes)) => {
                    fragment = Some(bytes);
                    break;
                }
                Ok(None) => {}
                Err(()) => return Load::Unreadable,
            }
        }
        let Some(fragment) = fragment else {
            return Load::Missing;
        };
        if fragment.is_empty() {
            return Load::Masked;
        }
        let mut dropins: Vec<(String, Base, &str)> = Vec::new();
        for &(base, dir) in UNIT_DIRS {
            let (root, path) = self.locate(base, dir, &format!("{name}.d"));
            for entry in list_in_root(root, &path).unwrap_or_default() {
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
        Load::Loaded(unit)
    }
}

/// How systemd would load a unit, as far as NAILS can tell.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Load {
    /// Its first file is a link to `/dev/null`, or empty: the decoy masks it.
    Masked,
    /// No unit directory has it.
    Missing,
    /// A file of it cannot be read, or systemd refuses it.
    Unreadable,
    /// Its assignments, its drop-ins' after its file's.
    Loaded(UnitFile),
}

/// A mount, swap or automount unit a target pulls in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeUnit {
    /// Its name (`srv-scratch.mount`).
    pub name: String,
    /// The target that requires it, when one links it in its `.requires`
    /// directory; `None` when targets only want it.
    pub required_by: Option<String>,
}

/// The mount, swap and automount units the targets pull in, in the order
/// the unit directories list them (see the module docs), each once.
pub fn read(dirs: UnitDirs<'_>) -> Vec<NativeUnit> {
    let mut units: Vec<NativeUnit> = Vec::new();
    let mut links: Vec<String> = Vec::new();
    for name in dirs.list("") {
        let target_link = name.ends_with(".target.wants") || name.ends_with(".target.requires");
        // The initrd's targets: only an initrd runs them.
        if target_link && !name.starts_with("initrd") && !links.contains(&name) {
            links.push(name);
        }
    }
    for link in links {
        let required_by = link.strip_suffix(".requires").map(str::to_string);
        for name in dirs.list(&link) {
            if !valid_unit_name(&name)
                || ![".mount", ".swap", ".automount"]
                    .iter()
                    .any(|suffix| name.ends_with(suffix))
            {
                continue;
            }
            match units.iter_mut().find(|unit| unit.name == name) {
                Some(unit) => {
                    if unit.required_by.is_none() {
                        unit.required_by = required_by.clone();
                    }
                }
                None => units.push(NativeUnit {
                    name,
                    required_by: required_by.clone(),
                }),
            }
        }
    }
    units
}

/// The path a unit name with `suffix` stands for, as systemd's
/// `unit_name_to_path()` reads it, when the name is the one systemd makes
/// for that path: `-` alone is `/`, every other `-` a `/`, `\xNN` the byte
/// NN.
fn unit_path(name: &str, suffix: &str) -> Option<PathBuf> {
    let stem = name.strip_suffix(suffix)?;
    if stem == "-" {
        return Some(PathBuf::from("/"));
    }
    let bytes = stem.as_bytes();
    let mut path = vec![b'/'];
    let mut at = 0;
    while at < bytes.len() {
        match bytes[at] {
            b'-' => path.push(b'/'),
            b'\\' if bytes.get(at + 1) == Some(&b'x') => {
                let hex = std::str::from_utf8(bytes.get(at + 2..at + 4)?).ok()?;
                path.push(u8::from_str_radix(hex, 16).ok()?);
                at += 3;
            }
            byte => path.push(byte),
        }
        at += 1;
    }
    let path = PathBuf::from(String::from_utf8(path).ok()?);
    (escape_path(&path) == stem).then_some(path)
}

/// Whether the unit `name`, pulled in by a mount or swap, acts on its device
/// or file.
fn acts_on_device(name: &str) -> bool {
    name.ends_with(".service")
        && (DEVICE_UNIT_TEMPLATES
            .iter()
            .any(|template| name.starts_with(template))
            || name.starts_with(NIXOS_MKSWAP))
}

/// The units the unit `name` pulls in that act on its device or file: those
/// its files require, bind to or want (`Requires=`, `BindsTo=`, `Wants=`),
/// and those in its `.requires` and `.wants` directories.
pub fn pulled_in(dirs: UnitDirs<'_>, name: &str) -> Vec<String> {
    let mut pulled: Vec<String> = Vec::new();
    if let Load::Loaded(unit) = dirs.load(name) {
        for key in ["Requires", "BindsTo", "Wants"] {
            for value in unit.values("Unit", key) {
                pulled.extend(
                    value
                        .split_ascii_whitespace()
                        .filter_map(without_specifiers),
                );
            }
        }
    }
    for kind in ["requires", "wants"] {
        pulled.extend(dirs.list(&format!("{name}.{kind}")));
    }
    let mut units: Vec<String> = Vec::new();
    for unit in pulled {
        if valid_unit_name(&unit) && acts_on_device(&unit) && !units.contains(&unit) {
            units.push(unit);
        }
    }
    units
}

/// Add to each of `skips` the units its units pull in that act on their
/// device or file ([`pulled_in`]), where it does not have them already.
pub fn pull_in(dirs: UnitDirs<'_>, skips: &mut [Skip]) {
    for skip in skips {
        let more: Vec<String> = skip
            .units
            .iter()
            .flat_map(|unit| pulled_in(dirs, unit))
            .collect();
        for unit in more {
            if !skip.pulled.contains(&unit) {
                skip.pulled.push(unit);
            }
        }
    }
}

/// The value of `key` in `section` of `unit`, with `%%` resolved: `Err` when
/// it holds another specifier.
fn value(unit: &UnitFile, section: &str, key: &str) -> Result<Option<String>, ()> {
    match unit.last(section, key) {
        None => Ok(None),
        Some(value) => without_specifiers(value).map(Some).ok_or(()),
    }
}

/// The fstab options that only the fstab generator reads, and which mean
/// nothing in a unit's `Options=`: a unit is pulled in by its links.
fn generator_option(option: &str) -> bool {
    matches!(
        option,
        "noauto" | "auto" | "nofail" | "fail" | "x-systemd.automount" | "comment=systemd.automount"
    ) || option.starts_with("x-systemd.wanted-by=")
        || option.starts_with("x-systemd.required-by=")
}

/// The reason a unit whose source NAILS cannot read is masked.
const UNRESOLVED: &str =
    "its unit names its source or options by a specifier NAILS does not resolve";

/// What the files of the mount or swap unit `name` say about it, as an fstab
/// line would: its source, mount point (`none` for swap), type and options,
/// the type and source of a filesystem mounted now as the decoy's mount
/// table has them. An automount point the decoy has not mounted a
/// filesystem on yet shows PID 1's autofs, which is not the filesystem: the
/// unit's files tell that. `Err` with the reason when they cannot be
/// resolved.
fn as_entry(
    unit: &UnitFile,
    name: &str,
    path: &Path,
    live: Option<&MountEntry>,
) -> Result<FstabEntry, &'static str> {
    let live = live.filter(|live| live.fstype != "autofs");
    let swap = name.ends_with(".swap");
    let section = if swap { "Swap" } else { "Mount" };
    let options = value(unit, section, "Options")
        .map_err(|()| UNRESOLVED)?
        .unwrap_or_default();
    let (spec, vfstype) = match (swap, live) {
        (true, _) => (path.to_string_lossy().into_owned(), "swap".to_string()),
        (false, Some(live)) => (
            live.source.to_string_lossy().into_owned(),
            live.fstype.clone(),
        ),
        (false, None) => {
            let what = value(unit, section, "What")
                .map_err(|()| UNRESOLVED)?
                .ok_or("its unit names no source, so it does not load")?;
            let fstype = value(unit, section, "Type").map_err(|()| UNRESOLVED)?;
            (what, fstype.unwrap_or_else(|| "auto".to_string()))
        }
    };
    Ok(FstabEntry {
        spec,
        file: if swap {
            PathBuf::from("none")
        } else {
            path.to_path_buf()
        },
        vfstype,
        options: options
            .split(',')
            .filter(|option| !option.is_empty() && !generator_option(option))
            .map(str::to_string)
            .collect(),
    })
}

/// A unit that cannot be decided is masked: it never starts.
fn mask(target: PathBuf, units: Vec<String>, reason: &'static str) -> Decision {
    Decision::Mask {
        target,
        units,
        reason,
        unreached: None,
    }
}

/// The decoy's live mount at exactly `target` (the topmost one).
fn mounted_at<'a>(mounts: &'a [MountEntry], target: &Path) -> Option<&'a MountEntry> {
    mounts.iter().rev().find(|m| m.mount_point == target)
}

/// Decide each of `units` as an fstab line with what its files say would be
/// decided (see the module docs). `mounts` is the decoy's live mount table,
/// with the mount points as the decoy sees them.
pub fn decide(
    dirs: UnitDirs<'_>,
    units: &[NativeUnit],
    mounts: &[MountEntry],
    hidden_root: &Path,
    present: Present<'_>,
) -> Vec<Decision> {
    let mut decisions: Vec<Decision> = Vec::new();
    for unit in units {
        for decision in decide_one(dirs, unit, mounts, hidden_root, present) {
            if !decisions.contains(&decision) {
                decisions.push(decision);
            }
        }
    }
    decisions
}

/// The decisions for one unit: none for one the fstab generator made from
/// the fstab.
fn decide_one(
    dirs: UnitDirs<'_>,
    native: &NativeUnit,
    mounts: &[MountEntry],
    hidden_root: &Path,
    present: Present<'_>,
) -> Vec<Decision> {
    let name = native.name.as_str();
    let (suffix, automount) = if name.ends_with(".automount") {
        (".automount", true)
    } else if name.ends_with(".swap") {
        (".swap", false)
    } else {
        (".mount", false)
    };
    let Some(path) = unit_path(name, suffix) else {
        return vec![mask(
            PathBuf::from(name),
            vec![name.to_string()],
            "its name is not the escape of a path",
        )];
    };
    let unit = match dirs.load(name) {
        Load::Masked => return Vec::new(),
        Load::Missing | Load::Unreadable => {
            return vec![mask(
                path,
                vec![name.to_string()],
                "its unit files cannot be read",
            )];
        }
        Load::Loaded(unit) => unit,
    };
    if unit.last("Unit", "SourcePath") == Some(FSTAB_SOURCE) {
        return Vec::new();
    }
    if suffix == ".swap" && path.to_string_lossy().starts_with("/dev/zram") {
        return vec![Decision::Leave {
            target: path,
            reason: "a RAM-only zram swap",
        }];
    }
    // An automount decides the mount it triggers, which only it starts.
    let (mount_name, mount_unit) = if automount {
        let mount_name = format!("{}.mount", escape_path(&path));
        match dirs.load(&mount_name) {
            Load::Loaded(mount) => (mount_name, mount),
            Load::Masked => return Vec::new(),
            Load::Missing | Load::Unreadable => {
                return vec![mask(
                    path,
                    vec![mount_name, name.to_string()],
                    "the unit files of the mount behind it cannot be read",
                )];
            }
        }
    } else {
        (name.to_string(), unit)
    };
    let live = (suffix != ".swap")
        .then(|| mounted_at(mounts, &path))
        .flatten();
    let entry = match as_entry(&mount_unit, &mount_name, &path, live) {
        Ok(entry) => entry,
        Err(reason) => {
            let mut kept = vec![mount_name];
            if automount {
                kept.push(name.to_string());
            }
            return vec![mask(path, kept, reason)];
        }
    };
    let units = Units {
        unit: Some(mount_name.clone()),
        automount: automount.then(|| name.to_string()),
        required_by: native.required_by.clone(),
        checkers: pulled_in(dirs, &mount_name),
    };
    let decision = policy::decide_units(&entry, &units, mounts, hidden_root, present);
    let placed = matches!(
        decision,
        Decision::ReadOnlyBind { .. } | Decision::Overlay { .. }
    );
    if !(automount && placed) {
        return vec![decision];
    }
    // The filesystem is put in place: the automount would find its mount
    // point taken and fail.
    let reason = "the session puts the filesystem behind it in place";
    let automount = name.to_string();
    let off = if native.required_by.is_some() {
        Decision::Skip {
            target: path,
            skip: Skip {
                units: vec![automount],
                pulled: Vec::new(),
                device: None,
            },
            masked: Vec::new(),
            reason,
        }
    } else {
        mask(path, vec![automount], reason)
    };
    vec![decision, off]
}

#[cfg(test)]
#[path = "mount_units_tests.rs"]
mod tests;
