// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! One section of a decoy unit, read from its unit file and its drop-ins as
//! systemd loads them.
//!
//! The unit file is the first of the manager's unit directories, in the
//! order the manager reads them, that holds the name, or, for an instance
//! such as `foo@bar.service` that none holds, its template `foo@.service`.
//! One that is a link to `/dev/null`, or empty, masks the unit. The drop-ins
//! are the `*.conf` files of `<unit>.d`, of the template's `foo@.service.d`,
//! of the directories of its name's prefixes up to each dash
//! (`plocate-.service.d` for `plocate-updatedb.service`), for an instance
//! those prefixes with its instance and their templates as well
//! ([`dropin_dir_names`]), then the same for each of its aliases
//! ([`aliases`]), and last of `service.d`, in every unit
//! directory: sorted by file name, where a name found in a directory systemd
//! looks at earlier shadows the same name further on, and applied after the
//! unit file. The manager takes a unit's names in an order of its own, so a
//! drop-in name that two of them hold in different files leaves the section
//! unknown.
//!
//! Every file is read with [`DecoyFiles`]: no write, no access time, and no
//! file that a link leads onto the hidden volume.

use super::super::systemd_conf::{Assignment, decode_config_bytes, parse_section};
use super::aliases::{Entries, aliases};
use super::files::{DecoyFile, DecoyFiles};
use crate::Filesystem;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// The directories the system manager loads unit files from, relative to
/// the root, in the order it reads them, and `/lib/systemd/system`, which a
/// systemd built for a split `/usr` reads too.
pub const SYSTEM_UNIT_PATH: &[&str] = &[
    "etc/systemd/system.control",
    "run/systemd/system.control",
    "run/systemd/transient",
    "run/systemd/generator.early",
    "etc/systemd/system",
    "etc/systemd/system.attached",
    "run/systemd/system",
    "run/systemd/system.attached",
    "run/systemd/generator",
    "usr/local/lib/systemd/system",
    "usr/lib/systemd/system",
    "lib/systemd/system",
    "run/systemd/generator.late",
];

/// What a unit's files say of one of its sections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnitSection {
    /// No unit directory holds the unit.
    Missing,
    /// The unit is masked: it does not start.
    Masked,
    /// The section's assignments, in the order systemd applies them.
    Assignments(Vec<Assignment>),
    /// What the files say is not known, for this reason.
    Unknown(String),
}

/// The template of an instance name: `foo@.service` for `foo@bar.service`.
pub(super) fn template(unit: &str) -> Option<String> {
    let (stem, kind) = unit.rsplit_once('.')?;
    let (prefix, instance) = stem.split_once('@')?;
    (!instance.is_empty()).then(|| format!("{prefix}@.{kind}"))
}

/// The drop-in directory names of `unit`, as systemd's
/// `unit_file_find_dirs()` looks for them, and last `<type>.d`. For a name,
/// its own `<name>.d`; for an instance, then its template's names; then the
/// names of its prefix up to the last dash in the name before any `@`
/// (`plocate-.service` for `plocate-updatedb.service`), which an instance
/// keeps its instance in (`systemd-@0.service` for
/// `systemd-coredump@0.service`), and so on for that name. A dash that ends
/// the prefix is dropped once to find the one before it, and one that starts
/// it is no prefix.
pub(in crate::preflight::checks) fn dropin_dir_names(unit: &str) -> Vec<String> {
    let mut names = Vec::new();
    find_dirs(unit, &mut names);
    if let Some((_, kind)) = unit.rsplit_once('.') {
        names.push(format!("{kind}.d"));
    }
    names
}

/// The prefix of `prefix`, a name before any `@`, up to and with its last
/// dash, as systemd builds it: a dash that ends `prefix` is dropped once to
/// find the one before it, and a dash that starts it is no prefix.
fn dash_prefix(prefix: &str) -> Option<&str> {
    let mut rest = prefix;
    let mut chopped = false;
    loop {
        let dash = rest.rfind('-')?;
        if dash == 0 {
            return None;
        }
        if dash + 1 < rest.len() || chopped {
            return Some(&rest[..=dash]);
        }
        rest = &rest[..dash];
        chopped = true;
    }
}

/// Add the drop-in directory names of `name` to `names`, as
/// [`dropin_dir_names`] says, each once.
fn find_dirs(name: &str, names: &mut Vec<String>) {
    let own = format!("{name}.d");
    if !names.contains(&own) {
        names.push(own);
    }
    let Some((stem, kind)) = name.rsplit_once('.') else {
        return;
    };
    let (prefix, instance) = match stem.split_once('@') {
        Some((prefix, instance)) => (prefix, Some(instance).filter(|i| !i.is_empty())),
        None => (stem, None),
    };
    if let Some(template) = template(name) {
        find_dirs(&template, names);
    }
    let Some(prefix) = dash_prefix(prefix) else {
        return;
    };
    let built = match instance {
        Some(instance) => format!("{prefix}@{instance}.{kind}"),
        None => format!("{prefix}.{kind}"),
    };
    find_dirs(&built, names);
}

/// The unit file of `unit`: the path in the first of `dirs` that holds the
/// name, else its template's, with what is there.
fn unit_file<F: Filesystem>(
    files: &DecoyFiles<'_, F>,
    dirs: &[PathBuf],
    unit: &str,
) -> Option<(PathBuf, DecoyFile)> {
    let find = |name: &str| {
        dirs.iter().find_map(|dir| {
            let path = dir.join(name);
            match files.read(&path) {
                DecoyFile::Absent => None,
                found => Some((path, found)),
            }
        })
    };
    find(unit).or_else(|| template(unit).and_then(|template| find(&template)))
}

/// The drop-ins of the directories called `names` in `dirs`, by file name:
/// in every unit directory in turn, where a file name found earlier shadows
/// the same name further on.
fn dropins_in<F: Filesystem>(
    files: &DecoyFiles<'_, F>,
    dirs: &[PathBuf],
    names: &[String],
) -> Result<BTreeMap<OsString, PathBuf>, String> {
    let mut found: BTreeMap<OsString, PathBuf> = BTreeMap::new();
    for dir in dirs {
        for name in names {
            for entry in files.list(&dir.join(name))? {
                let Some(file_name) = entry.file_name() else {
                    continue;
                };
                let bytes = file_name.as_encoded_bytes();
                if bytes.starts_with(b".") || !bytes.ends_with(b".conf") {
                    continue;
                }
                found.entry(file_name.to_os_string()).or_insert(entry);
            }
        }
    }
    Ok(found)
}

/// The drop-ins of `unit` in `dirs`, in the order systemd applies them: the
/// directories of the unit's names, its aliases' among them, in every unit
/// directory first, then those of its type.
fn dropins<F: Filesystem>(
    files: &DecoyFiles<'_, F>,
    dirs: &[PathBuf],
    unit: &str,
) -> Result<Vec<PathBuf>, String> {
    let mut names = dropin_dir_names(unit);
    // The last name is the type's, unless the unit has none.
    let kind = unit.contains('.').then(|| names.pop()).flatten();
    let mut found = dropins_in(files, dirs, &names)?;
    let entries = Entries::read(files, dirs)?;
    for alias in aliases(files, dirs, &entries, unit)? {
        let mut names = dropin_dir_names(&alias);
        names.pop();
        for (file_name, path) in dropins_in(files, dirs, &names)? {
            match found.get(&file_name) {
                Some(other) if *other != path => {
                    return Err(format!(
                        "NAILS cannot tell which of {} and {} the service manager reads for \
                         {unit}: both are drop-ins of its names, {alias} among them, which it \
                         takes in an order of its own",
                        other.display(),
                        path.display()
                    ));
                }
                Some(_) => {}
                None => {
                    found.insert(file_name, path);
                }
            }
        }
    }
    for (file_name, path) in dropins_in(files, dirs, kind.as_slice())? {
        found.entry(file_name).or_insert(path);
    }
    Ok(found.into_values().collect())
}

/// The assignments of `[section]` in `text`, appended to `out`.
fn apply(text: &[u8], path: &Path, section: &str, out: &mut Vec<Assignment>) -> Result<(), String> {
    if parse_section(&decode_config_bytes(text), section, out).is_err() {
        return Err(format!(
            "{} has a line systemd does not read",
            path.display()
        ));
    }
    Ok(())
}

/// What `unit`'s files in `dirs` (the manager's unit directories, highest
/// priority first) say of `[section]`.
pub fn unit_section<F: Filesystem>(
    files: &DecoyFiles<'_, F>,
    dirs: &[PathBuf],
    unit: &str,
    section: &str,
) -> UnitSection {
    let Some((path, main)) = unit_file(files, dirs, unit) else {
        return UnitSection::Missing;
    };
    let text = match main {
        DecoyFile::Absent => return UnitSection::Missing,
        DecoyFile::Null => return UnitSection::Masked,
        // An empty unit file masks the unit, as a link to /dev/null does.
        DecoyFile::Text(text) if text.is_empty() => return UnitSection::Masked,
        DecoyFile::Text(text) => text,
        DecoyFile::Unread(why) => return UnitSection::Unknown(why),
    };
    let mut assignments = Vec::new();
    if let Err(why) = apply(&text, &path, section, &mut assignments) {
        return UnitSection::Unknown(why);
    }
    let dropins = match dropins(files, dirs, unit) {
        Ok(dropins) => dropins,
        Err(why) => return UnitSection::Unknown(why),
    };
    for dropin in dropins {
        let text = match files.read(&dropin) {
            // A drop-in gone since the listing, or one that is a link to
            // /dev/null, adds nothing.
            DecoyFile::Absent | DecoyFile::Null => continue,
            DecoyFile::Text(text) => text,
            DecoyFile::Unread(why) => return UnitSection::Unknown(why),
        };
        if let Err(why) = apply(&text, &dropin, section, &mut assignments) {
            return UnitSection::Unknown(why);
        }
    }
    UnitSection::Assignments(assignments)
}

/// The values of `key` in `assignments` as systemd keeps a list: an empty
/// assignment drops the values before it.
pub fn list_values(assignments: &[Assignment], key: &str) -> Vec<String> {
    let mut out = Vec::new();
    for assignment in assignments
        .iter()
        .filter(|assignment| assignment.key == key)
    {
        if assignment.value.is_empty() {
            out.clear();
        } else {
            out.push(assignment.value.clone());
        }
    }
    out
}
