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
//! (`plocate-.service.d` for `plocate-updatedb.service`), and last of
//! `service.d`, in every unit directory: sorted by file name, where a name
//! found in a directory systemd looks at earlier shadows the same name
//! further on, and applied after the unit file.
//!
//! Every file is read with [`DecoyFiles`]: no write, no access time, and no
//! file that a link leads onto the hidden volume.

use super::super::systemd_conf::{Assignment, decode_config_bytes, parse_section};
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
fn template(unit: &str) -> Option<String> {
    let (stem, kind) = unit.rsplit_once('.')?;
    let (prefix, instance) = stem.split_once('@')?;
    (!instance.is_empty()).then(|| format!("{prefix}@.{kind}"))
}

/// The drop-in directory names of `unit`, as systemd looks for them: the
/// unit's own `<unit>.d`, its template's, then `<prefix>-.<type>.d` for each
/// dash in the name before any `@`, from the last one back, and last
/// `<type>.d`.
pub(super) fn dropin_dir_names(unit: &str) -> Vec<String> {
    let mut names = vec![format!("{unit}.d")];
    let Some((stem, kind)) = unit.rsplit_once('.') else {
        return names;
    };
    if let Some(template) = template(unit) {
        names.push(format!("{template}.d"));
    }
    let prefix = stem.split_once('@').map_or(stem, |(prefix, _)| prefix);
    // A dash that ends the name is no prefix of its own.
    let mut rest = prefix.strip_suffix('-').unwrap_or(prefix);
    while let Some((head, _)) = rest.rsplit_once('-') {
        if head.is_empty() {
            break;
        }
        names.push(format!("{head}-.{kind}.d"));
        rest = head;
    }
    names.push(format!("{kind}.d"));
    names
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

/// The drop-ins of `unit` in `dirs`, in the order systemd applies them: the
/// directories of the unit's names in every unit directory first, then
/// those of its type.
fn dropins<F: Filesystem>(
    files: &DecoyFiles<'_, F>,
    dirs: &[PathBuf],
    unit: &str,
) -> Result<Vec<PathBuf>, String> {
    let names = dropin_dir_names(unit);
    // The last name is the type's, unless the unit has none.
    let (specific, kind) = names.split_at(names.len() - usize::from(unit.contains('.')));
    let mut found: BTreeMap<OsString, PathBuf> = BTreeMap::new();
    let mut look = |dir: PathBuf| -> Result<(), String> {
        for entry in files.list(&dir)? {
            let Some(file_name) = entry.file_name() else {
                continue;
            };
            let bytes = file_name.as_encoded_bytes();
            if bytes.starts_with(b".") || !bytes.ends_with(b".conf") {
                continue;
            }
            found.entry(file_name.to_os_string()).or_insert(entry);
        }
        Ok(())
    };
    for names in [specific, kind] {
        for dir in dirs {
            for name in names {
                look(dir.join(name))?;
            }
        }
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
