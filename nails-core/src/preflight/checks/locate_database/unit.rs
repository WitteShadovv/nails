// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The `ExecStart=` of a decoy service, read from its unit file and its
//! drop-ins as systemd loads them.
//!
//! The unit file is the first of the unit directories that holds the name
//! (the administrator's, the runtime ones, the packages'). One that is a link
//! to `/dev/null`, or empty, masks the unit. The drop-ins are the `*.conf`
//! files of `<unit>.d`, of the directories of its name's prefixes up to each
//! dash (`plocate-.service.d` for `plocate-updatedb.service`) and of
//! `service.d`, in every unit directory: sorted by file name, where a name
//! found in an earlier directory shadows the same name further on, and
//! applied after the unit file. In `[Service]` each `ExecStart=` adds a
//! command, and an empty one drops the commands before it.
//!
//! Every file is read with [`DecoyFiles`]: no write, no access time, and no
//! file that a link leads onto the hidden volume.

use super::super::decoy_posture::UNIT_DIRS;
use super::super::systemd_conf::{decode_config_bytes, parse_section};
use super::files::{DecoyFile, DecoyFiles};
use crate::Filesystem;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// What a service's unit files say it runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnitExec {
    /// No unit directory holds the unit.
    Missing,
    /// The unit is masked: it does not start.
    Masked,
    /// The `ExecStart=` values in effect, in order.
    Commands(Vec<String>),
    /// What it runs is not known, for this reason.
    Unknown(String),
}

/// The drop-in directory names of `unit`, most specific first:
/// `<unit>.d`, then `<prefix>-.<type>.d` for each dash in the name from the
/// last one back, then `<type>.d`.
pub(super) fn dropin_dir_names(unit: &str) -> Vec<String> {
    let Some((stem, kind)) = unit.rsplit_once('.') else {
        return vec![format!("{unit}.d")];
    };
    let mut names = vec![format!("{unit}.d")];
    let mut prefix = stem;
    while let Some((head, _)) = prefix.rsplit_once('-') {
        names.push(format!("{head}-.{kind}.d"));
        prefix = head;
    }
    names.push(format!("{kind}.d"));
    names
}

/// The unit file of `unit` under `root`: the path in the first unit
/// directory that holds the name, with what is there.
fn unit_file<F: Filesystem>(files: &DecoyFiles<'_, F>, unit: &str) -> Option<(PathBuf, DecoyFile)> {
    UNIT_DIRS.iter().find_map(|dir| {
        let path = files.root().join(dir).join(unit);
        match files.read(&path) {
            DecoyFile::Absent => None,
            found => Some((path, found)),
        }
    })
}

/// The drop-ins of `unit`, in the order systemd applies them.
fn dropins<F: Filesystem>(files: &DecoyFiles<'_, F>, unit: &str) -> Result<Vec<PathBuf>, String> {
    let mut found: BTreeMap<OsString, PathBuf> = BTreeMap::new();
    for dir in UNIT_DIRS {
        for name in dropin_dir_names(unit) {
            let dir = files.root().join(dir).join(name);
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
        }
    }
    Ok(found.into_values().collect())
}

/// The `ExecStart=` values of `[Service]` in `text`, applied onto `commands`.
fn apply(text: &[u8], path: &Path, commands: &mut Vec<String>) -> Result<(), String> {
    let mut assignments = Vec::new();
    if parse_section(&decode_config_bytes(text), "Service", &mut assignments).is_err() {
        return Err(format!(
            "{} has a line systemd does not read",
            path.display()
        ));
    }
    for assignment in assignments
        .into_iter()
        .filter(|assignment| assignment.key == "ExecStart")
    {
        if assignment.value.is_empty() {
            commands.clear();
        } else {
            commands.push(assignment.value);
        }
    }
    Ok(())
}

/// What `unit`'s unit files under the decoy root say it runs.
pub fn unit_exec<F: Filesystem>(files: &DecoyFiles<'_, F>, unit: &str) -> UnitExec {
    let Some((path, main)) = unit_file(files, unit) else {
        return UnitExec::Missing;
    };
    let text = match main {
        DecoyFile::Absent => return UnitExec::Missing,
        DecoyFile::Null => return UnitExec::Masked,
        // An empty unit file masks the unit, as a link to /dev/null does.
        DecoyFile::Text(text) if text.is_empty() => return UnitExec::Masked,
        DecoyFile::Text(text) => text,
        DecoyFile::Unread(why) => return UnitExec::Unknown(why),
    };
    let mut commands = Vec::new();
    if let Err(why) = apply(&text, &path, &mut commands) {
        return UnitExec::Unknown(why);
    }
    let dropins = match dropins(files, unit) {
        Ok(dropins) => dropins,
        Err(why) => return UnitExec::Unknown(why),
    };
    for dropin in dropins {
        let text = match files.read(&dropin) {
            // A drop-in gone since the listing, or one that is a link to
            // /dev/null, adds nothing.
            DecoyFile::Absent | DecoyFile::Null => continue,
            DecoyFile::Text(text) => text,
            DecoyFile::Unread(why) => return UnitExec::Unknown(why),
        };
        if let Err(why) = apply(&text, &dropin, &mut commands) {
            return UnitExec::Unknown(why);
        }
    }
    UnitExec::Commands(commands)
}
