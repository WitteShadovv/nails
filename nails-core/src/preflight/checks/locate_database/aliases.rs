// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The other names of a decoy unit, whose drop-ins the service manager reads
//! for it too (systemd.unit(5): "dropins for the aliased name and all
//! aliases are loaded").
//!
//! An alias is a link in a unit directory, the first entry of its name in
//! the order the manager reads them, whose target lies in a unit directory:
//! it stands for the unit its target names, of the same type, a template for
//! a template and an instance or its template for an instance, and is
//! followed in turn through at most eight names. Any other entry is a unit
//! file of its own name. `systemctl enable` makes such links from a unit's
//! `Alias=`, as `dbus-org.fedoraproject.FirewallD1.service` for firewalld.
//! An instance takes the aliases of its template with its own instance.
//!
//! The unit's id, the name the manager keeps it under, is the name of its
//! unit file, with the unit's instance where that is a template
//! (`unit_load_fragment()` and `merge_by_names()` in
//! src/core/load-fragment.c), so a unit read by an alias has the name its
//! alias leads to as its id, and that alias among its aliases.
//!
//! Only a name some of whose drop-in directories exist is followed as an
//! alias, so NAILS reads no link that would add nothing.

use super::files::DecoyFiles;
use super::unit::{dropin_dir_names, template};
use crate::Filesystem;
use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

/// How many names an alias leads through at most, as systemd follows them.
const ALIAS_HOPS: usize = 8;

/// The entries of the manager's unit directories, in the order it reads them.
pub(super) struct Entries {
    /// Each directory's entries.
    dirs: Vec<Vec<PathBuf>>,
    /// The name of every entry.
    names: BTreeSet<String>,
}

impl Entries {
    /// The entries of `dirs`.
    pub(super) fn read<F: Filesystem>(
        files: &DecoyFiles<'_, F>,
        dirs: &[PathBuf],
    ) -> Result<Self, String> {
        let dirs = dirs
            .iter()
            .map(|dir| files.list(dir))
            .collect::<Result<Vec<_>, _>>()?;
        let names = dirs
            .iter()
            .flatten()
            .filter_map(|entry| Some(entry.file_name()?.to_str()?.to_string()))
            .collect();
        Ok(Self { dirs, names })
    }

    /// The first entry called `name`: the one the manager takes.
    fn first(&self, name: &str) -> Option<&PathBuf> {
        self.dirs
            .iter()
            .flatten()
            .find(|entry| entry.file_name().is_some_and(|file| file == name))
    }

    /// Whether some unit directory holds an entry called `name`.
    pub(super) fn has(&self, name: &str) -> bool {
        self.names.contains(name)
    }
}

/// `path` with its `.` and `..` taken out by the text, as systemd simplifies
/// a link's target before it looks where it lies.
fn simplified(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

/// Whether systemd takes a link called `link` to `target` for an alias: both
/// of one type, a template for a template, a plain name for a plain one, and
/// for an instance the same instance or its template.
fn valid_alias(link: &str, target: &str) -> bool {
    let kind = |name: &str| name.rsplit_once('.').map(|(_, kind)| kind.to_string());
    let instance = |name: &str| {
        let (stem, _) = name.rsplit_once('.')?;
        stem.split_once('@')
            .map(|(_, instance)| instance.to_string())
    };
    if link == target || kind(link).is_none() || kind(link) != kind(target) {
        return false;
    }
    match (instance(link), instance(target)) {
        (None, None) => true,
        (Some(link), Some(target)) if link.is_empty() => target.is_empty(),
        (Some(link), Some(target)) => target.is_empty() || target == link,
        _ => false,
    }
}

/// The name of the unit file that `name` stands for (see the [module
/// docs](self)); `None` for a name that leads to none, or that the manager
/// ignores.
fn fragment_name<F: Filesystem>(
    files: &DecoyFiles<'_, F>,
    dirs: &[PathBuf],
    entries: &Entries,
    name: &str,
) -> Result<Option<String>, String> {
    let mut name = name.to_string();
    for hop in 0..ALIAS_HOPS {
        let entry = match entries.first(&name) {
            Some(entry) => entry,
            // An alias of an instance that no directory holds stands for its
            // template.
            None => match template(&name) {
                Some(template) if hop > 0 && entries.has(&template) => {
                    name = template;
                    continue;
                }
                _ => return Ok(None),
            },
        };
        let Some(target) = files.link_target(entry)? else {
            return Ok(Some(name));
        };
        let target = simplified(&if target.is_absolute() {
            files
                .root()
                .join(target.strip_prefix("/").unwrap_or(&target))
        } else {
            entry.parent().unwrap_or(Path::new("/")).join(target)
        });
        if !dirs.iter().any(|dir| target.starts_with(dir)) {
            // A unit file linked from outside the unit directories.
            return Ok(Some(name));
        }
        let Some(next) = target.file_name().and_then(|next| next.to_str()) else {
            return Ok(None);
        };
        if !valid_alias(&name, next) {
            return Ok(None);
        }
        name = next.to_string();
    }
    Ok(None)
}

/// The names of a unit: its id, under which the service manager keeps it,
/// and its aliases, the other names it is loaded by.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Names {
    /// The name of its unit file, with the unit's instance where that is a
    /// template, as `unit_load_fragment()` chooses it.
    pub(super) id: String,
    /// Its other names whose drop-in directories exist, sorted.
    pub(super) aliases: Vec<String>,
}

/// The id of `unit` and its aliases (see the [module docs](self)): `unit`
/// itself where the manager loads it by an alias, and the other names that
/// lead to its unit file, of those whose drop-in directories exist. A unit
/// no directory holds keeps its own name.
pub(super) fn names<F: Filesystem>(
    files: &DecoyFiles<'_, F>,
    dirs: &[PathBuf],
    entries: &Entries,
    unit: &str,
) -> Result<Names, String> {
    let own_template = template(unit);
    let alone = || Names {
        id: unit.to_string(),
        aliases: Vec::new(),
    };
    let fragment = match fragment_name(files, dirs, entries, unit)? {
        Some(fragment) => fragment,
        None => match &own_template {
            Some(template) => match fragment_name(files, dirs, entries, template)? {
                Some(fragment) => fragment,
                None => return Ok(alone()),
            },
            None => return Ok(alone()),
        },
    };
    let instance = unit
        .rsplit_once('.')
        .and_then(|(stem, _)| stem.split_once('@'))
        .map(|(_, instance)| instance)
        .filter(|instance| !instance.is_empty());
    // A template's name with the instance of `unit`.
    let with_instance = |name: &str| match (instance, name.split_once("@.")) {
        (Some(instance), Some((prefix, kind))) => format!("{prefix}@{instance}.{kind}"),
        _ => name.to_string(),
    };
    let id = with_instance(&fragment);
    let kind = unit.rsplit_once('.').map(|(_, kind)| kind);
    // A drop-in directory of `name` exists, the type's aside.
    let has_dropins = |name: &str| {
        let mut own = dropin_dir_names(name);
        own.pop();
        own.iter().any(|dir| entries.has(dir))
    };
    let mut aliases = Vec::new();
    if unit != id && has_dropins(unit) {
        aliases.push(unit.to_string());
    }
    for candidate in entries.names.iter().map(String::as_str) {
        if candidate == unit
            || Some(candidate) == own_template.as_deref()
            || candidate.rsplit_once('.').map(|(_, kind)| kind) != kind
        {
            continue;
        }
        // For an instance, the aliases of its template, with its instance.
        let name = with_instance(candidate);
        if name == id || aliases.contains(&name) || !has_dropins(&name) {
            continue;
        }
        if fragment_name(files, dirs, entries, candidate)?.as_deref() == Some(fragment.as_str()) {
            aliases.push(name);
        }
    }
    aliases.sort();
    Ok(Names { id, aliases })
}

#[cfg(test)]
#[path = "aliases_tests.rs"]
mod tests;
