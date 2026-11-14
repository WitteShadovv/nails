// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The timer, path and socket units that start a unit of the decoy on their
//! own, so that the service manager starts it after the way back though it
//! is neither enabled nor active now.
//!
//! A trigger counts when it is enabled (a link to it in a `.wants`,
//! `.requires` or `.upholds` directory of a unit directory, which does not
//! lead to `/dev/null`) or active (its invocation marker), and its unit is
//! not masked. A timer or a path starts the first `Unit=` systemd takes, else
//! the service of its own name, as the locate-database check reads it
//! ([`triggered_unit`]); a socket starts its `Service=`, else the service of
//! its own name, unless it is `Accept=yes`, which starts instances of a
//! template of its own name instead. What NAILS cannot read of them, a
//! directory it cannot list, a trigger's unit file, or a name with a
//! specifier, counts as a trigger that may start any unit.

use super::super::locate_database::files::DecoyFiles;
use super::super::locate_database::unit::{SYSTEM_UNIT_PATH, UnitSection, unit_section};
use super::super::locate_database::units::triggered_unit;
use super::loggers::INVOCATION_DIR;
use crate::Filesystem;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// The trigger types, with the section that names the unit they start.
const KINDS: &[(&str, &str)] = &[
    (".timer", "Timer"),
    (".path", "Path"),
    (".socket", "Socket"),
];

/// The dependency directories that enable what they link.
const DEPENDENCY_SUFFIXES: &[&str] = &[".wants", ".requires", ".upholds"];

/// What the decoy's triggers start.
#[derive(Debug, Default)]
pub(super) struct Triggers {
    /// Each unit a trigger starts, with how, as a finding names it.
    starts: BTreeMap<String, String>,
    /// Why NAILS cannot tell what some trigger starts, if it cannot.
    untold: Option<String>,
}

impl Triggers {
    /// How a trigger starts `unit`: `Ok` with how, as a finding names it,
    /// `Err` with why NAILS cannot tell whether one does; `None` when none
    /// does.
    pub(super) fn of(&self, unit: &str) -> Option<Result<String, String>> {
        if let Some(how) = self.starts.get(unit) {
            return Some(Ok(how.clone()));
        }
        self.untold.as_ref().map(|why| {
            Err(format!(
                "NAILS cannot tell whether a timer, path or socket unit starts {unit}: {why}"
            ))
        })
    }
}

/// The unit a socket unit `socket`, whose `[Socket]` section is
/// `assignments`, starts, `None` for one that starts instances of a
/// template instead.
///
/// # Errors
///
/// Why NAILS cannot tell: its `Service=` has a specifier.
fn socket_service(
    assignments: &[super::super::systemd_conf::Assignment],
    socket: &str,
) -> Result<Option<String>, String> {
    let last = |key: &str| {
        assignments
            .iter()
            .rev()
            .find(|assignment| assignment.key == key)
            .map(|assignment| assignment.value.as_str())
    };
    if last("Accept").is_some_and(|accept| ["yes", "true", "on", "1"].contains(&accept)) {
        return Ok(None);
    }
    match last("Service") {
        Some(service) if service.contains('%') => Err(format!(
            "{socket} names the service it starts with a specifier, which NAILS does not expand"
        )),
        Some(service) if service.ends_with(".service") => Ok(Some(service.to_string())),
        _ => Ok(Some(format!(
            "{}.service",
            socket.strip_suffix(".socket").unwrap_or(socket)
        ))),
    }
}

/// The triggers of the decoy under `root` and what they start (see the
/// [module docs](self)); `hidden` are the hidden volume's locations,
/// resolved, which no read follows a link onto.
pub(super) fn read<F: Filesystem>(fs: &F, root: &Path, hidden: &[PathBuf]) -> Triggers {
    let files = DecoyFiles::new(fs, root, hidden);
    let dirs: Vec<PathBuf> = SYSTEM_UNIT_PATH.iter().map(|dir| root.join(dir)).collect();
    let is_trigger = |name: &str| KINDS.iter().any(|(suffix, _)| name.ends_with(suffix));
    let mut found = Triggers::default();
    let mut untold = Vec::new();
    // Each trigger that runs, with whether it is enabled.
    let mut runs: BTreeMap<String, bool> = BTreeMap::new();
    for dir in &dirs {
        let entries = match files.list(dir) {
            Ok(entries) => entries,
            Err(why) => {
                untold.push(why);
                continue;
            }
        };
        for entry in entries {
            let dependency = entry
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| DEPENDENCY_SUFFIXES.iter().any(|s| name.ends_with(s)));
            if !dependency {
                continue;
            }
            let links = match files.list(&entry) {
                Ok(links) => links,
                Err(why) => {
                    untold.push(why);
                    continue;
                }
            };
            for link in links {
                let Some(name) = link.file_name().and_then(|name| name.to_str()) else {
                    continue;
                };
                if !is_trigger(name) {
                    continue;
                }
                match files.link_target(&link) {
                    // A masked dependency, which systemd ignores.
                    Ok(Some(target)) if target == Path::new("/dev/null") => {}
                    Ok(_) => {
                        runs.insert(name.to_string(), true);
                    }
                    Err(why) => untold.push(why),
                }
            }
        }
    }
    match files.list(&root.join(INVOCATION_DIR)) {
        Ok(markers) => {
            for marker in markers {
                if let Some(name) = marker
                    .file_name()
                    .and_then(|name| name.to_str())
                    .and_then(|name| name.strip_prefix("invocation:"))
                    .filter(|name| is_trigger(name))
                {
                    runs.entry(name.to_string()).or_insert(false);
                }
            }
        }
        Err(why) => untold.push(why),
    }
    for (trigger, enabled) in &runs {
        let Some((suffix, section)) = KINDS.iter().find(|(suffix, _)| trigger.ends_with(suffix))
        else {
            continue;
        };
        let state = if *enabled { "is enabled" } else { "is active" };
        let assignments = match unit_section(&files, &dirs, trigger, section) {
            UnitSection::Assignments(assignments) => assignments,
            UnitSection::Masked => continue,
            // An enabling link left behind by a removed unit starts nothing;
            // the manager runs an active one as it was loaded.
            UnitSection::Missing if *enabled => continue,
            UnitSection::Missing => {
                untold.push(format!(
                    "{trigger} runs, and NAILS finds no file of it to read what it starts"
                ));
                continue;
            }
            UnitSection::Unknown(why) => {
                untold.push(why);
                continue;
            }
        };
        let started = if *suffix == ".socket" {
            socket_service(&assignments, trigger)
        } else {
            triggered_unit(&assignments, trigger, suffix).map(Some)
        };
        match started {
            Ok(Some(unit)) => {
                found
                    .starts
                    .entry(unit.clone())
                    .or_insert_with(|| format!("{trigger} {state} and starts {unit}"));
            }
            Ok(None) => {}
            Err(why) => untold.push(why),
        }
    }
    let untold: BTreeSet<String> = untold.into_iter().collect();
    found.untold = (!untold.is_empty()).then(|| untold.into_iter().collect::<Vec<_>>().join("; "));
    found
}

#[cfg(test)]
#[path = "triggers_tests.rs"]
mod tests;
