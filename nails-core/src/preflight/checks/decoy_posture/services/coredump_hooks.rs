// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The units systemd-coredump starts for each crash, which can read the
//! crash whatever `coredump.conf` keeps, and an enabled apport, which takes
//! the crashes again when the decoy starts after the way back.
//!
//! systemd-coredump takes each crash in an instance of
//! `systemd-coredump@.service`. The service manager starts the units that
//! instance wants, requires, binds to or upholds with it, and when the
//! instance ends the units its `OnSuccess=` and `OnFailure=` name. It logs
//! every crash to the journal, with `Storage=none` and `ProcessSizeMax=0`
//! too, so such a unit learns of each one. Ubuntu's apport package adds one
//! to every instance, `apport-coredump-hook@%i.service`, by the drop-in
//! `systemd-coredump@.service.d/apport-coredump-hook.conf`: it reads the
//! crash's journal entry, logs the path and the command line of the program
//! that crashed to `/var/log/apport.log`, with the time, and, for a program a
//! package installed, writes a report of the crash to `/var/crash`, both on
//! the decoy disk, whether `apport.service` runs or not. KDE's DrKonqi links
//! its `drkonqi-coredump-processor@.service` into
//! `systemd-coredump@.service.wants`, which hands each crash's journal entry
//! on to the user's DrKonqi. NAILS does not judge what such a unit keeps, so
//! one that is installed and not masked warns, as a `kernel.core_pattern` to
//! another handler does.
//!
//! The section is read with every drop-in by the unit reader the
//! locate-database check has ([`unit_section`]). A dependency list such as
//! `OnSuccess=` cannot be emptied by a later empty assignment, so every value
//! counts; of `Wants=`, `Requires=`, `BindsTo=` and `Upholds=` only services
//! count, as the sockets the stock unit requires are no hooks. The links of
//! the instance's dependency directories (`.wants`, `.requires`, `.upholds`)
//! count as systemd reads them: those of its own name, its template's, the
//! dashes' prefixes and its type's, in every unit directory, each link by its
//! name, but for one that leads to `/dev/null`. A section or a directory NAILS
//! cannot read warns too, and so does a unit named with a specifier NAILS
//! does not expand outside an instance, whose file NAILS cannot find.
//!
//! apport's own unit, `apport.service`, sets `kernel.core_pattern` to
//! apport's pipe when it starts and back to `core` when it stops. Stopped
//! but still enabled, it starts again when the decoy starts after the way
//! back, so that warns while the pattern does not already name apport.

use super::super::super::locate_database::files::{DecoyFile, DecoyFiles};
use super::super::super::locate_database::unit::{
    SYSTEM_UNIT_PATH, UnitSection, dropin_dir_names, unit_section,
};
use super::super::{Enabled, unit_enabled};
use crate::Filesystem;
use std::path::{Path, PathBuf};

/// An instance of systemd-coredump's unit: any instance reads the template
/// `systemd-coredump@.service` and its drop-ins.
const INSTANCE: &str = "systemd-coredump@0.service";

/// The instance of [`INSTANCE`], which a template it pulls in takes.
const INSTANCE_NAME: &str = "0";

/// The settings whose units start when an instance ends, of any type.
const HOOK_SETTINGS: &[&str] = &["OnSuccess", "OnFailure"];

/// The settings whose services start with an instance.
const DEPENDENCY_SETTINGS: &[&str] = &["Wants", "Requires", "BindsTo", "Upholds"];

/// The suffixes of the directories whose links an instance pulls in.
const DEPENDENCY_DIRS: &[&str] = &[".wants", ".requires", ".upholds"];

/// apport's unit.
const APPORT_UNIT: &str = "apport.service";

/// The template of an instance name such as `apport-coredump-hook@%i.service`:
/// `apport-coredump-hook@.service`, the name to mask so that no instance
/// starts.
fn template(unit: &str) -> Option<String> {
    let (prefix, rest) = unit.split_once('@')?;
    let (_, kind) = rest.rsplit_once('.')?;
    Some(format!("{prefix}@.{kind}"))
}

/// Whether NAILS reads the files of `unit` as the service manager would: its
/// name has no specifier, or only in the instance, which its template's
/// files serve whatever the instance is.
fn resolved(unit: &str) -> bool {
    template(unit).map_or_else(|| !unit.contains('%'), |template| !template.contains('%'))
}

/// A unit an instance of systemd-coredump starts.
struct Started {
    /// The name its files are looked up by: a template linked into a
    /// dependency directory takes the instance's instance.
    unit: String,
    /// What starts it, as a finding names it.
    by: String,
}

/// The units linked into the instance's dependency directories under `dirs`.
fn linked<F: Filesystem>(
    files: &DecoyFiles<'_, F>,
    dirs: &[PathBuf],
) -> Result<Vec<Started>, String> {
    let mut out: Vec<Started> = Vec::new();
    for suffix in DEPENDENCY_DIRS {
        let names: Vec<String> = dropin_dir_names(INSTANCE)
            .iter()
            .map(|name| format!("{}{suffix}", name.trim_end_matches(".d")))
            .collect();
        for dir in dirs {
            for name in &names {
                for entry in files.list(&dir.join(name))? {
                    let Some(unit) = entry.file_name().and_then(|unit| unit.to_str()) else {
                        continue;
                    };
                    if files.link_target(&entry)?.is_none() {
                        continue;
                    }
                    match files.read(&entry) {
                        // Masked as a dependency.
                        DecoyFile::Null => continue,
                        DecoyFile::Text(text) if text.is_empty() => continue,
                        _ => {}
                    }
                    let by = format!("{unit} in {name}");
                    let unit = match unit.split_once("@.") {
                        Some((prefix, kind)) => format!("{prefix}@{INSTANCE_NAME}.{kind}"),
                        None => unit.to_string(),
                    };
                    if !out.iter().any(|known| known.unit == unit) {
                        out.push(Started { unit, by });
                    }
                }
            }
        }
    }
    Ok(out)
}

/// The warning for the units systemd-coredump starts for each crash, on the
/// decoy under `root`; `hidden` are the hidden volume's locations, resolved,
/// which no read follows a link onto. `None` when it starts none, or only
/// units that are masked or not installed.
pub(in crate::preflight::checks::decoy_posture) fn finding<F: Filesystem>(
    fs: &F,
    root: &Path,
    hidden: &[PathBuf],
) -> Option<String> {
    let files = DecoyFiles::new(fs, root, hidden);
    let dirs: Vec<PathBuf> = SYSTEM_UNIT_PATH.iter().map(|dir| root.join(dir)).collect();
    let unknown = |why: String| {
        Some(format!(
            "NAILS cannot tell which units systemd-coredump starts for each crash ({why}), and \
             such a unit can keep a record of each crash on the decoy disk whatever coredump.conf \
             says"
        ))
    };
    let assignments = match unit_section(&files, &dirs, INSTANCE, "Unit") {
        UnitSection::Assignments(assignments) => assignments,
        UnitSection::Missing | UnitSection::Masked => return None,
        UnitSection::Unknown(why) => return unknown(why),
    };
    let mut started: Vec<Started> = Vec::new();
    for assignment in &assignments {
        let key = assignment.key.as_str();
        let services_only = DEPENDENCY_SETTINGS.contains(&key);
        if !services_only && !HOOK_SETTINGS.contains(&key) {
            continue;
        }
        for unit in assignment.value.split_whitespace() {
            if !services_only || unit.ends_with(".service") {
                started.push(Started {
                    unit: unit.to_string(),
                    by: format!("{unit} ({key}=)"),
                });
            }
        }
    }
    match linked(&files, &dirs) {
        Ok(units) => started.extend(units),
        Err(why) => return unknown(why),
    }
    let mut hooks = Vec::new();
    let mut masks = Vec::new();
    for Started { unit, by } in started {
        let starts = match unit_section(&files, &dirs, &unit, "Unit") {
            UnitSection::Masked => false,
            // A name with a specifier NAILS does not expand may name a unit
            // that is installed.
            UnitSection::Missing => !resolved(&unit),
            UnitSection::Assignments(_) | UnitSection::Unknown(_) => true,
        };
        if starts {
            hooks.push(by);
            let mask = template(&unit).unwrap_or(unit);
            if !masks.contains(&mask) {
                masks.push(mask);
            }
        }
    }
    if hooks.is_empty() {
        return None;
    }
    Some(format!(
        "systemd-coredump starts {} for each crash, which NAILS does not judge: such a unit can \
         read every crash from the journal, where systemd-coredump logs it even with \
         Storage=none and ProcessSizeMax=0, and Ubuntu's apport-coredump-hook@.service does, \
         logging the path and the command line of each program that crashed to \
         /var/log/apport.log, with the time, and for a program a package installed writing a \
         report of the crash to /var/crash, on the decoy disk; mask it (systemctl mask {})",
        hooks.join(", "),
        masks.join(" ")
    ))
}

/// The warning for an `apport.service` that is enabled on the decoy under
/// `root` where the service manager can start it, or that NAILS cannot tell
/// is enabled, so that it takes the kernel's core dumps again when the decoy
/// starts after the way back; `hidden` as for [`finding`].
pub(in crate::preflight::checks::decoy_posture) fn apport_finding<F: Filesystem>(
    fs: &F,
    root: &Path,
    hidden: &[PathBuf],
) -> Option<String> {
    let untold = match unit_enabled(fs, root, APPORT_UNIT) {
        Enabled::No => return None,
        Enabled::Yes => None,
        Enabled::Untold(why) => Some(why),
    };
    let files = DecoyFiles::new(fs, root, hidden);
    let dirs: Vec<PathBuf> = SYSTEM_UNIT_PATH.iter().map(|dir| root.join(dir)).collect();
    if matches!(
        unit_section(&files, &dirs, APPORT_UNIT, "Service"),
        UnitSection::Missing | UnitSection::Masked
    ) {
        return None;
    }
    let enabled = match untold {
        None => "apport.service is enabled".to_string(),
        Some(why) => format!("apport.service may be enabled ({why})"),
    };
    Some(format!(
        "{enabled}, though kernel.core_pattern does not name apport now: when the decoy starts \
         after the way back, it sets the pattern to apport's pipe again, and apport logs the path \
         and the command line of each program that crashes from then on to /var/log/apport.log \
         on the decoy disk; turn it off with systemctl disable --now apport.service"
    ))
}
