// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The decoy's systemd services that run updatedb, and what starts them.
//!
//! A service runs updatedb when a command of its `[Service]` section
//! (`ExecStart=`, `ExecStartPre=`, `ExecStartPost=`, `ExecCondition=`,
//! `ExecReload=`, `ExecStop=`, `ExecStopPost=`) has a word whose file name is
//! an updatedb's: the program, or a word after a program that runs another
//! (`nice`, `flock`, `sh -c updatedb`), which then is the program and the
//! words after it its arguments. One whose commands name updatedb otherwise,
//! as in `sh -c 'updatedb …'`, is a service NAILS cannot tell about. A
//! service whose program is a script that runs updatedb is not seen.
//!
//! Such a service runs updatedb:
//!
//! - now, when the system manager shows it active (its invocation marker, or
//!   a populated cgroup);
//! - when a timer or a path unit that is enabled or active, and not masked,
//!   starts it: the trigger's `Unit=`, or the service of the trigger's own
//!   name;
//! - whenever its manager starts, when it is enabled itself: an entry for it
//!   in a `.wants`, `.requires` or `.upholds` directory, as `systemctl
//!   enable` and `systemctl add-wants` make. The soft-reboot back to the
//!   decoy starts the system manager again;
//! - by hand otherwise, for plocate's, mlocate's and NixOS's own services,
//!   which `systemctl start` runs.
//!
//! A service another unit pulls in with `Wants=` or `Requires=` in its own
//! file, or that a unit started by hand runs, is not followed.
//!
//! The system manager's units are read from [`SYSTEM_UNIT_PATH`]. A user's
//! manager reads its own directories (`~/.config/systemd/user`,
//! `~/.local/share/systemd/user`, `/run/user/<uid>/systemd/…`) in each home
//! `/etc/passwd` names, and the directories every user shares
//! (`/etc/xdg/systemd/user`, `/etc/systemd/user`, `/run/systemd/user` and
//! `systemd/user` in `/usr/local/share`, `/usr/share`, `/usr/local/lib` and
//! `/usr/lib`), whose dependency entries, as `systemctl --global enable`
//! makes them, enable a unit for every user. A user's manager leaves no
//! marker of what it runs, so a user's updatedb running now is seen by its
//! process alone. A unit directory NAILS cannot list may hold a unit that
//! runs updatedb, so it is one NAILS cannot tell about.

use super::super::systemd_conf::Assignment;
use super::exec::{ExecCommand, exec_commands, is_updatedb, mentions_updatedb};
use super::files::{DecoyFile, DecoyFiles};
use super::judge::Start;
use super::read::Cwd;
use super::unit::{SYSTEM_UNIT_PATH, UnitSection, list_values, unit_section};
use crate::Filesystem;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// The keys of `[Service]` whose values are commands the service runs.
const EXEC_KEYS: &[&str] = &[
    "ExecCondition",
    "ExecStartPre",
    "ExecStart",
    "ExecStartPost",
    "ExecReload",
    "ExecStop",
    "ExecStopPost",
];

/// The units that start a service when they fire, by their type, with the
/// section that names the service in `Unit=`.
const TRIGGERS: &[(&str, &str)] = &[(".timer", "Timer"), (".path", "Path")];

/// The services plocate, mlocate and NixOS install for updatedb, with the
/// database each writes.
pub const LOCATE_SERVICES: &[(&str, &str)] = &[
    ("plocate-updatedb.service", "/var/lib/plocate/plocate.db"),
    ("mlocate-updatedb.service", "/var/lib/mlocate/mlocate.db"),
    ("update-locatedb.service", "/var/cache/locatedb"),
];

/// The directories every user's manager reads units from, relative to the
/// root, in the order it reads them.
const SHARED_USER_UNIT_PATH: &[&str] = &[
    "etc/xdg/systemd/user",
    "etc/systemd/user",
    "run/systemd/user",
    "usr/local/share/systemd/user",
    "usr/share/systemd/user",
    "usr/local/lib/systemd/user",
    "usr/lib/systemd/user",
];

/// How the shared user unit directories are named: every user's manager
/// reads them, and `systemctl --global` enables units in them.
const EVERY_USER: &str = "every user";

/// A service manager whose units are read.
struct Manager {
    /// How a message names it, and how its commands are typed: `None` for
    /// the system manager.
    user: Option<String>,
    /// Its unit directories, highest priority first, under the root.
    dirs: Vec<PathBuf>,
    /// The directories whose `.wants`, `.requires` and `.upholds` entries
    /// count for it: a user's own, or every user's shared ones.
    links: Vec<PathBuf>,
    /// Where its services run from without `WorkingDirectory=`: `/` for the
    /// system manager, the user's home for a user's.
    runs_from: Cwd,
}

impl Manager {
    /// `unit` as a message names it, with its manager.
    fn label(&self, unit: &str) -> String {
        match self.user.as_deref() {
            None => unit.to_string(),
            Some(EVERY_USER) => format!("{unit} of every user's manager"),
            Some(user) => format!("{unit} of {user}'s manager"),
        }
    }

    /// How to mask `unit` for this manager, for the fix.
    fn mask(&self, unit: &str) -> String {
        match self.user.as_deref() {
            None => format!("mask {unit} (`sudo systemctl mask {unit}`)"),
            Some(EVERY_USER) => format!("mask {unit} (`sudo systemctl --global mask {unit}`)"),
            Some(user) => format!("mask {unit} as {user} (`systemctl --user mask {unit}`)"),
        }
    }
}

/// What one manager's unit directories hold.
#[derive(Default)]
struct Index {
    /// Every service, timer and path unit name a unit directory holds.
    units: BTreeSet<String>,
    /// Every name a dependency directory holds, which enables it.
    enabled: BTreeSet<String>,
}

/// A service that runs updatedb, with what starts it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitRun {
    /// What starts it.
    pub start: Start,
    /// The service; empty for a unit directory NAILS cannot list.
    pub service: String,
    /// Its updatedb commands, each with the key that sets it, or why they
    /// are not known.
    pub commands: Result<Vec<(&'static str, ExecCommand)>, String>,
    /// Where its commands run, against which updatedb resolves a relative
    /// path.
    pub cwd: Cwd,
    /// The database it writes without `--output`, where known.
    pub database: Option<&'static str>,
}

/// What the managers' units hold of updatedb.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Units {
    /// Whether a service that runs updatedb, or one of plocate's, mlocate's
    /// or NixOS's, is installed.
    pub installed: bool,
    /// The services that run updatedb.
    pub runs: Vec<UnitRun>,
    /// How to stop what starts them, for the fix.
    pub remedies: Vec<String>,
    /// Why an installed service does not run updatedb, for a message.
    pub notes: Vec<String>,
}

/// A run that `what`, which NAILS cannot read, may start.
fn unread(what: String, why: String) -> UnitRun {
    UnitRun {
        start: Start::Unread(what),
        service: String::new(),
        commands: Err(why),
        cwd: Cwd::Root,
        database: None,
    }
}

/// List `dir` into `index`; `count_links` says whether its dependency
/// directories enable units. A directory NAILS cannot list goes to `unread`,
/// and the rest is still read.
fn index_dir<F: Filesystem>(
    fs: &F,
    files: &DecoyFiles<'_, F>,
    dir: &Path,
    count_links: bool,
    index: &mut Index,
    unread_dirs: &mut Vec<UnitRun>,
) {
    let unit_like = |name: &str| {
        [".service", ".timer", ".path"]
            .iter()
            .any(|kind| name.ends_with(kind))
    };
    let mut list = |dir: &Path| {
        files.list(dir).unwrap_or_else(|why| {
            unread_dirs.push(unread(format!("the units in {}", files.shown(dir)), why));
            Vec::new()
        })
    };
    for entry in list(dir) {
        let Some(name) = entry.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if unit_like(name) {
            index.units.insert(name.to_string());
        }
        let dependency = [".wants", ".requires", ".upholds"]
            .iter()
            .any(|suffix| name.ends_with(suffix));
        if !(count_links && dependency) {
            continue;
        }
        for link in list(&entry) {
            // An entry that leads to /dev/null is a masked dependency,
            // which systemd ignores.
            if fs
                .canonicalize(&link)
                .is_ok_and(|target| target == Path::new("/dev/null"))
            {
                continue;
            }
            if let Some(unit) = link.file_name().and_then(|name| name.to_str())
                && unit_like(unit)
            {
                index.enabled.insert(unit.to_string());
            }
        }
    }
}

/// The updatedb that `command` runs: its program, or the first word after it
/// that is an updatedb, as a program that runs another passes it; `Err` when
/// it names updatedb in a way NAILS does not follow.
fn updatedb_in(command: &ExecCommand) -> Result<Option<ExecCommand>, String> {
    let words: Vec<&Vec<u8>> = std::iter::once(&command.program)
        .chain(&command.args)
        .collect();
    let program = String::from_utf8_lossy(&command.program);
    match words.iter().position(|word| is_updatedb(word)) {
        Some(at) if words[..at].iter().any(|word| mentions_updatedb(word)) => Err(format!(
            "it runs {program}, which names updatedb before the updatedb it runs"
        )),
        Some(at) => Ok(Some(ExecCommand {
            program: words[at].clone(),
            args: words[at + 1..].iter().map(|word| (*word).clone()).collect(),
        })),
        None if words.iter().any(|word| mentions_updatedb(word)) => Err(format!(
            "it runs {program}, which names updatedb in a way NAILS does not follow"
        )),
        None => Ok(None),
    }
}

/// The updatedb commands of a service's `[Service]` assignments, each with
/// its key; `Err` when one names updatedb in a way NAILS does not follow. A
/// value NAILS cannot split, and that names no updatedb, runs none.
fn updatedb_commands(
    assignments: &[Assignment],
) -> Result<Vec<(&'static str, ExecCommand)>, String> {
    let mut out = Vec::new();
    for key in EXEC_KEYS {
        for value in list_values(assignments, key) {
            let commands = match exec_commands(&value) {
                Ok(commands) => commands,
                Err(why) if mentions_updatedb(value.as_bytes()) => {
                    return Err(format!("NAILS cannot read its {key}= ({why})"));
                }
                Err(_) => continue,
            };
            for command in commands {
                if let Some(found) = updatedb_in(&command)? {
                    out.push((*key, found));
                }
            }
        }
    }
    Ok(out)
}

/// The users `/etc/passwd` names, each with their home and uid.
fn users<F: Filesystem>(files: &DecoyFiles<'_, F>) -> BTreeMap<String, (String, Option<u32>)> {
    let mut out = BTreeMap::new();
    let DecoyFile::Text(passwd) = files.read(&files.root().join("etc/passwd")) else {
        return out;
    };
    for line in String::from_utf8_lossy(&passwd).lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if let (Some(name), Some(uid), Some(home)) = (fields.first(), fields.get(2), fields.get(5))
            && !name.is_empty()
            && home.starts_with('/')
            && *home != "/"
        {
            out.entry(name.to_string())
                .or_insert_with(|| (home.to_string(), uid.parse().ok()));
        }
    }
    out
}

/// The managers whose units are read: the system's, every user's shared
/// directories, and each user's own.
fn managers<F: Filesystem>(files: &DecoyFiles<'_, F>) -> Vec<Manager> {
    let root = files.root();
    let under = |dirs: &[&str]| -> Vec<PathBuf> { dirs.iter().map(|dir| root.join(dir)).collect() };
    let shared = under(SHARED_USER_UNIT_PATH);
    let mut out = vec![
        Manager {
            user: None,
            dirs: under(SYSTEM_UNIT_PATH),
            links: under(SYSTEM_UNIT_PATH),
            runs_from: Cwd::Root,
        },
        Manager {
            user: Some(EVERY_USER.to_string()),
            dirs: shared.clone(),
            links: shared.clone(),
            runs_from: Cwd::Unknown(
                "every user's manager runs it from that user's home".to_string(),
            ),
        },
    ];
    for (name, (home_dir, uid)) in users(files) {
        let home = root.join(home_dir.trim_start_matches('/'));
        let runtime = |dir: &str| uid.map(|uid| root.join(format!("run/user/{uid}/systemd/{dir}")));
        // The user manager's search path, highest priority first, and
        // which of it is the user's own.
        let path: Vec<(Option<PathBuf>, bool)> = vec![
            (Some(home.join(".config/systemd/user.control")), true),
            (runtime("user.control"), true),
            (runtime("transient"), true),
            (runtime("generator.early"), true),
            (Some(home.join(".config/systemd/user")), true),
            (Some(shared[0].clone()), false),
            (Some(shared[1].clone()), false),
            (runtime("user"), true),
            (Some(shared[2].clone()), false),
            (runtime("generator"), true),
            (Some(home.join(".local/share/systemd/user")), true),
            (Some(shared[3].clone()), false),
            (Some(shared[4].clone()), false),
            (Some(shared[5].clone()), false),
            (Some(shared[6].clone()), false),
            (runtime("generator.late"), true),
        ];
        let mut dirs = Vec::new();
        let mut links = Vec::new();
        for (dir, own) in path {
            let Some(dir) = dir else { continue };
            if own {
                links.push(dir.clone());
            }
            dirs.push(dir);
        }
        out.push(Manager {
            user: Some(name),
            dirs,
            links,
            runs_from: Cwd::Dir(PathBuf::from(home_dir)),
        });
    }
    out
}

/// The services that run updatedb under the root, with what starts each
/// (see the [module docs](self)).
pub fn units<F: Filesystem>(fs: &F, files: &DecoyFiles<'_, F>) -> Units {
    use super::super::decoy_posture::unit_active;
    let root = files.root().to_path_buf();
    let mut found = Units::default();
    for manager in managers(files) {
        let system = manager.user.is_none();
        let mut index = Index::default();
        for dir in &manager.dirs {
            let counts = manager.links.contains(dir);
            index_dir(fs, files, dir, counts, &mut index, &mut found.runs);
        }
        let active = |unit: &str| system && unit_active(fs, &root, unit);
        let named: BTreeSet<String> = index.units.union(&index.enabled).cloned().collect();
        // Each service a trigger that fires starts, with the trigger.
        let mut triggered: BTreeMap<String, String> = BTreeMap::new();
        for unit in &named {
            let Some((suffix, section)) =
                TRIGGERS.iter().find(|(suffix, _)| unit.ends_with(suffix))
            else {
                continue;
            };
            if !(index.enabled.contains(unit) || active(unit)) {
                continue;
            }
            let assignments = match unit_section(files, &manager.dirs, unit, section) {
                UnitSection::Assignments(assignments) => assignments,
                UnitSection::Missing | UnitSection::Masked => continue,
                UnitSection::Unknown(why) => {
                    found.runs.push(unread(manager.label(unit), why));
                    continue;
                }
            };
            let service = list_values(&assignments, "Unit").pop().unwrap_or_else(|| {
                format!("{}.service", unit.strip_suffix(suffix).unwrap_or(unit))
            });
            triggered.entry(service).or_insert_with(|| unit.clone());
        }
        // plocate's, mlocate's and NixOS's own services are looked for by
        // name too, as `systemctl start` finds them.
        let own = LOCATE_SERVICES
            .iter()
            .filter(|_| system)
            .map(|(name, _)| (*name).to_string());
        let services: BTreeSet<String> = named
            .iter()
            .chain(triggered.keys())
            .cloned()
            .chain(own)
            .filter(|unit| unit.ends_with(".service"))
            .collect();
        for service in &services {
            let known = system
                .then(|| LOCATE_SERVICES.iter().find(|(name, _)| name == service))
                .flatten();
            let trigger = triggered.get(service);
            let enabled = index.enabled.contains(service);
            let start = if active(service) {
                Start::Now(format!("{service} is active"))
            } else if let Some(trigger) = trigger {
                Start::Timer(manager.label(trigger))
            } else if enabled {
                Start::Enabled(manager.label(service))
            } else if known.is_some() {
                Start::ByHand(format!("systemctl start {service}"))
            } else {
                continue;
            };
            let assignments = match unit_section(files, &manager.dirs, service, "Service") {
                UnitSection::Missing => continue,
                UnitSection::Masked => {
                    if known.is_some() {
                        found.installed = true;
                        found.notes.push(format!("{service} is masked"));
                    }
                    continue;
                }
                UnitSection::Assignments(assignments) => assignments,
                UnitSection::Unknown(why) if known.is_none() => {
                    found.runs.push(unread(manager.label(service), why));
                    continue;
                }
                UnitSection::Unknown(why) => {
                    found.installed = true;
                    found.runs.push(UnitRun {
                        start,
                        service: service.clone(),
                        commands: Err(why),
                        cwd: Cwd::Root,
                        database: known.map(|(_, database)| *database),
                    });
                    continue;
                }
            };
            let commands = updatedb_commands(&assignments);
            if commands.as_ref().is_ok_and(Vec::is_empty) {
                if known.is_some() {
                    found.installed = true;
                    found
                        .notes
                        .push(format!("{service} runs no updatedb command"));
                }
                continue;
            }
            // A service that runs updatedb shows it is installed, wherever
            // its program lies.
            found.installed = true;
            let remedies = trigger
                .map(|trigger| manager.mask(trigger))
                .into_iter()
                .chain(enabled.then(|| manager.mask(service)));
            for remedy in remedies {
                if !found.remedies.contains(&remedy) {
                    found.remedies.push(remedy);
                }
            }
            found.runs.push(UnitRun {
                start,
                service: service.clone(),
                commands,
                cwd: if list_values(&assignments, "WorkingDirectory").is_empty() {
                    manager.runs_from.clone()
                } else {
                    Cwd::Unknown(format!("{service} sets WorkingDirectory="))
                },
                database: known.map(|(_, database)| *database),
            });
        }
    }
    found
}
