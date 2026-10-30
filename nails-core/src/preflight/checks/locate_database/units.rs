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
//! - when a timer or a path unit starts it that is enabled, or that the
//!   system manager runs as `systemctl list-units` shows it: one started with
//!   `systemctl start`, an instance of a template, a transient one as
//!   `systemd-run --on-calendar` makes it, and one masked, or whose file is
//!   gone, since it started. It starts its first `Unit=` systemd takes, or
//!   the service of its own name. Where NAILS cannot ask the system manager,
//!   and for a user's manager, which it never asks, a transient trigger whose
//!   file is there counts;
//! - whenever its manager starts, when it is enabled itself: an entry for it
//!   in a `.wants`, `.requires` or `.upholds` directory, as `systemctl
//!   enable` and `systemctl add-wants` make. The soft-reboot back to the
//!   decoy starts the system manager again;
//! - by hand otherwise, for plocate's, mlocate's and NixOS's own services,
//!   which `systemctl start` runs, and for a service a trigger starts whose
//!   state NAILS cannot ask the system manager about.
//!
//! A service another unit pulls in with `Wants=` or `Requires=` in its own
//! file, or that a unit started by hand runs, is not followed, nor are
//! sockets, udev rules and `at` jobs.
//!
//! The system manager's units are read from [`SYSTEM_UNIT_PATH`]. A user's
//! manager reads its own directories (`~/.config/systemd/user`,
//! `~/.local/share/systemd/user`, `/run/user/<uid>/systemd/…`) and the
//! directories every user shares (`/etc/xdg/systemd/user`,
//! `/etc/systemd/user`, `/run/systemd/user` and `systemd/user` in
//! `/usr/local/share`, `/usr/share`, `/usr/local/lib` and `/usr/lib`), whose
//! dependency entries, as `systemctl --global enable` makes them, enable a
//! unit for every user. The users are those `/etc/passwd` names, the owners
//! of the other directories in `/home`, and of the other numbers in
//! `/run/user`. A user's manager leaves no marker of what it runs and has no
//! bus NAILS asks, so of a user's triggers only an enabled or a transient one
//! counts, and a user's updatedb running now is seen by its process alone. A
//! unit directory, or an `/etc/passwd`, NAILS cannot read may hold a unit
//! that runs updatedb, so it is one NAILS cannot tell about.

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

/// Whose service manager a [`Manager`] is.
enum Owner {
    /// The system manager.
    System,
    /// Every user's, for the units in the directories all users share.
    EveryUser,
    /// The user `/etc/passwd` names so.
    User(String),
    /// The user of a home or runtime directory `/etc/passwd` names nobody
    /// for, such as `/home/x` or `user 1001`.
    Unlisted(String),
}

/// A service manager whose units are read.
struct Manager {
    /// Whose it is.
    owner: Owner,
    /// Its unit directories, highest priority first, under the root.
    dirs: Vec<PathBuf>,
    /// The directories whose `.wants`, `.requires` and `.upholds` entries
    /// count for it: a user's own, or every user's shared ones.
    links: Vec<PathBuf>,
    /// Its directory of transient units, which run from when they are made
    /// until they stop, and are gone then.
    transient: Option<PathBuf>,
    /// Where its services run from without `WorkingDirectory=`: `/` for the
    /// system manager, the user's home for a user's.
    runs_from: Cwd,
}

impl Manager {
    /// `unit` as a message names it, with its manager.
    fn label(&self, unit: &str) -> String {
        match &self.owner {
            Owner::System => unit.to_string(),
            Owner::EveryUser => format!("{unit} of every user's manager"),
            Owner::User(user) => format!("{unit} of {user}'s manager"),
            Owner::Unlisted(whose) => format!("{unit} of the manager of {whose}"),
        }
    }

    /// How to stop `unit` for good, for the fix: mask it and stop it, or
    /// stop a transient one, which is gone once it stops.
    fn remedy(&self, unit: &str, transient: bool) -> String {
        let (verb, args) = if transient {
            ("stop", "stop")
        } else {
            ("mask", "mask --now")
        };
        match &self.owner {
            Owner::System => format!("{verb} {unit} (`sudo systemctl {args} {unit}`)"),
            Owner::EveryUser => format!("mask {unit} (`sudo systemctl --global mask {unit}`)"),
            Owner::User(user) => {
                format!("{verb} {unit} as {user} (`systemctl --user {args} {unit}`)")
            }
            Owner::Unlisted(whose) => {
                format!("{verb} {unit} as the user of {whose} (`systemctl --user {args} {unit}`)")
            }
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
    /// Every name the transient directory holds.
    transient: BTreeSet<String>,
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
/// directories enable units, `transient` whether it is the manager's
/// directory of transient units. A directory NAILS cannot list goes to
/// `unread_dirs`, and the rest is still read.
fn index_dir<F: Filesystem>(
    fs: &F,
    files: &DecoyFiles<'_, F>,
    dir: &Path,
    (count_links, transient): (bool, bool),
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
            if transient {
                index.transient.insert(name.to_string());
            }
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

/// The users `/etc/passwd` names, each with their home and uid; an
/// `/etc/passwd` NAILS cannot read goes to `unread_files`.
fn users<F: Filesystem>(
    files: &DecoyFiles<'_, F>,
    unread_files: &mut Vec<UnitRun>,
) -> BTreeMap<String, (String, Option<u32>)> {
    let mut out = BTreeMap::new();
    let passwd = files.root().join("etc/passwd");
    let text = match files.read(&passwd) {
        DecoyFile::Text(text) => text,
        DecoyFile::Absent | DecoyFile::Null => return out,
        DecoyFile::Unread(why) => {
            unread_files.push(unread(
                "the units of the users /etc/passwd names".to_string(),
                why,
            ));
            return out;
        }
    };
    for line in String::from_utf8_lossy(&text).lines() {
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

/// A user's manager: its own directories in `home` and `/run/user/<uid>`,
/// those every user shares between them.
fn user_manager(root: &Path, owner: Owner, home: Option<&str>, uid: Option<u32>) -> Manager {
    let shared: Vec<PathBuf> = SHARED_USER_UNIT_PATH
        .iter()
        .map(|dir| root.join(dir))
        .collect();
    let home_dir = home.map(|home| root.join(home.trim_start_matches('/')));
    let in_home = |dir: &str| home_dir.as_ref().map(|home| home.join(dir));
    let runtime = |dir: &str| uid.map(|uid| root.join(format!("run/user/{uid}/systemd/{dir}")));
    // The user manager's search path, highest priority first, and which of
    // it is the user's own.
    let path: Vec<(Option<PathBuf>, bool)> = vec![
        (in_home(".config/systemd/user.control"), true),
        (runtime("user.control"), true),
        (runtime("transient"), true),
        (runtime("generator.early"), true),
        (in_home(".config/systemd/user"), true),
        (Some(shared[0].clone()), false),
        (Some(shared[1].clone()), false),
        (runtime("user"), true),
        (Some(shared[2].clone()), false),
        (runtime("generator"), true),
        (in_home(".local/share/systemd/user"), true),
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
    let runs_from = match home {
        Some(home) => Cwd::Dir(PathBuf::from(home)),
        None => Cwd::Unknown("NAILS does not know the home of its user".to_string()),
    };
    Manager {
        owner,
        dirs,
        links,
        transient: runtime("transient"),
        runs_from,
    }
}

/// The managers whose units are read: the system's, every user's shared
/// directories, each user's own, and those of the homes and runtime
/// directories no user `/etc/passwd` names has; what NAILS cannot read of
/// them goes to `unread_runs`.
fn managers<F: Filesystem>(
    files: &DecoyFiles<'_, F>,
    unread_runs: &mut Vec<UnitRun>,
) -> Vec<Manager> {
    let root = files.root();
    let under = |dirs: &[&str]| -> Vec<PathBuf> { dirs.iter().map(|dir| root.join(dir)).collect() };
    let shared = under(SHARED_USER_UNIT_PATH);
    let mut out = vec![
        Manager {
            owner: Owner::System,
            dirs: under(SYSTEM_UNIT_PATH),
            links: under(SYSTEM_UNIT_PATH),
            transient: Some(root.join("run/systemd/transient")),
            runs_from: Cwd::Root,
        },
        Manager {
            owner: Owner::EveryUser,
            dirs: shared.clone(),
            links: shared.clone(),
            transient: None,
            runs_from: Cwd::Unknown(
                "every user's manager runs it from that user's home".to_string(),
            ),
        },
    ];
    let users = users(files, unread_runs);
    let homes: BTreeSet<PathBuf> = users
        .values()
        .map(|(home, _)| root.join(home.trim_start_matches('/')))
        .collect();
    let uids: BTreeSet<u32> = users.values().filter_map(|(_, uid)| *uid).collect();
    for (name, (home, uid)) in &users {
        out.push(user_manager(
            root,
            Owner::User(name.clone()),
            Some(home.as_str()),
            *uid,
        ));
    }
    // The directories of /home and /run/user that belong to no user
    // /etc/passwd names: a user of a directory service, or one removed.
    let mut list = |dir: &str| {
        files.list(&root.join(dir)).unwrap_or_else(|why| {
            unread_runs.push(unread(
                format!("the units of the users with a directory in /{dir}"),
                why,
            ));
            Vec::new()
        })
    };
    let mut others: Vec<PathBuf> = list("home")
        .into_iter()
        .filter(|entry| !homes.contains(entry))
        .collect();
    others.sort();
    for home in others {
        let shown = files.shown(&home);
        out.push(user_manager(
            root,
            Owner::Unlisted(shown.clone()),
            Some(shown.as_str()),
            None,
        ));
    }
    let mut runtime_uids: Vec<u32> = list("run/user")
        .iter()
        .filter_map(|entry| entry.file_name()?.to_str()?.parse().ok())
        .filter(|uid| !uids.contains(uid))
        .collect();
    runtime_uids.sort_unstable();
    for uid in runtime_uids {
        out.push(user_manager(
            root,
            Owner::Unlisted(format!("user {uid}")),
            None,
            Some(uid),
        ));
    }
    out
}

/// The unit a trigger starts: the first `Unit=` systemd takes (a unit name
/// of a type, not the trigger itself; it ignores every later one), else the
/// service of the trigger's own name.
fn triggered_unit(
    assignments: &[Assignment],
    trigger: &str,
    suffix: &str,
) -> Result<String, String> {
    const TYPES: &[&str] = &[
        "service",
        "socket",
        "target",
        "device",
        "mount",
        "automount",
        "swap",
        "timer",
        "path",
        "slice",
        "scope",
    ];
    for assignment in assignments
        .iter()
        .filter(|assignment| assignment.key == "Unit")
    {
        let value = assignment.value.as_str();
        if value.contains('%') {
            return Err(format!(
                "{trigger} names the unit it starts with a specifier, which NAILS does not expand"
            ));
        }
        let typed = value
            .rsplit_once('.')
            .is_some_and(|(stem, kind)| !stem.is_empty() && TYPES.contains(&kind));
        if typed && value != trigger {
            return Ok(value.to_string());
        }
    }
    Ok(format!(
        "{}.service",
        trigger.strip_suffix(suffix).unwrap_or(trigger)
    ))
}

/// Whether a trigger runs.
enum Runs {
    /// It runs; `now` when the system manager shows it running, which no
    /// mask and no file gone since stops.
    Yes { now: bool },
    /// NAILS cannot tell, for this reason.
    Maybe(String),
}

/// The services a manager's triggers start: each one a trigger that runs
/// starts, with the trigger, and each one a trigger may run starts, with the
/// trigger and why NAILS cannot tell.
#[derive(Default)]
struct Starts {
    triggered: BTreeMap<String, String>,
    maybe: BTreeMap<String, (String, String)>,
}

/// What the `triggers` of `manager` start; what NAILS cannot read of them
/// goes to `unread_runs`.
fn trigger_starts<F: Filesystem>(
    files: &DecoyFiles<'_, F>,
    manager: &Manager,
    triggers: &[(&String, Runs)],
    unread_runs: &mut Vec<UnitRun>,
) -> Starts {
    let mut starts = Starts::default();
    for (unit, state) in triggers {
        let Some((suffix, section)) = TRIGGERS.iter().find(|(suffix, _)| unit.ends_with(suffix))
        else {
            continue;
        };
        let now = matches!(state, Runs::Yes { now: true });
        let own = || format!("{}.service", unit.strip_suffix(suffix).unwrap_or(unit));
        let service = match unit_section(files, &manager.dirs, unit, section) {
            UnitSection::Assignments(assignments) => {
                match triggered_unit(&assignments, unit, suffix) {
                    Ok(service) => service,
                    Err(why) => {
                        unread_runs.push(unread(manager.label(unit), why));
                        continue;
                    }
                }
            }
            // Masking stops nothing that runs: the manager runs the trigger
            // on until it stops, as it was loaded.
            UnitSection::Masked if now => own(),
            // One the manager runs from a file that is gone may start
            // another unit than that of its own name.
            UnitSection::Missing if now => {
                unread_runs.push(unread(
                    manager.label(unit),
                    format!(
                        "the system manager runs {unit}, and NAILS finds no file of it to read \
                         what it starts"
                    ),
                ));
                own()
            }
            UnitSection::Missing | UnitSection::Masked => continue,
            UnitSection::Unknown(why) => {
                unread_runs.push(unread(manager.label(unit), why));
                continue;
            }
        };
        match state {
            Runs::Yes { .. } => {
                starts
                    .triggered
                    .entry(service)
                    .or_insert_with(|| (*unit).clone());
            }
            Runs::Maybe(why) => {
                starts
                    .maybe
                    .entry(service)
                    .or_insert_with(|| ((*unit).clone(), why.clone()));
            }
        }
    }
    starts
}

/// The services that run updatedb under the root, with what starts each
/// (see the [module docs](self)). `started` are the timer and path units the
/// system manager runs now, or why NAILS cannot tell.
pub fn units<F: Filesystem>(
    fs: &F,
    files: &DecoyFiles<'_, F>,
    started: &Result<BTreeSet<String>, String>,
) -> Units {
    use super::super::decoy_posture::unit_active;
    let root = files.root().to_path_buf();
    let mut found = Units::default();
    for manager in managers(files, &mut found.runs) {
        let system = matches!(manager.owner, Owner::System);
        let mut index = Index::default();
        for dir in &manager.dirs {
            let flags = (
                manager.links.contains(dir),
                manager.transient.as_ref() == Some(dir),
            );
            index_dir(fs, files, dir, flags, &mut index, &mut found.runs);
        }
        let active = |unit: &str| system && unit_active(fs, &root, unit);
        let listed = started.as_ref().ok().filter(|_| system);
        // A trigger runs when the system manager runs it now, and when it is
        // enabled unless it is masked. A transient one runs until it stops,
        // and its file may stay a while after: the system manager's runs as
        // long as it lists it, a user's, whom NAILS does not ask, as long as
        // its file is there. Of the system manager's others, NAILS cannot
        // tell when it cannot ask.
        let started_now =
            |unit: &str| system && (active(unit) || listed.is_some_and(|set| set.contains(unit)));
        let runs = |unit: &str| {
            index.enabled.contains(unit)
                || started_now(unit)
                || (listed.is_none() && index.transient.contains(unit))
        };
        let unknown_state = started.as_ref().err().filter(|_| system);
        // The units on disk, and those the system manager runs: an instance
        // of a template, or one whose file is gone, it runs as loaded.
        let named: BTreeSet<String> = index
            .units
            .iter()
            .chain(&index.enabled)
            .chain(listed.into_iter().flatten())
            .cloned()
            .collect();
        // Whether each trigger runs, or why NAILS cannot tell.
        let mut triggers: Vec<(&String, Runs)> = Vec::new();
        for unit in &named {
            if !TRIGGERS.iter().any(|(suffix, _)| unit.ends_with(suffix)) {
                continue;
            }
            let state = if runs(unit) {
                Runs::Yes {
                    now: started_now(unit),
                }
            } else if let Some(why) = unknown_state {
                Runs::Maybe(why.clone())
            } else {
                continue;
            };
            triggers.push((unit, state));
        }
        let Starts { triggered, maybe } =
            trigger_starts(files, &manager, &triggers, &mut found.runs);
        // plocate's, mlocate's and NixOS's own services are looked for by
        // name too, as `systemctl start` finds them.
        let own = LOCATE_SERVICES
            .iter()
            .filter(|_| system)
            .map(|(name, _)| (*name).to_string());
        let services: BTreeSet<String> = named
            .iter()
            .chain(triggered.keys())
            .chain(maybe.keys())
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
            } else if let Some((trigger, why)) = maybe.get(service) {
                Start::ByHand(format!(
                    "systemctl start {trigger}, and NAILS cannot tell whether it runs now: {why}"
                ))
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
                .map(|trigger| manager.remedy(trigger, index.transient.contains(trigger)))
                .into_iter()
                .chain(enabled.then(|| manager.remedy(service, false)));
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
