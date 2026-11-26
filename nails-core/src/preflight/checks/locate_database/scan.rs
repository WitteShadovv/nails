// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What on the decoy may run updatedb: its units, the units the system
//! manager has loaded, its cron and `at` jobs, its processes, and the
//! updatedb programs a person may start ([`super`] says what each counts
//! for).

use super::files::{DecoyFile, DecoyFiles};
use super::unit::{SYSTEM_UNIT_PATH, template};
use crate::Filesystem;
use std::collections::BTreeSet;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// The words that name updatedb: `updatedb` (plocate's, mlocate's and
/// findutils' program, `updatedb.plocate`, `plocate-updatedb.timer`) and
/// `locatedb` (NixOS's `update-locatedb.service`, whose command is a script
/// of that name).
const NAMES: [&[u8]; 2] = [b"updatedb", b"locatedb"];

/// The directories every user's manager reads units from, relative to the
/// root.
const SHARED_USER_UNIT_PATH: &[&str] = &[
    "etc/xdg/systemd/user",
    "etc/systemd/user",
    "run/systemd/user",
    "usr/local/share/systemd/user",
    "usr/share/systemd/user",
    "usr/local/lib/systemd/user",
    "usr/lib/systemd/user",
];

/// A user's own unit directories, relative to the home.
const HOME_UNIT_PATH: &[&str] = &[
    ".config/systemd/user.control",
    ".config/systemd/user",
    ".local/share/systemd/user",
];

/// A user's runtime unit directories, relative to `/run/user/<uid>/systemd`:
/// `systemd-run --user` writes its units to `transient`.
const RUNTIME_USER_UNIT_PATH: &[&str] = &[
    "user.control",
    "transient",
    "generator.early",
    "user",
    "generator",
    "generator.late",
];

/// The cron and `at` tables read, relative to the root: system crontabs, the
/// anacrontab, the cron scripts run-parts runs, and the users' crontabs and
/// `at` jobs (Debian's `/var/spool/cron/crontabs` and `atjobs`, cronie's
/// `/var/spool/cron`, Fedora's and Arch's `/var/spool/at`).
const CRON_PATHS: &[&str] = &[
    "etc/crontab",
    "etc/anacrontab",
    "etc/cron.d",
    "etc/cron.hourly",
    "etc/cron.daily",
    "etc/cron.weekly",
    "etc/cron.monthly",
    "var/spool/cron",
    "var/spool/at",
];

/// Where an updatedb program a person may run is installed, relative to the
/// root.
const PROGRAM_DIRS: &[&str] = &[
    "usr/bin",
    "usr/sbin",
    "bin",
    "sbin",
    "usr/local/bin",
    "usr/local/sbin",
    "run/current-system/sw/bin",
];

/// The names of the updatedb programs.
const PROGRAMS: &[&str] = &[
    "updatedb",
    "updatedb.plocate",
    "updatedb.mlocate",
    "updatedb.findutils",
];

/// Whether `bytes` names updatedb, in any case.
pub(in crate::preflight::checks) fn names_updatedb(bytes: &[u8]) -> bool {
    bytes
        .windows(8)
        .any(|window| NAMES.iter().any(|name| window.eq_ignore_ascii_case(name)))
}

/// One thing that may run updatedb, and how to stop it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Finding {
    /// What it is, as the message names it.
    pub(super) what: String,
    /// How to stop it, as the remediation names it; `None` where the
    /// general fix is the way.
    pub(super) fix: Option<String>,
}

impl Finding {
    fn new(what: impl Into<String>, fix: Option<String>) -> Self {
        Self {
            what: what.into(),
            fix,
        }
    }

    /// What NAILS cannot read, which may hold or be an updatedb.
    fn unread(what: &str, why: String) -> Self {
        Self::new(
            format!("NAILS cannot tell whether {what} runs updatedb: {why}"),
            None,
        )
    }
}

/// What the check found.
#[derive(Default)]
pub(super) struct Found {
    /// What may run updatedb, which refuses.
    pub(super) runs: Vec<Finding>,
    /// The updatedb programs a person may start, which warn.
    pub(super) by_hand: Vec<String>,
}

impl Found {
    fn run(&mut self, finding: Finding) {
        if !self.runs.contains(&finding) {
            self.runs.push(finding);
        }
    }
}

/// A service manager's unit directories, highest priority first, and whether
/// it is the system manager's, whose units `systemctl mask` masks.
struct Tree {
    dirs: Vec<PathBuf>,
    system: bool,
}

/// How to stop `unit`, whose file `path` names updatedb, in `tree`: mask it,
/// for every user where it lies in a directory they share, and remove a
/// drop-in, which no mask of its own reaches, or a unit in a user's own
/// directories.
fn unit_fix(tree: &Tree, shared: &[PathBuf], unit: &str, path: &Path, shown: &str) -> String {
    let dropin = path
        .parent()
        .is_some_and(|dir| file_name(dir).ends_with(".d"));
    if dropin {
        format!("remove {shown}")
    } else if tree.system {
        format!("`sudo systemctl mask --now {unit}`")
    } else if shared.iter().any(|dir| path.starts_with(dir)) {
        format!("`sudo systemctl --global mask {unit}`")
    } else {
        format!("remove {shown}")
    }
}

/// The file of `unit` that `tree` loads first, as [`DecoyFiles::read`] reads
/// it, or `None` where no directory holds the name: for an instance, its
/// template's.
fn loaded_file<F: Filesystem>(
    files: &DecoyFiles<'_, F>,
    tree: &Tree,
    unit: &str,
) -> Option<DecoyFile> {
    for dir in &tree.dirs {
        match files.read(&dir.join(unit)) {
            DecoyFile::Absent => {}
            other => return Some(other),
        }
    }
    template(unit).and_then(|template| loaded_file(files, tree, &template))
}

/// Whether `unit` is masked in `tree`: the file systemd loads for it is a
/// link to `/dev/null` or empty.
fn masked<F: Filesystem>(files: &DecoyFiles<'_, F>, tree: &Tree, unit: &str) -> bool {
    match loaded_file(files, tree, unit) {
        Some(DecoyFile::Null) => true,
        Some(DecoyFile::Text(text)) => text.is_empty(),
        _ => false,
    }
}

/// The file name of `path`, lossily.
fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// The units of `tree` that name updatedb and are not masked: every file in
/// its directories and in their subdirectories (drop-ins and dependency
/// entries).
fn read_tree<F: Filesystem>(fs: &F, files: &DecoyFiles<'_, F>, tree: &Tree, found: &mut Found) {
    for dir in &tree.dirs {
        let entries = match files.list(dir) {
            Ok(entries) => entries,
            Err(why) => {
                found.run(Finding::unread(
                    &format!("a unit in {}", files.shown(dir)),
                    why,
                ));
                continue;
            }
        };
        for entry in entries {
            let name = file_name(&entry);
            if fs.is_directory(&entry).unwrap_or(false) {
                let inner = match files.list(&entry) {
                    Ok(inner) => inner,
                    Err(why) => {
                        found.run(Finding::unread(
                            &format!("a unit in {}", files.shown(&entry)),
                            why,
                        ));
                        continue;
                    }
                };
                for file in inner {
                    // A drop-in belongs to the unit its directory names; a
                    // dependency entry is the unit it names.
                    let unit = name
                        .strip_suffix(".d")
                        .map_or_else(|| file_name(&file), str::to_string);
                    read_unit_file(files, tree, &unit, &file, found);
                }
            } else {
                read_unit_file(files, tree, &name, &entry, found);
            }
        }
    }
}

/// `path`, a file of `unit` in `tree`: a finding where it names updatedb and
/// the unit is not masked, or where NAILS cannot read it.
fn read_unit_file<F: Filesystem>(
    files: &DecoyFiles<'_, F>,
    tree: &Tree,
    unit: &str,
    path: &Path,
    found: &mut Found,
) {
    let shown = files.shown(path);
    let names = match files.read(path) {
        DecoyFile::Absent | DecoyFile::Null => names_updatedb(unit.as_bytes()),
        DecoyFile::Text(text) => names_updatedb(unit.as_bytes()) || names_updatedb(&text),
        DecoyFile::Unread(why) => {
            found.run(Finding::unread(&shown, why));
            return;
        }
    };
    if !names || masked(files, tree, unit) {
        return;
    }
    let shared: Vec<PathBuf> = SHARED_USER_UNIT_PATH
        .iter()
        .map(|dir| files.root().join(dir))
        .collect();
    let fix = unit_fix(tree, &shared, unit, path, &shown);
    found.run(Finding::new(
        format!("{shown} names updatedb, and {unit} is not masked"),
        Some(fix),
    ));
}

/// The homes whose users' managers may run units: each `/etc/passwd` names,
/// and the directories of `/home`. What NAILS cannot read goes to `found`.
fn homes<F: Filesystem>(files: &DecoyFiles<'_, F>, found: &mut Found) -> BTreeSet<PathBuf> {
    let root = files.root();
    let mut out = BTreeSet::new();
    match files.read(&root.join("etc/passwd")) {
        DecoyFile::Text(text) => {
            for line in String::from_utf8_lossy(&text).lines() {
                if let Some(home) = line.split(':').nth(5)
                    && home.starts_with('/')
                    && home != "/"
                {
                    out.insert(root.join(home.trim_start_matches('/')));
                }
            }
        }
        DecoyFile::Absent | DecoyFile::Null => {}
        DecoyFile::Unread(why) => found.run(Finding::unread("a user's unit", why)),
    }
    match files.list(&root.join("home")) {
        Ok(entries) => out.extend(entries),
        Err(why) => found.run(Finding::unread("a user's unit", why)),
    }
    out
}

/// The unit trees: the system manager's, every user's own with the shared
/// directories, and the runtime directories of each user in `/run/user`.
fn trees<F: Filesystem>(files: &DecoyFiles<'_, F>, found: &mut Found) -> Vec<Tree> {
    let root = files.root();
    let shared: Vec<PathBuf> = SHARED_USER_UNIT_PATH
        .iter()
        .map(|dir| root.join(dir))
        .collect();
    let mut out = vec![
        Tree {
            dirs: SYSTEM_UNIT_PATH.iter().map(|dir| root.join(dir)).collect(),
            system: true,
        },
        // The shared directories alone, which a user's mask in a home does
        // not reach.
        Tree {
            dirs: shared.clone(),
            system: false,
        },
    ];
    for home in homes(files, found) {
        let mut dirs: Vec<PathBuf> = HOME_UNIT_PATH.iter().map(|dir| home.join(dir)).collect();
        dirs.extend(shared.iter().cloned());
        out.push(Tree {
            dirs,
            system: false,
        });
    }
    match files.list(&root.join("run/user")) {
        Ok(entries) => {
            for runtime in entries {
                let systemd = runtime.join("systemd");
                out.push(Tree {
                    dirs: RUNTIME_USER_UNIT_PATH
                        .iter()
                        .map(|dir| systemd.join(dir))
                        .collect(),
                    system: false,
                });
            }
        }
        Err(why) => found.run(Finding::unread("a user's unit", why)),
    }
    out
}

/// The cron and `at` tables of [`CRON_PATHS`] below `path`, `depth` levels
/// of directories deep, that name updatedb.
fn read_cron<F: Filesystem>(
    fs: &F,
    files: &DecoyFiles<'_, F>,
    path: &Path,
    depth: usize,
    found: &mut Found,
) {
    let shown = files.shown(path);
    if fs.is_directory(path).unwrap_or(false) {
        if depth == 0 {
            found.run(Finding::unread(&shown, format!("{shown} is not a file")));
            return;
        }
        match files.list(path) {
            Ok(entries) => {
                for entry in entries {
                    read_cron(fs, files, &entry, depth - 1, found);
                }
            }
            Err(why) => found.run(Finding::unread(&format!("a job in {shown}"), why)),
        }
        return;
    }
    match files.read(path) {
        DecoyFile::Absent | DecoyFile::Null => {}
        DecoyFile::Text(text) => {
            if names_updatedb(file_name(path).as_bytes()) || names_updatedb(&text) {
                found.run(Finding::new(
                    format!("{shown} names updatedb"),
                    Some(format!("remove {shown}")),
                ));
            }
        }
        DecoyFile::Unread(why) => found.run(Finding::unread(&shown, why)),
    }
}

/// The processes whose name names updatedb. A `/proc` that hides process 1,
/// or a process NAILS cannot read, may hide one.
fn read_processes<F: Filesystem>(fs: &F, root: &Path, found: &mut Found) {
    let proc = root.join("proc");
    let entries = match fs.list_directory(&proc) {
        Ok(entries) => entries,
        Err(e) => {
            found.run(Finding::unread(
                "a process",
                format!("NAILS cannot list /proc ({e})"),
            ));
            return;
        }
    };
    let pids: Vec<PathBuf> = entries
        .into_iter()
        .filter(|entry| {
            entry.file_name().is_some_and(|name| {
                !name.is_empty() && name.as_bytes().iter().all(u8::is_ascii_digit)
            })
        })
        .collect();
    if !pids.contains(&proc.join("1")) {
        found.run(Finding::unread(
            "a process",
            "/proc hides process 1 from NAILS, and so other users' processes; run the command \
             again with sudo"
                .to_string(),
        ));
    }
    for dir in pids {
        let pid = file_name(&dir);
        match fs.read_file_bytes(&dir.join("comm")) {
            Ok(comm) if names_updatedb(&comm) => found.run(Finding::new(
                format!(
                    "an updatedb runs now (process {pid}, {})",
                    String::from_utf8_lossy(comm.strip_suffix(b"\n").unwrap_or(&comm))
                ),
                Some(format!("wait for process {pid} to end")),
            )),
            Ok(_) => {}
            // A process that ended since the listing is gone.
            Err(e) if e.io_kind() == Some(std::io::ErrorKind::NotFound) => {}
            Err(e) => found.run(Finding::unread(
                &format!("process {pid}"),
                format!(
                    "NAILS cannot read /proc/{pid}/comm ({e}); run the command again with sudo"
                ),
            )),
        }
    }
}

/// The units `shown`, the text of `systemctl show`, gives that name updatedb
/// and are active, or loaded and not masked. An answer that shows no
/// `init.scope`, which every system manager runs, is none NAILS can read.
fn read_loaded(shown: std::result::Result<String, String>, found: &mut Found) {
    let text = match shown {
        Ok(text) if text.lines().any(|line| line == "Id=init.scope") => text,
        Ok(_) => {
            found.run(Finding::unread(
                "a unit the system manager has loaded",
                "`systemctl show` lists no init.scope".to_string(),
            ));
            return;
        }
        Err(why) => {
            found.run(Finding::unread("a unit the system manager has loaded", why));
            return;
        }
    };
    for block in text.split("\n\n") {
        let value = |key: &str| {
            block
                .lines()
                .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
                .unwrap_or("")
        };
        if !names_updatedb(block.as_bytes()) {
            continue;
        }
        let id = value("Id");
        // A unit whose state the answer leaves out counts as running.
        let active = !matches!(value("ActiveState"), "inactive" | "failed");
        let load = value("LoadState");
        if active {
            found.run(Finding::new(
                format!("the system manager runs {id}, which names updatedb"),
                Some(format!("`sudo systemctl stop {id}`")),
            ));
        } else if !matches!(load, "masked" | "not-found") {
            found.run(Finding::new(
                format!(
                    "the system manager has {id} loaded, which names updatedb, and it is not masked"
                ),
                Some(format!("`sudo systemctl mask --now {id}`")),
            ));
        }
    }
}

/// The updatedb programs a person may start.
fn read_programs<F: Filesystem>(fs: &F, files: &DecoyFiles<'_, F>, found: &mut Found) {
    for dir in PROGRAM_DIRS {
        for program in PROGRAMS {
            let path = files.root().join(dir).join(program);
            match fs.path_exists(&path) {
                Ok(true) => {
                    let shown = files.shown(&path);
                    if !found.by_hand.contains(&shown) {
                        found.by_hand.push(shown);
                    }
                }
                Ok(false) => {}
                Err(e) => found.run(Finding::unread(
                    &files.shown(&path),
                    format!("NAILS cannot look it up ({e})"),
                )),
            }
        }
    }
}

/// What on the decoy under the root of `files` may run updatedb, read
/// through `fs`; `shown` is what `systemctl show` gives, or why NAILS
/// cannot ask.
pub(super) fn scan<F: Filesystem>(
    fs: &F,
    files: &DecoyFiles<'_, F>,
    shown: std::result::Result<String, String>,
) -> Found {
    let mut found = Found::default();
    for tree in trees(files, &mut found) {
        read_tree(fs, files, &tree, &mut found);
    }
    read_loaded(shown, &mut found);
    for path in CRON_PATHS {
        read_cron(fs, files, &files.root().join(path), 2, &mut found);
    }
    read_processes(fs, files.root(), &mut found);
    read_programs(fs, files, &mut found);
    found
}
