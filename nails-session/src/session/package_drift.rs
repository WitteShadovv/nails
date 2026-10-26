// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Whether hidden sessions' package database still follows the decoy's.
//!
//! Hidden sessions run the decoy's programs through the root overlay, and
//! their package manager keeps its record of what is installed there as well:
//! the first change a hidden session makes to that record lands in the upper,
//! and from then on hidden sessions see their own copy of it, whatever the
//! decoy does to its own afterwards. Once the decoy installs, updates or
//! removes a package, hidden sessions run the decoy's new files under a record
//! that does not know of them, or keep their own older files over the decoy's
//! newer ones. Their package manager then works from a wrong record, and
//! programs can fail to start; on Arch Linux, after a full update in a hidden
//! session and a later one on the decoy, a hidden session can fail to boot.
//!
//! The `package-drift` check reads each package database the decoy keeps and
//! what the upper holds of it, and judges ([`judge_dpkg`], [`judge_pacman`],
//! [`judge_rpm`]):
//!
//! - dpkg rewrites its whole `status` file at each change, so hidden
//!   sessions keep a copy of it from their first change on. A package whose
//!   record in that copy differs from the decoy's drifted, unless a hidden
//!   session changed the package itself: dpkg writes, or deletes, a
//!   package's files in `/var/lib/dpkg/info` whenever it installs, updates or
//!   removes it, so a package with such a file, or a deletion of one, in the
//!   upper is one a hidden session changed.
//! - pacman keeps a directory per package, which the overlay merges: hidden
//!   sessions see the decoy's entries with their own added and the ones they
//!   deleted gone. A package drifted when the decoy changed one a hidden
//!   session changed too, so pacman lists it twice in hidden sessions and
//!   they keep their own files of it, or when a hidden session removed one the
//!   decoy changed since, so pacman lists the decoy's entry while the files
//!   the hidden session deleted stay deleted.
//! - rpm keeps a SQLite database, which NAILS does not read. Hidden sessions'
//!   copy drifted when the decoy's was written after it, by size and time
//!   alone; a change on the decoy between two changes in hidden sessions
//!   goes unseen.
//!
//! The check only warns, never refuses: a package a hidden session installs
//! on purpose is its own business, and the warning says what drifted and how
//! to bring it back in line. [`advisory`] gives the same warning for an entry
//! to show before it asks to log the operator out, and among the warnings of
//! its result.
//!
//! # Reading
//!
//! A database on a decoy filesystem of its own (a separate `/var`) is read
//! from the upper of that filesystem's overlay. Every read of the decoy goes
//! through the [`Filesystem`] seam ([`nails_base::packages`] on access times),
//! and each lookup below the decoy root passes only through entries already
//! seen not to be symbolic links. Only root reads the decoy's database without
//! changing its access time, so a `nails check` that is not running as root
//! says it cannot tell, and names the `sudo` line, whenever the verdict needs
//! more than the database's metadata. Nothing here writes.

use crate::error::Result;
use crate::filesystem::Filesystem;
use crate::preflight::{CheckResult, PreFlightCheck};
use nails_base::next_step::{NextStep, shell_word, sudo_line, sudo_line_for};
use nails_base::packages::{dpkg, pacman, rpm};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

mod read;

pub use read::verdicts;

/// The check's name, which the advisory carries too.
pub const NAME: &str = "package-drift";

/// How many drifted packages a message names before it counts the rest.
const NAMED: usize = 5;

/// The section of the operator guide on package changes in hidden sessions,
/// named by the fix.
const GUIDE: &str = "\"Package changes in hidden sessions\" in docs/operator-guide.md";

/// A package database the check judges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Database {
    /// dpkg's `/var/lib/dpkg/status` (Debian, Ubuntu).
    Dpkg,
    /// pacman's `/var/lib/pacman/local` (Arch Linux).
    Pacman,
    /// rpm's `rpmdb.sqlite` (Fedora).
    Rpm,
}

impl Database {
    /// Every database, in the order the check judges them.
    pub const ALL: [Database; 3] = [Database::Dpkg, Database::Pacman, Database::Rpm];

    /// The database as a message names it, after an article, at its path
    /// `at` as hidden sessions see it.
    fn shown(self, at: &str) -> String {
        let manager = match self {
            Database::Dpkg => "dpkg",
            Database::Pacman => "pacman",
            Database::Rpm => "rpm",
        };
        format!("{manager} package database ({at})")
    }
}

/// One package whose record differs between the decoy's database and hidden
/// sessions'.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Change {
    /// The package's name, with its architecture after a colon when the
    /// database records it for several.
    pub name: String,
    /// Its version on the decoy; `None` when the decoy does not have it.
    pub decoy: Option<String>,
    /// Its version in hidden sessions; `None` when they do not have it.
    pub hidden: Option<String>,
}

/// How hidden sessions' package database no longer follows the decoy's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Drift {
    /// dpkg: the packages the decoy installed, updated or removed since
    /// hidden sessions made their copy of the record, none of which a hidden
    /// session changed itself.
    Stale(Vec<Change>),
    /// pacman: the packages the decoy changed after a hidden session changed
    /// them too (`twice`), and those a hidden session removed and the decoy
    /// changed since (`removed`).
    Merged {
        /// Listed twice in hidden sessions.
        twice: Vec<Change>,
        /// Listed in hidden sessions without the files they deleted.
        removed: Vec<Change>,
    },
    /// rpm: the decoy's database was written after hidden sessions' copy.
    Older,
}

/// Why a verdict could not be reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Doubt {
    /// It needs the decoy's database read, which only root does without
    /// changing its access time.
    NeedsRoot,
    /// Anything else, said as a reason.
    Other(String),
}

/// The judgement of one package database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The decoy keeps no database of this kind.
    Absent,
    /// Hidden sessions see the decoy's own database: nothing of it in the
    /// upper.
    Shared,
    /// Hidden sessions keep records of their own, which follow the decoy's
    /// but for the `own` packages they changed themselves; `None` for rpm,
    /// whose packages are not read.
    Follows {
        /// The packages hidden sessions changed themselves.
        own: Option<usize>,
    },
    /// Hidden sessions' records no longer follow the decoy's.
    Drifted(Drift),
    /// A hidden session deleted (`deleted`) or replaced the database, or a
    /// directory on its way, at `path` as hidden sessions see it.
    Gone {
        /// The path hidden sessions changed.
        path: String,
        /// Whether they deleted it rather than replaced it.
        deleted: bool,
    },
    /// No verdict could be reached.
    Unknown(Doubt),
}

/// A dpkg package's key: its name and architecture.
type Key = (String, Option<String>);

/// Judge dpkg's record: `decoy` is the decoy's `status`, `hidden` hidden
/// sessions' copy of it, and `changed` the owners of the files of dpkg's
/// `info` directory the upper holds (or deleted), as
/// [`dpkg::info_owner`] reads their names. A package whose files are not on
/// disk counts as not installed.
pub fn judge_dpkg(
    decoy: &[dpkg::Package],
    hidden: &[dpkg::Package],
    changed: &BTreeSet<(String, Option<String>)>,
) -> Verdict {
    let installed = |packages: &[dpkg::Package]| -> BTreeMap<Key, String> {
        packages
            .iter()
            .filter(|package| package.files_present())
            .map(|package| {
                let key = (package.name.clone(), package.architecture.clone());
                (key, package.version.clone().unwrap_or_default())
            })
            .collect()
    };
    let decoy = installed(decoy);
    let hidden = installed(hidden);
    let keys: BTreeSet<&Key> = decoy.keys().chain(hidden.keys()).collect();
    let several = |name: &str| keys.iter().filter(|(other, _)| other == name).count() > 1;
    let mut own = 0;
    let mut stale = Vec::new();
    for key in &keys {
        let (on_decoy, in_hidden) = (decoy.get(*key), hidden.get(*key));
        if on_decoy == in_hidden {
            continue;
        }
        let (name, arch) = key;
        let touched = changed.contains(&(name.clone(), None))
            || (arch.is_some() && changed.contains(&(name.clone(), arch.clone())));
        if touched {
            own += 1;
            continue;
        }
        let name = match arch {
            Some(arch) if several(name.as_str()) => format!("{name}:{arch}"),
            _ => name.clone(),
        };
        stale.push(Change {
            name,
            decoy: on_decoy.cloned(),
            hidden: in_hidden.cloned(),
        });
    }
    if stale.is_empty() {
        Verdict::Follows { own: Some(own) }
    } else {
        Verdict::Drifted(Drift::Stale(stale))
    }
}

/// Judge pacman's database: `decoy` is the decoy's, `kept` the entries the
/// upper holds and `removed` those it deleted (its whiteouts).
pub fn judge_pacman(
    decoy: &[pacman::Package],
    kept: &[pacman::Package],
    removed: &[pacman::Package],
) -> Verdict {
    if kept.is_empty() && removed.is_empty() {
        return Verdict::Shared;
    }
    let entries = |packages: &[pacman::Package]| -> BTreeSet<String> {
        packages.iter().map(pacman::Package::entry).collect()
    };
    let (kept_entries, removed_entries) = (entries(kept), entries(removed));
    // The decoy's entries hidden sessions see on their own: neither deleted
    // nor merged with one of theirs of the same name.
    let shown: Vec<&pacman::Package> = decoy
        .iter()
        .filter(|package| {
            let entry = package.entry();
            !kept_entries.contains(&entry) && !removed_entries.contains(&entry)
        })
        .collect();
    let decoy_version = |name: &str| {
        shown
            .iter()
            .find(|package| package.name == name)
            .map(|package| package.version.clone())
    };
    let mut twice = BTreeSet::new();
    for package in kept {
        if let Some(decoy) = decoy_version(package.name.as_str()) {
            twice.insert(Change {
                name: package.name.clone(),
                decoy: Some(decoy),
                hidden: Some(package.version.clone()),
            });
        }
    }
    let mut gone = BTreeSet::new();
    for package in removed {
        if kept.iter().any(|kept| kept.name == package.name) {
            continue;
        }
        if let Some(decoy) = decoy_version(package.name.as_str()) {
            gone.insert(Change {
                name: package.name.clone(),
                decoy: Some(decoy),
                hidden: None,
            });
        }
    }
    if twice.is_empty() && gone.is_empty() {
        let own: BTreeSet<&str> = kept
            .iter()
            .chain(removed)
            .map(|package| package.name.as_str())
            .collect();
        return Verdict::Follows {
            own: Some(own.len()),
        };
    }
    Verdict::Drifted(Drift::Merged {
        twice: twice.into_iter().collect(),
        removed: gone.into_iter().collect(),
    })
}

/// Judge rpm's database by size and time: `decoy` is the decoy's stamp,
/// `hidden` that of hidden sessions' copy. The copy drifted when the decoy's
/// was written after it, or at the same time with another size.
pub fn judge_rpm(decoy: rpm::Stamp, hidden: rpm::Stamp) -> Verdict {
    let later = decoy.modified > hidden.modified
        || (decoy.modified == hidden.modified && decoy.size != hidden.size);
    if later {
        Verdict::Drifted(Drift::Older)
    } else {
        Verdict::Follows { own: None }
    }
}

/// `n` packages, in words.
fn packages(n: usize) -> String {
    if n == 1 {
        "1 package".to_string()
    } else {
        format!("{n} packages")
    }
}

/// The changes named, [`NAMED`] at most, and how many more there are.
fn listed(changes: &[Change]) -> String {
    let named: Vec<String> = changes
        .iter()
        .take(NAMED)
        .map(|change| {
            let decoy = change.decoy.as_deref().map_or_else(
                || "not on the decoy".to_string(),
                |version| format!("{version} on the decoy"),
            );
            let hidden = change.hidden.as_deref().map_or_else(
                || "not in hidden sessions".to_string(),
                |version| format!("{version} in hidden sessions"),
            );
            format!("{} ({decoy}, {hidden})", change.name)
        })
        .collect();
    match changes.len().saturating_sub(NAMED) {
        0 => named.join(", "),
        more => format!("{}, and {more} more", named.join(", ")),
    }
}

/// What the check reports of the databases: a pass, or a warning with what
/// to do about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// Whether it warns.
    pub warns: bool,
    /// What it found.
    pub message: String,
    /// What to do about it, when there is one thing to do.
    pub fix: Option<String>,
}

/// What a front end shows before it asks to enter a hidden session: a risk
/// that does not refuse the entry, and what to do about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advisory {
    /// The check that found it, [`NAME`].
    pub name: &'static str,
    /// What it found.
    pub message: String,
    /// What to do about it, when there is one thing to do.
    pub fix: Option<String>,
}

impl Advisory {
    /// The advisory as one warning: the message, then the fix on a line of
    /// its own, as [`CheckResult::warn_with`] puts them.
    pub fn text(&self) -> String {
        match &self.fix {
            Some(fix) => format!("{}\n{fix}", self.message),
            None => self.message.clone(),
        }
    }
}

/// The `discard` line that deletes hidden sessions' copy of `path`, with
/// `--allow-decoy-storage` when the run was given it.
fn discard(path: &str, allow_decoy_storage: bool) -> String {
    let path = shell_word(OsStr::new(path));
    if allow_decoy_storage {
        sudo_line_for(NextStep::Discard, &format!("--allow-decoy-storage {path}"))
    } else {
        sudo_line_for(NextStep::Discard, &path)
    }
}

/// The report for `verdicts`, one for each database at its path as hidden
/// sessions see it, for a run that accepted the hidden root on this
/// computer's own storage when `allow_decoy_storage` (the `discard` a fix
/// names takes the same flag).
pub fn report(verdicts: &[(Database, String, Verdict)], allow_decoy_storage: bool) -> Report {
    let mut warnings: Vec<String> = Vec::new();
    let mut fixes: Vec<String> = Vec::new();
    let mut passes: Vec<String> = Vec::new();
    let mut fix = |line: String| {
        if !fixes.contains(&line) {
            fixes.push(line);
        }
    };
    for (database, at, verdict) in verdicts {
        let shown = database.shown(at);
        match verdict {
            Verdict::Absent => {}
            Verdict::Shared => passes.push(format!("hidden sessions see the decoy's own {shown}")),
            Verdict::Follows { own: Some(0) } => passes.push(format!(
                "hidden sessions keep their own copy of the {shown}, which follows the decoy's"
            )),
            Verdict::Follows { own: Some(own) } if *database == Database::Pacman => {
                passes.push(format!(
                    "hidden sessions see the decoy's {shown} with the {} they changed \
                     themselves, none of which the decoy changed since",
                    packages(*own)
                ));
            }
            Verdict::Follows { own: Some(own) } => passes.push(format!(
                "hidden sessions keep their own copy of the {shown}, which follows the decoy's \
                 but for the {} they changed themselves",
                packages(*own)
            )),
            Verdict::Follows { own: None } => passes.push(format!(
                "hidden sessions keep their own copy of the {shown}, written no earlier than the \
                 decoy's"
            )),
            Verdict::Drifted(drift) => {
                warnings.push(drifted(&shown, drift));
                fix(drift_fix(*database));
            }
            Verdict::Gone { path, deleted } => {
                let what = if *deleted { "deleted" } else { "replaced" };
                warnings.push(format!(
                    "a hidden session {what} {path}, so hidden sessions do not see the decoy's \
                     {shown}"
                ));
                fix(format!(
                    "Bring the decoy's {path} back with `{}`, which deletes what hidden sessions \
                     changed there (it lists what it deletes and asks first).",
                    discard(path, allow_decoy_storage)
                ));
            }
            Verdict::Unknown(Doubt::NeedsRoot) => {
                warnings.push(format!(
                    "could not tell whether hidden sessions' copy of the {shown} follows the \
                     decoy's: only root reads the decoy's package database without changing its \
                     access time"
                ));
                fix(format!("Run `{}` to see it.", sudo_line(NextStep::Check)));
            }
            Verdict::Unknown(Doubt::Other(reason)) => warnings.push(format!(
                "could not tell whether hidden sessions' copy of the {shown} follows the \
                 decoy's: {reason}"
            )),
        }
    }
    if !warnings.is_empty() {
        return Report {
            warns: true,
            message: warnings.join("; "),
            fix: (!fixes.is_empty()).then(|| fixes.join(" ")),
        };
    }
    Report {
        warns: false,
        message: if passes.is_empty() {
            "the decoy keeps no dpkg, pacman or rpm package database".to_string()
        } else {
            passes.join("; ")
        },
        fix: None,
    }
}

/// What drifted, for the database `shown`.
fn drifted(shown: &str, drift: &Drift) -> String {
    match drift {
        Drift::Stale(changes) => format!(
            "the decoy installed, updated or removed {} since hidden sessions made their own \
             copy of the {shown}, which still records them as they were: {}",
            packages(changes.len()),
            listed(changes)
        ),
        Drift::Merged { twice, removed } => {
            let mut parts = Vec::new();
            if !twice.is_empty() {
                parts.push(format!(
                    "the decoy changed {} that hidden sessions changed too, so hidden sessions \
                     see each twice in the {shown} and keep their own files of it: {}",
                    packages(twice.len()),
                    listed(twice)
                ));
            }
            if !removed.is_empty() {
                parts.push(format!(
                    "hidden sessions removed {} that the decoy changed since, so hidden sessions \
                     see each in the {shown} without the files they deleted: {}",
                    packages(removed.len()),
                    listed(removed)
                ));
            }
            parts.join("; ")
        }
        Drift::Older => format!(
            "the decoy's {shown} changed after hidden sessions last changed their own copy, so \
             hidden sessions do not know what the decoy installed, updated or removed since"
        ),
    }
}

/// What brings hidden sessions' records of `database` back in line.
fn drift_fix(database: Database) -> String {
    let how = match database {
        Database::Dpkg => {
            "In a hidden session, run `sudo apt-get update` and `sudo apt-get full-upgrade`, and \
             install or remove there what the decoy installed or removed, so hidden sessions \
             record the same packages."
        }
        Database::Pacman => {
            "In a hidden session, install the decoy's version of each package again from its \
             package file in /var/cache/pacman/pkg (`sudo pacman -U <file>`), or remove there \
             again one hidden sessions had removed (`sudo pacman -R <name>`), so pacman keeps \
             one entry of each."
        }
        Database::Rpm => {
            "In a hidden session, run `sudo dnf upgrade --refresh`, and install or remove there \
             what the decoy installed or removed, so hidden sessions record the same packages."
        }
    };
    format!("{how} See {GUIDE}.")
}

/// `package-drift`.
#[derive(Debug)]
pub struct PackageDriftCheck {
    /// The decoy root, `/` outside tests.
    root: PathBuf,
    /// The hidden volume root, whose layers hold hidden sessions' copies.
    hidden_root: PathBuf,
    /// Whether this process reads the decoy's database without changing its
    /// access time: root.
    privileged: bool,
    /// Whether the run accepted a hidden root on this computer's own storage
    /// (`--allow-decoy-storage`), which the `discard` a fix names then needs
    /// too.
    allow_decoy_storage: bool,
}

impl PackageDriftCheck {
    /// The check of the package databases below the decoy `root`, against
    /// hidden sessions' copies on the hidden volume at `hidden_root`, as the
    /// current process.
    pub fn new(root: PathBuf, hidden_root: PathBuf) -> Self {
        Self {
            root,
            hidden_root,
            privileged: rustix::process::geteuid().is_root(),
            allow_decoy_storage: false,
        }
    }

    /// The check for a process that reads the decoy's database without
    /// changing its access time (`privileged`) or does not.
    pub fn as_privileged(mut self, privileged: bool) -> Self {
        self.privileged = privileged;
        self
    }

    /// The check for a run that accepted the hidden root on this computer's
    /// own storage: the `discard` its fix names takes the same flag.
    pub fn allowing_decoy_storage(mut self, allow: bool) -> Self {
        self.allow_decoy_storage = allow;
        self
    }

    /// The report for what `fs` reads, with the mount table `fs` gives.
    pub fn report<F: Filesystem>(&self, fs: &F) -> Report {
        let mounts = fs.mount_table().ok();
        let layout = super::layout::Layout::new(&self.hidden_root);
        let verdicts = verdicts(fs, &self.root, &layout, mounts.as_deref(), self.privileged);
        report(&verdicts, self.allow_decoy_storage)
    }
}

/// The advisory an entry shows when hidden sessions' package database does
/// not follow the decoy's, read through `fs` as root: the decoy root `root`,
/// hidden sessions' copies in `layout`, and the decoy's filesystems in
/// `mounts` (`None` when the mount table cannot be read, which no verdict
/// that needs hidden sessions' copy passes). `None` when it follows.
pub fn advisory<F: Filesystem>(
    fs: &F,
    root: &Path,
    layout: &super::layout::Layout,
    mounts: Option<&[nails_teardown::mountinfo::MountEntry]>,
    allow_decoy_storage: bool,
) -> Option<Advisory> {
    let verdicts = verdicts(fs, root, layout, mounts, true);
    let report = report(&verdicts, allow_decoy_storage);
    report.warns.then_some(Advisory {
        name: NAME,
        message: report.message,
        fix: report.fix,
    })
}

impl<F: Filesystem> PreFlightCheck<F> for PackageDriftCheck {
    fn name(&self) -> &'static str {
        NAME
    }

    fn description(&self) -> &'static str {
        "hidden sessions' package database follows the decoy's"
    }

    fn requires_hidden_volume(&self) -> bool {
        true
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        let report = self.report(fs);
        Ok(match (report.warns, report.fix) {
            (false, _) => CheckResult::Pass(report.message),
            (true, Some(fix)) => CheckResult::warn_with(report.message, fix),
            (true, None) => CheckResult::Warn(report.message),
        })
    }
}

#[cfg(test)]
#[path = "package_drift_tests.rs"]
mod tests;
