// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Whether the runs of updatedb on the decoy skip the hidden volume.
//!
//! Pure: [`verdict`] takes what the reader found ([`Run`]s, the volume's
//! [`Location`]s) and reads nothing itself, so a scan of an offline image can
//! judge with it too.
//!
//! updatedb walks the tree from its scan root (`/`, or `--database-root`),
//! one directory at a time, and does not enter a directory when:
//!
//! - its path, spelled as updatedb builds it from the scan root, equals a
//!   `PRUNEPATHS` entry (byte for byte: `/mnt/` prunes nothing);
//! - its name equals a `PRUNENAMES` entry (the scan root's own name is never
//!   compared);
//! - it is the mount point of a filesystem whose device differs from its
//!   parent's, and the type of the first mount the table lists there equals
//!   a `PRUNEFS` entry without ASCII case (the scan root's own filesystem is
//!   never compared).
//!
//! So the hidden volume is covered when any directory on the way from the
//! scan root down to its mount point, that one included, is skipped, or when
//! the scan never reaches it. `PRUNE_BIND_MOUNTS` covers it only where
//! updatedb judges its mount a bind mount, which a volume mounted from its
//! device is not, so it never counts here.

use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

/// One prune entry and where it is set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The entry, as updatedb compares it.
    pub value: Vec<u8>,
    /// Where it is set, such as `PRUNEPATHS in /etc/updatedb.conf`.
    pub origin: String,
}

/// One of updatedb's prune lists.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct List {
    /// Its entries.
    pub entries: Vec<Entry>,
    /// Whether they are all of them; `false` while the configuration file
    /// they extend could not be read.
    pub complete: bool,
}

impl List {
    /// A list known to hold exactly `entries`.
    pub fn complete(entries: Vec<Entry>) -> Self {
        Self {
            entries,
            complete: true,
        }
    }

    fn find(&self, value: &[u8]) -> Option<&Entry> {
        self.entries.iter().find(|entry| entry.value == value)
    }
}

/// What one run of updatedb prunes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Lists {
    /// `PRUNEPATHS`.
    pub paths: List,
    /// `PRUNENAMES`.
    pub names: List,
    /// `PRUNEFS`.
    pub fs: List,
    /// The scan root `--database-root` gives, resolved, with where that is
    /// set; the scan starts at `/` without one.
    pub scan_root: Option<(PathBuf, String)>,
    /// Why a list that is not complete may hold more.
    pub incomplete: Option<String>,
}

/// What starts a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Start {
    /// It runs now; the unit or process that shows it.
    Now(String),
    /// A timer starts it; the timer.
    Timer(String),
    /// Its service manager starts it whenever it starts, as at the
    /// soft-reboot back to the decoy: the enabled service.
    Enabled(String),
    /// A cron job starts it; the job, as a line of a crontab or a script.
    Cron(String),
    /// Something NAILS cannot read may start it: what that is, such as a
    /// crontab or a unit directory.
    Unread(String),
    /// Nothing starts it but a person; the program or unit.
    ByHand(String),
}

impl Start {
    /// Whether the run happens without anybody starting it: it runs now, or
    /// is scheduled.
    pub fn is_scheduled_or_running(&self) -> bool {
        !matches!(self, Start::ByHand(_))
    }
}

/// A run of updatedb on the decoy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Run {
    /// What starts it.
    pub start: Start,
    /// What it prunes, or why that is not known.
    pub lists: Result<Lists, String>,
    /// The database it writes, when known.
    pub database: Option<String>,
}

/// Where the hidden volume shows in the decoy's tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Location {
    /// The directory, resolved.
    pub path: PathBuf,
    /// The directories from `/` down to `path`, `path` included, at which the
    /// device changes from the parent's, with the type of the first mount the
    /// table lists there: what updatedb compares with `PRUNEFS`.
    pub crossings: Vec<(PathBuf, String)>,
}

/// Whether a run skips the hidden volume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cover {
    /// It does, by this rule.
    Covered(String),
    /// It indexes the volume at this location.
    Not(PathBuf),
    /// NAILS cannot tell, for this reason.
    Unknown(String),
}

/// Whether a run with `lists` skips the volume at `location`.
pub fn cover(lists: &Lists, location: &Location) -> Cover {
    let at = location.path.as_path();
    let (scan, scan_origin) = match &lists.scan_root {
        Some((root, origin)) => (root.as_path(), Some(origin.as_str())),
        None => (Path::new("/"), None),
    };
    // Not covered, unless a list that could cover it may hold more.
    let uncovered =
        |complete: bool| {
            if complete {
                Cover::Not(at.to_path_buf())
            } else {
                Cover::Unknown(lists.incomplete.clone().unwrap_or_else(|| {
                    "NAILS cannot read every list updatedb prunes with".to_string()
                }))
            }
        };
    if !at.starts_with(scan) {
        if !scan.starts_with(at) {
            let origin = scan_origin.unwrap_or("the scan root");
            return Cover::Covered(format!(
                "{origin} starts the scan at {}, which does not hold {}",
                scan.display(),
                at.display()
            ));
        }
        // The scan starts inside the volume: only pruning its start skips it.
        if let Some(entry) = lists.paths.find(scan.as_os_str().as_bytes()) {
            return Cover::Covered(format!(
                "{} lists {}, where the scan starts",
                entry.origin,
                scan.display()
            ));
        }
        return uncovered(lists.paths.complete);
    }

    let below: Vec<&std::ffi::OsStr> = at
        .strip_prefix(scan)
        .unwrap_or(Path::new(""))
        .components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(name),
            _ => None,
        })
        .collect();
    let mut dir = scan.to_path_buf();
    let mut visited = vec![dir.clone()];
    for name in &below {
        dir.push(name);
        visited.push(dir.clone());
    }
    if let Some((dir, entry)) = visited.iter().find_map(|dir| {
        lists
            .paths
            .find(dir.as_os_str().as_bytes())
            .map(|entry| (dir, entry))
    }) {
        return Cover::Covered(format!("{} lists {}", entry.origin, dir.display()));
    }
    if let Some((name, entry)) = below
        .iter()
        .find_map(|name| lists.names.find(name.as_bytes()).map(|entry| (name, entry)))
    {
        return Cover::Covered(format!(
            "{} lists {}, a directory on the way to {}",
            entry.origin,
            name.to_string_lossy(),
            at.display()
        ));
    }
    for (mount, fstype) in &location.crossings {
        if mount == scan || !mount.starts_with(scan) || !at.starts_with(mount) {
            continue;
        }
        if let Some(entry) = lists
            .fs
            .entries
            .iter()
            .find(|entry| entry.value.eq_ignore_ascii_case(fstype.as_bytes()))
        {
            return Cover::Covered(format!(
                "{} lists {}, the type of the filesystem mounted at {}",
                entry.origin,
                String::from_utf8_lossy(&entry.value),
                mount.display()
            ));
        }
    }
    uncovered(lists.paths.complete && lists.names.complete && lists.fs.complete)
}

/// Whether `run` skips the volume at every one of `locations`: the first
/// location it indexes, else the first it cannot tell about, else the rules
/// that cover each.
pub fn run_cover(run: &Run, locations: &[Location]) -> Cover {
    let lists = match &run.lists {
        Ok(lists) => lists,
        Err(why) => return Cover::Unknown(why.clone()),
    };
    let covers: Vec<Cover> = locations
        .iter()
        .map(|location| cover(lists, location))
        .collect();
    if let Some(not) = covers.iter().find(|cover| matches!(cover, Cover::Not(_))) {
        return not.clone();
    }
    if let Some(unknown) = covers
        .iter()
        .find(|cover| matches!(cover, Cover::Unknown(_)))
    {
        return unknown.clone();
    }
    let mut rules: Vec<String> = Vec::new();
    for cover in covers {
        if let Cover::Covered(rule) = cover
            && !rules.contains(&rule)
        {
            rules.push(rule);
        }
    }
    Cover::Covered(rules.join(", and "))
}

/// A run with what [`run_cover`] made of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Judged {
    /// The run.
    pub run: Run,
    /// Whether it skips the volume.
    pub cover: Cover,
}

/// The check's verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// No updatedb is installed.
    NotInstalled,
    /// Every run skips the volume, by these rules (none when nothing can run
    /// updatedb).
    Pass(Vec<String>),
    /// These runs, running now or scheduled, index the volume: those running
    /// now first.
    Fail(Vec<Judged>),
    /// NAILS cannot tell about these runs, or nothing but a person starts
    /// these runs that index the volume.
    Warn(Vec<Judged>),
}

/// The verdict on the decoy's runs of updatedb (see the module docs of the
/// check): a run that indexes the volume fails the check when it runs now or
/// is scheduled, and warns when only a person starts it; a run NAILS cannot
/// tell about warns.
pub fn verdict(installed: bool, runs: &[Run], locations: &[Location]) -> Verdict {
    if !installed {
        return Verdict::NotInstalled;
    }
    let mut judged: Vec<Judged> = runs
        .iter()
        .map(|run| Judged {
            run: run.clone(),
            cover: run_cover(run, locations),
        })
        .collect();
    // Running now first, then scheduled, then by hand, keeping the reader's
    // order within each.
    judged.sort_by_key(|judged| match judged.run.start {
        Start::Now(_) => 0,
        Start::Timer(_) | Start::Enabled(_) | Start::Cron(_) | Start::Unread(_) => 1,
        Start::ByHand(_) => 2,
    });
    let failing: Vec<Judged> = judged
        .iter()
        .filter(|judged| {
            judged.run.start.is_scheduled_or_running() && matches!(judged.cover, Cover::Not(_))
        })
        .cloned()
        .collect();
    if !failing.is_empty() {
        return Verdict::Fail(failing);
    }
    let warning: Vec<Judged> = judged
        .iter()
        .filter(|judged| !matches!(judged.cover, Cover::Covered(_)))
        .cloned()
        .collect();
    if !warning.is_empty() {
        return Verdict::Warn(warning);
    }
    let mut rules: Vec<String> = Vec::new();
    for judged in judged {
        if let Cover::Covered(rule) = judged.cover
            && !rules.contains(&rule)
        {
            rules.push(rule);
        }
    }
    Verdict::Pass(rules)
}

#[cfg(test)]
#[path = "judge_tests.rs"]
mod tests;
