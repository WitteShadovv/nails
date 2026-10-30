// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Pre-flight check that refuses a decoy whose locate database would list the
//! hidden volume.
//!
//! updatedb (plocate's, mlocate's, or NixOS's `update-locatedb.service`)
//! walks the whole tree and writes the name of every file it finds into the
//! locate database on the decoy disk (`/var/lib/plocate/plocate.db`,
//! `/var/lib/mlocate/mlocate.db`, `/var/cache/locatedb` on NixOS). A run
//! while the hidden volume is mounted on the decoy, before activation or
//! after the way back, writes every name on the volume there. The stock
//! timers run daily and catch a missed run up right after boot, when the
//! volume is unlocked for a session. Fedora installs and enables plocate by
//! default, and the default `PRUNEPATHS` of Debian 13, Ubuntu 26.04, Fedora
//! 44 and NixOS do not skip `/mnt`.
//!
//! The check judges the hidden volume where NAILS finds it: the hidden root
//! resolved, and every other mount of the volume's filesystem (see
//! [`judge`] for when a run skips it). Its verdict:
//!
//! - no updatedb installed: pass;
//! - every run skips the volume: pass, naming the rule that skips it;
//! - an updatedb that runs now, or that a timer, a path unit, an enabled
//!   service or a cron job starts ([`read`]), and that does not skip it:
//!   fail. No flag lifts this refusal;
//! - one NAILS cannot tell about (an unreadable or broken configuration file,
//!   a command or option it does not follow, findutils' updatedb, a unit
//!   directory, crontab or cron script it cannot read), or one only a person
//!   starts that does not skip the volume: warn.
//!
//! Nothing is written. The decoy's files are read under a root, so that a
//! scan of an offline image can read them as well, with `O_NOATIME` and
//! never where a link leads onto the hidden volume ([`files`]).

pub mod conf;
pub mod cron;
pub mod exec;
pub mod files;
pub mod judge;
pub mod options;
pub mod read;
pub mod shell;
mod unit;
mod units;

use super::super::{CheckResult, PreFlightCheck};
use crate::filesystem::mountinfo::{MountEntry, top_mount_at};
use crate::hidden_root::mount_holding;
use crate::process::{ProcessCommand, ProcessRunner, RealProcessRunner};
use crate::{Filesystem, Result};
use judge::{Cover, Judged, Location, Start, Verdict};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Where the docs explain the check.
const DOC: &str = "docs/decoy-requirements.md#the-locate-database";

/// Pre-flight check that refuses an updatedb that would list the hidden
/// volume in the decoy's locate database.
#[derive(Debug)]
pub struct LocateDatabaseCheck {
    /// The hidden root as configured.
    hidden_root: PathBuf,
    /// Whether the host carries a NixOS config layer, which picks the fix.
    is_nixos: bool,
    /// Root of the system tree whose configuration is read; `/` outside
    /// tests.
    root: PathBuf,
    /// The timer and path units the system manager runs, as tests give
    /// them; asked of the system manager when `None`.
    started: Option<std::result::Result<BTreeSet<String>, String>>,
}

impl LocateDatabaseCheck {
    /// The check for the hidden root at `hidden_root`; `is_nixos` gives the
    /// NixOS fix instead of the one for `/etc/updatedb.conf`.
    pub fn new(hidden_root: PathBuf, is_nixos: bool) -> Self {
        Self {
            hidden_root,
            is_nixos,
            root: PathBuf::from("/"),
            started: None,
        }
    }

    /// Read the system tree rooted at `root` instead of `/` (tests).
    #[cfg(test)]
    fn with_root(mut self, root: &Path) -> Self {
        self.root = root.to_path_buf();
        self
    }

    /// Take `started` as the timer and path units the system manager runs
    /// (tests).
    #[cfg(test)]
    fn with_started(mut self, started: std::result::Result<BTreeSet<String>, String>) -> Self {
        self.started = Some(started);
        self
    }

    /// The timer and path units the system manager runs, or why NAILS
    /// cannot tell: only the running system's manager can say, not that of
    /// an image read under another root.
    fn started(&self) -> std::result::Result<BTreeSet<String>, String> {
        if let Some(started) = &self.started {
            return started.clone();
        }
        if self.root != Path::new("/") {
            return Err(format!("the decoy is read under {}", self.root.display()));
        }
        started_triggers(&RealProcessRunner)
    }
}

/// The timer and path units the system manager runs now, as
/// `systemctl list-units` lists them, a timer started by hand among them:
/// systemd leaves no file that says a timer runs.
pub fn started_triggers(
    runner: &dyn ProcessRunner,
) -> std::result::Result<BTreeSet<String>, String> {
    let list = ProcessCommand::tool("systemctl")
        .args([
            "list-units",
            "--type=timer,path",
            "--state=active",
            "--plain",
            "--no-legend",
            "--no-pager",
            "--full",
        ])
        .deadline(crate::process::run::SYSTEMCTL_PROBE_BUDGET);
    match runner.run_text(&list) {
        Ok((true, out, _)) => Ok(out
            .lines()
            .filter_map(|line| line.split_whitespace().next())
            .filter(|unit| unit.ends_with(".timer") || unit.ends_with(".path"))
            .map(str::to_string)
            .collect()),
        Ok((false, _, err)) => Err(format!(
            "`systemctl list-units` failed ({})",
            err.lines().next().unwrap_or("no message")
        )),
        Err(e) => Err(format!("NAILS cannot run systemctl ({e})")),
    }
}

/// Where the hidden volume shows on the running system: the hidden root,
/// resolved as the attach gate resolves it, and every other mount of the
/// filesystem mounted there. Without a mount table only the root is known,
/// and no filesystem type can be compared with `PRUNEFS`.
pub fn hidden_locations<F: Filesystem>(fs: &F, hidden_root: &Path) -> Vec<Location> {
    let resolved = fs
        .canonicalize(hidden_root)
        .unwrap_or_else(|_| hidden_root.components().collect());
    let Ok(table) = fs.mount_table() else {
        return vec![Location {
            path: resolved,
            crossings: Vec::new(),
        }];
    };
    let mut paths = vec![resolved.clone()];
    if let Some(volume) = top_mount_at(&table, &resolved) {
        for other in table
            .iter()
            .filter(|entry| entry.dev == volume.dev && entry.mount_point != resolved)
        {
            if !paths.contains(&other.mount_point) {
                paths.push(other.mount_point.clone());
            }
        }
    }
    paths
        .into_iter()
        .map(|path| Location {
            crossings: crossings(&table, &path),
            path,
        })
        .collect()
}

/// The directories from `/` down to `path` at which the device changes from
/// the parent's, each with the type of the first mount the table lists there,
/// which is what updatedb compares with `PRUNEFS`.
fn crossings(table: &[MountEntry], path: &Path) -> Vec<(PathBuf, String)> {
    let device = |at: &Path| mount_holding(table, at).map(|entry| entry.dev.clone());
    let mut out = Vec::new();
    let mut at = PathBuf::from("/");
    for component in path.components().skip(1) {
        let parent = at.clone();
        at.push(component);
        if device(&at) == device(&parent) {
            continue;
        }
        if let Some(first) = table.iter().find(|entry| entry.mount_point == at) {
            out.push((at.clone(), first.fstype.clone()));
        }
    }
    out
}

/// The directories to prune so that updatedb skips `locations`: the
/// topmost of their parents that lie off the hidden volume, so that the line
/// names no mount point of it. `None` when a location's parent is `/`, or
/// lies on the volume with no parent off it above, where no such line exists.
fn prune_dirs(locations: &[Location]) -> Option<Vec<PathBuf>> {
    let on_volume = |dir: &Path| {
        locations
            .iter()
            .any(|location| dir.starts_with(&location.path))
    };
    let mut dirs: Vec<PathBuf> = Vec::new();
    for location in locations {
        let parent = location.path.parent()?;
        if parent == Path::new("/") {
            return None;
        }
        if !on_volume(parent) && !dirs.iter().any(|dir| dir == parent) {
            dirs.push(parent.to_path_buf());
        }
    }
    // Keep the topmost: a directory below another one listed is pruned with
    // it.
    let topmost: Vec<PathBuf> = dirs
        .iter()
        .filter(|dir| {
            !dirs
                .iter()
                .any(|other| other != *dir && dir.starts_with(other))
        })
        .cloned()
        .collect();
    locations
        .iter()
        .all(|location| topmost.iter().any(|dir| location.path.starts_with(dir)))
        .then_some(topmost)
}

/// NixOS's default `services.locate.prunePaths`.
const NIXOS_DEFAULT_PRUNEPATHS: &[&str] = &[
    "/tmp",
    "/var/tmp",
    "/var/cache",
    "/var/lock",
    "/var/run",
    "/var/spool",
    "/nix/store",
    "/nix/var/log/nix",
];

/// The fix for the decoy's updatedb: prune the directories the hidden volume
/// is mounted in, the NixOS way or in `/etc/updatedb.conf`, or stop what
/// starts it (`remedies`). `nixos_prunepaths` is what the `ExecStart=` of
/// NixOS's own service prunes, which tells whether the configuration sets
/// `services.locate.prunePaths`.
fn fix(
    locations: &[Location],
    is_nixos: bool,
    remedies: &[String],
    nixos_prunepaths: Option<&[Vec<u8>]>,
) -> String {
    let dirs = prune_dirs(locations);
    let stop = if remedies.is_empty() {
        "remove the locate package".to_string()
    } else {
        remedies.join(", or ")
    };
    let Some(dirs) = dirs else {
        if is_nixos {
            return "disable services.locate in the decoy's configuration and rebuild it: a \
                    prunePaths entry that skips the volume here would name its mount point in \
                    /etc/nixos"
                .to_string();
        }
        return format!(
            "{stop}; adding the mount point to PRUNEPATHS in /etc/updatedb.conf would name it \
             there"
        );
    };
    let shown: Vec<String> = dirs.iter().map(|dir| dir.display().to_string()).collect();
    if is_nixos {
        let quoted: Vec<String> = shown.iter().map(|dir| format!("\"{dir}\"")).collect();
        let quoted = quoted.join(" ");
        // lib.mkOptionDefault joins the option's default, and only while no
        // definition of the configuration sets the list: then a plain list
        // joins that definition instead.
        let default_list = nixos_prunepaths.is_none_or(|paths| {
            let mut paths: Vec<&[u8]> = paths.iter().map(Vec::as_slice).collect();
            let mut default: Vec<&[u8]> = NIXOS_DEFAULT_PRUNEPATHS
                .iter()
                .map(|path| path.as_bytes())
                .collect();
            paths.sort_unstable();
            paths.dedup();
            default.sort_unstable();
            paths == default
        });
        if !default_list {
            // Another definition of the option joins that one only at the
            // same priority: add to the list where it is set.
            return format!(
                "make updatedb skip {}: the decoy's configuration sets its own \
                 services.locate.prunePaths, so add {quoted} to that list and rebuild the decoy, \
                 or disable services.locate",
                shown.join(" and ")
            );
        }
        return format!(
            "make updatedb skip {}: add `services.locate.prunePaths = lib.mkOptionDefault [ \
             {quoted} ];` to the decoy's configuration and rebuild it (lib.mkOptionDefault \
             joins the default list, which a plain list would replace), or disable \
             services.locate",
            shown.join(" and ")
        );
    }
    format!(
        "make updatedb skip {}: add {} to PRUNEPATHS in /etc/updatedb.conf, or {stop}",
        shown.join(" and "),
        shown.join(" ")
    )
}

/// What a run writes into, for a message.
fn database(judged: &Judged) -> String {
    judged
        .run
        .database
        .clone()
        .unwrap_or_else(|| "the locate database".to_string())
}

/// One finding of a run that indexes the volume or that NAILS cannot tell
/// about.
fn finding(judged: &Judged) -> String {
    let what = match &judged.run.start {
        Start::Now(what) => format!("an updatedb runs now ({what})"),
        Start::Timer(timer) => format!("{timer} schedules updatedb"),
        Start::Enabled(service) => {
            format!("{service} is enabled and runs updatedb whenever its manager starts")
        }
        Start::Cron(job) => format!("the cron job at {job} runs updatedb"),
        Start::Unread(what) => {
            let why = match &judged.cover {
                Cover::Unknown(why) => why.as_str(),
                _ => "NAILS cannot read it",
            };
            return format!("{what} may start updatedb, which NAILS cannot tell: {why}");
        }
        Start::ByHand(what) => format!("updatedb can be started by hand ({what})"),
    };
    match &judged.cover {
        Cover::Not(at) => format!(
            "{what}, and it does not skip the hidden volume at {}: a run while the volume is \
             mounted writes the name of every file on it into {} on the decoy disk",
            at.display(),
            database(judged)
        ),
        Cover::Unknown(why) => {
            format!("{what}, and NAILS cannot tell whether it skips the hidden volume: {why}")
        }
        Cover::Covered(rule) => format!("{what}, and it skips the hidden volume: {rule}"),
    }
}

/// The findings of `runs`, each once.
fn findings(runs: &[Judged]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for judged in runs {
        let finding = finding(judged);
        if !out.contains(&finding) {
            out.push(finding);
        }
    }
    out
}

impl<F: Filesystem> PreFlightCheck<F> for LocateDatabaseCheck {
    fn name(&self) -> &'static str {
        "locate-database"
    }

    fn description(&self) -> &'static str {
        "Validates updatedb never writes the hidden volume's file names into the decoy's locate database"
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        let locations = hidden_locations(fs, &self.hidden_root);
        let hidden: Vec<PathBuf> = locations
            .iter()
            .map(|location| location.path.clone())
            .collect();
        let found = read::read_decoy(fs, &self.root, &hidden, &self.started());
        let remedy = || {
            fix(
                &locations,
                self.is_nixos,
                &found.remedies,
                found.nixos_prunepaths.as_deref(),
            )
        };
        Ok(
            match judge::verdict(found.installed, &found.runs, &locations) {
                Verdict::NotInstalled => CheckResult::Pass(
                    "no updatedb (plocate, mlocate or findutils' locate) is installed on the decoy"
                        .to_string(),
                ),
                Verdict::Pass(rules) if rules.is_empty() => {
                    CheckResult::Pass(if found.notes.is_empty() {
                        "nothing runs updatedb".to_string()
                    } else {
                        format!("nothing runs updatedb: {}", found.notes.join("; "))
                    })
                }
                Verdict::Pass(rules) => CheckResult::Pass(format!(
                    "updatedb skips the hidden volume: {}",
                    rules.join("; ")
                )),
                Verdict::Fail(runs) => {
                    let running = runs
                        .iter()
                        .any(|judged| matches!(judged.run.start, Start::Now(_)));
                    let mounted: Vec<String> = hidden
                        .iter()
                        .map(|path| path.display().to_string())
                        .collect();
                    let mut remediation = format!(
                        "Lock the hidden volume now: unmount {} and close it. Then, long before \
                         you use it again, {}.",
                        mounted.join(" and "),
                        remedy()
                    );
                    if running {
                        remediation.push_str(
                            " A database written while the volume was mounted lists its files \
                             until updatedb runs again with the volume locked.",
                        );
                    }
                    remediation.push_str(&format!(" See {DOC}."));
                    CheckResult::fail_with(
                        format!(
                            "the decoy's locate database would list the hidden volume: {}.",
                            findings(&runs).join("; ")
                        ),
                        remediation,
                    )
                }
                Verdict::Warn(runs) => CheckResult::warn_with(
                    format!(
                        "the decoy's locate database may list the hidden volume: {}.",
                        findings(&runs).join("; ")
                    ),
                    format!(
                        "Long before you use the volume again, {}. See {DOC}.",
                        remedy()
                    ),
                ),
            },
        )
    }
}

#[cfg(test)]
mod sources_tests;
#[cfg(test)]
mod tests;
