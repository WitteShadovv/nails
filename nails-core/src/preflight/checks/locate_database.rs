// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Pre-flight check that refuses a decoy that may run updatedb.
//!
//! updatedb (plocate's, mlocate's, findutils', or NixOS's
//! `update-locatedb.service`) walks the whole tree and writes the name of
//! every file it finds into the locate database on the decoy disk
//! (`/var/lib/plocate/plocate.db`, `/var/lib/mlocate/mlocate.db`,
//! `/var/cache/locatedb` on NixOS). A run while the hidden volume is mounted
//! on the decoy, before activation or after the way back, writes every name
//! on the volume there. The stock timers run daily and catch a missed run up
//! right after boot, when the volume is unlocked for a session, and Debian's
//! and Ubuntu's plocate package starts its service again at every upgrade.
//!
//! The check does not read what a run skips (`PRUNEPATHS` and the options of
//! the command line): it refuses while anything on the decoy may run
//! updatedb without a person typing it. That is, while:
//!
//! - a unit file or drop-in of the system manager or of a user's, in any
//!   directory systemd loads units from, names updatedb (`updatedb` or
//!   `locatedb` in its name or its text, in any case), and the unit is not
//!   masked. A mask stops every way the unit starts: its timer, a `.wants`
//!   entry, another unit, a socket, a package's own `systemctl start` or
//!   `restart` in its maintainer scripts. A drop-in of a unit that cannot be
//!   masked (`service.d`, `plocate-.service.d`), and a unit in a user's own
//!   directories, refuse until the file is removed;
//! - a unit the system manager has loaded names updatedb, by its names or
//!   its commands, and is active or not masked (`systemctl show`): this sees
//!   a timer masked but still running and a unit whose file is gone since it
//!   was loaded;
//! - a crontab, an anacrontab, a cron script or an `at` job names updatedb;
//! - a process whose name names updatedb runs now;
//! - NAILS cannot tell one of these: a directory, file or process it cannot
//!   read, a system manager it cannot ask, an automount point it does not
//!   mount.
//!
//! No flag lifts the refusal. An updatedb program that nothing schedules
//! warns: a run by hand while the volume is mounted lists it as well.
//!
//! Nothing is written. The decoy's files are read under a root with
//! `O_NOATIME` and never where a link leads onto the hidden volume
//! ([`files`]). The running system is read through the automount guard
//! ([`crate::filesystem::automount`]): a lookup that would mount an
//! automount point that nothing is mounted on yet is not made, and the check
//! refuses, naming the point. Without a readable mount table it looks up
//! nothing, and refuses.

pub(in crate::preflight::checks) mod aliases;
pub mod exec;
pub mod files;
// The decoy-persistence check reads the decoy's units, and what their
// triggers start.
mod scan;
pub(in crate::preflight::checks) mod targets;
pub(in crate::preflight::checks) mod unit;

use super::super::{CheckResult, PreFlightCheck};
use crate::filesystem::automount::{Guarded, OnSkip, Snapshot, settle};
use crate::filesystem::mountinfo::top_mount_at;
use crate::process::{ProcessCommand, ProcessRunner, RealProcessRunner};
use crate::{Filesystem, Result};
use files::DecoyFiles;
use std::path::{Path, PathBuf};

/// Where the docs explain the check.
const DOC: &str = "docs/decoy-requirements.md#the-locate-database";

/// The commands of a unit `systemctl show` gives, with its names and state.
const SHOWN: &str = "Id,Names,LoadState,ActiveState,ExecCondition,ExecStartPre,ExecStart,\
                     ExecStartPost,ExecReload,ExecStop,ExecStopPost";

/// Pre-flight check that refuses a decoy that may run updatedb.
#[derive(Debug)]
pub struct LocateDatabaseCheck {
    /// The hidden root as configured.
    hidden_root: PathBuf,
    /// Whether the host carries a NixOS config layer, which picks the fix.
    is_nixos: bool,
    /// Root of the system tree read; `/` outside tests.
    root: PathBuf,
    /// What `systemctl show` gives, as tests give it; asked of the system
    /// manager when `None`.
    shown: Option<std::result::Result<String, String>>,
}

impl LocateDatabaseCheck {
    /// The check for the hidden root at `hidden_root`; `is_nixos` gives the
    /// NixOS fix.
    pub fn new(hidden_root: PathBuf, is_nixos: bool) -> Self {
        Self {
            hidden_root,
            is_nixos,
            root: PathBuf::from("/"),
            shown: None,
        }
    }

    /// Read the system tree rooted at `root` instead of `/` (tests).
    #[cfg(test)]
    fn with_root(mut self, root: &Path) -> Self {
        self.root = root.to_path_buf();
        self
    }

    /// Take `shown` as what `systemctl show` gives (tests).
    #[cfg(test)]
    pub(crate) fn with_shown(mut self, shown: std::result::Result<String, String>) -> Self {
        self.shown = Some(shown);
        self
    }

    /// What the system manager shows of the units it has loaded, or why
    /// NAILS cannot tell: only the running system's manager can say.
    fn shown(&self) -> std::result::Result<String, String> {
        if let Some(shown) = &self.shown {
            return shown.clone();
        }
        if self.root != Path::new("/") {
            return Err(format!("the decoy is read under {}", self.root.display()));
        }
        loaded_units(&RealProcessRunner)
    }
}

/// The names, state and commands of every unit the system manager has
/// loaded, as `systemctl show --all '*'` gives them.
pub fn loaded_units(runner: &dyn ProcessRunner) -> std::result::Result<String, String> {
    let show = ProcessCommand::tool("systemctl")
        .args([
            "show",
            "--all",
            "--no-pager",
            &format!("--property={SHOWN}"),
            "*",
        ])
        .deadline(crate::process::run::SYSTEMCTL_PROBE_BUDGET);
    match runner.run_text(&show) {
        Ok((true, out, _)) => Ok(out),
        Ok((false, _, err)) => Err(format!(
            "`systemctl show` failed ({})",
            err.lines().next().unwrap_or("no message")
        )),
        Err(e) => Err(format!("NAILS cannot run systemctl ({e})")),
    }
}

/// Where the hidden volume shows on the running system: the hidden root,
/// resolved as the attach gate resolves it, and every other mount of the
/// filesystem mounted there. Without a mount table only the root is known.
pub fn hidden_locations<F: Filesystem>(fs: &F, hidden_root: &Path) -> Vec<PathBuf> {
    let resolved = fs
        .canonicalize(hidden_root)
        .unwrap_or_else(|_| hidden_root.components().collect());
    let mut paths = vec![resolved.clone()];
    let Ok(table) = fs.mount_table() else {
        return paths;
    };
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
}

impl<F: Filesystem> PreFlightCheck<F> for LocateDatabaseCheck {
    fn name(&self) -> &'static str {
        "locate-database"
    }

    fn description(&self) -> &'static str {
        "Validates nothing on the decoy schedules or runs updatedb, which would write the hidden \
         volume's file names into the decoy's locate database"
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        // Without the table a lookup could mount an automount point, so none
        // is made.
        let snapshot = Snapshot::read(fs, &self.root);
        if let Some(error) = snapshot.unreadable() {
            return Ok(CheckResult::fail_with(
                format!(
                    "NAILS cannot tell whether the decoy runs updatedb, which would write the \
                     name of every file on the hidden volume into the decoy's locate database: \
                     it cannot read the mount table ({error}), which shows where a lookup would \
                     mount an automount point, so it looks up nothing."
                ),
                format!("Run the check where /proc/self/mountinfo can be read. See {DOC}."),
            ));
        }
        let guarded = Guarded::new(fs.clone(), &snapshot);
        let result = self.judge(&guarded);
        Ok(settle(result, &guarded.skipped(), OnSkip::Refuse(None)))
    }
}

impl LocateDatabaseCheck {
    /// The general fix: remove the locate package, or disable NixOS's
    /// service.
    fn general_fix(&self) -> &'static str {
        if self.is_nixos {
            "set `services.locate.enable = false;` in the decoy's configuration, take out any \
             unit or cron job of its own that runs updatedb, and rebuild it"
        } else {
            "remove the locate package with its configuration: `sudo apt purge plocate` on \
             Debian and Ubuntu (mlocate or locate where that is the one installed), `sudo dnf \
             remove plocate` on Fedora, `sudo pacman -Rns plocate` on Arch Linux"
        }
    }

    /// The verdict on what the decoy holds of updatedb, read through `fs`.
    fn judge<F: Filesystem>(&self, fs: &F) -> CheckResult {
        let hidden = hidden_locations(fs, &self.hidden_root);
        let files = DecoyFiles::new(fs, &self.root, &hidden);
        let found = scan::scan(fs, &files, self.shown());

        if !found.runs.is_empty() {
            let what: Vec<&str> = found.runs.iter().map(|f| f.what.as_str()).collect();
            let mut fixes: Vec<&str> = Vec::new();
            for fix in found.runs.iter().filter_map(|f| f.fix.as_deref()) {
                if !fixes.contains(&fix) {
                    fixes.push(fix);
                }
            }
            let mounted: Vec<String> = hidden.iter().map(|p| p.display().to_string()).collect();
            let named = if fixes.is_empty() || self.is_nixos {
                String::new()
            } else {
                format!(" Or stop each one: {}.", fixes.join("; "))
            };
            return CheckResult::fail_with(
                format!(
                    "the decoy may run updatedb, which writes the name of every file on the \
                     hidden volume into the locate database on the decoy disk while the volume \
                     is mounted: {}.",
                    what.join("; ")
                ),
                format!(
                    "Lock the hidden volume now: unmount {} and close it. Then, long before you \
                     use it again, {}.{named} A database written while the volume was mounted \
                     lists its files until updatedb runs again with the volume locked. A \
                     PRUNEPATHS or prunePaths that skips the volume does not lift this refusal. \
                     See {DOC}.",
                    mounted.join(" and "),
                    self.general_fix()
                ),
            );
        }
        if !found.by_hand.is_empty() {
            return CheckResult::warn_with(
                format!(
                    "updatedb is installed on the decoy ({}). Nothing schedules it, but a run by \
                     hand while the hidden volume is mounted writes the name of every file on it \
                     into the locate database on the decoy disk.",
                    found.by_hand.join(", ")
                ),
                format!(
                    "Never run updatedb while the volume is mounted, or {}. See {DOC}.",
                    self.general_fix()
                ),
            );
        }
        CheckResult::Pass(
            "nothing on the decoy schedules or runs updatedb: no unit, cron or at job names it, \
             none runs now and no updatedb is installed"
                .to_string(),
        )
    }
}

#[cfg(test)]
mod tests;
