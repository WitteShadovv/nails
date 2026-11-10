// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Pre-flight check that refuses activation while a daily unattended-upgrade
//! run is in progress.
//!
//! unattended-upgrades (Debian, Ubuntu) runs a shutdown helper that waits for
//! logind's shutdown signal, which activation sends as `systemctl
//! soft-reboot` does. When the signal comes while a run of
//! unattended-upgrade holds its lock, `/run/unattended-upgrades.lock`, the
//! helper sends the run SIGTERM and writes `Unattended-upgrade in progress
//! during shutdown` to its log on the decoy disk, and the run logs that it
//! stops, whatever `Unattended-Upgrade::InstallOnShutdown` says. A run holds
//! the lock from its start to its end, while it plans, downloads and between
//! its install steps, but APT holds its shutdown block only while dpkg runs,
//! so the `shutdown-inhibitors` check does not see it. A daily run is started
//! by `apt-daily-upgrade.service`, which runs a while before it takes the
//! lock. `apt-daily.service` runs `apt-get update` first and then, with
//! unattended-upgrades installed, `unattended-upgrade --download-only`, which
//! takes the same lock: a switch made while it runs meets that lock if the
//! download run takes it between the last look and the helper's first look
//! for it, a moment with python3-gi and up to 3 seconds after the signal
//! without it.
//!
//! So activation is refused while `apt-daily-upgrade.service` or
//! `apt-daily.service` is active or a process holds the lock, until the run
//! ends, a few minutes as a rule. No flag lifts the refusal. The entry looks
//! again right before it asks logind for the switch ([`upgrade_run`]), as a
//! run can start while the entry is prepared.
//!
//! Whether the lock is held is asked of the kernel about the lock file itself
//! (`F_GETLK`, [`Filesystem::record_lock_holder`]): the file is opened
//! read-only, which changes none of its times, and closed again, and it is
//! neither locked nor read; nothing is written. The kernel's list of locks,
//! `/proc/locks`, is no snapshot: it prints a page at a time, and a lock that
//! goes away before another between two pages makes it skip that other one,
//! a held lock included. unattended-upgrade makes the lock file with mode
//! 0640, so only root can open it: a check run without root cannot tell
//! where the file exists, and says to run it as root, while activation runs
//! as root. Where the lock file does not exist, no run took it since the
//! boot, and nothing is opened. The helper opens the lock file without
//! following a link and takes one it cannot open for a held lock, as it
//! cannot open a link, a directory or a socket; a lock file that is anything
//! but a plain file leaves NAILS unable to tell, which refuses as well.

use super::super::{CheckResult, PreFlightCheck};
use super::decoy_posture::{Activity, unit_active};
use crate::next_step::{NextStep, sudo_line};
use crate::{Filesystem, Result};
use std::path::{Path, PathBuf};

/// The units of the daily runs, which their timers start: the install, and
/// the download, whose run of unattended-upgrade takes the same lock.
const DAILY_UPGRADE: &str = "apt-daily-upgrade.service";
const DAILY_DOWNLOAD: &str = "apt-daily.service";

/// The lock a run of unattended-upgrade holds from its start to its end,
/// relative to the root, under both of its names: unattended-upgrade names
/// it below `/var/run`, a link to `/run` on Debian and Ubuntu.
const LOCKS: &[&str] = &[
    "run/unattended-upgrades.lock",
    "var/run/unattended-upgrades.lock",
];

/// Whether a daily unattended-upgrade run is in progress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpgradeRun {
    /// None is.
    Idle,
    /// One is, as these say.
    InProgress(Vec<String>),
    /// NAILS cannot tell, for this reason.
    Unknown(String),
    /// NAILS cannot tell without root, for this reason: only root can open
    /// the lock file, which a run as root does.
    UnknownWithoutRoot(String),
}

/// What the switch makes of a run: the signs of one need not mean the helper
/// writes its line (unattended-upgrades may not be installed, or the run may
/// not hold the lock yet), so it says what the helper does when it does.
const AT_THE_SWITCH: &str = "at the switch, the shutdown helper of unattended-upgrades, if it \
                             runs, stops a run that holds the lock and writes `Unattended-upgrade \
                             in progress during shutdown` to its log on the decoy disk";

impl UpgradeRun {
    /// Why it refuses a switch, `None` when it does not.
    pub fn refusal(&self) -> Option<String> {
        match self {
            UpgradeRun::Idle => None,
            UpgradeRun::InProgress(signs) => Some(format!(
                "a daily unattended-upgrade run is in progress ({}): {AT_THE_SWITCH}",
                signs.join(", and ")
            )),
            UpgradeRun::Unknown(why) => Some(format!(
                "NAILS cannot tell whether a daily unattended-upgrade run is in progress \
                 ({why}): {AT_THE_SWITCH}"
            )),
            UpgradeRun::UnknownWithoutRoot(why) => Some(format!(
                "NAILS cannot tell without root whether a daily unattended-upgrade run is in \
                 progress ({why}): {AT_THE_SWITCH}"
            )),
        }
    }

    /// What to do about a refusal: wait for the run to end, let NAILS read
    /// what it could not, or run as root.
    pub fn fix(&self) -> String {
        match self {
            UpgradeRun::Unknown(_) => UNREAD.to_string(),
            UpgradeRun::UnknownWithoutRoot(_) => format!(
                "Run the check as root (`{}`), which can open the lock file to ask the kernel \
                 about its locks.",
                sudo_line(NextStep::Check)
            ),
            _ => RETRY.to_string(),
        }
    }
}

/// What a failed query of the lock file `shown` leaves: a doubt of its own
/// where the caller is not root and the open was refused, which a run as
/// root does not have, as only root can open the file.
fn lock_doubt(shown: &str, e: &crate::NailsError, as_root: bool) -> UpgradeRun {
    let why = format!("{shown} cannot be asked about its locks: {e}");
    if !as_root && e.io_kind() == Some(std::io::ErrorKind::PermissionDenied) {
        UpgradeRun::UnknownWithoutRoot(format!("{why}; only root can open it"))
    } else {
        UpgradeRun::Unknown(why)
    }
}

/// Whether a daily unattended-upgrade run is in progress on the system
/// under `root`: `apt-daily-upgrade.service` or `apt-daily.service` is
/// active, or a process holds unattended-upgrade's lock. Reads only; the
/// lock file is opened, to ask the kernel about its locks, only where it
/// exists.
pub fn upgrade_run<F: Filesystem>(fs: &F, root: &Path) -> UpgradeRun {
    upgrade_run_as(fs, root, nix::unistd::geteuid().is_root())
}

/// [`upgrade_run`], for a caller that is root (`as_root`) or not.
fn upgrade_run_as<F: Filesystem>(fs: &F, root: &Path, as_root: bool) -> UpgradeRun {
    let mut signs = Vec::new();
    // A unit NAILS cannot tell is active may run: unless another sign shows
    // a run, that leaves NAILS unable to tell.
    let mut untold = None;
    let units = [
        (DAILY_UPGRADE, format!("{DAILY_UPGRADE} is active")),
        (
            DAILY_DOWNLOAD,
            format!("{DAILY_DOWNLOAD} is active, whose download run takes the lock"),
        ),
    ];
    for (unit, sign) in units {
        match unit_active(fs, root, unit) {
            Activity::Active => signs.push(sign),
            Activity::Inactive => {}
            Activity::Untold(why) => {
                untold.get_or_insert(why);
            }
        }
    }
    let mut seen = Vec::new();
    for lock in LOCKS {
        let path = root.join(lock);
        let shown = format!("/{lock}");
        let doubt = |e| UpgradeRun::Unknown(format!("{shown} cannot be looked up: {e}"));
        // The helper opens the lock file with O_NOFOLLOW (apt's GetLock())
        // and takes a lock file it cannot open for a held lock
        // (unattended-upgrade-shutdown's iter()): a link, a directory or a
        // socket makes it write its line at every switch, which no lock
        // shows. Any other file that is no plain file is not judged.
        match fs.is_symlink(&path) {
            Ok(false) => {}
            Ok(true) => {
                return UpgradeRun::Unknown(format!(
                    "{shown} is a symbolic link, not a plain file"
                ));
            }
            Err(e) => return doubt(e),
        }
        let inode = match fs.inode(&path) {
            Ok(Some(inode)) => inode,
            Ok(None) => continue,
            Err(e) => return doubt(e),
        };
        match fs.is_regular_file(&path) {
            Ok(true) => {}
            Ok(false) => return UpgradeRun::Unknown(format!("{shown} is not a plain file")),
            Err(e) => return doubt(e),
        }
        let dev = match fs.device_id(&path) {
            Ok(dev) => dev,
            Err(e) => return doubt(e),
        };
        // The same file under its other name.
        if seen.contains(&(dev, inode)) {
            continue;
        }
        seen.push((dev, inode));
        match fs.record_lock_holder(&path) {
            Ok(None) => {}
            // A PID in this namespace; an open file description lock has
            // none (-1), and a holder outside the namespace shows as 0.
            Ok(Some(pid)) if pid > 0 => signs.push(format!("PID {pid} holds {shown}")),
            Ok(Some(_)) => signs.push(format!("a process holds {shown}")),
            Err(e) => return lock_doubt(&shown, &e, as_root),
        }
    }
    match untold {
        _ if !signs.is_empty() => UpgradeRun::InProgress(signs),
        Some(why) => UpgradeRun::Unknown(why),
        None => UpgradeRun::Idle,
    }
}

/// What to do: wait for the run to end.
pub const RETRY: &str = "Try again in a few minutes, once the run has ended \
                         (`systemctl status apt-daily.service apt-daily-upgrade.service` shows \
                         the daily runs).";

/// What to do when NAILS cannot tell.
const UNREAD: &str = "Make sure /run/unattended-upgrades.lock, where it exists, is a plain file \
                      that can be looked up and opened, then activate again.";

/// `unattended-upgrade-run`: refuses activation while a daily
/// unattended-upgrade run is in progress.
#[derive(Debug)]
pub struct UpgradeRunCheck {
    /// The system's root, `/` outside tests.
    root: PathBuf,
}

impl UpgradeRunCheck {
    /// The check of the running system.
    pub fn new() -> Self {
        Self {
            root: PathBuf::from("/"),
        }
    }

    /// The check of the system tree under `root` (tests).
    #[cfg(test)]
    fn with_root(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
        }
    }
}

impl Default for UpgradeRunCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: Filesystem> PreFlightCheck<F> for UpgradeRunCheck {
    fn name(&self) -> &'static str {
        "unattended-upgrade-run"
    }

    fn description(&self) -> &'static str {
        "no daily unattended-upgrade run is in progress"
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        let run = upgrade_run(fs, &self.root);
        Ok(match run.refusal() {
            None => CheckResult::Pass("no daily unattended-upgrade run is in progress".into()),
            Some(why) => CheckResult::fail_with(why, run.fix()),
        })
    }
}

#[cfg(test)]
#[path = "upgrade_run_tests.rs"]
mod tests;
