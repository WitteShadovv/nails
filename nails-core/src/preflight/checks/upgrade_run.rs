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
//! lock, and `apt-daily.service` takes it for its download.
//!
//! So activation is refused while `apt-daily-upgrade.service` is active or a
//! process holds the lock, until the run ends, a few minutes as a rule. No
//! flag lifts the refusal. The entry looks again right before it asks logind
//! for the switch ([`upgrade_run`]), as a run can start while the entry is
//! prepared.
//!
//! Whether the lock is held is read from `/proc/locks`, which lists every
//! lock with the device and inode of its file, against those of the lock
//! file: the lock file is looked up but neither opened nor locked, and
//! nothing is written. Where the lock file does not exist, no run took it
//! since the boot, and `/proc/locks` is not read. The helper opens the lock
//! file without following a link and takes one it cannot open for a held
//! lock, as it cannot open a link, a directory or a socket; a lock file that
//! is anything but a plain file leaves NAILS unable to tell, which refuses as
//! well.

use super::super::{CheckResult, PreFlightCheck};
use super::decoy_posture::unit_active;
use crate::{Filesystem, Result};
use std::path::{Path, PathBuf};

/// The unit of the daily run, which its timer starts.
const DAILY_UPGRADE: &str = "apt-daily-upgrade.service";

/// The lock a run of unattended-upgrade holds from its start to its end,
/// relative to the root, under both of its names: unattended-upgrade names
/// it below `/var/run`, a link to `/run` on Debian and Ubuntu.
const LOCKS: &[&str] = &[
    "run/unattended-upgrades.lock",
    "var/run/unattended-upgrades.lock",
];

/// The kernel's list of file locks, relative to the root.
const PROC_LOCKS: &str = "proc/locks";

/// Whether a daily unattended-upgrade run is in progress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpgradeRun {
    /// None is.
    Idle,
    /// One is, as these say.
    InProgress(Vec<String>),
    /// NAILS cannot tell, for this reason.
    Unknown(String),
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
        }
    }

    /// What to do about a refusal: wait for the run to end, or let NAILS
    /// read what it could not.
    pub fn fix(&self) -> &'static str {
        match self {
            UpgradeRun::Unknown(_) => UNREAD,
            _ => RETRY,
        }
    }
}

/// glibc's `major()` of a device number as `stat` gives it, the number the
/// kernel prints in `/proc/locks`.
fn major(dev: u64) -> u64 {
    ((dev >> 8) & 0xfff) | ((dev >> 32) & 0xffff_f000)
}

/// glibc's `minor()` of a device number as `stat` gives it.
fn minor(dev: u64) -> u64 {
    (dev & 0xff) | ((dev >> 12) & 0xffff_ff00)
}

/// The processes that hold a lock on the file with `(major, minor, inode)`,
/// as `/proc/locks` lists them: `POSIX` and `OFDLCK` entries, the kinds of
/// lock unattended-upgrade's lock conflicts with, and not a request that
/// waits (`->`). An open file description lock has no process (`-1`).
pub fn lock_holders(locks: &str, file: (u64, u64, u64)) -> Vec<i64> {
    let mut holders = Vec::new();
    for line in locks.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if !matches!(fields.get(1), Some(&("POSIX" | "OFDLCK"))) {
            continue;
        }
        // `<pid> <major>:<minor>:<inode>`, the device numbers in hex.
        let Some(at) = fields.iter().position(|field| {
            let parts: Vec<&str> = field.split(':').collect();
            parts.len() == 3
                && u64::from_str_radix(parts[0], 16).ok() == Some(file.0)
                && u64::from_str_radix(parts[1], 16).ok() == Some(file.1)
                && parts[2].parse::<u64>().ok() == Some(file.2)
        }) else {
            continue;
        };
        if let Some(pid) = at
            .checked_sub(1)
            .and_then(|before| fields[before].parse::<i64>().ok())
        {
            holders.push(pid);
        }
    }
    holders
}

/// Whether a daily unattended-upgrade run is in progress on the system
/// under `root`: `apt-daily-upgrade.service` is active, or a process holds
/// unattended-upgrade's lock. Reads only; nothing is opened but
/// `/proc/locks`, and only where the lock file exists.
pub fn upgrade_run<F: Filesystem>(fs: &F, root: &Path) -> UpgradeRun {
    let mut signs = Vec::new();
    if unit_active(fs, root, DAILY_UPGRADE) {
        signs.push(format!("{DAILY_UPGRADE} is active"));
    }
    let mut seen = Vec::new();
    let mut locks: Option<String> = None;
    for lock in LOCKS {
        let path = root.join(lock);
        let shown = format!("/{lock}");
        let doubt = |e| UpgradeRun::Unknown(format!("{shown} cannot be looked up: {e}"));
        // The helper opens the lock file with O_NOFOLLOW (apt's GetLock())
        // and takes a lock file it cannot open for a held lock
        // (unattended-upgrade-shutdown's iter()): a link, a directory or a
        // socket makes it write its line at every switch, which /proc/locks
        // does not show. Any other file that is no plain file is not judged.
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
        let file = (major(dev), minor(dev), inode);
        // The same file under its other name.
        if seen.contains(&file) {
            continue;
        }
        seen.push(file);
        if locks.is_none() {
            match fs.read_file_content(&root.join(PROC_LOCKS)) {
                Ok(content) => locks = Some(content),
                Err(e) => {
                    return UpgradeRun::Unknown(format!("/{PROC_LOCKS} cannot be read: {e}"));
                }
            }
        }
        let holders = lock_holders(locks.as_deref().unwrap_or_default(), file);
        if !holders.is_empty() {
            let who = holders
                .iter()
                .map(|pid| {
                    if *pid > 0 {
                        format!("PID {pid}")
                    } else {
                        "a process".to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join(" and ");
            signs.push(format!("{who} holds {shown}"));
        }
    }
    if signs.is_empty() {
        UpgradeRun::Idle
    } else {
        UpgradeRun::InProgress(signs)
    }
}

/// What to do: wait for the run to end.
pub const RETRY: &str = "Try again in a few minutes, once the run has ended \
                         (`systemctl status apt-daily.service apt-daily-upgrade.service` shows \
                         the daily runs).";

/// What to do when NAILS cannot tell.
const UNREAD: &str = "Make sure /proc is mounted and /run/unattended-upgrades.lock, where it \
                      exists, is a plain file that can be looked up, then activate again.";

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
