// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The pre-flight checks only a whole-root session has.
//!
//! - `systemd-version`: systemd >= 254 (`systemctl soft-reboot`); an older one
//!   is refused with how the host's distribution upgrades to a newer one;
//! - `soft-reboot-units`: the two units that implement it are installed;
//! - `decoy-root`: the decoy root can be mounted again by device for the way
//!   back;
//! - `session-state`: neither in the hidden root already nor with leftovers of
//!   an interrupted entry;
//! - `fstab-policy`: every decoy filesystem the hidden systemd would mount has a
//!   safe decision ([`super::policy`]).
//!
//! Each check reads the live system in `run` and judges through a pure
//! function, which the tests exercise directly.

use super::fstab::{parse_in_root, read_in_root as read_fstab};
use super::layout::Paths;
use super::policy::{self, Decision};
use super::probe::{self, SessionView};
use super::systemd::{self, MIN_SYSTEMD};
use crate::error::Result;
use crate::filesystem::Filesystem;
use crate::platform::{HostProfile, upgrade_hint};
use crate::preflight::{CheckResult, PreFlightCheck};
use nails_teardown::mountinfo::{MountEntry, read_mountinfo};
use std::path::{Path, PathBuf};

/// Judge a systemd version on `host`: one too old fails with how the host's
/// distribution upgrades to a release that is new enough.
pub fn judge_version(version: Option<u32>, host: Option<&HostProfile>) -> CheckResult {
    match version {
        Some(v) if v >= MIN_SYSTEMD => {
            CheckResult::Pass(format!("systemd {v} supports soft-reboot"))
        }
        Some(v) => CheckResult::fail_with(
            format!(
                "systemd {v} is too old: the hidden session is entered with `systemctl \
                 soft-reboot`, which needs systemd {MIN_SYSTEMD} or newer"
            ),
            upgrade_hint(host),
        ),
        None => CheckResult::fail_with(
            "could not read the version of the running systemd".to_string(),
            "NAILS needs a systemd host (PID 1 must be systemd 254 or newer).".to_string(),
        ),
    }
}

/// `systemd-version`.
#[derive(Debug)]
pub struct SystemdVersionCheck {
    /// The detected host, whose distribution the upgrade hint names.
    host: Option<HostProfile>,
}

impl SystemdVersionCheck {
    /// The check on the detected `host`; without one, a systemd too old is
    /// pointed at the platforms NAILS runs on.
    pub fn new(host: Option<HostProfile>) -> Self {
        Self { host }
    }

    /// Judge the running systemd's `version` on the host this check was built
    /// on.
    pub fn judge(&self, version: Option<u32>) -> CheckResult {
        judge_version(version, self.host.as_ref())
    }
}

impl<F: Filesystem> PreFlightCheck<F> for SystemdVersionCheck {
    fn name(&self) -> &'static str {
        "systemd-version"
    }
    fn description(&self) -> &'static str {
        "systemd supports soft-reboot (254 or newer)"
    }
    fn run(&self, _fs: &F) -> Result<CheckResult> {
        Ok(self.judge(systemd::running_version(&crate::process::RealProcessRunner)))
    }
}

/// Judge the soft-reboot units below `root`.
pub fn judge_units(root: &Path, nixos: bool) -> CheckResult {
    let missing = systemd::missing_soft_reboot_units(root);
    if missing.is_empty() {
        return CheckResult::Pass(
            "soft-reboot.target and systemd-soft-reboot.service are installed".into(),
        );
    }
    let remediation = if nixos {
        format!(
            "This nixpkgs does not install them yet (nixpkgs PR #514100). Add this to the decoy's \
             configuration, and to the hidden one, then rebuild the decoy:\n{}",
            systemd::NIXOS_UNITS_SNIPPET
        )
    } else {
        "Install a systemd package that ships them (systemd 254 or newer).".to_string()
    };
    CheckResult::fail_with(
        format!(
            "missing {}: {}",
            if missing.len() == 1 { "unit" } else { "units" },
            missing.join(", ")
        ),
        remediation,
    )
}

/// `soft-reboot-units`.
#[derive(Debug)]
pub struct SoftRebootUnitsCheck {
    root: PathBuf,
    nixos: bool,
}

impl SoftRebootUnitsCheck {
    /// The check for the root at `root`.
    pub fn new(root: PathBuf, nixos: bool) -> Self {
        Self { root, nixos }
    }
}

impl<F: Filesystem> PreFlightCheck<F> for SoftRebootUnitsCheck {
    fn name(&self) -> &'static str {
        "soft-reboot-units"
    }
    fn description(&self) -> &'static str {
        "the soft-reboot units are installed"
    }
    fn run(&self, _fs: &F) -> Result<CheckResult> {
        Ok(judge_units(&self.root, self.nixos))
    }
}

/// `decoy-root`.
#[derive(Debug)]
pub struct DecoyRootCheck {
    root: PathBuf,
}

impl DecoyRootCheck {
    /// The check for the decoy root at `root`.
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }
}

/// Judge the decoy root in `entries`.
pub fn judge_decoy_root(entries: &[MountEntry], root: &Path) -> CheckResult {
    match super::entry::decoy_root_of(entries, root) {
        Ok(decoy) => CheckResult::Pass(format!(
            "the decoy root ({} on {}) can be mounted again for the way back",
            decoy.fstype,
            decoy.source.display()
        )),
        Err(e) => CheckResult::fail_with(
            e.to_string(),
            "The whole-root session needs a decoy root on a block device (ext4, xfs, btrfs, \
             f2fs). An impermanent (RAM) root is not supported."
                .to_string(),
        ),
    }
}

impl<F: Filesystem> PreFlightCheck<F> for DecoyRootCheck {
    fn name(&self) -> &'static str {
        "decoy-root"
    }
    fn description(&self) -> &'static str {
        "the decoy root can be mounted again for the way back"
    }
    fn run(&self, _fs: &F) -> Result<CheckResult> {
        Ok(judge_decoy_root(
            &read_mountinfo().unwrap_or_default(),
            &self.root,
        ))
    }
}

/// Judge where the machine is.
pub fn judge_session(view: &SessionView) -> CheckResult {
    use nails_base::next_step::{NextStep, sudo_line};
    match view {
        SessionView::Decoy => CheckResult::Pass("on the plain decoy root".into()),
        SessionView::Hidden(_) | SessionView::HiddenWithoutPlan(_) => CheckResult::fail_with(
            "the hidden session is already active".to_string(),
            format!(
                "Run `{}` to return to the decoy.",
                sudo_line(NextStep::Deactivate)
            ),
        ),
        SessionView::Entering(_) => CheckResult::fail_with(
            "another activation is entering the hidden root".to_string(),
            format!(
                "Wait for the soft-reboot, or run `{}` if it hangs.",
                sudo_line(NextStep::Recover)
            ),
        ),
        SessionView::Interrupted { .. } => CheckResult::fail_with(
            "an interrupted activation left a next root or a session plan in /run".to_string(),
            format!("Run `{}` to remove them.", sudo_line(NextStep::Recover)),
        ),
    }
}

/// `session-state`.
#[derive(Debug)]
pub struct SessionStateCheck {
    paths: Paths,
    hidden_root: PathBuf,
}

impl SessionStateCheck {
    /// The check under `paths` for the hidden volume at `hidden_root`.
    pub fn new(paths: Paths, hidden_root: PathBuf) -> Self {
        Self { paths, hidden_root }
    }
}

impl<F: Filesystem> PreFlightCheck<F> for SessionStateCheck {
    fn name(&self) -> &'static str {
        "session-state"
    }
    fn description(&self) -> &'static str {
        "not in a hidden session and no interrupted entry"
    }
    fn run(&self, _fs: &F) -> Result<CheckResult> {
        Ok(judge_session(&probe::probe(&self.paths, &self.hidden_root)))
    }
}

/// Judge the fstab decisions.
pub fn judge_fstab(decisions: &[Decision]) -> CheckResult {
    if let Some(refused) = decisions
        .iter()
        .find(|d| matches!(d, Decision::Refuse { .. }))
    {
        return CheckResult::fail_with(
            refused.describe(),
            "Fix the fstab entry or remove it before activating.".to_string(),
        );
    }
    let notable: Vec<String> = decisions
        .iter()
        .filter(|d| !matches!(d, Decision::Leave { .. }))
        .map(Decision::describe)
        .collect();
    let masked_mounts = decisions.iter().any(|d| {
        matches!(d, Decision::Mask { units, .. } if units.iter().any(|u| !u.ends_with(".swap")))
    });
    let summary = if notable.is_empty() {
        "no decoy filesystem besides the root needs handling".to_string()
    } else {
        format!(
            "decoy filesystems in the hidden root: {}",
            notable.join("; ")
        )
    };
    if masked_mounts {
        CheckResult::Warn(format!(
            "{summary}. Masked filesystems are not available in the hidden session."
        ))
    } else {
        CheckResult::Pass(summary)
    }
}

/// `fstab-policy`.
#[derive(Debug)]
pub struct FstabPolicyCheck {
    root: PathBuf,
    hidden_root: PathBuf,
}

impl FstabPolicyCheck {
    /// The check for the decoy root at `root`.
    pub fn new(root: PathBuf, hidden_root: PathBuf) -> Self {
        Self { root, hidden_root }
    }
}

impl<F: Filesystem> PreFlightCheck<F> for FstabPolicyCheck {
    fn name(&self) -> &'static str {
        "fstab-policy"
    }
    fn description(&self) -> &'static str {
        "every decoy filesystem has a safe decision in the hidden root"
    }
    fn run(&self, _fs: &F) -> Result<CheckResult> {
        let text = match read_fstab(&self.root) {
            Ok(text) => text,
            Err(e) => {
                return Ok(CheckResult::fail_with(
                    format!(
                        "{} cannot be read: {e}",
                        self.root.join("etc/fstab").display()
                    ),
                    "Every decoy filesystem needs a decision before the switch; make the \
                     decoy's fstab readable by root and retry.",
                ));
            }
        };
        // Resolved in the decoy root, as activation decides them first.
        let entries = parse_in_root(&text, &self.root);
        let decisions = policy::decide_all(
            &entries,
            &read_mountinfo().unwrap_or_default(),
            &self.hidden_root,
        );
        Ok(judge_fstab(&decisions))
    }
}

#[cfg(test)]
#[path = "checks_tests.rs"]
mod tests;
