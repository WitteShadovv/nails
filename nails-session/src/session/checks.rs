// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The pre-flight checks only a whole-root session has.
//!
//! - `systemd-version`: systemd >= 254 (`systemctl soft-reboot`); Debian 12
//!   and Ubuntu 22.04 are refused with a clear message;
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

use super::fstab::parse_fstab;
use super::layout::Paths;
use super::policy::{self, Decision};
use super::probe::{self, SessionView};
use super::systemd::{self, MIN_SYSTEMD};
use crate::error::Result;
use crate::filesystem::Filesystem;
use crate::preflight::{CheckResult, PreFlightCheck};
use nails_teardown::mountinfo::{MountEntry, read_mountinfo};
use nails_teardown::whole_root::nextroot;
use std::path::{Path, PathBuf};

/// Judge a systemd version.
pub fn judge_version(version: Option<u32>) -> CheckResult {
    match version {
        Some(v) if v >= MIN_SYSTEMD => {
            CheckResult::Pass(format!("systemd {v} supports soft-reboot"))
        }
        Some(v) => CheckResult::fail_with(
            format!(
                "systemd {v} is too old: the hidden session is entered with `systemctl \
                 soft-reboot`, which needs systemd {MIN_SYSTEMD} or newer"
            ),
            "Debian 12 (bookworm, systemd 252) and Ubuntu 22.04 (jammy, systemd 249) are not \
             supported. Use Debian 13 (trixie), Ubuntu 24.04 or newer, or a current NixOS."
                .to_string(),
        ),
        None => CheckResult::fail_with(
            "could not read the version of the running systemd".to_string(),
            "NAILS needs a systemd host (PID 1 must be systemd 254 or newer).".to_string(),
        ),
    }
}

/// `systemd-version`.
#[derive(Debug, Default)]
pub struct SystemdVersionCheck;

impl<F: Filesystem> PreFlightCheck<F> for SystemdVersionCheck {
    fn name(&self) -> &'static str {
        "systemd-version"
    }
    fn description(&self) -> &'static str {
        "systemd supports soft-reboot (254 or newer)"
    }
    fn run(&self, _fs: &F) -> Result<CheckResult> {
        Ok(judge_version(systemd::running_version(
            &crate::process::RealProcessRunner,
        )))
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
        format!("missing unit(s): {}", missing.join(", ")),
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
    match view {
        SessionView::Decoy => CheckResult::Pass("on the plain decoy root".into()),
        SessionView::Hidden(_) | SessionView::HiddenWithoutPlan(_) => CheckResult::fail_with(
            "the hidden session is already active".to_string(),
            "Run `nails deactivate` to return to the decoy.".to_string(),
        ),
        SessionView::Entering(_) => CheckResult::fail_with(
            "another activation is entering the hidden root".to_string(),
            "Wait for the soft-reboot, or run `nails recover` if it hangs.".to_string(),
        ),
        SessionView::Interrupted { .. } => CheckResult::fail_with(
            "an interrupted activation left a next root or a session plan in /run".to_string(),
            "Run `nails recover` to remove them.".to_string(),
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
        let text = nextroot::read_in_root(&self.root, Path::new("/etc/fstab")).unwrap_or_default();
        let entries = parse_fstab(&String::from_utf8_lossy(&text));
        let decisions = policy::decide_all(
            &entries,
            &read_mountinfo().unwrap_or_default(),
            &self.hidden_root,
        );
        Ok(judge_fstab(&decisions))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nails_teardown::mountinfo::parse_mountinfo;

    #[test]
    fn old_systemd_is_refused_naming_the_unsupported_releases() {
        assert!(judge_version(Some(254)).is_pass());
        assert!(judge_version(Some(259)).is_pass());
        let old = judge_version(Some(252));
        assert!(old.is_fail());
        assert!(old.message().contains("252"));
        assert!(old.remediation().unwrap().contains("bookworm"));
        assert!(old.remediation().unwrap().contains("22.04"));
        assert!(judge_version(None).is_fail());
    }

    #[test]
    fn missing_units_on_nixos_come_with_the_module_snippet() {
        let root = tempfile::tempdir().unwrap();
        let result = judge_units(root.path(), true);
        assert!(result.is_fail());
        assert!(
            result
                .remediation()
                .unwrap()
                .contains("SuccessAction=soft-reboot-force")
        );
        assert!(
            !judge_units(root.path(), false)
                .remediation()
                .unwrap()
                .contains("nixpkgs")
        );
    }

    #[test]
    fn an_impermanent_root_is_refused() {
        let ram = parse_mountinfo("1 0 0:20 / / rw - tmpfs none rw\n");
        assert!(judge_decoy_root(&ram, Path::new("/")).is_fail());
        let disk = parse_mountinfo("1 0 8:2 / / rw - ext4 /dev/vda2 rw\n");
        assert!(judge_decoy_root(&disk, Path::new("/")).is_pass());
    }

    #[test]
    fn only_the_plain_decoy_may_activate() {
        assert!(judge_session(&SessionView::Decoy).is_pass());
        assert!(judge_session(&SessionView::HiddenWithoutPlan("x".into())).is_fail());
        let interrupted = judge_session(&SessionView::Interrupted {
            plan: None,
            nextroot_mounted: true,
        });
        assert!(interrupted.remediation().unwrap().contains("nails recover"));
    }

    #[test]
    fn masked_filesystems_warn_and_a_refusal_fails() {
        let mounts = parse_mountinfo(
            "1 0 8:2 / / rw - ext4 /dev/vda2 rw\n2 1 8:1 / /boot rw - vfat /dev/vda1 rw\n",
        );
        let decide =
            |text: &str| policy::decide_all(&parse_fstab(text), &mounts, Path::new("/mnt/data"));
        let boot = judge_fstab(&decide(
            "/dev/vda1 /boot vfat defaults 0 2\n/dev/vda3 none swap sw 0 0\n",
        ));
        assert!(boot.is_pass(), "{boot:?}");
        assert!(boot.message().contains("/boot: read-only"));
        assert!(judge_fstab(&decide("/dev/sdb1 /data ext4 defaults 0 2\n")).is_warn());
        assert!(judge_fstab(&decide("/dev/sdb1 data ext4 defaults 0 2\n")).is_fail());
    }
}
