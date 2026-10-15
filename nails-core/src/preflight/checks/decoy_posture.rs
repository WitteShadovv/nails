// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Platform-aware decoy-persistence pre-flight check.
//!
//! The forensic guarantees silently depend on an *amnesic* decoy: a system that
//! keeps no durable record of the hidden session on the decoy disk. This check
//! inspects the decoy's logging and crash posture before any state is written
//! and fails activation closed when the decoy would retain traces.
//!
//! # What it inspects
//!
//! Fail-closed (refuse activation unless the operator opts in with
//! `--accept-persistent-decoy` or `accept_persistent_decoy = true`):
//! - systemd-journald `Storage=` persisting the journal to `/var/log/journal`
//!   on the decoy disk (see [`super::journald_storage`]),
//! - an active `rsyslog`, `syslog-ng` or `auditd`, each of which writes to the
//!   decoy disk before the overlays are mounted.
//!
//! Warn (surface the hazard, never block):
//! - an atime policy that records read access on the decoy (`strictatime` /
//!   missing `noatime`),
//! - crash-dump channels that persist memory to the decoy disk: a disk
//!   `kernel.core_pattern`, systemd-coredump `Storage=external`, registered
//!   pstore records, or an armed kdump,
//! - the NixOS `nixos-upgrade.timer` (which can rebuild and touch EFI NVRAM
//!   from the decoy profile while the hidden session runs),
//! - sudo logging in sudoers (`logfile=`, I/O logging with `log_input`,
//!   `log_output` and friends, `iolog_dir=`), which records the activation
//!   command or whole terminal sessions on the decoy disk (see
//!   [`sudo_logging`]).
//!
//! # No writes
//!
//! Every probe reads the filesystem; nothing here creates, rotates or vacuums
//! anything. Destroying the decoy's own log history would itself be a
//! deniability tell, and a pre-flight check must never mutate the system. A unit
//! test asserts the mock records no write operation after a run.

use super::super::{CheckResult, PreFlightCheck};
use super::journald_storage::journald_persists_to_decoy_at;
use super::systemd_conf;
use crate::filesystem::parse_mountinfo;
use crate::{Filesystem, Result};
use std::path::{Path, PathBuf};

mod sudo_logging;
pub use sudo_logging::{SudoLogging, scan_sudoers};

/// `/proc/self/mountinfo`, the authoritative mount table.
const MOUNTINFO: &str = "/proc/self/mountinfo";
/// Directory systemd populates with an `invocation:<unit>` marker per *active*
/// unit, relative to the root. Its presence is a write-free way to tell a
/// running unit from an installed-but-stopped one.
const INVOCATION_DIR: &str = "run/systemd/units";
/// Kernel core-dump pattern.
const CORE_PATTERN: &str = "/proc/sys/kernel/core_pattern";
/// systemd-coredump configuration name, resolved with its drop-ins.
const COREDUMP_CONF: &str = "coredump.conf";
/// Persistent crash-record store exposed by the pstore filesystem.
const PSTORE_DIR: &str = "/sys/fs/pstore";
/// `1` here means a crash kernel is loaded and kdump will write a dump on panic.
const KEXEC_CRASH_LOADED: &str = "/sys/kernel/kexec_crash_loaded";
/// Enabled-timer marker for the NixOS automatic-upgrade timer.
const NIXOS_UPGRADE_TIMER: &str = "/etc/systemd/system/timers.target.wants/nixos-upgrade.timer";

/// Pre-flight check that refuses a forensically persistent decoy.
#[derive(Debug)]
pub struct DecoyPersistenceCheck {
    /// When set, the fail-closed findings are reported as a warning instead of a
    /// failure. Wired from `--accept-persistent-decoy` or the config key.
    accept_persistent_decoy: bool,
    /// Whether the host carries a NixOS config layer. Gates the NixOS-only
    /// `nixos-upgrade.timer` sub-check.
    is_nixos: bool,
    /// Root of the system tree whose configuration is inspected; `/` outside
    /// tests.
    root: PathBuf,
}

impl DecoyPersistenceCheck {
    /// Create the check. `accept_persistent_decoy` mirrors the override;
    /// `is_nixos` enables the NixOS maintenance-timer sub-check.
    pub fn new(accept_persistent_decoy: bool, is_nixos: bool) -> Self {
        Self {
            accept_persistent_decoy,
            is_nixos,
            root: PathBuf::from("/"),
        }
    }

    /// Inspect the system tree rooted at `root` instead of `/` (tests).
    #[cfg(test)]
    fn with_root(mut self, root: &Path) -> Self {
        self.root = root.to_path_buf();
        self
    }

    /// Whether a systemd unit is active, inferred from its runtime invocation
    /// marker. A stopped-but-installed unit has no marker, so this does not fire
    /// on a package that ships a disabled service.
    ///
    /// Recent systemd no longer writes that marker for every unit, so a unit
    /// whose cgroup reports a live process (`populated 1` in its
    /// `cgroup.events` under `system.slice`) counts as active too.
    fn unit_active<F: Filesystem>(fs: &F, root: &Path, unit: &str) -> bool {
        let marker = root.join(INVOCATION_DIR).join(format!("invocation:{unit}"));
        if fs.path_exists(&marker).unwrap_or(false) {
            return true;
        }
        let events = root
            .join("sys/fs/cgroup/system.slice")
            .join(unit)
            .join("cgroup.events");
        fs.read_file_content(&events)
            .is_ok_and(|content| content.lines().any(|line| line == "populated 1"))
    }

    /// Collect the fail-closed findings (persistent log sinks on the decoy).
    fn blockers<F: Filesystem>(fs: &F, root: &Path) -> Vec<String> {
        let mut out = Vec::new();
        if journald_persists_to_decoy_at(fs, root) {
            out.push(
                "systemd-journald keeps a persistent journal on the decoy disk \
                 (/var/log/journal); set Storage=volatile under [Journal] in \
                 /etc/systemd/journald.conf or in a drop-in such as \
                 /etc/systemd/journald.conf.d/50-volatile.conf (drop-ins override \
                 the main file)"
                    .to_string(),
            );
        }
        if Self::unit_active(fs, root, "rsyslog.service") {
            out.push("rsyslog is active and writes logs to the decoy disk".to_string());
        } else if Self::unit_active(fs, root, "syslog.service") {
            // NixOS runs rsyslogd as syslog.service; elsewhere the name is the
            // conventional alias of whichever syslog daemon is installed.
            out.push(
                "a syslog daemon (syslog.service) is active and writes logs to the decoy disk"
                    .to_string(),
            );
        }
        if Self::unit_active(fs, root, "syslog-ng.service") {
            out.push("syslog-ng is active and writes logs to the decoy disk".to_string());
        }
        if Self::unit_active(fs, root, "auditd.service") {
            out.push("auditd is active and writes audit records to the decoy disk".to_string());
        }
        out
    }

    /// Read-only probe: whether the decoy keeps a persistent log or audit store
    /// that a hidden session's metadata would land on (a persistent journald
    /// journal, or an active `rsyslog`/`syslog-ng`/`auditd`). Shared with
    /// `status` so the reported posture tracks the same detection as this
    /// pre-flight check without duplicating the journald parsing.
    ///
    /// Independent of the operator override: the decoy is physically persistent
    /// whether or not the operator accepted the risk, so an accepted run still
    /// reports an honest posture. Performs no writes.
    pub fn decoy_is_persistent<F: Filesystem>(fs: &F) -> bool {
        !Self::blockers(fs, Path::new("/")).is_empty()
    }

    /// The `/` mount entry's options, if the mount table can be read.
    ///
    /// The root's filesystem type is not judged here: `decoy-root` accepts
    /// only a root on a block device, which is always on a disk, and names its
    /// type.
    fn root_mount_options<F: Filesystem>(fs: &F) -> Option<String> {
        let content = fs.read_file_content(Path::new(MOUNTINFO)).ok()?;
        parse_mountinfo(&content)
            .into_iter()
            .find(|e| e.mount_point == Path::new("/"))
            .map(|e| e.mount_opts)
    }

    /// Collect the warning-level findings (atime, crash channels, sudo logging,
    /// timers).
    fn warnings<F: Filesystem>(fs: &F, root: &Path, is_nixos: bool) -> Vec<String> {
        let mut out = Vec::new();

        if let Some(opts) = Self::root_mount_options(fs) {
            // relatime (the kernel default) and noatime do not record every
            // read; strictatime (or an explicit atime with neither flag) leaves
            // a read-access trail on the decoy.
            let has_noatime = opts.split(',').any(|o| o == "noatime");
            let has_relatime = opts.split(',').any(|o| o == "relatime");
            if !has_noatime && !has_relatime {
                out.push(
                    "root filesystem records access times (no noatime/relatime); \
                     reads leave an atime trail on the decoy"
                        .to_string(),
                );
            }
        }

        out.extend(Self::crash_posture(fs, root));
        out.extend(scan_sudoers(fs, Path::new(sudo_logging::SUDOERS)).findings());

        if is_nixos
            && fs
                .path_exists(Path::new(NIXOS_UPGRADE_TIMER))
                .unwrap_or(false)
        {
            out.push(
                "nixos-upgrade.timer is enabled; an automatic decoy rebuild can run \
                 (and touch EFI NVRAM) while the hidden session is active"
                    .to_string(),
            );
        }

        out
    }

    /// Crash-dump channels that can persist memory contents to the decoy disk.
    fn crash_posture<F: Filesystem>(fs: &F, root: &Path) -> Vec<String> {
        let mut out = Vec::new();

        if let Ok(pattern) = fs.read_file_content(Path::new(CORE_PATTERN)) {
            let pattern = pattern.trim();
            if pattern.starts_with("|") {
                if pattern.contains("systemd-coredump") {
                    out.push(
                        "core dumps are piped to systemd-coredump; check its Storage= \
                         setting (external persists to the decoy disk)"
                            .to_string(),
                    );
                }
            } else if !pattern.is_empty() && pattern != "core" {
                out.push(format!(
                    "kernel.core_pattern writes core dumps to the decoy disk ({pattern})"
                ));
            }
        }

        if coredump_storage_external(fs, root) {
            out.push(
                "systemd-coredump Storage=external persists core dumps to the decoy disk"
                    .to_string(),
            );
        }

        // A non-empty pstore means crash records are already persisted in
        // firmware/RAM-console storage that survives reboot.
        if fs
            .list_directory(Path::new(PSTORE_DIR))
            .map(|entries| !entries.is_empty())
            .unwrap_or(false)
        {
            out.push(
                "pstore holds persisted crash records (/sys/fs/pstore is not empty)".to_string(),
            );
        }

        if fs
            .read_file_content(Path::new(KEXEC_CRASH_LOADED))
            .map(|v| v.trim() == "1")
            .unwrap_or(false)
        {
            out.push(
                "kdump is armed; a kernel crash dumps memory to the configured target".to_string(),
            );
        }

        out
    }
}

/// Whether systemd-coredump's effective `Storage=` persists dumps to disk.
///
/// `coredump.conf` is resolved with its drop-ins (see [`systemd_conf`]). When
/// no coredump configuration exists at all, systemd-coredump is taken as not
/// installed and nothing is reported; otherwise the upstream default is
/// `external`, so an unset `Storage=` is treated as persistent. `none` and
/// `journal` do not write standalone dump files to the decoy disk. Values match
/// exactly; an invalid one is ignored and an empty one resets to the default.
fn coredump_storage_external<F: Filesystem>(fs: &F, root: &Path) -> bool {
    if !systemd_conf::config_present(fs, root, COREDUMP_CONF) {
        return false;
    }
    let assignments = systemd_conf::section_assignments(fs, root, COREDUMP_CONF, "Coredump");
    coredump_external_from(&assignments)
}

/// Fold `Storage=` assignments of `[Coredump]` into whether dumps go to disk.
fn coredump_external_from(assignments: &[systemd_conf::Assignment]) -> bool {
    let mut external = true; // upstream default
    for assignment in assignments.iter().filter(|a| a.key == "Storage") {
        match assignment.value.as_str() {
            "external" | "" => external = true,
            "none" | "journal" => external = false,
            _ => {}
        }
    }
    external
}

impl<F: Filesystem> PreFlightCheck<F> for DecoyPersistenceCheck {
    fn name(&self) -> &'static str {
        "decoy-persistence"
    }

    fn description(&self) -> &'static str {
        "Validates the decoy keeps no durable trace of the hidden session"
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        let blockers = Self::blockers(fs, &self.root);
        let warnings = Self::warnings(fs, &self.root, self.is_nixos);

        if !blockers.is_empty() {
            let findings = blockers.join("; ");
            if self.accept_persistent_decoy {
                let mut msg = format!(
                    "persistent decoy posture accepted via accept_persistent_decoy: {findings}. \
                     Records written before the overlays are mounted may survive on the decoy disk."
                );
                if !warnings.is_empty() {
                    msg.push_str(&format!(" Also: {}.", warnings.join("; ")));
                }
                return Ok(CheckResult::Warn(msg));
            }
            return Ok(CheckResult::fail_with(
                format!("decoy keeps a persistent record of the hidden session: {findings}."),
                "Make the decoy amnesic (Storage=volatile for journald, set in journald.conf \
                 or a journald.conf.d/*.conf drop-in; no rsyslog/syslog-ng/auditd), \
                 or pass --accept-persistent-decoy / set accept_persistent_decoy = true in \
                 nails.toml to accept the risk. See docs/decoy-requirements.md.",
            ));
        }

        if !warnings.is_empty() {
            return Ok(CheckResult::Warn(format!(
                "decoy posture warnings: {}. See docs/decoy-requirements.md.",
                warnings.join("; ")
            )));
        }

        Ok(CheckResult::Pass(
            "decoy keeps no durable trace of the hidden session".into(),
        ))
    }
}

#[cfg(test)]
mod tests;
