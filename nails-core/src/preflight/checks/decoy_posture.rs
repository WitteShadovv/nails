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
//! Fail-closed (refuse activation unless the operator opts in for this run with
//! `--allow-persistent-decoy`):
//! - systemd-journald `Storage=` persisting the journal to `/var/log/journal`
//!   on the decoy disk (see [`super::journald_storage`]),
//! - an active syslog or audit daemon (`rsyslog`, `syslog-ng`, a `syslogd`,
//!   `metalog`, `socklog`, `auditd`), each of which writes to the decoy disk
//!   before the overlays are mounted, detected as a unit, a template instance,
//!   the unit `syslog.service` names, or a process (see [`loggers`]).
//!
//! Warn (surface the hazard, never block):
//! - an atime policy that records read access on the decoy (`strictatime` /
//!   missing `noatime`),
//! - crash-dump channels that persist memory to the decoy disk: a disk
//!   `kernel.core_pattern`, a systemd-coredump (reached by its pipe or its
//!   kernel coredump socket) that is not set to `Storage=none` with
//!   `ProcessSizeMax=0` (see [`coredump`]), registered pstore records, or an
//!   armed kdump (Ubuntu arms kdump-tools by default from 24.10). A kernel
//!   crash during the hidden session boots kdump's crash kernel, which mounts
//!   the decoy root by its device, outside the session's overlay, and writes a
//!   dump of kernel memory and the session's kernel log to `/var/crash` on the
//!   decoy disk; it stays a warning, like the other crash channels,
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
use crate::filesystem::parse_mountinfo;
use crate::{Filesystem, Result};
use std::path::{Path, PathBuf};

mod coredump;
mod loggers;
mod sudo_logging;
pub use sudo_logging::{SudoLogging, scan_sudoers};

/// `/proc/self/mountinfo`, the authoritative mount table.
const MOUNTINFO: &str = "/proc/self/mountinfo";
/// Kernel core-dump pattern.
const CORE_PATTERN: &str = "/proc/sys/kernel/core_pattern";
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
    /// failure. Wired from the per-run `--allow-persistent-decoy` flag.
    allow_persistent_decoy: bool,
    /// Whether the host carries a NixOS config layer. Gates the NixOS-only
    /// `nixos-upgrade.timer` sub-check.
    is_nixos: bool,
    /// Root of the system tree whose configuration is inspected; `/` outside
    /// tests.
    root: PathBuf,
}

impl DecoyPersistenceCheck {
    /// Create the check. `allow_persistent_decoy` mirrors the override;
    /// `is_nixos` enables the NixOS maintenance-timer sub-check.
    pub fn new(allow_persistent_decoy: bool, is_nixos: bool) -> Self {
        Self {
            allow_persistent_decoy,
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
        out.extend(loggers::active_logger_blockers(fs, root));
        out
    }

    /// Read-only probe: whether the decoy keeps a persistent log or audit store
    /// that a hidden session's metadata would land on (a persistent journald
    /// journal, or an active syslog or audit daemon). Shared with
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

        out.extend(Self::crash_posture(fs, root, is_nixos));
        out.extend(sudo_logging::decoy_sudo_findings(fs, root));

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
    ///
    /// systemd-coredump's settings are read only when the kernel hands dumps to
    /// it, by its pipe or its kernel coredump socket (see [`coredump`]): a
    /// `coredump.conf` left behind while another helper or a plain pattern takes
    /// the dumps decides nothing.
    fn crash_posture<F: Filesystem>(fs: &F, root: &Path, is_nixos: bool) -> Vec<String> {
        let mut out = Vec::new();

        if let Ok(pattern) = fs.read_file_content(Path::new(CORE_PATTERN)) {
            let pattern = pattern.trim();
            if coredump::pattern_targets_systemd_coredump(pattern) {
                out.extend(coredump::CoredumpSettings::read(fs, root).finding(is_nixos));
            } else if !pattern.is_empty()
                && pattern != "core"
                && !pattern.starts_with('|')
                && !pattern.starts_with('@')
            {
                // A plain path (not a pipe or a socket to another handler): the
                // kernel writes the core straight to the decoy disk.
                out.push(format!(
                    "kernel.core_pattern writes core dumps to the decoy disk ({pattern})"
                ));
            }
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

        // kdump: a loaded crash kernel dumps memory to the decoy disk on panic.
        // Ubuntu arms kdump-tools by default from 24.10 (so 26.04); Fedora and
        // others ship it as kdump.service. Catch the loaded crash kernel and the
        // enabled service alike. The crash kernel boots from the decoy's root
        // device, never through the session's overlay, so what it writes lands
        // on the decoy disk past every barrier the session keeps.
        let kdump_loaded = fs
            .read_file_content(Path::new(KEXEC_CRASH_LOADED))
            .map(|v| v.trim() == "1")
            .unwrap_or(false);
        if kdump_loaded
            || loggers::unit_active(fs, root, "kdump-tools.service")
            || loggers::unit_active(fs, root, "kdump.service")
        {
            out.push(
                "kdump is armed: if the kernel crashes during the hidden session, its crash \
                 kernel mounts the decoy root by its device, outside the session's overlay, and \
                 writes a dump of kernel memory (which can hold the hidden volume's encryption \
                 key and the names of the files the session used) and the session's kernel log \
                 to /var/crash on the decoy disk. Disable kdump on the decoy (Ubuntu: \
                 kdump-tools; Fedora: kdump)"
                    .to_string(),
            );
        }

        out
    }
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
            if self.allow_persistent_decoy {
                let mut msg = format!(
                    "persistent decoy posture allowed via --allow-persistent-decoy: {findings}. \
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
                 or a journald.conf.d/*.conf drop-in; no active syslog or audit daemon, such \
                 as rsyslog, syslog-ng, a syslogd or auditd), or pass --allow-persistent-decoy \
                 to allow the risk for this run. See docs/decoy-requirements.md.",
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
