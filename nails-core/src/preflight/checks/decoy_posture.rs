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
//!   the unit `syslog.service` names, or a process, and an enabled `auditd`
//!   that does not run now, which the decoy starts again after the way back
//!   unless its unit is masked or its kernel command line condition fails
//!   (see [`loggers`]),
//! - tuned or tuned-ppd started with a log file (`-l`, which Fedora's units
//!   pass, or `-d`): they log to `/var/log/tuned` on the decoy disk when they
//!   stop or start around a switch, with the time (see [`services`]),
//! - an armed kdump (Ubuntu arms kdump-tools by default from 24.10): a crash
//!   kernel loaded according to `/sys/kernel/kexec_crash_loaded`, or an enabled
//!   or active `kdump-tools.service` or `kdump.service` (an enabled one starts
//!   again in the hidden session and loads the crash kernel there, even when it
//!   is stopped at activation). A kernel crash during the hidden
//!   session boots kdump's crash kernel, which mounts the decoy root by its
//!   device, outside the session's overlay, and writes a dump of kernel memory
//!   and the session's kernel log to `/var/crash` on the decoy disk. When
//!   `kexec_crash_loaded` exists but cannot be read, or holds anything but `0`
//!   or `1`, the check cannot tell and refuses as if kdump were armed. A kernel
//!   without the file has no crash kernel support, so nothing is loaded,
//! - unattended-upgrades' shutdown helper running with
//!   `Unattended-Upgrade::InstallOnShutdown` on: a switch through logind is a
//!   shutdown to it, so at activation it installs the pending updates on the
//!   decoy disk and logs that run there. An apt configuration NAILS cannot
//!   read or does not follow, and one that changed since the helper started
//!   while no file sets the setting, as the helper keeps what it read then,
//!   leave the setting unknown, which is refused as if it were on. A file apt
//!   refuses is refused too: the helper then installs nothing, but writes two
//!   ERROR lines at the switch, which the refusal says (see
//!   [`install_on_shutdown`]).
//!
//! Warn (surface the hazard, never block):
//! - an atime policy that records read access on the decoy (`strictatime` /
//!   missing `noatime`),
//! - crash-dump channels that persist memory to the decoy disk: a disk
//!   `kernel.core_pattern`, one that hands core dumps to a program other than
//!   systemd-coredump (Ubuntu's apport, for one), a systemd-coredump (reached
//!   by its pipe or its kernel coredump socket) that is not set to
//!   `Storage=none` with `ProcessSizeMax=0` (see [`coredump`]), a unit that
//!   systemd-coredump starts for each crash (apport's hook, for one), an
//!   enabled `apport.service` while the pattern does not name apport, a
//!   pattern that a `sysctl.d` file sets again when the decoy starts after
//!   the way back, where it differs from the one in force (see [`sysctl`]),
//!   or registered pstore records,
//! - firewalld logging to a file, which its default log target does with its
//!   warnings and errors, and ABRT in use, which keeps crash reports in
//!   `/var/spool/abrt` (see [`services`]),
//! - the NixOS `nixos-upgrade.timer` (which can rebuild and touch EFI NVRAM
//!   from the decoy profile while the hidden session runs),
//! - sudo logging in sudoers (`logfile=`, I/O logging with `log_input`,
//!   `log_output` and friends, `iolog_dir=`), which records the activation
//!   command or whole terminal sessions on the decoy disk (see
//!   [`sudo_logging`]),
//! - sssd in use on the decoy, the service through which a decoy joins a
//!   domain: NAILS is not tested on a decoy joined to a domain, whose domain
//!   controller records the hidden session's logins out of NAILS's reach (see
//!   [`sssd`]),
//! - unattended-upgrades in the hidden session alone installing at the way
//!   back: the decoy's helper stopped while the decoy or the session's
//!   overlay enables it and nothing masks it as the session sees it, so the
//!   session starts its own copy, or the session's overlay turning the
//!   setting on. At the way back that copy installs the pending updates into
//!   the session's overlay. Where NAILS cannot tell what the session reads,
//!   as for a link among apt's files, it warns too (see
//!   [`install_on_shutdown`]),
//! - unattended-upgrades' shutdown helper enabled on the decoy without
//!   python3-gi: it then writes two WARNING lines to its log on the decoy
//!   disk each time it starts, so every way back adds a pair dated at the
//!   switch.
//!
//! # What it cannot tell
//!
//! Every probe reads the decoy through the automount guard
//! ([`crate::filesystem::automount`]): a lookup that would mount an
//! automount point that nothing is mounted on yet is not made. A blocker
//! NAILS cannot tell about, because a lookup failed or was not made, counts
//! as one the decoy has, and is refused with the same override; a warning it
//! cannot tell about warns. Without a readable mount table nothing is looked
//! up, and the check refuses as for a blocker.
//!
//! # No writes
//!
//! Every probe reads the filesystem; nothing here creates, rotates or vacuums
//! anything. Destroying the decoy's own log history would itself be a
//! deniability tell, and a pre-flight check must never mutate the system. A unit
//! test asserts the mock records no write operation after a run.

use super::super::{CheckResult, PreFlightCheck};
use super::journald_storage::journald_persistence_at;
use super::locate_database::files::DecoyFiles;
use super::locate_database::hidden_locations;
use crate::filesystem::automount::{Guarded, OnSkip, Snapshot, describe, settle, unnamed};
use crate::filesystem::parse_mountinfo;
use crate::{Filesystem, NailsError, Result};
use loggers::Auditd;
use nails_api::Allowable;
use std::path::{Path, PathBuf};

mod coredump;
mod install_on_shutdown;
mod loggers;
mod services;
mod sssd;
mod sudo_logging;
mod sysctl;
// The locate-database check reads the decoy's units the same way.
pub(in crate::preflight::checks) use loggers::{Activity, unit_active};
pub use sudo_logging::{SudoLogging, scan_sudoers};

/// `/proc/self/mountinfo`, the authoritative mount table.
const MOUNTINFO: &str = "/proc/self/mountinfo";
/// Kernel core-dump pattern.
const CORE_PATTERN: &str = "/proc/sys/kernel/core_pattern";
/// Persistent crash-record store exposed by the pstore filesystem.
const PSTORE_DIR: &str = "/sys/fs/pstore";
/// `1` here means a crash kernel is loaded and kdump will write a dump on panic;
/// a kernel without kexec crash support has no such file.
const KEXEC_CRASH_LOADED: &str = "/sys/kernel/kexec_crash_loaded";
/// Enabled-timer marker for the NixOS automatic-upgrade timer.
const NIXOS_UPGRADE_TIMER: &str = "/etc/systemd/system/timers.target.wants/nixos-upgrade.timer";
/// The kdump units: kdump-tools on Debian and Ubuntu, kdump on Fedora and
/// others.
const KDUMP_UNITS: &[&str] = &["kdump-tools.service", "kdump.service"];
/// The suffixes of the dependency directories `systemctl enable` links a unit
/// into, from its `WantedBy=`, `RequiredBy=` and `UpheldBy=`: a link to it in
/// `<target>.wants/` pulls it in wherever `<target>` starts.
const DEPENDENCY_DIR_SUFFIXES: &[&str] = &[".wants", ".requires", ".upholds"];
/// The unit directory whose `/dev/null` link masks a unit above every other.
const ADMIN_UNIT_DIR: &str = "etc/systemd/system";

/// One way the decoy keeps a record of the hidden session on its disk, or may
/// keep one where NAILS cannot tell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistenceFinding {
    /// What keeps the record, or why NAILS cannot tell, with what to do about
    /// it.
    pub sentence: String,
    /// Why NAILS cannot tell whether the decoy keeps the record, when it
    /// cannot: a path it could not look up or read, which counts as one that
    /// keeps it.
    pub untold: Option<String>,
}

impl PersistenceFinding {
    /// A record the decoy keeps.
    fn kept(sentence: impl Into<String>) -> Self {
        Self {
            sentence: sentence.into(),
            untold: None,
        }
    }

    /// A record NAILS cannot tell about, for `reason`, which says it all.
    fn untold(reason: impl Into<String>) -> Self {
        let reason = reason.into();
        Self {
            sentence: reason.clone(),
            untold: Some(reason),
        }
    }

    /// A record NAILS cannot tell about, for `reason`, said as `sentence`.
    fn untold_as(sentence: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            sentence: sentence.into(),
            untold: Some(reason.into()),
        }
    }
}

/// Why nothing on the decoy is looked up without its mount table.
fn no_mount_table(error: &str) -> String {
    format!(
        "NAILS cannot read the mount table ({error}), which shows where a lookup would mount an \
         automount point, so it looks up nothing"
    )
}

/// The findings of a probe of the decoy, read through `view`, with one for
/// each lookup the guard did not make that they do not name: such a path
/// may hold a record too.
fn with_unnamed<F: Filesystem>(
    mut findings: Vec<PersistenceFinding>,
    view: &Guarded<F>,
) -> Vec<PersistenceFinding> {
    let named: String = findings
        .iter()
        .map(|finding| finding.sentence.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    findings.extend(
        unnamed(&named, &view.skipped())
            .into_iter()
            .map(PersistenceFinding::untold),
    );
    findings
}

/// What an activation would make unattended-upgrades' shutdown helper on
/// the decoy do, by the cause for which the check refuses it
/// ([`DecoyPersistenceCheck::decoy_install_at_shutdown`]), as `status` shows
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallAtShutdown {
    /// `Unattended-Upgrade::InstallOnShutdown` is on: the helper installs
    /// the pending updates on the decoy disk.
    On,
    /// apt refuses a file of its configuration: the helper installs nothing,
    /// but writes two ERROR lines, on the decoy disk unless it started with
    /// the file already refused.
    RefusedFile,
    /// NAILS cannot tell that the helper does not install.
    Unknown,
    /// NAILS cannot tell without root: only root may read the helper's
    /// environment, where apt takes `APT_CONFIG` from.
    UnknownWithoutRoot,
}

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
    /// The root overlay's upper on the hidden volume, through which hidden
    /// sessions see the decoy: what unattended-upgrades does at the way back
    /// is read through it.
    upper: Option<PathBuf>,
    /// The hidden root as configured: no read of the decoy's units follows a
    /// link onto the volume mounted there.
    hidden_root: Option<PathBuf>,
}

impl DecoyPersistenceCheck {
    /// Create the check. `allow_persistent_decoy` mirrors the override;
    /// `is_nixos` enables the NixOS maintenance-timer sub-check.
    pub fn new(allow_persistent_decoy: bool, is_nixos: bool) -> Self {
        Self {
            allow_persistent_decoy,
            is_nixos,
            root: PathBuf::from("/"),
            upper: None,
            hidden_root: None,
        }
    }

    /// The check that reads what hidden sessions see through the root
    /// overlay's `upper` too.
    pub fn with_upper(mut self, upper: PathBuf) -> Self {
        self.upper = Some(upper);
        self
    }

    /// The check whose reads of the decoy's units follow no link onto the
    /// hidden volume mounted at `hidden_root`.
    pub fn with_hidden_root(mut self, hidden_root: PathBuf) -> Self {
        self.hidden_root = Some(hidden_root);
        self
    }

    /// Where the hidden volume shows on the running system, resolved.
    fn hidden<F: Filesystem>(&self, fs: &F) -> Vec<PathBuf> {
        self.hidden_root
            .as_deref()
            .map(|hidden_root| {
                hidden_locations(fs, hidden_root)
                    .into_iter()
                    .map(|location| location.path)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Inspect the system tree rooted at `root` instead of `/` (tests).
    #[cfg(test)]
    fn with_root(mut self, root: &Path) -> Self {
        self.root = root.to_path_buf();
        self
    }

    /// The fail-closed log findings that status and the window's launcher
    /// count: the persistent log sinks on the decoy (journald, syslog, a
    /// running audit daemon), and each one NAILS cannot tell about. The
    /// pre-flight check counts an enabled audit daemon as well
    /// ([`loggers::auditd`]), and its other blockers are
    /// [`Self::kdump_finding`], tuned's ([`services::blockers`]) and
    /// unattended-upgrades'.
    fn log_blockers<F: Filesystem>(fs: &F, root: &Path) -> Vec<PersistenceFinding> {
        let mut out = Self::journal_syslog_blockers(fs, root);
        out.extend(loggers::active_auditd_finding(fs, root));
        out
    }

    /// The fail-closed findings of journald and the syslog daemons, and each
    /// one NAILS cannot tell about.
    fn journal_syslog_blockers<F: Filesystem>(fs: &F, root: &Path) -> Vec<PersistenceFinding> {
        let mut out = Vec::new();
        match journald_persistence_at(fs, root) {
            Ok(false) => {}
            Ok(true) => out.push(PersistenceFinding::kept(
                "systemd-journald keeps a persistent journal on the decoy disk \
                 (/var/log/journal); set Storage=volatile under [Journal] in \
                 /etc/systemd/journald.conf or in a drop-in such as \
                 /etc/systemd/journald.conf.d/50-volatile.conf (drop-ins override \
                 the main file)",
            )),
            Err(unread) => out.push(PersistenceFinding::untold_as(
                format!(
                    "NAILS cannot tell where systemd-journald keeps the journal, so it counts as \
                     persistent: {}",
                    unread.with_advice()
                ),
                unread.to_string(),
            )),
        }
        out.extend(loggers::active_syslog_blockers(fs, root));
        out
    }

    /// Read-only probe: whether the decoy keeps, or may keep, a persistent log
    /// or audit store that a hidden session's metadata would land on (a
    /// persistent journald journal, or an active syslog or audit daemon), as
    /// [`Self::persistence`] finds them.
    pub fn decoy_is_persistent<F: Filesystem>(fs: &F) -> bool {
        !Self::persistence(fs).is_empty()
    }

    /// Read-only probe: each way the decoy keeps a persistent log or audit
    /// store, one sentence with its fix each, or may keep one where NAILS
    /// cannot tell, or none on an amnesic decoy. It reads through the
    /// automount guard as the pre-flight check reads it: a path the guard did
    /// not look up, or one whose lookup failed, is one NAILS cannot tell
    /// about. Shared with `status` and the window's launcher, which refuses
    /// to open on a decoy with any and names them, so that both track the
    /// same detection as this pre-flight check.
    ///
    /// Independent of the operator override: the decoy is physically persistent
    /// whether or not the operator accepted the risk, so an accepted run still
    /// reports an honest posture. Performs no writes.
    pub fn persistence<F: Filesystem>(fs: &F) -> Vec<PersistenceFinding> {
        let root = Path::new("/");
        let snapshot = Snapshot::read(fs, root);
        if let Some(error) = snapshot.unreadable() {
            return vec![PersistenceFinding::untold(no_mount_table(error))];
        }
        let view = Guarded::new(fs.clone(), &snapshot);
        let findings = Self::log_blockers(&view, root);
        with_unnamed(findings, &view)
    }

    /// Read-only probe: whether kdump is armed on the decoy, or its state
    /// cannot be read (which the pre-flight check refuses as if armed), as
    /// [`Self::kdump_on_decoy`] reads it.
    pub fn decoy_kdump_armed<F: Filesystem>(fs: &F) -> bool {
        Self::kdump_on_decoy(fs).is_some()
    }

    /// Read-only probe: the kdump blocker of the decoy, read through the
    /// automount guard as the pre-flight check reads it, if kdump is armed or
    /// NAILS cannot tell. Shared with `status`. Independent of the operator
    /// override, and performs no writes.
    pub fn kdump_on_decoy<F: Filesystem>(fs: &F) -> Option<PersistenceFinding> {
        let root = Path::new("/");
        let snapshot = Snapshot::read(fs, root);
        if let Some(error) = snapshot.unreadable() {
            return Some(PersistenceFinding::untold(no_mount_table(error)));
        }
        let view = Guarded::new(fs.clone(), &snapshot);
        let finding = Self::kdump_finding(&view, root);
        with_unnamed(finding.into_iter().collect(), &view)
            .into_iter()
            .next()
    }

    /// Read-only probe: what an activation would make the decoy's
    /// unattended-upgrades do at its shutdown helper's signal, by the cause
    /// for which the pre-flight check refuses it, or `None` where it does
    /// not, read through the automount guard as the pre-flight check reads
    /// it: without the mount table, or where the guard did not make a lookup
    /// that decides the refusal, NAILS cannot tell. A lookup it did not make
    /// for what only warns, python3-gi's module or the hidden session's own
    /// copy, leaves the answer as the rest gives it, as it leaves the
    /// check's refusal. Shared with `status`. Independent of the operator
    /// override, and performs no writes.
    pub fn decoy_install_at_shutdown<F: Filesystem>(fs: &F) -> Option<InstallAtShutdown> {
        let root = Path::new("/");
        let snapshot = Snapshot::read(fs, root);
        if snapshot.unreadable().is_some() {
            return Some(InstallAtShutdown::Unknown);
        }
        let blocking = Guarded::new(fs.clone(), &snapshot);
        let warning = Guarded::new(fs.clone(), &snapshot);
        let found = Self::install_at_shutdown_on(&blocking, &warning, root);
        // A lookup the guard did not make there may hide a setting that is
        // on.
        if found.is_none() && !blocking.skipped().is_empty() {
            return Some(InstallAtShutdown::Unknown);
        }
        found
    }

    /// [`Self::decoy_install_at_shutdown`] of the system tree under `root`,
    /// read through the views of [`install_on_shutdown::finding`].
    fn install_at_shutdown_on<F: Filesystem>(
        blocking: &F,
        warning: &F,
        root: &Path,
    ) -> Option<InstallAtShutdown> {
        use install_on_shutdown::AtTheSwitch;
        let blocker = install_on_shutdown::finding(blocking, warning, root, None).blocker?;
        Some(match blocker.at_the_switch {
            AtTheSwitch::Installs => InstallAtShutdown::On,
            AtTheSwitch::ErrorLines => InstallAtShutdown::RefusedFile,
            AtTheSwitch::Unknown => InstallAtShutdown::Unknown,
            AtTheSwitch::NeedsRoot => InstallAtShutdown::UnknownWithoutRoot,
        })
    }

    /// The kdump blocker, if kdump is armed or its state cannot be told.
    ///
    /// A loaded crash kernel dumps memory to the decoy disk on panic. Ubuntu
    /// arms kdump-tools by default from 24.10 (so 26.04); Fedora and others
    /// ship it as kdump.service. A kdump unit counts when it is enabled
    /// ([`unit_enabled`]): the soft-reboot into the hidden session starts the
    /// decoy's enabled units, so one that is stopped at activation, with no
    /// crash kernel loaded, starts again there and loads it. An active unit
    /// counts too, as its marker does not tell whether it is still loading the
    /// crash kernel. The crash kernel boots from the decoy's root device, never
    /// through the session's overlay, so what it writes lands on the decoy
    /// disk past every barrier the session keeps.
    fn kdump_finding<F: Filesystem>(fs: &F, root: &Path) -> Option<PersistenceFinding> {
        // Read below `root` like the unit markers, so a test on a temporary
        // tree never sees the live host's crash kernel.
        let path = root.join(KEXEC_CRASH_LOADED.trim_start_matches('/'));
        let path = path.as_path();
        let unknown = |why: String| {
            let reason = format!("{KEXEC_CRASH_LOADED} {why}");
            Some(PersistenceFinding::untold_as(
                format!(
                    "cannot tell whether kdump is armed: {reason}, so it is refused as if a crash \
                     kernel were loaded"
                ),
                reason,
            ))
        };
        let loaded = match fs.path_exists(path) {
            // No kexec crash support in this kernel: no crash kernel can load.
            Ok(false) => false,
            Ok(true) => match fs.read_file_content(path) {
                Ok(value) => match value.trim() {
                    "0" => false,
                    "1" => true,
                    other => return unknown(format!("holds {other:?}, not 0 or 1")),
                },
                Err(e) => return unknown(format!("cannot be read ({e})")),
            },
            Err(e) => return unknown(format!("cannot be probed ({e})")),
        };
        let mut armed = Vec::new();
        let mut untold = Vec::new();
        if loaded {
            armed.push("a crash kernel is loaded".to_string());
        }
        for unit in KDUMP_UNITS {
            let enabled = match unit_enabled(fs, root, unit) {
                Enabled::Yes => true,
                Enabled::No => false,
                Enabled::Untold(why) => {
                    untold.push(why);
                    false
                }
            };
            let active = match loggers::unit_active(fs, root, unit) {
                loggers::Activity::Active => true,
                loggers::Activity::Inactive => false,
                loggers::Activity::Untold(why) => {
                    untold.push(why);
                    false
                }
            };
            let state = match (enabled, active) {
                (true, true) => "enabled and active",
                (true, false) => "enabled",
                (false, true) => "active",
                (false, false) => continue,
            };
            armed.push(format!("{unit} is {state}"));
        }
        if armed.is_empty() {
            // A unit NAILS cannot tell is enabled or runs may arm kdump.
            let reason = untold.join("; ");
            return (!untold.is_empty()).then(|| {
                PersistenceFinding::untold_as(
                    format!(
                        "cannot tell whether kdump is armed: {reason}, so it is refused as if \
                         kdump were armed. Disable kdump on the decoy (Ubuntu: systemctl \
                         disable --now kdump-tools; Fedora: systemctl disable --now kdump)"
                    ),
                    reason,
                )
            });
        }
        let what = armed.join(" and ");
        Some(PersistenceFinding::kept(format!(
            "kdump is armed ({what}): if the kernel crashes during the hidden session, its \
             crash kernel mounts the decoy root by its device, outside the session's overlay, \
             and writes a dump of kernel memory (which can hold the hidden volume's encryption \
             key and the names of the files the session used) and the session's kernel log to \
             /var/crash on the decoy disk. Disable kdump on the decoy (Ubuntu: systemctl \
             disable --now kdump-tools; Fedora: systemctl disable --now kdump)"
        )))
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
    /// sssd, timers); `hidden` are the hidden volume's locations, resolved,
    /// which no read of the decoy's units follows a link onto.
    fn warnings<F: Filesystem>(
        fs: &F,
        root: &Path,
        is_nixos: bool,
        hidden: &[PathBuf],
    ) -> Vec<String> {
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

        out.extend(Self::crash_posture(fs, root, is_nixos, hidden));
        out.extend(sudo_logging::decoy_sudo_findings(fs, root));
        out.extend(sssd::sssd_finding(fs, root, is_nixos));

        // A link to a timer that is not there enables nothing, so the timer
        // is looked up through the link.
        if is_nixos {
            match fs.path_exists(Path::new(NIXOS_UPGRADE_TIMER)) {
                Ok(false) => {}
                Ok(true) => out.push(
                    "nixos-upgrade.timer is enabled; an automatic decoy rebuild can run \
                     (and touch EFI NVRAM) while the hidden session is active"
                        .to_string(),
                ),
                Err(error) => out.push(format!(
                    "NAILS cannot tell whether nixos-upgrade.timer is enabled, which can rebuild \
                     the decoy (and touch EFI NVRAM) while the hidden session is active: {}",
                    describe(NIXOS_UPGRADE_TIMER, &error).sentence
                )),
            }
        }

        out
    }

    /// Crash-dump channels that can persist memory contents to the decoy disk.
    ///
    /// systemd-coredump's settings are read only when the kernel hands dumps to
    /// it, by its pipe or its kernel coredump socket (see [`coredump`]): a
    /// `coredump.conf` left behind while another helper or a plain pattern takes
    /// the dumps decides nothing. Another helper NAILS does not judge, so it
    /// warns, but for one that only discards the dumps, as `|/bin/false`;
    /// that, the kernel default, `core`, which writes into the crashing
    /// program's working directory, and an empty pattern pass. Nor does it
    /// judge a unit that systemd-coredump starts for each crash, as Ubuntu's
    /// apport adds one, so that warns too
    /// ([`services::coredump_hook_finding`]), and so does an enabled
    /// `apport.service` while the pattern does not name apport, as it sets
    /// its pipe again when the decoy starts after the way back
    /// ([`services::apport_finding`]). The pattern the decoy's `sysctl.d`
    /// files set, which systemd-sysctl applies again then, is judged as well
    /// where it differs from the one in force ([`sysctl`]).
    fn crash_posture<F: Filesystem>(
        fs: &F,
        root: &Path,
        is_nixos: bool,
        hidden: &[PathBuf],
    ) -> Vec<String> {
        let mut out = Vec::new();

        let live = fs.read_file_content(Path::new(CORE_PATTERN)).ok();
        let live = live.as_deref().map(str::trim);
        if !live.is_some_and(|pattern| pattern.contains("/apport")) {
            out.extend(services::apport_finding(fs, root, hidden));
        }
        if let Some(pattern) = live {
            out.extend(Self::pattern_findings(fs, root, is_nixos, hidden, pattern));
        }
        // What systemd-sysctl sets again when the decoy starts after the way
        // back, where it differs from the pattern in force now.
        match sysctl::core_pattern(&DecoyFiles::new(fs, root, hidden)) {
            Ok(Some((pattern, file))) if Some(pattern.as_str()) != live => {
                let both_coredump = coredump::pattern_targets_systemd_coredump(&pattern)
                    && live.is_some_and(coredump::pattern_targets_systemd_coredump);
                let found = Self::pattern_findings(fs, root, is_nixos, hidden, &pattern);
                if !both_coredump && !found.is_empty() {
                    out.push(format!(
                        "{file} sets kernel.core_pattern to {pattern} when the decoy starts again \
                         after the way back, though another pattern is in force now: {}",
                        found.join("; ")
                    ));
                }
            }
            Ok(_) => {}
            Err(why) => out.push(format!(
                "NAILS cannot tell which kernel.core_pattern the decoy's sysctl.d files set when \
                 it starts again after the way back ({why}), and such a pattern can put core \
                 dumps, or a record of each crash, on the decoy disk"
            )),
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

        out
    }

    /// The warnings of the crash-dump pattern `pattern`: systemd-coredump's
    /// settings and the units it starts for each crash when it takes the
    /// dumps, another handler, or a plain path, where the kernel writes the
    /// core straight to the decoy disk. A pipe to a program that only
    /// discards the dumps, as `|/bin/false`, warns of nothing.
    fn pattern_findings<F: Filesystem>(
        fs: &F,
        root: &Path,
        is_nixos: bool,
        hidden: &[PathBuf],
        pattern: &str,
    ) -> Vec<String> {
        let mut out = Vec::new();
        if coredump::pattern_discards(pattern) {
            // A program that only discards the dumps keeps nothing.
        } else if coredump::pattern_targets_systemd_coredump(pattern) {
            out.extend(coredump::CoredumpSettings::read(fs, root).finding(is_nixos));
            out.extend(services::coredump_hook_finding(fs, root, hidden));
        } else if let Some(finding) = coredump::foreign_handler_finding(pattern) {
            out.push(finding);
        } else if !pattern.is_empty() && pattern != "core" {
            out.push(format!(
                "kernel.core_pattern writes core dumps to the decoy disk ({pattern})"
            ));
        }
        out
    }
}

/// Whether a unit is enabled, as [`unit_enabled`] reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Enabled {
    /// A link enables it, and nothing masks it.
    Yes,
    /// Nothing enables it, or a mask outranks what does.
    No,
    /// NAILS cannot tell, for this reason, which names the unit and the path
    /// it could not look up.
    Untold(String),
}

/// Whether `unit` is enabled under `root`: a link to it sits in a dependency
/// directory ([`DEPENDENCY_DIR_SUFFIXES`]) of a unit directory, and
/// `/etc/systemd/system` does not mask it.
///
/// Only a link counts, as `systemctl enable` makes one. The unit directories
/// are the ones [`loggers::UNIT_DIRS`] names, the packages' ones among them,
/// where a package ships the links that pull a unit in without an
/// `enable`. A mask (`systemctl mask`) is a link to `/dev/null` in
/// `/etc/systemd/system`, which outranks every link to the unit. It is followed
/// only once an enabling link was found, so on a decoy without one no unit
/// link is followed. A place where a link may be whose lookup failed, or that
/// the automount guard did not look up, leaves NAILS unable to tell, unless
/// another link enables the unit; so does a mask it cannot look up.
fn unit_enabled<F: Filesystem>(fs: &F, root: &Path, unit: &str) -> Enabled {
    match unit_linked(fs, root, unit) {
        Ok(false) => Enabled::No,
        Err(why) => Enabled::Untold(why),
        Ok(true) => match masked(fs, root, unit) {
            Ok(true) => Enabled::No,
            Ok(false) => Enabled::Yes,
            Err(why) => Enabled::Untold(why),
        },
    }
}

/// Whether a link to `unit` sits in a dependency directory of a unit
/// directory under `root`, a mask aside (see [`unit_enabled`]).
///
/// # Errors
///
/// Why NAILS cannot tell, where no link was found and the lookup of a place
/// where one may be failed or was not made.
fn unit_linked<F: Filesystem>(
    fs: &F,
    root: &Path,
    unit: &str,
) -> std::result::Result<bool, String> {
    let mut untold = None;
    let linked = loggers::UNIT_DIRS.iter().any(|dir| {
        fs.list_directory(&root.join(dir)).is_ok_and(|entries| {
            entries.iter().any(|entry| {
                let dependency_dir = entry
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| {
                        DEPENDENCY_DIR_SUFFIXES
                            .iter()
                            .any(|suffix| name.ends_with(suffix))
                    });
                if !dependency_dir {
                    return false;
                }
                let link = entry.join(unit);
                match fs.is_symlink(&link) {
                    Ok(linked) => linked,
                    Err(error) => {
                        untold.get_or_insert_with(|| unseen_link(unit, &link, &error));
                        false
                    }
                }
            })
        })
    });
    match untold {
        Some(why) if !linked => Err(why),
        _ => Ok(linked),
    }
}

/// Why NAILS cannot tell whether `unit` is enabled, where the lookup of the
/// enabling link `link` of `unit` failed with `error` or was not made.
fn unseen_link(unit: &str, link: &Path, error: &NailsError) -> String {
    format!(
        "NAILS cannot tell whether {unit} is enabled: {}",
        describe(&link.display().to_string(), error).sentence
    )
}

/// Whether `/etc/systemd/system` under `root` masks `unit`: a link there that
/// resolves to `/dev/null`.
///
/// # Errors
///
/// Why NAILS cannot tell: the lookup of the link failed or was not made, so
/// the unit counts as enabled, which an enabling link makes it unless it is
/// masked.
fn masked<F: Filesystem>(fs: &F, root: &Path, unit: &str) -> std::result::Result<bool, String> {
    let unit_file = root.join(ADMIN_UNIT_DIR).join(unit);
    match fs.is_symlink(&unit_file) {
        Ok(true) => Ok(fs
            .canonicalize(&unit_file)
            .is_ok_and(|target| target == Path::new("/dev/null"))),
        Ok(false) => Ok(false),
        Err(error) => Err(format!(
            "{unit} is enabled unless {} masks it, which NAILS cannot tell: {}",
            unit_file.display(),
            describe(&unit_file.display().to_string(), &error).sentence
        )),
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
        // Without the table a lookup could mount an automount point, so none
        // is made, and the blockers cannot be ruled out.
        let snapshot = Snapshot::read(fs, &self.root);
        if let Some(error) = snapshot.unreadable() {
            let blockers = Blockers {
                logs: vec![PersistenceFinding::untold(no_mount_table(error))],
                ..Blockers::default()
            };
            return Ok(self.verdict(blockers, Vec::new()));
        }
        // The blockers and the warnings are read through views of their own,
        // so a lookup the guard did not make refuses for a blocker, which the
        // override lifts, and warns for a warning.
        let blocking = Guarded::new(fs.clone(), &snapshot);
        let warning = Guarded::new(fs.clone(), &snapshot);
        let hidden = self.hidden(&blocking);
        let tuned = services::blockers(&blocking, &self.root, &hidden);
        // unattended-upgrades' install at shutdown reads what decides its
        // refusal through the blockers' view, and what only warns,
        // python3-gi's module and the hidden session's own copy, through the
        // warnings' view.
        let upgrades =
            install_on_shutdown::finding(&blocking, &warning, &self.root, self.upper.as_deref());
        let blockers = Blockers {
            logs: Self::journal_syslog_blockers(&blocking, &self.root),
            auditd: loggers::auditd(&blocking, &self.root, &hidden),
            kdump: Self::kdump_finding(&blocking, &self.root),
            tuned: tuned.blockers,
            tuned_units: tuned.units,
            tuned_programs: tuned.programs,
            upgrade: upgrades.blocker,
        };
        let mut warnings = Self::warnings(&warning, &self.root, self.is_nixos, &hidden);
        warnings.extend(services::warnings(
            &warning,
            &self.root,
            &hidden,
            self.is_nixos,
        ));
        warnings.extend(upgrades.warning);
        warnings.extend(upgrades.polling);
        let result = self.verdict(blockers, warnings);
        let on_blocker = if self.allow_persistent_decoy {
            OnSkip::Warn
        } else {
            OnSkip::Refuse(Some(Allowable::PersistentDecoy))
        };
        let result = settle(result, &blocking.skipped(), on_blocker);
        Ok(settle(result, &warning.skipped(), OnSkip::Warn))
    }
}

impl DecoyPersistenceCheck {
    /// The result for the `blockers` found and the `warnings`.
    fn verdict(&self, blockers: Blockers, warnings: Vec<String>) -> CheckResult {
        if !blockers.is_empty() {
            if self.allow_persistent_decoy {
                return CheckResult::Warn(blockers.allowed(&warnings));
            }
            let found = blockers.findings();
            // A blocker NAILS cannot tell about counts, and the decoy may keep
            // the record.
            let keeps = if found.iter().any(|finding| finding.untold.is_some()) {
                "keeps, or may keep,"
            } else {
                "keeps"
            };
            return CheckResult::fail_with(
                format!(
                    "decoy {keeps} a persistent record of the hidden session: {}.",
                    sentences(&found)
                ),
                format!(
                    "{}, or pass --allow-persistent-decoy to allow the risk for this run. See \
                     docs/decoy-requirements.md.",
                    blockers.remediation(self.is_nixos)
                ),
            )
            .accepted_by(Allowable::PersistentDecoy);
        }

        if !warnings.is_empty() {
            return CheckResult::Warn(format!(
                "decoy posture warnings: {}. See docs/decoy-requirements.md.",
                warnings.join("; ")
            ));
        }

        CheckResult::Pass("decoy keeps no durable trace of the hidden session".into())
    }
}

/// The sentences of `findings`, joined.
fn sentences(findings: &[PersistenceFinding]) -> String {
    findings
        .iter()
        .map(|finding| finding.sentence.as_str())
        .collect::<Vec<_>>()
        .join("; ")
}

/// What makes the check refuse activation, by kind.
#[derive(Default)]
struct Blockers {
    /// journald's and the syslog daemons' findings, and the one of a mount
    /// table NAILS cannot read.
    logs: Vec<PersistenceFinding>,
    /// What the audit daemon does, when it writes to the decoy disk or NAILS
    /// cannot tell.
    auditd: Option<Auditd>,
    /// kdump's finding.
    kdump: Option<PersistenceFinding>,
    /// tuned's and tuned-ppd's findings.
    tuned: Vec<PersistenceFinding>,
    /// The units of those findings, which their fix names.
    tuned_units: Vec<&'static str>,
    /// The programs of those findings that only a process shows.
    tuned_programs: Vec<&'static str>,
    /// unattended-upgrades' finding.
    upgrade: Option<install_on_shutdown::Blocker>,
}

impl Blockers {
    fn is_empty(&self) -> bool {
        self.logs.is_empty()
            && self.auditd.is_none()
            && self.kdump.is_none()
            && self.tuned.is_empty()
            && self.upgrade.is_none()
    }

    /// Every finding, in order: one that NAILS cannot tell about is one the
    /// decoy may keep.
    fn findings(&self) -> Vec<PersistenceFinding> {
        use install_on_shutdown::AtTheSwitch;
        let upgrade = self
            .upgrade
            .as_ref()
            .map(|blocker| match blocker.at_the_switch {
                AtTheSwitch::Installs | AtTheSwitch::ErrorLines => {
                    PersistenceFinding::kept(blocker.finding.clone())
                }
                AtTheSwitch::Unknown | AtTheSwitch::NeedsRoot => {
                    PersistenceFinding::untold(blocker.finding.clone())
                }
            });
        self.logs
            .iter()
            .cloned()
            .chain(self.auditd.as_ref().map(Auditd::finding))
            .chain(self.kdump.clone())
            .chain(self.tuned.iter().cloned())
            .chain(upgrade)
            .collect()
    }

    /// The warning of a run that `--allow-persistent-decoy` lets go on,
    /// with what the override lets happen, said only where NAILS can tell,
    /// and the check's `warnings`.
    fn allowed(&self, warnings: &[String]) -> String {
        use install_on_shutdown::AtTheSwitch;
        let mut msg = format!(
            "persistent decoy posture allowed via --allow-persistent-decoy: {}.",
            sentences(&self.findings())
        );
        let before_mount = matches!(self.auditd, Some(Auditd::Active | Auditd::MayRun(_)));
        if !self.logs.is_empty() || before_mount {
            msg.push_str(
                " Records written before the overlays are mounted may survive on the decoy disk.",
            );
        }
        match &self.auditd {
            Some(Auditd::Enabled) => msg.push_str(
                " When the decoy starts after the way back, auditd starts with it and writes \
                 audit records to /var/log/audit on the decoy disk.",
            ),
            Some(Auditd::MayStart(_) | Auditd::MayBeEnabled(_) | Auditd::MayRun(_)) => msg
                .push_str(
                    " When the decoy starts after the way back, auditd may start with it and write \
                 audit records to /var/log/audit on the decoy disk.",
                ),
            Some(Auditd::Active) | None => {}
        }
        if self.kdump.is_some() {
            msg.push_str(
                " A kernel crash during the session can leave a dump of its memory in /var/crash \
                 on the decoy disk.",
            );
        }
        if self.tuned.iter().any(|finding| finding.untold.is_none()) {
            msg.push_str(
                " What tuned or tuned-ppd logs around a switch stays on the decoy disk, with the \
                 time.",
            );
        } else if !self.tuned.is_empty() {
            msg.push_str(
                " What tuned or tuned-ppd logs around a switch may stay on the decoy disk, with \
                 the time.",
            );
        }
        match self.upgrade.as_ref().map(|blocker| blocker.at_the_switch) {
            Some(AtTheSwitch::Installs) => msg.push_str(
                " At the switch unattended-upgrades installs the pending updates on the decoy \
                 disk and logs that run there.",
            ),
            Some(AtTheSwitch::ErrorLines) => {
                msg.push(' ');
                msg.push_str(install_on_shutdown::ERROR_LINES);
            }
            Some(AtTheSwitch::Unknown | AtTheSwitch::NeedsRoot) | None => {}
        }
        if !warnings.is_empty() {
            msg.push_str(&format!(" Also: {}.", warnings.join("; ")));
        }
        msg
    }

    /// The fix of every finding, for a NixOS decoy when `is_nixos`, as a
    /// sentence that starts with a capital.
    fn remediation(&self, is_nixos: bool) -> String {
        let mut fixes = Vec::new();
        if !self.logs.is_empty() {
            fixes.push(
                "make the decoy amnesic (Storage=volatile for journald, set in journald.conf or \
                 a journald.conf.d/*.conf drop-in; no active syslog daemon, such as rsyslog, \
                 syslog-ng or a syslogd)"
                    .to_string(),
            );
        }
        if self.auditd.is_some() {
            fixes.push(auditd_fix(is_nixos).to_string());
        }
        if self.kdump.is_some() {
            fixes.push(
                "disarm kdump on the decoy (Ubuntu: systemctl disable --now kdump-tools; Fedora: \
                 systemctl disable --now kdump)"
                    .to_string(),
            );
        }
        if !self.tuned.is_empty() {
            fixes.push(services::tuned_fix(
                &self.tuned_units,
                &self.tuned_programs,
                is_nixos,
            ));
        }
        fixes.extend(self.upgrade.as_ref().map(|blocker| blocker.fix.clone()));
        let mut remediation = fixes.join(", and ");
        if let Some(first) = remediation.get_mut(..1) {
            first.make_ascii_uppercase();
        }
        remediation
    }
}

/// How to turn auditd off for good without a reboot, on a NixOS decoy when
/// `is_nixos`. A plain `systemctl stop` would not do: the unit refuses a
/// manual stop on Fedora and Arch, as upstream ships it, and `disable --now`
/// stops it as `systemctl stop` does. (`mask --now` does stop it, since the
/// reload after the mask leaves a masked unit that refuses nothing.)
/// `auditctl --signal stop` asks the daemon itself to stop, on every family.
fn auditd_fix(is_nixos: bool) -> &'static str {
    if is_nixos {
        "turn auditd off for good (set security.auditd.enable = false in the decoy \
         configuration, stop the running daemon with auditctl --signal stop, then run \
         nixos-rebuild switch)"
    } else {
        "turn auditd off for good, without a reboot (systemctl disable auditd.service and \
         systemctl mask auditd.service, then auditctl --signal stop, which has the daemon stop \
         itself: on Fedora and Arch its unit refuses a plain systemctl stop)"
    }
}

#[cfg(test)]
mod lookup_tests;
#[cfg(test)]
mod tests;
