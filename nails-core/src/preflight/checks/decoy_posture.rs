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
//!   the unit `syslog.service` names, or a process (see [`loggers`]),
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
//!   without the file has no crash kernel support, so nothing is loaded.
//!
//! Warn (surface the hazard, never block):
//! - an atime policy that records read access on the decoy (`strictatime` /
//!   missing `noatime`),
//! - crash-dump channels that persist memory to the decoy disk: a disk
//!   `kernel.core_pattern`, a systemd-coredump (reached by its pipe or its
//!   kernel coredump socket) that is not set to `Storage=none` with
//!   `ProcessSizeMax=0` (see [`coredump`]), or registered pstore records,
//! - the NixOS `nixos-upgrade.timer` (which can rebuild and touch EFI NVRAM
//!   from the decoy profile while the hidden session runs),
//! - sudo logging in sudoers (`logfile=`, I/O logging with `log_input`,
//!   `log_output` and friends, `iolog_dir=`), which records the activation
//!   command or whole terminal sessions on the decoy disk (see
//!   [`sudo_logging`]),
//! - sssd in use on the decoy, the service through which a decoy joins a
//!   domain: NAILS is not tested on a decoy joined to a domain, whose domain
//!   controller records the hidden session's logins out of NAILS's reach (see
//!   [`sssd`]).
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
use crate::filesystem::automount::{Guarded, OnSkip, Snapshot, describe, settle, unnamed};
use crate::filesystem::parse_mountinfo;
use crate::{Filesystem, NailsError, Result};
use nails_api::Allowable;
use std::path::{Path, PathBuf};

mod coredump;
mod loggers;
mod sssd;
mod sudo_logging;
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

    /// The fail-closed log findings: the persistent log sinks on the decoy
    /// (journald, syslog, audit), and each one NAILS cannot tell about. The
    /// other blocker is [`Self::kdump_finding`].
    fn log_blockers<F: Filesystem>(fs: &F, root: &Path) -> Vec<PersistenceFinding> {
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
        out.extend(loggers::active_logger_blockers(fs, root));
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
    /// sssd, timers).
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
    if !linked {
        return untold.map_or(Enabled::No, Enabled::Untold);
    }
    match masked(fs, root, unit) {
        Ok(true) => Enabled::No,
        Ok(false) => Enabled::Yes,
        Err(why) => Enabled::Untold(why),
    }
}

/// Why NAILS cannot tell whether kdump is enabled, where the lookup of the
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
            let unseen = PersistenceFinding::untold(no_mount_table(error));
            return Ok(self.verdict(vec![unseen], None, Vec::new()));
        }
        // The blockers and the warnings are read through views of their own,
        // so a lookup the guard did not make refuses for a blocker, which the
        // override lifts, and warns for a warning.
        let blocking = Guarded::new(fs.clone(), &snapshot);
        let warning = Guarded::new(fs.clone(), &snapshot);
        let log_blockers = Self::log_blockers(&blocking, &self.root);
        let kdump_blocker = Self::kdump_finding(&blocking, &self.root);
        let warnings = Self::warnings(&warning, &self.root, self.is_nixos);
        let result = self.verdict(log_blockers, kdump_blocker, warnings);
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
    /// The result for the blockers found, the log sinks and kdump, and the
    /// warnings.
    fn verdict(
        &self,
        log_blockers: Vec<PersistenceFinding>,
        kdump_blocker: Option<PersistenceFinding>,
        warnings: Vec<String>,
    ) -> CheckResult {
        let logs = !log_blockers.is_empty();
        let kdump = kdump_blocker.is_some();

        if logs || kdump {
            let blockers: Vec<PersistenceFinding> =
                log_blockers.into_iter().chain(kdump_blocker).collect();
            // A blocker NAILS cannot tell about counts, and the decoy may keep
            // the record.
            let keeps = if blockers.iter().any(|blocker| blocker.untold.is_some()) {
                "keeps, or may keep,"
            } else {
                "keeps"
            };
            let findings = blockers
                .iter()
                .map(|blocker| blocker.sentence.as_str())
                .collect::<Vec<_>>()
                .join("; ");
            if self.allow_persistent_decoy {
                let mut msg = format!(
                    "persistent decoy posture allowed via --allow-persistent-decoy: {findings}."
                );
                if logs {
                    msg.push_str(
                        " Records written before the overlays are mounted may survive on the \
                         decoy disk.",
                    );
                }
                if kdump {
                    msg.push_str(
                        " A kernel crash during the session can leave a dump of its memory in \
                         /var/crash on the decoy disk.",
                    );
                }
                if !warnings.is_empty() {
                    msg.push_str(&format!(" Also: {}.", warnings.join("; ")));
                }
                return CheckResult::Warn(msg);
            }
            let mut fixes = Vec::new();
            if logs {
                fixes.push(
                    "make the decoy amnesic (Storage=volatile for journald, set in journald.conf \
                     or a journald.conf.d/*.conf drop-in; no active syslog or audit daemon, such \
                     as rsyslog, syslog-ng, a syslogd or auditd)",
                );
            }
            if kdump {
                fixes.push(
                    "disarm kdump on the decoy (Ubuntu: systemctl disable --now kdump-tools; \
                     Fedora: systemctl disable --now kdump)",
                );
            }
            let mut remediation = fixes.join(", and ");
            if let Some(first) = remediation.get_mut(..1) {
                first.make_ascii_uppercase();
            }
            return CheckResult::fail_with(
                format!("decoy {keeps} a persistent record of the hidden session: {findings}."),
                format!(
                    "{remediation}, or pass --allow-persistent-decoy to allow the risk for this \
                     run. See docs/decoy-requirements.md."
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

#[cfg(test)]
mod lookup_tests;
#[cfg(test)]
mod tests;
