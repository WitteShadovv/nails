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
//! - the root filesystem type (the persistent decoy substrate),
//! - an atime policy that records read access on the decoy (`strictatime` /
//!   missing `noatime`),
//! - crash-dump channels that persist memory to the decoy disk: a disk
//!   `kernel.core_pattern`, systemd-coredump `Storage=external`, registered
//!   pstore records, or an armed kdump,
//! - the NixOS `nixos-upgrade.timer` (which can rebuild and touch EFI NVRAM
//!   from the decoy profile while the hidden session runs).
//!
//! # No writes
//!
//! Every probe reads the filesystem; nothing here creates, rotates or vacuums
//! anything. Destroying the decoy's own log history would itself be a
//! deniability tell, and a pre-flight check must never mutate the system. A unit
//! test asserts the mock records no write operation after a run.

use super::super::{CheckResult, PreFlightCheck};
use super::journald_storage::journald_persists_to_decoy;
use crate::filesystem::parse_mountinfo;
use crate::{Filesystem, Result};
use std::path::Path;

/// `/proc/self/mountinfo`, the authoritative mount table.
const MOUNTINFO: &str = "/proc/self/mountinfo";
/// Directory systemd populates with an `invocation:<unit>` marker per *active*
/// unit. Its presence is a write-free way to tell a running unit from an
/// installed-but-stopped one.
const INVOCATION_DIR: &str = "/run/systemd/units";
/// Kernel core-dump pattern.
const CORE_PATTERN: &str = "/proc/sys/kernel/core_pattern";
/// systemd-coredump configuration.
const COREDUMP_CONF: &str = "/etc/systemd/coredump.conf";
/// Persistent crash-record store exposed by the pstore filesystem.
const PSTORE_DIR: &str = "/sys/fs/pstore";
/// `1` here means a crash kernel is loaded and kdump will write a dump on panic.
const KEXEC_CRASH_LOADED: &str = "/sys/kernel/kexec_crash_loaded";
/// Enabled-timer marker for the NixOS automatic-upgrade timer.
const NIXOS_UPGRADE_TIMER: &str = "/etc/systemd/system/timers.target.wants/nixos-upgrade.timer";

/// Filesystem types that are volatile (RAM-backed) and therefore not a durable
/// decoy substrate.
const VOLATILE_FSTYPES: &[&str] = &["tmpfs", "ramfs", "overlay"];

/// Pre-flight check that refuses a forensically persistent decoy.
#[derive(Debug)]
pub struct DecoyPersistenceCheck {
    /// When set, the fail-closed findings are reported as a warning instead of a
    /// failure. Wired from `--accept-persistent-decoy` or the config key.
    accept_persistent_decoy: bool,
    /// Whether the host carries a NixOS config layer. Gates the NixOS-only
    /// `nixos-upgrade.timer` sub-check.
    is_nixos: bool,
}

impl DecoyPersistenceCheck {
    /// Create the check. `accept_persistent_decoy` mirrors the override;
    /// `is_nixos` enables the NixOS maintenance-timer sub-check.
    pub fn new(accept_persistent_decoy: bool, is_nixos: bool) -> Self {
        Self {
            accept_persistent_decoy,
            is_nixos,
        }
    }

    /// Whether a systemd unit is active, inferred from its runtime invocation
    /// marker. A stopped-but-installed unit has no marker, so this does not fire
    /// on a package that ships a disabled service.
    fn unit_active<F: Filesystem>(fs: &F, unit: &str) -> bool {
        let marker = format!("{INVOCATION_DIR}/invocation:{unit}");
        fs.path_exists(Path::new(&marker)).unwrap_or(false)
    }

    /// Collect the fail-closed findings (persistent log sinks on the decoy).
    fn blockers<F: Filesystem>(fs: &F) -> Vec<String> {
        let mut out = Vec::new();
        if journald_persists_to_decoy(fs) {
            out.push(
                "systemd-journald keeps a persistent journal on the decoy disk \
                 (/var/log/journal); set Storage=volatile in journald.conf"
                    .to_string(),
            );
        }
        if Self::unit_active(fs, "rsyslog.service") {
            out.push("rsyslog is active and writes logs to the decoy disk".to_string());
        }
        if Self::unit_active(fs, "syslog-ng.service") {
            out.push("syslog-ng is active and writes logs to the decoy disk".to_string());
        }
        if Self::unit_active(fs, "auditd.service") {
            out.push("auditd is active and writes audit records to the decoy disk".to_string());
        }
        out
    }

    /// The `/` mount entry's filesystem type and mount options, if the mount
    /// table can be read.
    fn root_mount<F: Filesystem>(fs: &F) -> Option<(String, String)> {
        let content = fs.read_file_content(Path::new(MOUNTINFO)).ok()?;
        parse_mountinfo(&content)
            .into_iter()
            .find(|e| e.mount_point == Path::new("/"))
            .map(|e| (e.fstype, e.mount_opts))
    }

    /// Collect the warning-level findings (root fs, atime, crash channels, timers).
    fn warnings<F: Filesystem>(fs: &F, is_nixos: bool) -> Vec<String> {
        let mut out = Vec::new();

        if let Some((fstype, opts)) = Self::root_mount(fs) {
            if !VOLATILE_FSTYPES.contains(&fstype.as_str()) {
                out.push(format!(
                    "root filesystem is persistent ({fstype}); the decoy's own \
                     records remain on disk outside the overlays"
                ));
            }
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

        out.extend(Self::crash_posture(fs));

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
    fn crash_posture<F: Filesystem>(fs: &F) -> Vec<String> {
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

        if let Ok(conf) = fs.read_file_content(Path::new(COREDUMP_CONF))
            && coredump_storage_external(&conf)
        {
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
/// The upstream default is `external`, so an unset `Storage=` is treated as
/// persistent. `none` and `journal` do not write standalone dump files to the
/// decoy disk. The last assignment wins, mirroring systemd drop-in semantics.
fn coredump_storage_external(conf: &str) -> bool {
    let mut external = true; // upstream default
    for raw in conf.lines() {
        let line = raw.trim();
        if line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if !key.trim().eq_ignore_ascii_case("Storage") {
            continue;
        }
        match value.trim().to_ascii_lowercase().as_str() {
            "external" => external = true,
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
        let blockers = Self::blockers(fs);
        let warnings = Self::warnings(fs, self.is_nixos);

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
                "Make the decoy amnesic (volatile journald, no rsyslog/syslog-ng/auditd), \
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
mod tests {
    use super::*;
    use crate::filesystem::{MockFilesystem, PathKind};

    /// Mark a systemd unit active by creating its runtime invocation marker.
    fn set_unit_active(fs: &MockFilesystem, unit: &str) {
        let marker = format!("{INVOCATION_DIR}/invocation:{unit}");
        fs.mock_set_path_exists(&marker, true);
    }

    /// A mountinfo with a single `/` entry of the given fstype and options.
    fn root_mountinfo(fstype: &str, opts: &str) -> String {
        format!("36 35 0:32 / / {opts} shared:1 - {fstype} /dev/sda1 rw\n")
    }

    #[test]
    fn clean_volatile_decoy_passes() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(
            "/etc/systemd/journald.conf",
            "[Journal]\nStorage=volatile\n",
        );
        fs.mock_add_file(MOUNTINFO, &root_mountinfo("tmpfs", "rw,noatime"));

        let check = DecoyPersistenceCheck::new(false, true);
        let result = check.run(&fs).unwrap();
        assert!(result.is_pass(), "clean decoy must pass: {result:?}");
    }

    #[test]
    fn persistent_journal_fails_closed() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(
            "/etc/systemd/journald.conf",
            "[Journal]\nStorage=persistent\n",
        );
        fs.mock_add_file(MOUNTINFO, &root_mountinfo("tmpfs", "rw,noatime"));

        let check = DecoyPersistenceCheck::new(false, true);
        let result = check.run(&fs).unwrap();
        assert!(result.is_fail(), "persistent journal must fail: {result:?}");
        assert!(result.remediation().is_some());
    }

    #[test]
    fn journald_auto_without_dir_passes() {
        let fs = MockFilesystem::new();
        fs.mock_add_file("/etc/systemd/journald.conf", "[Journal]\nStorage=auto\n");
        fs.mock_add_file(MOUNTINFO, &root_mountinfo("tmpfs", "rw,noatime"));

        let check = DecoyPersistenceCheck::new(false, true);
        assert!(check.run(&fs).unwrap().is_pass());
    }

    #[test]
    fn journald_auto_with_disk_dir_fails() {
        let fs = MockFilesystem::new();
        fs.mock_add_file("/etc/systemd/journald.conf", "[Journal]\nStorage=auto\n");
        fs.mock_set_path_type("/var/log/journal", PathKind::Dir);
        fs.mock_add_file(MOUNTINFO, &root_mountinfo("tmpfs", "rw,noatime"));

        let check = DecoyPersistenceCheck::new(false, true);
        assert!(check.run(&fs).unwrap().is_fail());
    }

    #[test]
    fn journald_auto_with_tmpfs_dir_passes() {
        let fs = MockFilesystem::new();
        fs.mock_add_file("/etc/systemd/journald.conf", "[Journal]\nStorage=auto\n");
        fs.mock_set_path_type("/var/log/journal", PathKind::Dir);
        fs.mock_set_filesystem_type(Path::new("/var/log/journal"), "tmpfs");
        fs.mock_add_file(MOUNTINFO, &root_mountinfo("tmpfs", "rw,noatime"));

        let check = DecoyPersistenceCheck::new(false, true);
        assert!(check.run(&fs).unwrap().is_pass());
    }

    #[test]
    fn active_rsyslog_fails_closed() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(
            "/etc/systemd/journald.conf",
            "[Journal]\nStorage=volatile\n",
        );
        fs.mock_add_file(MOUNTINFO, &root_mountinfo("tmpfs", "rw,noatime"));
        set_unit_active(&fs, "rsyslog.service");

        let check = DecoyPersistenceCheck::new(false, true);
        let result = check.run(&fs).unwrap();
        assert!(result.is_fail(), "active rsyslog must fail: {result:?}");
        assert!(result.message().contains("rsyslog"));
    }

    #[test]
    fn active_syslog_ng_fails_closed() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(
            "/etc/systemd/journald.conf",
            "[Journal]\nStorage=volatile\n",
        );
        fs.mock_add_file(MOUNTINFO, &root_mountinfo("tmpfs", "rw,noatime"));
        set_unit_active(&fs, "syslog-ng.service");

        let check = DecoyPersistenceCheck::new(false, true);
        assert!(check.run(&fs).unwrap().is_fail());
    }

    #[test]
    fn active_auditd_fails_closed() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(
            "/etc/systemd/journald.conf",
            "[Journal]\nStorage=volatile\n",
        );
        fs.mock_add_file(MOUNTINFO, &root_mountinfo("tmpfs", "rw,noatime"));
        set_unit_active(&fs, "auditd.service");

        let check = DecoyPersistenceCheck::new(false, true);
        let result = check.run(&fs).unwrap();
        assert!(result.is_fail());
        assert!(result.message().contains("auditd"));
    }

    #[test]
    fn override_turns_blocker_into_warning() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(
            "/etc/systemd/journald.conf",
            "[Journal]\nStorage=persistent\n",
        );
        fs.mock_add_file(MOUNTINFO, &root_mountinfo("tmpfs", "rw,noatime"));

        let check = DecoyPersistenceCheck::new(true, true);
        let result = check.run(&fs).unwrap();
        assert!(result.is_warn(), "override must warn, not fail: {result:?}");
    }

    #[test]
    fn persistent_root_fs_warns() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(
            "/etc/systemd/journald.conf",
            "[Journal]\nStorage=volatile\n",
        );
        fs.mock_add_file(MOUNTINFO, &root_mountinfo("ext4", "rw,noatime"));

        let check = DecoyPersistenceCheck::new(false, true);
        let result = check.run(&fs).unwrap();
        assert!(result.is_warn(), "persistent root fs must warn: {result:?}");
        assert!(result.message().contains("persistent"));
    }

    #[test]
    fn strictatime_root_warns() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(
            "/etc/systemd/journald.conf",
            "[Journal]\nStorage=volatile\n",
        );
        // tmpfs root so only the atime finding fires.
        fs.mock_add_file(MOUNTINFO, &root_mountinfo("tmpfs", "rw,strictatime"));

        let check = DecoyPersistenceCheck::new(false, true);
        let result = check.run(&fs).unwrap();
        assert!(result.is_warn());
        assert!(result.message().contains("atime"));
    }

    #[test]
    fn core_pattern_disk_path_warns() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(
            "/etc/systemd/journald.conf",
            "[Journal]\nStorage=volatile\n",
        );
        fs.mock_add_file(MOUNTINFO, &root_mountinfo("tmpfs", "rw,noatime"));
        fs.mock_add_file(CORE_PATTERN, "/var/crash/core.%e.%p\n");

        let check = DecoyPersistenceCheck::new(false, true);
        let result = check.run(&fs).unwrap();
        assert!(result.is_warn());
        assert!(result.message().contains("core_pattern"));
    }

    #[test]
    fn coredump_external_warns() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(
            "/etc/systemd/journald.conf",
            "[Journal]\nStorage=volatile\n",
        );
        fs.mock_add_file(MOUNTINFO, &root_mountinfo("tmpfs", "rw,noatime"));
        fs.mock_add_file(
            CORE_PATTERN,
            "|/run/current-system/sw/lib/systemd/systemd-coredump %P\n",
        );
        fs.mock_add_file(COREDUMP_CONF, "[Coredump]\nStorage=external\n");

        let check = DecoyPersistenceCheck::new(false, true);
        let result = check.run(&fs).unwrap();
        assert!(result.is_warn());
        assert!(
            result.message().contains("coredump") || result.message().contains("systemd-coredump")
        );
    }

    #[test]
    fn coredump_none_does_not_warn_on_that_axis() {
        assert!(!coredump_storage_external("[Coredump]\nStorage=none\n"));
        assert!(!coredump_storage_external("Storage=journal\n"));
        assert!(coredump_storage_external("Storage=external\n"));
        // Unset defaults to external.
        assert!(coredump_storage_external("[Coredump]\n"));
        // Last assignment wins.
        assert!(!coredump_storage_external(
            "Storage=external\nStorage=none\n"
        ));
    }

    #[test]
    fn pstore_records_warn() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(
            "/etc/systemd/journald.conf",
            "[Journal]\nStorage=volatile\n",
        );
        fs.mock_add_file(MOUNTINFO, &root_mountinfo("tmpfs", "rw,noatime"));
        fs.mock_set_directory_contents(
            Path::new(PSTORE_DIR),
            vec![std::path::PathBuf::from(format!(
                "{PSTORE_DIR}/dmesg-efi-1"
            ))],
        );

        let check = DecoyPersistenceCheck::new(false, true);
        let result = check.run(&fs).unwrap();
        assert!(result.is_warn());
        assert!(result.message().contains("pstore"));
    }

    #[test]
    fn kdump_armed_warns() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(
            "/etc/systemd/journald.conf",
            "[Journal]\nStorage=volatile\n",
        );
        fs.mock_add_file(MOUNTINFO, &root_mountinfo("tmpfs", "rw,noatime"));
        fs.mock_add_file(KEXEC_CRASH_LOADED, "1\n");

        let check = DecoyPersistenceCheck::new(false, true);
        let result = check.run(&fs).unwrap();
        assert!(result.is_warn());
        assert!(result.message().contains("kdump"));
    }

    #[test]
    fn nixos_upgrade_timer_warns_only_on_nixos() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(
            "/etc/systemd/journald.conf",
            "[Journal]\nStorage=volatile\n",
        );
        fs.mock_add_file(MOUNTINFO, &root_mountinfo("tmpfs", "rw,noatime"));
        fs.mock_set_path_exists(NIXOS_UPGRADE_TIMER, true);

        // On NixOS the timer warns.
        let nixos = DecoyPersistenceCheck::new(false, true);
        assert!(nixos.run(&fs).unwrap().is_warn());

        // On a non-NixOS host the same marker is ignored.
        let other = DecoyPersistenceCheck::new(false, false);
        assert!(other.run(&fs).unwrap().is_pass());
    }

    #[test]
    fn check_performs_no_writes() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(
            "/etc/systemd/journald.conf",
            "[Journal]\nStorage=persistent\n",
        );
        fs.mock_set_path_type("/var/log/journal", PathKind::Dir);
        fs.mock_add_file(MOUNTINFO, &root_mountinfo("ext4", "rw,strictatime"));
        fs.mock_add_file(CORE_PATTERN, "/var/crash/core\n");
        fs.mock_add_file(KEXEC_CRASH_LOADED, "1\n");
        set_unit_active(&fs, "rsyslog.service");

        let before = fs.mock_ops().len();
        let check = DecoyPersistenceCheck::new(false, true);
        let _ = check.run(&fs).unwrap();
        let after = fs.mock_ops();
        assert_eq!(
            after.len(),
            before,
            "decoy-persistence check must not write: {after:?}"
        );
    }
}
