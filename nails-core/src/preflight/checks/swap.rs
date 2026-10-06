// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Swap and hibernation pre-flight classification.
//!
//! A single swap can defeat the forensic guarantees: memory (including
//! decryption keys and traces of the hidden session) can be paged out to
//! persistent storage, and a hibernation image writes the whole of RAM to disk.
//!
//! Not every swap is equal, though. RAM-only `zram` (the Fedora default and
//! NixOS `zramSwap`) never touches persistent storage, so failing on it merely
//! trains users to bypass all pre-flight checks. This module classifies swap
//! *per device* instead of with a single boolean:
//!
//! - `/dev/zramN` passes only when `/sys/block/zramN/backing_dev` reads `none`
//!   (no disk backing); a backed zram device fails.
//! - dm-crypt swap (`/dev/mapper/*`) whose crypttab entry is keyed from a random
//!   ephemeral source (`/dev/urandom`, `/dev/random`, or the `swap` option)
//!   warns rather than fails: its contents are unrecoverable after reboot, but
//!   it is still worth surfacing.
//! - every other device (plain partition, file swap, or a mapper without a
//!   random key) fails.
//!
//! Hibernation is classified separately: a configured `/sys/power/resume` or a
//! `resume=` on the kernel command line means a hibernation image can be written
//! to disk, so it fails.
//!
//! # No writes
//!
//! Every probe reads the filesystem through the [`Filesystem`] trait; nothing
//! here calls `swapoff` or mutates anything. The same classifier backs the
//! pre-flight check, `verify`, and the post-switch re-check, so all three report
//! identical verdicts.

use super::super::{CheckResult, PreFlightCheck};
use crate::{Filesystem, Result};
use std::path::{Path, PathBuf};

/// The kernel's active-swap table.
const PROC_SWAPS: &str = "/proc/swaps";
/// Maps a dm-crypt mapper name to its backing device and key source.
const CRYPTTAB: &str = "/etc/crypttab";
/// The booted kernel command line (carries `resume=` when hibernation is wired).
const PROC_CMDLINE: &str = "/proc/cmdline";
/// `major:minor` of the configured hibernation resume device (`0:0` when unset).
const SYS_POWER_RESUME: &str = "/sys/power/resume";

/// Severity of a swap/hibernation posture, ordered `Pass < Warn < Fail` so the
/// worst finding across devices wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SwapSeverity {
    /// No device or hibernation channel can write memory to persistent storage.
    Pass,
    /// Only ephemeral encrypted swap is active; surfaced but not blocking.
    Warn,
    /// At least one channel can leak memory to persistent storage.
    Fail,
}

/// The aggregated swap/hibernation posture of the running system.
#[derive(Debug, Clone)]
pub struct SwapPosture {
    /// The worst severity across all swap devices and the hibernation check.
    pub severity: SwapSeverity,
    /// Human-readable description of each non-passing finding.
    pub findings: Vec<String>,
    /// The `/proc/swaps` filenames of the disk-backed devices that failed
    /// (plain partitions, file swap, disk-backed zram, fixed-key dm-crypt), in
    /// the order the kernel lists them. RAM-only zram and ephemeral encrypted
    /// swap are excluded, so the remediation can name exactly the devices the
    /// operator must `swapoff` instead of a blanket `swapoff -a`.
    pub disk_swap_devices: Vec<String>,
    /// Whether a hibernation channel (a configured resume device or a `resume=`
    /// kernel argument) can write memory to disk.
    pub hibernation_active: bool,
}

/// Classify every active swap device plus the hibernation channel.
///
/// Reads `/proc/swaps`, the relevant `/sys` and crypttab entries, and the kernel
/// command line through `fs`. A missing `/proc/swaps` (or an empty one) means no
/// swap is active and classifies as [`SwapSeverity::Pass`].
pub fn classify_swap<F: Filesystem>(fs: &F) -> SwapPosture {
    let mut severity = SwapSeverity::Pass;
    let mut findings = Vec::new();
    let mut disk_swap_devices = Vec::new();

    let swaps = fs
        .read_file_content(Path::new(PROC_SWAPS))
        .unwrap_or_default();

    // The first line of /proc/swaps is a header; every later line is a device.
    for line in swaps.lines().skip(1) {
        if line.trim().is_empty() {
            continue;
        }
        let mut cols = line.split_whitespace();
        let Some(raw_filename) = cols.next() else {
            continue;
        };
        // The kernel octal-escapes whitespace and backslashes in the path.
        let decoded = crate::filesystem::mountinfo::unescape_octal(raw_filename);
        let filename = decoded.as_str();
        let kind = cols.next().unwrap_or("");
        let (device_severity, detail) = classify_device(fs, filename, kind);
        if device_severity != SwapSeverity::Pass {
            severity = severity.max(device_severity);
            findings.push(detail);
        }
        // Only the disk-backed failures are offered to `swapoff`: an ephemeral
        // encrypted device merely warns and a RAM-only zram passes, so naming
        // them would send the operator to disable swap that is already safe.
        if device_severity == SwapSeverity::Fail {
            disk_swap_devices.push(filename.to_string());
        }
    }

    let hibernation = hibernation_findings(fs);
    let hibernation_active = !hibernation.is_empty();
    for detail in hibernation {
        severity = severity.max(SwapSeverity::Fail);
        findings.push(detail);
    }

    SwapPosture {
        severity,
        findings,
        disk_swap_devices,
        hibernation_active,
    }
}

/// Build the remediation for a failing swap posture, naming the exact devices to
/// disable so the operator does not have to run a blanket `swapoff -a`.
fn fail_remediation(posture: &SwapPosture) -> String {
    let swapoff = if posture.disk_swap_devices.is_empty() {
        None
    } else {
        Some(format!(
            "sudo swapoff {}",
            posture.disk_swap_devices.join(" ")
        ))
    };

    match (swapoff, posture.hibernation_active) {
        (Some(cmd), true) => format!(
            "Disable the active disk swap ({cmd}) and hibernation (remove resume= and clear \
             /sys/power/resume); keep only RAM-only zram."
        ),
        (Some(cmd), false) => {
            format!("Disable the active disk swap: {cmd}. Keep only RAM-only zram.")
        }
        (None, true) => {
            "Disable hibernation (remove resume= from the kernel command line and clear \
             /sys/power/resume)."
                .to_string()
        }
        // No specific disk device was identified (e.g. an unparsable row); fall
        // back to the blanket form.
        (None, false) => {
            "Disable disk and file swap (sudo swapoff -a) and hibernation (remove resume=); \
             keep only RAM-only zram."
                .to_string()
        }
    }
}

/// Classify a single `/proc/swaps` entry by its filename and type column.
fn classify_device<F: Filesystem>(fs: &F, filename: &str, kind: &str) -> (SwapSeverity, String) {
    if let Some(zram) = filename.strip_prefix("/dev/")
        && zram.starts_with("zram")
    {
        let backing_path = PathBuf::from(format!("/sys/block/{zram}/backing_dev"));
        // zram is RAM-only unless a backing device is explicitly configured;
        // the attribute reads `none` in that default case. Treat an
        // unreadable attribute as the default (RAM-only).
        let backing = fs
            .read_file_content(&backing_path)
            .map(|v| v.trim().to_string())
            .unwrap_or_else(|_| "none".to_string());
        return if backing == "none" {
            (SwapSeverity::Pass, String::new())
        } else {
            (
                SwapSeverity::Fail,
                format!(
                    "zram swap {filename} is backed by a disk device ({backing}); \
                     paged-out memory can reach persistent storage"
                ),
            )
        };
    }

    if kind == "file" {
        return (
            SwapSeverity::Fail,
            format!("file-backed swap {filename} writes memory to the decoy disk"),
        );
    }

    // swapon resolves /dev/mapper/<name> to the node it links to, so a dm-crypt
    // swap usually shows up as /dev/dm-N; its mapper name is in sysfs.
    let mapper_name = match filename.strip_prefix("/dev/mapper/") {
        Some(name) => Some(name.to_string()),
        None => filename
            .strip_prefix("/dev/")
            .filter(|node| node.starts_with("dm-"))
            .and_then(|node| {
                fs.read_file_content(&PathBuf::from(format!("/sys/block/{node}/dm/name")))
                    .ok()
            })
            .map(|name| name.trim().to_string())
            .filter(|name| !name.is_empty()),
    };
    if let Some(name) = mapper_name.as_deref() {
        return if crypttab_random_key(fs, name) {
            (
                SwapSeverity::Warn,
                format!(
                    "encrypted swap {filename} is keyed from an ephemeral random source; \
                     its contents are unrecoverable after reboot but it is still active"
                ),
            )
        } else {
            (
                SwapSeverity::Fail,
                format!(
                    "swap device {filename} is not keyed from a random ephemeral source; \
                     paged-out memory may be recoverable from disk"
                ),
            )
        };
    }

    (
        SwapSeverity::Fail,
        format!("disk swap {filename} writes memory to persistent storage"),
    )
}

/// Whether the crypttab entry for `name` is keyed from a random ephemeral
/// source: a `/dev/urandom`/`/dev/random` keyfile, or the `swap` option (which
/// makes systemd format the device with a fresh random key on every boot).
fn crypttab_random_key<F: Filesystem>(fs: &F, name: &str) -> bool {
    let Ok(content) = fs.read_file_content(Path::new(CRYPTTAB)) else {
        return false;
    };
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.first() != Some(&name) {
            continue;
        }
        let keyfile = fields.get(2).copied().unwrap_or("");
        let options = fields.get(3).copied().unwrap_or("");
        if keyfile == "/dev/urandom" || keyfile == "/dev/random" {
            return true;
        }
        return options.split(',').any(|o| o.trim() == "swap");
    }
    false
}

/// Hibernation findings: a configured resume device or a `resume=` kernel
/// argument, either of which lets a hibernation image write memory to disk.
fn hibernation_findings<F: Filesystem>(fs: &F) -> Vec<String> {
    let mut out = Vec::new();

    if let Ok(resume) = fs.read_file_content(Path::new(SYS_POWER_RESUME)) {
        let resume = resume.trim();
        if !resume.is_empty() && resume != "0:0" {
            out.push(format!(
                "hibernation resume device is configured ({resume}); \
                 a hibernation image can write memory to disk"
            ));
        }
    }

    if let Ok(cmdline) = fs.read_file_content(Path::new(PROC_CMDLINE))
        && cmdline.split_whitespace().any(|t| t.starts_with("resume="))
    {
        out.push(
            "kernel command line sets resume=; hibernation can write memory to disk".to_string(),
        );
    }

    out
}

/// Pre-flight check to validate swap cannot leak memory to persistent storage.
///
/// # Security
///
/// Swap and hibernation are the two channels through which RAM contents
/// (including encryption keys and traces of the hidden session) can reach the
/// decoy disk, defeating plausible deniability. RAM-only `zram` is permitted
/// because it never touches persistent storage.
///
/// # Example
///
/// ```rust
/// use nails_core::preflight::{SwapCheck, PreFlightCheck};
/// use nails_core::filesystem::MockFilesystem;
///
/// let fs = MockFilesystem::new();
/// let check = SwapCheck::new();
///
/// // No swap active: the check passes.
/// fs.mock_set_swap_enabled(false);
/// let result = check.run(&fs).unwrap();
/// assert!(result.is_pass());
/// ```
#[derive(Debug, Default)]
pub struct SwapCheck;

impl SwapCheck {
    /// Create a new SwapCheck
    pub fn new() -> Self {
        Self
    }
}

impl<F: Filesystem> PreFlightCheck<F> for SwapCheck {
    fn name(&self) -> &'static str {
        "swap"
    }

    fn description(&self) -> &'static str {
        "Validates swap cannot leak memory to persistent storage"
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        let posture = classify_swap(fs);
        match posture.severity {
            SwapSeverity::Pass => Ok(CheckResult::Pass(
                "no swap can leak memory to persistent storage (RAM-only zram is permitted)".into(),
            )),
            SwapSeverity::Warn => Ok(CheckResult::Warn(format!(
                "swap posture warning: {}",
                posture.findings.join("; ")
            ))),
            SwapSeverity::Fail => {
                let remediation = fail_remediation(&posture);
                Ok(CheckResult::fail_with(
                    format!(
                        "swap can leak memory to persistent storage: {}",
                        posture.findings.join("; ")
                    ),
                    remediation,
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::MockFilesystem;

    /// A `/proc/swaps` header plus the given device lines.
    fn proc_swaps(entries: &[&str]) -> String {
        let mut out = String::from("Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n");
        for e in entries {
            out.push_str(e);
            out.push('\n');
        }
        out
    }

    #[test]
    fn test_swap_check_trait_metadata() {
        let check = SwapCheck::new();
        assert_eq!(
            <SwapCheck as PreFlightCheck<MockFilesystem>>::name(&check),
            "swap"
        );
        assert_eq!(
            <SwapCheck as PreFlightCheck<MockFilesystem>>::description(&check),
            "Validates swap cannot leak memory to persistent storage"
        );
    }

    #[test]
    fn no_swap_passes() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(PROC_SWAPS, &proc_swaps(&[]));
        let result = SwapCheck::new().run(&fs).unwrap();
        assert!(result.is_pass(), "{result:?}");
    }

    #[test]
    fn missing_proc_swaps_passes() {
        let fs = MockFilesystem::new();
        // /proc/swaps absent entirely: no swap is active.
        let result = SwapCheck::new().run(&fs).unwrap();
        assert!(result.is_pass(), "{result:?}");
    }

    #[test]
    fn zram_without_backing_passes() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(
            PROC_SWAPS,
            &proc_swaps(&["/dev/zram0 partition 8388604 0 100"]),
        );
        fs.mock_add_file("/sys/block/zram0/backing_dev", "none\n");
        let result = SwapCheck::new().run(&fs).unwrap();
        assert!(result.is_pass(), "{result:?}");
    }

    #[test]
    fn zram_without_backing_dev_attribute_passes() {
        let fs = MockFilesystem::new();
        // The attribute is absent; a zram device is RAM-only by default.
        fs.mock_add_file(
            PROC_SWAPS,
            &proc_swaps(&["/dev/zram0 partition 8388604 0 100"]),
        );
        let result = SwapCheck::new().run(&fs).unwrap();
        assert!(result.is_pass(), "{result:?}");
    }

    #[test]
    fn zram_with_backing_fails() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(
            PROC_SWAPS,
            &proc_swaps(&["/dev/zram0 partition 8388604 0 100"]),
        );
        fs.mock_add_file("/sys/block/zram0/backing_dev", "/dev/sda3\n");
        let result = SwapCheck::new().run(&fs).unwrap();
        assert!(result.is_fail(), "{result:?}");
        assert!(result.message().contains("zram0"));
        assert!(result.remediation().is_some());
    }

    #[test]
    fn partition_swap_fails() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(
            PROC_SWAPS,
            &proc_swaps(&["/dev/sda2 partition 8388604 0 -2"]),
        );
        let result = SwapCheck::new().run(&fs).unwrap();
        assert!(result.is_fail(), "{result:?}");
        assert!(result.message().contains("/dev/sda2"));
    }

    #[test]
    fn file_swap_fails() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(PROC_SWAPS, &proc_swaps(&["/swapfile file 2097148 0 -3"]));
        let result = SwapCheck::new().run(&fs).unwrap();
        assert!(result.is_fail(), "{result:?}");
        assert!(result.message().contains("/swapfile"));
    }

    #[test]
    fn dmcrypt_random_key_warns() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(
            PROC_SWAPS,
            &proc_swaps(&["/dev/mapper/cryptswap partition 8388604 0 -2"]),
        );
        fs.mock_add_file(CRYPTTAB, "cryptswap /dev/sda2 /dev/urandom swap\n");
        let result = SwapCheck::new().run(&fs).unwrap();
        assert!(result.is_warn(), "{result:?}");
        assert!(result.message().contains("cryptswap"));
    }

    #[test]
    fn dmcrypt_swap_option_warns() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(
            PROC_SWAPS,
            &proc_swaps(&["/dev/mapper/cryptswap partition 8388604 0 -2"]),
        );
        fs.mock_add_file(
            CRYPTTAB,
            "cryptswap /dev/sda2 none swap,cipher=aes-xts-plain64\n",
        );
        let result = SwapCheck::new().run(&fs).unwrap();
        assert!(result.is_warn(), "{result:?}");
    }

    #[test]
    fn dmcrypt_fixed_key_fails() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(
            PROC_SWAPS,
            &proc_swaps(&["/dev/mapper/cryptswap partition 8388604 0 -2"]),
        );
        fs.mock_add_file(CRYPTTAB, "cryptswap /dev/sda2 /etc/keys/swap.key luks\n");
        let result = SwapCheck::new().run(&fs).unwrap();
        assert!(result.is_fail(), "{result:?}");
    }

    #[test]
    fn dmcrypt_without_crypttab_fails() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(
            PROC_SWAPS,
            &proc_swaps(&["/dev/mapper/cryptswap partition 8388604 0 -2"]),
        );
        let result = SwapCheck::new().run(&fs).unwrap();
        assert!(result.is_fail(), "{result:?}");
    }

    #[test]
    fn hibernation_resume_device_fails() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(PROC_SWAPS, &proc_swaps(&[]));
        fs.mock_add_file(SYS_POWER_RESUME, "259:2\n");
        let result = SwapCheck::new().run(&fs).unwrap();
        assert!(result.is_fail(), "{result:?}");
        assert!(result.message().contains("hibernation"));
    }

    #[test]
    fn hibernation_resume_zero_passes() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(PROC_SWAPS, &proc_swaps(&[]));
        fs.mock_add_file(SYS_POWER_RESUME, "0:0\n");
        let result = SwapCheck::new().run(&fs).unwrap();
        assert!(result.is_pass(), "{result:?}");
    }

    #[test]
    fn a_dm_node_resolves_to_its_crypttab_entry() {
        // swapon resolves /dev/mapper/cryptswap to /dev/dm-1 in /proc/swaps.
        let fs = MockFilesystem::new();
        fs.mock_add_file(
            PROC_SWAPS,
            &proc_swaps(&["/dev/dm-1\tpartition\t1048572\t0\t-2"]),
        );
        fs.mock_add_file("/sys/block/dm-1/dm/name", "cryptswap\n");
        fs.mock_add_file(
            CRYPTTAB,
            "cryptswap /dev/sda3 /dev/urandom swap,cipher=aes-xts-plain64\n",
        );
        let posture = classify_swap(&fs);
        assert_eq!(
            posture.severity,
            SwapSeverity::Warn,
            "{:?}",
            posture.findings
        );
    }

    #[test]
    fn an_escaped_swap_file_path_is_decoded() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(
            PROC_SWAPS,
            &proc_swaps(&["/swap\\040file\tfile\t1048572\t0\t-2"]),
        );
        let posture = classify_swap(&fs);
        assert_eq!(posture.disk_swap_devices, vec!["/swap file".to_string()]);
    }

    #[test]
    fn hibernation_cmdline_resume_fails() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(PROC_SWAPS, &proc_swaps(&[]));
        fs.mock_add_file(
            PROC_CMDLINE,
            "BOOT_IMAGE=/vmlinuz root=UUID=abc resume=UUID=def quiet\n",
        );
        let result = SwapCheck::new().run(&fs).unwrap();
        assert!(result.is_fail(), "{result:?}");
        assert!(result.message().contains("resume="));
    }

    #[test]
    fn worst_severity_wins() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(
            PROC_SWAPS,
            &proc_swaps(&[
                "/dev/zram0 partition 8388604 0 100",
                "/dev/mapper/cryptswap partition 8388604 0 -2",
                "/dev/sda2 partition 8388604 0 -3",
            ]),
        );
        fs.mock_add_file("/sys/block/zram0/backing_dev", "none\n");
        fs.mock_add_file(CRYPTTAB, "cryptswap /dev/sdb2 /dev/urandom swap\n");
        // zram passes, cryptswap warns, sda2 fails => overall Fail.
        let result = SwapCheck::new().run(&fs).unwrap();
        assert!(result.is_fail(), "{result:?}");
    }

    #[test]
    fn fail_remediation_names_the_active_disk_device() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(
            PROC_SWAPS,
            &proc_swaps(&["/dev/sda2 partition 8388604 0 -2"]),
        );
        let result = SwapCheck::new().run(&fs).unwrap();
        let remediation = result.remediation().expect("fail has remediation");
        assert!(
            remediation.contains("sudo swapoff /dev/sda2"),
            "remediation should name the device: {remediation}"
        );
        assert!(
            !remediation.contains("swapoff -a"),
            "a named device must not fall back to the blanket form: {remediation}"
        );
    }

    #[test]
    fn fail_remediation_names_every_active_disk_device() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(
            PROC_SWAPS,
            &proc_swaps(&[
                "/dev/sda2 partition 8388604 0 -2",
                "/swapfile file 2097148 0 -3",
            ]),
        );
        let result = SwapCheck::new().run(&fs).unwrap();
        let remediation = result.remediation().expect("fail has remediation");
        assert!(remediation.contains("/dev/sda2"), "{remediation}");
        assert!(remediation.contains("/swapfile"), "{remediation}");
    }

    #[test]
    fn ram_only_zram_is_not_named_in_remediation() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(
            PROC_SWAPS,
            &proc_swaps(&[
                "/dev/zram0 partition 8388604 0 100",
                "/dev/sda2 partition 8388604 0 -2",
            ]),
        );
        fs.mock_add_file("/sys/block/zram0/backing_dev", "none\n");
        let result = SwapCheck::new().run(&fs).unwrap();
        let remediation = result.remediation().expect("fail has remediation");
        assert!(remediation.contains("/dev/sda2"), "{remediation}");
        assert!(
            !remediation.contains("zram0"),
            "RAM-only zram must not be sent to swapoff: {remediation}"
        );
    }

    #[test]
    fn hibernation_only_failure_does_not_suggest_swapoff() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(PROC_SWAPS, &proc_swaps(&[]));
        fs.mock_add_file(SYS_POWER_RESUME, "259:2\n");
        let result = SwapCheck::new().run(&fs).unwrap();
        let remediation = result.remediation().expect("fail has remediation");
        assert!(remediation.contains("hibernation"), "{remediation}");
        assert!(
            !remediation.contains("swapoff"),
            "no disk swap is active, so swapoff should not be suggested: {remediation}"
        );
    }

    #[test]
    fn classifier_performs_no_writes() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(
            PROC_SWAPS,
            &proc_swaps(&["/dev/sda2 partition 8388604 0 -2"]),
        );
        fs.mock_add_file(SYS_POWER_RESUME, "259:2\n");
        let before = fs.mock_ops().len();
        let _ = classify_swap(&fs);
        assert_eq!(
            fs.mock_ops().len(),
            before,
            "swap classification must not write: {:?}",
            fs.mock_ops()
        );
    }
}
