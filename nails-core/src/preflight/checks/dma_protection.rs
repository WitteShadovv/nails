// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! DMA-protection posture pre-flight report.
//!
//! A machine that is powered on and unlocked keeps the hidden session's working
//! set — the overlay upper, the page cache and every running process — plaintext
//! in RAM. A DMA-capable peripheral (a Thunderbolt/USB4 device, a PCIe or
//! NVMe/M.2 card, an ExpressCard) can read that RAM straight off the bus without
//! going through the CPU, which is how an evil-maid or live-seizure attacker
//! lifts keys and data from a running machine. An IOMMU set to remap DMA is the
//! hardware defence against it.
//!
//! This check reports whether that defence is in effect. It reads effective
//! kernel state, not just declared intent: the Thunderbolt/USB4
//! `iommu_dma_protection` attribute, whether an active IOMMU is remapping DMA
//! (`/sys/class/iommu` and the `/sys/kernel/iommu_groups` domain types, so a
//! passthrough default does not pass as protection), and the kernel command
//! line's IOMMU flags (treated as corroboration, because the IOMMU can be on by a
//! build-time default or, on AMD, automatically, with no flag at all). It also
//! reads the kernel `lockdown` LSM state, which governs the separate *software*
//! memory-read path and so is only ever a modifier here.
//!
//! It **warns, never fails**: real DMA protection lives in firmware (VT-d /
//! AMD-Vi and "Kernel DMA Protection" in BIOS/UEFI setup, sometimes a kernel
//! command-line flag and a reboot), NVRAM and boot-configuration changes NAILS
//! refuses to make on the operator's behalf — the same boundary that stops it
//! setting the TCG Memory Overwrite Request (MOR) bit. The only reliable defence
//! against a live seizure is not being in that state, so the warning's advice is
//! to power off before the machine leaves the operator's control. Every probe
//! reads; nothing here writes.

use super::super::{CheckResult, PreFlightCheck};
use crate::{Filesystem, Result};
use std::path::PathBuf;

/// The booted kernel command line, read for its IOMMU flags.
const PROC_CMDLINE: &str = "/proc/cmdline";

/// The kernel `lockdown` LSM state (securityfs), `none [integrity] confidentiality`.
const LOCKDOWN: &str = "/sys/kernel/security/lockdown";

/// Where the Thunderbolt/USB4 domains and controllers appear; each may carry an
/// `iommu_dma_protection` attribute.
const THUNDERBOLT_DEVICES: &str = "/sys/bus/thunderbolt/devices";

/// The per-controller attribute: `1` when the firmware/kernel provide IOMMU DMA
/// protection for that Thunderbolt/USB4 domain.
const TB_DMA_PROTECTION: &str = "iommu_dma_protection";

/// Where the kernel lists every IOMMU it registered; non-empty means an IOMMU is
/// active and remapping DMA.
const IOMMU_CLASS: &str = "/sys/class/iommu";

/// The IOMMU groups the kernel formed; populated alongside an active IOMMU.
const IOMMU_GROUPS: &str = "/sys/kernel/iommu_groups";

/// The per-group domain type (Linux 5.14+): `DMA`/`DMA-FQ` when the group's DMA
/// is remapped, `identity` when DMA bypasses the IOMMU (passthrough). Absent on
/// older kernels, which do not expose it.
const IOMMU_GROUP_TYPE: &str = "type";

/// Why NAILS cannot turn DMA protection on, and the only reliable mitigation.
///
/// It rides on the warning's fix line, as the memory-wipe check's fix does.
const FIRMWARE_ADVICE: &str = "NAILS cannot turn DMA protection on for you: it lives in firmware — enable VT-d or AMD-Vi \
     and \"Kernel DMA Protection\" in BIOS/UEFI setup, and, if the kernel still does not remap \
     DMA, add the IOMMU flag to the decoy kernel command line and reboot. Those are NVRAM and \
     boot-configuration changes NAILS refuses to make on your behalf, the same boundary that \
     stops it setting the TCG Memory Overwrite Request (MOR) bit. No IOMMU makes a machine left \
     powered on and unlocked safe against seizure, because a DMA peripheral reads RAM straight \
     off the bus without the CPU; power off (nails emergency --poweroff) before the machine \
     leaves your control.";

/// Advisory for a DMA-hardened machine whose kernel `lockdown` is already
/// `confidentiality`: the software memory-read paths are closed too.
const LOCKDOWN_CONFIDENTIALITY_NOTE: &str = " Kernel lockdown is confidentiality, so the software memory-read paths (/dev/mem, \
     /proc/kcore, BPF) are closed too.";

/// Advisory for a DMA-hardened machine whose kernel `lockdown` is `integrity`.
const LOCKDOWN_INTEGRITY_ADVISORY: &str = " Advisory: kernel lockdown is integrity; raise it to confidentiality to also close the \
     software memory-read paths (/dev/mem, /proc/kcore, BPF).";

/// Advisory for a DMA-hardened machine whose kernel `lockdown` is off.
const LOCKDOWN_OFF_ADVISORY: &str = " Advisory: kernel lockdown is off; set it to confidentiality to close the software \
     memory-read paths (/dev/mem, /proc/kcore, BPF) a live root console could use.";

/// What the kernel command line declares about IOMMU DMA remapping.
///
/// Read as intent, not proof: the authoritative signal is the effective `/sys`
/// state, because the IOMMU can be enabled by a build-time default
/// (`CONFIG_INTEL_IOMMU_DEFAULT_ON`) or, on AMD, automatically, with no flag at
/// all. Only the decisive *negatives* are recorded here; a positive flag
/// (`intel_iommu=on`, `iommu.passthrough=0`) leaves the answer to `/sys`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IommuCmdline {
    /// `iommu=off`, `intel_iommu=off` or `amd_iommu=off`: the IOMMU is turned off.
    Off,
    /// `iommu=pt` or `iommu.passthrough=1`: an IOMMU is present but DMA bypasses
    /// it (identity-mapped), so devices still reach all of RAM.
    Passthrough,
    /// Nothing decisive about DMA remapping on the command line.
    Unset,
}

/// The effective IOMMU DMA-remapping state, from the command line's intent and
/// the `/sys` ground truth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IommuState {
    /// An IOMMU is active and remapping DMA, not in passthrough: device DMA is
    /// constrained.
    Translating,
    /// DMA is not remapped — the IOMMU is off or in passthrough, or `/sys` lists
    /// no active IOMMU — so a device can read all of RAM.
    Exposed,
    /// Could not determine: no decisive command-line flag and the `/sys` ground
    /// truth could not be read.
    Unknown,
}

/// The Thunderbolt/USB4 domain's DMA-protection posture, from the
/// `iommu_dma_protection` attribute across every controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TbProtection {
    /// At least one controller reports `iommu_dma_protection=1` and none reports
    /// `0`: the tunnelled-PCIe DMA path is closed by the IOMMU.
    Protected,
    /// A controller reports `iommu_dma_protection=0`: an authorized device on
    /// that port can DMA arbitrary RAM. A single exposed controller is decisive.
    Exposed,
    /// No Thunderbolt/USB4 controller, or none exposes the attribute (an older
    /// kernel): no Thunderbolt-specific signal.
    Absent,
}

/// The kernel `lockdown` LSM state. It governs the *software* memory-read path
/// (an attacker with code on the box), not the hardware DMA path, so it is only
/// a modifier to the DMA verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lockdown {
    /// Off: `/dev/mem`, `/proc/kcore`, BPF and friends can read kernel memory.
    None,
    /// Blocks interfaces that *modify* the running kernel.
    Integrity,
    /// Also blocks interfaces that *extract* kernel memory.
    Confidentiality,
    /// The lockdown LSM is not built in (file absent) or could not be read.
    Unavailable,
}

/// The kernel's `kstrtobool`: `None` for a value it rejects.
fn kstrtobool(value: &str) -> Option<bool> {
    let mut chars = value.chars().map(|c| c.to_ascii_lowercase());
    match chars.next()? {
        'y' | 't' | '1' => Some(true),
        'n' | 'f' | '0' => Some(false),
        'o' => match chars.next()? {
            'n' => Some(true),
            'f' => Some(false),
            _ => None,
        },
        _ => None,
    }
}

/// Classify the IOMMU DMA-remapping intent from `/proc/cmdline`.
///
/// Arguments after a bare `--` go to init, not the kernel, so they are ignored,
/// and the kernel treats `-` and `_` in parameter names as equivalent. An
/// explicit `iommu=off` dominates (most exposed); otherwise a requested
/// passthrough counts, with the last `iommu.passthrough=` assignment winning.
fn parse_iommu_cmdline(cmdline: &str) -> IommuCmdline {
    let mut off = false;
    let mut passthrough: Option<bool> = None;
    for token in cmdline.split_whitespace() {
        if token == "--" {
            break;
        }
        let Some((key, value)) = token.split_once('=') else {
            continue;
        };
        let value = value.trim_matches('"');
        match key.replace('-', "_").as_str() {
            "iommu" => match value {
                "off" => off = true,
                "pt" => passthrough = Some(true),
                "nopt" => passthrough = Some(false),
                _ => {}
            },
            "intel_iommu" | "amd_iommu" => {
                if value == "off" {
                    off = true;
                }
            }
            "iommu.passthrough" => {
                if let Some(enabled) = kstrtobool(value) {
                    passthrough = Some(enabled);
                }
            }
            _ => {}
        }
    }
    if off {
        IommuCmdline::Off
    } else if passthrough == Some(true) {
        IommuCmdline::Passthrough
    } else {
        IommuCmdline::Unset
    }
}

/// The effective IOMMU state from the command-line intent and the `/sys` ground
/// truth (`Some(true)` an IOMMU is active and remapping DMA, `Some(false)` `/sys`
/// is readable and lists no remapping IOMMU, `None` the ground truth could not be
/// read).
fn iommu_state(intent: IommuCmdline, present: Option<bool>) -> IommuState {
    match intent {
        IommuCmdline::Off | IommuCmdline::Passthrough => IommuState::Exposed,
        IommuCmdline::Unset => match present {
            Some(true) => IommuState::Translating,
            Some(false) => IommuState::Exposed,
            None => IommuState::Unknown,
        },
    }
}

/// The lockdown state bracketed in `content` (`none [integrity] confidentiality`);
/// a readable file with no bracketed token reads as off.
fn parse_lockdown(content: &str) -> Lockdown {
    for token in content.split_whitespace() {
        if let Some(inner) = token.strip_prefix('[').and_then(|t| t.strip_suffix(']')) {
            return match inner {
                "integrity" => Lockdown::Integrity,
                "confidentiality" => Lockdown::Confidentiality,
                _ => Lockdown::None,
            };
        }
    }
    Lockdown::None
}

/// The warning (never a failure) for a machine whose hardware DMA path is open.
///
/// Reached only when the IOMMU is exposed or a Thunderbolt controller reports
/// `iommu_dma_protection=0`, so the `else` branch is the Thunderbolt case.
fn exposed_warning(iommu: IommuState, lockdown: Lockdown) -> CheckResult {
    let risk = if iommu == IommuState::Exposed {
        "The kernel is not remapping DMA through an IOMMU (the command line turns it off or into \
         passthrough, or /sys lists no active IOMMU), so any DMA-capable device — Thunderbolt or \
         USB4, built-in PCIe, an NVMe/M.2 or ExpressCard slot — can map and read all of system \
         RAM over the bus."
    } else {
        // A Thunderbolt/USB4 controller reports no protection, with the general
        // IOMMU translating or unknown.
        "A Thunderbolt/USB4 controller reports no IOMMU DMA protection (iommu_dma_protection=0), \
         so a device plugged into that port can map and read all of system RAM over the bus."
    };
    let lockdown_note = if lockdown == Lockdown::Confidentiality {
        " Kernel lockdown is confidentiality, which closes the software memory-read paths, but a \
         DMA peripheral reads RAM without the CPU, so lockdown does not close this hardware path."
    } else {
        ""
    };
    CheckResult::warn_with(format!("{risk}{lockdown_note}"), FIRMWARE_ADVICE)
}

/// The pass (with an optional lockdown advisory) for a machine whose hardware DMA
/// path is constrained by the IOMMU.
fn protected_pass(tb: TbProtection, iommu: IommuState, lockdown: Lockdown) -> CheckResult {
    let basis = if tb == TbProtection::Protected && iommu == IommuState::Translating {
        "The IOMMU is remapping DMA and the Thunderbolt/USB4 controller reports DMA protection \
         (iommu_dma_protection=1)"
    } else if tb == TbProtection::Protected {
        "The Thunderbolt/USB4 controller reports IOMMU DMA protection (iommu_dma_protection=1)"
    } else {
        // iommu == Translating with no Thunderbolt signal.
        "The IOMMU is remapping DMA (an active IOMMU is present and the command line does not put \
         it in passthrough)"
    };
    let advisory = match lockdown {
        Lockdown::Confidentiality => LOCKDOWN_CONFIDENTIALITY_NOTE,
        Lockdown::Integrity => LOCKDOWN_INTEGRITY_ADVISORY,
        Lockdown::None => LOCKDOWN_OFF_ADVISORY,
        // The lockdown LSM is not built in or unreadable: judge on the DMA path,
        // and do not warn merely because the file is missing.
        Lockdown::Unavailable => "",
    };
    CheckResult::Pass(format!(
        "{basis}, so a DMA-capable device cannot freely read system RAM. A machine left powered \
         on and unlocked is still not safe against seizure — the live working set stays plaintext \
         in RAM while the volume is mounted; power off before handing it over.{advisory}"
    ))
}

/// The DMA-protection verdict from the four facts. Warn when the hardware DMA
/// path is open or cannot be confirmed, Pass when it is constrained, and Skipped
/// only when nothing could be read at all. It never fails.
fn verdict(
    tb: TbProtection,
    iommu: IommuState,
    lockdown: Lockdown,
    cmdline_readable: bool,
) -> CheckResult {
    // Nothing readable: no command line, no IOMMU ground truth, no Thunderbolt
    // controller and no lockdown file. Typically a stripped environment or a
    // VM/container guest, whose view does not reflect the host's DMA exposure.
    if !cmdline_readable
        && iommu == IommuState::Unknown
        && tb == TbProtection::Absent
        && lockdown == Lockdown::Unavailable
    {
        return CheckResult::skipped(
            "could not read the IOMMU state (/proc/cmdline, /sys/class/iommu, \
             /sys/kernel/iommu_groups) or the kernel lockdown (/sys/kernel/security/lockdown); \
             mount /proc and /sys, and assess DMA protection on the host rather than inside a \
             virtual-machine or container guest, whose view does not reflect the host's physical \
             DMA exposure",
        );
    }

    // The hardware DMA path is open: a Thunderbolt/USB4 controller reports no
    // protection, or the IOMMU is off/passthrough/absent. Effective /sys state
    // overrides a stale Thunderbolt attribute, so an exposed IOMMU warns even
    // when a controller claims protection.
    if tb == TbProtection::Exposed || iommu == IommuState::Exposed {
        return exposed_warning(iommu, lockdown);
    }

    // Could not confirm remapping is active, and there is no Thunderbolt signal
    // either. Absence of evidence is not protection, so the safe default is a
    // soft warning worded as "could not confirm".
    if iommu == IommuState::Unknown && tb == TbProtection::Absent {
        return CheckResult::warn_with(
            "Could not confirm the host is remapping DMA through an IOMMU: no decisive IOMMU flag \
             on the kernel command line, and /sys/class/iommu and /sys/kernel/iommu_groups could \
             not be read. This is a could-not-confirm, not a definite exposure — a missing \
             intel_iommu=on does not mean the IOMMU is off, because the kernel may enable it by \
             its built-in default or, on AMD, automatically — but an unprotected machine lets a \
             DMA-capable device read all of RAM. This also happens inside a virtual-machine or \
             container guest, whose view does not reflect the host's physical DMA exposure; \
             assess it on the host.",
            FIRMWARE_ADVICE,
        );
    }

    // The hardware DMA path is constrained: a Thunderbolt controller reports
    // protection, or the IOMMU is translating.
    protected_pass(tb, iommu, lockdown)
}

/// Pre-flight check reporting whether the host restricts DMA into RAM from
/// external ports, warning when it does not.
pub struct DmaProtectionCheck {
    /// The booted kernel command line.
    cmdline_path: PathBuf,
    /// The kernel `lockdown` LSM state file.
    lockdown_path: PathBuf,
    /// The Thunderbolt/USB4 device directory, enumerated for controllers.
    thunderbolt_devices_dir: PathBuf,
    /// The directory the kernel lists active IOMMUs in.
    iommu_class_dir: PathBuf,
    /// The directory the kernel lists IOMMU groups in.
    iommu_groups_dir: PathBuf,
}

impl DmaProtectionCheck {
    /// Create the check over the host's real paths.
    pub fn new() -> Self {
        Self {
            cmdline_path: PathBuf::from(PROC_CMDLINE),
            lockdown_path: PathBuf::from(LOCKDOWN),
            thunderbolt_devices_dir: PathBuf::from(THUNDERBOLT_DEVICES),
            iommu_class_dir: PathBuf::from(IOMMU_CLASS),
            iommu_groups_dir: PathBuf::from(IOMMU_GROUPS),
        }
    }

    /// Whether the kernel registered an active IOMMU that is *remapping* DMA:
    /// `Some(true)` when an IOMMU is present and remapping, `Some(false)` when
    /// `/sys` is readable but lists no IOMMU or every group reports passthrough
    /// (`identity`), and `None` when neither `/sys` path could be read.
    ///
    /// Presence alone is not translation: a kernel built with
    /// `CONFIG_IOMMU_DEFAULT_PASSTHROUGH=y`, or put in passthrough by a firmware
    /// default, still populates these directories while leaving DMA unremapped.
    /// So when a group exposes its `type` (Linux 5.14+), a `DMA`/`DMA-FQ` group
    /// proves remapping and an `identity` group is passthrough; a kernel too old
    /// to report a type falls back to presence, never downgrading an IOMMU it
    /// cannot inspect.
    fn iommu_present<F: Filesystem>(&self, fs: &F) -> Option<bool> {
        let class = fs.list_directory(&self.iommu_class_dir).ok();
        let groups = fs.list_directory(&self.iommu_groups_dir).ok();
        if class.is_none() && groups.is_none() {
            return None;
        }
        let class_populated = class.as_ref().is_some_and(|entries| !entries.is_empty());
        let group_entries = groups.unwrap_or_default();
        let mut any_translating = false;
        let mut any_passthrough = false;
        for group in &group_entries {
            if let Ok(kind) = fs.read_file_content(&group.join(IOMMU_GROUP_TYPE)) {
                match kind.trim() {
                    "DMA" | "DMA-FQ" => any_translating = true,
                    "identity" => any_passthrough = true,
                    _ => {}
                }
            }
        }
        if any_translating {
            // At least one group is remapped: the IOMMU is translating DMA.
            return Some(true);
        }
        if any_passthrough {
            // Groups exist and every one that reports a type is passthrough, so
            // DMA is not remapped and a device can still reach all of RAM.
            return Some(false);
        }
        // No group reports a type (a kernel before 5.14, or an empty `/sys`): fall
        // back to presence, never downgrading an IOMMU we cannot inspect.
        Some(class_populated || !group_entries.is_empty())
    }

    /// The Thunderbolt/USB4 DMA-protection posture, from the
    /// `iommu_dma_protection` attribute of every controller. A single controller
    /// reporting `0` is decisive; an absent directory or attribute is tolerated.
    fn thunderbolt_protection<F: Filesystem>(&self, fs: &F) -> TbProtection {
        let mut saw_protected = false;
        for entry in fs
            .list_directory(&self.thunderbolt_devices_dir)
            .unwrap_or_default()
        {
            let Ok(value) = fs.read_file_content(&entry.join(TB_DMA_PROTECTION)) else {
                continue;
            };
            match value.trim() {
                "0" => return TbProtection::Exposed,
                "1" => saw_protected = true,
                _ => {}
            }
        }
        if saw_protected {
            TbProtection::Protected
        } else {
            TbProtection::Absent
        }
    }

    /// The kernel lockdown state, or [`Lockdown::Unavailable`] when the LSM is not
    /// built in (file absent) or the file could not be read.
    fn lockdown<F: Filesystem>(&self, fs: &F) -> Lockdown {
        match fs.read_file_content(&self.lockdown_path) {
            Ok(content) => parse_lockdown(&content),
            Err(_) => Lockdown::Unavailable,
        }
    }
}

impl Default for DmaProtectionCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: Filesystem> PreFlightCheck<F> for DmaProtectionCheck {
    fn name(&self) -> &'static str {
        "dma-protection"
    }

    fn description(&self) -> &'static str {
        "Reports whether the host restricts DMA into RAM from external ports (an IOMMU), warning \
         when a live memory attacker could read RAM over the bus"
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        let cmdline = fs.read_file_content(&self.cmdline_path).ok();
        let intent = cmdline
            .as_deref()
            .map(parse_iommu_cmdline)
            .unwrap_or(IommuCmdline::Unset);
        let iommu = iommu_state(intent, self.iommu_present(fs));
        let tb = self.thunderbolt_protection(fs);
        let lockdown = self.lockdown(fs);
        Ok(verdict(tb, iommu, lockdown, cmdline.is_some()))
    }
}

#[cfg(test)]
mod tests;
