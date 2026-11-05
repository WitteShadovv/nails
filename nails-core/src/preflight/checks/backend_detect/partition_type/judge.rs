// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What the partition-type check makes of a partition's entry in its table,
//! and of all the partitions of the hidden root's storage together: pure
//! functions over what the check read.

use crate::forensic::layout::discoverable::{
    AutoRole, LINUX_FILESYSTEM, NO_AUTO, auto_discovery_role,
};
use crate::forensic::layout::{Checksums, RecordedTable};
use crate::preflight::CheckResult;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Where the partition types are explained.
pub(super) const DOC: &str = "docs/backends.md";

/// The partition a finding is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Place {
    /// Its kernel name.
    pub(super) partition: String,
    /// Its number in the table.
    pub(super) number: u32,
    /// The kernel name of its disk.
    pub(super) disk: String,
    /// The disk's name for `sgdisk`.
    pub(super) node: String,
}

impl Place {
    /// The partition for a sentence: `partition 5 of nvme0n1 (nvme0n1p5)`.
    fn shown(&self) -> String {
        format!(
            "partition {} of {} ({})",
            self.number, self.disk, self.partition
        )
    }
}

/// What the table on the disk says of a partition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Entry {
    /// A GPT entry: its type, its flags (`None` when udev's record holds a
    /// value that is no number) and what damage of the table makes the
    /// entry untrustworthy, if any.
    Gpt {
        type_id: String,
        flags: Option<u64>,
        damage: Option<Damage>,
    },
    /// An MBR entry.
    Mbr,
    /// The table does not list the partition where the kernel has it.
    Unlisted,
    /// Neither the disk nor udev's record could be read, and why.
    Unreadable(String),
}

/// What of a GPT breaks its own rules, so that its entries cannot be
/// trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Damage {
    /// The header does not match the checksum it keeps of itself.
    Header,
    /// The entries do not match the checksum the header keeps of them.
    Entries,
    /// Not every entry could be checked against that checksum.
    Unchecked,
    /// An entry does not fit within the blocks the partitions may use.
    Range,
}

impl Damage {
    /// The damage of `table`, a GPT, if any.
    pub(super) fn of(table: &RecordedTable) -> Option<Self> {
        match table.checksums {
            Checksums::HeaderFails => Some(Damage::Header),
            Checksums::EntriesFail => Some(Damage::Entries),
            Checksums::EntriesUnchecked => Some(Damage::Unchecked),
            Checksums::Hold if !table.consistent => Some(Damage::Range),
            Checksums::Hold => None,
        }
    }

    /// What is wrong with the table on `disk`, for a sentence that goes on
    /// with what follows from it.
    fn shown(self, disk: &str) -> String {
        match self {
            Damage::Header => format!(
                "The partition table on {disk} does not match the checksum its header keeps of \
                 itself"
            ),
            Damage::Entries => format!(
                "The partition table on {disk} does not match the checksum it keeps of its \
                 entries"
            ),
            Damage::Unchecked => format!(
                "Not every entry of the partition table on {disk} could be checked against the \
                 checksum the table keeps of them"
            ),
            Damage::Range => format!(
                "The partition table on {disk} lists an entry that does not fit within the \
                 blocks its partitions may use"
            ),
        }
    }
}

/// Whether systemd-gpt-auto-generator reads the partition table of a
/// partition's disk at boot. It reads that of one disk at most: the whole
/// disk of the device it finds below the decoy's root file system, or below
/// `/usr` where the root file system has no single block device, as a btrfs
/// filesystem of several. It follows `slaves/` one layer down before systemd
/// 259.1, as from a LUKS volume to its partition, and every layer from 259.1
/// on, as through LVM on LUKS. Where the devices one layer down are not all
/// on one whole disk, as with an md mirror (a device-mapper or md device is
/// a whole disk of its own), it stays at the root file system's own device,
/// which holds no partition table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Discovery {
    /// Every systemd from 254 on reads the disk's table.
    Every,
    /// systemd 259.1 and later read it; older versions stop one layer
    /// below the root file system, at a device that is not this disk.
    Recent,
    /// No systemd reads it.
    Elsewhere,
    /// sysfs did not let the check follow the devices below the root file
    /// system, so it cannot tell.
    Unknown,
}

impl Discovery {
    /// The condition a sentence on what systemd does with a partition of
    /// the disk by its type starts with.
    fn condition(self) -> &'static str {
        match self {
            Discovery::Recent => FROM_259_1,
            Discovery::Unknown => IF_READ,
            Discovery::Every | Discovery::Elsewhere => UNLESS_MASKED,
        }
    }

    /// The sentence on what older systemd does, with a space before it,
    /// for a disk only systemd 259.1 and later read; empty for any other.
    fn older(self) -> &'static str {
        match self {
            Discovery::Recent => OLDER,
            Discovery::Every | Discovery::Elsewhere | Discovery::Unknown => "",
        }
    }
}

/// What the check found for one partition, the least serious first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Finding {
    /// The type is no concern: the message.
    Pass(String),
    /// A concern that does not block: the message, and the partition to
    /// retype when the type is the concern.
    Warn(String, Option<Place>),
    /// A type systemd mounts or uses at boot: the message and the partition.
    Fail(String, Place),
}

impl Finding {
    /// The finding for `entry`, the table's entry of the partition at
    /// `place`, as sentences that start with the partition. `read` says
    /// whether systemd-gpt-auto-generator reads the table of its disk.
    pub(super) fn of(place: Place, entry: Entry, read: Discovery) -> Self {
        let shown = capitalized(&place.shown());
        let (type_id, flags, damage) = match entry {
            Entry::Gpt {
                type_id,
                flags,
                damage,
            } => (type_id, flags, damage),
            Entry::Mbr => {
                return Finding::Pass(format!(
                    "{shown} is in an MBR partition table, from which systemd discovers no \
                     partition."
                ));
            }
            Entry::Unlisted => {
                return Finding::Warn(
                    format!(
                        "{shown} is not where the kernel has it in the partition table on {}: \
                         the table changed since the kernel read it, so the partition's type \
                         cannot be checked.",
                        place.disk
                    ),
                    None,
                );
            }
            Entry::Unreadable(why) => {
                return Finding::Warn(
                    format!(
                        "The type of {} cannot be checked: {why}, and udev keeps no record of \
                         the partition's entry that matches it.",
                        place.shown()
                    ),
                    None,
                );
            }
        };
        let no_auto = flags.is_some_and(|flags| flags & NO_AUTO != 0);
        let Some(role) = auto_discovery_role(&type_id) else {
            return match damage {
                Some(damage) => Finding::Warn(
                    format!(
                        "{}, so the type read for {} cannot be trusted.",
                        damage.shown(&place.disk),
                        place.shown()
                    ),
                    None,
                ),
                None => Finding::Pass(format!(
                    "{shown} has a GPT type that systemd discovers nothing by."
                )),
            };
        };
        let typed = format!("{shown} has the GPT type of {}", role.describe());
        match role {
            AutoRole::Home | AutoRole::Srv | AutoRole::Var | AutoRole::VarTmp if no_auto => {
                Finding::Warn(
                    format!(
                        "{typed}, with the no-auto flag, which tells systemd not to mount it. \
                         systemd leaves it alone, but anyone who reads the partition table sees \
                         a partition typed for {} that the decoy never mounts.",
                        role.mount_point().unwrap_or_default()
                    ),
                    Some(place),
                )
            }
            AutoRole::Home | AutoRole::Srv | AutoRole::Var | AutoRole::VarTmp => {
                let point = role.mount_point().unwrap_or_default();
                let var = if role == AutoRole::Var {
                    ", and only when its partition uuid is the one this machine's ID gives it"
                } else {
                    ""
                };
                let text = match read {
                    Discovery::Elsewhere => format!(
                        "{typed}. {ELSEWHERE}, so systemd does not mount the partition, but \
                         anyone who reads the partition table sees a partition typed for \
                         {point} that the decoy never mounts, and the check refuses the type on \
                         any disk the decoy boots from."
                    ),
                    _ => format!(
                        "{typed}. {}, systemd mounts the first such partition of that disk at \
                         {point} at every later boot of the decoy when no fstab line mounts \
                         {point} and that folder is empty{var}, and asks for its passphrase \
                         first when it is a LUKS volume: a failed mount or a passphrase prompt \
                         shows that the partition is there.{} {SPARED}",
                        read.condition(),
                        read.older()
                    ),
                };
                Finding::Fail(text, place)
            }
            AutoRole::Swap if no_auto => Finding::Fail(
                format!(
                    "{typed}, with the no-auto flag, which tells systemd not to use it. systemd \
                     leaves it alone, but anyone who reads the partition table sees a swap \
                     partition that the decoy never uses, and the check refuses the swap type \
                     with or without the flag."
                ),
                place,
            ),
            AutoRole::Swap => {
                let text = match read {
                    Discovery::Elsewhere => format!(
                        "{typed}. {ELSEWHERE}, so systemd does not use the partition as swap, \
                         but anyone who reads the partition table sees a swap partition that \
                         the decoy never uses, and the check refuses the type on any disk the \
                         decoy boots from."
                    ),
                    _ => format!(
                        "{typed}. {}, systemd uses the first swap partition of that disk \
                         without the no-auto flag as swap at every later boot of the decoy when \
                         no fstab line names a swap, and asks for its passphrase first when it \
                         is a LUKS volume: a failed swap or a passphrase prompt shows that the \
                         partition is there.{} {SPARED}",
                        read.condition(),
                        read.older()
                    ),
                };
                Finding::Fail(text, place)
            }
            AutoRole::Esp | AutoRole::Xbootldr => {
                let text = match read {
                    Discovery::Elsewhere => format!(
                        "{typed}. {ELSEWHERE}, so systemd does not mount the partition. \
                         {UNEXPLAINED}"
                    ),
                    _ => format!(
                        "{typed}. {}, systemd {}.{} {UNEXPLAINED}",
                        read.condition(),
                        loader_use(role),
                        read.older()
                    ),
                };
                Finding::Warn(text, Some(place))
            }
            // Root discovery takes its disk from the boot loader, not from
            // the root file system, and runs in the initrd, which a mask in
            // the decoy's /etc need not reach: the same text on every disk.
            AutoRole::Root => Finding::Warn(
                format!("{typed}. {ROOT_USE}. {ROOT_INITRD} {UNEXPLAINED}"),
                Some(place),
            ),
        }
    }
}

/// The condition on what systemd does with a partition by its type after
/// the initrd: systemd-gpt-auto-generator runs. Ubuntu 24.04 and 26.04 mask
/// it by default, with a link from
/// `/etc/systemd/system-generators/systemd-gpt-auto-generator` to
/// `/dev/null`, and systemd runs no generator masked so
/// (systemd.generator(7)). The check reads no mask: its verdicts are the
/// same on a decoy that masks the generator, where the type still shows in
/// the partition table. Root discovery runs in the initrd instead, under
/// [`ROOT_USE`].
const UNLESS_MASKED: &str =
    "Unless the decoy masks systemd-gpt-auto-generator, as Ubuntu 24.04 and 26.04 do by default";

/// The same condition on a disk only systemd 259.1 and later read.
const FROM_259_1: &str = "From systemd 259.1 on, unless the decoy masks \
     systemd-gpt-auto-generator, as Ubuntu 24.04 and 26.04 do by default";

/// What systemd before 259.1 does with such a disk.
const OLDER: &str = " Older versions follow the devices below the decoy's root file system \
     only one layer down, as from a LUKS volume to its partition, so they leave this disk alone.";

/// The same condition where sysfs does not show whether the generator
/// reads the disk.
const IF_READ: &str = "If that disk is the one systemd-gpt-auto-generator reads at boot, \
     which sysfs did not let the check tell, and unless the decoy masks the generator, as Ubuntu \
     24.04 and 26.04 do by default";

/// Why systemd leaves a partition alone on a disk the generator does not
/// read.
const ELSEWHERE: &str = "systemd-gpt-auto-generator reads the partition table of one disk at \
     most at boot, and that is not this disk";

/// What any type systemd discovers leaves on a partition without that use.
const UNEXPLAINED: &str =
    "Anyone who reads the partition table sees a type the partition's use does not explain.";

/// When systemd takes a partition of the root type as its root: in the
/// initrd, where the generator has systemd wait for the root partition udev
/// finds on the disk the boot loader names (`find_gpt_root` reads
/// `LoaderDevicePartUUID` there), whatever disk the root file system is on
/// later.
const ROOT_USE: &str = "Where the decoy's initrd runs systemd-gpt-auto-generator, systemd takes \
     a root partition at boot from the disk the boot loader says it started from, on a UEFI boot \
     only, and only when the kernel command line names no root";

/// Which initrds run the generator by default. A mask in the decoy's `/etc`
/// reaches the initrd only where the tool that builds the initrd copies it.
/// dracut, Ubuntu 26.04's default, runs systemd in the initrd with the
/// generator in it (its `systemd` and `dracut-systemd` modules) and copies
/// nothing from `/etc/systemd/system-generators`. initramfs-tools, the
/// default of Debian 13 and Ubuntu 24.04, runs a shell script of its own as
/// the initrd's init, with no systemd manager and so no generator.
const ROOT_INITRD: &str = "By default, the initrd of Ubuntu 26.04, which dracut builds, runs it \
     even where the decoy masks it in /etc, as dracut does not copy that mask, and that of Debian \
     13 and Ubuntu 24.04, which initramfs-tools builds, runs no generator.";

/// What the decoy's boot does not touch, and what it leaves.
const SPARED: &str = "The hidden session, whose root is an overlay, is spared, but anyone who \
     reads the partition table sees the type, whether or not the generator is masked.";

/// `text` with its first letter in upper case.
fn capitalized(text: &str) -> String {
    let mut chars = text.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().chain(chars).collect()
    })
}

/// When systemd acts on a partition of `role`, an EFI system or extended
/// boot loader partition, on a disk the generator reads: under some
/// conditions only. systemd 254 and 255 look for fstab lines
/// that mount `/boot` or `/efi` themselves; from systemd 256 on, a line that
/// mounts anything at or below either, such as `/boot/efi`, stops it too.
/// It also leaves an EFI system partition alone that an fstab line names,
/// at any folder from systemd 255 on, and in 254 only at `/boot`, when
/// `/boot` exists and the disk has no extended boot loader partition. The
/// texts leave that out: they are about the hidden root's partition, and
/// `backend-entries` refuses a decoy fstab line that names it.
fn loader_use(role: AutoRole) -> &'static str {
    match role {
        AutoRole::Esp => {
            "mounts the first EFI system partition of that disk at /boot or /efi when no fstab \
             line mounts that folder (from systemd 256 on, anything at or below either) and it \
             is empty or missing, on a UEFI boot only when the boot loader says it started from \
             that disk, on a BIOS boot without that condition"
        }
        _ => {
            "mounts the first extended boot loader partition of that disk at /boot when no \
             fstab line mounts /boot (from systemd 256 on, anything at or below /boot or /efi) \
             and /boot is empty or missing, on a UEFI boot only when the boot loader says it \
             started from that disk"
        }
    }
}

/// The result for `findings`, one per partition: the most serious of them,
/// each of that kind named.
pub(super) fn verdict(root: &Path, findings: &[Finding]) -> CheckResult {
    let fails: Vec<(&String, &Place)> = findings
        .iter()
        .filter_map(|finding| match finding {
            Finding::Fail(message, place) => Some((message, place)),
            _ => None,
        })
        .collect();
    if !fails.is_empty() {
        let message = fails
            .iter()
            .map(|(message, _)| message.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        let places: Vec<&Place> = fails.iter().map(|(_, place)| *place).collect();
        return CheckResult::fail_with(format!("{} {message}", lead(root)), retype(&places));
    }
    let warnings: Vec<(&String, Option<&Place>)> = findings
        .iter()
        .filter_map(|finding| match finding {
            Finding::Warn(message, place) => Some((message, place.as_ref())),
            _ => None,
        })
        .collect();
    if !warnings.is_empty() {
        let message = warnings
            .iter()
            .map(|(message, _)| message.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        let places: Vec<&Place> = warnings.iter().filter_map(|(_, place)| *place).collect();
        let fix = if places.is_empty() {
            format!(
                "Check the partition table from a live system or where setup happens, as root. \
                 See {DOC}."
            )
        } else {
            retype(&places)
        };
        return CheckResult::warn_with(format!("{} {message}", lead(root)), fix);
    }
    let message = findings
        .iter()
        .filter_map(|finding| match finding {
            Finding::Pass(message) => Some(message.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join(" ");
    CheckResult::Pass(format!("{} {message}", lead(root)))
}

/// The sentence the result for partitions of a disk the decoy boots from
/// starts with.
fn lead(root: &Path) -> String {
    format!(
        "The hidden root at {} is stored on a disk the decoy boots from.",
        root.display()
    )
}

/// The `sgdisk` commands that give each partition of `places` the generic
/// Linux type, one per disk.
fn retype(places: &[&Place]) -> String {
    let mut by_disk: BTreeMap<&str, BTreeSet<u32>> = BTreeMap::new();
    for place in places {
        by_disk
            .entry(place.node.as_str())
            .or_default()
            .insert(place.number);
    }
    let commands: Vec<String> = by_disk
        .iter()
        .map(|(node, numbers)| {
            let types: Vec<String> = numbers
                .iter()
                .map(|number| format!("--typecode={number}:{LINUX_FILESYSTEM}"))
                .collect();
            format!("sgdisk {} {node}", types.join(" "))
        })
        .collect();
    format!(
        "From a live system or where setup happens, never on the decoy, give the partition the \
         generic Linux type: {}. See {DOC}.",
        commands.join("; ")
    )
}
