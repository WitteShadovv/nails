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
    /// `place`, as sentences that start with the partition.
    pub(super) fn of(place: Place, entry: Entry) -> Self {
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
                Finding::Fail(
                    format!(
                        "{typed}. At every later boot of the decoy, systemd mounts the first \
                         such partition of that disk at {point} when no fstab line mounts \
                         {point} and that folder is empty{var}, and asks for its passphrase \
                         first when it is a LUKS volume: a failed mount or a passphrase prompt \
                         shows that the partition is there. {SPARED}"
                    ),
                    place,
                )
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
            AutoRole::Swap => Finding::Fail(
                format!(
                    "{typed}. At every later boot of the decoy, systemd uses the first swap \
                     partition of that disk without the no-auto flag as swap, unless an fstab \
                     line names a swap, and asks for its passphrase first when it is a LUKS \
                     volume: a failed swap or a passphrase prompt shows that the partition is \
                     there. {SPARED}"
                ),
                place,
            ),
            AutoRole::Esp | AutoRole::Xbootldr | AutoRole::Root => Finding::Warn(
                format!(
                    "{typed}. systemd {}. Anyone who reads the partition table sees a type the \
                     partition's use does not explain.",
                    rare_use(role)
                ),
                Some(place),
            ),
        }
    }
}

/// What the decoy's boot does not touch, and what it leaves.
const SPARED: &str = "The hidden session, whose root is an overlay, is spared, but anyone who \
     reads the partition table sees the type.";

/// `text` with its first letter in upper case.
fn capitalized(text: &str) -> String {
    let mut chars = text.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().chain(chars).collect()
    })
}

/// When systemd acts on a partition of `role`, one of the types it uses
/// only under some conditions. systemd 254 and 255 look for fstab lines
/// that mount `/boot` or `/efi` themselves; from systemd 256 on, a line that
/// mounts anything at or below either, such as `/boot/efi`, stops it too.
fn rare_use(role: AutoRole) -> &'static str {
    match role {
        AutoRole::Esp => {
            "mounts the first EFI system partition of that disk at /boot or /efi when no fstab \
             line mounts that folder (from systemd 256 on, anything at or below either) and it \
             is empty or missing, on a UEFI boot only when the boot loader says it started from \
             that disk, on a BIOS boot without that condition"
        }
        AutoRole::Xbootldr => {
            "mounts the first extended boot loader partition of that disk at /boot when no \
             fstab line mounts /boot (from systemd 256 on, anything at or below /boot or /efi) \
             and /boot is empty or missing, on a UEFI boot only when the boot loader says it \
             started from that disk"
        }
        _ => {
            "takes a root partition from that disk at boot only when the kernel command line \
             names no root"
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
