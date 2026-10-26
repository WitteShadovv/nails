// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What happens to each decoy filesystem in the hidden root.
//!
//! The root overlay covers only the root filesystem. Every other filesystem
//! in the fstab the hidden systemd reads would be mounted by it **directly and
//! read-write**: a separate `/home` or `/var` would take hidden writes on the
//! decoy disk, the ESP would get `loader/random-seed` rewritten, and decoy swap
//! would take hidden RAM. Before the switch NAILS therefore decides for every
//! entry, and puts the result in place inside `/run/nextroot` (an already
//! mounted path counts as active for systemd) or masks the unit in `/run`:
//!
//! | Entry | Decision |
//! | --- | --- |
//! | `/` | the root overlay itself |
//! | swap | masked: never activated |
//! | RAM and kernel filesystems | left to the hidden systemd (nothing reaches a disk) |
//! | the hidden volume, or a path inside it | left alone: it is bound at its own path |
//! | a VM host share (9p, virtiofs) or an overlay entry mounted in the decoy | an overlay with its upper on the hidden volume |
//! | a VM host share not mounted now | left to the hidden systemd |
//! | `/boot`, `/boot/efi`, `/efi` (the ESP and boot partitions) | read-only bind of the decoy mount |
//! | a local filesystem mounted read-only in the decoy | read-only bind |
//! | any other local filesystem mounted in the decoy | an overlay with its upper on the hidden volume |
//! | a local filesystem not mounted now, mounted at boot | masked (and its automount) |
//! | `noauto` without an automount | left alone: never mounted |
//! | a network filesystem | masked: the hidden session would write to the server |
//! | an overlay entry not mounted now, its upper in RAM | left to the hidden systemd |
//! | an overlay entry not mounted now, its upper on a disk | masked |
//!
//! A mounted host share or overlay is overlaid rather than left to the hidden
//! systemd because the next root must already hold its contents when PID 1
//! checks the init: NixOS test VMs mount `/nix/store` as an overlay of a 9p
//! share and a tmpfs, and the next root would otherwise have an empty store.
//!
//! An entry behind an automount (`x-systemd.automount`, often the ESP) whose
//! filesystem the policy binds or overlays itself keeps its automount masked
//! too ([`masks`]): the hidden systemd would find the mount point taken and
//! fail to set the automount up, and `local-fs.target`, which requires it
//! unless the entry is `nofail`, would fail with it and start the hidden
//! session in emergency mode.
//!
//! An entry of the decoy's fstab that the next root resolves to another path
//! than the decoy root does (a symlink on the way that a session replaced or
//! added) is decided at that path as well ([`decide_redirected`]). There the
//! hidden-volume rule does not apply: a link that leads the entry into the
//! hidden volume still names a decoy filesystem, which the hidden systemd
//! would mount read-write inside the hidden volume, so it is masked.
//!
//! Nothing is refused outright today: every entry has a safe decision. The
//! `Refuse` decision exists for entries whose target cannot be mounted inside
//! the next root (a relative or odd mount point).

use super::fstab::{FstabEntry, automount_unit, mount_unit, swap_unit};
use nails_teardown::mountinfo::{MountEntry, parse_overlay_opts};
use std::path::{Component, Path, PathBuf};

/// Mount points whose filesystem is kept read-only in the hidden root. The
/// units that write there at every start are masked in the hidden root
/// ([`super::hidden_masks`]).
pub const BOOT_PATHS: &[&str] = &["/boot", "/boot/efi", "/efi"];

/// What to do with one fstab entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Bind the decoy mount at `target` read-only into the next root.
    ReadOnlyBind {
        /// The mount point.
        target: PathBuf,
    },
    /// Mount an overlay over the decoy mount at `target`, upper on the hidden
    /// volume.
    Overlay {
        /// The mount point.
        target: PathBuf,
    },
    /// Mask these units in `/run`, so the hidden systemd never starts them.
    Mask {
        /// The entry's mount point (or swap spec).
        target: PathBuf,
        /// The units.
        units: Vec<String>,
        /// Why.
        reason: &'static str,
    },
    /// Leave it to the hidden systemd or skip it.
    Leave {
        /// The mount point.
        target: PathBuf,
        /// Why that is safe.
        reason: &'static str,
    },
    /// No safe decision: activation is refused.
    Refuse {
        /// The mount point.
        target: PathBuf,
        /// Why.
        reason: String,
    },
}

impl Decision {
    /// The units to mask, if this is a mask.
    pub fn masked_units(&self) -> &[String] {
        match self {
            Decision::Mask { units, .. } => units,
            _ => &[],
        }
    }

    /// A one-line description for `check` and the activation log.
    pub fn describe(&self) -> String {
        match self {
            Decision::ReadOnlyBind { target } => format!("{}: read-only", target.display()),
            Decision::Overlay { target } => format!("{}: overlaid", target.display()),
            Decision::Mask { target, reason, .. } => {
                format!("{}: masked ({reason})", target.display())
            }
            Decision::Leave { target, reason } => {
                format!("{}: left as is ({reason})", target.display())
            }
            Decision::Refuse { target, reason } => {
                format!("{}: refused ({reason})", target.display())
            }
        }
    }
}

/// The decoy's live mount at exactly `target` (the topmost one).
fn mounted_at<'a>(mounts: &'a [MountEntry], target: &Path) -> Option<&'a MountEntry> {
    mounts.iter().rev().find(|m| m.mount_point == target)
}

/// The deepest decoy mount containing `path`.
fn mount_containing<'a>(mounts: &'a [MountEntry], path: &Path) -> Option<&'a MountEntry> {
    mounts
        .iter()
        .filter(|m| path.starts_with(&m.mount_point))
        .max_by_key(|m| m.mount_point.components().count())
}

fn plain_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
}

/// Decide one entry. `mounts` is the decoy's live mount table.
pub fn decide(entry: &FstabEntry, mounts: &[MountEntry], hidden_root: &Path) -> Decision {
    decide_entry(entry, mounts, hidden_root, false)
}

/// Decide an entry of the decoy's fstab at the path the next root resolves
/// it to, where that differs from the decoy root's (see the module docs): as
/// [`decide`], except that a path inside the hidden volume is masked rather
/// than left to the bind of the hidden volume.
pub fn decide_redirected(
    entry: &FstabEntry,
    mounts: &[MountEntry],
    hidden_root: &Path,
) -> Decision {
    decide_entry(entry, mounts, hidden_root, true)
}

/// Mask the units the hidden systemd generates for `entry`: its mount, and
/// its automount when it has one.
fn mask(entry: &FstabEntry, reason: &'static str) -> Decision {
    let mut units = vec![mount_unit(&entry.file)];
    if entry.is_automount() {
        units.push(automount_unit(&entry.file));
    }
    Decision::Mask {
        target: entry.file.clone(),
        units,
        reason,
    }
}

fn decide_entry(
    entry: &FstabEntry,
    mounts: &[MountEntry],
    hidden_root: &Path,
    redirected: bool,
) -> Decision {
    let target = entry.file.clone();
    if entry.is_swap() {
        let units: Vec<String> = swap_unit(&entry.spec).into_iter().collect();
        if units.is_empty() {
            return Decision::Leave {
                target,
                reason: "a swap entry without a device",
            };
        }
        return Decision::Mask {
            target: PathBuf::from(&entry.spec),
            units,
            reason: "swap would take hidden RAM onto a decoy disk",
        };
    }
    if !plain_absolute(&target) {
        return Decision::Refuse {
            reason: "the mount point is not a plain absolute path".to_string(),
            target,
        };
    }
    if target == Path::new("/") {
        return Decision::Leave {
            target,
            reason: "the root overlay",
        };
    }
    if entry.is_virtual() {
        return Decision::Leave {
            target,
            reason: "RAM or kernel filesystem",
        };
    }
    if target.starts_with(hidden_root) {
        if redirected {
            return mask(
                entry,
                "a link leads it into the hidden volume, where the hidden session would mount \
                 a decoy filesystem read-write",
            );
        }
        return Decision::Leave {
            target,
            reason: "the hidden volume is bound at its own path",
        };
    }
    let mounted = mounted_at(mounts, &target).is_some();
    if (entry.is_host_share() || entry.vfstype == "overlay") && mounted {
        return Decision::Overlay { target };
    }
    if entry.is_host_share() {
        return Decision::Leave {
            target,
            reason: "a host share, not mounted now",
        };
    }
    if entry.is_network() {
        return mask(entry, "the hidden session would write to the server");
    }
    if entry.vfstype == "overlay" {
        let opts = entry
            .option_value("upperdir")
            .map(PathBuf::from)
            .or_else(|| {
                mounted_at(mounts, &target).and_then(|m| parse_overlay_opts(&m.super_opts).upperdir)
            });
        let in_ram = opts
            .as_deref()
            .and_then(|upper| mount_containing(mounts, upper))
            .is_some_and(|m| m.fstype == "tmpfs" || m.fstype == "ramfs");
        return if in_ram {
            Decision::Leave {
                target,
                reason: "an overlay with its upper in RAM",
            }
        } else {
            mask(entry, "an overlay with its upper on a disk")
        };
    }
    match mounted_at(mounts, &target) {
        Some(mount) if BOOT_PATHS.iter().any(|b| target == Path::new(b)) || mount.read_only() => {
            Decision::ReadOnlyBind { target }
        }
        Some(_) => Decision::Overlay { target },
        None if entry.is_noauto() => Decision::Leave {
            target,
            reason: "noauto: never mounted",
        },
        None => mask(
            entry,
            "not mounted now; the hidden session would mount it read-write",
        ),
    }
}

/// Decide every entry, ordered by mount-point depth so a parent is in place
/// before a child mounted below it.
pub fn decide_all(
    entries: &[FstabEntry],
    mounts: &[MountEntry],
    hidden_root: &Path,
) -> Vec<Decision> {
    by_depth(entries, |entry| decide(entry, mounts, hidden_root))
}

/// [`decide_all`] for entries the next root resolves elsewhere, each decided
/// by [`decide_redirected`].
pub fn decide_all_redirected(
    entries: &[FstabEntry],
    mounts: &[MountEntry],
    hidden_root: &Path,
) -> Vec<Decision> {
    by_depth(entries, |entry| {
        decide_redirected(entry, mounts, hidden_root)
    })
}

/// The decision `decide` gives each of `entries`, ordered by mount-point
/// depth.
fn by_depth(entries: &[FstabEntry], decide: impl Fn(&FstabEntry) -> Decision) -> Vec<Decision> {
    let mut decisions: Vec<(usize, Decision)> = entries
        .iter()
        .map(|e| (e.file.components().count(), decide(e)))
        .collect();
    decisions.sort_by_key(|(depth, _)| *depth);
    decisions.into_iter().map(|(_, d)| d).collect()
}

/// Every unit the decisions mask.
pub fn masked_units(decisions: &[Decision]) -> Vec<String> {
    decisions
        .iter()
        .flat_map(|d| d.masked_units().iter().cloned())
        .collect()
}

/// Every unit the hidden session keeps masked, each once: the units the
/// `decisions` mask, and the automount of each entry of `fstab` whose
/// filesystem they put in place themselves, read-only or overlaid (see the
/// module docs).
pub fn masks(fstab: &[FstabEntry], decisions: &[Decision]) -> Vec<String> {
    let placed = |file: &Path| {
        decisions.iter().any(|decision| match decision {
            Decision::ReadOnlyBind { target } | Decision::Overlay { target } => target == file,
            _ => false,
        })
    };
    let automounts = fstab
        .iter()
        .filter(|entry| entry.is_automount() && placed(&entry.file))
        .map(|entry| automount_unit(&entry.file));
    let mut masks: Vec<String> = Vec::new();
    for unit in masked_units(decisions).into_iter().chain(automounts) {
        if !masks.contains(&unit) {
            masks.push(unit);
        }
    }
    masks
}

#[cfg(test)]
#[path = "policy_tests.rs"]
mod tests;
