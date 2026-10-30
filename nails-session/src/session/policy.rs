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
//! | swap | kept off: never activated |
//! | RAM and kernel filesystems | left to the hidden systemd (nothing reaches a disk) |
//! | the hidden volume, or a path inside it | left alone: it is bound at its own path |
//! | a VM host share (9p, virtiofs) or an overlay entry mounted in the decoy | an overlay with its upper on the hidden volume |
//! | a VM host share not mounted now | left to the hidden systemd |
//! | `/boot`, `/boot/efi`, `/efi` (the ESP and boot partitions) | read-only bind of the decoy mount |
//! | a local filesystem mounted read-only in the decoy | read-only bind |
//! | any other local filesystem mounted in the decoy | an overlay with its upper on the hidden volume |
//! | a local filesystem not mounted now, mounted at boot | kept unmounted (and its automount off) |
//! | `noauto` without an automount or a unit named to pull it in | left alone: never mounted |
//! | a network filesystem | kept unmounted: the hidden session would write to the server |
//! | an overlay entry not mounted now, its upper in RAM | left to the hidden systemd |
//! | an overlay entry not mounted now, its upper on a disk | kept unmounted |
//!
//! A unit kept off is masked in `/run`, or skipped where a boot target
//! requires it ([`Decision::Skip`]): `local-fs.target` requires the mount of
//! an entry without `nofail` (or its automount), `remote-fs.target` that of a
//! network filesystem, `swap.target` a swap line without `nofail` or
//! `noauto` ([`super::fstab::required_by`]). PID 1 cannot pull a masked unit
//! into a transaction, so it drops the job of a target that requires one,
//! silently, and with the target every unit only it pulls in: the hidden
//! session would run without `local-fs.target`. A skipped unit gets a runtime
//! drop-in whose start condition never holds
//! ([`nails_teardown::whole_root::skips`]); the units its fstab line has it
//! pull in that act on its device ([`super::fstab::checkers`]) are skipped
//! with it: its fsck, makefs or mkswap would start before that condition is
//! tested, and its growfs, pcrfs, validatefs and quota units, which are bound
//! to the mount, are skipped for caution. A skipped mount or swap still waits
//! for its device, and one that is not there would hold the hidden session up
//! until the device timeout and then start emergency mode: an entry whose
//! device is not there now is masked, with a warning that its target will not
//! be reached
//! ([`Decision::warning`]). A mount behind a skipped automount stays masked:
//! the target does not pull it in.
//!
//! A mounted host share or overlay is overlaid rather than left to the hidden
//! systemd because the next root must already hold its contents when PID 1
//! checks the init: NixOS test VMs mount `/nix/store` as an overlay of a 9p
//! share and a tmpfs, and the next root would otherwise have an empty store.
//!
//! An entry behind an automount (`x-systemd.automount`, often the ESP) whose
//! filesystem the policy binds or overlays itself keeps its automount off too
//! ([`runtime_units`]): the hidden systemd would find the mount point taken
//! and fail to set the automount up, and `local-fs.target`, which requires it
//! unless the entry is `nofail`, would fail with it and start the hidden
//! session in emergency mode. The automount is skipped where the target
//! requires it, and masked where the target only wants it.
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

use super::fstab::{
    FstabEntry, automount_unit, checkers, escape_path, mount_unit, required_by, swap_unit,
    waits_for,
};
use nails_teardown::mountinfo::{MountEntry, parse_overlay_opts};
use nails_teardown::whole_root::plan::{MaskCause, RequiredMask, Skip};
use std::path::{Component, Path, PathBuf};

/// Whether a device is there now: [`device_present`] on the running system,
/// a fixed answer in tests.
pub type Present<'a> = &'a dyn Fn(&Path) -> bool;

/// Whether `device` is there on the running system now, as systemd waits for
/// it: its node, or the link udev makes for it, resolves, and its device unit
/// is active. systemd makes a mount or swap wait for that unit, which udev's
/// record of the device makes active, in the hidden session as it does here;
/// a device udev marks not ready (`SYSTEMD_READY=0`) has a node but no active
/// unit. A unit that cannot be asked about counts as not there. `check` and
/// activation both decide with it.
pub fn device_present(device: &Path) -> bool {
    use nails_teardown::whole_root::tools;
    if !device.exists() {
        return false;
    }
    let unit = format!("{}.device", escape_path(device));
    tools::find(None, "systemctl")
        .and_then(|systemctl| {
            tools::run_output(
                &systemctl,
                &["show", "--property=ActiveState", "--value", &unit],
                std::time::Duration::from_secs(30),
            )
        })
        .is_some_and(|state| state.trim() == "active")
}

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
        /// The boot target the mask keeps from being reached, when one
        /// requires the units and their device was not there to skip them.
        unreached: Option<Unreached>,
    },
    /// Skip these units in the hidden root: a boot target requires them, and
    /// a mask would keep the target from being reached (see the module docs).
    Skip {
        /// The entry's mount point (or swap spec).
        target: PathBuf,
        /// The units skipped, those they pull in, and their device.
        skip: Skip,
        /// Units masked with them: the mount behind a skipped automount.
        masked: Vec<String>,
        /// Why they must not start.
        reason: &'static str,
    },
    /// Leave it to the hidden systemd, or leave it alone.
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

/// Why a mask keeps a boot target from being reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unreached {
    /// The target that requires the masked unit (`local-fs.target`).
    pub target: String,
    /// Why the unit is masked rather than skipped.
    pub cause: Unskippable,
    /// Whether the unit comes from a unit file of the decoy's own rather than
    /// an fstab line: `nofail` means nothing in its `Options=`, and a target
    /// requires it by a link.
    pub native: bool,
}

/// Why a unit a boot target requires is masked rather than skipped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unskippable {
    /// The device the unit waits for, which was not there: a skipped unit
    /// would have waited for it until the device timeout.
    NoDevice(PathBuf),
    /// NAILS cannot tell what the unit is (the mask's reason says why), so it
    /// keeps the unit from starting whatever it is
    /// ([`super::mount_units`]).
    Unread,
}

impl Decision {
    /// The units to mask: a mask's, or those masked with a skip.
    pub fn masked_units(&self) -> &[String] {
        match self {
            Decision::Mask { units, .. } => units,
            Decision::Skip { masked, .. } => masked,
            _ => &[],
        }
    }

    /// The units to skip, if this is a skip.
    pub fn skip(&self) -> Option<&Skip> {
        match self {
            Decision::Skip { skip, .. } => Some(skip),
            _ => None,
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
            Decision::Skip { target, reason, .. } => {
                format!("{}: skipped ({reason})", target.display())
            }
            Decision::Leave { target, reason } => {
                format!("{}: left as is ({reason})", target.display())
            }
            Decision::Refuse { target, reason } => {
                format!("{}: refused ({reason})", target.display())
            }
        }
    }

    /// What the operator should know about this decision before the switch:
    /// a mask that keeps a boot target from being reached.
    pub fn warning(&self) -> Option<String> {
        let Decision::Mask {
            target,
            reason,
            unreached:
                Some(Unreached {
                    target: boot,
                    cause,
                    native,
                }),
            ..
        } = self
        else {
            return None;
        };
        let remedy = if *native {
            "install the unit with WantedBy= rather than RequiredBy=, so that the target wants it \
             instead of requiring it"
        } else {
            "give the fstab entry the nofail option"
        };
        let unreached = format!(
            "the hidden session will not reach {boot}, which requires it, and the units only \
             that target pulls in will not start there"
        );
        Some(match cause {
            Unskippable::NoDevice(device) => format!(
                "{} is masked rather than skipped, as its device {} is not there: {unreached}. \
                 Attach the device before activating, or {remedy}",
                target.display(),
                device.display()
            ),
            Unskippable::Unread => {
                format!("{} is masked, as {reason}: {unreached}", target.display())
            }
        })
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

/// The units systemd makes for a mount or a swap, and what pulls them in at
/// boot: for an fstab entry what systemd's fstab generator makes of its line
/// ([`Units::of`]), for a unit outside the fstab what the decoy's unit files
/// say ([`super::mount_units`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Units {
    /// The `.mount` or `.swap` unit; none for a swap entry that names no
    /// device or file.
    pub unit: Option<String>,
    /// Its automount, if it has one.
    pub automount: Option<String>,
    /// What requires the unit, or its automount, at boot
    /// ([`super::fstab::required_by`]); `None` when nothing does.
    pub required_by: Option<String>,
    /// The units it pulls in that act on its device or filesystem
    /// ([`super::fstab::checkers`]).
    pub checkers: Vec<String>,
    /// Whether they come from a unit file of the decoy's own rather than an
    /// fstab line ([`Unreached::native`]).
    pub native: bool,
}

impl Units {
    /// The units systemd's fstab generator makes for `entry`.
    pub fn of(entry: &FstabEntry) -> Self {
        let unit = if entry.is_swap() {
            swap_unit(&entry.spec)
        } else {
            Some(mount_unit(&entry.file))
        };
        Self {
            unit,
            automount: entry.is_automount().then(|| automount_unit(&entry.file)),
            required_by: required_by(entry),
            checkers: checkers(entry),
            native: false,
        }
    }
}

/// Decide one entry. `mounts` is the decoy's live mount table, and `present`
/// tells whether a device is there now ([`device_present`]).
pub fn decide(
    entry: &FstabEntry,
    mounts: &[MountEntry],
    hidden_root: &Path,
    present: Present<'_>,
) -> Decision {
    decide_entry(
        entry,
        &Units::of(entry),
        mounts,
        hidden_root,
        false,
        present,
    )
}

/// Decide an entry of the decoy's fstab at the path the next root resolves
/// it to, where that differs from the decoy root's (see the module docs): as
/// [`decide`], except that a path inside the hidden volume is kept unmounted
/// rather than left to the bind of the hidden volume.
pub fn decide_redirected(
    entry: &FstabEntry,
    mounts: &[MountEntry],
    hidden_root: &Path,
    present: Present<'_>,
) -> Decision {
    decide_entry(entry, &Units::of(entry), mounts, hidden_root, true, present)
}

/// Decide a mount or swap that `units` start, outside the fstab: `entry`
/// holds what its unit files say (the source, the mount point, the type and
/// the options), and the decision is the one an fstab line with them gets.
pub fn decide_units(
    entry: &FstabEntry,
    units: &Units,
    mounts: &[MountEntry],
    hidden_root: &Path,
    present: Present<'_>,
) -> Decision {
    decide_entry(entry, units, mounts, hidden_root, false, present)
}

/// Keep `units` of `entry` from starting: its mount, and its automount when
/// it has one. They are skipped where a boot target requires them, unless
/// the device they wait for is not there now, and masked otherwise (see the
/// module docs).
fn keep_off(
    entry: &FstabEntry,
    units: &Units,
    reason: &'static str,
    present: Present<'_>,
) -> Decision {
    let target = entry.file.clone();
    let mount = units
        .unit
        .clone()
        .unwrap_or_else(|| mount_unit(&entry.file));
    if let Some(automount) = units.automount.clone() {
        if units.required_by.is_none() {
            return Decision::Mask {
                target,
                units: vec![mount, automount],
                reason,
                unreached: None,
            };
        }
        // The target pulls in the automount alone, which waits for no device;
        // the mount, which nothing starts then, stays masked.
        return Decision::Skip {
            target,
            skip: Skip {
                units: vec![automount],
                pulled: Vec::new(),
                device: None,
            },
            masked: vec![mount],
            reason,
        };
    }
    gate(target, vec![mount], entry, units, reason, present)
}

/// The decision for `kept` of `entry` that must not start: a skip when
/// something requires them ([`Units::required_by`]) and the device they wait
/// for, if any, is there now; a mask otherwise.
fn gate(
    target: PathBuf,
    kept: Vec<String>,
    entry: &FstabEntry,
    units: &Units,
    reason: &'static str,
    present: Present<'_>,
) -> Decision {
    let Some(required) = units.required_by.clone() else {
        return Decision::Mask {
            target,
            units: kept,
            reason,
            unreached: None,
        };
    };
    match waits_for(entry) {
        Some(device) if !present(&device) => Decision::Mask {
            target,
            units: kept,
            reason,
            unreached: Some(Unreached {
                target: required,
                cause: Unskippable::NoDevice(device),
                native: units.native,
            }),
        },
        device => Decision::Skip {
            target,
            skip: Skip {
                units: kept,
                pulled: units.checkers.clone(),
                device,
            },
            masked: Vec::new(),
            reason,
        },
    }
}

fn decide_entry(
    entry: &FstabEntry,
    units: &Units,
    mounts: &[MountEntry],
    hidden_root: &Path,
    redirected: bool,
    present: Present<'_>,
) -> Decision {
    let target = entry.file.clone();
    if entry.is_swap() {
        let Some(unit) = units.unit.clone() else {
            return Decision::Leave {
                target,
                reason: "a swap entry without a device",
            };
        };
        return gate(
            PathBuf::from(&entry.spec),
            vec![unit],
            entry,
            units,
            "swap would take hidden RAM onto a decoy disk",
            present,
        );
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
            return keep_off(
                entry,
                units,
                "a link leads it into the hidden volume, where the hidden session would mount \
                 a decoy filesystem read-write",
                present,
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
        return keep_off(
            entry,
            units,
            "the hidden session would write to the server",
            present,
        );
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
            keep_off(entry, units, "an overlay with its upper on a disk", present)
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
        None => keep_off(
            entry,
            units,
            "not mounted now; the hidden session would mount it read-write",
            present,
        ),
    }
}

/// Decide every entry, ordered by mount-point depth so a parent is in place
/// before a child mounted below it.
pub fn decide_all(
    entries: &[FstabEntry],
    mounts: &[MountEntry],
    hidden_root: &Path,
    present: Present<'_>,
) -> Vec<Decision> {
    by_depth(entries, |entry| decide(entry, mounts, hidden_root, present))
}

/// [`decide_all`] for entries the next root resolves elsewhere, each decided
/// by [`decide_redirected`].
pub fn decide_all_redirected(
    entries: &[FstabEntry],
    mounts: &[MountEntry],
    hidden_root: &Path,
    present: Present<'_>,
) -> Vec<Decision> {
    by_depth(entries, |entry| {
        decide_redirected(entry, mounts, hidden_root, present)
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

/// What the hidden session keeps from starting: the units it masks, each
/// once, and the units it skips.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeptOff {
    /// The units masked in `/run`.
    pub masks: Vec<String>,
    /// The units skipped, with those they pull in and their device.
    pub skips: Vec<Skip>,
    /// The units among [`masks`](Self::masks) that a boot target requires,
    /// each once with why it is masked rather than skipped.
    pub required_masks: Vec<RequiredMask>,
}

impl KeptOff {
    /// Record that `units`, which a boot target requires, are masked for
    /// `cause`, unless an earlier cause is recorded for one.
    pub fn record_masked(&mut self, units: &[String], cause: MaskCause, device: Option<&Path>) {
        for unit in units {
            if !self.required_masks.iter().any(|m| &m.unit == unit) {
                self.required_masks.push(RequiredMask {
                    unit: unit.clone(),
                    cause,
                    device: device.map(Path::to_path_buf),
                });
            }
        }
    }
}

/// The units of `decision` masked although a boot target requires them,
/// with why ([`Unreached`]).
fn required_masked(decision: &Decision) -> Option<(&[String], MaskCause, Option<&Path>)> {
    let Decision::Mask {
        units,
        unreached: Some(Unreached { cause, .. }),
        ..
    } = decision
    else {
        return None;
    };
    Some(match cause {
        Unskippable::NoDevice(device) => (units, MaskCause::DeviceAbsent, Some(device)),
        Unskippable::Unread => (units, MaskCause::Undetermined, None),
    })
}

/// What the hidden session keeps from starting for `decisions` and every
/// entry of `fstab` the hidden systemd may read: what the decisions mask and
/// skip, and the automount of each entry whose filesystem they put in place
/// themselves, read-only or overlaid (see the module docs), skipped where a
/// boot target requires it and masked otherwise.
///
/// The hidden systemd reads one fstab, but the entry decides several (the
/// decoy's, its entries resolved elsewhere, a hidden generation's), and two
/// of them can disagree about a unit. A unit that one of them masks is
/// masked, and its skip goes: a mask starts nothing, while a skip made for
/// another line could leave a checker of the line the hidden systemd reads
/// free to start. Two skips of the same unit become one, pulling in what
/// either pulls in; when they wait for different devices the unit is masked.
/// A unit a boot target requires that ends up masked is recorded with why
/// ([`KeptOff::required_masks`]).
pub fn runtime_units(fstab: &[FstabEntry], decisions: &[Decision]) -> KeptOff {
    let placed = |file: &Path| {
        decisions.iter().any(|decision| match decision {
            Decision::ReadOnlyBind { target } | Decision::Overlay { target } => target == file,
            _ => false,
        })
    };
    let mut masks: Vec<String> = masked_units(decisions);
    let mut skips: Vec<Skip> = decisions
        .iter()
        .filter_map(Decision::skip)
        .cloned()
        .collect();
    for entry in fstab
        .iter()
        .filter(|entry| entry.is_automount() && placed(&entry.file))
    {
        let automount = automount_unit(&entry.file);
        if required_by(entry).is_some() {
            skips.push(Skip {
                units: vec![automount],
                pulled: Vec::new(),
                device: None,
            });
        } else {
            masks.push(automount);
        }
    }
    let mut kept = KeptOff::default();
    for (units, cause, device) in decisions.iter().filter_map(required_masked) {
        kept.record_masked(units, cause, device);
    }
    let mut merged: Vec<Skip> = Vec::new();
    for skip in skips {
        match merged.iter_mut().find(|other| other.units == skip.units) {
            Some(other) if other.device == skip.device => {
                for unit in skip.pulled {
                    if !other.pulled.contains(&unit) {
                        other.pulled.push(unit);
                    }
                }
            }
            Some(_) => masks.extend(skip.units),
            None => merged.push(skip),
        }
    }
    for unit in masks {
        if !kept.masks.contains(&unit) {
            kept.masks.push(unit);
        }
    }
    for skip in merged {
        if skip.units.iter().any(|unit| kept.masks.contains(unit)) {
            kept.record_masked(&skip.units, MaskCause::ConflictingLines, None);
        } else {
            kept.skips.push(skip);
        }
    }
    kept
}

/// The units the hidden session keeps masked ([`runtime_units`]).
pub fn masks(fstab: &[FstabEntry], decisions: &[Decision]) -> Vec<String> {
    runtime_units(fstab, decisions).masks
}

#[cfg(test)]
#[path = "policy_tests.rs"]
mod tests;
