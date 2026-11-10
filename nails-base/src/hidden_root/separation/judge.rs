// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The judge: the decoy's claims, then the first verdict that matches.

use super::lines::{in_fstab, line_is_mounted, mounts_the_root, sharing};
use super::paths::{is_claimed, names_a_file};
use super::plain::source;
use super::{
    CRYPTTAB, Claimed, DeviceMap, EntryFinding, EntryKind, Extra, FSTAB, FileHolder, Judgement,
    LoopFile, Node, NodeKind, SYSTEM_MOUNTS, Scene, Severity, Sharing, UnplainLine, UntoldPath,
    Untraced, Verdict, is_system_folder,
};
use crate::filesystem::mountinfo::{MountEntry, top_mount_at};
use crate::fstab::FstabEntry;
use crate::hidden_root::mount_holding;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// One piece of the decoy's storage.
struct Claim {
    what: Claimed,
    /// `major:minor` of the mounts of it.
    superblocks: Vec<String>,
    /// The devices it names, with everything below them.
    nodes: BTreeSet<String>,
    /// The devices it names directly, and for a mounted filesystem those it
    /// keeps data on besides the one it is mounted from.
    tops: Vec<String>,
    noauto: bool,
    /// Why what a mounted filesystem keeps data on besides the device it is
    /// mounted from cannot be told, when it cannot.
    unknown: Option<Verdict>,
}

/// Judge where the mount `hidden` (the visible mount at the hidden root)
/// lives, against the decoy's storage in `scene`.
pub fn judge(scene: &Scene<'_>, hidden: &MountEntry) -> Judgement {
    if is_ram(&hidden.fstype) {
        return Judgement {
            verdict: Verdict::Separate,
            entries: Vec::new(),
        };
    }
    let (top, stack) = hidden_stack(scene.devices, hidden);
    let (claims, entries) = claims(scene, hidden, &stack);
    let verdict = if scene.unreadable.is_empty() {
        verdict(scene, hidden, top.as_deref(), &stack, &claims)
    } else {
        Verdict::CouldNotJudge {
            unreadable: scene.unreadable.to_vec(),
        }
    };
    Judgement { verdict, entries }
}

/// The block devices the decoy claims as its own storage when [`judge`]
/// judges `hidden` in `scene`, by kernel name: every device a claim names,
/// and every device below it, each with what of the decoy's storage it holds
/// (the first claim that reaches it). The decoy's entries for the hidden drive
/// claim nothing here either, except an fstab entry the boot mounts or swaps
/// on, one for another device of the root's btrfs filesystem, and a line
/// placed by its path, which claims the filesystem that holds its source or
/// file. A RAM filesystem claims nothing, as the judge follows no device for
/// it.
pub fn claimed_devices(scene: &Scene<'_>, hidden: &MountEntry) -> BTreeMap<String, Claimed> {
    let mut claimed = BTreeMap::new();
    if is_ram(&hidden.fstype) {
        return claimed;
    }
    let (_, stack) = hidden_stack(scene.devices, hidden);
    for claim in claims(scene, hidden, &stack).0 {
        for node in claim.nodes {
            claimed.entry(node).or_insert_with(|| claim.what.clone());
        }
    }
    claimed
}

/// The device `hidden` sits on, and that device with everything below it,
/// into an md array below a partition too, then the same of each device its
/// filesystem keeps data on besides that one (an XFS log, say): the stack the
/// judge walks, and the one the claims are built from.
fn hidden_stack(devices: &DeviceMap, hidden: &MountEntry) -> (Option<String>, Vec<String>) {
    // A stacked filesystem names no device of its own: whatever its source
    // says, its storage is elsewhere.
    let top = (!is_stacked(&hidden.fstype))
        .then(|| devices.node_of_mount(hidden))
        .flatten()
        .map(str::to_string);
    let mut stack = Vec::new();
    for start in starts(devices, hidden, top.as_deref()) {
        for node in devices.full_stack(&start) {
            if !stack.contains(&node) {
                stack.push(node);
            }
        }
    }
    (top, stack)
}

/// Where the root's data starts: `top`, the device `hidden` sits on, and the
/// devices its filesystem keeps data on besides that one. None without `top`.
fn starts(devices: &DeviceMap, hidden: &MountEntry, top: Option<&str>) -> Vec<String> {
    top.map(|top| {
        std::iter::once(top.to_string())
            .chain(devices.extra_devices(hidden).iter().cloned())
            .collect()
    })
    .unwrap_or_default()
}

fn verdict(
    scene: &Scene<'_>,
    hidden: &MountEntry,
    top: Option<&str>,
    stack: &[String],
    claims: &[Claim],
) -> Verdict {
    let devices = scene.devices;
    // What a filesystem of the decoy's keeps data on besides its device must
    // be told to tell what the decoy claims, as its files must be read.
    if let Some(verdict) = claims.iter().find_map(|claim| claim.unknown.clone()) {
        return verdict;
    }
    // Wherever the root's data reaches, the decoy's own storage included:
    // what cannot be followed to the disks that hold it. The override lifts
    // none of that, so it decides before anything that places the root on
    // the decoy's storage, which the override does lift.
    let starts = starts(devices, hidden, top);
    let reach = reach(scene, &starts, &BTreeSet::new());
    let untraced = top
        .and_then(|_| extra_unknown(devices, hidden, NOT_FOUND))
        .or_else(|| untraceable(scene, claims, &reach));
    if let Some(verdict) = untraced {
        return verdict;
    }

    for claim in claims {
        let Claimed::Mount(at) = &claim.what else {
            continue;
        };
        if claim.superblocks.contains(&hidden.dev) {
            return Verdict::OnDecoyFilesystem {
                how: sharing(hidden),
                at: at.clone(),
                in_fstab: in_fstab(scene, hidden, top, at),
            };
        }
        if let Some(top) = top
            && claim
                .tops
                .iter()
                .any(|t| t == top || devices.same_btrfs(t, top))
        {
            return Verdict::OnDecoyFilesystem {
                how: Sharing::Filesystem,
                at: at.clone(),
                in_fstab: in_fstab(scene, hidden, Some(top), at),
            };
        }
    }

    // Every rule below follows the root's device down to what stores it; a
    // root with no device found (an overlay, FUSE, a network filesystem)
    // cannot be followed, so where its writes land cannot be told.
    if top.is_none() {
        return Verdict::UntracedStorage {
            fstype: shown_fstype(&hidden.fstype),
        };
    }

    let sharing: Vec<(&Claim, &String)> = claims
        .iter()
        .filter_map(|claim| {
            stack
                .iter()
                .find(|node| claim.nodes.contains(*node))
                .map(|node| (claim, node))
        })
        .collect();
    // A device only entries the decoy never mounts at boot share only warns,
    // which it says once nothing below refuses.
    let mut by_hand = None;
    if let Some((claim, node)) = sharing.first() {
        let verdict = Verdict::InsideDecoyStorage {
            device: (*node).clone(),
            holds: claim.what.clone(),
            noauto_only: sharing.iter().all(|(claim, _)| claim.noauto),
        };
        if verdict.severity() == Severity::Refuse {
            return verdict;
        }
        by_hand = Some(verdict);
    }

    // An unencrypted image file on a decoy filesystem says where the root's
    // data lands, wherever the device below that filesystem keeps it, so it
    // comes before a disk that a program serves, below it or elsewhere; an
    // encrypted container, which only warns, comes after.
    let images = images_on_decoy(scene, claims, &starts);
    if let Some(image) = images.iter().find(|image| !image.encrypted) {
        return Verdict::ImageFileOnDecoy {
            file: image.file.clone(),
            at: image.at.clone(),
        };
    }

    // A disk that a program serves can keep the root's data in a file on
    // the decoy's disk, and nothing shows whether it does.
    for node in &reach {
        if let Some(Node {
            kind: NodeKind::Served(kind),
            ..
        }) = devices.nodes.get(node)
        {
            return Verdict::ServedDevice { kind: *kind };
        }
    }

    if let Some(container) = images.first() {
        return Verdict::ContainerOnDecoy {
            file: container.file.clone(),
            at: container.at.clone(),
        };
    }
    by_hand.unwrap_or(Verdict::Separate)
}

/// The verdict when the root's data reaches something that cannot be
/// followed to the disks that hold it, `reach` in its order: a device sysfs
/// does not list, a disk whose kind cannot be read or whose data lies on
/// disks nothing here reads (a ZFS volume), a partition whose disk is not
/// found, or an image file whose filesystem cannot be told. `None` when the
/// whole way down can be followed.
fn untraceable(scene: &Scene<'_>, claims: &[Claim], reach: &[String]) -> Option<Verdict> {
    let devices = scene.devices;
    for name in reach {
        let Some(node) = devices.nodes.get(name) else {
            return Some(NOT_FOUND);
        };
        match &node.kind {
            NodeKind::Unidentified(input) => {
                return Some(Verdict::CouldNotJudge {
                    unreadable: vec![input.clone()],
                });
            }
            NodeKind::Untraced(kind) => return Some(Verdict::UntracedDevice { kind: *kind }),
            // That disk could be a loop device over a file anywhere.
            NodeKind::Partition { .. } if devices.on_an_unknown_disk(name) => {
                return Some(Verdict::DiskNotFound);
            }
            NodeKind::Loop {
                file: Some(LoopFile { path, holder }),
            } => {
                let holder = match holding_mount(scene, path, holder) {
                    Ok(holder) => holder,
                    Err(verdict) => return Some(verdict),
                };
                if let Some(verdict) = extra_unknown(devices, holder, NOT_FOUND) {
                    return Some(verdict);
                }
                // An image file on a filesystem that is not the decoy's: that
                // filesystem must itself be on a device that can be traced.
                if claimed_holder(claims, devices, holder).is_none()
                    && !is_ram(&holder.fstype)
                    && untraced(devices, holder)
                {
                    return Some(Verdict::UntracedStorage {
                        fstype: shown_fstype(&holder.fstype),
                    });
                }
            }
            _ => {}
        }
    }
    None
}

/// An image file on a filesystem the decoy claims, as [`images_on_decoy`]
/// finds it.
struct DecoyImage {
    file: PathBuf,
    /// Where the decoy mounts the filesystem that holds it.
    at: PathBuf,
    /// Whether an encrypted mapping over it keeps the root's data encrypted
    /// in the file: a container file.
    encrypted: bool,
}

/// The image files on a filesystem the decoy claims that the root's data
/// reaches from `starts` before it reaches the decoy's own storage, in the
/// order it reaches them: an image file that a filesystem of the decoy's
/// holds lies below that filesystem, and is the decoy's own business.
fn images_on_decoy(scene: &Scene<'_>, claims: &[Claim], starts: &[String]) -> Vec<DecoyImage> {
    let devices = scene.devices;
    let decoys: BTreeSet<String> = claims
        .iter()
        .flat_map(|claim| claim.nodes.iter().cloned())
        .collect();
    let outside = reach(scene, starts, &decoys);
    outside
        .iter()
        .filter_map(|node| {
            let Some(Node {
                kind:
                    NodeKind::Loop {
                        file: Some(LoopFile { path, holder }),
                    },
                ..
            }) = devices.nodes.get(node)
            else {
                return None;
            };
            let at = holding_mount(scene, path, holder)
                .ok()
                .and_then(|holder| claimed_holder(claims, devices, holder))?;
            let encrypted = outside.iter().any(|above| {
                matches!(
                    devices.nodes.get(above).map(|n| &n.kind),
                    Some(NodeKind::Crypt { .. })
                ) && devices.full_stack(above).contains(node)
            });
            Some(DecoyImage {
                file: path.clone(),
                at,
                encrypted,
            })
        })
        .collect()
}

/// The mount of the filesystem that holds the image file `file`, by the
/// device the loop driver recorded, never by where its path leads today; the
/// verdict when that cannot be told.
fn holding_mount<'a>(
    scene: &Scene<'a>,
    file: &Path,
    holder: &FileHolder,
) -> Result<&'a MountEntry, Verdict> {
    let mount = match holder {
        FileHolder::Unreadable(path) => {
            return Err(Verdict::CouldNotJudge {
                unreadable: vec![path.clone()],
            });
        }
        FileHolder::Mount(dev) => scene.mounts.iter().find(|m| &m.dev == dev),
        FileHolder::Unplaced => None,
    };
    mount.ok_or_else(|| Verdict::UnplacedImageFile {
        file: file.to_path_buf(),
    })
}

/// Every device the root's data reaches from `starts` (see [`starts`]), in
/// their order and each once: the devices below each as the full stack goes,
/// every other device of a btrfs filesystem among them, and below a loop
/// device over a file the devices of the filesystem that holds the file, as
/// the loop driver recorded it, the decoy's own filesystems included. The
/// reach goes into no device of `stops`. It needs no bound: the map holds
/// the devices sysfs lists, and each is gone into once.
pub(super) fn reach(scene: &Scene<'_>, starts: &[String], stops: &BTreeSet<String>) -> Vec<String> {
    let devices = scene.devices;
    let mut seen = BTreeSet::new();
    let mut reached = Vec::new();
    let mut pending: Vec<String> = starts.iter().rev().cloned().collect();
    while let Some(next) = pending.pop() {
        if stops.contains(&next) || !seen.insert(next.clone()) {
            continue;
        }
        let mut below = devices.below(&next, true);
        below.extend(
            devices
                .btrfs
                .iter()
                .filter(|members| members.contains(&next))
                .flatten()
                .cloned(),
        );
        below.extend(holding_devices(scene, &next));
        reached.push(next);
        pending.extend(below.into_iter().rev());
    }
    reached
}

/// The devices of the filesystem that holds the image file of the loop
/// device `name`, as the loop driver recorded it: the one it is mounted from
/// and those it keeps data on besides; none for a filesystem stacked on
/// others or on no device here, which the judge cannot follow.
fn holding_devices(scene: &Scene<'_>, name: &str) -> Vec<String> {
    let Some(Node {
        kind:
            NodeKind::Loop {
                file:
                    Some(LoopFile {
                        holder: FileHolder::Mount(dev),
                        ..
                    }),
            },
        ..
    }) = scene.devices.nodes.get(name)
    else {
        return Vec::new();
    };
    let Some(holder) = scene
        .mounts
        .iter()
        .find(|m| &m.dev == dev)
        .filter(|m| !is_stacked(&m.fstype))
    else {
        return Vec::new();
    };
    let top = scene.devices.node_of_mount(holder);
    starts(scene.devices, holder, top)
}

/// The verdict of a root whose data reaches a device that cannot be found.
const NOT_FOUND: Verdict = Verdict::UntracedDevice {
    kind: Untraced::NotFound,
};

/// The verdict when what the filesystem mounted as `mount` keeps data on
/// besides the device it is mounted from cannot be told: an input could not
/// be read, or it names a device that cannot be found (`not_found`).
fn extra_unknown(devices: &DeviceMap, mount: &MountEntry, not_found: Verdict) -> Option<Verdict> {
    match devices.extra.get(&mount.dev)? {
        Extra::Devices(_) => None,
        Extra::Unreadable(input) => Some(Verdict::CouldNotJudge {
            unreadable: vec![input.clone()],
        }),
        Extra::NotFound => Some(not_found),
    }
}

/// Whether `fstype` is a RAM filesystem, which keeps nothing on a disk.
pub(super) fn is_ram(fstype: &str) -> bool {
    matches!(fstype, "tmpfs" | "ramfs")
}

/// Whether `fstype` is stacked on other filesystems or on a process (an
/// overlay, an encrypting stack, FUSE), so a device in its source names
/// nothing it stores data on. `fuseblk` sits on a block device of its own.
fn is_stacked(fstype: &str) -> bool {
    matches!(fstype, "overlay" | "aufs" | "ecryptfs" | "fuse") || fstype.starts_with("fuse.")
}

/// Whether nothing shows on which block device `mount` stores its data.
fn untraced(devices: &DeviceMap, mount: &MountEntry) -> bool {
    is_stacked(&mount.fstype) || devices.node_of_mount(mount).is_none()
}

/// The filesystem type to show the operator: a FUSE subtype can name the
/// program behind it, so only "fuse" is shown.
pub fn shown_fstype(fstype: &str) -> String {
    if fstype.starts_with("fuse.") {
        "fuse".to_string()
    } else {
        fstype.to_string()
    }
}

/// Where the decoy mounts the filesystem of `holder`, if it is claimed.
fn claimed_holder(claims: &[Claim], devices: &DeviceMap, holder: &MountEntry) -> Option<PathBuf> {
    let node = devices.node_of_mount(holder);
    claims.iter().find_map(|claim| match &claim.what {
        Claimed::Mount(at)
            if claim.superblocks.contains(&holder.dev)
                || node.is_some_and(|n| claim.tops.iter().any(|t| t == n)) =>
        {
            Some(at.clone())
        }
        _ => None,
    })
}

/// The decoy's claims, and its entries for the hidden drive.
fn claims(
    scene: &Scene<'_>,
    hidden: &MountEntry,
    stack: &[String],
) -> (Vec<Claim>, Vec<EntryFinding>) {
    let devices = scene.devices;
    let mut claims = Vec::new();
    let mut entries = Vec::new();
    // The root's own filesystem: the device it is mounted from and every
    // other device of its btrfs filesystem, each of which holds the volume.
    let top = stack.first().map(String::as_str);
    let members = btrfs_members(devices, top);
    let own_device = |node: &str| top == Some(node) || members.iter().any(|m| m.as_str() == node);
    // An entry is for the hidden drive when it names a device of the root's
    // stack, or another device of its btrfs filesystem or one below that.
    let entry_stack = &with_stacks_of(devices, stack, &members)[..];

    let root_mount = top_mount_at(scene.mounts, Path::new("/"));
    let system = SYSTEM_MOUNTS.iter().filter_map(|point| {
        let point = Path::new(point);
        (!point.starts_with(&hidden.mount_point))
            .then(|| top_mount_at(scene.mounts, point))
            .flatten()
    });
    // Whether the decoy itself uses the root's own filesystem: it is mounted
    // at / or at a system folder, or a line the boot needs mounts it. A
    // crypttab line that opens a device of it is then one the boot needs.
    let mut own_needed = false;
    for mount in root_mount.into_iter().chain(system) {
        own_needed |=
            mount.dev == hidden.dev || devices.node_of_mount(mount).is_some_and(own_device);
        claims.push(mount_claim(scene, mount, false));
    }

    let stack_names: Vec<&str> = stack
        .iter()
        .filter_map(|n| devices.nodes.get(n).and_then(Node::dm_name))
        .collect();
    let entry_names: Vec<&str> = entry_stack
        .iter()
        .filter_map(|n| devices.nodes.get(n).and_then(Node::dm_name))
        .collect();

    for (index, entry) in scene.fstab.iter().enumerate() {
        // The findings for this line, and whether one of them makes the
        // root's own filesystem one the decoy's boot needs.
        let mut found = Vec::new();
        let mut needs_own = false;
        'line: {
            if !is_claimed(entry) {
                break 'line;
            }
            // The device or path the line names: a FUSE line's by the source
            // it gives its program.
            let spec = source(entry);
            let node = spec.and_then(|spec| devices.node_of_spec(spec));
            if let Some(node) = node.filter(|n| entry_stack.iter().any(|s| s == n)) {
                let finding = fstab_finding(scene, hidden, entry, own_device(node));
                needs_own = own_device(node) && finding.boot_needs;
                found.push(finding);
                // An entry the boot mounts (or swaps on) makes the device
                // the decoy's own storage as well; only a `noauto` one is a
                // mere recipe for the hidden drive. One that names only
                // another device of the root's btrfs filesystem claims it all
                // the same.
                if entry.is_noauto() && stack.iter().any(|s| s == node) {
                    break 'line;
                }
            }
            let noauto = entry.is_noauto();
            if let Some(spec) =
                spec.filter(|_| entry.is_bind() || (node.is_none() && names_a_file(entry)))
            {
                // A bind, or a swap or image file or the file a FUSE program
                // reads: the filesystem holding the source or the file, read
                // as written, with no link followed. A bind of the volume or
                // of a folder of it mounts the volume, and a file in the
                // volume lies on it. A path whose place cannot be told may
                // lead anywhere, the volume included: a finding, which claims
                // the filesystem its text places it on.
                let source = match scene.named_path(spec) {
                    Ok(source) => Some(source),
                    Err(why) => {
                        found.push(untold_finding(entry, &why));
                        None
                    }
                };
                let path = source.unwrap_or(Path::new(spec));
                if let Some(holder) = mount_holding(scene.mounts, path) {
                    if let Some(source) = source {
                        found.extend(in_volume_finding(hidden, entry, source, holder));
                    }
                    claims.push(mount_claim(scene, holder, noauto));
                }
                break 'line;
            }
            // What the boot mounted at the entry's mount point is the
            // decoy's, whether or not its spec leads to a device here (a
            // label with an escaped space, a missing udev link).
            if !entry.is_swap()
                && !noauto
                && !entry.file.starts_with(&hidden.mount_point)
                && let Some(live) = top_mount_at(scene.mounts, &entry.file)
            {
                claims.push(mount_claim(scene, live, false));
            }
            let what = if entry.is_swap() {
                Claimed::Swap(entry.spec.clone())
            } else {
                Claimed::Mount(entry.file.clone())
            };
            claims.push(device_claim(
                scene,
                what,
                node.into_iter().map(str::to_string).collect(),
                noauto,
            ));
        }
        // A line that is not plain claims what NAILS reads in it, and is a
        // finding of its own, its only one: what it mounts cannot be told.
        match scene.unplain.get(&index) {
            Some(line) => entries.push(not_plain_finding(FSTAB, line)),
            None => {
                own_needed |= needs_own;
                entries.append(&mut found);
            }
        }
    }

    // Where the decoy mounts another part of the filesystem a folder or a
    // subvolume root is part of at / or at a system folder, if it does, by
    // its mount at / or by one of the fstab findings, all entries so far.
    let own_place = decoys_own_place(scene, hidden, &entries);
    let drive = Drive {
        stack,
        entry_stack,
        stack_names: &stack_names,
        entry_names: &entry_names,
        own_device: &own_device,
    };
    crypttab_claims(
        scene,
        hidden,
        &drive,
        own_needed,
        own_place.as_deref(),
        &mut claims,
        &mut entries,
    );
    (claims, entries)
}

/// The hidden root's devices, by which the entries for the hidden drive are
/// told.
struct Drive<'a> {
    /// The root's stack: the device it is mounted from and every device
    /// below it.
    stack: &'a [String],
    /// The devices an entry for the hidden drive names: the root's stack,
    /// the other devices of its btrfs filesystem and those below them.
    entry_stack: &'a [String],
    /// The names of the mappings in `stack`.
    stack_names: &'a [&'a str],
    /// The names of the mappings in `entry_stack`.
    entry_names: &'a [&'a str],
    /// Whether a device is the one the root is mounted from, or another
    /// device of its btrfs filesystem.
    own_device: &'a dyn Fn(&str) -> bool,
}

/// The claims of the decoy's crypttab lines and their entries for the hidden
/// drive `drive`, added to `claims` and `entries`, which hold those of its
/// mounts and its fstab. `own_needed` tells whether the decoy itself uses
/// the root's own filesystem, and `own_place` where it mounts another part
/// of it at `/` or at a system folder, if it does.
fn crypttab_claims(
    scene: &Scene<'_>,
    hidden: &MountEntry,
    drive: &Drive<'_>,
    own_needed: bool,
    own_place: Option<&Path>,
    claims: &mut Vec<Claim>,
    entries: &mut Vec<EntryFinding>,
) {
    let devices = scene.devices;
    let Drive {
        stack,
        entry_stack,
        stack_names,
        entry_names,
        own_device,
    } = *drive;
    for (index, entry) in scene.crypttab.iter().enumerate() {
        let line = format!("{} {}", entry.name, entry.source);
        let source = devices.node_of_spec(&entry.source);
        let mapping = devices.node_of_spec(&format!("/dev/mapper/{}", entry.name));
        let opens = |within: &[String], names: &[&str]| {
            names.contains(&entry.name.as_str())
                || [source, mapping]
                    .iter()
                    .any(|n| n.is_some_and(|n| within.iter().any(|s| s == n)))
        };
        // It makes a device the root's own filesystem lies on, which the
        // decoy may use itself: the mapping it lies on, or one opened from a
        // device below the one it is mounted from. Or it opens a device
        // below another filesystem of the decoy's.
        let makes_own = mapping.is_some_and(|m| entry_stack.iter().any(|s| s == m))
            || entry_names.contains(&entry.name.as_str())
            || source.is_some_and(|s| entry_stack.iter().any(|n| n == s) && !own_device(s));
        let needed = (own_needed && makes_own)
            || boot_needs(devices, claims, hidden, own_device, [source, mapping]);
        // The findings for this line, and whether it claims what it opens.
        let mut found = Vec::new();
        let claimed = 'line: {
            // A line that opens the hidden volume of a container blocks when
            // the container is on the hidden drive, or when its device cannot
            // be found, so nothing shows it is not; one for another drive is
            // that drive's business, and claims it like any other line. The
            // decoy's own boot can need it all the same, where one of its
            // filesystems lies on what it opens.
            if entry.is_tcrypt_hidden()
                && source
                    .is_none_or(|s| stack.iter().any(|n| n == s) || same_drive(devices, s, stack))
            {
                found.push(blocking(
                    CRYPTTAB,
                    line,
                    "it opens the hidden volume of a TrueCrypt or VeraCrypt container".to_string(),
                    needed,
                ));
                break 'line false;
            }
            if opens(entry_stack, entry_names) {
                let why = if entry.is_tcrypt() {
                    format!(
                        "it opens the device the volume at {} is opened from; whether that is \
                         the outer or the hidden volume cannot be told",
                        hidden.mount_point.display()
                    )
                } else {
                    format!(
                        "it opens the volume at {} or a device it is stored on",
                        hidden.mount_point.display()
                    )
                };
                // A line the boot opens that makes a device of that
                // filesystem, while the decoy mounts another part of it at /
                // or at a system folder, is the decoy's own line for that
                // place too. Never one that opens the hidden volume of a
                // container, whatever it names.
                let own = makes_own && !entry.has_option("noauto") && !entry.is_tcrypt_hidden();
                let system_folder = own_place.filter(|_| own).map(Path::to_path_buf);
                found.push(EntryFinding {
                    system_folder,
                    ..blocking(CRYPTTAB, line, why, needed)
                });
                // One that opens only another device of the root's btrfs
                // filesystem claims it all the same.
                break 'line !opens(stack, stack_names);
            }
            if entry.is_tcrypt() && source.is_some_and(|s| same_drive(devices, s, stack)) {
                found.push(outer_warning(line));
                break 'line false;
            }
            true
        };
        // A line that is not plain claims what NAILS reads in it, and is a
        // finding of its own, its only one: what it opens cannot be told.
        match scene.unplain_crypttab.get(&index) {
            Some(unplain) => entries.push(not_plain_finding(CRYPTTAB, unplain)),
            None => entries.append(&mut found),
        }
        if claimed {
            let tops: Vec<String> = source
                .into_iter()
                .chain(mapping)
                .map(str::to_string)
                .collect();
            claims.push(device_claim(
                scene,
                Claimed::Encrypted(entry.name.clone()),
                tops,
                entry.has_option("noauto"),
            ));
        }
    }
}

/// The warning for the crypttab line that reads `line`, which opens a
/// TrueCrypt or VeraCrypt volume on the hidden volume's drive other than the
/// device the volume is opened from.
fn outer_warning(line: String) -> EntryFinding {
    EntryFinding {
        kind: EntryKind::OuterWarning,
        file: CRYPTTAB,
        line,
        why: "the decoy is configured to open storage on this drive".to_string(),
        boot_needs: false,
        system_folder: None,
        not_plain: false,
    }
}

/// The other devices of the btrfs filesystem that the device `top` is one
/// of.
fn btrfs_members<'a>(devices: &'a DeviceMap, top: Option<&str>) -> Vec<&'a String> {
    let Some(top) = top else {
        return Vec::new();
    };
    devices
        .btrfs
        .iter()
        .filter(|members| members.contains(top))
        .flatten()
        .filter(|member| member.as_str() != top)
        .collect()
}

/// `stack`, then each device below `members` that it does not hold yet.
fn with_stacks_of(devices: &DeviceMap, stack: &[String], members: &[&String]) -> Vec<String> {
    let mut all = stack.to_vec();
    for member in members {
        for node in devices.full_stack(member) {
            if !all.contains(&node) {
                all.push(node);
            }
        }
    }
    all
}

/// Where the decoy itself mounts another part of the filesystem of `hidden`
/// (the visible mount at the hidden root) than the volume, at `/` or at a
/// system folder: `/` when the decoy's mount there is of that filesystem and
/// its root lies outside the volume's folder, as the filesystem's top or a
/// subvolume above or beside the volume's does, else the folder of the first
/// of the fstab findings `fstab` that is the decoy's own line for one
/// ([`EntryFinding::system_folder`]). `None` where the decoy mounts no other
/// part of it so, as for a volume that is the whole filesystem: its folder is
/// the top, which every mount of the filesystem lies in, and no fstab line
/// for it is the decoy's own.
fn decoys_own_place(
    scene: &Scene<'_>,
    hidden: &MountEntry,
    fstab: &[EntryFinding],
) -> Option<PathBuf> {
    let at_root = top_mount_at(scene.mounts, Path::new("/"))
        .is_some_and(|mount| mount.dev == hidden.dev && !mount.root.starts_with(&hidden.root));
    if at_root {
        return Some(PathBuf::from("/"));
    }
    fstab.iter().find_map(|entry| entry.system_folder.clone())
}

/// The finding for the fstab line `entry` for the hidden drive, `own` when
/// it names a device of the root's own filesystem rather than one below it.
fn fstab_finding(
    scene: &Scene<'_>,
    hidden: &MountEntry,
    entry: &FstabEntry,
    own: bool,
) -> EntryFinding {
    let line = shown(entry);
    let root = hidden.mount_point.display();
    let elsewhere = !entry.file.starts_with(&hidden.mount_point);
    // What of the root's own filesystem the line mounts: the volume, or
    // another part of the filesystem the root is part of.
    let root_itself = if own {
        mounts_the_root(scene, entry, hidden)
    } else {
        None
    };
    // A line for the root's own filesystem that mounts it at another place,
    // while the root shows only a folder or a subvolume of it (a bind of a
    // folder of /, say), mounts the filesystem the root is part of, not the
    // volume alone, unless it mounts the root's own subvolume or one inside
    // it.
    let part_of = own && elsewhere && !entry.is_swap() && root_itself != Some(true);
    let why = if part_of {
        format!("it mounts the filesystem the volume at {root} is part of")
    } else if own {
        format!("it mounts the volume at {root}")
    } else {
        format!("it mounts a device the volume at {root} is stored on")
    };
    // A line for the root's own filesystem at / or at a system folder that
    // the boot mounts (no noauto) is one the decoy's boot needs, whatever it
    // mounts of that filesystem, the volume too: never one to remove. A
    // noauto one is a recipe for the hidden drive, and goes.
    let system = own && !entry.is_swap() && is_system_folder(&entry.file, &hidden.mount_point);
    // A line the boot mounts outside the hidden root, for a device below the
    // volume or for the filesystem the root is part of, mounts one of the
    // decoy's own filesystems or its swap, and so does one the boot mounts at
    // / or at a system folder.
    let boot_needs = !entry.is_noauto()
        && if own {
            part_of || system
        } else {
            entry.is_swap() || elsewhere
        };
    // The decoy's own line for such a folder mounts another part of the
    // filesystem the root is a folder or a subvolume of, and its mount is
    // there: never the volume itself, never a line whose subvolume cannot be
    // told, and never one whose mount is not there now, since nothing then
    // shows that the decoy uses that filesystem there.
    let system_folder = (system
        && !entry.is_noauto()
        && root_itself == Some(false)
        && line_is_mounted(scene, entry, hidden))
    .then(|| entry.file.clone());
    EntryFinding {
        system_folder,
        ..blocking(FSTAB, line, why, boot_needs)
    }
}

/// The finding for the fstab line `entry`, a bind line or a swap or image
/// file line, whose path reads as `path` on the mount `holder`, when that
/// path lies in the volume of `hidden` (the visible mount at the hidden
/// root): at the volume's folder of that filesystem or inside it, as `holder`
/// shows it now. A bind line then mounts the volume or a folder of it, and a
/// swap or image line names a file in the volume, which the boot swaps on or
/// mounts. It goes as any line does that names the volume itself, unless the
/// boot mounts it at `/` or at a system folder, and it is never the decoy's
/// own line.
fn in_volume_finding(
    hidden: &MountEntry,
    entry: &FstabEntry,
    path: &Path,
    holder: &MountEntry,
) -> Option<EntryFinding> {
    let below = path.strip_prefix(&holder.mount_point).ok()?;
    let folder = holder.root.join(below);
    if holder.dev != hidden.dev || !folder.starts_with(&hidden.root) {
        return None;
    }
    let root = hidden.mount_point.display();
    let why = if !entry.is_bind() {
        format!("the file it names lies in the volume at {root}")
    } else if folder == hidden.root {
        format!("it mounts the volume at {root}")
    } else {
        format!("it mounts a folder of the volume at {root}")
    };
    let boot_needs = !entry.is_noauto() && is_system_folder(&entry.file, &hidden.mount_point);
    Some(blocking(FSTAB, shown(entry), why, boot_needs))
}

/// The finding for the fstab line `entry`, a bind line or a swap or image
/// file line, whose path cannot be told (`why`): it may lead anywhere, the
/// volume included, which cannot be told.
fn untold_finding(entry: &FstabEntry, why: &UntoldPath) -> EntryFinding {
    let what = if entry.is_bind() {
        "its source lies"
    } else {
        "the file it names lies"
    };
    EntryFinding {
        kind: EntryKind::Untold,
        file: FSTAB,
        line: shown(entry),
        why: format!("where {what} cannot be told: {}", why.reason()),
        boot_needs: false,
        system_folder: None,
        not_plain: false,
    }
}

/// The finding for `line`, a line of `file`, the fstab or the crypttab,
/// that is not plain: NAILS does not read it as `libmount` and systemd do,
/// so it may open or mount the volume, and what it opens or mounts cannot be
/// told.
fn not_plain_finding(file: &'static str, line: &UnplainLine) -> EntryFinding {
    EntryFinding {
        kind: EntryKind::Untold,
        file,
        line: line.shown.clone(),
        why: format!("NAILS reads only plain lines, and {}", line.reason()),
        boot_needs: false,
        system_folder: None,
        not_plain: true,
    }
}

/// The fstab line `entry`, as its first fields read.
fn shown(entry: &FstabEntry) -> String {
    format!("{} {} {}", entry.spec, entry.file.display(), entry.vfstype)
}

fn blocking(file: &'static str, line: String, why: String, boot_needs: bool) -> EntryFinding {
    EntryFinding {
        kind: EntryKind::Blocking,
        file,
        line,
        why,
        boot_needs,
        system_folder: None,
        not_plain: false,
    }
}

/// Whether the decoy's boot needs a volume opened from or as one of `named`:
/// it lies below the decoy's root, another filesystem its boot mounts or its
/// swap, as far down as their data goes (into an md array too, which the boot
/// assembles from it). A mount of the hidden volume's own filesystem, a
/// device `own_device` names, at the hidden root or elsewhere, is no such
/// need here: the judge counts the decoy's own use of it apart.
fn boot_needs(
    devices: &DeviceMap,
    claims: &[Claim],
    hidden: &MountEntry,
    own_device: &dyn Fn(&str) -> bool,
    named: [Option<&str>; 2],
) -> bool {
    claims
        .iter()
        .filter(|claim| !claim.noauto && !claim.tops.iter().any(|t| own_device(t)))
        .filter(|claim| match &claim.what {
            Claimed::Mount(at) => !at.starts_with(&hidden.mount_point),
            Claimed::Swap(_) => true,
            Claimed::Encrypted(_) => false,
        })
        .flat_map(|claim| claim.tops.iter().flat_map(|top| devices.full_stack(top)))
        .any(|node| named.contains(&Some(node.as_str())))
}

/// Whether the device `node` is on a disk the hidden stack also uses.
fn same_drive(devices: &DeviceMap, node: &str, stack: &[String]) -> bool {
    let disk_of = |name: &str| match devices.nodes.get(name).map(|n| &n.kind) {
        Some(NodeKind::Partition { disk }) => Some(disk.clone()),
        Some(
            NodeKind::Disk
            | NodeKind::Served(_)
            | NodeKind::Untraced(_)
            | NodeKind::Unidentified(_),
        ) => Some(name.to_string()),
        _ => None,
    };
    let disks: BTreeSet<String> = stack.iter().filter_map(|n| disk_of(n)).collect();
    devices
        .stack(node)
        .iter()
        .filter_map(|n| disk_of(n))
        .any(|disk| disks.contains(&disk))
}

/// A claim on a live mount: its superblock, its device and the devices its
/// filesystem keeps data on besides that one.
fn mount_claim(scene: &Scene<'_>, mount: &MountEntry, noauto: bool) -> Claim {
    let top = scene.devices.node_of_mount(mount);
    let mut claim = device_claim(
        scene,
        Claimed::Mount(mount.mount_point.clone()),
        starts(scene.devices, mount, top),
        noauto,
    );
    if !claim.superblocks.contains(&mount.dev) {
        claim.superblocks.push(mount.dev.clone());
    }
    claim.unknown =
        top.and_then(|_| extra_unknown(scene.devices, mount, Verdict::ClaimedDeviceNotFound));
    claim
}

/// A claim on devices: everything below them, and the mounts of them.
fn device_claim(scene: &Scene<'_>, what: Claimed, tops: Vec<String>, noauto: bool) -> Claim {
    let devices = scene.devices;
    let nodes: BTreeSet<String> = tops.iter().flat_map(|t| devices.stack(t)).collect();
    let superblocks = scene
        .mounts
        .iter()
        .filter(|m| {
            devices
                .node_of_mount(m)
                .is_some_and(|n| tops.iter().any(|t| t == n))
        })
        .map(|m| m.dev.clone())
        .collect();
    Claim {
        what,
        superblocks,
        nodes,
        tops,
        noauto,
        unknown: None,
    }
}
