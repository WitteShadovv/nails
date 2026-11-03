// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The judge: the decoy's claims, then the first verdict that matches.

use super::{
    CRYPTTAB, Claimed, DeviceMap, EntryFinding, EntryKind, FSTAB, FileHolder, Judgement, LoopFile,
    Node, NodeKind, SYSTEM_MOUNTS, Scene, Severity, Sharing, Untraced, Verdict,
};
use crate::filesystem::mountinfo::{MountEntry, top_mount_at};
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
    /// The devices it names directly.
    tops: Vec<String>,
    noauto: bool,
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
/// claim nothing here either, except an fstab entry the boot mounts. A RAM
/// filesystem claims nothing, as the judge follows no device for it.
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
/// into an md array below a partition too: the stack the judge walks, and
/// the one the claims are built from.
fn hidden_stack(devices: &DeviceMap, hidden: &MountEntry) -> (Option<String>, Vec<String>) {
    // A stacked filesystem names no device of its own: whatever its source
    // says, its storage is elsewhere.
    let top = (!is_stacked(&hidden.fstype))
        .then(|| devices.node_of_mount(hidden))
        .flatten()
        .map(str::to_string);
    let stack = top
        .as_deref()
        .map(|t| devices.full_stack(t))
        .unwrap_or_default();
    (top, stack)
}

fn verdict(
    scene: &Scene<'_>,
    hidden: &MountEntry,
    top: Option<&str>,
    stack: &[String],
    claims: &[Claim],
) -> Verdict {
    let devices = scene.devices;
    // Wherever the root's data reaches, the decoy's own storage included:
    // what cannot be followed to the disks that hold it. The override lifts
    // none of that, so it decides before anything that places the root on
    // the decoy's storage, which the override does lift.
    let reach = reach(scene, stack, &BTreeSet::new());
    if let Some(verdict) = untraceable(scene, claims, &reach) {
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
    let images = images_on_decoy(scene, claims, stack);
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
            return Some(Verdict::UntracedDevice {
                kind: Untraced::NotFound,
            });
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
/// reaches from `stack` before it reaches the decoy's own storage, in the
/// order it reaches them: an image file that a filesystem of the decoy's
/// holds lies below that filesystem, and is the decoy's own business.
fn images_on_decoy(scene: &Scene<'_>, claims: &[Claim], stack: &[String]) -> Vec<DecoyImage> {
    let devices = scene.devices;
    let decoys: BTreeSet<String> = claims
        .iter()
        .flat_map(|claim| claim.nodes.iter().cloned())
        .collect();
    let outside = reach(scene, stack, &decoys);
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

/// Every device the root's data reaches from `stack`, the hidden stack, its
/// top first and each once: the devices below each as the full stack goes,
/// every other device of a btrfs filesystem among them, and below a loop
/// device over a file the device of the filesystem that holds the file, as
/// the loop driver recorded it, the decoy's own filesystems included. The
/// reach goes into no device of `stops`. It needs no bound: the map holds
/// the devices sysfs lists, and each is gone into once.
pub(super) fn reach(scene: &Scene<'_>, stack: &[String], stops: &BTreeSet<String>) -> Vec<String> {
    let devices = scene.devices;
    let mut seen = BTreeSet::new();
    let mut reached = Vec::new();
    let mut pending: Vec<String> = stack.first().into_iter().cloned().collect();
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
        below.extend(holding_device(scene, &next));
        reached.push(next);
        pending.extend(below.into_iter().rev());
    }
    reached
}

/// The device of the filesystem that holds the image file of the loop device
/// `name`, as the loop driver recorded it; none for a filesystem stacked on
/// others or on no device here, which the judge cannot follow.
fn holding_device(scene: &Scene<'_>, name: &str) -> Option<String> {
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
        return None;
    };
    scene
        .mounts
        .iter()
        .find(|m| &m.dev == dev)
        .filter(|m| !is_stacked(&m.fstype))
        .and_then(|m| scene.devices.node_of_mount(m))
        .map(str::to_string)
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

/// How a mount on a claimed filesystem was made: its root inside the
/// filesystem tells a bind of a folder from the filesystem itself, and on
/// btrfs a subvolume (`subvol=` names the mount's root) from a bind.
fn sharing(hidden: &MountEntry) -> Sharing {
    let root = hidden.root.to_string_lossy();
    if root == "/" {
        return Sharing::Filesystem;
    }
    let subvol = hidden
        .super_opts
        .split(',')
        .chain(hidden.mount_opts.split(','))
        .find_map(|opt| opt.strip_prefix("subvol="));
    if hidden.fstype == "btrfs" && subvol == Some(root.as_ref()) {
        Sharing::Subvolume
    } else {
        Sharing::Bind
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

    let root_mount = top_mount_at(scene.mounts, Path::new("/"));
    let system = SYSTEM_MOUNTS.iter().filter_map(|point| {
        let point = Path::new(point);
        (!point.starts_with(&hidden.mount_point))
            .then(|| top_mount_at(scene.mounts, point))
            .flatten()
    });
    for mount in root_mount.into_iter().chain(system) {
        claims.push(mount_claim(scene, mount, false));
    }

    let hidden_names: Vec<&str> = stack
        .iter()
        .filter_map(|n| devices.nodes.get(n).and_then(Node::dm_name))
        .collect();

    for entry in scene.fstab {
        if entry.is_virtual()
            || entry.is_host_share()
            || entry.is_network()
            || entry.vfstype == "overlay"
        {
            continue;
        }
        let line = format!("{} {} {}", entry.spec, entry.file.display(), entry.vfstype);
        let node = devices.node_of_spec(&entry.spec);
        if let Some(node) = node.filter(|n| stack.iter().any(|s| s == n)) {
            let own = Some(node) == stack.first().map(String::as_str);
            let why = if own {
                format!("it mounts the volume at {}", hidden.mount_point.display())
            } else {
                format!(
                    "it mounts a device the volume at {} is stored on",
                    hidden.mount_point.display()
                )
            };
            // A line the boot mounts for a device below the volume, outside
            // the hidden root, mounts one of the decoy's own filesystems or
            // its swap.
            let boot_needs = !own
                && !entry.is_noauto()
                && (entry.is_swap() || !entry.file.starts_with(&hidden.mount_point));
            entries.push(blocking(FSTAB, line, why, boot_needs));
            // An entry the boot mounts (or swaps on) makes the device the
            // decoy's own storage as well; only a `noauto` one is a mere
            // recipe for the hidden drive.
            if entry.is_noauto() {
                continue;
            }
        }
        let noauto = entry.is_noauto();
        let file_spec = entry.spec.starts_with('/') && !entry.spec.starts_with("/dev/");
        if entry.is_bind() || (node.is_none() && file_spec) {
            // A bind, or a swap file: the filesystem holding the source.
            if let Some(holder) = mount_holding(scene.mounts, Path::new(&entry.spec)) {
                claims.push(mount_claim(scene, holder, noauto));
            }
            continue;
        }
        // What the boot mounted at the entry's mount point is the decoy's,
        // whether or not its spec leads to a device here (a label with an
        // escaped space, a missing udev link).
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

    for entry in scene.crypttab {
        let line = format!("{} {}", entry.name, entry.source);
        let source = devices.node_of_spec(&entry.source);
        let mapping = devices.node_of_spec(&format!("/dev/mapper/{}", entry.name));
        let in_stack = |n: &Option<&str>| n.is_some_and(|n| stack.iter().any(|s| s == n));
        // A line that opens the hidden volume of a container blocks when the
        // container is on the hidden drive, or when its device cannot be
        // found, so nothing shows it is not; one for another drive is that
        // drive's business, and claims it like any other line.
        if entry.is_tcrypt_hidden()
            && source.is_none_or(|s| stack.iter().any(|n| n == s) || same_drive(devices, s, stack))
        {
            entries.push(blocking(
                CRYPTTAB,
                line,
                "it opens the hidden volume of a TrueCrypt or VeraCrypt container".to_string(),
                false,
            ));
            continue;
        }
        if hidden_names.contains(&entry.name.as_str()) || in_stack(&source) || in_stack(&mapping) {
            let why = if entry.is_tcrypt() {
                format!(
                    "it opens the device the volume at {} is opened from; whether that is the \
                     outer or the hidden volume cannot be told",
                    hidden.mount_point.display()
                )
            } else {
                format!(
                    "it opens the volume at {} or a device it is stored on",
                    hidden.mount_point.display()
                )
            };
            let boot_needs = boot_needs(devices, &claims, hidden, stack, [source, mapping]);
            entries.push(blocking(CRYPTTAB, line, why, boot_needs));
            continue;
        }
        if entry.is_tcrypt() && source.is_some_and(|s| same_drive(devices, s, stack)) {
            entries.push(EntryFinding {
                kind: EntryKind::OuterWarning,
                file: CRYPTTAB,
                line,
                why: "the decoy is configured to open storage on this drive".to_string(),
                boot_needs: false,
            });
            continue;
        }
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
    (claims, entries)
}

fn blocking(file: &'static str, line: String, why: String, boot_needs: bool) -> EntryFinding {
    EntryFinding {
        kind: EntryKind::Blocking,
        file,
        line,
        why,
        boot_needs,
    }
}

/// Whether the decoy's boot needs a volume opened from or as one of `named`:
/// it lies below the decoy's root, another filesystem its boot mounts or its
/// swap, as far down as their data goes (into an md array too, which the boot
/// assembles from it). A mount of the hidden volume itself, at the hidden
/// root or elsewhere, is no such need.
fn boot_needs(
    devices: &DeviceMap,
    claims: &[Claim],
    hidden: &MountEntry,
    stack: &[String],
    named: [Option<&str>; 2],
) -> bool {
    claims
        .iter()
        .filter(|claim| !claim.noauto && !claim.tops.iter().any(|t| stack.first() == Some(t)))
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

/// A claim on a live mount: its superblock and its device.
fn mount_claim(scene: &Scene<'_>, mount: &MountEntry, noauto: bool) -> Claim {
    let tops: Vec<String> = scene
        .devices
        .node_of_mount(mount)
        .into_iter()
        .map(str::to_string)
        .collect();
    let mut claim = device_claim(
        scene,
        Claimed::Mount(mount.mount_point.clone()),
        tops,
        noauto,
    );
    if !claim.superblocks.contains(&mount.dev) {
        claim.superblocks.push(mount.dev.clone());
    }
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
    }
}
