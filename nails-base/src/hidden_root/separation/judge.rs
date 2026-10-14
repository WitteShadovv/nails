// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The judge: the decoy's claims, then the first verdict that matches.

use super::{
    CRYPTTAB, Claimed, DeviceMap, EntryFinding, EntryKind, FSTAB, Judgement, Node, NodeKind,
    SYSTEM_MOUNTS, Scene, Sharing, Verdict,
};
use crate::filesystem::mountinfo::{MountEntry, top_mount_at};
use crate::hidden_root::mount_holding;
use std::collections::BTreeSet;
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
    if is_ram(&hidden.fstype) || upper_in_ram(scene.mounts, hidden) {
        return Judgement {
            verdict: Verdict::Separate,
            entries: Vec::new(),
        };
    }
    let devices = scene.devices;
    // A stacked filesystem names no device of its own: whatever its source
    // says, its storage is elsewhere.
    let top = (!is_stacked(&hidden.fstype))
        .then(|| devices.node_of_mount(hidden))
        .flatten()
        .map(str::to_string);
    let stack: Vec<String> = top.as_deref().map(|t| devices.stack(t)).unwrap_or_default();
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

fn verdict(
    scene: &Scene<'_>,
    hidden: &MountEntry,
    top: Option<&str>,
    stack: &[String],
    claims: &[Claim],
) -> Verdict {
    let devices = scene.devices;
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
    if let Some((claim, node)) = sharing.first() {
        return Verdict::InsideDecoyStorage {
            device: (*node).clone(),
            holds: claim.what.clone(),
            noauto_only: sharing.iter().all(|(claim, _)| claim.noauto),
        };
    }

    for node in stack {
        let Some(Node {
            kind: NodeKind::Loop { file: Some(file) },
            ..
        }) = devices.nodes.get(node)
        else {
            continue;
        };
        let Some(at) = claimed_holder(scene, claims, file) else {
            // The image file lies on a filesystem that is not the decoy's;
            // that filesystem must itself be on a device that can be traced.
            if let Some(holder) = mount_holding(scene.mounts, file)
                .filter(|holder| !is_ram(&holder.fstype) && untraced(devices, holder))
            {
                return Verdict::UntracedStorage {
                    fstype: shown_fstype(&holder.fstype),
                };
            }
            continue;
        };
        let encrypted = stack.iter().any(|above| {
            matches!(
                devices.nodes.get(above).map(|n| &n.kind),
                Some(NodeKind::Crypt { .. })
            ) && devices.stack(above).contains(node)
        });
        return if encrypted {
            Verdict::ContainerOnDecoy {
                file: file.clone(),
                at,
            }
        } else {
            Verdict::ImageFileOnDecoy {
                file: file.clone(),
                at,
            }
        };
    }
    Verdict::Separate
}

/// Whether `fstype` is a RAM filesystem, which keeps nothing on a disk.
pub(super) fn is_ram(fstype: &str) -> bool {
    matches!(fstype, "tmpfs" | "ramfs")
}

/// Whether `mount` is an overlay whose upper layer, which takes every write,
/// lies on a RAM filesystem.
fn upper_in_ram(mounts: &[MountEntry], mount: &MountEntry) -> bool {
    mount.fstype == "overlay"
        && mount
            .super_opts
            .split(',')
            .find_map(|opt| opt.strip_prefix("upperdir="))
            .and_then(|upper| mount_holding(mounts, Path::new(upper)))
            .is_some_and(|holder| is_ram(&holder.fstype))
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

/// Where the decoy mounts the claimed filesystem that holds `file`, if a
/// claimed filesystem holds it.
fn claimed_holder(scene: &Scene<'_>, claims: &[Claim], file: &Path) -> Option<PathBuf> {
    let holder = mount_holding(scene.mounts, file)?;
    let node = scene.devices.node_of_mount(holder);
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
            let why = if Some(node) == stack.first().map(String::as_str) {
                format!("it mounts the volume at {}", hidden.mount_point.display())
            } else {
                format!(
                    "it mounts a device the volume at {} is stored on",
                    hidden.mount_point.display()
                )
            };
            entries.push(blocking(FSTAB, line, why));
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
        if entry.is_tcrypt_hidden() {
            entries.push(blocking(
                CRYPTTAB,
                line,
                "it opens the hidden volume of a TrueCrypt or VeraCrypt container".to_string(),
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
            entries.push(blocking(CRYPTTAB, line, why));
            continue;
        }
        if entry.is_tcrypt() && source.is_some_and(|s| same_drive(devices, s, stack)) {
            entries.push(EntryFinding {
                kind: EntryKind::OuterWarning,
                file: CRYPTTAB,
                line,
                why: "the decoy is configured to open storage on this drive".to_string(),
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

fn blocking(file: &'static str, line: String, why: String) -> EntryFinding {
    EntryFinding {
        kind: EntryKind::Blocking,
        file,
        line,
        why,
    }
}

/// Whether the device `node` is on a disk the hidden stack also uses.
fn same_drive(devices: &DeviceMap, node: &str, stack: &[String]) -> bool {
    let disk_of = |name: &str| match devices.nodes.get(name).map(|n| &n.kind) {
        Some(NodeKind::Partition { disk }) => Some(disk.clone()),
        Some(NodeKind::Disk) => Some(name.to_string()),
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
