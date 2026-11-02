// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Whether the hidden root's storage has encryption of its own.
//!
//! A hidden root that nothing encrypts shows its files to anyone who reads
//! the disk it is on, or a copy of it. One whose only encryption is the
//! decoy's own shows them to anyone who can unlock the decoy, and the threat
//! model counts on an adversary who obtains the decoy's credentials
//! (`docs/threat-model.md`, "Compelled disclosure of the decoy").
//!
//! The check walks the block devices under every device of the hidden root's
//! filesystem, each device of a btrfs or bcachefs filesystem included: through
//! `slaves/`, into the device behind a loop device over a block node, from a
//! partition into its disk where the disk keeps its data elsewhere, and from a
//! loop device over a file into the devices of the filesystem the loop driver
//! records for the file (see [`graph`]). Every way down to a device at the
//! bottom must pass an encrypting layer that is not one of the decoy's: not a
//! device the decoy claims as its own storage ([`separation::claimed_devices`]),
//! or one below a claimed partition on a disk that keeps its data elsewhere
//! (the devices of the md array the decoy's root lies on), nor a volume opened
//! under any name from a device or an image file the decoy's crypttab opens. A
//! logical volume spread over two disks, an md mirror of two or a btrfs
//! filesystem of two passes only when the way down to each disk does.
//!
//! It only warns. Encryption is not deniability (a LUKS header shows that an
//! encrypted volume exists), and a root kept in RAM to try NAILS out is no
//! error.

use super::CryptType;
use crate::blockdev::{DmKind, Layer, LoopBacking, MAX_STACK_DEVICES};
use crate::config::get_default_hidden_volume_root;
use crate::crypttab::CrypttabEntry;
use crate::filesystem::mountinfo::top_mount_at;
use crate::hidden_root::separation::{self, Claimed};
use crate::preflight::{CheckResult, PreFlightCheck};
use crate::{Filesystem, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

mod graph;
#[cfg(test)]
mod tests;

use graph::{Graph, MAX_DEVICES, filesystem_devices, leaf_kind, widen_claims};

/// The cryptsetup types that encrypt, as the `<TYPE>` of a `CRYPT-<TYPE>-`
/// device-mapper uuid. `INTEGRITY` and `VERITY` encrypt nothing.
const ENCRYPTING_TYPES: &[&str] = &[
    "TCRYPT", "LUKS1", "LUKS2", "PLAIN", "LOOPAES", "BITLK", "FVAULT2",
];

/// What the operator does about a hidden root without encryption of its own.
const FIX: &str = "Keep the hidden root in an encrypted volume of its own that the decoy does \
     not open (LUKS, or a VeraCrypt volume opened with cryptsetup), made where setup happens. \
     See docs/backends.md.";
/// What the operator does when the check cannot tell.
const UNKNOWN_FIX: &str = "If an encrypted volume of its own holds the hidden root, nothing \
     needs to change; otherwise move the hidden root into one. See docs/backends.md.";
/// What the operator does about a hidden root in RAM.
const RAM_FIX: &str = "Use a root in RAM only to try NAILS out, and keep a hidden environment \
     you mean to keep in an encrypted volume of its own.";

/// Pre-flight check that warns when the hidden root's storage has no
/// encryption of its own.
///
/// # Pass and warn
///
/// It passes when every way down from the devices of the hidden root's
/// filesystem to the bottom of the stack passes an encrypting layer that is
/// not the decoy's: a cryptsetup mapping of type TCRYPT, LUKS1, LUKS2, PLAIN,
/// LOOPAES, BITLK or FVAULT2, a `SUBDEV` mapping (cryptsetup's name for the
/// layers it puts below such a mapping), or a mapping named as the VeraCrypt
/// application names its own. It knows a mapping by its device-mapper uuid
/// and name alone, as it never reads a mapping's table. It warns, naming the
/// device, when a way down passes no encrypting layer at all; when the only
/// encryption on it is the decoy's own; when it cannot tell (a device-mapper
/// device of a kind it does not know, a loop device whose file it cannot
/// follow to a disk or whose path and recorded filesystem disagree, a device
/// that keeps its data where sysfs does not show, a stack deeper than it
/// reads, a filesystem that shows no block device); and when the hidden root
/// is a RAM filesystem, whose contents a power-off ends. It never fails.
///
/// # What it reads
///
/// The mount table, sysfs and the decoy's `/etc/fstab` and `/etc/crypttab`,
/// through the [`Filesystem`] abstraction, exactly as the attach gate does: a
/// pass needs every one of those files read, since one that could not be read
/// may name the encryption it found as the decoy's.
#[derive(Debug, Clone)]
pub struct BackendEncryptionCheck {
    hidden_volume_root: PathBuf,
}

impl BackendEncryptionCheck {
    /// A check of the volume mounted at `hidden_volume_root`.
    pub fn new(hidden_volume_root: PathBuf) -> Self {
        Self { hidden_volume_root }
    }
}

impl Default for BackendEncryptionCheck {
    /// Create the check with the default hidden-volume path.
    fn default() -> Self {
        Self::new(PathBuf::from(get_default_hidden_volume_root()))
    }
}

impl<F: Filesystem> PreFlightCheck<F> for BackendEncryptionCheck {
    fn name(&self) -> &'static str {
        "backend-encryption"
    }

    fn description(&self) -> &'static str {
        "Warns when the hidden root's storage has no encryption of its own"
    }

    fn requires_hidden_volume(&self) -> bool {
        true
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        let root = &self.hidden_volume_root;
        let Ok(table) = fs.mount_table() else {
            return Ok(unknown(root, "the mount table cannot be read"));
        };
        let canonical = fs.canonicalize(root).unwrap_or_else(|_| root.clone());
        let Some(hidden) = top_mount_at(&table, &canonical) else {
            // The attach gate refuses a root that is no mount point, and the
            // registry skips this check then.
            return Ok(CheckResult::Pass(format!(
                "Encryption check skipped: nothing is mounted at {}",
                root.display()
            )));
        };
        if matches!(hidden.fstype.as_str(), "tmpfs" | "ramfs") {
            return Ok(CheckResult::warn_with(
                format!(
                    "The hidden root at {} is a {}, held in RAM: nothing on it survives a \
                     power-off or a reboot.",
                    root.display(),
                    hidden.fstype
                ),
                RAM_FIX,
            ));
        }

        let collected = separation::collect(fs, &table, Path::new("/"));
        let claimed = widen_claims(
            fs,
            &table,
            &collected.devices,
            separation::claimed_devices(&collected.scene(&table), hidden),
        );
        let crypttab_files = crypttab_files(fs, &collected.crypttab);
        let cover = filesystem_devices(fs, hidden)
            .and_then(|roots| {
                let graph = Graph::read(fs, &table, &collected.devices, &roots);
                let stack = Stack {
                    graph: &graph,
                    claimed: &claimed,
                    crypttab_files: &crypttab_files,
                };
                stack.cover_of(&roots)
            })
            .unwrap_or_else(|| {
                Cover::Unknown(format!(
                    "its {} filesystem shows no block device to follow",
                    separation::shown_fstype(&hidden.fstype)
                ))
            });
        Ok(judge(root, cover, &collected.unreadable))
    }
}

/// The result for what the ways down from the hidden root at `root` pass,
/// with `unreadable` the inputs of the decoy's claims that could not be read.
fn judge(root: &Path, cover: Cover, unreadable: &[PathBuf]) -> CheckResult {
    let root_shown = root.display();
    match cover {
        Cover::Own(layers) if unreadable.is_empty() => CheckResult::Pass(format!(
            "The hidden root at {root_shown} has encryption of its own: {}",
            layers.into_iter().collect::<Vec<_>>().join(", ")
        )),
        Cover::Own(_) => unknown(
            root,
            &format!(
                "{} could not be read, so whether the decoy opens that encryption itself cannot \
                 be told",
                unreadable
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ),
        Cover::Unknown(why) => unknown(root, &why),
        Cover::Decoy { layer, holds } => CheckResult::warn_with(
            format!(
                "The only encryption under the hidden root at {root_shown} is the decoy's own: \
                 {layer}, which also holds {}. Whoever can unlock the decoy can read the hidden \
                 root's files.",
                holds_phrase(&holds)
            ),
            FIX,
        ),
        Cover::Plain(device) => CheckResult::warn_with(
            format!(
                "Nothing encrypts the hidden root at {root_shown} on {device}: anyone who can \
                 read {device}, or a copy of it, can read the hidden root's files."
            ),
            FIX,
        ),
    }
}

/// The image files the decoy's crypttab opens, as the loop driver would name
/// them (their links resolved), each as the volume it opens. A source under
/// `/dev`, or a `UUID=` and the like, names a device and is claimed as one.
fn crypttab_files<F: Filesystem>(fs: &F, crypttab: &[CrypttabEntry]) -> BTreeMap<PathBuf, Claimed> {
    crypttab
        .iter()
        .filter(|entry| entry.source.starts_with('/') && !entry.source.starts_with("/dev/"))
        .map(|entry| {
            let path = Path::new(&entry.source);
            let file = fs.canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
            (file, Claimed::Encrypted(entry.name.clone()))
        })
        .collect()
}

/// The warning that the check cannot tell, and `why`.
fn unknown(root: &Path, why: &str) -> CheckResult {
    CheckResult::warn_with(
        format!(
            "Could not confirm that the hidden root at {} is encrypted: {why}.",
            root.display()
        ),
        UNKNOWN_FIX,
    )
}

/// What of the decoy's storage a claimed device also holds, for a sentence.
fn holds_phrase(holds: &Claimed) -> String {
    match holds {
        Claimed::Mount(at) => format!("the decoy's filesystem at {}", at.display()),
        Claimed::Swap(_) => "the decoy's swap".to_string(),
        Claimed::Encrypted(name) => {
            format!(
                "the volume the decoy's {} opens as {name}",
                separation::CRYPTTAB
            )
        }
    }
}

/// What one device of the stack does to the data that passes it.
enum Role {
    /// It encrypts it; the label names its kind for the operator.
    Encrypts(String),
    /// It passes it on unencrypted: a disk, a partition, LVM, md, a loop
    /// device, dm-integrity, dm-verity.
    Passes,
    /// The check cannot tell, for the reason given.
    Unknown(String),
}

/// What `layer` does to the data that passes it.
fn role(layer: &Layer) -> Role {
    let Some(dm) = &layer.dm else {
        return Role::Passes;
    };
    let label = || CryptType::of(&dm.kind).map(|crypt| crypt.label());
    match &dm.kind {
        DmKind::Crypt(kind) if ENCRYPTING_TYPES.contains(&kind.as_str()) => {
            Role::Encrypts(label().unwrap_or_default())
        }
        DmKind::Crypt(kind) => Role::Unknown(format!(
            "{} is a cryptsetup mapping of type {kind}, which the check does not know",
            layer.name
        )),
        DmKind::CryptSubdev => Role::Encrypts(label().unwrap_or_default()),
        DmKind::VeraCrypt => Role::Encrypts("VeraCrypt".to_string()),
        DmKind::Integrity | DmKind::Verity | DmKind::Lvm => Role::Passes,
        DmKind::Other => Role::Unknown(format!(
            "{} is a device-mapper device of a kind the check does not know, and the check \
             never reads a mapping's table",
            layer.name
        )),
    }
}

/// What the ways down from a device to the bottom of the stack pass, the
/// least serious first: on each way, the first that holds of
///
/// 1. an encrypting layer the decoy does not claim ([`Cover::Own`]);
/// 2. a device the check cannot judge ([`Cover::Unknown`]), which may be one;
/// 3. an encrypting layer the decoy claims ([`Cover::Decoy`]);
/// 4. none of these ([`Cover::Plain`]).
///
/// For several ways, the most serious of theirs.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Cover {
    /// Each way passes encryption of the hidden root's own: the topmost
    /// such layer of every way, as the operator reads it.
    Own(BTreeSet<String>),
    /// A way passes something the check cannot judge, and why.
    Unknown(String),
    /// A way passes only the decoy's own encryption: its topmost such
    /// layer, as the operator reads it, and what of the decoy's it holds.
    Decoy {
        /// The layer, such as `LUKS mapping dm-0`.
        layer: String,
        /// What of the decoy's storage it holds.
        holds: Claimed,
    },
    /// A way passes no encrypting layer, down to this device.
    Plain(String),
}

impl Cover {
    /// How serious it is: the order of the variants.
    fn rank(&self) -> u8 {
        match self {
            Cover::Own(_) => 0,
            Cover::Unknown(_) => 1,
            Cover::Decoy { .. } => 2,
            Cover::Plain(_) => 3,
        }
    }

    /// The ways of `self` and of `other` together: the more serious, the
    /// first of two alike, and the layers of both when each is encrypted.
    fn and(self, other: Cover) -> Cover {
        match (self, other) {
            (Cover::Own(mut layers), Cover::Own(more)) => {
                layers.extend(more);
                Cover::Own(layers)
            }
            (first, second) if second.rank() > first.rank() => second,
            (first, _) => first,
        }
    }
}

/// The devices under the hidden root and the devices the decoy claims.
struct Stack<'a> {
    /// The devices read, and where the check goes on from each.
    graph: &'a Graph,
    /// The devices the decoy claims, and what each holds.
    claimed: &'a BTreeMap<String, Claimed>,
    /// The image files the decoy's crypttab opens, by path, each as the
    /// volume it opens.
    crypttab_files: &'a BTreeMap<PathBuf, Claimed>,
}

impl<'a> Stack<'a> {
    /// What the ways down from each of `roots`, the devices of the hidden
    /// root's filesystem, pass together; `None` for no root.
    fn cover_of(&self, roots: &[PathBuf]) -> Option<Cover> {
        roots
            .iter()
            .filter_map(|root| root.file_name())
            .map(|name| self.cover(&name.to_string_lossy(), &mut Vec::new()))
            .reduce(Cover::and)
    }

    /// What the ways down from the device `name` pass. `above` holds the
    /// devices above it on this way, so a link back up ends the way.
    fn cover(&self, name: &str, above: &mut Vec<String>) -> Cover {
        let Some(layer) = self.graph.layers.get(name) else {
            return Cover::Unknown(format!(
                "the stack under it holds more devices than the check reads ({MAX_STACK_DEVICES} \
                 below any one device, {MAX_DEVICES} in all)"
            ));
        };
        if above.iter().any(|seen| seen == name) {
            return Cover::Unknown(format!("sysfs shows {name} below itself"));
        }
        let role = role(layer);
        let claim = self
            .claimed
            .get(name)
            .or_else(|| self.decoys_volume_below(name, &role));
        if let (Role::Encrypts(label), None) = (&role, claim) {
            return Cover::Own(BTreeSet::from([format!("{label} mapping {}", layer.name)]));
        }

        let below = match self.graph.doubts.get(name) {
            Some(why) => Cover::Unknown(why.clone()),
            None => {
                above.push(name.to_string());
                let below = self
                    .graph
                    .children(name, layer)
                    .iter()
                    .map(|next| self.cover(next, above))
                    .reduce(Cover::and)
                    .unwrap_or_else(|| self.bottom(name, layer));
                above.pop();
                below
            }
        };

        // What this device adds to each way through it: the decoy's own
        // encryption, or a doubt, matter only where nothing better lies below.
        match (role, claim) {
            (Role::Encrypts(label), Some(holds)) => match below {
                Cover::Plain(_) | Cover::Decoy { .. } => Cover::Decoy {
                    layer: format!("{label} mapping {}", layer.name),
                    holds: holds.clone(),
                },
                other => other,
            },
            (Role::Unknown(why), _) => match below {
                Cover::Plain(_) | Cover::Decoy { .. } => Cover::Unknown(why),
                other => other,
            },
            _ => below,
        }
    }

    /// The decoy's crypttab volume that the encrypting layer `name` opens
    /// under a name of its own: the device the layer reads its ciphertext
    /// from (below the inner layers of a cipher chain), when the decoy's
    /// crypttab opens that device. A mapping the decoy opened itself, which an
    /// encrypting layer of its own may lie on, does not count.
    fn decoys_volume_below(&self, name: &str, kind: &Role) -> Option<&'a Claimed> {
        if !matches!(kind, Role::Encrypts(_)) {
            return None;
        }
        let mut at = name;
        for _ in 0..MAX_DEVICES {
            let [next] = self.graph.children(at, self.graph.layers.get(at)?) else {
                return None;
            };
            let below = self.graph.layers.get(next.as_str())?;
            let inner_cipher = matches!(
                below.dm.as_ref().map(|dm| &dm.kind),
                Some(DmKind::CryptSubdev | DmKind::VeraCrypt)
            );
            if inner_cipher {
                at = next;
                continue;
            }
            // An image file the decoy's crypttab opens is behind a loop
            // device, which systemd-cryptsetup or the operator attached.
            if let Some(LoopBacking::File(file)) = below.loop_device.as_ref().map(|l| &l.backing)
                && let Some(holds) = self.crypttab_files.get(file)
            {
                return Some(holds);
            }
            return match self.claimed.get(next.as_str()) {
                Some(holds @ Claimed::Encrypted(_))
                    if !matches!(role(below), Role::Encrypts(_)) =>
                {
                    Some(holds)
                }
                _ => None,
            };
        }
        None
    }

    /// What a way that ends at `layer`, a device the check goes on below
    /// from nowhere, passes there.
    fn bottom(&self, name: &str, layer: &Layer) -> Cover {
        if let Some(kind) = leaf_kind(name) {
            return Cover::Unknown(format!(
                "{} is {kind}, which keeps its data where the check cannot follow",
                layer.name
            ));
        }
        if !self.graph.unplaced.contains(&layer.name) {
            return Cover::Plain(layer.name.clone());
        }
        let file = layer
            .loop_device
            .as_ref()
            .map(|bound| bound.backing.path().display().to_string())
            .unwrap_or_default();
        Cover::Unknown(format!(
            "loop device {} reads {file}, which the check cannot follow to a disk",
            layer.name
        ))
    }
}
