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
//! The check walks the block devices under the hidden root
//! ([`blockdev::walk()`]): through `slaves/`, into the device behind a loop
//! device over a block node, and below a loop device over a file into the
//! device of the filesystem that holds the file. Every way down from the top
//! to a device at the bottom must pass an encrypting layer that is not one of
//! the decoy's: not a device the decoy claims as its own storage
//! ([`separation::claimed_devices`]). Two filesystems on one encrypted volume
//! group, or an md array of two encrypted disks, pass only when each way does.
//!
//! It only warns. Encryption is not deniability (a LUKS header shows that an
//! encrypted volume exists), and a root kept in RAM to try NAILS out is no
//! error.

use super::CryptType;
use crate::blockdev::{self, DmKind, Layer, LoopFollow, MAX_STACK_DEVICES};
use crate::config::get_default_hidden_volume_root;
use crate::filesystem::mountinfo::top_mount_at;
use crate::hidden_root::separation::{self, Claimed};
use crate::preflight::{CheckResult, PreFlightCheck};
use crate::{Filesystem, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

#[cfg(test)]
mod tests;

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
/// It passes when every way down from the hidden root's device to the bottom
/// of the stack passes an encrypting layer the decoy does not claim: a
/// cryptsetup mapping of a type in [`ENCRYPTING_TYPES`], a `SUBDEV` mapping
/// (cryptsetup's name for the layers it puts below such a mapping), or a
/// mapping the VeraCrypt application made. It warns, naming the device, when
/// a way down passes no encrypting layer at all; when the only encryption on
/// it is the decoy's own; when it cannot tell (a device-mapper device of a
/// kind it does not know, as it never reads a mapping's table, a loop device
/// whose file it cannot follow to a disk, a stack deeper than the walk reads,
/// a filesystem that shows no block device); and when the hidden root is a
/// RAM filesystem, whose contents a power-off ends. It never fails.
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
        let claimed = separation::claimed_devices(&collected.scene(&table), hidden);
        let cover = blockdev::device_of_mount(fs, hidden)
            .map(|top| blockdev::walk(fs, &top, LoopFollow::BackingFiles, MAX_STACK_DEVICES))
            .and_then(|walk| Stack::new(&walk, &claimed).cover_of_top())
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

/// The stack under the hidden root as the walk read it, by kernel name, and
/// the devices the decoy claims.
struct Stack<'a> {
    /// The devices read, top first.
    layers: Vec<(String, &'a Layer)>,
    /// The loop devices whose file the walk could not follow to a disk.
    unplaced: &'a [String],
    /// The devices the decoy claims, and what each holds.
    claimed: &'a BTreeMap<String, Claimed>,
}

impl<'a> Stack<'a> {
    fn new(walk: &'a blockdev::Walk, claimed: &'a BTreeMap<String, Claimed>) -> Self {
        // A device by the name its sysfs directory has, as `slaves/`, the
        // walk's `below` and the decoy's claims name it.
        let layers = walk
            .layers
            .iter()
            .map(|layer| {
                let name = layer
                    .sysfs
                    .file_name()
                    .map_or_else(|| layer.name.clone(), |n| n.to_string_lossy().into_owned());
                (name, layer)
            })
            .collect();
        Self {
            layers,
            unplaced: &walk.unplaced_loops,
            claimed,
        }
    }

    /// What the ways down from the top of the stack pass; `None` for a walk
    /// that read no device.
    fn cover_of_top(&self) -> Option<Cover> {
        let (top, _) = self.layers.first()?;
        Some(self.cover(top, &mut Vec::new()))
    }

    /// What the ways down from the device `name` pass. `above` holds the
    /// devices above it on this way, so a link back up ends the way.
    fn cover(&self, name: &str, above: &mut Vec<String>) -> Cover {
        let Some(layer) = self.layer(name) else {
            return Cover::Unknown(format!(
                "the stack under it holds more devices than the {MAX_STACK_DEVICES} the check \
                 reads"
            ));
        };
        if above.iter().any(|seen| seen == name) {
            return Cover::Unknown(format!("sysfs shows {name} below itself"));
        }
        let role = role(layer);
        let claim = self.claimed.get(name);
        if let (Role::Encrypts(label), None) = (&role, claim) {
            return Cover::Own(BTreeSet::from([format!("{label} mapping {}", layer.name)]));
        }

        above.push(name.to_string());
        let below = layer
            .below
            .iter()
            .map(|next| self.cover(next, above))
            .reduce(Cover::and)
            .unwrap_or_else(|| self.bottom(layer));
        above.pop();

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

    /// What a way that ends at `layer`, a device with nothing below it in the
    /// walk, passes there.
    fn bottom(&self, layer: &Layer) -> Cover {
        if !self.unplaced.contains(&layer.name) {
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

    fn layer(&self, name: &str) -> Option<&'a Layer> {
        self.layers
            .iter()
            .find(|(known, _)| known == name)
            .map(|(_, layer)| *layer)
    }
}
