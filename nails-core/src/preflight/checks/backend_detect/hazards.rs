// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The backend-specific hazards in a device stack, each as the warning text
//! `docs/backends.md` explains.

use super::luks2::{HeaderProbe, Luks2Metadata, same_volume};
use super::{Layer, mount_containing};
use crate::filesystem::mountinfo::MountEntry;

/// LUKS2 token types that name the unlock method and tie it to hardware.
const HARDWARE_TOKENS: &[&str] = &["systemd-tpm2", "systemd-fido2", "systemd-pkcs11"];
/// Filesystems that write changed blocks to new locations instead of in place.
const COW_FILESYSTEMS: &[&str] = &["btrfs", "zfs", "bcachefs"];

/// Pure seam: one sentence-group per hazard found in the device stack.
///
/// `entries` is the mount table, used to find the filesystem a container file
/// lives on.
pub(super) fn hazards(layers: &[Layer], entries: &[MountEntry]) -> Vec<String> {
    let mut found = Vec::new();

    for layer in layers {
        // Discards over the hidden volume are judged as a fail-closed finding
        // in `assess`, not here, so this function reports only the warnings.
        if let Some(header) = &layer.header {
            found.extend(header_hazard(layer, header));
        }
        if let Some(meta) = &layer.luks2 {
            found.extend(luks2_hazards(layer, meta));
        }
        if let (Some(device), false) = (&layer.loop_over, layer.autoclear) {
            found.push(format!(
                "Loop device {} over {device} was attached without autoclear, so it stays bound \
                 after the hidden volume is closed, after a session too, until losetup -d \
                 detaches it.",
                layer.name
            ));
        }

        let Some(backing_file) = &layer.backing_file else {
            continue;
        };
        let host = mount_containing(entries, backing_file);
        let host_fstype = host.map(|m| m.fstype.as_str());

        // A FUSE-provided file (for example VeraCrypt's aux mount without
        // kernel crypto) is not the container itself, so the container
        // timestamp and COW findings would name the wrong file.
        if let Some(fstype) = host_fstype.filter(|fs| fs.starts_with("fuse")) {
            found.push(format!(
                "Loop device {} is backed by a file on a {fstype} mount, so the hidden \
                 root depends on a userspace process that terminating the session can \
                 kill. Open the volume with cryptsetup so the kernel manages the mapping.",
                layer.name
            ));
            continue;
        }

        found.push(container_timestamp_hazard(layer, host));
        if let Some(fstype) = host_fstype.filter(|fs| COW_FILESYSTEMS.contains(fs)) {
            found.push(format!(
                "The container sits on a copy-on-write {fstype} filesystem, which writes \
                 changed container blocks to new locations and can keep old versions in \
                 free space or snapshots, so even one disk image can hold several versions \
                 of the container to compare. Prefer a whole-device hidden volume, and \
                 disable automatic snapshots of that filesystem."
            ));
        }
    }

    found
}

/// Pure seam: what the device stack shows that is no hazard to warn about,
/// one sentence each: the LUKS header a mapping was opened with, which
/// shows that an encrypted volume is there, as the backend chosen means it
/// to, and where the flags of a detached header are.
pub(super) fn notes(layers: &[Layer]) -> Vec<String> {
    layers
        .iter()
        .filter_map(|layer| {
            let device = layer.slaves.first()?;
            match layer.header.as_ref()? {
                HeaderProbe::Attached { version, uuid, .. }
                    if same_volume(uuid, layer.dm_uuid.as_deref().unwrap_or_default()) =>
                {
                    Some(format!(
                        "The LUKS{version} header at the start of {device} shows anyone who reads \
                         the disk that an encrypted volume is there (cryptsetup isLuks, blkid), \
                         though not what it holds."
                    ))
                }
                HeaderProbe::Detached { .. } => Some(format!(
                    "The flags and tokens of the detached LUKS header of {} are in its file, \
                     which `cryptsetup luksDump <file>` shows.",
                    layer.name
                )),
                _ => None,
            }
        })
        .collect()
}

/// What the start of the device below a LUKS mapping shows anyone who reads
/// the disk that the mapping was not opened with: a header of another volume
/// left behind, or the LUKS2 secondary header a device opened with a
/// detached header kept. `None` for a device that shows neither, or could
/// not be read.
fn header_hazard(layer: &Layer, header: &HeaderProbe) -> Option<String> {
    let device = layer.slaves.first()?;
    let name = &layer.name;
    match header {
        HeaderProbe::Attached { uuid, .. }
            if same_volume(uuid, layer.dm_uuid.as_deref().unwrap_or_default()) =>
        {
            None
        }
        HeaderProbe::Attached { version, uuid, .. } => Some(format!(
            "The device below LUKS mapping {name}, {device}, starts with a LUKS{version} header \
             of another volume (uuid {uuid}) than the one the mapping was opened with: a leftover \
             that blkid and an examiner identify as LUKS. docs/backends.md says how to clear it."
        )),
        HeaderProbe::Detached {
            secondary_at: Some(at),
        } => Some(format!(
            "The device below LUKS mapping {name}, {device}, opened with a header kept apart \
             from it, still holds a LUKS2 secondary header {} KiB in, which blkid and an \
             examiner identify as LUKS2. docs/backends.md says how to clear it.",
            at / 1024
        )),
        HeaderProbe::Detached { secondary_at: None } | HeaderProbe::Unreadable => None,
    }
}

/// Hazards recorded in a LUKS2 header: the checks `docs/backends.md` otherwise
/// asks for by hand with `cryptsetup luksDump`.
fn luks2_hazards(layer: &Layer, meta: &Luks2Metadata) -> Vec<String> {
    let mut found = Vec::new();
    // A stored allow-discards flag is a discard over the hidden volume, judged
    // as a fail-closed finding in `assess`, not reported here.
    let hardware: Vec<&str> = meta
        .token_types
        .iter()
        .map(String::as_str)
        .filter(|kind| HARDWARE_TOKENS.contains(kind))
        .collect();
    if !hardware.is_empty() {
        let tokens = if hardware.len() == 1 {
            format!("a {} token, which names", hardware[0])
        } else {
            format!("{} tokens, which name", hardware.join(", "))
        };
        found.push(format!(
            "The LUKS2 header of mapping {} carries {tokens} the unlock method in plain \
             text; a systemd-tpm2 token also seals the key to this machine's TPM, binding \
             the volume to the host. Remove the token with systemd-cryptenroll \
             --wipe-slot or cryptsetup token remove --token-id if the volume must not \
             point at this machine.",
            layer.name,
        ));
    }
    found
}

fn container_timestamp_hazard(layer: &Layer, host: Option<&MountEntry>) -> String {
    let host = match host {
        Some(mount) => format!(
            " on the {} filesystem mounted at {}",
            mount.fstype,
            mount.mount_point.display()
        ),
        None => String::new(),
    };
    format!(
        "The hidden root lives in a file container attached through loop device {}{host}. \
         Every read-write session updates the container's mtime and ctime, and ctime \
         cannot be restored, so the container shows when it was last used; a \
         whole-device hidden volume has no such timestamps.",
        layer.name
    )
}
