// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The backend-specific hazards in a device stack, each as the warning text
//! `docs/backends.md` explains.

use super::luks2::Luks2Metadata;
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
        if let Some(meta) = &layer.luks2 {
            found.extend(luks2_hazards(layer, meta));
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
