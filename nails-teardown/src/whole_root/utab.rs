// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! libmount's userspace mount table, `/run/mount/utab`, across a switch.
//!
//! libmount keeps the options the kernel does not store (`x-initrd.mount`,
//! `X-*`, a bind's source) in `utab`, one line per mount, and joins a line to
//! the mount whose kernel mount ID the line names. systemd reads the joined
//! options: a mount marked `x-initrd.mount` outside the initrd is one the
//! shutdown leaves alone, with no order against `umount.target`.
//!
//! A soft-reboot carries `/run` and every line in it, but not the mounts the
//! lines name: PID 1 detaches the root it leaves with all its submounts, and
//! the kernel hands their IDs to the next mounts it makes. A systemd initrd
//! writes `ID=62 SRC=/dev/vda TARGET=/sysroot ROOT=/ OPTS=x-initrd.mount` for
//! the decoy's root; once that root is gone, ID 62 can go to the hidden
//! volume, which systemd from then on takes for an initrd mount. A disk
//! mounted over the volume hides the line again, so the volume's unit has the
//! shutdown order while the disk is there and loses it when the shutdown
//! unmounts the disk, in the middle of the volume's own stop job. PID 1 then
//! never resumes the job it held back for that stop (`local-fs-pre.target`),
//! and the power-off hangs.
//!
//! [`surviving_lines`] keeps a line that names an ID only while the ID still
//! names the same mount on the other side of the switch: a mount at or below
//! the next root, with the line's source and root. A line without an ID is
//! joined by source, target and root rather than by ID, and is kept.

use crate::mountinfo::{MountEntry, unescape_octal};
use std::path::Path;

/// The lines of `utab` that still name the same mount once PID 1 has switched
/// to `nextroot`, given the live mount table `mounts`. Kept lines are copied
/// byte for byte; a line whose path is not UTF-8 matches no mount, so it is
/// kept only when it names no ID.
pub fn surviving_lines(utab: &[u8], mounts: &[MountEntry], nextroot: &Path) -> Vec<u8> {
    let mut kept = Vec::with_capacity(utab.len());
    for line in utab.split(|&b| b == b'\n') {
        if survives(&String::from_utf8_lossy(line), mounts, nextroot) {
            kept.extend_from_slice(line);
            kept.push(b'\n');
        }
    }
    kept
}

/// The value of the `key=` field of a `utab` line, still escaped.
fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.split(' ')
        .find_map(|f| f.strip_prefix(key)?.strip_prefix('='))
}

fn survives(line: &str, mounts: &[MountEntry], nextroot: &Path) -> bool {
    let Some(id) = field(line, "ID") else {
        return !line.trim().is_empty();
    };
    let Ok(id) = id.parse::<i32>() else {
        return false;
    };
    let same = |value: Option<&str>, path: &Path| {
        value.is_none_or(|v| Path::new(&unescape_octal(v)) == path)
    };
    mounts.iter().any(|m| {
        m.mount_id == id
            && m.mount_point.starts_with(nextroot)
            && same(field(line, "SRC"), &m.source)
            && same(field(line, "ROOT"), &m.root)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mountinfo::parse_mountinfo;

    /// The decoy's root at 62 and the next root's tree: its overlay, the
    /// hidden volume (which got a recycled ID, 71) and a bind with a space in
    /// its source.
    fn table() -> Vec<MountEntry> {
        parse_mountinfo(
            "62 1 253:0 / / rw - ext4 /dev/vda rw\n\
             40 62 0:40 / /run/nextroot rw - overlay overlay rw\n\
             71 40 254:0 / /run/nextroot/mnt/data rw - ext4 /dev/mapper/data rw\n\
             90 40 0:41 /sub /run/nextroot/srv rw - ext4 /dev/my\\040disk rw\n",
        )
    }

    fn kept(utab: &str) -> String {
        let kept = surviving_lines(utab.as_bytes(), &table(), Path::new("/run/nextroot"));
        String::from_utf8(kept).unwrap()
    }

    #[test]
    fn a_line_for_a_mount_the_next_root_keeps_survives() {
        let line = "ID=40 SRC=overlay TARGET=/sysroot ROOT=/ OPTS=x-initrd.mount\n";
        assert_eq!(kept(line), line);
        let escaped = "ID=90 SRC=/dev/my\\040disk TARGET=/srv ROOT=/sub OPTS=X-mine\n";
        assert_eq!(kept(escaped), escaped);
    }

    #[test]
    fn a_line_for_a_mount_the_switch_leaves_behind_is_dropped() {
        // The decoy's root is still mounted at the transition, but PID 1
        // detaches it with the switch, and its ID goes to the next mount.
        assert_eq!(
            kept("ID=62 SRC=/dev/vda TARGET=/sysroot ROOT=/ OPTS=x-initrd.mount\n"),
            ""
        );
    }

    #[test]
    fn a_line_whose_id_now_names_another_mount_is_dropped() {
        // ID 71 was the decoy's /nix/.ro-store; the hidden volume has it now.
        assert_eq!(
            kept("ID=71 SRC=nix-store TARGET=/sysroot/nix/.ro-store ROOT=/ OPTS=x-initrd.mount\n"),
            ""
        );
        assert_eq!(
            kept("ID=90 SRC=/dev/my\\040disk TARGET=/srv ROOT=/other OPTS=X-mine\n"),
            ""
        );
    }

    #[test]
    fn lines_without_an_id_stay_and_malformed_ones_go() {
        let utab = "SRC=/dev/vda TARGET=/ OPTS=x-initrd.mount\n\
                    ID=x SRC=/dev/vda TARGET=/ ROOT=/ OPTS=x-initrd.mount\n\
                    \n\
                    ID=40 SRC=overlay TARGET=/ ROOT=/ OPTS=x-initrd.mount\n";
        assert_eq!(
            kept(utab),
            "SRC=/dev/vda TARGET=/ OPTS=x-initrd.mount\n\
             ID=40 SRC=overlay TARGET=/ ROOT=/ OPTS=x-initrd.mount\n"
        );
    }

    #[test]
    fn a_line_that_is_not_utf8_is_copied_unchanged_or_dropped() {
        let line = b"SRC=/dev/disk\xff TARGET=/x OPTS=X-mine\n";
        assert_eq!(
            surviving_lines(line, &table(), Path::new("/run/nextroot")),
            line
        );
        let with_id = b"ID=40 SRC=over\xfflay TARGET=/ ROOT=/ OPTS=X-mine\n";
        assert!(surviving_lines(with_id, &table(), Path::new("/run/nextroot")).is_empty());
    }

    #[test]
    fn an_identifier_field_is_not_taken_for_the_id() {
        assert_eq!(field("UNIQ_ID=7 ID=40 SRC=overlay", "ID"), Some("40"));
        assert_eq!(field("UNIQ_ID=7 SRC=overlay", "ID"), None);
    }
}
