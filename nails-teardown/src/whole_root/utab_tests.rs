// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! libmount's `utab` lines across a switch, against given mount tables.

use super::*;
use crate::mountinfo::parse_mountinfo;

const NEXTROOT: &str = "/run/nextroot";

/// At an entry: the decoy's root at 62 and the next root's tree, with its
/// overlay, the hidden volume (on a reused ID, 71) and a bind with a space in
/// its source.
fn entry_table() -> Vec<MountEntry> {
    parse_mountinfo(
        "62 1 253:0 / / rw - ext4 /dev/vda rw\n\
         40 62 0:40 / /run/nextroot rw - overlay overlay rw\n\
         71 40 254:0 / /run/nextroot/mnt/data rw - ext4 /dev/mapper/data rw\n\
         90 40 0:41 /sub /run/nextroot/srv rw - ext4 /dev/my\\040disk rw\n",
    )
}

fn kept(utab: &str) -> String {
    let kept = surviving_lines(utab.as_bytes(), &entry_table(), Path::new(NEXTROOT));
    String::from_utf8(kept).unwrap()
}

#[test]
fn a_line_is_read_the_way_libmount_reads_it() {
    let line = Line::parse(
        b"ID=85 UNIQID=7 SRC=/dev/my\\040disk TARGET=/srv ROOT=/sub OPTS=X-a SRC=/dev/other",
    )
    .unwrap();
    assert_eq!(line.id, 85);
    assert_eq!(line.source.as_deref(), Some(Path::new("/dev/my disk")));
    assert_eq!(line.target.as_deref(), Some(Path::new("/srv")));
    assert_eq!(line.root.as_deref(), Some(Path::new("/sub")));
    // UNIQID is not the ID, and a field libmount does not know is skipped.
    let line = Line::parse(b"UNIQID=9 FOO=ID=3 TARGET=/x").unwrap();
    assert_eq!(line.id, 0);
    assert_eq!(line.target.as_deref(), Some(Path::new("/x")));
    // libmount skips a line whose number runs into the next field (it
    // writes UNIQID without a space after it) or is no number at all.
    assert!(Line::parse(b"ID=40 UNIQID=7SRC=overlay TARGET=/ ROOT=/").is_none());
    assert!(Line::parse(b"ID=x SRC=overlay TARGET=/ ROOT=/").is_none());
    assert!(Line::parse(b"ID=").is_none());
    assert_eq!(Line::parse(b"").unwrap().target, None);
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
fn a_line_without_an_id_survives_only_with_its_mount_in_the_next_root() {
    // libmount joins a line without an ID to the mount at its target with its
    // source and root, one mounted later too: carried without its mount, the
    // line would mark the next userspace's /run/wrappers an initrd mount while
    // systemd mounts it, which drops local-fs.target's order on it.
    for gone in [
        "SRC=wrappers TARGET=/run/wrappers ROOT=/ OPTS=x-initrd.mount\n",
        // The next root is the overlay, not the decoy's device.
        "SRC=/dev/vda TARGET=/ OPTS=x-initrd.mount\n",
        "SRC=/dev/my\\040disk TARGET=/srv ROOT=/ OPTS=X-mine\n",
        "SRC=/dev/other TARGET=/srv ROOT=/sub OPTS=X-mine\n",
        "SRC=/dev/my\\040disk ROOT=/sub OPTS=X-mine\n",
    ] {
        assert_eq!(kept(gone), "", "{gone}");
    }
    let utab = "SRC=/dev/my\\040disk TARGET=/srv ROOT=/sub OPTS=X-mine\n\
                SRC=overlay TARGET=/ ROOT=/ OPTS=X-kept\n\
                SRC=overlay TARGET=/ OPTS=X-no-root\n";
    assert_eq!(kept(utab), utab);
}

#[test]
fn malformed_lines_go() {
    let utab = "ID=x SRC=/dev/vda TARGET=/ ROOT=/ OPTS=x-initrd.mount\n\
                \n\
                ID=40 UNIQID=3SRC=overlay TARGET=/ ROOT=/ OPTS=x-initrd.mount\n\
                ID=40 SRC=overlay TARGET=/ ROOT=/ OPTS=x-initrd.mount";
    assert_eq!(
        kept(utab),
        "ID=40 SRC=overlay TARGET=/ ROOT=/ OPTS=x-initrd.mount\n"
    );
}

#[test]
fn a_line_that_is_not_utf8_is_copied_unchanged_or_dropped() {
    let nextroot = Path::new(NEXTROOT);
    let line = b"ID=40 SRC=overlay TARGET=/\xff ROOT=/ OPTS=X-mine\n";
    assert_eq!(surviving_lines(line, &entry_table(), nextroot), line);
    let other = b"ID=40 SRC=over\xfflay TARGET=/ ROOT=/ OPTS=X-mine\n";
    assert!(surviving_lines(other, &entry_table(), nextroot).is_empty());
    let pathless = b"SRC=/dev/disk\xff TARGET=/x OPTS=X-mine\n";
    assert!(surviving_lines(pathless, &entry_table(), nextroot).is_empty());
}
