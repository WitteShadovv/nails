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
    assert_eq!(line.id_at, 3..5);
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
    assert!(Line::parse(b"ID= SRC=overlay TARGET=/ ROOT=/").is_none());
    assert!(Line::parse(b"ID=99999999999999999999 TARGET=/").is_none());
    // An empty number at the end of the line is no number: libmount reads the
    // line without an ID and joins it by its path.
    for bare in [
        &b"TARGET=/x ID="[..],
        b"TARGET=/x UNIQID=",
        b"TARGET=/x ID=\r",
    ] {
        let line = Line::parse(bare).unwrap();
        assert_eq!(
            (line.id, line.target.as_deref()),
            (0, Some(Path::new("/x")))
        );
    }
    // Blanks before the first field and a carriage return at the end do not
    // count; blank lines and comments are skipped.
    let line = Line::parse(b" \tID=7 TARGET=/x\r").unwrap();
    assert_eq!((line.id, line.id_at), (7, 5..6));
    for skipped in [&b""[..], b"  \t", b"# ID=7 TARGET=/x", b" #ID=7"] {
        assert!(Line::parse(skipped).is_none());
    }
}

#[test]
fn a_line_with_an_empty_id_is_matched_by_its_path() {
    let line = "SRC=overlay TARGET=/ ROOT=/ OPTS=X-kept ID=\n";
    assert_eq!(kept(line), line);
    assert_eq!(
        kept("SRC=wrappers TARGET=/run/wrappers ROOT=/ OPTS=X ID=\n"),
        ""
    );
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

/// The decoy's mount table when the copy was taken, at the entry.
const DECOY_AT_ENTRY: &str = "\
62 1 253:0 / / rw - ext4 /dev/vda rw
65 62 0:30 / /nix/.ro-store ro - 9p nix-store rw
68 62 0:31 / /nix/.rw-store rw - tmpfs tmpfs rw
85 62 0:32 / /nix/store ro - overlay overlay rw
90 62 0:41 /sub /srv rw - ext4 /dev/my\\040disk rw
";

/// The decoy's copy: the initrd's lines (with the initrd's targets), a line
/// of the decoy's own, and two without an ID.
const SAVED: &str = "\
ID=62 SRC=/dev/vda TARGET=/sysroot ROOT=/ OPTS=x-initrd.mount
ID=65 SRC=nix-store TARGET=/sysroot/nix/.ro-store ROOT=/ OPTS=x-initrd.mount
ID=68 SRC=tmpfs TARGET=/sysroot/nix/.rw-store ROOT=/ OPTS=x-initrd.mount
ID=85 SRC=overlay TARGET=/sysroot/nix/store ROOT=/ OPTS=x-initrd.mount
ID=90 SRC=/dev/my\\040disk TARGET=/srv ROOT=/sub OPTS=X-mine
SRC=overlay TARGET=/nix/store ROOT=/ OPTS=x-initrd.mount
SRC=/dev/vda TARGET=/ OPTS=x-initrd.mount
";

/// At the way back, in the hidden session: the hidden volume has the decoy
/// root's old ID, and the decoy root and the filesystems the session carried
/// are back below the next root with new IDs (not /nix/.rw-store, which the
/// session did not carry).
fn way_back_table() -> Vec<MountEntry> {
    parse_mountinfo(
        "140 1 0:50 / / rw - overlay overlay rw\n\
         62 140 254:0 / /mnt/data rw - ext4 /dev/mapper/data rw\n\
         150 140 253:0 / /run/nextroot rw - ext4 /dev/vda rw\n\
         151 150 0:30 / /run/nextroot/nix/.ro-store ro - 9p nix-store rw\n\
         152 150 0:32 / /run/nextroot/nix/store ro - overlay overlay rw\n\
         153 150 0:41 /sub /run/nextroot/srv rw - ext4 /dev/my\\040disk rw\n",
    )
}

fn restored(saved: &str, named: Option<&str>) -> String {
    let named = named.map(parse_mountinfo);
    let lines = restored_lines(
        saved.as_bytes(),
        named.as_deref(),
        None,
        &way_back_table(),
        Path::new(NEXTROOT),
    );
    String::from_utf8(lines).unwrap()
}

#[test]
fn the_mounts_utab_names_are_recorded_with_it() {
    let mountinfo = format!("{DECOY_AT_ENTRY}99 62 0:60 / /tmp rw - tmpfs tmpfs rw\n");
    let named = named_mounts(SAVED.as_bytes(), &mountinfo);
    assert_eq!(named, DECOY_AT_ENTRY);
    assert_eq!(
        named_mounts(b"SRC=overlay TARGET=/ ROOT=/\n", &mountinfo),
        ""
    );
}

#[test]
fn the_way_back_gives_the_decoys_lines_to_its_restored_mounts() {
    assert_eq!(
        restored(SAVED, Some(DECOY_AT_ENTRY)),
        "ID=150 SRC=/dev/vda TARGET=/sysroot ROOT=/ OPTS=x-initrd.mount\n\
         ID=151 SRC=nix-store TARGET=/sysroot/nix/.ro-store ROOT=/ OPTS=x-initrd.mount\n\
         ID=152 SRC=overlay TARGET=/sysroot/nix/store ROOT=/ OPTS=x-initrd.mount\n\
         ID=153 SRC=/dev/my\\040disk TARGET=/srv ROOT=/sub OPTS=X-mine\n\
         SRC=overlay TARGET=/nix/store ROOT=/ OPTS=x-initrd.mount\n\
         SRC=/dev/vda TARGET=/ OPTS=x-initrd.mount\n"
    );
}

#[test]
fn a_line_that_named_no_mount_or_another_one_at_the_entry_is_dropped() {
    // ID 70 named nothing when the copy was taken; ID 65 named the store with
    // another source; ID 85's place now has another filesystem.
    let saved = "ID=70 SRC=/dev/vdb TARGET=/old ROOT=/ OPTS=x-initrd.mount\n\
                 ID=65 SRC=other TARGET=/sysroot/nix/.ro-store ROOT=/ OPTS=x-initrd.mount\n";
    assert_eq!(restored(saved, Some(DECOY_AT_ENTRY)), "");
    let moved = DECOY_AT_ENTRY.replace(
        "0:32 / /nix/store ro - overlay overlay",
        "0:32 / /nix/store ro - ext4 /dev/vdc",
    );
    assert_eq!(
        restored(
            "ID=85 SRC=/dev/vdc TARGET=/nix/store ROOT=/ OPTS=X\n",
            Some(&moved)
        ),
        ""
    );
}

#[test]
fn without_the_record_only_lines_that_still_fit_come_back() {
    // ID 62 is the hidden volume's now: the decoy root's line must not join it.
    assert_eq!(
        restored(SAVED, None),
        "SRC=overlay TARGET=/nix/store ROOT=/ OPTS=x-initrd.mount\n\
         SRC=/dev/vda TARGET=/ OPTS=x-initrd.mount\n"
    );
    assert_eq!(
        restored(
            "ID=151 SRC=nix-store TARGET=/nix/.ro-store ROOT=/ OPTS=x-initrd.mount\n",
            None
        ),
        "ID=151 SRC=nix-store TARGET=/nix/.ro-store ROOT=/ OPTS=x-initrd.mount\n"
    );
}

#[test]
fn a_restored_line_takes_the_newest_mount_at_its_place() {
    let mut table = way_back_table();
    table.extend(parse_mountinfo(
        "160 152 0:32 / /run/nextroot/nix/store ro - overlay overlay rw\n",
    ));
    let named = parse_mountinfo(DECOY_AT_ENTRY);
    let lines = restored_lines(
        b"ID=85 SRC=overlay TARGET=/sysroot/nix/store ROOT=/ OPTS=x-initrd.mount\n",
        Some(&named),
        None,
        &table,
        Path::new(NEXTROOT),
    );
    assert_eq!(
        lines,
        b"ID=160 SRC=overlay TARGET=/sysroot/nix/store ROOT=/ OPTS=x-initrd.mount\n"
    );
}

/// The decoy's store as the test VMs mount it, at entry: the initrd's overlay
/// (85) with NixOS's read-only bind of it stacked on top (41), and a store bind
/// of the root filesystem elsewhere (44).
const STACKED_AT_ENTRY: &str = "\
62 1 253:0 / / rw - ext4 /dev/vda rw
85 62 0:32 / /nix/store rw - overlay overlay rw
41 85 0:32 / /nix/store ro,nosuid,nodev - overlay overlay rw
44 62 253:0 /srv/store /srv/store ro,nosuid,nodev - ext4 /dev/vda rw
";

/// The way back made both layers again, the bottom first, and the store bind.
fn stacked_way_back() -> Vec<MountEntry> {
    parse_mountinfo(
        "140 1 0:50 / / rw - overlay overlay rw\n\
         150 140 253:0 / /run/nextroot rw - ext4 /dev/vda rw\n\
         152 150 0:32 / /run/nextroot/nix/store rw - overlay overlay rw\n\
         153 152 0:32 / /run/nextroot/nix/store ro - overlay overlay rw\n\
         154 150 253:0 /srv/store /run/nextroot/srv/store ro - ext4 /dev/vda rw\n",
    )
}

fn rekeyed(saved: &str, restored: &[(i32, i32)]) -> String {
    let named = parse_mountinfo(STACKED_AT_ENTRY);
    let lines = restored_lines(
        saved.as_bytes(),
        Some(&named),
        Some(restored),
        &stacked_way_back(),
        Path::new(NEXTROOT),
    );
    String::from_utf8(lines).unwrap()
}

#[test]
fn a_line_takes_the_id_of_the_mount_made_in_its_mount_s_place() {
    // The two layers of the store share their place, source and root: only
    // the way back's record tells which new mount took the bottom's place.
    let saved = "ID=62 SRC=/dev/vda TARGET=/sysroot ROOT=/ OPTS=x-initrd.mount\n\
                 ID=85 SRC=overlay TARGET=/sysroot/nix/store ROOT=/ OPTS=x-initrd.mount\n\
                 SRC=overlay TARGET=/nix/store ROOT=/ OPTS=x-initrd.mount\n\
                 ID=44 SRC=/dev/vda TARGET=/srv/store ROOT=/srv/store OPTS=X-bind\n";
    assert_eq!(
        rekeyed(saved, &[(62, 150), (85, 152), (41, 153), (44, 154)]),
        "ID=150 SRC=/dev/vda TARGET=/sysroot ROOT=/ OPTS=x-initrd.mount\n\
         ID=152 SRC=overlay TARGET=/sysroot/nix/store ROOT=/ OPTS=x-initrd.mount\n\
         SRC=overlay TARGET=/nix/store ROOT=/ OPTS=x-initrd.mount\n\
         ID=154 SRC=/dev/vda TARGET=/srv/store ROOT=/srv/store OPTS=X-bind\n"
    );
}

#[test]
fn a_line_whose_mount_did_not_come_back_is_dropped() {
    // The record has no new ID for 85, or one that is not at its place with
    // its source and root: the line would join another mount.
    let saved = "ID=85 SRC=overlay TARGET=/sysroot/nix/store ROOT=/ OPTS=x-initrd.mount\n";
    assert_eq!(rekeyed(saved, &[(62, 150)]), "");
    assert_eq!(rekeyed(saved, &[(85, 154)]), "");
    assert_eq!(rekeyed(saved, &[(85, 999)]), "");
}

/// A `/run` with libmount's `utab`.
fn run_with_utab(text: &str) -> tempfile::TempDir {
    let run = tempfile::tempdir().unwrap();
    std::fs::create_dir(run.path().join("mount")).unwrap();
    std::fs::write(run.path().join(UTAB), text).unwrap();
    run
}

#[test]
fn utab_is_rewritten_the_way_libmount_writes_it() {
    let run = run_with_utab("ID=1 decoy\nID=99 hidden\n");
    let path = run.path().join(UTAB);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let before = std::fs::metadata(&path).unwrap().ino();
    // What a transition killed halfway left, under this process's ID.
    std::fs::write(path.with_extension(std::process::id().to_string()), "x").unwrap();
    let written = update(run.path(), |text| {
        assert_eq!(text, b"ID=1 decoy\nID=99 hidden\n");
        b"ID=1 decoy\n".to_vec()
    });
    assert!(written.unwrap());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "ID=1 decoy\n");
    // A new file with libmount's mode, renamed over the old one; no other
    // file is left, and no lock file where there was none.
    let meta = std::fs::metadata(&path).unwrap();
    assert_ne!(meta.ino(), before);
    assert_eq!(meta.permissions().mode() & 0o7777, 0o644);
    let names: Vec<_> = std::fs::read_dir(run.path().join("mount"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(names, ["utab"]);
    // Unchanged, it is not written; missing, it stays missing.
    assert!(!update(run.path(), <[u8]>::to_vec).unwrap());
    assert_eq!(std::fs::metadata(&path).unwrap().ino(), meta.ino());
    let empty = tempfile::tempdir().unwrap();
    assert!(!update(empty.path(), |_| b"ID=1 decoy\n".to_vec()).unwrap());
    assert!(!empty.path().join(UTAB).exists());
}

#[test]
fn a_libmount_update_in_progress_finishes_first() {
    // libmount holds its lock while it reads utab and renames its new copy
    // over it: the switch reads only after that, and its copy is the last.
    let run = run_with_utab("ID=1 decoy\n");
    let lock = File::create(run.path().join(UTAB_LOCK)).unwrap();
    lock.lock().unwrap();
    let (read, seen) = std::sync::mpsc::channel();
    let switch = std::thread::spawn({
        let run = run.path().to_path_buf();
        move || {
            update(&run, |text| {
                read.send(text.to_vec()).unwrap();
                b"ID=2 back\n".to_vec()
            })
        }
    });
    assert!(seen.recv_timeout(Duration::from_millis(300)).is_err());
    std::fs::write(run.path().join(UTAB), "ID=1 decoy\nID=3 libmount\n").unwrap();
    lock.unlock().unwrap();
    assert_eq!(
        seen.recv_timeout(Duration::from_secs(10)).unwrap(),
        b"ID=1 decoy\nID=3 libmount\n"
    );
    assert!(switch.join().unwrap().unwrap());
    assert_eq!(
        std::fs::read_to_string(run.path().join(UTAB)).unwrap(),
        "ID=2 back\n"
    );
    assert!(run.path().join(UTAB_LOCK).exists());
}
