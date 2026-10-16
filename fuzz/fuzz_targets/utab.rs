// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! libmount's userspace mount table, `/run/mount/utab`, across a switch:
//! which lines still name a mount after PID 1 switches root, which ones the
//! way back gives the decoy again, and which mounts they mark as the
//! initrd's. Every program that mounts through libmount writes this file.
//!
//! The input is the utab text, a NUL, the mount table when the copy is taken
//! and, after another NUL, the one at the way back (the same table again when
//! it is missing). The target checks that:
//!
//! - every line reads the way libmount 2.42 reads it (the model in
//!   `nails_fuzz::libmount`): the ID NAILS finds in it, and whether it keeps
//!   the line once a mount with libmount's fields exists;
//! - the lines kept are input lines, in order, byte for byte, and keeping
//!   them again keeps them all;
//! - without a record of the mounts, the way back keeps what a switch keeps;
//! - the way back changes a line only in its ID, to a number;
//! - the initrd marks and the recorded lines name mounts of the tables.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nails_fuzz::libmount::{self, UtabLine};
use nails_teardown::mountinfo::{MountEntry, parse_mountinfo};
use nails_teardown::whole_root::utab::{
    initrd_mounts, named_mounts, restored_lines, surviving_lines,
};
use std::path::{Path, PathBuf};

const NEXTROOT: &str = "/run/nextroot";

/// The lines read one by one against libmount, so a long input stays fast.
const MODEL_LINES: usize = 64;

fuzz_target!(|data: &[u8]| {
    let parts = nails_fuzz::parts(data, 3);
    let utab = parts[0].as_bytes();
    let entry_text = parts.get(1).map_or("", String::as_str);
    let back_text = parts.get(2).map_or(entry_text, String::as_str);
    let at_entry = parse_mountinfo(entry_text);
    let at_back = parse_mountinfo(back_text);
    let nextroot = Path::new(NEXTROOT);

    for line in parts[0].split('\n').take(MODEL_LINES) {
        read_like_libmount(line, nextroot);
    }

    let kept = surviving_lines(utab, &at_entry, nextroot);
    assert_lines_of(&kept, utab);
    assert_eq!(surviving_lines(&kept, &at_entry, nextroot), kept);

    // Without the record, the way back decides as a switch does.
    assert_eq!(
        restored_lines(utab, None, None, &at_back, nextroot),
        surviving_lines(utab, &at_back, nextroot)
    );

    let named = named_mounts(utab, entry_text);
    // Each kept line of `str::lines()`, with a newline added.
    for line in named.split_terminator('\n') {
        assert!(
            entry_text.lines().any(|original| original == line),
            "{line}"
        );
    }
    let named = parse_mountinfo(&named);
    // A record of the way back: each recorded mount was made again as the
    // way-back mount at the same position.
    let pairs: Vec<(i32, i32)> = named
        .iter()
        .zip(&at_back)
        .map(|(then, now)| (then.mount_id, now.mount_id))
        .collect();
    for restored in [None, Some(pairs.as_slice())] {
        let lines = restored_lines(utab, Some(named.as_slice()), restored, &at_back, nextroot);
        assert_rekeyed(&lines, utab);
    }

    for id in initrd_mounts(utab, &at_entry) {
        assert!(at_entry.iter().any(|mount| mount.mount_id == id), "{id}");
    }
});

/// One line, alone, against libmount's reading of it: NAILS names the same
/// ID, and keeps the line exactly when libmount would join it to a mount
/// with the fields libmount reads.
fn read_like_libmount(line: &str, nextroot: &Path) {
    if !libmount::producible(line) {
        return;
    }
    let model = libmount::parse_utab_line(line);
    let utab = format!("{line}\n");

    // Every ID a lenient reader could find, one mount table line each.
    let mut candidates: Vec<i32> = loose_ids(line);
    candidates.extend(model.as_ref().map(|fields| fields.id));
    candidates.sort_unstable();
    candidates.dedup();
    let table: String = candidates
        .iter()
        .map(|id| format!("{id} 1 0:1 / /x rw - t s o\n"))
        .collect();
    let named: Vec<i32> = parse_mountinfo(&named_mounts(utab.as_bytes(), &table))
        .iter()
        .map(|mount| mount.mount_id)
        .collect();
    let expected: Vec<i32> = model.iter().map(|m| m.id).filter(|&id| id > 0).collect();
    assert_eq!(named, expected, "the ID in {line:?}");

    // A mount with libmount's fields, and one with a lenient reading's.
    let mut mounts: Vec<MountEntry> = model.iter().map(|m| mount_for(m, nextroot)).collect();
    mounts.push(mount_for(&loose_fields(line), nextroot));
    let kept = !surviving_lines(utab.as_bytes(), &mounts, nextroot).is_empty();
    let joins = model
        .as_ref()
        .is_some_and(|m| m.id > 0 || m.target.is_some());
    assert_eq!(kept, joins, "keeping {line:?} (libmount reads {model:?})");
}

/// The numbers after each `ID=` in `line`.
fn loose_ids(line: &str) -> Vec<i32> {
    line.match_indices("ID=")
        .filter_map(|(at, _)| {
            let rest = &line[at + 3..];
            let len = rest
                .char_indices()
                .take_while(|&(i, c)| c.is_ascii_digit() || (i == 0 && matches!(c, '-' | '+')))
                .count();
            rest[..len].parse().ok()
        })
        .collect()
}

/// The first value of each key, read leniently: split at spaces and tabs,
/// octal escapes decoded.
fn loose_fields(line: &str) -> UtabLine {
    let mut fields = UtabLine::default();
    for word in line.split([' ', '\t']) {
        let value = |key: &str| word.strip_prefix(key).map(decode);
        if fields.id == 0 {
            fields.id = word
                .strip_prefix("ID=")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
        }
        fields.source = fields.source.take().or_else(|| value("SRC="));
        fields.target = fields.target.take().or_else(|| value("TARGET="));
        fields.root = fields.root.take().or_else(|| value("ROOT="));
    }
    fields
}

/// Octal escapes (`\040`) decoded.
fn decode(text: &str) -> String {
    nails_teardown::mountinfo::unescape_octal(text)
}

/// A mount that libmount joins a line with `fields` to: by its ID below the
/// next root, or at its target in the next root, with its source and root.
fn mount_for(fields: &UtabLine, nextroot: &Path) -> MountEntry {
    let mount_point = match (&fields.target, fields.id > 0) {
        (Some(target), false) => below(nextroot, Path::new(target)),
        _ => nextroot.to_path_buf(),
    };
    MountEntry {
        mount_id: fields.id,
        parent_id: 1,
        dev: "0:1".into(),
        root: PathBuf::from(fields.root.as_deref().unwrap_or("/")),
        mount_point,
        mount_opts: "rw".into(),
        fstype: "t".into(),
        source: PathBuf::from(fields.source.as_deref().unwrap_or("s")),
        super_opts: "rw".into(),
    }
}

/// `path`, absolute inside the root mounted at `nextroot`, seen from outside.
fn below(nextroot: &Path, path: &Path) -> PathBuf {
    nextroot.join(path.strip_prefix("/").unwrap_or(path))
}

/// The lines of a utab text, each without its newline.
fn lines(text: &[u8]) -> Vec<&[u8]> {
    let mut lines: Vec<&[u8]> = text.split(|&b| b == b'\n').collect();
    if text.ends_with(b"\n") || text.is_empty() {
        lines.pop();
    }
    lines
}

/// `kept` is newline-terminated lines of `utab`, in their order.
fn assert_lines_of(kept: &[u8], utab: &[u8]) {
    assert!(kept.is_empty() || kept.ends_with(b"\n"));
    let mut source = utab.split(|&b| b == b'\n');
    for line in lines(kept) {
        assert!(source.any(|original| original == line), "{line:?}");
    }
}

/// Each line of `lines` is a line of `utab`, in order, with at most its ID
/// changed to another number.
fn assert_rekeyed(rekeyed: &[u8], utab: &[u8]) {
    assert!(rekeyed.is_empty() || rekeyed.ends_with(b"\n"));
    let mut source = utab.split(|&b| b == b'\n');
    for line in lines(rekeyed) {
        let found = source.any(|original| {
            let prefix = common_prefix(original, line);
            let suffix = common_prefix(&reversed(original), &reversed(line))
                .min(original.len().min(line.len()) - prefix);
            let changed = &line[prefix..line.len() - suffix];
            original == line
                || (original[..prefix].windows(3).any(|w| w == b"ID=")
                    && changed.iter().all(|b| b.is_ascii_digit() || *b == b'-'))
        });
        assert!(found, "{line:?}");
    }
}

fn common_prefix(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b).take_while(|(x, y)| x == y).count()
}

fn reversed(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().rev().copied().collect()
}
