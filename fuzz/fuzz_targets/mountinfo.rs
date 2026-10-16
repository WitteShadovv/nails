// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! `/proc/self/mountinfo`, read by the one parser in nails-teardown, and the
//! overlay options in it. Any mount on the system, made by anyone, puts its
//! paths and options into this text.
//!
//! The input is a mount table. The target checks that:
//!
//! - the entries, printed back the way the kernel prints them, parse to the
//!   same entries;
//! - every overlay's layers, given to mount(2) with NAILS's escaping and
//!   printed back with the kernel's, decode to the same paths in both forms;
//! - a lookup answers with a mount of the table at exactly the path asked
//!   for, ends on any table, and the hidden-session test agrees with it.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nails_fuzz::kernel;
use nails_teardown::mountinfo::{
    MountEntry, OverlayOpts, escape_overlay_path, parse_mountinfo, parse_overlay_opts,
    root_is_hidden_overlay, top_mount_at,
};
use std::path::Path;

/// The paths looked up per input, so a long table stays fast to check.
const LOOKUPS: usize = 32;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let entries = parse_mountinfo(&text);
    assert!(entries.len() <= text.lines().count());
    round_trip(&entries);
    for entry in &entries {
        let _ = entry.read_only();
        overlay_round_trip(&parse_overlay_opts(&entry.super_opts));
    }
    lookups(&entries);
});

/// Printed and parsed again, the entries come back unchanged.
fn round_trip(entries: &[MountEntry]) {
    // `str::lines` takes a carriage return right before a newline for part of
    // the line end, so a last field that ends in one does not come back.
    let printable: Vec<&MountEntry> = entries
        .iter()
        .filter(|entry| !entry.super_opts.ends_with('\r'))
        .collect();
    let text: String = printable
        .iter()
        .map(|entry| kernel::mountinfo_line(entry) + "\n")
        .collect();
    let again = parse_mountinfo(&text);
    assert_eq!(again.len(), printable.len(), "{text}");
    for (read, entry) in again.iter().zip(printable) {
        assert_eq!(read, entry, "{text}");
    }
}

/// The layers, given to mount(2) and read back from the kernel, decode to
/// the same paths.
fn overlay_round_trip(opts: &OverlayOpts) {
    // NAILS refuses a path mount(2) cannot take (one with a newline).
    let Some(lower) = opts
        .lowerdir
        .iter()
        .map(|path| escape_overlay_path(path))
        .collect::<Option<Vec<_>>>()
    else {
        return;
    };
    let mut given = vec![("lowerdir", lower.join(":"))];
    for (key, path) in [("upperdir", &opts.upperdir), ("workdir", &opts.workdir)] {
        if let Some(path) = path {
            let Some(escaped) = escape_overlay_path(path) else {
                return;
            };
            given.push((key, escaped));
        }
    }
    let as_given: Vec<String> = given.iter().map(|(k, v)| format!("{k}={v}")).collect();
    let as_shown: Vec<String> = given
        .iter()
        .map(|(k, v)| format!("{k}={}", kernel::escape(v, kernel::OPTION_SPECIAL)))
        .collect();
    for form in [as_given.join(","), as_shown.join(",")] {
        assert_eq!(&parse_overlay_opts(&form), opts, "{form}");
    }
}

/// Lookups answer with a mount of the table at the path asked for.
fn lookups(entries: &[MountEntry]) {
    let targets = std::iter::once(Path::new("/"))
        .chain(entries.iter().map(|entry| entry.mount_point.as_path()))
        .take(LOOKUPS);
    for target in targets {
        if let Some(found) = top_mount_at(entries, target) {
            assert_eq!(found.mount_point, target);
            assert!(entries.iter().any(|entry| std::ptr::eq(entry, found)));
        }
    }
    let hidden = entries
        .first()
        .map_or(Path::new("/mnt/data"), |entry| entry.mount_point.as_path());
    if let Some(upper) = root_is_hidden_overlay(entries, hidden) {
        let root = top_mount_at(entries, Path::new("/")).expect("a hidden root is mounted at /");
        assert_eq!(root.fstype, "overlay");
        assert!(Path::new(&upper).starts_with(hidden), "{upper}");
    }
}
