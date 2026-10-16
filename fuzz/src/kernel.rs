// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! How the kernel prints a mount table line (`show_mountinfo()` in
//! fs/proc_namespace.c), for the round trips of the mountinfo target.

use nails_teardown::mountinfo::MountEntry;
use std::path::Path;

/// The bytes `mangle()` octal-escapes in a path field of mountinfo.
pub const PATH_SPECIAL: &[u8] = b" \t\n\\";

/// The bytes `seq_show_option()` octal-escapes in an option's value.
pub const OPTION_SPECIAL: &[u8] = b", \t\n\\";

/// `text` with each byte of `special` as a three-digit octal escape, the way
/// `seq_escape()` writes it.
pub fn escape(text: &str, special: &[u8]) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_ascii() && special.contains(&(c as u8)) {
            out.push_str(&format!("\\{:03o}", u32::from(c)));
        } else {
            out.push(c);
        }
    }
    out
}

/// A root or mount point as the kernel prints it. Neither is ever a bare `-`
/// there (a root is a path in its filesystem, a mount point an absolute
/// path), and mountinfo's separator is the first field that is, so a decoded
/// `-` is written escaped to keep the line readable.
fn before_separator(path: &Path) -> String {
    let text = path.to_string_lossy();
    if text == "-" {
        "\\055".to_string()
    } else {
        escape(&text, PATH_SPECIAL)
    }
}

/// `entry` as a mountinfo line, without the optional fields.
pub fn mountinfo_line(entry: &MountEntry) -> String {
    format!(
        "{} {} {} {} {} {} - {} {} {}",
        entry.mount_id,
        entry.parent_id,
        entry.dev,
        before_separator(&entry.root),
        before_separator(&entry.mount_point),
        entry.mount_opts,
        entry.fstype,
        escape(&entry.source.to_string_lossy(), PATH_SPECIAL),
        entry.super_opts,
    )
}
