// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! How the kernel prints a mount table line (`show_mountinfo()` in
//! fs/proc_namespace.c), for the round trips of the mountinfo target.

use nails_teardown::mountinfo::MountEntry;
use std::os::unix::ffi::OsStrExt;
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

/// The bytes of `path` with each byte of `special` as a three-digit octal
/// escape, the way `mangle()` writes a path: every other byte as it is,
/// valid UTF-8 or not.
pub fn escape_bytes(path: &[u8], special: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(path.len());
    for &byte in path {
        if special.contains(&byte) {
            out.extend_from_slice(format!("\\{byte:03o}").as_bytes());
        } else {
            out.push(byte);
        }
    }
    out
}

/// A root or mount point as the kernel prints it. Neither is ever a bare `-`
/// there (a root is a path in its filesystem, a mount point an absolute
/// path), and mountinfo's separator is the first field that is, so a decoded
/// `-` is written escaped to keep the line readable.
fn before_separator(path: &Path) -> Vec<u8> {
    let bytes = path.as_os_str().as_bytes();
    if bytes == b"-" {
        b"\\055".to_vec()
    } else {
        escape_bytes(bytes, PATH_SPECIAL)
    }
}

/// `entry` as a mountinfo line, without the optional fields and without its
/// newline. Its paths are written byte for byte; its text fields as they
/// are kept, escapes and all, which parse back to the same text.
pub fn mountinfo_line(entry: &MountEntry) -> Vec<u8> {
    let mut line = format!("{} {} {} ", entry.mount_id, entry.parent_id, entry.dev).into_bytes();
    line.extend(before_separator(&entry.root));
    line.push(b' ');
    line.extend(before_separator(&entry.mount_point));
    line.extend(format!(" {} - {} ", entry.mount_opts, entry.fstype).into_bytes());
    line.extend(escape_bytes(
        entry.source.as_os_str().as_bytes(),
        PATH_SPECIAL,
    ));
    line.push(b' ');
    line.extend(entry.super_opts.as_bytes());
    line
}
