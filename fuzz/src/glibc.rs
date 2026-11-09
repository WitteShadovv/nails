// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! How glibc reads one line of an fstab with `getmntent()`, as
//! systemd-fstab-generator up to systemd 258 reads `/etc/fstab`:
//! `get_mnt_entry()` and `decode_name()` (misc/mntent_r.c), with the buffer
//! of 4096 bytes `getmntent()` passes (misc/mntent.c), as in glibc 2.39 to
//! 2.42.
//!
//! Left out: glibc skips an `autofs` line with the option `ignore`, which
//! NAILS deciding as well does no harm, and after a line with a NUL it drops
//! the next one too.

/// The fields of an fstab line, decoded; an empty one for each the line does
/// not have.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MntEnt {
    pub fsname: Vec<u8>,
    pub dir: Vec<u8>,
    pub kind: Vec<u8>,
    pub opts: Vec<u8>,
}

/// `fgets()` reads this much of a line at most, with its newline, into the
/// buffer `getmntent()` passes, and drops the rest.
const READ: usize = 4095;

/// `line`, without its newline, as `getmntent()` reads it; `None` for a
/// blank line or a comment.
pub fn getmntent(line: &[u8]) -> Option<MntEnt> {
    let read = &line[..line.len().min(READ)];
    // strchr() finds the newline only when it came with the line and no NUL
    // stands before it; the line then loses the spaces and tabs at its end.
    let newline = line.len() < READ && !read.contains(&0);
    let mut buffer = match read.iter().position(|byte| *byte == 0) {
        Some(nul) => &read[..nul],
        None => read,
    };
    if newline {
        while let [rest @ .., b' ' | b'\t'] = buffer {
            buffer = rest;
        }
    }
    let start = buffer
        .iter()
        .position(|byte| !matches!(byte, b' ' | b'\t'))
        .unwrap_or(buffer.len());
    let head = &buffer[start..];
    if head.first().is_none_or(|byte| *byte == b'#') {
        return None;
    }
    // strsep() at spaces and tabs, strspn() over the run after each field.
    let mut fields = head
        .split(|byte| matches!(byte, b' ' | b'\t'))
        .filter(|field| !field.is_empty())
        .map(decode_name);
    Some(MntEnt {
        fsname: fields.next().unwrap_or_default(),
        dir: fields.next().unwrap_or_default(),
        kind: fields.next().unwrap_or_default(),
        opts: fields.next().unwrap_or_default(),
    })
}

/// `decode_name()`: `\040`, `\011`, `\012` and `\134` undone, and `\\` read
/// as one backslash; every other byte as it is.
fn decode_name(field: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(field.len());
    let mut at = 0;
    while at < field.len() {
        let rest = &field[at..];
        let escape = [
            (b"\\040".as_slice(), b' '),
            (b"\\011", b'\t'),
            (b"\\012", b'\n'),
            (b"\\134", b'\\'),
            (b"\\\\", b'\\'),
        ]
        .into_iter()
        .find(|(escape, _)| rest.starts_with(escape));
        match escape {
            Some((escape, byte)) => {
                out.push(byte);
                at += escape.len();
            }
            None => {
                out.push(rest[0]);
                at += 1;
            }
        }
    }
    out
}
