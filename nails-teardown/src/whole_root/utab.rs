// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! libmount's userspace mount table, `/run/mount/utab`, across a switch.
//!
//! libmount keeps the options the kernel does not store (`x-initrd.mount`,
//! `x-*`, a bind's source) in `utab`, one line per mount, and joins the lines
//! to the mounts whenever a program reads the mount table through it, as
//! systemd does after every change. A line that names a kernel mount ID
//! (`ID=`) joins the mount that has that ID now, whatever its source and
//! target; a line without one joins the newest mount at the line's target
//! with its source and root. systemd reads the joined options: a mount marked
//! `x-initrd.mount` outside the initrd is one the shutdown leaves alone, with
//! no order against `local-fs.target` or `umount.target`.
//!
//! A soft-reboot carries `/run` and every line in it, but of the mounts only
//! those at or below the next root: PID 1 copies the API filesystems under new
//! IDs and detaches the root it leaves with everything else, and the kernel
//! hands the freed IDs to the next mounts it makes. A line left behind joins
//! whichever later mount gets its ID, or is mounted at its path with its source
//! and root. A systemd initrd writes
//! `ID=62 SRC=/dev/vda TARGET=/sysroot ROOT=/ OPTS=x-initrd.mount` for the
//! decoy's root; once that root is gone, ID 62 can go to `/run/wrappers` while
//! the next userspace mounts it, or to the hidden volume. systemd then takes
//! that mount for an initrd mount in the middle of its job and drops its order,
//! and PID 1 never resumes the job that waited for it: `local-fs.target` at
//! startup, `local-fs-pre.target` at a shutdown with a disk mounted over the
//! hidden volume.
//!
//! [`surviving_lines`] keeps a line only while it names a mount the switch
//! carries: by its ID, a mount at or below the next root with the line's source
//! and root; without an ID, the mount at the line's target in the next root,
//! with its source and root. The transition applies it on entry to the carried
//! `utab`, and on the way back to the decoy's copy.

use crate::mountinfo::{MountEntry, unescape_octal};
use std::borrow::Cow;
use std::path::{Path, PathBuf};

/// The lines of `utab` that still name the same mount once PID 1 has switched
/// to `nextroot`, given the live mount table `mounts`. Kept lines are copied
/// byte for byte.
pub fn surviving_lines(utab: &[u8], mounts: &[MountEntry], nextroot: &Path) -> Vec<u8> {
    rewrite(utab, |bytes| {
        Line::parse(bytes)?.carried(mounts, nextroot)?;
        Some(Cow::Borrowed(bytes))
    })
}

/// `utab` with each line replaced by what `keep` makes of it (`None` drops
/// it), every kept line ending in a newline.
fn rewrite<'a>(utab: &'a [u8], mut keep: impl FnMut(&'a [u8]) -> Option<Cow<'a, [u8]>>) -> Vec<u8> {
    let mut out = Vec::with_capacity(utab.len());
    for line in utab.split(|&b| b == b'\n') {
        if let Some(kept) = keep(line) {
            out.extend_from_slice(&kept);
            out.push(b'\n');
        }
    }
    out
}

/// `path`, absolute inside the root mounted at `nextroot`, seen from outside.
fn below(nextroot: &Path, path: &Path) -> PathBuf {
    nextroot.join(path.strip_prefix("/").unwrap_or(path))
}

/// The string fields of a line, in the order libmount tries them. Only the
/// first three are read; the others are skipped the way libmount skips them.
const STRING_KEYS: [&[u8]; 6] = [
    b"SRC=",
    b"TARGET=",
    b"ROOT=",
    b"BINDSRC=",
    b"OPTS=",
    b"ATTRS=",
];

/// One `utab` line as libmount 2.42 reads it (`mnt_parse_utab_line`): a field
/// starts after a run of spaces with its `KEY=`, only the first of each key
/// counts, a value runs to the next space or tab and is octal-escaped, and a
/// number that does not end at a space, a tab or the end of the line makes
/// libmount skip the whole line.
#[derive(Debug, Default)]
struct Line {
    /// The mount ID, 0 for none (a negative one is matched by path too).
    id: i32,
    source: Option<PathBuf>,
    target: Option<PathBuf>,
    root: Option<PathBuf>,
}

impl Line {
    /// The line's fields, or `None` for a line libmount skips.
    fn parse(bytes: &[u8]) -> Option<Self> {
        let mut line = Self::default();
        let mut uniq_id = 0;
        let mut set = [false; STRING_KEYS.len()];
        let mut at = 0;
        loop {
            while bytes.get(at) == Some(&b' ') {
                at += 1;
            }
            let rest = &bytes[at.min(bytes.len())..];
            if rest.is_empty() {
                return Some(line);
            }
            if uniq_id == 0 && rest.starts_with(b"UNIQID=") {
                (uniq_id, at) = number(bytes, at + 7)?;
            } else if line.id == 0 && rest.starts_with(b"ID=") {
                let (id, end) = number(bytes, at + 3)?;
                line.id = i32::try_from(id).ok()?;
                at = end;
            } else if let Some(key) =
                (0..STRING_KEYS.len()).find(|&k| !set[k] && rest.starts_with(STRING_KEYS[k]))
            {
                let start = at + STRING_KEYS[key].len();
                let value = &bytes[start..];
                let end = start
                    + value
                        .iter()
                        .position(|&b| b == b' ' || b == b'\t')
                        .unwrap_or(value.len());
                set[key] = true;
                let value =
                    PathBuf::from(unescape_octal(&String::from_utf8_lossy(&bytes[start..end])));
                match key {
                    0 => line.source = Some(value),
                    1 => line.target = Some(value),
                    2 => line.root = Some(value),
                    _ => {}
                }
                at = end;
            } else {
                // A field libmount does not know: skipped to the next space.
                at += rest.iter().position(|&b| b == b' ').unwrap_or(rest.len());
            }
        }
    }

    /// Whether `mount` has the line's source and root, each where the line
    /// names one.
    fn fits(&self, mount: &MountEntry) -> bool {
        self.source.as_ref().is_none_or(|s| *s == mount.source)
            && self.root.as_ref().is_none_or(|r| *r == mount.root)
    }

    /// The mount libmount joins the line to once PID 1 has switched to
    /// `nextroot`, if the switch carries it: by the line's ID, a mount at or
    /// below `nextroot`; without one, the newest mount at the line's target in
    /// it. Either way it has the line's source and root.
    fn carried<'a>(&self, mounts: &'a [MountEntry], nextroot: &Path) -> Option<&'a MountEntry> {
        if self.id > 0 {
            return mounts.iter().find(|m| {
                m.mount_id == self.id && m.mount_point.starts_with(nextroot) && self.fits(m)
            });
        }
        let at = below(nextroot, self.target.as_deref()?);
        mounts
            .iter()
            .rev()
            .find(|m| m.mount_point == at && self.fits(m))
    }
}

/// A number at `start` the way `strtol` reads one (blanks, a sign, digits),
/// and where it ends; `None` where libmount gives up on the line: no digits,
/// an overflow, or anything but a space, a tab or the end of the line after it.
fn number(bytes: &[u8], start: usize) -> Option<(i64, usize)> {
    let mut at = start;
    while bytes.get(at).is_some_and(u8::is_ascii_whitespace) {
        at += 1;
    }
    let negative = bytes.get(at) == Some(&b'-');
    if matches!(bytes.get(at), Some(b'-' | b'+')) {
        at += 1;
    }
    let digits = bytes
        .get(at..)?
        .iter()
        .take_while(|b| b.is_ascii_digit())
        .count();
    let magnitude: i64 = std::str::from_utf8(&bytes[at..at + digits])
        .ok()?
        .parse()
        .ok()?;
    let end = at + digits;
    if !matches!(bytes.get(end), None | Some(b' ' | b'\t')) {
        return None;
    }
    Some((if negative { -magnitude } else { magnitude }, end))
}

#[cfg(test)]
#[path = "utab_tests.rs"]
mod tests;
