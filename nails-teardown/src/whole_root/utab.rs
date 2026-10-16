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
//! with its source and root. The way back ([`restored_lines`]) gives the
//! decoy's own lines back to the decoy: its root and its other mounts come back
//! as new mounts with new IDs ([`crate::whole_root::decoy_mounts`]), so a line
//! takes the ID of the mount the way back made in place of the one it named
//! when the copy was taken ([`named_mounts`]), with the same source and root,
//! also where mounts are stacked at one place. Without that, the decoy's
//! initrd mounts would lose `x-initrd.mount` after a session, and its next
//! shutdown would unmount them as units, which neither a fresh boot nor a plain
//! soft-reboot does. A line without an ID joins the newest mount at its target
//! with its source and root, as before the session. A line of the decoy's that
//! names no mount the way back restores is not given back: one already stale
//! when the copy was taken, one whose mount does not come back, one libmount
//! skips.
//!
//! The transition writes `utab` the way libmount does ([`update`]): under
//! libmount's lock, through a new file renamed over the old one.

use crate::mountinfo::{MountEntry, unescape_octal};
use std::borrow::Cow;
use std::fs::{File, OpenOptions, TryLockError};
use std::io::{self, Write};
use std::ops::Range;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// libmount's userspace mount table below a `/run` root.
pub const UTAB: &str = "mount/utab";

/// libmount's lock file for [`UTAB`], below a `/run` root.
const UTAB_LOCK: &str = "mount/utab.lock";

/// How long a switch waits for a libmount update of `utab` to finish.
const LOCK_BUDGET: Duration = Duration::from_secs(2);

/// The mode libmount gives `utab`.
const UTAB_MODE: u32 = 0o644;

/// Rewrite `utab` below the `/run` root `run` to what `new` makes of its text,
/// the way libmount updates it: under libmount's lock, through a new file with
/// libmount's mode and the old file's owner, renamed over the old one. No
/// reader sees half a file, and a libmount update in progress neither reads
/// the file before this write nor renames its own copy over it afterwards.
/// The lock is taken only where its file exists, as creating it would leave a
/// file the other side never had, and after [`LOCK_BUDGET`] the write goes
/// ahead without it. A missing `utab` stays missing, and an unchanged one is
/// not written: the result says whether it was.
pub fn update(run: &Path, new: impl FnOnce(&[u8]) -> Vec<u8>) -> io::Result<bool> {
    let path = run.join(UTAB);
    let _lock = lock(&run.join(UTAB_LOCK));
    let old = match std::fs::read(&path) {
        Ok(old) => old,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    let text = new(&old);
    if text == old {
        return Ok(false);
    }
    replace(&path, &text)?;
    Ok(true)
}

/// libmount's lock (`flock`) on the existing file `path`, held until the file
/// is dropped; `None` when there is no such file or the lock stays taken for
/// [`LOCK_BUDGET`].
fn lock(path: &Path) -> Option<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .ok()?;
    let deadline = Instant::now() + LOCK_BUDGET;
    loop {
        match file.try_lock() {
            Ok(()) => return Some(file),
            Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(_) => return None,
        }
    }
}

/// Replace the file at `path` with `bytes`: a new file next to it, named the
/// way libmount names its own (`utab.<suffix>`), renamed over it. A file of
/// that name that a transition killed halfway left behind goes first.
fn replace(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let owner = std::fs::metadata(path)?;
    let temp = path.with_extension(std::process::id().to_string());
    let _ = std::fs::remove_file(&temp);
    let written = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        file.write_all(bytes)?;
        file.set_permissions(std::fs::Permissions::from_mode(UTAB_MODE))?;
        std::os::unix::fs::fchown(&file, Some(owner.uid()), Some(owner.gid()))?;
        std::fs::rename(&temp, path)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    written
}

/// The lines of `utab` that still name the same mount once PID 1 has switched
/// to `nextroot`, given the live mount table `mounts`. Kept lines are copied
/// byte for byte.
pub fn surviving_lines(utab: &[u8], mounts: &[MountEntry], nextroot: &Path) -> Vec<u8> {
    rewrite(utab, |bytes| {
        Line::parse(bytes)?.carried(mounts, nextroot)?;
        Some(Cow::Borrowed(bytes))
    })
}

/// The lines of `mountinfo` (`/proc/self/mountinfo` read just after `utab`)
/// for the mounts `utab` names by ID: what the way back needs to find each
/// of them again ([`restored_lines`]).
pub fn named_mounts(utab: &[u8], mountinfo: &str) -> String {
    let ids: Vec<i32> = utab
        .split(|&b| b == b'\n')
        .filter_map(Line::parse)
        .map(|line| line.id)
        .filter(|&id| id > 0)
        .collect();
    let mut named = String::new();
    for line in mountinfo.lines() {
        let id = line
            .split_whitespace()
            .next()
            .and_then(|id| id.parse().ok());
        if id.is_some_and(|id| ids.contains(&id)) {
            named.push_str(line);
            named.push('\n');
        }
    }
    named
}

/// The IDs of the mounts in `mounts` that a line of `utab` marks
/// `x-initrd.mount`, joined the way libmount joins a line: by its ID, or the
/// newest mount at its target with its source and root. systemd leaves such a
/// mount alone at a soft-reboot.
pub fn initrd_mounts(utab: &[u8], mounts: &[MountEntry]) -> Vec<i32> {
    utab.split(|&b| b == b'\n')
        .filter_map(Line::parse)
        .filter(|line| line.joins() && line.has_option("x-initrd.mount"))
        .filter_map(|line| line.carried(mounts, Path::new("/")))
        .map(|mount| mount.mount_id)
        .collect()
}

/// The lines of the decoy's `utab` copy to put back on the way back, once PID
/// 1 switches to the decoy root at `nextroot`. `named` holds the mount table
/// lines [`named_mounts`] recorded with the copy, and `restored` the ID each
/// decoy mount the way back made again had at entry with the ID it has now
/// ([`crate::whole_root::decoy_mounts`]). A line that names an ID takes the ID
/// its mount has now, below `nextroot` at its mount's place with that mount's
/// source and root; it is dropped when its mount did not come back, or when it
/// did not fit the mount its ID named when the copy was taken. A plan written
/// before the way back recorded the new IDs has no `restored`: the line then
/// takes the ID of the newest mount at that place. Without `named`, and for a
/// line without an ID, the rule of [`surviving_lines`] decides. Everything but
/// the ID is copied byte for byte.
pub fn restored_lines(
    saved: &[u8],
    named: Option<&[MountEntry]>,
    restored: Option<&[(i32, i32)]>,
    mounts: &[MountEntry],
    nextroot: &Path,
) -> Vec<u8> {
    rewrite(saved, |bytes| {
        let line = Line::parse(bytes)?;
        let Some(named) = named.filter(|_| line.id > 0) else {
            line.carried(mounts, nextroot)?;
            return Some(Cow::Borrowed(bytes));
        };
        let then = named
            .iter()
            .find(|m| m.mount_id == line.id && line.fits(m))?;
        let at = below(nextroot, &then.mount_point);
        let in_place =
            |m: &&MountEntry| m.mount_point == at && m.source == then.source && m.root == then.root;
        let now = match restored {
            Some(restored) => {
                let (_, id) = restored.iter().find(|(old, _)| *old == line.id)?;
                mounts.iter().find(|m| m.mount_id == *id).filter(in_place)?
            }
            None => mounts.iter().rev().find(in_place)?,
        };
        let mut rekeyed = bytes[..line.id_at.start].to_vec();
        rekeyed.extend_from_slice(now.mount_id.to_string().as_bytes());
        rekeyed.extend_from_slice(&bytes[line.id_at.end..]);
        Some(Cow::Owned(rekeyed))
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

/// One `utab` line as libmount 2.42 reads it (`mnt_parse_utab_line`): without
/// its newline and a carriage return before it, from its first character that
/// is not a blank; a field starts after a run of spaces with its `KEY=`, only
/// the first of each key counts, a value runs to the next space or tab and is
/// octal-escaped, and an empty value or a number that does not end at a space,
/// a tab or the end of the line makes libmount skip the whole line. libmount
/// joins a line to a mount only when it has a source, a target, a root and
/// options or attributes, and joins each mount to one line at most.
#[derive(Debug, Default)]
struct Line {
    /// The mount ID, 0 for none (a negative one is matched by path too).
    id: i32,
    /// Where the ID's value is in the line.
    id_at: Range<usize>,
    source: Option<PathBuf>,
    target: Option<PathBuf>,
    root: Option<PathBuf>,
    /// The options (`OPTS=`), still escaped.
    options: Option<String>,
    /// Whether it has attributes (`ATTRS=`).
    attributes: bool,
}

impl Line {
    /// The line's fields, or `None` for a line libmount skips: a blank line, a
    /// comment, one with a number it cannot read.
    fn parse(bytes: &[u8]) -> Option<Self> {
        let bytes = bytes.strip_suffix(b"\r").unwrap_or(bytes);
        let mut at = bytes
            .iter()
            .position(|&b| b != b' ' && b != b'\t')
            .filter(|&first| bytes[first] != b'#')?;
        let mut line = Self::default();
        let mut uniq_id = 0;
        let mut set = [false; STRING_KEYS.len()];
        loop {
            while bytes.get(at) == Some(&b' ') {
                at += 1;
            }
            let rest = &bytes[at.min(bytes.len())..];
            if rest.is_empty() {
                return Some(line);
            }
            if uniq_id == 0 && rest.starts_with(b"UNIQID=") {
                let (_, magnitude, end) = number(bytes, at + 7)?;
                (uniq_id, at) = (magnitude, end);
            } else if line.id == 0 && rest.starts_with(b"ID=") {
                let (negative, magnitude, end) = number(bytes, at + 3)?;
                // libmount gives up on a value beyond `long` and cuts one
                // beyond `int` short. Neither is a mount's ID: the line goes.
                let magnitude = i64::try_from(magnitude).ok()?;
                line.id = i32::try_from(if negative { -magnitude } else { magnitude }).ok()?;
                if line.id != 0 {
                    line.id_at = at + 3..end;
                }
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
                // libmount's unmangle() returns no string for an empty value,
                // which it takes for a failed allocation: the line goes.
                if end == start {
                    return None;
                }
                set[key] = true;
                let value = String::from_utf8_lossy(&bytes[start..end]);
                let path = || Some(PathBuf::from(unescape_octal(&value)));
                match key {
                    0 => line.source = path(),
                    1 => line.target = path(),
                    2 => line.root = path(),
                    4 => line.options = Some(value.into_owned()),
                    5 => line.attributes = true,
                    _ => {}
                }
                at = end;
            } else {
                // A field libmount does not know: skipped to the next space.
                at += rest.iter().position(|&b| b == b' ').unwrap_or(rest.len());
            }
        }
    }

    /// Whether libmount joins the line to a mount at all: it needs a source,
    /// a target, a root and options or attributes.
    fn joins(&self) -> bool {
        self.source.is_some()
            && self.target.is_some()
            && self.root.is_some()
            && (self.options.is_some() || self.attributes)
    }

    /// Whether the line's options hold `option`.
    fn has_option(&self, option: &str) -> bool {
        self.options
            .as_deref()
            .is_some_and(|options| options.split(',').any(|o| o == option))
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

/// A number at `start` the way `strtol` and `strtoumax` read one (blanks, a
/// sign, digits): whether it is negative, its magnitude and where it ends. An
/// empty value at the end of the line is no number, read as 0, and libmount
/// reads on. `None` where libmount gives up on the line: no digits, more than
/// 64 bits, or anything but a space, a tab or the end of the line after it.
fn number(bytes: &[u8], start: usize) -> Option<(bool, u64, usize)> {
    if start >= bytes.len() {
        return Some((false, 0, start));
    }
    let mut at = start;
    while bytes
        .get(at)
        .is_some_and(|b| matches!(b, b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r'))
    {
        at += 1;
    }
    let negative = bytes.get(at) == Some(&b'-');
    if matches!(bytes.get(at), Some(b'-' | b'+')) {
        at += 1;
    }
    let digits = bytes[at..]
        .iter()
        .take_while(|b| b.is_ascii_digit())
        .count();
    let magnitude = std::str::from_utf8(&bytes[at..at + digits])
        .ok()?
        .parse()
        .ok()?;
    let end = at + digits;
    if !matches!(bytes.get(end), None | Some(b' ' | b'\t')) {
        return None;
    }
    Some((negative, magnitude, end))
}

#[cfg(test)]
#[path = "utab_tests.rs"]
mod tests;
