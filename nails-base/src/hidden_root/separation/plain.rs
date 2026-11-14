// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Whether a line of the decoy's fstab or crypttab is plain: one whose fields
//! NAILS splits and decodes as `libmount` and systemd do, for the crypttab as
//! systemd's crypttab generator does, and whose first field or source, where
//! it names a device or a path, names it in a form NAILS reads. Where a path
//! that a plain line names leads is told apart (see the `paths` module). Of a
//! plain crypttab line the judge reads the name, the source and a few of the
//! options, and not the key file. A line that is not plain is an entry where
//! what it names cannot be told, and that is the only finding the judge makes
//! of it, while it still claims what NAILS reads in it.
//!
//! NAILS's parser splits a line at any white space and decodes the octal
//! escapes (a backslash and three octal digits) of its first two fields in
//! its own way, and of no other field, while `libmount` splits a line only at
//! spaces and tabs and decodes such an escape in every field, so that
//! `bin\144` is the option `bind` to it. A type list (`ext4,xfs`) is mounted
//! as each of its types in turn, which NAILS does not read either. So an
//! fstab line is not plain ([`Unplain`]) that holds a control character
//! other than a tab, or white space other than a space or a tab; whose first
//! field or mount point holds a backslash that begins none of the escapes
//! `\040`, `\011`, `\012` and `\134` (a space, a tab, a newline and a
//! backslash, which both read alike); whose type or options hold a
//! backslash; or whose type is a list. Nor is a line whose first field is
//! neither an absolute path nor a tag NAILS resolves (`UUID=`, `LABEL=`,
//! `PARTUUID=` or `PARTLABEL=`): `mount` and `swapon` look such a path up
//! from the folder they run in, and `libmount` looks an `ID=` tag up in
//! `/dev/disk/by-id`, which NAILS does not. That holds for every line but one
//! whose type names no local path by its first field
//! ([`names_no_local_path`]): a RAM, kernel, host-share, network, overlay or
//! ZFS filesystem's, and never a bind line's, whose first field is the path
//! of its source whatever its type, as `mount` binds whatever the type says.
//!
//! A FUSE line that is no bind line is read as `mount.fuse` reads it
//! ([`fuse_line`]): of the type `fuse`, its first field is a program and,
//! after the first `#`, the source that program gets (`sshfs#host:/path`);
//! of a type `fuse.<program>`, its first field is that source. The source is
//! read as any line's first field is, where NAILS judges what it names, and
//! a line whose source is neither an absolute path nor a tag NAILS resolves,
//! or that gives none, is not plain, unless its program is one that takes a
//! remote source by it ([`takes_a_remote_source`]). A `#` in the first field
//! of a line of any other type that begins with `fuse` (`fuse.<program>`,
//! `fuse3`, `fuseblk`) is not plain either: `mount.fuse3` reads it in a
//! `fuse3` line as it does in a `fuse` one, and in a `fuse.<program>` line a
//! program may read it in its own way.
//!
//! `mount.fuse` runs the program through `/bin/sh`, which looks a name with
//! no `/` up in `PATH` and runs one with a `/` as the path it is, from the
//! folder `mount` runs in, `/`, when it is not absolute ([`fuse_program`]).
//! The judge reads an absolute program as a path, as it reads a bind line's
//! source, and a program with a `/` that is not absolute is not plain.
//!
//! systemd's crypttab generator ends a line at a lone carriage return or a
//! NUL as well as at a newline, splits it at ASCII white space but not at a
//! no-break space, and keeps the quotes and backslashes of a field, which it
//! writes into the command that opens the volume, where they are read as
//! quotes and escapes: the source `'/dev/sdb'` opens `/dev/sdb`, and that
//! command reads `/dev/sd\x62` as `/dev/sdb`. So a crypttab line is not plain
//! that holds a control character other than a tab, or white space other
//! than a space or a tab, or a quote or a backslash in one of its four
//! fields, or whose source is neither an absolute path nor a tag NAILS
//! resolves: `systemd-cryptsetup` opens a relative path from the folder it
//! runs in, `/`. Of a plain line, the judge resolves a source that is a tag
//! or a device's path in `/dev` as a device's name, and reads any other
//! source, which `systemd-cryptsetup` opens through the links in it, as the
//! path of a file, with no link followed (see the `paths` module).

#[cfg(test)]
#[path = "plain_tests.rs"]
mod tests;

use super::paths::names_dev_otherwise;
use crate::crypttab::{CrypttabEntry, parse_crypttab_lines};
use crate::fstab::{
    FstabEntry, is_host_share_type, is_network_type, is_virtual_type, parse_fstab_lines,
};
use std::collections::BTreeMap;

/// The lines of the decoy's fstab or crypttab that are not plain, by the
/// index of their entry among those [`read_fstab`] or [`read_crypttab`]
/// reads. A line it does not hold is plain.
pub type UnplainLines = BTreeMap<usize, UnplainLine>;

/// A line of the decoy's fstab or crypttab that is not plain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnplainLine {
    /// Its first fields as they are written, escapes and all, split at
    /// spaces and tabs as `libmount` splits them, with a control character
    /// or white space other than a space or a tab shown by its code point:
    /// the first three of an fstab line, and the name and the source of a
    /// crypttab line. Never its options, which can hold a password.
    pub shown: String,
    /// Why it is not plain; never empty.
    pub why: Vec<Unplain>,
}

impl UnplainLine {
    /// Why, as a phrase that completes "NAILS reads only plain lines, and".
    pub fn reason(&self) -> String {
        let reasons: Vec<String> = self.why.iter().map(Unplain::reason).collect();
        match reasons.split_last() {
            Some((last, rest)) if !rest.is_empty() => format!("{} and {last}", rest.join(", ")),
            _ => reasons.join(""),
        }
    }
}

/// Why a line of the decoy's fstab or crypttab is not plain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unplain {
    /// The line holds this character: a control character other than a tab,
    /// or white space other than a space or a tab.
    Character(char),
    /// Its first field (`first field`) or its mount point (`mount point`)
    /// holds this backslash, as written with up to three characters after
    /// it, which begins none of the escapes `\040`, `\011`, `\012` and
    /// `\134`.
    Escape {
        /// Which field.
        field: &'static str,
        /// The backslash and up to three characters after it.
        written: String,
    },
    /// Its type holds a backslash.
    TypeBackslash,
    /// Its type is a list of types.
    TypeList,
    /// Its options hold a backslash.
    OptionsBackslash,
    /// Its first field is neither an absolute path nor a tag NAILS
    /// resolves, and its type names a local path by it.
    Relative,
    /// It names a device by an `ID=` tag, which NAILS does not resolve.
    IdTag,
    /// Its first field holds a `#`, and its type begins with `fuse` but is
    /// not `fuse`.
    FuseHash,
    /// It is of the type `fuse` and its first field holds no `#`, so the
    /// FUSE program it names gets no source.
    FuseNoSource,
    /// The source it gives its FUSE program is neither an absolute path nor
    /// a tag NAILS resolves, and that program is none known to take a remote
    /// source.
    FuseSource,
    /// The FUSE program it has `mount.fuse` run is written with a `/` and is
    /// no absolute path ([`fuse_program`]).
    FuseProgram,
    /// Its first field, or the source of a crypttab line, leads into `/dev`
    /// as it is written, while it does not start with `/dev/` or holds a
    /// `..`, such as `//dev/sdb`
    /// ([`names_dev_otherwise`](super::paths::names_dev_otherwise)).
    DevOtherwise,
    /// One of the fields of a crypttab line holds a quote.
    Quote,
    /// One of the fields of a crypttab line holds a backslash.
    Backslash,
    /// The source of a crypttab line is neither an absolute path nor a tag
    /// NAILS resolves.
    RelativeSource,
}

/// The tags NAILS resolves, as a tail completing "nor a".
const TAGS_SHOWN: &str = "UUID=, LABEL=, PARTUUID= or PARTLABEL= tag";

impl Unplain {
    /// Why, as a phrase.
    pub fn reason(&self) -> String {
        match self {
            Unplain::Character(c) => format!(
                "it holds the character U+{:04X}, which is neither a space nor a tab",
                u32::from(*c)
            ),
            Unplain::Escape { field, written } => format!(
                "its {field} holds {written}, which is no escape of a space, a tab, a newline or \
                 a backslash"
            ),
            Unplain::TypeBackslash => "its type holds a backslash".to_string(),
            Unplain::TypeList => "its type is a list of types".to_string(),
            Unplain::OptionsBackslash => "its options hold a backslash".to_string(),
            Unplain::Relative => {
                format!("its first field is neither an absolute path nor a {TAGS_SHOWN}")
            }
            Unplain::IdTag => {
                "it names a device by an ID= tag, which NAILS does not resolve".to_string()
            }
            Unplain::FuseHash => {
                "its first field holds a #, which NAILS reads only in a line of the type fuse"
                    .to_string()
            }
            Unplain::FuseNoSource => "it is of the type fuse with no # in its first field, so \
                                      the FUSE program it names gets no source"
                .to_string(),
            Unplain::FuseSource => format!(
                "the source it gives its FUSE program is neither an absolute path nor a \
                 {TAGS_SHOWN}, and that program is none known to take a remote source"
            ),
            Unplain::FuseProgram => {
                "its FUSE program is a path with a / that is not absolute".to_string()
            }
            Unplain::DevOtherwise => "it names a path in /dev by one that does not start with \
                                      /dev/ or holds a .."
                .to_string(),
            Unplain::Quote => "one of its fields holds a quote".to_string(),
            Unplain::Backslash => "one of its fields holds a backslash".to_string(),
            Unplain::RelativeSource => {
                format!("its source is neither an absolute path nor a {TAGS_SHOWN}")
            }
        }
    }
}

/// The escapes NAILS's parser and `libmount` decode alike in the first two
/// fields of a line: a space, a tab, a newline and a backslash.
const PLAIN_ESCAPES: &[&str] = &["\\040", "\\011", "\\012", "\\134"];

/// The tags NAILS resolves as a device's name in a line's first field, as
/// systemd does ([`spec_device`](crate::fstab::spec_device)). `libmount`
/// knows `ID=` too, which NAILS does not resolve.
const TAGS: &[&str] = &["UUID", "LABEL", "PARTUUID", "PARTLABEL"];

/// Types that `libmount` reads as pseudo or network filesystems besides
/// those NAILS knows as RAM, kernel, host-share and network filesystems, and
/// a few more kernel filesystems and host shares (`aufs`, `xenfs`, `prl_fs`,
/// `vmhgfs`): none names a local path by a line's first field.
const MORE_TYPES_WITHOUT_A_PATH: &[&str] = &[
    "afs",
    "anon_inodefs",
    "apparmorfs",
    "aufs",
    "bdev",
    "binder",
    "cpuset",
    "devfs",
    "dlmfs",
    "dmabuf",
    "drm",
    "ipathfs",
    "ncpfs",
    "none",
    "pipefs",
    "prl_fs",
    "resctrl",
    "rootfs",
    "selinuxfs",
    "smackfs",
    "sockfs",
    "spufs",
    "vboxsf",
    "vmhgfs",
    "xenfs",
];

/// FUSE programs that take a remote source by a line's first field, a name
/// of no path of this computer: an SSH server's folder (`sshfs`), an
/// Amazon S3 or Google Cloud Storage bucket (`s3fs`, `goofys`, `gcsfuse`), a
/// Ceph filesystem (`ceph`), VMware's host share (`vmhgfs-fuse`), and an
/// rclone remote (`rclone`, see [`takes_a_remote_source`]). Where such a
/// source leads, its server or the program's own configuration says, which
/// NAILS does not read.
const REMOTE_FUSE: &[&str] = &[
    "sshfs",
    "s3fs",
    "goofys",
    "gcsfuse",
    "ceph",
    "vmhgfs-fuse",
    "rclone",
];

/// Whether a line of the type `vfstype`, no bind line and no FUSE line,
/// names no local path by its first field: a RAM, kernel, host-share,
/// network (any `nfs` type too), overlay or ZFS filesystem. Such a first
/// field names a source of another kind: `tmpfs`, `server:/export`,
/// `rpool/data`. A FUSE line is read by [`fuse_line`].
pub fn names_no_local_path(vfstype: &str) -> bool {
    is_virtual_type(vfstype)
        || is_host_share_type(vfstype)
        || is_network_type(vfstype)
        || vfstype.starts_with("nfs")
        || MORE_TYPES_WITHOUT_A_PATH.contains(&vfstype)
        || matches!(vfstype, "overlay" | "zfs")
}

/// A FUSE line, as `mount.fuse` reads it: the program it runs, and the
/// source it hands that program, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct FuseLine<'a> {
    /// The program `mount.fuse` runs.
    pub program: &'a str,
    /// What `mount.fuse` hands the program as its source.
    pub source: Option<&'a str>,
}

/// How `mount.fuse` reads the fstab line `entry`, a FUSE line that is no
/// bind line: of the type `fuse`, the program is the part of its first field
/// before the first `#` and the source the part after it, or none without a
/// `#`; of a type `fuse.<program>`, the source is its whole first field,
/// which `mount.fuse` hands that program as it is, a `#` included. `None`
/// for a line of any other type, and for a bind line, which `mount` binds
/// itself whatever its type says.
pub(super) fn fuse_line(entry: &FstabEntry) -> Option<FuseLine<'_>> {
    if entry.is_bind() {
        return None;
    }
    if entry.vfstype == "fuse" {
        return Some(match entry.spec.split_once('#') {
            Some((program, source)) => FuseLine {
                program,
                source: Some(source),
            },
            None => FuseLine {
                program: &entry.spec,
                source: None,
            },
        });
    }
    let program = entry.vfstype.strip_prefix("fuse.")?;
    Some(FuseLine {
        program,
        source: Some(&entry.spec),
    })
}

/// The device or path the fstab line `entry` names by its first field, as
/// `mount` and `mount.fuse` read it: the source of a FUSE line
/// ([`fuse_line`]), none for one that gives none, and the whole first field
/// of every other line.
pub(super) fn source(entry: &FstabEntry) -> Option<&str> {
    fuse_line(entry).map_or(Some(entry.spec.as_str()), |fuse| fuse.source)
}

/// The program `mount.fuse` runs for the fstab line `entry`, as written: the
/// program of a `fuse` or `fuse.<program>` line ([`fuse_line`]), the
/// `<program>` of a `fuseblk.<program>` line, from which `mount.fuse` strips
/// `fuseblk.` as it strips `fuse.`, and the whole type of a line of any other
/// type that begins with `fuse` and holds a `.`, such as `fuse3.<program>`,
/// which `mount.fuse3` runs as it is written (fuse 3.17). `None` for a bind
/// line, and for a line of the type `fuse3` or `fuseblk`, whose program is
/// its first field, which NAILS reads as any line's first field is, and of
/// any other type.
pub(super) fn fuse_program(entry: &FstabEntry) -> Option<&str> {
    if let Some(fuse) = fuse_line(entry) {
        return Some(fuse.program);
    }
    if entry.is_bind() {
        return None;
    }
    if let Some(program) = entry.vfstype.strip_prefix("fuseblk.") {
        return Some(program);
    }
    (entry.vfstype.starts_with("fuse") && entry.vfstype.contains('.'))
        .then_some(entry.vfstype.as_str())
}

/// Whether the FUSE program `program` takes `source` as a remote one, a name
/// of no path of this computer: one of [`REMOTE_FUSE`], but rclone, which
/// takes a local path as well, only for a source it reads as a configured
/// remote's, `remote:path`, whose name before the first `:` is not empty and
/// holds no `/` (`srv/x` and `:local:/srv/x` are local paths to it).
fn takes_a_remote_source(program: &str, source: Option<&str>) -> bool {
    if program == "rclone" {
        return source
            .and_then(|source| source.split_once(':'))
            .is_some_and(|(name, _)| !name.is_empty() && !name.contains('/'));
    }
    REMOTE_FUSE.contains(&program)
}

/// Whether `field`, the first field of an fstab line or the source of a
/// crypttab line, decoded, is an absolute path or a tag NAILS resolves as a
/// device's name.
fn is_read(field: &str) -> bool {
    field.starts_with('/')
        || field
            .split_once('=')
            .is_some_and(|(key, _)| TAGS.contains(&key))
}

/// Why `field`, the device or path an fstab line names by its first field,
/// decoded, is none that NAILS reads: `None` for an absolute path or a tag
/// it resolves, an [`Unplain::IdTag`] for an `ID=` tag, which `libmount`
/// looks up in `/dev/disk/by-id`, and `otherwise` for anything else.
fn unread(field: &str, otherwise: Unplain) -> Option<Unplain> {
    if is_read(field) {
        None
    } else if field.starts_with("ID=") {
        Some(Unplain::IdTag)
    } else {
        Some(otherwise)
    }
}

/// The first backslash in `field`, as written, that begins none of the
/// escapes [`PLAIN_ESCAPES`], with up to three characters after it.
fn stray_backslash(field: &str) -> Option<String> {
    let mut rest = field;
    while let Some(at) = rest.find('\\') {
        let from = &rest[at..];
        if let Some(escape) = PLAIN_ESCAPES
            .iter()
            .find(|escape| from.starts_with(**escape))
        {
            rest = &from[escape.len()..];
            continue;
        }
        return Some(from.chars().take(4).collect());
    }
    None
}

/// Whether `c` is a control character other than a tab, or white space other
/// than a space or a tab.
fn is_unplain_character(c: char) -> bool {
    c != ' ' && c != '\t' && (c.is_control() || c.is_whitespace())
}

/// Why the fstab line `line`, as written and trimmed, whose entry is `entry`,
/// is not plain (see the module docs): nothing for a plain line.
pub fn unplain(entry: &FstabEntry, line: &str) -> Vec<Unplain> {
    // Fields split otherwise tell nothing more.
    if let Some(c) = line.chars().find(|c| is_unplain_character(*c)) {
        return vec![Unplain::Character(c)];
    }
    let mut why = Vec::new();
    let mut fields = line.split_whitespace();
    for field in ["first field", "mount point"] {
        if let Some(written) = fields.next().and_then(stray_backslash) {
            why.push(Unplain::Escape { field, written });
        }
    }
    if entry.vfstype.contains('\\') {
        why.push(Unplain::TypeBackslash);
    }
    if entry.vfstype.contains(',') {
        why.push(Unplain::TypeList);
    }
    if entry.options.iter().any(|option| option.contains('\\')) {
        why.push(Unplain::OptionsBackslash);
    }
    if !entry.is_bind()
        && entry.vfstype.starts_with("fuse")
        && entry.vfstype != "fuse"
        && entry.spec.contains('#')
    {
        why.push(Unplain::FuseHash);
    } else if let Some(fuse) = fuse_line(entry) {
        if !takes_a_remote_source(fuse.program, fuse.source) {
            why.extend(match fuse.source {
                Some(source) => unread(source, Unplain::FuseSource),
                None => Some(Unplain::FuseNoSource),
            });
        }
    } else if entry.is_bind() || !names_no_local_path(&entry.vfstype) {
        why.extend(unread(&entry.spec, Unplain::Relative));
    }
    if fuse_program(entry).is_some_and(|program| program.contains('/') && !program.starts_with('/'))
    {
        why.push(Unplain::FuseProgram);
    }
    if !entry.is_bind()
        && !names_no_local_path(&entry.vfstype)
        && source(entry).is_some_and(names_dev_otherwise)
    {
        why.push(Unplain::DevOtherwise);
    }
    why
}

/// Why the crypttab line `line`, as written and trimmed, whose entry is
/// `entry`, is not plain (see the module docs): nothing for a plain line.
pub fn unplain_crypttab(entry: &CrypttabEntry, line: &str) -> Vec<Unplain> {
    if let Some(c) = line.chars().find(|c| is_unplain_character(*c)) {
        return vec![Unplain::Character(c)];
    }
    let fields: Vec<&str> = line.split_whitespace().take(4).collect();
    let mut why = Vec::new();
    if fields.iter().any(|field| field.contains(['\'', '"'])) {
        why.push(Unplain::Quote);
    }
    if fields.iter().any(|field| field.contains('\\')) {
        why.push(Unplain::Backslash);
    }
    if !is_read(&entry.source) {
        why.push(Unplain::RelativeSource);
    }
    if names_dev_otherwise(&entry.source) {
        why.push(Unplain::DevOtherwise);
    }
    why
}

/// The first `count` fields of `line`, as written and as `libmount` splits
/// them, at spaces and tabs, with each character that
/// [`is_unplain_character`] shown by its code point.
fn shown(line: &str, count: usize) -> String {
    let fields: Vec<&str> = line
        .split([' ', '\t'])
        .filter(|field| !field.is_empty())
        .take(count)
        .collect();
    let mut shown = String::new();
    for c in fields.join(" ").chars() {
        if is_unplain_character(c) {
            shown.push_str(&format!("U+{:04X}", u32::from(c)));
        } else {
            shown.push(c);
        }
    }
    shown
}

/// The entries of the fstab text `text`, as [`parse_fstab`](crate::fstab::parse_fstab)
/// reads them, and those of its lines that are not plain.
pub fn read_fstab(text: &str) -> (Vec<FstabEntry>, UnplainLines) {
    let mut entries = Vec::new();
    let mut unplain_lines = UnplainLines::new();
    for (index, (entry, line)) in parse_fstab_lines(text).into_iter().enumerate() {
        let why = unplain(&entry, line);
        if !why.is_empty() {
            let shown = shown(line, 3);
            unplain_lines.insert(index, UnplainLine { shown, why });
        }
        entries.push(entry);
    }
    (entries, unplain_lines)
}

/// The entries of the crypttab text `text`, as
/// [`parse_crypttab`](crate::crypttab::parse_crypttab) reads them, and those
/// of its lines that are not plain.
pub fn read_crypttab(text: &str) -> (Vec<CrypttabEntry>, UnplainLines) {
    let mut entries = Vec::new();
    let mut unplain_lines = UnplainLines::new();
    for (index, (entry, line)) in parse_crypttab_lines(text).into_iter().enumerate() {
        let why = unplain_crypttab(&entry, line);
        if !why.is_empty() {
            let shown = shown(line, 2);
            unplain_lines.insert(index, UnplainLine { shown, why });
        }
        entries.push(entry);
    }
    (entries, unplain_lines)
}
