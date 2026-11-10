// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Whether NAILS reads a line of the decoy's fstab as `libmount` and systemd
//! read it: a plain line. A line that is not plain is an entry whose path
//! cannot be told, and that is the only finding the judge makes of it, while
//! it still claims what NAILS reads in it.
//!
//! NAILS's parser splits a line at any white space and decodes the octal
//! escapes (a backslash and three octal digits) of its first two fields in
//! its own way, and of no other field, while `libmount` splits a line only at
//! spaces and tabs and decodes such an escape in every field, so that
//! `bin\144` is the option `bind` to it. A type list (`ext4,xfs`) is mounted
//! as each of its types in turn, which NAILS does not read either. So a line
//! is not plain ([`Unplain`]) that holds a control character other than a
//! tab, or white space other than a space or a tab; whose first field or
//! mount point holds a backslash that begins none of the escapes `\040`,
//! `\011`, `\012` and `\134` (a space, a tab, a newline and a backslash,
//! which both read alike); whose type or options hold a backslash; or whose
//! type is a list. Nor is a line whose first field is neither an absolute
//! path nor a tag (`UUID=`, `LABEL=`, `PARTUUID=`, `PARTLABEL=` or `ID=`):
//! `mount` and `swapon` look such a path up from the folder they run in.
//! That holds for every line but one whose type names no local path by its
//! first field ([`names_no_local_path`]): a RAM, kernel, host-share, network,
//! overlay, ZFS or FUSE filesystem's, and never a bind line's, whose first
//! field is the path of its source whatever its type.

#[cfg(test)]
#[path = "plain_tests.rs"]
mod tests;

use crate::fstab::{
    FstabEntry, is_host_share_type, is_network_type, is_virtual_type, parse_fstab_lines,
};
use std::collections::BTreeMap;

/// The lines of the decoy's fstab that are not plain, by the index of their
/// entry among those [`read_fstab`] reads. A line it does not hold is plain.
pub type UnplainLines = BTreeMap<usize, UnplainLine>;

/// A line of the decoy's fstab that is not plain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnplainLine {
    /// Its first three fields as they are written, escapes and all, split
    /// at spaces and tabs as `libmount` splits them, with a control
    /// character or white space other than a space or a tab shown by its
    /// code point. Never its options, which can hold a password.
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

/// Why a line of the decoy's fstab is not plain.
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
    /// Its first field is neither an absolute path nor a tag, and its type
    /// names a local path by it.
    Relative,
}

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
            Unplain::Relative => "its first field is neither an absolute path nor a UUID=, \
                                  LABEL=, PARTUUID=, PARTLABEL= or ID= tag"
                .to_string(),
        }
    }
}

/// The escapes NAILS's parser and `libmount` decode alike in the first two
/// fields of a line: a space, a tab, a newline and a backslash.
const PLAIN_ESCAPES: &[&str] = &["\\040", "\\011", "\\012", "\\134"];

/// The tags `libmount` reads as a device's name in a line's first field.
const TAGS: &[&str] = &["UUID", "LABEL", "PARTUUID", "PARTLABEL", "ID"];

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

/// Whether a line of the type `vfstype`, no bind line, names no local path by
/// its first field: a RAM, kernel, host-share, network (any `nfs` type too),
/// overlay, ZFS or FUSE filesystem (`fuse` or `fuse.<type>`, not `fuseblk`,
/// which names a block device). Such a first field names a source of
/// another kind: `tmpfs`, `server:/export`, `rpool/data`, `remote:path`.
pub fn names_no_local_path(vfstype: &str) -> bool {
    is_virtual_type(vfstype)
        || is_host_share_type(vfstype)
        || is_network_type(vfstype)
        || vfstype.starts_with("nfs")
        || MORE_TYPES_WITHOUT_A_PATH.contains(&vfstype)
        || matches!(vfstype, "overlay" | "zfs" | "fuse")
        || vfstype.starts_with("fuse.")
}

/// Whether `spec`, the first field of an fstab line, decoded, is a tag
/// `libmount` reads as a device's name.
fn is_tag(spec: &str) -> bool {
    spec.split_once('=')
        .is_some_and(|(key, _)| TAGS.contains(&key))
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
    let names_a_path = entry.is_bind() || !names_no_local_path(&entry.vfstype);
    if names_a_path && !entry.spec.starts_with('/') && !is_tag(&entry.spec) {
        why.push(Unplain::Relative);
    }
    why
}

/// The first three fields of `line`, as written and as `libmount` splits
/// them, at spaces and tabs, with each character that
/// [`is_unplain_character`] shown by its code point.
fn shown(line: &str) -> String {
    let fields: Vec<&str> = line
        .split([' ', '\t'])
        .filter(|field| !field.is_empty())
        .take(3)
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
            let shown = shown(line);
            unplain_lines.insert(index, UnplainLine { shown, why });
        }
        entries.push(entry);
    }
    (entries, unplain_lines)
}
