// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! One correct parser for `/proc/self/mountinfo`.
//!
//! Every mount-table reader in the crate goes through this module. The table
//! is read as bytes: the kernel writes a path exactly as it is stored, so a
//! mount point, a root, a source or an option may hold any byte but the
//! newline, and one that is not valid UTF-8 is still a mount like any other.
//! The kernel octal-escapes the bytes space (`\040`), tab (`\011`), newline
//! (`\012`) and backslash (`\134`) in the `root`, `mount_point` and `source`
//! fields, so a hidden root at a path with a space (common for udisks
//! automounts) must be decoded before it can be compared. The parser:
//!
//! - decodes those escapes everywhere a path appears and keeps every other
//!   byte of the path as the kernel gave it, valid UTF-8 or not,
//! - keeps each other field as text in the kernel's own escaped form, with a
//!   byte that is not valid UTF-8 written as an octal escape too (see
//!   [`MountEntry::super_opts`]), so nothing is replaced or dropped,
//! - never stats or canonicalizes an entry (only the single queried target is
//!   canonicalized, by the caller), so a dead NFS/CIFS/FUSE mount cannot block
//!   the scan,
//! - skips a malformed line with a debug log instead of aborting the whole scan.
//!
//! `/proc/self/mountinfo` is used rather than `/proc/mounts` because it carries
//! `mount_id`/`parent_id`/`dev` and a per-superblock options field (an overlay's
//! layers), which is how the session tells its own overlay root apart.

use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

/// One parsed line of `/proc/self/mountinfo`.
///
/// Field names follow proc(5). `root`, `mount_point` and `source` are already
/// octal-decoded, byte for byte; `super_opts` is the raw per-superblock option
/// string (overlay `lowerdir`/`upperdir`/`workdir` live here) and is decoded
/// lazily by [`parse_overlay_opts`].
///
/// The text fields (`dev`, `mount_opts`, `fstype`, `super_opts`) hold what the
/// kernel wrote, still escaped as the kernel escapes them. Where the kernel
/// wrote a byte that is not valid UTF-8 there (an option value or a FUSE
/// subtype may hold one), the field holds that byte as a three-digit octal
/// escape (`\377`), the form in which the kernel writes a space there, so
/// [`unescape_octal_bytes`] gives back the kernel's byte and no comparison
/// meets a replaced one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountEntry {
    pub mount_id: i32,
    pub parent_id: i32,
    /// `major:minor` of the backing device, as text.
    pub dev: String,
    /// Directory in the filesystem that forms the root of this mount.
    pub root: PathBuf,
    /// Where the mount appears in the namespace.
    pub mount_point: PathBuf,
    /// Per-mount options before the ` - ` separator (`rw,relatime`, `ro,nosuid`…).
    ///
    /// This is the VFS mount-flag field, not the per-superblock options, so it is
    /// where a mount's read-only-ness is recorded independent of how the
    /// filesystem itself was mounted. [`read_only`](MountEntry::read_only) reads
    /// it to decide whether a hidden submount can be re-attached read-only or
    /// needs its own nested overlay.
    pub mount_opts: String,
    /// Filesystem type after the ` - ` separator (e.g. `overlay`, `ext4`).
    pub fstype: String,
    /// Mount source after the ` - ` separator (device or bind source).
    pub source: PathBuf,
    /// Per-superblock options after the ` - ` separator, escaped as the
    /// struct's docs say.
    pub super_opts: String,
}

impl MountEntry {
    /// Whether this mount is read-only, from its per-mount option field.
    ///
    /// The VFS records read-only-ness as a bare `ro` token in the per-mount
    /// options (field 6 of mountinfo), so the check is an exact token match
    /// rather than a substring test — `relatime` must never be mistaken for `ro`.
    pub fn read_only(&self) -> bool {
        self.mount_opts.split(',').any(|opt| opt == "ro")
    }
}

/// Overlay options recovered from a mount's super-option string.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OverlayOpts {
    pub lowerdir: Vec<PathBuf>,
    pub upperdir: Option<PathBuf>,
    pub workdir: Option<PathBuf>,
}

/// A path made of exactly `bytes`.
pub fn path_from_bytes(bytes: Vec<u8>) -> PathBuf {
    PathBuf::from(OsString::from_vec(bytes))
}

/// The value of the octal escape at the start of `b` (a backslash and three
/// octal digits that make a byte), if there is one there.
fn octal_at(b: &[u8]) -> Option<u8> {
    if b.len() < 4 || b[0] != b'\\' || !b[1..4].iter().all(|x| (b'0'..=b'7').contains(x)) {
        return None;
    }
    let v = u16::from(b[1] - b'0') * 64 + u16::from(b[2] - b'0') * 8 + u16::from(b[3] - b'0');
    u8::try_from(v).ok()
}

/// Decode kernel octal escapes (`\0NN`) and backslash-literal escapes (`\c`)
/// into the bytes they stand for.
///
/// The kernel only ever emits `\040 \011 \012 \134` in mountinfo path fields,
/// but the overlay option builder ([`escape_overlay_path`]) also backslash-
/// escapes `,`, `:` and `\`, so both schemes are decoded here: a backslash
/// followed by three octal digits becomes that byte, any other backslash takes
/// the next byte literally.
fn unescape(b: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if let Some(byte) = octal_at(&b[i..]) {
            out.push(byte);
            i += 4;
        } else if b[i] == b'\\' && i + 1 < b.len() {
            out.push(b[i + 1]);
            i += 2;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    out
}

/// `bytes` as text: unchanged where they are valid UTF-8, with each byte
/// that is not written as a three-digit octal escape (`\377`), the escape the
/// kernel itself uses in the mount table.
pub fn escaped_text(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for chunk in bytes.utf8_chunks() {
        out.push_str(chunk.valid());
        for byte in chunk.invalid() {
            out.push_str(&format!("\\{byte:03o}"));
        }
    }
    out
}

/// Split `s` on an unescaped `delim`, preserving escape sequences in the output.
///
/// A `delim` preceded by a backslash is kept inside the current token, as is the
/// start of an octal escape, so the pieces can be [`unescape`]d afterwards.
fn split_raw(s: &[u8], delim: u8) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut cur = Vec::new();
    let mut escaped = false;
    for &c in s {
        if escaped {
            cur.push(b'\\');
            cur.push(c);
            escaped = false;
        } else if c == b'\\' {
            escaped = true;
        } else if c == delim {
            out.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
    }
    if escaped {
        cur.push(b'\\');
    }
    out.push(cur);
    out
}

/// Parse the whole mountinfo buffer, skipping malformed lines.
///
/// Lines end at a newline only, which the kernel never writes inside a field.
/// Fields are single-space separated and any embedded whitespace is octal-
/// escaped, so splitting on `' '` is both correct and necessary — splitting on
/// arbitrary whitespace would corrupt a path containing a tab. Empty fields are
/// kept: a mount whose source is the empty string (`mount -t tmpfs "" /x`) is
/// printed as nothing between two spaces, and dropping that empty token would
/// shift the super options into the source and discard the whole line.
pub fn parse_mountinfo(content: &(impl AsRef<[u8]> + ?Sized)) -> Vec<MountEntry> {
    content
        .as_ref()
        .split(|&b| b == b'\n')
        .filter_map(parse_line)
        .collect()
}

fn parse_line(line: &[u8]) -> Option<MountEntry> {
    let line = line.trim_ascii_start();
    let tokens: Vec<&[u8]> = line.split(|&b| b == b' ').collect();
    // Need at least: id parent dev root mount_point opts - fstype source super.
    let sep = tokens.iter().position(|&t| t == b"-")?;
    if sep < 6 || sep + 3 >= tokens.len() {
        return None;
    }

    let number = |token: &[u8]| std::str::from_utf8(token).ok()?.parse().ok();
    let mount_id = number(tokens[0])?;
    let parent_id = number(tokens[1])?;

    Some(MountEntry {
        mount_id,
        parent_id,
        dev: escaped_text(tokens[2]),
        root: path_from_bytes(unescape(tokens[3])),
        mount_point: path_from_bytes(unescape(tokens[4])),
        mount_opts: escaped_text(tokens[5]),
        fstype: escaped_text(tokens[sep + 1]),
        source: path_from_bytes(unescape(tokens[sep + 2])),
        super_opts: escaped_text(tokens[sep + 3]),
    })
}

/// The mount table of this process's own mount namespace.
pub const SELF_MOUNTINFO: &str = "/proc/self/mountinfo";

/// Read and parse a mountinfo file (`/proc/self/mountinfo`, or another
/// process's `/proc/<pid>/mountinfo` to see its mount namespace) once, byte
/// for byte. An error means the table could not be read, never that it is
/// empty: a caller that cannot tell its mounts takes the end it takes for any
/// other error.
pub fn read_mountinfo_at(path: &Path) -> std::io::Result<Vec<MountEntry>> {
    Ok(parse_mountinfo(&std::fs::read(path)?))
}

/// Read and parse `/proc/self/mountinfo` once (see [`read_mountinfo_at`]).
pub fn read_mountinfo() -> std::io::Result<Vec<MountEntry>> {
    read_mountinfo_at(Path::new(SELF_MOUNTINFO))
}

/// Recover `lowerdir`/`upperdir`/`workdir` from an overlay super-option string.
///
/// The paths carry two layers of escaping. The kernel stores each value exactly
/// as it was passed to `mount(2)`, still holding the overlay syntax's own
/// backslash escapes (`\,`, `\:`, `\\` from [`escape_overlay_path`]), and
/// `seq_show_option` then octal-escapes `,`, space, tab, newline and backslash
/// (never `:`) when printing it. A layer `/a,b:c` mounted by NAILS therefore
/// reads back as `/a\134\054b\134:c`; one mounted through mount(8), which hands
/// each option to fsconfig(2) whole and so needs no `\,`, reads back as
/// `/a\054b\134:c`. Decoding runs in reverse: split the options on `,` (a comma
/// inside a value is always `\054` from the kernel, or `\,` in a hand-written
/// string), undo the kernel's octal escapes, split `lowerdir` on unescaped `:`,
/// and finally drop the overlay backslash escapes. Both kernel forms and the
/// single-escaped form NAILS builds for `mount(2)` decode alike, and every
/// path comes out byte for byte, valid UTF-8 or not.
pub fn parse_overlay_opts(super_opts: &str) -> OverlayOpts {
    let path = |value: &[u8]| path_from_bytes(unescape_overlay(value));
    let mut opts = OverlayOpts::default();
    for raw in split_raw(super_opts.as_bytes(), b',') {
        if let Some(v) = raw.strip_prefix(b"lowerdir=") {
            opts.lowerdir = split_raw(&unescape_octal_bytes(v), b':')
                .into_iter()
                .filter(|s| !s.is_empty())
                .map(|s| path(&s))
                .collect();
        } else if let Some(v) = raw.strip_prefix(b"upperdir=") {
            opts.upperdir = Some(path(&unescape_octal_bytes(v)));
        } else if let Some(v) = raw.strip_prefix(b"workdir=") {
            opts.workdir = Some(path(&unescape_octal_bytes(v)));
        }
    }
    opts
}

/// Undo only the kernel's `\ooo` octal escapes, leaving every other backslash
/// escape (`\\`, `\,`, `\:`) in place, pair and all, for [`unescape_overlay`],
/// and give the bytes they stand for.
/// Kernel output never holds such a pair (it prints a backslash as `\134`), so
/// keeping pairs intact only matters for an option string that was never
/// through the kernel, such as the one nails builds for `mount(2)`.
pub fn unescape_octal_bytes(s: &(impl AsRef<[u8]> + ?Sized)) -> Vec<u8> {
    let b = s.as_ref();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if let Some(byte) = octal_at(&b[i..]) {
            out.push(byte);
            i += 4;
            continue;
        }
        if b[i] == b'\\' && i + 1 < b.len() {
            out.extend_from_slice(&b[i..i + 2]);
            i += 2;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

/// [`unescape_octal_bytes`] as a path.
pub fn unescape_octal_path(s: &(impl AsRef<[u8]> + ?Sized)) -> PathBuf {
    path_from_bytes(unescape_octal_bytes(s))
}

/// [`unescape_octal_bytes`] as text, for a value that is compared as text
/// only: a byte that is not valid UTF-8 stays an octal escape
/// ([`escaped_text`]), so two values that differ in such a byte never compare
/// equal. A path is read with [`unescape_octal_path`] instead.
pub fn unescape_octal(s: &str) -> String {
    escaped_text(&unescape_octal_bytes(s))
}

/// Undo the overlay option syntax's escapes: a backslash takes the next
/// byte literally (the inverse of [`escape_overlay_path`]).
fn unescape_overlay(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let mut bytes = s.iter();
    while let Some(&c) = bytes.next() {
        if c == b'\\' {
            match bytes.next() {
                Some(&next) => out.push(next),
                None => out.push(b'\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Escape a path for use inside an overlay mount option value.
///
/// The kernel's overlay option parser treats `,` as the option separator, `:`
/// as the lower-layer separator and `\` as the escape character, so each is
/// backslash-escaped here. A newline cannot be represented in a mount option
/// line and is rejected (`None`) rather than silently truncating the option
/// string, and so is a path that is not valid UTF-8, which the option text
/// handed to `mount(2)` cannot hold unchanged: it is never mounted under
/// another name.
pub fn escape_overlay_path(path: &Path) -> Option<String> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.contains(&b'\n') {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len());
    for &c in bytes {
        if matches!(c, b'\\' | b':' | b',') {
            out.push(b'\\');
        }
        out.push(c);
    }
    String::from_utf8(out).ok()
}

/// The mount a lookup of `target` reaches, when that is a mount whose mount
/// point is exactly `target`; `None` otherwise.
///
/// Two mounts can share a mount point (an overlay on the decoy's own `/home`
/// partition, a hand-stacked second overlay), and a mount can also be shadowed
/// without anything at its own point: the decoy's `/tmp/xchg` stays in the
/// table after an overlay is mounted on `/tmp`, but a lookup of `/tmp/xchg` now
/// ends in the overlay and never reaches it. So the visible mount is found the
/// way the kernel walks: from the namespace root, at each prefix of `target`
/// follow the mounts whose parent is the mount reached so far, topmost last.
pub fn top_mount_at<'a>(entries: &'a [MountEntry], target: &Path) -> Option<&'a MountEntry> {
    let root = Path::new("/");
    let mut current = entries.iter().find(|e| {
        e.mount_point == root
            && !entries
                .iter()
                .any(|below| below.mount_id == e.parent_id && below.mount_point == root)
    })?;
    // A table names each mount once, so no stack is taller than the table.
    // A table that names one ID twice (a mount freed and its ID given to a
    // new one while the table was being read) can hold a cycle, which this
    // bound leaves after one round instead of following for ever.
    let climb = |mut at: &'a MountEntry, point: &Path| {
        for _ in 0..entries.len() {
            match entries.iter().find(|e| {
                e.mount_point == point && e.parent_id == at.mount_id && e.mount_id != at.mount_id
            }) {
                Some(above) => at = above,
                None => break,
            }
        }
        at
    };
    current = climb(current, root);
    let mut prefix = PathBuf::from("/");
    for component in target.components().skip(1) {
        prefix.push(component);
        current = climb(current, &prefix);
    }
    (current.mount_point == target).then_some(current)
}

/// Whether `/` is an overlay whose upper lies under `hidden_root`, which is
/// how the hidden session looks from inside: the upper's path when it is.
pub fn root_is_hidden_overlay(entries: &[MountEntry], hidden_root: &Path) -> Option<String> {
    let root = top_mount_at(entries, Path::new("/"))?;
    if root.fstype != "overlay" {
        return None;
    }
    let upper = parse_overlay_opts(&root.super_opts).upperdir?;
    upper
        .starts_with(hidden_root)
        .then(|| upper.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const OCT_SPACE: &str = "\\040";
    const OCT_TAB: &str = "\\011";
    const OCT_BACKSLASH: &str = "\\134";

    #[test]
    fn the_visible_mount_skips_one_shadowed_by_an_overlay_above_it() {
        let table = parse_mountinfo(
            "\
1 0 8:1 / / rw - ext4 /dev/sda1 rw
2 1 0:30 / /tmp rw - tmpfs tmpfs rw
3 2 0:31 / /tmp/xchg rw - 9p xchg rw
4 2 0:50 / /tmp rw - overlay overlay rw,lowerdir=/tmp,upperdir=/h/u,workdir=/h/w
5 4 0:31 / /tmp/xchg ro - 9p xchg rw
6 4 0:51 / /tmp rw - overlay overlay rw,lowerdir=/x,upperdir=/h/x,workdir=/h/y
",
        );
        // /tmp: the second overlay stacked on the first.
        assert_eq!(
            top_mount_at(&table, Path::new("/tmp")).map(|e| e.mount_id),
            Some(6)
        );
        // /tmp/xchg: the re-attach (5) sits on overlay 4, now covered by 6, and
        // the decoy's own (3) on the partition below: neither is reached.
        assert_eq!(top_mount_at(&table, Path::new("/tmp/xchg")), None);
        let without_top: Vec<_> = table.iter().filter(|e| e.mount_id != 6).cloned().collect();
        assert_eq!(
            top_mount_at(&without_top, Path::new("/tmp/xchg")).map(|e| e.mount_id),
            Some(5)
        );
        assert_eq!(
            top_mount_at(&table, Path::new("/")).map(|e| e.mount_id),
            Some(1)
        );
    }

    /// A table that names one mount ID twice made the climb go round a cycle
    /// for ever: here the second mount 2 sits on mount 4, which sits on the
    /// first. Found by the `mountinfo` fuzz target as a timeout.
    #[test]
    fn a_lookup_ends_on_a_table_that_names_an_id_twice() {
        let table = parse_mountinfo(
            "\
1 0 8:1 / / rw - ext4 /dev/sda1 rw
2 1 0:30 / /tmp rw - tmpfs tmpfs rw
4 2 0:50 / /tmp rw - overlay overlay rw,lowerdir=/tmp,upperdir=/h/u,workdir=/h/w
2 4 0:51 / /tmp rw - overlay overlay rw,lowerdir=/x,upperdir=/h/x,workdir=/h/y
",
        );
        let found = top_mount_at(&table, Path::new("/tmp")).expect("a mount at /tmp");
        assert_eq!(found.mount_point, Path::new("/tmp"));
        assert_eq!(top_mount_at(&table, Path::new("/tmp/x")), None);
    }

    #[test]
    fn a_mount_with_an_empty_source_is_kept() {
        // `mount -t tmpfs "" /mnt/x` prints nothing between two spaces.
        let entries =
            parse_mountinfo("40 22 0:50 / /mnt/x rw,relatime shared:9 - tmpfs  rw,size=10k\n");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].mount_point, PathBuf::from("/mnt/x"));
        assert_eq!(entries[0].source, PathBuf::new());
        assert_eq!(entries[0].super_opts, "rw,size=10k");
    }

    #[test]
    fn overlay_paths_are_decoded_through_both_escape_layers() {
        // NAILS mounted upperdir=/h/a\,b and lowerdir=/l\:x; the kernel prints
        // the stored strings with `\` and `,` octal-escaped.
        let opts = parse_overlay_opts(
            "rw,lowerdir=/l\\134:x:/m,upperdir=/h/a\\134\\054b,workdir=/w\\040d",
        );
        assert_eq!(
            opts.lowerdir,
            vec![PathBuf::from("/l:x"), PathBuf::from("/m")]
        );
        assert_eq!(opts.upperdir, Some(PathBuf::from("/h/a,b")));
        assert_eq!(opts.workdir, Some(PathBuf::from("/w d")));
    }

    #[test]
    fn unescape_decodes_kernel_octal_escapes() {
        assert_eq!(unescape(b"a\\040b"), b"a b");
        assert_eq!(unescape(b"a\\011b"), b"a\tb");
        assert_eq!(unescape(b"a\\012b"), b"a\nb");
        assert_eq!(unescape(b"a\\134b"), b"a\\b");
        assert_eq!(unescape(b"a\\377b"), b"a\xffb");
    }

    #[test]
    fn unescape_decodes_backslash_literals() {
        assert_eq!(unescape(b"a\\,b"), b"a,b");
        assert_eq!(unescape(b"a\\:b"), b"a:b");
        assert_eq!(unescape(b"a\\\\b"), b"a\\b");
    }

    /// A byte that is not valid UTF-8 in any field (the kernel writes it as
    /// it is) failed the whole read before: each path field keeps it byte for
    /// byte, and each text field holds it as an octal escape that decodes to
    /// it again.
    #[test]
    fn a_byte_that_is_not_utf8_is_kept_in_every_field() {
        let line = b"36 35 98:0 /r\xff /run/a\xff rw,relatime shared:1 - fuse.s\xff /dev/\xfe rw,lowerdir=/l\xff,upperdir=/u\xfd\\040x,workdir=/w\n";
        let entries = parse_mountinfo(line);
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.root.as_os_str().as_bytes(), b"/r\xff");
        assert_eq!(entry.mount_point.as_os_str().as_bytes(), b"/run/a\xff");
        assert_eq!(entry.source.as_os_str().as_bytes(), b"/dev/\xfe");
        assert_eq!(entry.fstype, "fuse.s\\377");
        assert_eq!(unescape_octal_bytes(&entry.fstype), b"fuse.s\xff");
        assert_eq!(
            entry.super_opts,
            "rw,lowerdir=/l\\377,upperdir=/u\\375\\040x,workdir=/w"
        );
        let opts = parse_overlay_opts(&entry.super_opts);
        assert_eq!(opts.lowerdir, vec![path_from_bytes(b"/l\xff".to_vec())]);
        assert_eq!(opts.upperdir, Some(path_from_bytes(b"/u\xfd x".to_vec())));
        assert_eq!(opts.workdir, Some(PathBuf::from("/w")));
        // Two mount points that differ only in such a byte stay apart.
        let two = parse_mountinfo(
            b"1 0 0:1 / /a\xfe rw - tmpfs t rw\n2 0 0:2 / /a\xff rw - tmpfs t rw\n",
        );
        assert_ne!(two[0].mount_point, two[1].mount_point);
        assert_eq!(top_mount_at(&two, &two[1].mount_point), None);
        assert_eq!(unescape_octal("a\\377"), "a\\377");
        assert_eq!(unescape_octal("a\\040"), "a ");
    }

    /// The kernel ends a line at a newline only: a carriage return is a byte
    /// of the field it is in.
    #[test]
    fn a_carriage_return_is_part_of_its_field() {
        let entries = parse_mountinfo(b"36 35 98:0 / /a\r rw - tmpfs t rw\r\n");
        assert_eq!(entries[0].mount_point, PathBuf::from("/a\r"));
        assert_eq!(entries[0].super_opts, "rw\r");
    }

    /// The mount table read as the kernel gives it: a mount at a folder whose
    /// name is not valid UTF-8 failed the read before (read_to_string).
    #[test]
    fn a_table_file_that_is_not_utf8_is_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mountinfo");
        std::fs::write(
            &path,
            b"1 0 8:1 / / rw - ext4 /dev/sda1 rw\n2 1 0:30 / /run/a\xff rw - tmpfs tmpfs rw\n",
        )
        .unwrap();
        let entries = read_mountinfo_at(&path).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].mount_point.as_os_str().as_bytes(), b"/run/a\xff");
        assert!(read_mountinfo_at(&dir.path().join("missing")).is_err());
    }

    #[test]
    fn a_path_that_is_not_utf8_is_never_an_overlay_option() {
        assert_eq!(
            escape_overlay_path(&path_from_bytes(b"/a\xff".to_vec())),
            None
        );
        assert_eq!(
            escape_overlay_path(Path::new("/a\u{e4}")).as_deref(),
            Some("/a\u{e4}")
        );
    }

    #[test]
    fn parse_mountinfo_decodes_space_tab_backslash_in_paths() {
        let line = format!(
            "36 35 98:0 / /mnt/hidden{OCT_SPACE}root{OCT_TAB}x{OCT_BACKSLASH}y rw - ext4 /dev/sda1 rw"
        );
        let entries = parse_mountinfo(&line);
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].mount_point,
            PathBuf::from("/mnt/hidden root\tx\\y")
        );
        assert_eq!(entries[0].fstype, "ext4");
    }

    #[test]
    fn parse_mountinfo_captures_per_mount_options_and_read_only_flag() {
        let content = "\
36 35 98:0 / /ro rw,relatime - ext4 /dev/sda1 ro
37 35 98:1 / /snap/app/7 ro,nodev,relatime - squashfs /dev/loop3 ro
38 35 98:2 / /var/log rw,nosuid,nodev - ext4 /dev/sdb1 rw";
        let entries = parse_mountinfo(content);
        assert_eq!(entries.len(), 3);
        // The per-mount options field (not the super options after ` - `) decides
        // read-only-ness.
        assert_eq!(entries[0].mount_opts, "rw,relatime");
        assert!(!entries[0].read_only());
        assert_eq!(entries[1].mount_opts, "ro,nodev,relatime");
        assert!(entries[1].read_only());
        assert_eq!(entries[2].mount_opts, "rw,nosuid,nodev");
        assert!(!entries[2].read_only());
    }

    #[test]
    fn read_only_matches_whole_token_not_substring() {
        // `relatime` contains neither a bare `ro` token nor should it ever read as
        // read-only.
        let entry = &parse_mountinfo("36 35 98:0 / /x rw,relatime - ext4 /dev/sda1 rw")[0];
        assert!(!entry.read_only());
    }

    #[test]
    fn parse_mountinfo_skips_malformed_lines_without_aborting_scan() {
        // A short/garbage line and an entry whose mount point is a dead mount
        // must not stop the scan: the good entry *after* them is still found.
        let content = "\
this is not a mountinfo line
19 20 0:21 / /proc rw - proc proc rw
77 1 0:55 / /mnt/dead rw - nfs4 198.51.100.9:/x rw
88 1 8:1 / /data/good rw - ext4 /dev/sdb1 rw";
        let entries = parse_mountinfo(content);
        let points: Vec<_> = entries.iter().map(|e| e.mount_point.clone()).collect();
        assert!(points.contains(&PathBuf::from("/data/good")));
        assert!(points.contains(&PathBuf::from("/mnt/dead")));
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn parse_overlay_opts_round_trips_escaped_separators() {
        // lowerdir has an escaped comma in a segment and an escaped colon;
        // upperdir carries an octal-escaped space.
        let opts =
            parse_overlay_opts("rw,lowerdir=/a\\,b:/c\\:d,upperdir=/up\\040per,workdir=/work");
        assert_eq!(
            opts.lowerdir,
            vec![PathBuf::from("/a,b"), PathBuf::from("/c:d")]
        );
        assert_eq!(opts.upperdir, Some(PathBuf::from("/up per")));
        assert_eq!(opts.workdir, Some(PathBuf::from("/work")));
    }

    #[test]
    fn parse_overlay_opts_decodes_the_doubly_escaped_kernel_form() {
        // Verbatim from /proc/self/mountinfo on Linux 7.2 for an overlay mounted
        // by RealFilesystem::mount_overlay with lower `lower, with:colon`, upper
        // `upper\dir` and work `work dir` (see tests/kernel_semantics.rs). The
        // kernel octal-escapes the backslashes NAILS added, so `\,` reads back
        // as `\134\054` and `\:` as `\134:`.
        let opts = parse_overlay_opts(
            "rw,lowerdir=/t/lower\\134\\054\\040with\\134:colon,upperdir=/t/upper\\134\\134dir,\
             workdir=/t/work\\040dir,redirect_dir=nofollow,uuid=null",
        );
        assert_eq!(opts.lowerdir, vec![PathBuf::from("/t/lower, with:colon")]);
        assert_eq!(opts.upperdir, Some(PathBuf::from("/t/upper\\dir")));
        assert_eq!(opts.workdir, Some(PathBuf::from("/t/work dir")));
    }

    #[test]
    fn parse_overlay_opts_decodes_a_captured_fsconfig_mount() {
        // Captured by scripts/capture-kernel-fixtures.sh: mount(8) hands each
        // option to fsconfig(2) separately, so the comma needs no `\,` and the
        // kernel prints it as a bare `\054`. Both forms must decode alike.
        let scene = include_str!(
            "../../nails-base/tests/fixtures/kernel/userns/mountinfo-overlay-scene.txt"
        );
        let overlay = parse_mountinfo(scene)
            .into_iter()
            .find(|e| e.fstype == "overlay")
            .expect("the captured overlay line");
        let opts = parse_overlay_opts(&overlay.super_opts);
        assert_eq!(
            opts.lowerdir,
            vec![PathBuf::from("/fixture/lower, with:colon")]
        );
        assert_eq!(opts.upperdir, Some(PathBuf::from("/fixture/upper\\dir")));
        assert_eq!(opts.workdir, Some(PathBuf::from("/fixture/work dir")));
    }

    #[test]
    fn parse_overlay_opts_keeps_a_literal_backslash_before_digits() {
        // Path `/a\101`: escaped to `/a\\101` for mount, shown as `/a\134\134101`.
        let opts = parse_overlay_opts("rw,lowerdir=/l,upperdir=/a\\134\\134101,workdir=/w");
        assert_eq!(opts.upperdir, Some(PathBuf::from("/a\\101")));
        // The same path in the single-escaped form (`\\` before the digits) is a
        // literal backslash, not an octal escape (a proptest shrink).
        let opts = parse_overlay_opts("lowerdir=/\\\\000,upperdir=/u,workdir=/w");
        assert_eq!(opts.lowerdir, vec![PathBuf::from("/\\000")]);
    }

    #[test]
    fn escape_overlay_path_escapes_separators_and_rejects_newline() {
        assert_eq!(
            escape_overlay_path(Path::new("/a,b:c\\d")).unwrap(),
            "/a\\,b\\:c\\\\d"
        );
        assert!(escape_overlay_path(Path::new("/a\nb")).is_none());
    }

    #[test]
    fn escape_round_trips_through_overlay_opts() {
        let lower = escape_overlay_path(Path::new("/weird,path:seg")).unwrap();
        let opts = parse_overlay_opts(&format!("rw,lowerdir={lower},upperdir=/u,workdir=/w"));
        assert_eq!(opts.lowerdir, vec![PathBuf::from("/weird,path:seg")]);
    }

    #[test]
    fn only_an_overlay_root_with_its_upper_on_the_hidden_volume_is_the_hidden_session() {
        let hidden = parse_mountinfo(
            "1 0 0:40 / / rw - overlay overlay rw,lowerdir=/x,upperdir=/mnt/data/root/upper,workdir=/mnt/data/root/work\n",
        );
        assert_eq!(
            root_is_hidden_overlay(&hidden, Path::new("/mnt/data")).as_deref(),
            Some("/mnt/data/root/upper")
        );
        // The upper elsewhere, or a sibling sharing a string prefix.
        assert_eq!(
            root_is_hidden_overlay(&hidden, Path::new("/mnt/other")),
            None
        );
        assert_eq!(root_is_hidden_overlay(&hidden, Path::new("/mnt/dat")), None);
        let decoy = parse_mountinfo("1 0 8:2 / / rw - ext4 /dev/vda2 rw\n");
        assert_eq!(root_is_hidden_overlay(&decoy, Path::new("/mnt/data")), None);
    }

    /// The mount table of a live hidden session, captured as root in the
    /// decoy-journal-leak VM test (nails-base's fixture README): `/` is the
    /// overlay whose upper is on the hidden volume at `/mnt/data`.
    #[test]
    fn the_captured_hidden_session_has_a_hidden_overlay_root() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../nails-base/tests/fixtures/kernel/vm/mountinfo-host.txt");
        let Ok(mountinfo) = std::fs::read_to_string(path) else {
            eprintln!("the VM capture is not taken yet (nails-base fixture README)");
            return;
        };
        let entries = parse_mountinfo(&mountinfo);
        let upper = root_is_hidden_overlay(&entries, Path::new("/mnt/data"))
            .expect("the captured root is the hidden overlay");
        assert!(upper.starts_with("/mnt/data/"), "{upper}");
        assert_eq!(
            root_is_hidden_overlay(&entries, Path::new("/mnt/other")),
            None
        );
    }
}
