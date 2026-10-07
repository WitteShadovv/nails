// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! One correct parser for `/proc/self/mountinfo`.
//!
//! Every mount-table reader in the crate goes through this module. The kernel
//! octal-escapes the bytes space (`\040`), tab (`\011`), newline (`\012`) and
//! backslash (`\134`) in the `root`, `mount_point` and `source` fields, so a
//! hidden root at a path with a space (common for udisks automounts) must be
//! decoded before it can be compared. The parser:
//!
//! - decodes those escapes everywhere a path appears,
//! - never stats or canonicalizes an entry (only the single queried target is
//!   canonicalized, by the caller), so a dead NFS/CIFS/FUSE mount cannot block
//!   the scan,
//! - skips a malformed line with a debug log instead of aborting the whole scan.
//!
//! `/proc/self/mountinfo` is used rather than `/proc/mounts` because it carries
//! `mount_id`/`parent_id`/`dev` and a per-superblock options field, which is what
//! lets [`NailsMounts`] classify which mounts NAILS actually created.

use std::path::{Path, PathBuf};

/// The directory under the hidden root that holds the fresh persona home.
const PERSONA_DIR: &str = "persona";
/// The persona home directory name inside [`PERSONA_DIR`].
const PERSONA_HOME_DIR: &str = "home";

/// Whether a mount-table `root` path (the in-filesystem subtree a bind exposes)
/// is the fresh-home persona bind of `{hidden_root}/persona/home`.
///
/// The bind shows in `/proc/self/mountinfo` with a `root` ending in
/// `persona/home` wherever the hidden volume is mounted, so the two-component
/// tail identifies it without the configured hidden root.
pub fn is_persona_home_root(mount_root: &Path) -> bool {
    let mut components = mount_root.components().rev();
    let last = components.next();
    let penultimate = components.next();
    matches!(
        (penultimate, last),
        (Some(p), Some(l))
            if p.as_os_str() == PERSONA_DIR && l.as_os_str() == PERSONA_HOME_DIR
    )
}

/// The read-only bind NAILS restores over an overlaid `/nix`.
const NIX_STORE: &str = "/nix/store";
/// The directory NAILS overlays when hiding the Nix store.
const NIX_OVERLAY: &str = "/nix";

/// One parsed line of `/proc/self/mountinfo`.
///
/// Field names follow proc(5). `root`, `mount_point` and `source` are already
/// octal-decoded; `super_opts` is the raw per-superblock option string (overlay
/// `lowerdir`/`upperdir`/`workdir` live here) and is decoded lazily by
/// [`parse_overlay_opts`].
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
    /// Per-superblock options after the ` - ` separator.
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

/// Decode kernel octal escapes (`\0NN`) and backslash-literal escapes (`\c`).
///
/// The kernel only ever emits `\040 \011 \012 \134` in mountinfo path fields,
/// but the overlay option builder ([`escape_overlay_path`]) also backslash-
/// escapes `,`, `:` and `\`, so both schemes are decoded here: a backslash
/// followed by three octal digits becomes that byte, any other backslash takes
/// the next character literally.
fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' {
            if i + 4 <= b.len() && b[i + 1..i + 4].iter().all(|x| (b'0'..=b'7').contains(x)) {
                let v = ((b[i + 1] - b'0') as u16) * 64
                    + ((b[i + 2] - b'0') as u16) * 8
                    + (b[i + 3] - b'0') as u16;
                if v <= 255 {
                    out.push(v as u8);
                    i += 4;
                    continue;
                }
            }
            if i + 1 < b.len() {
                out.push(b[i + 1]);
                i += 2;
                continue;
            }
            out.push(b'\\');
            i += 1;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Split `s` on an unescaped `delim`, preserving escape sequences in the output.
///
/// A `delim` preceded by a backslash is kept inside the current token, as is the
/// start of an octal escape, so the pieces can be [`unescape`]d afterwards.
fn split_raw(s: &str, delim: char) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut escaped = false;
    for c in s.chars() {
        if escaped {
            cur.push('\\');
            cur.push(c);
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == delim {
            out.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
    }
    if escaped {
        cur.push('\\');
    }
    out.push(cur);
    out
}

/// Parse the whole mountinfo buffer, skipping malformed lines.
///
/// Fields are single-space separated and any embedded whitespace is octal-
/// escaped, so splitting on `' '` is both correct and necessary — splitting on
/// arbitrary whitespace would corrupt a path containing a tab. Empty fields are
/// kept: a mount whose source is the empty string (`mount -t tmpfs "" /x`) is
/// printed as nothing between two spaces, and dropping that empty token would
/// shift the super options into the source and discard the whole line.
pub fn parse_mountinfo(content: &str) -> Vec<MountEntry> {
    content.lines().filter_map(parse_line).collect()
}

fn parse_line(line: &str) -> Option<MountEntry> {
    let tokens: Vec<&str> = line.trim_start().split(' ').collect();
    // Need at least: id parent dev root mount_point opts - fstype source super.
    let sep = tokens.iter().position(|&t| t == "-")?;
    if sep < 6 || sep + 3 >= tokens.len() {
        return None;
    }

    let mount_id = tokens[0].parse().ok()?;
    let parent_id = tokens[1].parse().ok()?;

    Some(MountEntry {
        mount_id,
        parent_id,
        dev: tokens[2].to_string(),
        root: PathBuf::from(unescape(tokens[3])),
        mount_point: PathBuf::from(unescape(tokens[4])),
        mount_opts: tokens[5].to_string(),
        fstype: tokens[sep + 1].to_string(),
        source: PathBuf::from(unescape(tokens[sep + 2])),
        super_opts: tokens[sep + 3].to_string(),
    })
}

/// The mount table of this process's own mount namespace.
pub const SELF_MOUNTINFO: &str = "/proc/self/mountinfo";

/// Read and parse a mountinfo file (`/proc/self/mountinfo`, or another
/// process's `/proc/<pid>/mountinfo` to see its mount namespace) once.
pub fn read_mountinfo_at(path: &Path) -> std::io::Result<Vec<MountEntry>> {
    Ok(parse_mountinfo(&std::fs::read_to_string(path)?))
}

/// Read and parse `/proc/self/mountinfo` once.
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
/// single-escaped form NAILS builds for `mount(2)` decode alike.
pub fn parse_overlay_opts(super_opts: &str) -> OverlayOpts {
    let path = |value: &str| PathBuf::from(unescape_overlay(value));
    let mut opts = OverlayOpts::default();
    for raw in split_raw(super_opts, ',') {
        if let Some(v) = raw.strip_prefix("lowerdir=") {
            opts.lowerdir = split_raw(&unescape_octal(v), ':')
                .into_iter()
                .filter(|s| !s.is_empty())
                .map(|s| path(&s))
                .collect();
        } else if let Some(v) = raw.strip_prefix("upperdir=") {
            opts.upperdir = Some(path(&unescape_octal(v)));
        } else if let Some(v) = raw.strip_prefix("workdir=") {
            opts.workdir = Some(path(&unescape_octal(v)));
        }
    }
    opts
}

/// Undo only the kernel's `\ooo` octal escapes, leaving every other backslash
/// escape (`\\`, `\,`, `\:`) in place, pair and all, for [`unescape_overlay`].
/// Kernel output never holds such a pair (it prints a backslash as `\134`), so
/// keeping pairs intact only matters for an option string that was never
/// through the kernel, such as the one nails builds for `mount(2)`.
pub fn unescape_octal(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\'
            && i + 4 <= b.len()
            && b[i + 1..i + 4].iter().all(|x| (b'0'..=b'7').contains(x))
        {
            let v = u16::from(b[i + 1] - b'0') * 64
                + u16::from(b[i + 2] - b'0') * 8
                + u16::from(b[i + 3] - b'0');
            if let Ok(byte) = u8::try_from(v) {
                out.push(byte);
                i += 4;
                continue;
            }
        }
        if b[i] == b'\\' && i + 1 < b.len() {
            out.extend_from_slice(&b[i..i + 2]);
            i += 2;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Undo the overlay option syntax's escapes: a backslash takes the next
/// character literally (the inverse of [`escape_overlay_path`]).
fn unescape_overlay(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some(next) => out.push(next),
                None => out.push('\\'),
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
/// string.
pub fn escape_overlay_path(path: &Path) -> Option<String> {
    let s = path.to_string_lossy();
    if s.contains('\n') {
        return None;
    }
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '\\' | ':' | ',') {
            out.push('\\');
        }
        out.push(c);
    }
    Some(out)
}

/// Whether a read-only self-bind is stacked at `target`: a read-only mount at
/// `target` on the same device as the mount it sits on. That is the shape of a
/// read-only guard, whether `target` is its own partition (the guard's parent is
/// that partition, at the same point) or a plain directory (the guard is a bind
/// of a subtree of the filesystem it sits on). A decoy mount that merely sits at
/// `target` (a separate `/usr` partition, the root filesystem) sits on another
/// device's mount and does not match.
pub fn is_read_only_self_bind(entries: &[MountEntry], target: &Path) -> bool {
    entries.iter().any(|guard| {
        guard.mount_point == target
            && guard.read_only()
            && entries
                .iter()
                .any(|below| below.mount_id == guard.parent_id && below.dev == guard.dev)
    })
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
    let climb = |mut at: &'a MountEntry, point: &Path| {
        while let Some(above) = entries.iter().find(|e| {
            e.mount_point == point && e.parent_id == at.mount_id && e.mount_id != at.mount_id
        }) {
            at = above;
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

/// The NAILS-created mounts currently present, classified by kind.
///
/// Discovery is what makes unmount safe: the teardown path escalates to
/// `MNT_FORCE | MNT_DETACH`, which would lazily detach a real filesystem if
/// stale state pointed NAILS at a mount it never created. [`is_owned`] answers
/// "did NAILS mount this?" from the live mount table, independent of state.
///
/// [`is_owned`]: NailsMounts::is_owned
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NailsMounts {
    /// Overlays whose upper/work live under the hidden root.
    pub persistent_overlays: Vec<PathBuf>,
    /// Overlays whose upper/work live under the per-activation runtime root.
    pub ephemeral_overlays: Vec<PathBuf>,
    /// Mounts staged inside the per-activation runtime root (the pivot staging
    /// overlays, the vfat snapshot tmpfs, and the read-only `/nix/store` bind).
    pub pivot_binds: Vec<PathBuf>,
    /// The per-activation runtime scaffolding tmpfs itself, if one is present.
    /// Unmounted and removed last, after everything staged inside it.
    pub runtime_tmpfs: Option<PathBuf>,
    /// The `/nix/store` restore bind, if present.
    pub nix_store_bind: Option<PathBuf>,
    /// Whether an overlay is mounted on `/nix` (gates `/nix/store` ownership).
    pub nix_overlay_present: bool,
    /// Fresh-home persona binds: plain binds of `{hidden_root}/persona/home` over
    /// the operator's home. Recognised by the tail of their in-filesystem root
    /// (`persona/home`), so teardown can unmount them without knowing where the
    /// hidden volume is mounted.
    pub persona_binds: Vec<PathBuf>,
}

impl NailsMounts {
    /// Classify the live mount table.
    ///
    /// `hidden_root` distinguishes persistent overlays from foreign ones; when it
    /// is unknown, any overlay is treated as NAILS-owned, because NAILS only ever
    /// asks to unmount its own targets and this keeps a real teardown correct
    /// while still refusing a plain non-overlay mount like an ext4 `/home`.
    pub fn discover(hidden_root: Option<&Path>) -> std::io::Result<Self> {
        Ok(Self::from_entries(&read_mountinfo()?, hidden_root))
    }

    /// Structurally identify this activation's runtime scaffolding root from the
    /// live mount table, without relying on the state file or a fixed name.
    ///
    /// The runtime root is a tmpfs mounted directly under `/run` (so its parent
    /// is exactly `/run`) that *hosts NAILS scaffolding*: an overlay whose
    /// upper/work dir is inside it, a staging overlay mounted inside it, or the
    /// read-only `/nix/store` bind inside it. Requiring that correlation keeps an
    /// unrelated `/run/*` tmpfs (a container runtime, snapd) from matching. An
    /// umbrella tmpfs that happens to be empty (an overlay-only activation that
    /// needed no staging or store bind) is deliberately not matched here: it holds
    /// nothing and is volatile, and a trusted teardown removes it from the
    /// recorded state path regardless.
    fn discover_runtime_root(entries: &[MountEntry]) -> Option<PathBuf> {
        let run = Path::new("/run");
        let under =
            |p: &Option<PathBuf>, base: &Path| p.as_deref().is_some_and(|x| x.starts_with(base));

        entries
            .iter()
            .filter(|e| e.fstype == "tmpfs" && e.mount_point.parent() == Some(run))
            .map(|e| &e.mount_point)
            .find(|root| {
                entries.iter().any(|e| {
                    // A staging overlay or the /nix/store bind mounted inside root.
                    (e.mount_point != **root && e.mount_point.starts_with(root))
                        && (e.fstype == "overlay" || e.source == Path::new(NIX_STORE))
                }) || entries.iter().any(|e| {
                    // An overlay anywhere whose upper/work backing lives inside root.
                    e.fstype == "overlay" && {
                        let opts = parse_overlay_opts(&e.super_opts);
                        under(&opts.upperdir, root) || under(&opts.workdir, root)
                    }
                })
            })
            .cloned()
    }

    /// Classify an already-parsed mount table (the testable core of `discover`).
    pub fn from_entries(entries: &[MountEntry], hidden_root: Option<&Path>) -> Self {
        let runtime_root = Self::discover_runtime_root(entries);
        let under =
            |p: &Option<PathBuf>, base: &Path| p.as_deref().is_some_and(|x| x.starts_with(base));

        let mut m = NailsMounts {
            runtime_tmpfs: runtime_root.clone(),
            ..Default::default()
        };

        for e in entries {
            let mp = &e.mount_point;

            // Everything staged inside the runtime root — staging overlays, the
            // snapshot tmpfs, the /nix/store bind — is torn down before the root
            // itself. The root tmpfs is tracked separately in `runtime_tmpfs`.
            if let Some(root) = &runtime_root
                && mp != root
                && mp.starts_with(root)
            {
                m.pivot_binds.push(mp.clone());
                continue;
            }

            if e.fstype == "overlay" {
                if mp == Path::new(NIX_OVERLAY) {
                    m.nix_overlay_present = true;
                }
                let opts = parse_overlay_opts(&e.super_opts);
                if let Some(root) = hidden_root
                    && (under(&opts.upperdir, root) || under(&opts.workdir, root))
                {
                    m.persistent_overlays.push(mp.clone());
                } else if let Some(root) = &runtime_root
                    && (under(&opts.upperdir, root) || under(&opts.workdir, root))
                {
                    m.ephemeral_overlays.push(mp.clone());
                } else if hidden_root.is_none() {
                    m.persistent_overlays.push(mp.clone());
                }
            } else if mp == Path::new(NIX_STORE) {
                m.nix_store_bind = Some(mp.clone());
            } else if is_persona_home_root(&e.root) {
                // A plain bind whose in-filesystem root is `.../persona/home` is
                // the fresh-home persona bind NAILS created over the operator's
                // home. The distinctive two-component tail keeps this from matching
                // an unrelated host mount.
                m.persona_binds.push(mp.clone());
            }
        }
        m
    }

    /// Every mount point NAILS owns in the live table, as a flat list.
    ///
    /// Used by state reconciliation to report what is still mounted when the
    /// persisted state disagrees with the kernel. Includes overlay targets
    /// (persistent and ephemeral), pivot staging binds, fresh-home persona
    /// binds and the `/nix/store` restore bind when NAILS also overlaid `/nix`.
    pub fn owned_mount_points(&self) -> Vec<PathBuf> {
        let mut points = Vec::new();
        points.extend(self.persistent_overlays.iter().cloned());
        points.extend(self.ephemeral_overlays.iter().cloned());
        points.extend(self.pivot_binds.iter().cloned());
        points.extend(self.persona_binds.iter().cloned());
        if self.nix_overlay_present
            && let Some(bind) = &self.nix_store_bind
        {
            points.push(bind.clone());
        }
        // The umbrella tmpfs comes last: it can only be unmounted once everything
        // staged inside it (pivot binds above) is gone.
        if let Some(root) = &self.runtime_tmpfs {
            points.push(root.clone());
        }
        points
    }

    /// The mount ids of the writable NAILS-created mounts in `entries`: the
    /// overlays, the fresh-home persona binds, everything staged in the runtime
    /// root and the runtime root tmpfs itself.
    ///
    /// The teardown's overlay-rooted kill compares process references against
    /// these ids. A read-only mount is left out — above all the `/nix/store`
    /// restore bind, which shares the decoy filesystem and cannot be written
    /// through — and so is the decoy's own mount at the same mount point as an
    /// overlay (a separate `/home` partition the `/home` overlay sits on): only
    /// the entry NAILS created counts.
    pub fn owned_writable_mount_ids(
        entries: &[MountEntry],
        hidden_root: Option<&Path>,
    ) -> std::collections::HashSet<i32> {
        let mounts = Self::from_entries(entries, hidden_root);
        entries
            .iter()
            .filter(|e| !e.read_only())
            .filter(|e| {
                let mp = &e.mount_point;
                let overlay = e.fstype == "overlay"
                    && (mounts.persistent_overlays.contains(mp)
                        || mounts.ephemeral_overlays.contains(mp));
                let persona = mounts.persona_binds.contains(mp) && is_persona_home_root(&e.root);
                let staged = mounts.pivot_binds.contains(mp) && e.source != Path::new(NIX_STORE);
                let runtime_root = e.fstype == "tmpfs" && mounts.runtime_tmpfs.as_ref() == Some(mp);
                overlay || persona || staged || runtime_root
            })
            .map(|e| e.mount_id)
            .collect()
    }

    /// Whether `target` is a mount NAILS created and may therefore unmount.
    ///
    /// `target` must already be canonicalized, since mountinfo records canonical
    /// kernel paths.
    pub fn is_owned(&self, target: &Path) -> bool {
        if self.persistent_overlays.iter().any(|p| p == target)
            || self.ephemeral_overlays.iter().any(|p| p == target)
            || self.pivot_binds.iter().any(|p| p == target)
            || self.persona_binds.iter().any(|p| p == target)
            || self.runtime_tmpfs.as_deref() == Some(target)
        {
            return true;
        }
        // The /nix/store restore bind is ours only when we also overlaid /nix;
        // otherwise it is the host's real store and must not be detached.
        if target == Path::new(NIX_STORE) {
            return self.nix_store_bind.is_some() && self.nix_overlay_present;
        }
        false
    }
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
        assert_eq!(unescape("a\\040b"), "a b");
        assert_eq!(unescape("a\\011b"), "a\tb");
        assert_eq!(unescape("a\\012b"), "a\nb");
        assert_eq!(unescape("a\\134b"), "a\\b");
    }

    #[test]
    fn unescape_decodes_backslash_literals() {
        assert_eq!(unescape("a\\,b"), "a,b");
        assert_eq!(unescape("a\\:b"), "a:b");
        assert_eq!(unescape("a\\\\b"), "a\\b");
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
            "../../nails-core/tests/fixtures/kernel/userns/mountinfo-overlay-scene.txt"
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

    fn overlay_line(id: i32, mount_point: &str, upper: &str, work: &str) -> String {
        format!(
            "{id} 1 0:50 / {mount_point} rw - overlay overlay rw,lowerdir=/l,upperdir={upper},workdir={work}"
        )
    }

    #[test]
    fn discover_classifies_persistent_ephemeral_pivot_and_nix_store() {
        let hidden = Path::new("/mnt/hidden");
        // The runtime scaffolding root is a random-named tmpfs under /run. It is
        // discovered structurally — not by a fixed name — because it hosts the
        // /var ephemeral overlay's upper and the /etc staging overlay.
        let root = "/run/0123456789abcdef";
        let rt = format!("20 1 0:70 / {root} rw - tmpfs tmpfs rw,mode=700");
        let var = overlay_line(
            11,
            "/var",
            &format!("{root}/var-upper"),
            &format!("{root}/var-work"),
        );
        let pivot = format!(
            "13 1 0:60 / {root}/etc rw - overlay overlay rw,lowerdir=/etc,upperdir=/mnt/hidden/etc/upper,workdir=/mnt/hidden/etc/work"
        );
        let content = format!(
            "{rt}\n{home}\n{var}\n{nix}\n{pivot}\n{nixstore}\n{foreign}",
            home = overlay_line(
                10,
                "/home",
                "/mnt/hidden/home/upper",
                "/mnt/hidden/home/work"
            ),
            nix = overlay_line(12, "/nix", "/mnt/hidden/nix/upper", "/mnt/hidden/nix/work"),
            nixstore = "14 1 8:1 /store /nix/store ro - ext4 /dev/sda1 ro",
            foreign = "15 1 8:2 / /home/other rw - ext4 /dev/sdc1 rw",
        );
        let entries = parse_mountinfo(&content);
        let m = NailsMounts::from_entries(&entries, Some(hidden));

        assert_eq!(m.runtime_tmpfs, Some(PathBuf::from(root)));
        assert!(m.persistent_overlays.contains(&PathBuf::from("/home")));
        assert!(m.persistent_overlays.contains(&PathBuf::from("/nix")));
        assert!(m.ephemeral_overlays.contains(&PathBuf::from("/var")));
        assert!(
            m.pivot_binds
                .contains(&PathBuf::from(format!("{root}/etc")))
        );
        assert_eq!(m.nix_store_bind, Some(PathBuf::from("/nix/store")));
        assert!(m.nix_overlay_present);

        assert!(m.is_owned(Path::new("/home")));
        assert!(m.is_owned(Path::new("/var")));
        assert!(m.is_owned(Path::new("/nix")));
        assert!(m.is_owned(&PathBuf::from(format!("{root}/etc"))));
        // The umbrella tmpfs itself is owned so teardown can remove it last.
        assert!(m.is_owned(Path::new(root)));
        // /nix/store bind is owned because /nix is overlaid.
        assert!(m.is_owned(Path::new("/nix/store")));
        // A foreign ext4 mount is never owned.
        assert!(!m.is_owned(Path::new("/home/other")));
    }

    #[test]
    fn a_read_only_guard_is_told_apart_from_a_decoy_mount_at_the_same_path() {
        let content = "\
1 0 8:1 / / rw - ext4 /dev/sda1 rw
2 1 8:2 / /usr rw - ext4 /dev/sda2 rw
3 2 8:2 / /usr ro - ext4 /dev/sda2 rw
4 1 8:3 / /srv ro - ext4 /dev/sda3 ro
";
        let entries = parse_mountinfo(content);
        // The read-only self-bind stacked on the decoy /usr partition.
        assert!(is_read_only_self_bind(&entries, Path::new("/usr")));
        // The root filesystem and a decoy mount that is read-only by itself.
        assert!(!is_read_only_self_bind(&entries, Path::new("/")));
        assert!(!is_read_only_self_bind(&entries, Path::new("/srv")));
        // Without the guard the bare /usr partition is no guard either.
        let bare = parse_mountinfo(
            "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n2 1 8:2 / /usr rw - ext4 /dev/sda2 rw\n",
        );
        assert!(!is_read_only_self_bind(&bare, Path::new("/usr")));
        // A guard on a plain directory of the root filesystem: a read-only bind
        // of that subtree, on the root's own device.
        let plain = parse_mountinfo(
            "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n5 1 8:1 /usr /usr ro - ext4 /dev/sda1 rw\n",
        );
        assert!(is_read_only_self_bind(&plain, Path::new("/usr")));
    }

    #[test]
    fn owned_writable_mount_ids_skip_the_store_bind_and_the_decoy_underneath() {
        let hidden = Path::new("/mnt/hidden");
        let root = "/run/0123456789abcdef";
        let content = [
            // The decoy's own /home partition, which the /home overlay sits on.
            "9 1 8:3 / /home rw - ext4 /dev/sdb1 rw".to_string(),
            overlay_line(10, "/home", "/mnt/hidden/home/upper", "/mnt/hidden/home/work"),
            overlay_line(12, "/nix", "/mnt/hidden/nix/upper", "/mnt/hidden/nix/work"),
            "14 1 8:1 /store /nix/store ro - ext4 /dev/sda1 ro".to_string(),
            format!("20 1 0:70 / {root} rw - tmpfs tmpfs rw,mode=700"),
            format!(
                "21 20 0:61 / {root}/etc rw - overlay overlay rw,lowerdir=/etc,upperdir=/mnt/hidden/etc/upper,workdir=/mnt/hidden/etc/work"
            ),
            format!("22 20 8:1 /nix/store {root}/original-nix-store ro - ext4 /dev/sda1 ro"),
            "15 1 8:2 / /home/other rw - ext4 /dev/sdc1 rw".to_string(),
        ]
        .join("\n");
        let ids = NailsMounts::owned_writable_mount_ids(&parse_mountinfo(&content), Some(hidden));
        let mut ids: Vec<i32> = ids.into_iter().collect();
        ids.sort_unstable();
        // The overlays, the runtime root and its staging overlay; never the
        // read-only store binds, the decoy /home underneath, or a foreign mount.
        assert_eq!(ids, vec![10, 12, 20, 21]);
    }

    #[test]
    fn foreign_run_tmpfs_without_nails_scaffolding_is_not_mistaken_for_the_runtime_root() {
        // A /run tmpfs that hosts no NAILS overlay, staging mount or /nix/store
        // bind (here a snap runtime with only a plain bind under it) must not be
        // picked up as our scaffolding root, and an empty NAILS umbrella (no
        // staging yet) is likewise not discovered structurally — a trusted
        // teardown removes that one from the recorded state path instead.
        let content = concat!(
            "40 1 0:80 / /run/snapd rw - tmpfs tmpfs rw,mode=755\n",
            "41 40 0:81 / /run/snapd/ns rw - nsfs nsfs rw\n",
            "42 1 0:82 / /run/0123456789abcdef rw - tmpfs tmpfs rw,mode=700\n",
        );
        let entries = parse_mountinfo(content);
        let m = NailsMounts::from_entries(&entries, Some(Path::new("/mnt/hidden")));
        assert_eq!(
            m.runtime_tmpfs, None,
            "neither a foreign /run tmpfs nor an empty umbrella is our runtime root"
        );
        assert!(m.pivot_binds.is_empty());
    }

    #[test]
    fn unmanaged_ext4_home_is_not_owned_so_umount_is_refused() {
        // The exact done-when case: a plain ext4 /home must not be unmountable.
        let content = "25 1 8:3 / /home rw - ext4 /dev/sdd1 rw";
        let entries = parse_mountinfo(content);
        let m = NailsMounts::from_entries(&entries, Some(Path::new("/mnt/hidden")));
        assert!(!m.is_owned(Path::new("/home")));
    }

    #[test]
    fn nix_store_bind_not_owned_without_nix_overlay() {
        // /nix/store is bound but /nix is NOT overlaid: this is the host's real
        // store and must be refused.
        let content = "30 1 8:1 /store /nix/store ro - ext4 /dev/sda1 ro";
        let entries = parse_mountinfo(content);
        let m = NailsMounts::from_entries(&entries, None);
        assert!(!m.is_owned(Path::new("/nix/store")));
    }

    #[test]
    fn persona_home_bind_is_classified_and_owned() {
        // A plain bind of {hidden_root}/persona/home over the operator's home:
        // mountinfo shows its in-filesystem root ending in /persona/home.
        let content = "\
50 1 8:1 /persona/home /home/op rw - ext4 /dev/sda1 rw
51 1 8:2 / /home/other rw - ext4 /dev/sdc1 rw";
        let entries = parse_mountinfo(content);

        // Recognised even without the hidden root (unmount discovers with None).
        let m = NailsMounts::from_entries(&entries, None);
        assert!(m.persona_binds.contains(&PathBuf::from("/home/op")));
        assert!(m.is_owned(Path::new("/home/op")));
        // An unrelated ext4 mount over another home is still refused.
        assert!(!m.is_owned(Path::new("/home/other")));
    }

    #[test]
    fn discover_without_hidden_root_treats_any_overlay_as_owned() {
        let content = overlay_line(40, "/home", "/somewhere/upper", "/somewhere/work");
        let entries = parse_mountinfo(&content);
        let m = NailsMounts::from_entries(&entries, None);
        assert!(m.is_owned(Path::new("/home")));
    }
}
