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

use crate::{NailsError, Result};
use std::path::{Path, PathBuf};

/// Runtime directory holding tmpfs-backed ephemeral overlay upper/work dirs.
const RUNTIME_DIR: &str = "/run/nails";
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
/// arbitrary whitespace would corrupt a path containing a tab.
pub fn parse_mountinfo(content: &str) -> Vec<MountEntry> {
    content.lines().filter_map(parse_line).collect()
}

fn parse_line(line: &str) -> Option<MountEntry> {
    let tokens: Vec<&str> = line.split(' ').filter(|t| !t.is_empty()).collect();
    // Need at least: id parent dev root mount_point opts - fstype source super.
    let sep = tokens.iter().position(|&t| t == "-")?;
    if sep < 6 || sep + 3 >= tokens.len() {
        tracing::debug!(line = %line, "Skipping malformed mountinfo line");
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

/// Read and parse `/proc/self/mountinfo` once.
pub fn read_mountinfo() -> Result<Vec<MountEntry>> {
    let content = std::fs::read_to_string("/proc/self/mountinfo")?;
    Ok(parse_mountinfo(&content))
}

/// Recover `lowerdir`/`upperdir`/`workdir` from an overlay super-option string.
///
/// Options are comma-separated and lower layers colon-separated; a `\,` or `\:`
/// inside a path is honoured, then every path is [`unescape`]d.
pub fn parse_overlay_opts(super_opts: &str) -> OverlayOpts {
    let mut opts = OverlayOpts::default();
    for raw in split_raw(super_opts, ',') {
        if let Some(v) = raw.strip_prefix("lowerdir=") {
            opts.lowerdir = split_raw(v, ':')
                .into_iter()
                .filter(|s| !s.is_empty())
                .map(|s| PathBuf::from(unescape(&s)))
                .collect();
        } else if let Some(v) = raw.strip_prefix("upperdir=") {
            opts.upperdir = Some(PathBuf::from(unescape(v)));
        } else if let Some(v) = raw.strip_prefix("workdir=") {
            opts.workdir = Some(PathBuf::from(unescape(v)));
        }
    }
    opts
}

/// Escape a path for use inside an overlay mount option value.
///
/// The kernel's overlay option parser treats `,` as the option separator, `:`
/// as the lower-layer separator and `\` as the escape character, so each is
/// backslash-escaped here. A newline cannot be represented in a mount option
/// line and is rejected rather than silently truncating the option string.
pub fn escape_overlay_path(path: &Path) -> Result<String> {
    let s = path.to_string_lossy();
    if s.contains('\n') {
        return Err(NailsError::OverlayError(format!(
            "overlay path contains a newline and cannot be mounted: {}",
            path.display()
        )));
    }
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '\\' | ':' | ',') {
            out.push('\\');
        }
        out.push(c);
    }
    Ok(out)
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
    /// Overlays whose upper/work live under the runtime dir (`/run/nails`).
    pub ephemeral_overlays: Vec<PathBuf>,
    /// Mounts under the pivot staging base (`/run/nails-pivot`).
    pub pivot_binds: Vec<PathBuf>,
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
    pub fn discover(hidden_root: Option<&Path>) -> Result<Self> {
        Ok(Self::from_entries(&read_mountinfo()?, hidden_root))
    }

    /// Classify an already-parsed mount table (the testable core of `discover`).
    pub fn from_entries(entries: &[MountEntry], hidden_root: Option<&Path>) -> Self {
        let pivot_base = Path::new(crate::overlay::PIVOT_STAGING_BASE);
        let runtime_dir = Path::new(RUNTIME_DIR);
        let under =
            |p: &Option<PathBuf>, base: &Path| p.as_deref().is_some_and(|x| x.starts_with(base));

        let mut m = NailsMounts::default();
        for e in entries {
            let mp = &e.mount_point;

            if mp.starts_with(pivot_base) {
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
                } else if under(&opts.upperdir, runtime_dir) || under(&opts.workdir, runtime_dir) {
                    m.ephemeral_overlays.push(mp.clone());
                } else if hidden_root.is_none() {
                    m.persistent_overlays.push(mp.clone());
                }
            } else if mp == Path::new(NIX_STORE) {
                m.nix_store_bind = Some(mp.clone());
            } else if crate::config::persona::is_persona_home_root(&e.root) {
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
        points
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
    fn escape_overlay_path_escapes_separators_and_rejects_newline() {
        assert_eq!(
            escape_overlay_path(Path::new("/a,b:c\\d")).unwrap(),
            "/a\\,b\\:c\\\\d"
        );
        assert!(escape_overlay_path(Path::new("/a\nb")).is_err());
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
        let content = format!(
            "{home}\n{var}\n{nix}\n{pivot}\n{nixstore}\n{foreign}",
            home = overlay_line(
                10,
                "/home",
                "/mnt/hidden/home/upper",
                "/mnt/hidden/home/work"
            ),
            var = overlay_line(11, "/var", "/run/nails/var/upper", "/run/nails/var/work"),
            nix = overlay_line(12, "/nix", "/mnt/hidden/nix/upper", "/mnt/hidden/nix/work"),
            pivot = "13 1 0:60 / /run/nails-pivot/etc rw - overlay overlay rw,lowerdir=/etc,upperdir=/mnt/hidden/etc/upper,workdir=/mnt/hidden/etc/work",
            nixstore = "14 1 8:1 /store /nix/store ro - ext4 /dev/sda1 ro",
            foreign = "15 1 8:2 / /home/other rw - ext4 /dev/sdc1 rw",
        );
        let entries = parse_mountinfo(&content);
        let m = NailsMounts::from_entries(&entries, Some(hidden));

        assert!(m.persistent_overlays.contains(&PathBuf::from("/home")));
        assert!(m.persistent_overlays.contains(&PathBuf::from("/nix")));
        assert!(m.ephemeral_overlays.contains(&PathBuf::from("/var")));
        assert!(
            m.pivot_binds
                .contains(&PathBuf::from("/run/nails-pivot/etc"))
        );
        assert_eq!(m.nix_store_bind, Some(PathBuf::from("/nix/store")));
        assert!(m.nix_overlay_present);

        assert!(m.is_owned(Path::new("/home")));
        assert!(m.is_owned(Path::new("/var")));
        assert!(m.is_owned(Path::new("/nix")));
        assert!(m.is_owned(Path::new("/run/nails-pivot/etc")));
        // /nix/store bind is owned because /nix is overlaid.
        assert!(m.is_owned(Path::new("/nix/store")));
        // A foreign ext4 mount is never owned.
        assert!(!m.is_owned(Path::new("/home/other")));
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
