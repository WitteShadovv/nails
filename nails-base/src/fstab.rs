// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! `/etc/fstab`: the filesystems a system's systemd mounts at boot.
//!
//! `systemd-fstab-generator` turns every entry into a `.mount` or `.swap`
//! unit. The one parser here, and the classes of filesystem an entry belongs
//! to, are shared by every reader of a decoy's fstab: the session policy in
//! `nails-session` decides each entry before the switch, and its unit names
//! for an entry live there too.

use std::path::{Path, PathBuf};

/// One fstab line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FstabEntry {
    /// The first field: a device, `UUID=`/`LABEL=`/`PARTUUID=`/`PARTLABEL=`, a
    /// path for a bind, or a pseudo source.
    pub spec: String,
    /// The mount point (`none` for swap).
    pub file: PathBuf,
    /// The filesystem type.
    pub vfstype: String,
    /// The mount options.
    pub options: Vec<String>,
}

/// Whether `vfstype` is the type of a RAM or kernel filesystem.
pub fn is_virtual_type(vfstype: &str) -> bool {
    VIRTUAL_TYPES.contains(&vfstype)
}

/// Filesystem types that live in RAM or the kernel, never on a decoy disk.
const VIRTUAL_TYPES: &[&str] = &[
    "tmpfs",
    "ramfs",
    "proc",
    "sysfs",
    "devtmpfs",
    "devpts",
    "cgroup",
    "cgroup2",
    "securityfs",
    "debugfs",
    "tracefs",
    "configfs",
    "fusectl",
    "mqueue",
    "hugetlbfs",
    "bpf",
    "pstore",
    "efivarfs",
    "binfmt_misc",
    "autofs",
    "rpc_pipefs",
    "nsfs",
    "zram",
];

/// Host shares of a virtual machine: they never reach a disk of the guest.
const HOST_SHARE_TYPES: &[&str] = &["9p", "virtiofs"];

/// Filesystems backed by a server.
const NETWORK_TYPES: &[&str] = &[
    "nfs",
    "nfs4",
    "cifs",
    "smb3",
    "smbfs",
    "ceph",
    "glusterfs",
    "sshfs",
    "davfs",
];

impl FstabEntry {
    /// Whether an option is present (`noauto`, `bind`, `ro`, …).
    pub fn has_option(&self, name: &str) -> bool {
        self.options.iter().any(|o| o == name)
    }

    /// The value of a `key=value` option.
    pub fn option_value(&self, key: &str) -> Option<&str> {
        self.options
            .iter()
            .find_map(|o| o.strip_prefix(key).and_then(|rest| rest.strip_prefix('=')))
    }

    /// A swap entry.
    pub fn is_swap(&self) -> bool {
        self.vfstype == "swap"
    }

    /// A RAM or kernel filesystem.
    pub fn is_virtual(&self) -> bool {
        is_virtual_type(&self.vfstype)
    }

    /// A virtual machine's host share.
    pub fn is_host_share(&self) -> bool {
        HOST_SHARE_TYPES.contains(&self.vfstype.as_str())
    }

    /// A network filesystem (including FUSE network types).
    pub fn is_network(&self) -> bool {
        NETWORK_TYPES.contains(&self.vfstype.as_str())
            || self.vfstype.starts_with("fuse.sshfs")
            || self.has_option("_netdev")
    }

    /// A bind mount.
    pub fn is_bind(&self) -> bool {
        self.has_option("bind") || self.has_option("rbind")
    }

    /// Whether the last of the options `yes` and `no` the entry gives is
    /// `yes`, the way systemd's fstab generator reads a pair such as
    /// `noauto` and `auto`: `noauto,auto` is `auto`, and an entry with
    /// neither is `no`.
    pub fn yes_no_option(&self, yes: &str, no: &str) -> bool {
        self.options
            .iter()
            .rev()
            .find(|o| *o == yes || *o == no)
            .is_some_and(|o| o == yes)
    }

    /// Mounted only on demand by an automount unit: `x-systemd.automount`, or
    /// its older spelling `comment=systemd.automount`. systemd makes no
    /// automount for a swap entry.
    pub fn is_automount(&self) -> bool {
        !self.is_swap()
            && (self.has_option("x-systemd.automount")
                || self.has_option("comment=systemd.automount"))
    }

    /// Never mounted at boot (and not on demand): `noauto`, unless a later
    /// `auto` takes it back, the entry has an automount, which the boot sets
    /// up whatever `noauto` says, or it names a unit that pulls it in
    /// ([`names_units_that_pull_it_in`](Self::names_units_that_pull_it_in)).
    pub fn is_noauto(&self) -> bool {
        self.yes_no_option("noauto", "auto")
            && !self.is_automount()
            && !self.names_units_that_pull_it_in()
    }

    /// A mount entry that names units to pull it in: `x-systemd.wanted-by=`
    /// or `x-systemd.required-by=` with a unit. systemd's fstab generator
    /// links its unit into those units' `.wants` or `.requires` directory
    /// whatever `noauto` and `nofail` say. It reads no such option for swap.
    pub fn names_units_that_pull_it_in(&self) -> bool {
        !self.is_swap()
            && self.options.iter().any(|option| {
                ["x-systemd.wanted-by=", "x-systemd.required-by="]
                    .iter()
                    .any(|key| {
                        option
                            .strip_prefix(key)
                            .is_some_and(|unit| !unit.is_empty())
                    })
            })
    }

    /// `nofail`, unless a later `fail` takes it back: the boot then only
    /// wants the entry's unit, and goes on without it.
    pub fn is_nofail(&self) -> bool {
        self.yes_no_option("nofail", "fail")
    }

    /// The block device the spec names, as a `/dev` path.
    pub fn device(&self) -> Option<PathBuf> {
        spec_device(&self.spec)
    }
}

/// Decode fstab's octal escapes (`\040` for a space).
fn unescape(field: &str) -> String {
    crate::filesystem::mountinfo::unescape_octal(field)
}

/// Parse fstab text. Comments, blank lines and short lines are skipped.
pub fn parse_fstab(text: &str) -> Vec<FstabEntry> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let spec = unescape(fields.next()?);
            let file = PathBuf::from(unescape(fields.next()?));
            let vfstype = fields.next().unwrap_or("auto").to_string();
            let options = fields
                .next()
                .unwrap_or("defaults")
                .split(',')
                .map(str::to_string)
                .collect();
            Some(FstabEntry {
                spec,
                file,
                vfstype,
                options,
            })
        })
        .collect()
}

/// The `/dev` path a spec names, as systemd's `fstab_node_to_udev_node()`
/// reads it: `/dev/...` as is, and `UUID=`, `LABEL=`, `PARTUUID=` and
/// `PARTLABEL=` as the link udev makes for the value under `/dev/disk/by-*`.
/// The value loses one pair of quotes around it and is encoded as udev
/// encodes the name of a link: `LABEL=My Data` is
/// `/dev/disk/by-label/My\x20Data`.
pub fn spec_device(spec: &str) -> Option<PathBuf> {
    if spec.starts_with("/dev/") {
        return Some(PathBuf::from(spec));
    }
    let (key, value) = spec.split_once('=')?;
    let dir = match key {
        "UUID" => "by-uuid",
        "LABEL" => "by-label",
        "PARTUUID" => "by-partuuid",
        "PARTLABEL" => "by-partlabel",
        _ => return None,
    };
    Some(
        Path::new("/dev/disk")
            .join(dir)
            .join(encode_devnode_name(unquote(value))),
    )
}

/// `value` without one pair of matching quotes, `"` or `'`, around it.
fn unquote(value: &str) -> &str {
    let bytes = value.as_bytes();
    match bytes {
        [quote @ (b'"' | b'\''), .., last] if last == quote => &value[1..value.len() - 1],
        _ => value,
    }
}

/// `value` as udev writes it in the name of a link (`encode_devnode_name()`
/// in systemd): ASCII letters and digits, `#+-.:=@_` and valid multi-byte
/// characters stay, and every other byte, the backslash included, becomes
/// `\xNN`. A `/` in a label therefore stays inside the link's name.
fn encode_devnode_name(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        let code = u32::from(c);
        // systemd's unichar_is_valid() refuses the noncharacters.
        let kept = if c.is_ascii() {
            c.is_ascii_alphanumeric() || "#+-.:=@_".contains(c)
        } else {
            !(0xfdd0..=0xfdef).contains(&code) && code & 0xfffe != 0xfffe
        };
        if kept {
            out.push(c);
        } else {
            let mut buf = [0u8; 4];
            for byte in c.encode_utf8(&mut buf).bytes() {
                out.push_str(&format!("\\x{byte:02x}"));
            }
        }
    }
    out
}

/// systemd's path escaping (`systemd-escape --path`): the name a unit for
/// `path` carries (`/mnt/my-disk` is `mnt-my\x2ddisk`). The path is first
/// simplified as systemd's `path_simplify()` does: repeated slashes and `.`
/// components go, and so does `..` at the start of an absolute path, which
/// cannot climb above `/` (`/mnt/./data/` is `mnt-data`). A single file name
/// escapes as an instance name does (`vg-root` is `vg\x2droot`).
pub fn escape_path(path: &Path) -> String {
    let text = path.to_string_lossy();
    let absolute = text.starts_with('/');
    let mut kept: Vec<&str> = Vec::new();
    for component in text.split('/').filter(|c| !c.is_empty() && *c != ".") {
        if absolute && kept.is_empty() && component == ".." {
            continue;
        }
        kept.push(component);
    }
    if kept.is_empty() {
        return "-".to_string();
    }
    let joined = kept.join("/");
    let mut out = String::new();
    for (i, byte) in joined.bytes().enumerate() {
        match byte {
            b'/' => out.push('-'),
            b'.' if i == 0 => out.push_str("\\x2e"),
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b':' | b'_' | b'.' => out.push(byte as char),
            other => out.push_str(&format!("\\x{other:02x}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_typical_fstab_is_parsed_with_escapes_and_defaults() {
        let entries = parse_fstab(
            "# comment\n\
             UUID=1234-ABCD /boot vfat umask=0077 0 2\n\
             /dev/mapper/root / ext4 errors=remount-ro 0 1\n\
             LABEL=home /home ext4 defaults,noatime 0 2\n\
             /dev/sdb1 /mnt/My\\040Disk ntfs-3g noauto 0 0\n\
             /swapfile none swap sw 0 0\n\
             tmpfs /tmp tmpfs\n\
             \n",
        );
        assert_eq!(entries.len(), 6);
        assert_eq!(entries[0].file, Path::new("/boot"));
        assert_eq!(
            entries[0].device(),
            Some(PathBuf::from("/dev/disk/by-uuid/1234-ABCD"))
        );
        assert_eq!(entries[3].file, Path::new("/mnt/My Disk"));
        assert!(entries[3].is_noauto());
        assert!(entries[4].is_swap());
        assert!(entries[5].is_virtual());
        assert_eq!(entries[5].options, vec!["defaults"]);
        assert_eq!(entries[1].option_value("errors"), Some("remount-ro"));
    }

    #[test]
    fn filesystem_classes_are_told_apart() {
        let entry = |t: &str, o: &str| FstabEntry {
            spec: "x".into(),
            file: "/x".into(),
            vfstype: t.into(),
            options: o.split(',').map(str::to_string).collect(),
        };
        assert!(entry("9p", "trans=virtio").is_host_share());
        assert!(entry("nfs4", "defaults").is_network());
        assert!(entry("ext4", "_netdev").is_network());
        assert!(entry("none", "bind").is_bind());
        assert!(!entry("ext4", "noauto,x-systemd.automount").is_noauto());
        assert!(entry("ext4", "noauto,x-systemd.automount").is_automount());
    }

    /// systemd's fstab generator takes the last of `noauto` and `auto`, and of
    /// `nofail` and `fail`: an entry that reads `noauto` first and `auto`
    /// after it is mounted at boot, and read as `noauto` the session left it
    /// to the hidden systemd, which mounted it read-write.
    #[test]
    fn the_last_of_an_option_and_its_opposite_counts() {
        let entry = |t: &str, o: &str| FstabEntry {
            spec: "/dev/vdb1".into(),
            file: "/data".into(),
            vfstype: t.into(),
            options: o.split(',').map(str::to_string).collect(),
        };
        assert!(!entry("ext4", "noauto,auto").is_noauto());
        assert!(entry("ext4", "auto,noauto").is_noauto());
        assert!(!entry("ext4", "defaults").is_noauto());
        assert!(entry("ext4", "nofail").is_nofail());
        assert!(!entry("ext4", "nofail,fail").is_nofail());
        assert!(entry("ext4", "fail,defaults,nofail").is_nofail());
        assert!(!entry("ext4", "defaults").is_nofail());
        assert!(!entry("ext4", "nofail=no").is_nofail());
        // The older spelling of an automount, which systemd still reads; and
        // none for swap, which systemd never gives one.
        assert!(entry("ext4", "comment=systemd.automount").is_automount());
        assert!(!entry("ext4", "comment=systemd.automount,noauto").is_noauto());
        assert!(!entry("swap", "x-systemd.automount").is_automount());
        assert!(entry("swap", "noauto,x-systemd.automount").is_noauto());
        // A unit named to pull the entry in takes noauto back, as the fstab
        // generator then links the mount there; not for swap, nor with no
        // unit named.
        for options in [
            "noauto,x-systemd.wanted-by=multi-user.target",
            "x-systemd.required-by=backup.service,noauto",
        ] {
            assert!(!entry("ext4", options).is_noauto(), "{options}");
            assert!(entry("ext4", options).names_units_that_pull_it_in());
        }
        assert!(entry("ext4", "noauto,x-systemd.wanted-by=").is_noauto());
        assert!(entry("swap", "noauto,x-systemd.wanted-by=multi-user.target").is_noauto());
    }

    #[test]
    fn specs_name_their_dev_paths() {
        assert_eq!(
            spec_device("PARTUUID=0a1b-02"),
            Some(PathBuf::from("/dev/disk/by-partuuid/0a1b-02"))
        );
        assert_eq!(
            spec_device("PARTLABEL=\"data\""),
            Some(PathBuf::from("/dev/disk/by-partlabel/data"))
        );
        assert_eq!(spec_device("/dev/vdb"), Some(PathBuf::from("/dev/vdb")));
        assert_eq!(spec_device("tmpfs"), None);
        assert_eq!(spec_device("ID=1"), None);
    }

    /// A path is simplified as systemd simplifies it before it is escaped.
    /// Found by the `fstab_crypttab` fuzz target: the swap on
    /// `/dev/disk/by-/./label/swap` kept its `.` in the unit the session
    /// masked, so the unit systemd generates stayed free.
    #[test]
    fn a_path_is_simplified_as_systemd_simplifies_it() {
        for (path, name) in [
            ("/mnt/./data/.", "mnt-data"),
            ("/./x", "x"),
            ("//mnt//data//", "mnt-data"),
            ("/../../mnt/data", "mnt-data"),
            ("/.", "-"),
            ("/./.hidden", "\\x2ehidden"),
            ("./vg-root", "vg\\x2droot"),
        ] {
            assert_eq!(escape_path(Path::new(path)), name, "{path}");
        }
    }

    /// A tag names the link udev makes for it, in udev's encoding. Found by
    /// the `fstab_crypttab` fuzz target: `LABEL=swap space` named
    /// `/dev/disk/by-label/swap space`, which no link is, so the session
    /// masked a swap unit systemd never generates and left the real one free.
    #[test]
    fn a_tag_names_the_link_udev_makes() {
        for (spec, device) in [
            ("LABEL=My Data", "/dev/disk/by-label/My\\x20Data"),
            ("LABEL=\"My Data\"", "/dev/disk/by-label/My\\x20Data"),
            (
                "PARTLABEL='EFI system'",
                "/dev/disk/by-partlabel/EFI\\x20system",
            ),
            ("LABEL=\"\"half\"", "/dev/disk/by-label/\\x22half"),
            ("LABEL=a/b", "/dev/disk/by-label/a\\x2fb"),
            // Not the absolute path /etc, which Path::join made of it.
            ("LABEL=/etc", "/dev/disk/by-label/\\x2fetc"),
            ("LABEL=back\\slash", "/dev/disk/by-label/back\\x5cslash"),
            ("LABEL=Données#2", "/dev/disk/by-label/Données#2"),
            ("UUID=0a1b-2c3d", "/dev/disk/by-uuid/0a1b-2c3d"),
        ] {
            assert_eq!(spec_device(spec), Some(PathBuf::from(device)), "{spec}");
        }
    }
}
