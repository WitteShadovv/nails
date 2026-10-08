// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! `/etc/fstab` as the hidden systemd will read it, and systemd's unit names.
//!
//! The hidden root runs the decoy's own fstab (or, on NixOS, the hidden
//! toplevel's). `systemd-fstab-generator` turns every entry into a `.mount` or
//! `.swap` unit, so the session policy ([`super::policy`]) needs the same view
//! of it, plus the unit names it would generate, to overlay, bind or mask each
//! entry before the switch.

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
        VIRTUAL_TYPES.contains(&self.vfstype.as_str())
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

    /// Mounted only on demand by an automount unit.
    pub fn is_automount(&self) -> bool {
        self.has_option("x-systemd.automount")
    }

    /// Never mounted at boot (and not on demand).
    pub fn is_noauto(&self) -> bool {
        self.has_option("noauto") && !self.is_automount()
    }

    /// The block device the spec names, as a `/dev` path.
    pub fn device(&self) -> Option<PathBuf> {
        spec_device(&self.spec)
    }
}

/// Decode fstab's octal escapes (`\040` for a space).
fn unescape(field: &str) -> String {
    nails_teardown::mountinfo::unescape_octal(field)
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

/// The `/dev` path a spec names: `/dev/...` as is, `UUID=x` as
/// `/dev/disk/by-uuid/x`, and likewise for `LABEL`, `PARTUUID`, `PARTLABEL`.
pub fn spec_device(spec: &str) -> Option<PathBuf> {
    if spec.starts_with("/dev/") {
        return Some(PathBuf::from(spec));
    }
    let (key, value) = spec.split_once('=')?;
    let value = value.trim_matches('"');
    let dir = match key {
        "UUID" => "by-uuid",
        "LABEL" => "by-label",
        "PARTUUID" => "by-partuuid",
        "PARTLABEL" => "by-partlabel",
        _ => return None,
    };
    Some(Path::new("/dev/disk").join(dir).join(value))
}

/// systemd's path escaping (`systemd-escape --path`).
pub fn escape_path(path: &Path) -> String {
    let text = path.to_string_lossy();
    let trimmed: Vec<&str> = text.split('/').filter(|s| !s.is_empty()).collect();
    if trimmed.is_empty() {
        return "-".to_string();
    }
    let joined = trimmed.join("/");
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

/// The `.mount` unit for a mount point.
pub fn mount_unit(path: &Path) -> String {
    format!("{}.mount", escape_path(path))
}

/// The `.automount` unit for a mount point.
pub fn automount_unit(path: &Path) -> String {
    format!("{}.automount", escape_path(path))
}

/// The `.swap` unit for a swap spec, when it names a device or file.
pub fn swap_unit(spec: &str) -> Option<String> {
    let path = spec_device(spec).or_else(|| spec.starts_with('/').then(|| PathBuf::from(spec)))?;
    Some(format!("{}.swap", escape_path(&path)))
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
    fn units_are_named_the_way_systemd_names_them() {
        assert_eq!(mount_unit(Path::new("/")), "-.mount");
        assert_eq!(mount_unit(Path::new("/boot/efi")), "boot-efi.mount");
        assert_eq!(mount_unit(Path::new("/home/")), "home.mount");
        assert_eq!(
            mount_unit(Path::new("/mnt/my-disk")),
            "mnt-my\\x2ddisk.mount"
        );
        assert_eq!(
            mount_unit(Path::new("/mnt/My Disk")),
            "mnt-My\\x20Disk.mount"
        );
        assert_eq!(mount_unit(Path::new("/.snapshots")), "\\x2esnapshots.mount");
        assert_eq!(automount_unit(Path::new("/srv/x")), "srv-x.automount");
        assert_eq!(swap_unit("/dev/vda3").as_deref(), Some("dev-vda3.swap"));
        assert_eq!(
            swap_unit("UUID=0a-1b").as_deref(),
            Some("dev-disk-by\\x2duuid-0a\\x2d1b.swap")
        );
        assert_eq!(swap_unit("/swapfile").as_deref(), Some("swapfile.swap"));
        assert_eq!(swap_unit("none"), None);
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
}
