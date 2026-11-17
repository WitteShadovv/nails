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

/// Whether `vfstype` is the type of a virtual machine's host share.
pub fn is_host_share_type(vfstype: &str) -> bool {
    HOST_SHARE_TYPES.contains(&vfstype)
}

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

/// Whether `vfstype` is the type of a filesystem backed by a server
/// (including FUSE network types), whatever the options of a line say.
pub fn is_network_type(vfstype: &str) -> bool {
    NETWORK_TYPES.contains(&vfstype) || vfstype.starts_with("fuse.sshfs")
}

/// What the mount option `option` gives when its name is `name`, as systemd's
/// `fstab_test_option()` and `libmount` match an option by its name, the
/// part before a `=`: `Some(None)` for the name alone, `Some(Some(value))` for
/// `name=value`, an empty value too, and `None` for an option of another
/// name (`noauto=1` is named `noauto`, and neither `noautox` nor `auto` is).
pub fn option_named<'a>(option: &'a str, name: &str) -> Option<Option<&'a str>> {
    match option.strip_prefix(name)? {
        "" => Some(None),
        rest => rest.strip_prefix('=').map(Some),
    }
}

/// Whether an option of `options` has one of `names`, alone or with a value,
/// as systemd's `fstab_test_option()` matches an option by its name
/// ([`option_named`]): `x-systemd.makefs=1` and `usrjquota=aquota.user` are
/// `x-systemd.makefs` and `usrjquota` to it.
pub fn any_named<S: AsRef<str>>(options: &[S], names: &[&str]) -> bool {
    options.iter().any(|option| {
        names
            .iter()
            .any(|name| option_named(option.as_ref(), name).is_some())
    })
}

/// Whether the last of `options` named `yes` or `no`, alone or with a value,
/// is named `yes`, as systemd's `fstab_test_yes_no_option()` reads such a
/// pair, whatever the value: neither is `no`. systemd 260.5's fstab
/// generator mounts a line with `noauto,auto=1` or `noauto,auto=0` at boot,
/// and takes `nofail=0` for `nofail`.
pub fn last_named(options: &[String], yes: &str, no: &str) -> bool {
    options
        .iter()
        .rev()
        .find_map(|option| {
            if option_named(option, yes).is_some() {
                Some(true)
            } else {
                option_named(option, no).map(|_| false)
            }
        })
        .unwrap_or(false)
}

/// Whether the mount option `option` makes a bind mount: its name, the part
/// before a `=`, is `bind` or `rbind`. `libmount` and systemd's
/// `fstab_test_option()` match an option by that name, so `bind=x` and
/// `rbind=` bind as `bind` and `rbind` do, whatever the type of the line.
pub fn is_bind_option(option: &str) -> bool {
    let name = option.split_once('=').map_or(option, |(name, _)| name);
    matches!(name, "bind" | "rbind")
}

impl FstabEntry {
    /// Whether an option is present as `name` exactly, with no value. The
    /// generators and `libmount` read an option by its name, with a value
    /// too, as [`has_named`](Self::has_named) does.
    pub fn has_option(&self, name: &str) -> bool {
        self.options.iter().any(|o| o == name)
    }

    /// Whether an option is named `name`, alone or with a value, as systemd
    /// reads it ([`any_named`]).
    pub fn has_named(&self, name: &str) -> bool {
        any_named(&self.options, &[name])
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
        is_host_share_type(&self.vfstype)
    }

    /// A network filesystem (including FUSE network types), or a line
    /// marked `_netdev`, by its name: the fstab generator links a line with
    /// `_netdev=1` into `remote-fs.target`.
    pub fn is_network(&self) -> bool {
        is_network_type(&self.vfstype) || self.has_named("_netdev")
    }

    /// A bind mount: an option `bind` or `rbind`, with a value too
    /// ([`is_bind_option`]).
    pub fn is_bind(&self) -> bool {
        self.options.iter().any(|option| is_bind_option(option))
    }

    /// Whether the last of the options named `yes` and `no` the entry gives,
    /// alone or with a value, is `yes`, the way systemd's fstab generator
    /// reads a pair such as `noauto` and `auto` ([`last_named`]):
    /// `noauto,auto` and `noauto,auto=1` are `auto`, and an entry with
    /// neither is `no`.
    pub fn yes_no_option(&self, yes: &str, no: &str) -> bool {
        last_named(&self.options, yes, no)
    }

    /// Mounted only on demand by an automount unit: an option named
    /// `x-systemd.automount`, or its older spelling
    /// `comment=systemd.automount`, alone or with a value, which the fstab
    /// generator reads by its name (`x-systemd.automount=0` too). systemd
    /// makes no automount for a swap entry, nor for a mount of `/` or `/usr`
    /// ([`is_mandatory`](Self::is_mandatory)).
    pub fn is_automount(&self) -> bool {
        !self.is_swap()
            && !self.is_mandatory()
            && any_named(
                &self.options,
                &["x-systemd.automount", "comment=systemd.automount"],
            )
    }

    /// Whether systemd's fstab generator mounts the entry whatever its
    /// options say: a mount of `/` or `/usr`, as written with no `.` or `..`,
    /// which it takes for mandatory and mounts, `noauto`, `nofail` and an
    /// automount ignored.
    pub fn is_mandatory(&self) -> bool {
        !self.is_swap()
            && crate::hidden_root::separation::as_written(&self.file)
                .is_some_and(|at| at == Path::new("/") || at == Path::new("/usr"))
    }

    /// Never mounted at boot (and not on demand), as systemd's fstab
    /// generator reads its options, by their names: the last of `noauto` and
    /// `auto` is `noauto` ([`yes_no_option`](Self::yes_no_option)), and the
    /// entry has no automount, which the boot sets up whatever `noauto` says,
    /// names no unit that pulls it in
    /// ([`names_units_that_pull_it_in`](Self::names_units_that_pull_it_in))
    /// and is no mount of `/` or `/usr` ([`is_mandatory`](Self::is_mandatory)).
    /// It says nothing of the options NAILS does not read: a reader that acts
    /// on it asks that too
    /// ([`unread_fstab_options`](crate::hidden_root::separation::unread_fstab_options)).
    pub fn is_noauto(&self) -> bool {
        self.yes_no_option("noauto", "auto")
            && !self.is_automount()
            && !self.names_units_that_pull_it_in()
            && !self.is_mandatory()
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

    /// `nofail`, unless a later `fail` takes it back, each by its name
    /// ([`yes_no_option`](Self::yes_no_option)): the boot then only wants
    /// the entry's unit, and goes on without it. A mount of `/` or `/usr`
    /// is never `nofail` ([`is_mandatory`](Self::is_mandatory)).
    pub fn is_nofail(&self) -> bool {
        self.yes_no_option("nofail", "fail") && !self.is_mandatory()
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
    parse_fstab_lines(text)
        .into_iter()
        .map(|(entry, _)| entry)
        .collect()
}

/// [`parse_fstab`], each entry with the line it is read from as that line is
/// written, without the spaces and tabs around it: its fields still hold
/// their escapes. The lines are read as `libmount` reads them ([`lines`]).
pub fn parse_fstab_lines(text: &str) -> Vec<(FstabEntry, &str)> {
    lines(text)
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
            let entry = FstabEntry {
                spec,
                file,
                vfstype,
                options,
            };
            Some((entry, line))
        })
        .collect()
}

/// The lines of the text of an fstab, as `libmount` reads them: the text
/// split at each newline, one carriage return before it dropped, and only
/// the spaces and tabs at either end of a line trimmed, as its `skip_blank()`
/// skips them. Any other white space stays, so a line that starts with a
/// vertical tab or a no-break space before a `#` is no comment, as it is
/// none to `libmount` and systemd either. The crypttab parser splits its
/// text the same way, though systemd also ends a crypttab line at a lone
/// carriage return or a NUL, which then stay inside a line here.
pub fn lines(text: &str) -> impl Iterator<Item = &str> {
    text.split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .map(|line| line.trim_matches([' ', '\t']))
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
#[path = "fstab_tests.rs"]
mod tests;
