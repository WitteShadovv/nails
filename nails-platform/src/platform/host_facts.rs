// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Host security facts: the active Linux Security Modules and the SELinux mode.
//!
//! These are read once by [`detect`](super::detect) and carried on the
//! [`HostProfile`](super::HostProfile), so the parts of NAILS that care about a
//! host's mandatory-access-control layer (the window, and the Fedora label work)
//! read them from one place rather than probing the kernel themselves. Every
//! read goes through the [`Filesystem`] trait and tolerates absence: a host
//! without SELinux, or a kernel that does not expose the LSM list, simply
//! reports nothing.

use std::path::Path;

use crate::filesystem::Filesystem;

/// Where the kernel lists the Linux Security Modules in use, comma-separated.
const LSM_LIST: &str = "/sys/kernel/security/lsm";
/// The selinuxfs mount point. The directory alone proves nothing: it can be
/// there with nothing mounted on it.
const SELINUX_FS: &str = "/sys/fs/selinux";
/// The mount table of this process's mount namespace, where a mounted
/// selinuxfs shows with its filesystem type, wherever it is mounted.
const SELF_MOUNTS: &str = "/proc/self/mounts";
/// The filesystem type of the SELinux kernel interface.
const SELINUXFS_TYPE: &str = "selinuxfs";
/// The runtime enforce flag: `1` enforcing, `0` permissive.
const SELINUX_ENFORCE: &str = "/sys/fs/selinux/enforce";
/// The boot-time SELinux configuration.
const SELINUX_CONFIG: &str = "/etc/selinux/config";

/// SELinux's runtime enforcement state, as read from `/sys/fs/selinux/enforce`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelinuxMode {
    /// Denials are enforced.
    Enforcing,
    /// Denials are logged but not enforced.
    Permissive,
}

/// Whether the kernel's SELinux interface, selinuxfs, is mounted.
///
/// Read from the mount table (`/proc/self/mounts`), not from the existence of
/// `/sys/fs/selinux`: that directory can exist with nothing mounted on it, and
/// a selinuxfs mounted elsewhere still shows in the table by its type. The
/// table is also a plain file, so the fact reads through the [`Filesystem`]
/// trait like every other host fact, where a `statfs` of the mount point would
/// need a call of its own and would look at that one path only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selinuxfs {
    /// The mount table lists a selinuxfs: SELinux runs in this kernel.
    Mounted,
    /// The mount table could be read and lists none: SELinux does not run, so
    /// nothing reads a label, whatever `/etc/selinux/config` says.
    NotMounted,
    /// The mount table could not be read, so nothing rules SELinux out.
    Unknown,
}

/// What NAILS knows about a host's SELinux.
///
/// Built only when SELinux looks present (selinuxfs is mounted,
/// `/sys/fs/selinux` exists, or `/etc/selinux/config` names a mode or a
/// policy). Each field is independently optional, so a host that mounts
/// selinuxfs but has no config file, or vice versa, still reports what it can.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelinuxStatus {
    /// Whether selinuxfs is mounted, from the mount table.
    pub selinuxfs: Selinuxfs,
    /// The runtime enforcement state, when the enforce flag could be read.
    pub enforce: Option<SelinuxMode>,
    /// `SELINUX=` from `/etc/selinux/config` (`enforcing`, `permissive`,
    /// `disabled`), lowercased.
    pub config_mode: Option<String>,
    /// `SELINUXTYPE=` from `/etc/selinux/config` (`targeted`, `mls`, `minimum`),
    /// lowercased.
    pub config_policy: Option<String>,
}

/// The Linux Security Modules the kernel reports as active, in kernel order.
///
/// Empty when the kernel does not expose the list (an older kernel, or
/// `securityfs` not mounted).
pub(crate) fn read_lsms<F: Filesystem>(fs: &F) -> Vec<String> {
    let Some(raw) = read_optional(fs, LSM_LIST) else {
        return Vec::new();
    };
    raw.trim()
        .split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(str::to_string)
        .collect()
}

/// The host's SELinux status, or `None` when SELinux is not present.
pub(crate) fn read_selinux<F: Filesystem>(fs: &F) -> Option<SelinuxStatus> {
    let selinuxfs = read_selinuxfs(fs);
    let fs_present =
        selinuxfs == Selinuxfs::Mounted || fs.path_exists(Path::new(SELINUX_FS)).unwrap_or(false);
    let enforce = read_optional(fs, SELINUX_ENFORCE).and_then(|raw| match raw.trim() {
        "1" => Some(SelinuxMode::Enforcing),
        "0" => Some(SelinuxMode::Permissive),
        _ => None,
    });
    let (config_mode, config_policy) = read_optional(fs, SELINUX_CONFIG)
        .as_deref()
        .map(parse_selinux_config)
        .unwrap_or((None, None));

    if !fs_present && config_mode.is_none() && config_policy.is_none() {
        return None;
    }
    Some(SelinuxStatus {
        selinuxfs,
        enforce,
        config_mode,
        config_policy,
    })
}

/// Whether the mount table lists a selinuxfs. A table that cannot be read is
/// [`Selinuxfs::Unknown`], never [`Selinuxfs::NotMounted`].
fn read_selinuxfs<F: Filesystem>(fs: &F) -> Selinuxfs {
    match read_optional(fs, SELF_MOUNTS) {
        Some(table) if lists_selinuxfs(&table) => Selinuxfs::Mounted,
        Some(_) => Selinuxfs::NotMounted,
        None => Selinuxfs::Unknown,
    }
}

/// Whether a `/proc/self/mounts` table holds a line whose filesystem type, the
/// third field, is selinuxfs. The kernel escapes blanks in the fields before
/// it, so splitting on whitespace finds the type.
fn lists_selinuxfs(table: &str) -> bool {
    table
        .lines()
        .any(|line| line.split_whitespace().nth(2) == Some(SELINUXFS_TYPE))
}

/// Parse `SELINUX=` and `SELINUXTYPE=` out of `/etc/selinux/config`.
///
/// The file is `KEY=value` lines with `#` comments, like os-release but without
/// quoting. Unknown keys and malformed lines are skipped, so the parser is total
/// on any bytes a decoy's config file could hold.
fn parse_selinux_config(content: &str) -> (Option<String>, Option<String>) {
    let mut mode = None;
    let mut policy = None;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim().to_ascii_lowercase();
        match key.trim() {
            "SELINUX" => mode = Some(value),
            "SELINUXTYPE" => policy = Some(value),
            _ => {}
        }
    }
    (mode, policy)
}

/// Read a file, treating "absent/unreadable" as `None`: these facts are optional.
fn read_optional<F: Filesystem>(fs: &F, path: &str) -> Option<String> {
    fs.read_file_content(Path::new(path)).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::{MockFilesystem, PathKind};

    #[test]
    fn lsms_are_split_and_trimmed() {
        let fs = MockFilesystem::new();
        fs.mock_set_file_content(LSM_LIST, "lockdown,capability,landlock,yama,selinux,bpf\n");
        assert_eq!(
            read_lsms(&fs),
            [
                "lockdown",
                "capability",
                "landlock",
                "yama",
                "selinux",
                "bpf"
            ]
        );
    }

    #[test]
    fn lsms_are_empty_when_the_kernel_lists_none() {
        assert!(read_lsms(&MockFilesystem::new()).is_empty());
        // A stray trailing comma or blank entry does not produce an empty token.
        let fs = MockFilesystem::new();
        fs.mock_set_file_content(LSM_LIST, "capability,,apparmor,\n");
        assert_eq!(read_lsms(&fs), ["capability", "apparmor"]);
    }

    /// A mount table without selinuxfs.
    const PLAIN_MOUNTS: &str = "sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\n\
                                proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n";
    /// A mount table with selinuxfs at its usual place.
    const SELINUX_MOUNTS: &str = "sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\n\
                                  selinuxfs /sys/fs/selinux selinuxfs rw,nosuid,noexec,relatime 0 0\n";

    #[test]
    fn selinux_is_absent_without_a_filesystem_or_config() {
        assert_eq!(read_selinux(&MockFilesystem::new()), None);
        let fs = MockFilesystem::new();
        fs.mock_set_file_content(SELF_MOUNTS, PLAIN_MOUNTS);
        assert_eq!(read_selinux(&fs), None);
    }

    #[test]
    fn a_mounted_selinuxfs_is_read_from_the_mount_table() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_type(SELINUX_FS, PathKind::Dir);
        fs.mock_set_file_content(SELF_MOUNTS, SELINUX_MOUNTS);
        let status = read_selinux(&fs).expect("selinuxfs is mounted");
        assert_eq!(status.selinuxfs, Selinuxfs::Mounted);
    }

    #[test]
    fn a_selinuxfs_mounted_elsewhere_is_still_mounted() {
        // An old layout mounts it at /selinux, with no /sys/fs/selinux at all.
        let fs = MockFilesystem::new();
        fs.mock_set_file_content(SELF_MOUNTS, "none /selinux selinuxfs rw,relatime 0 0\n");
        let status = read_selinux(&fs).expect("the table lists selinuxfs");
        assert_eq!(status.selinuxfs, Selinuxfs::Mounted);
    }

    #[test]
    fn an_empty_mount_point_is_not_a_mounted_selinuxfs() {
        // The directory exists, but nothing is mounted on it.
        let fs = MockFilesystem::new();
        fs.mock_set_path_type(SELINUX_FS, PathKind::Dir);
        fs.mock_set_file_content(SELF_MOUNTS, PLAIN_MOUNTS);
        let status = read_selinux(&fs).expect("the directory marks SELinux present");
        assert_eq!(status.selinuxfs, Selinuxfs::NotMounted);
    }

    #[test]
    fn a_config_on_a_host_without_selinuxfs_is_not_mounted() {
        // A Debian host that once installed the SELinux packages.
        let fs = MockFilesystem::new();
        fs.mock_set_file_content(SELF_MOUNTS, PLAIN_MOUNTS);
        fs.mock_set_file_content(SELINUX_CONFIG, "SELINUX=permissive\nSELINUXTYPE=default\n");
        let status = read_selinux(&fs).expect("the config file marks SELinux present");
        assert_eq!(status.selinuxfs, Selinuxfs::NotMounted);
        assert_eq!(status.config_mode.as_deref(), Some("permissive"));
    }

    #[test]
    fn an_unreadable_mount_table_is_unknown_not_unmounted() {
        let fs = MockFilesystem::new();
        fs.mock_set_file_content(SELINUX_CONFIG, "SELINUX=disabled\n");
        let status = read_selinux(&fs).expect("the config file marks SELinux present");
        assert_eq!(status.selinuxfs, Selinuxfs::Unknown);
    }

    #[test]
    fn the_type_is_the_third_field_of_a_line() {
        assert!(lists_selinuxfs(SELINUX_MOUNTS));
        assert!(!lists_selinuxfs(PLAIN_MOUNTS));
        // A mount point or a source named selinuxfs is not the type.
        assert!(!lists_selinuxfs("selinuxfs /mnt/selinuxfs ext4 rw 0 0\n"));
        assert!(!lists_selinuxfs(""));
    }

    #[test]
    fn enforcing_selinux_reads_both_runtime_and_config() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_type(SELINUX_FS, PathKind::Dir);
        fs.mock_set_file_content(SELINUX_ENFORCE, "1\n");
        fs.mock_set_file_content(
            SELINUX_CONFIG,
            "# comment\nSELINUX=enforcing\nSELINUXTYPE=targeted\n",
        );
        let status = read_selinux(&fs).expect("SELinux is present");
        assert_eq!(status.enforce, Some(SelinuxMode::Enforcing));
        assert_eq!(status.config_mode.as_deref(), Some("enforcing"));
        assert_eq!(status.config_policy.as_deref(), Some("targeted"));
    }

    #[test]
    fn permissive_runtime_is_read() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_type(SELINUX_FS, PathKind::Dir);
        fs.mock_set_file_content(SELINUX_ENFORCE, "0");
        let status = read_selinux(&fs).expect("selinuxfs is mounted");
        assert_eq!(status.enforce, Some(SelinuxMode::Permissive));
        assert_eq!(status.config_mode, None);
    }

    #[test]
    fn a_config_without_a_mounted_filesystem_is_still_reported() {
        // SELinux disabled at boot: no selinuxfs, but the config survives.
        let fs = MockFilesystem::new();
        fs.mock_set_file_content(SELINUX_CONFIG, "SELINUX=disabled\nSELINUXTYPE=mls\n");
        let status = read_selinux(&fs).expect("the config file marks SELinux present");
        assert_eq!(status.enforce, None);
        assert_eq!(status.config_mode.as_deref(), Some("disabled"));
        assert_eq!(status.config_policy.as_deref(), Some("mls"));
    }

    #[test]
    fn an_unreadable_enforce_flag_is_ignored() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_type(SELINUX_FS, PathKind::Dir);
        fs.mock_set_file_content(SELINUX_ENFORCE, "garbage");
        let status = read_selinux(&fs).expect("selinuxfs is mounted");
        assert_eq!(status.enforce, None);
    }

    #[test]
    fn config_values_are_lowercased() {
        assert_eq!(
            parse_selinux_config("SELINUX=Enforcing\nSELINUXTYPE=Targeted\n"),
            (Some("enforcing".to_string()), Some("targeted".to_string()))
        );
    }

    proptest::proptest! {
        /// The config parser is total: no byte sequence makes it panic.
        #[test]
        fn config_parse_never_panics(text in "\\PC{0,400}") {
            let _ = parse_selinux_config(&text);
        }
    }
}
