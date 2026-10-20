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
/// The selinuxfs mount point; present only when SELinux is active.
const SELINUX_FS: &str = "/sys/fs/selinux";
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

/// What NAILS knows about a host's SELinux.
///
/// Built only when SELinux looks present (selinuxfs is mounted or
/// `/etc/selinux/config` exists). Each field is independently optional, so a
/// host that mounts selinuxfs but has no config file, or vice versa, still
/// reports what it can.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelinuxStatus {
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
    let fs_present = fs.path_exists(Path::new(SELINUX_FS)).unwrap_or(false);
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
        enforce,
        config_mode,
        config_policy,
    })
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

    #[test]
    fn selinux_is_absent_without_a_filesystem_or_config() {
        assert_eq!(read_selinux(&MockFilesystem::new()), None);
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
