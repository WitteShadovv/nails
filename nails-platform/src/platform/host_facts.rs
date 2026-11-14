// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Host security facts: the active Linux Security Modules and the SELinux mode.
//!
//! These are read once by [`detect`](super::detect) and carried on the
//! [`HostProfile`](super::HostProfile), so the parts of NAILS that care about a
//! host's mandatory-access-control layer (the window, and the Fedora label work)
//! read them from one place rather than probing the kernel themselves. The
//! `lsm-status` check reads them again with the same functions when it runs,
//! together with the label of the process ([`read_process_label`]). Every
//! read goes through the [`Filesystem`] trait and tolerates absence: a host
//! without SELinux, or a kernel that does not expose the LSM list, simply
//! reports nothing. None of them uses libselinux: `/etc/selinux/config` is
//! read the way libselinux reads it, which is how systemd's policy load at
//! boot reads it.

use std::path::Path;

use crate::filesystem::Filesystem;

/// Where the kernel lists the Linux Security Modules in use, comma-separated.
pub const LSM_LIST: &str = "/sys/kernel/security/lsm";
/// Where the kernel shows the label of the process that reads it.
pub const PROCESS_LABEL: &str = "/proc/self/attr/current";
/// The selinuxfs mount point. The directory alone proves nothing: it can be
/// there with nothing mounted on it.
const SELINUX_FS: &str = "/sys/fs/selinux";
/// The mount table of this process's mount namespace, where a mounted
/// selinuxfs shows with its filesystem type, wherever it is mounted.
const SELF_MOUNTS: &str = "/proc/self/mounts";
/// The filesystem type of the SELinux kernel interface.
const SELINUXFS_TYPE: &str = "selinuxfs";
/// The runtime enforce flag: `1` enforcing, `0` permissive.
pub const SELINUX_ENFORCE: &str = "/sys/fs/selinux/enforce";
/// The boot-time SELinux configuration.
pub const SELINUX_CONFIG: &str = "/etc/selinux/config";
/// The most `selinux_getenforcemode` reads of the configuration in one piece:
/// it reads with `fgets` into a buffer of one page (4,096 bytes on x86_64),
/// which holds this many bytes and the NUL.
const ENFORCEMODE_PIECE: usize = 4095;

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
    /// The mount table could be read and lists none: no policy shows, whatever
    /// `/etc/selinux/config` says. The kernel may still have SELinux on,
    /// without a policy, as `SELINUX=disabled` leaves a kernel that started
    /// SELinux at boot, or with selinuxfs unmounted after a policy was
    /// loaded: the kernel's list of LSMs tells.
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
    /// The mode `SELINUX=` sets in `/etc/selinux/config`, as libselinux's
    /// `selinux_getenforcemode` reads it: `enforcing`, `permissive` or
    /// `disabled`.
    pub config_mode: Option<String>,
    /// The policy `SELINUXTYPE=` names in `/etc/selinux/config`, as libselinux's
    /// `init_selinux_config` reads it, with its case kept: it names the
    /// directory below `/etc/selinux` the policy is loaded from (`targeted`,
    /// `mls`, `minimum`, Debian's `default`).
    pub config_policy: Option<String>,
}

/// The Linux Security Modules the kernel reports as active, in kernel order.
///
/// Empty when the kernel does not expose the list (an older kernel, or
/// `securityfs` not mounted).
pub fn read_lsms<F: Filesystem>(fs: &F) -> Vec<String> {
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

/// The host's SELinux status, or `None` when SELinux is not present. A
/// `/sys/fs/selinux` whose lookup fails for another reason than that nothing
/// is there counts as there: SELinux may run, so the labels are required
/// unless the mount table shows no selinuxfs.
pub fn read_selinux<F: Filesystem>(fs: &F) -> Option<SelinuxStatus> {
    let selinuxfs = read_selinuxfs(fs);
    let fs_present = selinuxfs == Selinuxfs::Mounted
        || !matches!(fs.path_exists(Path::new(SELINUX_FS)), Ok(false));
    let enforce = read_optional(fs, SELINUX_ENFORCE).and_then(|raw| match raw.trim() {
        "1" => Some(SelinuxMode::Enforcing),
        "0" => Some(SelinuxMode::Permissive),
        _ => None,
    });
    let (config_mode, config_policy) = fs
        .read_file_bytes(Path::new(SELINUX_CONFIG))
        .ok()
        .map(|content| parse_selinux_config(&content))
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

/// What this process's `/proc/self/attr/current` holds, without the NUL or the
/// newline that ends it, or `None` where it cannot be read.
///
/// Where SELinux runs it is the SELinux context of the process
/// (`unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023`). Another LSM that
/// labels processes answers there otherwise, AppArmor with the name of a
/// profile or `unconfined`, and a kernel where none does refuses the read.
pub fn read_process_label<F: Filesystem>(fs: &F) -> Option<String> {
    let raw = read_optional(fs, PROCESS_LABEL)?;
    Some(raw.trim_end_matches(['\0', '\n']).to_string())
}

/// `SELINUX=` and `SELINUXTYPE=` of `/etc/selinux/config`, as libselinux reads
/// them: the mode as [`config_mode`] and the policy as [`config_policy`] read
/// them.
///
/// Both are total on any bytes a decoy's config file could hold.
fn parse_selinux_config(content: &[u8]) -> (Option<String>, Option<String>) {
    (
        config_mode(content).map(str::to_string),
        config_policy(content),
    )
}

/// The mode `SELINUX=` sets, read as libselinux's `selinux_getenforcemode`
/// reads it, which is what systemd's policy load at boot goes by.
///
/// The file is read in pieces, each up to and including a newline but never
/// longer than [`ENFORCEMODE_PIECE`] bytes, and as a C string, so a piece ends
/// at a NUL. The first piece that starts with `SELINUX=`, in that case and
/// with nothing before it, and whose value, after blanks, starts with
/// `enforcing`, `permissive` or `disabled` in any case sets the mode. A piece
/// with any other value is passed over, so a later one still counts.
fn config_mode(content: &[u8]) -> Option<&'static str> {
    const TAG: &[u8] = b"SELINUX=";
    let mut rest = content;
    while !rest.is_empty() {
        let line = rest
            .iter()
            .position(|&byte| byte == b'\n')
            .map_or(rest.len(), |at| at + 1);
        let (piece, after) = rest.split_at(line.min(ENFORCEMODE_PIECE));
        rest = after;
        let Some(value) = until_nul(piece).strip_prefix(TAG) else {
            continue;
        };
        let value = skip_c_space(value);
        let mode = ["enforcing", "permissive", "disabled"]
            .into_iter()
            .find(|mode| {
                value
                    .get(..mode.len())
                    .is_some_and(|start| start.eq_ignore_ascii_case(mode.as_bytes()))
            });
        if mode.is_some() {
            return mode;
        }
    }
    None
}

/// The policy `SELINUXTYPE=` names, read as libselinux's
/// `init_selinux_config` reads it, which is where the policy is loaded from at
/// boot (`/etc/selinux/<policy>`).
///
/// Each line, up to a newline and as a C string up to a NUL, after leading
/// blanks, that is no comment and starts with `SELINUXTYPE=` in any case names
/// the policy: the rest of the line after blanks, with trailing blanks and
/// control characters cut off but its first character kept, in its case. The
/// last such line wins. `None` where no line names one: libselinux then falls
/// back to a policy it was built with, which this reading does not guess.
fn config_policy(content: &[u8]) -> Option<String> {
    const TAG: &[u8] = b"SELINUXTYPE=";
    let mut policy = None;
    for line in content.split(|&byte| byte == b'\n') {
        let line = skip_c_space(until_nul(line));
        if line.first() == Some(&b'#')
            || !line
                .get(..TAG.len())
                .is_some_and(|key| key.eq_ignore_ascii_case(TAG))
        {
            continue;
        }
        let value = skip_c_space(&line[TAG.len()..]);
        let mut end = value.len();
        while end > 1 && (is_c_space(value[end - 1]) || value[end - 1].is_ascii_control()) {
            end -= 1;
        }
        policy = Some(String::from_utf8_lossy(&value[..end]).into_owned());
    }
    policy
}

/// `bytes` up to its first NUL, as C reads a string.
fn until_nul(bytes: &[u8]) -> &[u8] {
    bytes
        .iter()
        .position(|&byte| byte == 0)
        .map_or(bytes, |at| &bytes[..at])
}

/// `bytes` after the blanks it starts with, as C's `isspace` tells them.
fn skip_c_space(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|&byte| !is_c_space(byte))
        .unwrap_or(bytes.len());
    &bytes[start..]
}

/// Whether C's `isspace` takes `byte` for a blank in the C locale: Rust's
/// ASCII whitespace and the vertical tab.
fn is_c_space(byte: u8) -> bool {
    byte.is_ascii_whitespace() || byte == b'\x0b'
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

    /// A `/sys/fs/selinux` NAILS cannot look up may be there, so SELinux may
    /// run: with a mount table that cannot be read, nothing rules it out and
    /// the labels are required, where SELinux used to count as absent.
    #[test]
    fn a_selinux_directory_that_cannot_be_looked_up_counts_as_there() {
        let fs = MockFilesystem::new();
        fs.mock_set_lookup_error(SELINUX_FS, std::io::ErrorKind::PermissionDenied);
        let status = read_selinux(&fs).expect("SELinux may be present");
        assert_eq!(status.selinuxfs, Selinuxfs::Unknown);
        // A mount table that lists no selinuxfs says SELinux does not run.
        fs.mock_set_file_content(SELF_MOUNTS, PLAIN_MOUNTS);
        let status = read_selinux(&fs).expect("SELinux may be present");
        assert_eq!(status.selinuxfs, Selinuxfs::NotMounted);
        // Nothing there is no SELinux, as before.
        let fs = MockFilesystem::new();
        fs.mock_set_lookup_error(SELINUX_FS, std::io::ErrorKind::NotFound);
        assert_eq!(read_selinux(&fs), None);
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
    fn the_mode_is_lowercased_and_the_policy_keeps_its_case() {
        // libselinux matches the mode in any case, and loads the policy from
        // the directory the value names, which /etc/selinux/Targeted is not.
        assert_eq!(
            parse_selinux_config(b"SELINUX=Enforcing\nSELINUXTYPE=Targeted\n"),
            (Some("enforcing".to_string()), Some("Targeted".to_string()))
        );
    }

    #[test]
    fn the_mode_is_the_first_line_that_starts_with_the_tag_and_a_mode() {
        for (config, mode) in [
            ("SELINUX=enforcing\n", Some("enforcing")),
            ("SELINUX=  \tpermissive\n", Some("permissive")),
            ("SELINUX=DISABLED", Some("disabled")),
            // The value only has to start with a mode.
            (
                "SELINUX=enforcing # set by the installer\n",
                Some("enforcing"),
            ),
            ("SELINUX=permissively\n", Some("permissive")),
            // The first line with a mode wins; one without is passed over.
            (
                "SELINUX=permissive\nSELINUX=enforcing\n",
                Some("permissive"),
            ),
            ("SELINUX=strict\nSELINUX=enforcing\n", Some("enforcing")),
            // The tag must start the line, in its case.
            (" SELINUX=enforcing\n", None),
            ("selinux=enforcing\n", None),
            ("SELINUX = enforcing\n", None),
            ("#SELINUX=enforcing\n", None),
            ("SELINUXTYPE=enforcing\n", None),
            ("SELINUX=\n", None),
            ("SELINUX=enforc\n", None),
            // A NUL ends the line where C reads it.
            ("SELINUX=\0enforcing\n", None),
            ("SELINUX=enforcing\0x\n", Some("enforcing")),
            ("", None),
        ] {
            assert_eq!(config_mode(config.as_bytes()), mode, "{config:?}");
        }
    }

    #[test]
    fn the_mode_is_read_in_the_pieces_fgets_reads() {
        // A line longer than one piece goes on in the next piece, which counts
        // as a line of its own when it starts with the tag.
        let long = format!("#{}SELINUX=permissive\n", "x".repeat(ENFORCEMODE_PIECE - 1));
        assert_eq!(config_mode(long.as_bytes()), Some("permissive"));
        // One byte shorter, and the tag stays inside the first piece.
        let fits = format!("#{}SELINUX=permissive\n", "x".repeat(ENFORCEMODE_PIECE - 2));
        assert_eq!(config_mode(fits.as_bytes()), None);
        // A line that ends exactly at the end of a piece starts the next one
        // with the following line.
        let exact = format!(
            "#{}\nSELINUX=enforcing\n",
            "x".repeat(ENFORCEMODE_PIECE - 2)
        );
        assert_eq!(config_mode(exact.as_bytes()), Some("enforcing"));
    }

    #[test]
    fn the_policy_is_the_last_line_that_names_one() {
        for (config, policy) in [
            ("SELINUXTYPE=targeted\n", Some("targeted")),
            // The tag in any case, after blanks; the value after blanks, with
            // trailing blanks and control characters cut off.
            ("  selinuxtype=targeted\n", Some("targeted")),
            ("\x0bSELINUXTYPE=\t mls \r\n", Some("mls")),
            ("SELINUXTYPE=targeted\x01\x7f\n", Some("targeted")),
            // The last line wins.
            ("SELINUXTYPE=mls\nSELINUXTYPE=targeted\n", Some("targeted")),
            ("SELINUXTYPE=targeted\nSELINUXTYPE=mls\n", Some("mls")),
            // A blank before the = is no tag, and a comment is none.
            ("SELINUXTYPE =mls\n", None),
            ("# SELINUXTYPE=mls\n", None),
            ("SELINUXTYPE_EXTRA=mls\n", None),
            // An empty value names the empty policy, and the first character
            // of the value is kept even when it is a control character.
            ("SELINUXTYPE=\n", Some("")),
            ("SELINUXTYPE=\x01\n", Some("\x01")),
            // A NUL ends the line where C reads it.
            ("SELINUXTYPE=mls\0targeted\n", Some("mls")),
            ("SELINUX\0TYPE=mls\n", None),
            ("", None),
        ] {
            assert_eq!(
                config_policy(config.as_bytes()).as_deref(),
                policy,
                "{config:?}"
            );
        }
    }

    #[test]
    fn a_config_that_is_no_utf8_is_still_read() {
        let fs = MockFilesystem::new();
        fs.mock_set_file_bytes(
            SELINUX_CONFIG,
            b"# \xe9t\xe9\nSELINUX=enforcing\nSELINUXTYPE=targeted\n",
        );
        let status = read_selinux(&fs).expect("the config file marks SELinux present");
        assert_eq!(status.config_mode.as_deref(), Some("enforcing"));
        assert_eq!(status.config_policy.as_deref(), Some("targeted"));
    }

    #[test]
    fn the_process_label_is_read_without_its_nul_or_newline() {
        let fs = MockFilesystem::new();
        assert_eq!(read_process_label(&fs), None);
        fs.mock_set_file_content(
            PROCESS_LABEL,
            "unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023\0",
        );
        assert_eq!(
            read_process_label(&fs).as_deref(),
            Some("unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023")
        );
        // AppArmor's answer for a process without a profile.
        fs.mock_set_file_content(PROCESS_LABEL, "unconfined\n");
        assert_eq!(read_process_label(&fs).as_deref(), Some("unconfined"));
    }

    proptest::proptest! {
        /// The config parser is total: no byte sequence makes it panic.
        #[test]
        fn config_parse_never_panics(
            bytes in proptest::collection::vec(proptest::num::u8::ANY, 0..400)
        ) {
            let _ = parse_selinux_config(&bytes);
        }

        /// The policy names no newline or NUL, and ends in no blank or control
        /// character unless that is all it holds.
        #[test]
        fn the_policy_ends_in_neither_a_blank_nor_a_control_character(
            text in r"[ \t\x0B\x01a-zA-Z=_#\n\x00]{0,80}"
        ) {
            if let Some(policy) = config_policy(text.as_bytes()) {
                proptest::prop_assert!(!policy.contains(['\n', '\0']), "{policy:?}");
                if policy.chars().count() > 1 {
                    let last = policy.chars().last().unwrap();
                    proptest::prop_assert!(
                        !last.is_ascii_whitespace() && !last.is_ascii_control(),
                        "{policy:?}"
                    );
                }
            }
        }
    }
}
