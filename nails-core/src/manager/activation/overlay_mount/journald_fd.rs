// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Judging whether systemd-journald's open journal fds resolve into the
//! `/var` overlay after the restart, so a hidden session's records cannot
//! leak onto the decoy journal.

use crate::process::mount_refs::parse_fdinfo_mnt_id;
use std::path::{Path, PathBuf};

/// Outcome of inspecting systemd-journald's open journal file descriptors after
/// the `/var` overlay is mounted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JournaldFdCheck {
    /// Every persistent-journal fd journald holds is backed by the overlay, so
    /// the hidden session's records land on the overlay upper, not the decoy.
    InOverlay,
    /// journald still holds a persistent-journal fd on the base `/var`: records
    /// are leaking to the decoy journal, so activation must roll back.
    NotInOverlay,
    /// journald could not be inspected (not running, no persistent-journal fds, or
    /// `/proc` unreadable). Tolerated rather than treated as a leak.
    Indeterminate,
}

// In a test or runtime-safety context, force the fd check to a given outcome.
// Host inspection is skipped there, so a test that needs to exercise the re-home
// rollback path pins the result to `JournaldFdCheck::NotInOverlay`.
#[cfg(test)]
thread_local! {
    static FORCED_JOURNALD_FD_CHECK: std::cell::Cell<Option<JournaldFdCheck>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(test)]
pub(crate) fn set_forced_journald_fd_check(value: Option<JournaldFdCheck>) {
    FORCED_JOURNALD_FD_CHECK.with(|cell| cell.set(value));
}

/// Decide whether journald's journal fds resolve into the `/var` overlay.
///
/// Returns the posture and, when it is [`JournaldFdCheck::NotInOverlay`], a human
/// diagnostic naming every offending fd. In a test or runtime-safety context no
/// host is touched: the check records that it ran and returns the forced outcome
/// (if a test pinned one) or [`JournaldFdCheck::Indeterminate`]. On a real host it
/// inspects journald's open file descriptors against `upper_dir`, the `/var`
/// overlay's upper directory.
pub(super) fn journald_fds_resolve_into_overlay(
    upper_dir: &Path,
) -> (JournaldFdCheck, Option<String>) {
    if crate::runtime_safety::should_skip_host_interaction() {
        #[cfg(test)]
        {
            crate::manager::helpers::record_service_action("verify-journald-fds");
            if let Some(forced) = FORCED_JOURNALD_FD_CHECK.with(std::cell::Cell::get) {
                return (forced, None);
            }
        }
        let _ = upper_dir;
        return (JournaldFdCheck::Indeterminate, None);
    }

    inspect_journald_journal_fds(upper_dir)
}

/// A writable persistent-journal fd journald holds, with where it resolves.
///
/// `mnt_id` is the mount the fd was opened on (from `/proc/<pid>/fdinfo/<n>`), the
/// robust signal for whether the fd lives on the `/var` overlay; `dev` is the
/// backing device (from stat'ing the fd), carried only for the diagnostic.
#[derive(Debug, Clone)]
struct JournalFdSite {
    target: PathBuf,
    mnt_id: Option<i32>,
    dev: Option<u64>,
}

/// Inspect systemd-journald's open persistent-journal fds on a real host.
///
/// Finds the system journald (see [`find_journald_pid`]), resolves the mount id of the `/var` overlay
/// from journald's *own* mount namespace (`/proc/<pid>/mountinfo`), then compares
/// the mount id of each writable `/var/log/journal/...` fd (from
/// `/proc/<pid>/fdinfo/<n>`) against it. A fd journald opened under the overlay
/// carries the overlay's mount id; a fd still on the decoy's base `/var` carries a
/// different one and is a leak.
///
/// The mount id is used rather than `st_dev`: overlayfs without `xino` reports an
/// anonymous per-superblock device for its files, which does not equal the upper
/// layer's real device, so a device comparison wrongly flagged correctly-overlaid
/// journal fds as leaks. A fd's mount id, by contrast, is exactly the overlay
/// mount's id, read from the same namespace the fd lives in.
fn inspect_journald_journal_fds(upper_dir: &Path) -> (JournaldFdCheck, Option<String>) {
    use std::os::unix::fs::MetadataExt;

    let Some(pid) = find_journald_pid() else {
        return (JournaldFdCheck::Indeterminate, None);
    };

    // The /var overlay's mount id, read from journald's namespace and matched on
    // both the mount point and the upper dir so a foreign overlay on /var cannot be
    // mistaken for ours. Without it there is nothing to compare against, so the
    // posture is indeterminate rather than a false leak.
    let Some(overlay_mount_id) = journald_var_overlay_mount_id(pid, upper_dir) else {
        return (JournaldFdCheck::Indeterminate, None);
    };

    let fd_dir = format!("/proc/{pid}/fd");
    let entries = match std::fs::read_dir(&fd_dir) {
        Ok(entries) => entries,
        Err(_) => return (JournaldFdCheck::Indeterminate, None),
    };

    let mut writable = Vec::new();
    for entry in entries.flatten() {
        let fd_path = entry.path();
        let Ok(target) = std::fs::read_link(&fd_path) else {
            continue;
        };
        // Only persistent-journal fds matter: a volatile /run/log/journal fd is on
        // tmpfs and never reaches the decoy disk.
        if !target.to_string_lossy().starts_with("/var/log/journal/") {
            continue;
        }
        let Some(fd_name) = fd_path.file_name() else {
            continue;
        };
        let Ok(fdinfo) =
            std::fs::read_to_string(format!("/proc/{pid}/fdinfo/{}", fd_name.to_string_lossy()))
        else {
            continue;
        };
        // Only a *writable* fd can leak hidden-session records onto the decoy. On a
        // persistent-journal decoy journald keeps the pre-existing journals open
        // read-only; those stay on the base /var but are the decoy's own history,
        // not a leak. The active journal journald writes to is what must land on the
        // overlay, so judge the posture by the writable fds alone.
        if !fdinfo_is_writable(&fdinfo) {
            continue;
        }
        writable.push(JournalFdSite {
            target,
            mnt_id: parse_fdinfo_mnt_id(&fdinfo),
            dev: std::fs::metadata(&fd_path).ok().map(|m| m.dev()),
        });
    }

    classify_journald_fd_mounts(overlay_mount_id, &writable)
}

/// The mount id of the `/var` overlay NAILS mounted, from journald's namespace.
///
/// Reads `/proc/<pid>/mountinfo` (journald's own view, so the id matches what its
/// fds carry) and finds the overlay mounted at `/var` whose `upperdir` is
/// `upper_dir`. Returns `None` when no such overlay is visible, which the caller
/// treats as indeterminate rather than a leak.
fn journald_var_overlay_mount_id(pid: u32, upper_dir: &Path) -> Option<i32> {
    let content = std::fs::read_to_string(format!("/proc/{pid}/mountinfo")).ok()?;
    let want_upper = std::fs::canonicalize(upper_dir).unwrap_or_else(|_| upper_dir.to_path_buf());
    crate::filesystem::parse_mountinfo(&content)
        .into_iter()
        .filter(|entry| entry.fstype == "overlay" && entry.mount_point == Path::new("/var"))
        .find_map(|entry| {
            let upper = crate::filesystem::parse_overlay_opts(&entry.super_opts).upperdir?;
            let upper_canon = std::fs::canonicalize(&upper).unwrap_or(upper);
            (upper_canon == want_upper).then_some(entry.mount_id)
        })
}

/// Classify journald's writable persistent-journal fds against the `/var` overlay's
/// mount id, returning a diagnostic for any offender.
///
/// With no writable persistent fd, or none whose mount id could be read, the
/// posture is [`JournaldFdCheck::Indeterminate`] (journald may not have reopened
/// its journal yet, or the kernel did not expose `mnt_id`). Otherwise every fd with
/// a known mount id must carry the overlay's; one that does not is still writing to
/// the decoy's base `/var` and is a leak ([`JournaldFdCheck::NotInOverlay`]). An fd
/// whose mount id could not be read is left out of the verdict rather than flagged.
fn classify_journald_fd_mounts(
    overlay_mount_id: i32,
    writable: &[JournalFdSite],
) -> (JournaldFdCheck, Option<String>) {
    if writable.is_empty() || writable.iter().all(|fd| fd.mnt_id.is_none()) {
        return (JournaldFdCheck::Indeterminate, None);
    }

    let offending: Vec<&JournalFdSite> = writable
        .iter()
        .filter(|fd| matches!(fd.mnt_id, Some(id) if id != overlay_mount_id))
        .collect();

    if offending.is_empty() {
        return (JournaldFdCheck::InOverlay, None);
    }

    let detail = offending
        .iter()
        .map(|fd| {
            let mnt = fd
                .mnt_id
                .map_or_else(|| "unknown".to_string(), |id| id.to_string());
            let dev = fd
                .dev
                .map_or_else(|| "unknown".to_string(), |d| d.to_string());
            format!("{} (mount id {mnt}, device {dev})", fd.target.display())
        })
        .collect::<Vec<_>>()
        .join("; ");
    (
        JournaldFdCheck::NotInOverlay,
        Some(format!(
            "offending journal fds: {detail}; expected /var overlay mount id {overlay_mount_id}"
        )),
    )
}

/// Whether a `/proc/<pid>/fdinfo/<n>` body describes a writable fd: the octal
/// `flags:` line has a non-zero access mode (`O_WRONLY`/`O_RDWR`) or `O_APPEND`.
/// A missing or unparsable `flags:` reads as not-writable, so an unreadable fd is
/// never treated as a leak that would roll the activation back.
fn fdinfo_is_writable(content: &str) -> bool {
    crate::process::detection::parse_fdinfo_flags(content)
        .is_some_and(|flags| flags & 0o3 != 0 || flags & 0o2000 != 0)
}

/// The pid of the system journald: the `MainPID` systemd reports for
/// `systemd-journald.service`.
///
/// Matching on the process name alone picked whichever `systemd-journal` came
/// first in `/proc` — a journald of a container, or of a nested systemd, in
/// another mount namespace whose fds say nothing about the host's `/var`. When
/// `systemctl` cannot answer, the fallback still requires the name, PID 1 as the
/// parent and this process's own mount namespace.
fn find_journald_pid() -> Option<u32> {
    use crate::process::{ProcessCommand, ProcessRunner, RealProcessRunner};
    let command = ProcessCommand::tool("systemctl")
        .args([
            "show",
            "-p",
            "MainPID",
            "--value",
            "systemd-journald.service",
        ])
        .deadline(crate::process::run::SYSTEMCTL_PROBE_BUDGET);
    if let Ok((true, stdout, _)) = RealProcessRunner.run_text(&command)
        && let Some(pid) = parse_main_pid(&stdout)
    {
        return Some(pid);
    }
    let entries = std::fs::read_dir("/proc").ok()?;
    entries
        .flatten()
        .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
        .find(|&pid| is_host_journald(pid))
}

/// The pid in `systemctl show -p MainPID --value` output; `None` for `0` (the
/// unit is not running) or anything unparsable.
fn parse_main_pid(stdout: &str) -> Option<u32> {
    stdout.trim().parse::<u32>().ok().filter(|pid| *pid != 0)
}

/// Whether `pid` is a journald started by PID 1 in this mount namespace.
fn is_host_journald(pid: u32) -> bool {
    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
    comm.trim_end() == "systemd-journal"
        && crate::process::identity::parent_pid(pid) == Some(1)
        && crate::process::mount_refs::same_mount_namespace(pid)
}

#[cfg(test)]
mod fdinfo_tests {
    use super::{
        JournalFdSite, JournaldFdCheck, classify_journald_fd_mounts, fdinfo_is_writable,
        parse_fdinfo_mnt_id, parse_main_pid,
    };
    use std::path::PathBuf;

    const OVERLAY_MNT: i32 = 42;
    const DECOY_MNT: i32 = 7;

    fn fd(target: &str, mnt_id: Option<i32>) -> JournalFdSite {
        JournalFdSite {
            target: PathBuf::from(target),
            mnt_id,
            dev: None,
        }
    }

    #[test]
    fn journald_fds_judged_against_the_overlay_mount_id() {
        // No writable persistent fd yet: journald may not have reopened its
        // journal, so the posture is indeterminate rather than a leak.
        assert_eq!(
            classify_journald_fd_mounts(OVERLAY_MNT, &[]).0,
            JournaldFdCheck::Indeterminate
        );
        // Writable fds present but none exposed a mount id (older kernel): nothing
        // to compare, so indeterminate rather than a false leak.
        assert_eq!(
            classify_journald_fd_mounts(
                OVERLAY_MNT,
                &[fd("/var/log/journal/m/system.journal", None)]
            )
            .0,
            JournaldFdCheck::Indeterminate
        );
        // The re-homed journal fd carries the overlay's mount id, so journald writes
        // under the overlay. This is the regression: the device of such a fd differs
        // from the upper layer's real device (overlayfs reports an anonymous dev),
        // but its mount id is exactly the overlay's.
        assert_eq!(
            classify_journald_fd_mounts(
                OVERLAY_MNT,
                &[fd("/var/log/journal/m/system.journal", Some(OVERLAY_MNT))]
            )
            .0,
            JournaldFdCheck::InOverlay
        );
        // A writable persistent fd still on the decoy's base `/var` carries a
        // different mount id: a genuine leak that must roll the activation back, with
        // a diagnostic naming the offending fd and the expected mount id.
        let (check, diagnostic) = classify_journald_fd_mounts(
            OVERLAY_MNT,
            &[fd("/var/log/journal/m/system.journal", Some(DECOY_MNT))],
        );
        assert_eq!(check, JournaldFdCheck::NotInOverlay);
        let diagnostic = diagnostic.expect("a leak must carry a diagnostic");
        assert!(diagnostic.contains("system.journal"), "{diagnostic}");
        assert!(diagnostic.contains("mount id 7"), "{diagnostic}");
        assert!(diagnostic.contains("mount id 42"), "{diagnostic}");
        // A mix of a correctly-overlaid fd and a leaking one is still a leak.
        assert_eq!(
            classify_journald_fd_mounts(
                OVERLAY_MNT,
                &[
                    fd("/var/log/journal/m/system.journal", Some(OVERLAY_MNT)),
                    fd("/var/log/journal/m/user-1000.journal", Some(DECOY_MNT)),
                ]
            )
            .0,
            JournaldFdCheck::NotInOverlay
        );
        // An unreadable mount id alongside a correctly-overlaid fd is tolerated.
        assert_eq!(
            classify_journald_fd_mounts(
                OVERLAY_MNT,
                &[
                    fd("/var/log/journal/m/system.journal", Some(OVERLAY_MNT)),
                    fd("/var/log/journal/m/user-1000.journal", None),
                ]
            )
            .0,
            JournaldFdCheck::InOverlay
        );
    }

    #[test]
    fn main_pid_is_parsed_and_zero_means_not_running() {
        assert_eq!(parse_main_pid("412\n"), Some(412));
        assert_eq!(parse_main_pid("0\n"), None);
        assert_eq!(parse_main_pid(""), None);
        assert_eq!(parse_main_pid("n/a"), None);
    }

    #[test]
    fn mnt_id_is_parsed_from_fdinfo() {
        assert_eq!(
            parse_fdinfo_mnt_id("pos:\t0\nflags:\t0100002\nmnt_id:\t42\n"),
            Some(42)
        );
        assert_eq!(parse_fdinfo_mnt_id("flags:\t0100002\n"), None);
        assert_eq!(parse_fdinfo_mnt_id("mnt_id:\tnope\n"), None);
    }

    #[test]
    fn writable_fds_are_detected_from_the_octal_flags_line() {
        // O_WRONLY (0o1) and O_RDWR (0o2), with the usual extra flags, are writable.
        assert!(fdinfo_is_writable(
            "pos:\t0\nflags:\t0100002\nmnt_id:\t42\n"
        ));
        assert!(fdinfo_is_writable("flags:\t02100001\n"));
        // O_RDONLY (low two bits zero) is not writable — the decoy's own journals
        // journald keeps open for reading.
        assert!(!fdinfo_is_writable(
            "pos:\t0\nflags:\t0100000\nmnt_id:\t42\n"
        ));
        // A missing or unparsable flags line reads as not-writable.
        assert!(!fdinfo_is_writable("pos:\t0\nmnt_id:\t42\n"));
        assert!(!fdinfo_is_writable("flags:\tnope\n"));
    }

    proptest::proptest! {
        /// `mnt_id:` and the writable verdict are recovered from any fdinfo body
        /// laid out as the kernel writes it, and arbitrary text never panics.
        #[test]
        fn fuzz_fdinfo_mnt_id_and_access_mode(
            mnt_id in 0i32..1_000_000,
            flags in 0u32..0o20000000,
            extra in proptest::collection::vec("[a-z_]{1,10}:\t[0-9a-f ]{0,16}", 0..3),
            noise in "\\PC{0,120}",
        ) {
            let mut body = format!("pos:\t0\nflags:\t0{flags:o}\nmnt_id:\t{mnt_id}\nino:\t7\n");
            for line in &extra {
                body.push_str(line);
                body.push('\n');
            }
            proptest::prop_assert_eq!(parse_fdinfo_mnt_id(&body), Some(mnt_id));
            proptest::prop_assert_eq!(
                fdinfo_is_writable(&body),
                flags & 0o3 != 0 || flags & 0o2000 != 0
            );
            let _ = parse_fdinfo_mnt_id(&noise);
            let _ = fdinfo_is_writable(&noise);
        }
    }
}
