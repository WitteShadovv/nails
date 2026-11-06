// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Pre-flight check that refuses a decoy with a pending offline system update.
//!
//! systemd's offline-update mechanism (and PackageKit on Debian/Ubuntu) stages a
//! system update by creating a `/system-update` symlink to the prepared payload;
//! some tools use `/etc/system-update`. At the next boot `system-update-generator`
//! redirects into `system-update.target`, which applies the update and reboots.
//!
//! A decoy with one staged is a trap for a hidden session: once NAILS has mounted
//! the overlays and the session soft-reboots, the decoy's offline updater would
//! run the package manager against the overlay (writing into the upper on the
//! hidden volume) and then reboot the machine out from under the session. So
//! activation is refused until the pending update is cleared.
//!
//! The marker is looked for on the decoy root and in the root overlay's upper, so
//! one left staged in the upper by an earlier session is caught too. An overlay
//! whiteout in the upper is not a marker: it records that a session deleted
//! one. A marker in the upper is the hidden session's own copy, which neither
//! the decoy's updater nor an `rm` on the decoy reaches, so the remediation
//! names the `discard` that deletes it, with `--allow-decoy-storage` when the
//! run accepted a root on this computer's own storage, which `discard` refuses
//! without it. A marker whose lookup fails for another reason than that
//! nothing is there may be staged, so the check refuses then too, naming it.
//! Every probe reads; nothing here writes.

use super::super::{CheckResult, PreFlightCheck};
use crate::next_step::{NextStep, sudo_line_for};
use crate::{Filesystem, NailsError, Result};
use std::path::{Path, PathBuf};

/// The offline-update markers, relative to a root: systemd's `/system-update`
/// and the `/etc/system-update` some tools use.
const UPDATE_MARKERS: &[&str] = &["system-update", "etc/system-update"];

/// Pre-flight check that refuses a decoy with a pending offline update staged.
#[derive(Debug)]
pub struct OfflineUpdateCheck {
    /// The decoy root, `/` outside tests.
    root: PathBuf,
    /// The root overlay's upper on the hidden volume, where a staged update left
    /// by an earlier session would sit.
    upper: PathBuf,
    /// Whether the run accepted a hidden root on this computer's own storage
    /// (`--allow-decoy-storage`).
    allow_decoy_storage: bool,
}

impl OfflineUpdateCheck {
    /// Create the check over the decoy `root` and the root overlay's `upper`.
    pub fn new(root: PathBuf, upper: PathBuf) -> Self {
        Self {
            root,
            upper,
            allow_decoy_storage: false,
        }
    }

    /// The check for a run that accepted the hidden root on this computer's
    /// own storage (`--allow-decoy-storage`): the `discard` its remediation
    /// names takes the same flag, without which it refuses that root.
    pub fn allowing_decoy_storage(mut self, allow: bool) -> Self {
        self.allow_decoy_storage = allow;
        self
    }

    /// Whether `path` is present as a file, directory or symlink.
    ///
    /// A `/system-update` symlink is counted even when it dangles: its presence
    /// shows the offline-update mechanism is in use, so refusing is the safe,
    /// fail-closed response. The link itself is looked up first, so one whose
    /// target cannot be looked up counts as well. An overlay whiteout is not
    /// counted: in the upper it means the marker was deleted. Only a whiteout
    /// seen as one is left out; an entry that cannot be inspected counts.
    ///
    /// # Errors
    ///
    /// A lookup of `path` that fails for another reason than that nothing is
    /// there: the marker may be there.
    fn present<F: Filesystem>(fs: &F, path: &Path) -> Result<bool> {
        Ok(fs.entry_exists(path)? && !fs.is_overlay_whiteout(path).unwrap_or(false))
    }

    /// The staged-update markers found, as absolute paths in the hidden root:
    /// those on the decoy, and those in the root overlay's upper; and those
    /// NAILS cannot tell about.
    fn staged<F: Filesystem>(&self, fs: &F) -> Staged {
        let mut staged = Staged::default();
        for marker in UPDATE_MARKERS {
            for (base, place) in [(&self.root, Place::Decoy), (&self.upper, Place::Upper)] {
                match Self::present(fs, &base.join(marker)) {
                    Ok(false) => {}
                    Ok(true) => match place {
                        Place::Decoy => staged.on_decoy.push(format!("/{marker}")),
                        Place::Upper => staged.in_upper.push(format!("/{marker}")),
                    },
                    Err(error) => staged.untold.push((place, format!("/{marker}"), error)),
                }
            }
        }
        staged
    }
}

/// Where a marker lies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Place {
    /// On the decoy root.
    Decoy,
    /// In the root overlay's upper, the hidden session's own.
    Upper,
}

/// What [`OfflineUpdateCheck::staged`] found of the markers.
#[derive(Default)]
struct Staged {
    /// The markers on the decoy.
    on_decoy: Vec<String>,
    /// The markers in the root overlay's upper.
    in_upper: Vec<String>,
    /// The markers whose lookup failed, with where they lie and the error.
    untold: Vec<(Place, String, NailsError)>,
}

/// Why NAILS cannot tell whether the marker `marker` is staged at `place`,
/// whose lookup failed with `error`, and what to do so that it can. The
/// hidden volume's path is not named: an error is told by what failed.
fn unseen(place: Place, marker: &str, error: &NailsError) -> (String, String) {
    let what = match error {
        NailsError::IoError { source, .. } => source.to_string(),
        other => other.to_string(),
    };
    let at = match place {
        Place::Decoy => format!("{marker} on the decoy"),
        Place::Upper => format!("{marker} in the hidden session's overlay"),
    };
    let fix = if error.io_kind() == Some(std::io::ErrorKind::PermissionDenied) {
        "Run the command again with sudo.".to_string()
    } else {
        format!("Find out why {at} cannot be looked up, then run the command again.")
    };
    (
        format!(
            "NAILS cannot tell whether an offline update is staged: it cannot look up {at} ({what})"
        ),
        fix,
    )
}

/// What to do about the markers found: on the decoy, cancel the update or
/// remove the marker there; in the upper, delete the hidden session's copy with
/// `discard`, the one command that reaches it, given `--allow-decoy-storage`
/// when the run accepted the root with it (`allow_decoy_storage`).
fn remediation(on_decoy: &[String], in_upper: &[String], allow_decoy_storage: bool) -> String {
    let mut steps = Vec::new();
    if !on_decoy.is_empty() {
        steps.push(format!(
            "Cancel the pending update on the decoy and remove the system-update marker \
             before activating (for example {}, or cancel it in the decoy's software updater).",
            commands(on_decoy, |marker| format!("rm {marker}"))
        ));
    }
    if !in_upper.is_empty() {
        steps.push(format!(
            "The marker in the hidden session's overlay is that session's own copy, which \
             neither the decoy's updater nor `rm` on the decoy reaches: delete it with {} \
             (it lists what it deletes and asks first), then activate again.",
            commands(in_upper, |marker| {
                if allow_decoy_storage {
                    sudo_line_for(
                        NextStep::Discard,
                        &format!("--allow-decoy-storage {marker}"),
                    )
                } else {
                    sudo_line_for(NextStep::Discard, marker)
                }
            })
        ));
    }
    steps.join(" ")
}

/// The command `command` gives for each of `markers`, quoted, joined by "and".
fn commands(markers: &[String], command: impl Fn(&str) -> String) -> String {
    markers
        .iter()
        .map(|marker| format!("`{}`", command(marker)))
        .collect::<Vec<_>>()
        .join(" and ")
}

impl<F: Filesystem> PreFlightCheck<F> for OfflineUpdateCheck {
    fn name(&self) -> &'static str {
        "pending-offline-update"
    }

    fn description(&self) -> &'static str {
        "Refuses a decoy with a pending offline system update staged"
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        let Staged {
            on_decoy,
            in_upper,
            untold,
        } = self.staged(fs);
        if on_decoy.is_empty() && in_upper.is_empty() && untold.is_empty() {
            return Ok(CheckResult::Pass(
                "no pending offline update is staged on the decoy".into(),
            ));
        }
        let mut problems = Vec::new();
        let mut steps = Vec::new();
        if !on_decoy.is_empty() || !in_upper.is_empty() {
            // Each marker by its location, without naming the hidden volume
            // path.
            let found: Vec<String> = on_decoy
                .iter()
                .map(|marker| format!("{marker} on the decoy"))
                .chain(
                    in_upper
                        .iter()
                        .map(|marker| format!("{marker} in the hidden session's overlay")),
                )
                .collect();
            problems.push(format!(
                "a pending offline update is staged ({}); once the overlays are mounted the \
                 decoy's offline updater would apply it inside the hidden session and reboot \
                 into it",
                found.join(", ")
            ));
            steps.push(remediation(&on_decoy, &in_upper, self.allow_decoy_storage));
        }
        // A marker NAILS cannot tell about may be staged.
        for (place, marker, error) in &untold {
            let (problem, fix) = unseen(*place, marker, error);
            problems.push(problem);
            if !steps.contains(&fix) {
                steps.push(fix);
            }
        }
        Ok(CheckResult::fail_with(problems.join("; "), steps.join(" ")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::{MockFilesystem, PathKind};

    fn check() -> OfflineUpdateCheck {
        OfflineUpdateCheck::new(PathBuf::from("/"), PathBuf::from("/mnt/hidden/upper"))
    }

    #[test]
    fn a_clean_decoy_passes() {
        let fs = MockFilesystem::new();
        let result = check().run(&fs).unwrap();
        assert!(result.is_pass(), "{result:?}");
    }

    /// A marker whose lookup fails may be staged: the check refuses, naming
    /// where it could not look and what to do, and never names the hidden
    /// volume's path. It used to pass.
    #[test]
    fn a_marker_nails_cannot_look_up_refuses() {
        use std::io::ErrorKind;
        let fs = MockFilesystem::new();
        fs.mock_set_lookup_error("/etc/system-update", ErrorKind::Other);
        let result = check().run(&fs).unwrap();
        assert_eq!(
            result,
            CheckResult::fail_with(
                "NAILS cannot tell whether an offline update is staged: it cannot look up \
                 /etc/system-update on the decoy (Mock: the lookup fails here)",
                "Find out why /etc/system-update on the decoy cannot be looked up, then run the \
                 command again."
            )
        );

        let fs = MockFilesystem::new();
        fs.mock_set_lookup_error("/mnt/hidden/upper", ErrorKind::PermissionDenied);
        fs.mock_set_path_type("/system-update", PathKind::Symlink);
        let result = check().run(&fs).unwrap();
        assert!(result.is_fail(), "{result:?}");
        assert_eq!(
            result.message(),
            "a pending offline update is staged (/system-update on the decoy); once the overlays \
             are mounted the decoy's offline updater would apply it inside the hidden session and \
             reboot into it; NAILS cannot tell whether an offline update is staged: it cannot \
             look up /system-update in the hidden session's overlay (Mock: the lookup fails \
             here); NAILS cannot tell whether an offline update is staged: it cannot look up \
             /etc/system-update in the hidden session's overlay (Mock: the lookup fails here)"
        );
        assert!(!result.message().contains("/mnt/hidden"), "{result:?}");
        let remediation = result.remediation().unwrap();
        assert!(remediation.contains("rm /system-update"), "{remediation}");
        assert!(
            remediation.ends_with("Run the command again with sudo."),
            "{remediation}"
        );
        assert_eq!(remediation.matches("with sudo").count(), 1, "{remediation}");
    }

    /// A marker that is a link is counted by the link itself: one whose
    /// target cannot be looked up counts, and is no lookup NAILS failed.
    #[test]
    fn a_marker_link_whose_target_cannot_be_looked_up_counts() {
        let fs = MockFilesystem::new();
        fs.create_symlink(
            Path::new("/var/lib/PackageKit/prepared-update"),
            Path::new("/system-update"),
        )
        .unwrap();
        fs.mock_set_lookup_error("/var/lib/PackageKit", std::io::ErrorKind::PermissionDenied);
        let result = check().run(&fs).unwrap();
        assert!(result.is_fail(), "{result:?}");
        assert!(
            result
                .message()
                .starts_with("a pending offline update is staged (/system-update on the decoy)"),
            "{result:?}"
        );
        assert!(!result.message().contains("cannot tell"), "{result:?}");
    }

    #[test]
    fn a_system_update_symlink_on_the_decoy_refuses() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_type("/system-update", PathKind::Symlink);
        let result = check().run(&fs).unwrap();
        assert!(result.is_fail(), "{result:?}");
        assert!(result.message().contains("/system-update"), "{result:?}");
        assert!(result.remediation().is_some());
    }

    #[test]
    fn an_etc_system_update_directory_on_the_decoy_refuses() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_type("/etc/system-update", PathKind::Dir);
        let result = check().run(&fs).unwrap();
        assert!(result.is_fail(), "{result:?}");
        assert!(
            result.message().contains("/etc/system-update"),
            "{result:?}"
        );
    }

    #[test]
    fn a_marker_staged_in_the_overlay_upper_refuses() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_type("/mnt/hidden/upper/system-update", PathKind::Symlink);
        let result = check().run(&fs).unwrap();
        assert!(result.is_fail(), "{result:?}");
        assert!(
            result.message().contains("in the hidden session's overlay"),
            "{result:?}"
        );
        // The refusal describes the location without naming the hidden path.
        assert!(!result.message().contains("/mnt/hidden"), "{result:?}");
        // Neither the decoy's updater nor an `rm` on the decoy reaches the
        // hidden session's copy: the fix names the discard that deletes it.
        let remediation = result.remediation().unwrap();
        assert!(
            remediation.contains(&crate::next_step::sudo_line_for(
                NextStep::Discard,
                "/system-update"
            )),
            "{remediation}"
        );
        assert!(
            !remediation.contains("`rm /system-update`"),
            "{remediation}"
        );
    }

    #[test]
    fn on_a_root_accepted_as_decoy_storage_the_discard_takes_the_override() {
        // `discard` refuses such a root without --allow-decoy-storage, as
        // activation does: the line the fix names carries the flag the run
        // was given, and only then.
        let fs = MockFilesystem::new();
        fs.mock_set_path_type("/mnt/hidden/upper/system-update", PathKind::Symlink);
        let accepted = check().allowing_decoy_storage(true).run(&fs).unwrap();
        let remediation = accepted.remediation().unwrap();
        assert!(
            remediation.contains(&format!(
                "`{}`",
                crate::next_step::sudo_line_for(
                    NextStep::Discard,
                    "--allow-decoy-storage /system-update"
                )
            )),
            "{remediation}"
        );
        assert!(!accepted.message().contains("/mnt/hidden"), "{accepted:?}");
        let plain = check().allowing_decoy_storage(false).run(&fs).unwrap();
        assert!(
            !plain
                .remediation()
                .unwrap()
                .contains("--allow-decoy-storage"),
            "{plain:?}"
        );
    }

    #[test]
    fn a_marker_on_the_decoy_is_removed_there() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_type("/etc/system-update", PathKind::File);
        let result = check().run(&fs).unwrap();
        let remediation = result.remediation().unwrap();
        assert!(
            remediation.contains("`rm /etc/system-update`"),
            "{remediation}"
        );
        assert!(!remediation.contains("discard"), "{remediation}");
    }

    #[test]
    fn markers_in_both_places_get_both_fixes() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_type("/system-update", PathKind::Symlink);
        fs.mock_set_path_type("/mnt/hidden/upper/etc/system-update", PathKind::File);
        let result = check().run(&fs).unwrap();
        assert!(result.is_fail(), "{result:?}");
        let remediation = result.remediation().unwrap();
        assert!(remediation.contains("`rm /system-update`"), "{remediation}");
        assert!(
            remediation.contains(&crate::next_step::sudo_line_for(
                NextStep::Discard,
                "/etc/system-update"
            )),
            "{remediation}"
        );
    }

    #[test]
    fn an_overlay_whiteout_in_the_upper_is_no_staged_update() {
        // A session deleted the marker: the upper holds a whiteout, which the
        // merged view shows as no file at all.
        let fs = MockFilesystem::new();
        fs.mock_set_whiteout("/mnt/hidden/upper/system-update");
        let result = check().run(&fs).unwrap();
        assert!(result.is_pass(), "{result:?}");
    }

    #[test]
    fn a_real_whiteout_passes_and_a_real_dangling_marker_refuses() {
        use crate::RealFilesystem;
        use nix::sys::stat::{Mode, SFlag, mknod};
        let root = tempfile::tempdir().unwrap();
        let upper = tempfile::tempdir().unwrap();
        let marker = upper.path().join("system-update");
        let in_upper =
            OfflineUpdateCheck::new(root.path().to_path_buf(), upper.path().to_path_buf());

        // The 0:0 character device overlayfs leaves for a deleted file; Linux
        // lets an unprivileged process make one since 5.8.
        match mknod(&marker, SFlag::S_IFCHR, Mode::from_bits_truncate(0o600), 0) {
            Ok(()) => {
                let result = in_upper.run(&RealFilesystem).unwrap();
                assert!(result.is_pass(), "{result:?}");
                std::fs::remove_file(&marker).unwrap();
            }
            // A host that forbids it (a device cgroup) has no whiteout to read.
            Err(nix::errno::Errno::EPERM) => {}
            Err(errno) => panic!("mknod a whiteout: {errno}"),
        }

        // A staged update's marker: a symlink to a payload the decoy does not
        // have, so it dangles there, and still refuses.
        std::os::unix::fs::symlink("/var/lib/PackageKit/prepared-update", &marker).unwrap();
        let result = in_upper.run(&RealFilesystem).unwrap();
        assert!(result.is_fail(), "{result:?}");
        assert!(
            result
                .remediation()
                .unwrap()
                .contains("discard /system-update"),
            "{result:?}"
        );
    }

    #[test]
    fn a_dangling_system_update_symlink_still_refuses() {
        // systemd's generator follows the link, but a stray /system-update symlink
        // is a tell on its own, so NAILS refuses fail-closed regardless.
        let fs = MockFilesystem::new();
        fs.mock_set_is_symlink("/system-update", true);
        fs.mock_set_path_exists("/system-update", false);
        let result = check().run(&fs).unwrap();
        assert!(result.is_fail(), "{result:?}");
    }

    #[test]
    fn the_check_reports_its_name_and_description() {
        // The id is a status contract the preflight runner keys rows on, so pin
        // it exactly.
        assert_eq!(
            PreFlightCheck::<MockFilesystem>::name(&check()),
            "pending-offline-update"
        );
        // The description is surfaced to the user; it must be present and name
        // the offline-update hazard this check guards against.
        let description = PreFlightCheck::<MockFilesystem>::description(&check());
        assert!(!description.is_empty(), "{description:?}");
        assert!(
            description.contains("offline system update"),
            "{description:?}"
        );
    }
}
