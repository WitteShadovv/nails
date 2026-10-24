// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use nails_platform::SelinuxMode;
use std::os::unix::fs::MetadataExt;

/// The decoy directory of the judged copies.
const DECOY: &str = "/home";
/// The upper directory of the judged copies.
const UPPER: &str = "/mnt/data/root/mounts/home/upper";

/// A host's SELinux facts, as the host facts read them.
fn facts(enforce: Option<SelinuxMode>, config_mode: Option<&str>) -> SelinuxStatus {
    SelinuxStatus {
        enforce,
        config_mode: config_mode.map(str::to_string),
        config_policy: config_mode.map(|_| "targeted".to_string()),
    }
}

/// A copy from [`DECOY`] to [`UPPER`] that ended in `copied`, judged under
/// `labels`.
fn judged(labels: Labels, copied: std::result::Result<(), Failure>) -> Result<Copied> {
    judge(Path::new(DECOY), Path::new(UPPER), labels, copied)
}

/// The status change time of `path`, which any attribute written moves.
fn ctime(path: &Path) -> (i64, i64) {
    let meta = std::fs::symlink_metadata(path).unwrap();
    (meta.ctime(), meta.ctime_nsec())
}

#[test]
fn a_host_without_selinux_copies_labels_on_a_best_effort_basis() {
    assert_eq!(Labels::for_host(None), Labels::BestEffort);
}

#[test]
fn any_selinux_the_host_facts_report_requires_the_labels() {
    for selinux in [
        facts(Some(SelinuxMode::Enforcing), Some("enforcing")),
        facts(Some(SelinuxMode::Permissive), Some("permissive")),
        // selinuxfs is mounted, but its enforce flag could not be read.
        facts(None, None),
        // Disabled at boot: only the configuration file is left, which the
        // facts cannot tell apart from the host above.
        facts(None, Some("disabled")),
    ] {
        assert_eq!(
            Labels::for_host(Some(&selinux)),
            Labels::Required,
            "{selinux:?}"
        );
    }
}

#[test]
fn a_label_in_place_is_a_copy_on_every_host() {
    for labels in [Labels::Required, Labels::BestEffort] {
        assert_eq!(judged(labels, Ok(())).unwrap(), Copied::Label);
    }
}

#[test]
fn without_selinux_a_decoy_directory_without_a_label_leaves_the_upper_alone() {
    assert_eq!(
        judged(Labels::BestEffort, Err(Failure::Read(Errno::NODATA))).unwrap(),
        Copied::NoLabel
    );
    // No decoy directory at all: the fresh home of an operator without one.
    assert_eq!(
        judged(Labels::BestEffort, Err(Failure::Read(Errno::NOENT))).unwrap(),
        Copied::NoLabel
    );
}

#[test]
fn without_selinux_a_filesystem_without_extended_attributes_is_skipped() {
    // The decoy's filesystem stores none, or the hidden volume's cannot.
    for failure in [Failure::Read(Errno::NOTSUP), Failure::Write(Errno::NOTSUP)] {
        assert_eq!(
            judged(Labels::BestEffort, Err(failure)).unwrap(),
            Copied::Unsupported,
            "{failure:?}"
        );
    }
}

#[test]
fn without_selinux_any_other_failure_is_still_an_error() {
    for failure in [
        Failure::Read(Errno::IO),
        Failure::Read(Errno::ACCESS),
        Failure::Write(Errno::PERM),
        Failure::Write(Errno::NOSPC),
        // The upper must exist: the caller has just created it.
        Failure::Write(Errno::NOENT),
    ] {
        let error = judged(Labels::BestEffort, Err(failure)).unwrap_err();
        assert!(matches!(error, NailsError::InvalidState(_)), "{error:?}");
        let text = error.to_string();
        assert!(text.contains(DECOY) && text.contains(UPPER), "{text}");
        assert!(!text.contains("SELinux is enabled"), "{text}");
    }
}

#[test]
fn with_selinux_every_failure_refuses_the_entry() {
    for failure in [
        Failure::Read(Errno::NODATA),
        Failure::Read(Errno::NOENT),
        Failure::Read(Errno::NOTSUP),
        Failure::Write(Errno::NOTSUP),
        Failure::Read(Errno::ACCESS),
        // The policy refuses the relabel, or does not know the label.
        Failure::Write(Errno::ACCESS),
        Failure::Write(Errno::INVAL),
    ] {
        let error = judged(Labels::Required, Err(failure)).unwrap_err();
        assert!(matches!(error, NailsError::InvalidState(_)), "{error:?}");
        let text = error.to_string();
        assert!(text.contains("SELinux is enabled on this host"), "{text}");
        assert!(text.contains(DECOY) && text.contains(UPPER), "{text}");
    }
}

#[test]
fn a_refusal_names_what_failed() {
    let why = |failure| {
        judged(Labels::Required, Err(failure))
            .unwrap_err()
            .to_string()
    };
    assert!(why(Failure::Read(Errno::NODATA)).ends_with("but /home has no label"));
    assert!(why(Failure::Read(Errno::NOENT)).ends_with("but /home does not exist"));
    assert!(
        why(Failure::Read(Errno::NOTSUP)).ends_with("the filesystem of /home stores no labels")
    );
    assert!(
        why(Failure::Write(Errno::NOTSUP))
            .ends_with(&format!("the filesystem of {UPPER} cannot store labels"))
    );
    let unreadable = why(Failure::Read(Errno::IO));
    assert!(
        unreadable.contains("reading the label of /home failed"),
        "{unreadable}"
    );
    let denied = why(Failure::Write(Errno::ACCESS));
    assert!(
        denied.contains(&format!("writing the label onto {UPPER} failed")),
        "{denied}"
    );
    assert!(denied.contains("Permission denied"), "{denied}");
}

#[test]
fn a_decoy_directory_that_does_not_exist_leaves_the_upper_alone() {
    // Real calls: every host answers a missing path with ENOENT, SELinux or not.
    let dir = tempfile::tempdir().unwrap();
    let decoy = dir.path().join("decoy/home/alice");
    let upper = dir.path().join("upper");
    std::fs::create_dir(&upper).unwrap();
    let before = ctime(&upper);

    assert_eq!(
        copy_label(&decoy, &upper, Labels::BestEffort).unwrap(),
        Copied::NoLabel
    );
    let error = copy_label(&decoy, &upper, Labels::Required).unwrap_err();
    let text = error.to_string();
    assert!(
        text.ends_with(&format!("but {} does not exist", decoy.display())),
        "{text}"
    );
    // Neither copy wrote anything onto the upper.
    assert_eq!(ctime(&upper), before);
}
