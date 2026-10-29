// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use nails_platform::platform::FakePlatform;
use nails_platform::{SelinuxMode, SelinuxStatus, Selinuxfs};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::time::Duration;

/// The decoy directory of the judged copies.
const DECOY: &str = "/home";
/// The upper directory of the judged copies.
const UPPER: &str = "/mnt/data/root/mounts/home/upper";
/// Where SELinux runs.
const RUNNING: Labels = Labels::Required(Reason::SelinuxRunning);
/// Where the host facts report SELinux and the mount table could not be read.
const UNREADABLE: Labels = Labels::Required(Reason::MountsUnreadable);
/// Where the host was not detected.
const UNDETECTED: Labels = Labels::Required(Reason::HostUndetected);

/// A host's SELinux facts, as the host facts read them.
fn facts(
    selinuxfs: Selinuxfs,
    enforce: Option<SelinuxMode>,
    config_mode: Option<&str>,
) -> SelinuxStatus {
    SelinuxStatus {
        selinuxfs,
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

/// Long enough for a write to move a time, on a kernel whose timestamps are
/// coarse.
fn tick() {
    std::thread::sleep(Duration::from_millis(20));
}

/// A walk down the way to a home: both share every rule but what a directory
/// missing from the upper means.
type Walk = fn(&Path, &Path, &Path, Labels) -> Result<()>;

/// The walk that follows a fresh home's creation, and the one along what the
/// upper holds.
const WALKS: [Walk; 2] = [copy_labels_along, copy_labels_along_existing];

#[test]
fn a_host_whose_facts_report_no_selinux_copies_labels_on_a_best_effort_basis() {
    let profile = FakePlatform::fhs().host_profile();
    assert_eq!(profile.selinux, None);
    assert_eq!(Labels::for_host(Some(&profile)), Labels::BestEffort);
}

#[test]
fn a_host_that_was_not_detected_requires_the_labels() {
    // The detection failed, so there are no facts to rule SELinux out.
    assert_eq!(Labels::for_host(None), UNDETECTED);
}

/// A detected host with these SELinux facts.
fn host_with(selinux: SelinuxStatus) -> HostProfile {
    let mut profile = FakePlatform::fhs().host_profile();
    profile.selinux = Some(selinux);
    profile
}

#[test]
fn a_host_with_selinuxfs_mounted_requires_the_labels() {
    for selinux in [
        facts(
            Selinuxfs::Mounted,
            Some(SelinuxMode::Enforcing),
            Some("enforcing"),
        ),
        facts(
            Selinuxfs::Mounted,
            Some(SelinuxMode::Permissive),
            Some("permissive"),
        ),
        // selinuxfs is mounted, but its enforce flag could not be read.
        facts(Selinuxfs::Mounted, None, None),
        // Mounted, whatever the configuration file says about the next boot.
        facts(
            Selinuxfs::Mounted,
            Some(SelinuxMode::Permissive),
            Some("disabled"),
        ),
    ] {
        let profile = host_with(selinux);
        assert_eq!(Labels::for_host(Some(&profile)), RUNNING, "{profile:?}");
        assert!(!configured_but_not_running(Some(&profile)));
    }
}

#[test]
fn a_host_configured_for_selinux_without_selinuxfs_copies_labels_on_a_best_effort_basis() {
    // The configuration file of SELinux packages installed once, or an empty
    // /sys/fs/selinux, while the mount table lists no selinuxfs: SELinux does
    // not run, and no policy reads a label.
    for selinux in [
        facts(Selinuxfs::NotMounted, None, Some("permissive")),
        facts(Selinuxfs::NotMounted, None, Some("enforcing")),
        facts(Selinuxfs::NotMounted, None, Some("disabled")),
        facts(Selinuxfs::NotMounted, None, None),
    ] {
        let profile = host_with(selinux);
        assert_eq!(
            Labels::for_host(Some(&profile)),
            Labels::BestEffort,
            "{profile:?}"
        );
        assert!(configured_but_not_running(Some(&profile)));
    }
}

#[test]
fn a_host_whose_mount_table_could_not_be_read_requires_the_labels() {
    // Nothing tells whether selinuxfs is mounted, so nothing rules SELinux out.
    for selinux in [
        facts(Selinuxfs::Unknown, None, Some("disabled")),
        facts(
            Selinuxfs::Unknown,
            Some(SelinuxMode::Enforcing),
            Some("enforcing"),
        ),
        facts(Selinuxfs::Unknown, None, None),
    ] {
        let profile = host_with(selinux);
        assert_eq!(Labels::for_host(Some(&profile)), UNREADABLE, "{profile:?}");
        assert!(!configured_but_not_running(Some(&profile)));
    }
}

#[test]
fn only_a_host_configured_for_selinux_without_selinuxfs_gets_the_note() {
    assert!(!configured_but_not_running(None));
    let profile = FakePlatform::fhs().host_profile();
    assert!(!configured_but_not_running(Some(&profile)));
}

#[test]
fn a_label_in_place_is_a_copy_on_every_host() {
    for labels in [RUNNING, UNDETECTED, Labels::BestEffort] {
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
fn without_selinux_a_link_or_a_file_in_place_of_the_upper_is_left_alone() {
    // The kernel's answer to opening one as a directory without following it.
    for failure in [Failure::Upper(Errno::NOTDIR), Failure::Upper(Errno::LOOP)] {
        assert_eq!(
            judged(Labels::BestEffort, Err(failure)).unwrap(),
            Copied::NotADirectory,
            "{failure:?}"
        );
    }
}

#[test]
fn without_selinux_any_other_failure_is_still_an_error() {
    for failure in [
        Failure::Read(Errno::IO),
        Failure::Read(Errno::ACCESS),
        // The upper must exist: the caller has just created it.
        Failure::Upper(Errno::NOENT),
        Failure::Upper(Errno::ACCESS),
        Failure::Write(Errno::PERM),
        Failure::Write(Errno::NOSPC),
    ] {
        let error = judged(Labels::BestEffort, Err(failure)).unwrap_err();
        assert!(matches!(error, NailsError::InvalidState(_)), "{error:?}");
        let text = error.to_string();
        assert!(
            text.contains(&format!(
                "the SELinux label of {DECOY} could not be copied onto {UPPER}: "
            )),
            "{text}"
        );
    }
}

#[test]
fn where_the_labels_are_required_every_failure_refuses_the_entry() {
    for labels in [RUNNING, UNDETECTED] {
        for failure in [
            Failure::Read(Errno::NODATA),
            Failure::Read(Errno::NOENT),
            Failure::Read(Errno::NOTSUP),
            Failure::Read(Errno::ACCESS),
            // A link in place of the upper: an overlay would take its root
            // from the link's target, which never got the label.
            Failure::Upper(Errno::NOTDIR),
            Failure::Upper(Errno::NOENT),
            Failure::Write(Errno::NOTSUP),
            // The policy refuses the relabel, or does not know the label.
            Failure::Write(Errno::ACCESS),
            Failure::Write(Errno::INVAL),
        ] {
            let error = judged(labels, Err(failure)).unwrap_err();
            assert!(matches!(error, NailsError::InvalidState(_)), "{error:?}");
            let text = error.to_string();
            assert!(
                text.contains(&format!(
                    ", so {UPPER} must carry the SELinux label of {DECOY}, but "
                )),
                "{text}"
            );
        }
    }
}

#[test]
fn a_refusal_says_why_the_labels_are_required() {
    let refusal = |labels| {
        judged(labels, Err(Failure::Read(Errno::NODATA)))
            .unwrap_err()
            .to_string()
    };
    // Each reason claims no more than its facts: only a mounted selinuxfs says
    // that SELinux runs.
    let reported = refusal(RUNNING);
    assert!(
        reported.contains("SELinux runs on this host (selinuxfs is mounted), so "),
        "{reported}"
    );
    let unreadable = refusal(UNREADABLE);
    assert!(
        unreadable.contains(
            "the host facts report SELinux and /proc/self/mounts could not be read to tell \
             whether selinuxfs is mounted, so "
        ),
        "{unreadable}"
    );
    let undetected = refusal(UNDETECTED);
    assert!(
        undetected.contains("the host could not be detected and may run SELinux, so "),
        "{undetected}"
    );
    for text in [reported, unreadable, undetected] {
        assert!(!text.contains("enabled"), "{text}");
        assert!(!text.contains("to boot"), "{text}");
    }
}

#[test]
fn a_refusal_names_what_failed() {
    let why = |failure| judged(RUNNING, Err(failure)).unwrap_err().to_string();
    assert!(why(Failure::Read(Errno::NODATA)).ends_with("but /home has no label"));
    assert!(why(Failure::Read(Errno::NOENT)).ends_with("but /home does not exist"));
    assert!(
        why(Failure::Read(Errno::NOTSUP)).ends_with("the filesystem of /home stores no labels")
    );
    assert!(
        why(Failure::Upper(Errno::NOTDIR))
            .ends_with(&format!("but {UPPER} is a link or a file, not a directory"))
    );
    assert!(why(Failure::Upper(Errno::NOENT)).ends_with(&format!("but {UPPER} does not exist")));
    let unopened = why(Failure::Upper(Errno::ACCESS));
    assert!(
        unopened.contains(&format!("opening {UPPER} failed: Permission denied")),
        "{unopened}"
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
    tick();

    assert_eq!(
        copy_label(&decoy, &upper, Labels::BestEffort).unwrap(),
        Copied::NoLabel
    );
    let error = copy_label(&decoy, &upper, RUNNING).unwrap_err();
    let text = error.to_string();
    assert!(
        text.ends_with(&format!("but {} does not exist", decoy.display())),
        "{text}"
    );
    // Neither copy wrote anything onto the upper.
    assert_eq!(ctime(&upper), before);
}

/// A decoy root with `home/alice`, and an upper root next to it.
fn walk_world() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let decoy = dir.path().join("decoy");
    std::fs::create_dir_all(decoy.join("home/alice")).unwrap();
    let upper = dir.path().join("upper");
    std::fs::create_dir(&upper).unwrap();
    (dir, decoy, upper)
}

#[test]
fn the_walk_never_follows_a_link_below_the_upper_root() {
    // Real calls, on any host: the walk opens each upper directory before it
    // reads the decoy's label, and a link fails that open.
    let (dir, decoy, upper) = walk_world();
    let elsewhere = dir.path().join("elsewhere");
    std::fs::create_dir_all(elsewhere.join("alice")).unwrap();
    std::os::unix::fs::symlink(&elsewhere, upper.join("home")).unwrap();
    let before = (ctime(&elsewhere), ctime(&elsewhere.join("alice")));
    tick();

    for walk in WALKS {
        walk(&decoy, &upper, Path::new("home/alice"), Labels::BestEffort).unwrap();
        for labels in [RUNNING, UNDETECTED] {
            let text = walk(&decoy, &upper, Path::new("home/alice"), labels)
                .unwrap_err()
                .to_string();
            assert!(
                text.contains(&format!(
                    "must carry the SELinux label of {}, but {} is a link or a file, not a \
                     directory",
                    decoy.join("home").display(),
                    upper.join("home").display()
                )),
                "{text}"
            );
        }
    }
    // Nothing was written through the link.
    assert_eq!((ctime(&elsewhere), ctime(&elsewhere.join("alice"))), before);
}

#[test]
fn the_walk_stops_at_an_upper_root_that_is_a_link() {
    let (dir, decoy, _) = walk_world();
    let elsewhere = dir.path().join("elsewhere");
    std::fs::create_dir_all(elsewhere.join("home/alice")).unwrap();
    let upper = dir.path().join("linked-upper");
    std::os::unix::fs::symlink(&elsewhere, &upper).unwrap();
    let before = ctime(&elsewhere.join("home"));
    tick();

    for walk in WALKS {
        walk(&decoy, &upper, Path::new("home/alice"), Labels::BestEffort).unwrap();
        let text = walk(&decoy, &upper, Path::new("home/alice"), RUNNING)
            .unwrap_err()
            .to_string();
        assert!(
            text.ends_with(&format!(
                "but {} is a link or a file, not a directory",
                upper.display()
            )),
            "{text}"
        );
    }
    assert_eq!(ctime(&elsewhere.join("home")), before);
}

#[test]
fn the_walk_needs_every_directory_on_the_way() {
    // The home and its parents are created before the walk: a missing one is
    // an error on every host.
    let (_dir, decoy, upper) = walk_world();
    for labels in [Labels::BestEffort, RUNNING] {
        let text = copy_labels_along(&decoy, &upper, Path::new("home/alice"), labels)
            .unwrap_err()
            .to_string();
        assert!(
            text.ends_with(&format!("{} does not exist", upper.join("home").display())),
            "{text}"
        );
    }
    // With all of them in place the walk goes down to the home. What it
    // writes depends on whether this host labels the decoy's directories;
    // the kernel tier checks the labels themselves, and that nothing is
    // written where the decoy's directories carry none.
    std::fs::create_dir_all(upper.join("home/alice")).unwrap();
    copy_labels_along(&decoy, &upper, Path::new("home/alice"), Labels::BestEffort).unwrap();
}

#[test]
fn the_walk_along_what_exists_ends_where_the_upper_holds_no_more() {
    // Real calls, on any host: the walk reads no label before it finds a
    // directory of the way in the upper. A shared-home entry may find no upper
    // root yet, or one that holds nothing of the way to the home.
    let (dir, decoy, upper) = walk_world();
    let rest = Path::new("home/alice");
    let no_upper = dir.path().join("no-upper");
    let before = ctime(&upper);
    tick();

    for labels in [Labels::BestEffort, RUNNING, UNDETECTED] {
        copy_labels_along_existing(&decoy, &no_upper, rest, labels).unwrap();
        copy_labels_along_existing(&decoy, &upper, rest, labels).unwrap();
    }
    assert!(!no_upper.exists());
    assert!(!upper.join("home").exists());
    assert_eq!(ctime(&upper), before);
    // The walk after a fresh home's creation needs all of the way.
    for at in [&no_upper, &upper] {
        let text = copy_labels_along(&decoy, at, rest, Labels::BestEffort)
            .unwrap_err()
            .to_string();
        assert!(text.ends_with(" does not exist"), "{text}");
    }
}

#[test]
fn the_walk_takes_a_relative_path_of_plain_names() {
    let (_dir, decoy, upper) = walk_world();
    for walk in WALKS {
        for rest in ["/home/alice", "../home/alice", "home/../home/alice"] {
            let error = walk(&decoy, &upper, Path::new(rest), Labels::BestEffort).unwrap_err();
            assert!(
                error.to_string().ends_with(&format!(
                    "{rest} is not a path of plain names below {}",
                    upper.display()
                )),
                "{error}"
            );
        }
    }
    // A home that is the upper root itself (a separate filesystem mounted at
    // the home) leaves nothing to walk.
    let before = ctime(&upper);
    tick();
    for walk in WALKS {
        for rest in ["", "."] {
            walk(&decoy, &upper, Path::new(rest), RUNNING).unwrap();
        }
    }
    assert_eq!(ctime(&upper), before);
}
