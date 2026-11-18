// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::test_support::FakeSelinux;
use std::os::fd::AsFd;

const INIT: &str = "system_u:system_r:init_t:s0";
const UNCONFINED: &str = "system_u:system_r:unconfined_service_t:s0";

/// The label goes onto the copy as libselinux writes one, with its NUL, and
/// is read back through the same descriptor: as written, or as the kernel
/// gives it without the NUL, it passes.
#[test]
fn a_copy_takes_the_label_with_its_nul_and_reads_it_back() {
    let file = tempfile::tempfile().unwrap();
    let selinux = FakeSelinux::targeted();
    label_file(&selinux, file.as_fd(), PROGRAM_LABEL).unwrap();
    assert_eq!(
        selinux.labels_written(),
        [b"system_u:object_r:bin_t:s0\0".to_vec()]
    );
    for read_back in [
        &b"system_u:object_r:bin_t:s0"[..],
        b"system_u:object_r:bin_t:s0\0\0",
    ] {
        let selinux = FakeSelinux {
            read_back: Some(read_back.to_vec()),
            ..FakeSelinux::targeted()
        };
        label_file(&selinux, file.as_fd(), PROGRAM_LABEL).unwrap();
    }
}

/// A label the kernel refuses, one it cannot read back, or one that reads
/// back as another fails the copy: no step may start from a copy that kept
/// the label of the files in `/run`.
#[test]
fn a_label_that_is_refused_or_reads_back_otherwise_fails() {
    let file = tempfile::tempfile().unwrap();
    let refused = FakeSelinux {
        write_error: Some(libc::EOPNOTSUPP),
        ..FakeSelinux::targeted()
    };
    let error = label_file(&refused, file.as_fd(), PROGRAM_LABEL).unwrap_err();
    assert!(matches!(error, Unlabelled::Write(_)), "{error:?}");
    assert!(
        error.to_string().starts_with("could not take the label: "),
        "{error}"
    );

    let kept = FakeSelinux {
        read_back: Some(b"system_u:object_r:var_run_t:s0\0".to_vec()),
        ..FakeSelinux::targeted()
    };
    let error = label_file(&kept, file.as_fd(), PROGRAM_LABEL).unwrap_err();
    assert_eq!(
        error.to_string(),
        "reads back as system_u:object_r:var_run_t:s0 after the label"
    );
    // A label that only starts as the one written is another label.
    let longer = FakeSelinux {
        read_back: Some(b"system_u:object_r:bin_t:s0:c0".to_vec()),
        ..FakeSelinux::targeted()
    };
    assert!(matches!(
        label_file(&longer, file.as_fd(), PROGRAM_LABEL),
        Err(Unlabelled::Other(_))
    ));
}

/// A label written that the kernel then does not give back fails as well.
#[test]
fn a_label_that_cannot_be_read_back_fails() {
    #[derive(Debug)]
    struct Unreadable(FakeSelinux);
    impl crate::whole_root::selinux::Selinux for Unreadable {
        fn pid1(&self) -> io::Result<Option<String>> {
            self.0.pid1()
        }
        fn current(&self) -> io::Result<String> {
            self.0.current()
        }
        fn udevd(&self) -> io::Result<Option<String>> {
            self.0.udevd()
        }
        fn exec_context(&self, source: &str, file: &str) -> io::Result<String> {
            self.0.exec_context(source, file)
        }
        fn new_label(
            &self,
            source: &str,
            parent: &str,
            class: &str,
            name: Option<&str>,
        ) -> io::Result<String> {
            self.0.new_label(source, parent, class, name)
        }
        fn denied(
            &self,
            source: &str,
            target: &str,
            class: &str,
            perms: &[&'static str],
        ) -> io::Result<Vec<&'static str>> {
            self.0.denied(source, target, class, perms)
        }
        fn capability(&self, name: &str) -> io::Result<bool> {
            self.0.capability(name)
        }
        fn set_label(&self, file: BorrowedFd<'_>, value: &[u8]) -> io::Result<()> {
            self.0.set_label(file, value)
        }
        fn label(&self, _file: BorrowedFd<'_>) -> io::Result<Vec<u8>> {
            Err(io::Error::from_raw_os_error(libc::EIO))
        }
        fn path_label(&self, path: &Path) -> io::Result<String> {
            self.0.path_label(path)
        }
    }
    let file = tempfile::tempfile().unwrap();
    let error = label_file(
        &Unreadable(FakeSelinux::targeted()),
        file.as_fd(),
        PROGRAM_LABEL,
    )
    .unwrap_err();
    assert!(matches!(error, Unlabelled::Read(_)), "{error:?}");
}

/// A copy given its label again is opened without following a link, and must
/// be a regular file: a link, a directory or a pipe in its place, or nothing
/// at all, fails with nothing written.
#[test]
fn a_copy_labelled_by_its_path_must_be_a_regular_file() {
    let dir = tempfile::tempdir().unwrap();
    let copy = dir.path().join("control");
    std::fs::write(&copy, b"\x7fELF").unwrap();
    let selinux = FakeSelinux::targeted();
    label_path(&selinux, &copy, PROGRAM_LABEL).unwrap();
    assert_eq!(selinux.labels_written().len(), 1);

    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&copy, &link).unwrap();
    let pipe = dir.path().join("pipe");
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &pipe,
        FileType::Fifo,
        Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
    for (path, open) in [
        (dir.path().join("missing"), true),
        (link, true),
        (dir.path().to_path_buf(), false),
        (pipe, false),
    ] {
        let selinux = FakeSelinux::targeted();
        let error = label_path(&selinux, &path, PROGRAM_LABEL).unwrap_err();
        if open {
            assert!(
                matches!(error, Unlabelled::Open(_)),
                "{}: {error:?}",
                path.display()
            );
        } else {
            assert!(
                matches!(error, Unlabelled::NotAFile),
                "{}: {error:?}",
                path.display()
            );
        }
        assert!(selinux.labels_written().is_empty(), "{}", path.display());
    }
}

/// Where no policy is loaded nothing more is asked: no label decides a domain
/// there.
#[test]
fn without_a_policy_any_start_passes() {
    let selinux = FakeSelinux::without_policy();
    check_start(&selinux, PROGRAM_LABEL).unwrap();
    assert_eq!(selinux.questions(), ["pid1"]);
}

/// A targeted policy lets PID 1 start the copy and gives the start the
/// unconfined service domain: every permission the start and the change of
/// domain need is asked, under no_new_privs and from a nosuid mount too.
#[test]
fn a_targeted_policy_starts_the_copy_in_the_unconfined_service_domain() {
    let selinux = FakeSelinux::targeted();
    check_start(&selinux, PROGRAM_LABEL).unwrap();
    assert_eq!(
        selinux.questions(),
        [
            "pid1".to_string(),
            format!("access {INIT} {PROGRAM_LABEL} file"),
            format!("create {INIT} {PROGRAM_LABEL}"),
            format!("access {INIT} {UNCONFINED} process"),
            format!("access {INIT} {UNCONFINED} process2"),
            format!("access {UNCONFINED} {PROGRAM_LABEL} file"),
            format!("capability {NNP_NOSUID}"),
        ]
    );
}

/// A start the policy denies does not run, and a switch would go on without
/// its step.
#[test]
fn a_start_the_policy_denies_does_not_run() {
    let selinux = FakeSelinux {
        denied: vec![("file", "execute")],
        ..FakeSelinux::targeted()
    };
    let unfit = check_start(&selinux, PROGRAM_LABEL).unwrap_err();
    assert_eq!(
        unfit,
        Unfit::Start {
            pid1: INIT.to_string(),
            perms: vec!["execute"]
        }
    );
    assert_eq!(unfit.effect(), Effect::NotStarted);
    assert_eq!(
        unfit.to_string(),
        "is denied: the loaded SELinux policy does not let PID 1 (system_u:system_r:init_t:s0) \
         execute such a file"
    );
}

/// A policy without the change of domain on the program label (a policy
/// without the unconfined module, say) keeps the step in PID 1's domain, or
/// gives it another: neither is the unconfined service domain.
#[test]
fn a_policy_without_the_change_to_the_unconfined_service_domain_fails() {
    let own = FakeSelinux {
        entered: INIT.to_string(),
        ..FakeSelinux::targeted()
    };
    let unfit = check_start(&own, PROGRAM_LABEL).unwrap_err();
    assert_eq!(
        unfit,
        Unfit::OwnDomain {
            pid1: INIT.to_string()
        }
    );
    assert_eq!(unfit.effect(), Effect::Confined);
    assert!(
        unfit.to_string().starts_with("runs in PID 1's own domain"),
        "{unfit}"
    );

    let elsewhere = FakeSelinux {
        entered: "system_u:system_r:bin_service_t:s0".to_string(),
        ..FakeSelinux::targeted()
    };
    let unfit = check_start(&elsewhere, PROGRAM_LABEL).unwrap_err();
    assert!(matches!(unfit, Unfit::Elsewhere { .. }), "{unfit:?}");
    assert_eq!(unfit.effect(), Effect::Confined);
    assert!(
        unfit
            .to_string()
            .starts_with("runs in system_u:system_r:bin_service_t:s0, not in unconfined_service_t"),
        "{unfit}"
    );
}

/// Each permission the change of domain needs: without `transition` or
/// `entrypoint` the start fails; without `nnp_transition` or
/// `nosuid_transition`, or with the capability off, the kernel keeps PID 1's
/// domain.
#[test]
fn every_permission_of_the_change_is_needed() {
    for (class, perm, effect) in [
        ("process", "transition", Effect::NotStarted),
        ("process2", "nnp_transition", Effect::Confined),
        ("process2", "nosuid_transition", Effect::Confined),
        ("file", "entrypoint", Effect::NotStarted),
    ] {
        let selinux = FakeSelinux {
            denied: vec![(class, perm)],
            ..FakeSelinux::targeted()
        };
        let unfit = check_start(&selinux, PROGRAM_LABEL).unwrap_err();
        let Unfit::Denied {
            class: denied_class,
            perms,
            ..
        } = &unfit
        else {
            panic!("{class} {perm}: {unfit:?}");
        };
        assert_eq!((*denied_class, perms.as_slice()), (class, &[perm][..]));
        assert_eq!(unfit.effect(), effect, "{class} {perm}");
        assert!(unfit.to_string().contains(perm), "{unfit}");
    }
    let off = FakeSelinux {
        capability: false,
        ..FakeSelinux::targeted()
    };
    let unfit = check_start(&off, PROGRAM_LABEL).unwrap_err();
    assert_eq!(unfit, Unfit::Capability);
    assert_eq!(unfit.effect(), Effect::Confined);
    assert!(unfit.to_string().contains(NNP_NOSUID), "{unfit}");
}

/// A policy that cannot be asked, as with no selinuxfs mounted or a caller
/// the policy does not let ask, and answers without a type fail the check.
#[test]
fn a_policy_that_cannot_be_asked_fails() {
    let unreadable = FakeSelinux {
        pid1_error: Some(libc::EACCES),
        ..FakeSelinux::targeted()
    };
    let unfit = check_start(&unreadable, PROGRAM_LABEL).unwrap_err();
    assert!(matches!(unfit, Unfit::Unjudged(_)), "{unfit:?}");
    assert_eq!(unfit.effect(), Effect::Unknown);
    assert!(
        unfit
            .to_string()
            .starts_with("cannot be judged against the loaded SELinux policy: PID 1's context"),
        "{unfit}"
    );

    let unasked = FakeSelinux {
        policy_error: Some(libc::ENOENT),
        ..FakeSelinux::targeted()
    };
    let unfit = check_start(&unasked, PROGRAM_LABEL).unwrap_err();
    assert!(
        unfit.to_string().contains("the policy cannot be asked"),
        "{unfit}"
    );

    let typeless = FakeSelinux {
        entered: "kernel".to_string(),
        ..FakeSelinux::targeted()
    };
    assert!(matches!(
        check_start(&typeless, PROGRAM_LABEL),
        Err(Unfit::Unjudged(_))
    ));
}

/// Before a switch the copy takes the label again and the start is checked:
/// either failing keeps the switch from being armed, and says why.
#[test]
fn a_copy_is_ready_once_labelled_and_started_in_the_domain() {
    let dir = tempfile::tempdir().unwrap();
    let copy = dir.path().join("control");
    std::fs::write(&copy, b"\x7fELF").unwrap();
    let selinux = FakeSelinux::targeted();
    ready(&selinux, &copy, PROGRAM_LABEL).unwrap();
    assert_eq!(selinux.labels_written().len(), 1);

    let refused = FakeSelinux {
        write_error: Some(libc::EACCES),
        ..FakeSelinux::targeted()
    };
    let not_ready = ready(&refused, &copy, PROGRAM_LABEL).unwrap_err();
    assert!(
        matches!(not_ready, NotReady::Unlabelled(_)),
        "{not_ready:?}"
    );
    assert!(
        refused.questions().is_empty(),
        "nothing asked before the label"
    );
    let text = not_ready_text(&copy, PROGRAM_LABEL, &not_ready);
    assert!(
        text.starts_with(&format!(
            "the RAM copy of the binary at {}, which must carry the SELinux label \
             system_u:object_r:bin_t:s0, could not take the label: ",
            copy.display()
        )),
        "{text}"
    );

    let own = FakeSelinux {
        entered: INIT.to_string(),
        ..FakeSelinux::targeted()
    };
    let not_ready = ready(&own, &copy, PROGRAM_LABEL).unwrap_err();
    assert!(matches!(
        not_ready,
        NotReady::Unfit(Unfit::OwnDomain { .. })
    ));
    let text = not_ready_text(&copy, PROGRAM_LABEL, &not_ready);
    assert!(
        text.starts_with(&format!(
            "PID 1's start of the RAM copy of the binary at {}, labelled \
             system_u:object_r:bin_t:s0, runs in PID 1's own domain",
            copy.display()
        )),
        "{text}"
    );
}

/// The label is the one a targeted policy gives the system's programs, and
/// the domain the one it starts them in from PID 1.
#[test]
fn the_label_and_the_domain_are_those_of_the_system_s_programs() {
    assert_eq!(PROGRAM_LABEL, "system_u:object_r:bin_t:s0");
    assert_eq!(type_of(PROGRAM_LABEL), Some("bin_t"));
    assert_eq!(DOMAIN, "unconfined_service_t");
}

/// A copy for the domain check to label: a regular file in its own directory.
fn copy_in(dir: &tempfile::TempDir) -> std::path::PathBuf {
    let copy = dir.path().join("control");
    std::fs::write(&copy, b"\x7fELF").unwrap();
    copy
}

/// A start again that must not come.
fn never() -> io::Error {
    panic!("the unit must not start itself again")
}

/// A unit PID 1 did not start is asked nothing, and one where no policy is
/// loaded only that: neither writes a label nor starts itself again.
#[test]
fn a_unit_outside_the_check_s_reach_is_asked_nothing_or_only_for_a_policy() {
    let dir = tempfile::tempdir().unwrap();
    let copy = copy_in(&dir);
    let in_pid1 = FakeSelinux {
        current: INIT.to_string(),
        ..FakeSelinux::targeted()
    };
    enter_domain(&in_pid1, &copy, false, false, never).unwrap();
    assert!(in_pid1.questions().is_empty());

    let without = FakeSelinux::without_policy();
    enter_domain(&without, &copy, true, false, never).unwrap();
    assert_eq!(without.questions(), ["pid1"]);
    assert!(without.labels_written().is_empty());
}

/// A unit that runs in the unconfined service domain goes on, as the start
/// again does once it runs there: no label, no start again.
#[test]
fn a_unit_in_the_unconfined_service_domain_goes_on() {
    let dir = tempfile::tempdir().unwrap();
    let copy = copy_in(&dir);
    for again in [false, true] {
        let selinux = FakeSelinux::targeted();
        enter_domain(&selinux, &copy, true, again, never).unwrap();
        assert_eq!(selinux.questions(), ["pid1", "current"]);
        assert!(selinux.labels_written().is_empty());
    }
}

/// A unit PID 1 started in its own domain, as from a copy that took the
/// label of the files in `/run` again at the switch, gives the copy the
/// label again and starts itself again from it; only a start again that
/// fails comes back, with its error.
#[test]
fn a_unit_in_pid_1_s_domain_labels_its_copy_again_and_starts_again() {
    let dir = tempfile::tempdir().unwrap();
    let copy = copy_in(&dir);
    let selinux = FakeSelinux {
        current: INIT.to_string(),
        ..FakeSelinux::targeted()
    };
    let mut started = 0;
    let outside = enter_domain(&selinux, &copy, true, false, || {
        started += 1;
        io::Error::from_raw_os_error(libc::EACCES)
    })
    .unwrap_err();
    assert_eq!(started, 1);
    let Outside::NotStarted(error) = outside else {
        panic!("expected the failed start again, got {outside:?}");
    };
    assert_eq!(error.raw_os_error(), Some(libc::EACCES));
    assert_eq!(
        selinux.labels_written(),
        [b"system_u:object_r:bin_t:s0\0".to_vec()]
    );

    // So does one that a context of its own keeps in another domain.
    let elsewhere = FakeSelinux {
        current: "system_u:system_r:udev_t:s0-s0:c0.c1023".to_string(),
        ..FakeSelinux::targeted()
    };
    let outside = enter_domain(&elsewhere, &copy, true, false, || {
        io::Error::from_raw_os_error(libc::EPERM)
    })
    .unwrap_err();
    assert!(matches!(outside, Outside::NotStarted(_)), "{outside:?}");
    assert_eq!(elsewhere.labels_written().len(), 1);
}

/// The start again that still runs outside the unconfined service domain
/// fails at once, with the context it runs in: it labels nothing and does
/// not start itself once more.
#[test]
fn the_start_again_outside_the_domain_fails_with_its_context() {
    let dir = tempfile::tempdir().unwrap();
    let copy = copy_in(&dir);
    let selinux = FakeSelinux {
        current: format!("{INIT}\0"),
        ..FakeSelinux::targeted()
    };
    let outside = enter_domain(&selinux, &copy, true, true, never).unwrap_err();
    let Outside::Still(context) = outside else {
        panic!("expected the start again still outside, got {outside:?}");
    };
    assert_eq!(context, format!("{INIT}\0"));
    assert!(selinux.labels_written().is_empty());
    // A context with no type is no domain either.
    let typeless = FakeSelinux {
        current: "kernel".to_string(),
        ..FakeSelinux::targeted()
    };
    assert!(matches!(
        enter_domain(&typeless, &copy, true, true, never),
        Err(Outside::Still(_))
    ));
    assert_ne!(UNCONFINED, INIT);
}

/// A unit whose copy does not take the label again, or is not there, does
/// not start itself again; one that cannot read whether a policy is loaded,
/// or its own context, fails as well.
#[test]
fn a_unit_that_cannot_label_its_copy_or_read_its_context_fails() {
    let dir = tempfile::tempdir().unwrap();
    let copy = copy_in(&dir);
    let refused = FakeSelinux {
        current: INIT.to_string(),
        write_error: Some(libc::EOPNOTSUPP),
        ..FakeSelinux::targeted()
    };
    let outside = enter_domain(&refused, &copy, true, false, never).unwrap_err();
    assert!(
        matches!(outside, Outside::Unlabelled(Unlabelled::Write(_))),
        "{outside:?}"
    );
    let outside = enter_domain(
        &FakeSelinux {
            current: INIT.to_string(),
            ..FakeSelinux::targeted()
        },
        &dir.path().join("missing"),
        true,
        false,
        never,
    )
    .unwrap_err();
    assert!(
        matches!(outside, Outside::Unlabelled(Unlabelled::Open(_))),
        "{outside:?}"
    );

    let unread = FakeSelinux {
        current_error: Some(libc::EINVAL),
        ..FakeSelinux::targeted()
    };
    let outside = enter_domain(&unread, &copy, true, false, never).unwrap_err();
    assert!(
        matches!(&outside, Outside::Unread(e) if e.raw_os_error() == Some(libc::EINVAL)),
        "{outside:?}"
    );
    let untold = FakeSelinux {
        pid1_error: Some(libc::ENOENT),
        ..FakeSelinux::targeted()
    };
    let outside = enter_domain(&untold, &copy, true, false, never).unwrap_err();
    assert!(
        matches!(&outside, Outside::Unread(e) if e.raw_os_error() == Some(libc::ENOENT)),
        "{outside:?}"
    );
    assert_eq!(untold.questions(), ["pid1"]);
}

/// The fake's late write error: the labels before it are written, the rest
/// fail.
#[test]
fn a_late_write_error_fails_only_the_labels_after_it() {
    let file = tempfile::tempfile().unwrap();
    let selinux = FakeSelinux {
        write_error: Some(libc::EOPNOTSUPP),
        write_error_from: Some(1),
        ..FakeSelinux::targeted()
    };
    label_file(&selinux, file.as_fd(), PROGRAM_LABEL).unwrap();
    assert!(matches!(
        label_file(&selinux, file.as_fd(), PROGRAM_LABEL),
        Err(Unlabelled::Write(_))
    ));
    assert_eq!(selinux.labels_written().len(), 1);
}

/// Each reason a unit runs outside the domain reads as a clause, as the
/// transition step keeps it for the refusal of its switch.
#[test]
fn each_reason_a_unit_runs_outside_the_domain_reads_as_a_clause() {
    for (outside, text) in [
        (
            Outside::Unread(io::Error::from_raw_os_error(libc::ENOENT)),
            "whether a policy is loaded, or the context it runs in, could not be read: No such \
             file or directory (os error 2)",
        ),
        (
            Outside::Unlabelled(Unlabelled::NotAFile),
            "its RAM copy is not a regular file",
        ),
        (
            Outside::NotStarted(io::Error::from_raw_os_error(libc::EACCES)),
            "it could not start itself again from its RAM copy: Permission denied (os error 13)",
        ),
        (
            Outside::Still(INIT.to_string()),
            "it runs in system_u:system_r:init_t:s0, though it started itself again from its \
             RAM copy with the label",
        ),
    ] {
        assert_eq!(outside.to_string(), text);
    }
}

/// A unit run by hand is asked nothing and never starts itself again; one
/// PID 1 started starts itself again from the copy it checks, as its start
/// says.
#[test]
fn a_unit_run_by_hand_is_asked_nothing_and_one_pid_1_started_starts_from_its_copy() {
    let dir = tempfile::tempdir().unwrap();
    let copy = copy_in(&dir);
    let in_pid1 = || FakeSelinux {
        current: INIT.to_string(),
        ..FakeSelinux::targeted()
    };
    let selinux = in_pid1();
    Started::by_hand().enter_domain(&selinux, &copy).unwrap();
    assert!(selinux.questions().is_empty());
    assert!(selinux.labels_written().is_empty());
    assert_eq!(
        (Started::by_hand().start_again)(&copy).kind(),
        io::ErrorKind::Other
    );

    fn refused(copy: &Path) -> io::Error {
        io::Error::other(format!("not started from {}", copy.display()))
    }
    let by_pid1 = Started {
        by_pid1: true,
        again: false,
        start_again: refused,
    };
    let outside = by_pid1.enter_domain(&in_pid1(), &copy).unwrap_err();
    assert_eq!(
        outside.to_string(),
        format!(
            "it could not start itself again from its RAM copy: not started from {}",
            copy.display()
        )
    );
    let again = Started {
        again: true,
        ..by_pid1
    };
    assert!(matches!(
        again.enter_domain(&in_pid1(), &copy),
        Err(Outside::Still(_))
    ));
}
