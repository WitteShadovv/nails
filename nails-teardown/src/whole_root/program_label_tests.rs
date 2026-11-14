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
        fn exec_context(&self, source: &str, file: &str) -> io::Result<String> {
            self.0.exec_context(source, file)
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
