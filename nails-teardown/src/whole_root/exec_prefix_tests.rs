// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::test_support::{BIN_T, FakeSelinux, INIT_T, UNCONFINED_SERVICE_T, write_executable};
use crate::whole_root::boot_records::{FIXUP_BINARY, FIXUP_DIR_PATH};
use crate::whole_root::plan::{BINARY_NAME, RUNTIME_DIR};
use std::os::unix::fs::symlink;

/// A kernel without SELinux: the file alone decides.
const OFF: FakeSelinux = FakeSelinux {
    pid1: None,
    labels: Vec::new(),
    starts: Vec::new(),
    denials: Vec::new(),
    unanswered: None,
};

#[test]
fn without_a_prefix_the_copy_starts_as_before_and_with_one_through_it() {
    let binary = Path::new("/run/overlay-runtime/control");
    assert_eq!(command(None, binary), "/run/overlay-runtime/control");
    assert_eq!(
        command(Some(Path::new(TRAMPOLINE)), binary),
        "/usr/bin/env /run/overlay-runtime/control"
    );
}

/// Every copy PID 1 starts lies at a path that `env` takes for the program
/// to run, never for an option or a variable to set, and that a unit file
/// line holds word for word.
#[test]
fn the_trampoline_and_every_copy_are_plain_paths() {
    assert!(is_plain(Path::new(TRAMPOLINE)));
    for copy in [
        Path::new(RUNTIME_DIR).join(BINARY_NAME),
        Path::new(FIXUP_DIR_PATH).join(FIXUP_BINARY),
    ] {
        assert!(is_plain(&copy), "{}", copy.display());
    }
}

#[test]
fn only_an_absolute_path_of_plain_names_is_plain() {
    for plain in ["/usr/bin/env", "/bin/x86_64-env+1.2", "/.env"] {
        assert!(is_plain(Path::new(plain)), "{plain}");
    }
    for odd in [
        "",
        "/",
        "usr/bin/env",
        "./env",
        "/usr//bin/env",
        "/usr/bin/env/",
        "/usr/./bin/env",
        "/usr/../bin/env",
        "/usr/bin/my env",
        "/usr/bin/%n",
        "/usr/bin/$ENV",
        "/usr/bin/a\\x20b",
        "/usr/bin/\"env\"",
        "/usr/bin/a;b",
        "/usr/bin/a=b",
        "/usr/bin/\u{e9}nv",
        "/usr/bin/env\n",
    ] {
        assert!(!is_plain(Path::new(odd)), "{odd:?}");
    }
}

#[test]
fn a_root_holds_the_prefix_only_as_an_executable_file() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    let env = Path::new(TRAMPOLINE);
    assert_eq!(check(root, env, &OFF), Err(Unusable::Absent));

    std::fs::create_dir_all(root.join("usr/bin")).unwrap();
    std::fs::create_dir(root.join("usr/bin/env")).unwrap();
    assert_eq!(
        check(root, env, &OFF),
        Err(Unusable::NotExecutable),
        "a folder"
    );
    std::fs::remove_dir(root.join("usr/bin/env")).unwrap();

    write_executable(&root.join("usr/bin/env"), "#!/bin/sh\n", 0o644);
    assert_eq!(
        check(root, env, &OFF),
        Err(Unusable::NotExecutable),
        "no x bit"
    );

    write_executable(&root.join("usr/bin/env"), "#!/bin/sh\n", 0o755);
    assert_eq!(check(root, env, &OFF), Ok(()));

    assert_eq!(
        check(root, Path::new("/usr/bin/../bin/env"), &OFF),
        Err(Unusable::NotPlain)
    );
}

/// A multi-call build of the tools installs `env` as a link to one
/// program: it starts as that program does, and the link is followed
/// inside the root, as PID 1 follows it once the root is its own.
#[test]
fn a_link_is_followed_inside_the_root() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    let env = Path::new(TRAMPOLINE);
    std::fs::create_dir_all(root.join("usr/bin")).unwrap();
    symlink("coreutils", root.join("usr/bin/env")).unwrap();
    assert_eq!(
        check(root, env, &OFF),
        Err(Unusable::Absent),
        "a link to nothing"
    );
    write_executable(&root.join("usr/bin/coreutils"), "", 0o755);
    assert_eq!(check(root, env, &OFF), Ok(()));

    // An absolute link resolves in the root, never on the running system,
    // where /usr/bin/env exists.
    std::fs::remove_file(root.join("usr/bin/env")).unwrap();
    symlink("/usr/bin/missing", root.join("usr/bin/env")).unwrap();
    assert_eq!(check(root, env, &OFF), Err(Unusable::Absent));
    symlink("/usr/bin/coreutils", root.join("usr/bin/missing")).unwrap();
    assert_eq!(check(root, env, &OFF), Ok(()));

    // A loop of links is no program either.
    std::fs::remove_file(root.join("usr/bin/missing")).unwrap();
    symlink("/usr/bin/env", root.join("usr/bin/missing")).unwrap();
    assert!(
        matches!(check(root, env, &OFF), Err(Unusable::Unreachable(_))),
        "{:?}",
        check(root, env, &OFF)
    );
}

#[test]
fn the_reasons_read_after_the_path_in_a_sentence() {
    assert_eq!(Unusable::Absent.to_string(), "does not exist");
    assert_eq!(
        Unusable::Unreachable("Too many levels of symbolic links (os error 40)".into()).to_string(),
        "cannot be looked up: Too many levels of symbolic links (os error 40)"
    );
    assert_eq!(
        Unusable::NotExecutable.to_string(),
        "is not an executable file"
    );
    assert_eq!(
        Unusable::NotPlain.to_string(),
        "is not an absolute path of plain names"
    );
}

/// A root whose `/usr/bin/env` is an executable file.
fn root_with_env() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("usr/bin")).unwrap();
    write_executable(&root.path().join("usr/bin/env"), "", 0o755);
    root
}

/// Where a policy is loaded, the label of the file decides as well: one the
/// targeted policy starts in a service domain passes, whatever else stands at
/// the path.
#[test]
fn a_loaded_policy_must_start_the_prefix_in_a_domain_of_its_own() {
    let root = root_with_env();
    let root = root.path();
    let env = Path::new(TRAMPOLINE);
    let targeted = FakeSelinux::targeted().with_label(root, BIN_T);
    assert_eq!(check(root, env, &targeted), Ok(()));

    // A label the policy gives no domain of its own, as a configuration
    // file's: the step would run in PID 1's domain.
    let etc = FakeSelinux::targeted().with_label(root, "system_u:object_r:etc_t:s0");
    let error = check(root, env, &etc).unwrap_err();
    assert_eq!(
        error,
        Unusable::OwnDomain {
            label: "system_u:object_r:etc_t:s0".to_string(),
            pid1: INIT_T.to_string(),
        }
    );
    assert_eq!(error.effect(), Effect::OwnDomain);
    assert_eq!(error.remedy(), Remedy::Label);
    assert_eq!(
        error.to_string(),
        "is labelled system_u:object_r:etc_t:s0, which the loaded SELinux policy gives no domain \
         of its own when PID 1 (system_u:system_r:init_t:s0) starts it"
    );

    // Only the type counts: a start that keeps PID 1's type at another level
    // keeps its domain.
    let level = FakeSelinux {
        starts: vec![(INIT_T, BIN_T, "system_u:system_r:init_t:s0-s0:c0.c1023")],
        ..targeted.clone()
    };
    assert!(matches!(
        check(root, env, &level),
        Err(Unusable::OwnDomain { .. })
    ));
}

/// A file PID 1 may not start, as one a hidden session moved there from
/// root's home, does not start at all.
#[test]
fn a_loaded_policy_must_let_pid_1_start_the_prefix() {
    let root = root_with_env();
    let root = root.path();
    let env = Path::new(TRAMPOLINE);
    const HOME: &str = "unconfined_u:object_r:admin_home_t:s0";
    let home = FakeSelinux {
        denials: vec![
            (INIT_T, HOME, "file", "execute"),
            (INIT_T, HOME, "file", "open"),
        ],
        ..FakeSelinux::targeted().with_label(root, HOME)
    };
    let error = check(root, env, &home).unwrap_err();
    assert_eq!(
        error,
        Unusable::Denied {
            label: HOME.to_string(),
            pid1: INIT_T.to_string(),
            denial: Denial::Start(vec!["execute", "open"]),
        }
    );
    assert_eq!(error.effect(), Effect::NotStarted);
    assert_eq!(error.remedy(), Remedy::Label);
    assert_eq!(
        error.to_string(),
        "is labelled unconfined_u:object_r:admin_home_t:s0, and the loaded SELinux policy does not \
         let PID 1 (system_u:system_r:init_t:s0) execute or open it"
    );

    // The domain the policy gives the start must be one PID 1 may change to,
    // and one the file may be entered through.
    for (denial, said) in [
        (
            (INIT_T, UNCONFINED_SERVICE_T, "process", "transition"),
            "gives PID 1's start of it the domain system_u:system_r:unconfined_service_t:s0 but \
             does not let PID 1 (system_u:system_r:init_t:s0) change to it",
        ),
        (
            (UNCONFINED_SERVICE_T, BIN_T, "file", "entrypoint"),
            "gives PID 1's start of it the domain system_u:system_r:unconfined_service_t:s0 but \
             does not let that domain be entered through it",
        ),
    ] {
        let policy = FakeSelinux {
            denials: vec![denial],
            ..FakeSelinux::targeted().with_label(root, BIN_T)
        };
        let error = check(root, env, &policy).unwrap_err();
        assert_eq!(error.effect(), Effect::NotStarted);
        assert_eq!(
            error.to_string(),
            format!("is labelled system_u:object_r:bin_t:s0, and the loaded SELinux policy {said}")
        );
    }
}

/// A policy that cannot be asked, or a label or context that cannot be read,
/// fails the check: nothing tells where the step would run.
#[test]
fn a_policy_that_cannot_be_asked_fails_the_check() {
    let root = root_with_env();
    let root = root.path();
    let env = Path::new(TRAMPOLINE);
    let unanswered = FakeSelinux {
        unanswered: Some("/sys/fs/selinux/access: No such file or directory (os error 2)"),
        ..FakeSelinux::targeted().with_label(root, BIN_T)
    };
    let error = check(root, env, &unanswered).unwrap_err();
    assert_eq!(error.effect(), Effect::Unknown);
    assert_eq!(error.remedy(), Remedy::Policy);
    assert_eq!(
        error.to_string(),
        "cannot be judged against the loaded SELinux policy: the policy cannot be asked: \
         /sys/fs/selinux/access: No such file or directory (os error 2)"
    );

    // No label given: the file's own attribute is read, and a file on a
    // kernel without SELinux has none to give. (A kernel that runs SELinux
    // labels every file.)
    if !Path::new(crate::whole_root::selinux::SELINUXFS).exists() {
        let unlabelled = FakeSelinux::targeted();
        let Err(Unusable::Unjudged(why)) = check(root, env, &unlabelled) else {
            panic!("expected the label read to fail");
        };
        assert!(why.starts_with("its label cannot be read: "), "{why}");
    }

    // A context without a type is no domain to compare.
    let odd = FakeSelinux {
        pid1: Some("init"),
        ..FakeSelinux::targeted().with_label(root, BIN_T)
    };
    assert_eq!(
        check(root, env, &odd),
        Err(Unusable::Unjudged(
            "init or init is no SELinux context with a type".to_string()
        ))
    );
}

/// The file is checked first: a policy is asked only about a program that is
/// there, and about nothing where no policy is loaded.
#[test]
fn the_policy_is_asked_only_about_a_program_that_is_there() {
    let root = tempfile::tempdir().unwrap();
    let unanswered = FakeSelinux {
        unanswered: Some("not to be asked"),
        ..FakeSelinux::targeted()
    };
    assert_eq!(
        check(root.path(), Path::new(TRAMPOLINE), &unanswered),
        Err(Unusable::Absent)
    );
    assert_eq!(Unusable::Absent.effect(), Effect::NotStarted);
    assert_eq!(Unusable::Absent.remedy(), Remedy::Program);
    let with = root_with_env();
    assert_eq!(check(with.path(), Path::new(TRAMPOLINE), &OFF), Ok(()));
}

#[test]
fn a_list_of_permissions_reads_as_one_denied_each() {
    assert_eq!(either(&[]), "");
    assert_eq!(either(&["execute"]), "execute");
    assert_eq!(either(&["execute", "read"]), "execute or read");
    assert_eq!(
        either(&["execute", "read", "open"]),
        "execute, read or open"
    );
}
