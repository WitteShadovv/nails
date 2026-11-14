// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use nails_base::test_support::write_executable;
use nails_platform::platform::FakePlatform;
use nails_platform::{SelinuxMode, SelinuxStatus, Selinuxfs};
use std::path::PathBuf;

/// A detected FHS host with these SELinux facts.
fn host_with(selinuxfs: Selinuxfs, enforce: Option<SelinuxMode>) -> HostProfile {
    let mut profile = FakePlatform::fhs().host_profile();
    profile.selinux = Some(SelinuxStatus {
        selinuxfs,
        enforce,
        config_mode: Some("enforcing".to_string()),
        config_policy: Some("targeted".to_string()),
    });
    profile
}

/// A root whose `/usr/bin/env` is an executable file.
fn root_with_env() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("usr/bin")).unwrap();
    write_executable(&root.path().join("usr/bin/env"), "", 0o755);
    root
}

/// The one refusal `error` carries: its name, reason and fix.
fn refusal_of(error: NailsError) -> (String, String, String) {
    let NailsError::PreFlightCheckFailed(mut failures) = error else {
        panic!("expected the exec-prefix refusal, got {error:?}");
    };
    assert_eq!(failures.len(), 1, "{failures:?}");
    let (name, reason, fix) = failures.remove(0);
    (name, reason, fix.expect("the refusal says what to do"))
}

/// Where SELinux does not run, on a stock Debian, Ubuntu or NixOS host, PID 1
/// starts the copy itself: nothing changes there.
#[test]
fn a_host_without_selinux_starts_the_copy_directly() {
    for profile in [
        FakePlatform::fhs().host_profile(),
        FakePlatform::nixos().host_profile(),
    ] {
        assert_eq!(profile.selinux, None);
        assert_eq!(ExecPrefix::for_host(Some(&profile)), ExecPrefix::Direct);
    }
    // Configured once but not running: no policy reads a domain there.
    let configured = host_with(Selinuxfs::NotMounted, None);
    assert_eq!(ExecPrefix::for_host(Some(&configured)), ExecPrefix::Direct);
    assert_eq!(ExecPrefix::Direct.program(), None);
}

/// Where SELinux runs or may run, as the labels judge it, PID 1 starts the
/// copy through `/usr/bin/env`, whatever mode the policy runs in: a
/// permissive policy still gives the step PID 1's domain, and logs what it
/// would deny.
#[test]
fn a_host_that_may_run_selinux_starts_the_copy_through_env() {
    for (profile, reason) in [
        (
            Some(host_with(Selinuxfs::Mounted, Some(SelinuxMode::Enforcing))),
            Reason::SelinuxRunning,
        ),
        (
            Some(host_with(Selinuxfs::Mounted, Some(SelinuxMode::Permissive))),
            Reason::SelinuxRunning,
        ),
        (
            Some(host_with(Selinuxfs::Unknown, None)),
            Reason::MountsUnreadable,
        ),
        (None, Reason::HostUndetected),
    ] {
        let prefix = ExecPrefix::for_host(profile.as_ref());
        assert_eq!(prefix, ExecPrefix::Trampoline(reason));
        assert_eq!(prefix.program(), Some(Path::new("/usr/bin/env")));
        // The same facts require the labels, for the same reason.
        assert_eq!(Labels::for_host(profile.as_ref()), Labels::Required(reason));
    }
}

#[test]
fn starting_the_copy_directly_needs_nothing_in_either_root() {
    let empty = tempfile::tempdir().unwrap();
    for which in [Root::Decoy, Root::Next] {
        assert!(ExecPrefix::Direct.require(empty.path(), which).is_ok());
    }
}

#[test]
fn an_entry_through_env_needs_it_in_both_roots() {
    let prefix = ExecPrefix::Trampoline(Reason::SelinuxRunning);
    let with = root_with_env();
    for which in [Root::Decoy, Root::Next] {
        assert!(prefix.require(with.path(), which).is_ok());
    }

    let without = tempfile::tempdir().unwrap();
    let (name, reason, fix) = refusal_of(prefix.require(without.path(), Root::Decoy).unwrap_err());
    assert_eq!(name, CHECK);
    assert_eq!(
        reason,
        "SELinux runs on this host (selinuxfs is mounted), so PID 1 starts NAILS's own steps \
         through /usr/bin/env, and in the decoy root /usr/bin/env does not exist: the last step \
         before the switch into the hidden session, which keeps the hidden session's systemd \
         off the decoy's disks, would not start"
    );
    assert!(
        fix.starts_with("Install /usr/bin/env on the decoy"),
        "{fix}"
    );

    let (name, reason, fix) = refusal_of(
        ExecPrefix::Trampoline(Reason::HostUndetected)
            .require(without.path(), Root::Next)
            .unwrap_err(),
    );
    assert_eq!(name, CHECK);
    assert_eq!(
        reason,
        "the host could not be detected and may run SELinux, so PID 1 starts NAILS's own steps \
         through /usr/bin/env, and in the hidden root /usr/bin/env does not exist: the hidden \
         session's own units and the last step of the way back would not start"
    );
    assert!(fix.starts_with("Run `sudo "), "{fix}");
    assert!(fix.contains(" discard /usr/bin/env`"), "{fix}");
}

#[test]
fn an_env_that_is_no_executable_file_refuses_the_entry_too() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("usr/bin/env")).unwrap();
    let (_, reason, _) = refusal_of(
        ExecPrefix::Trampoline(Reason::SelinuxRunning)
            .require(root.path(), Root::Decoy)
            .unwrap_err(),
    );
    assert!(
        reason.contains("in the decoy root /usr/bin/env is not an executable file:"),
        "{reason}"
    );
}

/// The way back checks the program the plan records, whatever this host's
/// facts say now: the drop-in the entry wrote names that one.
#[test]
fn a_way_back_needs_the_plan_s_program_in_the_hidden_root() {
    let without = tempfile::tempdir().unwrap();
    let mut plan = nails_teardown::whole_root::plan::Plan::from_json(
        r#"{"version":2,"hidden_root":"/mnt/data","upper":"/mnt/data/root/upper",
            "work":"/mnt/data/root/work","decoy_root":{"source":"/dev/vda2","fstype":"ext4"},
            "decoy":{"init":"/sbin/init"},"hidden":{"init":"/sbin/init"}}"#,
    )
    .unwrap();
    // A plan without one, from a host without SELinux or written before it
    // was recorded: nothing to check.
    assert!(check_way_back(without.path(), &plan).is_ok());

    plan.exec_prefix = Some(PathBuf::from(TRAMPOLINE));
    assert!(check_way_back(root_with_env().path(), &plan).is_ok());
    let (name, reason, fix) = refusal_of(check_way_back(without.path(), &plan).unwrap_err());
    assert_eq!(name, CHECK);
    assert_eq!(
        reason,
        "PID 1 starts the last step of the way back through /usr/bin/env, and in the hidden root \
         /usr/bin/env does not exist: the switch to the decoy could go on without that step, and \
         the decoy would start with the hidden session's files in /run"
    );
    assert!(
        fix.contains(" deactivate --poweroff`, which powers off"),
        "{fix}"
    );
    assert!(fix.contains(" emergency` does here"), "{fix}");
}
