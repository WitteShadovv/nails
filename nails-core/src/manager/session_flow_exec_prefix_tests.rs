// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The entries through the exec prefix, through the manager: where SELinux
//! runs or may run, PID 1 starts NAILS's steps through `/usr/bin/env`, which
//! the decoy root must hold, with a label the loaded policy starts in a
//! domain of its own, and the switch's unit must leave the domain to the
//! policy. Kept apart from `session_flow_tests.rs` so each file stays within
//! the line budget of a test file.

use super::*;
use nails_teardown::test_support::FakeSelinux;

/// A host whose mount table lists a selinuxfs, with the SELinux facts a
/// targeted, enforcing host reports.
fn selinux_host() -> crate::platform::HostProfile {
    let mut profile = FakePlatform::fhs().host_profile();
    profile.selinux = Some(crate::platform::SelinuxStatus {
        selinuxfs: Selinuxfs::Mounted,
        enforce: Some(crate::platform::SelinuxMode::Enforcing),
        config_mode: Some("enforcing".to_string()),
        config_policy: Some("targeted".to_string()),
    });
    profile
}

/// Where SELinux runs, PID 1 starts NAILS's steps through `/usr/bin/env`: a
/// decoy without it is refused before the entry writes anything, as the
/// entry's own step could not start there.
#[test]
fn an_entry_on_a_host_that_runs_selinux_needs_env_on_the_decoy_before_anything_is_written() {
    let dir = tempfile::tempdir().unwrap();
    let hidden = dir.path().join("hidden");
    std::fs::create_dir_all(&hidden).unwrap();
    let machine = machine(dir.path(), DECOY_TABLE);
    let mut m = manager(&hidden);
    m.set_host_profile(selinux_host());
    let host = FakeEntryHost::default();

    let error = m
        .enter_session_no_preflight_on(&machine, &EnterOptions::default(), &host)
        .unwrap_err();

    let NailsError::PreFlightCheckFailed(failures) = &error else {
        panic!("expected the exec-prefix refusal, got {error:?}");
    };
    assert_eq!(failures[0].0, crate::session::exec_prefix::CHECK, "{error}");
    assert!(
        failures[0]
            .1
            .contains("in the decoy root /usr/bin/env does not exist"),
        "{error}"
    );
    assert!(!machine.paths.runtime().exists());
    assert_eq!(host.reloads.get(), 0, "no drop-in was written");
    assert!(!hidden.join("state.json").exists());
}

/// The decoy root's own label, as a targeted policy gives `/`.
const ROOT_LABEL: &[u8] = b"system_u:object_r:root_t:s0\0";

#[test]
fn an_entry_on_a_host_that_runs_selinux_starts_every_step_through_env() {
    // The labels this host needs are given to the decoy root, so the entry
    // gets past them: on a kernel without SELinux the namespace's root may
    // write the attribute on its own tmpfs.
    let _ = Rerun::new(crate::test_path!(
        an_entry_on_a_host_that_runs_selinux_starts_every_step_through_env
    ))
    .in_user_mount_ns()
    .run(|| {
        let decoy = unlabelled_fhs_decoy();
        rustix::fs::lsetxattr(
            decoy.path(),
            crate::session::labels::LABEL_XATTR,
            ROOT_LABEL,
            rustix::fs::XattrFlags::empty(),
        )
        .unwrap();
        let hidden = ScratchTmpfs::new("");
        let run = ScratchTmpfs::new("");
        let machine = Machine {
            paths: Paths {
                root: decoy.path().to_path_buf(),
                run: run.path().to_path_buf(),
            },
            mounts: Some(parse_mountinfo(DECOY_TABLE)),
        };
        let mut m = manager(hidden.path());
        m.set_host_profile(selinux_host());
        let options = EnterOptions {
            binary: PathBuf::from("/proc/self/exe"),
            ..EnterOptions::default()
        };
        let host = FakeEntryHost::default();

        let outcome = m
            .enter_session_no_preflight_on(&machine, &options, &host)
            .unwrap();

        let EnterOutcome::Prepared { entry, .. } = outcome else {
            panic!("expected a prepared entry, got {outcome:?}");
        };
        let env = Path::new(nails_teardown::whole_root::exec_prefix::TRAMPOLINE);
        // The plan records the program, so the way back starts its step the
        // same way and checks the same program.
        assert_eq!(entry.plan.exec_prefix.as_deref(), Some(env));
        // The step's drop-in, written once for both directions.
        assert_eq!(
            std::fs::read_to_string(
                run.path()
                    .join(nails_teardown::whole_root::transition::DROPIN_DIR)
                    .join(nails_teardown::whole_root::transition::DROPIN_NAME)
            )
            .unwrap(),
            nails_teardown::whole_root::transition::dropin_text(
                Path::new("/run/overlay-runtime/control"),
                Some(env)
            )
        );
        // The hidden session's own units: the watcher, at least.
        assert!(!entry.plan.session_units.is_empty());
        assert_eq!(
            entry.plan.session_units,
            crate::session::units::session_units(m.config(), Some(env))
        );
        entry::rollback(&machine.paths);
    });
}

/// Where SELinux runs, the decoy's PID 1 must start the transition step
/// through `/usr/bin/env` in the domain the policy gives it. With
/// `NoNewPrivileges=yes` on `systemd-soft-reboot.service` it may not, so the
/// entry is refused once the drop-in is loaded, and undone.
#[test]
fn an_entry_whose_switch_unit_keeps_pid_1_s_domain_is_refused_and_undone() {
    let _ = Rerun::new(crate::test_path!(
        an_entry_whose_switch_unit_keeps_pid_1_s_domain_is_refused_and_undone
    ))
    .in_user_mount_ns()
    .run(|| {
        let decoy = fhs_decoy();
        let hidden = ScratchTmpfs::new("");
        let run = ScratchTmpfs::new("");
        let machine = Machine {
            paths: Paths {
                root: decoy.path().to_path_buf(),
                run: run.path().to_path_buf(),
            },
            mounts: Some(parse_mountinfo(DECOY_TABLE)),
        };
        let mut m = manager(hidden.path());
        m.set_host_profile(selinux_host());
        let options = EnterOptions {
            binary: PathBuf::from("/proc/self/exe"),
            ..EnterOptions::default()
        };
        let host = FakeEntryHost {
            no_new_privileges: Some("yes"),
            ..FakeEntryHost::default()
        };

        let error = m
            .enter_session_no_preflight_on(&machine, &options, &host)
            .unwrap_err();

        let NailsError::PreFlightCheckFailed(failures) = &error else {
            panic!("expected the exec-prefix refusal, got {error:?}");
        };
        assert_eq!(failures[0].0, crate::session::exec_prefix::CHECK, "{error}");
        assert!(
            failures[0].1.contains(
                "systemd-soft-reboot.service, whose start runs the last step before the \
                 switch, has NoNewPrivileges=yes with every drop-in loaded"
            ),
            "{error}"
        );
        assert!(!machine.paths.runtime().exists());
        assert!(
            !run.path()
                .join(nails_teardown::whole_root::transition::DROPIN_DIR)
                .exists()
        );
        assert_eq!(host.reloads.get(), 2, "one loads the drop-in, one drops it");
        assert!(!hidden.path().join("state.json").exists());
    });
}

/// Where a policy is loaded, the decoy's `/usr/bin/env` must carry a label
/// the policy starts in a domain of its own: one it gives none, as a
/// configuration file's, is refused before the entry writes anything, as the
/// entry's own step would run in PID 1's domain.
#[test]
fn an_entry_whose_decoy_env_keeps_pid_1_s_domain_is_refused_before_anything_is_written() {
    let dir = tempfile::tempdir().unwrap();
    let hidden = dir.path().join("hidden");
    std::fs::create_dir_all(&hidden).unwrap();
    let machine = machine(dir.path(), DECOY_TABLE);
    std::fs::create_dir_all(machine.paths.root.join("usr/bin")).unwrap();
    write_executable(&machine.paths.root.join("usr/bin/env"), "", 0o755);
    let mut m = manager(&hidden);
    m.set_host_profile(selinux_host());
    let host = FakeEntryHost {
        selinux: FakeSelinux::targeted()
            .with_label(&machine.paths.root, "system_u:object_r:etc_t:s0"),
        ..FakeEntryHost::default()
    };

    let error = m
        .enter_session_no_preflight_on(&machine, &EnterOptions::default(), &host)
        .unwrap_err();

    let NailsError::PreFlightCheckFailed(failures) = &error else {
        panic!("expected the exec-prefix refusal, got {error:?}");
    };
    assert_eq!(failures[0].0, crate::session::exec_prefix::CHECK, "{error}");
    assert!(
        failures[0].1.contains(
            "in the decoy root /usr/bin/env is labelled system_u:object_r:etc_t:s0, which the \
             loaded SELinux policy gives no domain of its own when PID 1 \
             (system_u:system_r:init_t:s0) starts it"
        ),
        "{error}"
    );
    assert!(!machine.paths.runtime().exists());
    assert_eq!(host.reloads.get(), 0, "no drop-in was written");
    assert!(!hidden.join("state.json").exists());
}

/// A kernel that lists SELinux among its security modules enforces a policy
/// it has loaded, though no selinuxfs is mounted where the activation runs:
/// the entry starts its steps through `/usr/bin/env` there, and the labels
/// stay best effort, so this decoy without labels is entered.
#[test]
fn an_entry_on_a_kernel_that_lists_selinux_starts_its_steps_through_env() {
    let _ = Rerun::new(crate::test_path!(
        an_entry_on_a_kernel_that_lists_selinux_starts_its_steps_through_env
    ))
    .in_user_mount_ns()
    .run(|| {
        let decoy = unlabelled_fhs_decoy();
        let hidden = ScratchTmpfs::new("");
        let run = ScratchTmpfs::new("");
        let machine = Machine {
            paths: Paths {
                root: decoy.path().to_path_buf(),
                run: run.path().to_path_buf(),
            },
            mounts: Some(parse_mountinfo(DECOY_TABLE)),
        };
        let mut m = manager(hidden.path());
        let mut profile = selinux_host();
        if let Some(selinux) = profile.selinux.as_mut() {
            selinux.selinuxfs = Selinuxfs::NotMounted;
        }
        profile.lsms = [
            "lockdown",
            "capability",
            "landlock",
            "yama",
            "selinux",
            "bpf",
        ]
        .map(str::to_string)
        .to_vec();
        m.set_host_profile(profile);
        let options = EnterOptions {
            binary: PathBuf::from("/proc/self/exe"),
            ..EnterOptions::default()
        };
        let host = FakeEntryHost::default();

        let outcome = m
            .enter_session_no_preflight_on(&machine, &options, &host)
            .unwrap();

        let EnterOutcome::Prepared { entry, .. } = outcome else {
            panic!("expected a prepared entry, got {outcome:?}");
        };
        assert_eq!(
            entry.plan.exec_prefix.as_deref(),
            Some(Path::new(
                nails_teardown::whole_root::exec_prefix::TRAMPOLINE
            ))
        );
        let upper = crate::session::Layout::new(hidden.path()).upper();
        assert_eq!(selinux_label(&upper), Err(rustix::io::Errno::NODATA));
        entry::rollback(&machine.paths);
    });
}
