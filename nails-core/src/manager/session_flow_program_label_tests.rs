// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The SELinux label of the RAM copies of the binary, through the manager:
//! the copy takes it only where the host facts leave SELinux possible, the
//! units and the drop-in are the same either way, and an entry whose policy
//! would keep NAILS's steps confined is refused before it writes anything.

use super::*;
use crate::session::program_label::{CHECK, PROGRAM_LABEL};
use nails_teardown::test_support::FakeSelinux;
use nails_teardown::whole_root::transition::{DROPIN_DIR, DROPIN_NAME};

/// A Debian host as the facts read it: AppArmor among the kernel's security
/// modules, and no SELinux.
fn debian() -> crate::platform::HostProfile {
    let mut profile = FakePlatform::fhs().host_profile();
    profile.lsms = [
        "lockdown",
        "capability",
        "landlock",
        "yama",
        "apparmor",
        "bpf",
    ]
    .map(str::to_string)
    .to_vec();
    profile
}

/// A host whose kernel lists SELinux among its security modules while no
/// selinuxfs is mounted: the copies take the label, and the uppers' labels
/// are copied on a best effort basis, so a decoy without labels enters.
fn selinux_kernel() -> crate::platform::HostProfile {
    let mut profile = FakePlatform::fhs().host_profile();
    profile.lsms = ["capability", "selinux"].map(str::to_string).to_vec();
    profile.selinux = Some(crate::platform::SelinuxStatus {
        selinuxfs: Selinuxfs::NotMounted,
        enforce: None,
        config_mode: Some("enforcing".to_string()),
        config_policy: Some("targeted".to_string()),
    });
    profile
}

/// On a host whose facts rule SELinux out the copy takes no label and the
/// plan records none; on one whose kernel lists SELinux it takes the label of
/// the system's programs, written through the running kernel and read back.
/// The drop-in and the hidden session's units are byte for byte the same.
#[test]
fn the_copy_takes_the_label_only_where_selinux_may_run_and_no_unit_changes() {
    let _ = Rerun::new(crate::test_path!(
        the_copy_takes_the_label_only_where_selinux_may_run_and_no_unit_changes
    ))
    .in_user_mount_ns()
    .run(|| {
        let decoy = unlabelled_fhs_decoy();
        let options = EnterOptions {
            binary: PathBuf::from("/proc/self/exe"),
            ..EnterOptions::default()
        };
        let mut written = Vec::new();
        for (profile, label) in [(debian(), None), (selinux_kernel(), Some(PROGRAM_LABEL))] {
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
            m.config.backend_watch.enabled = true;
            m.set_host_profile(profile);
            let host = FakeEntryHost::default();

            let outcome = m
                .enter_session_no_preflight_on(&machine, &options, &host)
                .unwrap();

            assert!(
                matches!(outcome, EnterOutcome::Prepared { .. }),
                "{outcome:?}"
            );
            let text = std::fs::read_to_string(machine.paths.plan()).unwrap();
            let plan = Plan::from_json(&text).unwrap();
            assert_eq!(plan.program_label.as_deref(), label);
            assert_eq!(text.contains("program_label"), label.is_some(), "{text}");
            let copy = machine.paths.binary_copy();
            match label {
                None => assert_eq!(selinux_label(&copy), Err(rustix::io::Errno::NODATA)),
                Some(label) => {
                    assert_eq!(
                        selinux_label(&copy).unwrap(),
                        format!("{label}\0").into_bytes()
                    );
                }
            }
            let dropin =
                std::fs::read(machine.paths.run.join(DROPIN_DIR).join(DROPIN_NAME)).unwrap();
            assert!(!plan.session_units.is_empty());
            written.push((dropin, plan.session_units));
            entry::rollback(&machine.paths);
        }
        assert_eq!(
            written[0], written[1],
            "the units and the drop-in are the same"
        );
    });
}

/// Where the copies take the label and the loaded policy would start a
/// program of that label from PID 1 in PID 1's own domain, or not at all, the
/// entry is refused before it writes anything: no runtime directory, no
/// drop-in and no reload, and nothing recorded.
#[test]
fn an_entry_whose_policy_keeps_the_steps_confined_is_refused_before_anything_is_written() {
    let _ = Rerun::new(crate::test_path!(
        an_entry_whose_policy_keeps_the_steps_confined_is_refused_before_anything_is_written
    ))
    .in_user_mount_ns()
    .run(|| {
        let decoy = unlabelled_fhs_decoy();
        let options = EnterOptions {
            binary: PathBuf::from("/proc/self/exe"),
            ..EnterOptions::default()
        };
        for (selinux, what) in [
            (
                FakeSelinux {
                    entered: "system_u:system_r:init_t:s0".to_string(),
                    ..FakeSelinux::targeted()
                },
                "runs in PID 1's own domain",
            ),
            (
                FakeSelinux {
                    denied: vec![("process", "transition")],
                    ..FakeSelinux::targeted()
                },
                "would not start, and a switch would go on without its step",
            ),
        ] {
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
            m.set_host_profile(selinux_kernel());
            let host = FakeEntryHost {
                selinux: Some(selinux),
                ..FakeEntryHost::default()
            };

            let error = m
                .enter_session_no_preflight_on(&machine, &options, &host)
                .unwrap_err();

            let NailsError::PreFlightCheckFailed(failures) = &error else {
                panic!("expected the program label's refusal, got {error:?}");
            };
            assert_eq!(failures[0].0, CHECK, "{error}");
            assert!(failures[0].1.contains(what), "{error}");
            assert!(!machine.paths.runtime().exists(), "nothing written");
            assert!(!machine.paths.run.join(DROPIN_DIR).exists());
            assert_eq!(host.reloads.get(), 0, "no drop-in to load");
            assert!(
                host.selinux
                    .as_ref()
                    .is_some_and(|selinux| selinux.labels_written().is_empty())
            );
            assert!(!hidden.path().join("state.json").exists());
        }
    });
}
