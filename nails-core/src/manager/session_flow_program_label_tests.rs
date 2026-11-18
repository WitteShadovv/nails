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

/// Whether a mount stands at or below the next root of `machine`.
fn next_root_mounted(machine: &Machine) -> bool {
    read_mountinfo()
        .unwrap()
        .iter()
        .any(|e| e.mount_point.starts_with(machine.paths.nextroot()))
}

/// A labelled entry is refused, and undone, where the decoy's PID 1, once the
/// reload has loaded the drop-in, starts `systemd-soft-reboot.service` in an
/// `SELinuxContext=` of its own, and where the copy, which took its label
/// when it was written, does not take it again right before the entry is
/// armed: no runtime directory, no drop-in and no next root are left, and
/// nothing is recorded.
#[test]
fn a_labelled_entry_is_refused_and_undone_after_the_reload_and_at_the_arm() {
    let _ = Rerun::new(crate::test_path!(
        a_labelled_entry_is_refused_and_undone_after_the_reload_and_at_the_arm
    ))
    .in_user_mount_ns()
    .run(|| {
        let decoy = unlabelled_fhs_decoy();
        let options = EnterOptions {
            binary: PathBuf::from("/proc/self/exe"),
            ..EnterOptions::default()
        };
        for (host, what) in [
            (
                FakeEntryHost {
                    selinux: Some(FakeSelinux::targeted()),
                    unit_context: "system_u:system_r:init_t:s0",
                    ..FakeEntryHost::default()
                },
                "has SELinuxContext=system_u:system_r:init_t:s0 with every drop-in loaded",
            ),
            (
                FakeEntryHost {
                    selinux: Some(FakeSelinux {
                        write_error: Some(rustix::io::Errno::OPNOTSUPP.raw_os_error()),
                        write_error_from: Some(1),
                        ..FakeSelinux::targeted()
                    }),
                    ..FakeEntryHost::default()
                },
                "must carry the SELinux label system_u:object_r:bin_t:s0, but it could not take \
                 the label",
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

            let error = m
                .enter_session_no_preflight_on(&machine, &options, &host)
                .unwrap_err();

            let NailsError::PreFlightCheckFailed(failures) = &error else {
                panic!("expected the program label's refusal, got {error:?}");
            };
            assert_eq!(failures[0].0, CHECK, "{error}");
            assert!(failures[0].1.contains(what), "{error}");
            // Written once, with the copy, before the refusal: the context is
            // asked once the drop-in is loaded, and the second label comes
            // right before the arm.
            let selinux = host.selinux.as_ref().unwrap();
            assert_eq!(selinux.labels_written().len(), 1, "{error}");
            assert!(
                host.reloads.get() >= 1,
                "refused once the drop-in was loaded"
            );
            assert!(!next_root_mounted(&machine), "the next root is detached");
            assert!(!machine.paths.runtime().exists(), "no runtime directory");
            assert!(!machine.paths.run.join(DROPIN_DIR).exists(), "no drop-in");
            assert!(
                !hidden.path().join("state.json").exists(),
                "nothing recorded"
            );
        }
    });
}

/// A plan of a session whose way back mounts `decoy` as its decoy root, a
/// read-only overlay of `decoy` over the empty directory `empty` (overlayfs
/// needs two layers where it has no upper), whose RAM copy takes the
/// program's label, and whose backend `dmsetup` marks for deferred removal.
fn labelled_session(hidden: &Path, decoy: &Path, empty: &Path, dmsetup: &Path) -> Plan {
    let mut session = super::plan(hidden);
    session.decoy_root = DecoyRoot {
        source: PathBuf::from("overlay"),
        fstype: "overlay".into(),
        data: Some(format!("lowerdir={}:{}", decoy.display(), empty.display())),
    };
    session.program_label = Some(PROGRAM_LABEL.to_string());
    session.backend = vec!["hidden-crypt".to_string()];
    session.tools.dmsetup = Some(dmsetup.to_path_buf());
    session
}

/// `deactivate`'s way back gives the copy its label again, through the
/// running kernel, after it mounted the decoy root and before it marks the
/// backend for deferred removal and arms the switch. Where the copy cannot
/// take the label (its `/run` is a ramfs, which stores none), the return is
/// refused with the backend left as it was, the plan unarmed, the next root
/// detached and nothing enqueued; where it can (a tmpfs), the backend is
/// marked, the plan armed and the soft-reboot enqueued.
#[test]
fn the_way_back_labels_the_copy_again_before_it_marks_the_backend_and_arms() {
    let _ = Rerun::new(crate::test_path!(
        the_way_back_labels_the_copy_again_before_it_marks_the_backend_and_arms
    ))
    .in_user_mount_ns()
    .run(|| {
        let decoy = unlabelled_fhs_decoy();
        let hidden = ScratchTmpfs::new("");
        let tools = ScratchTmpfs::new("");
        let empty = tools.mkdir("empty");
        let marked = tools.path().join("marked");
        let dmsetup = tools.path().join("dmsetup");
        write_executable(
            &dmsetup,
            format!("#!/bin/sh\necho \"$*\" >> {}\n", marked.display()),
            0o755,
        );
        for ramfs in [true, false] {
            let scratch = ScratchTmpfs::new("");
            let run = scratch.mkdir("run");
            if ramfs
                && let Err(errno) = nix::mount::mount(
                    Some("ramfs"),
                    &run,
                    Some("ramfs"),
                    nix::mount::MsFlags::empty(),
                    None::<&str>,
                )
            {
                crate::test_support::skip(&format!(
                    "cannot mount a ramfs in this namespace: {errno}"
                ));
            }
            // The decoy root has the mount point the way back binds /run on.
            std::fs::create_dir_all(decoy.path().join(run.strip_prefix("/").unwrap())).unwrap();
            let machine = Machine {
                paths: Paths {
                    root: hidden.path().join("root/upper"),
                    run: run.clone(),
                },
                mounts: None,
            };
            let mut session = labelled_session(hidden.path(), decoy.path(), &empty, &dmsetup);
            write_plan(&machine, &session);
            std::fs::write(machine.paths.binary_copy(), b"\x7fELF").unwrap();
            let _ = std::fs::remove_file(&marked);
            let target = FakeTarget::default();

            let left = crate::session::leave(&machine.paths, &mut session, LeaveTo::Decoy, &target);

            let on_disk = Plan::load(&machine.paths.plan()).unwrap();
            if ramfs {
                let error = left.unwrap_err();
                let NailsError::PreFlightCheckFailed(failures) = &error else {
                    panic!("expected the program label's refusal, got {error:?}");
                };
                assert_eq!(failures[0].0, CHECK, "{error}");
                assert!(
                    failures[0].1.contains("could not take the label"),
                    "{error}"
                );
                assert!(!marked.exists(), "the backend is left as it was");
                assert!(session.armed.is_none() && on_disk.armed.is_none());
                assert!(!next_root_mounted(&machine), "the next root is detached");
                assert!(target.started.borrow().is_empty(), "nothing enqueued");
            } else {
                let report = left.unwrap();
                assert_eq!(report.deferred, [("hidden-crypt".to_string(), true)]);
                assert_eq!(
                    std::fs::read_to_string(&marked).unwrap(),
                    "remove --deferred --noudevsync -- hidden-crypt\n"
                );
                assert_eq!(
                    selinux_label(&machine.paths.binary_copy()).unwrap(),
                    format!("{PROGRAM_LABEL}\0").into_bytes()
                );
                assert_eq!(
                    on_disk.armed.map(|arm| arm.direction),
                    Some(Direction::Leave)
                );
                assert_eq!(*target.started.borrow(), ["soft-reboot.target"]);
                nails_teardown::whole_root::nextroot::detach_tree(&machine.paths.nextroot());
            }
        }
    });
}

/// Under a loaded policy, as a stand-in for the kernel's SELinux tells it,
/// `deactivate`'s way back asks the policy before it prepares anything, and
/// gives the copy the label again and asks the policy again right before the
/// arm. A copy that then reads back another label, as one a relabel of
/// `/run` gave the label of the files there, refuses the return: the backend
/// is left as it was, the plan unarmed, the next root detached and nothing
/// enqueued.
#[test]
fn a_way_back_under_a_loaded_policy_asks_it_again_at_the_arm_and_refuses_a_copy_read_back_otherwise()
 {
    let _ = Rerun::new(crate::test_path!(
        a_way_back_under_a_loaded_policy_asks_it_again_at_the_arm_and_refuses_a_copy_read_back_otherwise
    ))
    .in_user_mount_ns()
    .run(|| {
        let decoy = unlabelled_fhs_decoy();
        let hidden = ScratchTmpfs::new("");
        let tools = ScratchTmpfs::new("");
        let empty = tools.mkdir("empty");
        let marked = tools.path().join("marked");
        let dmsetup = tools.path().join("dmsetup");
        write_executable(
            &dmsetup,
            format!("#!/bin/sh\necho \"$*\" >> {}\n", marked.display()),
            0o755,
        );
        let relabelled = b"system_u:object_r:var_run_t:s0\0".to_vec();
        for read_back in [None, Some(relabelled)] {
            let scratch = ScratchTmpfs::new("");
            let run = scratch.mkdir("run");
            std::fs::create_dir_all(decoy.path().join(run.strip_prefix("/").unwrap())).unwrap();
            let machine = Machine {
                paths: Paths {
                    root: hidden.path().join("root/upper"),
                    run: run.clone(),
                },
                mounts: None,
            };
            let mut session = labelled_session(hidden.path(), decoy.path(), &empty, &dmsetup);
            write_plan(&machine, &session);
            std::fs::write(machine.paths.binary_copy(), b"\x7fELF").unwrap();
            let _ = std::fs::remove_file(&marked);
            let target = FakeTarget {
                selinux: Some(FakeSelinux {
                    read_back: read_back.clone(),
                    ..FakeSelinux::targeted()
                }),
                ..FakeTarget::default()
            };

            let left = crate::session::leave(&machine.paths, &mut session, LeaveTo::Decoy, &target);

            let selinux = target.selinux.as_ref().unwrap();
            assert_eq!(
                selinux.labels_written(),
                [format!("{PROGRAM_LABEL}\0").into_bytes()]
            );
            let asked_for_pid1 = || {
                selinux
                    .questions()
                    .iter()
                    .filter(|question| *question == "pid1")
                    .count()
            };
            let on_disk = Plan::load(&machine.paths.plan()).unwrap();
            if read_back.is_none() {
                left.unwrap();
                assert_eq!(asked_for_pid1(), 2, "before anything and at the arm");
                assert!(marked.exists(), "the backend is marked");
                assert_eq!(
                    on_disk.armed.map(|arm| arm.direction),
                    Some(Direction::Leave)
                );
                assert_eq!(*target.started.borrow(), ["soft-reboot.target"]);
                nails_teardown::whole_root::nextroot::detach_tree(&machine.paths.nextroot());
            } else {
                let error = left.unwrap_err();
                let NailsError::PreFlightCheckFailed(failures) = &error else {
                    panic!("expected the program label's refusal, got {error:?}");
                };
                assert_eq!(failures[0].0, CHECK, "{error}");
                assert!(
                    failures[0]
                        .1
                        .contains("reads back as system_u:object_r:var_run_t:s0 after the label"),
                    "{error}"
                );
                assert_eq!(asked_for_pid1(), 1, "refused before it asks again");
                assert!(!marked.exists(), "the backend is left as it was");
                assert!(session.armed.is_none() && on_disk.armed.is_none());
                assert!(!next_root_mounted(&machine), "the next root is detached");
                assert!(target.started.borrow().is_empty(), "nothing enqueued");
            }
        }
    });
}
