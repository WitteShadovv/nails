// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the emergency hot path. They run with `act` off, or act
//! for real only on a scratch `/run`: nothing is enqueued, killed or
//! signalled.

use super::*;
use crate::whole_root::plan::sample;

fn host(dir: &Path) -> Host {
    Host {
        run: dir.join("run"),
        nextroot: dir.join("run/nextroot"),
        runtime_dir: dir.join("run/overlay-runtime"),
        cgroup_root: dir.join("cgroup"),
        protected_pids: Vec::new(),
        act: false,
    }
}

#[test]
fn without_a_plan_only_an_explicit_power_action_is_dispatched() {
    let dir = tempfile::tempdir().unwrap();
    let report = run(None, &host(dir.path()), Finish::Return);
    assert_eq!(report.side, Side::None);
    assert!(report.found_nothing());
    assert_eq!(report.dispatched, None);
    let report = run(None, &host(dir.path()), Finish::Poweroff);
    assert_eq!(report.dispatched, Some(Finish::Poweroff));
}

#[test]
fn a_plan_outside_the_hidden_root_is_a_decoy_side_cleanup() {
    // This test process does not run in the plan's overlay root.
    let dir = tempfile::tempdir().unwrap();
    let report = run(Some(sample()), &host(dir.path()), Finish::Return);
    assert_eq!(report.side, Side::Decoy);
    assert_eq!(report.dispatched, None, "the decoy needs no soft-reboot");
    let names: Vec<_> = report.phases.iter().map(|(n, _)| *n).collect();
    assert_eq!(
        names,
        ["signal-activation", "detach-nextroot", "remove-runtime"]
    );
    let report = run(Some(sample()), &host(dir.path()), Finish::Reboot);
    assert_eq!(report.dispatched, Some(Finish::Reboot));
}

#[test]
fn the_hidden_side_prepares_arms_kills_shells_enqueues_then_kills_in_that_order() {
    let dir = tempfile::tempdir().unwrap();
    let h = host(dir.path());
    std::fs::create_dir_all(&h.runtime_dir).unwrap();
    let mut plan = sample();
    plan.armed = None;
    let mut report = HotReport::new(Side::Hidden, Finish::Return);
    hidden(&mut plan, &h, &mut report);
    let names: Vec<_> = report.phases.iter().map(|(n, _)| *n).collect();
    assert_eq!(
        names,
        [
            "prepare-return",
            "close-backend",
            "arm",
            "kill-shells",
            "enqueue",
            "kill"
        ]
    );
    assert_eq!(report.dispatched, Some(Finish::Return));
    let written = Plan::load(&h.plan_path()).unwrap();
    assert!(written.armed_for(
        crate::whole_root::plan::Direction::Leave,
        crate::whole_root::plan::unix_now()
    ));
}

#[test]
fn a_way_back_that_cannot_be_armed_powers_off_instead() {
    let dir = tempfile::tempdir().unwrap();
    // No runtime directory: the plan cannot be written.
    let h = host(dir.path());
    let mut plan = sample();
    let mut report = HotReport::new(Side::Hidden, Finish::Return);
    hidden(&mut plan, &h, &mut report);
    assert_eq!(report.dispatched, Some(Finish::Poweroff));
    assert!(report.fallback.unwrap().contains("powering off"));
}

/// On the decoy (an activation interrupted after its entry transition,
/// or a switch that failed), acting for real on a scratch `/run`: the
/// session's masks of both kinds go, the kernel paths come back, the
/// runtime directory is removed and PID 1 is reloaded, so it forgets the
/// masks and the drop-in.
#[test]
fn the_decoy_side_undoes_the_masks_and_the_kernel_paths() {
    let dir = tempfile::tempdir().unwrap();
    let h = Host {
        act: true,
        ..host(dir.path())
    };
    std::fs::create_dir_all(&h.runtime_dir).unwrap();
    let kept = Snapshot::take(&h.run);
    std::fs::write(h.runtime_dir.join(SNAPSHOT_NAME), kept.to_text()).unwrap();
    let modprobe = dir.path().join("modprobe");
    std::fs::write(&modprobe, "/nix/store/decoy-kmod/bin/modprobe\n").unwrap();
    let calls = dir.path().join("systemctl-calls");
    let systemctl = dir.path().join("systemctl");
    std::fs::write(
        &systemctl,
        format!("#!/bin/sh\necho \"$@\" >> {}\n", calls.display()),
    )
    .unwrap();
    std::fs::set_permissions(
        &systemctl,
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .unwrap();
    let mut plan = sample();
    plan.owner = None;
    plan.backend = Vec::new();
    plan.tools.systemctl = Some(systemctl);
    transition::install_dropin(&h.run, Path::new("/x")).unwrap();
    plan.boot_masks = vec!["systemd-boot-random-seed.service".to_string()];
    plan.kernel_settings = kernel_helpers::read(&[modprobe.to_str().unwrap()]);
    std::fs::write(&modprobe, "/nix/store/hidden-kmod/bin/modprobe\n").unwrap();
    let mut masks = runtime_units::mask_units(&h.run, &plan.masks).unwrap();
    masks.extend(runtime_units::mask_units_best_effort(
        &h.run,
        &plan.boot_masks,
    ));
    assert_eq!(masks.len(), 2);
    let mut report = HotReport::new(Side::Decoy, Finish::Return);

    decoy(&plan, &h, &mut report);

    assert_eq!(
        std::fs::read_to_string(&modprobe).unwrap(),
        "/nix/store/decoy-kmod/bin/modprobe"
    );
    for mask in masks {
        assert!(std::fs::symlink_metadata(&mask).is_err(), "{mask:?} stays");
    }
    assert!(!h.runtime_dir.exists());
    assert!(
        !h.run
            .join(transition::DROPIN_DIR)
            .join(transition::DROPIN_NAME)
            .exists()
    );
    assert_eq!(std::fs::read_to_string(&calls).unwrap(), "daemon-reload\n");
}

#[test]
fn a_requested_power_off_skips_the_way_back() {
    let dir = tempfile::tempdir().unwrap();
    let h = host(dir.path());
    let mut plan = sample();
    let mut report = HotReport::new(Side::Hidden, Finish::Poweroff);
    hidden(&mut plan, &h, &mut report);
    let names: Vec<_> = report.phases.iter().map(|(n, _)| *n).collect();
    assert_eq!(names, ["kill-shells", "enqueue", "kill"]);
    assert_eq!(report.dispatched, Some(Finish::Poweroff));
}
