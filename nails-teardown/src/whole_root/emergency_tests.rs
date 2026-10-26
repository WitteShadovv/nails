// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the emergency hot path. They run with `act` off, or act
//! for real only on a scratch `/run`: nothing is enqueued, killed or
//! signalled.

use super::*;
use crate::test_support::write_executable;
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

fn phases(report: &HotReport) -> Vec<&'static str> {
    report.phases.iter().map(|(name, _)| *name).collect()
}

/// On the decoy side a requested power action follows the cleanup at once;
/// only a decoy that keeps running is reloaded after it.
#[test]
fn a_plan_outside_the_hidden_root_is_a_decoy_side_cleanup() {
    // This test process does not run in the plan's overlay root.
    let dir = tempfile::tempdir().unwrap();
    let report = run(Some(sample()), &host(dir.path()), Finish::Return);
    assert_eq!(report.side, Side::Decoy);
    assert_eq!(report.dispatched, None, "the decoy needs no soft-reboot");
    assert_eq!(
        phases(&report),
        [
            "signal-activation",
            "detach-nextroot",
            "remove-runtime",
            "reload"
        ]
    );
    for finish in [Finish::Reboot, Finish::Poweroff] {
        let report = run(Some(sample()), &host(dir.path()), finish);
        assert_eq!(report.dispatched, Some(finish));
        assert_eq!(
            phases(&report),
            [
                "signal-activation",
                "detach-nextroot",
                "remove-runtime",
                "kill-shells",
                "enqueue"
            ],
            "{finish:?}"
        );
    }
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

/// A scratch decoy `/run` as an activation interrupted after its entry
/// transition, or a switch that failed, leaves it: the session's masks of
/// every kind, the transition drop-in and the hidden kernel paths, with a
/// `systemctl` that records its calls. The decoy side acts on it for real.
struct Interrupted {
    dir: tempfile::TempDir,
    host: Host,
    plan: Plan,
    masks: Vec<PathBuf>,
}

impl Interrupted {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let host = Host {
            act: true,
            ..host(dir.path())
        };
        std::fs::create_dir_all(&host.runtime_dir).unwrap();
        let kept = Snapshot::take(&host.run);
        std::fs::write(host.runtime_dir.join(SNAPSHOT_NAME), kept.to_text()).unwrap();
        let modprobe = dir.path().join("modprobe");
        std::fs::write(&modprobe, "/nix/store/decoy-kmod/bin/modprobe\n").unwrap();
        let systemctl = dir.path().join("systemctl");
        write_executable(
            &systemctl,
            format!(
                "#!/bin/sh\necho \"$@\" >> {}\n",
                dir.path().join("systemctl-calls").display()
            ),
            0o755,
        );
        let mut plan = sample();
        plan.owner = None;
        plan.backend = Vec::new();
        plan.tools.systemctl = Some(systemctl);
        transition::install_dropin(&host.run, Path::new("/x")).unwrap();
        plan.boot_masks = vec!["systemd-boot-random-seed.service".to_string()];
        plan.generator_masks = vec!["systemd-gpt-auto-generator".to_string()];
        plan.kernel_settings = kernel_helpers::read(&[modprobe.to_str().unwrap()]);
        std::fs::write(&modprobe, "/nix/store/hidden-kmod/bin/modprobe\n").unwrap();
        let mut masks = runtime_units::mask_units(&host.run, &plan.masks).unwrap();
        masks.extend(runtime_units::mask_units_best_effort(
            &host.run,
            &plan.boot_masks,
        ));
        masks.extend(runtime_units::mask_generators(&host.run, &plan.generator_masks).unwrap());
        assert_eq!(masks.len(), 3);
        Self {
            dir,
            host,
            plan,
            masks,
        }
    }

    /// The decoy side as `run` takes it there, with `dispatched` standing
    /// for what `dispatch` enqueued: it is not run here, as it kills every
    /// interactive shell.
    fn clean_up(&self, requested: Finish, dispatched: Option<Finish>) -> HotReport {
        let mut report = HotReport::new(Side::Decoy, requested);
        let unloaded = decoy(&self.plan, &self.host, &mut report);
        assert!(unloaded, "a drop-in and three masks were removed");
        report.dispatched = dispatched;
        settle(&self.plan, &self.host, unloaded, &mut report);
        report
    }

    /// The masks are gone, the kernel paths are back, the runtime directory
    /// and the drop-in are removed.
    fn assert_cleaned(&self) {
        assert_eq!(
            std::fs::read_to_string(self.dir.path().join("modprobe")).unwrap(),
            "/nix/store/decoy-kmod/bin/modprobe"
        );
        for mask in &self.masks {
            assert!(std::fs::symlink_metadata(mask).is_err(), "{mask:?} stays");
        }
        assert!(!self.host.runtime_dir.exists());
        assert!(
            !self
                .host
                .run
                .join(transition::DROPIN_DIR)
                .join(transition::DROPIN_NAME)
                .exists()
        );
    }

    /// The `systemctl` calls made, one per line.
    fn calls(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("systemctl-calls")).unwrap_or_default()
    }
}

/// On the decoy, with nothing enqueued, the cleanup undoes the masks and the
/// kernel paths, removes the runtime directory and the drop-in, and reloads
/// PID 1, so it forgets the masks and the drop-in.
#[test]
fn the_decoy_side_undoes_the_masks_and_the_kernel_paths() {
    let scratch = Interrupted::new();
    let report = scratch.clean_up(Finish::Return, None);
    scratch.assert_cleaned();
    assert_eq!(scratch.calls(), "daemon-reload\n");
    assert_eq!(phases(&report).last(), Some(&"reload"));
}

/// A power action enqueued after the cleanup discards PID 1's state, so it
/// waits for no reload; one that could not be enqueued leaves a decoy that
/// keeps running, which is reloaded.
#[test]
fn a_power_action_on_the_decoy_side_waits_for_no_reload() {
    for finish in [Finish::Poweroff, Finish::Reboot] {
        let scratch = Interrupted::new();
        let report = scratch.clean_up(finish, Some(finish));
        scratch.assert_cleaned();
        assert_eq!(scratch.calls(), "", "{finish:?}");
        assert!(!phases(&report).contains(&"reload"), "{finish:?}");

        let scratch = Interrupted::new();
        scratch.clean_up(finish, None);
        assert_eq!(scratch.calls(), "daemon-reload\n", "{finish:?}");
    }
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
