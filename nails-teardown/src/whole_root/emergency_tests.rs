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
        selinux: &selinux::KERNEL,
    }
}

#[test]
fn without_a_plan_only_an_explicit_power_action_is_dispatched() {
    let dir = tempfile::tempdir().unwrap();
    let report = run(None, &host(dir.path()), Finish::Default);
    assert_eq!(report.side, Side::None);
    assert!(report.found_nothing());
    assert_eq!(report.dispatched, None);
    let report = run(None, &host(dir.path()), Finish::Poweroff);
    assert_eq!(report.dispatched, Some(Finish::Poweroff));
}

fn phases(report: &HotReport) -> Vec<&'static str> {
    report.phases.iter().map(|(name, _)| *name).collect()
}

/// On the decoy side a requested power action follows the cleanup at once,
/// and the soft-reboot logind may still hold for the entry is dropped only
/// after it; a decoy that keeps running drops it first, and is reloaded after
/// the cleanup.
#[test]
fn a_plan_outside_the_hidden_root_is_a_decoy_side_cleanup() {
    // This test process does not run in the plan's overlay root.
    let dir = tempfile::tempdir().unwrap();
    let report = run(Some(sample()), &host(dir.path()), Finish::Default);
    assert_eq!(report.side, Side::Decoy);
    assert_eq!(report.dispatched, None, "the decoy needs no soft-reboot");
    assert_eq!(
        phases(&report),
        [
            "signal-activation",
            "drop-soft-reboot",
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
                "enqueue",
                "drop-soft-reboot"
            ],
            "{finish:?}"
        );
    }
}

/// A soft-reboot of the entry that logind cannot drop, or that PID 1 has
/// started, would restart the decoy's userspace, and PID 1 runs it as soon as
/// a power action next to it: a decoy-side emergency then powers off, or
/// reboots as asked, at once, past PID 1's queue.
#[test]
fn a_soft_reboot_that_may_still_come_forces_the_power_action() {
    use logind::Pending;
    assert_eq!(decoy_escape(Finish::Default, Pending::Nothing), None);
    assert_eq!(decoy_escape(Finish::Poweroff, Pending::Nothing), None);
    let (finish, why) = decoy_escape(Finish::Default, Pending::Held).unwrap();
    assert_eq!(finish, Finish::Poweroff);
    assert!(
        why.contains("cannot drop") && why.ends_with("powering off at once, before it can run")
    );
    let (finish, why) = decoy_escape(Finish::Default, Pending::Started).unwrap();
    assert_eq!(finish, Finish::Poweroff);
    assert!(why.starts_with("PID 1 has started"), "{why}");
    let (finish, why) = decoy_escape(Finish::Reboot, Pending::Held).unwrap();
    assert_eq!(finish, Finish::Reboot);
    assert!(
        why.ends_with("rebooting at once, before it can run"),
        "{why}"
    );
    assert_eq!(
        decoy_escape(Finish::Poweroff, Pending::Started).map(|(finish, _)| finish),
        Some(Finish::Poweroff)
    );
}

/// The emergency without a flag ends a hidden session the way every hidden
/// session ends: it powers off. It prepares nothing of a way back, marks no
/// backend and arms nothing; it kills the shells, enqueues the power-off and
/// kills the rest, in that order.
#[test]
fn the_hidden_side_without_a_flag_ends_the_session_in_a_power_off() {
    let dir = tempfile::tempdir().unwrap();
    let h = host(dir.path());
    std::fs::create_dir_all(&h.runtime_dir).unwrap();
    let mut plan = sample();
    plan.armed = None;
    plan.write_atomic(&h.runtime_dir.join(crate::whole_root::plan::PLAN_NAME))
        .unwrap();
    let mut report = HotReport::new(Side::Hidden, Finish::Default);
    hidden(Some(&plan), &h, &mut report);
    assert_eq!(phases(&report), ["kill-shells", "enqueue", "kill"]);
    assert_eq!(report.dispatched, Some(Finish::Poweroff));
    assert_eq!(report.fallback, None);
    assert!(report.deferred.is_empty());
    let written = Plan::load(&h.runtime_dir.join(crate::whole_root::plan::PLAN_NAME)).unwrap();
    assert_eq!(written.armed, None, "nothing armed");
    assert!(!h.nextroot.exists(), "no decoy root prepared");
    assert_eq!(Finish::session_end(), Finish::Poweroff);
    assert_eq!(Finish::Default.target(), "poweroff.target");
}

/// Where the plan records a label for the RAM copy, the emergency asks
/// SELinux nothing: no last step of a way back will start from the copy.
#[test]
fn the_hidden_side_asks_selinux_nothing() {
    use crate::test_support::FakeSelinux;
    let dir = tempfile::tempdir().unwrap();
    let mut h = host(dir.path());
    let selinux = FakeSelinux::targeted().leak();
    h.selinux = selinux;
    let mut plan = sample();
    plan.program_label = Some(crate::whole_root::program_label::PROGRAM_LABEL.to_string());
    let mut report = HotReport::new(Side::Hidden, Finish::Default);
    hidden(Some(&plan), &h, &mut report);
    assert_eq!(report.dispatched, Some(Finish::Poweroff));
    assert!(selinux.labels_written().is_empty() && selinux.questions().is_empty());
}

/// Where the emergency runs: a hidden root is told by its root overlay with
/// the plan's upper; without a plan, an overlay root is a hidden root whose
/// plan is gone, and a mount table that cannot be read cannot be told from
/// one. Only a plain root without a plan is no session.
#[test]
fn the_side_fails_closed_where_it_cannot_be_told() {
    use crate::mountinfo::parse_mountinfo;
    let plan = sample();
    let hidden = parse_mountinfo(&format!(
        "1 0 0:30 / / rw - overlay overlay rw,lowerdir=/run/x,upperdir={},workdir=/w\n",
        plan.upper.display()
    ));
    let other_overlay = parse_mountinfo(
        "1 0 0:30 / / rw - overlay overlay rw,lowerdir=/a,upperdir=/b,workdir=/c\n",
    );
    let plain = parse_mountinfo("1 0 8:2 / / rw - ext4 /dev/vda2 rw\n");
    assert_eq!(side_of(Some(&plan), Some(&hidden)), Side::Hidden);
    assert_eq!(side_of(Some(&plan), Some(&plain)), Side::Decoy);
    assert_eq!(side_of(Some(&plan), None), Side::Hidden);
    assert_eq!(side_of(None, Some(&hidden)), Side::Hidden);
    assert_eq!(side_of(None, Some(&other_overlay)), Side::Hidden);
    assert_eq!(side_of(None, None), Side::Hidden);
    assert_eq!(side_of(None, Some(&plain)), Side::None);
}

/// A hidden root without its plan ends in a power-off too, with the system's
/// `systemctl`.
#[test]
fn a_hidden_root_without_its_plan_powers_off() {
    let dir = tempfile::tempdir().unwrap();
    let h = host(dir.path());
    let mut report = HotReport::new(Side::Hidden, Finish::Default);
    hidden(None, &h, &mut report);
    assert_eq!(phases(&report), ["kill-shells", "enqueue", "kill"]);
    assert_eq!(report.dispatched, Some(Finish::Poweroff));
}

/// A full reboot asked for stays a full reboot: the firmware boots the decoy
/// afresh, which is no return to its kernel.
#[test]
fn the_hidden_side_reboots_when_asked() {
    let dir = tempfile::tempdir().unwrap();
    let h = host(dir.path());
    let mut report = HotReport::new(Side::Hidden, Finish::Reboot);
    hidden(Some(&sample()), &h, &mut report);
    assert_eq!(report.dispatched, Some(Finish::Reboot));
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
        // The decoy unit's mask in the runtime unit and control directories.
        assert_eq!(masks.len(), 4);
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

    /// The masks are gone, the kernel paths are back, the runtime directory,
    /// the drop-in and the runtime guards (the switch's timeout guard among
    /// them) are removed, each guard with its directory.
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
        let units: Vec<_> = transition::runtime_guards().map(|(unit, _)| unit).collect();
        assert!(
            units.contains(&transition::SWITCH_TIMEOUT_UNIT),
            "{units:?}"
        );
        for unit in units {
            let dir = self.host.run.join(transition::stop_guard_dir(unit));
            assert!(!dir.exists(), "{} stays", dir.display());
        }
    }

    /// The `systemctl` calls made, one per line.
    fn calls(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("systemctl-calls")).unwrap_or_default()
    }
}

/// The drop asks PID 1 whether it holds a soft-reboot for the entry, then,
/// as the entry recorded no `busctl` here, whether logind runs: logind may
/// hold the soft-reboot unless PID 1 says it does not run.
#[test]
fn the_entry_s_soft_reboot_counts_as_held_unless_logind_says_otherwise() {
    let scratch = Interrupted::new();
    let mut report = HotReport::new(Side::Decoy, Finish::Default);
    assert_eq!(
        drop_switch(&scratch.plan, &scratch.host, &mut report),
        logind::Pending::Held
    );
    assert_eq!(
        scratch.calls(),
        "list-jobs --plain --no-legend --full\n\
         show --property=ActiveState --value systemd-logind.service\n"
    );

    let scratch = Interrupted::new();
    write_executable(
        scratch.plan.tools.systemctl.as_deref().unwrap(),
        "#!/bin/sh\ncase \"$*\" in show*) echo inactive ;; esac\n",
        0o755,
    );
    assert_eq!(
        drop_switch(&scratch.plan, &scratch.host, &mut report),
        logind::Pending::Nothing
    );
}

/// On the decoy, with nothing enqueued, the cleanup undoes the masks and the
/// kernel paths, removes the runtime directory and the drop-in, and reloads
/// PID 1, so it forgets the masks and the drop-in.
#[test]
fn the_decoy_side_undoes_the_masks_and_the_kernel_paths() {
    let scratch = Interrupted::new();
    let report = scratch.clean_up(Finish::Default, None);
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
fn a_requested_power_off_takes_the_same_path() {
    let dir = tempfile::tempdir().unwrap();
    let h = host(dir.path());
    let mut report = HotReport::new(Side::Hidden, Finish::Poweroff);
    hidden(Some(&sample()), &h, &mut report);
    let names: Vec<_> = report.phases.iter().map(|(n, _)| *n).collect();
    assert_eq!(names, ["kill-shells", "enqueue", "kill"]);
    assert_eq!(report.dispatched, Some(Finish::Poweroff));
}
