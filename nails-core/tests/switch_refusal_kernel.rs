// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The transition-refusal record against a real kernel, without root (the
//! real-kernel tier of docs/testing-strategy.md).
//!
//! A refused entry keeps its reason on the hidden volume so `status` can read
//! it back. When the transition runs, the decoy's shutdown has already
//! unmounted the volume at its own path, and only its bind in the next root is
//! left. These tests build that shape on scratch tmpfs: a next root that is a
//! mount of its own, the hidden volume bound into it at the hidden root, and
//! nothing of the volume at the hidden root's own path. They prove the record
//! goes through that bind onto the volume, with the device identity read from
//! the live mount table, and that the same guard keeps it out of the next root
//! when the recorded device is not the one mounted there.

mod kernel_tests {
    use nails_core::test_path;
    use nails_core::test_support::{Rerun, ScratchTmpfs};
    use nails_teardown::mountinfo::{read_mountinfo, top_mount_at};
    use nails_teardown::whole_root::nextroot;
    use nails_teardown::whole_root::plan::{
        Arm, DecoyRoot, Direction, PLAN_NAME, PLAN_VERSION, Plan, RootSide, Tools,
    };
    use nails_teardown::whole_root::switch_refusal;
    use nails_teardown::whole_root::transition::{self, Env, Outcome};
    use std::path::{Path, PathBuf};

    /// The hidden root, as the plan and the hidden session name it.
    const HIDDEN_ROOT: &str = "/mnt/data";

    /// A hidden volume, a `/run` and a next root, each its own tmpfs, with the
    /// volume bound into the next root at [`HIDDEN_ROOT`], as the entry leaves
    /// them for the transition.
    struct World {
        hidden: ScratchTmpfs,
        run: ScratchTmpfs,
        next: ScratchTmpfs,
    }

    impl World {
        fn new() -> Self {
            let hidden = ScratchTmpfs::new("");
            let run = ScratchTmpfs::new("");
            run.mkdir("overlay-runtime");
            let next = ScratchTmpfs::new("");
            std::fs::write(next.mkdir("etc").join("os-release"), "ID=hidden\n").unwrap();
            let volume = next.mkdir("mnt/data");
            nextroot::bind(hidden.path(), &volume, false).expect("bind the hidden volume");
            Self { hidden, run, next }
        }

        /// The volume's device, as the live mount table names it.
        fn hidden_dev(&self) -> String {
            let mounts = read_mountinfo().expect("the live mount table");
            let root = std::fs::canonicalize(self.hidden.path()).unwrap();
            top_mount_at(&mounts, &root)
                .expect("the hidden volume is mounted")
                .dev
                .clone()
        }

        fn runtime(&self) -> PathBuf {
            self.run.path().join("overlay-runtime")
        }

        fn env(&self) -> Env {
            Env {
                run: self.run.path().to_path_buf(),
                nextroot: std::fs::canonicalize(self.next.path()).unwrap(),
                runtime_dir: self.runtime(),
                kmsg: self.run.path().join("no-kmsg"),
                systemctl: None,
                now: 1_234,
                mounts: read_mountinfo().expect("the live mount table"),
                network: nails_teardown::whole_root::network::Places::system(self.run.path()),
                network_tools: None,
                power_off: transition::PowerOff {
                    grace: std::time::Duration::ZERO,
                    kernel: || false,
                },
            }
        }
    }

    /// A plan that armed an entry into the hidden volume on device `dev`,
    /// whose hidden init is missing from the next root, so the transition
    /// refuses it.
    fn armed_plan(dev: Option<String>) -> Plan {
        let side = RootSide {
            init: PathBuf::from("/usr/lib/systemd/systemd"),
            system: None,
        };
        Plan {
            version: PLAN_VERSION,
            hidden_root: PathBuf::from(HIDDEN_ROOT),
            hidden_dev: dev,
            accepted_decoy_storage: None,
            upper: Path::new(HIDDEN_ROOT).join("root/upper"),
            work: Path::new(HIDDEN_ROOT).join("root/work"),
            owner: None,
            decoy_root: DecoyRoot {
                source: PathBuf::from("/dev/null"),
                fstype: "ext4".to_string(),
                data: None,
            },
            decoy: side.clone(),
            hidden: side,
            policy_mounts: Vec::new(),
            masks: Vec::new(),
            boot_masks: Vec::new(),
            generator_masks: Vec::new(),
            session_units: Vec::new(),
            backend: Vec::new(),
            tools: Tools::default(),
            armed: Some(Arm::now(Direction::Enter)),
            entered_at: None,
            run_noexec: false,
            carried: Vec::new(),
            decoy_mounts: Vec::new(),
            read_only_disks: false,
            failed_at_entry: Vec::new(),
            kernel_settings: Vec::new(),
        }
    }

    #[test]
    fn a_refused_entry_s_reason_reaches_the_hidden_volume_through_the_next_root() {
        let _ = Rerun::new(test_path!(
            a_refused_entry_s_reason_reaches_the_hidden_volume_through_the_next_root
        ))
        .in_user_mount_ns()
        .run(|| {
            let world = World::new();
            let mut env = world.env();
            let plan = armed_plan(Some(world.hidden_dev()));
            plan.write_atomic(&world.runtime().join(PLAN_NAME)).unwrap();
            env.now = plan.armed.map_or(0, |arm| arm.at);

            let outcome = transition::run(&env);

            let Outcome::Disarmed(why) = outcome else {
                panic!("expected a refused switch, got {outcome:?}");
            };
            assert!(why.contains("does not resolve"), "{why}");
            // The next root is detached, and the reason is on the volume
            // itself: read through its own mount, as `status` reads it once
            // the operator opened the volume again.
            assert!(
                read_mountinfo()
                    .unwrap()
                    .iter()
                    .all(|m| !m.mount_point.starts_with(&env.nextroot)),
                "the next root is detached"
            );
            let kept = switch_refusal::read(world.hidden.path()).expect("a recorded refusal");
            assert_eq!(kept.reason, why);
            assert_eq!(kept.at, env.now);
            // A later activation supersedes it.
            switch_refusal::clear(world.hidden.path());
            assert!(switch_refusal::read(world.hidden.path()).is_none());
        });
    }

    #[test]
    fn a_stale_device_keeps_the_record_off_the_disk() {
        let _ = Rerun::new(test_path!(a_stale_device_keeps_the_record_off_the_disk))
            .in_user_mount_ns()
            .run(|| {
                let world = World::new();
                let env = world.env();
                // The plan's recorded device is not the one bound at the hidden
                // root in the next root: nothing must be written there.
                let plan = armed_plan(Some("0:0".to_string()));
                switch_refusal::record_on_volume(
                    &env.mounts,
                    &plan,
                    &env.nextroot,
                    "failed init check",
                    1,
                );

                assert!(switch_refusal::read(world.hidden.path()).is_none());
                assert!(!switch_refusal::refusal_path(world.hidden.path()).exists());
                // With the bind gone, the hidden root's directory in the next
                // root is the next root's own: nothing lands there either.
                nextroot::detach_tree(&env.nextroot.join("mnt/data"));
                let plan = armed_plan(Some(world.hidden_dev()));
                switch_refusal::record_on_volume(
                    &read_mountinfo().unwrap(),
                    &plan,
                    &env.nextroot,
                    "failed init check",
                    1,
                );
                let volume_dir = env.nextroot.join("mnt/data");
                assert!(!switch_refusal::refusal_path(&volume_dir).exists());
                assert!(switch_refusal::read(world.hidden.path()).is_none());
            });
    }
}
