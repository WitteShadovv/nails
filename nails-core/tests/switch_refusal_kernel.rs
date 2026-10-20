// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The transition-refusal record against a real kernel, without root (the
//! real-kernel tier of docs/testing-strategy.md).
//!
//! A refused switch keeps its reason on the hidden volume so `status` can read
//! it back. This proves the write and read work on a genuinely mounted volume,
//! with the device identity read from the live mount table, and that the same
//! guard keeps the record off the decoy disk when the recorded device is not
//! the one mounted at the path now.

mod kernel_tests {
    use nails_core::test_path;
    use nails_core::test_support::{Rerun, ScratchTmpfs};
    use nails_teardown::mountinfo::{read_mountinfo, top_mount_at};
    use nails_teardown::whole_root::plan::{
        Arm, DecoyRoot, Direction, PLAN_VERSION, Plan, RootSide, Tools,
    };
    use nails_teardown::whole_root::switch_refusal;
    use std::path::{Path, PathBuf};

    /// A plan that armed an entry into the hidden volume at `hidden_root`,
    /// mounted on device `dev`.
    fn armed_plan(hidden_root: &Path, dev: Option<String>) -> Plan {
        Plan {
            version: PLAN_VERSION,
            hidden_root: hidden_root.to_path_buf(),
            hidden_dev: dev,
            accepted_decoy_storage: None,
            upper: hidden_root.join("root/upper"),
            work: hidden_root.join("root/work"),
            owner: None,
            decoy_root: DecoyRoot {
                source: PathBuf::from("/dev/null"),
                fstype: "ext4".to_string(),
                data: None,
            },
            decoy: RootSide {
                init: PathBuf::from("/usr/lib/systemd/systemd"),
                system: None,
            },
            hidden: RootSide {
                init: PathBuf::from("/usr/lib/systemd/systemd"),
                system: None,
            },
            policy_mounts: Vec::new(),
            masks: Vec::new(),
            boot_masks: Vec::new(),
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
    fn a_refusal_survives_on_a_mounted_hidden_volume_and_reads_back() {
        let _ = Rerun::new(test_path!(
            a_refusal_survives_on_a_mounted_hidden_volume_and_reads_back
        ))
        .in_user_mount_ns()
        .run(|| {
            // A real tmpfs stands in for the hidden volume, with its own device.
            let hidden = ScratchTmpfs::new("");
            let root = std::fs::canonicalize(hidden.path()).expect("canonical hidden root");
            let mounts = read_mountinfo().expect("the live mount table");
            let dev = top_mount_at(&mounts, &root)
                .expect("the hidden volume is mounted")
                .dev
                .clone();

            let plan = armed_plan(&root, Some(dev));
            switch_refusal::record(&mounts, &plan, "failed init check", 1234);

            let back = switch_refusal::read(&root).expect("a recorded refusal");
            assert_eq!(back.reason, "failed init check");
            assert_eq!(back.at, 1234);

            // A later activation supersedes it.
            switch_refusal::clear(&root);
            assert!(switch_refusal::read(&root).is_none());
        });
    }

    #[test]
    fn a_stale_device_keeps_the_record_off_the_disk() {
        let _ = Rerun::new(test_path!(a_stale_device_keeps_the_record_off_the_disk))
            .in_user_mount_ns()
            .run(|| {
                let hidden = ScratchTmpfs::new("");
                let root = std::fs::canonicalize(hidden.path()).expect("canonical hidden root");
                let mounts = read_mountinfo().expect("the live mount table");

                // The plan's recorded device is not the one mounted here now:
                // the hidden volume the entry saw is gone, and what sits at the
                // path is the decoy's own filesystem. Nothing must be written.
                let plan = armed_plan(&root, Some("0:0".to_string()));
                switch_refusal::record(&mounts, &plan, "failed init check", 1);

                assert!(switch_refusal::read(&root).is_none());
                assert!(!switch_refusal::refusal_path(&root).exists());
            });
    }
}
