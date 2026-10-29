// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The units a boot target requires, against real mounts: the entry decides
//! to skip them where their device is there and to mask them where it is
//! not, the transition writes the skips at the switch, and a rollback removes
//! them again.

use super::entry_kernel_tests::{FakeHost, World};
use nails_core::session::entry;
use nails_core::test_path;
use nails_core::test_support::Rerun;
use nails_teardown::mountinfo::read_mountinfo;
use nails_teardown::whole_root::plan::{MaskCause, RequiredMask, Skip, unix_now};
use nails_teardown::whole_root::skips::{SKIP_DROPIN_NAME, SKIP_TEXT, dropin_dir};
use nails_teardown::whole_root::transition::{self, Env, Outcome};
use std::path::{Path, PathBuf};

#[test]
fn the_units_a_boot_target_requires_are_skipped_at_the_switch_while_their_device_is_there() {
    // The decoy's fstab lists a disk that is not mounted now, without nofail:
    // local-fs.target requires its mount. A node every host has stands for
    // its device, which is there at the entry and at the switch. A second
    // disk is not there: masked, with a warning. A swap file waits for no
    // device, and the ESP's automount none either.
    let _ = Rerun::new(test_path!(
        the_units_a_boot_target_requires_are_skipped_at_the_switch_while_their_device_is_there
    ))
    .in_user_mount_ns()
    .run(|| {
        let world = World::new();
        let decoy = world.decoy.path();
        world.decoy.mkdir("srv/spare");
        let fstab = decoy.join("etc/fstab");
        let text = std::fs::read_to_string(&fstab).unwrap().replace(
            "/boot vfat umask=0077",
            "/boot vfat umask=0077,x-systemd.automount",
        );
        std::fs::write(
            &fstab,
            text + "/dev/null /srv/spare ext4 defaults,x-systemd.makefs 0 2\n\
                    /dev/vdy1 /srv/gone ext4 defaults 0 2\n\
                    /swapfile none swap sw 0 0\n",
        )
        .unwrap();
        let host = FakeHost::with_devices(vec![PathBuf::from("/dev/null")]);
        let paths = world.paths();
        let entry = entry::prepare(&paths, &world.inputs(), &host).expect("the entry");

        let plan = &entry.plan;
        assert_eq!(
            plan.skips,
            [
                Skip {
                    units: vec!["swapfile.swap".into()],
                    pulled: Vec::new(),
                    device: None,
                },
                Skip {
                    units: vec!["srv-spare.mount".into()],
                    pulled: vec![
                        "systemd-fsck@dev-null.service".into(),
                        "systemd-makefs@dev-null.service".into()
                    ],
                    device: Some("/dev/null".into()),
                },
                Skip {
                    units: vec!["boot.automount".into()],
                    pulled: Vec::new(),
                    device: None,
                },
            ],
            "{:?}",
            plan.skips
        );
        assert!(plan.masks.contains(&"srv-gone.mount".to_string()));
        assert!(!plan.masks.contains(&"srv-spare.mount".to_string()));
        // `status` names the masked one and why.
        assert_eq!(
            plan.required_masks,
            [RequiredMask {
                unit: "srv-gone.mount".into(),
                cause: MaskCause::DeviceAbsent,
                device: Some("/dev/vdy1".into()),
            }]
        );
        assert_eq!(entry.warnings.len(), 1, "{:?}", entry.warnings);
        let warning = &entry.warnings[0];
        for part in ["/srv/gone", "/dev/vdy1", "local-fs.target"] {
            assert!(warning.contains(part), "{part}: {warning}");
        }
        let units = paths.run.join("systemd/system");
        let skipped = [
            "swapfile.swap",
            "srv-spare.mount",
            "systemd-fsck@dev-null.service",
            "systemd-makefs@dev-null.service",
            "boot.automount",
        ];
        for unit in skipped {
            assert!(
                !paths.run.join(dropin_dir(unit)).exists(),
                "{unit} is skipped before the switch"
            );
        }

        let env = Env {
            run: paths.run.clone(),
            nextroot: paths.nextroot(),
            runtime_dir: paths.runtime(),
            kmsg: paths.run.join("no-kmsg"),
            systemctl: None,
            now: unix_now(),
            mounts: read_mountinfo().unwrap(),
            pid_places: None,
        };
        assert_eq!(transition::run(&env), Outcome::Entered);
        for unit in skipped {
            let dropin = paths.run.join(dropin_dir(unit)).join(SKIP_DROPIN_NAME);
            assert_eq!(
                std::fs::read_to_string(&dropin).unwrap(),
                SKIP_TEXT,
                "{unit}"
            );
            assert!(
                std::fs::symlink_metadata(units.join(unit)).is_err(),
                "{unit}"
            );
        }
        assert_eq!(
            std::fs::read_link(units.join("srv-gone.mount")).unwrap(),
            Path::new("/dev/null")
        );

        // The switch failed: the decoy runs again over the same /run, and
        // skips none of its units.
        entry::rollback(&paths);
        for unit in skipped {
            assert!(!paths.run.join(dropin_dir(unit)).exists(), "{unit}");
        }
        assert!(std::fs::symlink_metadata(units.join("srv-gone.mount")).is_err());
    });
}
