// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The decoy's mount, swap and automount units outside its fstab, against
//! real mounts: the entry reads them in the next root and in `/run`, puts in
//! place a filesystem the decoy has mounted now, and keeps the others off as
//! fstab lines would be.

use super::entry_kernel_tests::{FakeHost, World};
use nails_core::session::entry;
use nails_core::session::policy::Decision;
use nails_core::test_path;
use nails_core::test_support::{Rerun, ScratchTmpfs};
use nails_teardown::mountinfo::{read_mountinfo, top_mount_at};
use nails_teardown::whole_root::nextroot;
use nails_teardown::whole_root::plan::{PolicyMountKind, Skip, unix_now};
use nails_teardown::whole_root::skips::{SKIP_DROPIN_NAME, SKIP_TEXT, dropin_dir};
use nails_teardown::whole_root::transition::{self, Env, Outcome};
use std::path::{Path, PathBuf};

/// Write `text` at `path` below `dir`, with its parents.
fn write(dir: &Path, path: &str, text: &str) {
    let full = dir.join(path);
    std::fs::create_dir_all(full.parent().unwrap()).unwrap();
    std::fs::write(full, text).unwrap();
}

/// Link `path` below `dir` to `target`.
fn link(dir: &Path, path: &str, target: &str) {
    let full = dir.join(path);
    std::fs::create_dir_all(full.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(target, full).unwrap();
}

#[test]
fn the_units_outside_the_fstab_are_kept_off_in_the_hidden_root_as_fstab_lines() {
    // A disk of a native unit local-fs.target requires, not mounted now, its
    // device there (a node every host has stands for it); a tmpfs systemd
    // ships; the ESP behind the GPT auto-generator's automount, not mounted
    // now and not there.
    let _ = Rerun::new(test_path!(
        the_units_outside_the_fstab_are_kept_off_in_the_hidden_root_as_fstab_lines
    ))
    .in_user_mount_ns()
    .run(|| {
        let world = World::new();
        let decoy = world.decoy.path();
        world.decoy.mkdir("srv/native");
        write(
            decoy,
            "etc/systemd/system/srv-native.mount",
            "[Unit]\nRequires=systemd-fsck@dev-null.service\n\
             [Mount]\nWhat=/dev/null\nType=ext4\n",
        );
        link(
            decoy,
            "etc/systemd/system/local-fs.target.requires/srv-native.mount",
            "../srv-native.mount",
        );
        write(
            decoy,
            "usr/lib/systemd/system/tmp.mount",
            "[Mount]\nWhat=tmpfs\nType=tmpfs\n",
        );
        link(
            decoy,
            "usr/lib/systemd/system/local-fs.target.wants/tmp.mount",
            "../tmp.mount",
        );
        let paths = world.paths();
        let generated = paths.run.join("systemd/generator.late");
        write(&generated, "efi.automount", "[Automount]\nWhere=/efi\n");
        write(
            &generated,
            "efi.mount",
            "[Mount]\nWhat=/dev/vdz1\nType=vfat\nOptions=umask=0077\n",
        );
        link(
            &generated,
            "local-fs.target.wants/efi.automount",
            "../efi.automount",
        );

        let host = FakeHost::with_devices(vec![PathBuf::from("/dev/null")]);
        let entry = entry::prepare(&paths, &world.inputs(), &host).expect("the entry");

        let plan = &entry.plan;
        assert!(
            plan.skips.contains(&Skip {
                units: vec!["srv-native.mount".into()],
                pulled: vec!["systemd-fsck@dev-null.service".into()],
                device: Some("/dev/null".into()),
            }),
            "{:?}",
            plan.skips
        );
        for unit in ["efi.mount", "efi.automount"] {
            assert!(plan.masks.contains(&unit.to_string()), "{:?}", plan.masks);
        }
        assert!(!plan.masks.iter().any(|unit| unit == "tmp.mount"));
        let described: Vec<String> = entry.decisions.iter().map(Decision::describe).collect();
        assert!(
            described.contains(
                &"/srv/native: skipped (not mounted now; the hidden session would mount it \
                  read-write)"
                    .to_string()
            ),
            "{described:?}"
        );
        assert!(entry.warnings.is_empty(), "{:?}", entry.warnings);

        let env = Env {
            run: paths.run.clone(),
            nextroot: paths.nextroot(),
            runtime_dir: paths.runtime(),
            kmsg: paths.run.join("no-kmsg"),
            systemctl: None,
            now: unix_now(),
            mounts: read_mountinfo().unwrap(),
        };
        assert_eq!(transition::run(&env), Outcome::Entered);
        let dropin = paths
            .run
            .join(dropin_dir("srv-native.mount"))
            .join(SKIP_DROPIN_NAME);
        assert_eq!(std::fs::read_to_string(dropin).unwrap(), SKIP_TEXT);
        let units = paths.run.join("systemd/system");
        assert_eq!(
            std::fs::read_link(units.join("efi.automount")).unwrap(),
            Path::new("/dev/null")
        );
        entry::rollback(&paths);
        assert!(!paths.run.join(dropin_dir("srv-native.mount")).exists());
        assert!(std::fs::symlink_metadata(units.join("efi.automount")).is_err());
    });
}

#[test]
fn a_filesystem_of_a_unit_outside_the_fstab_mounted_now_is_overlaid() {
    // A native unit's overlay the decoy has mounted at /srv/layered: the next
    // root shows it, and a write there lands in an upper of its own on the
    // hidden volume, never in the decoy's layers.
    let _ = Rerun::new(test_path!(
        a_filesystem_of_a_unit_outside_the_fstab_mounted_now_is_overlaid
    ))
    .in_user_mount_ns()
    .run(|| {
        let world = World::new();
        let decoy = world.decoy.path();
        let layers = ScratchTmpfs::new("");
        for dir in ["lower", "upper", "work"] {
            layers.mkdir(dir);
        }
        std::fs::write(layers.path().join("lower/decoy-file"), "decoy").unwrap();
        let mount_point = world.decoy.mkdir("srv/layered");
        nextroot::mount_overlay(
            &layers.path().join("lower"),
            &layers.path().join("upper"),
            &layers.path().join("work"),
            &mount_point,
        )
        .unwrap();
        write(
            decoy,
            "etc/systemd/system/srv-layered.mount",
            "[Mount]\nWhat=overlay\nType=overlay\n\
             Options=lowerdir=/x,upperdir=/y,workdir=/z\n",
        );
        link(
            decoy,
            "etc/systemd/system/multi-user.target.wants/srv-layered.mount",
            "../srv-layered.mount",
        );
        let paths = world.paths();

        let entry =
            entry::prepare(&paths, &world.inputs(), &FakeHost::default()).expect("the entry");

        assert!(
            entry.plan.policy_mounts.iter().any(
                |m| m.target == Path::new("/srv/layered") && m.kind == PolicyMountKind::Overlay
            ),
            "{:?}",
            entry.plan.policy_mounts
        );
        let inside = paths.nextroot().join("srv/layered");
        let live = read_mountinfo().unwrap();
        assert_eq!(
            top_mount_at(&live, &inside).map(|m| m.fstype.as_str()),
            Some("overlay")
        );
        assert_eq!(
            std::fs::read_to_string(inside.join("decoy-file")).unwrap(),
            "decoy"
        );
        std::fs::write(inside.join("hidden-file"), "hidden").unwrap();
        assert!(!layers.path().join("upper/hidden-file").exists());
        assert!(!layers.path().join("lower/hidden-file").exists());
        assert!(
            world
                .hidden_path()
                .join("root/mounts/srv-layered/upper/hidden-file")
                .exists()
        );
        entry::rollback(&paths);
    });
}
