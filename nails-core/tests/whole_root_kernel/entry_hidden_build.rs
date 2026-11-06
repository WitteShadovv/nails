// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! A hidden NixOS build, against the whole entry on real mounts: the fstab
//! the build brings is decided before anything runs from it. A build whose
//! fstab mounts something below the hidden root is refused before its
//! closure is kept and before its activation writes the hidden `/etc` into
//! the root upper. An entry without a build (`--overlay-only`) runs with that
//! upper's `/etc`, so the refused line never reaches a hidden session through
//! it. A build the policy accepts is activated as before.

use super::{FakeHost, World};
use nails_core::nixos::NixOSBuilder;
use nails_core::session::GuardHost;
use nails_core::session::entry::{self, EntryHost};
use nails_core::session::layout::Layout;
use nails_core::session::store::KeepReport;
use nails_core::test_path;
use nails_core::test_support::{Rerun, write_executable};
use nails_core::{NailsError, Result};
use nails_teardown::mountinfo::read_mountinfo;
use nails_teardown::whole_root::fresh_pids;
use nails_teardown::whole_root::kernel_helpers::KernelSetting;
use std::cell::Cell;
use std::path::{Path, PathBuf};

/// The toplevel the fake build makes, as the next root's store holds it.
const SYSTEM: &str = "/nix/store/aaaa-nixos-system-test";

/// A host whose build makes a toplevel that brings `fstab`, and that records
/// whether its closure was kept and whether it was activated.
struct BuildHost {
    host: FakeHost,
    fstab: String,
    kept: Cell<bool>,
    activated: Cell<bool>,
}

impl BuildHost {
    fn new(fstab: String) -> Self {
        Self {
            host: FakeHost::default(),
            fstab,
            kept: Cell::new(false),
            activated: Cell::new(false),
        }
    }
}

impl GuardHost for BuildHost {
    fn unit_stop_commands(&self, unit: &str) -> Result<String> {
        self.host.unit_stop_commands(unit)
    }
    fn job_timeout_action(&self, unit: &str) -> Result<String> {
        self.host.job_timeout_action(unit)
    }
    fn job_timeout(&self, unit: &str) -> Result<String> {
        self.host.job_timeout(unit)
    }
    fn service_watchdogs(&self) -> Result<String> {
        self.host.service_watchdogs()
    }
    fn unit_dropins(&self, unit: &str) -> Result<String> {
        self.host.unit_dropins(unit)
    }
}

impl EntryHost for BuildHost {
    fn daemon_reload(&self) -> Result<()> {
        self.host.daemon_reload()
    }
    /// What a build leaves in the next root's store: the toplevel, which
    /// links its etc by an absolute path, as NixOS's does, and its init.
    fn build_hidden_system(&self, _: &NixOSBuilder, root: &Path, _: &Path) -> Result<PathBuf> {
        let store = root.join("nix/store");
        let etc = store.join("bbbb-etc/etc");
        std::fs::create_dir_all(&etc).unwrap();
        std::fs::write(etc.join("fstab"), &self.fstab).unwrap();
        let system = store.join("aaaa-nixos-system-test");
        std::fs::create_dir_all(system.join("systemd/lib/systemd")).unwrap();
        std::os::unix::fs::symlink("/nix/store/bbbb-etc/etc", system.join("etc")).unwrap();
        write_executable(
            &system.join("systemd/lib/systemd/systemd"),
            "#!/bin/sh\n",
            0o755,
        );
        Ok(PathBuf::from(SYSTEM))
    }
    fn keep_hidden_closure(&self, _: &Path, _: &Path, _: &Path) -> Result<KeepReport> {
        self.kept.set(true);
        Ok(KeepReport::default())
    }
    /// What the activation writes into the root upper: the link to the
    /// toplevel's etc and the fstab read through it.
    fn activate_hidden_system(&self, root: &Path, system: &Path) -> Result<()> {
        self.activated.set(true);
        std::os::unix::fs::symlink(system.join("etc"), root.join("etc/static")).unwrap();
        std::fs::write(root.join("etc/fstab"), &self.fstab).unwrap();
        Ok(())
    }
    fn kernel_settings(&self) -> Vec<KernelSetting> {
        self.host.kernel_settings()
    }
    fn pid_record(&self) -> fresh_pids::Record {
        self.host.pid_record()
    }
    fn device_present(&self, device: &Path) -> bool {
        self.host.device_present(device)
    }
}

#[test]
fn a_build_whose_fstab_mounts_below_the_hidden_root_is_refused_before_it_is_activated() {
    let _ = Rerun::new(test_path!(
        a_build_whose_fstab_mounts_below_the_hidden_root_is_refused_before_it_is_activated
    ))
    .in_user_mount_ns()
    .run(|| {
        let world = World::new();
        let hidden = world.hidden_path();
        let builder = NixOSBuilder::new(hidden.join("nixos"));
        let mut inputs = world.inputs();
        inputs.nixos = true;
        inputs.builder = Some(&builder);
        let host = BuildHost::new(format!(
            "/dev/vda2 / ext4 defaults 0 1\n/dev/vdd1 {}/archive ext4 defaults 0 2\n",
            hidden.display()
        ));
        let paths = world.paths();
        let error = entry::prepare(&paths, &inputs, &host).unwrap_err();
        let NailsError::InvalidState(message) = &error else {
            panic!("{error:?}");
        };
        assert!(
            message.starts_with(&format!(
                "the hidden NixOS system's fstab entry {}/archive: it lies at or below {}",
                hidden.display(),
                hidden.display()
            )),
            "{message}"
        );
        assert!(message.contains("Remove this mount from the hidden NixOS configuration"));
        assert!(!host.kept.get(), "refused before its closure is kept");
        assert!(!host.activated.get(), "refused before it is activated");
        // The root upper holds nothing of the activation, so an entry
        // without a build finds the decoy's /etc there, not the build's.
        let upper = Layout::new(hidden).upper();
        assert!(std::fs::symlink_metadata(upper.join("etc/static")).is_err());
        assert!(std::fs::symlink_metadata(upper.join("etc/fstab")).is_err());
        assert!(
            !read_mountinfo()
                .unwrap()
                .iter()
                .any(|e| e.mount_point.starts_with(paths.nextroot())),
            "the next root is detached"
        );
        assert!(!paths.runtime().exists());
    });
}

#[test]
fn a_build_whose_fstab_the_policy_accepts_is_activated() {
    let _ = Rerun::new(test_path!(
        a_build_whose_fstab_the_policy_accepts_is_activated
    ))
    .in_user_mount_ns()
    .run(|| {
        let world = World::new();
        let hidden = world.hidden_path();
        let builder = NixOSBuilder::new(hidden.join("nixos"));
        let mut inputs = world.inputs();
        inputs.nixos = true;
        inputs.builder = Some(&builder);
        // A line outside the hidden root, for a disk the decoy does not
        // mount now: decided as the decoy's fstab line would be.
        let host = BuildHost::new(
            "/dev/vda2 / ext4 defaults 0 1\n/dev/vdd1 /srv/archive ext4 defaults,nofail 0 2\n"
                .to_string(),
        );
        let paths = world.paths();
        let entry = entry::prepare(&paths, &inputs, &host).expect("the entry");
        assert!(host.kept.get() && host.activated.get());
        assert_eq!(entry.plan.hidden.system.as_deref(), Some(Path::new(SYSTEM)));
        assert!(
            std::fs::symlink_metadata(Layout::new(hidden).upper().join("etc/static")).is_ok(),
            "the activation wrote into the root upper"
        );
        entry::rollback(&paths);
    });
}
