// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The whole entry, `nails_core::session::entry::prepare`, against real
//! mounts: a decoy root with a separate `/home` and an ESP, the fstab
//! policy, the drop-in, and the transition that consumes it.

use nails_core::session::entry::{self, EntryHost, EntryInputs};
use nails_core::session::layout::Paths;
use nails_core::test_path;
use nails_core::test_support::{Rerun, ScratchTmpfs, skip_host, write_executable};
use nails_core::{NailsError, nixos::NixOSBuilder};
use nails_teardown::mountinfo::{MountEntry, parse_mountinfo, read_mountinfo, top_mount_at};
use nails_teardown::whole_root::kernel_helpers::{self, KernelSetting};
use nails_teardown::whole_root::plan::{
    CarriedMount, DecoyRoot, Direction, MountSource, Plan, PolicyMountKind, SNAPSHOT_NAME,
    UTAB_MOUNTS_NAME, unix_now,
};
use nails_teardown::whole_root::transition::{self, DROPIN_DIR, DROPIN_NAME, Env, Outcome};
use nails_teardown::whole_root::{carry, nextroot, runtime_units};
use std::cell::Cell;
use std::path::{Path, PathBuf};

#[derive(Default)]
pub(crate) struct FakeHost {
    reloads: Cell<u32>,
    /// The next root to look at on the first reload.
    nextroot: Option<PathBuf>,
    /// Whether it was a mount point then.
    populated_at_first_reload: Cell<Option<bool>>,
    /// Request a cancel during the first reload, as a Ctrl+C would.
    cancel_at_reload: bool,
    /// The files that stand for the kernel's helper paths.
    helpers: Vec<PathBuf>,
    /// The devices that are there; no other is, whatever the test host has.
    pub(crate) devices: Vec<PathBuf>,
}

impl FakeHost {
    /// A host on which `devices`, and no other device, are there.
    pub(crate) fn with_devices(devices: Vec<PathBuf>) -> Self {
        Self {
            devices,
            ..Self::default()
        }
    }
}

impl EntryHost for FakeHost {
    fn unit_stop_commands(&self, _: &str) -> nails_core::Result<String> {
        Ok(String::new())
    }
    fn daemon_reload(&self) -> nails_core::Result<()> {
        if self.cancel_at_reload && self.reloads.get() == 0 {
            nails_core::cancel::testing::request();
        }
        if self.reloads.get() == 0
            && let Some(nextroot) = &self.nextroot
        {
            let entries = read_mountinfo().unwrap();
            self.populated_at_first_reload
                .set(Some(entries.iter().any(|e| e.mount_point == *nextroot)));
        }
        self.reloads.set(self.reloads.get() + 1);
        Ok(())
    }
    fn build_hidden_system(
        &self,
        _: &NixOSBuilder,
        _: &Path,
        _: &Path,
    ) -> nails_core::Result<PathBuf> {
        Err(NailsError::NixOSError("not in this test".into()))
    }
    fn keep_hidden_closure(
        &self,
        _: &Path,
        _: &Path,
        _: &Path,
    ) -> nails_core::Result<nails_core::session::store::KeepReport> {
        Err(NailsError::NixOSError("not in this test".into()))
    }
    fn activate_hidden_system(&self, _: &Path, _: &Path) -> nails_core::Result<()> {
        Ok(())
    }
    fn kernel_settings(&self) -> Vec<KernelSetting> {
        let paths: Vec<&str> = self.helpers.iter().filter_map(|p| p.to_str()).collect();
        kernel_helpers::read(&paths)
    }
    fn device_present(&self, device: &Path) -> bool {
        self.devices.iter().any(|known| known == device)
    }
}

pub(crate) struct World {
    pub(crate) decoy: ScratchTmpfs,
    _esp: ScratchTmpfs,
    _home: ScratchTmpfs,
    hidden: ScratchTmpfs,
    run: ScratchTmpfs,
}

impl World {
    /// A decoy root with its ESP at /boot and a separate /home, both
    /// listed in its fstab with a swap partition and an unmounted disk, which
    /// no boot target requires (`nofail`): the mask of their units warns of
    /// no target left unreached, whichever devices are there.
    pub(crate) fn new() -> Self {
        let decoy = ScratchTmpfs::new("");
        for dir in [
            "etc",
            "usr/lib/systemd/system",
            "boot",
            "home",
            "run",
            "srv/data",
        ] {
            decoy.mkdir(dir);
        }
        for unit in ["soft-reboot.target", "systemd-soft-reboot.service"] {
            std::fs::write(decoy.path().join("usr/lib/systemd/system").join(unit), "").unwrap();
        }
        std::fs::write(decoy.path().join("etc/os-release"), "ID=debian\n").unwrap();
        std::fs::write(
            decoy.path().join("etc/fstab"),
            "/dev/vda2 / ext4 defaults 0 1\n\
             /dev/vda1 /boot vfat umask=0077 0 2\n\
             /dev/vda3 /home ext4 defaults 0 2\n\
             /dev/vda4 none swap sw,nofail 0 0\n\
             /dev/vdc1 /srv/data ext4 defaults,nofail 0 2\n",
        )
        .unwrap();
        write_executable(
            &decoy.path().join("usr/lib/systemd/systemd"),
            "#!/bin/sh\n",
            0o755,
        );
        let esp = ScratchTmpfs::new("");
        nix::mount::mount(
            Some(esp.path()),
            &decoy.path().join("boot"),
            None::<&str>,
            nix::mount::MsFlags::MS_BIND,
            None::<&str>,
        )
        .unwrap();
        let home = ScratchTmpfs::new("");
        std::fs::write(home.path().join("decoy-file"), "decoy").unwrap();
        let autostart = home.path().join("alice/.config/autostart");
        std::fs::create_dir_all(&autostart).unwrap();
        std::fs::write(
            autostart.join("dropbox.desktop"),
            "[Desktop Entry]\nName=Dropbox\nExec=dropbox\n",
        )
        .unwrap();
        nix::mount::mount(
            Some(home.path()),
            &decoy.path().join("home"),
            None::<&str>,
            nix::mount::MsFlags::MS_BIND,
            None::<&str>,
        )
        .unwrap();
        let run = ScratchTmpfs::new("");
        run.mkdir("mount");
        std::fs::write(run.path().join("mount/utab"), "ID=1 decoy\n").unwrap();
        Self {
            decoy,
            _esp: esp,
            _home: home,
            hidden: ScratchTmpfs::new(""),
            run,
        }
    }
    pub(crate) fn hidden_path(&self) -> &Path {
        self.hidden.path()
    }
    pub(crate) fn paths(&self) -> Paths {
        Paths {
            root: self.decoy.path().to_path_buf(),
            run: self.run.path().to_path_buf(),
        }
    }
    pub(crate) fn inputs(&self) -> EntryInputs<'_> {
        EntryInputs {
            hidden_root: self.hidden.path(),
            decoy_root: DecoyRoot {
                source: PathBuf::from("/dev/vda2"),
                fstype: "ext4".into(),
                data: None,
            },
            nixos: false,
            builder: None,
            binary: Path::new("/proc/self/exe"),
            config_toml: Some("hidden_volume_root = \"/x\"\n".into()),
            session_units: Vec::new(),
            backend: vec!["data".into()],
            persona: Default::default(),
            operator: None,
            rebuild_space_mb: 0,
            read_only_disks: false,
            accepted_decoy_storage: None,
        }
    }
}

fn fstype_at(path: &Path) -> Option<String> {
    let entries = read_mountinfo().unwrap();
    top_mount_at(&entries, path).map(|e| e.fstype.clone())
}

#[test]
fn a_decoy_fstab_in_a_separate_store_is_read_before_the_next_root_needs_it() {
    // NixOS links /etc/fstab into /nix/store; with the store on its own
    // filesystem (a separate /nix, a VM's store share) the next root's
    // store is empty until the policy has overlaid it. The VM run of the
    // first version found exactly this: no decision, no store, PID 1's
    // init missing.
    let _ = Rerun::new(test_path!(
        a_decoy_fstab_in_a_separate_store_is_read_before_the_next_root_needs_it
    ))
    .in_user_mount_ns()
    .run(|| {
        let world = World::new();
        let decoy = world.decoy.path();
        let fstab = std::fs::read(decoy.join("etc/fstab")).unwrap();
        let store = ScratchTmpfs::new("");
        std::fs::write(
            store.path().join("etc-fstab"),
            [fstab.as_slice(), b"store /nix/store ext4 defaults 0 0\n"].concat(),
        )
        .unwrap();
        world.decoy.mkdir("nix/store");
        nix::mount::mount(
            Some(store.path()),
            &decoy.join("nix/store"),
            None::<&str>,
            nix::mount::MsFlags::MS_BIND,
            None::<&str>,
        )
        .unwrap();
        std::fs::remove_file(decoy.join("etc/fstab")).unwrap();
        std::os::unix::fs::symlink("/nix/store/etc-fstab", decoy.join("etc/fstab")).unwrap();

        let paths = world.paths();
        let entry =
            entry::prepare(&paths, &world.inputs(), &FakeHost::default()).expect("the entry");
        let nextroot = paths.nextroot();
        assert_eq!(
            fstype_at(&nextroot.join("nix/store")).as_deref(),
            Some("overlay")
        );
        assert!(nextroot.join("nix/store/etc-fstab").is_file());
        assert_eq!(
            fstype_at(&nextroot.join("home")).as_deref(),
            Some("overlay")
        );
        assert!(entry.plan.masks.contains(&"dev-vda4.swap".to_string()));
        entry::rollback(&paths);
    });
}

#[test]
fn the_decoy_filesystems_are_carried_through_the_session_and_put_back_on_the_way_back() {
    // The way back mounts the decoy root device alone; the VM run found
    // the decoy init missing because its store is a filesystem of its own.
    let _ = Rerun::new(test_path!(
        the_decoy_filesystems_are_carried_through_the_session_and_put_back_on_the_way_back
    ))
    .in_user_mount_ns()
    .run(|| {
        let world = World::new();
        let paths = world.paths();
        let entry =
            entry::prepare(&paths, &world.inputs(), &FakeHost::default()).expect("the entry");
        let mut carried = entry.plan.carried.clone();
        let targets: Vec<_> = carried.iter().map(|c| c.target.clone()).collect();
        assert!(targets.contains(&PathBuf::from("/home")), "{targets:?}");
        assert!(targets.contains(&PathBuf::from("/boot")), "{targets:?}");
        assert!(carried.iter().all(|c| !c.read_only));
        for mount in &mut carried {
            // The hidden session sees the hidden volume at its own path;
            // from the decoy it is reached through the next root.
            assert!(mount.at.starts_with(world.hidden.path()));
            mount.at = paths.in_nextroot(&mount.at);
            assert!(
                std::fs::write(mount.at.join("x"), "").is_err(),
                "carried read-only"
            );
        }
        let home = carried
            .iter()
            .find(|c| c.target == Path::new("/home"))
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(home.at.join("decoy-file")).unwrap(),
            "decoy"
        );

        // The way back: a bare decoy root gets its filesystems again,
        // writable as the decoy had them.
        let back = ScratchTmpfs::new("");
        back.mkdir("home");
        back.mkdir("boot");
        carry::restore(&carried, back.path()).expect("restored");
        assert_eq!(
            std::fs::read_to_string(back.path().join("home/decoy-file")).unwrap(),
            "decoy"
        );
        std::fs::write(back.path().join("boot/written-back"), "").unwrap();
        assert!(world._esp.path().join("written-back").exists());

        // A missing mount point is refused, never created on the decoy.
        let bare = ScratchTmpfs::new("");
        assert!(carry::restore(&carried, bare.path()).is_err());
        assert!(!bare.path().join("home").exists());
        entry::rollback(&paths);
    });
}

#[test]
fn the_entry_records_every_decoy_mount_the_way_back_makes_again() {
    // NixOS's read-only bind over a store on the root filesystem, a
    // read-only bind of /home stacked on the decoy's own /home, and a tmpfs
    // the initrd mounted, like the test VMs' /nix/.rw-store under their
    // store's overlay: the hidden systemd mounts its own, so the session
    // carries the decoy's.
    let _ = Rerun::new(test_path!(
        the_entry_records_every_decoy_mount_the_way_back_makes_again
    ))
    .in_user_mount_ns()
    .run(|| {
        let world = World::new();
        let decoy = world.decoy.path();
        let store = world.decoy.mkdir("nix/store");
        bind(&store, &store);
        remount(
            &store,
            nix::mount::MsFlags::MS_RDONLY | nix::mount::MsFlags::MS_NOSUID,
        );
        let home = decoy.join("home");
        bind(&home, &home);
        remount(&home, nix::mount::MsFlags::MS_RDONLY);
        let rw_store = ScratchTmpfs::new("");
        bind(rw_store.path(), &world.decoy.mkdir("nix/.rw-store"));
        let fstab = decoy.join("etc/fstab");
        let text = std::fs::read_to_string(&fstab).unwrap();
        std::fs::write(
            &fstab,
            text + "tmpfs /nix/.rw-store tmpfs mode=0755,x-initrd.mount 0 0\n",
        )
        .unwrap();
        let paths = world.paths();

        let entry =
            entry::prepare(&paths, &world.inputs(), &FakeHost::default()).expect("the entry");

        let recorded: Vec<(&Path, &str)> = entry
            .plan
            .decoy_mounts
            .iter()
            .map(|m| (m.target.as_path(), m.options.as_str()))
            .collect();
        assert_eq!(
            recorded,
            [
                (Path::new("/"), "rw,relatime"),
                (Path::new("/boot"), "rw,relatime"),
                (Path::new("/home"), "rw,relatime"),
                (Path::new("/nix/store"), "ro,nosuid,relatime"),
                (Path::new("/home"), "ro,relatime"),
                (Path::new("/nix/.rw-store"), "rw,relatime"),
            ]
        );
        let store_bind = &entry.plan.decoy_mounts[3];
        assert_eq!(store_bind.source, MountSource::Root);
        assert_eq!(store_bind.path, Path::new("nix/store"));
        let carried: Vec<&Path> = entry
            .plan
            .carried
            .iter()
            .map(|c| c.target.as_path())
            .collect();
        assert!(
            carried.contains(&Path::new("/nix/.rw-store")),
            "{carried:?}"
        );
        assert!(
            entry
                .plan
                .carried
                .iter()
                .all(|c| c.dev.is_some() && c.root.is_some())
        );
        assert!(entry.warnings.is_empty(), "{:?}", entry.warnings);
        entry::rollback(&paths);
    });
}

#[test]
fn a_decoy_mount_lost_under_a_carried_filesystem_is_reported() {
    // A tmpfs mounted by hand over the decoy's /home covers it: the session
    // carries what the decoy shows at /home, and nothing it holds reaches the
    // filesystem below.
    let _ = Rerun::new(test_path!(
        a_decoy_mount_lost_under_a_carried_filesystem_is_reported
    ))
    .in_user_mount_ns()
    .run(|| {
        let world = World::new();
        let cover = ScratchTmpfs::new("");
        bind(cover.path(), &world.decoy.path().join("home"));
        let paths = world.paths();

        let entry =
            entry::prepare(&paths, &world.inputs(), &FakeHost::default()).expect("the entry");

        assert_eq!(entry.warnings.len(), 1, "{:?}", entry.warnings);
        assert!(entry.warnings[0].contains("/home"), "{}", entry.warnings[0]);
        let homes = entry
            .plan
            .decoy_mounts
            .iter()
            .filter(|m| m.target == Path::new("/home"))
            .count();
        assert_eq!(homes, 1, "the carried cover alone");
        entry::rollback(&paths);
    });
}

#[test]
fn a_lost_decoy_mount_that_systemd_keeps_at_a_soft_reboot_is_reported() {
    // An initrd's tmpfs that the decoy's fstab does not list, marked
    // x-initrd.mount in utab: a plain soft-reboot keeps it, the way back has
    // nothing to make it from. A tmpfs mounted by hand is gone after a plain
    // soft-reboot as well, and goes to the debug log alone.
    let _ = Rerun::new(test_path!(
        a_lost_decoy_mount_that_systemd_keeps_at_a_soft_reboot_is_reported
    ))
    .in_user_mount_ns()
    .run(|| {
        let world = World::new();
        let initrd = ScratchTmpfs::new("");
        let by_hand = ScratchTmpfs::new("");
        let keys = world.decoy.mkdir("srv/keys");
        bind(initrd.path(), &keys);
        bind(by_hand.path(), &world.decoy.mkdir("srv/other"));
        let mount = top_mount_at(&read_mountinfo().unwrap(), &keys)
            .unwrap()
            .clone();
        std::fs::write(
            world.run.path().join("mount/utab"),
            utab_line(&mount, "/sysroot/srv/keys", "x-initrd.mount"),
        )
        .unwrap();
        let paths = world.paths();

        let entry =
            entry::prepare(&paths, &world.inputs(), &FakeHost::default()).expect("the entry");

        assert_eq!(entry.warnings.len(), 1, "{:?}", entry.warnings);
        let warning = &entry.warnings[0];
        assert!(warning.contains("mount /srv/keys (tmpfs"), "{warning}");
        assert!(
            warning.contains("a plain soft-reboot keeps it"),
            "{warning}"
        );
        entry::rollback(&paths);
    });
}

#[test]
fn the_automount_of_a_filesystem_the_entry_binds_read_only_is_skipped() {
    // The ESP behind an automount: the session binds it read-only at /boot,
    // where the hidden systemd's automount would fail and take
    // local-fs.target down with it. The target requires the automount, so it
    // is skipped rather than masked, which would leave the target unreached.
    let _ = Rerun::new(test_path!(
        the_automount_of_a_filesystem_the_entry_binds_read_only_is_skipped
    ))
    .in_user_mount_ns()
    .run(|| {
        let world = World::new();
        let fstab = world.decoy.path().join("etc/fstab");
        let text = std::fs::read_to_string(&fstab).unwrap().replace(
            "/boot vfat umask=0077",
            "/boot vfat umask=0077,x-systemd.automount",
        );
        std::fs::write(&fstab, text).unwrap();
        let paths = world.paths();

        let entry =
            entry::prepare(&paths, &world.inputs(), &FakeHost::default()).expect("the entry");

        let skipped: Vec<&String> = entry.plan.skips.iter().flat_map(|s| &s.units).collect();
        assert_eq!(skipped, ["boot.automount"], "{:?}", entry.plan.skips);
        assert!(entry.plan.skips[0].device.is_none() && entry.plan.skips[0].pulled.is_empty());
        assert!(
            !entry.plan.masks.contains(&"boot.automount".to_string()),
            "{:?}",
            entry.plan.masks
        );
        assert!(!entry.plan.masks.contains(&"boot.mount".to_string()));
        assert!(
            entry
                .plan
                .policy_mounts
                .iter()
                .any(|m| m.target == Path::new("/boot") && m.kind == PolicyMountKind::ReadOnlyBind)
        );
        entry::rollback(&paths);
    });
}

#[test]
fn the_automount_of_a_symlinked_mount_point_is_skipped_at_its_real_path() {
    // The decoy keeps /data at var/data and mounts the filesystem there; its
    // fstab names /data behind an automount. The session overlays /var/data,
    // so the automount the hidden systemd generates for that path, the one
    // that would fail on the taken mount point, must be the one skipped.
    let _ = Rerun::new(test_path!(
        the_automount_of_a_symlinked_mount_point_is_skipped_at_its_real_path
    ))
    .in_user_mount_ns()
    .run(|| {
        let world = World::new();
        let decoy = world.decoy.path();
        let data = ScratchTmpfs::new("");
        bind(data.path(), &world.decoy.mkdir("var/data"));
        std::os::unix::fs::symlink("var/data", decoy.join("data")).unwrap();
        let fstab = decoy.join("etc/fstab");
        let text = std::fs::read_to_string(&fstab).unwrap();
        std::fs::write(
            &fstab,
            text + "/dev/vdd1 /data ext4 defaults,x-systemd.automount 0 2\n",
        )
        .unwrap();
        let paths = world.paths();

        let entry =
            entry::prepare(&paths, &world.inputs(), &FakeHost::default()).expect("the entry");

        assert!(
            entry
                .plan
                .policy_mounts
                .iter()
                .any(|m| m.target == Path::new("/var/data") && m.kind == PolicyMountKind::Overlay),
            "{:?}",
            entry.plan.policy_mounts
        );
        let skipped: Vec<&String> = entry.plan.skips.iter().flat_map(|s| &s.units).collect();
        assert!(
            skipped.contains(&&"var-data.automount".to_string()),
            "{skipped:?}"
        );
        assert!(
            !skipped.contains(&&"data.automount".to_string()),
            "{skipped:?}"
        );
        assert!(!entry.plan.masks.iter().any(|m| m.ends_with(".automount")));
        entry::rollback(&paths);
    });
}

#[test]
fn an_entry_the_next_root_resolves_elsewhere_is_masked_there_too() {
    // The decoy links /opt to var/opt, where its fstab entry is not mounted
    // now: masked as var-opt.mount. An earlier session replaced the link with
    // a directory of its own, so the hidden systemd reads the same entry as
    // /opt; left free, opt.mount would mount the decoy's disk read-write.
    let _ = Rerun::new(test_path!(
        an_entry_the_next_root_resolves_elsewhere_is_masked_there_too
    ))
    .in_user_mount_ns()
    .run(|| {
        let world = World::new();
        let decoy = world.decoy.path();
        world.decoy.mkdir("var/opt");
        std::os::unix::fs::symlink("var/opt", decoy.join("opt")).unwrap();
        let fstab = decoy.join("etc/fstab");
        let text = std::fs::read_to_string(&fstab).unwrap();
        std::fs::write(&fstab, text + "/dev/vde1 /opt ext4 defaults 0 2\n").unwrap();
        world.hidden.mkdir("root/upper/opt");
        let paths = world.paths();

        let entry =
            entry::prepare(&paths, &world.inputs(), &FakeHost::default()).expect("the entry");

        let masks = &entry.plan.masks;
        assert!(masks.contains(&"var-opt.mount".to_string()), "{masks:?}");
        assert!(masks.contains(&"opt.mount".to_string()), "{masks:?}");
        entry::rollback(&paths);
    });
}

#[test]
fn an_entry_a_link_leads_into_the_hidden_volume_is_masked_there() {
    // The decoy's fstab names /data, an empty directory whose disk is not
    // mounted now: masked as data.mount. An earlier session moved /data onto
    // the hidden volume, replacing the directory with a link into it. The
    // hidden systemd follows the link; left free, the unit it generates there
    // would mount the decoy's disk read-write inside the hidden volume.
    let _ = Rerun::new(test_path!(
        an_entry_a_link_leads_into_the_hidden_volume_is_masked_there
    ))
    .in_user_mount_ns()
    .run(|| {
        let world = World::new();
        let decoy = world.decoy.path();
        world.decoy.mkdir("data");
        let fstab = decoy.join("etc/fstab");
        let text = std::fs::read_to_string(&fstab).unwrap();
        std::fs::write(&fstab, text + "/dev/vdf1 /data ext4 defaults,nofail 0 2\n").unwrap();
        let moved = world.hidden.mkdir("data");
        world.hidden.mkdir("root/upper");
        std::os::unix::fs::symlink(&moved, world.hidden.path().join("root/upper/data")).unwrap();
        let paths = world.paths();

        let entry =
            entry::prepare(&paths, &world.inputs(), &FakeHost::default()).expect("the entry");

        let masks = &entry.plan.masks;
        assert!(masks.contains(&"data.mount".to_string()), "{masks:?}");
        let inside = nails_core::session::fstab::mount_unit(&moved);
        assert!(masks.contains(&inside), "{inside} is not in {masks:?}");
        entry::rollback(&paths);
    });
}

#[test]
fn the_entry_builds_the_next_root_by_the_fstab_policy_and_arms_the_plan() {
    let _ = Rerun::new(test_path!(
        the_entry_builds_the_next_root_by_the_fstab_policy_and_arms_the_plan
    ))
    .in_user_mount_ns()
    .run(|| {
        let world = World::new();
        let paths = world.paths();
        let host = FakeHost {
            nextroot: Some(paths.nextroot()),
            ..FakeHost::default()
        };
        let mut inputs = world.inputs();
        // dropbox is in the decoy home; the other two are in no directory
        // the inventory reads and are masked by their names alone.
        inputs.persona.mask_inherited = vec![
            "dropbox".into(),
            "not-inventoried".into(),
            "not-inventoried.timer".into(),
        ];
        inputs.operator = Some(nails_core::TargetUser::for_test(
            nix::unistd::getuid().as_raw(),
            nix::unistd::getgid().as_raw(),
            "alice",
            "/home/alice",
            "/bin/sh",
        ));
        let decoy_root = seed_utab(&world);
        let entry = entry::prepare(&paths, &inputs, &host).expect("the entry");
        let nextroot = paths.nextroot();
        assert_named_mount(&paths, &decoy_root);
        // The drop-in is live before anything is mounted at the next root,
        // so an activation killed during the build leaves nothing a later
        // soft-reboot would enter.
        assert_eq!(host.populated_at_first_reload.get(), Some(false));

        assert_eq!(fstype_at(&nextroot).as_deref(), Some("overlay"));
        // The ESP is read-only, /home is an overlay with its own upper.
        let boot = std::fs::write(nextroot.join("boot/x"), "");
        assert_eq!(boot.unwrap_err().raw_os_error(), Some(nix::libc::EROFS));
        assert_eq!(
            fstype_at(&nextroot.join("home")).as_deref(),
            Some("overlay")
        );
        std::fs::write(nextroot.join("home/hidden-file"), "hidden").unwrap();
        // The persona mask is in the hidden /home's upper, not on the decoy.
        let mask =
            std::fs::read_to_string(nextroot.join("home/alice/.config/autostart/dropbox.desktop"))
                .unwrap();
        assert!(mask.contains("Hidden=true"), "{mask}");
        assert!(
            !std::fs::read_to_string(
                world
                    .decoy
                    .path()
                    .join("home/alice/.config/autostart/dropbox.desktop")
            )
            .unwrap()
            .contains("Hidden=true")
        );
        // Names the inventory never saw are masked too, by their suffix,
        // and only in the hidden /home.
        let unlisted = std::fs::read_to_string(
            nextroot.join("home/alice/.config/autostart/not-inventoried.desktop"),
        )
        .unwrap();
        assert!(unlisted.contains("Hidden=true"), "{unlisted}");
        assert_eq!(
            std::fs::read_link(
                nextroot.join("home/alice/.config/systemd/user/not-inventoried.timer")
            )
            .unwrap(),
            Path::new("/dev/null")
        );
        for decoy_path in [
            "home/alice/.config/autostart/not-inventoried.desktop",
            "home/alice/.config/systemd/user/not-inventoried.timer",
        ] {
            assert!(
                world
                    .decoy
                    .path()
                    .join(decoy_path)
                    .symlink_metadata()
                    .is_err(),
                "{decoy_path} reached the decoy"
            );
        }
        assert!(!world.decoy.path().join("home/hidden-file").exists());
        assert!(
            world
                .hidden
                .path()
                .join("root/mounts/home/upper/hidden-file")
                .exists()
        );
        assert_eq!(
            std::fs::read_to_string(nextroot.join("home/decoy-file")).unwrap(),
            "decoy"
        );
        // The hidden volume is reachable at its own path, /run is bound.
        assert!(
            paths
                .in_nextroot(world.hidden.path())
                .join("root/upper")
                .is_dir()
        );
        assert!(nextroot.join("run/mount/utab").exists());

        // Swap and the unmounted disk are masked at entry, not now.
        assert!(entry.plan.masks.contains(&"dev-vda4.swap".to_string()));
        assert!(entry.plan.masks.contains(&"srv-data.mount".to_string()));
        assert!(
            !world
                .run
                .path()
                .join("systemd/system/dev-vda4.swap")
                .exists()
        );
        let kinds: Vec<_> = entry.plan.policy_mounts.iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&PolicyMountKind::ReadOnlyBind));
        assert!(kinds.contains(&PolicyMountKind::Overlay));
        assert!(kinds.contains(&PolicyMountKind::HiddenVolume));

        // The runtime directory, the drop-in and the armed plan.
        assert!(paths.runtime().join(SNAPSHOT_NAME).exists());
        assert!(paths.binary_copy().is_file());
        assert!(world.run.path().join(DROPIN_DIR).join(DROPIN_NAME).exists());
        assert_eq!(host.reloads.get(), 1);
        let plan = Plan::load(&paths.plan()).unwrap();
        assert!(plan.armed_for(Direction::Enter, unix_now()));
        assert_eq!(plan.hidden.init, Path::new("/usr/lib/systemd/systemd"));
        // The hidden volume's device, which the attach gate holds the
        // session's hidden root to.
        let hidden = world.hidden.path().canonicalize().unwrap();
        let hidden_dev = top_mount_at(&read_mountinfo().unwrap(), &hidden)
            .map(|mount| mount.dev.clone())
            .expect("the hidden tmpfs is mounted");
        assert_eq!(plan.hidden_dev.as_deref(), Some(hidden_dev.as_str()));

        // A line for a mount the switch carries: the next root's /home.
        let carried = add_utab_line(&world, &nextroot.join("home"), "/home");

        // The transition consumes it: masks in place, entry recorded, and of
        // utab only the line of the mount the switch carries is left.
        let env = Env {
            run: paths.run.clone(),
            nextroot: nextroot.clone(),
            runtime_dir: paths.runtime(),
            kmsg: paths.run.join("no-kmsg"),
            systemctl: None,
            now: unix_now(),
            mounts: read_mountinfo().unwrap(),
        };
        assert_eq!(transition::run(&env), Outcome::Entered);
        assert!(
            world
                .run
                .path()
                .join("systemd/system/dev-vda4.swap")
                .exists()
        );
        assert!(Plan::load(&paths.plan()).unwrap().entered_at.is_some());
        assert_utab(&world, &carried);
        entry::rollback(&paths);
    });
}

/// libmount's utab line for `mount` at `target`, with `options`.
fn utab_line(mount: &MountEntry, target: &str, options: &str) -> String {
    format!(
        "ID={} SRC={} TARGET={target} ROOT={} OPTS={options}\n",
        mount.mount_id,
        mount.source.display(),
        mount.root.display()
    )
}

/// Make the decoy's utab hold libmount's line for the decoy root, as an
/// initrd writes it, under the root's real mount ID; returns that mount.
fn seed_utab(world: &World) -> MountEntry {
    let root = top_mount_at(&read_mountinfo().unwrap(), world.decoy.path())
        .unwrap()
        .clone();
    std::fs::write(
        world.run.path().join("mount/utab"),
        utab_line(&root, "/sysroot", "x-initrd.mount"),
    )
    .unwrap();
    root
}

/// Add to the decoy's utab a line for the mount at `path`, as libmount
/// writes it for `target` inside the next root; returns the line.
fn add_utab_line(world: &World, path: &Path, target: &str) -> String {
    let mount = top_mount_at(&read_mountinfo().unwrap(), path)
        .unwrap()
        .clone();
    let line = utab_line(&mount, target, "X-kept");
    let utab = world.run.path().join("mount/utab");
    let mut text = std::fs::read_to_string(&utab).unwrap();
    text.push_str(&line);
    std::fs::write(&utab, text).unwrap();
    line
}

/// Beside its copy of utab, the entry keeps the mount table line of each
/// mount the copy names, here `mount`: the way back finds it by that line.
fn assert_named_mount(paths: &Paths, mount: &MountEntry) {
    let named = std::fs::read_to_string(paths.runtime().join(UTAB_MOUNTS_NAME)).unwrap();
    assert_eq!(parse_mountinfo(&named), std::slice::from_ref(mount));
}

/// The decoy's utab holds `expected` and nothing else.
fn assert_utab(world: &World, expected: &str) {
    let text = std::fs::read_to_string(world.run.path().join("mount/utab")).unwrap();
    assert_eq!(text, expected);
}

/// The mount points outside `inside`, sorted, a stacked mount once per
/// layer.
fn mounts_outside(inside: &Path) -> Vec<PathBuf> {
    let mut points: Vec<PathBuf> = read_mountinfo()
        .unwrap()
        .into_iter()
        .map(|e| e.mount_point)
        .filter(|m| !m.starts_with(inside))
        .collect();
    points.sort();
    points
}

/// Make the tree at `path` shared, as systemd makes `/` at boot.
fn make_rshared(path: &Path) {
    rustix::mount::mount_change(
        path,
        rustix::mount::MountPropagationFlags::SHARED | rustix::mount::MountPropagationFlags::REC,
    )
    .unwrap();
}

fn bind(source: &Path, target: &Path) {
    nix::mount::mount(
        Some(source),
        target,
        None::<&str>,
        nix::mount::MsFlags::MS_BIND,
        None::<&str>,
    )
    .unwrap();
}

/// Give the bind at `target` the per-mount `flags`, as `mount -o remount,bind`.
fn remount(target: &Path, flags: nix::mount::MsFlags) {
    nix::mount::mount(
        None::<&str>,
        target,
        None::<&str>,
        nix::mount::MsFlags::MS_REMOUNT | nix::mount::MsFlags::MS_BIND | flags,
        None::<&str>,
    )
    .unwrap();
}

#[test]
fn nothing_the_entry_mounts_shows_in_the_decoy_s_shared_tree() {
    // On the decoy every mount is shared, and a bind of one joins its
    // peer group: a carried /boot below the hidden volume's bind showed
    // below the decoy's /mnt/data, and the bind of an ESP nested below
    // /boot stacked a second ESP on the decoy's /boot/efi. The switch
    // could then not unmount the hidden volume.
    let _ = Rerun::new(test_path!(
        nothing_the_entry_mounts_shows_in_the_decoy_s_shared_tree
    ))
    .in_user_mount_ns()
    .run(|| {
        let world = World::new();
        let esp = ScratchTmpfs::new("");
        let nested = world.decoy.mkdir("boot/efi");
        bind(esp.path(), &nested);
        let fstab = world.decoy.path().join("etc/fstab");
        let text = std::fs::read_to_string(&fstab).unwrap();
        std::fs::write(&fstab, text + "/dev/vda15 /boot/efi vfat umask=0077 0 2\n").unwrap();
        for tree in [world.decoy.path(), world.hidden.path(), world.run.path()] {
            make_rshared(tree);
        }
        let paths = world.paths();
        let before = mounts_outside(&paths.nextroot());

        let entry =
            entry::prepare(&paths, &world.inputs(), &FakeHost::default()).expect("the entry");

        let targets: Vec<_> = entry
            .plan
            .carried
            .iter()
            .map(|c| c.target.clone())
            .collect();
        assert!(targets.contains(&PathBuf::from("/boot/efi")), "{targets:?}");
        assert_eq!(mounts_outside(&paths.nextroot()), before);
        // What the switch does in the decoy: nothing below the hidden
        // volume keeps it busy.
        nix::mount::umount2(world.hidden.path(), nix::mount::MntFlags::empty())
            .expect("the hidden volume unmounts");
        entry::rollback(&paths);
    });
}

#[test]
#[allow(unsafe_code)]
fn a_service_s_mount_namespace_sees_the_whole_next_root() {
    // logind looks for an OS tree at /run/nextroot from a mount namespace
    // of its own, a slave of the decoy's made long before the entry, to
    // turn a plain reboot into a soft-reboot that the transition then
    // disarms. It must find the mounts below the next root there (here a
    // separate /home, on NixOS the store that holds os-release).
    let _ = Rerun::new(test_path!(
        a_service_s_mount_namespace_sees_the_whole_next_root
    ))
    .in_user_mount_ns()
    .run(|| {
        use std::os::unix::process::CommandExt;
        let world = World::new();
        for tree in [world.decoy.path(), world.hidden.path(), world.run.path()] {
            make_rshared(tree);
        }
        let paths = world.paths();
        let done = world.run.path().join("entry-done");
        let seen = paths.nextroot().join("home/decoy-file");
        let mut service = std::process::Command::new("sh");
        service.arg("-c").arg(format!(
            "i=0; while [ ! -e '{}' ] && [ $i -lt 600 ]; do sleep 0.05; i=$((i+1)); done; \
             test -e '{}'",
            done.display(),
            seen.display()
        ));
        // SAFETY: unshare and mount are plain system calls on constant
        // arguments, made in the child between fork and exec.
        unsafe {
            service.pre_exec(|| {
                nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNS)?;
                nix::mount::mount(
                    None::<&str>,
                    "/",
                    None::<&str>,
                    nix::mount::MsFlags::MS_REC | nix::mount::MsFlags::MS_SLAVE,
                    None::<&str>,
                )?;
                Ok(())
            });
        }
        let mut service = service.spawn().unwrap();

        let entry = entry::prepare(&paths, &world.inputs(), &FakeHost::default());
        std::fs::write(&done, "").unwrap();
        let status = service.wait().unwrap();
        entry.expect("the entry");
        assert!(
            status.success(),
            "the service's namespace lacks {}",
            seen.display()
        );
        entry::rollback(&paths);
    });
}

/// The mount points at and below `point`, each with whether its mount is
/// shared (a `shared:` tag in `/proc/self/mountinfo`).
fn propagation_at(point: &Path) -> Vec<(PathBuf, bool)> {
    std::fs::read_to_string("/proc/self/mountinfo")
        .unwrap()
        .lines()
        .filter_map(|line| {
            let (fields, _) = line.split_once(" - ")?;
            let fields: Vec<&str> = fields.split(' ').collect();
            let mount_point = PathBuf::from(fields.get(4)?);
            let shared = fields.iter().skip(6).any(|f| f.starts_with("shared:"));
            mount_point
                .starts_with(point)
                .then_some((mount_point, shared))
        })
        .collect()
}

/// The mount table lines below the next root that a mount namespace made
/// before the entry still holds once the entry ran and `undo` undid it. The
/// namespace is a slave of this one, as a sandboxed service's or logind's is.
#[allow(unsafe_code)]
fn left_in_a_service_namespace(
    world: &World,
    host: &FakeHost,
    undo: impl FnOnce(&Paths, nails_core::Result<entry::Entry>),
) -> String {
    use std::os::unix::process::CommandExt;
    for tree in [world.decoy.path(), world.hidden.path(), world.run.path()] {
        make_rshared(tree);
    }
    let paths = world.paths();
    let done = world.run.path().join("undone");
    let mut service = std::process::Command::new("sh");
    service.arg("-c").arg(format!(
        "i=0; while [ ! -e '{}' ] && [ $i -lt 600 ]; do sleep 0.05; i=$((i+1)); done; \
         grep -F ' {}' /proc/self/mountinfo || true",
        done.display(),
        paths.nextroot().display()
    ));
    service.stdout(std::process::Stdio::piped());
    // SAFETY: unshare and mount are plain system calls on constant
    // arguments, made in the child between fork and exec.
    unsafe {
        service.pre_exec(|| {
            nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNS)?;
            nix::mount::mount(
                None::<&str>,
                "/",
                None::<&str>,
                nix::mount::MsFlags::MS_REC | nix::mount::MsFlags::MS_SLAVE,
                None::<&str>,
            )?;
            Ok(())
        });
    }
    let service = service.spawn().unwrap();
    undo(&paths, entry::prepare(&paths, &world.inputs(), host));
    std::fs::write(&done, "").unwrap();
    String::from_utf8(service.wait_with_output().unwrap().stdout).unwrap()
}

#[test]
fn a_rolled_back_entry_leaves_nothing_in_a_service_s_namespace() {
    // A namespace made before the entry received a copy of every mount below
    // the next root: the hidden volume's bind and the overlays with their
    // uppers on it. A rollback of the finished tree must take those copies
    // too; they would show the hidden volume's layers to every user and keep
    // its filesystem busy until the service restarts.
    let _ = Rerun::new(test_path!(
        a_rolled_back_entry_leaves_nothing_in_a_service_s_namespace
    ))
    .in_user_mount_ns()
    .run(|| {
        let world = World::new();
        let left = left_in_a_service_namespace(&world, &FakeHost::default(), |paths, entry| {
            entry.expect("the entry");
            let nextroot = paths.nextroot();
            let tree = propagation_at(&nextroot);
            assert!(
                tree.iter()
                    .any(|(point, shared)| *point == nextroot && *shared),
                "the next root's own mount stays shared until the switch: {tree:?}"
            );
            assert!(
                tree.iter()
                    .all(|(point, shared)| *point == nextroot || !shared),
                "everything below it is private: {tree:?}"
            );
            assert!(entry::rollback(paths).is_empty());
        });
        assert_eq!(left, "", "the service's namespace keeps them");
    });
}

#[test]
fn an_entry_refused_at_its_last_check_leaves_nothing_in_a_service_s_namespace() {
    // Refused once the tree is complete (here at the init check), the entry
    // rolls back by itself and takes the copies with it.
    let _ = Rerun::new(test_path!(
        an_entry_refused_at_its_last_check_leaves_nothing_in_a_service_s_namespace
    ))
    .in_user_mount_ns()
    .run(|| {
        let world = World::new();
        std::fs::remove_file(world.decoy.path().join("usr/lib/systemd/systemd")).unwrap();
        let left = left_in_a_service_namespace(&world, &FakeHost::default(), |_, entry| {
            let error = entry.expect_err("the entry is refused");
            assert!(error.to_string().contains("does not resolve"), "{error}");
        });
        assert_eq!(left, "", "the service's namespace keeps them");
    });
}

#[test]
fn a_rollback_gives_the_decoy_back_its_kernel_paths_and_unit_masks() {
    // Every entry records the kernel's helper paths before anything runs (an
    // activation in a session entered without a build points them at its own
    // store too), and a switch that fails after the entry transition leaves
    // the session's masks in /run. A rollback (`nails recover` runs one)
    // gives the decoy back both.
    let _ = Rerun::new(test_path!(
        a_rollback_gives_the_decoy_back_its_kernel_paths_and_unit_masks
    ))
    .in_user_mount_ns()
    .run(|| {
        let world = World::new();
        std::fs::write(
            world
                .decoy
                .path()
                .join("usr/lib/systemd/system/systemd-boot-random-seed.service"),
            "",
        )
        .unwrap();
        let helpers = tempfile::tempdir().unwrap();
        let modprobe = helpers.path().join("modprobe");
        let firmware = helpers.path().join("path");
        std::fs::write(&modprobe, "/nix/store/decoy-kmod/bin/modprobe\n").unwrap();
        std::fs::write(&firmware, "/nix/store/decoy-firmware/lib/firmware\n").unwrap();
        let host = FakeHost {
            helpers: vec![modprobe.clone(), firmware.clone()],
            ..FakeHost::default()
        };
        let paths = world.paths();
        let entry = entry::prepare(&paths, &world.inputs(), &host).expect("the entry");
        let recorded: Vec<&str> = entry
            .plan
            .kernel_settings
            .iter()
            .map(|s| s.value.as_str())
            .collect();
        assert_eq!(
            recorded,
            [
                "/nix/store/decoy-kmod/bin/modprobe",
                "/nix/store/decoy-firmware/lib/firmware"
            ]
        );
        let plan = &entry.plan;
        assert!(!plan.masks.is_empty(), "{plan:?}");
        assert_eq!(plan.boot_masks, ["systemd-boot-random-seed.service"]);
        // The entry transition masked the units, an activation in the
        // session repointed the kernel, and then the switch failed.
        runtime_units::mask_units(&paths.run, &plan.masks).unwrap();
        runtime_units::mask_units_best_effort(&paths.run, &plan.boot_masks);
        std::fs::write(&modprobe, "/nix/store/hidden-kmod/bin/modprobe\n").unwrap();
        std::fs::write(&firmware, "/nix/store/hidden-firmware/lib/firmware").unwrap();

        entry::rollback(&paths);

        assert_eq!(
            std::fs::read_to_string(&modprobe).unwrap(),
            "/nix/store/decoy-kmod/bin/modprobe"
        );
        assert_eq!(
            std::fs::read_to_string(&firmware).unwrap(),
            "/nix/store/decoy-firmware/lib/firmware"
        );
        for (dir, names) in [
            ("systemd/system", &plan.masks),
            ("systemd/system.control", &plan.boot_masks),
        ] {
            for name in names {
                let mask = paths.run.join(dir).join(name);
                assert!(std::fs::symlink_metadata(&mask).is_err(), "{mask:?} stays");
            }
        }
    });
}

#[test]
fn the_hidden_root_masks_are_written_at_the_switch_only() {
    // A root with the two units that failed on Debian 13's root overlay and
    // Ubuntu 26.04's GRUB unit. The entry picks the masks, the entry
    // transition writes them at the switch, never before (the decoy's PID 1
    // must not reload with them), and a rollback after a failed switch gives
    // the decoy its units and generators back.
    let _ = Rerun::new(test_path!(
        the_hidden_root_masks_are_written_at_the_switch_only
    ))
    .in_user_mount_ns()
    .run(|| {
        let world = World::new();
        let units = world.decoy.path().join("usr/lib/systemd/system");
        for unit in [
            "systemd-remount-fs.service",
            "systemd-growfs-root.service",
            "grub2-common.service",
        ] {
            std::fs::write(units.join(unit), "").unwrap();
        }
        let paths = world.paths();
        let entry =
            entry::prepare(&paths, &world.inputs(), &FakeHost::default()).expect("the entry");
        let plan = &entry.plan;
        assert_eq!(
            plan.boot_masks,
            [
                "grub2-common.service",
                "systemd-remount-fs.service",
                "systemd-growfs-root.service"
            ]
        );
        assert_eq!(plan.generator_masks, ["systemd-gpt-auto-generator"]);
        let control = paths.run.join(runtime_units::RUNTIME_CONTROL_DIR);
        let generators = paths.run.join(runtime_units::GENERATOR_DIR);
        assert!(!control.exists(), "a unit is masked before the switch");
        assert!(
            !generators.exists(),
            "a generator is masked before the switch"
        );

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
        for unit in &plan.boot_masks {
            assert_eq!(
                std::fs::read_link(control.join(unit)).unwrap(),
                Path::new("/dev/null"),
                "{unit}"
            );
        }
        assert_eq!(
            std::fs::read_link(generators.join("systemd-gpt-auto-generator")).unwrap(),
            Path::new("/dev/null")
        );

        // The switch failed: the decoy runs again over the same /run.
        entry::rollback(&paths);
        assert!(!control.exists(), "the decoy's units stay masked");
        assert!(!generators.exists(), "the decoy's generators stay masked");
    });
}

/// Every path below `dir` with its kind: what a test compares to see that a
/// tree did not change.
fn listing(dir: &Path) -> Vec<(PathBuf, &'static str)> {
    let mut out = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(current) = pending.pop() {
        for entry in std::fs::read_dir(&current).unwrap().flatten() {
            let path = entry.path();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                pending.push(path.clone());
            }
            let what = if kind.is_symlink() {
                "link"
            } else if kind.is_dir() {
                "dir"
            } else {
                "file"
            };
            out.push((path.strip_prefix(dir).unwrap().to_path_buf(), what));
        }
    }
    out.sort();
    out
}

#[test]
fn a_mount_point_behind_an_absolute_link_is_made_inside_the_next_root() {
    // The first directory on the hidden volume's path is an absolute link in
    // the decoy. The bind must land where the hidden root resolves the path,
    // inside the next root; through the link on the running system it would
    // create directories and mount outside the next root.
    let _ = Rerun::new(test_path!(
        a_mount_point_behind_an_absolute_link_is_made_inside_the_next_root
    ))
    .in_user_mount_ns()
    .run(|| {
        let world = World::new();
        let hidden = world.hidden.path().to_path_buf();
        let mut parts = hidden.components().skip(1);
        let first = parts.next().unwrap().as_os_str().to_owned();
        let rest: PathBuf = parts.collect();
        let link = world.decoy.path().join(&first);
        if link.exists() {
            skip_host("the scratch directory's first component is a directory of the test decoy");
        }
        world.decoy.mkdir("linked");
        std::os::unix::fs::symlink("/linked", &link).unwrap();
        let before = listing(world.decoy.path());
        let paths = world.paths();

        entry::prepare(&paths, &world.inputs(), &FakeHost::default()).expect("the entry");

        let inside = paths.nextroot().join("linked").join(&rest);
        assert!(
            read_mountinfo()
                .unwrap()
                .iter()
                .any(|e| e.mount_point == inside),
            "the hidden volume is not bound at {}",
            inside.display()
        );
        assert_eq!(listing(world.decoy.path()), before, "the decoy changed");
        entry::rollback(&paths);
    });
}

#[test]
fn nothing_the_way_back_mounts_shows_below_the_hidden_volume() {
    // In the hidden session the carried filesystems are shared binds on
    // the hidden volume; the way back binds them into the decoy root at
    // the next root, the ESP below /boot.
    let _ = Rerun::new(test_path!(
        nothing_the_way_back_mounts_shows_below_the_hidden_volume
    ))
    .in_user_mount_ns()
    .run(|| {
        let hidden = ScratchTmpfs::new("");
        let boot = ScratchTmpfs::new("");
        boot.mkdir("efi");
        let esp = ScratchTmpfs::new("");
        let mut carried = Vec::new();
        for (target, source, name) in [
            ("/boot", boot.path(), "boot"),
            ("/boot/efi", esp.path(), "boot-efi"),
        ] {
            let at = hidden.mkdir(&format!("root/decoy/{name}"));
            bind(source, &at);
            carried.push(CarriedMount {
                target: PathBuf::from(target),
                at,
                read_only: false,
                dev: None,
                root: None,
            });
        }
        make_rshared(hidden.path());
        let back = ScratchTmpfs::new("");
        back.mkdir("boot");
        let before = mounts_outside(back.path());

        carry::restore(&carried, back.path()).expect("restored");

        assert!(back.path().join("boot/efi").is_dir());
        assert_eq!(mounts_outside(back.path()), before);
        assert!(nextroot::detach_tree(back.path()).is_empty());
    });
}

#[test]
fn a_failed_entry_leaves_no_next_root_and_no_runtime_pieces() {
    let _ = Rerun::new(test_path!(
        a_failed_entry_leaves_no_next_root_and_no_runtime_pieces
    ))
    .in_user_mount_ns()
    .run(|| {
        let world = World::new();
        // No init: PID 1 would freeze in this root, so the entry fails.
        std::fs::remove_file(world.decoy.path().join("usr/lib/systemd/systemd")).unwrap();
        let paths = world.paths();
        let host = FakeHost::default();
        let error = entry::prepare(&paths, &world.inputs(), &host).unwrap_err();
        assert!(error.to_string().contains("does not resolve"), "{error}");
        let entries = read_mountinfo().unwrap();
        assert!(
            !entries
                .iter()
                .any(|e| e.mount_point.starts_with(paths.nextroot())),
            "the next root is detached"
        );
        assert!(!paths.runtime().exists());
        assert!(!world.run.path().join(DROPIN_DIR).join(DROPIN_NAME).exists());
        // One reload installs the drop-in, one removes it again.
        assert_eq!(host.reloads.get(), 2);
    });
}

#[test]
fn a_cancel_stops_the_entry_at_its_next_step_and_undoes_it() {
    let _ = Rerun::new(test_path!(
        a_cancel_stops_the_entry_at_its_next_step_and_undoes_it
    ))
    .in_user_mount_ns()
    .run(|| {
        let world = World::new();
        let paths = world.paths();
        // The signal arrives while the service manager loads the drop-in.
        let host = FakeHost {
            cancel_at_reload: true,
            ..FakeHost::default()
        };
        let error = entry::prepare(&paths, &world.inputs(), &host).unwrap_err();
        nails_core::cancel::testing::reset();
        assert!(matches!(error, NailsError::Cancelled), "{error}");
        let entries = read_mountinfo().unwrap();
        assert!(
            !entries
                .iter()
                .any(|e| e.mount_point.starts_with(paths.nextroot())),
            "nothing was mounted at the next root"
        );
        assert!(!paths.runtime().exists());
        assert!(!world.run.path().join(DROPIN_DIR).exists());
        assert_eq!(host.reloads.get(), 2);
    });
}

#[test]
fn an_entry_whose_root_cannot_leave_again_is_refused() {
    let _ = Rerun::new(test_path!(
        an_entry_whose_root_cannot_leave_again_is_refused
    ))
    .in_user_mount_ns()
    .run(|| {
        let world = World::new();
        std::fs::remove_file(
            world
                .decoy
                .path()
                .join("usr/lib/systemd/system/systemd-soft-reboot.service"),
        )
        .unwrap();
        let paths = world.paths();
        let host = FakeHost::default();
        let error = entry::prepare(&paths, &world.inputs(), &host).unwrap_err();
        let text = error.to_string();
        assert!(text.contains("systemd-soft-reboot.service"), "{text}");
        assert!(text.contains("soft-reboot units"), "{text}");
        assert!(!paths.runtime().exists());
        let entries = read_mountinfo().unwrap();
        assert!(
            !entries
                .iter()
                .any(|e| e.mount_point.starts_with(paths.nextroot()))
        );
    });
}

#[test]
fn a_noexec_run_is_cleared_for_the_session_and_set_again_on_rollback() {
    let _ = Rerun::new(test_path!(
        a_noexec_run_is_cleared_for_the_session_and_set_again_on_rollback
    ))
    .in_user_mount_ns()
    .run(|| {
        let world = World::new();
        let paths = world.paths();
        nix::mount::mount(
            None::<&str>,
            &paths.run,
            None::<&str>,
            nix::mount::MsFlags::MS_REMOUNT
                | nix::mount::MsFlags::MS_BIND
                | nix::mount::MsFlags::MS_NOEXEC,
            None::<&str>,
        )
        .unwrap();
        assert!(nextroot::is_noexec(&paths.run).unwrap());
        let host = FakeHost::default();
        let entry = entry::prepare(&paths, &world.inputs(), &host).expect("the entry");
        assert!(entry.plan.run_noexec);
        assert!(!nextroot::is_noexec(&paths.run).unwrap());
        entry::rollback(&paths);
        assert!(nextroot::is_noexec(&paths.run).unwrap());
    });
}

/// A decoy fstab that cannot be read refuses the entry, which rolls back:
/// taken for an empty one, it would leave every decoy filesystem without a
/// decision in the next root.
#[test]
fn an_unreadable_decoy_fstab_refuses_the_entry() {
    let _ = Rerun::new(test_path!(an_unreadable_decoy_fstab_refuses_the_entry))
        .in_user_mount_ns()
        .run(|| {
            let world = World::new();
            let fstab = world.decoy.path().join("etc/fstab");
            std::fs::remove_file(&fstab).unwrap();
            std::fs::create_dir(&fstab).unwrap();
            let paths = world.paths();

            let Err(error) = entry::prepare(&paths, &world.inputs(), &FakeHost::default()) else {
                panic!("entered with an unreadable fstab");
            };

            assert!(error.to_string().contains("etc/fstab"), "{error}");
            let nextroot = paths.nextroot();
            assert!(
                !read_mountinfo()
                    .unwrap()
                    .iter()
                    .any(|e| e.mount_point.starts_with(&nextroot)),
                "the next root is still mounted"
            );
        });
}

/// A mount below the next root that a later mount on its parent shadows is
/// out of reach of its path: the backstop leaves it, private since it was
/// made, and makes the mount on top private. It used to fail with EINVAL and
/// roll back an entry that was valid.
#[test]
fn a_shadowed_mount_below_the_next_root_does_not_fail_the_backstop() {
    let _ = Rerun::new(test_path!(
        a_shadowed_mount_below_the_next_root_does_not_fail_the_backstop
    ))
    .in_user_mount_ns()
    .run(|| {
        let run = ScratchTmpfs::new("");
        run.mkdir("nextroot");
        let root = run.path().join("nextroot");
        let top = ScratchTmpfs::new("");
        top.mkdir("srv/data");
        bind(top.path(), &root);
        let child = ScratchTmpfs::new("");
        nextroot::bind(child.path(), &root.join("srv/data"), false).unwrap();
        let parent = ScratchTmpfs::new("");
        parent.mkdir("data");
        nextroot::bind(parent.path(), &root.join("srv"), false).unwrap();

        nextroot::make_below_private(&root).expect("the backstop");

        let srv = root.join("srv");
        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
        let line = mountinfo
            .lines()
            .find(|line| line.split(' ').nth(4) == Some(srv.to_str().unwrap()))
            .expect("the mount on top");
        assert!(!line.contains(" shared:"), "{line}");
    });
}

/// An emergency on the decoy, after an entry that cleared `noexec` on `/run`,
/// sets it again as a rollback does, and detaches the next root.
#[test]
fn an_emergency_on_the_decoy_sets_noexec_on_run_again() {
    use nails_teardown::whole_root::emergency::{self, Finish, Side};
    let _ = Rerun::new(test_path!(
        an_emergency_on_the_decoy_sets_noexec_on_run_again
    ))
    .in_user_mount_ns()
    .run(|| {
        let world = World::new();
        let paths = world.paths();
        nix::mount::mount(
            None::<&str>,
            &paths.run,
            None::<&str>,
            nix::mount::MsFlags::MS_REMOUNT
                | nix::mount::MsFlags::MS_BIND
                | nix::mount::MsFlags::MS_NOEXEC,
            None::<&str>,
        )
        .unwrap();
        let entry =
            entry::prepare(&paths, &world.inputs(), &FakeHost::default()).expect("the entry");
        assert!(!nextroot::is_noexec(&paths.run).unwrap());
        let mut plan = entry.plan.clone();
        plan.backend = Vec::new();
        plan.tools = Default::default();
        let cgroup = ScratchTmpfs::new("");
        let host = emergency::Host {
            run: paths.run.clone(),
            nextroot: paths.nextroot(),
            runtime_dir: paths.runtime(),
            cgroup_root: cgroup.path().to_path_buf(),
            protected_pids: Vec::new(),
            act: true,
        };

        let report = emergency::run(Some(plan), &host, Finish::Return);

        assert_eq!(report.side, Side::Decoy);
        assert!(report.remaining.is_empty(), "{:?}", report.remaining);
        assert!(nextroot::is_noexec(&paths.run).unwrap());
    });
}
