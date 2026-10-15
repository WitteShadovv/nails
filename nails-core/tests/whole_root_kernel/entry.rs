// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The whole entry, `nails_core::session::entry::prepare`, against real
//! mounts: a decoy root with a separate `/home` and an ESP, the fstab
//! policy, the drop-in, and the transition that consumes it.

use nails_core::session::entry::{self, EntryHost, EntryInputs};
use nails_core::session::layout::Paths;
use nails_core::test_path;
use nails_core::test_support::{Rerun, ScratchTmpfs};
use nails_core::{NailsError, nixos::NixOSBuilder};
use nails_teardown::mountinfo::{read_mountinfo, top_mount_at};
use nails_teardown::whole_root::kernel_helpers::{self, KernelSetting};
use nails_teardown::whole_root::plan::{
    CarriedMount, DecoyRoot, Direction, Plan, PolicyMountKind, SNAPSHOT_NAME, unix_now,
};
use nails_teardown::whole_root::transition::{self, DROPIN_DIR, DROPIN_NAME, Env, Outcome};
use nails_teardown::whole_root::{carry, nextroot, runtime_units};
use std::cell::Cell;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

#[derive(Default)]
struct FakeHost {
    reloads: Cell<u32>,
    /// The next root to look at on the first reload.
    nextroot: Option<PathBuf>,
    /// Whether it was a mount point then.
    populated_at_first_reload: Cell<Option<bool>>,
    /// Request a cancel during the first reload, as a Ctrl+C would.
    cancel_at_reload: bool,
    /// The files that stand for the kernel's helper paths.
    helpers: Vec<PathBuf>,
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
}

struct World {
    decoy: ScratchTmpfs,
    _esp: ScratchTmpfs,
    _home: ScratchTmpfs,
    hidden: ScratchTmpfs,
    run: ScratchTmpfs,
}

impl World {
    /// A decoy root with its ESP at /boot and a separate /home, both
    /// listed in its fstab with a swap partition and an unmounted disk.
    fn new() -> Self {
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
             /dev/vda4 none swap sw 0 0\n\
             /dev/vdc1 /srv/data ext4 defaults 0 2\n",
        )
        .unwrap();
        let init = decoy.path().join("usr/lib/systemd/systemd");
        std::fs::write(&init, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&init, std::fs::Permissions::from_mode(0o755)).unwrap();
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
    fn paths(&self) -> Paths {
        Paths {
            root: self.decoy.path().to_path_buf(),
            run: self.run.path().to_path_buf(),
        }
    }
    fn inputs(&self) -> EntryInputs<'_> {
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
        let entry = entry::prepare(&paths, &inputs, &host).expect("the entry");
        let nextroot = paths.nextroot();
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

        // The transition consumes it: masks in place, entry recorded.
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
        entry::rollback(&paths);
    });
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
