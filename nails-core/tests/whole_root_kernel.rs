// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The whole-root mechanics against a real kernel, without root (ADR 0006,
//! ADR 0008).
//!
//! Each test re-runs itself in a private user + mount namespace and builds the
//! real thing on scratch tmpfs: a decoy "root" with its own ESP, a hidden
//! volume, a `/run` with a next root in it. The production mount primitives
//! from `nails_teardown::whole_root` make the root overlay, the binds and the
//! read-only ESP; the transition step runs against the live mount table; the
//! kill runs in a delegated cgroup. Only the soft-reboot itself and the device
//! mount of the way back need a VM.

mod kernel_tests {
    use nails_core::test_path;
    use nails_core::test_support::{Rerun, ScratchTmpfs};
    use nails_teardown::mountinfo::{parse_overlay_opts, read_mountinfo, top_mount_at};
    use nails_teardown::whole_root::nextroot;
    use nails_teardown::whole_root::plan::{
        Arm, DecoyRoot, Direction, PLAN_NAME, PLAN_VERSION, Plan, RootSide, SNAPSHOT_NAME, Tools,
        UTAB_NAME,
    };
    use nails_teardown::whole_root::run_scrub::Snapshot;
    use nails_teardown::whole_root::transition::{self, Env, Outcome};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};

    /// A decoy root, a hidden volume and a `/run`, each its own tmpfs.
    struct World {
        decoy: ScratchTmpfs,
        esp: ScratchTmpfs,
        hidden: ScratchTmpfs,
        run: ScratchTmpfs,
    }

    impl World {
        fn new() -> Self {
            let decoy = ScratchTmpfs::strictatime();
            for dir in ["etc", "usr/lib/systemd", "boot", "run", "mnt/data", "root"] {
                decoy.mkdir(dir);
            }
            std::fs::write(decoy.path().join("etc/os-release"), "ID=decoy\n").unwrap();
            let init = decoy.path().join("usr/lib/systemd/systemd");
            std::fs::write(&init, "#!/bin/sh\n").unwrap();
            std::fs::set_permissions(&init, std::fs::Permissions::from_mode(0o755)).unwrap();
            let esp = ScratchTmpfs::new("");
            std::fs::write(esp.path().join("random-seed"), "seed").unwrap();
            let hidden = ScratchTmpfs::new("");
            hidden.mkdir("root/upper");
            hidden.mkdir("root/work");
            let run = ScratchTmpfs::new("");
            run.mkdir("nextroot");
            run.mkdir("overlay-runtime");
            run.mkdir("systemd/journal");
            Self {
                decoy,
                esp,
                hidden,
                run,
            }
        }
        fn nextroot(&self) -> PathBuf {
            self.run.path().join("nextroot")
        }
        fn upper(&self) -> PathBuf {
            self.hidden.path().join("root/upper")
        }

        /// What activation builds: the root overlay, `/run`, the hidden
        /// volume and a read-only ESP, all below the next root, made private.
        fn build(&self) {
            let nextroot = self.nextroot();
            nextroot::overlay_over(
                self.decoy.path(),
                &self.run.path().join("overlay-runtime/lower"),
                &self.upper(),
                &self.hidden.path().join("root/work"),
                &nextroot,
            )
            .expect("the root overlay");
            nextroot::bind(self.run.path(), &nextroot.join("run"), false).expect("bind /run");
            nextroot::bind(self.hidden.path(), &nextroot.join("mnt/data"), false)
                .expect("bind the hidden volume");
            nextroot::bind_read_only(self.esp.path(), &nextroot.join("boot"))
                .expect("the read-only ESP");
            nextroot::make_rprivate(&nextroot).expect("private");
        }

        fn plan(&self, direction: Direction) -> Plan {
            Plan {
                version: PLAN_VERSION,
                hidden_root: self.hidden.path().to_path_buf(),
                upper: self.upper(),
                work: self.hidden.path().join("root/work"),
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
                masks: vec!["dev-vdb1.swap".to_string()],
                session_units: Vec::new(),
                backend: Vec::new(),
                tools: Tools::default(),
                armed: Some(Arm::now(direction)),
                entered_at: None,
                run_noexec: false,
                carried: Vec::new(),
            }
        }

        fn env(&self) -> Env {
            Env {
                run: self.run.path().to_path_buf(),
                nextroot: self.nextroot(),
                runtime_dir: self.run.path().join("overlay-runtime"),
                kmsg: self.run.path().join("no-kmsg"),
                systemctl: None,
                now: nails_teardown::whole_root::plan::unix_now(),
                mounts: read_mountinfo().unwrap(),
            }
        }
    }

    fn mounted_below(path: &Path) -> Vec<PathBuf> {
        read_mountinfo()
            .unwrap()
            .into_iter()
            .map(|e| e.mount_point)
            .filter(|m| m.starts_with(path))
            .collect()
    }

    #[test]
    fn the_next_root_writes_to_the_upper_keeps_the_esp_read_only_and_never_touches_decoy_atimes() {
        let _ = Rerun::new(test_path!(
            the_next_root_writes_to_the_upper_keeps_the_esp_read_only_and_never_touches_decoy_atimes
        ))
        .in_user_mount_ns()
        .run(|| {
            let world = World::new();
            let os_release = world.decoy.path().join("etc/os-release");
            let atime_before = std::fs::metadata(&os_release).unwrap().atime_nsec();
            std::thread::sleep(std::time::Duration::from_millis(20));
            world.build();
            let nextroot = world.nextroot();

            // The root overlay: lower is the decoy, upper on the hidden volume.
            let entries = read_mountinfo().unwrap();
            let root = top_mount_at(&entries, &nextroot).expect("the next root is mounted");
            assert_eq!(root.fstype, "overlay");
            let opts = parse_overlay_opts(&root.super_opts);
            assert_eq!(opts.upperdir.as_deref(), Some(world.upper().as_path()));
            // The lower helper bind is gone again: the overlay holds its own
            // private clone, nothing else can reach the decoy through it.
            assert!(mounted_below(&world.run.path().join("overlay-runtime")).is_empty());

            // A hidden write lands in the upper, never on the decoy.
            std::fs::write(nextroot.join("root/hidden-write"), "hidden").unwrap();
            assert!(world.upper().join("root/hidden-write").exists());
            assert!(!world.decoy.path().join("root/hidden-write").exists());

            // Reading a decoy file through the overlay leaves its atime alone,
            // even on a strictatime decoy: the lower is a read-only bind.
            assert_eq!(
                std::fs::read_to_string(nextroot.join("etc/os-release")).unwrap(),
                "ID=decoy\n"
            );
            assert_eq!(
                std::fs::metadata(&os_release).unwrap().atime_nsec(),
                atime_before
            );

            // The ESP is read-only in the next root and writable on the decoy.
            let refused = std::fs::write(nextroot.join("boot/random-seed"), "hidden");
            assert_eq!(refused.unwrap_err().raw_os_error(), Some(nix::libc::EROFS));
            std::fs::write(world.esp.path().join("random-seed"), "decoy").unwrap();

            // The hidden volume and /run are reachable at their own paths.
            assert!(nextroot.join("mnt/data/root/upper").is_dir());
            assert!(nextroot.join("run/overlay-runtime").is_dir());

            // PID 1's check passes, and the whole tree detaches.
            nextroot::precheck(&nextroot, Path::new("/usr/lib/systemd/systemd")).unwrap();
            assert!(nextroot::detach_tree(&nextroot).is_empty());
            assert!(mounted_below(&nextroot).is_empty());
        });
    }

    #[test]
    fn the_transition_enters_an_armed_root_and_detaches_an_unarmed_one() {
        let _ = Rerun::new(test_path!(
            the_transition_enters_an_armed_root_and_detaches_an_unarmed_one
        ))
        .in_user_mount_ns()
        .run(|| {
            let world = World::new();
            let runtime = world.run.path().join("overlay-runtime");

            // Unarmed: an activation died after building the tree. A later
            // reboot must never enter it.
            world.build();
            let mut plan = world.plan(Direction::Enter);
            plan.armed = None;
            plan.write_atomic(&runtime.join(PLAN_NAME)).unwrap();
            assert!(matches!(
                transition::run(&world.env()),
                Outcome::Disarmed(_)
            ));
            assert!(mounted_below(&world.nextroot()).is_empty());
            assert!(!runtime.exists());

            // Armed: the entry is prepared and the tree stays for PID 1.
            std::fs::create_dir_all(&runtime).unwrap();
            world.build();
            world
                .plan(Direction::Enter)
                .write_atomic(&runtime.join(PLAN_NAME))
                .unwrap();
            assert_eq!(transition::run(&world.env()), Outcome::Entered);
            assert!(!mounted_below(&world.nextroot()).is_empty());
            let link = world.run.path().join("systemd/system/dev-vdb1.swap");
            assert_eq!(std::fs::read_link(link).unwrap(), Path::new("/dev/null"));
            nextroot::detach_tree(&world.nextroot());
        });
    }

    #[test]
    fn a_killed_entry_s_writable_lower_bind_is_detached_before_the_runtime_dir_goes() {
        // An activation killed between its lower bind and the read-only
        // remount leaves a writable bind of the decoy root in the runtime
        // directory: removing the directory must never walk into it.
        let _ = Rerun::new(test_path!(
            a_killed_entry_s_writable_lower_bind_is_detached_before_the_runtime_dir_goes
        ))
        .in_user_mount_ns()
        .run(|| {
            let world = World::new();
            let decoy = world.decoy.path();
            std::fs::write(decoy.join("precious"), "decoy").unwrap();
            let runtime = world.run.path().join("overlay-runtime");
            let lower = runtime.join("lower");
            std::fs::create_dir_all(&lower).unwrap();
            nextroot::bind(decoy, &lower, false).unwrap();
            nextroot::remove_runtime_dir(&runtime);
            assert_eq!(
                std::fs::read_to_string(decoy.join("precious")).unwrap(),
                "decoy"
            );
            assert!(!runtime.exists());
        });
    }

    #[test]
    fn the_way_back_detaches_mounts_the_hidden_shutdown_made_under_run() {
        // The spike's third run: NixOS mounts a tmpfs at /run/initramfs during
        // every shutdown. The scrub must unmount it before removing its
        // mountpoint, and keep everything the decoy had before entering.
        let _ = Rerun::new(test_path!(
            the_way_back_detaches_mounts_the_hidden_shutdown_made_under_run
        ))
        .in_user_mount_ns()
        .run(|| {
            let world = World::new();
            let run = world.run.path();
            let runtime = run.join("overlay-runtime");
            std::fs::write(run.join("decoy-lock"), "").unwrap();
            std::fs::create_dir_all(run.join("mount")).unwrap();
            std::fs::write(run.join("mount/utab"), "ID=1 decoy\n").unwrap();
            std::fs::write(runtime.join(SNAPSHOT_NAME), Snapshot::take(run).to_text()).unwrap();
            std::fs::write(runtime.join(UTAB_NAME), "ID=1 decoy\n").unwrap();

            // The hidden session and its shutdown.
            let initramfs = run.join("initramfs");
            std::fs::create_dir_all(&initramfs).unwrap();
            nix::mount::mount(
                Some("tmpfs"),
                &initramfs,
                Some("tmpfs"),
                nix::mount::MsFlags::empty(),
                Some("mode=0755"),
            )
            .unwrap();
            std::fs::write(initramfs.join("shutdown"), "hidden exitrd").unwrap();
            std::fs::write(run.join("mount/utab"), "ID=1 decoy\nID=9 /hidden\n").unwrap();
            std::fs::write(run.join("nologin"), "").unwrap();

            // The decoy root at the next root, with /run bound in.
            nextroot::bind(world.decoy.path(), &world.nextroot(), false).unwrap();
            nextroot::bind(run, &world.nextroot().join("run"), false).unwrap();
            let mut plan = world.plan(Direction::Leave);
            plan.entered_at = Some(1);
            // The entry cleared noexec on this /run; the way back sets it again.
            plan.run_noexec = true;
            plan.write_atomic(&runtime.join(PLAN_NAME)).unwrap();
            assert!(!nextroot::is_noexec(run).unwrap());

            let outcome = transition::run(&world.env());
            assert!(
                matches!(outcome, Outcome::Returned { failed: 0, .. }),
                "{outcome:?}"
            );
            assert!(
                !initramfs.exists(),
                "the shutdown's mount and mountpoint are gone"
            );
            assert!(mounted_below(&initramfs).is_empty());
            assert!(!run.join("nologin").exists());
            assert!(!runtime.exists());
            assert!(nextroot::is_noexec(run).unwrap(), "noexec is back");
            assert!(run.join("decoy-lock").exists());
            assert_eq!(
                std::fs::read_to_string(run.join("mount/utab")).unwrap(),
                "ID=1 decoy\n"
            );
            nextroot::detach_tree(&world.nextroot());
        });
    }

    /// A delegated cgroup tree of this run's own, or a skip.
    fn delegated_cgroup(root: &Path, name: &str) -> PathBuf {
        std::fs::create_dir_all(root).unwrap();
        if let Err(e) = nix::mount::mount(
            Some("none"),
            root,
            Some("cgroup2"),
            nix::mount::MsFlags::empty(),
            None::<&str>,
        ) {
            nails_core::test_support::skip(&format!("cannot mount cgroup2 in the namespace: {e}"));
        }
        let dir = root.join(name);
        if let Err(e) = std::fs::create_dir(&dir) {
            nails_core::test_support::skip(&format!("the caller's cgroup is not delegated: {e}"));
        }
        dir
    }

    /// A sleeper in a session of its own (so it is no part of this test's
    /// invocation), moved into the cgroup at `dir`.
    #[allow(unsafe_code)]
    fn spawn_sleeper_in(dir: &Path) -> std::process::Child {
        use std::os::unix::process::CommandExt;
        let mut command = std::process::Command::new("sleep");
        command
            .arg("600")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        // SAFETY: setsid is async-signal-safe and touches no shared state.
        unsafe {
            command.pre_exec(|| {
                nix::unistd::setsid().map_err(std::io::Error::from)?;
                Ok(())
            });
        }
        let child = command.spawn().unwrap();
        std::fs::write(dir.join("cgroup.procs"), child.id().to_string()).unwrap();
        child
    }

    #[test]
    fn the_kill_empties_every_cgroup_but_the_invocations() {
        let _ = Rerun::new(test_path!(
            the_kill_empties_every_cgroup_but_the_invocations
        ))
        .in_cgroup_ns()
        .run(|| {
            let scratch = ScratchTmpfs::new("");
            let mount = scratch.path().join("cgroup");
            let name = format!("run-{}", std::process::id());
            let tree = delegated_cgroup(&mount, &name);
            let desktop = tree.join("user.slice/session-2.scope");
            let service = tree.join("system.slice/writer.service");
            let own = tree.join("system.slice/emergency.scope");
            // The service manager's machinery is left to the shutdown.
            let journald = tree.join("system.slice/systemd-journald.service");
            let mount_unit = tree.join("system.slice/nix-.rw\\x2dstore.mount");
            for dir in [&desktop, &service, &own, &journald, &mount_unit] {
                std::fs::create_dir_all(dir).unwrap();
            }
            let mut victims = [spawn_sleeper_in(&desktop), spawn_sleeper_in(&service)];
            let mut spared = [spawn_sleeper_in(&journald), spawn_sleeper_in(&mount_unit)];
            std::fs::write(own.join("cgroup.procs"), std::process::id().to_string()).unwrap();

            let invocation = nails_teardown::proc::Invocation::current();
            let report = nails_teardown::whole_root::kill::kill_below(
                &mount,
                &format!("/{name}"),
                &invocation,
            );
            assert!(
                report.cgroups.iter().any(|c| desktop.starts_with(c)),
                "{report:?}"
            );
            assert!(report.cgroups.contains(&service), "{report:?}");
            assert!(
                !report.cgroups.iter().any(|c| own.starts_with(c)),
                "{report:?}"
            );
            for victim in &mut victims {
                let status = victim.wait().unwrap();
                assert!(!status.success(), "the victim was killed");
            }
            for survivor in &mut spared {
                assert_eq!(survivor.try_wait().unwrap(), None, "{report:?}");
                survivor.kill().unwrap();
                survivor.wait().unwrap();
            }
            assert!(
                !report.cgroups.iter().any(|c| journald.starts_with(c)),
                "{report:?}"
            );
        });
    }
}

mod entry_kernel_tests {
    //! The whole entry, `nails_core::session::entry::prepare`, against real
    //! mounts: a decoy root with a separate `/home` and an ESP, the fstab
    //! policy, the drop-in, and the transition that consumes it.

    use nails_core::session::entry::{self, EntryHost, EntryInputs};
    use nails_core::session::layout::Paths;
    use nails_core::test_path;
    use nails_core::test_support::{Rerun, ScratchTmpfs};
    use nails_core::{NailsError, nixos::NixOSBuilder};
    use nails_teardown::mountinfo::{read_mountinfo, top_mount_at};
    use nails_teardown::whole_root::plan::{
        DecoyRoot, Direction, Plan, PolicyMountKind, SNAPSHOT_NAME, unix_now,
    };
    use nails_teardown::whole_root::transition::{self, DROPIN_DIR, DROPIN_NAME, Env, Outcome};
    use nails_teardown::whole_root::{carry, nextroot};
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
    }

    impl EntryHost for FakeHost {
        fn daemon_reload(&self) -> nails_core::Result<()> {
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
            inputs.persona.mask_inherited = vec!["dropbox".into()];
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
            let mask = std::fs::read_to_string(
                nextroot.join("home/alice/.config/autostart/dropbox.desktop"),
            )
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
}

mod nixos_kernel_tests {
    //! The chrooted activation of a hidden toplevel (ADR 0008, §3, variant B):
    //! it runs inside the next root, sees `/proc`, `/dev` and `/sys`, writes
    //! into the root, and gets a fresh `/run`, never the real one.

    use nails_core::session::nixos::activate_in;
    use nails_core::test_path;
    use nails_core::test_support::{Rerun, ScratchTmpfs, skip};
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    /// A shell that lives in the host's `/nix/store`, usable inside a root
    /// that binds the store.
    fn store_shell() -> Option<PathBuf> {
        let sh = std::fs::canonicalize("/bin/sh").ok()?;
        sh.starts_with("/nix/store").then_some(sh)
    }

    #[test]
    fn the_activation_runs_chrooted_with_a_private_run() {
        let _ = Rerun::new(test_path!(the_activation_runs_chrooted_with_a_private_run))
            .in_user_mount_ns()
            .run(|| {
                let Some(shell) = store_shell() else {
                    skip("no /nix/store shell on this host");
                };
                let root = ScratchTmpfs::new("");
                for dir in ["nix/store", "dev", "proc", "sys", "run", "etc", "system"] {
                    root.mkdir(dir);
                }
                nix::mount::mount(
                    Some("/nix/store"),
                    &root.path().join("nix/store"),
                    None::<&str>,
                    nix::mount::MsFlags::MS_BIND | nix::mount::MsFlags::MS_REC,
                    None::<&str>,
                )
                .unwrap();
                // A marker in the real /run that the activation must not see.
                let real_run = ScratchTmpfs::new("");
                std::fs::write(real_run.path().join("marker"), "").unwrap();
                nix::mount::mount(
                    Some(real_run.path()),
                    &root.path().join("run"),
                    None::<&str>,
                    nix::mount::MsFlags::MS_BIND,
                    None::<&str>,
                )
                .unwrap();
                let activate = root.path().join("system/activate");
                std::fs::write(
                    &activate,
                    format!(
                        "#!{}\nset -e\n\
                         test -r /proc/self/mountinfo\n\
                         test -e /dev/null\n\
                         n=0; for f in /run/*; do [ -e \"$f\" ] && n=$((n+1)); done\n\
                         echo \"run-entries=$n\" > /etc/activated\n",
                        shell.display()
                    ),
                )
                .unwrap();
                std::fs::set_permissions(&activate, std::fs::Permissions::from_mode(0o755))
                    .unwrap();

                activate_in(root.path(), Path::new("/system")).unwrap();

                assert_eq!(
                    std::fs::read_to_string(root.path().join("etc/activated")).unwrap(),
                    "run-entries=0\n"
                );
                // Nothing the child mounted is visible here.
                let entries = nails_teardown::mountinfo::read_mountinfo().unwrap();
                assert!(
                    !entries
                        .iter()
                        .any(|e| e.mount_point == root.path().join("proc"))
                );
            });
    }
}

mod store_kernel_tests {
    //! Keeping the hidden closure on the hidden volume (T-137): copied up
    //! through the store overlay, it survives the decoy deleting it from the
    //! lower, and the lower is never written.

    use nails_core::session::store::keep_closure;
    use nails_core::test_path;
    use nails_core::test_support::{Rerun, ScratchTmpfs};
    use nails_teardown::whole_root::nextroot::mount_overlay;
    use std::fs::FileTimes;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::time::{Duration, UNIX_EPOCH};

    /// Every entry below `dir` with its type, mode, size, mtime and content.
    fn listing(dir: &Path) -> Vec<String> {
        let mut out = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(path) = stack.pop() {
            let meta = std::fs::symlink_metadata(&path).unwrap();
            let rel = path.strip_prefix(dir).unwrap().display().to_string();
            let body = if meta.is_file() {
                std::fs::read_to_string(&path).unwrap()
            } else if meta.is_symlink() {
                std::fs::read_link(&path).unwrap().display().to_string()
            } else {
                let mut children: Vec<PathBuf> = std::fs::read_dir(&path)
                    .unwrap()
                    .map(|e| e.unwrap().path())
                    .collect();
                children.sort();
                stack.extend(children);
                String::new()
            };
            out.push(format!(
                "{rel} {:o} {} {} {body}",
                meta.mode(),
                meta.len(),
                meta.mtime()
            ));
        }
        out.sort();
        out
    }

    fn file(path: &Path, content: &str, mode: u32) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
        let f = std::fs::File::options().write(true).open(path).unwrap();
        f.set_times(FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(1)))
            .unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn a_kept_closure_survives_the_decoy_deleting_it_from_the_lower() {
        let _ = Rerun::new(test_path!(
            a_kept_closure_survives_the_decoy_deleting_it_from_the_lower
        ))
        .in_user_mount_ns()
        .run(|| {
            let decoy = ScratchTmpfs::new("");
            let store = decoy.mkdir("nix/store");
            file(&store.join("aaa-pkg/bin/tool"), "tool", 0o555);
            file(&store.join("aaa-pkg/share/doc"), "doc", 0o444);
            std::fs::create_dir_all(store.join("aaa-pkg/share/empty")).unwrap();
            std::os::unix::fs::symlink("bin", store.join("aaa-pkg/lib")).unwrap();
            file(&store.join("bbb-script"), "#!/bin/sh\n", 0o555);
            std::os::unix::fs::symlink("aaa-pkg", store.join("ccc-link")).unwrap();
            // Shared with the decoy but not in the hidden closure.
            file(&store.join("ddd-other/x"), "other", 0o444);
            let before = listing(decoy.path());

            let hidden = ScratchTmpfs::new("");
            let upper = hidden.mkdir("root/upper");
            let work = hidden.mkdir("root/work");
            let root = ScratchTmpfs::new("");
            mount_overlay(decoy.path(), &upper, &work, root.path()).unwrap();
            let kept_view = listing(&root.path().join("nix/store/aaa-pkg"));

            let closure: Vec<PathBuf> = ["aaa-pkg", "bbb-script", "ccc-link"]
                .iter()
                .map(|n| Path::new("/nix/store").join(n))
                .collect();
            let record = hidden.path().join("root/store-kept");
            let mounts = nails_teardown::mountinfo::read_mountinfo().unwrap();
            let report = keep_closure(root.path(), &closure, &record, &mounts).unwrap();
            assert_eq!((report.paths, report.copied), (3, 3), "{report:?}");
            assert!(report.bytes > 0, "{report:?}");
            assert_eq!(listing(decoy.path()), before, "the lower was written");
            assert!(upper.join("nix/store/aaa-pkg/bin/tool").is_file());
            assert!(!upper.join("nix/store/ddd-other").exists());

            // A later entry copies nothing again.
            let again = keep_closure(root.path(), &closure, &record, &mounts).unwrap();
            assert_eq!(again.copied, 0, "{again:?}");

            // The decoy garbage-collects between sessions: the paths leave
            // the lower, and the next session mounts the overlay again.
            nix::mount::umount(root.path()).unwrap();
            for name in ["aaa-pkg", "bbb-script", "ccc-link", "ddd-other"] {
                let path = store.join(name);
                if path.is_dir() && !path.is_symlink() {
                    std::fs::remove_dir_all(&path).unwrap();
                } else {
                    std::fs::remove_file(&path).unwrap();
                }
            }
            mount_overlay(decoy.path(), &upper, &work, root.path()).unwrap();
            let merged = root.path().join("nix/store");
            assert_eq!(listing(&merged.join("aaa-pkg")), kept_view);
            assert_eq!(
                std::fs::read_to_string(merged.join("bbb-script")).unwrap(),
                "#!/bin/sh\n"
            );
            assert_eq!(
                std::fs::read_link(merged.join("ccc-link")).unwrap(),
                Path::new("aaa-pkg")
            );
            assert!(!merged.join("ddd-other").exists());
        });
    }
}
