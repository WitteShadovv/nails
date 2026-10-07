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
            }
        }

        fn env(&self) -> Env {
            Env {
                run: self.run.path().to_path_buf(),
                nextroot: self.nextroot(),
                runtime_dir: self.run.path().join("overlay-runtime"),
                kmsg: self.run.path().join("no-kmsg"),
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
            plan.write_atomic(&runtime.join(PLAN_NAME)).unwrap();

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
            for dir in [&desktop, &service, &own] {
                std::fs::create_dir_all(dir).unwrap();
            }
            let mut victims = [spawn_sleeper_in(&desktop), spawn_sleeper_in(&service)];
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
        });
    }
}
