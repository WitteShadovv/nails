// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The whole-root mechanics against a real kernel, without root (the
//! real-kernel tier of docs/testing-strategy.md).
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
    use nails_core::test_support::{Rerun, ScratchTmpfs, write_executable};
    use nails_teardown::mountinfo::{MountEntry, parse_overlay_opts, read_mountinfo, top_mount_at};
    use nails_teardown::whole_root::nextroot;
    use nails_teardown::whole_root::plan::{
        Arm, DecoyRoot, Direction, PLAN_NAME, PLAN_VERSION, Plan, RootSide, SNAPSHOT_NAME, Tools,
        UTAB_MOUNTS_NAME, UTAB_NAME,
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
            write_executable(
                &decoy.path().join("usr/lib/systemd/systemd"),
                "#!/bin/sh\n",
                0o755,
            );
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
        /// volume and a read-only ESP, everything below the next root private.
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
            nextroot::make_below_private(&nextroot).expect("private");
        }

        fn plan(&self, direction: Direction) -> Plan {
            Plan {
                version: PLAN_VERSION,
                hidden_root: self.hidden.path().to_path_buf(),
                hidden_dev: None,
                accepted_decoy_storage: None,
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
                // Decoy swap, and an automount the policy masks.
                masks: vec!["dev-vdb1.swap".to_string(), "boot.automount".to_string()],
                boot_masks: Vec::new(),
                generator_masks: Vec::new(),
                skips: Vec::new(),
                required_masks: Vec::new(),
                session_units: Vec::new(),
                backend: Vec::new(),
                tools: Tools::default(),
                armed: Some(Arm::now(direction)),
                entered_at: None,
                run_noexec: false,
                carried: Vec::new(),
                decoy_mounts: Vec::new(),
                read_only_disks: false,
                failed_at_entry: Vec::new(),
                kernel_settings: Vec::new(),
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
    fn the_session_s_unit_files_are_readable_by_all_under_a_restrictive_umask() {
        // PID 1 warns about, and names in the kernel log, a configuration
        // file that is not readable by all; a hardened root's umask of 077
        // must not bring that back.
        let _ = Rerun::new(test_path!(
            the_session_s_unit_files_are_readable_by_all_under_a_restrictive_umask
        ))
        .run(|| {
            use nails_teardown::whole_root::{disk_guard, runtime_units};
            nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o077));
            let run = tempfile::tempdir().unwrap();
            let binary = Path::new("/run/overlay-runtime/control");
            let dropin = transition::install_dropin(run.path(), binary).unwrap();
            let rule = disk_guard::install_rule(run.path(), binary).unwrap();
            let units = runtime_units::install_units(
                run.path(),
                &[runtime_units::RuntimeUnit {
                    name: "overlay-runtime-monitor.service".into(),
                    content: "[Service]\n".into(),
                    wanted_by: Vec::new(),
                }],
            )
            .unwrap();
            let guards = transition::runtime_guards().map(|(unit, _)| {
                run.path()
                    .join(transition::stop_guard_dir(unit))
                    .join(transition::STOP_GUARD_NAME)
            });
            for file in guards.chain([dropin, rule]).chain(units) {
                let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o7777;
                assert_eq!(mode, 0o644, "{}: {mode:o}", file.display());
            }
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
            for unit in ["dev-vdb1.swap", "boot.automount"] {
                let link = world.run.path().join("systemd/system").join(unit);
                assert_eq!(std::fs::read_link(link).unwrap(), Path::new("/dev/null"));
            }
            nextroot::detach_tree(&world.nextroot());
        });
    }

    #[test]
    fn a_generator_mask_is_never_written_onto_a_filesystem_the_scrub_skips() {
        // The way back's scrub stays on the filesystem of /run: a generator
        // directory that is a mount of its own would keep the mask past the
        // session, so the entry transition refuses to write it there.
        let _ = Rerun::new(test_path!(
            a_generator_mask_is_never_written_onto_a_filesystem_the_scrub_skips
        ))
        .in_user_mount_ns()
        .run(|| {
            use nails_teardown::whole_root::runtime_units;
            let run = ScratchTmpfs::new("");
            let generators = run.path().join(runtime_units::GENERATOR_DIR);
            std::fs::create_dir_all(&generators).unwrap();
            let other = ScratchTmpfs::new("");
            nix::mount::mount(
                Some(other.path()),
                &generators,
                None::<&str>,
                nix::mount::MsFlags::MS_BIND,
                None::<&str>,
            )
            .unwrap();
            let gpt = ["systemd-gpt-auto-generator".to_string()];
            assert!(runtime_units::mask_generators(run.path(), &gpt).is_err());
            assert!(std::fs::read_dir(other.path()).unwrap().next().is_none());

            // On the filesystem of /run the mask is written.
            nix::mount::umount(&generators).unwrap();
            assert_eq!(
                runtime_units::mask_generators(run.path(), &gpt).unwrap(),
                [generators.join("systemd-gpt-auto-generator")]
            );
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
            // The decoy's copy taken at entry: a line for the decoy root,
            // which is the next root's mount now, and one whose mount the
            // entry's switch left behind (here the scratch /run's own ID,
            // which is not below the next root).
            let table = read_mountinfo().unwrap();
            let decoy_root = top_mount_at(&table, &world.nextroot()).unwrap();
            let left_behind = top_mount_at(&table, run).unwrap();
            let kept = format!(
                "ID={} SRC={} TARGET=/sysroot ROOT={} OPTS=x-initrd.mount\n",
                decoy_root.mount_id,
                decoy_root.source.display(),
                decoy_root.root.display()
            );
            std::fs::write(
                runtime.join(UTAB_NAME),
                format!(
                    "{kept}ID={} SRC={} TARGET=/sysroot/run ROOT=/ OPTS=x-initrd.mount\n",
                    left_behind.mount_id,
                    left_behind.source.display()
                ),
            )
            .unwrap();
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
                kept,
                "only the decoy's line for a mount of the next root is back"
            );
            nextroot::detach_tree(&world.nextroot());
        });
    }

    #[test]
    fn the_way_back_gives_the_decoys_utab_lines_to_its_restored_mounts() {
        // The decoy's copy of utab names its root and its ESP by the IDs they
        // had at entry. The way back binds both below the next root again,
        // where the kernel gives them IDs of their own; the mount table lines
        // the entry kept beside the copy (as the decoy saw them) lead each
        // line to its mount.
        let _ = Rerun::new(test_path!(
            the_way_back_gives_the_decoys_utab_lines_to_its_restored_mounts
        ))
        .in_user_mount_ns()
        .run(|| {
            let world = World::new();
            let run = world.run.path();
            let runtime = run.join("overlay-runtime");
            let table = read_mountinfo().unwrap();
            let root_then = top_mount_at(&table, world.decoy.path()).unwrap().clone();
            let esp_then = top_mount_at(&table, world.esp.path()).unwrap().clone();
            let seen_at = |m: &MountEntry, at: &str| {
                format!(
                    "{} 1 {} {} {at} rw - {} {} rw\n",
                    m.mount_id,
                    m.dev,
                    m.root.display(),
                    m.fstype,
                    m.source.display()
                )
            };
            std::fs::write(
                runtime.join(UTAB_MOUNTS_NAME),
                seen_at(&root_then, "/") + &seen_at(&esp_then, "/boot"),
            )
            .unwrap();
            let line = |id: i32, m: &MountEntry, target: &str| {
                format!(
                    "ID={id} SRC={} TARGET={target} ROOT={} OPTS=x-initrd.mount\n",
                    m.source.display(),
                    m.root.display()
                )
            };
            std::fs::write(
                runtime.join(UTAB_NAME),
                line(root_then.mount_id, &root_then, "/sysroot")
                    + &line(esp_then.mount_id, &esp_then, "/sysroot/boot"),
            )
            .unwrap();
            std::fs::create_dir_all(run.join("mount")).unwrap();
            std::fs::write(run.join("mount/utab"), "ID=1 hidden\n").unwrap();

            // The way back: the decoy root and its ESP below the next root.
            nextroot::bind(world.decoy.path(), &world.nextroot(), false).unwrap();
            nextroot::bind(world.esp.path(), &world.nextroot().join("boot"), false).unwrap();
            nextroot::bind(run, &world.nextroot().join("run"), false).unwrap();
            let table = read_mountinfo().unwrap();
            let root_now = top_mount_at(&table, &world.nextroot()).unwrap().mount_id;
            let esp_now = top_mount_at(&table, &world.nextroot().join("boot"))
                .unwrap()
                .mount_id;
            assert_ne!(root_now, root_then.mount_id);
            assert_ne!(esp_now, esp_then.mount_id);
            let mut plan = world.plan(Direction::Leave);
            plan.entered_at = Some(1);
            plan.write_atomic(&runtime.join(PLAN_NAME)).unwrap();

            let outcome = transition::run(&world.env());
            assert!(matches!(outcome, Outcome::Returned { .. }), "{outcome:?}");
            assert_eq!(
                std::fs::read_to_string(run.join("mount/utab")).unwrap(),
                line(root_now, &root_then, "/sysroot") + &line(esp_now, &esp_then, "/sysroot/boot")
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
            nails_core::test_support::skip_host(&format!(
                "the caller's cgroup is not delegated: {e}"
            ));
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

#[path = "whole_root_kernel/entry.rs"]
mod entry_kernel_tests;

#[path = "whole_root_kernel/way_back.rs"]
mod way_back_kernel_tests;

#[path = "whole_root_kernel/labels.rs"]
mod labels_kernel_tests;

#[path = "whole_root_kernel/kernel_modules.rs"]
mod kernel_modules_kernel_tests;

#[path = "whole_root_kernel/package_drift.rs"]
mod package_drift_kernel_tests;

#[path = "whole_root_kernel/skips.rs"]
mod skips_kernel_tests;

#[path = "whole_root_kernel/mount_units.rs"]
mod mount_units_kernel_tests;

mod nixos_kernel_tests {
    //! The chrooted activation of a hidden toplevel:
    //! it runs inside the next root, sees `/proc`, `/dev` and `/sys`, writes
    //! into the root, and gets a fresh `/run`, never the real one.

    use nails_core::session::nixos::activate_in;
    use nails_core::test_path;
    use nails_core::test_support::{
        Rerun, ScratchTmpfs, copy_executable, skip_host, write_executable,
    };
    use std::path::{Path, PathBuf};

    /// A shell that lives in the host's `/nix/store`, usable inside a root
    /// that binds the store: `/bin/sh` on NixOS, else the `sh` or `bash` a
    /// Nix development shell puts on `PATH`.
    fn store_shell() -> Option<PathBuf> {
        let path = std::env::var_os("PATH").unwrap_or_default();
        std::iter::once(PathBuf::from("/bin/sh"))
            .chain(std::env::split_paths(&path).flat_map(|dir| [dir.join("sh"), dir.join("bash")]))
            .filter_map(|shell| std::fs::canonicalize(shell).ok())
            .find(|shell| shell.starts_with("/nix/store"))
    }

    /// A statically linked `busybox` on `PATH` (Debian's and Ubuntu's
    /// `busybox-static`), which runs inside a root that holds nothing else.
    fn static_busybox() -> Option<PathBuf> {
        let path = std::env::var_os("PATH").unwrap_or_default();
        std::env::split_paths(&path)
            .filter_map(|dir| std::fs::canonicalize(dir.join("busybox")).ok())
            .find(|busybox| is_static_elf(busybox))
    }

    /// Whether `path` is a 64-bit little-endian ELF file that names no
    /// program interpreter (no `PT_INTERP` program header).
    fn is_static_elf(path: &Path) -> bool {
        let Ok(bytes) = std::fs::read(path) else {
            return false;
        };
        if bytes.len() < 64 || !bytes.starts_with(b"\x7fELF\x02\x01") {
            return false;
        }
        let word = |at: usize, len: usize| {
            bytes.get(at..at + len).map(|b| {
                b.iter()
                    .rev()
                    .fold(0usize, |value, &byte| value << 8 | usize::from(byte))
            })
        };
        let (Some(offset), Some(size), Some(count)) = (word(0x20, 8), word(0x36, 2), word(0x38, 2))
        else {
            return false;
        };
        const PT_INTERP: usize = 3;
        (0..count).all(|index| word(offset + index * size, 4).is_some_and(|kind| kind != PT_INTERP))
    }

    #[test]
    fn the_activation_runs_chrooted_with_a_private_run() {
        let _ = Rerun::new(test_path!(the_activation_runs_chrooted_with_a_private_run))
            .in_user_mount_ns()
            .run(|| {
                let root = ScratchTmpfs::new("");
                for dir in ["nix/store", "dev", "proc", "sys", "run", "etc", "system", "bin"] {
                    root.mkdir(dir);
                }
                // The shell the activation script runs in: one from the host's
                // store, which the root binds as the hidden store would be,
                // or a static busybox copied into the root.
                let shell = if let Some(shell) = store_shell() {
                    nix::mount::mount(
                        Some("/nix/store"),
                        &root.path().join("nix/store"),
                        None::<&str>,
                        nix::mount::MsFlags::MS_BIND | nix::mount::MsFlags::MS_REC,
                        None::<&str>,
                    )
                    .unwrap();
                    shell
                } else if let Some(busybox) = static_busybox() {
                    copy_executable(&busybox, &root.path().join("bin/sh"), 0o755);
                    PathBuf::from("/bin/sh")
                } else {
                    skip_host("no /nix/store shell and no static busybox on this host");
                };
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
                // It also records its process group and the signals it
                // ignores: a Ctrl+C on the terminal reaches the whole
                // foreground group, and an activation killed halfway would
                // leave the hidden /etc half written.
                write_executable(
                    &root.path().join("system/activate"),
                    format!(
                        "#!{}\nset -e\n\
                         test -r /proc/self/mountinfo\n\
                         test -e /dev/null\n\
                         n=0; for f in /run/*; do [ -e \"$f\" ] && n=$((n+1)); done\n\
                         echo \"run-entries=$n\" > /etc/activated\n\
                         read -r stat < /proc/$$/stat\n\
                         set -- $stat\n\
                         echo \"process=$1 group=$5\" >> /etc/activated\n\
                         while read -r key value; do \
                           if [ \"$key\" = SigIgn: ]; then echo \"ignored=$value\" >> /etc/activated; fi; \
                         done < /proc/$$/status\n",
                        shell.display()
                    ),
                    0o755,
                );

                activate_in(root.path(), Path::new("/system")).unwrap();

                let activated = std::fs::read_to_string(root.path().join("etc/activated")).unwrap();
                let lines: Vec<&str> = activated.lines().collect();
                assert_eq!(lines.first(), Some(&"run-entries=0"), "{activated}");
                let ids: Vec<&str> = lines[1]
                    .split(' ')
                    .filter_map(|field| field.split_once('=').map(|(_, id)| id))
                    .collect();
                assert_eq!(ids[0], ids[1], "the activation leads its own group: {activated}");
                let ignored = lines[2].strip_prefix("ignored=").expect(&activated);
                let ignored = u64::from_str_radix(ignored, 16).unwrap();
                for signal in [nix::libc::SIGHUP, nix::libc::SIGINT, nix::libc::SIGTERM] {
                    assert_ne!(
                        ignored & (1 << (signal - 1)),
                        0,
                        "signal {signal} is not ignored: {activated}"
                    );
                }
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
    //! Keeping the hidden closure on the hidden volume: copied up
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
