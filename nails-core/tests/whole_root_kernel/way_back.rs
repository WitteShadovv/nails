// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The decoy's mounts across the way back, against real mounts: a decoy root
//! with NixOS's read-only bind over its store and an ESP with a read-only bind
//! of itself stacked on top, recorded as the entry records them, made again
//! below a next root as the way back makes them, and their `utab` lines given
//! back by the transition. The way back's preparation after the device mount
//! ([`ret::complete_decoy_root`]) runs on the decoy root bound at the next
//! root.

use nails_core::test_path;
use nails_core::test_support::{Rerun, ScratchTmpfs, write_executable};
use nails_teardown::mountinfo::{MountEntry, read_mountinfo, top_mount_at};
use nails_teardown::whole_root::decoy_mounts::{self, Record, Why};
use nails_teardown::whole_root::plan::{
    Arm, CarriedMount, DecoyMount, Direction, PLAN_NAME, Plan, UTAB_MOUNTS_NAME, UTAB_NAME,
};
use nails_teardown::whole_root::ret::{self, ReturnError};
use nails_teardown::whole_root::transition::{self, Env, Outcome};
use nails_teardown::whole_root::{carry, nextroot};
use nix::mount::MsFlags;
use std::path::{Path, PathBuf};

fn bind(source: &Path, target: &Path) {
    nix::mount::mount(
        Some(source),
        target,
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )
    .unwrap();
}

fn remount(target: &Path, flags: MsFlags) {
    nix::mount::mount(
        None::<&str>,
        target,
        None::<&str>,
        MsFlags::MS_REMOUNT | MsFlags::MS_BIND | flags,
        None::<&str>,
    )
    .unwrap();
}

/// A decoy root as NixOS boots one with its store on the root filesystem: the
/// store a read-only `nosuid,nodev` bind of itself, and an ESP at `/boot` with
/// a read-only bind of itself stacked on it.
struct Decoy {
    root: ScratchTmpfs,
    _esp: ScratchTmpfs,
    hidden: ScratchTmpfs,
    run: ScratchTmpfs,
}

impl Decoy {
    fn new() -> Self {
        let root = ScratchTmpfs::new("");
        for dir in ["etc", "usr/lib/systemd", "boot", "nix/store", "run"] {
            root.mkdir(dir);
        }
        std::fs::write(root.path().join("etc/os-release"), "ID=decoy\n").unwrap();
        write_executable(
            &root.path().join("usr/lib/systemd/systemd"),
            "#!/bin/sh\n",
            0o755,
        );
        std::fs::write(root.path().join("nix/store/aaa-system"), "decoy").unwrap();
        let store = root.path().join("nix/store");
        bind(&store, &store);
        remount(
            &store,
            MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        );
        let esp = ScratchTmpfs::new("");
        std::fs::write(esp.path().join("random-seed"), "seed").unwrap();
        let boot = root.path().join("boot");
        bind(esp.path(), &boot);
        bind(&boot, &boot);
        remount(&boot, MsFlags::MS_RDONLY);
        let run = ScratchTmpfs::new("");
        run.mkdir("nextroot");
        run.mkdir("overlay-runtime");
        run.mkdir("mount");
        Self {
            root,
            _esp: esp,
            hidden: ScratchTmpfs::new(""),
            run,
        }
    }

    fn root(&self) -> PathBuf {
        self.root.path().canonicalize().unwrap()
    }

    fn nextroot(&self) -> PathBuf {
        self.run.path().canonicalize().unwrap().join("nextroot")
    }

    /// Carry the ESP as the entry does: a read-only bind of what the decoy
    /// shows at `/boot`, on the hidden volume.
    fn carry_boot(&self) -> CarriedMount {
        let at = self.hidden.mkdir("root/decoy/boot").canonicalize().unwrap();
        carry::carry(&self.root().join("boot"), &at, &at).unwrap();
        let held = top_mount_at(&read_mountinfo().unwrap(), &at)
            .unwrap()
            .clone();
        CarriedMount {
            target: PathBuf::from("/boot"),
            at,
            read_only: true,
            dev: Some(held.dev),
            root: Some(held.root),
        }
    }

    /// The record the entry makes of this decoy.
    fn record(&self, carried: &[CarriedMount]) -> Record {
        decoy_mounts::record(&tree(&self.root()), self.hidden.path(), carried)
    }

    /// The `/run` the way back binds into the decoy root: the decoy root has
    /// its mount point, as a real decoy has `/run`.
    fn run(&self) -> PathBuf {
        let run = self.run.path().canonicalize().unwrap();
        std::fs::create_dir_all(self.root().join(run.strip_prefix("/").unwrap())).unwrap();
        run
    }

    /// A plan of this decoy with what the session carried and its record.
    fn plan(&self, carried: Vec<CarriedMount>, decoy_mounts: Vec<DecoyMount>) -> Plan {
        let mut plan = Plan::from_json(&format!(
            r#"{{"version":2,"hidden_root":"{}","upper":"/u","work":"/w",
                "decoy_root":{{"source":"/dev/null","fstype":"ext4"}},
                "decoy":{{"init":"/usr/lib/systemd/systemd"}},
                "hidden":{{"init":"/usr/lib/systemd/systemd"}}}}"#,
            self.hidden.path().display()
        ))
        .unwrap();
        plan.carried = carried;
        plan.decoy_mounts = decoy_mounts;
        plan
    }
}

/// The mounts at and below `root`, in the order of the mount table, with
/// their mount points relative to it.
fn tree(root: &Path) -> Vec<MountEntry> {
    read_mountinfo()
        .unwrap()
        .into_iter()
        .filter_map(|mut mount| {
            let rest = mount.mount_point.strip_prefix(root).ok()?.to_path_buf();
            mount.mount_point = Path::new("/").join(rest);
            Some(mount)
        })
        .collect()
}

/// What a tree's mounts are, without their IDs: mount point, filesystem,
/// directory, per-mount options, and the mount each sits on, by its place
/// in the tree.
fn shape(tree: &[MountEntry]) -> Vec<(PathBuf, String, PathBuf, String, Option<usize>)> {
    tree.iter()
        .map(|mount| {
            let parent = tree.iter().position(|m| m.mount_id == mount.parent_id);
            (
                mount.mount_point.clone(),
                mount.dev.clone(),
                mount.root.clone(),
                mount.mount_opts.clone(),
                parent,
            )
        })
        .collect()
}

#[test]
fn the_way_back_makes_the_decoy_s_mounts_again_as_the_decoy_had_them() {
    let _ = Rerun::new(test_path!(
        the_way_back_makes_the_decoy_s_mounts_again_as_the_decoy_had_them
    ))
    .in_user_mount_ns()
    .run(|| {
        let decoy = Decoy::new();
        let before = tree(&decoy.root());
        let carried = [decoy.carry_boot()];
        let record = decoy.record(&carried);
        assert!(record.lost.is_empty(), "{:?}", record.lost);
        let targets: Vec<&Path> = record.mounts.iter().map(|m| m.target.as_path()).collect();
        assert_eq!(
            targets,
            ["/", "/nix/store", "/boot", "/boot"].map(Path::new)
        );

        // The way back: the decoy root again, without its submounts (as the
        // device mount gives it), and its mounts made again below it.
        let nextroot = decoy.nextroot();
        nextroot::bind(&decoy.root(), &nextroot, false).unwrap();
        assert_eq!(tree(&nextroot).len(), 1);
        let mut mounts = record.mounts.clone();
        decoy_mounts::restore(&mut mounts, &carried, &nextroot).expect("the way back");

        let after = tree(&nextroot);
        assert_eq!(shape(&after), shape(&before));
        let ids: Vec<Option<i32>> = after.iter().map(|m| Some(m.mount_id)).collect();
        let restored: Vec<Option<i32>> = mounts.iter().map(|m| m.restored).collect();
        assert_eq!(restored, ids);
        // The store bind is read-only and keeps nothing of the hidden volume.
        let written = std::fs::write(nextroot.join("nix/store/hidden"), "");
        assert_eq!(written.unwrap_err().raw_os_error(), Some(nix::libc::EROFS));
        let hidden_root = decoy.hidden.path().canonicalize().unwrap();
        let hidden = top_mount_at(&read_mountinfo().unwrap(), &hidden_root)
            .unwrap()
            .dev
            .clone();
        assert!(after.iter().all(|m| m.dev != hidden), "{after:?}");
        assert!(nextroot::detach_tree(&nextroot).is_empty());
    });
}

#[test]
fn a_carried_mount_the_session_let_go_fails_the_way_back() {
    let _ = Rerun::new(test_path!(
        a_carried_mount_the_session_let_go_fails_the_way_back
    ))
    .in_user_mount_ns()
    .run(|| {
        let decoy = Decoy::new();
        let carried = [decoy.carry_boot()];
        let record = decoy.record(&carried);
        // The hidden session unmounted the carried ESP; the empty directory
        // on the hidden volume is no way back to it.
        nix::mount::umount(&carried[0].at).unwrap();
        let nextroot = decoy.nextroot();
        nextroot::bind(&decoy.root(), &nextroot, false).unwrap();
        let mut mounts = record.mounts.clone();
        let error = decoy_mounts::restore(&mut mounts, &carried, &nextroot).unwrap_err();
        assert!(error.to_string().contains("/boot"), "{error}");
        assert!(mounts.iter().all(|m| m.restored.is_none()));
        // Nothing of the hidden volume was mounted in the decoy root.
        assert_eq!(tree(&nextroot).len(), 1);
        assert!(nextroot::detach_tree(&nextroot).is_empty());
    });
}

#[test]
fn a_directory_reached_through_another_mount_is_refused() {
    let _ = Rerun::new(test_path!(
        a_directory_reached_through_another_mount_is_refused
    ))
    .in_user_mount_ns()
    .run(|| {
        let decoy = Decoy::new();
        let carried = [decoy.carry_boot()];
        let mut mounts = decoy.record(&carried).mounts;
        // A record that names the ESP's directory as one of the root
        // filesystem's: the lookup would cross into the ESP's mount.
        let store = mounts
            .iter_mut()
            .find(|m| m.target == Path::new("/nix/store"))
            .unwrap();
        store.path = PathBuf::from("boot");
        let nextroot = decoy.nextroot();
        nextroot::bind(&decoy.root(), &nextroot, false).unwrap();
        nextroot::bind(&decoy.root().join("boot"), &nextroot.join("boot"), false).unwrap();
        let error = decoy_mounts::restore(&mut mounts, &carried, &nextroot).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::CrossesDevices, "{error}");
        assert!(error.to_string().contains("/nix/store"), "{error}");
        assert!(nextroot::detach_tree(&nextroot).is_empty());
    });
}

/// The `utab` line libmount writes for `mount`, by its ID when `id` is set.
fn utab_line(mount: &MountEntry, target: &str, id: bool) -> String {
    let id = if id {
        format!("ID={} ", mount.mount_id)
    } else {
        String::new()
    };
    format!(
        "{id}SRC={} TARGET={target} ROOT={} OPTS=x-initrd.mount\n",
        mount.source.display(),
        mount.root.display()
    )
}

#[test]
fn the_transition_gives_each_utab_line_the_mount_made_in_its_mount_s_place() {
    // The ESP's two layers share their place, source and root: by place, the
    // bottom's line would take the top's new ID, and libmount would join both
    // lines to the top.
    let _ = Rerun::new(test_path!(
        the_transition_gives_each_utab_line_the_mount_made_in_its_mount_s_place
    ))
    .in_user_mount_ns()
    .run(|| {
        let decoy = Decoy::new();
        let carried = vec![decoy.carry_boot()];
        let record = decoy.record(&carried);
        let before = tree(&decoy.root());
        let named: String = before
            .iter()
            .map(|m| {
                format!(
                    "{} 1 {} {} {} {} - {} {} rw\n",
                    m.mount_id,
                    m.dev,
                    m.root.display(),
                    m.mount_point.display(),
                    m.mount_opts,
                    m.fstype,
                    m.source.display()
                )
            })
            .collect();
        let (root, store, boot) = (&before[0], &before[1], &before[2]);
        let saved = utab_line(root, "/sysroot", true)
            + &utab_line(boot, "/sysroot/boot", true)
            + &utab_line(store, "/nix/store", false);
        let run = decoy.run.path().canonicalize().unwrap();
        let runtime = run.join("overlay-runtime");
        std::fs::write(runtime.join(UTAB_NAME), &saved).unwrap();
        std::fs::write(runtime.join(UTAB_MOUNTS_NAME), named).unwrap();
        std::fs::write(run.join("mount/utab"), "ID=1 hidden\n").unwrap();

        let nextroot = decoy.nextroot();
        nextroot::bind(&decoy.root(), &nextroot, false).unwrap();
        let mut plan = decoy.plan(carried, record.mounts);
        decoy_mounts::restore(&mut plan.decoy_mounts, &plan.carried, &nextroot).unwrap();
        nextroot::bind(&run, &nextroot.join("run"), false).unwrap();
        plan.armed = Some(Arm::now(Direction::Leave));
        plan.entered_at = Some(1);
        plan.write_atomic(&runtime.join(PLAN_NAME)).unwrap();
        let now = |i: usize| plan.decoy_mounts[i].restored.unwrap();

        let outcome = transition::run(&Env {
            run: run.clone(),
            nextroot: nextroot.clone(),
            runtime_dir: runtime,
            kmsg: run.join("no-kmsg"),
            systemctl: None,
            pid_places: None,
            now: nails_teardown::whole_root::plan::unix_now(),
            mounts: read_mountinfo().unwrap(),
            network: nails_teardown::whole_root::network::Places::system(&run),
            network_tools: None,
            power_off: transition::PowerOff {
                grace: std::time::Duration::ZERO,
                kernel: || false,
            },
        });
        assert!(matches!(outcome, Outcome::Returned { .. }), "{outcome:?}");
        let rekeyed = |mount: &MountEntry, id: i32, target: &str| {
            utab_line(mount, target, false).replacen("SRC=", &format!("ID={id} SRC="), 1)
        };
        assert_eq!(
            std::fs::read_to_string(run.join("mount/utab")).unwrap(),
            rekeyed(root, now(0), "/sysroot")
                + &rekeyed(boot, now(2), "/sysroot/boot")
                + &utab_line(store, "/nix/store", false)
        );
        assert_ne!(now(2), now(3));
        nextroot::detach_tree(&nextroot);
    });
}

#[test]
fn a_bind_below_a_mount_made_before_it_comes_back() {
    // A store path bound after NixOS's store bind (fileSystems with a
    // `${pkg}/share` device), and a bind from inside a self-bind (a hardened
    // /var/tmp bound onto itself): each source is a directory of the root
    // filesystem that a lookup reaches only through the mount made before.
    let _ = Rerun::new(test_path!(a_bind_below_a_mount_made_before_it_comes_back))
        .in_user_mount_ns()
        .run(|| {
            let root = ScratchTmpfs::new("");
            for dir in ["nix/store/aaa-pkg/share", "opt/pkg", "var/tmp/x", "mnt/x"] {
                root.mkdir(dir);
            }
            std::fs::write(root.path().join("nix/store/aaa-pkg/share/doc"), "pkg").unwrap();
            let r = root.path().canonicalize().unwrap();
            let store = r.join("nix/store");
            bind(&store, &store);
            remount(
                &store,
                MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
            );
            bind(&r.join("nix/store/aaa-pkg/share"), &r.join("opt/pkg"));
            let var_tmp = r.join("var/tmp");
            bind(&var_tmp, &var_tmp);
            remount(&var_tmp, MsFlags::MS_NOSUID | MsFlags::MS_NODEV);
            bind(&r.join("var/tmp/x"), &r.join("mnt/x"));
            let before = tree(&r);
            let hidden = ScratchTmpfs::new("");
            let record = decoy_mounts::record(&before, hidden.path(), &[]);
            assert!(record.lost.is_empty(), "{:?}", record.lost);
            assert_eq!(record.mounts.len(), 5, "{:?}", record.mounts);

            let run = ScratchTmpfs::new("");
            let nextroot = run.mkdir("nextroot").canonicalize().unwrap();
            nextroot::bind(&r, &nextroot, false).unwrap();
            let mut mounts = record.mounts.clone();
            decoy_mounts::restore(&mut mounts, &[], &nextroot).expect("the way back");
            assert_eq!(shape(&tree(&nextroot)), shape(&before));
            assert_eq!(
                std::fs::read_to_string(nextroot.join("opt/pkg/doc")).unwrap(),
                "pkg"
            );
            assert!(nextroot::detach_tree(&nextroot).is_empty());
        });
}

#[test]
fn a_bind_of_what_was_deleted_since_is_lost_and_the_way_back_goes_on() {
    let _ = Rerun::new(test_path!(
        a_bind_of_what_was_deleted_since_is_lost_and_the_way_back_goes_on
    ))
    .in_user_mount_ns()
    .run(|| {
        let root = ScratchTmpfs::new("");
        for dir in ["etc", "srv/gone", "mnt/view"] {
            root.mkdir(dir);
        }
        let r = root.path().canonicalize().unwrap();
        std::fs::write(r.join("etc/conf"), "decoy").unwrap();
        std::fs::write(r.join("srv/file"), "bound").unwrap();
        bind(&r.join("srv/file"), &r.join("etc/conf"));
        std::fs::remove_file(r.join("srv/file")).unwrap();
        bind(&r.join("srv/gone"), &r.join("mnt/view"));
        std::fs::remove_dir(r.join("srv/gone")).unwrap();
        let hidden = ScratchTmpfs::new("");
        let record = decoy_mounts::record(&tree(&r), hidden.path(), &[]);
        let lost: Vec<(&Path, Why)> = record
            .lost
            .iter()
            .map(|m| (m.target.as_path(), m.why))
            .collect();
        assert_eq!(
            lost,
            [
                (Path::new("/etc/conf"), Why::Deleted),
                (Path::new("/mnt/view"), Why::Deleted)
            ]
        );

        let run = ScratchTmpfs::new("");
        let nextroot = run.mkdir("nextroot").canonicalize().unwrap();
        nextroot::bind(&r, &nextroot, false).unwrap();
        let mut mounts = record.mounts.clone();
        decoy_mounts::restore(&mut mounts, &[], &nextroot).expect("the way back");
        assert_eq!(tree(&nextroot).len(), 1);
        assert!(nextroot::detach_tree(&nextroot).is_empty());
    });
}

#[test]
fn a_mount_point_that_became_a_link_takes_no_mount_out_of_the_decoy_root() {
    // The bind itself goes by path: through a link at its mount point it
    // would land wherever the link points, outside the decoy root.
    let _ = Rerun::new(test_path!(
        a_mount_point_that_became_a_link_takes_no_mount_out_of_the_decoy_root
    ))
    .in_user_mount_ns()
    .run(|| {
        let root = ScratchTmpfs::new("");
        root.mkdir("a");
        root.mkdir("srv/b");
        let r = root.path().canonicalize().unwrap();
        bind(&r.join("a"), &r.join("srv/b"));
        let hidden = ScratchTmpfs::new("");
        let record = decoy_mounts::record(&tree(&r), hidden.path(), &[]);
        assert_eq!(record.mounts.len(), 2);
        nix::mount::umount(&r.join("srv/b")).unwrap();
        std::fs::remove_dir(r.join("srv/b")).unwrap();
        let outside = ScratchTmpfs::new("");
        let elsewhere = outside.mkdir("elsewhere").canonicalize().unwrap();
        std::os::unix::fs::symlink(&elsewhere, r.join("srv/b")).unwrap();

        let run = ScratchTmpfs::new("");
        let nextroot = run.mkdir("nextroot").canonicalize().unwrap();
        nextroot::bind(&r, &nextroot, false).unwrap();
        let mut mounts = record.mounts.clone();
        let error = decoy_mounts::restore(&mut mounts, &[], &nextroot).unwrap_err();
        let eloop = std::io::Error::from_raw_os_error(nix::libc::ELOOP);
        assert_eq!(error.kind(), eloop.kind(), "{error}");
        assert!(error.to_string().contains(&eloop.to_string()), "{error}");
        assert!(error.to_string().contains("/srv/b"), "{error}");
        let live = read_mountinfo().unwrap();
        assert!(
            live.iter().all(|m| !m.mount_point.starts_with(&elsewhere)),
            "{live:?}"
        );
        assert_eq!(tree(&nextroot).len(), 1);
        assert!(nextroot::detach_tree(&nextroot).is_empty());
    });
}

#[test]
fn a_directory_is_not_put_on_a_file() {
    let _ = Rerun::new(test_path!(a_directory_is_not_put_on_a_file))
        .in_user_mount_ns()
        .run(|| {
            let root = ScratchTmpfs::new("");
            root.mkdir("etc");
            root.mkdir("srv/dir");
            let r = root.path().canonicalize().unwrap();
            std::fs::write(r.join("etc/conf"), "decoy").unwrap();
            std::fs::write(r.join("srv/file"), "bound").unwrap();
            bind(&r.join("srv/file"), &r.join("etc/conf"));
            let hidden = ScratchTmpfs::new("");
            let mut mounts = decoy_mounts::record(&tree(&r), hidden.path(), &[]).mounts;
            // A record that names a directory for the file's place.
            assert_eq!(mounts[1].path, Path::new("srv/file"));
            mounts[1].path = PathBuf::from("srv/dir");

            let run = ScratchTmpfs::new("");
            let nextroot = run.mkdir("nextroot").canonicalize().unwrap();
            nextroot::bind(&r, &nextroot, false).unwrap();
            let error = decoy_mounts::restore(&mut mounts, &[], &nextroot).unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidData, "{error}");
            assert!(error.to_string().contains("/etc/conf"), "{error}");
            assert_eq!(tree(&nextroot).len(), 1);
            assert!(nextroot::detach_tree(&nextroot).is_empty());
        });
}

#[test]
fn the_decoy_root_gets_its_own_options_back() {
    // The device mount gives the decoy root the filesystem's default
    // per-mount options; the decoy had it read-only and nosuid.
    let _ = Rerun::new(test_path!(the_decoy_root_gets_its_own_options_back))
        .in_user_mount_ns()
        .run(|| {
            let root = ScratchTmpfs::new("");
            root.mkdir("etc");
            let r = root.path().canonicalize().unwrap();
            remount(&r, MsFlags::MS_RDONLY | MsFlags::MS_NOSUID);
            let hidden = ScratchTmpfs::new("");
            let mut mounts = decoy_mounts::record(&tree(&r), hidden.path(), &[]).mounts;
            assert_eq!(mounts[0].options, "ro,nosuid,relatime");

            let run = ScratchTmpfs::new("");
            let nextroot = run.mkdir("nextroot").canonicalize().unwrap();
            nextroot::bind(&r, &nextroot, false).unwrap();
            remount(&nextroot, MsFlags::empty());
            assert_eq!(tree(&nextroot)[0].mount_opts, "rw,relatime");
            decoy_mounts::restore(&mut mounts, &[], &nextroot).expect("the way back");
            assert_eq!(tree(&nextroot)[0].mount_opts, "ro,nosuid,relatime");
            assert!(nextroot::detach_tree(&nextroot).is_empty());
        });
}

/// The mount points of the tree at `nextroot`, relative to it.
fn points(nextroot: &Path) -> Vec<PathBuf> {
    tree(nextroot).into_iter().map(|m| m.mount_point).collect()
}

#[test]
fn the_way_back_puts_the_recorded_mounts_or_the_carried_ones_and_run_in_place() {
    let _ = Rerun::new(test_path!(
        the_way_back_puts_the_recorded_mounts_or_the_carried_ones_and_run_in_place
    ))
    .in_user_mount_ns()
    .run(|| {
        let decoy = Decoy::new();
        let carried = vec![decoy.carry_boot()];
        let record = decoy.record(&carried);
        let run = decoy.run();
        let run_point = Path::new("/").join(run.strip_prefix("/").unwrap());
        let nextroot = decoy.nextroot();

        // With the record: the store bind and both ESP layers.
        let mut plan = decoy.plan(carried.clone(), record.mounts);
        nextroot::bind(&decoy.root(), &nextroot, false).unwrap();
        ret::complete_decoy_root(&mut plan, &nextroot, &run).expect("the way back");
        assert_eq!(
            points(&nextroot),
            ["/", "/nix/store", "/boot", "/boot"]
                .map(PathBuf::from)
                .into_iter()
                .chain([run_point.clone()])
                .collect::<Vec<_>>()
        );
        let ids: Vec<i32> = tree(&nextroot).iter().map(|m| m.mount_id).collect();
        let restored: Vec<Option<i32>> = plan.decoy_mounts.iter().map(|m| m.restored).collect();
        assert_eq!(
            restored,
            ids[..4].iter().copied().map(Some).collect::<Vec<_>>()
        );
        assert!(nextroot::detach_tree(&nextroot).is_empty());

        // A plan written before the record: the carried ESP alone, once.
        let mut plan = decoy.plan(carried, Vec::new());
        nextroot::bind(&decoy.root(), &nextroot, false).unwrap();
        ret::complete_decoy_root(&mut plan, &nextroot, &run).expect("the way back");
        assert_eq!(
            points(&nextroot),
            [PathBuf::from("/"), PathBuf::from("/boot"), run_point]
        );
        assert!(nextroot::detach_tree(&nextroot).is_empty());
    });
}

#[test]
fn a_way_back_that_fails_leaves_nothing_at_the_next_root_and_no_new_id() {
    let _ = Rerun::new(test_path!(
        a_way_back_that_fails_leaves_nothing_at_the_next_root_and_no_new_id
    ))
    .in_user_mount_ns()
    .run(|| {
        let decoy = Decoy::new();
        let carried = vec![decoy.carry_boot()];
        let record = decoy.record(&carried);
        let run = decoy.run();
        let nextroot = decoy.nextroot();

        // The decoy init is not where the plan says: the check fails once
        // every mount is made.
        let mut plan = decoy.plan(carried.clone(), record.mounts.clone());
        plan.decoy.init = PathBuf::from("/usr/lib/systemd/no-such-init");
        nextroot::bind(&decoy.root(), &nextroot, false).unwrap();
        let error = ret::complete_decoy_root(&mut plan, &nextroot, &run).unwrap_err();
        assert!(matches!(error, ReturnError::Precheck(_)), "{error}");
        assert!(points(&nextroot).is_empty(), "{:?}", points(&nextroot));
        assert!(plan.decoy_mounts.iter().all(|m| m.restored.is_none()));

        // The hidden session unmounted the carried ESP.
        nix::mount::umount(&carried[0].at).unwrap();
        let mut plan = decoy.plan(carried, record.mounts);
        nextroot::bind(&decoy.root(), &nextroot, false).unwrap();
        let error = ret::complete_decoy_root(&mut plan, &nextroot, &run).unwrap_err();
        assert!(matches!(error, ReturnError::DecoyMounts(_)), "{error}");
        assert!(
            error
                .to_string()
                .starts_with("could not make the decoy's mounts again: /boot"),
            "{error}"
        );
        assert!(points(&nextroot).is_empty(), "{:?}", points(&nextroot));
        assert!(plan.decoy_mounts.iter().all(|m| m.restored.is_none()));
    });
}
