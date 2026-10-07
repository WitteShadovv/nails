// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The teardown plan against real mounts, in a private user + mount namespace
//! (see `crate::test_support`).
//!
//! Every kind of activation step is made for real with the production mount
//! code and recorded through the production recorder; the assertions read the
//! kernel's mount table afterwards. The recorded undo takes each step down and
//! spares the decoy mount underneath, a second run touches nothing, a plan
//! rebuilt from the mount table names the same steps in the same order, and the
//! emergency hot path's cgroup kill frees an overlay a busy cgroup pinned.

use super::{FsMountOps, PlanRecorder};
use crate::filesystem::{Filesystem, RealFilesystem};
use crate::manager::mount_tracker::{MountInfo, MountTracker};
use crate::test_support::{Rerun, ScratchTmpfs};
use nails_teardown::mountinfo::{read_mountinfo, top_mount_at};
use nails_teardown::{MountKind, Phase, Plan, Undo};
use std::path::{Path, PathBuf};

const RUNTIME_ROOT: &str = "/run/0123456789abcdef";

/// The session layout: what an activation mounts, made with the production
/// code and recorded step by step.
struct Session {
    hidden: ScratchTmpfs,
    decoy: ScratchTmpfs,
    recorder: PlanRecorder,
}

impl Session {
    fn home(&self) -> PathBuf {
        self.decoy.path().join("home")
    }
    fn var(&self) -> PathBuf {
        self.decoy.path().join("var")
    }
    fn usr(&self) -> PathBuf {
        self.decoy.path().join("usr")
    }
    fn persona(&self) -> PathBuf {
        self.home().join("op")
    }
    fn staging(&self) -> PathBuf {
        self.hidden.path().join(".nails-submounts/staging/data")
    }
}

fn mounted(target: &Path) -> bool {
    let entries = read_mountinfo().unwrap();
    top_mount_at(&entries, target).is_some()
}

fn fstype(target: &Path) -> Option<String> {
    let entries = read_mountinfo().unwrap();
    top_mount_at(&entries, target).map(|e| e.fstype.clone())
}

/// Mount every kind of step, the way activation does, and record it.
fn activate() -> Session {
    let fs = RealFilesystem;
    // A private /run for the runtime root and the plan file.
    nix::mount::mount(
        Some("tmpfs"),
        "/run",
        Some("tmpfs"),
        nix::mount::MsFlags::empty(),
        Some("mode=0755"),
    )
    .expect("a private /run");
    let hidden = ScratchTmpfs::new("");
    let decoy = ScratchTmpfs::new("");
    let recorder = PlanRecorder::new(
        hidden.path().to_path_buf(),
        Some(nails_teardown::plan::default_plan_path()),
    );
    let session = Session {
        hidden,
        decoy,
        recorder,
    };
    let mut tracker = MountTracker::with_plan(&fs, session.recorder.clone());

    // The runtime scaffolding root.
    fs.mount_tmpfs(Path::new(RUNTIME_ROOT), "16M").unwrap();
    tracker.push_mount(MountInfo::tmpfs(PathBuf::from(RUNTIME_ROOT)));

    // A persistent overlay over a decoy directory that is its own mount (the
    // decoy's separate /home partition), holding a decoy file.
    let home = session.home();
    fs.mount_tmpfs(&home, "8M").unwrap();
    std::fs::write(home.join("decoy.txt"), "decoy").unwrap();
    let upper = session.hidden.mkdir("home/upper");
    let work = session.hidden.mkdir("home/work");
    fs.mount_overlay(&[home.as_path()], &upper, &work, &home)
        .unwrap();
    tracker.push_mount(MountInfo::persistent(home.clone()));

    // An ephemeral overlay whose upper and work are tmpfs in the runtime root.
    let var = session.decoy.mkdir("var");
    let var_layers = PathBuf::from(RUNTIME_ROOT).join("var");
    fs.mount_tmpfs(&var_layers, "8M").unwrap();
    let (var_upper, var_work) = (var_layers.join("upper"), var_layers.join("work"));
    std::fs::create_dir(&var_upper).unwrap();
    std::fs::create_dir(&var_work).unwrap();
    fs.mount_overlay(&[var.as_path()], &var_upper, &var_work, &var)
        .unwrap();
    tracker.push_mount(MountInfo::ephemeral(var, vec![var_layers]));

    // The fresh-home persona bind over the operator's home, inside the overlay.
    let persona_source = session.hidden.mkdir("persona/home");
    std::fs::create_dir_all(session.persona()).unwrap();
    fs.bind_mount(&persona_source, &session.persona()).unwrap();
    tracker.push_mount(MountInfo::persistent(session.persona()));

    // A submount staging bind under the hidden root.
    let data = session.decoy.mkdir("data");
    std::fs::create_dir_all(session.staging()).unwrap();
    fs.bind_mount(&data, &session.staging()).unwrap();
    tracker.push_mount(MountInfo::bind(session.staging()));
    tracker.take_mounts();

    // A read-only guard on a decoy OS tree, recorded where activation does.
    let usr = session.decoy.mkdir("usr");
    fs.remount_read_only(&usr).unwrap();
    session
        .recorder
        .record(Undo::RemoveReadOnlyGuard { tree: usr });
    session
}

/// The NAILS mounts of the session still in the table.
fn nails_left(session: &Session) -> Vec<PathBuf> {
    [
        PathBuf::from(RUNTIME_ROOT),
        session.var(),
        session.persona(),
        session.staging(),
    ]
    .into_iter()
    .filter(|p| mounted(p))
    .chain((fstype(&session.home()).as_deref() == Some("overlay")).then(|| session.home()))
    .collect()
}

#[test]
fn every_recorded_step_is_undone_and_the_decoy_mount_beneath_is_spared() {
    let _ = Rerun::new(crate::test_path!(
        every_recorded_step_is_undone_and_the_decoy_mount_beneath_is_spared
    ))
    .in_user_mount_ns()
    .run(|| {
        let session = activate();
        let plan = session.recorder.snapshot();

        // The plan file on the decoy /run is the plan in memory, with the
        // kernel's mount ids recorded for the mounts.
        assert_eq!(
            Plan::load(&nails_teardown::plan::default_plan_path()).unwrap(),
            plan
        );
        assert!(plan.steps.iter().all(|step| match &step.undo {
            Undo::Unmount { mount_id, .. } => mount_id.is_some(),
            _ => true,
        }));
        assert!(std::fs::write(session.usr().join("x"), "x").is_err());

        crate::manager::activation::rollback::undo_plan(&RealFilesystem, &plan);

        assert!(
            nails_left(&session).is_empty(),
            "{:?}",
            nails_left(&session)
        );
        assert!(
            !Path::new(RUNTIME_ROOT).exists(),
            "the runtime root is removed"
        );
        // The decoy /home partition the overlay sat on is still mounted, with
        // its file, and the guarded tree is writable again.
        assert_eq!(fstype(&session.home()).as_deref(), Some("tmpfs"));
        assert_eq!(
            std::fs::read_to_string(session.home().join("decoy.txt")).unwrap(),
            "decoy"
        );
        std::fs::write(session.usr().join("x"), "x").unwrap();

        // Running the plan again finds every step gone and leaves the decoy's
        // own mount at the overlay's target alone.
        let again = crate::manager::activation::rollback::undo_plan(&RealFilesystem, &plan);
        assert!(again.failures().is_empty(), "{again:?}");
        assert_eq!(fstype(&session.home()).as_deref(), Some("tmpfs"));
    });
}

#[test]
fn a_plan_rebuilt_from_the_mount_table_names_the_recorded_steps_in_order() {
    let _ = Rerun::new(crate::test_path!(
        a_plan_rebuilt_from_the_mount_table_names_the_recorded_steps_in_order
    ))
    .in_user_mount_ns()
    .run(|| {
        let session = activate();
        let recorded = session.recorder.snapshot();
        let derived =
            nails_teardown::derive::derive_plan(&read_mountinfo().unwrap(), session.hidden.path());
        let unmounts = |plan: &Plan| -> Vec<(PathBuf, MountKind)> {
            plan.undo_order()
                .filter_map(|undo| match undo {
                    Undo::Unmount { target, kind, .. } => Some((target.clone(), *kind)),
                    _ => None,
                })
                .collect()
        };
        // The mount table cannot show a submount staging bind or a guard; every
        // mount step it can show comes back in the recorded teardown order.
        let expected: Vec<_> = unmounts(&recorded)
            .into_iter()
            .filter(|(_, kind)| *kind != MountKind::Attachment)
            .collect();
        assert_eq!(unmounts(&derived), expected);

        // The rebuilt plan, run through the kernel operations of the hot path
        // with the reconcile, leaves no NAILS mount.
        let ops = nails_teardown::KernelMountOps::new(
            session.hidden.path().to_path_buf(),
            derived.runtime_root.clone(),
            derived.mount_namespace,
        );
        let report = nails_teardown::undo::run_plan(
            &ops,
            &derived,
            &[Phase::Dependents, Phase::Store, Phase::Main],
            true,
        );
        assert!(report.failures().is_empty(), "{report:?}");
        // Only the staging bind, which the table cannot attribute, is left;
        // the recorded plan's undo of it then finds it.
        assert_eq!(nails_left(&session), vec![session.staging()]);
        crate::manager::activation::rollback::undo_plan(&RealFilesystem, &recorded);
        assert!(nails_left(&session).is_empty());
    });
}

#[test]
fn the_filesystem_and_kernel_operations_judge_presence_alike() {
    let _ = Rerun::new(crate::test_path!(
        the_filesystem_and_kernel_operations_judge_presence_alike
    ))
    .in_user_mount_ns()
    .run(|| {
        use nails_teardown::MountOps;
        let session = activate();
        let plan = session.recorder.snapshot();
        let fs_ops = FsMountOps::for_plan(&RealFilesystem, &plan);
        let kernel = nails_teardown::KernelMountOps::new(
            plan.hidden_root.clone(),
            plan.runtime_root.clone(),
            plan.mount_namespace,
        );
        for step in &plan.steps {
            if let Undo::Unmount {
                target,
                kind,
                mount_id,
            } = &step.undo
            {
                assert_eq!(
                    fs_ops.presence(target, *kind, *mount_id).unwrap(),
                    kernel.presence(target, *kind, *mount_id).unwrap(),
                    "{target:?}"
                );
            }
        }
        crate::manager::activation::rollback::undo_plan(&RealFilesystem, &plan);
    });
}

/// A delegated cgroup in the namespace's own cgroup2 mount, or a skip.
fn delegated_cgroup(root: &Path, name: &str) -> PathBuf {
    std::fs::create_dir_all(root).unwrap();
    if let Err(e) = nix::mount::mount(
        Some("none"),
        root,
        Some("cgroup2"),
        nix::mount::MsFlags::empty(),
        None::<&str>,
    ) {
        crate::test_support::skip(&format!("cannot mount cgroup2 in the namespace: {e}"));
    }
    let dir = root.join(name);
    if let Err(e) = std::fs::create_dir(&dir) {
        crate::test_support::skip(&format!("the caller's cgroup is not delegated: {e}"));
    }
    dir
}

/// Spawn `sh -c script` with `cwd`, joined to the cgroup at `dir` before exec.
#[allow(unsafe_code)]
fn spawn_in(dir: &Path, cwd: &Path, script: &str) -> std::process::Child {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    let procs = std::fs::OpenOptions::new()
        .write(true)
        .open(dir.join("cgroup.procs"))
        .unwrap();
    let fd = procs.as_raw_fd();
    let mut command = std::process::Command::new("sh");
    command
        .args(["-c", script])
        .current_dir(cwd)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    // SAFETY: one raw write to an fd opened before the fork.
    unsafe {
        command.pre_exec(move || {
            if nix::libc::write(fd, b"0".as_ptr().cast(), 1) != 1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command.spawn().unwrap();
    drop(procs);
    child
}

#[test]
fn cgroup_kill_empties_a_busy_cgroup_and_frees_its_overlay() {
    let _ = Rerun::new(crate::test_path!(
        cgroup_kill_empties_a_busy_cgroup_and_frees_its_overlay
    ))
    .in_cgroup_ns()
    .run(|| {
        let hidden = ScratchTmpfs::new("");
        let decoy = ScratchTmpfs::new("");
        let lower = decoy.mkdir("lower");
        let target = decoy.mkdir("target");
        let upper = hidden.mkdir("upper");
        let work = hidden.mkdir("work");
        RealFilesystem
            .mount_overlay(&[lower.as_path()], &upper, &work, &target)
            .unwrap();
        let cgroup = delegated_cgroup(
            &decoy.path().join("cgroup"),
            &format!("hidden-{}.service", std::process::id()),
        );
        let desktop = cgroup
            .parent()
            .unwrap()
            .join(format!("desktop-{}", std::process::id()));
        std::fs::create_dir(&desktop).unwrap();

        let mut holders = vec![
            spawn_in(&cgroup, &target, "exec sleep 600"),
            spawn_in(
                &cgroup,
                &target,
                "trap '' TERM; while :; do echo x >> log; sleep 0.01; done",
            ),
            spawn_in(
                &cgroup,
                &target,
                "i=0; while [ $i -lt 200 ]; do sleep 600 & i=$((i+1)); done; wait",
            ),
        ];
        let mut bystander = spawn_in(&desktop, decoy.path(), "exec sleep 600");
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(nix::mount::umount2(&target, nix::mount::MntFlags::empty()).is_err());

        let method = nails_teardown::cgroup::kill(&cgroup, &[]).unwrap();
        assert_eq!(method, nails_teardown::cgroup::KillMethod::Atomic);
        let full = nails_teardown::cgroup::await_empty(
            std::slice::from_ref(&cgroup),
            std::time::Duration::from_secs(5),
        );
        assert!(full.is_empty(), "the cgroup drained");
        nix::mount::umount2(&target, nix::mount::MntFlags::empty())
            .expect("a non-lazy unmount once the cgroup is empty");
        assert!(
            matches!(bystander.try_wait(), Ok(None)),
            "the sibling survives"
        );
        for holder in &mut holders {
            let _ = holder.wait();
        }
        let _ = bystander.kill();
        let _ = bystander.wait();
        let _ = std::fs::remove_dir(&cgroup);
        let _ = std::fs::remove_dir(&desktop);
    });
}

#[test]
fn the_hot_path_kills_the_hidden_unit_and_a_writer_and_spares_the_session() {
    let _ = Rerun::new(crate::test_path!(
        the_hot_path_kills_the_hidden_unit_and_a_writer_and_spares_the_session
    ))
    .in_cgroup_ns()
    .in_pid_ns()
    .run(|| {
        let hidden = ScratchTmpfs::new("");
        let decoy = ScratchTmpfs::new("");
        let lower = decoy.mkdir("lower");
        let target = decoy.mkdir("target");
        let upper = hidden.mkdir("upper");
        let work = hidden.mkdir("work");
        RealFilesystem
            .mount_overlay(&[lower.as_path()], &upper, &work, &target)
            .unwrap();
        // A cgroup tree of this run's own (runs share the delegated cgroup),
        // laid out like a systemd host's.
        let root = delegated_cgroup(
            &decoy.path().join("cgroup"),
            &format!("host-{}", std::process::id()),
        );
        let unit = root.join("system.slice");
        std::fs::create_dir(&unit).unwrap();
        let unit = {
            let dir = unit.join("hidden.service");
            std::fs::create_dir(&dir).unwrap();
            dir
        };
        let session = root.join("user.slice/user-1000.slice/user@1000.service");
        std::fs::create_dir_all(&session).unwrap();
        let others = root.join("other.scope");
        std::fs::create_dir(&others).unwrap();

        // The hidden unit's process, a lone writer holding a file open for
        // append in the overlay, and the desktop working in the overlay.
        let mut service = spawn_in(&unit, &target, "exec sleep 600");
        let mut writer = spawn_in(
            &others,
            decoy.path(),
            &format!("exec 3>>{}/w.log; exec sleep 600", target.display()),
        );
        let mut desktop = spawn_in(&session, &target, "exec sleep 600");
        std::thread::sleep(std::time::Duration::from_millis(300));

        let mut plan = Plan::new(hidden.path().to_path_buf());
        plan.mount_namespace = nails_teardown::derive::own_mount_namespace();
        plan.push(Undo::Unmount {
            target: target.clone(),
            kind: MountKind::Overlay,
            mount_id: top_mount_at(&read_mountinfo().unwrap(), &target).map(|e| e.mount_id),
        });
        plan.push(Undo::StopUnit {
            unit: "hidden.service".to_string(),
        });
        plan.session.spare_fragments = vec!["/user@1000.service".to_string()];
        let host = nails_teardown::Host {
            systemctl: Some(nails_teardown::plan::Tool::direct("/bin/sh".into())),
            journalctl: None,
            spared_units: Vec::new(),
            protected_pids: Vec::new(),
            sessions_dir: decoy.path().join("sessions"),
            cgroup_root: root.clone(),
        };
        std::fs::create_dir(decoy.path().join("sessions")).unwrap();
        let ops = nails_teardown::KernelMountOps::new(
            plan.hidden_root.clone(),
            None,
            plan.mount_namespace,
        );
        let report = nails_teardown::emergency::run(
            &ops,
            plan,
            nails_teardown::PlanSource::Recorded,
            Some(&host),
        );

        // The unit's cgroup and the writer were killed, the desktop spared, and
        // the overlay it still pins was detached lazily.
        assert_eq!(report.units_stopped, vec!["hidden.service".to_string()]);
        assert!(report.cgroups_killed.contains(&unit), "{report:?}");
        assert_eq!(report.processes_killed, vec![writer.id()]);
        assert_eq!(report.session_processes_spared, 1);
        assert!(service.wait().is_ok());
        assert!(writer.wait().is_ok());
        assert!(
            matches!(desktop.try_wait(), Ok(None)),
            "the desktop survives"
        );
        assert!(!mounted(&target));
        assert!(report.remaining.is_empty());
        assert_eq!(
            report.undo.detached(&[MountKind::Overlay]),
            vec![(target, true)]
        );
        let _ = desktop.kill();
        let _ = desktop.wait();
        // Leave the delegated cgroup as it was: remove the run's tree.
        for dir in [
            unit.clone(),
            unit.parent().unwrap().to_path_buf(),
            session.clone(),
            root.join("user.slice/user-1000.slice"),
            root.join("user.slice"),
            others.clone(),
            root.clone(),
        ] {
            let _ = std::fs::remove_dir(dir);
        }
    });
}
