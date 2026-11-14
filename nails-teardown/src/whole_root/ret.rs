// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Preparing the way back to the plain decoy root.
//!
//! Shared by `deactivate` and `emergency`, both running in the hidden session:
//!
//! 1. mount the decoy root device at `/run/nextroot`. It is the same superblock
//!    as the overlay's lower, so the mount writes nothing;
//! 2. make the decoy's mounts again in the order the decoy mounted them, from
//!    the decoy root and the filesystems the hidden session carried, each with
//!    its per-mount options ([`crate::whole_root::decoy_mounts`]): the
//!    filesystems the fstab policy placed, mounts stacked on them, binds such
//!    as NixOS's read-only store, so a decoy store on its own filesystem is
//!    there for the init check and the decoy starts with every mount it had.
//!    A plan written without that record puts back the carried filesystems
//!    alone ([`crate::whole_root::carry`]);
//! 3. bind `/run` there (PID 1's init check on NixOS resolves
//!    `/run/current-system` inside the new root) and make everything below
//!    the decoy root private (its own mount stays shared until the switch, see
//!    [`crate::whole_root::nextroot`]);
//! 4. check the decoy init resolves in it;
//! 5. mark the hidden backend's device-mapper stack for deferred removal, so its
//!    key leaves the kernel the moment the switch releases the hidden volume;
//! 6. arm the plan for the way back, with the process-number counter it sets
//!    ([`crate::whole_root::fresh_pids`]).
//!
//! [`mount_decoy_root`] takes the first four steps, [`complete_decoy_root`]
//! the second to the fourth on a decoy root mounted already. The caller then
//! enqueues the soft-reboot. The transition step
//! ([`crate::whole_root::transition`]) does the rest.
//!
//! Where the plan records an exec prefix ([`crate::whole_root::exec_prefix`]),
//! PID 1 starts that step through it in the hidden root, and the pieces the
//! step leaves for the decoy's first start in the decoy root: before it mounts
//! anything [`mount_decoy_root`] checks the prefix in the root it runs in, the
//! hidden root, and in the fourth step [`complete_decoy_root`] checks it in the
//! decoy root as well. A way back whose step could not start is not prepared:
//! the switch would go on without it.

use crate::mountinfo::{MountEntry, parse_overlay_opts, read_mountinfo, top_mount_at};
use crate::whole_root::plan::{Arm, Direction, Plan, RootSide};
use crate::whole_root::tools;
use crate::whole_root::{carry, decoy_mounts, exec_prefix, fresh_pids, nextroot};
use std::path::{Path, PathBuf};

/// Whether this process runs in the hidden root of `plan`: `/` is an overlay
/// whose upper is the plan's.
pub fn in_hidden_root(entries: &[MountEntry], plan: &Plan) -> bool {
    top_mount_at(entries, Path::new("/")).is_some_and(|root| {
        root.fstype == "overlay"
            && parse_overlay_opts(&root.super_opts).upperdir.as_deref()
                == Some(plan.upper.as_path())
    })
}

/// The init path of `side` as it resolves *before* `/run/current-system` is
/// repointed: on NixOS the init is reached through the link, which still names
/// the other side until the transition step repoints it.
pub fn init_before_repoint(side: &RootSide) -> PathBuf {
    match (&side.system, side.init.strip_prefix("/run/current-system")) {
        (Some(system), Ok(rest)) => system.join(rest),
        _ => side.init.clone(),
    }
}

/// Why the way back could not be prepared.
#[derive(Debug)]
pub enum ReturnError {
    /// The decoy root could not be mounted at `/run/nextroot`.
    Mount(String),
    /// A mount of the decoy could not be made again below it, or `/run` not
    /// bound into it.
    DecoyMounts(String),
    /// The decoy root failed the init check.
    Precheck(String),
    /// The program the plan starts the transition step through
    /// ([`Plan::exec_prefix`]) does not start in a root the way back starts
    /// it in, as the message says.
    ExecPrefix(String),
    /// The plan could not be armed.
    Arm(String),
}

impl std::fmt::Display for ReturnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReturnError::Mount(e) => write!(f, "could not mount the decoy root: {e}"),
            ReturnError::DecoyMounts(e) => {
                write!(f, "could not make the decoy's mounts again: {e}")
            }
            ReturnError::Precheck(e) => write!(f, "the decoy root is not bootable: {e}"),
            ReturnError::ExecPrefix(e) => write!(f, "{e}"),
            ReturnError::Arm(e) => write!(f, "could not arm the way back: {e}"),
        }
    }
}

impl std::error::Error for ReturnError {}

/// Mount the decoy root at `nextroot` with the decoy's mounts and `run` bound
/// into it, and check it ([`complete_decoy_root`]). The plan's record of the
/// decoy's mounts gets the ID each one has now, which the transition gives
/// their `utab` lines; the caller writes the plan. On failure nothing is left
/// mounted there. First of all it checks the plan's exec prefix in `/`, the
/// hidden root, where PID 1 starts the transition step through it
/// ([`check_exec_prefix`]): without it nothing is mounted.
pub fn mount_decoy_root(plan: &mut Plan, nextroot: &Path, run: &Path) -> Result<(), ReturnError> {
    check_exec_prefix(plan, Path::new("/"), Side::Hidden)?;
    if read_mountinfo().is_ok_and(|e| nextroot::is_mount_point(&e, nextroot)) {
        nextroot::detach_tree(nextroot);
    }
    let mounted = std::fs::create_dir_all(nextroot)
        .map_err(|e| ReturnError::Mount(e.to_string()))
        .and_then(|()| {
            nextroot::mount_device(
                &plan.decoy_root.source,
                &plan.decoy_root.fstype,
                plan.decoy_root.data.as_deref(),
                nextroot,
            )
            .map_err(|e| ReturnError::Mount(format!("{}: {e}", plan.decoy_root.source.display())))
        });
    match mounted {
        Ok(()) => complete_decoy_root(plan, nextroot, run),
        Err(e) => {
            give_up(plan, nextroot);
            Err(e)
        }
    }
}

/// The rest of [`mount_decoy_root`], once the decoy root is mounted at
/// `nextroot`: make the decoy's mounts again below it from the plan's record
/// of them, or, for a plan written without that record, put the carried
/// filesystems back ([`carry::restore`]); bind `run` there and make everything
/// below the decoy root private; check the decoy init resolves in it, and the
/// plan's exec prefix, through which PID 1 starts the pieces the way back
/// leaves for the decoy's first start ([`check_exec_prefix`]). On failure
/// nothing is left mounted at `nextroot`, the decoy root included, and no
/// decoy mount keeps an ID the way back gave it.
pub fn complete_decoy_root(
    plan: &mut Plan,
    nextroot: &Path,
    run: &Path,
) -> Result<(), ReturnError> {
    let result = (|| {
        if plan.decoy_mounts.is_empty() {
            carry::restore(&plan.carried, nextroot)
        } else {
            decoy_mounts::restore(&mut plan.decoy_mounts, &plan.carried, nextroot)
        }
        .map_err(|e| ReturnError::DecoyMounts(e.to_string()))?;
        nextroot::bind(
            run,
            &nextroot.join(run.strip_prefix("/").unwrap_or(run)),
            false,
        )
        .map_err(|e| ReturnError::DecoyMounts(format!("bind of {}: {e}", run.display())))?;
        nextroot::make_below_private(nextroot)
            .map_err(|e| ReturnError::DecoyMounts(e.to_string()))?;
        nextroot::precheck(nextroot, &init_before_repoint(&plan.decoy))
            .map_err(|e| ReturnError::Precheck(e.to_string()))?;
        check_exec_prefix(plan, nextroot, Side::Decoy)
    })();
    if result.is_err() {
        give_up(plan, nextroot);
    }
    result
}

/// The root a way back starts something in through the plan's exec prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// The hidden root, where PID 1 starts the transition step.
    Hidden,
    /// The decoy root, where it starts the pieces the step leaves for the
    /// decoy's first start.
    Decoy,
}

/// Check that the program the plan starts the binary copy through, if it
/// records one, starts in `root`, the `side` the way back starts something in
/// through it ([`exec_prefix::check`]). Without it there the transition step
/// would not start, and the switch would go on without it, or the decoy's
/// first start would run none of its pieces.
pub fn check_exec_prefix(plan: &Plan, root: &Path, side: Side) -> Result<(), ReturnError> {
    let Some(prefix) = plan.exec_prefix.as_deref() else {
        return Ok(());
    };
    exec_prefix::check(root, prefix).map_err(|unusable| {
        let (place, what) = match side {
            Side::Hidden => ("the hidden root", "the last step of the way back"),
            Side::Decoy => (
                "the decoy root",
                "what the way back leaves for the decoy's first start",
            ),
        };
        let prefix = prefix.display();
        ReturnError::ExecPrefix(format!(
            "PID 1 starts {what} through {prefix}, and in {place} {prefix} {unusable}"
        ))
    })
}

/// Undo a way back that failed halfway: detach everything at `nextroot` and
/// forget the IDs the way back gave the decoy's mounts.
fn give_up(plan: &mut Plan, nextroot: &Path) {
    nextroot::detach_tree(nextroot);
    for mount in &mut plan.decoy_mounts {
        mount.restored = None;
    }
}

/// Mark the plan's device-mapper stack for deferred removal, top first.
/// Returns each name with whether the mark took.
pub fn close_backend_deferred(plan: &Plan) -> Vec<(String, bool)> {
    let Some(dmsetup) = tools::find(plan.tools.dmsetup.as_deref(), "dmsetup") else {
        return plan.backend.iter().map(|n| (n.clone(), false)).collect();
    };
    plan.backend
        .iter()
        .map(|name| (name.clone(), tools::remove_deferred(&dmsetup, name)))
        .collect()
}

/// What became of one backend device when the decoy side closed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendClose {
    /// It is closed: its key has left kernel memory.
    Closed,
    /// It is still open, in use (mounted, or a device stacked on it).
    InUse,
}

/// On the decoy side, close the plan's device-mapper stack, top first, where
/// nothing uses it any more. A device in use is left open and reported: the
/// operator may have the hidden volume mounted on purpose. Devices that are
/// already gone are not listed.
pub fn close_idle_backend(plan: &Plan, mapper_dir: &Path) -> Vec<(String, BackendClose)> {
    let present: Vec<&String> = plan
        .backend
        .iter()
        .filter(|name| mapper_dir.join(name).exists())
        .collect();
    if present.is_empty() {
        return Vec::new();
    }
    let dmsetup = tools::find(plan.tools.dmsetup.as_deref(), "dmsetup");
    present
        .into_iter()
        .map(|name| {
            let closed = dmsetup
                .as_deref()
                .is_some_and(|dmsetup| tools::remove_now(dmsetup, name));
            let state = if closed {
                BackendClose::Closed
            } else {
                BackendClose::InUse
            };
            (name.clone(), state)
        })
        .collect()
}

/// Arm `plan` for the way back and write it to `path`, with the process-number
/// counter the way back sets measured now, while the hidden session's own
/// start still runs ([`fresh_pids::counter`]).
pub fn arm_leave(plan: &mut Plan, path: &Path) -> Result<(), ReturnError> {
    plan.pids.counter = fresh_pids::counter(&plan.pids, Path::new("/proc"));
    plan.armed = Some(Arm::now(Direction::Leave));
    plan.write_atomic(path)
        .map_err(|e| ReturnError::Arm(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mountinfo::parse_mountinfo;
    use crate::whole_root::plan::sample;

    #[test]
    fn the_hidden_root_is_recognised_by_its_upper() {
        let plan = sample();
        let hidden = parse_mountinfo(
            "30 1 0:30 / / rw - overlay overlay rw,lowerdir=/run/overlay-runtime/lower,upperdir=/mnt/data/root/upper,workdir=/mnt/data/root/work\n",
        );
        assert!(in_hidden_root(&hidden, &plan));
        let other = parse_mountinfo(
            "30 1 0:30 / / rw - overlay overlay rw,lowerdir=/x,upperdir=/elsewhere/upper,workdir=/w\n",
        );
        assert!(!in_hidden_root(&other, &plan));
        let decoy = parse_mountinfo("30 1 8:2 / / rw - ext4 /dev/vda2 rw\n");
        assert!(!in_hidden_root(&decoy, &plan));
    }

    #[test]
    fn a_nixos_init_is_checked_through_the_system_it_will_point_at() {
        let side = RootSide {
            init: PathBuf::from("/run/current-system/systemd/lib/systemd/systemd"),
            system: Some(PathBuf::from("/nix/store/aaa-nixos-system")),
        };
        assert_eq!(
            init_before_repoint(&side),
            Path::new("/nix/store/aaa-nixos-system/systemd/lib/systemd/systemd")
        );
        let fhs = RootSide {
            init: PathBuf::from("/usr/lib/systemd/systemd"),
            system: None,
        };
        assert_eq!(
            init_before_repoint(&fhs),
            Path::new("/usr/lib/systemd/systemd")
        );
    }

    #[test]
    fn the_plan_s_exec_prefix_must_start_in_the_root_of_each_side() {
        use crate::test_support::write_executable;
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        let mut plan = sample();
        // Without a prefix PID 1 starts the copy itself: nothing to check.
        assert!(check_exec_prefix(&plan, root, Side::Hidden).is_ok());

        plan.exec_prefix = Some(PathBuf::from(exec_prefix::TRAMPOLINE));
        for (side, said) in [
            (
                Side::Hidden,
                "PID 1 starts the last step of the way back through /usr/bin/env, and in \
                 the hidden root /usr/bin/env does not exist",
            ),
            (
                Side::Decoy,
                "PID 1 starts what the way back leaves for the decoy's first start through \
                 /usr/bin/env, and in the decoy root /usr/bin/env does not exist",
            ),
        ] {
            let error = check_exec_prefix(&plan, root, side).unwrap_err();
            assert!(matches!(error, ReturnError::ExecPrefix(_)), "{error:?}");
            assert_eq!(error.to_string(), said);
        }
        std::fs::create_dir_all(root.join("usr/bin")).unwrap();
        write_executable(&root.join("usr/bin/env"), "", 0o644);
        assert_eq!(
            check_exec_prefix(&plan, root, Side::Decoy)
                .unwrap_err()
                .to_string(),
            "PID 1 starts what the way back leaves for the decoy's first start through \
             /usr/bin/env, and in the decoy root /usr/bin/env is not an executable file"
        );
        write_executable(&root.join("usr/bin/env"), "", 0o755);
        for side in [Side::Hidden, Side::Decoy] {
            assert!(check_exec_prefix(&plan, root, side).is_ok());
        }
    }

    /// The hidden root is where this process runs: a prefix that does not
    /// start in `/` refuses the way back before anything is made or mounted.
    #[test]
    fn a_way_back_whose_step_cannot_start_mounts_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let nextroot = dir.path().join("nextroot");
        let mut plan = sample();
        plan.exec_prefix = Some(PathBuf::from("/no-such-directory-of-this-test/env"));
        let error = mount_decoy_root(&mut plan, &nextroot, &dir.path().join("run")).unwrap_err();
        assert!(matches!(error, ReturnError::ExecPrefix(_)), "{error:?}");
        assert!(error.to_string().contains("in the hidden root"), "{error}");
        assert!(!nextroot.exists(), "nothing was made");
    }

    /// A decoy root with no directory to bind `/run` on is not prepared for
    /// the way back, and is not checked further.
    #[test]
    fn a_decoy_root_that_cannot_take_run_is_not_prepared() {
        let dir = tempfile::tempdir().unwrap();
        let nextroot = dir.path().join("nextroot");
        std::fs::create_dir(&nextroot).unwrap();
        let mut plan = sample();
        plan.exec_prefix = Some(PathBuf::from(exec_prefix::TRAMPOLINE));
        let error = complete_decoy_root(&mut plan, &nextroot, &dir.path().join("run")).unwrap_err();
        assert!(matches!(error, ReturnError::DecoyMounts(_)), "{error:?}");
        assert!(error.to_string().contains("bind of "), "{error}");
    }

    #[test]
    fn an_idle_backend_is_closed_and_one_in_use_reported() {
        use crate::test_support::write_executable;
        let dir = tempfile::tempdir().unwrap();
        let mapper = dir.path().join("mapper");
        std::fs::create_dir(&mapper).unwrap();
        let mut plan = sample();
        plan.backend = vec!["top".to_string(), "gone".to_string()];
        assert!(close_idle_backend(&plan, &mapper).is_empty());

        std::fs::write(mapper.join("top"), "").unwrap();
        for (exit, expected) in [(0, BackendClose::Closed), (1, BackendClose::InUse)] {
            let tool = dir.path().join(format!("dmsetup-{exit}"));
            write_executable(&tool, format!("#!/bin/sh\nexit {exit}\n"), 0o755);
            plan.tools.dmsetup = Some(tool);
            assert_eq!(
                close_idle_backend(&plan, &mapper),
                vec![("top".to_string(), expected)]
            );
        }
    }
}
