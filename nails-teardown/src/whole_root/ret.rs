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
//! 6. arm the plan for the way back.
//!
//! [`mount_decoy_root`] takes the first four steps, [`complete_decoy_root`]
//! the second to the fourth on a decoy root mounted already. The caller then
//! enqueues the soft-reboot. The transition step
//! ([`crate::whole_root::transition`]) does the rest.

use crate::mountinfo::{MountEntry, parse_overlay_opts, read_mountinfo, top_mount_at};
use crate::whole_root::plan::{Arm, Direction, Plan, RootSide};
use crate::whole_root::tools;
use crate::whole_root::{carry, decoy_mounts, nextroot};
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
            ReturnError::Arm(e) => write!(f, "could not arm the way back: {e}"),
        }
    }
}

impl std::error::Error for ReturnError {}

/// Mount the decoy root at `nextroot` with the decoy's mounts and `run` bound
/// into it, and check it ([`complete_decoy_root`]). The plan's record of the
/// decoy's mounts gets the ID each one has now, which the transition gives
/// their `utab` lines; the caller writes the plan. On failure nothing is left
/// mounted there.
pub fn mount_decoy_root(plan: &mut Plan, nextroot: &Path, run: &Path) -> Result<(), ReturnError> {
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
/// below the decoy root private; check the decoy init resolves in it. On
/// failure nothing is left mounted at `nextroot`, the decoy root included,
/// and no decoy mount keeps an ID the way back gave it.
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
            .map_err(|e| ReturnError::Precheck(e.to_string()))
    })();
    if result.is_err() {
        give_up(plan, nextroot);
    }
    result
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

/// Arm `plan` for the way back and write it to `path`.
pub fn arm_leave(plan: &mut Plan, path: &Path) -> Result<(), ReturnError> {
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
