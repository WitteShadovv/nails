// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Preparing the way back to the plain decoy root (ADR 0008, section 5).
//!
//! Shared by `deactivate` and `emergency`, both running in the hidden session:
//!
//! 1. mount the decoy root device at `/run/nextroot`. It is the same superblock
//!    as the overlay's lower, so the mount writes nothing;
//! 2. bind `/run` there (PID 1's init check on NixOS resolves
//!    `/run/current-system` inside the new root) and make the tree private;
//! 3. check the decoy init resolves in it;
//! 4. mark the hidden backend's device-mapper stack for deferred removal, so its
//!    key leaves the kernel the moment the switch releases the hidden volume;
//! 5. arm the plan for the way back.
//!
//! The caller then enqueues the soft-reboot. The transition step
//! ([`crate::whole_root::transition`]) does the rest.

use crate::mountinfo::{MountEntry, parse_overlay_opts, read_mountinfo, top_mount_at};
use crate::whole_root::nextroot;
use crate::whole_root::plan::{Arm, Direction, Plan, RootSide};
use crate::whole_root::tools;
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
    /// The decoy root failed the init check.
    Precheck(String),
    /// The plan could not be armed.
    Arm(String),
}

impl std::fmt::Display for ReturnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReturnError::Mount(e) => write!(f, "could not mount the decoy root: {e}"),
            ReturnError::Precheck(e) => write!(f, "the decoy root is not bootable: {e}"),
            ReturnError::Arm(e) => write!(f, "could not arm the way back: {e}"),
        }
    }
}

impl std::error::Error for ReturnError {}

/// Mount the decoy root at `nextroot` with `run` bound into it, and check it.
/// On failure nothing is left mounted there.
pub fn mount_decoy_root(plan: &Plan, nextroot: &Path, run: &Path) -> Result<(), ReturnError> {
    if read_mountinfo().is_ok_and(|e| nextroot::is_mount_point(&e, nextroot)) {
        nextroot::detach_tree(nextroot);
    }
    let result = (|| {
        std::fs::create_dir_all(nextroot).map_err(|e| ReturnError::Mount(e.to_string()))?;
        nextroot::mount_device(
            &plan.decoy_root.source,
            &plan.decoy_root.fstype,
            plan.decoy_root.data.as_deref(),
            nextroot,
        )
        .map_err(|e| ReturnError::Mount(format!("{}: {e}", plan.decoy_root.source.display())))?;
        nextroot::bind(
            run,
            &nextroot.join(run.strip_prefix("/").unwrap_or(run)),
            false,
        )
        .map_err(|e| ReturnError::Mount(format!("bind of {}: {e}", run.display())))?;
        nextroot::make_rprivate(nextroot).map_err(|e| ReturnError::Mount(e.to_string()))?;
        nextroot::precheck(nextroot, &init_before_repoint(&plan.decoy))
            .map_err(|e| ReturnError::Precheck(e.to_string()))
    })();
    if result.is_err() {
        nextroot::detach_tree(nextroot);
    }
    result
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
}
