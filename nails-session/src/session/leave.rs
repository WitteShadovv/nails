// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Leaving the hidden root the orderly way (`nails deactivate`).
//!
//! In the hidden session: unmount the disks the session mounted itself (a USB
//! drive, a decoy partition mounted by hand), mount the decoy root at
//! `/run/nextroot` with `/run` bound in, check its init, mark the hidden backend for deferred removal, arm
//! the plan and enqueue `soft-reboot.target`. The orderly shutdown stops every
//! hidden unit (applications flush, the hidden journal reaches the upper), the
//! transition scrubs `/run` and writes the kmsg cursor, and PID 1 switches back
//! into the plain decoy root. The hidden volume is detached with the old root
//! and its mapping closes on its own, because it was marked for deferred
//! removal: nothing of the hidden session survives the switch. `--poweroff`
//! powers off instead, and needs no way back.

use super::layout::Paths;
use crate::error::{NailsError, Result};
use nails_teardown::mountinfo::{MountEntry, read_mountinfo};
use nails_teardown::whole_root::nextroot;
use nails_teardown::whole_root::plan::Plan;
use nails_teardown::whole_root::{disk_guard, ret, tools};
use rustix::mount::UnmountFlags;
use std::path::PathBuf;

/// Enqueues a systemd target: tests replace it.
pub trait TargetHost {
    /// Enqueue `target` with PID 1. An error means PID 1 is known not to
    /// have taken it.
    fn start_target(&self, target: &str) -> Result<()>;
}

/// The real host, through the plan's `systemctl`.
#[derive(Debug, Clone)]
pub struct RealTargetHost {
    systemctl: Option<std::path::PathBuf>,
}

impl RealTargetHost {
    /// The host for `plan` (its recorded `systemctl`, else the system's).
    pub fn for_plan(plan: Option<&Plan>) -> Self {
        Self {
            systemctl: tools::find(plan.and_then(|p| p.tools.systemctl.as_deref()), "systemctl"),
        }
    }
}

impl TargetHost for RealTargetHost {
    fn start_target(&self, target: &str) -> Result<()> {
        let systemctl = self
            .systemctl
            .as_deref()
            .ok_or_else(|| NailsError::InvalidState("systemctl not found".to_string()))?;
        // A call cut short (by the very stop it enqueued, typically) counts
        // as enqueued: undoing a prepared next root while PID 1 may already
        // be switching into it would leave it switching into an empty one.
        match tools::start_target(systemctl, target) {
            tools::Outcome::Done | tools::Outcome::Unknown => Ok(()),
            tools::Outcome::Refused => Err(NailsError::InvalidState(format!(
                "systemctl could not enqueue {target}"
            ))),
        }
    }
}

/// How the session ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaveTo {
    /// Soft-reboot back into the plain decoy root.
    Decoy,
    /// Power off.
    Poweroff,
}

/// What [`leave`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LeaveReport {
    /// Device-mapper names marked for deferred removal, with the result.
    pub deferred: Vec<(String, bool)>,
    /// Disks mounted during the session that were unmounted (or, busy,
    /// detached) before the way back.
    pub unmounted: Vec<PathBuf>,
}

impl LeaveReport {
    /// The hidden backend's device-mapper devices whose mark for deferred
    /// removal did not take (no `dmsetup`, or it refused), top first: they
    /// stay open after the switch, their key in RAM, until power-off.
    pub fn left_open(&self) -> Vec<String> {
        self.deferred
            .iter()
            .filter(|(_, marked)| !marked)
            .map(|(name, _)| name.clone())
            .collect()
    }
}

/// The disks mounted during the session, deepest first: every mount under
/// `paths.root` backed by a block device (`is_block`) that is not the
/// session's own (inside the hidden volume, the decoy root at
/// `/run/nextroot`, or a policy target such as the read-only ESP).
pub fn session_disk_mounts(
    paths: &Paths,
    plan: &Plan,
    mounts: &[MountEntry],
    is_block: &dyn Fn(&MountEntry) -> bool,
) -> Vec<PathBuf> {
    let nextroot = paths.nextroot();
    let policy: Vec<PathBuf> = plan
        .policy_mounts
        .iter()
        .map(|m| paths.decoy(&m.target))
        .collect();
    let mut found: Vec<PathBuf> = mounts
        .iter()
        .filter(|m| {
            m.mount_point.starts_with(&paths.root)
                && m.mount_point != paths.root
                && !m.mount_point.starts_with(&plan.hidden_root)
                && !m.mount_point.starts_with(&nextroot)
                && !policy.contains(&m.mount_point)
                && is_block(m)
        })
        .map(|m| m.mount_point.clone())
        .collect();
    found.sort_by_key(|p| std::cmp::Reverse(p.components().count()));
    found.dedup();
    found
}

/// Unmount the disks mounted during the session before the way back,
/// so a filesystem the decoy mounts again is not still held, read-only, by the
/// hidden session. A busy mount is detached instead; the soft-reboot ends its
/// users.
fn unmount_session_disks(paths: &Paths, plan: &Plan) -> Vec<PathBuf> {
    let mounts = read_mountinfo().unwrap_or_default();
    let is_block = |m: &MountEntry| disk_guard::mount_device(m).is_some();
    session_disk_mounts(paths, plan, &mounts, &is_block)
        .into_iter()
        .filter(|target| {
            rustix::mount::unmount(target, UnmountFlags::empty()).is_ok()
                || rustix::mount::unmount(target, UnmountFlags::DETACH).is_ok()
        })
        .collect()
}

/// Whether the last step of the way back will find `tool`, such as `ip`
/// (iproute2), which it runs to delete the links the session made and set
/// each device's recorded MAC address back. The step runs in the hidden root
/// once every hidden unit has stopped, and on NixOS only after it repointed
/// `/run/current-system` to the decoy's system: it looks in the system
/// directories as they resolve then ([`tools::find_for_system`]). It cannot
/// report anything itself, so the hidden session checks before the switch.
pub fn way_back_finds(plan: &Plan, tool: &str) -> bool {
    tools::find_for_system(plan.decoy.system.as_deref(), tool).is_some()
}

/// Prepare the way back and enqueue the soft-reboot (or power off).
pub fn leave(
    paths: &Paths,
    plan: &mut Plan,
    to: LeaveTo,
    host: &dyn TargetHost,
) -> Result<LeaveReport> {
    if to == LeaveTo::Poweroff {
        host.start_target("poweroff.target")?;
        return Ok(LeaveReport::default());
    }
    let unmounted = unmount_session_disks(paths, plan);
    let nextroot = paths.nextroot();
    ret::mount_decoy_root(plan, &nextroot, &paths.run)
        .map_err(|e| NailsError::InvalidState(e.to_string()))?;
    let deferred = ret::close_backend_deferred(plan);
    let armed = ret::arm_leave(plan, &paths.plan())
        .map_err(|e| NailsError::InvalidState(e.to_string()))
        .and_then(|()| host.start_target("soft-reboot.target"));
    if let Err(e) = armed {
        nextroot::detach_tree(&nextroot);
        plan.armed = None;
        let _ = plan.write_atomic(&paths.plan());
        return Err(e);
    }
    Ok(LeaveReport {
        deferred,
        unmounted,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nails_teardown::mountinfo::parse_mountinfo;
    use nails_teardown::whole_root::plan::{PolicyMount, PolicyMountKind};

    fn plan() -> Plan {
        let text = r#"{"version":2,"hidden_root":"/mnt/data","upper":"/mnt/data/root/upper",
            "work":"/mnt/data/root/work","decoy_root":{"source":"/dev/vda2","fstype":"ext4"},
            "decoy":{"init":"/sbin/init"},"hidden":{"init":"/sbin/init"}}"#;
        let mut plan = Plan::from_json(text).unwrap();
        plan.policy_mounts = vec![PolicyMount {
            target: PathBuf::from("/boot"),
            kind: PolicyMountKind::ReadOnlyBind,
        }];
        plan
    }

    #[test]
    fn only_the_disks_the_session_mounted_itself_are_unmounted_deepest_first() {
        let mounts = parse_mountinfo(
            "1 0 0:30 / / rw - overlay overlay rw\n\
             2 1 253:0 / /mnt/data rw - ext4 /dev/mapper/data rw\n\
             3 2 8:3 / /mnt/data/root/decoy/home rw - ext4 /dev/vda3 rw\n\
             4 1 8:1 / /boot ro - vfat /dev/vda1 ro\n\
             5 1 8:2 / /run/nextroot rw - ext4 /dev/vda2 rw\n\
             6 1 8:33 / /mnt/usb rw - vfat /dev/sdc1 rw\n\
             7 6 8:34 / /mnt/usb/inner ro - ext4 /dev/sdc2 ro\n\
             8 1 0:40 / /tmp rw - tmpfs tmpfs rw\n",
        );
        let is_block = |m: &MountEntry| m.source.starts_with("/dev/");
        assert_eq!(
            session_disk_mounts(&Paths::system(), &plan(), &mounts, &is_block),
            vec![PathBuf::from("/mnt/usb/inner"), PathBuf::from("/mnt/usb")]
        );
    }

    #[test]
    fn a_test_tree_only_sees_its_own_mounts() {
        let paths = Paths {
            root: PathBuf::from("/scratch/decoy"),
            run: PathBuf::from("/scratch/run"),
        };
        let mounts = parse_mountinfo(
            "1 0 8:2 / / rw - ext4 /dev/vda2 rw\n\
             2 1 8:3 / /home rw - ext4 /dev/vda3 rw\n\
             3 1 8:33 / /scratch/decoy/mnt rw - vfat /dev/sdc1 rw\n",
        );
        let is_block = |m: &MountEntry| m.source.starts_with("/dev/");
        assert_eq!(
            session_disk_mounts(&paths, &plan(), &mounts, &is_block),
            vec![PathBuf::from("/scratch/decoy/mnt")]
        );
    }

    #[test]
    fn a_device_whose_mark_did_not_take_is_left_open() {
        let report = LeaveReport {
            deferred: vec![
                ("hidden-crypt".to_string(), false),
                ("hidden-loop".to_string(), true),
                ("hidden-base".to_string(), false),
            ],
            unmounted: Vec::new(),
        };
        assert_eq!(report.left_open(), ["hidden-crypt", "hidden-base"]);
        assert!(LeaveReport::default().left_open().is_empty());
    }

    /// On NixOS the step looks in the decoy's system it repoints to, never in
    /// the hidden system the link names during the session.
    #[test]
    fn the_way_back_looks_for_a_tool_in_the_decoy_system_it_returns_to() {
        let dir = tempfile::tempdir().unwrap();
        let decoy = dir.path().join("decoy-system");
        let hidden = dir.path().join("hidden-system");
        for system in [&decoy, &hidden] {
            std::fs::create_dir_all(system.join("sw/bin")).unwrap();
        }
        let mut plan = plan();
        plan.decoy.system = Some(decoy.clone());
        plan.hidden.system = Some(hidden.clone());
        // A name no system directory of the host holds.
        let tool = "way-back-test-tool";
        std::fs::write(hidden.join("sw/bin").join(tool), "").unwrap();
        assert!(!way_back_finds(&plan, tool));
        std::fs::write(decoy.join("sw/bin").join(tool), "").unwrap();
        assert!(way_back_finds(&plan, tool));
    }
}
