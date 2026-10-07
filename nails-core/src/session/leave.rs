// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Leaving the hidden root the orderly way (`nails deactivate`).
//!
//! In the hidden session: mount the decoy root at `/run/nextroot` with `/run`
//! bound in, check its init, mark the hidden backend for deferred removal, arm
//! the plan and enqueue `soft-reboot.target`. The orderly shutdown stops every
//! hidden unit (applications flush, the hidden journal reaches the upper), the
//! transition scrubs `/run` and writes the kmsg cursor, and PID 1 switches back
//! into the plain decoy root. The hidden volume is detached with the old root
//! and its mapping closes on its own, because it was marked for deferred
//! removal: nothing of the hidden session survives the switch. `--poweroff`
//! powers off instead, and needs no way back.

use super::layout::Paths;
use crate::error::{NailsError, Result};
use nails_teardown::whole_root::nextroot;
use nails_teardown::whole_root::plan::Plan;
use nails_teardown::whole_root::{ret, tools};

/// Enqueues a systemd target: tests replace it.
pub trait TargetHost {
    /// Enqueue `target` with PID 1.
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
        if tools::start_target(systemctl, target) {
            Ok(())
        } else {
            Err(NailsError::InvalidState(format!(
                "systemctl could not enqueue {target}"
            )))
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
    Ok(LeaveReport { deferred })
}
