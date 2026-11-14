// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Whether PID 1 starts NAILS's own steps through an exec prefix on this
//! host, and the refusals of a switch whose roots lack it.
//!
//! On a host that may run SELinux, as [`Labels::for_host`] judges it from the
//! host facts (never from a flag or a setting), PID 1 starts the binary copy
//! through [`TRAMPOLINE`] instead of starting the copy itself:
//! [`nails_teardown::whole_root::exec_prefix`] says why, and which units and
//! drop-ins do. The activation decides it once ([`ExecPrefix::for_host`]): the
//! hidden session's units take it into their text
//! ([`super::units::session_units`]), and the entry records it in the plan,
//! which the transition step's drop-in and the way back take it from. A step
//! that does not start at all is worse than one that runs confined, so the
//! entry refuses unless the program starts in the decoy root, where the step
//! of the entry starts, and in the next root, where the hidden session's
//! units and the step of the way back start ([`ExecPrefix::require`]).
//! `deactivate` refuses a return from a hidden root that lacks it before it
//! prepares anything ([`check_way_back`]), and the way back's own preparation
//! asks again ([`nails_teardown::whole_root::ret::check_exec_prefix`]), which
//! makes `emergency` power off instead of returning. Where SELinux does not
//! run, as on a stock Debian, Ubuntu or NixOS, the plan records no prefix and
//! every unit starts the copy as before.

use super::labels::{Labels, Reason};
use crate::error::{NailsError, Result};
use nails_base::next_step::{NextStep, sudo_line, sudo_line_for};
use nails_platform::HostProfile;
use nails_teardown::whole_root::exec_prefix::{self, TRAMPOLINE};
use nails_teardown::whole_root::plan::Plan;
use std::path::Path;

/// The name the refusals go by.
pub const CHECK: &str = "exec-prefix";

/// How PID 1 starts the binary copy on the host the activation runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecPrefix {
    /// PID 1 starts the copy itself: SELinux does not run.
    Direct,
    /// PID 1 starts the copy through [`TRAMPOLINE`]: SELinux runs or may run,
    /// for the reason given.
    Trampoline(Reason),
}

/// A root PID 1 starts NAILS's steps in, as the entry checks it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Root {
    /// The decoy root, where the step of the entry starts.
    Decoy,
    /// The next root, the hidden root to be, where the hidden session's own
    /// units and the step of the way back start.
    Next,
}

impl ExecPrefix {
    /// How PID 1 starts the copy on the host `profile` describes (`None`
    /// where the detection failed): through [`TRAMPOLINE`] where
    /// [`Labels::for_host`] requires the SELinux labels, for its reason, and
    /// directly elsewhere.
    pub fn for_host(profile: Option<&HostProfile>) -> Self {
        match Labels::for_host(profile) {
            Labels::Required(reason) => Self::Trampoline(reason),
            Labels::BestEffort => Self::Direct,
        }
    }

    /// The program PID 1 starts the copy through, `None` where it starts the
    /// copy itself.
    pub fn program(self) -> Option<&'static Path> {
        match self {
            Self::Direct => None,
            Self::Trampoline(_) => Some(Path::new(TRAMPOLINE)),
        }
    }

    /// Refuse the entry unless the program starts in `root`, the `which` root
    /// of the switch ([`exec_prefix::check`]): a step that PID 1 could not
    /// start there would let the switch go on without it. Where PID 1 starts
    /// the copy itself there is nothing to check. The refusal says why the
    /// host needs the program and what to do.
    pub fn require(self, root: &Path, which: Root) -> Result<()> {
        let Self::Trampoline(reason) = self else {
            return Ok(());
        };
        let program = Path::new(TRAMPOLINE);
        exec_prefix::check(root, program).map_err(|unusable| {
            let shown = program.display();
            let (place, lost, fix) = match which {
                Root::Decoy => (
                    "the decoy root",
                    "the last step before the switch into the hidden session, which keeps the \
                     hidden session's systemd off the decoy's disks, would not start",
                    format!(
                        "Install {shown} on the decoy (coreutils provides it on most \
                         distributions) and activate again"
                    ),
                ),
                Root::Next => (
                    "the hidden root",
                    "the hidden session's own units and the last step of the way back would not \
                     start",
                    format!(
                        "Run `{}`, which deletes the hidden sessions' copy of it so that the \
                         decoy's shows through, and activate again",
                        sudo_line_for(NextStep::Discard, &program.to_string_lossy())
                    ),
                ),
            };
            refusal(
                format!(
                    "{reason}, so PID 1 starts NAILS's own steps through {shown}, and in {place} \
                     {shown} {unusable}: {lost}"
                ),
                fix,
            )
        })
    }
}

/// Refuse a return to the decoy whose last step would not start in the hidden
/// root at `root` (`/`, but in tests): `plan` records an exec prefix that does
/// not start there ([`exec_prefix::check`]), as when a hidden session removed
/// `/usr/bin/env`. The switch would go on without its last step, and the decoy
/// would start with the hidden session's files in `/run`. Asked before
/// anything is prepared, as the runtime guards are
/// ([`super::guards::check_way_back`]); a power-off needs no such step and asks
/// nothing.
pub fn check_way_back(root: &Path, plan: &Plan) -> Result<()> {
    let Some(program) = plan.exec_prefix.as_deref() else {
        return Ok(());
    };
    exec_prefix::check(root, program).map_err(|unusable| {
        let shown = program.display();
        refusal(
            format!(
                "PID 1 starts the last step of the way back through {shown}, and in the hidden \
                 root {shown} {unusable}: the switch to the decoy could go on without that step, \
                 and the decoy would start with the hidden session's files in /run"
            ),
            format!(
                "Install {shown} again in the hidden session (coreutils provides it on most \
                 distributions) and deactivate again, or end the session with `{}`, which \
                 powers off, as `{}` does here",
                sudo_line(NextStep::DeactivatePoweroff),
                sudo_line(NextStep::Emergency)
            ),
        )
    })
}

/// The refusal of a switch, under [`CHECK`].
fn refusal(reason: String, fix: String) -> NailsError {
    NailsError::PreFlightCheckFailed(vec![(CHECK.to_string(), reason, Some(fix))])
}

#[cfg(test)]
#[path = "exec_prefix_tests.rs"]
mod tests;
