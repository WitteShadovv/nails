// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The next command the operator should run, as typed data with one renderer.
//!
//! NAILS is not on `PATH`: the binary lives on the hidden volume (for example
//! `/mnt/data/nails`) and is run with `sudo`, so a hint that says a bare
//! `nails recover` cannot be copied and pasted. Every next step is named by a
//! [`NextStep`] value and rendered through [`sudo_line`], the one place that
//! turns it into `sudo <real path> <command>` with the running binary's own
//! path. The renderer is the single source of that line, so no hint can drift
//! back to a bare `nails …`. It lives here, below every other crate, so the
//! CLI, the facade, the session and the forensics all render a hint alike.

use std::path::Path;

/// A command the operator runs next, named so a front end can render it with
/// the real binary path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NextStep {
    /// `recover`: remove what an interrupted entry left behind.
    Recover,
    /// `verify`: scan for residue.
    Verify,
    /// `verify --offline --root <mount>`: scan a mounted decoy image.
    VerifyOffline,
    /// `deactivate`: end the hidden session.
    Deactivate,
    /// `emergency`: the way back right now.
    Emergency,
    /// `init <root>`: bootstrap the layout on the hidden volume.
    Init,
    /// `rehearse plant`: plant the canary.
    RehearsePlant,
    /// `rehearse scan`: scan the decoy for the canary.
    RehearseScan,
    /// `rehearse reset`: remove the rehearsal.
    RehearseReset,
}

impl NextStep {
    /// Every next step, for the no-bare-hint guard.
    pub const ALL: &'static [NextStep] = &[
        NextStep::Recover,
        NextStep::Verify,
        NextStep::VerifyOffline,
        NextStep::Deactivate,
        NextStep::Emergency,
        NextStep::Init,
        NextStep::RehearsePlant,
        NextStep::RehearseScan,
        NextStep::RehearseReset,
    ];

    /// The subcommand words after the binary.
    pub fn command(self) -> &'static str {
        match self {
            NextStep::Recover => "recover",
            NextStep::Verify => "verify",
            NextStep::VerifyOffline => "verify --offline --root <mount>",
            NextStep::Deactivate => "deactivate",
            NextStep::Emergency => "emergency",
            NextStep::Init => "init <root>",
            NextStep::RehearsePlant => "rehearse plant",
            NextStep::RehearseScan => "rehearse scan",
            NextStep::RehearseReset => "rehearse reset",
        }
    }
}

/// The real path of the running binary, for the hints to name. The process's own
/// executable is the hidden-volume binary when NAILS runs as documented; when it
/// cannot be resolved the hint falls back to the plain name.
fn running_binary() -> std::path::PathBuf {
    std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("nails"))
}

/// Render `step` as `sudo <real path> <command>`, naming the running binary.
pub fn sudo_line(step: NextStep) -> String {
    sudo_line_with(&running_binary(), step)
}

/// Render `step` as `sudo <binary> <command>` for an explicit binary path.
pub fn sudo_line_with(binary: &Path, step: NextStep) -> String {
    format!("sudo {} {}", binary.display(), step.command())
}

#[cfg(test)]
#[path = "next_step_tests.rs"]
mod tests;
