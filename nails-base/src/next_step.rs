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
    /// `discard <path>`: delete the hidden session's copy of a path, so the
    /// decoy's own shows through again.
    Discard,
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
        NextStep::Discard,
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
            NextStep::Discard => "discard <path>",
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

/// Render `step` as [`sudo_line`] does, with `argument` in place of its
/// `<…>` placeholder: `discard <path>` with `/system-update` reads
/// `sudo /mnt/data/nails discard /system-update`.
pub fn sudo_line_for(step: NextStep, argument: &str) -> String {
    sudo_line_for_with(&running_binary(), step, argument)
}

/// [`sudo_line_for`] for an explicit binary path. A step without a
/// placeholder gets `argument` appended.
pub fn sudo_line_for_with(binary: &Path, step: NextStep, argument: &str) -> String {
    let line = sudo_line_with(binary, step);
    match line.rfind(" <") {
        Some(at) if line.ends_with('>') => format!("{} {argument}", &line[..at]),
        _ => format!("{line} {argument}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every next step renders the real binary path, never a bare `nails …`.
    #[test]
    fn every_next_step_renders_the_real_path_not_a_bare_nails() {
        let binary = Path::new("/mnt/data/nails");
        for &step in NextStep::ALL {
            let line = sudo_line_with(binary, step);
            assert!(
                line.starts_with("sudo /mnt/data/nails "),
                "names the real path: {line}"
            );
            assert!(!line.contains("`nails"), "no backtick-nails: {line}");
            assert!(
                !line.split_whitespace().any(|word| word == "nails"),
                "no bare `nails` word: {line}"
            );
        }
    }

    /// Each step names its exact subcommand words. These are a CLI contract: the
    /// operator copies the rendered line and types these words, so a stubbed
    /// empty or placeholder return must not pass.
    #[test]
    fn command_words_are_the_exact_cli_subcommands() {
        assert_eq!(NextStep::Recover.command(), "recover");
        assert_eq!(NextStep::Verify.command(), "verify");
        assert_eq!(
            NextStep::VerifyOffline.command(),
            "verify --offline --root <mount>"
        );
        assert_eq!(NextStep::Deactivate.command(), "deactivate");
        assert_eq!(NextStep::Emergency.command(), "emergency");
        assert_eq!(NextStep::Init.command(), "init <root>");
        assert_eq!(NextStep::RehearsePlant.command(), "rehearse plant");
        assert_eq!(NextStep::RehearseScan.command(), "rehearse scan");
        assert_eq!(NextStep::RehearseReset.command(), "rehearse reset");
        assert_eq!(NextStep::Discard.command(), "discard <path>");
    }

    /// A step that takes an argument renders with the argument in place of
    /// its placeholder, so the line can be pasted as it is.
    #[test]
    fn an_argument_takes_the_place_of_the_placeholder() {
        let binary = Path::new("/mnt/data/nails");
        assert_eq!(
            sudo_line_for_with(binary, NextStep::Discard, "/system-update"),
            "sudo /mnt/data/nails discard /system-update"
        );
        assert_eq!(
            sudo_line_for_with(binary, NextStep::VerifyOffline, "/mnt/image"),
            "sudo /mnt/data/nails verify --offline --root /mnt/image"
        );
        // A step without a placeholder takes the argument after its words,
        // also when the binary's own path holds something like one.
        assert_eq!(
            sudo_line_for_with(binary, NextStep::Verify, "--deep"),
            "sudo /mnt/data/nails verify --deep"
        );
        assert_eq!(
            sudo_line_for_with(Path::new("/mnt/a <b>/nails"), NextStep::Verify, "--deep"),
            "sudo /mnt/a <b>/nails verify --deep"
        );
        // The running binary, as `sudo_line` names it.
        assert_eq!(
            sudo_line_for(NextStep::Discard, "/etc/system-update"),
            sudo_line_for_with(&running_binary(), NextStep::Discard, "/etc/system-update")
        );
    }

    /// The hint resolves to the process's own executable, a real non-empty path,
    /// never an empty default. Under test `current_exe` resolves to the test
    /// binary, so the two agree.
    #[test]
    fn running_binary_resolves_to_the_running_executable() {
        let resolved = running_binary();
        assert!(
            !resolved.as_os_str().is_empty(),
            "running binary path is non-empty: {}",
            resolved.display()
        );
        assert_eq!(
            resolved,
            std::env::current_exe().expect("current_exe resolves under test"),
            "names the process's own executable"
        );
    }

    /// The public renderer prefixes `sudo`, ends with the step's command, and is
    /// exactly `sudo_line_with` applied to the running binary; an empty or
    /// placeholder stub fails all three checks.
    #[test]
    fn sudo_line_renders_sudo_running_binary_and_command() {
        let line = sudo_line(NextStep::Recover);
        assert!(line.starts_with("sudo "), "prefixed with sudo: {line}");
        assert!(line.ends_with(" recover"), "ends with the command: {line}");
        assert_eq!(
            line,
            sudo_line_with(&running_binary(), NextStep::Recover),
            "delegates to sudo_line_with with the running binary"
        );
    }
}
