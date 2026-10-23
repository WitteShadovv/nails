// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the next steps: the command words, the running binary they
//! name and the sudo line.

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
