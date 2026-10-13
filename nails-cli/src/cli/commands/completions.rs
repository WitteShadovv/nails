// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Completions command handler
//!
//! Writes a shell completion script to stdout and nothing else. It never
//! touches the hidden volume or the decoy disk: the operator runs
//! `source <(nails completions bash)` inside the hidden session so the
//! completions live only in that shell's memory and leave no file behind.

use clap::CommandFactory;
use clap_complete::{Shell, generate};

use crate::cli::args::{Cli, CompletionsArgs};
use crate::cli::output::ExitStatus;

/// Generate the completion script for `args.shell` on stdout.
///
/// Takes no configuration and reads no state, so it works from any directory and
/// before the hidden volume is mounted. Always succeeds with [`ExitStatus::Ok`].
pub fn execute(args: &CompletionsArgs) -> ExitStatus {
    print_completions(args.shell, &mut std::io::stdout());
    ExitStatus::Ok
}

/// Render the completion script for `shell` into `out`.
///
/// Split out so a test can drive it against an in-memory buffer and assert the
/// script is non-empty without spawning a process or writing a file.
fn print_completions<W: std::io::Write>(shell: Shell, out: &mut W) {
    let mut command = Cli::command();
    let name = command.get_name().to_string();
    generate(shell, &mut command, name, out);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_shell_produces_a_non_empty_script() {
        for shell in [Shell::Bash, Shell::Zsh, Shell::Fish] {
            let mut buffer: Vec<u8> = Vec::new();
            print_completions(shell, &mut buffer);
            assert!(
                !buffer.is_empty(),
                "{shell} completion script should not be empty"
            );
            // The generated script always mentions the binary name it completes.
            let text = String::from_utf8(buffer).expect("completion script is UTF-8");
            assert!(text.contains("nails"), "{shell} script names the binary");
        }
    }
}
