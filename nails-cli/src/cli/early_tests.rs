// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The strict recogniser never runs the hot path for a command line clap would
//! refuse or parse as something else.

use super::{EarlyArgs, recognise};
use crate::cli::args::{Cli, Commands};
use std::ffi::OsString;

fn argv(words: &[&str]) -> Vec<OsString> {
    std::iter::once("nails")
        .chain(words.iter().copied())
        .map(OsString::from)
        .collect()
}

/// Every command line built from these pieces, up to four of them around the
/// subcommand, so flags land before and after it in many orders.
fn corpus() -> Vec<Vec<&'static str>> {
    const PIECES: &[&[&str]] = &[
        &["emergency"],
        &["--countdown", "3"],
        &["--countdown=5"],
        &["--countdown", "x"],
        &["--poweroff"],
        &["--reboot"],
        &["--lock-backend"],
        &["--json"],
        &["-q"],
        &["--quiet"],
        &["-v"],
        &["-vv"],
        &["--verbose"],
        &["--ascii"],
        &["--no-log-file"],
        &["--config", "/tmp/n.toml"],
        &["--config=/tmp/n.toml"],
        &["-c", "/tmp/n.toml"],
        &["--color", "never"],
        &["--color=sometimes"],
        &["--help"],
        &["status"],
        &["--bogus"],
    ];
    let mut out: Vec<Vec<&str>> = vec![Vec::new()];
    for _ in 0..4 {
        let mut next = Vec::new();
        for prefix in &out {
            for piece in PIECES {
                let mut words = prefix.clone();
                words.extend_from_slice(piece);
                next.push(words);
            }
        }
        out.extend(next);
        out.dedup();
    }
    out
}

#[test]
fn whatever_the_recogniser_accepts_clap_parses_as_the_same_emergency() {
    let mut accepted = 0;
    for words in corpus() {
        let Some(early) = recognise(&argv(&words)) else {
            continue;
        };
        accepted += 1;
        let cli = Cli::try_parse_checked_from(argv(&words))
            .unwrap_or_else(|e| panic!("clap refuses {words:?} the early path accepted: {e}"));
        match cli.command {
            Commands::Emergency(args) => assert_eq!(
                args.countdown, early.countdown,
                "countdown differs for {words:?}"
            ),
            other => panic!("{words:?} parsed as {other:?}"),
        }
    }
    assert!(
        accepted > 1000,
        "the corpus exercised the recogniser: {accepted}"
    );
}

#[test]
fn the_common_emergency_command_lines_are_recognised() {
    for (words, countdown) in [
        (vec!["emergency"], None),
        (vec!["--config", "/c.toml", "emergency", "--json"], None),
        (vec!["emergency", "--countdown", "3"], Some(3)),
        (vec!["emergency", "--poweroff", "-vv"], None),
        (vec!["emergency", "--lock-backend"], None),
    ] {
        assert_eq!(
            recognise(&argv(&words)),
            Some(EarlyArgs { countdown }),
            "{words:?}"
        );
    }
}

#[test]
fn help_conflicts_and_other_commands_are_left_to_clap() {
    for words in [
        vec![],
        vec!["emergency", "--help"],
        vec!["emergency", "--poweroff", "--reboot"],
        vec!["-q", "emergency", "-v"],
        vec!["emergency", "--json", "--json"],
        vec!["--poweroff", "emergency"],
        vec!["status"],
        vec!["emergency", "emergency"],
    ] {
        assert_eq!(recognise(&argv(&words)), None, "{words:?}");
    }
}

#[test]
fn main_runs_the_early_dispatch_before_clap_the_environment_and_tracing() {
    let main = include_str!("../main.rs");
    let position = |needle: &str| {
        main.find(needle)
            .unwrap_or_else(|| panic!("main.rs no longer contains {needle}"))
    };
    let early = position("cli::early::dispatch()");
    for later in [
        "Cli::parse_checked()",
        "RuntimeEnv::from_process_env()",
        "init_subscriber(",
        "execute_command(",
    ] {
        assert!(
            early < position(later),
            "{later} runs before the early dispatch"
        );
    }
}

#[test]
fn the_early_module_reaches_for_no_cli_config_or_tracing() {
    let source = include_str!("early.rs");
    let code: String = source
        .split("#[cfg(test)]")
        .next()
        .unwrap()
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    for forbidden in ["clap", "nails_core", "tracing::", "Config"] {
        assert!(!code.contains(forbidden), "early.rs uses {forbidden}");
    }
}
