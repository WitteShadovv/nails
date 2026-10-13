// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The strict recogniser never runs the hot path for a command line clap would
//! refuse or parse as something else.

use super::{EarlyArgs, guarded_device, is_transition, recognise};
use crate::cli::args::{Cli, Commands};
use nails_teardown::whole_root::emergency::Finish;
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
        &["transition"],
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
            Commands::Emergency(args) => {
                assert_eq!(
                    args.countdown, early.countdown,
                    "countdown differs for {words:?}"
                );
                let finish = if args.poweroff {
                    Finish::Poweroff
                } else if args.reboot {
                    Finish::Reboot
                } else {
                    Finish::Return
                };
                assert_eq!(finish, early.finish, "finish differs for {words:?}");
            }
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
    for (words, countdown, finish) in [
        (vec!["emergency"], None, Finish::Return),
        (
            vec!["--config", "/c.toml", "emergency", "--json"],
            None,
            Finish::Return,
        ),
        (
            vec!["emergency", "--countdown", "3"],
            Some(3),
            Finish::Return,
        ),
        (
            vec!["emergency", "--poweroff", "-vv"],
            None,
            Finish::Poweroff,
        ),
        (vec!["emergency", "--reboot"], None, Finish::Reboot),
    ] {
        assert_eq!(
            recognise(&argv(&words)),
            Some(EarlyArgs { countdown, finish }),
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
        vec!["emergency", "--lock-backend"],
        vec!["transition"],
    ] {
        assert_eq!(recognise(&argv(&words)), None, "{words:?}");
    }
}

#[test]
fn only_the_bare_transition_word_is_the_transition_step() {
    assert!(is_transition(&argv(&["transition"])));
    for words in [
        vec![],
        vec!["transition", "-v"],
        vec!["--json", "transition"],
        vec!["emergency"],
    ] {
        assert!(!is_transition(&argv(&words)), "{words:?}");
    }
}

#[test]
fn only_a_device_node_after_the_bare_guard_word_is_the_device_guard() {
    assert_eq!(
        guarded_device(&argv(&["guard-device", "/dev/sdb1"])),
        Some(std::path::Path::new("/dev/sdb1"))
    );
    for words in [
        vec!["guard-device"],
        vec!["guard-device", "sdb1"],
        vec!["guard-device", "/dev/sdb1", "-v"],
        vec!["-v", "guard-device", "/dev/sdb1"],
        vec!["transition", "/dev/sdb1"],
    ] {
        assert_eq!(guarded_device(&argv(&words)), None, "{words:?}");
    }
    let cli = Cli::try_parse_checked_from(argv(&["guard-device", "/dev/sdb1"])).unwrap();
    assert!(matches!(cli.command, Commands::GuardDevice { .. }));
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
    for forbidden in [
        "clap",
        "nails_core",
        "tracing::",
        "Config",
        "println",
        "eprintln",
    ] {
        assert!(!code.contains(forbidden), "early.rs uses {forbidden}");
    }
}
