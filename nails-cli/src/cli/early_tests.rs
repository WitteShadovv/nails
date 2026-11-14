// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The strict recogniser never runs the hot path for a command line clap would
//! refuse or parse as something else.

use super::{
    CopyUnit, EarlyArgs, ReconcileArgs, UnitEnd, again_command, boot_writer, end_of, fixup_copy,
    guarded_device, is_transition, recognise, reconcile_records, session_copy, session_unit,
};
use crate::cli::args::{Cli, Commands};
use nails_teardown::test_support::FakeSelinux;
use nails_teardown::whole_root::emergency::Finish;
use nails_teardown::whole_root::program_label::{PROGRAM_LABEL, Started};
use nails_teardown::whole_root::{boot_records, boot_writer as writer};
use std::cell::RefCell;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

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
                assert_eq!(cli.global.json, early.json, "--json differs for {words:?}");
                assert_eq!(
                    cli.global.ascii, early.ascii,
                    "--ascii differs for {words:?}"
                );
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
    let plain = EarlyArgs::default();
    for (words, expected) in [
        (vec!["emergency"], plain.clone()),
        (
            vec!["--config", "/c.toml", "emergency", "--json"],
            EarlyArgs {
                json: true,
                ..plain.clone()
            },
        ),
        (
            vec!["emergency", "--countdown", "3", "--ascii"],
            EarlyArgs {
                countdown: Some(3),
                ascii: true,
                ..plain.clone()
            },
        ),
        (
            vec!["emergency", "--poweroff", "-vv"],
            EarlyArgs {
                finish: Finish::Poweroff,
                ..plain.clone()
            },
        ),
        (
            vec!["emergency", "--reboot"],
            EarlyArgs {
                finish: Finish::Reboot,
                ..plain.clone()
            },
        ),
    ] {
        assert_eq!(recognise(&argv(&words)), Some(expected), "{words:?}");
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
fn the_reconcile_step_is_recognised_exactly_as_its_unit_starts_it() {
    // The command line comes from the same function the unit text uses, so a
    // change to one cannot leave the other behind: the step would then never
    // run, and /run would stay executable.
    for (switched_at, restore_noexec) in [
        (Duration::ZERO, false),
        (Duration::from_micros(1_234_567_890), true),
    ] {
        let args = boot_records::reconcile_args(switched_at, restore_noexec);
        let words: Vec<&str> = args.iter().map(String::as_str).collect();
        assert_eq!(
            reconcile_records(&argv(&words)),
            Some(ReconcileArgs {
                switched_at,
                restore_noexec
            }),
            "{words:?}"
        );
        let cli = Cli::try_parse_checked_from(argv(&words)).unwrap();
        assert!(matches!(cli.command, Commands::ReconcileRecords { .. }));
    }
    for words in [
        vec!["reconcile-records"],
        vec!["reconcile-records", "--restore-noexec"],
        vec!["reconcile-records", "12x"],
        vec!["reconcile-records", "-1"],
        vec!["reconcile-records", "1", "--bogus"],
        vec!["reconcile-records", "1", "--restore-noexec", "x"],
        vec!["-v", "reconcile-records", "1"],
        vec!["transition", "1"],
    ] {
        assert_eq!(reconcile_records(&argv(&words)), None, "{words:?}");
    }
    assert_eq!(reconcile_records(&[]), None, "an empty command line");
}

#[test]
fn the_writer_start_is_recognised_exactly_as_its_drop_in_gives_it() {
    let switched_at = Duration::from_micros(987_654_321);
    let command = ["/usr/bin/wtmpdb".to_string(), "boot".to_string()];
    let args = writer::writer_args(switched_at, &command);
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    let line = argv(&words);
    let (clock, started) = boot_writer(&line).expect("the drop-in's command line");
    assert_eq!(clock, switched_at);
    assert_eq!(started, [OsString::from("/usr/bin/wtmpdb"), "boot".into()]);
    let cli = Cli::try_parse_checked_from(argv(&words)).unwrap();
    assert!(matches!(cli.command, Commands::BootWriter { .. }));

    for words in [
        vec!["boot-writer"],
        vec!["boot-writer", "1"],
        vec!["boot-writer", "1", "wtmpdb", "boot"],
        vec!["boot-writer", "x", "/usr/bin/wtmpdb", "boot"],
        vec!["-v", "boot-writer", "1", "/usr/bin/wtmpdb"],
        vec!["reconcile-records", "1", "/usr/bin/wtmpdb"],
    ] {
        assert_eq!(boot_writer(&argv(&words)), None, "{words:?}");
    }
    assert_eq!(boot_writer(&[]), None, "an empty command line");
}

/// The command line of each of the hidden session's own units, as its unit
/// file gives it: the copy, then the words.
fn unit_command_lines() -> Vec<Vec<OsString>> {
    let mut config = nails_core::Config::test_default();
    config.backend_watch.enabled = true;
    config.sleep_policy.mode = nails_core::config::SleepPolicyMode::Block;
    let units = nails_core::session::units::session_units(&config);
    assert_eq!(units.len(), 2, "the watcher and the sleep guard");
    units
        .iter()
        .map(|unit| {
            let line = unit
                .content
                .lines()
                .find_map(|line| line.strip_prefix("ExecStart="))
                .expect("a start command");
            line.split(' ').map(OsString::from).collect()
        })
        .collect()
}

/// The domain check of the hidden session's own units knows them by exactly
/// the command lines their unit files give, and nothing else: clap still
/// parses each, once the check lets it go on.
#[test]
fn the_session_units_are_recognised_exactly_as_their_units_start_them() {
    for line in unit_command_lines() {
        assert_eq!(line[0], session_copy().into_os_string(), "{line:?}");
        assert!(session_unit(&line), "{line:?}");
        let cli = Cli::try_parse_checked_from(line.clone()).unwrap();
        assert!(
            matches!(cli.command, Commands::Watch | Commands::SleepGuard),
            "{line:?}"
        );
    }
    for words in [
        vec![],
        vec!["watch", "-v"],
        vec!["-v", "watch"],
        vec!["sleep-guard", "x"],
        vec!["watcher"],
        vec!["transition"],
    ] {
        assert!(!session_unit(&argv(&words)), "{words:?}");
    }
}

/// A unit starts itself again from its copy with the same arguments and the
/// variable that keeps the start again from starting itself once more.
#[test]
fn the_start_again_takes_the_copy_the_same_arguments_and_the_variable() {
    use nails_teardown::whole_root::program_label::STARTED_AGAIN;
    let copy = session_copy();
    let line = argv(&["watch"]);
    let command = again_command(&copy, &line);
    assert_eq!(command.get_program(), copy.as_os_str());
    assert_eq!(command.get_args().collect::<Vec<_>>(), ["watch"]);
    assert_eq!(
        command.get_envs().collect::<Vec<_>>(),
        [(
            std::ffi::OsStr::new(STARTED_AGAIN),
            Some(std::ffi::OsStr::new("1"))
        )]
    );
    assert_eq!(
        fixup_copy(),
        std::path::Path::new(boot_records::FIXUP_DIR_PATH).join(boot_records::FIXUP_BINARY)
    );
    assert!(again_command(&copy, &[]).get_args().next().is_none());
}

/// Each unit PID 1 starts from a RAM copy is told by exactly the command line
/// its unit file or drop-in gives, and checks its domain against the copy it
/// starts from: the session's for the watcher and the sleep guard, the one
/// the way back leaves for the units of the decoy's first start.
#[test]
fn each_unit_started_from_a_copy_is_told_by_its_command_line_and_checks_its_copy() {
    for line in unit_command_lines() {
        assert_eq!(CopyUnit::of(&line), Some(CopyUnit::Session), "{line:?}");
    }
    let args = boot_records::reconcile_args(Duration::from_secs(5), true);
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    assert_eq!(
        CopyUnit::of(&argv(&words)),
        Some(CopyUnit::Reconcile(ReconcileArgs {
            switched_at: Duration::from_secs(5),
            restore_noexec: true,
        }))
    );
    let command = ["/usr/bin/wtmpdb".to_string(), "boot".to_string()];
    let args = writer::writer_args(Duration::from_secs(5), &command);
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    let line = argv(&words);
    assert_eq!(
        CopyUnit::of(&line),
        Some(CopyUnit::Writer(
            Duration::from_secs(5),
            &[OsString::from("/usr/bin/wtmpdb"), "boot".into()]
        ))
    );
    for words in [
        vec![],
        vec!["emergency"],
        vec!["transition"],
        vec!["guard-device", "/dev/sdb1"],
        vec!["watch", "-v"],
        vec!["status"],
    ] {
        assert_eq!(CopyUnit::of(&argv(&words)), None, "{words:?}");
    }

    assert_eq!(CopyUnit::Session.copy(), session_copy());
    assert_eq!(
        session_copy(),
        Path::new("/run/overlay-runtime").join(nails_teardown::whole_root::plan::BINARY_NAME)
    );
    let reconcile = CopyUnit::Reconcile(ReconcileArgs {
        switched_at: Duration::ZERO,
        restore_noexec: false,
    });
    for unit in [reconcile, CopyUnit::Writer(Duration::ZERO, &[])] {
        assert_eq!(unit.copy(), fixup_copy(), "{unit:?}");
    }
    assert_ne!(session_copy(), fixup_copy());
}

const INIT: &str = "system_u:system_r:init_t:s0";

thread_local! {
    /// The copies the units of this test thread started themselves again
    /// from.
    static STARTED_AGAIN_FROM: RefCell<Vec<PathBuf>> = const { RefCell::new(Vec::new()) };
}

/// A start again that fails, once it noted the copy it was to start from.
fn refused_start_again(copy: &Path) -> std::io::Error {
    STARTED_AGAIN_FROM.with(|from| from.borrow_mut().push(copy.to_path_buf()));
    std::io::Error::from(std::io::ErrorKind::PermissionDenied)
}

/// The copies this thread's units started themselves again from so far.
fn started_again_from() -> Vec<PathBuf> {
    STARTED_AGAIN_FROM.with(|from| from.borrow().clone())
}

/// A unit PID 1 started, not again.
const BY_PID1: Started = Started {
    by_pid1: true,
    again: false,
    start_again: refused_start_again,
};

/// A copy to label, in `dir`.
fn copy_in(dir: &tempfile::TempDir) -> PathBuf {
    let copy = dir.path().join("control");
    std::fs::write(&copy, b"\x7fELF").unwrap();
    copy
}

/// Every unit started from a copy, each with the end it takes where it
/// cannot run in its domain: the watcher and the sleep guard power off, the
/// reconcile step only cleans up after itself with the `noexec` flag it was
/// given, the drop-in starts the writer as the decoy runs it.
fn units_and_their_fail_closed_ends(writer: &[OsString]) -> Vec<(CopyUnit<'_>, UnitEnd<'_>)> {
    let reconcile = |restore_noexec| {
        CopyUnit::Reconcile(ReconcileArgs {
            switched_at: Duration::from_secs(5),
            restore_noexec,
        })
    };
    vec![
        (CopyUnit::Session, UnitEnd::Emergency(Finish::Poweroff)),
        (
            reconcile(true),
            UnitEnd::CleanUp {
                restore_noexec: true,
            },
        ),
        (
            reconcile(false),
            UnitEnd::CleanUp {
                restore_noexec: false,
            },
        ),
        (
            CopyUnit::Writer(Duration::from_secs(5), writer),
            UnitEnd::AsDecoy(writer),
        ),
    ]
}

/// A unit PID 1 started in its own domain gives its copy the label again and
/// starts itself again from it; where that start fails, where its start
/// again still runs there, and where the copy does not take the label, it
/// takes its fail-closed end.
#[test]
fn a_unit_that_cannot_run_in_its_domain_takes_its_fail_closed_end() {
    let dir = tempfile::tempdir().unwrap();
    let copy = copy_in(&dir);
    let writer = [OsString::from("/usr/bin/wtmpdb"), "boot".into()];
    let in_init = || FakeSelinux {
        current: INIT.to_string(),
        ..FakeSelinux::targeted()
    };
    for (unit, end) in units_and_their_fail_closed_ends(&writer) {
        STARTED_AGAIN_FROM.with(|from| from.borrow_mut().clear());

        let selinux = in_init();
        assert_eq!(end_of(unit, &copy, &selinux, &BY_PID1), end, "{unit:?}");
        assert_eq!(
            selinux.labels_written(),
            [format!("{PROGRAM_LABEL}\0").into_bytes()],
            "{unit:?}"
        );
        assert_eq!(
            started_again_from(),
            std::slice::from_ref(&copy),
            "{unit:?}"
        );

        let selinux = in_init();
        let again = Started {
            again: true,
            ..BY_PID1
        };
        assert_eq!(end_of(unit, &copy, &selinux, &again), end, "{unit:?}");
        assert!(selinux.labels_written().is_empty(), "{unit:?}");

        let refused = FakeSelinux {
            write_error: Some(nix::libc::EOPNOTSUPP),
            ..in_init()
        };
        assert_eq!(end_of(unit, &copy, &refused, &BY_PID1), end, "{unit:?}");
        assert_eq!(
            started_again_from(),
            std::slice::from_ref(&copy),
            "neither starts itself again: {unit:?}"
        );
    }
}

/// A unit does its work where it runs in its domain and where no policy is
/// loaded, and one PID 1 did not start is asked nothing at all: none of them
/// writes a label or starts itself again.
#[test]
fn a_unit_in_its_domain_without_a_policy_or_run_by_hand_does_its_work() {
    let dir = tempfile::tempdir().unwrap();
    let copy = copy_in(&dir);
    let writer = [OsString::from("/usr/bin/wtmpdb"), "boot".into()];
    STARTED_AGAIN_FROM.with(|from| from.borrow_mut().clear());
    for (unit, _) in units_and_their_fail_closed_ends(&writer) {
        let in_domain = FakeSelinux::targeted();
        assert_eq!(
            end_of(unit, &copy, &in_domain, &BY_PID1),
            UnitEnd::Work(unit)
        );
        assert_eq!(in_domain.questions(), ["pid1", "current"], "{unit:?}");

        let without = FakeSelinux::without_policy();
        assert_eq!(end_of(unit, &copy, &without, &BY_PID1), UnitEnd::Work(unit));
        assert_eq!(without.questions(), ["pid1"], "{unit:?}");

        let in_init = FakeSelinux {
            current: INIT.to_string(),
            ..FakeSelinux::targeted()
        };
        let by_hand = Started {
            by_pid1: false,
            ..BY_PID1
        };
        assert_eq!(end_of(unit, &copy, &in_init, &by_hand), UnitEnd::Work(unit));
        assert!(in_init.questions().is_empty(), "{unit:?}");
        for selinux in [&in_domain, &without, &in_init] {
            assert!(selinux.labels_written().is_empty(), "{unit:?}");
        }
    }
    assert!(started_again_from().is_empty());
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

/// Who started a process, on a real kernel: in a PID namespace of its own the
/// test runs as PID 1.
mod kernel_tests {
    use super::super::by_pid1;
    use nails_core::test_path;
    use nails_core::test_support::Rerun;

    /// Run `body` in a child forked from this process and give its answer,
    /// `None` where the child did not end with one.
    fn in_child(body: fn() -> bool) -> Option<bool> {
        use nix::sys::wait::{WaitStatus, waitpid};
        use nix::unistd::{ForkResult, fork};

        // SAFETY: the child makes only system calls (getppid, fork, waitpid)
        // and leaves with `_exit`, never touching a lock another thread of
        // this process may hold.
        match unsafe { fork() }.expect("fork") {
            ForkResult::Child => {
                let code = i32::from(!body());
                // SAFETY: `_exit` skips the atexit handlers and is
                // async-signal-safe.
                unsafe { nix::libc::_exit(code) }
            }
            ForkResult::Parent { child } => match waitpid(child, None) {
                Ok(WaitStatus::Exited(_, code @ (0 | 1))) => Some(code == 0),
                _ => None,
            },
        }
    }

    /// PID 1 of the namespace was not started by PID 1, whose parent is
    /// outside it; a child it forks was; and that child's own child was not.
    #[test]
    fn only_a_child_of_pid_1_counts_as_started_by_pid_1() {
        let _ = Rerun::new(test_path!(only_a_child_of_pid_1_counts_as_started_by_pid_1))
            .in_pid_ns()
            .run(|| {
                assert_eq!(std::process::id(), 1);
                assert!(!by_pid1(), "the namespace's PID 1");
                assert_eq!(in_child(by_pid1), Some(true), "a child of PID 1");
                assert_eq!(
                    in_child(|| in_child(by_pid1) == Some(false)),
                    Some(true),
                    "a child of a child of PID 1"
                );
            });
    }
}
