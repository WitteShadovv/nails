// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use std::ffi::OsString;
use std::path::Path;

use super::gate::{ADMITTED_DESKTOPS, DecoyFacts, decide_on_decoy};
use super::runtime_dir::{DirFacts, judge};
use super::*;
use crate::cli::{Cli, Commands};

const ENGINE: &str = "/mnt/nails";

fn decoy(persistence: &[&str], desktop: Option<&str>) -> DecoyFacts {
    DecoyFacts {
        persistence: persistence.iter().map(ToString::to_string).collect(),
        desktop: desktop.map(str::to_string),
    }
}

fn refusal(facts: &DecoyFacts, admitted: &[&str]) -> Refusal {
    decide_on_decoy(facts, admitted, Path::new(ENGINE)).expect_err("refused")
}

#[test]
fn the_launcher_is_a_hidden_root_command_without_arguments() {
    let cli = Cli::try_parse_checked_from(["nails", "gui"]).unwrap();
    assert!(matches!(cli.command, Commands::Gui));
    assert!(crate::cli::main_guard::requires_root(&cli.command));
    assert!(
        !super::super::command_is_mutating(&cli.command),
        "the launcher itself changes nothing"
    );
    assert!(Cli::try_parse_checked_from(["nails", "gui", "x"]).is_err());
}

#[test]
fn no_desktop_is_admitted_on_the_decoy_before_its_trace_test() {
    assert!(ADMITTED_DESKTOPS.is_empty());
    let refused = refusal(&decoy(&[], Some("GNOME")), ADMITTED_DESKTOPS);
    assert_eq!(refused.status, ExitStatus::Unsupported);
    assert_eq!(refused.status.code(), 8);
    assert_eq!(refused.body.code, "desktop_untested");
    assert_eq!(
        refused.body.message,
        "The window has not been tested on this desktop (GNOME) yet, so it does not open \
         here. On the decoy it opens only on a desktop whose disk, journal and D-Bus trace \
         test has passed.\nUse: sudo /mnt/nails activate"
    );
}

#[test]
fn an_admitted_desktop_on_an_amnesic_decoy_opens() {
    assert!(decide_on_decoy(&decoy(&[], Some("GNOME")), &["GNOME"], Path::new(ENGINE)).is_ok());
    // XDG_CURRENT_DESKTOP is a list; one admitted name is enough, in any case.
    assert!(
        decide_on_decoy(
            &decoy(&[], Some("ubuntu:GNOME")),
            &["gnome"],
            Path::new(ENGINE)
        )
        .is_ok()
    );
    assert!(decide_on_decoy(&decoy(&[], Some("KDE")), &["GNOME"], Path::new(ENGINE)).is_err());
}

#[test]
fn a_persistent_decoy_refuses_even_an_admitted_desktop_and_names_each_record() {
    let facts = decoy(
        &["journald keeps a journal", "auditd is active"],
        Some("GNOME"),
    );
    let refused = refusal(&facts, &["GNOME"]);
    assert_eq!(refused.status, ExitStatus::PreflightRefused);
    assert_eq!(refused.body.code, "decoy_persistent");
    assert_eq!(
        refused.body.message,
        "This decoy keeps a record on its disk, so the window does not open here:\n\
         - journald keeps a journal\n\
         - auditd is active\n\
         Fix this first: sudo /mnt/nails check lists every finding.\n\
         Use: sudo /mnt/nails activate"
    );
}

#[test]
fn a_refusal_names_every_reason_and_an_unset_desktop() {
    let refused = refusal(&decoy(&["auditd is active"], None), ADMITTED_DESKTOPS);
    assert_eq!(refused.body.code, "decoy_persistent");
    assert!(
        refused
            .body
            .message
            .contains("this desktop (XDG_CURRENT_DESKTOP is not set)"),
        "{}",
        refused.body.message
    );
    assert!(refused.body.message.contains("- auditd is active"));
}

#[test]
fn a_desktop_name_is_printed_without_control_characters() {
    let refused = refusal(&decoy(&[], Some("GNOME\x1b[2J")), ADMITTED_DESKTOPS);
    assert!(
        refused.body.message.contains("(GNOME?[2J)"),
        "{}",
        refused.body.message
    );
}

#[test]
fn the_window_never_runs_as_root() {
    let root = TargetUser::for_test(0, 0, "root", "/root", "/bin/sh");
    let refused = refuse_root(root, Path::new("/mnt/my data/nails")).unwrap_err();
    assert_eq!(refused.status, ExitStatus::Config);
    assert_eq!(refused.body.code, "operator_is_root");
    assert!(
        refused
            .body
            .message
            .ends_with("Start it from your own account: sudo '/mnt/my data/nails' gui"),
        "{}",
        refused.body.message
    );
    let operator = TargetUser::for_test(1000, 100, "operator", "/home/operator", "/bin/sh");
    assert_eq!(refuse_root(operator, Path::new(ENGINE)).unwrap().uid, 1000);
}

#[test]
fn the_window_program_lies_beside_the_engine() {
    let dir = tempfile::tempdir().unwrap();
    let engine = dir.path().join("nails");
    let missing = window_program(&engine).unwrap_err();
    assert_eq!(missing.body.code, "window_missing");
    assert!(
        missing
            .body
            .message
            .contains(&dir.path().join("gui/bin/nails-gui").display().to_string()),
        "{}",
        missing.body.message
    );

    std::fs::create_dir_all(dir.path().join("gui/bin/nails-gui")).unwrap();
    let not_a_file = window_program(&engine).unwrap_err();
    assert!(not_a_file.body.message.contains("it is not a file"));

    std::fs::remove_dir(dir.path().join("gui/bin/nails-gui")).unwrap();
    std::fs::write(dir.path().join("gui/bin/nails-gui"), "").unwrap();
    assert_eq!(
        window_program(&engine).unwrap(),
        dir.path().join("gui/bin/nails-gui")
    );
}

#[test]
fn the_helper_reads_the_launchers_configuration() {
    let config = Path::new("/mnt/config/nails.toml");
    let args = helper_args(HelperOptions {
        config: Some(config),
        no_log_file: true,
    });
    assert_eq!(
        args,
        [
            "--no-log-file",
            "--config",
            "/mnt/config/nails.toml",
            "helper",
            "--stdio"
        ]
        .map(OsString::from)
    );
    let plain = helper_args(HelperOptions {
        config: None,
        no_log_file: false,
    });
    assert_eq!(plain, ["helper", "--stdio"].map(OsString::from));
}

#[test]
fn only_a_private_runtime_directory_of_the_operator_in_ram_is_used() {
    let good = DirFacts {
        is_dir: true,
        owner: 1000,
        mode: 0o700,
        in_ram: true,
    };
    assert_eq!(judge(&good, 1000), Ok(()));
    assert_eq!(
        judge(
            &DirFacts {
                is_dir: false,
                ..good
            },
            1000
        ),
        Err("it is not a directory".to_string())
    );
    assert_eq!(
        judge(&good, 1001),
        Err("it belongs to uid 1000".to_string())
    );
    assert_eq!(
        judge(
            &DirFacts {
                mode: 0o750,
                ..good
            },
            1000
        ),
        Err("other accounts can reach it (mode 750)".to_string())
    );
    assert_eq!(
        judge(
            &DirFacts {
                in_ram: false,
                ..good
            },
            1000
        ),
        Err("it is not in RAM (tmpfs)".to_string())
    );
}

#[test]
fn a_missing_runtime_directory_names_the_operator_and_the_way_in() {
    let operator = TargetUser::for_test(4242, 100, "operator", "/home/operator", "/bin/sh");
    let dir = tempfile::tempdir().unwrap();
    let env = RuntimeEnv::default().with_test_hooks(nails_core::runtime_env::TestHooks {
        user_runtime_base: Some(dir.path().as_os_str().to_owned()),
        ..Default::default()
    });
    let refused = runtime_dir::find(&env, &operator).unwrap_err();
    assert_eq!(refused.status, ExitStatus::Config);
    assert_eq!(refused.body.code, "no_desktop_session");
    assert!(
        refused.body.message.starts_with(&format!(
            "No desktop session of operator to open the window in: {} cannot be used (",
            dir.path().join("4242").display()
        )),
        "{}",
        refused.body.message
    );
}

#[test]
fn the_windows_own_directory_is_fresh_private_and_the_operators() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let runtime = tempfile::tempdir().unwrap();
    let operator = TargetUser::for_test(
        nix::unistd::getuid().as_raw(),
        nix::unistd::getgid().as_raw(),
        "operator",
        "/home/operator",
        "/bin/sh",
    );
    let first = runtime_dir::make_own_dir(runtime.path(), &operator).unwrap();
    let second = runtime_dir::make_own_dir(runtime.path(), &operator).unwrap();
    assert_ne!(first, second, "each window gets a directory of its own");
    assert_eq!(first.parent(), Some(runtime.path()));
    let name = first.file_name().unwrap().to_string_lossy().into_owned();
    assert_eq!(name.len(), 16, "{name}");
    assert!(name.bytes().all(|b| b.is_ascii_hexdigit()), "{name}");
    let meta = std::fs::metadata(&first).unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o700);
    assert_eq!((meta.uid(), meta.gid()), (operator.uid, operator.gid));

    let gone = runtime_dir::make_own_dir(&runtime.path().join("missing"), &operator).unwrap_err();
    assert_eq!(gone.body.code, "launch_failed");
}
