// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What of the files a zsh that runs now read as it started may have changed
//! since: a startup file, a link on the way to it, or the directory it is in.

use super::*;
use crate::filesystem::PathKind;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// When the shell of these tests started, in seconds from the epoch.
const STARTED: u64 = 2_000_000_000;

/// The time `seconds` from the epoch.
fn at(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
}

/// What `fs` sets for an interactive zsh that started as `started` says.
fn since(fs: &MockFilesystem, started: Option<Result<SystemTime, String>>) -> Scan {
    let install = Install {
        started,
        ..Install::default()
    };
    zsh(fs, &[PathBuf::from(HOME)], NOT_LOGIN, &install)
}

/// What `fs` sets for an interactive zsh that started at [`STARTED`].
fn started(fs: &MockFilesystem) -> Scan {
    since(fs, Some(Ok(at(STARTED))))
}

/// The directories of the root, `/etc` and the home, as a disk holds them.
fn dirs(fs: &MockFilesystem) {
    for dir in ["/", "/etc", "/home", HOME] {
        fs.mock_set_path_type(dir, PathKind::Dir);
    }
}

/// What a doubt that `shown` changed after the shell started says.
fn changed(shown: &str) -> String {
    format!(
        "it cannot tell what the shell read as it started, as {shown} changed after it started \
         (a shell started now reads what is there now)"
    )
}

/// What a doubt that `shown`, a directory among them, changed after the
/// shell started says.
fn changed_directory(shown: &str) -> String {
    format!(
        "it cannot tell what the shell read as it started, as {shown} changed after it started \
         (a shell started now reads what is there now, and zsh changes the directory that holds \
         its history file as it starts unless HIST_FCNTL_LOCK is on)"
    )
}

#[test]
fn a_startup_file_that_changed_after_the_shell_started_is_a_doubt() {
    // zsh 5.9 to 5.9.2 keep SHARE_HISTORY on after it is taken out of
    // ~/.zshrc while they run, and a ~/.zshrc that copies another over
    // itself as it runs leaves the one it read behind.
    let fs = MockFilesystem::new();
    dirs(&fs);
    seed(&fs, "/home/alice/.zshrc", "HISTFILE=~/.zsh_history\n");
    assert_eq!(started(&fs), Scan::default());
    // Changed in the second before the one it started in, or later.
    for changed_at in [STARTED - 1, STARTED, STARTED + 60] {
        fs.mock_set_change_time("/home/alice/.zshrc", at(changed_at));
        assert_eq!(
            started(&fs).doubts,
            [changed("/home/alice/.zshrc")],
            "{changed_at}"
        );
    }
    // Earlier than that, or for a shell that may not run yet, it is none.
    fs.mock_set_change_time("/home/alice/.zshrc", at(STARTED - 2));
    assert_eq!(started(&fs), Scan::default());
    fs.mock_set_change_time("/home/alice/.zshrc", at(STARTED + 60));
    assert_eq!(since(&fs, None), Scan::default());
    // A file a startup file sources, and one a function is read from.
    for (rc, file) in [
        (
            "source ~/.zsh/history.zsh\n",
            "/home/alice/.zsh/history.zsh",
        ),
        (
            "fpath=(~/.zfunc $fpath)\nautoload -Uz hist && hist\n",
            "/home/alice/.zfunc/hist",
        ),
    ] {
        let fs = MockFilesystem::new();
        dirs(&fs);
        seed(&fs, "/home/alice/.zshrc", rc);
        seed(&fs, file, "true\n");
        assert_eq!(started(&fs), Scan::default(), "{rc}");
        fs.mock_set_change_time(file, at(STARTED + 1));
        assert_eq!(started(&fs).doubts, [changed(file)], "{rc}");
    }
}

#[test]
fn a_file_removed_after_the_shell_started_shows_in_its_directory() {
    // zsh 5.9.2 keeps SHARE_HISTORY on after the file that turned it on is
    // removed, its directory removed, or its compiled form is.
    let fs = MockFilesystem::new();
    dirs(&fs);
    assert_eq!(started(&fs), Scan::default());
    fs.mock_set_change_time(HOME, at(STARTED + 5));
    assert_eq!(started(&fs).doubts, [changed_directory("/home/alice")]);
    // A file sourced from a directory that is no longer there: the deepest
    // one on the way that is.
    let fs = MockFilesystem::new();
    dirs(&fs);
    seed(&fs, "/home/alice/.zshrc", ". ~/.d/x\n");
    fs.mock_set_change_time("/home/alice/.zshrc", at(STARTED - 10));
    assert_eq!(started(&fs), Scan::default());
    fs.mock_set_change_time(HOME, at(STARTED + 5));
    assert_eq!(started(&fs).doubts, [changed_directory("/home/alice")]);
    // The directory of a file there, which holds its compiled form.
    let fs = MockFilesystem::new();
    dirs(&fs);
    fs.mock_set_path_type("/etc/zsh", PathKind::Dir);
    seed(&fs, "/etc/zsh/zshrc", "true\n");
    fs.mock_set_change_time("/etc/zsh", at(STARTED + 5));
    assert_eq!(started(&fs).doubts, [changed_directory("/etc/zsh")]);
}

#[test]
fn a_directory_above_what_the_shell_read_counts_too() {
    // zsh 5.9 to 5.9.2 keep SHARE_HISTORY on after `mv ~/.zsh/plugins
    // ~/.zsh/plugins.old; mv ~/.zsh/plugins.new ~/.zsh/plugins` takes the
    // file that turned it on away: the directories renamed and the one that
    // holds them change, what is in them keeps its change times.
    for dir in ["/home/alice/.zsh/plugins", "/home/alice/.zsh", "/home", "/"] {
        let fs = MockFilesystem::new();
        dirs(&fs);
        for path in ["/home/alice/.zsh", "/home/alice/.zsh/plugins"] {
            fs.mock_set_path_type(path, PathKind::Dir);
        }
        fs.mock_set_path_type("/home/alice/.zsh/plugins/hist", PathKind::Dir);
        seed(
            &fs,
            "/home/alice/.zshrc",
            "source ~/.zsh/plugins/hist/hist.zsh\n",
        );
        seed(&fs, "/home/alice/.zsh/plugins/hist/hist.zsh", "true\n");
        assert_eq!(started(&fs), Scan::default(), "{dir}");
        fs.mock_set_change_time(dir, at(STARTED + 5));
        assert_eq!(started(&fs).doubts, [changed_directory(dir)], "{dir}");
    }
}

#[test]
fn only_what_changed_is_fixed_by_a_zsh_started_after_it() {
    use super::super::restart_fix;
    let fix = |doubts: &[&str]| {
        restart_fix(
            &doubts
                .iter()
                .map(|doubt| (*doubt).to_string())
                .collect::<Vec<_>>(),
        )
    };
    let file = changed("/home/alice/.zshrc");
    let directory = changed_directory("/home/alice");
    let restart = "Type the decoy commands in a zsh you start after the change, the way you \
                   started this one: it reads the startup files as they are then.";
    assert_eq!(fix(&[&file]), Some(restart));
    // Where a directory changed, the history file's lock may have changed it.
    let lock = fix(&[&file, &directory]).expect("a fix");
    assert!(lock.starts_with(restart), "{lock}");
    assert!(lock.contains("turn HIST_FCNTL_LOCK on"), "{lock}");
    // What the check cannot read, a new zsh cannot fix: the start, a change
    // time or a link, beside such a doubt or alone; nor another doubt.
    for other in [
        "it cannot tell what the shell read as it started, as it cannot tell when it started \
         (/proc/stat gives no boot time)",
        "it cannot tell what the shell read as it started, as when /etc changed cannot be read \
         (permission denied)",
        "it cannot tell what the shell read as it started in /home/alice/.d/x, as /home/alice/.d \
         leads through more than 40 links",
        "it cannot follow the file /home/alice/.zshrc sources as `$f`",
    ] {
        assert_eq!(fix(&[other]), None, "{other}");
        assert_eq!(fix(&[&file, other]), None, "{other}");
    }
    assert_eq!(fix(&[]), None);
}

#[test]
fn a_link_on_the_way_that_changed_after_the_shell_started_is_a_doubt() {
    // A NixOS switch replaces /etc/zshrc and /etc/static, which lead into
    // the store, with links to the new generation's files.
    let fs = MockFilesystem::new();
    dirs(&fs);
    let generation = "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-etc/etc"; // pragma: allowlist secret
    let file = "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-zshrc"; // pragma: allowlist secret
    fs.create_symlink(Path::new(file), Path::new(&format!("{generation}/zshrc")))
        .unwrap();
    fs.create_symlink(Path::new(generation), Path::new("/etc/static"))
        .unwrap();
    fs.create_symlink(Path::new("static/zshrc"), Path::new("/etc/zshrc"))
        .unwrap();
    seed(&fs, file, "true\n");
    seed(&fs, "/etc/zshrc", "true\n");
    // What is in the store changed as it came to be, never after.
    fs.mock_set_change_time(file, at(STARTED + 60));
    fs.mock_set_change_time(generation, at(STARTED + 60));
    assert_eq!(started(&fs), Scan::default());
    fs.mock_set_change_time("/etc/static", at(STARTED + 60));
    assert_eq!(started(&fs).doubts, [changed("/etc/static")]);
    fs.mock_set_change_time("/etc/zshrc", at(STARTED + 60));
    fs.mock_set_change_time("/etc", at(STARTED + 60));
    assert_eq!(
        started(&fs).doubts,
        [changed_directory("/etc, /etc/static and /etc/zshrc")]
    );
    fs.mock_set_change_time(HOME, at(STARTED + 60));
    assert_eq!(
        started(&fs).doubts,
        [changed_directory(
            "/etc, /etc/static, /etc/zshrc and 1 more"
        )]
    );
}

#[test]
fn a_nixos_switch_after_the_shell_started_is_a_doubt_whatever_etc_is_made_of() {
    // A NixOS switch replaces /run/current-system, also where /etc is a mount
    // of an image whose files keep the change times they had.
    let fs = MockFilesystem::new();
    dirs(&fs);
    seed(&fs, "/etc/NIXOS", "");
    seed(&fs, "/etc/zshrc", "true\n");
    fs.create_symlink(
        Path::new("/nix/store/0123456789abcdfghijklmnpqrsvwxyz-nixos-system"), // pragma: allowlist secret
        Path::new("/run/current-system"),
    )
    .unwrap();
    fs.mock_set_change_time("/run/current-system", at(STARTED - 60));
    assert_eq!(started(&fs), Scan::default());
    fs.mock_set_change_time("/run/current-system", at(STARTED + 60));
    assert_eq!(started(&fs).doubts, [changed("/run/current-system")]);
    // Elsewhere it is no link the check looks at.
    let fs = MockFilesystem::new();
    dirs(&fs);
    fs.mock_set_change_time("/run/current-system", at(STARTED + 60));
    assert_eq!(started(&fs), Scan::default());
}

#[test]
fn a_start_the_check_cannot_read_or_a_link_it_cannot_follow_is_a_doubt() {
    let fs = MockFilesystem::new();
    dirs(&fs);
    assert_eq!(
        since(&fs, Some(Err("/proc/stat gives no boot time".to_string()))).doubts,
        [
            "it cannot tell what the shell read as it started, as it cannot tell when it started \
          (/proc/stat gives no boot time)"
        ]
    );
    // A loop of links on the way leads nowhere.
    let fs = MockFilesystem::new();
    dirs(&fs);
    fs.create_symlink(Path::new("/home/alice/.e"), Path::new("/home/alice/.d"))
        .unwrap();
    fs.create_symlink(Path::new(".d"), Path::new("/home/alice/.e"))
        .unwrap();
    seed(&fs, "/home/alice/.zshrc", "source ~/.d/x\n");
    let doubts = started(&fs).doubts;
    assert!(
        doubts.contains(
            &"it cannot tell what the shell read as it started in /home/alice/.d/x, as \
              /home/alice/.d leads through more than 40 links"
                .to_string()
        ),
        "{doubts:?}"
    );
}

#[test]
fn a_change_counts_from_the_second_before_the_shell_started() {
    use super::super::since::changed_since;
    let started = at(STARTED) + Duration::from_millis(500);
    assert!(changed_since(at(STARTED - 1), started));
    assert!(changed_since(
        at(STARTED) + Duration::from_millis(100),
        started
    ));
    assert!(changed_since(at(STARTED + 3600), started));
    assert!(!changed_since(
        at(STARTED - 2) + Duration::from_millis(999),
        started
    ));
    assert!(!changed_since(UNIX_EPOCH, started));
}
