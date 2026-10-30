// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

use super::*;

const DECOY: &str = "\
22 1 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw
23 22 0:21 / /proc rw,nosuid shared:12 - proc proc rw
41 22 253:0 / /mnt/data rw,noatime shared:30 - ext4 /dev/mapper/cargo rw
";

const HIDDEN: &str = "\
1 0 0:40 / / rw,relatime shared:1 - overlay overlay rw,lowerdir=/run/nails/lower,upperdir=/mnt/data/root/upper,workdir=/mnt/data/root/work
23 1 0:21 / /proc rw,nosuid shared:12 - proc proc rw
41 1 253:0 / /mnt/data rw,noatime shared:30 - ext4 /dev/mapper/cargo rw
";

fn program(root: &str) -> PathBuf {
    Path::new(root).join("gui/bin/nails-gui")
}

#[test]
fn the_install_root_is_two_levels_above_the_gui_directory() {
    assert_eq!(
        install_root(&program("/mnt/data")),
        Some(PathBuf::from("/mnt/data"))
    );
    // A bundled loader in gui/lib lies under the same root.
    assert_eq!(
        install_root(Path::new("/mnt/data/gui/lib/ld-linux-x86-64.so.2")),
        Some(PathBuf::from("/mnt/data"))
    );
    for elsewhere in [
        "/usr/bin/nails-gui",
        "/nails-gui",
        "/target/debug/nails-gui",
        "nails-gui",
    ] {
        assert_eq!(install_root(Path::new(elsewhere)), None, "{elsewhere}");
    }
    assert_eq!(
        engine_of(Path::new("/mnt/data")),
        PathBuf::from("/mnt/data/nails")
    );
}

#[test]
fn a_hidden_overlay_root_of_this_volume_is_recognised() {
    assert!(root_is_hidden_overlay(HIDDEN, Path::new("/mnt/data")));
}

#[test]
fn the_decoy_another_volume_or_another_overlay_is_not_a_hidden_session() {
    assert!(!root_is_hidden_overlay(DECOY, Path::new("/mnt/data")));
    // An overlay root whose upper lies on another volume.
    assert!(!root_is_hidden_overlay(HIDDEN, Path::new("/mnt/other")));
    // A volume whose name only begins like the upper's directory.
    assert!(!root_is_hidden_overlay(HIDDEN, Path::new("/mnt/dat")));
    // The overlay is not on `/`.
    let elsewhere = HIDDEN.replacen(" / / ", " / /srv ", 1);
    assert!(!root_is_hidden_overlay(&elsewhere, Path::new("/mnt/data")));
    // The last mount on `/` is the one in view.
    let covered = format!("{HIDDEN}50 1 8:3 / / rw - ext4 /dev/sda3 rw\n");
    assert!(!root_is_hidden_overlay(&covered, Path::new("/mnt/data")));
}

#[test]
fn escapes_in_the_mount_table_are_undone() {
    let table = "1 0 0:40 / / rw - overlay overlay rw,upperdir=/mnt/my\\040drive/root/upper\n";
    assert!(root_is_hidden_overlay(table, Path::new("/mnt/my drive")));
    assert_eq!(unescape_octal("a\\040b\\134c\\011"), "a b\\c\t");
    // Not an escape: kept as it is.
    assert_eq!(unescape_octal("a\\9b\\"), "a\\9b\\");
    assert_eq!(unescape_octal("\\777"), "\\777");
}

#[test]
fn a_mount_table_of_another_shape_reads_as_no() {
    for table in [
        "",
        "garbage",
        "1 0 0:40 / / rw overlay overlay rw,upperdir=/mnt/data/u\n",
        "1 0 0:40 / / rw - overlay\n",
        "1 0 0:40 / / rw - overlay overlay rw,upperdir=relative/u\n",
        "- - - - - - - - - -\n",
    ] {
        assert!(
            !root_is_hidden_overlay(table, Path::new("/mnt/data")),
            "{table:?}"
        );
    }
}

#[test]
fn the_launchers_socket_is_used_wherever_the_window_runs() {
    let (stream, _other) = UnixStream::pair().unwrap();
    match decide(None, Some(stream), &program("/mnt/data"), None) {
        Start::Launcher { engine, .. } => {
            assert_eq!(engine, Some(PathBuf::from("/mnt/data/nails")))
        }
        other => panic!("{other:?}"),
    }
    // Outside a NAILS tree the pages name no engine.
    let (stream, _other) = UnixStream::pair().unwrap();
    assert!(matches!(
        decide(None, Some(stream), Path::new("/anywhere"), None),
        Start::Launcher { engine: None, .. }
    ));
}

#[test]
fn a_named_engine_never_takes_standard_input_for_the_launchers_socket() {
    for (mountinfo, pkexec) in [(DECOY, false), (HIDDEN, true)] {
        let (stream, _other) = UnixStream::pair().unwrap();
        let start = decide(
            Some(PathBuf::from("/mnt/data/nails")),
            Some(stream),
            &program("/mnt/data"),
            Some(mountinfo),
        );
        match start {
            Start::Pkexec { .. } => assert!(pkexec),
            Start::Refuse(_) => assert!(!pkexec),
            Start::Launcher { .. } => panic!("the socket was taken with an engine named"),
        }
    }
}

#[test]
fn the_menu_entrys_engine_gets_pkexec_only_in_a_hidden_session_of_its_volume() {
    let engine = || Some(PathBuf::from("/mnt/data/nails"));
    match decide(engine(), None, &program("/mnt/data"), Some(HIDDEN)) {
        Start::Pkexec { engine } => assert_eq!(engine, PathBuf::from("/mnt/data/nails")),
        other => panic!("{other:?}"),
    }
    // Where the window lies does not matter, the engine's volume does.
    assert!(matches!(
        decide(
            engine(),
            None,
            Path::new("/usr/bin/nails-gui"),
            Some(HIDDEN)
        ),
        Start::Pkexec { .. }
    ));
    for (engine, mountinfo) in [
        (engine(), Some(DECOY)),
        (engine(), None),
        (Some(PathBuf::from("/mnt/other/nails")), Some(HIDDEN)),
        (Some(PathBuf::from("nails")), Some(HIDDEN)),
        (Some(PathBuf::from("/")), Some(HIDDEN)),
    ] {
        match decide(engine.clone(), None, &program("/mnt/data"), mountinfo) {
            Start::Refuse(line) => assert!(
                line.starts_with("The window opens from a terminal: sudo "),
                "{line}"
            ),
            other => panic!("{engine:?}: {other:?}"),
        }
    }
}

#[test]
fn without_the_launcher_or_an_engine_the_window_opens_nothing() {
    // Not even in a hidden session: only the menu entry, which names the
    // engine, starts pkexec.
    for mountinfo in [Some(HIDDEN), Some(DECOY), None] {
        assert!(matches!(
            decide(None, None, &program("/mnt/data"), mountinfo),
            Start::Refuse(_)
        ));
    }
}

#[test]
fn the_refusal_names_the_line_that_opens_the_window() {
    let Start::Refuse(line) = decide(None, None, &program("/mnt/data"), Some(DECOY)) else {
        panic!("not refused");
    };
    assert_eq!(
        line,
        "The window opens from a terminal: sudo /mnt/data/nails gui"
    );
    let Start::Refuse(line) = decide(
        Some(PathBuf::from("/mnt/x/nails")),
        None,
        &program("/mnt/data"),
        Some(DECOY),
    ) else {
        panic!("not refused");
    };
    assert_eq!(
        line,
        "The window opens from a terminal: sudo /mnt/x/nails gui"
    );
    assert_eq!(gui_line(None), "sudo <hidden volume>/nails gui");
    assert_eq!(
        gui_line(Some(Path::new("/mnt/my drive/nails"))),
        "sudo '/mnt/my drive/nails' gui"
    );
    assert_eq!(
        sudo_line(Some(Path::new("/mnt/data/nails")), "activate"),
        "sudo /mnt/data/nails activate"
    );
    assert_eq!(shell_word("it's"), r"'it'\''s'");
}

#[test]
fn pkexecs_own_exit_codes_tell_a_dismissed_dialog_from_a_missing_agent() {
    use std::os::unix::process::ExitStatusExt;
    let status = |code: i32| ExitStatus::from_raw(code << 8);
    assert_eq!(pkexec_end(status(126)), PkexecEnd::Dismissed);
    assert_eq!(pkexec_end(status(127)), PkexecEnd::NotAuthorized);
    assert_eq!(pkexec_end(status(1)), PkexecEnd::Other(Some(1)));
    assert_eq!(pkexec_end(ExitStatus::from_raw(9)), PkexecEnd::Other(None));
}
