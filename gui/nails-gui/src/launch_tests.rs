// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

use std::os::unix::fs::PermissionsExt;

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
    Path::new(root).join("gui/bin/session")
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
        "/usr/bin/session",
        "/session",
        "/target/debug/session",
        "session",
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
    assert_eq!(unescape_octal(b"a\\040b\\134c\\011"), b"a b\\c\t");
    // Not an escape: kept as it is.
    assert_eq!(unescape_octal(b"a\\9b\\"), b"a\\9b\\");
    assert_eq!(unescape_octal(b"\\777"), b"\\777");
}

/// The engine mounts each layer with the overlay syntax's own escapes before
/// a `,`, `:` or `\`, which the kernel prints octal-escaped once more: a
/// hidden root at such a path is read as the engine reads it.
#[test]
fn the_overlay_s_own_escapes_are_undone_too() {
    let table = "1 0 0:40 / / rw - overlay overlay \
                 rw,upperdir=/mnt/a\\134\\054b\\134:c\\134\\134d/root/upper\n";
    assert!(root_is_hidden_overlay(table, Path::new("/mnt/a,b:c\\d")));
    assert!(!root_is_hidden_overlay(table, Path::new("/mnt/a\\,b")));
    assert_eq!(unescape_overlay(b"a\\,b\\:c\\\\d\\"), b"a,b:c\\d\\");
}

/// A mount whose path is not valid UTF-8, anywhere in the table, failed the
/// read before, and the window refused in the hidden session: the table is
/// read byte for byte, and an upper with such a byte is matched exactly.
#[test]
fn a_mount_table_with_a_byte_that_is_not_utf8_is_read() {
    let mut table = HIDDEN.as_bytes().to_vec();
    table.extend_from_slice(b"60 1 0:50 / /run/a\xff rw - tmpfs tmpfs rw\n");
    assert!(root_is_hidden_overlay(&table, Path::new("/mnt/data")));
    let odd: &[u8] = b"1 0 0:40 / / rw - overlay overlay rw,upperdir=/mnt/d\xff/root/upper\n";
    let root = |bytes: &[u8]| PathBuf::from(std::ffi::OsStr::from_bytes(bytes));
    assert!(root_is_hidden_overlay(odd, &root(b"/mnt/d\xff")));
    assert!(!root_is_hidden_overlay(odd, &root(b"/mnt/d\xfe")));
    match decide(
        Some(PathBuf::from("/mnt/data/nails")),
        None,
        &program("/mnt/data"),
        Ok(&table),
    ) {
        Start::Pkexec { .. } => {}
        other => panic!("{other:?}"),
    }
}

/// A mount table that cannot be read refuses a named engine, and says so.
#[test]
fn a_mount_table_that_cannot_be_read_is_named_in_the_refusal() {
    let Start::Refuse(line) = decide(
        Some(PathBuf::from("/mnt/data/nails")),
        None,
        &program("/mnt/data"),
        Err("Permission denied (os error 13)".to_string()),
    ) else {
        panic!("not refused");
    };
    assert_eq!(
        line,
        "The window could not read the mount table (Permission denied (os error 13)), so it \
         cannot tell that it runs in a hidden session. It opens from a terminal: sudo \
         /mnt/data/nails gui"
    );
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
    match decide(
        None,
        Some(stream),
        &program("/mnt/data"),
        Err(String::new()),
    ) {
        Start::Launcher { engine, .. } => {
            assert_eq!(engine, Some(PathBuf::from("/mnt/data/nails")))
        }
        other => panic!("{other:?}"),
    }
    // Outside a NAILS tree the pages name no engine.
    let (stream, _other) = UnixStream::pair().unwrap();
    assert!(matches!(
        decide(
            None,
            Some(stream),
            Path::new("/anywhere"),
            Err(String::new())
        ),
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
            Ok(mountinfo.as_bytes()),
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
    match decide(engine(), None, &program("/mnt/data"), Ok(HIDDEN.as_bytes())) {
        Start::Pkexec { engine } => assert_eq!(engine, PathBuf::from("/mnt/data/nails")),
        other => panic!("{other:?}"),
    }
    // Where the window lies does not matter, the engine's volume does.
    assert!(matches!(
        decide(
            engine(),
            None,
            Path::new("/usr/bin/session"),
            Ok(HIDDEN.as_bytes())
        ),
        Start::Pkexec { .. }
    ));
    for (engine, mountinfo) in [
        (engine(), DECOY),
        (Some(PathBuf::from("/mnt/other/nails")), HIDDEN),
        (Some(PathBuf::from("nails")), HIDDEN),
        (Some(PathBuf::from("/")), HIDDEN),
    ] {
        match decide(
            engine.clone(),
            None,
            &program("/mnt/data"),
            Ok(mountinfo.as_bytes()),
        ) {
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
    for mountinfo in [
        Ok(HIDDEN.as_bytes()),
        Ok(DECOY.as_bytes()),
        Err(String::new()),
    ] {
        assert!(matches!(
            decide(None, None, &program("/mnt/data"), mountinfo),
            Start::Refuse(_)
        ));
    }
}

#[test]
fn the_refusal_names_the_line_that_opens_the_window() {
    let Start::Refuse(line) = decide(None, None, &program("/mnt/data"), Ok(DECOY.as_bytes()))
    else {
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
        Ok(DECOY.as_bytes()),
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

#[test]
fn only_a_set_user_id_program_of_roots_runs_as_root() {
    let pkexec = ProgramFacts {
        is_file: true,
        owner: 0,
        mode: 0o4755,
    };
    assert!(runs_as_root(pkexec));
    // NixOS's wrapper: set-user-ID, executable by everyone, readable by none.
    assert!(runs_as_root(ProgramFacts {
        mode: 0o4511,
        ..pkexec
    }));
    for (facts, why) in [
        (
            ProgramFacts {
                mode: 0o555,
                ..pkexec
            },
            "NixOS's pkexec in the store: not set-user-ID",
        ),
        (
            ProgramFacts {
                owner: 1000,
                ..pkexec
            },
            "set-user-ID to another account",
        ),
        (
            ProgramFacts {
                is_file: false,
                ..pkexec
            },
            "not a file",
        ),
        (
            ProgramFacts {
                mode: 0o4000,
                ..pkexec
            },
            "not executable",
        ),
    ] {
        assert!(!runs_as_root(facts), "{why}");
    }
}

#[test]
fn pkexec_is_looked_for_by_its_set_user_id_path_only() {
    assert_eq!(
        PKEXEC_PATHS,
        ["/run/wrappers/bin/pkexec", "/usr/bin/pkexec"]
    );
    // A program of the test's own account, even set-user-ID, and a missing
    // one are passed over, and the error names where the window looked.
    let dir = std::env::temp_dir().join(format!("nails-gui-find-pkexec-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let own = dir.join("pkexec");
    std::fs::write(&own, "#!/bin/sh\n").unwrap();
    std::fs::set_permissions(&own, std::fs::Permissions::from_mode(0o4755)).unwrap();
    let missing = dir.join("missing");
    let refused = find_pkexec_in(&[&own, &missing]);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(
        refused,
        Err(format!(
            "no set-user-ID pkexec was found ({}, {})",
            own.display(),
            missing.display()
        ))
    );
    // The first that runs as root is the one: su is set-user-ID root on
    // every host the tests run on, at one of these paths.
    let su: Vec<&Path> = ["/run/wrappers/bin/su", "/usr/bin/su", "/bin/su"]
        .into_iter()
        .map(Path::new)
        .filter(|path| {
            std::fs::metadata(path).is_ok_and(|meta| meta.mode() & 0o4000 != 0 && meta.uid() == 0)
        })
        .collect();
    let first = su.first().expect("a set-user-ID su");
    assert_eq!(find_pkexec_in(&[&missing, first]), Ok(first.to_path_buf()));
}

/// The Emergency control shows from the start in a hidden session, and where
/// the mount table could not be read, which leaves that untold.
#[test]
fn the_emergency_shows_from_the_start_where_the_table_cannot_be_read() {
    let engine = PathBuf::from("/mnt/data/nails");
    assert!(emergency_from_start(Some(&engine), Ok(HIDDEN.as_bytes())));
    assert!(!emergency_from_start(Some(&engine), Ok(DECOY.as_bytes())));
    assert!(!emergency_from_start(None, Ok(HIDDEN.as_bytes())));
    assert!(emergency_from_start(
        Some(&engine),
        Err("Permission denied")
    ));
    assert!(emergency_from_start(None, Err("Permission denied")));
}
