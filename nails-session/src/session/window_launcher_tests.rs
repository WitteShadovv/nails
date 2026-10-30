// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the window's launcher in the hidden session.

use super::*;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

fn me(home: &Path) -> TargetUser {
    let uid = rustix::process::getuid().as_raw();
    let gid = rustix::process::getgid().as_raw();
    TargetUser::for_test(uid, gid, "alice", home.to_path_buf(), "/bin/sh")
}

fn launcher(root: &str) -> WindowLauncher {
    WindowLauncher {
        engine: Path::new(root).join("nails"),
        window: Path::new(root).join("gui/bin/nails-gui"),
    }
}

/// A desktop entry's string value with its escapes undone, as a reader does
/// first: `\s` a space, `\\` a backslash; the writer makes no other.
fn unescape(value: &str) -> String {
    let mut out = String::new();
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('s') => out.push(' '),
            Some('\\') => out.push('\\'),
            Some(other) => panic!("an escape the writer never makes: \\{other}"),
            None => panic!("a lone backslash at the end of {value}"),
        }
    }
    out
}

/// `arg` with its field codes undone: `%%` is a `%`, and any other `%` would
/// be a field code the launcher never means.
fn literal(arg: &str) -> String {
    let mut out = String::new();
    let mut chars = arg.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('%') => out.push('%'),
            code => panic!("a field code in {arg}: %{code:?}"),
        }
    }
    out
}

/// A desktop entry's `Exec` value read back as the specification reads it:
/// the string escapes undone first, then the quoting, then the field codes.
/// In quotes only `"`, `` ` ``, `$` and `\` may follow a backslash, and `$` and
/// `` ` `` must; outside them no reserved character may stand.
fn exec_args(value: &str) -> Vec<String> {
    let unescaped = unescape(value);
    let mut args = Vec::new();
    let mut current = String::new();
    let (mut started, mut quoted) = (false, false);
    let mut chars = unescaped.chars();
    while let Some(c) = chars.next() {
        match (quoted, c) {
            (true, '"') => quoted = false,
            (true, '\\') => match chars.next() {
                Some(escaped @ ('"' | '`' | '$' | '\\')) => current.push(escaped),
                other => panic!("a backslash before {other:?} in quotes: {value}"),
            },
            (true, '$' | '`') => panic!("an unescaped {c} in quotes: {value}"),
            (true, _) => current.push(c),
            (false, ' ') if started => {
                args.push(std::mem::take(&mut current));
                started = false;
            }
            (false, ' ') => {}
            (false, '"') => (quoted, started) = (true, true),
            (false, _) => {
                assert!(
                    !"\"'\\><~|&;$*?#()`\t".contains(c),
                    "a reserved character outside quotes: {c}"
                );
                current.push(c);
                started = true;
            }
        }
    }
    assert!(!quoted, "an unterminated quote in {value}");
    if started {
        args.push(current);
    }
    args.into_iter().map(|arg| literal(&arg)).collect()
}

/// The value of `key` in the entry `text`.
fn value<'a>(text: &'a str, key: &str) -> &'a str {
    text.lines()
        .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
        .unwrap_or_else(|| panic!("no {key} in {text}"))
}

#[test]
fn the_entry_runs_the_window_with_the_engine_whose_helper_it_starts() {
    let text = desktop_entry(&launcher("/mnt/data")).unwrap();
    assert_eq!(
        text,
        "[Desktop Entry]\n\
         Type=Application\n\
         Name=Session\n\
         Exec=\"/mnt/data/gui/bin/nails-gui\" --engine \"/mnt/data/nails\"\n\
         TryExec=/mnt/data/gui/bin/nails-gui\n\
         Terminal=false\n\
         Categories=System;\n"
    );
    assert_eq!(
        exec_args(value(&text, "Exec")),
        ["/mnt/data/gui/bin/nails-gui", "--engine", "/mnt/data/nails"]
    );
}

#[test]
fn every_path_reads_back_from_the_entry_as_it_was_written() {
    for root in [
        "/mnt/my data",
        "/mnt/a\"b",
        "/mnt/$HOME`id`",
        "/mnt/back\\slash",
        "/mnt/100%",
        "/mnt/%f %u",
        "/mnt/'quote'; rm -rf ~ | x & y",
        "/mnt/données",
    ] {
        let paths = launcher(root);
        let text = desktop_entry(&paths).unwrap();
        let window = paths.window.to_str().unwrap();
        let engine = paths.engine.to_str().unwrap();
        assert_eq!(
            exec_args(value(&text, "Exec")),
            [window, "--engine", engine],
            "{text}"
        );
        assert_eq!(unescape(value(&text, "TryExec")), window, "{text}");
        assert_eq!(text.lines().count(), 7, "{text}");
    }
}

#[test]
fn the_action_matches_the_engine_and_its_helper_and_asks_every_time() {
    let text = policy(&launcher("/mnt/data")).unwrap();
    assert_eq!(
        text,
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC
 "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig>
  <action id="session.open">
    <description>Session</description>
    <message>Session needs your password each time it opens.</message>
    <defaults>
      <allow_any>auth_admin</allow_any>
      <allow_inactive>auth_admin</allow_inactive>
      <allow_active>auth_admin</allow_active>
    </defaults>
    <annotate key="org.freedesktop.policykit.exec.path">/mnt/data/nails</annotate>
    <annotate key="org.freedesktop.policykit.exec.argv1">helper</annotate>
  </action>
</policyconfig>
"#
    );
    // Nothing names the tool on a surface the dialog can show.
    for surface in [ACTION_ID, NAME, MESSAGE, APP_ID] {
        assert!(
            !surface.to_lowercase().contains("nails"),
            "{surface} names the tool"
        );
    }
}

#[test]
fn a_path_neither_file_can_carry_is_refused() {
    let relative = WindowLauncher {
        engine: PathBuf::from("nails"),
        window: PathBuf::from("/mnt/data/gui/bin/nails-gui"),
    };
    assert!(desktop_entry(&relative).is_err());
    assert!(policy(&relative).is_err());
    let control = launcher("/mnt/da\nta");
    assert!(desktop_entry(&control).unwrap_err().contains("control"));
    assert!(policy(&control).is_err());
    let not_utf8 = WindowLauncher {
        engine: PathBuf::from(
            <std::ffi::OsString as std::os::unix::ffi::OsStringExt>::from_vec(
                b"/mnt/\xff/nails".to_vec(),
            ),
        ),
        window: PathBuf::from("/mnt/data/gui/bin/nails-gui"),
    };
    assert!(desktop_entry(&not_utf8).unwrap_err().contains("UTF-8"));
    // A character XML must escape: the entry can carry it, the action not.
    let ampersand = launcher("/mnt/a&b");
    assert!(desktop_entry(&ampersand).is_ok());
    assert!(policy(&ampersand).unwrap_err().contains("cannot match"));
}

#[test]
fn each_family_gets_the_files_where_it_reads_them() {
    let paths = launcher("/mnt/data");
    let fhs: Vec<_> = plan(false, None, &paths)
        .into_iter()
        .map(|planned| {
            let planned = planned.unwrap();
            assert_eq!(planned.owner, None, "{planned:?}");
            planned.path()
        })
        .collect();
    assert_eq!(
        fhs,
        [
            PathBuf::from("/usr/share/applications/session.desktop"),
            PathBuf::from("/usr/share/polkit-1/actions/session.open.policy"),
        ]
    );
    let alice = me(Path::new("/home/alice"));
    let nixos = plan(true, Some(&alice), &paths);
    let entry = nixos[0].as_ref().unwrap();
    assert_eq!(
        entry.path(),
        Path::new("/home/alice/.local/share/applications/session.desktop")
    );
    assert_eq!(entry.owner, Some(&alice));
    let action = nixos[1].as_ref().unwrap();
    assert_eq!(
        action.path(),
        Path::new("/etc/polkit-1/actions/session.open.policy")
    );
    assert_eq!(action.owner, None);
    // Without an operator NixOS has no place for the entry; the action is
    // still planned.
    let alone = plan(true, None, &paths);
    assert!(alone[0].as_ref().unwrap_err().contains("operator"));
    assert!(alone[1].is_ok());
}

fn mode_of(path: &Path) -> u32 {
    std::fs::symlink_metadata(path).unwrap().mode() & 0o7777
}

#[test]
fn the_launcher_is_written_into_the_root_and_replaced_at_the_next_entry() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("usr/share")).unwrap();
    let written = put_in_place(root.path(), false, None, &launcher("/mnt/data"));
    assert_eq!(
        written,
        [
            PathBuf::from("/usr/share/applications/session.desktop"),
            PathBuf::from("/usr/share/polkit-1/actions/session.open.policy"),
        ]
    );
    let entry = root.path().join("usr/share/applications/session.desktop");
    let action = root
        .path()
        .join("usr/share/polkit-1/actions/session.open.policy");
    assert_eq!(mode_of(&entry), 0o644);
    assert_eq!(mode_of(&action), 0o644);
    for made in [
        "usr/share/applications",
        "usr/share/polkit-1",
        "usr/share/polkit-1/actions",
    ] {
        assert_eq!(mode_of(&root.path().join(made)), 0o755, "{made}");
    }
    assert!(
        std::fs::read_to_string(&action)
            .unwrap()
            .contains(">/mnt/data/nails<")
    );

    // The hidden volume mounted elsewhere at the next entry: both follow.
    let written = put_in_place(root.path(), false, None, &launcher("/media/disk"));
    assert_eq!(written.len(), 2);
    let text = std::fs::read_to_string(&entry).unwrap();
    assert!(text.contains("\"/media/disk/nails\""), "{text}");
    assert!(!text.contains("/mnt/data"), "{text}");
    assert!(
        std::fs::read_to_string(&action)
            .unwrap()
            .contains(">/media/disk/nails<")
    );
}

#[test]
fn on_nixos_the_entry_is_the_operator_s_and_the_action_is_in_etc() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("home/alice")).unwrap();
    std::fs::create_dir_all(root.path().join("etc/polkit-1/rules.d")).unwrap();
    let alice = me(Path::new("/home/alice"));
    let written = put_in_place(root.path(), true, Some(&alice), &launcher("/mnt/data"));
    assert_eq!(
        written,
        [
            PathBuf::from("/home/alice/.local/share/applications/session.desktop"),
            PathBuf::from("/etc/polkit-1/actions/session.open.policy"),
        ]
    );
    let entry = root
        .path()
        .join("home/alice/.local/share/applications/session.desktop");
    let meta = std::fs::metadata(&entry).unwrap();
    assert_eq!((meta.uid(), meta.gid()), (alice.uid, alice.gid));
    assert_eq!(meta.permissions().mode() & 0o7777, 0o644);
    for made in [".local", ".local/share", ".local/share/applications"] {
        assert_eq!(
            mode_of(&root.path().join("home/alice").join(made)),
            0o700,
            "{made}"
        );
    }
    assert_eq!(mode_of(&root.path().join("etc/polkit-1/actions")), 0o755);
}

#[test]
fn a_home_missing_from_the_root_is_not_made_and_the_action_is_still_written() {
    let root = tempfile::tempdir().unwrap();
    let alice = me(Path::new("/home/alice"));
    let written = put_in_place(root.path(), true, Some(&alice), &launcher("/mnt/data"));
    assert_eq!(
        written,
        [PathBuf::from("/etc/polkit-1/actions/session.open.policy")]
    );
    assert!(!root.path().join("home").exists());
}

#[test]
fn a_file_that_cannot_be_written_leaves_the_other_and_fails_nothing() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("usr/share")).unwrap();
    // No directory can be made where a file is.
    std::fs::write(root.path().join("usr/share/applications"), "a file").unwrap();
    let written = put_in_place(root.path(), false, None, &launcher("/mnt/data"));
    assert_eq!(
        written,
        [PathBuf::from(
            "/usr/share/polkit-1/actions/session.open.policy"
        )]
    );
    assert_eq!(
        std::fs::read_to_string(root.path().join("usr/share/applications")).unwrap(),
        "a file"
    );
}

#[test]
fn a_directory_that_resolves_into_the_store_is_refused() {
    let root = tempfile::tempdir().unwrap();
    let store = root
        .path()
        .join("nix/store/abc-home-manager-files/share/applications");
    std::fs::create_dir_all(&store).unwrap();
    std::fs::create_dir_all(root.path().join("home/alice/.local/share")).unwrap();
    // An absolute link, as a home manager makes it: it resolves inside the root.
    std::os::unix::fs::symlink(
        "/nix/store/abc-home-manager-files/share/applications",
        root.path().join("home/alice/.local/share/applications"),
    )
    .unwrap();
    let alice = me(Path::new("/home/alice"));
    let written = put_in_place(root.path(), true, Some(&alice), &launcher("/mnt/data"));
    assert_eq!(
        written,
        [PathBuf::from("/etc/polkit-1/actions/session.open.policy")]
    );
    assert_eq!(std::fs::read_dir(&store).unwrap().count(), 0);
}

/// A store link higher up (`~/.local/share`, with no `applications` in the
/// store path yet) is refused before the missing directory is made in there.
#[test]
fn a_store_link_on_the_way_is_refused_before_anything_is_made_in_the_store() {
    let root = tempfile::tempdir().unwrap();
    let share = root.path().join("nix/store/abc-home-manager-files/share");
    std::fs::create_dir_all(&share).unwrap();
    std::fs::create_dir_all(root.path().join("home/alice/.local")).unwrap();
    std::os::unix::fs::symlink(
        "/nix/store/abc-home-manager-files/share",
        root.path().join("home/alice/.local/share"),
    )
    .unwrap();
    let alice = me(Path::new("/home/alice"));
    let written = put_in_place(root.path(), true, Some(&alice), &launcher("/mnt/data"));
    assert_eq!(
        written,
        [PathBuf::from("/etc/polkit-1/actions/session.open.policy")]
    );
    assert_eq!(
        std::fs::read_dir(&share).unwrap().count(),
        0,
        "nothing was made in the store path"
    );
}

#[test]
fn a_link_planted_at_the_file_s_name_is_replaced_and_not_followed() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("usr/share/applications")).unwrap();
    std::fs::create_dir_all(root.path().join("etc")).unwrap();
    std::fs::write(root.path().join("etc/shadow"), "untouched").unwrap();
    std::os::unix::fs::symlink(
        "/etc/shadow",
        root.path().join("usr/share/applications/session.desktop"),
    )
    .unwrap();
    put_in_place(root.path(), false, None, &launcher("/mnt/data"));
    let entry = root.path().join("usr/share/applications/session.desktop");
    assert!(std::fs::symlink_metadata(&entry).unwrap().is_file());
    assert_eq!(
        std::fs::read_to_string(root.path().join("etc/shadow")).unwrap(),
        "untouched"
    );
}

/// In the kernel tier: the launcher written through a real overlay over a
/// decoy whose directories are absolute links.
mod kernel_tests {
    use super::*;
    use nails_base::test_support::{Rerun, ScratchTmpfs};
    use std::collections::BTreeMap;

    /// Every entry below `dir`: file contents, link targets and modes, so any
    /// change to the decoy shows.
    fn tree(dir: &Path) -> BTreeMap<PathBuf, String> {
        let mut out = BTreeMap::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(current) = stack.pop() {
            for entry in std::fs::read_dir(&current).unwrap().flatten() {
                let path = entry.path();
                let meta = std::fs::symlink_metadata(&path).unwrap();
                let what = if meta.file_type().is_symlink() {
                    format!("-> {}", std::fs::read_link(&path).unwrap().display())
                } else if meta.is_dir() {
                    stack.push(path.clone());
                    format!("dir {:o}", meta.mode())
                } else {
                    format!(
                        "{:o} {}",
                        meta.mode(),
                        std::fs::read_to_string(&path).unwrap()
                    )
                };
                out.insert(path.strip_prefix(dir).unwrap().to_path_buf(), what);
            }
        }
        out
    }

    /// The next root over `decoy`, with its upper on `hidden`.
    fn next_root(decoy: &Path, hidden: &ScratchTmpfs) -> PathBuf {
        let next = hidden.mkdir("next");
        nextroot::overlay_over(
            decoy,
            &hidden.path().join("lower"),
            &hidden.mkdir("upper"),
            &hidden.mkdir("work"),
            &next,
        )
        .expect("the root overlay");
        next
    }

    #[test]
    fn the_launcher_lands_in_the_upper_and_the_decoy_stays_as_it_was() {
        let _ = Rerun::new(nails_base::test_path!(
            the_launcher_lands_in_the_upper_and_the_decoy_stays_as_it_was
        ))
        .in_user_mount_ns()
        .run(|| {
            // A Debian-family decoy whose polkit actions are an absolute link
            // into /opt, and a NixOS decoy whose /home is one into /srv.
            let fhs = ScratchTmpfs::new("");
            fhs.mkdir("usr/share/applications");
            fhs.mkdir("opt/polkit/actions");
            std::fs::create_dir_all(fhs.path().join("usr/share/polkit-1")).unwrap();
            std::os::unix::fs::symlink(
                "/opt/polkit/actions",
                fhs.path().join("usr/share/polkit-1/actions"),
            )
            .unwrap();
            let nixos = ScratchTmpfs::new("");
            nixos.mkdir("srv/people/alice");
            nixos.mkdir("etc/polkit-1/rules.d");
            std::os::unix::fs::symlink("/srv/people", nixos.path().join("home")).unwrap();
            let alice = me(Path::new("/home/alice"));

            for (decoy, is_nixos, in_upper) in [
                (
                    &fhs,
                    false,
                    [
                        "usr/share/applications/session.desktop",
                        "opt/polkit/actions/session.open.policy",
                    ],
                ),
                (
                    &nixos,
                    true,
                    [
                        "srv/people/alice/.local/share/applications/session.desktop",
                        "etc/polkit-1/actions/session.open.policy",
                    ],
                ),
            ] {
                let before = tree(decoy.path());
                let hidden = ScratchTmpfs::new("");
                let next = next_root(decoy.path(), &hidden);
                let written = put_in_place(&next, is_nixos, Some(&alice), &launcher("/mnt/data"));
                assert_eq!(written.len(), 2, "{written:?}");
                for file in in_upper {
                    let text = std::fs::read_to_string(hidden.path().join("upper").join(file))
                        .unwrap_or_else(|e| panic!("{file} is not in the upper: {e}"));
                    assert!(text.contains("/mnt/data/nails"), "{file}: {text}");
                }
                assert_eq!(tree(decoy.path()), before, "the decoy changed");
                nextroot::detach_tree(&next);
            }
        });
    }
}
