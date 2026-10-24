// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the persona put in place at entry.

use super::*;

fn me(home: &Path) -> TargetUser {
    let uid = rustix::process::getuid().as_raw();
    let gid = rustix::process::getgid().as_raw();
    TargetUser::for_test(uid, gid, "alice", home.to_path_buf(), "/bin/sh")
}

#[test]
fn masks_land_in_the_home_owned_by_the_operator() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home/alice");
    std::fs::create_dir_all(home.join(".config/autostart")).unwrap();
    std::fs::write(
        home.join(".config/autostart/dropbox.desktop"),
        "[Desktop Entry]\nName=Dropbox\nExec=dropbox\n",
    )
    .unwrap();
    std::fs::write(
        home.join(".config/autostart/keep.desktop"),
        "[Desktop Entry]\nName=Keep\nExec=keep\n",
    )
    .unwrap();
    let wants = home.join(".config/systemd/user/default.target.wants");
    std::fs::create_dir_all(&wants).unwrap();
    std::os::unix::fs::symlink(
        "/usr/lib/systemd/user/syncthing.service",
        wants.join("syncthing.service"),
    )
    .unwrap();
    let persona = PersonaConfig {
        mode: PersonaMode::SharedHome,
        mask_inherited: vec!["dropbox".into(), "syncthing.service".into()],
    };
    let written = write_masks(dir.path(), &persona, &me(Path::new("/home/alice")));
    assert_eq!(written.len(), 2, "{written:?}");
    let mask = std::fs::read_to_string(home.join(".config/autostart/dropbox.desktop")).unwrap();
    assert!(mask.contains("Hidden=true"));
    assert!(
        !std::fs::read_to_string(home.join(".config/autostart/keep.desktop"))
            .unwrap()
            .contains("Hidden=true")
    );
    assert_eq!(
        std::fs::read_link(home.join(".config/systemd/user/syncthing.service")).unwrap(),
        Path::new("/dev/null")
    );
}

#[test]
fn a_named_entry_the_inventory_misses_is_masked_by_its_suffix() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home/alice");
    std::fs::create_dir_all(&home).unwrap();
    let persona = PersonaConfig {
        mode: PersonaMode::FreshHome,
        mask_inherited: vec![
            "org.kde.kdeconnect.daemon".into(),
            "ghost.service".into(),
            "../escape".into(),
        ],
    };
    let written = write_masks(dir.path(), &persona, &me(Path::new("/home/alice")));
    assert_eq!(written.len(), 2, "{written:?}");
    let mask =
        std::fs::read_to_string(home.join(".config/autostart/org.kde.kdeconnect.daemon.desktop"))
            .unwrap();
    assert!(mask.contains("Hidden=true"), "{mask}");
    assert_eq!(
        std::fs::read_link(home.join(".config/systemd/user/ghost.service")).unwrap(),
        Path::new("/dev/null")
    );
    assert!(
        !dir.path().join("home/escape.desktop").exists()
            && !home.join(".config/escape.desktop").exists(),
        "a name with a slash writes nothing"
    );
}

#[test]
fn nothing_is_written_without_a_mask_list_or_a_home() {
    let dir = tempfile::tempdir().unwrap();
    let persona = PersonaConfig::default();
    assert!(write_masks(dir.path(), &persona, &me(Path::new("/"))).is_empty());
    let persona = PersonaConfig {
        mode: PersonaMode::SharedHome,
        mask_inherited: vec!["dropbox".into()],
    };
    assert!(write_masks(dir.path(), &persona, &me(Path::new("/home/alice"))).is_empty());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

/// The decoy's `/home` and the operator's `~/.config` are absolute links
/// (`/home -> /nails-test-data/home`, `.config -> /nails-test-dotfiles`):
/// the masks follow them inside the next root, where the hidden root will
/// read them. Resolved on the running system instead, the targets would
/// not exist (nothing outside the next root is written to show it).
#[test]
fn masks_follow_absolute_links_inside_the_next_root() {
    let root = tempfile::tempdir().unwrap();
    let data = root.path().join("nails-test-data/home/alice");
    let dotfiles = root.path().join("nails-test-dotfiles/autostart");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::create_dir_all(&dotfiles).unwrap();
    std::fs::write(
        dotfiles.join("dropbox.desktop"),
        "[Desktop Entry]\nExec=dropbox\n",
    )
    .unwrap();
    std::os::unix::fs::symlink("/nails-test-data/home", root.path().join("home")).unwrap();
    std::os::unix::fs::symlink("/nails-test-dotfiles", data.join(".config")).unwrap();
    // The inventory reads the home the same way.
    let inventory = collect_inherited_persona(
        &InNextRoot { root: root.path() },
        &root.path().join("home/alice"),
        "alice",
        false,
    );
    assert!(
        inventory.entries.iter().any(|entry| entry.name == "dropbox"
            && entry.source == crate::persona::InheritedSource::UserAutostart),
        "{inventory:?}"
    );
    // It tells a file from a directory through the same links; a path
    // outside the next root is the running system's.
    let source = InNextRoot { root: root.path() };
    let home = root.path().join("home/alice");
    assert!(source.is_file(&home.join(".config/autostart/dropbox.desktop")));
    assert!(!source.is_file(&home.join(".config/autostart")));
    let outside = tempfile::NamedTempFile::new().unwrap();
    assert!(source.is_file(outside.path()));
    assert!(!source.is_file(Path::new("/dev/null")));
    let persona = PersonaConfig {
        mode: PersonaMode::SharedHome,
        mask_inherited: vec!["dropbox".into(), "syncthing.service".into()],
    };
    let written = write_masks(root.path(), &persona, &me(Path::new("/home/alice")));
    assert_eq!(written.len(), 2, "{written:?}");
    let mask = std::fs::read_to_string(dotfiles.join("dropbox.desktop")).unwrap();
    assert!(
        mask.contains("Hidden=true"),
        "the listed entry is masked: {mask}"
    );
    assert_eq!(
        std::fs::read_link(
            root.path()
                .join("nails-test-dotfiles/systemd/user/syncthing.service")
        )
        .unwrap(),
        Path::new("/dev/null")
    );
    // A dangling link is never written through.
    std::fs::remove_dir_all(root.path().join("nails-test-dotfiles")).unwrap();
    assert!(write_masks(root.path(), &persona, &me(Path::new("/home/alice"))).is_empty());
    assert!(!root.path().join("nails-test-dotfiles").exists());
}

#[test]
fn an_existing_hidden_home_is_kept_as_it_is() {
    let dir = tempfile::tempdir().unwrap();
    let upper_home = dir.path().join("upper/home/alice");
    std::fs::create_dir_all(&upper_home).unwrap();
    std::fs::write(upper_home.join("notes"), "hidden").unwrap();
    let created = prepare_fresh_home(
        &upper_home,
        &dir.path().join("home/alice"),
        &me(&upper_home),
    )
    .unwrap();
    assert!(!created);
    assert!(upper_home.join("notes").exists());
}

#[test]
fn a_new_hidden_home_takes_the_decoy_parents_attributes() {
    let dir = tempfile::tempdir().unwrap();
    let decoy_home = dir.path().join("decoy/home/alice");
    std::fs::create_dir_all(&decoy_home).unwrap();
    std::fs::set_permissions(
        dir.path().join("decoy/home"),
        std::fs::Permissions::from_mode(0o751),
    )
    .unwrap();
    let upper_home = dir.path().join("upper/home/alice");
    std::fs::create_dir_all(dir.path().join("upper")).unwrap();
    // Without CAP_SYS_ADMIN the opaque xattr cannot be set; the parents are
    // created either way.
    if prepare_fresh_home(&upper_home, &decoy_home, &me(&upper_home)).is_err() {
        assert!(!upper_home.exists(), "no plain home is left behind");
    }
    let mode = std::fs::metadata(dir.path().join("upper/home"))
        .unwrap()
        .mode()
        & 0o7777;
    assert_eq!(mode, 0o751);
}

/// The masks through a real overlay, as activation writes them: the decoy
/// is the read-only lower, the upper is on the hidden volume.
mod kernel_tests {
    use super::*;
    use nails_base::test_support::{Rerun, ScratchTmpfs};
    use std::collections::BTreeMap;

    /// Every entry below `dir`: file contents, link targets and modes,
    /// so any change to the decoy shows.
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

    fn masks() -> PersonaConfig {
        PersonaConfig {
            mode: PersonaMode::SharedHome,
            mask_inherited: vec!["dropbox".into(), "syncthing.service".into()],
        }
    }

    #[test]
    fn masks_behind_absolute_links_land_in_the_upper_and_leave_the_decoy_as_it_was() {
        let _ = Rerun::new(nails_base::test_path!(
            masks_behind_absolute_links_land_in_the_upper_and_leave_the_decoy_as_it_was
        ))
        .in_user_mount_ns()
        .run(|| {
            // ~/.config is an absolute link into a dotfiles directory.
            let decoy = ScratchTmpfs::new("");
            let config = decoy.mkdir("home/alice/.dotfiles/config/autostart");
            std::fs::write(
                config.join("dropbox.desktop"),
                "[Desktop Entry]\nExec=dropbox\n",
            )
            .unwrap();
            std::os::unix::fs::symlink(
                "/home/alice/.dotfiles/config",
                decoy.path().join("home/alice/.config"),
            )
            .unwrap();
            // In a second decoy, /home itself is an absolute link.
            let linked = ScratchTmpfs::new("");
            linked.mkdir("srv/people/alice");
            std::os::unix::fs::symlink("/srv/people", linked.path().join("home")).unwrap();

            for (decoy, upper_config) in [
                (&decoy, "home/alice/.dotfiles/config"),
                (&linked, "srv/people/alice/.config"),
            ] {
                let before = tree(decoy.path());
                let hidden = ScratchTmpfs::new("");
                let next = next_root(decoy.path(), &hidden);
                let written = write_masks(&next, &masks(), &me(Path::new("/home/alice")));
                assert_eq!(written.len(), 2, "{upper_config}: {written:?}");
                let upper = hidden.path().join("upper").join(upper_config);
                let mask =
                    std::fs::read_to_string(upper.join("autostart/dropbox.desktop")).unwrap();
                assert!(mask.contains("Hidden=true"), "{upper_config}: {mask}");
                assert_eq!(
                    std::fs::read_link(upper.join("systemd/user/syncthing.service")).unwrap(),
                    Path::new("/dev/null")
                );
                assert_eq!(
                    tree(decoy.path()),
                    before,
                    "{upper_config}: the decoy changed"
                );
                nextroot::detach_tree(&next);
            }
        });
    }

    /// `mask_inherited = ["*"]` masks what the inventory finds, and the
    /// inventory reads `~/.config` through the absolute link as the hidden
    /// root resolves it. Read on the running system instead, it would find
    /// nothing there and mask nothing.
    #[test]
    fn a_wildcard_masks_the_entries_behind_an_absolute_link() {
        let _ = Rerun::new(nails_base::test_path!(
            a_wildcard_masks_the_entries_behind_an_absolute_link
        ))
        .in_user_mount_ns()
        .run(|| {
            let decoy = ScratchTmpfs::new("");
            let config = decoy.mkdir("home/alice/.dotfiles/config/autostart");
            std::fs::write(
                config.join("dropbox.desktop"),
                "[Desktop Entry]\nExec=dropbox\n",
            )
            .unwrap();
            std::os::unix::fs::symlink(
                "/home/alice/.dotfiles/config",
                decoy.path().join("home/alice/.config"),
            )
            .unwrap();
            let before = tree(decoy.path());
            let hidden = ScratchTmpfs::new("");
            let next = next_root(decoy.path(), &hidden);
            let everything = PersonaConfig {
                mode: PersonaMode::SharedHome,
                mask_inherited: vec!["*".into()],
            };

            let written = write_masks(&next, &everything, &me(Path::new("/home/alice")));

            // The test host's own system entries are masked too.
            assert!(
                written.contains(&PathBuf::from(
                    "/home/alice/.config/autostart/dropbox.desktop"
                )),
                "{written:?}"
            );
            let mask = std::fs::read_to_string(
                hidden
                    .path()
                    .join("upper/home/alice/.dotfiles/config/autostart/dropbox.desktop"),
            )
            .unwrap();
            assert!(mask.contains("Hidden=true"), "{mask}");
            assert_eq!(tree(decoy.path()), before, "the decoy changed");
            nextroot::detach_tree(&next);
        });
    }
}
