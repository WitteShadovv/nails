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

/// A FIFO among the autostart entries of the next root's home is skipped
/// unread: opened, it would hold the entry up until a writer came along.
/// Here a writer comes at once, so an inventory that opens it lists it and
/// fails the test rather than hanging it.
#[test]
fn the_inventory_at_entry_never_opens_a_fifo() {
    let root = tempfile::tempdir().unwrap();
    let autostart = root.path().join("home/alice/.config/autostart");
    std::fs::create_dir_all(&autostart).unwrap();
    std::fs::write(autostart.join("dropbox.desktop"), "[Desktop Entry]\n").unwrap();
    let fifo = autostart.join("nails-test-fifo.desktop");
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::FileType::Fifo,
        Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
    let inventory = crate::test_fifo::releasing_readers(&fifo, || {
        collect_inherited_persona(
            &InNextRoot { root: root.path() },
            &root.path().join("home/alice"),
            "alice",
            false,
        )
    });
    let in_home: Vec<&str> = inventory
        .entries
        .iter()
        .filter(|entry| entry.source == crate::persona::InheritedSource::UserAutostart)
        .map(|entry| entry.name.as_str())
        .collect();
    assert_eq!(in_home, ["dropbox"]);
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

/// The directories missing on the way to a new home, above the root of the
/// upper and below it, take the mode of the decoy directory each stands for,
/// and the home itself is made opaque or not left at all.
#[test]
fn a_new_hidden_home_takes_the_decoy_parents_attributes() {
    let dir = tempfile::tempdir().unwrap();
    let decoy_home = dir.path().join("decoy/home/alice");
    std::fs::create_dir_all(&decoy_home).unwrap();
    // The scratch directory stands for the directory above the decoy, which
    // `hidden/root` stands for in turn.
    for (decoy_dir, mode) in [
        ("", 0o701),
        ("decoy", 0o755),
        ("decoy/home", 0o751),
        ("decoy/home/alice", 0o710),
    ] {
        let path = dir.path().join(decoy_dir);
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }
    // Of the hidden volume only its root is there.
    std::fs::create_dir(dir.path().join("hidden")).unwrap();
    let upper_home = dir.path().join("hidden/root/upper/home/alice");
    let made = prepare_fresh_home(&upper_home, &decoy_home, &me(&upper_home));
    if rustix::process::geteuid().is_root() {
        assert!(made.unwrap(), "the home is made");
        let mut value = [0; 8];
        let len = rustix::fs::getxattr(&upper_home, OPAQUE_XATTR, &mut value[..]).unwrap();
        assert_eq!(&value[..len], b"y");
        assert_eq!(
            std::fs::metadata(&upper_home).unwrap().mode() & 0o7777,
            0o710
        );
    } else {
        // Without CAP_SYS_ADMIN the opaque xattr cannot be set, and a home
        // without it would let the decoy home show through: none is left.
        let error = made.unwrap_err();
        assert_eq!(
            error.io_kind(),
            Some(std::io::ErrorKind::PermissionDenied),
            "{error}"
        );
        assert!(
            upper_home.symlink_metadata().is_err(),
            "no plain home is left behind"
        );
    }
    // The parents are made either way.
    for (parent, mode) in [
        ("hidden/root", 0o701),
        ("hidden/root/upper", 0o755),
        ("hidden/root/upper/home", 0o751),
    ] {
        let meta = std::fs::symlink_metadata(dir.path().join(parent)).unwrap();
        assert!(meta.is_dir(), "{parent}");
        assert_eq!(meta.mode() & 0o7777, mode, "{parent}");
    }
}

/// The way down to a home in the root upper, in the upper of a separate
/// filesystem, and to a home that is a filesystem of its own: it starts where
/// the two paths part, and each directory from the root of the upper down
/// stands for the decoy directory at the same place.
#[test]
fn the_way_to_the_home_starts_at_the_root_of_the_upper() {
    fn step<'a>(name: &'a str, path: &str, like: Option<&'a str>) -> Step<'a> {
        Step {
            name: OsStr::new(name),
            path: PathBuf::from(path),
            like: like.map(Path::new),
        }
    }

    let way = Way::new(
        Path::new("/mnt/data/root/upper/home/alice"),
        Path::new("/home/alice"),
    )
    .unwrap();
    assert_eq!(way.base, Path::new("/mnt/data/root"));
    assert_eq!(way.base_like, None);
    assert_eq!(
        way.parents,
        [
            step("upper", "/mnt/data/root/upper", Some("/")),
            step("home", "/mnt/data/root/upper/home", Some("/home")),
        ]
    );
    assert_eq!(way.home, "alice");

    let way = Way::new(
        Path::new("/mnt/data/root/mounts/home/upper/staff/bob"),
        Path::new("/home/staff/bob"),
    )
    .unwrap();
    assert_eq!(way.base, Path::new("/mnt/data/root/mounts/home"));
    assert_eq!(way.base_like, Some(Path::new("/")));
    assert_eq!(
        way.parents,
        [
            step("upper", "/mnt/data/root/mounts/home/upper", Some("/home")),
            step(
                "staff",
                "/mnt/data/root/mounts/home/upper/staff",
                Some("/home/staff")
            ),
        ]
    );
    assert_eq!(way.home, "bob");

    // A home that is a filesystem of its own is the root of its upper.
    let way = Way::new(
        Path::new("/mnt/data/root/mounts/home-alice/upper"),
        Path::new("/home/alice"),
    )
    .unwrap();
    assert_eq!(way.base, Path::new("/mnt/data/root/mounts/home-alice"));
    assert_eq!(way.base_like, Some(Path::new("/home")));
    assert!(way.parents.is_empty());
    assert_eq!(way.home, "upper");

    // A decoy filesystem mounted at a directory named `upper` shares one more
    // name: the way starts above the root of its upper.
    let way = Way::new(
        Path::new("/mnt/data/root/mounts/srv-upper/upper/alice"),
        Path::new("/srv/upper/alice"),
    )
    .unwrap();
    assert_eq!(way.base, Path::new("/mnt/data/root/mounts"));
    assert_eq!(
        way.parents,
        [
            step("srv-upper", "/mnt/data/root/mounts/srv-upper", Some("/srv")),
            step(
                "upper",
                "/mnt/data/root/mounts/srv-upper/upper",
                Some("/srv/upper")
            ),
        ]
    );

    // A relative path starts in the working directory, and a path without a
    // name names no home.
    let way = Way::new(Path::new("upper/alice"), Path::new("/home/alice")).unwrap();
    assert_eq!(way.base, Path::new("."));
    assert_eq!(way.parents, [step("upper", "./upper", Some("/home"))]);
    assert_eq!(way.base_like, Some(Path::new("/")));
    for nameless in ["/", "/mnt/data/.."] {
        let error = Way::new(Path::new(nameless), Path::new("/home/alice")).unwrap_err();
        assert!(
            error.to_string().contains("names no directory"),
            "{nameless}: {error}"
        );
    }
}

/// A link target that leads from the directory `from` to `to` by `..` up to
/// `/` and down again.
fn relative(from: &Path, to: &Path) -> PathBuf {
    let from = from.canonicalize().unwrap();
    let mut out: PathBuf = from.components().skip(1).map(|_| "..").collect();
    out.push(to.canonicalize().unwrap().strip_prefix("/").unwrap());
    out
}

/// `dir` and every entry below it, with its mode and its modification and
/// status change times, which making or removing anything in it moves.
fn stamps(dir: &Path) -> Vec<(PathBuf, u32, [i64; 4])> {
    let mut out = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(current) = pending.pop() {
        let meta = std::fs::symlink_metadata(&current).unwrap();
        if meta.is_dir() {
            for entry in std::fs::read_dir(&current).unwrap() {
                pending.push(entry.unwrap().path());
            }
        }
        let times = [
            meta.mtime(),
            meta.mtime_nsec(),
            meta.ctime(),
            meta.ctime_nsec(),
        ];
        out.push((current, meta.mode(), times));
    }
    out.sort();
    out
}

/// Long enough for a change to move a time.
fn tick() {
    std::thread::sleep(std::time::Duration::from_millis(20));
}

/// A hidden session replaced `/home`, or a directory below it on the way to
/// the home, with a link that leads out of the upper, absolute or relative.
/// The fresh home is refused there, the link is kept, and nothing is made or
/// changed where it leads, which is the decoy's directory in the hidden root's
/// layout. Followed, the link would take the new home there.
#[test]
fn a_link_on_the_way_to_the_home_refuses_it_and_nothing_is_made_where_it_leads() {
    for (at, relative_link) in [
        ("home", false),
        ("home", true),
        ("home/staff", false),
        ("home/staff", true),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = dir.path().join("decoy/var/home");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::fs::create_dir_all(dir.path().join("decoy/home/staff/alice")).unwrap();
        let upper = dir.path().join("hidden/root/upper");
        let link = upper.join(at);
        let above = link.parent().unwrap();
        std::fs::create_dir_all(above).unwrap();
        let target = if relative_link {
            relative(above, &elsewhere)
        } else {
            elsewhere.clone()
        };
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let before = stamps(dir.path());
        tick();

        let refused = prepare_fresh_home(
            &upper.join("home/staff/alice"),
            &dir.path().join("decoy/home/staff/alice"),
            &me(Path::new("/home/staff/alice")),
        );

        assert_eq!(stamps(dir.path()), before, "{at}: something changed");
        let error = refused.unwrap_err();
        let named = format!(
            "{} is a symbolic link to {}: ",
            link.display(),
            target.display()
        );
        assert!(error.to_string().contains(&named), "{at}: {error}");
        assert_eq!(std::fs::read_link(&link).unwrap(), target);
    }
}

/// A dangling link, a link in place of the root of the upper and a file on
/// the way refuse the fresh home as well, with nothing made.
#[test]
fn a_dangling_link_a_linked_upper_or_a_file_on_the_way_refuses_the_fresh_home() {
    let dir = tempfile::tempdir().unwrap();
    let elsewhere = dir.path().join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    let decoy_home = dir.path().join("decoy/home/alice");
    let hidden = dir.path().join("hidden");
    std::fs::create_dir(&hidden).unwrap();
    let upper = hidden.join("upper");
    let refusal = |planted: &Path| {
        let before = stamps(dir.path());
        tick();
        let refused = prepare_fresh_home(&upper.join("home/alice"), &decoy_home, &me(&decoy_home));
        assert_eq!(stamps(dir.path()), before, "{}", planted.display());
        refused.unwrap_err().to_string()
    };

    // The root of the upper is a link: it is opened without following it.
    std::os::unix::fs::symlink(&elsewhere, &upper).unwrap();
    let error = refusal(&upper);
    assert!(
        error.contains(&format!("{} is a symbolic link to", upper.display())),
        "{error}"
    );
    std::fs::remove_file(&upper).unwrap();

    // A link to nothing: followed, it would make the directory it names.
    std::fs::create_dir(&upper).unwrap();
    std::os::unix::fs::symlink(dir.path().join("nowhere"), upper.join("home")).unwrap();
    let error = refusal(&upper.join("home"));
    assert!(error.contains("is a symbolic link to"), "{error}");
    assert!(!dir.path().join("nowhere").exists());
    std::fs::remove_file(upper.join("home")).unwrap();

    // A file, and the whiteout that marks a directory a hidden session
    // deleted (a 0:0 character device, which any user may make since Linux
    // 5.8).
    let not_a_directory = format!(
        "{} is not a directory: the fresh home is made only through directories",
        upper.join("home").display()
    );
    std::fs::write(upper.join("home"), "").unwrap();
    let error = refusal(&upper.join("home"));
    assert!(error.contains(&not_a_directory), "{error}");
    std::fs::remove_file(upper.join("home")).unwrap();
    let whiteout = rustix::fs::mknodat(
        rustix::fs::CWD,
        upper.join("home"),
        rustix::fs::FileType::CharacterDevice,
        Mode::empty(),
        0,
    );
    if whiteout.is_ok() {
        let error = refusal(&upper.join("home"));
        assert!(error.contains(&not_a_directory), "{error}");
    }
}

/// What a hidden session put at the home itself is the hidden home: kept as
/// it is, even a link, which is not followed, so nothing is made where it
/// leads.
#[test]
fn a_link_at_the_home_is_left_as_it_is() {
    let dir = tempfile::tempdir().unwrap();
    let elsewhere = dir.path().join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    let upper_home = dir.path().join("upper/home/alice");
    std::fs::create_dir_all(upper_home.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &upper_home).unwrap();
    let before = stamps(dir.path());
    tick();

    let made = prepare_fresh_home(
        &upper_home,
        &dir.path().join("home/alice"),
        &me(&upper_home),
    )
    .unwrap();

    assert!(!made);
    assert_eq!(stamps(dir.path()), before);
}

/// Any other failure on the way is the kernel's error, for the path it came
/// from: here a name longer than the kernel takes, on the way and at the home,
/// and a file where the directory above the root of the upper should be.
#[test]
fn another_failure_on_the_way_is_the_kernel_s_error() {
    let dir = tempfile::tempdir().unwrap();
    let long = "n".repeat(300);
    for rest in [format!("{long}/alice"), format!("home/{long}")] {
        let upper_home = dir.path().join("upper").join(&rest);
        let error = prepare_fresh_home(
            &upper_home,
            &dir.path().join("decoy").join(&rest),
            &me(&upper_home),
        )
        .unwrap_err();
        assert!(error.io_kind().is_some(), "{rest}: {error}");
        assert!(error.to_string().contains(&long), "{rest}: {error}");
    }

    let file = dir.path().join("file");
    std::fs::write(&file, "").unwrap();
    let upper_home = file.join("upper/home/alice");
    let error = prepare_fresh_home(
        &upper_home,
        &dir.path().join("decoy/home/alice"),
        &me(&upper_home),
    )
    .unwrap_err();
    assert_eq!(
        error.io_kind(),
        Some(std::io::ErrorKind::NotADirectory),
        "{error}"
    );
    assert!(
        error
            .to_string()
            .starts_with(&format!("{}: ", file.display())),
        "{error}"
    );
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
