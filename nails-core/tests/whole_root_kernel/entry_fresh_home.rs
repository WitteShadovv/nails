// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The fresh home and a link a hidden session left in an upper, against the
//! whole entry on real mounts. A hidden session replaced `/home` in the root
//! upper, or a directory below a separate `/home` on the way to the operator's
//! home in that filesystem's upper, with a symbolic link, absolute or
//! relative, to a directory of the decoy. Followed, it would take the new
//! home, its mode, owner and opaque attribute onto the decoy disk. The
//! fresh-home entry is refused instead and undone, and nothing on the decoy or
//! on the hidden volume is made or changed, not even a time. Once a directory
//! stands there again, an entry goes on.

use super::{FakeHost, World};
use nails_core::config::PersonaMode;
use nails_core::session::entry;
use nails_core::session::layout::{Layout, Paths};
use nails_core::test_path;
use nails_core::test_support::Rerun;
use nails_teardown::mountinfo::read_mountinfo;
use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Every entry at and below `dir`, with what a change to it moves: its type
/// and mode, owner, size, modification and status change times, and a link's
/// target or a file's contents. Access times are left out, since the test
/// reads the tree itself.
fn snapshot(dir: &Path) -> BTreeMap<PathBuf, String> {
    let mut out = BTreeMap::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(current) = pending.pop() {
        let meta = std::fs::symlink_metadata(&current).unwrap();
        let mut what = format!(
            "{:o} {}:{} {} {}.{} {}.{}",
            meta.mode(),
            meta.uid(),
            meta.gid(),
            meta.size(),
            meta.mtime(),
            meta.mtime_nsec(),
            meta.ctime(),
            meta.ctime_nsec()
        );
        if meta.file_type().is_symlink() {
            let target = std::fs::read_link(&current).unwrap();
            what.push_str(&format!(" -> {}", target.display()));
        } else if meta.is_dir() {
            for entry in std::fs::read_dir(&current).unwrap() {
                pending.push(entry.unwrap().path());
            }
        } else if meta.is_file() {
            what.push_str(&format!(" {:?}", std::fs::read(&current).unwrap()));
        }
        out.insert(current.strip_prefix(dir).unwrap().to_path_buf(), what);
    }
    out
}

/// A link target that leads from the directory `from` to `to` by `..` up to
/// `/` and down again.
fn relative(from: &Path, to: &Path) -> PathBuf {
    let from = from.canonicalize().unwrap();
    let mut out: PathBuf = from.components().skip(1).map(|_| "..").collect();
    out.push(to.canonicalize().unwrap().strip_prefix("/").unwrap());
    out
}

/// The operator `name`, who runs the tests, with the home `home`.
fn operator(name: &str, home: &str) -> nails_core::TargetUser {
    nails_core::TargetUser::for_test(
        nix::unistd::getuid().as_raw(),
        nix::unistd::getgid().as_raw(),
        name,
        home,
        "/bin/sh",
    )
}

/// Whether anything is mounted at or below the next root of `paths`.
fn next_root_mounted(paths: &Paths) -> bool {
    read_mountinfo()
        .unwrap()
        .iter()
        .any(|e| e.mount_point.starts_with(paths.nextroot()))
}

/// Put a link at `at` in an upper that leads to `target` on the decoy, by its
/// absolute path or by a relative one. Returns what the link holds.
fn link(at: &Path, target: &Path, relative_link: bool) -> PathBuf {
    let above = at.parent().unwrap();
    std::fs::create_dir_all(above).unwrap();
    let held = if relative_link {
        relative(above, target)
    } else {
        target.to_path_buf()
    };
    std::os::unix::fs::symlink(&held, at).unwrap();
    held
}

/// The fresh-home entry of `world` for `operator`, which must be refused at
/// `link`, a link to `target`: undone, and with nothing on the decoy or the
/// hidden volume made or changed.
fn refused_at(world: &World, operator: nails_core::TargetUser, link: &Path, target: &Path) {
    let paths = world.paths();
    let mut inputs = world.inputs();
    inputs.persona.mode = PersonaMode::FreshHome;
    inputs.operator = Some(operator);
    let decoy = snapshot(world.decoy.path());
    let hidden = snapshot(world.hidden.path());
    // Long enough for a change to move a time.
    std::thread::sleep(Duration::from_millis(20));

    let refused = entry::prepare(&paths, &inputs, &FakeHost::default());

    assert_eq!(snapshot(world.decoy.path()), decoy, "the decoy changed");
    assert_eq!(
        snapshot(world.hidden.path()),
        hidden,
        "the hidden volume changed"
    );
    let error = refused.expect_err("the entry is refused");
    let named = format!(
        "{} is a symbolic link to {}: ",
        link.display(),
        target.display()
    );
    assert!(error.to_string().contains(&named), "{error}");
    assert!(!next_root_mounted(&paths));
    assert!(!paths.runtime().exists());
}

/// The fresh-home entry of `world` for `operator`, which must go on, with
/// `home` in the next root the one in the upper at `upper_home`.
fn goes_on(world: &World, operator: nails_core::TargetUser, home: &str, upper_home: &Path) {
    let paths = world.paths();
    let mut inputs = world.inputs();
    inputs.persona.mode = PersonaMode::FreshHome;
    inputs.operator = Some(operator);
    std::fs::write(upper_home.join("hidden-file"), "hidden").unwrap();

    entry::prepare(&paths, &inputs, &FakeHost::default()).expect("the entry");

    let in_next_root = paths.nextroot().join(home.trim_start_matches('/'));
    assert_eq!(
        std::fs::read_to_string(in_next_root.join("hidden-file")).unwrap(),
        "hidden"
    );
    entry::rollback(&paths);
}

#[test]
fn a_link_in_place_of_home_in_the_root_upper_refuses_the_fresh_home_entry() {
    let _ = Rerun::new(test_path!(
        a_link_in_place_of_home_in_the_root_upper_refuses_the_fresh_home_entry
    ))
    .in_user_mount_ns()
    .run(|| {
        for relative_link in [false, true] {
            // `/home` on the decoy's root filesystem, alice's home in it.
            let world = World::new();
            nix::mount::umount2(
                &world.decoy.path().join("home"),
                nix::mount::MntFlags::MNT_DETACH,
            )
            .unwrap();
            world.decoy.mkdir("home/alice");
            let elsewhere = world.decoy.path().join("srv/data");
            let upper_link = Layout::new(world.hidden.path()).upper().join("home");
            let held = link(&upper_link, &elsewhere, relative_link);

            refused_at(&world, operator("alice", "/home/alice"), &upper_link, &held);

            // A directory there again, with the home an earlier entry made.
            std::fs::remove_file(&upper_link).unwrap();
            let upper_home = upper_link.join("alice");
            std::fs::create_dir_all(&upper_home).unwrap();
            goes_on(
                &world,
                operator("alice", "/home/alice"),
                "/home/alice",
                &upper_home,
            );
        }
    });
}

#[test]
fn a_link_on_the_way_to_the_home_in_the_upper_of_a_separate_home_refuses_the_entry() {
    let _ = Rerun::new(test_path!(
        a_link_on_the_way_to_the_home_in_the_upper_of_a_separate_home_refuses_the_entry
    ))
    .in_user_mount_ns()
    .run(|| {
        for relative_link in [false, true] {
            // bob's home lies below /home/staff, on the decoy's separate /home.
            let world = World::new();
            world.decoy.mkdir("home/staff/bob");
            let elsewhere = world.decoy.path().join("srv/data");
            let upper_link = Layout::new(world.hidden.path())
                .mount_layers(Path::new("/home"))
                .0
                .join("staff");
            let held = link(&upper_link, &elsewhere, relative_link);

            refused_at(
                &world,
                operator("bob", "/home/staff/bob"),
                &upper_link,
                &held,
            );

            std::fs::remove_file(&upper_link).unwrap();
            let upper_home = upper_link.join("bob");
            std::fs::create_dir_all(&upper_home).unwrap();
            goes_on(
                &world,
                operator("bob", "/home/staff/bob"),
                "/home/staff/bob",
                &upper_home,
            );
        }
    });
}
