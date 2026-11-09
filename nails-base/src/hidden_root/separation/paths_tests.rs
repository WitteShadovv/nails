// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Following the paths of the decoy's fstab on `MockFilesystem` fixtures:
//! the links on the way, read one at a time, where a lookup stops, and why
//! a path cannot be followed.

use super::*;
use crate::filesystem::MockFilesystem;
use crate::filesystem::mountinfo::parse_mountinfo;
use crate::fstab::parse_fstab;
use std::io::ErrorKind;

/// The mount table of a plain decoy.
const PLAIN: &str = "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n";

/// Where `path` of the running decoy leads on `fs`, below the mounts of
/// `table`.
fn followed_in(fs: &MockFilesystem, table: &str, path: &str) -> Result<PathBuf, Unfollowed> {
    follow(fs, &parse_mountinfo(table), Path::new("/"), Path::new(path))
}

/// [`followed_in`] the plain decoy.
fn followed(fs: &MockFilesystem, path: &str) -> Result<PathBuf, Unfollowed> {
    followed_in(fs, PLAIN, path)
}

/// A mock filesystem with these links, each `(link, target)`.
fn linked(links: &[(&str, &str)]) -> MockFilesystem {
    let fs = MockFilesystem::new();
    for (link, target) in links {
        fs.create_symlink(Path::new(target), Path::new(link))
            .unwrap();
    }
    fs
}

fn leads(path: &str) -> Result<PathBuf, Unfollowed> {
    Ok(PathBuf::from(path))
}

#[test]
fn a_path_without_links_stays_as_it_is() {
    let fs = MockFilesystem::new();
    for path in ["/srv/x", "/srv/x/sub", "/swapfile", "/"] {
        assert_eq!(followed(&fs, path), leads(path), "{path}");
    }
    // `.` is no step, and `..` goes up from the place reached so far, never
    // above the root.
    assert_eq!(followed(&fs, "/srv/./x/../y/"), leads("/srv/y"));
    assert_eq!(followed(&fs, "/../srv/x"), leads("/srv/x"));
}

#[test]
fn a_link_on_the_way_is_followed_as_mount_follows_it() {
    // A link to the folder, absolute or relative to the folder it lies in,
    // in any part of the path, and a chain of links.
    let fs = linked(&[
        ("/srv/link", "/srv/x"),
        ("/srv/rel", "x"),
        ("/srv/up", "../srv/x"),
        ("/srv/a", "/srv/b"),
        ("/srv/b", "rel/sub"),
        ("/data", "/srv"),
    ]);
    for (path, place) in [
        ("/srv/link", "/srv/x"),
        ("/srv/link/sub", "/srv/x/sub"),
        ("/srv/rel", "/srv/x"),
        ("/srv/up", "/srv/x"),
        ("/srv/a", "/srv/x/sub"),
        ("/data/x", "/srv/x"),
        ("/data/link", "/srv/x"),
        // `..` after a link goes up from where the link leads.
        ("/srv/link/../y", "/srv/y"),
        ("/data/../etc", "/etc"),
    ] {
        assert_eq!(followed(&fs, path), leads(place), "{path}");
    }
}

#[test]
fn a_place_that_is_not_there_ends_the_lookup_with_the_rest_as_written() {
    // No link leads on from a place that is not there.
    let fs = MockFilesystem::new();
    fs.mock_set_mount_root_error("/srv/gone", ErrorKind::NotFound);
    assert_eq!(followed(&fs, "/srv/gone"), leads("/srv/gone"));
    assert_eq!(followed(&fs, "/srv/gone/x"), leads("/srv/gone/x"));
    assert_eq!(followed(&fs, "/srv/gone/../x"), leads("/srv/x"));
    // So past a link that leads to a place that is there.
    let fs = linked(&[("/srv/link", "/srv/x")]);
    fs.mock_set_mount_root_error("/srv/x/new", ErrorKind::NotFound);
    assert_eq!(followed(&fs, "/srv/link/new/sub"), leads("/srv/x/new/sub"));
}

#[test]
fn a_link_that_leads_to_nothing_cannot_be_followed() {
    let fs = linked(&[
        ("/srv/link", "/srv/nothing"),
        ("/srv/chain", "/srv/link"),
        ("/srv/deep", "x/nothing"),
    ]);
    fs.mock_set_mount_root_error("/srv/nothing", ErrorKind::NotFound);
    fs.mock_set_mount_root_error("/srv/x/nothing", ErrorKind::NotFound);
    let dangling = |link: &str| Err(Unfollowed::Dangling(PathBuf::from(link)));
    assert_eq!(followed(&fs, "/srv/link"), dangling("/srv/link"));
    assert_eq!(followed(&fs, "/srv/link/sub"), dangling("/srv/link"));
    // The link named is the one whose target is not there, the last of a
    // chain, also where only the end of the target is missing.
    assert_eq!(followed(&fs, "/srv/chain"), dangling("/srv/link"));
    assert_eq!(followed(&fs, "/srv/deep"), dangling("/srv/deep"));
    assert_eq!(
        Unfollowed::Dangling(PathBuf::from("/srv/link")).reason(),
        "the link /srv/link leads to nothing"
    );
}

#[test]
fn links_that_go_round_cannot_be_followed() {
    let fs = linked(&[("/srv/a", "/srv/b"), ("/srv/b", "a"), ("/srv/self", "self")]);
    assert_eq!(followed(&fs, "/srv/a"), Err(Unfollowed::Loop));
    assert_eq!(followed(&fs, "/srv/self/x"), Err(Unfollowed::Loop));
    // The kernel follows 40 links in one lookup, and fails at the 41st.
    let names: Vec<String> = (0..=41).map(|i| format!("/l{i}")).collect();
    let chain: Vec<(&str, &str)> = names
        .windows(2)
        .map(|pair| (pair[0].as_str(), pair[1].as_str()))
        .collect();
    let fs = linked(&chain);
    assert_eq!(followed(&fs, "/l1"), leads("/l41"));
    assert_eq!(followed(&fs, "/l0"), Err(Unfollowed::Loop));
    assert_eq!(
        Unfollowed::Loop.reason(),
        "the links on its way go round, or are more than the kernel follows"
    );
}

#[test]
fn a_place_that_cannot_be_looked_up_or_a_link_that_cannot_be_read_stops_the_lookup() {
    let fs = MockFilesystem::new();
    fs.mock_set_mount_root_error("/root/x", ErrorKind::PermissionDenied);
    let unreadable = |place: &str| Err(Unfollowed::Unreadable(PathBuf::from(place)));
    assert_eq!(followed(&fs, "/root/x/swapfile"), unreadable("/root/x"));
    // A link whose target cannot be read.
    fs.mock_set_is_symlink("/srv/l", true);
    assert_eq!(followed(&fs, "/srv/l/x"), unreadable("/srv/l"));
    assert_eq!(
        Unfollowed::Unreadable(PathBuf::from("/root/x")).reason(),
        "/root/x on its way could not be looked up"
    );
}

#[test]
fn no_lookup_is_made_that_would_mount_an_automount_point() {
    // A direct automount point nothing is mounted on yet, and a name in the
    // directory of an indirect map, as the mount table shows them, on the
    // way or at the end, through a link too.
    let table = "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n\
                 20 1 0:50 / /data rw - autofs systemd-1 rw,fd=50,pgrp=1,direct\n\
                 21 1 0:51 / /net rw - autofs auto.net rw,fd=51,pgrp=1,indirect\n";
    let fs = linked(&[("/srv/link", "/data/x")]);
    let automount = |point: &str| Err(Unfollowed::Automount(PathBuf::from(point)));
    assert_eq!(followed_in(&fs, table, "/data/x"), automount("/data"));
    assert_eq!(followed_in(&fs, table, "/data"), automount("/data"));
    assert_eq!(followed_in(&fs, table, "/srv/link"), automount("/data"));
    assert_eq!(
        followed_in(&fs, table, "/net/host/x"),
        automount("/net/host")
    );
    // Once a filesystem is mounted there, the lookup goes on.
    let mounted = format!("{table}22 20 8:17 / /data rw - ext4 /dev/sdb1 rw\n");
    assert_eq!(followed_in(&fs, &mounted, "/srv/link"), leads("/data/x"));
    // One that the mount table does not show, as statx says it.
    let fs = MockFilesystem::new();
    fs.mock_set_automount("/media/auto");
    assert_eq!(followed(&fs, "/media/auto/x"), automount("/media/auto"));
    assert_eq!(
        Unfollowed::Automount(PathBuf::from("/data")).reason(),
        "the lookup would mount the automount point /data, which nothing is mounted on yet"
    );
}

#[test]
fn a_path_that_is_not_absolute_cannot_be_followed() {
    let fs = MockFilesystem::new();
    for path in ["srv/x", "none", ""] {
        assert_eq!(followed(&fs, path), Err(Unfollowed::Relative), "{path:?}");
    }
    assert_eq!(Unfollowed::Relative.reason(), "it is no absolute path");
}

#[test]
fn under_another_root_a_link_is_followed_inside_it() {
    let fs = linked(&[
        ("/media/decoy/srv/link", "/srv/x"),
        ("/media/decoy/srv/up", "../../../etc"),
    ]);
    let inside = |path: &str| {
        follow(
            &fs,
            &parse_mountinfo(PLAIN),
            Path::new("/media/decoy"),
            Path::new(path),
        )
    };
    assert_eq!(inside("/srv/link/sub"), leads("/srv/x/sub"));
    // `..` goes no higher than that root.
    assert_eq!(inside("/srv/up"), leads("/etc"));
}

#[test]
fn the_paths_the_claims_place_a_line_by_are_followed_and_no_other() {
    // A bind line's source, under /dev too, and a swap or image file outside
    // /dev; no device line, and no RAM or network line.
    let fstab = parse_fstab(
        "/dev/sda1 / ext4 defaults 0 1\nUUID=f1 /home ext4 defaults 0 2\n\
         /swapfile none swap sw 0 0\n/srv/x /mnt none bind 0 0\n\
         /dev/shm /run/shm none bind 0 0\ntmpfs /tmp tmpfs defaults 0 0\n\
         server:/x /net nfs defaults 0 0\n/srv/img.raw /mnt/img ext4 loop 0 0\n\
         none /srv/y none bind 0 0\n/srv/x /mnt/again none rbind 0 0\n",
    );
    let fs = linked(&[("/swapfile", "/var/swapfile")]);
    let paths = follow_all(&fs, &parse_mountinfo(PLAIN), Path::new("/"), &fstab);
    assert_eq!(
        paths.keys().map(String::as_str).collect::<Vec<_>>(),
        ["/dev/shm", "/srv/img.raw", "/srv/x", "/swapfile", "none"]
    );
    assert_eq!(paths["/swapfile"], leads("/var/swapfile"));
    assert_eq!(paths["/srv/x"], leads("/srv/x"));
    assert_eq!(paths["none"], Err(Unfollowed::Relative));
}

#[test]
fn on_a_real_filesystem_the_lookup_follows_links_and_stops_as_the_kernel_does() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let at = dir.path().canonicalize().unwrap();
    std::fs::create_dir_all(at.join("x/sub")).unwrap();
    symlink(at.join("x"), at.join("absolute")).unwrap();
    symlink("x/sub", at.join("relative")).unwrap();
    symlink("relative", at.join("chain")).unwrap();
    symlink(at.join("nothing"), at.join("dangling")).unwrap();
    symlink("round", at.join("round")).unwrap();
    let fs = crate::filesystem::RealFilesystem;
    let follow_real = |path: &str| follow(&fs, &[], Path::new("/"), &at.join(path));
    assert_eq!(follow_real("absolute/sub"), Ok(at.join("x/sub")));
    assert_eq!(follow_real("chain"), Ok(at.join("x/sub")));
    assert_eq!(follow_real("x/missing/y"), Ok(at.join("x/missing/y")));
    assert_eq!(
        follow_real("dangling"),
        Err(Unfollowed::Dangling(at.join("dangling")))
    );
    assert_eq!(follow_real("round"), Err(Unfollowed::Loop));
}
