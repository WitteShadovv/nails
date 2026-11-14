// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::filesystem::MockFilesystem;

/// A mock filesystem with each `(link, target)` a symbolic link.
fn linked(links: &[(&str, &str)]) -> MockFilesystem {
    let fs = MockFilesystem::new();
    for (link, target) in links {
        fs.create_symlink(Path::new(target), Path::new(link))
            .unwrap();
    }
    fs
}

fn follow(fs: &MockFilesystem, path: &str) -> Result<PathBuf, OutOfDev> {
    follow_in_dev(fs, Path::new(path))
}

#[test]
fn a_udev_name_leads_to_its_node_in_dev() {
    // udev's links are relative, `..` included, and lead to the node.
    let fs = linked(&[
        ("/dev/disk/by-uuid/abcd", "../../sdc"),
        ("/dev/mapper/data", "../dm-9"),
        ("/dev/disk/by-label/keys", "/dev/disk/by-uuid/abcd"),
        ("/dev/back", "../dev/sdb"),
    ]);
    for (path, node) in [
        ("/dev/disk/by-uuid/abcd", "/dev/sdc"),
        ("/dev/mapper/data", "/dev/dm-9"),
        ("/dev/disk/by-label/keys", "/dev/sdc"),
        ("/dev/back", "/dev/sdb"),
        ("/dev/sdb", "/dev/sdb"),
        ("/dev/./mapper//data", "/dev/dm-9"),
    ] {
        assert_eq!(follow(&fs, path), Ok(PathBuf::from(node)), "{path}");
    }
}

#[test]
fn a_link_that_leads_out_of_dev_is_not_followed() {
    // A lookup of /mnt or /tmp here would fail: the walk makes none, and
    // stops at the link that leads there, whatever lies past it, a link
    // back into /dev too.
    let fs = linked(&[
        ("/dev/box.link", "/mnt/box.img"),
        ("/dev/shm/box.link", "/mnt/box.img"),
        ("/dev/f.link", "../srv/f.img"),
        ("/dev/out.link", "/tmp/back"),
        ("/tmp/back", "/dev/sdb"),
        ("/dev/a", "/dev/b/c"),
        ("/dev/b", "/mnt"),
        ("/dev/up", ".."),
    ]);
    for place in ["/mnt", "/tmp", "/srv"] {
        fs.mock_set_mount_root_error(place, std::io::ErrorKind::PermissionDenied);
    }
    for (path, link) in [
        ("/dev/box.link", "/dev/box.link"),
        ("/dev/shm/box.link", "/dev/shm/box.link"),
        ("/dev/f.link", "/dev/f.link"),
        ("/dev/out.link", "/dev/out.link"),
        ("/dev/a", "/dev/b"),
        ("/dev/up", "/dev/up"),
        ("/dev/box.link/x", "/dev/box.link"),
    ] {
        assert_eq!(
            follow(&fs, path),
            Err(OutOfDev::Leaves(PathBuf::from(link))),
            "{path}"
        );
    }
    // The link /dev/out.link leads back to the drive through a link on the
    // disk, which a lookup that follows every link would read.
    assert_eq!(
        fs.canonicalize(Path::new("/dev/out.link")).unwrap(),
        Path::new("/dev/sdb")
    );
}

#[test]
fn a_path_out_of_dev_or_one_that_cannot_be_looked_up_leads_nowhere() {
    let fs = linked(&[
        ("/dev/loop.link", "/dev/loop.link"),
        ("/dev/disk/by-uuid/gone", "../../sdz9"),
    ]);
    fs.mock_set_mount_root_error("/dev/sdz9", std::io::ErrorKind::NotFound);
    fs.mock_set_mount_root_error("/dev/null/x", std::io::ErrorKind::NotADirectory);
    fs.mock_set_mount_root_error("/dev/locked", std::io::ErrorKind::PermissionDenied);
    fs.mock_set_automount("/dev/auto");
    fs.mock_set_is_symlink("/dev/odd", true);
    for path in ["/srv/x", "dev/sdb", "/dev/../srv", "/devices/x"] {
        assert_eq!(follow(&fs, path), Err(OutOfDev::NotInDev), "{path}");
    }
    for path in ["/dev/disk/by-uuid/gone", "/dev/null/x"] {
        assert_eq!(follow(&fs, path), Err(OutOfDev::Missing), "{path}");
    }
    assert_eq!(
        follow(&fs, "/dev/loop.link"),
        Err(OutOfDev::Unreadable(PathBuf::from("/dev/loop.link")))
    );
    for (path, part) in [("/dev/locked/x", "/dev/locked"), ("/dev/odd", "/dev/odd")] {
        assert_eq!(
            follow(&fs, path),
            Err(OutOfDev::Unreadable(PathBuf::from(part))),
            "{path}"
        );
    }
    assert_eq!(
        follow(&fs, "/dev/auto/x"),
        Err(OutOfDev::Automount(PathBuf::from("/dev/auto")))
    );
}

#[test]
fn on_a_real_filesystem_a_node_is_found_and_a_missing_name_is_missing() {
    let fs = crate::filesystem::RealFilesystem;
    assert_eq!(
        follow_in_dev(&fs, Path::new("/dev/null")),
        Ok(PathBuf::from("/dev/null"))
    );
    for path in ["/dev/nails-no-such-device", "/dev/null/x"] {
        assert_eq!(
            follow_in_dev(&fs, Path::new(path)),
            Err(OutOfDev::Missing),
            "{path}"
        );
    }
}
