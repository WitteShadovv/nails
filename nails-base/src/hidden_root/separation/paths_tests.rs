// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Reading the paths of the decoy's fstab on `MockFilesystem` fixtures and
//! on a real one: each part looked at on its own, no link followed, and why
//! where a path lies cannot be told.

use super::*;
use crate::crypttab::parse_crypttab;
use crate::filesystem::MockFilesystem;
use crate::filesystem::mountinfo::parse_mountinfo;
use crate::fstab::parse_fstab;
use std::io::ErrorKind;

/// The mount table of a plain decoy.
const PLAIN: &str = "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n";

/// `path` of the running decoy as it reads on `fs`, below the mounts of
/// `table`, with the boot's folders `unmounted` not mounted now.
fn read_in(
    fs: &MockFilesystem,
    table: &str,
    unmounted: &[&str],
    path: &str,
) -> Result<PathBuf, UntoldPath> {
    let unmounted: Vec<PathBuf> = unmounted.iter().map(PathBuf::from).collect();
    read(
        fs,
        &parse_mountinfo(table),
        Path::new("/"),
        &unmounted,
        Path::new(path),
    )
}

/// [`read_in`] the plain decoy, every folder the boot mounts mounted.
fn read_plain(fs: &MockFilesystem, path: &str) -> Result<PathBuf, UntoldPath> {
    read_in(fs, PLAIN, &[], path)
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

fn reads(path: &str) -> Result<PathBuf, UntoldPath> {
    Ok(PathBuf::from(path))
}

fn link(at: &str) -> Result<PathBuf, UntoldPath> {
    Err(UntoldPath::Link(PathBuf::from(at)))
}

#[test]
fn a_path_without_links_reads_as_it_is_written() {
    let fs = MockFilesystem::new();
    for path in ["/srv/x", "/srv/x/sub", "/swapfile", "/"] {
        assert_eq!(read_plain(&fs, path), reads(path), "{path}");
    }
    // `.` is no part, and `..` goes back up a part as written, never above
    // the root: with no link on the way that is where the kernel goes too.
    assert_eq!(read_plain(&fs, "/srv/./x/../y/"), reads("/srv/y"));
    assert_eq!(read_plain(&fs, "/../srv/x"), reads("/srv/x"));
    let written = |path: &str| as_written(Path::new(path));
    assert_eq!(written("/srv/./x/../y/"), Some(PathBuf::from("/srv/y")));
    assert_eq!(written("/../srv"), Some(PathBuf::from("/srv")));
    assert_eq!(written("srv/x"), None);
}

#[test]
fn a_link_in_any_part_of_the_path_is_not_followed() {
    // A link at the end, in a parent folder, one whose target is not there
    // and one that leads to itself: none is read, so the first link on the
    // way is what the path holds, wherever it leads.
    let fs = linked(&[
        ("/srv/link", "/srv/x"),
        ("/data", "/srv"),
        ("/srv/gone", "/srv/nothing"),
        ("/srv/self", "self"),
    ]);
    fs.mock_set_mount_root_error("/srv/nothing", ErrorKind::NotFound);
    for (path, at) in [
        ("/srv/link", "/srv/link"),
        ("/srv/link/sub", "/srv/link"),
        ("/data/x", "/data"),
        ("/data/link", "/data"),
        ("/srv/gone", "/srv/gone"),
        ("/srv/self/x", "/srv/self"),
        // Also where a `..` would lead back out of what the link names.
        ("/srv/link/../y", "/srv/link"),
    ] {
        assert_eq!(read_plain(&fs, path), link(at), "{path}");
    }
    // A path that only passes beside a link has none in it.
    assert_eq!(read_plain(&fs, "/srv/x/sub"), reads("/srv/x/sub"));
    assert_eq!(
        UntoldPath::Link(PathBuf::from("/srv/link")).reason(),
        "/srv/link is a symbolic link, which NAILS does not follow"
    );
}

#[test]
fn a_part_that_is_not_there_ends_the_looking_until_a_dot_dot_leads_back() {
    // What is not there holds no link, so the rest reads as written.
    let fs = MockFilesystem::new();
    fs.mock_set_mount_root_error("/srv/gone", ErrorKind::NotFound);
    assert_eq!(read_plain(&fs, "/srv/gone"), reads("/srv/gone"));
    assert_eq!(read_plain(&fs, "/srv/gone/x"), reads("/srv/gone/x"));
    assert_eq!(read_plain(&fs, "/srv/gone/../x"), reads("/srv/x"));
    // Back at a place that is there, each part is looked at again: a link
    // there is one, also two levels down.
    let fs = linked(&[("/srv/link", "/srv/x")]);
    fs.mock_set_mount_root_error("/srv/gone", ErrorKind::NotFound);
    assert_eq!(read_plain(&fs, "/srv/gone/../link"), link("/srv/link"));
    assert_eq!(read_plain(&fs, "/srv/gone/a/../../link"), link("/srv/link"));
    assert_eq!(read_plain(&fs, "/srv/gone/link/.."), reads("/srv/gone"));
}

#[test]
fn a_path_that_is_a_device_node_cannot_be_told() {
    // swapon and mount use a device node as the device it is, wherever it
    // lies, outside /dev too. Only the path itself is asked: a device node
    // on the way is no folder, and a lookup below it fails.
    let fs = MockFilesystem::new();
    fs.mock_set_device_node("/srv/node");
    fs.mock_set_device_node("/dev/null");
    assert_eq!(
        read_plain(&fs, "/srv/node"),
        Err(UntoldPath::Device(PathBuf::from("/srv/node")))
    );
    assert_eq!(
        read_plain(&fs, "/dev/../srv/node"),
        Err(UntoldPath::Device(PathBuf::from("/srv/node")))
    );
    assert_eq!(
        read_plain(&fs, "/dev/null"),
        Err(UntoldPath::Device(PathBuf::from("/dev/null")))
    );
    fs.mock_set_mount_root_error("/srv/node/x", ErrorKind::NotADirectory);
    assert_eq!(
        read_plain(&fs, "/srv/node/x"),
        Err(UntoldPath::Unreadable(PathBuf::from("/srv/node/x")))
    );
    // A link to a device node is a link, and nothing that is not there is
    // asked.
    let fs = linked(&[("/swap.link", "/dev/sdb")]);
    fs.mock_set_device_node("/dev/sdb");
    assert_eq!(read_plain(&fs, "/swap.link"), link("/swap.link"));
    fs.mock_set_mount_root_error("/srv/gone", ErrorKind::NotFound);
    fs.mock_set_device_node("/srv/gone/node");
    assert_eq!(read_plain(&fs, "/srv/gone/node"), reads("/srv/gone/node"));
    assert_eq!(
        UntoldPath::Device(PathBuf::from("/srv/node")).reason(),
        "/srv/node is a device node"
    );
}

#[test]
fn a_path_that_crosses_a_folder_the_boot_mounts_but_is_not_mounted_cannot_be_told() {
    // What lies there at boot is on the filesystem the boot mounts, which
    // cannot be read now: at the folder, below it, through a `..` that comes
    // back out of it, and where nothing is there now.
    let fs = MockFilesystem::new();
    fs.mock_set_mount_root_error("/backup/link", ErrorKind::NotFound);
    let unmounted = Err(UntoldPath::Unmounted(PathBuf::from("/backup")));
    for path in [
        "/backup",
        "/backup/link",
        "/backup/link/x",
        "/backup/../srv/x",
    ] {
        assert_eq!(read_in(&fs, PLAIN, &["/backup"], path), unmounted, "{path}");
    }
    // A link before that folder is the first thing on the way.
    let fs = linked(&[("/srv/l", "/backup")]);
    assert_eq!(
        read_in(&fs, PLAIN, &["/srv/l/x"], "/srv/l/x"),
        link("/srv/l")
    );
    // A path that does not cross it reads as written.
    assert_eq!(
        read_in(&fs, PLAIN, &["/backup"], "/backups/x"),
        reads("/backups/x")
    );
    assert_eq!(
        UntoldPath::Unmounted(PathBuf::from("/backup")).reason(),
        "a line of /etc/fstab mounts /backup, and that mount is not there now"
    );
}

#[test]
fn a_part_that_cannot_be_looked_up_stops_the_reading() {
    let fs = MockFilesystem::new();
    fs.mock_set_mount_root_error("/root/x", ErrorKind::PermissionDenied);
    assert_eq!(
        read_plain(&fs, "/root/x/swapfile"),
        Err(UntoldPath::Unreadable(PathBuf::from("/root/x")))
    );
    assert_eq!(
        UntoldPath::Unreadable(PathBuf::from("/root/x")).reason(),
        "/root/x on its way could not be looked up"
    );
}

#[test]
fn no_lookup_is_made_that_would_mount_an_automount_point() {
    // A direct automount point nothing is mounted on yet, and a name in the
    // directory of an indirect map, as the mount table shows them, on the
    // way or at the end.
    let table = "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n\
                 20 1 0:50 / /data rw - autofs systemd-1 rw,fd=50,pgrp=1,direct\n\
                 21 1 0:51 / /net rw - autofs auto.net rw,fd=51,pgrp=1,indirect\n";
    let fs = MockFilesystem::new();
    let automount = |point: &str| Err(UntoldPath::Automount(PathBuf::from(point)));
    assert_eq!(read_in(&fs, table, &[], "/data/x"), automount("/data"));
    assert_eq!(read_in(&fs, table, &[], "/data"), automount("/data"));
    assert_eq!(
        read_in(&fs, table, &[], "/net/host/x"),
        automount("/net/host")
    );
    // Once a filesystem is mounted there, the reading goes on.
    let mounted = format!("{table}22 20 8:17 / /data rw - ext4 /dev/sdb1 rw\n");
    assert_eq!(read_in(&fs, &mounted, &[], "/data/x"), reads("/data/x"));
    // One that the mount table does not show, as statx says it.
    fs.mock_set_automount("/media/auto");
    assert_eq!(read_plain(&fs, "/media/auto/x"), automount("/media/auto"));
    assert_eq!(
        UntoldPath::Automount(PathBuf::from("/data")).reason(),
        "the lookup would mount the automount point /data, which nothing is mounted on yet"
    );
}

#[test]
fn a_path_that_is_not_absolute_cannot_be_told() {
    let fs = MockFilesystem::new();
    for path in ["srv/x", "swapfile", "none", ""] {
        assert_eq!(read_plain(&fs, path), Err(UntoldPath::Relative), "{path:?}");
    }
    assert_eq!(UntoldPath::Relative.reason(), "it is no absolute path");
    assert_eq!(UntoldPath::NotLookedUp.reason(), "it was not looked up");
}

#[test]
fn under_another_root_each_part_is_read_inside_it() {
    let fs = linked(&[("/media/decoy/srv/link", "/srv/x")]);
    let inside = |path: &str| {
        read(
            &fs,
            &parse_mountinfo(PLAIN),
            Path::new("/media/decoy"),
            &[],
            Path::new(path),
        )
    };
    assert_eq!(inside("/srv/link/sub"), link("/srv/link"));
    assert_eq!(inside("/srv/x"), reads("/srv/x"));
    // `..` goes no higher than that root.
    assert_eq!(inside("/srv/../../../etc"), reads("/etc"));
}

#[test]
fn the_paths_the_claims_place_a_line_by_are_read_and_no_other() {
    // A bind line's source, under /dev too, relative too and of any type, a
    // swap or image file outside /dev, and a path under /dev that `..` leads
    // out of. No device line, tag, RAM or network line other than a bind
    // line, no line whose type names its source otherwise, as a ZFS
    // dataset's does, and no relative first field of a swap, loop or device
    // line, which makes the line one that is not plain.
    let fstab = parse_fstab(
        "/dev/sda1 / ext4 defaults 0 1\nUUID=f1 /home ext4 defaults 0 2\n\
         /swapfile none swap sw 0 0\n/srv/x /mnt none bind 0 0\n\
         /dev/shm /run/shm none bind 0 0\ntmpfs /tmp tmpfs defaults 0 0\n\
         server:/x /net nfs defaults 0 0\n/srv/img.raw /mnt/img ext4 loop 0 0\n\
         none /srv/y none bind 0 0\n/srv/x /mnt/again none rbind 0 0\n\
         swapfile none swap sw 0 0\nsrv/a.img /mnt/a ext4 loop 0 0\n\
         srv/b.img /mnt/b ext4 defaults 0 0\nsrv/c.img /mnt/c auto loop=/dev/loop7 0 0\n\
         rpool/data /data zfs defaults 0 0\nLABEL=swap none swap sw 0 0\n\
         /dev/../srv/node none swap sw 0 0\n/dev/sdb2 none swap sw 0 0\n\
         /srv/t /mnt/t tmpfs bind 0 0\n/srv/n /mnt/n none bind,_netdev 0 0\n\
         /srv/swap.img none swap sw,_netdev 0 0\n",
    );
    let fs = linked(&[("/swapfile", "/var/swapfile")]);
    let paths = read_all(
        &fs,
        &parse_mountinfo(PLAIN),
        Path::new("/"),
        &fstab,
        &[],
        &DeviceMap::default(),
    );
    assert_eq!(
        paths.keys().map(String::as_str).collect::<Vec<_>>(),
        [
            "/dev/../srv/node",
            "/dev/shm",
            "/srv/img.raw",
            "/srv/n",
            "/srv/swap.img",
            "/srv/t",
            "/srv/x",
            "/swapfile",
            "none",
        ]
    );
    assert_eq!(paths["/swapfile"], link("/swapfile"));
    assert_eq!(paths["/srv/x"], reads("/srv/x"));
    assert_eq!(paths["/dev/../srv/node"], reads("/srv/node"));
    assert_eq!(paths["none"], Err(UntoldPath::Relative));
}

#[test]
fn a_fuse_program_named_by_its_path_is_read_as_well() {
    // The program a FUSE line names by an absolute path, before the # of a
    // `fuse` line or in a `fuse.<program>` or `fuseblk.<program>` type. No
    // program named by its name alone, which PATH finds, and none with a
    // relative path, which makes the line one that is not plain.
    let fstab = parse_fstab(
        "/dev/sda1 / ext4 defaults 0 1\n/srv/prog#/tmp/y /media/b fuse nofail 0 0\n\
         /tmp/z /media/c fuse./srv/prog2 nofail 0 0\n/tmp/w /media/d fuseblk./srv/prog3 nofail 0 0\n\
         bindfs#/srv/q /media/q fuse nofail 0 0\nsrv/rel#/tmp/v /media/r fuse nofail 0 0\n\
         /tmp/u /media/u fuse3./srv/prog4 nofail 0 0\n/srv/link/prog#/tmp/y /media/l fuse nofail 0 0\n",
    );
    let fs = linked(&[("/srv/link", "/srv/x")]);
    let paths = read_all(
        &fs,
        &parse_mountinfo(PLAIN),
        Path::new("/"),
        &fstab,
        &[],
        &DeviceMap::default(),
    );
    assert_eq!(
        paths.keys().map(String::as_str).collect::<Vec<_>>(),
        [
            "/srv/link/prog",
            "/srv/prog",
            "/srv/prog2",
            "/srv/prog3",
            "/srv/q",
            "/tmp/u",
            "/tmp/v",
            "/tmp/w",
            "/tmp/y",
            "/tmp/z",
        ]
    );
    assert_eq!(paths["/srv/prog"], reads("/srv/prog"));
    assert_eq!(paths["/srv/link/prog"], link("/srv/link"));
}

#[test]
fn a_crypttab_file_is_read_as_well() {
    // The file a crypttab line opens: any absolute source that is no
    // device's path in /dev, such as `//dev/sdb` or a link. No tag, device
    // path or relative source, and no key file.
    let crypttab = parse_crypttab(
        "vault //dev/sdb none luks\nbox /srv/box.img /srv/key luks\ndata /dev/sdc none luks\n\
         root UUID=e1 none luks\nrel dev/sdd none luks\nlinked /sdb.link none luks\n\
         up /dev/../srv/up.img none luks\n",
    );
    let fs = linked(&[("/sdb.link", "/dev/sdb")]);
    fs.mock_set_device_node("/dev/sdb");
    let mut devices = DeviceMap::default();
    devices
        .by_spec
        .insert("/dev/sdc".to_string(), "sdc".to_string());
    let paths = read_all(
        &fs,
        &parse_mountinfo(PLAIN),
        Path::new("/"),
        &[],
        &crypttab,
        &devices,
    );
    assert_eq!(
        paths.keys().map(String::as_str).collect::<Vec<_>>(),
        [
            "//dev/sdb",
            "/dev/../srv/up.img",
            "/sdb.link",
            "/srv/box.img"
        ]
    );
    assert_eq!(paths["/srv/box.img"], reads("/srv/box.img"));
    assert_eq!(paths["/dev/../srv/up.img"], reads("/srv/up.img"));
    assert_eq!(paths["/sdb.link"], link("/sdb.link"));
    assert_eq!(
        paths["//dev/sdb"],
        Err(UntoldPath::Device(PathBuf::from("/dev/sdb")))
    );
}

#[test]
fn a_device_path_that_leads_out_of_dev_cannot_be_told() {
    // A link in /dev, as a tmpfiles.d line can make at boot, to a file
    // elsewhere: mount, swapon and systemd-cryptsetup open that file. A
    // device's path that no block device answers to is read for that alone,
    // of a line that is no bind line or of a crypttab line, and one that
    // stays in /dev, or a device the map holds, is no path to tell.
    let fstab = parse_fstab(
        "/dev/sda1 / ext4 defaults 0 1\n/dev/img.link /media/i ext4 loop,nofail 0 0\n\
         /dev/sdz1 /media/z ext4 nofail 0 0\nfuse2fs#/dev/f.link /media/f fuse nofail 0 0\n\
         /dev/disk/by-uuid/e1 /media/e ext4 nofail 0 0\n/dev/loop.link /media/l ext4 nofail 0 0\n",
    );
    let crypttab = parse_crypttab("box /dev/box.link none luks\nvault /dev/sdb none luks\n");
    let fs = linked(&[
        ("/dev/img.link", "/srv/img.raw"),
        ("/dev/f.link", "../srv/f.img"),
        ("/dev/box.link", "/srv/box.img"),
        ("/dev/disk/by-uuid/e1", "../../sdb1"),
        ("/dev/loop.link", "/dev/loop.link"),
    ]);
    let mut devices = DeviceMap::default();
    devices
        .by_spec
        .insert("/dev/sdb".to_string(), "sdb".to_string());
    let paths = read_all(
        &fs,
        &parse_mountinfo(PLAIN),
        Path::new("/"),
        &fstab,
        &crypttab,
        &devices,
    );
    let leaves = |spec: &str| Err(UntoldPath::LeavesDev(PathBuf::from(spec)));
    assert_eq!(paths["/dev/img.link"], leaves("/dev/img.link"));
    assert_eq!(paths["/dev/f.link"], leaves("/dev/f.link"));
    assert_eq!(paths["/dev/box.link"], leaves("/dev/box.link"));
    assert_eq!(
        paths["/dev/loop.link"],
        Err(UntoldPath::Unreadable(PathBuf::from("/dev/loop.link")))
    );
    for spec in ["/dev/sdz1", "/dev/disk/by-uuid/e1", "/dev/sdb"] {
        assert!(!paths.contains_key(spec), "{spec}");
    }
    assert!(is_untold_device(&paths, "/dev/img.link"));
    assert!(!is_untold_device(&paths, "/dev/sdz1"));
}

#[test]
fn on_a_real_filesystem_a_device_path_that_stays_in_dev_or_is_not_there_is_none() {
    // /dev/null stays in /dev, a missing name is not there, and a name below
    // a device node is no folder: none of them leads out of /dev.
    let fs = crate::filesystem::RealFilesystem;
    for spec in ["/dev/null", "/dev/nails-no-such-device", "/dev/null/x"] {
        assert_eq!(leaving_dev(&fs, spec), None, "{spec}");
    }
}

#[test]
fn the_paths_are_read_with_the_folders_of_lines_that_are_not_mounted() {
    // /backup is the folder of a line the boot mounts whose drive is not
    // mounted now, and /srv/n that of a noauto line, which systemd mounts
    // for a bind line's source below it: both count.
    let fstab = parse_fstab(
        "/dev/sda1 / ext4 defaults 0 1\n/dev/sdc1 /backup ext4 defaults,nofail 0 2\n\
         /dev/sdd1 /srv/n ext4 noauto 0 0\n/backup/link /mnt none bind 0 0\n\
         /srv/n/x /srv/y none bind 0 0\n",
    );
    let paths = read_all(
        &MockFilesystem::new(),
        &parse_mountinfo(PLAIN),
        Path::new("/"),
        &fstab,
        &[],
        &DeviceMap::default(),
    );
    assert_eq!(
        paths["/backup/link"],
        Err(UntoldPath::Unmounted(PathBuf::from("/backup")))
    );
    assert_eq!(
        paths["/srv/n/x"],
        Err(UntoldPath::Unmounted(PathBuf::from("/srv/n")))
    );
}

#[test]
fn a_folder_of_a_line_is_mounted_while_a_mount_its_line_makes_is_there() {
    // The mount of a device line is one of its device that shows what it
    // mounts, `_netdev` or not, a bind line's, of any type, a bind of its
    // source's folder, and the mount of another RAM, kernel or network
    // line any mount there, as systemd mounts /dev/shm before the fstab's
    // line for it. A noauto line's folder counts too. The line for / and a
    // swap line have no such folder, and a folder reads with no `.` or `..`,
    // as systemd mounts it.
    let table = "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n\
                 2 1 8:2 / /home rw - ext4 /dev/sda2 rw\n\
                 3 1 8:1 /srv/data /data rw - ext4 /dev/sda1 rw\n\
                 4 1 0:30 / /dev/shm rw - tmpfs tmpfs rw\n\
                 5 1 8:2 /other /backup rw - ext4 /dev/sda2 rw\n\
                 6 1 0:31 / /srv/t rw - tmpfs tmpfs rw\n\
                 7 1 0:32 / /srv/u rw - tmpfs tmpfs rw\n";
    let fstab = parse_fstab(
        "/dev/sda1 / ext4 defaults 0 1\n/dev/sda2 /home ext4 defaults 0 2\n\
         /srv/data /data none bind 0 0\nnone /dev/shm tmpfs defaults 0 0\n\
         /dev/sda2 /backup ext4 defaults 0 2\nserver:/x /net nfs defaults 0 0\n\
         /srv/elsewhere /srv/b none bind 0 0\n/dev/sdz1 /srv/c ext4 noauto 0 0\n\
         /swapfile none swap sw 0 0\n/dev/sdz2 /srv/./d/../e/ ext4 defaults 0 2\n\
         /srv/data /srv/t tmpfs bind 0 0\n/dev/sdz3 /srv/u ext4 _netdev 0 0\n",
    );
    let mut devices = DeviceMap::default();
    for (name, dev) in [("sda1", "8:1"), ("sda2", "8:2")] {
        devices.by_dev.insert(dev.to_string(), name.to_string());
        devices
            .by_spec
            .insert(format!("/dev/{name}"), name.to_string());
    }
    assert_eq!(
        unmounted_folders(&parse_mountinfo(table), &fstab, &devices),
        [
            "/backup", "/net", "/srv/b", "/srv/c", "/srv/e", "/srv/t", "/srv/u"
        ]
        .map(PathBuf::from)
    );
}

#[test]
fn on_a_real_filesystem_no_link_is_followed_and_a_device_node_is_seen() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let at = dir.path().canonicalize().unwrap();
    std::fs::create_dir_all(at.join("x/sub")).unwrap();
    symlink(at.join("x"), at.join("absolute")).unwrap();
    symlink(at.join("nothing"), at.join("dangling")).unwrap();
    symlink("/dev/null", at.join("node")).unwrap();
    let fs = crate::filesystem::RealFilesystem;
    let read_real = |path: &Path| read(&fs, &[], Path::new("/"), &[], path);
    assert_eq!(read_real(&at.join("x/sub")), Ok(at.join("x/sub")));
    assert_eq!(
        read_real(&at.join("x/missing/y")),
        Ok(at.join("x/missing/y"))
    );
    for name in ["absolute", "dangling", "node"] {
        assert_eq!(
            read_real(&at.join(name).join("sub")),
            Err(UntoldPath::Link(at.join(name))),
            "{name}"
        );
    }
    // Every Linux system has /dev/null, a character device.
    assert_eq!(
        read_real(Path::new("/dev/null")),
        Err(UntoldPath::Device(PathBuf::from("/dev/null")))
    );
}
