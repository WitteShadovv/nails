// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The loop driver's record, and the filesystem it names for a loop
//! device's file, against given mount tables.

use super::*;
use crate::mountinfo::parse_mountinfo;

#[test]
fn a_node_that_is_no_loop_device_has_no_record() {
    // /dev/null opens, but the loop driver does not answer for it.
    assert!(record(Path::new("/dev/null")).is_err());
    assert!(record(Path::new("/dev/nails-no-such-loop")).is_err());
}

#[test]
fn only_a_filesystem_on_a_loop_device_is_looked_up() {
    // A disk's number, a table line with no number, and an anonymous
    // number whose source is no device node: none is on a loop device,
    // whatever the host has at these paths.
    let mounts = parse_mountinfo(
        "1 0 8:2 / / rw - ext4 /dev/loop9 rw\n\
         2 1 x:1 / /odd rw - ext4 /dev/loop9 rw\n\
         3 1 0:44 / /srv rw - btrfs /nonexistent/loop9 rw\n\
         4 1 0:45 / /tmp rw - tmpfs tmpfs rw\n",
    );
    for mount in &mounts {
        assert_eq!(loop_node(mount), None, "{mount:?}");
        assert_eq!(backing_filesystem(mount), None, "{mount:?}");
    }
    // A loop device's number: its node by number when the source is not
    // that node, and no record where no node is.
    let image = parse_mountinfo("5 1 7:1048575 / /mnt/img rw - ext4 /nonexistent/loop rw\n");
    assert_eq!(
        loop_node(&image[0]),
        Some((
            PathBuf::from("/dev/block/7:1048575"),
            rustix::fs::makedev(7, 1_048_575)
        ))
    );
    assert_eq!(backing_filesystem(&image[0]), None);
}

/// The image the tests bind a loop device to, on the hidden volume.
const IMAGE: &str = "/mnt/data/images/disk.img";

/// A session's mount table, with the hidden volume on btrfs at
/// `/mnt/data`, which the table shows by the filesystem's number, 0:47.
/// Below it are an image mounted from its loop device, a USB disk and an
/// automount point.
fn btrfs_session() -> Vec<MountEntry> {
    parse_mountinfo(
        "1 0 254:0 / / rw - ext4 /dev/mapper/root rw\n\
         40 1 0:47 / /mnt/data rw - btrfs /dev/mapper/data rw,subvol=/\n\
         41 40 7:3 / /mnt/data/vm rw - ext4 /dev/loop3 rw\n\
         42 40 8:33 / /mnt/data/usb rw - vfat /dev/sdc1 rw\n\
         43 40 0:52 / /mnt/data/net rw - autofs systemd-1 rw\n",
    )
}

/// The device the files of the volume's subvolume show, 0:48, which no
/// mount line shows.
fn subvolume() -> u64 {
    rustix::fs::makedev(0, 48)
}

/// The inode number of the image on that subvolume.
const INODE: u64 = 257;

/// The loop driver's record of the image on that subvolume.
fn on_subvolume() -> LoopRecord {
    LoopRecord {
        device: subvolume(),
        inode: INODE,
        rdevice: 0,
    }
}

/// A lookup that ends on the mount `mount_id`, at the file `inode` of the
/// device `device`.
fn reached(mount_id: u64, device: u64, inode: u64) -> Option<Reached> {
    Some(Reached {
        mount_id,
        device,
        inode,
    })
}

#[test]
fn a_file_on_btrfs_is_held_by_the_mount_its_path_leads_to() {
    let held = holding_filesystem(
        &btrfs_session(),
        Some(PathBuf::from(IMAGE)),
        || Some(on_subvolume()),
        |path| {
            assert_eq!(path, Path::new(IMAGE));
            reached(40, subvolume(), INODE)
        },
    );
    assert_eq!(held.as_deref(), Some("0:47"));
}

#[test]
fn a_file_on_a_filesystem_the_table_shows_needs_no_lookup() {
    // As on ext4: the file shows the number the table shows.
    let on_root = LoopRecord {
        device: rustix::fs::makedev(254, 0),
        inode: INODE,
        rdevice: 0,
    };
    let held = holding_filesystem(
        &btrfs_session(),
        Some(PathBuf::from("/var/lib/images/disk.img")),
        || Some(on_root),
        |_| unreachable!("no lookup is made"),
    );
    assert_eq!(held.as_deref(), Some("254:0"));
}

#[test]
fn a_path_that_leads_elsewhere_names_no_filesystem() {
    let mounts = btrfs_session();
    let held = |file: &str, reached: Option<Reached>| {
        holding_filesystem(
            &mounts,
            Some(PathBuf::from(file)),
            || Some(on_subvolume()),
            |_| reached,
        )
    };
    // A disk mounted over the image's folder: the lookup ends on it, at a
    // file of its own.
    let usb = rustix::fs::makedev(8, 33);
    assert_eq!(
        held("/mnt/data/usb/disk.img", reached(42, usb, INODE)),
        None
    );
    // On another mount than the table shows there (one mounted or
    // unmounted since), even at the recorded file.
    assert_eq!(held(IMAGE, reached(42, subvolume(), INODE)), None);
    // On the volume, at a file of another subvolume, or at another file of
    // the image's subvolume.
    let other = rustix::fs::makedev(0, 49);
    assert_eq!(held(IMAGE, reached(40, other, INODE)), None);
    assert_eq!(held(IMAGE, reached(40, subvolume(), INODE + 1)), None);
    // No file there, or a link on the way.
    assert_eq!(held(IMAGE, None), None);
}

/// What the filesystem that holds `file` is named by `mounts`, where the
/// driver's record of it is never read and its path never looked up.
fn unasked(mounts: &[MountEntry], file: Option<&str>) -> Option<String> {
    holding_filesystem(
        mounts,
        file.map(PathBuf::from),
        || unreachable!("no record is read"),
        |_| unreachable!("no lookup is made"),
    )
}

#[test]
fn nothing_is_asked_without_a_mount_to_reach_or_below_an_automount_point() {
    let mounts = btrfs_session();
    // The driver shows no path, or one no mount the table shows holds.
    assert_eq!(unasked(&mounts, None), None);
    assert_eq!(unasked(&mounts, Some("disk.img")), None);
    // A lookup below an automount point that nothing is mounted on would
    // mount it.
    assert_eq!(unasked(&mounts, Some("/mnt/data/net/host/disk.img")), None);
    // A table with no root.
    assert_eq!(unasked(&[], Some(IMAGE)), None);
}

/// The btrfs session of [`btrfs_session`], with a FUSE filesystem mounted
/// over the image's folder (sshfs), and outside the hidden root an NFS
/// share, a share of a virtual machine's host and a FUSE filesystem on a
/// disk of its own (ntfs-3g).
fn served_session() -> Vec<MountEntry> {
    let mut mounts = btrfs_session();
    mounts.extend(parse_mountinfo(
        "44 40 0:53 / /mnt/data/images rw - fuse.sshfs host:/srv rw\n\
         45 1 0:54 / /mnt/nas rw - nfs4 nas:/export rw\n\
         46 1 0:55 / /mnt/host rw - virtiofs share rw\n\
         47 1 8:49 / /mnt/win rw - fuseblk /dev/sdd1 rw\n",
    ));
    mounts
}

#[test]
fn nothing_is_asked_through_a_fuse_or_network_filesystem() {
    let mounts = served_session();
    // The image's folder on the volume, now covered by sshfs: a lookup of
    // the path would wait for its daemon, and so would the driver's record
    // if the file were there.
    assert_eq!(unasked(&mounts, Some(IMAGE)), None);
    // A file on the NFS share, in a folder of the host's share, or on the
    // FUSE disk.
    for file in [
        "/mnt/nas/disk.img",
        "/mnt/host/vm/disk.img",
        "/mnt/win/disk.img",
    ] {
        assert_eq!(unasked(&mounts, Some(file)), None, "{file}");
    }
}

#[test]
fn nothing_is_asked_below_a_network_filesystem_on_the_way() {
    // The volume is mounted in a folder of an NFS share, and the image lies
    // on the volume: a lookup of its path asks the share for the volume's
    // folder.
    let mounts = parse_mountinfo(
        "1 0 254:0 / / rw - ext4 /dev/mapper/root rw\n\
         30 1 0:60 / /srv rw - nfs nas:/srv rw\n\
         40 30 0:47 / /srv/data rw - btrfs /dev/mapper/data rw\n",
    );
    assert_eq!(unasked(&mounts, Some("/srv/data/images/disk.img")), None);
    // Where the volume holds the file by the table, as on ext4, the record
    // would name it, but it is not read either.
    let ext4 = parse_mountinfo(
        "1 0 254:0 / / rw - ext4 /dev/mapper/root rw\n\
         30 1 0:60 / /srv rw - nfs nas:/srv rw\n\
         40 30 253:1 / /srv/data rw - ext4 /dev/mapper/data rw\n",
    );
    assert_eq!(unasked(&ext4, Some("/srv/data/disk.img")), None);
}

#[test]
fn only_an_automount_point_fuse_and_a_network_filesystem_are_served_from_outside() {
    for fstype in [
        "autofs",
        "fuse",
        "fuse.sshfs",
        "fuse.portal",
        "fuseblk",
        "fuseblk.ntfs-3g",
        "nfs",
        "nfs4",
        "cifs",
        "smb3",
        "ceph",
        "9p",
        "virtiofs",
        "vboxsf",
        "glusterfs",
    ] {
        assert!(served_from_outside(fstype), "{fstype}");
    }
    // The FUSE control filesystem is the kernel's own, and so are these.
    for fstype in [
        "fusectl", "fuseblkx", "btrfs", "ext4", "xfs", "tmpfs", "overlay", "devtmpfs", "squashfs",
        "",
    ] {
        assert!(!served_from_outside(fstype), "{fstype}");
    }
}

#[test]
fn a_loop_device_bound_to_a_device_node_names_no_filesystem() {
    // It reads the disk the node is (8:33), not the filesystem that holds
    // the node, even where that is shown or found by the path.
    let mounts = btrfs_session();
    let disk = rustix::fs::makedev(8, 33);
    let shown = LoopRecord {
        device: rustix::fs::makedev(254, 0),
        inode: INODE,
        rdevice: disk,
    };
    let found = LoopRecord {
        device: subvolume(),
        inode: INODE,
        rdevice: disk,
    };
    for record in [shown, found] {
        let held = holding_filesystem(
            &mounts,
            Some(PathBuf::from("/mnt/data/sdc")),
            || Some(record),
            |_| reached(40, subvolume(), INODE),
        );
        assert_eq!(held, None, "{record:?}");
    }
}

#[test]
fn the_shown_path_is_read_as_the_driver_writes_it() {
    use std::os::unix::ffi::OsStrExt;
    assert_eq!(
        parse_shown_file(b"/mnt/data/disk image.img\n"),
        Some(PathBuf::from("/mnt/data/disk image.img"))
    );
    // Only the newline the driver adds is cut, and bytes that are no
    // UTF-8 stay.
    assert_eq!(
        parse_shown_file(b"/mnt/\xff.img\n\n"),
        Some(PathBuf::from(std::ffi::OsStr::from_bytes(
            b"/mnt/\xff.img\n"
        )))
    );
    assert_eq!(
        parse_shown_file(b"/mnt/a.img"),
        Some(PathBuf::from("/mnt/a.img"))
    );
    assert_eq!(parse_shown_file(b"\n"), None);
    assert_eq!(parse_shown_file(b""), None);
}

#[test]
fn a_lookup_names_the_mount_it_ends_on_and_follows_no_link() {
    let dir = tempfile::tempdir().expect("temp dir");
    let base = dir.path().canonicalize().expect("canonical temp dir");
    let file = base.join("disk.img");
    std::fs::write(&file, b"").expect("write the file");
    let reached = reach(&file).expect("a lookup of a path with no link");
    let meta = std::fs::metadata(&file).expect("stat the file");
    assert_eq!((reached.device, reached.inode), (meta.dev(), meta.ino()));
    let mounts = crate::mountinfo::read_mountinfo().expect("read mountinfo");
    let holder = file
        .ancestors()
        .find_map(|folder| top_mount_at(&mounts, folder))
        .expect("the mount that holds the temp dir");
    assert_eq!(u64::try_from(holder.mount_id), Ok(reached.mount_id));
    // A link on the way, or at the end, ends the lookup, and so does a
    // missing file.
    std::os::unix::fs::symlink(&base, base.join("folder")).unwrap();
    std::os::unix::fs::symlink(&file, base.join("image")).unwrap();
    assert_eq!(reach(&base.join("folder/disk.img")), None);
    assert_eq!(reach(&base.join("image")), None);
    assert_eq!(reach(&base.join("missing.img")), None);
}
