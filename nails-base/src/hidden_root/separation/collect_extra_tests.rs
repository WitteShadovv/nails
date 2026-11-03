// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The attach gate on a filesystem that keeps data on other devices besides
//! the one it is mounted from, as the collector reads them: an XFS log or
//! realtime device from the filesystem's options, an ext4 journal on a device
//! of its own from jbd2's list and the filesystem's journal thread, and the
//! other devices of a bcachefs filesystem from its source.

use super::super::{Decoy, SDB};
use super::{NBD0, SDC, ZD0, assert_served, assert_unjudged, assert_untraced, assess, decoy};
use crate::hidden_root::separation::{Served, Untraced, Verdict};
use crate::hidden_root::{Allow, Assessment, RefusalKind};
use std::path::{Path, PathBuf};

const NBD1: &str = "/sys/devices/virtual/block/nbd1";

/// An XFS root on the separate disk `sdb` at `/mnt`, mounted with `options`,
/// beside the disk `sdc`, the network block devices `nbd0` and `nbd1` and
/// the ZFS volume `zd0`.
fn xfs(options: &str) -> Decoy {
    decoy(&format!("5 1 8:16 / /mnt rw - xfs /dev/sdb rw,{options}\n"))
        .device(SDB, "sdb", "8:16", &[])
        .device(SDC, "sdc", "8:32", &[])
        .device(NBD0, "nbd0", "43:0", &[])
        .device(NBD1, "nbd1", "43:32", &[])
        .device(ZD0, "zd0", "230:0", &[])
}

#[test]
fn an_xfs_root_is_judged_with_its_log_and_realtime_devices() {
    assert_eq!(xfs("attr2,inode64,noquota").assess(), Assessment::Attached);
    assert_eq!(
        xfs("logdev=/dev/sdc,noquota").assess(),
        Assessment::Attached
    );
    assert_served(
        "a log on a network block device",
        &xfs("attr2,logdev=/dev/nbd1,noquota"),
        Served::Network,
    );
    assert_served(
        "a realtime device on a network block device",
        &xfs("logdev=/dev/sdc,rtdev=/dev/nbd0"),
        Served::Network,
    );
    assert_untraced(
        "a realtime device on a ZFS volume",
        &xfs("rtdev=/dev/zd0"),
        Untraced::ZfsVolume,
    );
    // The kernel opened the path it was given, which leads to no device here.
    assert_untraced(
        "a log named by a node outside /dev",
        &xfs("logdev=/root/log"),
        Untraced::NotFound,
    );
}

#[test]
fn an_xfs_option_is_read_as_the_kernel_escapes_it() {
    // The mount table writes a space in a path as \040.
    let decoy = xfs("logdev=/dev/disk/by-label/the\\040log");
    decoy.link("/dev/disk/by-label/the log", "/dev/nbd1");
    assert_served(
        "a log named by a label with a space",
        &decoy,
        Served::Network,
    );
}

#[test]
fn an_image_file_on_a_filesystem_whose_log_a_program_serves_is_refused() {
    let loop0 = "/sys/devices/virtual/block/loop0";
    let image = decoy(
        "4 1 8:32 / /media/x rw - xfs /dev/sdc rw,logdev=/dev/nbd1\n\
         5 1 7:0 / /mnt rw - ext4 /dev/loop0 rw\n",
    )
    .device(SDC, "sdc", "8:32", &[])
    .device(NBD1, "nbd1", "43:32", &[])
    .device(loop0, "loop0", "7:0", &[]);
    image.attr(loop0, "loop/backing_file", "/media/x/disk.img");
    image
        .fs
        .mock_set_loop_backing_device(Path::new("/dev/loop0"), rustix::fs::makedev(8, 32));
    assert_served(
        "an image file on XFS whose log is served",
        &image,
        Served::Network,
    );
}

#[test]
fn a_decoy_filesystem_whose_log_cannot_be_found_leaves_every_root_unjudged() {
    // The decoy's /srv is XFS with its log named by a node outside /dev:
    // whether the root on a disk of its own shares that log's storage cannot
    // be told, and no flag lifts that.
    let decoy = decoy(
        "4 1 8:32 / /srv rw - xfs /dev/sdc rw,logdev=/root/log\n\
         5 1 8:16 / /mnt rw - ext4 /dev/sdb rw\n",
    )
    .device(SDB, "sdb", "8:16", &[])
    .device(SDC, "sdc", "8:32", &[]);
    for allow in [Allow::Nothing, Allow::DecoyStorage] {
        let Assessment::Refused(refusal) = assess(&decoy, allow) else {
            panic!("{allow:?}: it attached");
        };
        assert_eq!(
            refusal.kind,
            RefusalKind::StorageUntraced {
                verdict: Verdict::ClaimedDeviceNotFound
            },
            "{allow:?}"
        );
        assert_eq!(refusal.code(), "storage_unjudged");
    }
}

/// An ext4 root on the separate disk `sdb` at `/mnt`, beside `sdc` and
/// `nbd1`, with `journals` the journals jbd2 lists (the decoy's own `/`
/// among them).
fn ext4(journals: &[&str]) -> Decoy {
    let decoy = decoy("5 1 8:16 / /mnt rw - ext4 /dev/sdb rw\n")
        .device(SDB, "sdb", "8:16", &[])
        .device(SDC, "sdc", "8:32", &[])
        .device(NBD1, "nbd1", "43:32", &[]);
    let listed = std::iter::once("nvme0n1p3-8")
        .chain(journals.iter().copied())
        .map(|journal| PathBuf::from(format!("/proc/fs/jbd2/{journal}")))
        .collect();
    decoy
        .fs
        .mock_set_directory_contents(Path::new("/proc/fs/jbd2"), listed);
    decoy
}

/// [`ext4`] with the root's journal on the device `journal`, as jbd2 lists
/// it and the root's journal thread names it.
fn ext4_journal_on(journal: &str) -> Decoy {
    ext4(&[journal])
        .file("/sys/fs/ext4/sdb/journal_task", "412\n")
        .file("/proc/412/comm", &format!("jbd2/{journal}\n"))
}

#[test]
fn an_ext4_root_is_judged_with_the_device_its_journal_is_on() {
    // A journal inside the filesystem is listed by its device and inode.
    assert_eq!(ext4(&["sdb-8"]).assess(), Assessment::Attached);
    // A filesystem without a journal has none to place.
    let none = ext4(&["nbd1"]).file("/sys/fs/ext4/sdb/journal_task", "<none>\n");
    assert_eq!(none.assess(), Assessment::Attached);
    assert_eq!(ext4_journal_on("sdc").assess(), Assessment::Attached);
    assert_served(
        "a journal on a network block device",
        &ext4_journal_on("nbd1"),
        Served::Network,
    );
    assert_untraced(
        "a journal on a device sysfs does not list",
        &ext4_journal_on("sdq"),
        Untraced::NotFound,
    );
    // Without a list of journals, jbd2 writes none.
    let unlisted = decoy("5 1 8:16 / /mnt rw - ext4 /dev/sdb rw\n").device(SDB, "sdb", "8:16", &[]);
    assert_eq!(unlisted.assess(), Assessment::Attached);
}

#[test]
fn an_ext4_journal_that_cannot_be_placed_leaves_the_root_unjudged() {
    let task = "/sys/fs/ext4/sdb/journal_task";
    assert_unjudged("the journal thread", &ext4(&["nbd1"]), task);
    let garbled = ext4(&["nbd1"]).file(task, "?\n");
    assert_unjudged("a journal thread that is no number", &garbled, task);
    // A thread an unprivileged reader may not see (hidepid).
    let hidden = ext4(&["nbd1"]).file(task, "412\n");
    assert_unjudged("the journal thread's name", &hidden, "/proc/412/comm");
    let Assessment::Refused(refusal) = hidden.assess() else {
        unreachable!()
    };
    assert_eq!(
        refusal.message(),
        "could not read where an ext3 or ext4 filesystem keeps its journal to tell where /mnt \
         lives. Nothing was written."
    );
    assert_eq!(refusal.hint(None), ["Run the command again with sudo."]);
    // jbd2's list, which the decoy's own journal is on too.
    let unread = ext4(&[]);
    unread.fs.mock_set_unreadable_dir("/proc/fs/jbd2");
    assert_unjudged("jbd2's list", &unread, "/proc/fs/jbd2");
    let Assessment::Refused(refusal) = unread.assess() else {
        unreachable!()
    };
    assert_eq!(
        refusal.kind,
        RefusalKind::StorageUnjudged {
            unreadable: vec![PathBuf::from("/proc/fs/jbd2")]
        }
    );
}

#[test]
fn a_bcachefs_root_is_judged_with_every_device_its_source_names() {
    // bcachefs shows the first device's number and names them all.
    let bcachefs = |source: &str| {
        decoy(&format!("5 1 8:16 / /mnt rw - bcachefs {source} rw\n"))
            .device(SDB, "sdb", "8:16", &[])
            .device(SDC, "sdc", "8:32", &[])
            .device(NBD1, "nbd1", "43:32", &[])
    };
    assert_eq!(bcachefs("/dev/sdb").assess(), Assessment::Attached);
    assert_eq!(bcachefs("/dev/sdb:/dev/sdc").assess(), Assessment::Attached);
    assert_served(
        "a second device that a program serves",
        &bcachefs("/dev/sdb:/dev/nbd1"),
        Served::Network,
    );
    assert_untraced(
        "a second device that cannot be found",
        &bcachefs("/dev/sdb:/dev/sdq"),
        Untraced::NotFound,
    );
}
