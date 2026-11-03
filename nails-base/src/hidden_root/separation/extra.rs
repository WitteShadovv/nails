// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What a mounted filesystem keeps data on besides the device it is mounted
//! from ([`DeviceMap::extra`]), read through the [`Filesystem`] trait.
//!
//! - XFS names its log and realtime devices in its options, `logdev=` and
//!   `rtdev=`, by the paths it was mounted with.
//! - An ext3 or ext4 filesystem made with its journal on a device of its own
//!   shows that device nowhere in the mount table. jbd2 lists every journal
//!   it writes in `/proc/fs/jbd2`: one inside a filesystem by that
//!   filesystem's device and the journal's inode (`sda1-8`), one on a device
//!   of its own by that device. For a filesystem whose journal is not inside
//!   it, `journal_task` in `/sys/fs/ext4/<device>` names the thread that
//!   writes its journal, which is called `jbd2/<journal>`.
//! - bcachefs names every device of a filesystem of several in its source
//!   (`/dev/sdb:/dev/sdc`), and shows the first one's number.
//!
//! A path that leads to no block device, or a journal on a device sysfs does
//! not list, is [`Extra::NotFound`]; an input that cannot be read is
//! [`Extra::Unreadable`].

use super::{DeviceMap, Extra};
use crate::Filesystem;
use crate::blockdev;
use crate::filesystem::mountinfo::{MountEntry, unescape_octal};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Where jbd2 lists the journals it writes.
pub const PROC_JBD2: &str = "/proc/fs/jbd2";

/// Where ext3 and ext4 show each mounted filesystem, by its device.
pub const SYS_FS_EXT4: &str = "/sys/fs/ext4";

/// What jbd2 lists: the names of its journals, or none when it lists none at
/// all (it writes no journal); the error is the listing that could not be
/// read.
type Journals = Result<Option<Vec<String>>, PathBuf>;

/// What each filesystem in `mounts` keeps data on besides the device it is
/// mounted from, by the `major:minor` of its mounts, with `devices` the
/// block devices sysfs lists (see the module docs). A filesystem that keeps
/// none has no entry.
pub(super) fn extra_devices<F: Filesystem>(
    fs: &F,
    mounts: &[MountEntry],
    devices: &DeviceMap,
) -> BTreeMap<String, Extra> {
    let mut extra = BTreeMap::new();
    let mut journals = None;
    for mount in mounts {
        if extra.contains_key(&mount.dev) {
            continue;
        }
        let found = match mount.fstype.as_str() {
            "xfs" => named(fs, xfs_devices(mount)),
            "bcachefs" => named(fs, bcachefs_devices(mount)),
            "ext3" | "ext4" => devices.node_of_mount(mount).and_then(|name| {
                let journals = journals.get_or_insert_with(|| listed_journals(fs));
                journal(fs, devices, name, journals)
            }),
            _ => None,
        };
        if let Some(found) = found {
            extra.insert(mount.dev.clone(), found);
        }
    }
    extra
}

/// The devices `paths` name, by kernel name; none for no path.
fn named<F: Filesystem>(fs: &F, paths: Vec<String>) -> Option<Extra> {
    if paths.is_empty() {
        return None;
    }
    let names: Option<Vec<String>> = paths
        .iter()
        .map(|path| {
            blockdev::resolve_spec(fs, path)
                .as_deref()
                .and_then(Path::file_name)
                .map(|name| name.to_string_lossy().into_owned())
        })
        .collect();
    Some(names.map_or(Extra::NotFound, Extra::Devices))
}

/// The paths of an XFS filesystem's log and realtime devices, as its options
/// name them.
fn xfs_devices(mount: &MountEntry) -> Vec<String> {
    mount
        .super_opts
        .split(',')
        .filter_map(|option| {
            option
                .strip_prefix("logdev=")
                .or_else(|| option.strip_prefix("rtdev="))
        })
        .map(unescape_octal)
        .collect()
}

/// The paths of the devices of a bcachefs filesystem of several, as its
/// source names them; none for one of one device.
fn bcachefs_devices(mount: &MountEntry) -> Vec<String> {
    let source = mount.source.to_string_lossy();
    if !source.contains(':') {
        return Vec::new();
    }
    source
        .split(':')
        .filter(|path| !path.is_empty())
        .map(str::to_string)
        .collect()
}

/// The journals jbd2 lists, by name.
fn listed_journals<F: Filesystem>(fs: &F) -> Journals {
    match fs.list_directory(Path::new(PROC_JBD2)) {
        Ok(entries) => Ok(Some(
            entries
                .iter()
                .filter_map(|entry| entry.file_name())
                .map(|name| name.to_string_lossy().into_owned())
                .collect(),
        )),
        Err(error) if error.io_kind() == Some(std::io::ErrorKind::NotFound) => Ok(None),
        Err(_) => Err(PathBuf::from(PROC_JBD2)),
    }
}

/// The journal of the ext3 or ext4 filesystem on the device `name`, where it
/// is on a device of its own; none where it is inside the filesystem, or
/// there is none.
fn journal<F: Filesystem>(
    fs: &F,
    devices: &DeviceMap,
    name: &str,
    journals: &Journals,
) -> Option<Extra> {
    let journals = match journals {
        Ok(Some(journals)) => journals,
        Ok(None) => return None,
        Err(listing) => return Some(Extra::Unreadable(listing.clone())),
    };
    if journals.iter().any(|journal| is_inside(journal, name)) {
        return None;
    }
    let task = Path::new(SYS_FS_EXT4).join(name).join("journal_task");
    let Ok(text) = fs.read_file_content(&task) else {
        return Some(Extra::Unreadable(task));
    };
    let text = text.trim();
    // A filesystem made, or mounted, without a journal.
    if text == "<none>" {
        return None;
    }
    let Ok(pid) = text.parse::<u32>() else {
        return Some(Extra::Unreadable(task));
    };
    let thread = Path::new("/proc").join(pid.to_string()).join("comm");
    let journal = fs.read_file_content(&thread).ok().and_then(|comm| {
        comm.trim_end_matches('\n')
            .strip_prefix("jbd2/")
            .map(str::to_string)
    });
    let Some(journal) = journal else {
        return Some(Extra::Unreadable(thread));
    };
    if is_inside(&journal, name) {
        None
    } else if devices.nodes.contains_key(&journal) {
        Some(Extra::Devices(vec![journal]))
    } else {
        Some(Extra::NotFound)
    }
}

/// Whether jbd2's name `journal` is that of a journal inside the filesystem
/// on the device `name`: `<name>-<inode>`.
fn is_inside(journal: &str, name: &str) -> bool {
    journal
        .strip_prefix(name)
        .and_then(|rest| rest.strip_prefix('-'))
        .is_some_and(|inode| !inode.is_empty() && inode.bytes().all(|b| b.is_ascii_digit()))
}
