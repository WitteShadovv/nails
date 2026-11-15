// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What the operator reads when the attach gate refuses a root.
//!
//! Every command that refuses a root (`init`, `activate`, `check`, `rehearse
//! plant`) says the same thing in the same words, under one of three stable
//! codes:
//!
//! - [`NOT_SEPARATE_VOLUME`]: the root is not a volume of its own. The hint
//!   redirects the operator: setting up here leaves files on this computer's
//!   own disk, so the volume is prepared elsewhere and only mounted here.
//! - [`ROOT_COVERED`]: another filesystem is mounted over the root.
//! - [`STORAGE_UNJUDGED`]: what the gate must read to tell where the root
//!   lives could not be read.
//!
//! The text is printed on the terminal of the computer it protects, where
//! anyone may read it. It names no storage tool and no volume type, and none
//! of the words that say what the program is for; the only names in it are the
//! paths of this computer, the root the operator typed and filesystem types. It
//! names no device either: a device-mapper name (`/dev/mapper/<name>`) can name
//! the tool that opened a volume, so a filesystem is named by where it is
//! mounted and its type, and what could not be read of a device (a loop
//! device's record, an attribute in sysfs) by what it is.

use super::separation::{SYS_CLASS_BLOCK, Sharing, Verdict};
use super::{Refusal, RefusalKind};
use crate::blockdev::PROC_DEVICES;
use crate::error::Skip;
use std::path::Path;

/// Where the kernel's block devices and their attributes are read.
const SYS: &str = "/sys";

/// Where the kernel lists the devices of each btrfs filesystem.
const SYS_FS_BTRFS: &str = "/sys/fs/btrfs";

/// The attribute in which a loop device's directory shows its file.
const LOOP_FILE: &str = "loop/backing_file";

/// What an attribute in a block device's sysfs directory says, as the text
/// names it, by the attribute's name.
const DEVICE_ATTRIBUTES: &[(&str, &str)] = &[
    (LOOP_FILE, "the path of a loop device's file"),
    ("slaves", "the devices below a block device"),
    ("backing_dev", "the writeback device of a zram device"),
    ("dev", "the number of a block device"),
    ("journal_task", JOURNAL),
];

/// What the gate reads to tell which device an ext3 or ext4 filesystem keeps
/// its journal on (the filesystem's `journal_task` in sysfs, and the name of
/// the thread it names), as the text names it.
const JOURNAL: &str = "where an ext3 or ext4 filesystem keeps its journal";

/// What to use instead of storage the gate cannot follow to its disks.
const OWN_VOLUME: &str = "Use a volume on a disk or partition of its own, or an encrypted volume \
                          opened from one: only such a volume can be told apart from this \
                          computer's own storage.";

/// The code of a root that is not a volume of its own.
pub const NOT_SEPARATE_VOLUME: &str = "not_separate_volume";
/// The code of a root another filesystem is mounted over.
pub const ROOT_COVERED: &str = "root_covered";
/// The code of a root whose storage could not be judged.
pub const STORAGE_UNJUDGED: &str = "storage_unjudged";

/// Where the operator guide explains where to set up.
pub const GUIDE_SECTION: &str = "Where setup happens";

/// What accepting a root with `--allow-decoy-storage` means, wherever it is
/// shown (the warning, the logout confirmation, `status`).
pub const OVERRIDE_CONSEQUENCE: &str = "everything written there lands on that storage";

impl RefusalKind {
    /// A root whose lookup failed with `error` for another reason than that
    /// nothing is there, or was not made. An I/O error is named by what
    /// failed, as the root is named beside it. A lookup the automount guard
    /// did not make is one that would mount an automount point, or one made
    /// without the mount table, which the gate reads too.
    pub fn lookup_failed(error: &crate::NailsError) -> Self {
        match error {
            crate::NailsError::IoError { source, .. } => RefusalKind::LookupFailed {
                error: source.to_string(),
                denied: source.kind() == std::io::ErrorKind::PermissionDenied,
            },
            crate::NailsError::NotLookedUp {
                reason: Skip::Automount { point },
                ..
            } => RefusalKind::NotLookedUp {
                point: point.clone(),
            },
            crate::NailsError::NotLookedUp {
                reason: Skip::NoMountTable { error },
                ..
            } => RefusalKind::MountTableUnreadable {
                error: error.clone(),
            },
            other => RefusalKind::LookupFailed {
                error: other.to_string(),
                denied: false,
            },
        }
    }

    /// The stable code a caller can branch on.
    pub fn code(&self) -> &'static str {
        match self {
            RefusalKind::Covered { .. } | RefusalKind::NotTheSessionVolume { .. } => ROOT_COVERED,
            RefusalKind::StorageUnjudged { .. } | RefusalKind::StorageUntraced { .. } => {
                STORAGE_UNJUDGED
            }
            RefusalKind::NotConfigured
            | RefusalKind::Missing
            | RefusalKind::LookupFailed { .. }
            | RefusalKind::NotLookedUp { .. }
            | RefusalKind::MountTableUnreadable { .. }
            | RefusalKind::NotAMountPoint { .. }
            | RefusalKind::DecoyStorage { .. }
            | RefusalKind::SameDeviceAsRoot => NOT_SEPARATE_VOLUME,
        }
    }

    /// Why a root is not a volume of its own, as a phrase that completes
    /// "<root> is not a volume of its own:"; `None` for the other kinds.
    pub fn why(&self) -> Option<String> {
        match self {
            RefusalKind::NotAMountPoint { mount_point } => Some(format!(
                "it is a folder on the filesystem mounted at {}",
                mount_point.display()
            )),
            RefusalKind::DecoyStorage { verdict } => Some(verdict.reason()),
            RefusalKind::SameDeviceAsRoot => Some("it is on the device that holds /".to_string()),
            _ => None,
        }
    }

    /// The sentence that says why `root` was refused, without a full stop.
    fn sentence(&self, root: &Path) -> String {
        let root = root.display();
        match self {
            RefusalKind::NotConfigured => "no root folder is configured".to_string(),
            RefusalKind::Missing => format!("{root} does not exist"),
            RefusalKind::LookupFailed { error, .. } => format!(
                "nothing shows that {root} is a volume of its own: it cannot be looked up ({error})"
            ),
            RefusalKind::NotLookedUp { point } => format!(
                "nothing shows that {root} is a volume of its own: it is not looked up, since the \
                 lookup would mount the automount point {}",
                point.display()
            ),
            RefusalKind::MountTableUnreadable { error } => format!(
                "nothing shows that {root} is a volume of its own: the mount table cannot be \
                 read ({error})"
            ),
            RefusalKind::NotAMountPoint { .. }
            | RefusalKind::DecoyStorage { .. }
            | RefusalKind::SameDeviceAsRoot => format!(
                "{root} is not a volume of its own: {}",
                self.why().unwrap_or_default()
            ),
            RefusalKind::Covered { below, above } => format!(
                "two filesystems are mounted at {root}: one of type {below}, then one of type \
                 {above} over it"
            ),
            RefusalKind::NotTheSessionVolume { fstype } => format!(
                "the filesystem at {root} (of type {fstype}) is not the volume this session \
                 started from"
            ),
            RefusalKind::StorageUntraced { verdict } => {
                let reason = verdict.reason();
                format!(
                    "{root} {}, so where it lives cannot be told",
                    reason.strip_prefix("it ").unwrap_or(&reason)
                )
            }
            RefusalKind::StorageUnjudged { unreadable } => format!(
                "could not read {} to tell where {root} lives",
                unreadable
                    .iter()
                    .map(|p| shown_input(p))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }
}

/// An input the gate could not read, as the text names it: a file and a
/// listing of the kernel's by its path, and what is read of one device or
/// filesystem (a device node, which is a loop device's record, an attribute
/// in sysfs) by what it is, never by the name of the device.
fn shown_input(path: &Path) -> String {
    if path.starts_with("/dev") {
        return "the record of a loop device".to_string();
    }
    // The name of a thread, as /proc/<pid>/comm shows it.
    if path.starts_with("/proc") && path.ends_with("comm") {
        return JOURNAL.to_string();
    }
    let listing = [SYS_CLASS_BLOCK, SYS_FS_BTRFS]
        .iter()
        .any(|listing| path == Path::new(listing));
    if !path.starts_with(SYS) || listing {
        return path.display().to_string();
    }
    let what = if path.starts_with(SYS_FS_BTRFS) {
        "the devices of a btrfs filesystem"
    } else {
        DEVICE_ATTRIBUTES
            .iter()
            .find(|(attribute, _)| path.ends_with(attribute))
            .map_or("an attribute of a block device", |(_, what)| what)
    };
    what.to_string()
}

impl Refusal {
    /// A refusal of `root` for `kind`, with the operator's sentence.
    pub fn new(kind: RefusalKind, root: &Path) -> Self {
        Self {
            reason: kind.sentence(root),
            root: root.to_path_buf(),
            kind,
        }
    }

    /// The stable code a caller can branch on.
    pub fn code(&self) -> &'static str {
        self.kind.code()
    }

    /// The message of a command that refused before writing anything.
    pub fn message(&self) -> String {
        format!("{}. Nothing was written.", self.reason)
    }

    /// Whether the root is used only because the operator overrode this
    /// refusal ([`Allow::DecoyStorage`](super::Allow::DecoyStorage)); a refusal
    /// that only warns by itself, such as a container file, is not.
    pub fn overridden(&self) -> bool {
        matches!(&self.kind, RefusalKind::DecoyStorage { verdict }
            if verdict.severity() == super::separation::Severity::Refuse)
    }

    /// The warning of a root that attached with this refusal
    /// ([`Assessment::Warned`](super::Assessment::Warned)). A root that only
    /// warns by itself (a container file) is described, not refused.
    pub fn warning(&self) -> String {
        let Some(why) = self.kind.why() else {
            return self.reason.clone();
        };
        let root = self.root.display();
        if self.overridden() {
            format!("--allow-decoy-storage: using {root} although {why}; {OVERRIDE_CONSEQUENCE}")
        } else {
            format!("{root} {}", why.strip_prefix("it ").unwrap_or(&why))
        }
    }

    /// What the operator does next, one line each. `exe` is the running
    /// program; when it lies under a root that is not a volume of its own,
    /// that copy is on this computer's disk too, and the first line says so.
    pub fn hint(&self, exe: Option<&Path>) -> Vec<String> {
        match &self.kind {
            RefusalKind::Covered { .. } => {
                vec!["Unmount the one that is not the volume, then run the command again.".into()]
            }
            RefusalKind::NotTheSessionVolume { .. } => {
                vec!["Unmount what was mounted over it, then run the command again.".into()]
            }
            // The kernel shows no file of a loop device whose path does not
            // fit in the page it writes it to, less two bytes: 4094 bytes on
            // most computers, more where a page is larger.
            RefusalKind::StorageUnjudged { unreadable }
                if unreadable.iter().any(|p| p.ends_with(LOOP_FILE)) =>
            {
                vec![
                    "Set the loop device up again from a file with a shorter path, then run the \
                     command again."
                        .into(),
                ]
            }
            // sudo alone does not bring back a list of block devices, or a
            // device's number, that is missing because /sys is not mounted.
            RefusalKind::StorageUnjudged { unreadable }
                if unreadable.iter().any(|p| p.starts_with(SYS)) =>
            {
                vec![
                    "Run the command again as root, on the host rather than in a container, \
                     with /sys mounted."
                        .into(),
                ]
            }
            // Anyone may read the kernel's list of drivers where /proc is
            // mounted.
            RefusalKind::StorageUnjudged { unreadable }
                if unreadable.iter().any(|p| p == Path::new(PROC_DEVICES)) =>
            {
                vec!["Run the command where /proc is mounted and readable.".into()]
            }
            RefusalKind::StorageUnjudged { .. } => {
                vec!["Run the command again with sudo.".into()]
            }
            // A partition always lies inside its disk in the sysfs of the
            // host, and a device a mounted filesystem keeps data on is
            // listed there: what is missing is read without the host's /sys.
            RefusalKind::StorageUntraced {
                verdict: Verdict::DiskNotFound | Verdict::ClaimedDeviceNotFound,
            } => vec![
                "Run the command again on the host rather than in a container, with /sys \
                 mounted."
                    .into(),
            ],
            RefusalKind::StorageUntraced { .. } => vec![OWN_VOLUME.into()],
            RefusalKind::NotConfigured => {
                vec!["Set the root folder in the configuration file.".into()]
            }
            RefusalKind::MountTableUnreadable { .. } => {
                vec!["Run the command where /proc is mounted and readable.".into()]
            }
            RefusalKind::LookupFailed { denied: true, .. } => {
                vec!["Run the command again with sudo.".into()]
            }
            RefusalKind::LookupFailed { denied: false, .. } => vec![format!(
                "Find out why {} cannot be looked up, then run the command again.",
                self.root.display()
            )],
            RefusalKind::NotLookedUp { point } => vec![format!(
                "Mount {} (for example `ls {}`), then run the command again.",
                point.display(),
                crate::next_step::shell_word(point.as_os_str())
            )],
            RefusalKind::Missing | RefusalKind::NotAMountPoint { .. } => {
                // Most often the volume is simply not unlocked yet, or the
                // path has a typo.
                let mut lines = vec![format!(
                    "If the volume is already prepared, unlock and mount it at {}, then run the \
                     command again.",
                    self.root.display()
                )];
                lines.extend(self.redirect(exe));
                lines
            }
            RefusalKind::DecoyStorage {
                verdict:
                    Verdict::OnDecoyFilesystem {
                        how: Sharing::Filesystem,
                        ..
                    },
            } => {
                // A volume prepared elsewhere that the boot mounts through
                // fstab is the computer's storage too, until its line goes.
                let mut lines = vec![format!(
                    "If {} is the volume you prepared, remove its line from {} long before the \
                     next use, and mount it by hand each time.",
                    self.root.display(),
                    super::separation::FSTAB
                )];
                lines.extend(self.redirect(exe));
                lines
            }
            // The guide says when the override fits a served disk.
            RefusalKind::DecoyStorage {
                verdict: Verdict::ServedDevice { .. },
            } => vec![
                OWN_VOLUME.into(),
                format!(
                    "If the device keeps its data on storage this computer does not use, read \
                     \"{GUIDE_SECTION}\" in the operator guide on another device: opening it \
                     here leaves traces such as ~/.lesshst."
                ),
            ],
            RefusalKind::DecoyStorage { .. } | RefusalKind::SameDeviceAsRoot => self.redirect(exe),
        }
    }

    /// Where to set up instead of here.
    fn redirect(&self, exe: Option<&Path>) -> Vec<String> {
        let mut lines = Vec::new();
        if let Some(exe) = exe.filter(|exe| self.holds(exe)) {
            lines.push(format!(
                "This copy of the program ({}) is itself on this computer's disk.",
                exe.display()
            ));
        }
        lines.extend([
            "Setting up here would leave files on this computer's own disk, where an \
             examination can find them."
                .to_string(),
            "Prepare the volume where nothing reaches this disk: on an external drive prepared \
             on another computer (recommended), or from a setup medium (a live system started \
             from a USB stick)."
                .to_string(),
            "Then unlock and mount it here, and run the program from it.".to_string(),
            format!(
                "Read \"{GUIDE_SECTION}\" in the operator guide on another device: opening it \
                 here leaves traces such as ~/.lesshst."
            ),
        ]);
        lines
    }

    /// Whether `path` lies under the refused root.
    fn holds(&self, path: &Path) -> bool {
        !self.root.as_os_str().is_empty() && path.starts_with(&self.root)
    }
}

#[cfg(test)]
#[path = "refusal_tests.rs"]
mod tests;
