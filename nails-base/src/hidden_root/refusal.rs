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
//! mounted and its type.

use super::separation::{SYS_CLASS_BLOCK, Sharing, Verdict};
use super::{Refusal, RefusalKind};
use std::path::Path;

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
    /// The stable code a caller can branch on.
    pub fn code(&self) -> &'static str {
        match self {
            RefusalKind::Covered { .. } | RefusalKind::NotTheSessionVolume { .. } => ROOT_COVERED,
            RefusalKind::StorageUnjudged { .. } | RefusalKind::StorageUntraced { .. } => {
                STORAGE_UNJUDGED
            }
            RefusalKind::NotConfigured
            | RefusalKind::Missing
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
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }
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
            // sudo alone does not bring back a list of block devices that
            // is missing because /sys is not mounted.
            RefusalKind::StorageUnjudged { unreadable }
                if unreadable.iter().any(|p| p == Path::new(SYS_CLASS_BLOCK)) =>
            {
                vec![
                    "Run the command again as root, on the host rather than in a container, \
                     with /sys mounted."
                        .into(),
                ]
            }
            RefusalKind::StorageUnjudged { .. } => {
                vec!["Run the command again with sudo.".into()]
            }
            RefusalKind::StorageUntraced { .. } => vec![
                "Use a volume on a disk or partition of its own, or an encrypted volume opened \
                 from one: only such a volume can be told apart from this computer's own storage."
                    .into(),
            ],
            RefusalKind::NotConfigured => {
                vec!["Set the root folder in the configuration file.".into()]
            }
            RefusalKind::MountTableUnreadable { .. } => {
                vec!["Run the command where /proc is mounted and readable.".into()]
            }
            RefusalKind::Missing | RefusalKind::NotAMountPoint { .. } => {
                // Most often the volume is simply not unlocked yet, or the
                // path has a typo.
                let mut lines = vec![format!(
                    "If the volume is already prepared, unlock it, mount it at {} and run the \
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
mod tests {
    use super::*;
    use crate::hidden_root::separation::{Claimed, Sharing, Verdict};
    use std::path::PathBuf;

    /// One refusal of every kind, of `root`.
    pub(crate) fn every_refusal(root: &Path) -> Vec<Refusal> {
        let at = || PathBuf::from("/home");
        [
            RefusalKind::NotConfigured,
            RefusalKind::Missing,
            RefusalKind::MountTableUnreadable {
                error: "permission denied".into(),
            },
            RefusalKind::NotAMountPoint {
                mount_point: PathBuf::from("/"),
            },
            RefusalKind::DecoyStorage {
                verdict: Verdict::OnDecoyFilesystem {
                    how: Sharing::Subvolume,
                    at: at(),
                },
            },
            RefusalKind::DecoyStorage {
                verdict: Verdict::OnDecoyFilesystem {
                    how: Sharing::Bind,
                    at: at(),
                },
            },
            RefusalKind::DecoyStorage {
                verdict: Verdict::OnDecoyFilesystem {
                    how: Sharing::Filesystem,
                    at: PathBuf::from("/srv"),
                },
            },
            RefusalKind::DecoyStorage {
                verdict: Verdict::InsideDecoyStorage {
                    device: "dm-0".into(),
                    holds: Claimed::Mount(PathBuf::from("/")),
                    noauto_only: false,
                },
            },
            RefusalKind::DecoyStorage {
                verdict: Verdict::InsideDecoyStorage {
                    device: "sda3".into(),
                    holds: Claimed::Swap("/dev/sda3".into()),
                    noauto_only: false,
                },
            },
            RefusalKind::DecoyStorage {
                verdict: Verdict::InsideDecoyStorage {
                    device: "sdb".into(),
                    holds: Claimed::Encrypted("veracrypt1".into()),
                    noauto_only: false,
                },
            },
            RefusalKind::DecoyStorage {
                verdict: Verdict::ImageFileOnDecoy {
                    file: PathBuf::from("/home/u/disk.img"),
                    at: at(),
                },
            },
            RefusalKind::DecoyStorage {
                verdict: Verdict::ContainerOnDecoy {
                    file: PathBuf::from("/home/u/files.bin"),
                    at: at(),
                },
            },
            RefusalKind::SameDeviceAsRoot,
            RefusalKind::Covered {
                below: "ext4".into(),
                above: "vfat".into(),
            },
            RefusalKind::NotTheSessionVolume {
                fstype: "vfat".into(),
            },
            RefusalKind::StorageUnjudged {
                unreadable: vec![PathBuf::from("/etc/crypttab")],
            },
            RefusalKind::StorageUntraced {
                verdict: Verdict::UntracedStorage {
                    fstype: "fuse".into(),
                },
            },
            RefusalKind::StorageUntraced {
                verdict: Verdict::UnplacedImageFile {
                    file: PathBuf::from("/home/u/disk.img"),
                },
            },
        ]
        .into_iter()
        .map(|kind| Refusal::new(kind, root))
        .collect()
    }

    #[test]
    fn each_kind_has_its_code() {
        let codes: Vec<&str> = every_refusal(Path::new("/mnt"))
            .iter()
            .map(Refusal::code)
            .collect();
        assert_eq!(&codes[..13], &[NOT_SEPARATE_VOLUME; 13]);
        assert_eq!(&codes[13..15], &[ROOT_COVERED; 2]);
        assert_eq!(&codes[15..], &[STORAGE_UNJUDGED; 3]);
    }

    #[test]
    fn the_text_names_no_tool_and_no_purpose() {
        // The root is the operator's own word: one that contains a blocked
        // word must not count against the text around it.
        let root = Path::new("/mnt/hidden-decoy");
        for refusal in every_refusal(root) {
            let text = std::iter::once(refusal.message())
                .chain(refusal.hint(Some(&root.join("nails"))))
                .collect::<Vec<_>>()
                .join("\n")
                .replace(&root.display().to_string(), "<root>")
                .to_lowercase();
            for word in [
                "hidden",
                "decoy",
                "deniab",
                "veracrypt",
                "tcrypt",
                "cryptsetup",
                // No device either: a mapping's name can name what opened it.
                "/dev/",
            ] {
                assert!(!text.contains(word), "{word} in {text}");
            }
        }
    }

    #[test]
    fn the_message_says_nothing_was_written() {
        let refusal = Refusal::new(
            RefusalKind::NotAMountPoint {
                mount_point: PathBuf::from("/"),
            },
            Path::new("/mnt"),
        );
        assert_eq!(
            refusal.message(),
            "/mnt is not a volume of its own: it is a folder on the filesystem mounted at /. \
             Nothing was written."
        );
    }

    #[test]
    fn the_redirect_names_the_program_only_when_it_lies_under_the_root() {
        let refusal = Refusal::new(RefusalKind::SameDeviceAsRoot, Path::new("/mnt"));
        let inside = refusal.hint(Some(Path::new("/mnt/nails")));
        assert_eq!(
            inside[0],
            "This copy of the program (/mnt/nails) is itself on this computer's disk."
        );
        let outside = refusal.hint(Some(Path::new("/usr/bin/nails")));
        assert!(outside[0].starts_with("Setting up here"), "{outside:?}");
        assert_eq!(outside.len() + 1, inside.len());
        assert_eq!(refusal.hint(None), outside);
        // A root that shares only a prefix of the name does not hold it.
        assert_eq!(refusal.hint(Some(Path::new("/mnt2/nails"))), outside);
    }

    #[test]
    fn the_override_covers_only_the_decoys_storage() {
        use crate::hidden_root::Allow;
        for refusal in every_refusal(Path::new("/mnt")) {
            let covered = matches!(refusal.kind, RefusalKind::DecoyStorage { .. });
            assert_eq!(
                Allow::DecoyStorage.covers(&refusal.kind),
                covered,
                "{refusal:?}"
            );
            assert!(!Allow::Nothing.covers(&refusal.kind), "{refusal:?}");
        }
    }

    #[test]
    fn an_unlisted_sysfs_asks_for_the_host_not_only_for_sudo() {
        let hint = |unreadable: &[&str]| {
            Refusal::new(
                RefusalKind::StorageUnjudged {
                    unreadable: unreadable.iter().map(PathBuf::from).collect(),
                },
                Path::new("/mnt"),
            )
            .hint(None)
        };
        assert_eq!(
            hint(&["/etc/crypttab"]),
            ["Run the command again with sudo."]
        );
        let sysfs = [
            "Run the command again as root, on the host rather than in a container, with /sys \
             mounted.",
        ];
        assert_eq!(hint(&["/sys/class/block"]), sysfs);
        assert_eq!(hint(&["/etc/crypttab", "/sys/class/block"]), sysfs);
    }

    #[test]
    fn the_override_warning_names_the_storage() {
        let folder = Refusal::new(
            RefusalKind::NotAMountPoint {
                mount_point: PathBuf::from("/srv"),
            },
            Path::new("/srv/x"),
        );
        assert!(!folder.overridden());
        let subvolume = Refusal::new(
            RefusalKind::DecoyStorage {
                verdict: Verdict::OnDecoyFilesystem {
                    how: Sharing::Subvolume,
                    at: PathBuf::from("/pool"),
                },
            },
            Path::new("/mnt"),
        );
        assert!(subvolume.overridden());
        assert_eq!(
            subvolume.warning(),
            "--allow-decoy-storage: using /mnt although it is a subvolume of the btrfs filesystem \
             at /pool; everything written there lands on that storage"
        );
        // A container file only warns by itself: its warning is the reason.
        let container = Refusal::new(
            RefusalKind::DecoyStorage {
                verdict: Verdict::ContainerOnDecoy {
                    file: PathBuf::from("/home/u/files.bin"),
                    at: PathBuf::from("/home"),
                },
            },
            Path::new("/mnt"),
        );
        assert!(!container.overridden());
        assert!(
            container
                .warning()
                .starts_with("/mnt is an encrypted container file (/home/u/files.bin) on /home;"),
            "{}",
            container.warning()
        );
        let covered = Refusal::new(
            RefusalKind::Covered {
                below: "/dev/a".into(),
                above: "/dev/b".into(),
            },
            Path::new("/mnt"),
        );
        assert!(!covered.overridden());
    }

    #[test]
    fn only_the_redirect_kinds_redirect() {
        for refusal in every_refusal(Path::new("/mnt")) {
            let hint = refusal.hint(None).join("\n");
            let redirects = hint.contains(GUIDE_SECTION);
            let expected = !matches!(
                refusal.kind,
                RefusalKind::Covered { .. }
                    | RefusalKind::NotTheSessionVolume { .. }
                    | RefusalKind::StorageUnjudged { .. }
                    | RefusalKind::StorageUntraced { .. }
                    | RefusalKind::NotConfigured
                    | RefusalKind::MountTableUnreadable { .. }
            );
            assert_eq!(redirects, expected, "{refusal:?}: {hint}");
        }
    }

    #[test]
    fn a_folder_or_a_missing_root_first_asks_to_mount_the_volume() {
        for kind in [
            RefusalKind::Missing,
            RefusalKind::NotAMountPoint {
                mount_point: PathBuf::from("/"),
            },
        ] {
            let hint = Refusal::new(kind, Path::new("/mnt")).hint(None);
            assert_eq!(
                hint[0],
                "If the volume is already prepared, unlock it, mount it at /mnt and run the \
                 command again."
            );
            assert!(hint[1].starts_with("Setting up here"), "{hint:?}");
        }
    }

    #[test]
    fn a_filesystem_the_boot_mounts_first_asks_to_drop_its_fstab_line() {
        let refusal = Refusal::new(
            RefusalKind::DecoyStorage {
                verdict: Verdict::OnDecoyFilesystem {
                    how: Sharing::Filesystem,
                    at: PathBuf::from("/srv"),
                },
            },
            Path::new("/srv"),
        );
        let hint = refusal.hint(None);
        assert_eq!(
            hint[0],
            "If /srv is the volume you prepared, remove its line from /etc/fstab long before the \
             next use, and mount it by hand each time."
        );
        assert!(
            hint.iter().any(|line| line.contains(GUIDE_SECTION)),
            "{hint:?}"
        );
    }
}
