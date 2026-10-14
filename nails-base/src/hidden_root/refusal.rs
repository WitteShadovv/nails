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
//! paths of this computer and the root the operator typed.

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

impl RefusalKind {
    /// The stable code a caller can branch on.
    pub fn code(&self) -> &'static str {
        match self {
            RefusalKind::Covered { .. } | RefusalKind::NotTheSessionVolume { .. } => ROOT_COVERED,
            RefusalKind::StorageUnjudged { .. } => STORAGE_UNJUDGED,
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
                "two filesystems are mounted at {root}: {}, then {} over it",
                below.display(),
                above.display()
            ),
            RefusalKind::NotTheSessionVolume { source } => format!(
                "the filesystem at {root} ({}) is not the volume this session started from",
                source.display()
            ),
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
    /// refusal ([`Allow::NotSeparate`](super::Allow::NotSeparate)); a refusal
    /// that only warns by itself, such as a container file, is not.
    pub fn overridden(&self) -> bool {
        match &self.kind {
            RefusalKind::NotAMountPoint { .. } => true,
            RefusalKind::DecoyStorage { verdict } => {
                verdict.severity() == super::separation::Severity::Refuse
            }
            _ => false,
        }
    }

    /// The warning of a root that attached with this refusal
    /// ([`Assessment::Warned`](super::Assessment::Warned)).
    pub fn warning(&self) -> String {
        let Some(why) = self.kind.why().filter(|_| self.overridden()) else {
            return self.reason.clone();
        };
        format!(
            "--allow-unmounted: using {} although {why}; every file nails writes there lands \
             on that storage",
            self.root.display()
        )
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
            RefusalKind::StorageUnjudged { .. } => {
                vec!["Run the command again with sudo.".into()]
            }
            RefusalKind::NotConfigured => {
                vec!["Set the root folder in the configuration file.".into()]
            }
            RefusalKind::MountTableUnreadable { .. } => {
                vec!["Run the command where /proc is mounted and readable.".into()]
            }
            RefusalKind::Missing
            | RefusalKind::NotAMountPoint { .. }
            | RefusalKind::DecoyStorage { .. }
            | RefusalKind::SameDeviceAsRoot => self.redirect(exe),
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
                below: PathBuf::from("/dev/mapper/data"),
                above: PathBuf::from("/dev/sdc1"),
            },
            RefusalKind::NotTheSessionVolume {
                source: PathBuf::from("/dev/sdc1"),
            },
            RefusalKind::StorageUnjudged {
                unreadable: vec![PathBuf::from("/etc/crypttab")],
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
        assert_eq!(codes[15], STORAGE_UNJUDGED);
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
    fn the_override_covers_only_a_folder_and_the_decoys_storage() {
        use crate::hidden_root::Allow;
        for refusal in every_refusal(Path::new("/mnt")) {
            let covered = matches!(
                refusal.kind,
                RefusalKind::NotAMountPoint { .. } | RefusalKind::DecoyStorage { .. }
            );
            assert_eq!(
                Allow::NotSeparate.covers(&refusal.kind),
                covered,
                "{refusal:?}"
            );
            assert!(!Allow::Nothing.covers(&refusal.kind), "{refusal:?}");
        }
    }

    #[test]
    fn the_override_warning_names_the_storage() {
        let folder = Refusal::new(
            RefusalKind::NotAMountPoint {
                mount_point: PathBuf::from("/srv"),
            },
            Path::new("/srv/x"),
        );
        assert!(folder.overridden());
        assert_eq!(
            folder.warning(),
            "--allow-unmounted: using /srv/x although it is a folder on the filesystem mounted \
             at /srv; every file nails writes there lands on that storage"
        );
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
        assert!(
            subvolume
                .warning()
                .contains("although it is a subvolume of the btrfs filesystem at /pool;"),
            "{}",
            subvolume.warning()
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
        assert_eq!(container.warning(), container.reason);
        let covered = Refusal::new(
            RefusalKind::Covered {
                below: PathBuf::from("/dev/a"),
                above: PathBuf::from("/dev/b"),
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
                    | RefusalKind::NotConfigured
                    | RefusalKind::MountTableUnreadable { .. }
            );
            assert_eq!(redirects, expected, "{refusal:?}: {hint}");
        }
    }
}
