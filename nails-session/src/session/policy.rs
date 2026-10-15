// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What happens to each decoy filesystem in the hidden root.
//!
//! The root overlay covers only the root filesystem. Every other filesystem
//! in the fstab the hidden systemd reads would be mounted by it **directly and
//! read-write**: a separate `/home` or `/var` would take hidden writes on the
//! decoy disk, the ESP would get `loader/random-seed` rewritten, and decoy swap
//! would take hidden RAM. Before the switch NAILS therefore decides for every
//! entry, and puts the result in place inside `/run/nextroot` (an already
//! mounted path counts as active for systemd) or masks the unit in `/run`:
//!
//! | Entry | Decision |
//! | --- | --- |
//! | `/` | the root overlay itself |
//! | swap | masked: never activated |
//! | RAM and kernel filesystems | left to the hidden systemd (nothing reaches a disk) |
//! | the hidden volume, or a path inside it | left alone: it is bound at its own path |
//! | a VM host share (9p, virtiofs) or an overlay entry mounted in the decoy | an overlay with its upper on the hidden volume |
//! | a VM host share not mounted now | left to the hidden systemd |
//! | `/boot`, `/boot/efi`, `/efi` (the ESP and boot partitions) | read-only bind of the decoy mount |
//! | a local filesystem mounted read-only in the decoy | read-only bind |
//! | any other local filesystem mounted in the decoy | an overlay with its upper on the hidden volume |
//! | a local filesystem not mounted now, mounted at boot | masked (and its automount) |
//! | `noauto` without an automount | left alone: never mounted |
//! | a network filesystem | masked: the hidden session would write to the server |
//! | an overlay entry not mounted now, its upper in RAM | left to the hidden systemd |
//! | an overlay entry not mounted now, its upper on a disk | masked |
//!
//! A mounted host share or overlay is overlaid rather than left to the hidden
//! systemd because the next root must already hold its contents when PID 1
//! checks the init: NixOS test VMs mount `/nix/store` as an overlay of a 9p
//! share and a tmpfs, and the next root would otherwise have an empty store.
//!
//! Nothing is refused outright today: every entry has a safe decision. The
//! `Refuse` decision exists for entries whose target cannot be mounted inside
//! the next root (a relative or odd mount point).

use super::fstab::{FstabEntry, automount_unit, mount_unit, swap_unit};
use nails_teardown::mountinfo::{MountEntry, parse_overlay_opts};
use std::path::{Component, Path, PathBuf};

/// Mount points whose filesystem is kept read-only in the hidden root.
pub const BOOT_PATHS: &[&str] = &["/boot", "/boot/efi", "/efi"];

/// Units that write to the boot filesystems at every start: systemd-boot's
/// random seed, and GRUB's record of a good boot on Debian and Ubuntu. On the
/// read-only boot filesystems they would only fail in every hidden session,
/// so the entry masks those the hidden root has, in the hidden root alone. The
/// decoy runs them at its own start, as it always does.
pub const BOOT_WRITER_UNITS: &[&str] = &[
    "systemd-boot-random-seed.service",
    "grub-common.service",
    "grub-initrd-fallback.service",
];

/// What to do with one fstab entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Bind the decoy mount at `target` read-only into the next root.
    ReadOnlyBind {
        /// The mount point.
        target: PathBuf,
    },
    /// Mount an overlay over the decoy mount at `target`, upper on the hidden
    /// volume.
    Overlay {
        /// The mount point.
        target: PathBuf,
    },
    /// Mask these units in `/run`, so the hidden systemd never starts them.
    Mask {
        /// The entry's mount point (or swap spec).
        target: PathBuf,
        /// The units.
        units: Vec<String>,
        /// Why.
        reason: &'static str,
    },
    /// Leave it to the hidden systemd or skip it.
    Leave {
        /// The mount point.
        target: PathBuf,
        /// Why that is safe.
        reason: &'static str,
    },
    /// No safe decision: activation is refused.
    Refuse {
        /// The mount point.
        target: PathBuf,
        /// Why.
        reason: String,
    },
}

impl Decision {
    /// The units to mask, if this is a mask.
    pub fn masked_units(&self) -> &[String] {
        match self {
            Decision::Mask { units, .. } => units,
            _ => &[],
        }
    }

    /// A one-line description for `check` and the activation log.
    pub fn describe(&self) -> String {
        match self {
            Decision::ReadOnlyBind { target } => format!("{}: read-only", target.display()),
            Decision::Overlay { target } => format!("{}: overlaid", target.display()),
            Decision::Mask { target, reason, .. } => {
                format!("{}: masked ({reason})", target.display())
            }
            Decision::Leave { target, reason } => {
                format!("{}: left as is ({reason})", target.display())
            }
            Decision::Refuse { target, reason } => {
                format!("{}: refused ({reason})", target.display())
            }
        }
    }
}

/// The decoy's live mount at exactly `target` (the topmost one).
fn mounted_at<'a>(mounts: &'a [MountEntry], target: &Path) -> Option<&'a MountEntry> {
    mounts.iter().rev().find(|m| m.mount_point == target)
}

/// The deepest decoy mount containing `path`.
fn mount_containing<'a>(mounts: &'a [MountEntry], path: &Path) -> Option<&'a MountEntry> {
    mounts
        .iter()
        .filter(|m| path.starts_with(&m.mount_point))
        .max_by_key(|m| m.mount_point.components().count())
}

fn plain_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
}

/// Decide one entry. `mounts` is the decoy's live mount table.
pub fn decide(entry: &FstabEntry, mounts: &[MountEntry], hidden_root: &Path) -> Decision {
    let target = entry.file.clone();
    if entry.is_swap() {
        let units: Vec<String> = swap_unit(&entry.spec).into_iter().collect();
        if units.is_empty() {
            return Decision::Leave {
                target,
                reason: "a swap entry without a device",
            };
        }
        return Decision::Mask {
            target: PathBuf::from(&entry.spec),
            units,
            reason: "swap would take hidden RAM onto a decoy disk",
        };
    }
    if !plain_absolute(&target) {
        return Decision::Refuse {
            reason: "the mount point is not a plain absolute path".to_string(),
            target,
        };
    }
    if target == Path::new("/") {
        return Decision::Leave {
            target,
            reason: "the root overlay",
        };
    }
    if entry.is_virtual() {
        return Decision::Leave {
            target,
            reason: "RAM or kernel filesystem",
        };
    }
    if target.starts_with(hidden_root) {
        return Decision::Leave {
            target,
            reason: "the hidden volume is bound at its own path",
        };
    }
    let mounted = mounted_at(mounts, &target).is_some();
    if (entry.is_host_share() || entry.vfstype == "overlay") && mounted {
        return Decision::Overlay { target };
    }
    if entry.is_host_share() {
        return Decision::Leave {
            target,
            reason: "a host share, not mounted now",
        };
    }
    let mask = |reason: &'static str| {
        let mut units = vec![mount_unit(&entry.file)];
        if entry.is_automount() {
            units.push(automount_unit(&entry.file));
        }
        Decision::Mask {
            target: entry.file.clone(),
            units,
            reason,
        }
    };
    if entry.is_network() {
        return mask("the hidden session would write to the server");
    }
    if entry.vfstype == "overlay" {
        let opts = entry
            .option_value("upperdir")
            .map(PathBuf::from)
            .or_else(|| {
                mounted_at(mounts, &target).and_then(|m| parse_overlay_opts(&m.super_opts).upperdir)
            });
        let in_ram = opts
            .as_deref()
            .and_then(|upper| mount_containing(mounts, upper))
            .is_some_and(|m| m.fstype == "tmpfs" || m.fstype == "ramfs");
        return if in_ram {
            Decision::Leave {
                target,
                reason: "an overlay with its upper in RAM",
            }
        } else {
            mask("an overlay with its upper on a disk")
        };
    }
    match mounted_at(mounts, &target) {
        Some(mount) if BOOT_PATHS.iter().any(|b| target == Path::new(b)) || mount.read_only() => {
            Decision::ReadOnlyBind { target }
        }
        Some(_) => Decision::Overlay { target },
        None if entry.is_noauto() => Decision::Leave {
            target,
            reason: "noauto: never mounted",
        },
        None => mask("not mounted now; the hidden session would mount it read-write"),
    }
}

/// Decide every entry, ordered by mount-point depth so a parent is in place
/// before a child mounted below it.
pub fn decide_all(
    entries: &[FstabEntry],
    mounts: &[MountEntry],
    hidden_root: &Path,
) -> Vec<Decision> {
    let mut decisions: Vec<(usize, Decision)> = entries
        .iter()
        .map(|e| (e.file.components().count(), decide(e, mounts, hidden_root)))
        .collect();
    decisions.sort_by_key(|(depth, _)| *depth);
    decisions.into_iter().map(|(_, d)| d).collect()
}

/// Every unit the decisions mask.
pub fn masked_units(decisions: &[Decision]) -> Vec<String> {
    decisions
        .iter()
        .flat_map(|d| d.masked_units().iter().cloned())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::fstab::parse_fstab;
    use nails_teardown::mountinfo::parse_mountinfo;

    const HIDDEN: &str = "/mnt/data";

    fn mounts() -> Vec<MountEntry> {
        parse_mountinfo(
            "1 0 8:2 / / rw,relatime - ext4 /dev/vda2 rw\n\
             2 1 8:1 / /boot rw - vfat /dev/vda1 rw\n\
             3 1 8:3 / /home rw - ext4 /dev/vda3 rw\n\
             4 1 8:4 / /srv ro - ext4 /dev/vda4 ro\n\
             5 1 0:5 / /tmp rw - tmpfs tmpfs rw\n\
             6 1 0:6 / /nix/.rw-store rw - tmpfs tmpfs rw\n\
             7 1 0:7 / /nix/store rw - overlay overlay rw,lowerdir=/nix/.ro-store,upperdir=/nix/.rw-store/store,workdir=/nix/.rw-store/work\n\
             8 1 253:0 / /mnt/data rw - ext4 /dev/mapper/data rw\n\
             9 1 0:9 / /nix/.ro-store rw - 9p store rw,trans=virtio\n",
        )
    }

    fn decide_line(line: &str) -> Decision {
        let entries = parse_fstab(line);
        decide(&entries[0], &mounts(), Path::new(HIDDEN))
    }

    #[test]
    fn boot_filesystems_and_read_only_mounts_are_bound_read_only() {
        assert_eq!(
            decide_line("UUID=AB /boot vfat umask=0077 0 2"),
            Decision::ReadOnlyBind {
                target: "/boot".into()
            }
        );
        assert_eq!(
            decide_line("/dev/vda4 /srv ext4 ro 0 2"),
            Decision::ReadOnlyBind {
                target: "/srv".into()
            }
        );
    }

    #[test]
    fn other_mounted_local_filesystems_are_overlaid() {
        assert_eq!(
            decide_line("LABEL=home /home ext4 defaults 0 2"),
            Decision::Overlay {
                target: "/home".into()
            }
        );
    }

    #[test]
    fn swap_unmounted_and_network_filesystems_are_masked() {
        assert_eq!(
            decide_line("/dev/vda5 none swap sw 0 0").masked_units(),
            ["dev-vda5.swap"]
        );
        assert_eq!(
            decide_line("/dev/sdb1 /data ext4 defaults 0 2").masked_units(),
            ["data.mount"]
        );
        assert_eq!(
            decide_line("/dev/sdb1 /data ext4 noauto,x-systemd.automount 0 2").masked_units(),
            ["data.mount", "data.automount"]
        );
        assert_eq!(
            decide_line("server:/export /net nfs4 defaults 0 0").masked_units(),
            ["net.mount"]
        );
    }

    #[test]
    fn ram_kernel_noauto_root_and_hidden_entries_are_left_alone() {
        for line in [
            "/dev/vda2 / ext4 defaults 0 1",
            "tmpfs /tmp tmpfs defaults 0 0",
            "share /mnt/share virtiofs defaults 0 0",
            "/dev/sdb1 /mnt/usb vfat noauto 0 0",
            "/dev/mapper/data /mnt/data ext4 noauto 0 0",
            "overlay /var/cache overlay lowerdir=/usr,upperdir=/tmp/up,workdir=/tmp/w 0 0",
        ] {
            assert!(
                matches!(decide_line(line), Decision::Leave { .. }),
                "{line}: {:?}",
                decide_line(line)
            );
        }
    }

    #[test]
    fn a_mounted_host_share_or_overlay_is_overlaid_into_the_next_root() {
        // A NixOS test VM: the store is an overlay of a 9p share and a tmpfs.
        for (line, target) in [
            ("store /nix/.ro-store 9p trans=virtio 0 0", "/nix/.ro-store"),
            (
                "overlay /nix/store overlay lowerdir=/nix/.ro-store,upperdir=/nix/.rw-store/store,workdir=/nix/.rw-store/work 0 0",
                "/nix/store",
            ),
        ] {
            assert_eq!(
                decide_line(line),
                Decision::Overlay {
                    target: target.into()
                },
                "{line}"
            );
        }
    }

    #[test]
    fn an_overlay_entry_with_its_upper_on_disk_is_masked() {
        assert_eq!(
            decide_line(
                "overlay /opt overlay lowerdir=/usr,upperdir=/persist/up,workdir=/persist/w 0 0"
            )
            .masked_units(),
            ["opt.mount"]
        );
    }

    #[test]
    fn decisions_come_parents_first_and_odd_mount_points_are_refused() {
        let entries = parse_fstab(
            "/dev/vda6 /home/alice/media ext4 defaults 0 2\n\
             LABEL=home /home ext4 defaults 0 2\n\
             /dev/vda7 relative ext4 defaults 0 2\n",
        );
        let decisions = decide_all(&entries, &mounts(), Path::new(HIDDEN));
        assert!(matches!(&decisions[0], Decision::Refuse { .. }));
        assert_eq!(
            decisions[1],
            Decision::Overlay {
                target: "/home".into()
            }
        );
        assert!(matches!(&decisions[2], Decision::Mask { .. }));
        assert_eq!(masked_units(&decisions), ["home-alice-media.mount"]);
    }
}
