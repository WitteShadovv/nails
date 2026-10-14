// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The decoy-storage judge on literal scenes: a mount table, the decoy's
//! fstab and crypttab, and the block devices, as the collector would read
//! them on the distributions and layouts named in each test.

use super::*;
use crate::crypttab::parse_crypttab;
use crate::filesystem::mountinfo::{parse_mountinfo, top_mount_at};
use crate::fstab::parse_fstab;
use std::path::Path;

/// One scene: the inputs of the judge, built up in the test.
#[derive(Default)]
struct World {
    mountinfo: String,
    fstab: String,
    crypttab: String,
    devices: DeviceMap,
    unreadable: Vec<PathBuf>,
}

impl World {
    fn new(mountinfo: &str) -> Self {
        Self {
            mountinfo: mountinfo.to_string(),
            ..Self::default()
        }
    }

    fn fstab(mut self, text: &str) -> Self {
        self.fstab = text.to_string();
        self
    }

    fn crypttab(mut self, text: &str) -> Self {
        self.crypttab = text.to_string();
        self
    }

    fn unreadable(mut self, path: &str) -> Self {
        self.unreadable.push(PathBuf::from(path));
        self
    }

    /// A device `name` with `major:minor` `dev`, found as `/dev/<name>` and,
    /// for a mapping, as `/dev/mapper/<dm name>`.
    fn node(mut self, name: &str, dev: &str, kind: NodeKind, below: &[&str]) -> Self {
        if let NodeKind::Crypt { name: dm } | NodeKind::Mapper { name: dm } = &kind {
            self.devices
                .by_spec
                .insert(format!("/dev/mapper/{dm}"), name.to_string());
        }
        self.devices
            .by_spec
            .insert(format!("/dev/{name}"), name.to_string());
        self.devices
            .by_dev
            .insert(dev.to_string(), name.to_string());
        self.devices.nodes.insert(
            name.to_string(),
            Node {
                kind,
                below: below.iter().map(|b| b.to_string()).collect(),
            },
        );
        self
    }

    fn disk(self, name: &str, dev: &str) -> Self {
        self.node(name, dev, NodeKind::Disk, &[])
    }

    fn part(self, name: &str, dev: &str, disk: &str) -> Self {
        let kind = NodeKind::Partition {
            disk: disk.to_string(),
        };
        self.node(name, dev, kind, &[])
    }

    fn crypt(self, name: &str, dev: &str, dm: &str, below: &[&str]) -> Self {
        let kind = NodeKind::Crypt {
            name: dm.to_string(),
        };
        self.node(name, dev, kind, below)
    }

    fn lv(self, name: &str, dev: &str, dm: &str, below: &[&str]) -> Self {
        let kind = NodeKind::Mapper {
            name: dm.to_string(),
        };
        self.node(name, dev, kind, below)
    }

    fn loop_file(self, name: &str, dev: &str, file: &str) -> Self {
        let kind = NodeKind::Loop {
            file: Some(PathBuf::from(file)),
        };
        self.node(name, dev, kind, &[])
    }

    /// `spec` (a `UUID=`, say) names `name`.
    fn spec(mut self, spec: &str, name: &str) -> Self {
        self.devices
            .by_spec
            .insert(spec.to_string(), name.to_string());
        self
    }

    fn btrfs(mut self, members: &[&str]) -> Self {
        self.devices
            .btrfs
            .push(members.iter().map(|m| m.to_string()).collect());
        self
    }

    fn judge(&self, root: &str) -> Judgement {
        let mounts = parse_mountinfo(&self.mountinfo);
        let fstab = parse_fstab(&self.fstab);
        let crypttab = parse_crypttab(&self.crypttab);
        let hidden = top_mount_at(&mounts, Path::new(root)).expect("a mount at the root");
        judge(
            &Scene {
                mounts: &mounts,
                fstab: &fstab,
                crypttab: &crypttab,
                devices: &self.devices,
                unreadable: &self.unreadable,
            },
            hidden,
        )
    }

    fn verdict(&self, root: &str) -> Verdict {
        self.judge(root).verdict
    }
}

/// A plain ext4 decoy on `sda1`, plus `extra` mount lines.
fn plain_decoy(extra: &str) -> World {
    World::new(&format!(
        "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n\
         2 1 8:2 / /home rw - ext4 /dev/sda2 rw\n{extra}"
    ))
    .disk("sda", "8:0")
    .part("sda1", "8:1", "sda")
    .part("sda2", "8:2", "sda")
    .fstab("/dev/sda1 / ext4 defaults 0 1\n/dev/sda2 /home ext4 defaults 0 2\n")
}

/// The plain decoy and a whole-device VeraCrypt volume on the external `sdb`,
/// mounted at `/mnt`.
fn external_veracrypt() -> World {
    plain_decoy("5 1 254:9 / /mnt rw - ext4 /dev/mapper/veracrypt1 rw\n")
        .disk("sdb", "8:16")
        .crypt("dm-9", "254:9", "veracrypt1", &["sdb"])
}

// ---------------------------------------------------------------------------
// Refused
// ---------------------------------------------------------------------------

#[test]
fn a_subvolume_of_the_decoy_root_is_refused() {
    let world = World::new(
        "1 0 0:30 /root / rw - btrfs /dev/nvme0n1p2 rw,subvolid=256,subvol=/root\n\
         3 1 0:30 /vault /mnt rw - btrfs /dev/nvme0n1p2 rw,subvolid=300,subvol=/vault\n",
    )
    .disk("nvme0n1", "259:0")
    .part("nvme0n1p2", "259:2", "nvme0n1")
    .btrfs(&["nvme0n1p2"])
    .fstab("UUID=f1 / btrfs subvol=root 0 0\n")
    .spec("UUID=f1", "nvme0n1p2");
    let verdict = world.verdict("/mnt");
    assert_eq!(
        verdict,
        Verdict::OnDecoyFilesystem {
            how: Sharing::Subvolume,
            at: PathBuf::from("/"),
        }
    );
    assert_eq!(verdict.severity(), Severity::Refuse);
    assert_eq!(
        verdict.reason(),
        "it is a subvolume of the btrfs filesystem at /"
    );
}

#[test]
fn archinstall_subvolumes_at_and_home_and_a_third_are_one_filesystem() {
    let world = World::new(
        "1 0 0:31 /@ / rw - btrfs /dev/sda2 rw,subvolid=256,subvol=/@\n\
         2 1 0:31 /@home /home rw - btrfs /dev/sda2 rw,subvolid=257,subvol=/@home\n\
         3 1 0:31 /@vault /mnt rw - btrfs /dev/sda2 rw,subvolid=260,subvol=/@vault\n",
    )
    .disk("sda", "8:0")
    .part("sda2", "8:2", "sda")
    .btrfs(&["sda2"])
    .fstab("UUID=a1 / btrfs subvol=/@ 0 0\nUUID=a1 /home btrfs subvol=/@home 0 0\n")
    .spec("UUID=a1", "sda2");
    assert!(matches!(
        world.verdict("/mnt"),
        Verdict::OnDecoyFilesystem {
            how: Sharing::Subvolume,
            ..
        }
    ));
}

#[test]
fn a_fedora_bind_of_a_home_folder_is_refused() {
    let world = World::new(
        "1 0 0:35 /root / rw - btrfs /dev/mapper/luks-f1 rw,subvolid=256,subvol=/root\n\
         2 1 0:35 /home /home rw - btrfs /dev/mapper/luks-f1 rw,subvolid=257,subvol=/home\n\
         4 1 0:35 /home/op/x /mnt rw - btrfs /dev/mapper/luks-f1 rw,subvolid=257,subvol=/home\n",
    )
    .disk("nvme0n1", "259:0")
    .part("nvme0n1p3", "259:3", "nvme0n1")
    .crypt("dm-0", "254:0", "luks-f1", &["nvme0n1p3"])
    .btrfs(&["dm-0"])
    .fstab("UUID=b1 / btrfs subvol=root 0 0\nUUID=b1 /home btrfs subvol=home 0 0\n")
    .crypttab("luks-f1 UUID=c1 none discard\n")
    .spec("UUID=b1", "dm-0")
    .spec("UUID=c1", "nvme0n1p3");
    let verdict = world.verdict("/mnt");
    assert!(
        matches!(
            verdict,
            Verdict::OnDecoyFilesystem {
                how: Sharing::Bind,
                ..
            }
        ),
        "{verdict:?}"
    );
    assert!(
        verdict
            .reason()
            .starts_with("it is a bind mount of a folder of /")
    );
}

#[test]
fn a_debian_bind_of_a_home_folder_on_lvm_is_refused() {
    let world = World::new(
        "1 0 254:1 / / rw - ext4 /dev/mapper/vg-root rw\n\
         2 1 254:2 / /home rw - ext4 /dev/mapper/vg-home rw\n\
         3 1 254:2 /op/vault /mnt rw - ext4 /dev/mapper/vg-home rw\n",
    )
    .disk("sda", "8:0")
    .part("sda5", "8:5", "sda")
    .lv("dm-1", "254:1", "vg-root", &["sda5"])
    .lv("dm-2", "254:2", "vg-home", &["sda5"])
    .fstab(
        "/dev/mapper/vg-root / ext4 defaults 0 1\n/dev/mapper/vg-home /home ext4 defaults 0 2\n",
    );
    assert_eq!(
        world.verdict("/mnt"),
        Verdict::OnDecoyFilesystem {
            how: Sharing::Bind,
            at: PathBuf::from("/home"),
        }
    );
}

#[test]
fn the_filesystem_the_decoy_mounts_elsewhere_is_refused_at_the_root() {
    let world = plain_decoy("5 1 8:17 / /mnt rw - ext4 /dev/sdb1 rw\n")
        .disk("sdb", "8:16")
        .part("sdb1", "8:17", "sdb")
        .fstab("/dev/sda1 / ext4 defaults 0 1\nUUID=d1 /data ext4 defaults 0 2\n")
        .spec("UUID=d1", "sdb1");
    let judgement = world.judge("/mnt");
    let verdict = judgement.verdict.clone();
    assert_eq!(
        verdict,
        Verdict::OnDecoyFilesystem {
            how: Sharing::Filesystem,
            at: PathBuf::from("/data"),
        }
    );
    assert_eq!(
        verdict.reason(),
        "it is the filesystem this computer mounts at /data per /etc/fstab"
    );
    // The fstab line mounts the volume at the root at every boot: a claim, and
    // an entry for that drive as well.
    assert_eq!(entry_kinds(&judgement), vec![(EntryKind::Blocking, FSTAB)]);
}

#[test]
fn a_luks_volume_in_the_decoys_encrypted_volume_group_is_refused() {
    let world = World::new(
        "1 0 254:1 / / rw - ext4 /dev/mapper/vg-root rw\n\
         5 1 254:4 / /mnt rw - ext4 /dev/mapper/vault rw\n",
    )
    .disk("nvme0n1", "259:0")
    .part("nvme0n1p3", "259:3", "nvme0n1")
    .crypt("dm-0", "254:0", "cryptroot", &["nvme0n1p3"])
    .lv("dm-1", "254:1", "vg-root", &["dm-0"])
    .lv("dm-3", "254:3", "vg-vault", &["dm-0"])
    .crypt("dm-4", "254:4", "vault", &["dm-3"])
    .fstab("/dev/mapper/vg-root / ext4 defaults 0 1\n")
    .crypttab("cryptroot UUID=e1 none luks,discard\n")
    .spec("UUID=e1", "nvme0n1p3");
    let verdict = world.verdict("/mnt");
    assert_eq!(
        verdict,
        Verdict::InsideDecoyStorage {
            device: "dm-0".to_string(),
            holds: Claimed::Mount(PathBuf::from("/")),
            noauto_only: false,
        }
    );
    assert_eq!(
        verdict.reason(),
        "it is stored inside /dev/dm-0, which also holds /"
    );
}

#[test]
fn the_decoys_swap_partition_reused_is_refused() {
    let world = plain_decoy("5 1 254:5 / /mnt rw - ext4 /dev/mapper/vault rw\n")
        .part("sda3", "8:3", "sda")
        .crypt("dm-5", "254:5", "vault", &["sda3"])
        .fstab("/dev/sda1 / ext4 defaults 0 1\n/dev/sda3 none swap sw 0 0\n");
    let judgement = world.judge("/mnt");
    let verdict = judgement.verdict.clone();
    assert_eq!(
        verdict,
        Verdict::InsideDecoyStorage {
            device: "sda3".to_string(),
            holds: Claimed::Swap("/dev/sda3".to_string()),
            noauto_only: false,
        }
    );
    assert_eq!(
        verdict.reason(),
        "it is stored inside /dev/sda3, which this computer uses as swap"
    );
    assert_eq!(entry_kinds(&judgement), vec![(EntryKind::Blocking, FSTAB)]);
}

#[test]
fn a_crypttab_device_reopened_under_another_name_is_refused() {
    // The decoy opens sdb1 as cryptdata for /data; the same device is opened
    // a second time as vault and mounted at the root.
    let world = plain_decoy(
        "4 1 254:6 / /data rw - ext4 /dev/mapper/cryptdata rw\n\
         5 1 254:7 / /mnt rw - ext4 /dev/mapper/vault rw\n",
    )
    .disk("sdb", "8:16")
    .part("sdb1", "8:17", "sdb")
    .crypt("dm-6", "254:6", "cryptdata", &["sdb1"])
    .crypt("dm-7", "254:7", "vault", &["sdb1"])
    .fstab("/dev/sda1 / ext4 defaults 0 1\n/dev/mapper/cryptdata /data ext4 defaults 0 2\n")
    .crypttab("cryptdata /dev/sdb1 none luks\n");
    assert_eq!(
        world.verdict("/mnt"),
        Verdict::InsideDecoyStorage {
            device: "sdb1".to_string(),
            holds: Claimed::Mount(PathBuf::from("/data")),
            noauto_only: false,
        }
    );
}

#[test]
fn an_unencrypted_image_file_on_home_is_refused() {
    let world = plain_decoy("5 1 7:0 / /mnt rw - ext4 /dev/loop0 rw\n").loop_file(
        "loop0",
        "7:0",
        "/home/op/disk.img",
    );
    let verdict = world.verdict("/mnt");
    assert_eq!(
        verdict,
        Verdict::ImageFileOnDecoy {
            file: PathBuf::from("/home/op/disk.img"),
            at: PathBuf::from("/home"),
        }
    );
    assert_eq!(verdict.severity(), Severity::Refuse);
    assert_eq!(
        verdict.reason(),
        "it is an unencrypted image file (/home/op/disk.img) on /home"
    );
}

#[test]
fn an_encrypted_container_on_home_follows_the_container_setting() {
    let world = plain_decoy("5 1 254:8 / /mnt rw - ext4 /dev/mapper/veracrypt1 rw\n")
        .loop_file("loop0", "7:0", "/home/op/vault.hc")
        .crypt("dm-8", "254:8", "veracrypt1", &["loop0"]);
    let verdict = world.verdict("/mnt");
    assert_eq!(
        verdict,
        Verdict::ContainerOnDecoy {
            file: PathBuf::from("/home/op/vault.hc"),
            at: PathBuf::from("/home"),
        }
    );
    // The owner's setting warns; refusing is the other setting.
    assert_eq!(CONTAINER_VERDICT, Severity::Warn);
    assert_eq!(verdict.severity(), Severity::Warn);
    assert_eq!(verdict.severity_with(Severity::Refuse), Severity::Refuse);
    let reason = verdict.reason();
    assert!(reason.contains("on /home"), "{reason}");
    assert!(
        reason.contains("copy-on-write snapshots (btrfs, snapper)"),
        "{reason}"
    );
}

#[test]
fn a_bind_entry_claims_the_filesystem_holding_its_source() {
    // A disk the decoy mounts by hand, known to it only through a bind line.
    let world = plain_decoy(
        "4 1 8:17 / /media/disk rw - ext4 /dev/sdb1 rw\n\
         5 1 8:17 /vault /mnt rw - ext4 /dev/sdb1 rw\n",
    )
    .disk("sdb", "8:16")
    .part("sdb1", "8:17", "sdb")
    .fstab("/dev/sda1 / ext4 defaults 0 1\n/media/disk/share /srv/share none bind 0 0\n");
    assert_eq!(
        world.verdict("/mnt"),
        Verdict::OnDecoyFilesystem {
            how: Sharing::Bind,
            at: PathBuf::from("/media/disk"),
        }
    );
}

#[test]
fn a_logical_volume_beside_an_encrypted_one_the_decoy_opens_is_refused() {
    let world = plain_decoy("5 1 254:3 / /mnt rw - ext4 /dev/mapper/vg-vault rw\n")
        .disk("sdb", "8:16")
        .lv("dm-2", "254:2", "vg-secret", &["sdb"])
        .lv("dm-3", "254:3", "vg-vault", &["sdb"])
        .crypttab("secret /dev/mapper/vg-secret none luks\n");
    let verdict = world.verdict("/mnt");
    assert_eq!(
        verdict,
        Verdict::InsideDecoyStorage {
            device: "sdb".to_string(),
            holds: Claimed::Encrypted("secret".to_string()),
            noauto_only: false,
        }
    );
    assert_eq!(
        verdict.reason(),
        "it is stored inside /dev/sdb, which this computer unlocks through /etc/crypttab"
    );
}

#[test]
fn a_swap_file_claims_the_filesystem_holding_it() {
    // An image of the hidden volume next to the decoy's swap file on /data,
    // which only the swap line makes the decoy's.
    let world = plain_decoy(
        "4 1 8:3 / /data rw - ext4 /dev/sda3 rw\n\
         5 1 7:0 / /mnt rw - ext4 /dev/loop0 rw\n",
    )
    .part("sda3", "8:3", "sda")
    .loop_file("loop0", "7:0", "/data/disk.img")
    .fstab("/dev/sda1 / ext4 defaults 0 1\n/data/swapfile none swap sw 0 0\n");
    assert_eq!(
        world.verdict("/mnt"),
        Verdict::ImageFileOnDecoy {
            file: PathBuf::from("/data/disk.img"),
            at: PathBuf::from("/data"),
        }
    );
}

#[test]
fn the_separate_reason_and_several_unreadable_files_read_well() {
    assert_eq!(
        Verdict::Separate.reason(),
        "it is separate from this computer's own storage"
    );
    let verdict = Verdict::CouldNotJudge {
        unreadable: vec![PathBuf::from(FSTAB), PathBuf::from(CRYPTTAB)],
    };
    assert_eq!(
        verdict.reason(),
        "/etc/fstab, /etc/crypttab could not be read, so where it lives cannot be told"
    );
}

#[test]
fn another_member_of_a_btrfs_filesystem_the_decoy_mounts_by_hand_is_refused() {
    // A two-disk btrfs pool the decoy lists as noauto at /pool, mounted at the
    // root through its second member.
    let world = plain_decoy("5 1 0:40 / /mnt rw - btrfs /dev/sdc rw,subvol=/\n")
        .disk("sdb", "8:16")
        .disk("sdc", "8:32")
        .btrfs(&["sdb", "sdc"])
        .fstab("/dev/sda1 / ext4 defaults 0 1\nUUID=p1 /pool btrfs noauto 0 0\n")
        .spec("UUID=p1", "sdb");
    assert_eq!(
        world.verdict("/mnt"),
        Verdict::OnDecoyFilesystem {
            how: Sharing::Filesystem,
            at: PathBuf::from("/pool"),
        }
    );
}

#[test]
fn a_device_reached_twice_is_walked_once() {
    let devices = World::default()
        .lv("dm-2", "254:2", "a", &["dm-0", "dm-1"])
        .lv("dm-0", "254:0", "b", &["sda1"])
        .lv("dm-1", "254:1", "c", &["sda1"])
        .part("sda1", "8:1", "sda")
        .devices;
    assert_eq!(devices.stack("dm-2"), vec!["dm-2", "dm-0", "sda1", "dm-1"]);
}

// ---------------------------------------------------------------------------
// Separate
// ---------------------------------------------------------------------------

#[test]
fn whole_device_veracrypt_on_an_external_disk_is_separate() {
    let judgement = external_veracrypt().judge("/mnt");
    assert_eq!(judgement.verdict, Verdict::Separate);
    assert!(judgement.entries.is_empty());
    assert_eq!(judgement.verdict.severity(), Severity::Pass);
}

#[test]
fn a_spare_partition_beside_the_decoys_is_separate() {
    let world = World::new(
        "1 0 254:1 / / rw - ext4 /dev/mapper/vg-root rw\n\
         5 1 254:5 / /mnt rw - ext4 /dev/mapper/vault rw\n",
    )
    .disk("nvme0n1", "259:0")
    .part("nvme0n1p3", "259:3", "nvme0n1")
    .part("nvme0n1p4", "259:4", "nvme0n1")
    .crypt("dm-0", "254:0", "cryptroot", &["nvme0n1p3"])
    .lv("dm-1", "254:1", "vg-root", &["dm-0"])
    .crypt("dm-5", "254:5", "vault", &["nvme0n1p4"])
    .fstab("/dev/mapper/vg-root / ext4 defaults 0 1\n")
    .crypttab("cryptroot /dev/nvme0n1p3 none luks\n");
    assert_eq!(world.verdict("/mnt"), Verdict::Separate);
}

#[test]
fn a_bind_of_a_folder_on_a_disk_the_decoy_does_not_use_is_separate() {
    // The bind-mounted-root VM scene: a second disk mounted by hand at
    // /mnt/backing, and a folder of it bound at the root.
    let world = World::new(
        "1 0 252:1 / / rw - ext4 /dev/vda1 rw\n\
         6 1 252:16 / /mnt/backing rw - ext4 /dev/vdb rw\n\
         7 1 252:16 /vol /mnt/data rw - ext4 /dev/vdb rw\n",
    )
    .disk("vda", "252:0")
    .part("vda1", "252:1", "vda")
    .disk("vdb", "252:16")
    .fstab("/dev/vda1 / ext4 defaults 0 1\n");
    assert_eq!(world.verdict("/mnt/data"), Verdict::Separate);
}

#[test]
fn a_tmpfs_root_is_separate_even_when_inputs_are_unreadable() {
    let world = plain_decoy("5 1 0:40 / /mnt rw - tmpfs tmpfs rw\n").unreadable(CRYPTTAB);
    assert_eq!(world.verdict("/mnt"), Verdict::Separate);
}

#[test]
fn luks_on_a_loop_file_in_run_is_separate() {
    let world = plain_decoy(
        "3 1 0:25 / /run rw - tmpfs tmpfs rw\n\
         5 1 254:9 / /mnt rw - ext4 /dev/mapper/stage rw\n",
    )
    .loop_file("loop1", "7:1", "/run/stage.img")
    .crypt("dm-9", "254:9", "stage", &["loop1"]);
    assert_eq!(world.verdict("/mnt"), Verdict::Separate);
}

// ---------------------------------------------------------------------------
// Warned
// ---------------------------------------------------------------------------

#[test]
fn a_noauto_entry_sharing_a_device_only_warns() {
    // A backup volume group on sdb1 the decoy mounts only by hand; the
    // hidden volume is another logical volume of that group.
    let world = plain_decoy("5 1 254:3 / /mnt rw - ext4 /dev/mapper/vault rw\n")
        .disk("sdb", "8:16")
        .part("sdb1", "8:17", "sdb")
        .lv("dm-2", "254:2", "backup-data", &["sdb1"])
        .lv("dm-3", "254:3", "vault", &["sdb1"])
        .fstab("/dev/sda1 / ext4 defaults 0 1\n/dev/mapper/backup-data /backup ext4 noauto 0 0\n");
    let verdict = world.verdict("/mnt");
    assert_eq!(
        verdict,
        Verdict::InsideDecoyStorage {
            device: "sdb1".to_string(),
            holds: Claimed::Mount(PathBuf::from("/backup")),
            noauto_only: true,
        }
    );
    assert_eq!(verdict.severity(), Severity::Warn);
}

// ---------------------------------------------------------------------------
// Entries for the hidden drive
// ---------------------------------------------------------------------------

fn entry_kinds(judgement: &Judgement) -> Vec<(EntryKind, &'static str)> {
    judgement.entries.iter().map(|e| (e.kind, e.file)).collect()
}

#[test]
fn a_tcrypt_hidden_line_blocks() {
    let judgement = external_veracrypt()
        .crypttab("vault /dev/sdb none tcrypt-hidden\n")
        .judge("/mnt");
    assert_eq!(judgement.verdict, Verdict::Separate);
    assert_eq!(
        entry_kinds(&judgement),
        vec![(EntryKind::Blocking, CRYPTTAB)]
    );
    assert_eq!(judgement.entries[0].line, "vault /dev/sdb");
}

#[test]
fn a_line_naming_the_hidden_mapping_blocks() {
    // The device is not present under that name, but the mapping name is the
    // one the volume at the root is opened as.
    let judgement = external_veracrypt()
        .crypttab("veracrypt1 UUID=absent none\n")
        .judge("/mnt");
    assert_eq!(judgement.verdict, Verdict::Separate);
    assert_eq!(
        entry_kinds(&judgement),
        vec![(EntryKind::Blocking, CRYPTTAB)]
    );
}

#[test]
fn an_fstab_line_for_the_hidden_filesystem_blocks() {
    let judgement = external_veracrypt()
        .fstab("/dev/sda1 / ext4 defaults 0 1\nUUID=h1 /srv/x ext4 noauto 0 0\n")
        .spec("UUID=h1", "dm-9")
        .judge("/mnt");
    assert_eq!(judgement.verdict, Verdict::Separate);
    assert_eq!(entry_kinds(&judgement), vec![(EntryKind::Blocking, FSTAB)]);
    assert_eq!(judgement.entries[0].why, "it mounts the volume at /mnt");
}

#[test]
fn a_tcrypt_line_for_the_device_of_the_volume_blocks_until_outer_and_hidden_can_be_told_apart() {
    let judgement = external_veracrypt()
        .crypttab("outer /dev/sdb none tcrypt-veracrypt\n")
        .judge("/mnt");
    assert_eq!(judgement.verdict, Verdict::Separate);
    assert_eq!(
        entry_kinds(&judgement),
        vec![(EntryKind::Blocking, CRYPTTAB)]
    );
    assert!(judgement.entries[0].why.contains("cannot be told"));
}

#[test]
fn a_tcrypt_line_for_another_volume_on_the_same_drive_warns() {
    // The hidden volume is on sdb2; the decoy opens the VeraCrypt volume on
    // sdb1, another partition of that drive.
    let world = plain_decoy("5 1 254:9 / /mnt rw - ext4 /dev/mapper/veracrypt1 rw\n")
        .disk("sdb", "8:16")
        .part("sdb1", "8:17", "sdb")
        .part("sdb2", "8:18", "sdb")
        .crypt("dm-9", "254:9", "veracrypt1", &["sdb2"])
        .crypttab("outer /dev/sdb1 none tcrypt-veracrypt\n");
    let judgement = world.judge("/mnt");
    assert_eq!(judgement.verdict, Verdict::Separate);
    assert_eq!(
        entry_kinds(&judgement),
        vec![(EntryKind::OuterWarning, CRYPTTAB)]
    );
}

#[test]
fn a_tcrypt_line_for_a_partition_of_the_disk_the_volume_uses_whole_warns() {
    let judgement = external_veracrypt()
        .part("sdb1", "8:17", "sdb")
        .crypttab("old /dev/sdb1 none tcrypt\n")
        .judge("/mnt");
    assert_eq!(
        entry_kinds(&judgement),
        vec![(EntryKind::OuterWarning, CRYPTTAB)]
    );
}

#[test]
fn an_entry_for_another_device_is_no_finding() {
    let judgement = external_veracrypt()
        .disk("sdc", "8:32")
        .crypttab("backup /dev/sdc none luks,noauto\n")
        .judge("/mnt");
    assert_eq!(judgement.verdict, Verdict::Separate);
    assert!(judgement.entries.is_empty());
}

#[test]
fn a_bind_of_a_data_mount_whose_fstab_spec_does_not_resolve_is_refused() {
    // The label has an escaped space and no /dev/disk link leads to it; the
    // boot still mounted sdc1 at /data.
    let world = plain_decoy(
        "4 1 8:33 / /data rw - ext4 /dev/sdc1 rw\n\
         5 1 8:33 /x /mnt rw - ext4 /dev/sdc1 rw\n",
    )
    .disk("sdc", "8:32")
    .part("sdc1", "8:33", "sdc")
    .fstab(
        "/dev/sda1 / ext4 defaults 0 1\n/dev/sda2 /home ext4 defaults 0 2\n\
         LABEL=My\\040Data /data ext4 defaults 0 2\n",
    );
    assert_eq!(
        world.verdict("/mnt"),
        Verdict::OnDecoyFilesystem {
            how: Sharing::Bind,
            at: PathBuf::from("/data"),
        }
    );
}

// ---------------------------------------------------------------------------
// Storage that cannot be followed to a device
// ---------------------------------------------------------------------------

#[test]
fn an_overlay_whose_upper_is_on_home_is_refused() {
    let verdict = plain_decoy(
        "5 1 0:77 / /mnt rw - overlay overlay rw,lowerdir=/home/u/low,upperdir=/home/u/up,\
         workdir=/home/u/work\n",
    )
    .verdict("/mnt");
    assert_eq!(
        verdict,
        Verdict::UntracedStorage {
            fstype: "overlay".into()
        }
    );
    assert_eq!(verdict.severity(), Severity::Refuse);
}

#[test]
fn an_overlay_whose_upper_is_in_ram_is_refused() {
    // An overlay names its upper directory as the path was when it was
    // mounted, and another filesystem may be mounted there since: even an
    // upper that looks to be in RAM is not followed.
    let world = plain_decoy(
        "3 1 0:25 / /run rw - tmpfs tmpfs rw\n\
         5 1 0:77 / /mnt rw - overlay overlay rw,lowerdir=/home/u/low,upperdir=/run/up,\
         workdir=/run/work\n",
    );
    assert_eq!(
        world.verdict("/mnt"),
        Verdict::UntracedStorage {
            fstype: "overlay".into()
        }
    );
}

#[test]
fn a_fuse_filesystem_is_refused_without_naming_its_program() {
    let verdict =
        plain_decoy("5 1 0:78 / /mnt rw - fuse.gocryptfs /home/u/cipher rw\n").verdict("/mnt");
    assert_eq!(
        verdict,
        Verdict::UntracedStorage {
            fstype: "fuse".into()
        }
    );
    assert_eq!(
        verdict.reason(),
        "it is on a filesystem of type fuse, which shows no disk it stores its data on"
    );
}

#[test]
fn a_stacked_filesystem_is_refused_whatever_its_source_names() {
    // The source of a stacked filesystem is any string; one that names an
    // external disk says nothing about where the data lies.
    let verdict = plain_decoy("5 1 0:79 / /mnt rw - ecryptfs /dev/sdb rw\n")
        .disk("sdb", "8:16")
        .verdict("/mnt");
    assert_eq!(
        verdict,
        Verdict::UntracedStorage {
            fstype: "ecryptfs".into()
        }
    );
}

#[test]
fn a_network_filesystem_is_refused() {
    let verdict = plain_decoy("5 1 0:80 / /mnt rw - nfs4 server:/export rw\n").verdict("/mnt");
    assert_eq!(
        verdict,
        Verdict::UntracedStorage {
            fstype: "nfs4".into()
        }
    );
}

#[test]
fn a_loop_file_on_a_fuse_filesystem_is_refused() {
    // A container opened without kernel crypto: a loop device over the file
    // a FUSE process serves, whose own storage is somewhere else.
    let world = plain_decoy(
        "4 1 0:81 / /tmp/.aux1 rw - fuse.veracrypt veracrypt rw\n\
         5 1 7:3 / /mnt rw - ext4 /dev/loop3 rw\n",
    )
    .loop_file("loop3", "7:3", "/tmp/.aux1/volume");
    assert_eq!(
        world.verdict("/mnt"),
        Verdict::UntracedStorage {
            fstype: "fuse".into()
        }
    );
}

#[test]
fn a_loop_file_on_a_disk_the_decoy_does_not_use_is_separate() {
    let world = plain_decoy(
        "4 1 8:17 / /media/usb rw - ext4 /dev/sdb1 rw\n\
         5 1 7:3 / /mnt rw - ext4 /dev/loop3 rw\n",
    )
    .disk("sdb", "8:16")
    .part("sdb1", "8:17", "sdb")
    .loop_file("loop3", "7:3", "/media/usb/disk.img");
    assert_eq!(world.verdict("/mnt"), Verdict::Separate);
}

// ---------------------------------------------------------------------------
// Inputs that cannot be read
// ---------------------------------------------------------------------------

#[test]
fn an_unreadable_crypttab_cannot_be_judged_on_a_disk_root() {
    let verdict = external_veracrypt().unreadable(CRYPTTAB).verdict("/mnt");
    assert_eq!(
        verdict,
        Verdict::CouldNotJudge {
            unreadable: vec![PathBuf::from(CRYPTTAB)]
        }
    );
    assert_eq!(verdict.severity(), Severity::Refuse);
    assert_eq!(
        verdict.reason(),
        "/etc/crypttab could not be read, so where it lives cannot be told"
    );
}

mod properties {
    use super::*;
    use proptest::prelude::*;

    fn dev() -> impl Strategy<Value = String> {
        (0u32..300, 0u32..40).prop_map(|(major, minor)| format!("{major}:{minor}"))
    }

    proptest! {
        /// Whatever the mount line, devices and files say, the judge answers.
        #[test]
        fn the_judge_never_panics(
            hidden_dev in dev(),
            fstype in "(ext4|btrfs|xfs|tmpfs|vfat)",
            root in "/[a-z]{0,6}",
            fstab in "[ -~\n]{0,200}",
            crypttab in "[ -~\n]{0,200}",
            links in prop::collection::vec((dev(), "[a-z]{1,4}", "[a-z]{1,4}"), 0..8),
        ) {
            let mut world = World::new(&format!(
                "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n\
                 9 1 {hidden_dev} {root} /mnt rw - {fstype} /dev/x rw,subvol={root}\n"
            ))
            .fstab(&fstab)
            .crypttab(&crypttab);
            for (dev, name, below) in &links {
                world = world.node(name, dev, NodeKind::Mapper { name: name.clone() }, &[below]);
            }
            let _ = world.judge("/mnt");
        }

        /// With nothing claimed but a root on no device (a live system's
        /// overlay), any volume on a device of its own is separate.
        #[test]
        fn a_claim_free_table_is_separate(
            hidden_dev in (1u32..300, 0u32..40).prop_map(|(a, b)| format!("{a}:{b}")),
            fstype in "(ext4|btrfs|xfs|vfat)",
            root in "/[a-z]{0,6}",
            name in "[a-z]{1,4}",
        ) {
            let world = World::new(&format!(
                "1 0 0:1 / / rw - overlay overlay rw\n\
                 9 1 {hidden_dev} {root} /mnt rw - {fstype} /dev/{name} rw\n"
            ))
            .crypt(&name, &hidden_dev, &name, &["sdz"])
            .disk("sdz", "8:250");
            prop_assert_eq!(world.verdict("/mnt"), Verdict::Separate);
        }
    }
}
