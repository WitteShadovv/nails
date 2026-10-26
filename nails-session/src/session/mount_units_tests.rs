// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the decoy's mount, swap and automount units outside its
//! fstab.

use super::*;
use nails_teardown::mountinfo::parse_mountinfo;
use std::os::unix::fs::symlink;

const HIDDEN: &str = "/mnt/data";

/// A decoy root and its `/run`.
struct Decoy {
    root: tempfile::TempDir,
    run: tempfile::TempDir,
}

impl Decoy {
    fn new() -> Self {
        Self {
            root: tempfile::tempdir().unwrap(),
            run: tempfile::tempdir().unwrap(),
        }
    }

    fn dirs(&self) -> UnitDirs<'_> {
        UnitDirs {
            root: self.root.path(),
            run: self.run.path(),
        }
    }

    /// Write `text` at `path` below the root (`/run/...` below the run).
    fn write(&self, path: &str, text: &str) {
        let full = self.at(path);
        std::fs::create_dir_all(full.parent().unwrap()).unwrap();
        std::fs::write(full, text).unwrap();
    }

    /// Link `path` to `target`, as `systemctl enable` and generators do.
    fn link(&self, path: &str, target: &str) {
        let full = self.at(path);
        std::fs::create_dir_all(full.parent().unwrap()).unwrap();
        symlink(target, full).unwrap();
    }

    fn at(&self, path: &str) -> PathBuf {
        match path.strip_prefix("/run/") {
            Some(rest) => self.run.path().join(rest),
            None => self.root.path().join(path.trim_start_matches('/')),
        }
    }

    fn decide(&self, mounts: &str, present: bool) -> Vec<Decision> {
        let units = read(self.dirs());
        decide(
            self.dirs(),
            &units,
            &parse_mountinfo(mounts),
            Path::new(HIDDEN),
            &|_| present,
        )
    }
}

/// The decoy's root, and nothing else mounted.
const ROOT_ONLY: &str = "1 0 8:2 / / rw - ext4 /dev/vda2 rw\n";

const NATIVE_MOUNT: &str = "[Unit]\nDescription=Scratch\nRequires=systemd-fsck@dev-disk-by\\x2did-virtio\\x2dscratch.service\n\
                            [Mount]\nWhat=/dev/disk/by-id/virtio-scratch\nWhere=/srv/scratch\nType=ext4\n";

#[test]
fn a_native_mount_a_target_requires_is_skipped_with_its_fsck_while_its_disk_is_there() {
    let decoy = Decoy::new();
    decoy.write("/etc/systemd/system/srv-scratch.mount", NATIVE_MOUNT);
    decoy.link(
        "/etc/systemd/system/local-fs.target.requires/srv-scratch.mount",
        "../srv-scratch.mount",
    );
    assert_eq!(
        read(decoy.dirs()),
        [NativeUnit {
            name: "srv-scratch.mount".into(),
            required_by: Some("local-fs.target".into()),
        }]
    );
    let decisions = decoy.decide(ROOT_ONLY, true);
    assert_eq!(
        decisions,
        [Decision::Skip {
            target: "/srv/scratch".into(),
            skip: Skip {
                units: vec!["srv-scratch.mount".into()],
                pulled: vec!["systemd-fsck@dev-disk-by\\x2did-virtio\\x2dscratch.service".into()],
                device: Some("/dev/disk/by-id/virtio-scratch".into()),
            },
            masked: Vec::new(),
            reason: "not mounted now; the hidden session would mount it read-write",
        }]
    );

    // Its disk is not there: masked, and local-fs.target is not reached.
    let decisions = decoy.decide(ROOT_ONLY, false);
    assert_eq!(decisions[0].masked_units(), ["srv-scratch.mount"]);
    let warning = decisions[0].warning().expect("a warning");
    assert!(warning.contains("local-fs.target"), "{warning}");
}

#[test]
fn a_native_mount_targets_only_want_is_masked() {
    let decoy = Decoy::new();
    decoy.write("/etc/systemd/system/srv-scratch.mount", NATIVE_MOUNT);
    decoy.link(
        "/etc/systemd/system/multi-user.target.wants/srv-scratch.mount",
        "/etc/systemd/system/srv-scratch.mount",
    );
    let decisions = decoy.decide(ROOT_ONLY, false);
    assert!(
        matches!(&decisions[..], [Decision::Mask { units, unreached: None, .. }] if units == &["srv-scratch.mount"]),
        "{decisions:?}"
    );
}

#[test]
fn a_native_mount_mounted_now_is_overlaid_or_bound_read_only() {
    let decoy = Decoy::new();
    decoy.write("/usr/lib/systemd/system/srv-scratch.mount", NATIVE_MOUNT);
    decoy.link(
        "/usr/lib/systemd/system/local-fs.target.wants/srv-scratch.mount",
        "../srv-scratch.mount",
    );
    let rw = format!("{ROOT_ONLY}2 1 8:17 / /srv/scratch rw - ext4 /dev/vdb1 rw\n");
    assert_eq!(
        decoy.decide(&rw, false),
        [Decision::Overlay {
            target: "/srv/scratch".into()
        }]
    );
    let ro = format!("{ROOT_ONLY}2 1 8:17 / /srv/scratch ro - squashfs /dev/loop3 ro\n");
    assert_eq!(
        decoy.decide(&ro, false),
        [Decision::ReadOnlyBind {
            target: "/srv/scratch".into()
        }]
    );
}

#[test]
fn ram_kernel_and_fstab_units_and_the_decoy_s_masks_are_left_to_the_hidden_systemd() {
    let decoy = Decoy::new();
    // A tmpfs and a kernel filesystem as systemd ships them.
    decoy.write(
        "/usr/lib/systemd/system/tmp.mount",
        "[Mount]\nWhat=tmpfs\nWhere=/tmp\nType=tmpfs\nOptions=mode=1777,strictatime\n",
    );
    decoy.link(
        "/usr/lib/systemd/system/local-fs.target.wants/tmp.mount",
        "../tmp.mount",
    );
    decoy.write(
        "/usr/lib/systemd/system/dev-hugepages.mount",
        "[Mount]\nWhat=hugetlbfs\nWhere=/dev/hugepages\nType=hugetlbfs\n",
    );
    decoy.link(
        "/usr/lib/systemd/system/sysinit.target.wants/dev-hugepages.mount",
        "../dev-hugepages.mount",
    );
    decoy.write(
        "/usr/lib/systemd/system/proc-sys-fs-binfmt_misc.automount",
        "[Automount]\nWhere=/proc/sys/fs/binfmt_misc\n",
    );
    decoy.write(
        "/usr/lib/systemd/system/proc-sys-fs-binfmt_misc.mount",
        "[Mount]\nWhat=binfmt_misc\nWhere=/proc/sys/fs/binfmt_misc\nType=binfmt_misc\n",
    );
    decoy.link(
        "/usr/lib/systemd/system/sysinit.target.wants/proc-sys-fs-binfmt_misc.automount",
        "../proc-sys-fs-binfmt_misc.automount",
    );
    // The fstab generator's unit for an fstab line: the fstab policy's.
    decoy.write(
        "/run/systemd/generator/srv-data.mount",
        "[Unit]\nSourcePath=/etc/fstab\n[Mount]\nWhat=/dev/vdc1\nWhere=/srv/data\nType=ext4\n",
    );
    decoy.link(
        "/run/systemd/generator/local-fs.target.requires/srv-data.mount",
        "../srv-data.mount",
    );
    // A unit the decoy masks, and one the decoy's own unit masks below it.
    decoy.link("/etc/systemd/system/srv-old.mount", "/dev/null");
    decoy.link(
        "/etc/systemd/system/local-fs.target.requires/srv-old.mount",
        "/etc/systemd/system/srv-old.mount",
    );
    decoy.write("/etc/systemd/system/srv-empty.mount", "");
    decoy.write("/usr/lib/systemd/system/srv-empty.mount", NATIVE_MOUNT);
    decoy.link(
        "/usr/lib/systemd/system/local-fs.target.requires/srv-empty.mount",
        "../srv-empty.mount",
    );
    // An initrd target's unit: only an initrd starts it.
    decoy.write("/usr/lib/systemd/system/sysroot.mount", NATIVE_MOUNT);
    decoy.link(
        "/usr/lib/systemd/system/initrd-root-fs.target.requires/sysroot.mount",
        "../sysroot.mount",
    );

    let decisions = decoy.decide(ROOT_ONLY, false);
    assert!(
        decisions
            .iter()
            .all(|decision| matches!(decision, Decision::Leave { .. })),
        "{decisions:?}"
    );
    let left: Vec<String> = decisions.iter().map(Decision::describe).collect();
    assert_eq!(
        left,
        [
            "/tmp: left as is (RAM or kernel filesystem)",
            "/dev/hugepages: left as is (RAM or kernel filesystem)",
            "/proc/sys/fs/binfmt_misc: left as is (RAM or kernel filesystem)",
        ]
    );
}

#[test]
fn zram_swap_is_left_and_a_disk_swap_is_kept_off_with_its_mkswap() {
    let decoy = Decoy::new();
    // zram-generator's swap, which swap.target wants.
    decoy.write(
        "/run/systemd/generator/dev-zram0.swap",
        "[Unit]\nRequires=systemd-zram-setup@zram0.service\n[Swap]\nWhat=/dev/zram0\nPriority=100\n",
    );
    decoy.link(
        "/run/systemd/generator/swap.target.wants/dev-zram0.swap",
        "../dev-zram0.swap",
    );
    // A swap partition of a native unit swap.target requires, which NixOS's
    // mkswap service formats first, and a swap file.
    decoy.write(
        "/etc/systemd/system/dev-vdb2.swap",
        "[Swap]\nWhat=/dev/vdb2\nOptions=discard\n",
    );
    decoy.link(
        "/etc/systemd/system/swap.target.requires/dev-vdb2.swap",
        "../dev-vdb2.swap",
    );
    decoy.link(
        "/etc/systemd/system/dev-vdb2.swap.wants/mkswap-dev-vdb2.service",
        "../mkswap-dev-vdb2.service",
    );
    decoy.link(
        "/etc/systemd/system/dev-vdb2.swap.wants/swap-alert.service",
        "../swap-alert.service",
    );
    decoy.write(
        "/etc/systemd/system/swap-swapfile.swap",
        "[Swap]\nWhat=/swap/swapfile\n",
    );
    decoy.link(
        "/etc/systemd/system/swap.target.requires/swap-swapfile.swap",
        "../swap-swapfile.swap",
    );

    let decisions = decoy.decide(ROOT_ONLY, true);
    assert_eq!(decisions.len(), 3, "{decisions:?}");
    // The mkswap that writes the partition is skipped with it; the service
    // that only wants the swap is not one of them.
    assert_eq!(
        decisions[0].skip(),
        Some(&Skip {
            units: vec!["dev-vdb2.swap".into()],
            pulled: vec!["mkswap-dev-vdb2.service".into()],
            device: Some("/dev/vdb2".into()),
        })
    );
    assert_eq!(
        decisions[1].skip(),
        Some(&Skip {
            units: vec!["swap-swapfile.swap".into()],
            pulled: Vec::new(),
            device: None,
        })
    );
    assert_eq!(
        decisions[2],
        Decision::Leave {
            target: "/dev/zram0".into(),
            reason: "a RAM-only zram swap",
        }
    );
}

#[test]
fn the_gpt_auto_esp_is_bound_read_only_and_its_automount_kept_off() {
    // arch-boxes: the ESP is not in the fstab; the GPT auto-generator mounts
    // it at /efi behind an automount local-fs.target wants.
    let decoy = Decoy::new();
    decoy.write(
        "/run/systemd/generator.late/efi.automount",
        "[Unit]\nDescription=EFI System Partition Automount\n[Automount]\nWhere=/efi\nTimeoutIdleSec=120\n",
    );
    decoy.write(
        "/run/systemd/generator.late/efi.mount",
        "[Unit]\nDescription=EFI System Partition Automount\nRequires=systemd-fsck@dev-disk-by\\x2ddiskseq-1\\x2dpart1.service\n\
         [Mount]\nWhat=/dev/disk/by-diskseq/1-part1\nWhere=/efi\nType=vfat\nOptions=umask=0077,noauto,rw\n",
    );
    decoy.link(
        "/run/systemd/generator.late/local-fs.target.wants/efi.automount",
        "../efi.automount",
    );
    let mask_automount = Decision::Mask {
        target: "/efi".into(),
        units: vec!["efi.automount".into()],
        reason: "the session puts the filesystem behind it in place",
        unreached: None,
    };
    // Mounted, or only the automount set up: the bind of /efi mounts the ESP
    // on it.
    for mounted in [
        "2 1 0:40 / /efi rw - autofs systemd-1 rw,fd=50,direct\n3 2 8:1 / /efi rw - vfat /dev/vda1 rw\n",
        "2 1 0:40 / /efi rw - autofs systemd-1 rw,fd=50,direct\n",
    ] {
        assert_eq!(
            decoy.decide(&format!("{ROOT_ONLY}{mounted}"), true),
            [
                Decision::ReadOnlyBind {
                    target: "/efi".into()
                },
                mask_automount.clone()
            ]
        );
    }
    // Not mounted: both kept off, the automount only wanted, so masked.
    assert_eq!(
        decoy.decide(ROOT_ONLY, true)[0].masked_units(),
        ["efi.mount", "efi.automount"]
    );
    // Required, the automount is skipped and the mount behind it masked.
    decoy.link(
        "/etc/systemd/system/local-fs.target.requires/efi.automount",
        "/run/systemd/generator.late/efi.automount",
    );
    let decisions = decoy.decide(ROOT_ONLY, true);
    assert_eq!(decisions[0].masked_units(), ["efi.mount"]);
    assert_eq!(decisions[0].skip().unwrap().units, ["efi.automount"]);
}

#[test]
fn a_drop_in_is_read_after_its_unit_file() {
    let decoy = Decoy::new();
    decoy.write(
        "/usr/lib/systemd/system/srv-ram.mount",
        "[Mount]\nWhat=tmpfs\nWhere=/srv/ram\nType=tmpfs\n",
    );
    decoy.link(
        "/usr/lib/systemd/system/local-fs.target.wants/srv-ram.mount",
        "../srv-ram.mount",
    );
    assert!(matches!(
        decoy.decide(ROOT_ONLY, true)[..],
        [Decision::Leave { .. }]
    ));
    // The administrator's drop-in mounts a disk there instead.
    decoy.write(
        "/etc/systemd/system/srv-ram.mount.d/50-disk.conf",
        "[Mount]\nWhat=/dev/vdd1\nType=ext4\n",
    );
    decoy.link(
        "/run/systemd/system/srv-ram.mount.d/10-masked.conf",
        "/dev/null",
    );
    assert_eq!(
        decoy.decide(ROOT_ONLY, true)[0].masked_units(),
        ["srv-ram.mount"]
    );
}

#[test]
fn a_unit_that_cannot_be_read_or_resolved_is_masked() {
    for (unit, reason) in [
        ("[Mount\nWhat=/dev/vdd1\n", "its unit files cannot be read"),
        (
            "[Mount]\nWhat=/dev/disk/by-label/%H\nType=ext4\n",
            UNRESOLVED,
        ),
        (
            "[Mount]\nType=ext4\n",
            "its unit names no source, so it does not load",
        ),
    ] {
        let decoy = Decoy::new();
        decoy.write("/etc/systemd/system/srv-x.mount", unit);
        decoy.link(
            "/etc/systemd/system/local-fs.target.requires/srv-x.mount",
            "../srv-x.mount",
        );
        assert_eq!(
            decoy.decide(ROOT_ONLY, true),
            [Decision::Mask {
                target: "/srv/x".into(),
                units: vec!["srv-x.mount".into()],
                reason,
                unreached: None,
            }],
            "{unit}"
        );
    }
    // A FIFO, which a read would wait on, and a link to a device a read
    // never ends: not regular files, so never read.
    let fifo: fn(&Path) = |path| {
        rustix::fs::mknodat(
            rustix::fs::CWD,
            path,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o644),
            0,
        )
        .unwrap();
    };
    let device: fn(&Path) = |path| symlink("/dev/zero", path).unwrap();
    for make in [fifo, device] {
        let decoy = Decoy::new();
        let unit = decoy.at("/etc/systemd/system/srv-x.mount");
        std::fs::create_dir_all(unit.parent().unwrap()).unwrap();
        make(&unit);
        decoy.link(
            "/etc/systemd/system/local-fs.target.requires/srv-x.mount",
            "../srv-x.mount",
        );
        assert_eq!(
            decoy.decide(ROOT_ONLY, true)[0].masked_units(),
            ["srv-x.mount"]
        );
    }
    // A link to a unit no directory has.
    let decoy = Decoy::new();
    decoy.link(
        "/etc/systemd/system/local-fs.target.wants/srv-y.mount",
        "/opt/units/srv-y.mount",
    );
    assert_eq!(
        decoy.decide(ROOT_ONLY, true)[0].masked_units(),
        ["srv-y.mount"]
    );
}

#[test]
fn a_unit_name_is_the_escape_of_its_path() {
    for (name, suffix, path) in [
        ("-.mount", ".mount", Some("/")),
        ("srv-scratch.mount", ".mount", Some("/srv/scratch")),
        (
            "dev-disk-by\\x2did-virtio\\x2dswap.swap",
            ".swap",
            Some("/dev/disk/by-id/virtio-swap"),
        ),
        ("\\x2esnapshots.mount", ".mount", Some("/.snapshots")),
        (
            "mnt-My\\x20Disk.automount",
            ".automount",
            Some("/mnt/My Disk"),
        ),
        // Not the name systemd makes for any path.
        ("srv--x.mount", ".mount", None),
        ("srv-x-.mount", ".mount", None),
        (".snapshots.mount", ".mount", None),
        ("srv-my-disk\\x2.mount", ".mount", None),
        ("mnt-\\xff.mount", ".mount", None),
        ("srv.swap", ".mount", None),
    ] {
        assert_eq!(
            unit_path(name, suffix).as_deref(),
            path.map(Path::new),
            "{name}"
        );
    }
}

#[test]
fn the_units_a_skip_pulls_in_that_act_on_its_device_are_added() {
    let decoy = Decoy::new();
    decoy.write(
        "/run/systemd/generator/srv-data.mount",
        "[Unit]\nSourcePath=/etc/fstab\nRequires=systemd-fsck@dev-vdc1.service\nWants=network-online.target\n",
    );
    decoy.link(
        "/run/systemd/generator/srv-data.mount.requires/systemd-makefs@dev-vdc1.service",
        "/usr/lib/systemd/system/systemd-makefs@.service",
    );
    decoy.link(
        "/etc/systemd/system/srv-data.mount.wants/backup.service",
        "../backup.service",
    );
    let mut skips = vec![Skip {
        units: vec!["srv-data.mount".into()],
        pulled: vec!["systemd-fsck@dev-vdc1.service".into()],
        device: Some("/dev/vdc1".into()),
    }];
    pull_in(decoy.dirs(), &mut skips);
    assert_eq!(
        skips[0].pulled,
        [
            "systemd-fsck@dev-vdc1.service",
            "systemd-makefs@dev-vdc1.service"
        ]
    );
}
