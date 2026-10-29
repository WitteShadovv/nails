// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the decoy's mount, swap and automount units outside its
//! fstab.

use super::*;
use nails_teardown::mountinfo::parse_mountinfo;
use nails_teardown::whole_root::plan::RequiredMask;
use std::os::unix::fs::symlink;

const HIDDEN: &str = "/mnt/data";

/// A decoy root, its `/run` and its `/sys`.
struct Decoy {
    root: tempfile::TempDir,
    run: tempfile::TempDir,
    sys: tempfile::TempDir,
}

impl Decoy {
    fn new() -> Self {
        Self {
            root: tempfile::tempdir().unwrap(),
            run: tempfile::tempdir().unwrap(),
            sys: tempfile::tempdir().unwrap(),
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
        if let Some(rest) = path.strip_prefix("/sys/") {
            return self.sys.path().join(rest);
        }
        match path.strip_prefix("/run/") {
            Some(rest) => self.run.path().join(rest),
            None => self.root.path().join(path.trim_start_matches('/')),
        }
    }

    fn decide(&self, mounts: &str, present: bool) -> Vec<Decision> {
        let units = read(self.dirs()).expect("the unit directories are listed");
        decide(
            self.dirs(),
            &units,
            &parse_mountinfo(mounts),
            Path::new(HIDDEN),
            &|_| present,
            self.sys.path(),
        )
    }

    /// What the hidden session keeps off for `decisions`, which the fstab
    /// `fstab` and these units were given, and the warnings for the skips it
    /// masks instead.
    fn kept_off(&self, fstab: &str, decisions: &[Decision]) -> (KeptOff, Vec<String>) {
        kept_off(
            self.dirs(),
            &crate::session::fstab::parse_fstab(fstab),
            decisions,
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
        read(decoy.dirs()).unwrap(),
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
    // zram0 has no backing device.
    decoy.write("/sys/block/zram0/backing_dev", "none\n");

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
fn a_zram_swap_that_may_write_back_to_a_disk_is_kept_off_as_disk_swap() {
    let decoy = Decoy::new();
    decoy.write(
        "/run/systemd/generator/dev-zram0.swap",
        "[Unit]\nRequires=systemd-zram-setup@zram0.service\n[Swap]\nWhat=/dev/zram0\n",
    );
    decoy.link(
        "/run/systemd/generator/swap.target.wants/dev-zram0.swap",
        "../dev-zram0.swap",
    );
    let left = Decision::Leave {
        target: "/dev/zram0".into(),
        reason: "a RAM-only zram swap",
    };
    let masked = Decision::Mask {
        target: "/dev/zram0".into(),
        units: vec!["dev-zram0.swap".into()],
        reason: "swap would take hidden RAM onto a decoy disk",
        unreached: None,
    };
    // The device is not there: what the hidden session's zram-generator sets
    // up is not known.
    assert_eq!(decoy.decide(ROOT_ONLY, true), std::slice::from_ref(&masked));
    // A kernel without writeback gives it no backing_dev at all.
    std::fs::create_dir_all(decoy.at("/sys/block/zram0")).unwrap();
    assert_eq!(decoy.decide(ROOT_ONLY, true), std::slice::from_ref(&left));
    for (backing, decision) in [("none\n", &left), ("/dev/vda3\n", &masked)] {
        decoy.write("/sys/block/zram0/backing_dev", backing);
        assert_eq!(
            decoy.decide(ROOT_ONLY, true),
            std::slice::from_ref(decision),
            "{backing}"
        );
    }
    // An attribute that cannot be read tells nothing.
    std::fs::remove_file(decoy.at("/sys/block/zram0/backing_dev")).unwrap();
    std::fs::create_dir(decoy.at("/sys/block/zram0/backing_dev")).unwrap();
    assert_eq!(decoy.decide(ROOT_ONLY, true), [masked]);
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
        let decisions = decoy.decide(ROOT_ONLY, true);
        assert_eq!(
            decisions,
            [Decision::Mask {
                target: "/srv/x".into(),
                units: vec!["srv-x.mount".into()],
                reason,
                unreached: Some(Unreached {
                    target: "local-fs.target".into(),
                    cause: Unskippable::Unread,
                }),
            }],
            "{unit}"
        );
        let warning = decisions[0].warning().expect("a warning");
        for part in [reason, "will not reach local-fs.target"] {
            assert!(warning.contains(part), "{part}: {warning}");
        }
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
        // Paths systemd refuses: a `..` component, a NUL.
        ("srv-..-x.mount", ".mount", None),
        ("srv-\\x00.mount", ".mount", None),
    ] {
        assert_eq!(
            unit_path(name, suffix).as_deref(),
            path.map(Path::new),
            "{name}"
        );
    }
}

#[test]
fn the_units_a_skip_pulls_in_that_act_on_its_device_are_skipped_with_it() {
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
    let (kept, unskipped) = decoy.kept_off(DATA, &decide_data());
    assert!(unskipped.is_empty(), "{unskipped:?}");
    assert_eq!(
        kept.skips,
        [Skip {
            units: vec!["srv-data.mount".into()],
            pulled: vec![
                "systemd-fsck@dev-vdc1.service".into(),
                "systemd-makefs@dev-vdc1.service".into()
            ],
            device: Some("/dev/vdc1".into()),
        }]
    );
}

/// An fstab line `local-fs.target` requires, not mounted now.
const DATA: &str = "/dev/vdc1 /srv/data ext4 defaults 0 2\n";

/// The decisions for [`DATA`], its device there.
fn decide_data() -> Vec<Decision> {
    policy::decide_all(
        &crate::session::fstab::parse_fstab(DATA),
        &parse_mountinfo(ROOT_ONLY),
        Path::new(HIDDEN),
        &|_| true,
    )
}

#[test]
fn a_skip_whose_pulls_cannot_all_be_told_is_masked_with_a_warning() {
    // The administrator's drop-in names a checker by a specifier.
    let by_specifier = Decoy::new();
    by_specifier.write(
        "/etc/systemd/system/srv-data.mount.d/fsck.conf",
        "[Unit]\nRequires=systemd-fsck@%i.service\n",
    );
    by_specifier.write(
        "/run/systemd/generator/srv-data.mount",
        "[Unit]\nSourcePath=/etc/fstab\n[Mount]\nWhat=/dev/vdc1\n",
    );
    // A directory of the units it pulls in is a loop of links.
    let unlisted = Decoy::new();
    unlisted.link(
        "/etc/systemd/system/srv-data.mount.wants",
        "srv-data.mount.wants",
    );
    // Its unit file is one.
    let unreadable = Decoy::new();
    unreadable.link("/etc/systemd/system/srv-data.mount", "srv-data.mount");
    for (decoy, why) in [
        (by_specifier, UNRESOLVED_PULL),
        (unlisted, UNLISTED_PULL),
        (unreadable, UNREADABLE),
    ] {
        let (kept, unskipped) = decoy.kept_off(DATA, &decide_data());
        assert!(kept.skips.is_empty(), "{why}: {:?}", kept.skips);
        assert_eq!(kept.masks, ["srv-data.mount"], "{why}");
        assert_eq!(
            kept.required_masks,
            [RequiredMask {
                unit: "srv-data.mount".into(),
                cause: MaskCause::Undetermined,
                device: None,
            }],
            "{why}"
        );
        assert_eq!(unskipped.len(), 1, "{why}: {unskipped:?}");
        for part in [
            "srv-data.mount is masked rather than skipped",
            why,
            "will not reach the boot target that requires it",
        ] {
            assert!(unskipped[0].contains(part), "{part}: {}", unskipped[0]);
        }
    }
}

#[test]
fn a_directory_of_links_that_cannot_be_listed_refuses_the_entry() {
    for (link, dir) in [
        (
            "/etc/systemd/system/local-fs.target.wants",
            "/etc/systemd/system/local-fs.target.wants",
        ),
        (
            "/run/systemd/generator/local-fs.target.requires",
            "/run/systemd/generator/local-fs.target.requires",
        ),
        // A unit directory itself.
        ("/etc/systemd/system", "/etc/systemd/system"),
    ] {
        let decoy = Decoy::new();
        // A loop of links: the hidden systemd may read what NAILS cannot.
        decoy.link(link, link.rsplit('/').next().unwrap());
        let unlisted = read(decoy.dirs()).expect_err(link);
        assert_eq!(unlisted.dir, Path::new(dir), "{link}");
        let refusal = unlisted.refusal();
        assert!(matches!(refusal, Decision::Refuse { .. }), "{refusal:?}");
        assert!(
            refusal
                .describe()
                .contains(": refused (NAILS cannot list this unit directory: "),
            "{}",
            refusal.describe()
        );
    }
}

#[test]
fn a_unit_whose_files_fail_to_be_looked_up_is_masked_not_read_elsewhere() {
    // A tmpfs the vendor ships, which the administrator's copy, or drop-ins,
    // in a place NAILS cannot look up must not be read past.
    let decoy = Decoy::new();
    decoy.write(
        "/usr/lib/systemd/system/srv-ram.mount",
        "[Mount]\nWhat=tmpfs\nType=tmpfs\n",
    );
    decoy.link(
        "/usr/lib/systemd/system/local-fs.target.requires/srv-ram.mount",
        "../srv-ram.mount",
    );
    assert!(matches!(
        decoy.decide(ROOT_ONLY, true)[..],
        [Decision::Leave { .. }]
    ));
    for path in [
        "/etc/systemd/system/srv-ram.mount",
        "/etc/systemd/system/srv-ram.mount.d",
    ] {
        decoy.link(path, path.rsplit('/').next().unwrap());
        assert_eq!(
            decoy.decide(ROOT_ONLY, true),
            [Decision::Mask {
                target: "/srv/ram".into(),
                units: vec!["srv-ram.mount".into()],
                reason: UNREADABLE,
                unreached: Some(Unreached {
                    target: "local-fs.target".into(),
                    cause: Unskippable::Unread,
                }),
            }],
            "{path}"
        );
        std::fs::remove_file(decoy.at(path)).unwrap();
    }
}

#[test]
fn only_mount_swap_and_automount_units_a_target_pulls_in_are_read() {
    let decoy = Decoy::new();
    decoy.write("/etc/systemd/system/srv-scratch.mount", NATIVE_MOUNT);
    for (link, target) in [
        (
            "local-fs.target.wants/srv-scratch.mount",
            "../srv-scratch.mount",
        ),
        // A service a target wants is no filesystem.
        (
            "local-fs.target.wants/backup.service",
            "/usr/lib/systemd/system/backup.service",
        ),
        // Nor is a link systemd loads no unit by.
        (
            "local-fs.target.wants/.hidden.mount",
            "../srv-scratch.mount",
        ),
    ] {
        decoy.link(&format!("/etc/systemd/system/{link}"), target);
    }
    assert_eq!(
        read(decoy.dirs()).unwrap(),
        [NativeUnit {
            name: "srv-scratch.mount".into(),
            required_by: None,
        }]
    );
}

#[test]
fn a_unit_s_options_pass_on_without_those_only_the_fstab_generator_reads() {
    let unit = unit_file::parse(
        b"[Mount]\nWhat=/dev/vdb1\nWhere=/srv/x\nType=ext4\n\
          Options=ro,noauto,auto,,nofail,fail,x-systemd.wanted-by=a.target,\
          x-systemd.required-by=b.target,x-systemd.automount,\
          comment=systemd.automount,noatime\n",
    )
    .unwrap();
    let entry = as_entry(&unit, "srv-x.mount", Path::new("/srv/x"), None).unwrap();
    assert_eq!(entry.options, ["ro", "noatime"]);
}

#[test]
fn a_zram_device_is_named_by_its_number() {
    assert_eq!(zram_device(Path::new("/dev/zram0")), Some("zram0"));
    assert_eq!(zram_device(Path::new("/dev/zram12")), Some("zram12"));
    for path in [
        "/dev/zram",
        "/dev/zramx",
        "/dev/zram0p1",
        "/dev/vda",
        "/zram0",
    ] {
        assert_eq!(zram_device(Path::new(path)), None, "{path}");
    }
}

#[test]
fn a_filesystem_mounted_now_is_placed_as_the_mount_table_has_it() {
    // The unit names a server, and the decoy has a disk filesystem mounted
    // there now: that filesystem is overlaid, so the hidden systemd finds the
    // mount point mounted.
    let decoy = Decoy::new();
    decoy.write(
        "/usr/lib/systemd/system/srv-scratch.mount",
        "[Mount]\nWhat=server:/export\nWhere=/srv/scratch\nType=nfs4\n",
    );
    decoy.link(
        "/usr/lib/systemd/system/remote-fs.target.wants/srv-scratch.mount",
        "../srv-scratch.mount",
    );
    let disk = format!("{ROOT_ONLY}2 1 8:17 / /srv/scratch rw - ext4 /dev/vdb1 rw\n");
    assert_eq!(
        decoy.decide(&disk, true),
        [Decision::Overlay {
            target: "/srv/scratch".into()
        }]
    );
}

#[test]
fn a_unit_file_of_up_to_four_mebibytes_is_read_and_a_larger_one_is_not() {
    let decoy = Decoy::new();
    // Comments fill the unit file to `size` bytes.
    let sized = |size: usize| {
        let comment = format!("#{}\n", "x".repeat(1022));
        let mut text = NATIVE_MOUNT.to_string();
        while text.len() + comment.len() <= size {
            text.push_str(&comment);
        }
        let padding = "\n".repeat(size - text.len());
        text + &padding
    };
    for (size, loads) in [(2 << 20, true), (4 << 20, true), ((4 << 20) + 1, false)] {
        decoy.write("/etc/systemd/system/srv-scratch.mount", &sized(size));
        let load = decoy.dirs().load("srv-scratch.mount");
        if loads {
            assert!(matches!(load, Load::Loaded(_)), "{size} bytes");
        } else {
            assert!(matches!(load, Load::Unreadable), "{size} bytes");
        }
    }
}

#[test]
fn only_conf_drop_ins_apply_each_name_from_the_first_directory_that_has_it() {
    let decoy = Decoy::new();
    decoy.write(
        "/usr/lib/systemd/system/srv-ram.mount",
        "[Mount]\nWhat=tmpfs\nWhere=/srv/ram\nType=tmpfs\n",
    );
    decoy.write(
        "/etc/systemd/system/srv-ram.mount.d/20-mode.conf",
        "[Mount]\nOptions=mode=0700\n",
    );
    decoy.write(
        "/etc/systemd/system/srv-ram.mount.d/10-size.conf",
        "[Mount]\nOptions=size=1G\n",
    );
    // Hidden by the one of the same name in /etc, which comes first.
    decoy.write(
        "/usr/lib/systemd/system/srv-ram.mount.d/10-size.conf",
        "[Mount]\nWhat=/dev/vdb1\n",
    );
    // No drop-in at all.
    decoy.write(
        "/etc/systemd/system/srv-ram.mount.d/30-off.conf.disabled",
        "[Mount]\nType=ext4\n",
    );
    let Load::Loaded(unit) = decoy.dirs().load("srv-ram.mount") else {
        panic!("the unit loads");
    };
    let mount = |key: &str, value: &str| ("Mount".to_string(), key.to_string(), value.to_string());
    assert_eq!(
        unit.assignments,
        [
            mount("What", "tmpfs"),
            mount("Where", "/srv/ram"),
            mount("Type", "tmpfs"),
            mount("Options", "size=1G"),
            mount("Options", "mode=0700"),
        ]
    );
}

#[test]
fn a_ram_filesystem_over_a_disk_unit_s_mount_point_is_put_in_place_not_left_to_the_unit() {
    // The unit mounts a disk, and the decoy has a tmpfs mounted over its mount
    // point now. Left to the hidden systemd, the unit would mount the disk
    // read-write in the hidden session. The tmpfs is overlaid instead, as for
    // the same line in the fstab, so the hidden systemd finds the mount point
    // mounted and mounts nothing there.
    let decoy = Decoy::new();
    decoy.write("/etc/systemd/system/srv-scratch.mount", NATIVE_MOUNT);
    decoy.link(
        "/etc/systemd/system/local-fs.target.requires/srv-scratch.mount",
        "../srv-scratch.mount",
    );
    let ram = format!("{ROOT_ONLY}2 1 0:45 / /srv/scratch rw - tmpfs tmpfs rw\n");
    let overlay = [Decision::Overlay {
        target: "/srv/scratch".into(),
    }];
    let fstab = crate::session::fstab::parse_fstab(
        "/dev/disk/by-id/virtio-scratch /srv/scratch ext4 defaults 0 2\n",
    );
    assert_eq!(
        policy::decide_all(&fstab, &parse_mountinfo(&ram), Path::new(HIDDEN), &|_| true),
        overlay
    );
    assert_eq!(decoy.decide(&ram, true), overlay);
    // A RAM filesystem the unit mounts itself stays the hidden systemd's.
    decoy.write(
        "/etc/systemd/system/srv-scratch.mount",
        "[Mount]\nWhat=tmpfs\nWhere=/srv/scratch\nType=tmpfs\n",
    );
    assert!(matches!(
        decoy.decide(&ram, true)[..],
        [Decision::Leave { .. }]
    ));
}
