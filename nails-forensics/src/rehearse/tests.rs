// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The rehearsal: tokens and state, the redirect guard, planting through a
//! real overlay (in a user + mount namespace), and scans of image files.

use super::plant::redirect_for;
use super::*;
use crate::filesystem::parse_mountinfo;
use crate::forensic::Encoding;
use crate::test_support::{Rerun, ScratchTmpfs};
use std::io::{Seek, SeekFrom, Write};

pub(super) const TOKEN: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"; // pragma: allowlist secret

fn state(token: &str) -> RehearsalState {
    RehearsalState {
        schema_version: STATE_SCHEMA_VERSION,
        token: token.to_string(),
        phase: Phase::Planted,
        planted_at: "2026-10-07T10:00:00Z".to_string(),
        planted_boot_id: Some("boot-a".to_string()),
        planted_entered_at: None,
        planted_soft_reboots: Some(2),
        channels: Vec::new(),
        scans: Vec::new(),
    }
}

#[test]
fn tokens_are_random_hex_and_only_a_fingerprint_is_printable() {
    let a = generate_token().unwrap();
    let b = generate_token().unwrap();
    assert!(valid_token(&a), "{a}");
    assert_eq!(a.len(), 32);
    assert_ne!(a, b);
    let print = fingerprint(&a);
    assert_eq!(print.chars().count(), 7);
    assert!(!print.contains(&a[6..]));
    assert!(!valid_token("short"));
    assert!(!valid_token("zz1e2d3c4b5a69788796a5b4c3d2e1f0"));
}

#[test]
fn the_state_is_refused_on_an_unmounted_hidden_root() {
    let fs = crate::MockFilesystem::new();
    let root = Path::new("/mnt/data");
    fs.mock_set_path_exists("/mnt/data", true);
    fs.mock_set_path_exists("/mnt/data/state.json", true);

    let err = save_state(&fs, root, &state(TOKEN)).unwrap_err();
    assert!(
        err.to_string().contains("is not a volume of its own"),
        "{err}"
    );
    assert!(
        fs.get_written_content(&root.join(state_relative_path()))
            .is_none()
    );
}

#[test]
fn reset_on_an_unattached_root_deletes_nothing() {
    // The state and a planted copy exist on disk, but the gate sees the root
    // as a folder on `/`: nothing may be removed from it.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join(REHEARSE_DIR)).unwrap();
    std::fs::write(root.join(state_relative_path()), "{}").unwrap();
    let copy = root.join(format!("home/{FILE_PREFIX}{TOKEN}.txt"));
    std::fs::create_dir_all(copy.parent().unwrap()).unwrap();
    std::fs::write(&copy, TOKEN).unwrap();
    let mut st = state(TOKEN);
    st.channels = vec![ChannelRecord {
        kind: ChannelKind::OverlayFile,
        location: "/home".to_string(),
        upper_copy: Some(copy.clone()),
        skipped: None,
    }];

    let fs = crate::MockFilesystem::new();
    fs.mock_set_path_exists(root.to_str().unwrap(), true);
    fs.mock_set_mount_table("1 0 8:1 / / rw - ext4 /dev/vda1 rw\n");
    let error = reset(&fs, root, &st).unwrap_err();
    assert!(
        error.to_string().contains("is not a volume of its own"),
        "{error}"
    );
    assert!(root.join(state_relative_path()).exists());
    assert!(copy.exists());
}

#[test]
fn the_state_round_trips_on_a_mounted_hidden_volume() {
    let _ = Rerun::new(crate::test_path!(
        the_state_round_trips_on_a_mounted_hidden_volume
    ))
    .in_user_mount_ns()
    .run(|| {
        let hidden = ScratchTmpfs::new("size=4M");
        std::fs::create_dir_all(hidden.path().join("config")).unwrap();
        std::fs::write(hidden.path().join("config/nails.toml"), "").unwrap();
        let fs = crate::RealFilesystem;

        assert_eq!(load_state(&fs, hidden.path()).unwrap(), None);
        save_state(&fs, hidden.path(), &state(TOKEN)).unwrap();
        let loaded = load_state(&fs, hidden.path()).unwrap().unwrap();
        assert_eq!(loaded, state(TOKEN));

        let removed = reset(&fs, hidden.path(), &loaded).unwrap();
        assert_eq!(removed, vec![hidden.path().join(state_relative_path())]);
        assert_eq!(load_state(&fs, hidden.path()).unwrap(), None);
    });
}

/// A mount table: `/` on the decoy disk, the hidden volume at /mnt/data, an
/// overlay on /home whose upper is on it, and a foreign overlay on /opt.
fn mounts() -> Vec<crate::filesystem::MountEntry> {
    parse_mountinfo(
        "1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n\
         2 1 253:0 / /mnt/data rw,relatime - ext4 /dev/mapper/data rw\n\
         3 1 0:40 / /home rw,relatime - overlay overlay rw,lowerdir=/home,upperdir=/mnt/data/home,workdir=/mnt/data/.work/home\n\
         4 1 0:41 / /opt rw,relatime - overlay overlay rw,lowerdir=/opt,upperdir=/var/opt-upper,workdir=/var/opt-work\n\
         5 3 253:0 /persona/home /home/alice rw,relatime - ext4 /dev/mapper/data rw\n\
         6 1 7:0 / /nix/.ro-store ro,relatime - erofs /dev/vdb ro\n\
         7 1 8:16 / /media/usb rw,relatime - vfat /dev/sdb1 rw\n",
    )
}

#[test]
fn a_write_is_redirected_only_onto_the_hidden_volume() {
    let mounts = mounts();
    let hidden = Path::new("/mnt/data");

    let home = redirect_for(Path::new("/home/bob/docs"), &mounts, hidden).unwrap();
    assert_eq!(home.hidden_dir, Path::new("/mnt/data/home/bob/docs"));
    // A persona bind from the hidden volume is the hidden volume.
    let persona = redirect_for(Path::new("/home/alice"), &mounts, hidden).unwrap();
    assert_eq!(persona.hidden_dir, Path::new("/home/alice"));
    // The decoy root, a foreign overlay and another disk are refused.
    assert!(redirect_for(Path::new("/etc"), &mounts, hidden).is_none());
    assert!(redirect_for(Path::new("/opt/x"), &mounts, hidden).is_none());
    assert!(redirect_for(Path::new("/media/usb"), &mounts, hidden).is_none());
}

#[test]
fn default_targets_are_the_writable_decoy_devices_and_swap() {
    let swaps = "Filename\tType\tSize\tUsed\tPriority\n/dev/sdc2 partition 1024 0 -2\n/swapfile file 10 0 -3\n";
    let targets = default_scan_targets(&mounts(), swaps, Path::new("/mnt/data"));
    assert_eq!(
        targets.iter().map(|t| t.device.clone()).collect::<Vec<_>>(),
        vec![
            PathBuf::from("/dev/sda1"),
            PathBuf::from("/dev/sdb1"),
            PathBuf::from("/dev/sdc2"),
        ]
    );
    // The decoy root and USB are ext4 and vfat, and swap carries no filesystem:
    // none is a storage blind spot.
    assert!(targets.iter().all(|t| t.blind_spot.is_none()));
    // The mount table and the swap list name each one's storage, so the scan
    // does not identify it again, and each is a device it reads. A mounted
    // one keeps the type its mount shows, which says whether the scan reads
    // its superblock for the encrypt feature.
    assert!(
        targets.iter().all(|t| !t.probe && t.unread.is_none()),
        "{targets:?}"
    );
    assert_eq!(
        targets
            .iter()
            .map(|t| t.fstype.as_deref())
            .collect::<Vec<_>>(),
        vec![Some("ext4"), Some("vfat"), None]
    );
}

#[test]
fn a_zfs_dataset_is_listed_unread_and_not_checked() {
    // A zfs dataset is named by its pool, not by a device, so a raw scan cannot
    // read it. It is listed with its blind spot all the same (once, however
    // often it is mounted), so a zfs decoy is never reported clean, while a
    // tmpfs and the hidden volume stay out.
    let mounts = parse_mountinfo(
        "1 0 0:30 / / rw,relatime - zfs rpool/ROOT/decoy rw,xattr,noacl\n\
         2 1 0:31 / /home rw,relatime - zfs rpool/home rw,xattr,noacl\n\
         3 1 0:31 / /srv rw,relatime - zfs rpool/home rw,xattr,noacl\n\
         4 1 253:0 / /mnt/data rw,relatime - ext4 /dev/mapper/data rw\n\
         5 1 0:32 / /tmp rw - tmpfs tmpfs rw\n",
    );
    let targets = default_scan_targets(&mounts, "", Path::new("/mnt/data"));
    assert_eq!(
        targets.iter().map(|t| t.device.clone()).collect::<Vec<_>>(),
        vec![
            PathBuf::from("rpool/ROOT/decoy"),
            PathBuf::from("rpool/home")
        ]
    );
    assert!(
        targets.iter().all(|t| t.unread.is_some()
            && t.blind_spot
                .as_deref()
                .is_some_and(|reason| reason.contains("copy-on-write"))),
        "{targets:?}"
    );

    let report = scan(TOKEN, &targets, None).unwrap();

    assert!(report.inconclusive(), "{report:?}");
    assert!(report.incomplete(), "{report:?}");
    for device in &report.devices {
        assert_eq!(device.bytes_scanned, 0, "{device:?}");
        assert!(
            device
                .error
                .as_deref()
                .is_some_and(|error| error.contains("a zfs mount")),
            "{device:?}"
        );
    }
}

#[test]
fn a_copy_on_write_decoy_root_is_marked_a_blind_spot() {
    // The decoy root is btrfs; the hidden volume and a vfat ESP are not.
    let mounts = parse_mountinfo(
        "1 0 8:1 / / rw,relatime - btrfs /dev/sda2 rw,ssd,space_cache=v2,subvolid=256\n\
         2 1 253:0 / /mnt/data rw,relatime - ext4 /dev/mapper/data rw\n\
         3 1 8:0 / /boot/efi rw,relatime - vfat /dev/sda1 rw\n",
    );
    let targets = default_scan_targets(&mounts, "", Path::new("/mnt/data"));
    let root = targets
        .iter()
        .find(|t| t.device.as_path() == Path::new("/dev/sda2"))
        .expect("the btrfs root is a target");
    assert!(
        root.blind_spot
            .as_deref()
            .is_some_and(|reason| reason.contains("copy-on-write")),
        "{root:?}"
    );
    // The vfat ESP is verbatim storage: a clean scan of it is a clean result.
    let esp = targets
        .iter()
        .find(|t| t.device.as_path() == Path::new("/dev/sda1"))
        .expect("the ESP is a target");
    assert!(esp.blind_spot.is_none(), "{esp:?}");
}

#[test]
fn a_mounted_f2fs_is_judged_by_its_mount_options() {
    // The kernel lists compress_algorithm= and compress_log_size= among the
    // options of every mounted f2fs made with the compression feature, so the
    // root, made with it, is a blind spot. /home was made without it: the
    // kernel refuses the compression flag there, and a clean scan is clean.
    let mounts = parse_mountinfo(
        "1 0 8:2 / / rw,relatime - f2fs /dev/sda2 rw,lazytime,background_gc=on,discard,\
         compress_algorithm=lz4,compress_log_size=2,compress_mode=fs,alloc_mode=default\n\
         2 1 8:3 / /home rw,relatime - f2fs /dev/sda3 rw,lazytime,background_gc=on,discard,\
         flush_merge,extent_cache,mode=adaptive,alloc_mode=default\n\
         3 1 253:0 / /mnt/data rw,relatime - ext4 /dev/mapper/data rw\n",
    );
    let targets = default_scan_targets(&mounts, "", Path::new("/mnt/data"));
    let target = |device: &str| {
        targets
            .iter()
            .find(|t| t.device.as_path() == Path::new(device))
            .unwrap_or_else(|| panic!("{device} is a target: {targets:?}"))
    };
    assert!(
        target("/dev/sda2")
            .blind_spot
            .as_deref()
            .is_some_and(|reason| reason.contains("compresses file contents")),
        "{:?}",
        target("/dev/sda2")
    );
    assert_eq!(target("/dev/sda3").blind_spot, None);
}

#[test]
fn classified_reads_the_blind_spot_from_the_matching_mount_entry() {
    // Two devices named only in the mount table (so neither path canonicalizes),
    // matched to their entry by an exact source path. A `classified` target
    // carries the blind spot of the filesystem on its own device, not another's.
    let mounts = parse_mountinfo(
        "1 0 8:1 / / rw,relatime - btrfs /dev/nails-test-btrfs rw,ssd,space_cache=v2\n\
         2 1 253:0 / /mnt/data rw,relatime - ext4 /dev/nails-test-ext4 rw\n",
    );

    // The btrfs device matches its own entry: a copy-on-write blind spot lands on
    // it. (Kills `==`->`!=` at the source match and `||`->`&&`: either flip makes
    // this entry stop matching, so the btrfs reason is lost.)
    // No eCryptfs mount is active, so no sysfs is read.
    let fs = crate::MockFilesystem::new();
    let cow = ScanTarget::classified(&fs, PathBuf::from("/dev/nails-test-btrfs"), &mounts);
    assert_eq!(cow.device, PathBuf::from("/dev/nails-test-btrfs"));
    assert!(
        cow.blind_spot
            .as_deref()
            .is_some_and(|reason| reason.contains("copy-on-write")),
        "{cow:?}"
    );

    // The ext4 device matches its own entry, not the btrfs one: a clean scan of
    // verbatim storage is conclusive. (A flipped source match would pick the
    // btrfs entry and wrongly mark it a blind spot.)
    let plain = ScanTarget::classified(&fs, PathBuf::from("/dev/nails-test-ext4"), &mounts);
    assert_eq!(plain.device, PathBuf::from("/dev/nails-test-ext4"));
    assert!(plain.blind_spot.is_none(), "{plain:?}");
    // Both are named by the mount table, so the scan does not identify them
    // again; a device it does not show is identified from its raw bytes.
    assert!(!cow.probe && !plain.probe);
    assert_eq!(cow.fstype.as_deref(), Some("btrfs"));
    assert_eq!(plain.fstype.as_deref(), Some("ext4"));
    let unmounted =
        ScanTarget::classified(&fs, PathBuf::from("/dev/nails-test-unmounted"), &mounts);
    assert!(
        unmounted.probe && unmounted.blind_spot.is_none() && unmounted.fstype.is_none(),
        "{unmounted:?}"
    );
}

#[test]
fn classified_matches_a_device_to_its_entry_by_canonical_path() {
    // The device and the mount entry name the same disk through two different
    // symlinks (as /dev/disk/by-id/… and /dev/mapper/… do): not equal as text,
    // tied together only by canonicalizing both to the real node. The btrfs blind
    // spot must still reach the device. This exercises the second comparison,
    // whose `==`->`!=` flip only shows up when the exact source match is false
    // and canonicalization succeeds on both sides.
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("realdev");
    std::fs::write(&real, b"").unwrap();
    let real = real.canonicalize().unwrap();
    let by_device = dir.path().join("by-id");
    let by_mount = dir.path().join("by-uuid");
    std::os::unix::fs::symlink(&real, &by_device).unwrap();
    std::os::unix::fs::symlink(&real, &by_mount).unwrap();
    assert_ne!(by_device, by_mount, "the two names must differ as text");

    let entry = crate::filesystem::MountEntry {
        mount_id: 1,
        parent_id: 0,
        dev: "253:0".to_string(),
        root: PathBuf::from("/"),
        mount_point: PathBuf::from("/"),
        mount_opts: "rw,relatime".to_string(),
        fstype: "btrfs".to_string(),
        source: by_mount.clone(),
        super_opts: "rw,ssd,space_cache=v2".to_string(),
    };

    let target = ScanTarget::classified(&crate::MockFilesystem::new(), by_device.clone(), &[entry]);
    // The device is recorded by its canonical node.
    assert_eq!(target.device, real);
    // And matched to the entry through that node, carrying the blind spot. With
    // the second comparison flipped to `!=`, the entry no longer matches and the
    // blind spot is lost.
    assert!(
        target
            .blind_spot
            .as_deref()
            .is_some_and(|reason| reason.contains("copy-on-write")),
        "{target:?}"
    );
}

#[test]
fn an_ntfs_or_fuseblk_mount_is_a_blind_spot_and_each_target_keeps_its_type() {
    // A USB stick under ntfs3 and one under ntfs-3g, which FUSE shows as
    // fuseblk: both are blind spots, beside the ext4 root.
    let mounts = parse_mountinfo(
        "1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n\
         2 1 253:0 / /mnt/data rw,relatime - ext4 /dev/mapper/data rw\n\
         3 1 8:17 / /media/a rw,relatime - ntfs3 /dev/sdb1 rw,uid=1000,gid=1000,iocharset=utf8\n\
         4 1 8:33 / /media/b rw,nosuid,nodev,relatime - fuseblk /dev/sdc1 \
         rw,user_id=0,group_id=0,default_permissions,allow_other,blksize=4096\n",
    );
    let swaps = "Filename\tType\tSize\tUsed\tPriority\n/dev/sdd2 partition 1024 0 -2\n";
    let targets = default_scan_targets(&mounts, swaps, Path::new("/mnt/data"));
    let found: Vec<(&str, Option<&str>, bool)> = targets
        .iter()
        .map(|t| {
            (
                t.device.to_str().unwrap(),
                t.fstype.as_deref(),
                t.blind_spot.is_some(),
            )
        })
        .collect();
    assert_eq!(
        found,
        vec![
            ("/dev/sda1", Some("ext4"), false),
            ("/dev/sdb1", Some("ntfs3"), true),
            ("/dev/sdc1", Some("fuseblk"), true),
            ("/dev/sdd2", None, false),
        ]
    );
    assert!(targets[1].blind_spot.as_deref().unwrap().contains("NTFS"));
    assert!(
        targets[2]
            .blind_spot
            .as_deref()
            .unwrap()
            .contains("fuseblk")
    );
}

#[test]
fn the_recent_files_document_gains_one_bookmark() {
    use super::plant::tests_support::xbel;
    let fresh = xbel(None, "file:///home/a/x.txt", "2026-10-07T10:00:00Z");
    assert!(fresh.starts_with("<?xml"));
    assert_eq!(fresh.matches("<bookmark ").count(), 1);
    assert!(fresh.trim_end().ends_with("</xbel>"));

    let existing = "<?xml version=\"1.0\"?>\n<xbel version=\"1.0\">\n  <bookmark href=\"file:///old\"/>\n</xbel>\n";
    let updated = xbel(Some(existing), "file:///new", "t");
    assert_eq!(updated.matches("<bookmark ").count(), 2);
    assert!(updated.find("file:///old").unwrap() < updated.find("file:///new").unwrap());
}

/// A sparse 64 MiB image with `writes` at their offsets.
fn image(dir: &tempfile::TempDir, name: &str, writes: &[(u64, &[u8])]) -> PathBuf {
    let path = dir.path().join(name);
    let mut file = std::fs::File::create(&path).unwrap();
    file.set_len(64 << 20).unwrap();
    for (offset, bytes) in writes {
        file.seek(SeekFrom::Start(*offset)).unwrap();
        file.write_all(bytes).unwrap();
    }
    file.sync_all().unwrap();
    path
}

/// The ext4 superblock magic at 0x438: storage a raw scan reads verbatim.
const EXT4: (u64, &[u8]) = (0x438, &[0x53, 0xEF]);

#[test]
fn a_scan_reports_both_encodings_by_offset_and_a_clean_image_has_none() {
    let dir = tempfile::tempdir().unwrap();
    let wide = crate::forensic::scan::utf16le(TOKEN);
    let leaky = image(
        &dir,
        "leaky.img",
        &[
            EXT4,
            (1 << 20, TOKEN.as_bytes()),
            (40 << 20, wide.as_slice()),
        ],
    );
    let clean = image(&dir, "clean.img", &[EXT4, (1 << 20, b"nothing to see")]);
    let missing = dir.path().join("missing.img");

    let report = scan(
        TOKEN,
        &[
            ScanTarget::new(leaky.clone()),
            ScanTarget::new(clean.clone()),
            ScanTarget::new(missing.clone()),
        ],
        None,
    )
    .unwrap();

    assert_eq!(report.total_hits(), 2);
    let leaky_scan = &report.devices[0];
    assert_eq!(leaky_scan.hits[0].offset, 1 << 20);
    assert_eq!(leaky_scan.hits[0].encoding, Encoding::Ascii);
    assert_eq!(leaky_scan.hits[1].offset, 40 << 20);
    assert_eq!(leaky_scan.hits[1].encoding, Encoding::Utf16Le);
    assert!(report.devices[1].hits.is_empty());
    assert!(report.devices[2].error.is_some());
    assert!(report.incomplete());
    // Both images are ext4, which keeps file contents verbatim, so neither is
    // a storage blind spot.
    assert!(!report.inconclusive());
    assert!(report.devices.iter().all(|d| d.blind_spot.is_none()));
    assert!(report.not_visible.iter().any(|line| line.contains("SSD")));
    // The compression/copy-on-write caveat is always listed, so a clean scan on
    // the image or --device path (which carries no per-device classification) is
    // never read as conclusive.
    let caveat = "stored compressed or copy-on-write";
    assert!(report.not_visible.iter().any(|line| line.contains(caveat)));
    // So is the caveat of file-level encryption and NTFS compression, with
    // what the scan does not see of it.
    let file_level = "stored encrypted or compressed file by file";
    assert!(
        report
            .not_visible
            .iter()
            .any(|line| line.contains(file_level)
                && line.contains("an eCryptfs folder not mounted during the scan")
                && line.contains("mount or filesystem was moved or detached")
                && line.contains("every eCryptfs folder in an --offline scan")
                && line.contains("a device a program serves from a folder's storage")
                && line.contains("reaches a folder's image file by another path")
                && line.ends_with("and a FUSE tool's vault")),
        "{:?}",
        report.not_visible
    );
}

#[test]
fn a_clean_scan_of_compressed_or_copy_on_write_storage_is_not_checked() {
    let dir = tempfile::tempdir().unwrap();
    // A clean image with nothing planted: a verbatim filesystem would read it
    // clean, but a copy-on-write decoy cannot rule the canary out.
    let clean = image(&dir, "clean.img", &[(1 << 20, b"nothing to see")]);
    let reason = scan_blind_spot("btrfs", "rw,compress=zstd")
        .unwrap()
        .reason()
        .to_string();
    // A blind spot already known is kept: identifying the image from its raw
    // bytes, which hold no filesystem, would give another reason.
    let target = ScanTarget {
        device: clean.clone(),
        blind_spot: Some(reason.clone()),
        probe: true,
        fstype: None,
        unread: None,
    };

    let report = scan(TOKEN, &[target], None).unwrap();

    // No hit, yet the result is not clean: the device is a blind spot.
    assert_eq!(report.total_hits(), 0);
    assert!(report.inconclusive());
    // A blind spot is not the same as an unreadable device.
    assert!(!report.incomplete());
    assert_eq!(
        report.devices[0].blind_spot.as_deref(),
        Some(reason.as_str())
    );
}

#[test]
fn an_offline_image_on_a_copy_on_write_filesystem_is_classified_from_its_superblock() {
    let dir = tempfile::tempdir().unwrap();
    // A btrfs image (its superblock magic at 0x10040) with nothing planted: the
    // mount table never sees it, but the superblock marks it copy-on-write, so a
    // clean scan of it must read "not checked", not clean.
    let btrfs = image(&dir, "decoy-root.img", &[(0x1_0040, b"_BHRfS_M")]);
    let target = ScanTarget::new(btrfs);
    assert!(
        target.blind_spot.is_none(),
        "new() carries no classification"
    );

    let report = scan(TOKEN, &[target], None).unwrap();

    assert_eq!(report.total_hits(), 0);
    assert!(!report.incomplete());
    assert!(
        report.inconclusive(),
        "a btrfs image read offline is a blind spot"
    );
    assert!(
        report.devices[0]
            .blind_spot
            .as_deref()
            .is_some_and(|reason| reason.contains("copy-on-write")),
        "{:?}",
        report.devices[0].blind_spot
    );
}

/// The start of an f2fs superblock (at 1 KiB) as mkfs.f2fs writes it for
/// `blocks` blocks of 4 KiB, with the compression feature when asked.
fn f2fs_superblock(blocks: u64, compression: bool) -> Vec<u8> {
    let mut superblock = vec![0u8; 0x888];
    superblock[..4].copy_from_slice(&[0x10, 0x20, 0xF5, 0xF2]);
    superblock[0x10..0x14].copy_from_slice(&12u32.to_le_bytes());
    superblock[0x24..0x2C].copy_from_slice(&blocks.to_le_bytes());
    // extra_attr, which compression needs, and the compression feature.
    let features: u32 = if compression { 0x0008 | 0x2000 } else { 0x0008 };
    superblock[0x884..].copy_from_slice(&features.to_le_bytes());
    superblock
}

#[test]
fn an_offline_image_on_an_f2fs_filesystem_is_classified_from_its_superblock() {
    let dir = tempfile::tempdir().unwrap();
    // Made with the compression feature: the files flagged for it are stored
    // compressed, so a clean scan is not a clean result.
    let compressing = image(
        &dir,
        "compressing.img",
        &[(0x400, &f2fs_superblock(16384, true))],
    );
    let report = scan(TOKEN, &[ScanTarget::new(compressing)], None).unwrap();
    assert!(report.inconclusive());
    assert!(
        report.devices[0]
            .blind_spot
            .as_deref()
            .is_some_and(|reason| reason.contains("f2fs made with the compression feature")),
        "{:?}",
        report.devices[0].blind_spot
    );

    // Made without it, and whole: every file is stored verbatim.
    let plain = image(
        &dir,
        "plain.img",
        &[(0x400, &f2fs_superblock(16384, false))],
    );
    assert_eq!(verdict(plain), None);

    // Made without it, but cut short: the rest was never read.
    let cut = image(&dir, "cut.img", &[(0x400, &f2fs_superblock(16385, false))]);
    let reason = verdict(cut).expect("a cut-short f2fs is a blind spot");
    assert!(
        reason.contains("the f2fs filesystem here spans 67112960 bytes"),
        "{reason}"
    );
}

#[test]
fn an_offline_image_on_a_verbatim_filesystem_stays_conclusive() {
    let dir = tempfile::tempdir().unwrap();
    // ext4 superblock magic 0x53 0xEF at offset 0x438 is read verbatim.
    let ext4 = image(&dir, "decoy-root.img", &[(0x438, &[0x53, 0xEF])]);

    let report = scan(TOKEN, &[ScanTarget::new(ext4)], None).unwrap();

    assert!(
        !report.inconclusive(),
        "an ext4 image is read verbatim, so a clean scan of it is conclusive"
    );
    assert!(report.devices[0].blind_spot.is_none());
}

/// The blind spot a scan of the image at `path` finds on its own, from its raw
/// superblock and partition table; `None` when a clean scan of it is
/// conclusive.
pub(super) fn verdict(path: PathBuf) -> Option<String> {
    let report = scan(TOKEN, &[ScanTarget::new(path)], None).unwrap();
    assert!(!report.incomplete(), "{report:?}");
    assert_eq!(report.total_hits(), 0, "{report:?}");
    report.devices[0].blind_spot.clone()
}

/// A sparse 64 MiB disk image with a protective MBR and a GPT, its checksums
/// in place, listing `parts` as `(first, last)` 512-byte blocks.
fn gpt_image(dir: &tempfile::TempDir, parts: &[(u64, u64)]) -> (PathBuf, std::fs::File) {
    use crate::forensic::layout::tests::{gpt_entry, gpt_header, put};
    let path = dir.path().join("gpt.img");
    let mut file = std::fs::File::create(&path).unwrap();
    file.set_len(64 << 20).unwrap();
    let mut mbr = [0u8; 512];
    mbr[450] = 0xEE;
    mbr[510] = 0x55;
    mbr[511] = 0xAA;
    put(&mut file, 0, &mbr);
    let mut entries = vec![0u8; 128 * 128];
    for (slot, &(first, last)) in entries.chunks_mut(128).zip(parts) {
        slot.copy_from_slice(&gpt_entry(first, last));
    }
    // Usable from block 34 to 131038; the backup header is the last block.
    put(&mut file, 512, &gpt_header(34, 131_038, 131_071, &entries));
    put(&mut file, 1024, &entries);
    (path, file)
}

/// An ext4 superblock (from 1 KiB in) for `blocks` blocks of 4 KiB.
pub(super) fn ext4_superblock(blocks: u32) -> Vec<u8> {
    let mut sb = vec![0u8; 0x154];
    sb[0x04..0x08].copy_from_slice(&blocks.to_le_bytes());
    sb[0x18..0x1C].copy_from_slice(&2u32.to_le_bytes());
    sb[0x38..0x3A].copy_from_slice(&[0x53, 0xEF]);
    sb
}

#[test]
fn an_image_with_no_filesystem_the_scan_identifies_is_not_checked() {
    // Bytes with no superblock the scan knows: a zfs pool, an encrypted volume
    // without a header, or plain data. A clean read of them proves nothing.
    let dir = tempfile::tempdir().unwrap();
    let raw = image(&dir, "raw.img", &[(1 << 20, b"nothing to see")]);
    let reason = verdict(raw).expect("unidentified storage is a blind spot");
    assert!(reason.contains("identifies no filesystem"), "{reason}");
}

#[test]
fn an_encrypted_container_is_not_checked_and_names_the_unlocked_mapping() {
    // A raw scan of a LUKS2 container, one whose primary header is gone and a
    // BitLocker volume reads only ciphertext: the unlocked mapping is what to
    // scan.
    let dir = tempfile::tempdir().unwrap();
    for (name, header, kind) in [
        ("luks.img", (0, &b"LUKS\xba\xbe\x00\x02"[..]), "(LUKS)"),
        (
            "secondary.img",
            (0x4000, &b"SKUL\xba\xbe\x00\x02"[..]),
            "(LUKS)",
        ),
        ("bitlocker.img", (3, &b"-FVE-FS-"[..]), "(BitLocker)"),
    ] {
        let reason = verdict(image(&dir, name, &[header]))
            .unwrap_or_else(|| panic!("{name} is a blind spot"));
        assert!(
            reason.contains(&format!("encrypted container {kind}")),
            "{name}: {reason}"
        );
        assert!(reason.contains("/dev/mapper/<name>"), "{name}: {reason}");
    }
}

#[test]
fn an_lvm_physical_volume_is_not_checked() {
    // Its logical volumes may hold any filesystem, btrfs among them.
    let dir = tempfile::tempdir().unwrap();
    let pv = image(&dir, "pv.img", &[(0x218, b"LVM2 001")]);
    let reason = verdict(pv).expect("a physical volume is a blind spot");
    assert!(reason.contains("LVM physical volume"), "{reason}");
    assert!(reason.contains("/dev/mapper/<vg>-<lv>"), "{reason}");
}

#[test]
fn a_bcachefs_image_is_classified_from_its_superblock() {
    let dir = tempfile::tempdir().unwrap();
    let magic = [
        0xC6, 0x85, 0x73, 0xF6, 0x66, 0xCE, 0x90, 0xA9, 0xD9, 0x6A, 0x60, 0xCF, 0x80, 0x3D, 0xF7,
        0xEF,
    ];
    let bcachefs = image(&dir, "bcachefs.img", &[(0x1018, &magic)]);
    let reason = verdict(bcachefs).expect("bcachefs is a blind spot");
    assert!(reason.contains("copy-on-write"), "{reason}");
}

#[test]
fn an_f2fs_superblock_wins_over_a_stale_iso9660_descriptor() {
    // mkfs.f2fs leaves an older ISO9660 descriptor at 32 KiB in place on a
    // device without discard, and that descriptor comes first in the signature
    // order. The f2fs is found all the same, and judged as an f2fs.
    let dir = tempfile::tempdir().unwrap();
    let compressing = image(
        &dir,
        "compressing.img",
        &[(0x400, &f2fs_superblock(16384, true)), (0x8001, b"CD001")],
    );
    let reason = verdict(compressing).expect("the f2fs is a blind spot");
    assert!(reason.contains("f2fs"), "{reason}");

    // Without the compression feature it is verbatim, and its own size, not
    // the stale descriptor's, decides whether the image holds all of it.
    let plain = image(
        &dir,
        "plain.img",
        &[(0x400, &f2fs_superblock(16384, false)), (0x8001, b"CD001")],
    );
    assert_eq!(verdict(plain), None);
    let cut = image(
        &dir,
        "cut.img",
        &[(0x400, &f2fs_superblock(32768, false)), (0x8001, b"CD001")],
    );
    let reason = verdict(cut).expect("a cut-short f2fs is a blind spot");
    assert!(
        reason.contains("the f2fs filesystem here spans"),
        "{reason}"
    );
}

#[test]
fn a_whole_disk_image_is_classified_partition_by_partition() {
    use crate::forensic::layout::tests::{mbr_image, put};
    // A 64 MiB disk: ext4 at 1 MiB, btrfs at 17 MiB and ext4 at 33 MiB, 16 MiB
    // each. Only the btrfs partition is a blind spot, and it is named.
    let dir = tempfile::tempdir().unwrap();
    let (path, mut file) = mbr_image(
        &dir,
        64 << 20,
        &[
            (0x83, 2048, 32768),
            (0x83, 34816, 32768),
            (0x83, 67584, 32768),
        ],
    );
    put(&mut file, (1 << 20) + 0x438, &[0x53, 0xEF]);
    put(&mut file, (17 << 20) + 0x1_0040, b"_BHRfS_M");
    put(&mut file, (33 << 20) + 0x438, &[0x53, 0xEF]);
    file.sync_all().unwrap();

    let reason = verdict(path).expect("a btrfs partition is a blind spot");
    assert!(reason.starts_with("partition 2: "), "{reason}");
    assert!(reason.contains("copy-on-write"), "{reason}");
    assert!(
        !reason.contains("partition 1") && !reason.contains("partition 3"),
        "{reason}"
    );
}

#[test]
fn a_whole_disk_image_of_verbatim_filesystems_stays_conclusive() {
    use crate::forensic::layout::tests::{fat_boot_sector, mbr_image, put};
    let dir = tempfile::tempdir().unwrap();
    let (path, mut file) = mbr_image(&dir, 64 << 20, &[(0x83, 2048, 32768), (0x0c, 34816, 32768)]);
    put(&mut file, (1 << 20) + 0x438, &[0x53, 0xEF]);
    put(&mut file, 17 << 20, &fat_boot_sector(512, 0, 32768));
    file.sync_all().unwrap();

    assert_eq!(verdict(path), None);
}

#[test]
fn every_partition_that_can_hide_the_canary_is_named() {
    use crate::forensic::layout::tests::{fat_boot_sector, put};
    // A GPT disk as an encrypted install lays it out: an ESP, a LUKS container,
    // and a partition holding no filesystem the scan identifies.
    let dir = tempfile::tempdir().unwrap();
    let (path, mut file) = gpt_image(&dir, &[(2048, 34815), (34816, 67583), (67584, 100_351)]);
    put(&mut file, 1 << 20, &fat_boot_sector(512, 0, 32768));
    put(&mut file, 17 << 20, b"LUKS\xba\xbe\x00\x02");
    file.sync_all().unwrap();

    let reason = verdict(path).expect("the LUKS and the unidentified partitions are blind spots");
    assert!(!reason.contains("partition 1"), "{reason}");
    assert!(
        reason.contains("partition 2: this is an encrypted container (LUKS)"),
        "{reason}"
    );
    assert!(
        reason.contains("; partition 3: the scan identifies no filesystem"),
        "{reason}"
    );
}

#[test]
fn a_partition_table_behind_a_stale_superblock_is_still_walked() {
    use crate::forensic::layout::tests::{mbr_image, put};
    // The disk once held one ext4 across its whole length: partitioning wrote
    // the MBR but left that superblock in the space before the first
    // partition. The table is walked all the same, and its btrfs partition
    // found.
    let dir = tempfile::tempdir().unwrap();
    let (path, mut file) = mbr_image(&dir, 64 << 20, &[(0x83, 2048, 32768), (0x83, 34816, 32768)]);
    put(&mut file, 0x438, &[0x53, 0xEF]);
    put(&mut file, (1 << 20) + 0x438, &[0x53, 0xEF]);
    put(&mut file, (17 << 20) + 0x1_0040, b"_BHRfS_M");
    file.sync_all().unwrap();

    let reason = verdict(path).expect("the btrfs partition is a blind spot");
    assert!(reason.starts_with("partition 2: "), "{reason}");
}

#[test]
fn a_partition_table_that_lists_no_partition_is_not_checked() {
    let dir = tempfile::tempdir().unwrap();
    let (path, file) = gpt_image(&dir, &[]);
    file.sync_all().unwrap();
    let reason = verdict(path).expect("an empty table holds no identified filesystem");
    assert!(reason.contains("identifies no filesystem"), "{reason}");
}

#[test]
fn an_image_that_ends_before_its_filesystem_is_not_checked() {
    // An ext4 that spans the whole 64 MiB image is whole. One whose superblock
    // records a block more was cut short, as a copy that stopped early leaves
    // it, and the rest of it was never read.
    let dir = tempfile::tempdir().unwrap();
    let whole = image(&dir, "whole.img", &[(0x400, &ext4_superblock(16384))]);
    assert_eq!(verdict(whole), None);
    let cut = image(&dir, "cut.img", &[(0x400, &ext4_superblock(16385))]);
    let reason = verdict(cut).expect("a cut-short filesystem is a blind spot");
    assert!(
        reason.contains("ext2/3/4 filesystem here spans 67112960 bytes"),
        "{reason}"
    );
    assert!(reason.contains("only 67108864 of them"), "{reason}");
}

#[test]
fn a_bare_fat_exfat_or_swap_image_cut_short_is_not_checked() {
    use crate::forensic::layout::tests::{exfat_boot_sector, fat_boot_sector, swap_header};
    // Each format spanning the whole 64 MiB image is whole; one that records
    // a sector or a page more was cut short, and the rest of it never read.
    let dir = tempfile::tempdir().unwrap();
    let swap = |last_page: u32| swap_header([1, 0, 0, 0], last_page.to_le_bytes());
    let cases: [(&str, Vec<u8>, Vec<u8>, &str); 3] = [
        (
            "vfat",
            fat_boot_sector(512, 0, 131_072).to_vec(),
            fat_boot_sector(512, 0, 131_073).to_vec(),
            "the vfat filesystem here spans 67109376 bytes",
        ),
        (
            "exfat",
            exfat_boot_sector(9, 131_072).to_vec(),
            exfat_boot_sector(9, 131_073).to_vec(),
            "the exfat filesystem here spans 67109376 bytes",
        ),
        (
            "swap",
            swap(16_383).to_vec(),
            swap(16_384).to_vec(),
            "the swap area here spans 67112960 bytes",
        ),
    ];
    for (name, whole, cut, spans) in cases {
        let whole = image(&dir, &format!("{name}-whole.img"), &[(0, &whole)]);
        assert_eq!(verdict(whole), None, "{name}");
        let cut = image(&dir, &format!("{name}-cut.img"), &[(0, &cut)]);
        let reason = verdict(cut).unwrap_or_else(|| panic!("a cut-short {name} is not clean"));
        assert!(reason.starts_with(spans), "{name}: {reason}");
        assert!(reason.contains("only 67108864 of them"), "{name}: {reason}");
    }

    // A boot sector or swap header that records what none of them has is no
    // such filesystem: storage the scan does not identify.
    for (name, bytes) in [
        ("fat-sector.img", fat_boot_sector(1000, 0, 131_072).to_vec()),
        (
            "swap-version.img",
            swap_header([2, 0, 0, 0], [1; 4]).to_vec(),
        ),
    ] {
        let reason = verdict(image(&dir, name, &[(0, &bytes)]))
            .unwrap_or_else(|| panic!("{name} is a blind spot"));
        assert!(
            reason.contains("identifies no filesystem"),
            "{name}: {reason}"
        );
    }
}

#[test]
fn an_ntfs_image_is_not_checked_even_when_whole() {
    use crate::forensic::layout::tests::ntfs_boot_sector;
    // mkntfs on 64 MiB records one sector less than the volume: the image
    // holds all of it, yet NTFS can compress the canary.
    let dir = tempfile::tempdir().unwrap();
    let ntfs = image(&dir, "ntfs.img", &[(0, &ntfs_boot_sector(512, 131_071))]);
    let reason = verdict(ntfs).expect("NTFS is a blind spot");
    assert!(
        reason.starts_with("the decoy is an NTFS filesystem"),
        "{reason}"
    );
}

/// The ext4 superblock of [`ext4_superblock`] with the encrypt feature.
fn ext4_encrypting_superblock(blocks: u32) -> Vec<u8> {
    let mut sb = ext4_superblock(blocks);
    sb[0x60..0x64].copy_from_slice(&0x1_0000u32.to_le_bytes());
    sb
}

/// The f2fs superblock of [`f2fs_superblock`], without compression, with the
/// encrypt feature.
fn f2fs_encrypting_superblock(blocks: u64) -> Vec<u8> {
    let mut sb = f2fs_superblock(blocks, false);
    sb[0x884..].copy_from_slice(&(0x0008u32 | 0x0001).to_le_bytes());
    sb
}

#[test]
fn an_offline_ext4_or_f2fs_with_the_encrypt_feature_is_not_checked() {
    use crate::forensic::layout::tests::{mbr_image, put};
    let dir = tempfile::tempdir().unwrap();
    let encrypting = "the decoy filesystem has the encrypt feature (fscrypt)";
    for (name, at, sb) in [
        ("ext4.img", 0x400, ext4_encrypting_superblock(16384)),
        ("f2fs.img", 0x400, f2fs_encrypting_superblock(16384)),
        // Cut short as well: the encryption decides, a whole copy being no
        // more readable.
        ("ext4-cut.img", 0x400, ext4_encrypting_superblock(16385)),
    ] {
        let reason = verdict(image(&dir, name, &[(at, &sb)]))
            .unwrap_or_else(|| panic!("{name} is a blind spot"));
        assert_eq!(reason, ScanBlindSpot::EncryptionCapable.reason(), "{name}");
        assert!(reason.starts_with(encrypting), "{name}: {reason}");
    }

    // On a whole disk, the partition is named.
    let (path, mut file) = mbr_image(&dir, 64 << 20, &[(0x83, 2048, 32768)]);
    put(
        &mut file,
        (1 << 20) + 0x400,
        &ext4_encrypting_superblock(4096),
    );
    file.sync_all().unwrap();
    let reason = verdict(path).expect("the encrypting partition is a blind spot");
    assert!(
        reason.starts_with(&format!("partition 1: {encrypting}")),
        "{reason}"
    );
}

#[test]
fn an_image_cut_inside_its_superblock_is_cut_short() {
    // A copy that stopped inside the superblock of an ext4, between its magic
    // and its feature flags at 0x460, or of an f2fs, before its flags at
    // 0xC84, holds no flags to read: the size its superblock records shows it
    // cut short, whatever the flags would have said.
    let dir = tempfile::tempdir().unwrap();
    let cut = |name: &str, superblock: &[u8], len: usize| {
        let mut bytes = vec![0u8; 0x400];
        bytes.extend_from_slice(superblock);
        bytes.truncate(len);
        let path = dir.path().join(name);
        std::fs::write(&path, &bytes).unwrap();
        verdict(path).unwrap_or_else(|| panic!("{name} is a blind spot"))
    };
    assert_eq!(
        cut("ext4.img", &ext4_encrypting_superblock(16384), 0x450),
        "the ext2/3/4 filesystem here spans 67108864 bytes, but the source holds only 1104 of \
         them, so the rest was never read"
    );
    let f2fs = cut("f2fs.img", &f2fs_superblock(16384, true), 0x800);
    assert!(
        f2fs.starts_with(
            "the f2fs filesystem here spans 67108864 bytes, but the source holds only 2048 of them"
        ),
        "{f2fs}"
    );

    // A superblock that records no more than the source holds, yet ends
    // before its flags, contradicts itself: not checked either.
    let mut tiny = ext4_superblock(1);
    tiny[0x18..0x1C].copy_from_slice(&0u32.to_le_bytes());
    let reason = cut("tiny.img", &tiny, 0x450);
    assert!(
        reason.starts_with(
            "the source ends inside the ext2/3/4 superblock here, before its feature flags"
        ),
        "{reason}"
    );
}

/// A target the mount table shows as `fstype` on the image at `path`.
fn mounted(path: PathBuf, fstype: &str) -> ScanTarget {
    ScanTarget {
        device: path,
        blind_spot: None,
        probe: false,
        fstype: Some(fstype.to_string()),
        unread: None,
    }
}

#[test]
fn a_mounted_ext4_or_f2fs_is_read_for_the_encrypt_feature() {
    let dir = tempfile::tempdir().unwrap();
    let ext4 = image(
        &dir,
        "ext4.img",
        &[(0x400, &ext4_encrypting_superblock(16384))],
    );
    let f2fs = image(
        &dir,
        "f2fs.img",
        &[(0x400, &f2fs_encrypting_superblock(16384))],
    );
    let plain = image(&dir, "plain.img", &[(0x400, &ext4_superblock(16384))]);
    let blind = |target: ScanTarget| {
        let report = scan(TOKEN, &[target], None).unwrap();
        assert!(!report.incomplete(), "{report:?}");
        report.devices[0].blind_spot.clone()
    };
    let encrypting = Some(ScanBlindSpot::EncryptionCapable.reason().to_string());

    // The kernel's ext4 driver mounts ext2 and ext3 too, each with the same
    // superblock.
    for fstype in ["ext4", "ext3", "ext2"] {
        assert_eq!(blind(mounted(ext4.clone(), fstype)), encrypting, "{fstype}");
        assert_eq!(blind(mounted(plain.clone(), fstype)), None, "{fstype}");
    }
    assert_eq!(blind(mounted(f2fs.clone(), "f2fs")), encrypting);
    // Each type's superblock is its own: an xfs mount is not read for it,
    // and neither is a swap partition, which no mount names.
    assert_eq!(blind(mounted(ext4.clone(), "xfs")), None);
    assert_eq!(blind(mounted(f2fs.clone(), "ext4")), None);
    let swap = ScanTarget {
        fstype: None,
        ..mounted(ext4.clone(), "swap")
    };
    assert_eq!(blind(swap), None);
    // A blind spot the mount already shows stands.
    let compressed = ScanTarget {
        blind_spot: Some("compressed".to_string()),
        ..mounted(ext4.clone(), "f2fs")
    };
    assert_eq!(blind(compressed).as_deref(), Some("compressed"));

    // A device that ends inside its superblock, before the flags, shows
    // nothing either way.
    let short = dir.path().join("short.img");
    std::fs::write(&short, vec![0u8; 0x450]).unwrap();
    let reason = blind(mounted(short, "ext4")).unwrap_or_default();
    assert!(
        reason.starts_with("the source ends inside the ext2/3/4 superblock here"),
        "{reason}"
    );

    // A superblock that cannot be read is no evidence the filesystem is plain.
    let source = crate::forensic::RawSource::unreadable(&ext4).unwrap();
    let reason = super::identify::mounted_blind_spot(&source, "ext4")
        .expect("an unread superblock is a blind spot");
    assert!(
        reason.starts_with("its first blocks could not be read ("),
        "{reason}"
    );
    assert_eq!(super::identify::mounted_blind_spot(&source, "xfs"), None);
}

#[test]
fn a_partition_its_filesystem_outgrows_is_named() {
    use crate::forensic::layout::tests::{mbr_image, put};
    // The partition is 16 MiB from 1 MiB in, but the ext4 in it records 32
    // MiB, or a single 4 KiB block more than the partition holds.
    for (blocks, spans) in [(8192, 33_554_432), (4097, 16_781_312)] {
        let dir = tempfile::tempdir().unwrap();
        let (path, mut file) = mbr_image(&dir, 64 << 20, &[(0x83, 2048, 32768)]);
        put(&mut file, (1 << 20) + 0x400, &ext4_superblock(blocks));
        file.sync_all().unwrap();

        let reason = verdict(path).expect("a cut-short partition is a blind spot");
        assert!(
            reason.starts_with(&format!(
                "partition 1: the ext2/3/4 filesystem here spans {spans} bytes"
            )),
            "{reason}"
        );
        assert!(reason.contains("only 16777216 of them"), "{reason}");
    }
}

#[test]
fn a_whole_disk_image_cut_short_is_not_checked() {
    use crate::forensic::layout::tests::{fat_boot_sector, mbr_image, put};
    let dir = tempfile::tempdir().unwrap();
    // A GPT disk as an encrypted install lays it out: an ESP from 1 MiB to
    // 17 MiB, then a LUKS container to the end of the 64 MiB disk. A copy
    // that stopped inside the ESP, or right where the container starts, holds
    // none of the container.
    for cut in [10u64 << 20, 17 << 20] {
        let (path, mut file) = gpt_image(&dir, &[(2048, 34815), (34816, 131_038)]);
        put(&mut file, 1 << 20, &fat_boot_sector(512, 0, 32768));
        put(&mut file, 17 << 20, b"LUKS\xba\xbe\x00\x02");
        file.set_len(cut).unwrap();
        file.sync_all().unwrap();

        let reason = verdict(path).unwrap_or_else(|| panic!("a copy cut at {cut} is not clean"));
        assert!(
            reason.starts_with(&format!(
                "the partition table was written for a disk of 67108864 bytes, but the source \
                 holds only {cut} of them"
            )),
            "{reason}"
        );
        assert!(
            reason.contains(&format!(
                "; partition 2: it runs from byte 17825792 to byte 67091968, but the source \
                 holds only {cut} bytes, so none of it was read"
            )),
            "{reason}"
        );
        // The ESP is named only where the copy cut through it: held whole,
        // its FAT records the size of its partition, and is plain.
        assert_eq!(
            reason.contains(
                "; partition 1: it runs from byte 1048576 to byte 17825792, but the source holds \
                 only 10485760 bytes, so the rest of it was never read"
            ),
            cut < 17 << 20,
            "{reason}"
        );
        assert_eq!(reason.contains("partition 1"), cut < 17 << 20, "{reason}");
    }

    // An MBR disk, which records no disk size: swap from 1 MiB to 17 MiB, a
    // btrfs from there to 49 MiB, and a copy cut inside the swap.
    let (path, mut file) = mbr_image(&dir, 64 << 20, &[(0x82, 2048, 32768), (0x83, 34816, 65536)]);
    put(&mut file, (1 << 20) + 0xff6, b"SWAPSPACE2");
    put(&mut file, (17 << 20) + 0x1_0040, b"_BHRfS_M");
    file.set_len(12 << 20).unwrap();
    file.sync_all().unwrap();

    let reason = verdict(path).expect("a copy cut inside the swap is not clean");
    assert_eq!(
        reason,
        "partition 1: it runs from byte 1048576 to byte 17825792, but the source holds only \
         12582912 bytes, so the rest of it was never read; partition 2: it runs from byte \
         17825792 to byte 51380224, but the source holds only 12582912 bytes, so none of it was \
         read"
    );
}

#[test]
fn a_stale_gpt_header_in_front_of_an_ext4_is_not_its_table() {
    use crate::forensic::layout::tests::{gpt_entry, gpt_header};
    // An ext4 on a whole disk that still carries the header of an older GPT
    // at block 1: its superblock wrote over the entries from block 2. The
    // entries now break the table's rules, so the ext4 is classified on its
    // own and, spanning the whole image, is a clean result.
    let dir = tempfile::tempdir().unwrap();
    let mut entries = vec![0u8; 128 * 128];
    entries[..128].copy_from_slice(&gpt_entry(2048, 131_038));
    let header = gpt_header(34, 131_038, 131_071, &entries);
    let sb = ext4_superblock(16384);
    let kept = image(
        &dir,
        "kept.img",
        &[(512, &header), (1024, &entries), (0x400, &sb)],
    );
    assert_eq!(verdict(kept), None);

    // A header that keeps no checksums: the superblock's first bytes read as
    // an entry from block 0, inside the table's own blocks.
    let mut unchecked = header;
    unchecked[16..20].fill(0);
    unchecked[88..92].fill(0);
    let bare = image(&dir, "bare.img", &[(512, &unchecked), (0x400, &sb)]);
    assert_eq!(verdict(bare), None);
}

#[test]
fn a_gpt_that_breaks_its_rules_is_still_walked_where_no_filesystem_shows() {
    use crate::forensic::layout::tests::put;
    // Behind a protective MBR, a GPT whose entries no longer match their
    // checksum is still the only table there is: its btrfs partition is
    // found.
    let dir = tempfile::tempdir().unwrap();
    let (path, mut file) = gpt_image(&dir, &[(2048, 34815)]);
    put(&mut file, 1024 + 56, b"o\0v\0e\0r\0");
    put(&mut file, (1 << 20) + 0x1_0040, b"_BHRfS_M");
    file.sync_all().unwrap();

    let reason = verdict(path).expect("the btrfs partition is a blind spot");
    assert!(reason.starts_with("partition 1: "), "{reason}");
    assert!(reason.contains("copy-on-write"), "{reason}");
}

#[test]
fn an_ext4_magic_in_random_bytes_is_no_filesystem() {
    // The ciphertext of a volume without a header (plain dm-crypt, LUKS with
    // a detached header) reads as random bytes, and one time in 65536 they
    // carry the ext4 magic at 0x438. The superblock around it then records a
    // block size no ext4 uses: no filesystem is identified, and a clean scan
    // is no clean result.
    let dir = tempfile::tempdir().unwrap();
    let mut state = 0x9E37_79B9_7F4A_7C15_u64;
    let mut noise: Vec<u8> = (0..4 << 20)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_le_bytes()[0]
        })
        .collect();
    noise[0x438..0x43A].copy_from_slice(&[0x53, 0xEF]);
    // s_log_block_size: ext4 blocks are 1 KiB shifted by at most 6.
    assert!(u32::from_le_bytes(noise[0x418..0x41C].try_into().unwrap()) > 6);
    let path = dir.path().join("noise.img");
    std::fs::write(&path, &noise).unwrap();

    let reason = verdict(path).expect("random bytes are not a filesystem");
    assert!(reason.contains("identifies no filesystem"), "{reason}");
}

#[test]
fn an_empty_image_is_reported_not_scanned() {
    // A 0-byte image (a copy that failed before its first byte) opens fine
    // and holds nothing: it is not scanned, never a clean pass.
    let dir = tempfile::tempdir().unwrap();
    let empty = dir.path().join("empty.img");
    std::fs::write(&empty, b"").unwrap();

    let report = scan(TOKEN, &[ScanTarget::new(empty)], None).unwrap();

    assert!(report.incomplete(), "{report:?}");
    let error = report.devices[0].error.as_deref().unwrap_or_default();
    assert!(error.contains("it is empty: 0 bytes to read"), "{error}");
}

#[test]
fn a_superblock_that_cannot_be_read_is_not_checked() {
    // A read error while identifying the storage is no evidence it is plain.
    let dir = tempfile::tempdir().unwrap();
    let path = image(&dir, "unreadable.img", &[EXT4]);
    let source = crate::forensic::RawSource::unreadable(&path).unwrap();
    let reason =
        super::identify::blind_spot(&source).expect("an unread superblock is a blind spot");
    assert!(
        reason.starts_with("its first blocks could not be read ("),
        "{reason}"
    );
}

#[test]
fn a_device_the_mount_table_names_is_not_identified_again() {
    // The mount table names a filesystem the raw superblock check does not
    // identify but that stores contents verbatim (jfs, say): its verdict
    // stands, and a clean scan of the device is conclusive.
    let dir = tempfile::tempdir().unwrap();
    let named = ScanTarget {
        device: image(&dir, "jfs.img", &[(1 << 20, b"nothing to see")]),
        blind_spot: None,
        probe: false,
        fstype: Some("jfs".to_string()),
        unread: None,
    };

    let report = scan(TOKEN, &[named], None).unwrap();

    assert!(!report.inconclusive(), "{report:?}");
    assert!(!report.incomplete(), "{report:?}");
}

#[test]
fn a_malformed_token_is_refused_before_any_read() {
    assert!(scan("not-hex", &[], None).is_err());
}

#[test]
fn planting_writes_only_into_the_overlay_upper() {
    let _ = Rerun::new(crate::test_path!(
        planting_writes_only_into_the_overlay_upper
    ))
    .in_user_mount_ns()
    .run(|| {
        // The decoy: a home tree and an un-overlaid /srv-like tree.
        let decoy = ScratchTmpfs::new("");
        let lower = decoy.mkdir("home");
        std::fs::create_dir_all(lower.join("alice/.local/share")).unwrap();
        std::fs::write(
            lower.join("alice/.local/share/recently-used.xbel"),
            "<?xml version=\"1.0\"?>\n<xbel version=\"1.0\">\n</xbel>\n",
        )
        .unwrap();
        let bare = decoy.mkdir("bare");
        // The hidden volume with the overlay's upper and work.
        let hidden = ScratchTmpfs::new("");
        let upper = hidden.mkdir("home");
        let work = hidden.mkdir(".work");
        let target = decoy.mkdir("merged");
        nix::mount::mount(
            Some("overlay"),
            &target,
            Some("overlay"),
            nix::mount::MsFlags::empty(),
            Some(
                format!(
                    "lowerdir={},upperdir={},workdir={}",
                    lower.display(),
                    upper.display(),
                    work.display()
                )
                .as_str(),
            ),
        )
        .expect("mount the overlay");

        let table = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
        let mounts = parse_mountinfo(&table);
        let user = crate::TargetUser::for_test(0, 0, "alice", target.join("alice"), "/bin/sh");
        let hidden_root = hidden.path().canonicalize().unwrap();
        let ctx = PlantContext {
            token: TOKEN,
            hidden_root: &hidden_root,
            mounts: &mounts,
            operator: Some(&user),
            env: None,
            host_channels: false,
        };

        let records = plant(&ctx);

        let planted: Vec<&ChannelRecord> = records.iter().filter(|r| r.planted()).collect();
        let kinds: Vec<ChannelKind> = planted.iter().map(|r| r.kind).collect();
        assert!(kinds.contains(&ChannelKind::OverlayFile), "{records:#?}");
        assert!(kinds.contains(&ChannelKind::HomeFile), "{records:#?}");
        assert!(kinds.contains(&ChannelKind::RecentFiles), "{records:#?}");
        for record in &planted {
            let copy = record.upper_copy.as_ref().unwrap();
            assert!(copy.starts_with(&hidden_root), "{copy:?}");
            assert!(std::fs::read_to_string(copy).unwrap().contains(TOKEN));
        }
        // The decoy layer is untouched.
        let name = format!("{FILE_PREFIX}{TOKEN}.txt");
        assert!(!lower.join(&name).exists());
        assert!(!lower.join("alice").join(&name).exists());
        let lower_xbel =
            std::fs::read_to_string(lower.join("alice/.local/share/recently-used.xbel")).unwrap();
        assert!(!lower_xbel.contains(TOKEN));

        // A directory that is not overlaid is refused and left empty.
        let refused = plant_file_for_test(&ctx, &bare);
        assert!(!refused.planted());
        assert_eq!(std::fs::read_dir(&bare).unwrap().count(), 0);

        // Reset removes the upper copies.
        let mut st = state(TOKEN);
        st.channels = records.clone();
        std::fs::create_dir_all(hidden_root.join(REHEARSE_DIR)).unwrap();
        std::fs::write(hidden_root.join(state_relative_path()), "{}").unwrap();
        reset(&crate::RealFilesystem, &hidden_root, &st).unwrap();
        assert!(!upper.join(&name).exists());
        let upper_xbel =
            std::fs::read_to_string(upper.join("alice/.local/share/recently-used.xbel")).unwrap();
        assert!(!upper_xbel.contains(TOKEN));
    });
}

fn plant_file_for_test(ctx: &PlantContext<'_>, dir: &Path) -> ChannelRecord {
    super::plant::tests_support::plant_file(ctx, dir)
}

/// In a hidden session entered at `entered_at` (when its plan says), in boot
/// `boot_id`, where systemd reports `soft_reboots`.
fn in_session(entered_at: Option<u64>, boot_id: &str, soft_reboots: Option<u64>) -> Here {
    Here {
        session: Some(LiveSession { entered_at }),
        boot_id: Some(boot_id.to_string()),
        soft_reboots,
    }
}

/// Planted in boot-a, in the session entered at 1000; `soft_reboots` is what
/// systemd reported then.
fn planted_at_1000(soft_reboots: Option<u64>) -> RehearsalState {
    RehearsalState {
        planted_entered_at: Some(1_000),
        planted_soft_reboots: soft_reboots,
        ..state(TOKEN)
    }
}

#[test]
fn outside_a_hidden_session_the_planting_session_has_ended() {
    // Back on the decoy after a plain deactivate: the same boot, and on
    // systemd 255 no soft-reboot count at either end.
    let decoy = Here {
        session: None,
        boot_id: Some("boot-a".to_string()),
        soft_reboots: None,
    };
    assert!(!planted_at_1000(None).planted_in_this_session(&decoy));
    let older = RehearsalState {
        planted_soft_reboots: None,
        ..state(TOKEN)
    };
    assert!(!older.planted_in_this_session(&decoy));
    assert!(!older.planted_in_this_session(&Here::default()));
}

#[test]
fn the_entry_time_tells_the_planting_session_from_a_later_one_without_a_count() {
    // systemd 255 reports no soft-reboot count.
    let state = planted_at_1000(None);
    assert!(state.planted_in_this_session(&in_session(Some(1_000), "boot-a", None)));
    assert!(!state.planted_in_this_session(&in_session(Some(2_000), "boot-a", None)));
    // On 256 and newer the entry time decides first, also when a failed probe
    // left the count out at one end.
    let counted = planted_at_1000(Some(2));
    assert!(!counted.planted_in_this_session(&in_session(Some(2_000), "boot-a", Some(2))));
    assert!(counted.planted_in_this_session(&in_session(Some(1_000), "boot-a", None)));
}

#[test]
fn without_an_entry_time_the_soft_reboot_count_decides_or_the_answer_is_yes() {
    // A rehearsal planted before the entry time was recorded, or a session
    // whose plan cannot be read.
    let state = state(TOKEN);
    assert!(state.planted_in_this_session(&in_session(None, "boot-a", Some(2))));
    assert!(!state.planted_in_this_session(&in_session(None, "boot-a", Some(4))));
    assert!(!state.planted_in_this_session(&in_session(Some(2_000), "boot-a", Some(4))));
    // Nothing tells the sessions apart: assume the planting one.
    assert!(state.planted_in_this_session(&in_session(None, "boot-a", None)));
    assert!(planted_at_1000(None).planted_in_this_session(&in_session(None, "boot-a", Some(2))));
}

#[test]
fn a_later_boot_is_never_the_planting_session() {
    let state = planted_at_1000(Some(2));
    assert!(!state.planted_in_this_session(&in_session(Some(1_000), "boot-b", Some(2))));
    assert!(!state.planted_in_this_session(&in_session(None, "boot-b", None)));
    // An unknown boot ID at either end leaves the decision to the session.
    let no_boot = RehearsalState {
        planted_boot_id: None,
        ..planted_at_1000(None)
    };
    assert!(no_boot.planted_in_this_session(&in_session(Some(1_000), "boot-b", None)));
    assert!(!no_boot.planted_in_this_session(&in_session(Some(2_000), "boot-a", None)));
}

#[test]
fn a_state_without_the_entry_time_still_loads() {
    let json = format!(
        r#"{{"schema_version":1,"token":"{TOKEN}","phase":"planted",
        "planted_at":"2026-10-07T10:00:00Z","planted_boot_id":"boot-a",
        "planted_soft_reboots":0,"channels":[]}}"#
    );
    let state: RehearsalState = serde_json::from_str(&json).unwrap();
    assert_eq!(state.planted_entered_at, None);
    assert_eq!(state.planted_soft_reboots, Some(0));
}
