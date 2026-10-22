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

const TOKEN: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"; // pragma: allowlist secret

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
fn an_f2fs_decoy_root_is_marked_a_blind_spot() {
    // An f2fs root with plain mount options is a blind spot all the same: its
    // on-disk compression feature and a `chattr +c` flag can compress a file
    // with nothing shown in the mount options, so a raw scan proves nothing.
    let mounts = parse_mountinfo(
        "1 0 8:1 / / rw,relatime - f2fs /dev/sda2 rw,background_gc=on\n\
         2 1 253:0 / /mnt/data rw,relatime - ext4 /dev/mapper/data rw\n",
    );
    let targets = default_scan_targets(&mounts, "", Path::new("/mnt/data"));
    let root = targets
        .iter()
        .find(|t| t.device.as_path() == Path::new("/dev/sda2"))
        .expect("the f2fs root is a target");
    assert!(
        root.blind_spot
            .as_deref()
            .is_some_and(|reason| reason.contains("f2fs")),
        "{root:?}"
    );
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
    let cow = ScanTarget::classified(PathBuf::from("/dev/nails-test-btrfs"), &mounts);
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
    let plain = ScanTarget::classified(PathBuf::from("/dev/nails-test-ext4"), &mounts);
    assert_eq!(plain.device, PathBuf::from("/dev/nails-test-ext4"));
    assert!(plain.blind_spot.is_none(), "{plain:?}");
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

    let target = ScanTarget::classified(by_device.clone(), &[entry]);
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

#[test]
fn a_scan_reports_both_encodings_by_offset_and_a_clean_image_has_none() {
    let dir = tempfile::tempdir().unwrap();
    let wide = crate::forensic::scan::utf16le(TOKEN);
    let leaky = image(
        &dir,
        "leaky.img",
        &[(1 << 20, TOKEN.as_bytes()), (40 << 20, wide.as_slice())],
    );
    let clean = image(&dir, "clean.img", &[(1 << 20, b"nothing to see")]);
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
    // Images carry no filesystem, so none is a storage blind spot.
    assert!(!report.inconclusive());
    assert!(report.devices.iter().all(|d| d.blind_spot.is_none()));
    assert!(report.not_visible.iter().any(|line| line.contains("SSD")));
    // The compression/copy-on-write caveat is always listed, so a clean scan on
    // the image or --device path (which carries no per-device classification) is
    // never read as conclusive.
    let caveat = "stored compressed or copy-on-write";
    assert!(report.not_visible.iter().any(|line| line.contains(caveat)));
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
    let target = ScanTarget {
        device: clean.clone(),
        blind_spot: Some(reason.clone()),
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

#[test]
fn an_offline_image_on_an_f2fs_filesystem_is_classified_from_its_superblock() {
    let dir = tempfile::tempdir().unwrap();
    // f2fs superblock magic 0x10 0x20 0xF5 0xF2 at offset 0x400.
    let f2fs = image(
        &dir,
        "decoy-root.img",
        &[(0x400, &[0x10, 0x20, 0xF5, 0xF2])],
    );

    let report = scan(TOKEN, &[ScanTarget::new(f2fs)], None).unwrap();

    assert!(report.inconclusive());
    assert!(
        report.devices[0]
            .blind_spot
            .as_deref()
            .is_some_and(|reason| reason.contains("f2fs")),
        "{:?}",
        report.devices[0].blind_spot
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
