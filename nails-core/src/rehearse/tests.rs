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

const TOKEN: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f0";

fn state(token: &str) -> RehearsalState {
    RehearsalState {
        schema_version: STATE_SCHEMA_VERSION,
        token: token.to_string(),
        phase: Phase::Planted,
        planted_at: "2026-10-07T10:00:00Z".to_string(),
        planted_boot_id: Some("boot-a".to_string()),
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
    let slash = fs.device_id(Path::new("/")).unwrap();
    fs.mock_set_device_id(root, slash);

    let err = save_state(&fs, root, &state(TOKEN)).unwrap_err();
    assert!(err.to_string().contains("shares a device with /"), "{err}");
    assert!(
        fs.get_written_content(&root.join(state_relative_path()))
            .is_none()
    );
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

        let removed = reset(hidden.path(), &loaded).unwrap();
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
        targets,
        vec![
            PathBuf::from("/dev/sda1"),
            PathBuf::from("/dev/sdb1"),
            PathBuf::from("/dev/sdc2"),
        ]
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
        &[leaky.clone(), clean.clone(), missing.clone()],
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
    assert!(report.not_visible.iter().any(|line| line.contains("SSD")));
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
        use crate::filesystem::{Filesystem, RealFilesystem};

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
        RealFilesystem
            .mount_overlay(&[lower.as_path()], &upper, &work, &target)
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
        reset(&hidden_root, &st).unwrap();
        assert!(!upper.join(&name).exists());
        let upper_xbel =
            std::fs::read_to_string(upper.join("alice/.local/share/recently-used.xbel")).unwrap();
        assert!(!upper_xbel.contains(TOKEN));
    });
}

fn plant_file_for_test(ctx: &PlantContext<'_>, dir: &Path) -> ChannelRecord {
    super::plant::tests_support::plant_file(ctx, dir)
}
