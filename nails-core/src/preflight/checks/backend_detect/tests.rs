// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the storage-backend detection check, driven by
//! `MockFilesystem` fixtures of `/proc/self/mountinfo` and `/sys`.

use super::*;
use crate::config::DEFAULT_HIDDEN_VOLUME_ROOT;
use crate::filesystem::MockFilesystem;

const ROOT: &str = "/mnt/hidden-volume";

/// A decoy root on LUKS, a decoy `/home` of type `home_fs`, and the hidden
/// root mounted from `hidden_source` (device number `hidden_dev`).
fn mountinfo_with_home(
    home_fs: &str,
    hidden_dev: &str,
    hidden_fstype: &str,
    hidden_source: &str,
) -> String {
    format!(
        "23 1 254:0 / / rw,relatime shared:1 - ext4 /dev/mapper/cryptroot rw\n\
         30 23 254:1 / /home rw,relatime shared:5 - {home_fs} /dev/mapper/home rw\n\
         40 23 {hidden_dev} / {ROOT} rw,relatime shared:9 - {hidden_fstype} {hidden_source} rw\n"
    )
}

/// [`mountinfo_with_home`] with an ext4 `/home`.
fn mountinfo(hidden_dev: &str, hidden_fstype: &str, hidden_source: &str) -> String {
    mountinfo_with_home("ext4", hidden_dev, hidden_fstype, hidden_source)
}

/// Register one block device under `dir` with optional attributes.
fn add_device(
    fs: &MockFilesystem,
    dir: &str,
    devname: &str,
    dm_uuid: Option<&str>,
    backing_file: Option<&str>,
    discard_max_bytes: &str,
) {
    fs.mock_set_file_content(&format!("{dir}/dev"), "0:0\n");
    fs.mock_set_file_content(
        &format!("{dir}/uevent"),
        &format!("MAJOR=0\nMINOR=0\nDEVNAME={devname}\nDEVTYPE=disk\n"),
    );
    if let Some(uuid) = dm_uuid {
        fs.mock_set_file_content(&format!("{dir}/dm/uuid"), &format!("{uuid}\n"));
    }
    if let Some(file) = backing_file {
        fs.mock_set_file_content(&format!("{dir}/loop/backing_file"), &format!("{file}\n"));
    }
    fs.mock_set_file_content(
        &format!("{dir}/queue/discard_max_bytes"),
        &format!("{discard_max_bytes}\n"),
    );
}

/// A tcrypt mapping (`253:3` -> dm-3) over a loop-backed container whose
/// file lives on a `/home` of type `home_fs`.
fn tcrypt_container_fixture(home_fs: &str, discard_max_bytes: &str) -> MockFilesystem {
    let fs = MockFilesystem::new();
    fs.mock_set_file_content(
        MOUNTINFO,
        &mountinfo_with_home(home_fs, "253:3", "ext4", "/dev/mapper/veracrypt-hidden"),
    );
    add_device(
        &fs,
        "/sys/dev/block/253:3",
        "dm-3",
        Some("CRYPT-TCRYPT-veracrypt-hidden"),
        None,
        discard_max_bytes,
    );
    fs.mock_set_directory_contents(
        Path::new("/sys/dev/block/253:3/slaves"),
        vec![PathBuf::from("/sys/dev/block/253:3/slaves/loop0")],
    );
    add_device(
        &fs,
        "/sys/dev/block/253:3/slaves/loop0",
        "loop0",
        None,
        Some("/home/alice/family_photos"),
        "4096",
    );
    fs
}

// ------------------------------------------------------------------------
// Construction and trait metadata
// ------------------------------------------------------------------------

#[test]
fn default_uses_default_hidden_root() {
    let check = BackendDetectCheck::default();
    assert_eq!(
        check.hidden_volume_root,
        PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT)
    );
}

#[test]
fn new_keeps_custom_root_and_clone_preserves_it() {
    let check = BackendDetectCheck::new(PathBuf::from("/custom/root"));
    assert_eq!(
        check.clone().hidden_volume_root,
        PathBuf::from("/custom/root")
    );
}

#[test]
fn trait_metadata_is_stable() {
    let check = BackendDetectCheck::default();
    assert_eq!(
        <BackendDetectCheck as PreFlightCheck<MockFilesystem>>::name(&check),
        "backend-detect"
    );
    assert!(
        <BackendDetectCheck as PreFlightCheck<MockFilesystem>>::description(&check)
            .contains("backend")
    );
}

#[test]
fn run_without_mountinfo_passes() {
    // An empty mock has no mount table: detection is skipped, never failed.
    let fs = MockFilesystem::new();
    let result = BackendDetectCheck::default().run(&fs).unwrap();
    assert!(result.is_pass());
    assert!(result.message().contains("skipped"));
}

// ------------------------------------------------------------------------
// Parsing seams
// ------------------------------------------------------------------------

#[test]
fn classify_dm_uuid_recognises_cryptsetup_types() {
    assert_eq!(
        classify_dm_uuid("CRYPT-TCRYPT-veracrypt-hidden\n"),
        Some(CryptType::Tcrypt)
    );
    assert_eq!(
        classify_dm_uuid("CRYPT-LUKS2-2f8d0c6a9b8e4f1ea1b2c3d4e5f60718-hidden"),
        Some(CryptType::Luks)
    );
    assert_eq!(
        classify_dm_uuid("CRYPT-LUKS1-0123456789abcdef0123456789abcdef-old"),
        Some(CryptType::Luks)
    );
    assert_eq!(
        classify_dm_uuid("CRYPT-PLAIN-scratch"),
        Some(CryptType::Plain)
    );
    assert_eq!(
        classify_dm_uuid("CRYPT-BITLK-0123-usb"),
        Some(CryptType::Other("BITLK".into()))
    );
}

#[test]
fn classify_dm_uuid_rejects_non_cryptsetup_devices() {
    assert_eq!(classify_dm_uuid("LVM-abcdefabcdef"), None);
    assert_eq!(classify_dm_uuid(""), None);
    assert_eq!(classify_dm_uuid("CRYPT-"), None);
    assert_eq!(classify_dm_uuid("crypt-tcrypt-lowercase"), None);
}

#[test]
fn parse_backing_file_strips_newline_and_rejects_empty() {
    assert_eq!(
        parse_backing_file("/home/alice/family photos\n"),
        Some(PathBuf::from("/home/alice/family photos"))
    );
    assert_eq!(parse_backing_file("\n"), None);
    assert_eq!(parse_backing_file(""), None);
}

#[test]
fn parse_discard_max_bytes_handles_zero_value_and_garbage() {
    assert_eq!(parse_discard_max_bytes("0\n"), Some(0));
    assert_eq!(parse_discard_max_bytes("2147450880\n"), Some(2_147_450_880));
    assert_eq!(parse_discard_max_bytes("not-a-number"), None);
}

#[test]
fn parse_devname_reads_uevent() {
    assert_eq!(
        parse_devname("MAJOR=253\nMINOR=3\nDEVNAME=dm-3\nDEVTYPE=disk\n"),
        Some("dm-3".into())
    );
    assert_eq!(parse_devname("MAJOR=7\nMINOR=0\n"), None);
    assert_eq!(parse_devname("DEVNAME=\n"), None);
}

#[test]
fn mount_containing_picks_longest_prefix_and_topmost_overmount() {
    let entries = parse_mountinfo(&format!(
        "{}50 40 0:50 / {ROOT} rw - tmpfs tmpfs rw\n",
        mountinfo("253:3", "ext4", "/dev/mapper/hidden")
    ));

    let hidden = mount_containing(&entries, Path::new("/mnt/hidden-volume/nails")).unwrap();
    assert_eq!(
        hidden.fstype, "tmpfs",
        "the later overmount is the visible one"
    );

    let home = mount_containing(&entries, Path::new("/home/alice/file")).unwrap();
    assert_eq!(home.mount_point, PathBuf::from("/home"));

    // A sibling sharing a string prefix is not a path prefix.
    let root = mount_containing(&entries, Path::new("/homework")).unwrap();
    assert_eq!(root.mount_point, PathBuf::from("/"));
}

// ------------------------------------------------------------------------
// Device-stack discovery against MockFilesystem fixtures
// ------------------------------------------------------------------------

#[test]
fn detects_tcrypt_mapping_over_loop_container_from_fixtures() {
    let fs = tcrypt_container_fixture("ext4", "0");
    let entries = parse_mountinfo(&fs.read_file_content(Path::new(MOUNTINFO)).unwrap());
    let mount = mount_containing(&entries, Path::new(ROOT)).unwrap();
    let top = device_dir_for_mount(&fs, mount).unwrap();
    assert_eq!(top, PathBuf::from("/sys/dev/block/253:3"));
    let layers = device_stack(&fs, top);

    assert_eq!(layers.len(), 2);
    assert_eq!(layers[0].name, "dm-3");
    assert_eq!(layers[0].crypt, Some(CryptType::Tcrypt));
    assert_eq!(layers[0].discard_max_bytes, 0);
    assert_eq!(layers[1].name, "loop0");
    assert_eq!(
        layers[1].backing_file,
        Some(PathBuf::from("/home/alice/family_photos"))
    );
}

#[test]
fn btrfs_anonymous_dev_falls_back_to_mapper_name() {
    let fs = MockFilesystem::new();
    fs.mock_set_file_content(MOUNTINFO, &mountinfo("0:45", "btrfs", "/dev/mapper/hidden"));
    fs.mock_set_directory_contents(
        Path::new(SYS_BLOCK),
        vec![
            PathBuf::from("/sys/block/dm-0"),
            PathBuf::from("/sys/block/dm-3"),
        ],
    );
    fs.mock_set_file_content("/sys/block/dm-0/dm/name", "cryptroot\n");
    fs.mock_set_file_content("/sys/block/dm-3/dm/name", "hidden\n");
    add_device(
        &fs,
        "/sys/block/dm-3",
        "dm-3",
        Some("CRYPT-LUKS2-00112233445566778899aabbccddeeff-hidden"),
        None,
        "0",
    );

    let result = assess(&fs, Path::new(ROOT));
    assert!(result.is_pass(), "{}", result.message());
    assert!(result.message().contains("btrfs on LUKS mapping dm-3"));
}

#[test]
fn kernel_name_source_resolves_through_class_block() {
    let fs = MockFilesystem::new();
    fs.mock_set_file_content(MOUNTINFO, &mountinfo("0:46", "btrfs", "/dev/loop7"));
    add_device(
        &fs,
        "/sys/class/block/loop7",
        "loop7",
        None,
        Some("/home/alice/disk.img"),
        "4096",
    );

    let result = assess(&fs, Path::new(ROOT));
    assert!(result.is_warn());
    assert!(
        result
            .message()
            .contains("loop device loop7 (file container)")
    );
}

#[test]
fn unidentifiable_device_passes_with_fstype() {
    let fs = MockFilesystem::new();
    fs.mock_set_file_content(MOUNTINFO, &mountinfo("0:47", "zfs", "tank/hidden"));

    let result = assess(&fs, Path::new(ROOT));
    assert!(result.is_pass());
    assert!(
        result
            .message()
            .contains("zfs with no identifiable block device")
    );
}

#[test]
fn hidden_root_below_another_mount_is_skipped() {
    // A hidden root that is only a directory on the decoy `/home` must not be
    // described (or warned about) as if `/home` were the hidden backend.
    let fs = tcrypt_container_fixture("btrfs", "4096");

    let result = assess(&fs, Path::new("/home/alice/hidden"));
    assert!(result.is_pass());
    assert!(result.message().contains("not a mount point"));
}

#[test]
fn hidden_root_on_decoy_root_is_skipped() {
    let fs = MockFilesystem::new();
    fs.mock_set_file_content(
        MOUNTINFO,
        "23 1 254:0 / / rw,relatime shared:1 - ext4 /dev/mapper/cryptroot rw\n",
    );

    let result = assess(&fs, Path::new(ROOT));
    assert!(result.is_pass());
    assert!(result.message().contains("not a mount point"));
}

// ------------------------------------------------------------------------
// Assessment: WARN, never FAIL
// ------------------------------------------------------------------------

#[test]
fn luks_on_whole_device_passes() {
    let fs = MockFilesystem::new();
    fs.mock_set_file_content(MOUNTINFO, &mountinfo("253:2", "ext4", "/dev/mapper/hidden"));
    add_device(
        &fs,
        "/sys/dev/block/253:2",
        "dm-2",
        Some("CRYPT-LUKS2-00112233445566778899aabbccddeeff-hidden"),
        None,
        "0",
    );
    fs.mock_set_directory_contents(
        Path::new("/sys/dev/block/253:2/slaves"),
        vec![PathBuf::from("/sys/dev/block/253:2/slaves/vdb")],
    );
    add_device(
        &fs,
        "/sys/dev/block/253:2/slaves/vdb",
        "vdb",
        None,
        None,
        "0",
    );

    let result = assess(&fs, Path::new(ROOT));
    assert!(result.is_pass(), "{}", result.message());
    assert_eq!(
        result.message(),
        "Hidden root backend: ext4 on LUKS mapping dm-2 on block device vdb; \
         no backend-specific hazards detected"
    );
}

#[test]
fn discard_enabled_tcrypt_mapping_warns() {
    let fs = tcrypt_container_fixture("ext4", "2147450880");

    let result = assess(&fs, Path::new(ROOT));
    assert!(result.is_warn());
    assert!(!result.is_fail());
    let message = result.message();
    assert!(message.contains("Discards are enabled on the VeraCrypt/TrueCrypt (tcrypt)"));
    assert!(message.contains("--allow-discards"));
    assert!(message.contains("destroy the hidden volume"));
    assert!(message.contains("fstrim"));
    assert!(message.contains(BACKENDS_DOC));
}

#[test]
fn discard_disabled_tcrypt_mapping_has_no_discard_warning() {
    let fs = tcrypt_container_fixture("ext4", "0");

    let result = assess(&fs, Path::new(ROOT));
    // Still a file container, so a timestamp warning remains.
    assert!(result.is_warn());
    assert!(!result.message().contains("Discards are enabled"));
    assert!(result.message().contains("mtime and ctime"));
}

#[test]
fn discard_enabled_plain_mapping_warns_without_hidden_volume_wording() {
    let layers = [Layer {
        name: "dm-4".into(),
        is_dm: true,
        crypt: Some(CryptType::Plain),
        discard_max_bytes: 4096,
        ..Layer::default()
    }];

    let found = hazards(&layers, &[]);
    assert_eq!(found.len(), 1);
    assert!(found[0].contains("plain dm-crypt mapping dm-4"));
    assert!(found[0].contains("uniform random data"));
    assert!(!found[0].contains("hidden volume"));
}

#[test]
fn discard_enabled_luks_mapping_is_not_a_hazard() {
    let layers = [Layer {
        name: "dm-2".into(),
        is_dm: true,
        crypt: Some(CryptType::Luks),
        discard_max_bytes: 4096,
        ..Layer::default()
    }];

    assert!(hazards(&layers, &[]).is_empty());
}

#[test]
fn file_container_on_btrfs_warns_about_cow() {
    let fs = tcrypt_container_fixture("btrfs", "0");

    let result = assess(&fs, Path::new(ROOT));
    assert!(result.is_warn());
    let message = result.message();
    assert!(message.contains("copy-on-write btrfs filesystem"));
    assert!(message.contains("disable automatic snapshots"));
    assert!(message.contains("on a btrfs filesystem"));
}

#[test]
fn file_container_on_zfs_warns_about_cow() {
    let fs = tcrypt_container_fixture("zfs", "0");

    let result = assess(&fs, Path::new(ROOT));
    assert!(result.is_warn());
    assert!(result.message().contains("copy-on-write zfs filesystem"));
}

#[test]
fn file_container_on_ext4_has_no_cow_warning() {
    let fs = tcrypt_container_fixture("ext4", "0");

    let result = assess(&fs, Path::new(ROOT));
    assert!(!result.message().contains("copy-on-write"));
}

#[test]
fn every_hazard_together_is_still_only_a_warning() {
    let fs = tcrypt_container_fixture("btrfs", "4096");

    let result = assess(&fs, Path::new(ROOT));
    assert!(result.is_warn());
    let message = result.message();
    assert!(message.contains("Discards are enabled"));
    assert!(message.contains("mtime and ctime"));
    assert!(message.contains("copy-on-write"));
}

#[test]
fn fuse_backed_loop_warns_about_userspace_process_only() {
    let entries = parse_mountinfo(
        "23 1 254:0 / / rw - ext4 /dev/mapper/cryptroot rw\n\
         60 23 0:60 / /tmp/.veracrypt_aux_mnt1 rw - fuse.veracrypt veracrypt rw\n",
    );
    let layers = [Layer {
        name: "loop1".into(),
        backing_file: Some(PathBuf::from("/tmp/.veracrypt_aux_mnt1/volume")),
        ..Layer::default()
    }];

    let found = hazards(&layers, &entries);
    assert_eq!(found.len(), 1);
    assert!(found[0].contains("fuse.veracrypt"));
    assert!(found[0].contains("userspace process"));
}

#[test]
fn describe_names_each_layer_kind() {
    let layers = [
        Layer {
            name: "dm-5".into(),
            is_dm: true,
            ..Layer::default()
        },
        Layer {
            name: "dm-3".into(),
            is_dm: true,
            crypt: Some(CryptType::Other("BITLK".into())),
            ..Layer::default()
        },
        Layer {
            name: "sdc1".into(),
            ..Layer::default()
        },
    ];
    assert_eq!(
        describe("xfs", &layers),
        "xfs on device-mapper device dm-5 on dm-crypt (BITLK) mapping dm-3 on block device sdc1"
    );
}
