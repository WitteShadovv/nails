// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the storage-backend detection check, driven by
//! `MockFilesystem` fixtures of `/proc/self/mountinfo` and `/sys`.

use super::*;
use crate::config::DEFAULT_HIDDEN_VOLUME_ROOT;
use crate::filesystem::MockFilesystem;

const ROOT: &str = "/mnt/hidden-volume";
/// Whole block devices by kernel name; device-mapper devices live here.
const SYS_BLOCK: &str = "/sys/block";

/// [`assess`] with an empty device directory, so a LUKS layer's header is
/// never read from the host's `/dev`. Discards fail closed (the default).
fn assess_offline(fs: &MockFilesystem, root: &Path) -> CheckResult {
    let dev = tempfile::tempdir().unwrap();
    assess_with_dev_dir(fs, root, dev.path(), false)
}

/// [`assess_offline`] with the per-run `--allow-discards` override on, so a
/// discard over the hidden volume warns instead of refusing.
fn assess_offline_allowing_discards(fs: &MockFilesystem, root: &Path) -> CheckResult {
    let dev = tempfile::tempdir().unwrap();
    assess_with_dev_dir(fs, root, dev.path(), true)
}

/// The cryptsetup type the check gives a device-mapper uuid.
fn classify_dm_uuid(uuid: &str) -> Option<CryptType> {
    CryptType::of(&blockdev::classify_dm(uuid, ""))
}

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
fn allowing_discards_sets_the_flag_and_keeps_the_custom_root() {
    // The per-run override turns the flag on while preserving the custom
    // hidden root; it must not reset the check to its defaults.
    let check = BackendDetectCheck::new(PathBuf::from("/custom/root")).allowing_discards(true);
    assert!(check.allow_discards, "the override must turn discards on");
    assert_eq!(
        check.hidden_volume_root,
        PathBuf::from("/custom/root"),
        "the override must keep the custom hidden root"
    );

    // And off keeps the fail-closed default while still preserving the root.
    let off = BackendDetectCheck::new(PathBuf::from("/custom/root")).allowing_discards(false);
    assert!(!off.allow_discards, "passing false must leave discards off");
    assert_eq!(off.hidden_volume_root, PathBuf::from("/custom/root"));
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
    // The inner layer of a cipher chain and the integrity and verity mappings
    // keep their own type names.
    for (fixture, kind) in [
        ("CRYPT-SUBDEV-vault_1", "SUBDEV"),
        ("CRYPT-INTEGRITY-data", "INTEGRITY"),
        (
            "CRYPT-VERITY-0123456789abcdef0123456789abcdef-usr",
            "VERITY",
        ),
    ] {
        assert_eq!(
            classify_dm_uuid(fixture),
            Some(CryptType::Other(kind.into())),
            "{fixture}"
        );
    }
}

#[test]
fn classify_dm_uuid_rejects_non_cryptsetup_devices() {
    assert_eq!(classify_dm_uuid("LVM-abcdefabcdef"), None);
    assert_eq!(classify_dm_uuid(""), None);
    assert_eq!(classify_dm_uuid("CRYPT-"), None);
    assert_eq!(classify_dm_uuid("crypt-tcrypt-lowercase"), None);
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
    let top = blockdev::device_of_mount(&fs, mount).unwrap();
    assert_eq!(top, PathBuf::from("/sys/dev/block/253:3"));
    let layers = device_layers(&fs, &top);

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

    let result = assess_offline(&fs, Path::new(ROOT));
    assert!(result.is_pass(), "{}", result.message());
    assert!(result.message().contains("btrfs on LUKS mapping dm-3"));
}

/// The captured hidden-root scene (fixture README): the kernel prints the
/// root's space as `\040` and gives the mount an anonymous device, so the root
/// is found only through the decoded mount point and the device only through
/// the mapper name in the source column.
#[test]
fn captured_mountinfo_resolves_an_escaped_root_through_its_mapper_name() {
    let fs = MockFilesystem::new();
    fs.mock_set_file_content(
        MOUNTINFO,
        &crate::kernel_fixtures::userns("mountinfo-hidden-root.txt"),
    );
    fs.mock_set_directory_contents(Path::new(SYS_BLOCK), vec![PathBuf::from("/sys/block/dm-2")]);
    fs.mock_set_file_content("/sys/block/dm-2/dm/name", "vault\n");
    add_device(
        &fs,
        "/sys/block/dm-2",
        "dm-2",
        Some("CRYPT-LUKS2-00112233445566778899aabbccddeeff-vault"),
        None,
        "0",
    );

    let result = assess_offline(&fs, Path::new("/fixture/mnt/hidden root"));
    assert!(result.is_pass(), "{}", result.message());
    assert!(
        result.message().contains("tmpfs on LUKS mapping dm-2"),
        "{}",
        result.message()
    );
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

    let result = assess_offline(&fs, Path::new(ROOT));
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

    let result = assess_offline(&fs, Path::new(ROOT));
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

    let result = assess_offline(&fs, Path::new("/home/alice/hidden"));
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

    let result = assess_offline(&fs, Path::new(ROOT));
    assert!(result.is_pass());
    assert!(result.message().contains("not a mount point"));
}

// ------------------------------------------------------------------------
// Assessment: PASS, WARN, and the discard refusal (fail closed)
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

    let result = assess_offline(&fs, Path::new(ROOT));
    assert!(result.is_pass(), "{}", result.message());
    assert_eq!(
        result.message(),
        "Hidden root backend: ext4 on LUKS mapping dm-2 on block device vdb; \
         no backend-specific hazards detected"
    );
}

/// An LVM snapshot of the hidden volume: the snapshot (`253:3` -> dm-3) sits on
/// the origin's `-real` device (dm-1) and on its copy-on-write store (dm-2),
/// and both sit on one plain dm-crypt mapping (dm-0) with discards on. As in
/// sysfs, each `slaves/` entry is a link to the device's own directory.
#[test]
fn a_device_two_layers_sit_on_is_named_once() {
    let fs = MockFilesystem::new();
    fs.mock_set_file_content(
        MOUNTINFO,
        &mountinfo("253:3", "ext4", "/dev/mapper/vg-snap"),
    );
    let slaves = |dir: &str, names: &[&str]| {
        let links = names
            .iter()
            .map(|name| {
                let link = PathBuf::from(format!("{dir}/slaves/{name}"));
                fs.create_symlink(&Path::new(SYS_BLOCK).join(name), &link)
                    .unwrap();
                link
            })
            .collect();
        fs.mock_set_directory_contents(&Path::new(dir).join("slaves"), links);
    };
    add_device(
        &fs,
        "/sys/dev/block/253:3",
        "dm-3",
        Some("LVM-snap"),
        None,
        "0",
    );
    slaves("/sys/dev/block/253:3", &["dm-1", "dm-2"]);
    for (name, uuid) in [("dm-1", "LVM-origin-real"), ("dm-2", "LVM-snap-cow")] {
        let dir = format!("{SYS_BLOCK}/{name}");
        add_device(&fs, &dir, name, Some(uuid), None, "0");
        slaves(&dir, &["dm-0"]);
    }
    add_device(
        &fs,
        "/sys/block/dm-0",
        "dm-0",
        Some("CRYPT-PLAIN-pv"),
        None,
        "4096",
    );

    // The plain mapping has discards on, so the risk is accepted for the run to
    // exercise the layer naming: each device is named once in the summary.
    let result = assess_offline_allowing_discards(&fs, Path::new(ROOT));
    let message = result.message();
    assert!(result.is_warn(), "{message}");
    assert!(
        message.starts_with(
            "Hidden root backend: ext4 on device-mapper device dm-3 on device-mapper device \
             dm-1 on device-mapper device dm-2 on plain dm-crypt mapping dm-0. Discards"
        ),
        "{message}"
    );
    assert_eq!(
        message.matches("Discards are enabled").count(),
        1,
        "{message}"
    );
}

#[test]
fn discard_enabled_tcrypt_mapping_refuses_unless_allowed() {
    let fs = tcrypt_container_fixture("ext4", "2147450880");

    // Fails closed by default, naming no device-mapper node.
    let refused = assess_offline(&fs, Path::new(ROOT));
    assert!(refused.is_fail(), "{refused:?}");
    assert!(
        refused
            .message()
            .contains("Discards are enabled over the hidden volume")
    );
    assert_names_no_dm_node(&refused);
    // The refusal names the override that accepts it.
    assert_eq!(refused.allowable(), Some(nails_api::Allowable::Discards));

    // Accepted for the run, it warns and points at the backend guide.
    let allowed = assess_offline_allowing_discards(&fs, Path::new(ROOT));
    assert!(allowed.is_warn(), "{allowed:?}");
    assert_eq!(allowed.allowable(), None);
    assert!(allowed.message().contains("accepted for this run"));
    assert!(allowed.message().contains(BACKENDS_DOC));
}

/// The refusal and its remediation name no device-mapper node (`dm-N` or
/// `/dev/mapper/...`).
fn assert_names_no_dm_node(result: &CheckResult) {
    let message = result.message();
    let remediation = result.remediation().unwrap_or_default();
    for text in [message, remediation] {
        assert!(!text.contains("dm-"), "names a dm node: {text}");
        assert!(!text.contains("/dev/mapper"), "names a mapper node: {text}");
        assert!(!text.contains("/dev/dm"), "names a dm node: {text}");
    }
}

#[test]
fn discard_disabled_tcrypt_mapping_has_no_discard_warning() {
    let fs = tcrypt_container_fixture("ext4", "0");

    let result = assess_offline(&fs, Path::new(ROOT));
    // Still a file container, so a timestamp warning remains.
    assert!(result.is_warn());
    assert!(!result.message().contains("Discards are enabled"));
    assert!(result.message().contains("mtime and ctime"));
}

#[test]
fn discard_enabled_plain_mapping_is_a_fail_closed_finding() {
    let layers = [Layer {
        name: "dm-4".into(),
        is_dm: true,
        crypt: Some(CryptType::Plain),
        discard_max_bytes: 4096,
        ..Layer::default()
    }];

    // The discard is detected for the fail-closed decision, and is no longer a
    // `hazards()` warning.
    assert!(discards_over_hidden(&layers));
    assert!(hazards(&layers, &[]).is_empty());
}

#[test]
fn luks_runtime_discards_are_a_fail_closed_finding() {
    // A LUKS mapping opened with runtime discards (no stored header flag) now
    // counts, where it used to be ignored.
    let layers = [Layer {
        name: "dm-2".into(),
        is_dm: true,
        crypt: Some(CryptType::Luks),
        discard_max_bytes: 4096,
        ..Layer::default()
    }];

    assert!(discards_over_hidden(&layers));
    assert!(hazards(&layers, &[]).is_empty());
}

#[test]
fn discards_over_a_ram_only_zram_device_are_excepted() {
    let crypt_on = |leaf: &str| {
        [
            Layer {
                name: "dm-5".into(),
                is_dm: true,
                crypt: Some(CryptType::Luks),
                discard_max_bytes: 4096,
                slaves: vec![leaf.into()],
                below: vec![leaf.into()],
                ..Layer::default()
            },
            Layer {
                name: leaf.into(),
                ..Layer::default()
            },
        ]
    };
    // zram is RAM-only, so TRIM never reaches persistent storage.
    assert!(!discards_over_hidden(&crypt_on("zram0")));
    // The same stack on a real disk still fails closed.
    assert!(discards_over_hidden(&crypt_on("vdb")));
    // "zram" must be followed by a device number, not any suffix.
    assert!(discards_over_hidden(&crypt_on("zrama")));
}

#[test]
fn a_zram_device_beside_a_disk_in_the_stack_excepts_nothing() {
    // LUKS with discards on a logical volume cached with dm-cache, its cache
    // on zram0 and its origin on an SSD partition: the walk lists every device
    // of the stack, and dm-cache passes the discards down to the SSD.
    let layer = |name: &str, slaves: &[&str]| Layer {
        name: name.into(),
        is_dm: name.starts_with("dm-"),
        slaves: slaves.iter().map(|s| (*s).into()).collect(),
        below: slaves.iter().map(|s| (*s).into()).collect(),
        ..Layer::default()
    };
    let layers = [
        Layer {
            crypt: Some(CryptType::Luks),
            discard_max_bytes: 4096,
            ..layer("dm-4", &["dm-3"])
        },
        layer("dm-3", &["dm-1", "dm-2", "dm-0"]),
        layer("dm-1", &["zram0"]),
        layer("dm-2", &["zram0"]),
        layer("dm-0", &["nvme0n1p3"]),
        layer("zram0", &[]),
        layer("nvme0n1p3", &[]),
    ];
    assert!(
        discards_over_hidden(&layers),
        "the SSD below the cache takes the discards"
    );

    // The same stack resting on zram alone reaches no persistent storage.
    let mut on_ram = layers.clone();
    on_ram[4] = layer("dm-0", &["zram1"]);
    on_ram[6] = layer("zram1", &[]);
    assert!(!discards_over_hidden(&on_ram));

    // A forwarding mapping whose devices below could not be read is no
    // proof of RAM: it fails closed.
    let unread = [Layer {
        crypt: Some(CryptType::Luks),
        discard_max_bytes: 4096,
        ..layer("dm-4", &[])
    }];
    assert!(discards_over_hidden(&unread));

    // Nor is a walk that ended before any device at the bottom: with no
    // bottom device seen, nothing shows the stack rests on RAM.
    let cut_short = [Layer {
        crypt: Some(CryptType::Luks),
        discard_max_bytes: 4096,
        ..layer("dm-4", &["dm-3"])
    }];
    assert!(discards_over_hidden(&cut_short));
}

/// LUKS with discards (dm-20) on a logical volume cached with dm-cache
/// (dm-19): its origin (dm-16) is striped over ten physical volumes that are
/// LUKS mappings opened with discards (dm-0 to dm-9, on sda to sdj), its data
/// and metadata (dm-17, dm-18) sit on zram0. As in sysfs, each `slaves/` entry
/// is a link to the device's own directory.
#[test]
fn a_walk_cut_short_after_a_zram_leaf_excepts_nothing() {
    let fs = MockFilesystem::new();
    fs.mock_set_file_content(
        MOUNTINFO,
        &mountinfo("254:20", "ext4", "/dev/mapper/hidden"),
    );
    // A device at `dir` named `name`, with discards on, and the devices
    // below it.
    let device = |dir: &str, name: &str, uuid: Option<&str>, below: &[&str]| {
        add_device(&fs, dir, name, uuid, None, "4096");
        let links = below
            .iter()
            .map(|slave| {
                let link = PathBuf::from(format!("{dir}/slaves/{slave}"));
                fs.create_symlink(&Path::new(SYS_BLOCK).join(slave), &link)
                    .unwrap();
                link
            })
            .collect();
        fs.mock_set_directory_contents(&Path::new(dir).join("slaves"), links);
    };
    let block = |name: &str| format!("{SYS_BLOCK}/{name}");
    let top = "/sys/dev/block/254:20";
    device(top, "dm-20", Some("CRYPT-LUKS2-20-hidden"), &["dm-19"]);
    device(
        &block("dm-19"),
        "dm-19",
        Some("LVM-cache"),
        &["dm-16", "dm-17", "dm-18"],
    );
    let pvs = [
        "dm-0", "dm-1", "dm-2", "dm-3", "dm-4", "dm-5", "dm-6", "dm-7", "dm-8", "dm-9",
    ];
    device(&block("dm-16"), "dm-16", Some("LVM-corig"), &pvs);
    device(&block("dm-17"), "dm-17", Some("LVM-cdata"), &["zram0"]);
    device(&block("dm-18"), "dm-18", Some("LVM-cmeta"), &["zram0"]);
    let disks = [
        "sda", "sdb", "sdc", "sdd", "sde", "sdf", "sdg", "sdh", "sdi", "sdj",
    ];
    for (pv, disk) in pvs.into_iter().zip(disks) {
        let uuid = format!("CRYPT-LUKS2-{pv}-pv");
        device(&block(pv), pv, Some(uuid.as_str()), &[disk]);
        device(&block(disk), disk, None, &[]);
    }
    device(&block("zram0"), "zram0", None, &[]);

    // The walk reads sixteen devices, zram0 the last of them, and stops
    // before the ten disks: the only bottom device it saw is zram0.
    let layers = device_layers(&fs, Path::new(top));
    assert_eq!(layers.len(), blockdev::MAX_STACK_DEVICES);
    assert!(layers.iter().any(|layer| layer.name == "zram0"));
    assert!(!layers.iter().any(|layer| layer.name.starts_with("sd")));

    // The disks it did not reach take the discards: refused.
    let result = assess_offline(&fs, Path::new(ROOT));
    assert!(result.is_fail(), "{result:?}");
    assert!(
        result
            .message()
            .contains("Discards are enabled over the hidden volume"),
        "{result:?}"
    );
}

#[test]
fn file_container_on_btrfs_warns_about_cow() {
    let fs = tcrypt_container_fixture("btrfs", "0");

    let result = assess_offline(&fs, Path::new(ROOT));
    assert!(result.is_warn());
    let message = result.message();
    assert!(message.contains("copy-on-write btrfs filesystem"));
    assert!(message.contains("disable automatic snapshots"));
    assert!(message.contains("on the btrfs filesystem mounted at /home"));
}

#[test]
fn file_container_on_zfs_warns_about_cow() {
    let fs = tcrypt_container_fixture("zfs", "0");

    let result = assess_offline(&fs, Path::new(ROOT));
    assert!(result.is_warn());
    assert!(result.message().contains("copy-on-write zfs filesystem"));
}

#[test]
fn file_container_on_ext4_has_no_cow_warning() {
    let fs = tcrypt_container_fixture("ext4", "0");

    let result = assess_offline(&fs, Path::new(ROOT));
    assert!(!result.message().contains("copy-on-write"));
}

#[test]
fn discards_fail_closed_even_with_other_hazards_and_warn_when_allowed() {
    let fs = tcrypt_container_fixture("btrfs", "4096");

    // The discard refusal takes precedence over the (warning) hazards.
    assert!(assess_offline(&fs, Path::new(ROOT)).is_fail());

    // Accepted for the run, every finding shows together as a warning.
    let allowed = assess_offline_allowing_discards(&fs, Path::new(ROOT));
    assert!(allowed.is_warn());
    let message = allowed.message();
    assert!(message.contains("Discards are enabled over the hidden volume, accepted"));
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

// ------------------------------------------------------------------------
// LUKS2 header and Shufflecake
// ------------------------------------------------------------------------

/// A LUKS2 mapping (`253:2` -> dm-2) over partition `sdb2`.
fn luks_on_partition_fixture() -> MockFilesystem {
    let fs = MockFilesystem::new();
    fs.mock_set_file_content(MOUNTINFO, &mountinfo("253:2", "ext4", "/dev/mapper/data"));
    add_device(
        &fs,
        "/sys/dev/block/253:2",
        "dm-2",
        Some("CRYPT-LUKS2-0123456789abcdef0123456789abcdef-data"),
        None,
        "0",
    );
    fs.mock_set_directory_contents(
        Path::new("/sys/dev/block/253:2/slaves"),
        vec![PathBuf::from("/sys/dev/block/253:2/slaves/sdb2")],
    );
    add_device(
        &fs,
        "/sys/dev/block/253:2/slaves/sdb2",
        "sdb2",
        None,
        None,
        "0",
    );
    fs
}

/// A `dev` directory holding `sdb2` with a LUKS2 header carrying `json`.
fn dev_dir_with_header(json: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let mut image = luks2::header_image(json, 16384);
    image.extend(std::iter::repeat_n(0u8, 4096));
    std::fs::write(dir.path().join("sdb2"), image).unwrap();
    dir
}

#[test]
fn luks2_persistent_discards_refuse_and_the_tpm_token_warns_when_allowed() {
    let fs = luks_on_partition_fixture();
    let dev = dev_dir_with_header(
        r#"{"tokens":{"0":{"type":"systemd-tpm2"}},"config":{"flags":["allow-discards"]}}"#,
    );

    // The stored allow-discards flag is a discard over the hidden volume, so it
    // fails closed and names no device-mapper node.
    let refused = assess_with_dev_dir(&fs, Path::new(ROOT), dev.path(), false);
    assert!(refused.is_fail(), "{refused:?}");
    assert!(
        refused
            .message()
            .contains("Discards are enabled over the hidden volume")
    );
    assert_names_no_dm_node(&refused);

    // Accepted for the run, it warns and still surfaces the TPM-token tell.
    let allowed = assess_with_dev_dir(&fs, Path::new(ROOT), dev.path(), true);
    assert!(allowed.is_warn(), "{allowed:?}");
    let message = allowed.message();
    assert!(message.contains("accepted for this run"), "{message}");
    assert!(message.contains("systemd-tpm2 token"), "{message}");
    assert!(
        message.contains("binding the volume to the host"),
        "{message}"
    );
}

#[test]
fn the_mappings_own_luks_header_is_named_in_the_pass_line() {
    let fs = luks_on_partition_fixture();
    let dev = dev_dir_with_header(r#"{"tokens":{},"config":{"flags":[]}}"#);
    let result = assess_with_dev_dir(&fs, Path::new(ROOT), dev.path(), false);
    assert_eq!(
        result,
        CheckResult::Pass(
            "Hidden root backend: ext4 on LUKS mapping dm-2 on block device sdb2; no \
             backend-specific hazards detected. The LUKS2 header at the start of sdb2 shows \
             anyone who reads the disk that an encrypted volume is there (cryptsetup isLuks, \
             blkid), though not what it holds."
                .into()
        )
    );
}

#[test]
fn a_header_cryptsetup_wrote_is_the_mappings_own_by_the_uuid_the_mapping_names() {
    // The start of an image cryptsetup formatted and gave a systemd-tpm2
    // token, below a mapping whose device-mapper uuid names that image's
    // uuid, as cryptsetup names it: its token is the mapping's, and warns.
    let uuid = "c163aa97-37dc-45ab-a296-f1ed26db0fb0";
    let fs = luks_on_partition_fixture();
    fs.mock_set_file_content(
        "/sys/dev/block/253:2/dm/uuid",
        &format!("CRYPT-LUKS2-{}-data\n", uuid.replace('-', "")),
    );
    let dev = tempfile::tempdir().unwrap();
    std::fs::write(
        dev.path().join("sdb2"),
        include_bytes!("fixtures/luks2-tpm2-token.hdr"),
    )
    .unwrap();
    let result = assess_with_dev_dir(&fs, Path::new(ROOT), dev.path(), false);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        result
            .message()
            .contains("The LUKS2 header of mapping dm-2 carries a systemd-tpm2 token"),
        "{result:?}"
    );
    assert!(
        !result.message().contains("of another volume"),
        "{result:?}"
    );
}

#[test]
fn an_attached_luks1_header_is_named_by_its_version() {
    let fs = luks_on_partition_fixture();
    let dev = tempfile::tempdir().unwrap();
    let mut image = luks2::header_image("{}", 16384);
    image[6..8].copy_from_slice(&1u16.to_be_bytes());
    std::fs::write(dev.path().join("sdb2"), image).unwrap();
    let result = assess_with_dev_dir(&fs, Path::new(ROOT), dev.path(), false);
    assert!(result.is_pass(), "{result:?}");
    assert!(
        result
            .message()
            .contains("The LUKS1 header at the start of sdb2 shows anyone"),
        "{result:?}"
    );
}

#[test]
fn ciphertext_at_the_start_is_described_as_a_detached_header() {
    let fs = luks_on_partition_fixture();
    let dev = tempfile::tempdir().unwrap();
    std::fs::write(dev.path().join("sdb2"), vec![0x5Au8; 65536]).unwrap();
    let result = assess_with_dev_dir(&fs, Path::new(ROOT), dev.path(), false);
    assert_eq!(
        result,
        CheckResult::Pass(
            "Hidden root backend: ext4 on LUKS mapping dm-2 (detached header) on block device \
             sdb2; no backend-specific hazards detected. The flags and tokens of the detached \
             LUKS header of dm-2 are in its file, which `cryptsetup luksDump <file>` shows."
                .into()
        )
    );
}

#[test]
fn discards_over_a_detached_header_mapping_fail_closed() {
    let fs = luks_on_partition_fixture();
    fs.mock_set_file_content("/sys/dev/block/253:2/queue/discard_max_bytes", "4096\n");
    let dev = tempfile::tempdir().unwrap();
    std::fs::write(dev.path().join("sdb2"), vec![0x5Au8; 65536]).unwrap();
    let result = assess_with_dev_dir(&fs, Path::new(ROOT), dev.path(), false);
    assert!(result.is_fail(), "{result:?}");
}

#[test]
fn a_surviving_luks2_secondary_header_warns() {
    let fs = luks_on_partition_fixture();
    let dev = tempfile::tempdir().unwrap();
    let mut image = vec![0x5Au8; 65536];
    image[0x4000..0x4006].copy_from_slice(b"SKUL\xba\xbe");
    std::fs::write(dev.path().join("sdb2"), image).unwrap();
    let result = assess_with_dev_dir(&fs, Path::new(ROOT), dev.path(), false);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        result.message().contains(
            "The device below LUKS mapping dm-2, sdb2, opened with a header kept apart from it, \
             still holds a LUKS2 secondary header 16 KiB in, which blkid and an examiner \
             identify as LUKS2. docs/backends.md says how to clear it."
        ),
        "{result:?}"
    );
    assert!(result.message().contains("(detached header)"), "{result:?}");
}

#[test]
fn a_header_of_another_volume_warns_and_its_flags_are_not_the_mappings() {
    // The mapping was opened with a header kept elsewhere; the device still
    // starts with the header of a volume made on it before, which stores
    // allow-discards.
    let fs = luks_on_partition_fixture();
    fs.mock_set_file_content(
        "/sys/dev/block/253:2/dm/uuid",
        "CRYPT-LUKS2-ffffffffffffffffffffffffffffffff-data\n",
    );
    let dev = dev_dir_with_header(r#"{"tokens":{},"config":{"flags":["allow-discards"]}}"#);
    let result = assess_with_dev_dir(&fs, Path::new(ROOT), dev.path(), false);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        result.message().contains(&format!(
            "The device below LUKS mapping dm-2, sdb2, starts with a LUKS2 header of another \
             volume (uuid {}) than the one the mapping was opened with: a leftover that blkid \
             and an examiner identify as LUKS. docs/backends.md says how to clear it.",
            luks2::TEST_UUID
        )),
        "{result:?}"
    );
}

#[test]
fn a_luks2_volume_on_a_self_encrypting_drive_has_its_header_told_from_another() {
    // cryptsetup gives a LUKS2 volume that uses the drive's own encryption
    // the type LUKS2-OPAL, `CRYPT-LUKS2-OPAL-<hex>-<name>`.
    let fs = luks_on_partition_fixture();
    let dev = dev_dir_with_header(r#"{"tokens":{},"config":{"flags":[]}}"#);
    fs.mock_set_file_content(
        "/sys/dev/block/253:2/dm/uuid",
        "CRYPT-LUKS2-OPAL-ffffffffffffffffffffffffffffffff-data\n",
    );
    let result = assess_with_dev_dir(&fs, Path::new(ROOT), dev.path(), false);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        result.message().contains(&format!(
            "The device below LUKS mapping dm-2, sdb2, starts with a LUKS2 header of another \
             volume (uuid {}) than the one the mapping was opened with",
            luks2::TEST_UUID
        )),
        "{result:?}"
    );
    // Its own header is named in the pass line, as for any LUKS2 volume.
    fs.mock_set_file_content(
        "/sys/dev/block/253:2/dm/uuid",
        &format!(
            "CRYPT-LUKS2-OPAL-{}-data\n",
            luks2::TEST_UUID.replace('-', "")
        ),
    );
    let result = assess_with_dev_dir(&fs, Path::new(ROOT), dev.path(), false);
    assert_eq!(
        result,
        CheckResult::Pass(
            "Hidden root backend: ext4 on LUKS mapping dm-2 on block device sdb2; no \
             backend-specific hazards detected. The LUKS2 header at the start of sdb2 shows \
             anyone who reads the disk that an encrypted volume is there (cryptsetup isLuks, \
             blkid), though not what it holds."
                .into()
        )
    );
}

/// A mock host with the hidden root on a LUKS2 volume with authenticated
/// encryption: the LUKS mapping `dm-9` on its integrity layer `dm-8`, whose
/// device-mapper uuid has the type `integrity` (`SUBDEV` from cryptsetup 2.8
/// on, `INTEGRITY` before), on `sdb2`. The integrity layer's start is
/// ciphertext, written to `dev`.
fn luks_with_integrity(integrity: &str, dev: &tempfile::TempDir) -> super::tests_host::Host {
    let hex = luks2::TEST_UUID.replace('-', "");
    std::fs::write(dev.path().join("dm-8"), vec![0x5Au8; 65536]).unwrap();
    super::tests_host::Host::new("254:9", "ext4", "/dev/mapper/data")
        .disk("sdb", "8:16")
        .partition_at("sdb2", "8:18", "sdb", 2, 2048)
        .mapping(
            "dm-8",
            "254:8",
            "data_dif",
            &format!("CRYPT-{integrity}-{hex}-data_dif"),
            &["sdb2"],
        )
        .mapping(
            "dm-9",
            "254:9",
            "data",
            &format!("CRYPT-LUKS2-{hex}-data"),
            &["dm-8"],
        )
}

#[test]
fn a_luks2_volume_with_integrity_has_its_header_read_below_its_integrity_layer() {
    for integrity in ["SUBDEV", "INTEGRITY"] {
        let dev = dev_dir_with_header(r#"{"tokens":{},"config":{"flags":[]}}"#);
        let host = luks_with_integrity(integrity, &dev);
        let root = Path::new(super::tests_host::ROOT);
        assert_eq!(
            assess_with_dev_dir(&host.fs, root, dev.path(), false),
            CheckResult::Pass(
                "Hidden root backend: ext4 on LUKS mapping dm-9 on dm-integrity mapping dm-8 \
                 (encrypts nothing) on block device sdb2; no backend-specific hazards detected. \
                 The LUKS2 header at the start of sdb2 shows anyone who reads the disk that an \
                 encrypted volume is there (cryptsetup isLuks, blkid), though not what it holds."
                    .into()
            ),
            "{integrity}"
        );
    }
}

#[test]
fn the_stored_flags_of_a_luks2_volume_with_integrity_count() {
    let dev = dev_dir_with_header(r#"{"tokens":{},"config":{"flags":["allow-discards"]}}"#);
    let host = luks_with_integrity("SUBDEV", &dev);
    let result = assess_with_dev_dir(
        &host.fs,
        Path::new(super::tests_host::ROOT),
        dev.path(),
        false,
    );
    assert!(result.is_fail(), "{result:?}");
}

/// A mock host with the hidden root on a LUKS2 volume that `cryptsetup
/// reencrypt` re-encrypts while it is open, as cryptsetup 2.7 and 2.8 build
/// it: the volume's mapping `dm-4` maps to the overlay `dm-6`, which holds
/// the crypt segments, on `sdb2` and on the hotzone `dm-5`, a linear map of
/// `sdb2`. Both carry the type `SUBDEV` and the volume's uuid, as the
/// integrity layer does. The overlay's start is plaintext and the hotzone's
/// ciphertext, written to `dev`.
fn luks_under_reencryption(dev: &tempfile::TempDir) -> super::tests_host::Host {
    let hex = luks2::TEST_UUID.replace('-', "");
    std::fs::write(dev.path().join("dm-5"), vec![0x5Au8; 65536]).unwrap();
    std::fs::write(dev.path().join("dm-6"), vec![0u8; 65536]).unwrap();
    super::tests_host::Host::new("254:4", "ext4", "/dev/mapper/data")
        .disk("sdb", "8:16")
        .partition_at("sdb2", "8:18", "sdb", 2, 2048)
        .mapping(
            "dm-5",
            "254:5",
            "data-hotzone-forward",
            &format!("CRYPT-SUBDEV-{hex}-data-hotzone-forward"),
            &["sdb2"],
        )
        .mapping(
            "dm-6",
            "254:6",
            "data-overlay",
            &format!("CRYPT-SUBDEV-{hex}-data-overlay"),
            &["dm-5", "sdb2"],
        )
        .mapping(
            "dm-4",
            "254:4",
            "data",
            &format!("CRYPT-LUKS2-{hex}-data"),
            &["dm-6"],
        )
}

#[test]
fn a_luks2_volume_under_reencryption_has_its_header_read_below_its_sub_devices() {
    // The overlay and the hotzone are no integrity layers, and the header is
    // on sdb2, below both: not at the start of the hotzone, which sorts
    // first below the overlay.
    let dev = dev_dir_with_header(r#"{"tokens":{},"config":{"flags":[]}}"#);
    let host = luks_under_reencryption(&dev);
    let root = Path::new(super::tests_host::ROOT);
    assert_eq!(
        assess_with_dev_dir(&host.fs, root, dev.path(), false),
        CheckResult::Pass(
            "Hidden root backend: ext4 on LUKS mapping dm-4 on LUKS2 sub-device dm-6 (SUBDEV) on \
             LUKS2 sub-device dm-5 (SUBDEV) on block device sdb2; no backend-specific hazards \
             detected. The LUKS2 header at the start of sdb2 shows anyone who reads the disk \
             that an encrypted volume is there (cryptsetup isLuks, blkid), though not what it \
             holds."
                .into()
        )
    );
    // So its stored flags count.
    let dev = dev_dir_with_header(r#"{"tokens":{},"config":{"flags":["allow-discards"]}}"#);
    let host = luks_under_reencryption(&dev);
    let result = assess_with_dev_dir(&host.fs, root, dev.path(), false);
    assert!(result.is_fail(), "{result:?}");
}

#[test]
fn a_luks_volume_on_a_sub_device_of_another_volume_has_its_header_read_there() {
    // A LUKS volume made on the integrity layer of another LUKS2 volume: a
    // sub-device that names another volume uuid than the mapping's is no
    // sub-device of its volume, and its start holds the header.
    let dev = tempfile::tempdir().unwrap();
    std::fs::write(
        dev.path().join("dm-8"),
        luks2::header_image(r#"{"tokens":{},"config":{"flags":[]}}"#, 16384),
    )
    .unwrap();
    let host = super::tests_host::Host::new("254:9", "ext4", "/dev/mapper/data")
        .disk("sdb", "8:16")
        .partition_at("sdb2", "8:18", "sdb", 2, 2048)
        .mapping(
            "dm-8",
            "254:8",
            "outer_dif",
            "CRYPT-SUBDEV-ffffffffffffffffffffffffffffffff-outer_dif",
            &["sdb2"],
        )
        .mapping(
            "dm-9",
            "254:9",
            "data",
            "CRYPT-LUKS2-0123456789abcdef0123456789abcdef-data",
            &["dm-8"],
        );
    let result = assess_with_dev_dir(
        &host.fs,
        Path::new(super::tests_host::ROOT),
        dev.path(),
        false,
    );
    assert_eq!(
        result,
        CheckResult::Pass(
            "Hidden root backend: ext4 on LUKS mapping dm-9 on dm-integrity mapping dm-8 \
             (encrypts nothing) on block device sdb2; no backend-specific hazards detected. The \
             LUKS2 header at the start of dm-8 shows anyone who reads the disk that an encrypted \
             volume is there (cryptsetup isLuks, blkid), though not what it holds."
                .into()
        )
    );
}

#[test]
fn a_luks_volume_on_an_integrity_device_of_its_own_has_its_header_read_there() {
    // integritysetup's device, which names no volume uuid, with a LUKS
    // volume made on it: the header is at the start of the integrity device.
    let dev = tempfile::tempdir().unwrap();
    std::fs::write(
        dev.path().join("dm-8"),
        luks2::header_image(r#"{"tokens":{},"config":{"flags":[]}}"#, 16384),
    )
    .unwrap();
    let host = super::tests_host::Host::new("254:9", "ext4", "/dev/mapper/data")
        .disk("sdb", "8:16")
        .partition_at("sdb2", "8:18", "sdb", 2, 2048)
        .mapping("dm-8", "254:8", "integ", "CRYPT-INTEGRITY-integ", &["sdb2"])
        .mapping(
            "dm-9",
            "254:9",
            "data",
            "CRYPT-LUKS2-0123456789abcdef0123456789abcdef-data",
            &["dm-8"],
        );
    let result = assess_with_dev_dir(
        &host.fs,
        Path::new(super::tests_host::ROOT),
        dev.path(),
        false,
    );
    assert!(
        result.message().contains(
            "ext4 on LUKS mapping dm-9 on dm-integrity mapping dm-8 (encrypts nothing) on block \
             device sdb2"
        ) && result
            .message()
            .contains("The LUKS2 header at the start of dm-8 shows anyone"),
        "{result:?}"
    );
}

#[test]
fn an_unreadable_device_leaves_the_description_as_it_is() {
    let fs = luks_on_partition_fixture();
    let result = assess_offline(&fs, Path::new(ROOT));
    assert_eq!(
        result,
        CheckResult::Pass(
            "Hidden root backend: ext4 on LUKS mapping dm-2 on block device sdb2; no \
             backend-specific hazards detected"
                .into()
        )
    );
}

#[test]
fn a_fido2_token_names_the_method() {
    let layer = Layer {
        name: "dm-2".into(),
        crypt: Some(CryptType::Luks),
        luks2: Some(luks2::Luks2Metadata {
            flags: Vec::new(),
            token_types: vec!["systemd-fido2".into(), "user-defined".into()],
        }),
        ..Layer::default()
    };
    let found = hazards(&[layer], &[]);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("systemd-fido2 token"), "{found:?}");
    assert!(!found[0].contains("user-defined"), "{found:?}");
}

#[test]
fn a_shufflecake_volume_is_recognised() {
    let fs = MockFilesystem::new();
    fs.mock_set_file_content(
        MOUNTINFO,
        &mountinfo("253:7", "ext4", "/dev/mapper/sflc_0_1"),
    );
    add_device(&fs, "/sys/dev/block/253:7", "dm-7", None, None, "0");
    fs.mock_set_file_content("/sys/dev/block/253:7/dm/name", "sflc_0_1\n");
    fs.mock_set_directory_contents(
        Path::new("/sys/dev/block/253:7/slaves"),
        vec![PathBuf::from("/sys/dev/block/253:7/slaves/sdc")],
    );
    add_device(
        &fs,
        "/sys/dev/block/253:7/slaves/sdc",
        "sdc",
        None,
        None,
        "0",
    );

    let result = assess_offline(&fs, Path::new(ROOT));
    assert!(result.is_pass(), "{result:?}");
    assert!(
        result
            .message()
            .contains("Shufflecake volume sflc_0_1 (dm-7) on block device sdc"),
        "{}",
        result.message()
    );
}

#[test]
fn shufflecake_naming_is_strict() {
    let named = |name: &str| Layer {
        dm_name: Some(name.into()),
        ..Layer::default()
    };
    assert!(named("sflc_12_3").is_shufflecake());
    assert!(!named("sflc_x_3").is_shufflecake());
    assert!(!named("sflc_1").is_shufflecake());
    assert!(!named("data").is_shufflecake());
}

// ------------------------------------------------------------------------
// Loops over block devices, VeraCrypt's own mappings, the decoy's storage
// ------------------------------------------------------------------------

/// backend-detect of the hidden root of the mock host `host`, with no LUKS
/// header to read.
fn detect_on(host: &super::tests_host::Host) -> CheckResult {
    let dev = tempfile::tempdir().unwrap();
    assess_with_dev_dir(
        &host.fs,
        Path::new(super::tests_host::ROOT),
        dev.path(),
        false,
    )
}

/// A mock host with the hidden root on the LUKS mapping `dm-9` of a loop
/// device over `sdb2`, bound with autoclear or not.
fn luks_on_a_loop_over_a_partition(autoclear: bool) -> super::tests_host::Host {
    let host = super::tests_host::Host::new("254:9", "ext4", "/dev/mapper/data")
        .disk("sdb", "8:16")
        .partition_at("sdb2", "8:18", "sdb", 2, 2048)
        .loop_device("loop0", "7:0", "/dev/sdb2")
        .luks("dm-9", "254:9", "data", &["loop0"]);
    if autoclear {
        host.fs
            .mock_set_file_content("/sys/devices/virtual/block/loop0/loop/autoclear", "1\n");
    }
    host
}

#[test]
fn a_loop_over_a_block_device_is_followed_and_is_no_file_container() {
    let result = detect_on(&luks_on_a_loop_over_a_partition(true));
    assert_eq!(
        result,
        CheckResult::Pass(
            "Hidden root backend: ext4 on LUKS mapping dm-9 on loop device loop0 on block device \
             sdb2; no backend-specific hazards detected"
                .into()
        )
    );
}

#[test]
fn a_loop_over_a_block_device_without_autoclear_warns() {
    let result = detect_on(&luks_on_a_loop_over_a_partition(false));
    assert!(result.is_warn(), "{result:?}");
    assert!(
        result.message().contains(
            "Loop device loop0 over sdb2 was attached without autoclear, so it stays bound after \
             the hidden volume is closed, after a session too, until losetup -d detaches it."
        ),
        "{result:?}"
    );
    assert!(!result.message().contains("mtime and ctime"), "{result:?}");
}

#[test]
fn discards_over_a_loop_over_zram_alone_are_excepted() {
    let host = super::tests_host::Host::new("254:9", "ext4", "/dev/mapper/data")
        .disk("zram0", "252:0")
        .loop_device("loop0", "7:0", "/dev/zram0")
        .luks("dm-9", "254:9", "data", &["loop0"]);
    host.fs.mock_set_file_content(
        "/sys/devices/virtual/block/dm-9/queue/discard_max_bytes",
        "4096\n",
    );
    // TRIM reaches no persistent storage: only the loop's missing autoclear
    // warns.
    let result = detect_on(&host);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        !result.message().contains("Discards are enabled"),
        "{result:?}"
    );
    assert!(
        result.message().contains("Loop device loop0 over zram0"),
        "{result:?}"
    );
}

#[test]
fn a_mapping_the_veracrypt_application_made_is_named_and_its_discards_refused() {
    // No uuid up to VeraCrypt 1.26.29, VERACRYPT-<serial>-<name> from 1.26.30
    // on.
    for uuid in ["", "VERACRYPT-1762101445123456-veracrypt1"] {
        let host = super::tests_host::Host::new("254:9", "ext4", "/dev/mapper/veracrypt1")
            .disk("sdb", "8:16")
            .mapping("dm-9", "254:9", "veracrypt1", uuid, &["sdb"]);
        assert_eq!(
            detect_on(&host),
            CheckResult::Pass(
                "Hidden root backend: ext4 on VeraCrypt application mapping dm-9 on block device \
                 sdb; no backend-specific hazards detected"
                    .into()
            ),
            "{uuid}"
        );
        host.fs.mock_set_file_content(
            "/sys/devices/virtual/block/dm-9/queue/discard_max_bytes",
            "4096\n",
        );
        assert!(detect_on(&host).is_fail(), "{uuid}");
    }
}

#[test]
fn cascade_integrity_and_verity_layers_are_named_for_what_they_are() {
    let layer = |name: &str, kind: &str| Layer {
        name: name.into(),
        is_dm: true,
        crypt: Some(CryptType::Other(kind.into())),
        ..Layer::default()
    };
    assert_eq!(
        describe(
            "ext4",
            &[
                layer("dm-8", "SUBDEV"),
                layer("dm-7", "INTEGRITY"),
                layer("dm-6", "VERITY")
            ]
        ),
        "ext4 on dm-crypt cascade layer dm-8 (SUBDEV) on dm-integrity mapping dm-7 (encrypts \
         nothing) on dm-verity mapping dm-6 (encrypts nothing)"
    );
}

#[test]
fn a_root_on_a_filesystem_the_decoy_uses_is_left_to_the_hidden_volume_check() {
    // A bind of a folder of the decoy's /home, which the attach gate refuses
    // unless the run accepts the decoy's storage.
    let host = super::tests_host::Host::with_mounts(
        "40 1 254:1 /alice /mnt/data rw,relatime - ext4 /dev/mapper/home rw\n",
    )
    .file(
        "/proc/devices",
        "Block devices:\n  7 loop\n  8 sd\n254 device-mapper\n259 blkext\n",
    );
    assert_eq!(
        detect_on(&host),
        CheckResult::Pass(
            "Backend detection skipped: the hidden root is on a filesystem the decoy uses, which \
             the hidden-volume check reports"
                .into()
        )
    );

    // Discards over the decoy's stack, which keeps the root's data, are
    // refused all the same, and accepted for a run they warn.
    host.fs.mock_set_file_content(
        "/sys/devices/virtual/block/dm-1/queue/discard_max_bytes",
        "4096\n",
    );
    let refused = detect_on(&host);
    assert!(refused.is_fail(), "{refused:?}");
    assert!(
        refused
            .message()
            .starts_with("Discards are enabled over the hidden volume."),
        "{refused:?}"
    );
    let dev = tempfile::tempdir().unwrap();
    let root = Path::new(super::tests_host::ROOT);
    assert_eq!(
        assess_with_dev_dir(&host.fs, root, dev.path(), true),
        CheckResult::Warn(format!(
            "Backend detection skipped: the hidden root is on a filesystem the decoy uses, which \
             the hidden-volume check reports. {DISCARD_ACCEPTED} See docs/backends.md."
        ))
    );
}
