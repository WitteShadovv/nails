// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The partition-type check on the mock hosts of
//! [`tests_host`](super::super::tests_host), with each disk's start written
//! to a file of a directory that stands in for `/dev`. The hidden root's
//! partition is partition 5 of the decoy's disk `nvme0n1` unless a test
//! says otherwise.

use super::super::tests_host::{Host, ROOT};
use super::*;
use crate::filesystem::MockFilesystem;
use crate::forensic::layout::discoverable::{LINUX_FILESYSTEM, NO_AUTO};
use crate::forensic::layout::images::{gpt_disk, typed_gpt_entry};
use std::os::unix::fs::FileExt;

const HOME: &str = "933AC7E1-2EB4-4F13-B844-0E14E2AEF915";
const SRV: &str = "3B8F8425-20E0-4F3B-907F-1A25A76F98E8";
const VAR: &str = "4D21B016-B534-45C2-A9FB-5C16E091FD2D";
const VAR_TMP: &str = "7EC6F557-3BC5-4ACA-B293-16EF5DF639D1";
const SWAP: &str = "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F";
const ESP: &str = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B";
const XBOOTLDR: &str = "BC13C2FF-59E6-4262-A352-B275FD6F7172";
const ROOT_X86_64: &str = "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709";

/// The size of every disk image, in 512-byte blocks (4 GiB).
const BLOCKS: u64 = 1 << 23;
/// Where partition 5 starts and ends, in blocks.
const P5_START: u64 = 2_099_200;
const P5_END: u64 = P5_START + 2_097_151;

/// The command the remediation gives for partition 5 of `node`.
fn sgdisk(node: &str) -> String {
    format!("sgdisk --typecode=5:{LINUX_FILESYSTEM} {node}")
}

/// The hidden root on the LUKS mapping `dm-9` of `nvme0n1p5`, partition 5
/// of the decoy's disk.
fn on_the_decoys_disk() -> Host {
    Host::new("254:9", "ext4", "/dev/mapper/data")
        .partition_at("nvme0n1p5", "259:5", "nvme0n1", 5, P5_START)
        .luks("dm-9", "254:9", "data", &["nvme0n1p5"])
}

/// A directory in place of `/dev` whose file `disk` starts with `image`.
fn devices(disk: &str, image: &[u8]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let file = std::fs::File::create(dir.path().join(disk)).unwrap();
    file.set_len(BLOCKS * 512).unwrap();
    file.write_all_at(image, 0).unwrap();
    dir
}

/// A GPT whose fifth entry is partition 5 with `type_id` and `flags`.
fn gpt(type_id: &str, flags: u64) -> Vec<u8> {
    let mut entries = vec![[0u8; 128]; 4];
    entries.push(typed_gpt_entry(type_id, P5_START, P5_END, flags, "data"));
    gpt_disk(BLOCKS, &entries)
}

/// The check of the hidden root at [`ROOT`] on `fs`, reading disks from
/// `dev`.
fn check(fs: &MockFilesystem, dev: &tempfile::TempDir) -> CheckResult {
    BackendPartitionTypeCheck::new(PathBuf::from(ROOT))
        .reading_devices_in(dev.path())
        .run(fs)
        .unwrap()
}

/// The check of the hidden root on partition 5 of the decoy's disk, of the
/// type `type_id` with `flags`.
fn typed(type_id: &str, flags: u64) -> CheckResult {
    check(
        &on_the_decoys_disk().fs,
        &devices("nvme0n1", &gpt(type_id, flags)),
    )
}

/// The warning's sentences, without the fix on its own line.
fn warning(result: &CheckResult) -> &str {
    assert!(result.is_warn(), "{result:?}");
    result.message().lines().next().unwrap_or_default()
}

/// Its fix, on its own line.
fn fix(result: &CheckResult) -> &str {
    result.message().lines().nth(1).unwrap_or_default()
}

// ------------------------------------------------------------------------
// Types systemd mounts or uses at boot
// ------------------------------------------------------------------------

#[test]
fn each_type_systemd_mounts_or_swaps_on_refuses_with_the_retype_command() {
    for (type_id, kind) in [
        (HOME, "a /home partition"),
        (SRV, "a /srv partition"),
        (VAR, "a /var partition"),
        (VAR_TMP, "a /var/tmp partition"),
        (SWAP, "a swap partition"),
    ] {
        let result = typed(type_id, 0);
        assert!(result.is_fail(), "{type_id}: {result:?}");
        assert!(
            result.message().starts_with(&format!(
                "The hidden root at {ROOT} is stored on a disk the decoy boots from. Partition 5 \
                 of nvme0n1 (nvme0n1p5) has the GPT type of {kind}. At every later boot of the \
                 decoy, systemd "
            )),
            "{type_id}: {result:?}"
        );
        assert!(
            result.message().ends_with(
                "The hidden session, whose root is an overlay, is spared, but anyone who reads \
                 the partition table sees the type."
            ),
            "{type_id}: {result:?}"
        );
        assert_eq!(
            result.remediation(),
            Some(
                format!(
                    "From a live system or where setup happens, never on the decoy, give the \
                     partition the generic Linux type: {}. See docs/backends.md.",
                    sgdisk("/dev/nvme0n1")
                )
                .as_str()
            ),
            "{type_id}"
        );
    }
}

#[test]
fn a_mount_type_says_when_systemd_mounts_it() {
    let result = typed(SRV, 0);
    assert!(
        result.message().contains(
            "systemd mounts the first such partition of that disk at /srv when no fstab line \
             mounts /srv and that folder is empty, and asks for its passphrase first when it is a \
             LUKS volume: a failed mount or a passphrase prompt shows that the partition is there."
        ),
        "{result:?}"
    );
    // /var only with the partition uuid the machine ID gives it.
    let result = typed(VAR, 0);
    assert!(
        result.message().contains(
            "at /var when no fstab line mounts /var and that folder is empty, and only when its \
             partition uuid is the one this machine's ID gives it, and asks"
        ),
        "{result:?}"
    );
    let result = typed(SWAP, 0);
    assert!(
        result.message().contains(
            "systemd uses the first swap partition of that disk without the no-auto flag as \
             swap, unless an fstab line names a swap, and asks for its passphrase first when it \
             is a LUKS volume: a failed swap or a passphrase prompt shows that the partition is \
             there."
        ),
        "{result:?}"
    );
}

#[test]
fn the_no_auto_flag_turns_a_mount_type_into_a_warning_but_a_swap_type_is_refused() {
    for (type_id, point) in [
        (HOME, "/home"),
        (SRV, "/srv"),
        (VAR, "/var"),
        (VAR_TMP, "/var/tmp"),
    ] {
        let result = typed(type_id, NO_AUTO);
        assert_eq!(
            warning(&result),
            format!(
                "The hidden root at {ROOT} is stored on a disk the decoy boots from. Partition 5 \
                 of nvme0n1 (nvme0n1p5) has the GPT type of a {point} partition, with the no-auto \
                 flag, which tells systemd not to mount it. systemd leaves it alone, but anyone \
                 who reads the partition table sees a partition typed for {point} that the decoy \
                 never mounts."
            )
        );
        assert!(fix(&result).contains(&sgdisk("/dev/nvme0n1")), "{result:?}");
    }
    // systemd leaves a swap partition with the flag alone too, but the check
    // refuses the swap type with or without it.
    let result = typed(SWAP, NO_AUTO);
    assert!(result.is_fail(), "{result:?}");
    assert_eq!(
        result.message(),
        format!(
            "The hidden root at {ROOT} is stored on a disk the decoy boots from. Partition 5 of \
             nvme0n1 (nvme0n1p5) has the GPT type of a swap partition, with the no-auto flag, \
             which tells systemd not to use it. systemd leaves it alone, but anyone who reads \
             the partition table sees a swap partition that the decoy never uses, and the check \
             refuses the swap type with or without the flag."
        )
    );
    assert!(
        result
            .remediation()
            .unwrap_or_default()
            .contains(&sgdisk("/dev/nvme0n1")),
        "{result:?}"
    );
    // Another flag changes nothing.
    assert!(typed(SRV, 1).is_fail());
}

#[test]
fn the_boot_and_root_types_only_warn() {
    for (type_id, kind, when) in [
        (
            ESP,
            "an EFI system partition",
            "mounts the first EFI system partition of that disk at /boot or /efi when no fstab \
             line mounts anything at or below either and one of them is empty or missing, on a \
             UEFI boot only when the boot loader says it started from that disk, on a BIOS boot \
             without that condition",
        ),
        (
            XBOOTLDR,
            "an extended boot loader partition",
            "mounts the first extended boot loader partition of that disk at /boot when no \
             fstab line mounts anything at or below /boot or /efi and /boot is empty or missing, \
             on a UEFI boot only when the boot loader says it started from that disk",
        ),
        (
            ROOT_X86_64,
            "a root partition",
            "takes a root partition from that disk at boot only when the kernel command line \
             names no root",
        ),
    ] {
        let result = typed(type_id, 0);
        assert_eq!(
            warning(&result),
            format!(
                "The hidden root at {ROOT} is stored on a disk the decoy boots from. Partition 5 \
                 of nvme0n1 (nvme0n1p5) has the GPT type of {kind}. systemd {when}. Anyone who \
                 reads the partition table sees a type the partition's use does not explain."
            )
        );
        assert!(fix(&result).contains(&sgdisk("/dev/nvme0n1")), "{result:?}");
        // The no-auto flag changes nothing about a warning.
        assert!(typed(type_id, NO_AUTO).is_warn(), "{type_id}");
    }
}

#[test]
fn the_generic_type_and_other_types_pass() {
    for type_id in [
        LINUX_FILESYSTEM,
        // Linux LUKS, Microsoft basic data.
        "CA7D7CCB-63ED-4C53-861C-1742536059CC",
        "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7",
    ] {
        let result = typed(type_id, NO_AUTO);
        assert_eq!(
            result,
            CheckResult::Pass(format!(
                "The hidden root at {ROOT} is stored on a disk the decoy boots from. Partition 5 \
                 of nvme0n1 (nvme0n1p5) has a GPT type that systemd discovers nothing by."
            )),
            "{type_id}"
        );
    }
}

#[test]
fn the_retype_command_names_the_disk_by_its_link_in_by_id() {
    let host = on_the_decoys_disk();
    host.fs.mock_set_directory_contents(
        Path::new(BY_ID),
        vec![
            PathBuf::from("/dev/disk/by-id/nvme-Example_SSD_0001"),
            PathBuf::from("/dev/disk/by-id/nvme-Example_SSD_0001-part5"),
            PathBuf::from("/dev/disk/by-id/ata-Other_Disk_0002"),
        ],
    );
    host.link("/dev/disk/by-id/nvme-Example_SSD_0001", "/dev/nvme0n1");
    host.link(
        "/dev/disk/by-id/nvme-Example_SSD_0001-part5",
        "/dev/nvme0n1p5",
    );
    host.link("/dev/disk/by-id/ata-Other_Disk_0002", "/dev/sda");
    let result = check(&host.fs, &devices("nvme0n1", &gpt(SRV, 0)));
    assert!(
        result
            .remediation()
            .unwrap_or_default()
            .contains(&sgdisk("/dev/disk/by-id/nvme-Example_SSD_0001")),
        "{result:?}"
    );
}

// ------------------------------------------------------------------------
// Storage the check follows
// ------------------------------------------------------------------------

#[test]
fn a_partition_below_a_logical_volume_or_a_loop_device_is_judged() {
    // An LV on the LUKS mapping of partition 5.
    let host = Host::new("254:10", "ext4", "/dev/mapper/vg-data")
        .partition_at("nvme0n1p5", "259:5", "nvme0n1", 5, P5_START)
        .luks("dm-9", "254:9", "pv", &["nvme0n1p5"])
        .mapping("dm-10", "254:10", "vg-data", "LVM-a1b2-data", &["dm-9"]);
    assert!(check(&host.fs, &devices("nvme0n1", &gpt(HOME, 0))).is_fail());

    // LUKS on a loop device over partition 5.
    let host = Host::new("254:9", "ext4", "/dev/mapper/data")
        .partition_at("nvme0n1p5", "259:5", "nvme0n1", 5, P5_START)
        .loop_device("loop0", "7:0", "/dev/nvme0n1p5")
        .luks("dm-9", "254:9", "data", &["loop0"]);
    assert!(check(&host.fs, &devices("nvme0n1", &gpt(SWAP, 0))).is_fail());
}

#[test]
fn a_root_on_no_partition_of_a_boot_disk_passes() {
    let expected = format!(
        "The hidden root at {ROOT} is on no partition of a disk the decoy boots from (nvme0n1), \
         where systemd discovers partitions by their type."
    );
    // A partition of an external disk, whatever its type.
    let host = Host::new("254:9", "ext4", "/dev/mapper/data")
        .disk("sdb", "8:16")
        .partition_at("sdb2", "8:18", "sdb", 2, P5_START)
        .luks("dm-9", "254:9", "data", &["sdb2"]);
    let dev = devices("sdb", &gpt(SRV, 0));
    assert_eq!(check(&host.fs, &dev), CheckResult::Pass(expected.clone()));

    // A whole disk of its own.
    let host = Host::new("254:9", "ext4", "/dev/mapper/data")
        .disk("sdb", "8:16")
        .luks("dm-9", "254:9", "data", &["sdb"]);
    assert_eq!(check(&host.fs, &dev), CheckResult::Pass(expected.clone()));

    // A container file on the decoy's /home: the check does not follow it
    // into the decoy's filesystem.
    let host = Host::new("254:9", "ext4", "/dev/mapper/data")
        .loop_device("loop0", "7:0", "/home/alice/archive.img")
        .file_on("/home/alice/archive.img", 254, 1)
        .luks("dm-9", "254:9", "data", &["loop0"]);
    assert_eq!(check(&host.fs, &dev), CheckResult::Pass(expected));
}

#[test]
fn a_partition_of_the_decoys_own_storage_is_left_to_the_attach_gate() {
    // A root on the decoy's own /home volume, as --allow-decoy-storage
    // accepts: its partition's type is the decoy's.
    let host = Host::new("254:1", "ext4", "/dev/mapper/home");
    let mut entries = vec![[0u8; 128]; 3];
    entries.push(typed_gpt_entry(HOME, 105_908_224, 109_000_000, 0, "home"));
    let result = check(&host.fs, &devices("nvme0n1", &gpt_disk(BLOCKS, &entries)));
    assert_eq!(
        result,
        CheckResult::Pass(format!(
            "The hidden root at {ROOT} is on no partition of a disk the decoy boots from but the \
             decoy's own, whose types are the decoy's; the hidden-volume check reports a root on \
             the decoy's storage."
        ))
    );
}

#[test]
fn a_decoy_root_on_a_whole_disk_makes_that_disk_its_boot_disk() {
    // The decoy's root straight on vda, the hidden volume on a partition of
    // another disk.
    let host = Host::new("254:9", "ext4", "/dev/mapper/data")
        .disk("vda", "253:0")
        .disk("sdb", "8:16")
        .partition_at("sdb2", "8:18", "sdb", 2, P5_START)
        .luks("dm-9", "254:9", "data", &["sdb2"]);
    host.fs.mock_set_mount_table(&format!(
        "1 0 253:0 / / rw,relatime - ext4 /dev/vda rw\n\
         40 1 254:9 / {ROOT} rw,relatime - ext4 /dev/mapper/data rw\n"
    ));
    assert_eq!(
        check(&host.fs, &devices("sdb", &gpt(SRV, 0))),
        CheckResult::Pass(format!(
            "The hidden root at {ROOT} is on no partition of a disk the decoy boots from (vda), \
             where systemd discovers partitions by their type."
        ))
    );
}

#[test]
fn a_disk_under_the_efi_system_partition_is_a_boot_disk_too() {
    let host = Host::with_mounts(
        "3 1 8:1 / /boot/efi rw,relatime - vfat /dev/sda1 rw\n\
         40 1 254:9 / /mnt/data rw,relatime - ext4 /dev/mapper/data rw\n",
    )
    .disk("sda", "8:0")
    .partition_at("sda1", "8:1", "sda", 1, 2048)
    .partition_at("sda5", "8:5", "sda", 5, P5_START)
    .luks("dm-9", "254:9", "data", &["sda5"]);
    let result = check(&host.fs, &devices("sda", &gpt(SRV, 0)));
    assert!(result.is_fail(), "{result:?}");
    assert!(
        result
            .message()
            .contains("Partition 5 of sda (sda5) has the GPT type of a /srv partition"),
        "{result:?}"
    );
    // An automount not used yet shows no device and adds no disk.
    let host = Host::with_mounts(
        "3 1 0:52 / /boot/efi rw,relatime - autofs systemd-1 rw\n\
         40 1 254:9 / /mnt/data rw,relatime - ext4 /dev/mapper/data rw\n",
    )
    .disk("sda", "8:0")
    .partition_at("sda5", "8:5", "sda", 5, P5_START)
    .luks("dm-9", "254:9", "data", &["sda5"]);
    assert!(
        check(&host.fs, &devices("sda", &gpt(SRV, 0))).is_pass(),
        "only nvme0n1 is a boot disk"
    );
}

// ------------------------------------------------------------------------
// Tables that do not answer
// ------------------------------------------------------------------------

#[test]
fn an_mbr_passes() {
    let mut mbr = [0u8; 512];
    mbr[446 + 4] = 0x83;
    mbr[446 + 8..446 + 12].copy_from_slice(&u32::try_from(P5_START).unwrap().to_le_bytes());
    mbr[446 + 12..446 + 16].copy_from_slice(&2_097_152u32.to_le_bytes());
    mbr[510] = 0x55;
    mbr[511] = 0xAA;
    let host = Host::new("254:9", "ext4", "/dev/mapper/data")
        .partition_at("nvme0n1p1", "259:5", "nvme0n1", 1, P5_START)
        .luks("dm-9", "254:9", "data", &["nvme0n1p1"]);
    assert_eq!(
        check(&host.fs, &devices("nvme0n1", &mbr)),
        CheckResult::Pass(format!(
            "The hidden root at {ROOT} is stored on a disk the decoy boots from. Partition 1 of \
             nvme0n1 (nvme0n1p1) is in an MBR partition table, from which systemd discovers no \
             partition."
        ))
    );
}

#[test]
fn a_table_that_does_not_list_the_partition_where_the_kernel_has_it_warns() {
    let unlisted = format!(
        "The hidden root at {ROOT} is stored on a disk the decoy boots from. Partition 5 of \
         nvme0n1 (nvme0n1p5) is not where the kernel has it in the partition table on nvme0n1: \
         the table changed since the kernel read it, so the partition's type cannot be checked."
    );
    // Another start.
    let mut entries = vec![[0u8; 128]; 4];
    entries.push(typed_gpt_entry(SRV, P5_START + 8, P5_END, 0, "data"));
    let result = check(
        &on_the_decoys_disk().fs,
        &devices("nvme0n1", &gpt_disk(BLOCKS, &entries)),
    );
    assert_eq!(warning(&result), unlisted);
    assert_eq!(
        fix(&result),
        "Check the partition table from a live system or where setup happens, as root. See \
         docs/backends.md."
    );
    // No fifth entry.
    let result = check(
        &on_the_decoys_disk().fs,
        &devices("nvme0n1", &gpt_disk(BLOCKS, &entries[..4])),
    );
    assert_eq!(warning(&result), unlisted);
    // The kernel's start, listed under another number.
    let mut entries = vec![[0u8; 128]; 2];
    entries.push(typed_gpt_entry(SRV, P5_START, P5_END, 0, "data"));
    let result = check(
        &on_the_decoys_disk().fs,
        &devices("nvme0n1", &gpt_disk(BLOCKS, &entries)),
    );
    assert_eq!(warning(&result), unlisted);
    // No table at all.
    let result = check(&on_the_decoys_disk().fs, &devices("nvme0n1", &[]));
    assert_eq!(warning(&result), unlisted);
}

#[test]
fn a_damaged_table_warns_unless_it_names_a_type_systemd_uses() {
    let damaged = |type_id: &str| {
        let mut image = gpt(type_id, 0);
        // A byte of an entry's name written over: the entries no longer
        // match the checksum the header keeps of them.
        image[1024 + 4 * 128 + 60] ^= 0xFF;
        check(&on_the_decoys_disk().fs, &devices("nvme0n1", &image))
    };
    let result = damaged(LINUX_FILESYSTEM);
    assert!(
        warning(&result).ends_with(
            "The partition table on nvme0n1 does not match the checksum it keeps of its \
             entries, so the type read for partition 5 of nvme0n1 (nvme0n1p5) cannot be trusted."
        ),
        "{result:?}"
    );
    assert!(damaged(SRV).is_fail());

    // A header whose own checksum fails vouches for nothing it says.
    let mut image = gpt(LINUX_FILESYSTEM, 0);
    image[512 + 20] ^= 0xFF;
    let result = check(&on_the_decoys_disk().fs, &devices("nvme0n1", &image));
    assert!(
        warning(&result).ends_with(
            "The partition table on nvme0n1 does not match the checksum its header keeps of \
             itself, so the type read for partition 5 of nvme0n1 (nvme0n1p5) cannot be trusted."
        ),
        "{result:?}"
    );

    // An entry past the blocks the partitions may use, checksums intact.
    let mut entries = vec![[0u8; 128]; 4];
    entries.push(typed_gpt_entry(
        LINUX_FILESYSTEM,
        P5_START,
        P5_END,
        0,
        "data",
    ));
    entries.push(typed_gpt_entry(
        LINUX_FILESYSTEM,
        P5_END + 1,
        BLOCKS,
        0,
        "past",
    ));
    let result = check(
        &on_the_decoys_disk().fs,
        &devices("nvme0n1", &gpt_disk(BLOCKS, &entries)),
    );
    assert!(
        warning(&result).ends_with(
            "The partition table on nvme0n1 lists an entry that does not fit within the blocks \
             its partitions may use, so the type read for partition 5 of nvme0n1 (nvme0n1p5) \
             cannot be trusted."
        ),
        "{result:?}"
    );
}

#[test]
fn a_table_whose_entries_could_not_all_be_checked_warns() {
    let place = Place {
        partition: "nvme0n1p5".into(),
        number: 5,
        disk: "nvme0n1".into(),
        node: "/dev/nvme0n1".into(),
    };
    let entry = Entry::Gpt {
        type_id: LINUX_FILESYSTEM.into(),
        flags: Some(0),
        damage: Some(Damage::Unchecked),
    };
    assert_eq!(
        Finding::of(place, entry),
        Finding::Warn(
            "Not every entry of the partition table on nvme0n1 could be checked against the \
             checksum the table keeps of them, so the type read for partition 5 of nvme0n1 \
             (nvme0n1p5) cannot be trusted."
                .into(),
            None
        )
    );
}

#[test]
fn without_the_disk_the_type_comes_from_udevs_record_of_the_partition() {
    let record = |number: u32, offset: u64, flags: &str| {
        format!(
            "E:ID_PART_TABLE_TYPE=gpt\n\
             E:ID_PART_ENTRY_SCHEME=gpt\n\
             E:ID_PART_ENTRY_TYPE=3b8f8425-20e0-4f3b-907f-1a25a76f98e8\n\
             {flags}\
             E:ID_PART_ENTRY_NUMBER={number}\n\
             E:ID_PART_ENTRY_OFFSET={offset}\n"
        )
    };
    // No disk image: the device node cannot be opened.
    let no_disk = tempfile::tempdir().unwrap();
    let host = on_the_decoys_disk().file("/run/udev/data/b259:5", &record(5, P5_START, ""));
    assert!(check(&host.fs, &no_disk).is_fail());
    let host = on_the_decoys_disk().file(
        "/run/udev/data/b259:5",
        &record(5, P5_START, "E:ID_PART_ENTRY_FLAGS=0x8000000000000000\n"),
    );
    assert!(check(&host.fs, &no_disk).is_warn());
    // Flags udev wrote as no number count as none.
    let host = on_the_decoys_disk().file(
        "/run/udev/data/b259:5",
        &record(5, P5_START, "E:ID_PART_ENTRY_FLAGS=0xno\n"),
    );
    assert!(check(&host.fs, &no_disk).is_fail());
    // An MBR, as udev saw it.
    let host = on_the_decoys_disk().file(
        "/run/udev/data/b259:5",
        "E:ID_PART_ENTRY_SCHEME=dos\nE:ID_PART_ENTRY_TYPE=0x83\nE:ID_PART_ENTRY_NUMBER=5\nE:ID_PART_ENTRY_OFFSET=2099200\n",
    );
    assert!(check(&host.fs, &no_disk).is_pass());
}

#[test]
fn without_the_disk_or_a_record_that_matches_the_kernel_the_type_is_not_checked() {
    let no_disk = tempfile::tempdir().unwrap();
    let node = no_disk.path().join("nvme0n1");
    for record in [
        None,
        // Another partition's number, another start, a table udev did not
        // know.
        Some(format!(
            "E:ID_PART_ENTRY_SCHEME=gpt\nE:ID_PART_ENTRY_TYPE={SRV}\nE:ID_PART_ENTRY_NUMBER=4\nE:ID_PART_ENTRY_OFFSET={P5_START}\n"
        )),
        Some(format!(
            "E:ID_PART_ENTRY_SCHEME=gpt\nE:ID_PART_ENTRY_TYPE={SRV}\nE:ID_PART_ENTRY_NUMBER=5\nE:ID_PART_ENTRY_OFFSET=2048\n"
        )),
        Some(format!(
            "E:ID_PART_ENTRY_SCHEME=mac\nE:ID_PART_ENTRY_TYPE={SRV}\nE:ID_PART_ENTRY_NUMBER=5\nE:ID_PART_ENTRY_OFFSET={P5_START}\n"
        )),
    ] {
        let host = match &record {
            Some(text) => on_the_decoys_disk().file("/run/udev/data/b259:5", text),
            None => on_the_decoys_disk(),
        };
        let result = check(&host.fs, &no_disk);
        let text = warning(&result);
        assert!(
            text.starts_with(&format!(
                "The hidden root at {ROOT} is stored on a disk the decoy boots from. The type of \
                 partition 5 of nvme0n1 (nvme0n1p5) cannot be checked: {}: ",
                node.display()
            )),
            "{record:?}: {result:?}"
        );
        assert!(
            text.ends_with(", and udev keeps no record of the partition's entry that matches it."),
            "{record:?}: {result:?}"
        );
    }
}

// ------------------------------------------------------------------------
// What the check cannot follow
// ------------------------------------------------------------------------

#[test]
fn a_root_in_ram_or_not_mounted_passes() {
    let dev = tempfile::tempdir().unwrap();
    let host = Host::new("0:45", "tmpfs", "tmpfs");
    assert_eq!(
        check(&host.fs, &dev),
        CheckResult::Pass(format!(
            "The hidden root at {ROOT} is a tmpfs, on no partition."
        ))
    );
    let host = Host::with_mounts("");
    assert_eq!(
        check(&host.fs, &dev),
        CheckResult::Pass(format!(
            "Partition type check skipped: nothing is mounted at {ROOT}"
        ))
    );
}

#[test]
fn what_the_check_cannot_follow_warns() {
    let dev = tempfile::tempdir().unwrap();
    // A filesystem that shows no block device.
    let host = Host::new("0:60", "nfs4", "server:/export");
    assert_eq!(
        warning(&check(&host.fs, &dev)),
        format!(
            "Could not check the partition type of the hidden root at {ROOT}: its nfs4 \
             filesystem shows no block device to follow."
        )
    );
    // A decoy root whose devices cannot be found.
    let host = on_the_decoys_disk();
    host.fs.mock_set_mount_table(&format!(
        "1 0 0:30 / / rw,relatime - overlay overlay rw\n\
         40 1 254:9 / {ROOT} rw,relatime - ext4 /dev/mapper/data rw\n"
    ));
    let result = check(&host.fs, &dev);
    assert_eq!(
        warning(&result),
        format!(
            "Could not check the partition type of the hidden root at {ROOT}: the disk the \
             decoy's root file system is on cannot be found."
        )
    );
    assert_eq!(
        fix(&result),
        "Make sure the hidden root is on no partition of the decoy's disk that has a type \
         systemd mounts or uses at boot. See docs/backends.md."
    );
    // A mount table that cannot be read.
    let host = on_the_decoys_disk();
    host.fs.mock_set_mount_table_error("no procfs");
    assert!(warning(&check(&host.fs, &dev)).ends_with("the mount table cannot be read."));
}

#[test]
fn a_device_whose_devices_below_cannot_be_listed_warns() {
    let host = on_the_decoys_disk();
    host.fs
        .mock_set_unreadable_dir(&format!("{}/slaves", host.dir("dm-9")));
    let result = check(&host.fs, &devices("nvme0n1", &gpt(SRV, 0)));
    assert_eq!(
        warning(&result),
        format!(
            "Could not check the partition type of the hidden root at {ROOT}: its storage holds \
             more devices than the check reads."
        )
    );
}

#[test]
fn several_partitions_are_judged_together() {
    // An md mirror of partitions 5 and 6 of the decoy's disk.
    let host = Host::new("9:0", "ext4", "/dev/md0")
        .partition_at("nvme0n1p5", "259:5", "nvme0n1", 5, P5_START)
        .partition_at("nvme0n1p6", "259:6", "nvme0n1", 6, P5_END + 1)
        .device(
            "/sys/devices/virtual/block/md0",
            "md0",
            "9:0",
            &["nvme0n1p5", "nvme0n1p6"],
        );
    let mut entries = vec![[0u8; 128]; 4];
    entries.push(typed_gpt_entry(SRV, P5_START, P5_END, 0, "a"));
    entries.push(typed_gpt_entry(
        SWAP,
        P5_END + 1,
        P5_END + 2_097_152,
        0,
        "b",
    ));
    let result = check(&host.fs, &devices("nvme0n1", &gpt_disk(BLOCKS, &entries)));
    assert!(result.is_fail(), "{result:?}");
    assert!(
        result
            .message()
            .contains("(nvme0n1p5) has the GPT type of a /srv partition")
            && result
                .message()
                .contains("(nvme0n1p6) has the GPT type of a swap partition"),
        "{result:?}"
    );
    // One command for the disk, retyping both.
    assert!(
        result.remediation().unwrap_or_default().contains(&format!(
            "sgdisk --typecode=5:{LINUX_FILESYSTEM} --typecode=6:{LINUX_FILESYSTEM} /dev/nvme0n1"
        )),
        "{result:?}"
    );

    // A generic partition beside a no-auto one: the warning alone.
    let mut entries = vec![[0u8; 128]; 4];
    entries.push(typed_gpt_entry(LINUX_FILESYSTEM, P5_START, P5_END, 0, "a"));
    entries.push(typed_gpt_entry(
        HOME,
        P5_END + 1,
        P5_END + 2_097_152,
        NO_AUTO,
        "b",
    ));
    let result = check(&host.fs, &devices("nvme0n1", &gpt_disk(BLOCKS, &entries)));
    assert!(warning(&result).contains("(nvme0n1p6) has the GPT type of a /home partition"));
    assert!(!warning(&result).contains("nvme0n1p5"), "{result:?}");
    assert!(
        fix(&result).contains(&format!(
            "sgdisk --typecode=6:{LINUX_FILESYSTEM} /dev/nvme0n1"
        )),
        "{result:?}"
    );

    // Two generic partitions: both named.
    let mut entries = vec![[0u8; 128]; 4];
    entries.push(typed_gpt_entry(LINUX_FILESYSTEM, P5_START, P5_END, 0, "a"));
    entries.push(typed_gpt_entry(
        LINUX_FILESYSTEM,
        P5_END + 1,
        P5_END + 2_097_152,
        0,
        "b",
    ));
    let result = check(&host.fs, &devices("nvme0n1", &gpt_disk(BLOCKS, &entries)));
    assert!(result.is_pass(), "{result:?}");
    assert!(
        result.message().contains("(nvme0n1p5) has a GPT type")
            && result.message().contains("(nvme0n1p6) has a GPT type"),
        "{result:?}"
    );
}

#[test]
fn the_check_names_itself_and_needs_the_hidden_volume() {
    let check = BackendPartitionTypeCheck::default();
    assert_eq!(
        <BackendPartitionTypeCheck as PreFlightCheck<MockFilesystem>>::name(&check),
        "backend-partition-type"
    );
    assert_eq!(
        <BackendPartitionTypeCheck as PreFlightCheck<MockFilesystem>>::description(&check),
        "Refuses a hidden root on a partition whose type the decoy's systemd mounts or uses at \
         boot"
    );
    assert!(<BackendPartitionTypeCheck as PreFlightCheck<
        MockFilesystem,
    >>::requires_hidden_volume(&check));
    assert_eq!(check.dev_dir, PathBuf::from("/dev"));
    assert_eq!(
        check.hidden_volume_root,
        PathBuf::from(get_default_hidden_volume_root())
    );
}
