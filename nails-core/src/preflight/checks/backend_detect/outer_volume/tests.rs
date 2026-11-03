// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The outer-volume check on the mock hosts of
//! [`tests_host`](super::super::tests_host). The hidden volume is a
//! VeraCrypt hidden volume on `sdb2`, opened by cryptsetup as the mapping
//! `dm-9` named `data`, unless a test says otherwise.

use super::super::tests_host::{Host, ROOT};
use super::*;
use crate::filesystem::MockFilesystem;

fn run(host: &Host) -> CheckResult {
    OuterVolumeCheck::new(PathBuf::from(ROOT))
        .run(&host.fs)
        .unwrap()
}

/// The external disk `sdb` and its partition `sdb2`.
fn drive(host: Host) -> Host {
    host.disk("sdb", "8:16")
        .partition_at("sdb2", "8:18", "sdb", 2, 2048)
}

/// The hidden root on the TCRYPT mapping `dm-9` of `sdb2`, with the mount
/// lines `mounts` beside it.
fn hidden(mounts: &str) -> Host {
    drive(Host::with_mounts(&format!(
        "40 1 254:9 / {ROOT} rw,relatime - ext4 /dev/mapper/data rw\n{mounts}"
    )))
    .mapping("dm-9", "254:9", "data", "CRYPT-TCRYPT-data", &["sdb2"])
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

const CRYPTSETUP: &str = "cryptsetup offers no hidden-volume protection, so a write to it can \
     overwrite the hidden root.";

// ------------------------------------------------------------------------
// An outer volume open beside the hidden one
// ------------------------------------------------------------------------

#[test]
fn an_outer_volume_open_read_write_warns() {
    let host = hidden("").mapping("dm-4", "254:4", "outer", "CRYPT-TCRYPT-outer", &["sdb2"]);
    let result = run(&host);
    assert_eq!(
        warning(&result),
        format!(
            "Another VeraCrypt or TrueCrypt mapping is open read-write on the storage the hidden \
             root's volume at {ROOT} is opened from: outer (dm-4), on sdb2, not mounted. \
             {CRYPTSETUP}"
        )
    );
    assert_eq!(
        fix(&result),
        "Unmount it and close it before activating (cryptsetup close <name>, or veracrypt \
         --dismount for a volume the VeraCrypt application mounted), or open it read-only with \
         cryptsetup open --readonly when it has to be shown. See docs/backends.md."
    );
}

#[test]
fn an_outer_volume_open_read_only_passes() {
    let host = hidden("")
        .mapping("dm-4", "254:4", "outer", "CRYPT-TCRYPT-outer", &["sdb2"])
        .read_only("dm-4");
    assert_eq!(
        run(&host),
        CheckResult::Pass(format!(
            "Other VeraCrypt or TrueCrypt mappings are open on the storage the hidden root's \
             volume at {ROOT} is opened from, all of them read-only, so no write through them \
             reaches it: outer (dm-4), on sdb2."
        ))
    );
}

#[test]
fn the_warning_names_where_the_outer_volume_is_mounted() {
    let host = hidden("50 1 254:4 / /media/outer rw,relatime - exfat /dev/mapper/outer rw\n")
        .mapping("dm-4", "254:4", "outer", "CRYPT-TCRYPT-outer", &["sdb2"]);
    assert!(
        warning(&run(&host))
            .contains(": outer (dm-4), on sdb2, mounted read-write at /media/outer. "),
        "{:?}",
        run(&host)
    );
    // A read-only mount of a mapping the kernel lets be written warns too.
    let host = hidden("50 1 254:4 / /media/outer ro,relatime - exfat /dev/mapper/outer ro\n")
        .mapping("dm-4", "254:4", "outer", "CRYPT-TCRYPT-outer", &["sdb2"]);
    assert!(
        warning(&run(&host))
            .contains(": outer (dm-4), on sdb2, mounted read-only at /media/outer. "),
        "{:?}",
        run(&host)
    );
}

#[test]
fn every_mount_of_the_outer_volume_is_named() {
    let host = hidden(
        "50 1 254:4 / /media/outer rw,relatime - exfat /dev/mapper/outer rw\n\
         51 1 254:4 / /srv/share ro,relatime - exfat /dev/mapper/outer ro\n",
    )
    .mapping("dm-4", "254:4", "outer", "CRYPT-TCRYPT-outer", &["sdb2"]);
    assert!(
        warning(&run(&host)).contains(
            ": outer (dm-4), on sdb2, mounted read-write at /media/outer and read-only at \
             /srv/share. "
        ),
        "{:?}",
        run(&host)
    );
}

#[test]
fn a_cascade_is_followed_up_to_its_topmost_mapping() {
    // cryptsetup opens a cascade as a TCRYPT mapping over a SUBDEV mapping
    // per further cipher; the outer's lowest layer is the one on sdb2.
    let host = hidden("50 1 254:5 / /media/outer rw,relatime - exfat /dev/mapper/outer rw\n")
        .mapping(
            "dm-4",
            "254:4",
            "outer_1",
            "CRYPT-SUBDEV-outer_1",
            &["sdb2"],
        )
        .mapping("dm-5", "254:5", "outer", "CRYPT-TCRYPT-outer", &["dm-4"]);
    assert!(
        warning(&run(&host))
            .contains(": outer (dm-5), on sdb2, mounted read-write at /media/outer. "),
        "{:?}",
        run(&host)
    );
    // The hidden volume's own cascade is no other mapping.
    let host = drive(Host::new("254:9", "ext4", "/dev/mapper/data"))
        .mapping("dm-8", "254:8", "data_1", "CRYPT-SUBDEV-data_1", &["sdb2"])
        .mapping("dm-9", "254:9", "data", "CRYPT-TCRYPT-data", &["dm-8"]);
    assert_eq!(
        run(&host),
        CheckResult::Pass(format!(
            "No other VeraCrypt or TrueCrypt mapping is open on the storage the hidden root's \
             volume at {ROOT} is opened from (sdb2)."
        ))
    );
}

#[test]
fn a_mapping_the_veracrypt_application_made_warns_even_mounted_read_only() {
    let host =
        hidden("50 1 254:4 / /media/veracrypt1 ro,relatime - exfat /dev/mapper/veracrypt1 ro\n")
            .mapping("dm-4", "254:4", "veracrypt1", "", &["sdb2"]);
    assert_eq!(
        warning(&run(&host)),
        format!(
            "Another VeraCrypt or TrueCrypt mapping is open read-write on the storage the hidden \
             root's volume at {ROOT} is opened from: veracrypt1 (dm-4), on sdb2, mounted \
             read-only at /media/veracrypt1. A mapping the VeraCrypt application makes in the \
             kernel has no hidden-volume protection, and the application leaves it writable even \
             for a volume it mounts read-only, so a write to it can overwrite the hidden root."
        )
    );
}

#[test]
fn an_outer_volume_opened_from_another_loop_device_warns() {
    // The hidden volume on the partition, the outer one on a loop device
    // over it.
    let host = hidden("").loop_device("loop1", "7:1", "/dev/sdb2").mapping(
        "dm-4",
        "254:4",
        "outer",
        "CRYPT-TCRYPT-outer",
        &["loop1"],
    );
    assert!(warning(&run(&host)).contains(": outer (dm-4), on loop1, not mounted."));

    // The hidden volume on a loop device over the partition, the outer one
    // on the partition itself.
    let host = drive(Host::new("254:9", "ext4", "/dev/mapper/data"))
        .loop_device("loop0", "7:0", "/dev/sdb2")
        .mapping("dm-9", "254:9", "data", "CRYPT-TCRYPT-data", &["loop0"])
        .mapping("dm-4", "254:4", "outer", "CRYPT-TCRYPT-outer", &["sdb2"]);
    assert!(
        warning(&run(&host)).contains(": outer (dm-4), on sdb2, not mounted."),
        "{:?}",
        run(&host)
    );
}

#[test]
fn two_loop_devices_on_one_container_file_warn() {
    let container = "/home/alice/archive.hc";
    let host = Host::new("254:9", "ext4", "/dev/mapper/data")
        .loop_device("loop0", "7:0", container)
        .loop_device("loop1", "7:1", container)
        .mapping("dm-9", "254:9", "data", "CRYPT-TCRYPT-data", &["loop0"])
        .mapping("dm-4", "254:4", "outer", "CRYPT-TCRYPT-outer", &["loop1"]);
    assert!(
        warning(&run(&host)).contains(": outer (dm-4), on loop1, not mounted."),
        "{:?}",
        run(&host)
    );
    // A loop device over the same file from another offset reads other data.
    let host = Host::new("254:9", "ext4", "/dev/mapper/data")
        .loop_device("loop0", "7:0", container)
        .loop_at("loop1", "7:1", container, 1 << 20)
        .mapping("dm-9", "254:9", "data", "CRYPT-TCRYPT-data", &["loop0"])
        .mapping("dm-4", "254:4", "outer", "CRYPT-TCRYPT-outer", &["loop1"]);
    assert!(run(&host).is_pass(), "{:?}", run(&host));
}

// ------------------------------------------------------------------------
// Nothing to warn about
// ------------------------------------------------------------------------

#[test]
fn a_root_in_no_veracrypt_or_truecrypt_volume_passes() {
    let host = drive(Host::new("254:9", "ext4", "/dev/mapper/data"))
        .luks("dm-9", "254:9", "data", &["sdb2"])
        // Another LUKS mapping of the same partition is no outer volume.
        .luks("dm-4", "254:4", "other", &["sdb2"]);
    assert_eq!(
        run(&host),
        CheckResult::Pass(format!(
            "The hidden root at {ROOT} is in no VeraCrypt or TrueCrypt volume, so no outer \
             volume of it can be open."
        ))
    );
}

#[test]
fn the_integrity_layer_of_a_luks2_volume_is_no_veracrypt_or_truecrypt_mapping() {
    // cryptsetup 2.8 and later name the integrity layer of a LUKS2 volume
    // with authenticated encryption SUBDEV, with the volume's uuid.
    let hex = super::super::luks2::TEST_UUID.replace('-', "");
    let host = drive(Host::new("254:9", "ext4", "/dev/mapper/data"))
        .mapping(
            "dm-8",
            "254:8",
            "data_dif",
            &format!("CRYPT-SUBDEV-{hex}-data_dif"),
            &["sdb2"],
        )
        .mapping(
            "dm-9",
            "254:9",
            "data",
            &format!("CRYPT-LUKS2-{hex}-data"),
            &["dm-8"],
        );
    assert_eq!(
        run(&host),
        CheckResult::Pass(format!(
            "The hidden root at {ROOT} is in no VeraCrypt or TrueCrypt volume, so no outer \
             volume of it can be open."
        ))
    );
    // Beside a hidden VeraCrypt volume, such a layer is no other mapping of
    // it.
    let host = hidden("").mapping(
        "dm-4",
        "254:4",
        "other_dif",
        &format!("CRYPT-SUBDEV-{hex}-other_dif"),
        &["sdb2"],
    );
    assert_eq!(
        run(&host),
        CheckResult::Pass(format!(
            "No other VeraCrypt or TrueCrypt mapping is open on the storage the hidden root's \
             volume at {ROOT} is opened from (sdb2)."
        ))
    );
}

#[test]
fn the_devices_of_an_online_reencryption_are_no_veracrypt_or_truecrypt_mappings() {
    // While cryptsetup reencrypt runs on an open LUKS2 volume, the volume's
    // mapping maps to an overlay on the partition and on a hotzone, a
    // linear map of the partition: both SUBDEV, with the volume's uuid.
    let hex = super::super::luks2::TEST_UUID.replace('-', "");
    let host = drive(Host::new("254:4", "ext4", "/dev/mapper/data"))
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
        );
    assert_eq!(
        run(&host),
        CheckResult::Pass(format!(
            "The hidden root at {ROOT} is in no VeraCrypt or TrueCrypt volume, so no outer \
             volume of it can be open."
        ))
    );
}

#[test]
fn a_mapping_that_is_no_veracrypt_or_truecrypt_one_is_left_alone() {
    // A linear mapping over the partition, such as one that fences the
    // hidden volume off while the outer one is filled.
    let host = hidden("").mapping("dm-4", "254:4", "fence", "", &["sdb2"]);
    assert!(run(&host).is_pass(), "{:?}", run(&host));
}

#[test]
fn a_root_in_ram_or_not_mounted_passes() {
    assert_eq!(
        run(&Host::new("0:45", "tmpfs", "tmpfs")),
        CheckResult::Pass(format!(
            "The hidden root at {ROOT} is a tmpfs, in no VeraCrypt or TrueCrypt volume."
        ))
    );
    assert_eq!(
        run(&Host::with_mounts("")),
        CheckResult::Pass(format!(
            "Outer volume check skipped: nothing is mounted at {ROOT}"
        ))
    );
}

#[test]
fn what_the_check_cannot_follow_warns() {
    let result = run(&Host::new("0:60", "nfs4", "server:/export"));
    assert_eq!(
        warning(&result),
        format!(
            "Could not check for an outer volume open beside the hidden root at {ROOT}: its nfs4 \
             filesystem shows no block device to follow."
        )
    );
    assert_eq!(
        fix(&result),
        "Make sure no outer volume of the hidden volume is open read-write while it is in use. \
         See docs/backends.md."
    );
    let host = hidden("");
    host.fs.mock_set_mount_table_error("no procfs");
    assert!(warning(&run(&host)).ends_with("the mount table cannot be read."));
}

#[test]
fn devices_sysfs_does_not_let_the_check_list_warn() {
    let cannot = |why: &str| {
        format!("Could not check for an outer volume open beside the hidden root at {ROOT}: {why}.")
    };
    // The devices built on the partition, a writable outer volume among
    // them.
    let host = hidden("").mapping("dm-4", "254:4", "outer", "CRYPT-TCRYPT-outer", &["sdb2"]);
    host.fs
        .mock_set_unreadable_dir(&format!("{}/holders", host.dir("sdb2")));
    assert_eq!(
        warning(&run(&host)),
        cannot("the devices built on its storage cannot all be listed")
    );
    // The devices below the hidden volume's mapping.
    let host = hidden("");
    host.fs
        .mock_set_unreadable_dir(&format!("{}/slaves", host.dir("dm-9")));
    assert_eq!(
        warning(&run(&host)),
        cannot("the devices below it cannot all be listed")
    );
    // The block devices, among them the loop devices over the partition.
    let host = hidden("");
    host.fs.mock_set_unreadable_dir("/sys/class/block");
    assert_eq!(
        warning(&run(&host)),
        cannot("the block devices cannot be listed")
    );
}

#[test]
fn the_check_names_itself_and_needs_the_hidden_volume() {
    let check = OuterVolumeCheck::default();
    assert_eq!(
        <OuterVolumeCheck as PreFlightCheck<MockFilesystem>>::name(&check),
        "outer-volume"
    );
    assert_eq!(
        <OuterVolumeCheck as PreFlightCheck<MockFilesystem>>::description(&check),
        "Warns when another VeraCrypt or TrueCrypt mapping of the hidden volume's device is open \
         read-write"
    );
    assert!(<OuterVolumeCheck as PreFlightCheck<MockFilesystem>>::requires_hidden_volume(&check));
    assert_eq!(
        check.hidden_volume_root,
        PathBuf::from(get_default_hidden_volume_root())
    );
}
