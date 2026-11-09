// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The hidden-volume check on mock mounts: the attach gate's answers, the
//! write probe and the audit of the names a volume shows.

use super::*;
use crate::config::DEFAULT_HIDDEN_VOLUME_ROOT;
use crate::filesystem::{MockFilesystem, MountSource};
use std::path::Path;

/// A neutral root, used wherever a check must pass without a naming warning.
const NEUTRAL_ROOT: &str = "/mnt/data";

/// Mark `root` as existing, mounted and writable.
fn mount_ok(fs: &MockFilesystem, root: &str) {
    fs.mock_set_path_exists(root, true);
    fs.mock_set_mounted(Path::new(root), true);
    fs.mock_set_writable(root, true);
}

#[test]
fn test_hidden_volume_check_default_path() {
    let check = HiddenVolumeCheck::default();
    assert_eq!(
        check.hidden_volume_root,
        PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT)
    );
}

#[test]
fn default_root_is_neutral() {
    // The built-in fallback must not itself read as hidden storage.
    assert!(
        suspicious_token(DEFAULT_HIDDEN_VOLUME_ROOT).is_none(),
        "the default hidden root '{DEFAULT_HIDDEN_VOLUME_ROOT}' hints at hidden storage"
    );
}

#[test]
fn test_hidden_volume_check_custom_path() {
    let custom_path = PathBuf::from("/custom/path");
    let check = HiddenVolumeCheck::new(custom_path.clone());
    assert_eq!(check.hidden_volume_root, custom_path);
}

#[test]
fn test_hidden_volume_check_trait_metadata() {
    let check = HiddenVolumeCheck::default();

    assert_eq!(
        <HiddenVolumeCheck as PreFlightCheck<MockFilesystem>>::name(&check),
        "hidden-volume"
    );
    assert_eq!(
        <HiddenVolumeCheck as PreFlightCheck<MockFilesystem>>::description(&check),
        "Validates hidden volume is mounted and writable"
    );
}

#[test]
fn test_hidden_volume_check_pass_when_mounted_and_writable() {
    let fs = MockFilesystem::new();
    let check = HiddenVolumeCheck::new(PathBuf::from(NEUTRAL_ROOT));

    mount_ok(&fs, NEUTRAL_ROOT);

    let result = check.run(&fs).unwrap();
    assert!(result.is_pass(), "got {result:?}");
    assert_eq!(result.message(), "Hidden volume mounted at /mnt/data");
}

#[test]
fn test_hidden_volume_check_fail_when_path_does_not_exist() {
    let fs = MockFilesystem::new();
    let check = HiddenVolumeCheck::new(PathBuf::from(NEUTRAL_ROOT));

    // Volume path does not exist
    fs.mock_set_path_exists(NEUTRAL_ROOT, false);

    let result = check.run(&fs).unwrap();
    assert!(result.is_fail());
    assert_eq!(result.message(), "/mnt/data does not exist");
    assert_eq!(result.allowable(), None, "no flag makes a missing root");
    assert!(
        result
            .remediation()
            .unwrap()
            .starts_with("If the volume is already prepared, unlock and mount it at /mnt/data")
    );
}

#[test]
fn test_hidden_volume_check_fail_when_not_mounted() {
    let fs = MockFilesystem::new();
    let check = HiddenVolumeCheck::new(PathBuf::from(NEUTRAL_ROOT));

    // Volume exists but is NOT mounted
    fs.mock_set_path_exists(NEUTRAL_ROOT, true);
    fs.mock_set_mounted(Path::new(NEUTRAL_ROOT), false);

    let result = check.run(&fs).unwrap();
    assert!(result.is_fail());
    assert!(
        result.message().starts_with(
            "/mnt/data is not a volume of its own: it is a folder on the filesystem \
             mounted at /"
        ),
        "{}",
        result.message()
    );
    // The remediation is the gate's redirect, which names no backend.
    // Matched case-insensitively so any spelling of a backend name trips it.
    let remediation = result.remediation().unwrap().to_lowercase();
    assert!(remediation.contains("where setup happens"), "{remediation}");
    for backend in ["luks", "veracrypt", "tcrypt", "cryptsetup"] {
        assert!(!remediation.contains(backend), "names {backend}");
    }
    // The override never covers a folder.
    assert_eq!(result.allowable(), None);
    assert!(fs.mock_ops().is_empty(), "{:?}", fs.mock_ops());
}

#[test]
fn test_hidden_volume_check_fail_when_not_writable() {
    let fs = MockFilesystem::new();
    let check = HiddenVolumeCheck::new(PathBuf::from(NEUTRAL_ROOT));

    // Volume exists and is mounted but NOT writable
    fs.mock_set_path_exists(NEUTRAL_ROOT, true);
    fs.mock_set_mounted(Path::new(NEUTRAL_ROOT), true);
    fs.mock_set_writable(NEUTRAL_ROOT, false);

    let result = check.run(&fs).unwrap();
    assert!(result.is_fail());
    assert!(result.message().contains("is not writable"));
    assert!(result.message().contains("Check permissions"));
}

#[test]
fn test_hidden_volume_check_custom_path_works() {
    let fs = MockFilesystem::new();
    let custom_path = PathBuf::from("/custom/volume");
    let check = HiddenVolumeCheck::new(custom_path.clone());

    mount_ok(&fs, "/custom/volume");

    let result = check.run(&fs).unwrap();
    assert!(result.is_pass());
    assert!(result.message().contains("/custom/volume"));
}

#[test]
fn test_hidden_volume_check_clone() {
    let check = HiddenVolumeCheck::default();
    let cloned = check.clone();
    assert_eq!(check.hidden_volume_root, cloned.hidden_volume_root);
}

// ------------------------------------------------------------------------
// Neutral-naming audit (the token list is tested in `nails_base::naming`)
// ------------------------------------------------------------------------

#[test]
fn warns_when_root_path_hints_at_hidden_storage() {
    let fs = MockFilesystem::new();
    let root = "/mnt/hidden-volume";
    let check = HiddenVolumeCheck::new(PathBuf::from(root));
    mount_ok(&fs, root);

    let result = check.run(&fs).unwrap();
    assert!(result.is_warn(), "got {result:?}");
    let msg = result.message();
    assert!(msg.contains("mount path component"), "{msg}");
    assert!(msg.contains("\"hidden\""), "{msg}");
    // The volume is still reported as usable and the message routes the
    // operator to the residue guidance.
    assert!(msg.contains("/mnt/hidden-volume"), "{msg}");
    assert!(msg.contains("pre-activation residue"), "{msg}");
}

#[test]
fn warns_when_dm_name_hints_at_hidden_storage() {
    let fs = MockFilesystem::new();
    let check = HiddenVolumeCheck::new(PathBuf::from(NEUTRAL_ROOT));
    mount_ok(&fs, NEUTRAL_ROOT);
    fs.mock_set_mount_source(
        Path::new(NEUTRAL_ROOT),
        MountSource {
            device: Some("/dev/mapper/veracrypt-hidden".to_string()),
            dm_name: Some("veracrypt-hidden".to_string()),
            label: None,
        },
    );

    let result = check.run(&fs).unwrap();
    assert!(result.is_warn(), "got {result:?}");
    let msg = result.message();
    assert!(msg.contains("device-mapper name"), "{msg}");
    assert!(msg.contains("veracrypt-hidden"), "{msg}");
}

#[test]
fn warns_when_filesystem_label_hints_at_hidden_storage() {
    let fs = MockFilesystem::new();
    let check = HiddenVolumeCheck::new(PathBuf::from(NEUTRAL_ROOT));
    mount_ok(&fs, NEUTRAL_ROOT);
    fs.mock_set_mount_source(
        Path::new(NEUTRAL_ROOT),
        MountSource {
            device: Some("/dev/sdb1".to_string()),
            dm_name: None,
            label: Some("decoy-vault".to_string()),
        },
    );

    let result = check.run(&fs).unwrap();
    assert!(result.is_warn(), "got {result:?}");
    let msg = result.message();
    assert!(
        msg.contains("the filesystem label \"decoy-vault\" contains \"decoy\""),
        "{msg}"
    );
    assert!(msg.contains("and no filesystem label"), "{msg}");
    // The telling word is the warning; the one for any label is not added.
    assert!(!msg.contains("Even a neutral label"), "{msg}");
}

#[test]
fn warns_report_every_offending_name_at_once() {
    let fs = MockFilesystem::new();
    let root = "/mnt/nails-store";
    let check = HiddenVolumeCheck::new(PathBuf::from(root));
    mount_ok(&fs, root);
    fs.mock_set_mount_source(
        Path::new(root),
        MountSource {
            device: Some("/dev/mapper/tcrypt0".to_string()),
            dm_name: Some("tcrypt0".to_string()),
            label: Some("hidden".to_string()),
        },
    );

    let result = check.run(&fs).unwrap();
    assert!(result.is_warn(), "got {result:?}");
    let msg = result.message();
    assert!(msg.contains("mount path component"), "{msg}");
    assert!(msg.contains("device-mapper name"), "{msg}");
    assert!(msg.contains("filesystem label"), "{msg}");
}

#[test]
fn a_root_covered_by_a_mount_on_its_parent_is_no_volume_of_its_own() {
    // The volume is still in the table, but a later mount on /mnt covers
    // it: a lookup of the root ends on that mount instead.
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists(NEUTRAL_ROOT, true);
    fs.mock_set_writable(NEUTRAL_ROOT, true);
    fs.mock_set_mount_table(
        "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
         30 1 253:0 / /mnt/data rw - ext4 /dev/mapper/data rw\n\
         31 1 0:40 / /mnt rw - tmpfs tmpfs rw\n",
    );

    let result = HiddenVolumeCheck::new(PathBuf::from(NEUTRAL_ROOT))
        .run(&fs)
        .unwrap();
    assert!(result.is_fail(), "got {result:?}");
    assert!(result.message().contains("is not a volume of its own"));
}

#[test]
fn two_filesystems_at_the_root_fail_before_any_audit_or_probe() {
    let fs = MockFilesystem::new();
    let check = HiddenVolumeCheck::new(PathBuf::from(NEUTRAL_ROOT)).allowing(Allow::DecoyStorage);
    fs.mock_set_path_exists(NEUTRAL_ROOT, true);
    fs.mock_set_writable(NEUTRAL_ROOT, true);
    let stacked = |below: &str, above: &str| {
        format!(
            "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
             30 1 253:0 / /mnt/data rw - ext4 /dev/mapper/{below} rw\n\
             31 30 253:1 / /mnt/data rw - ext4 /dev/mapper/{above} rw\n"
        )
    };
    // Neither order is accepted, not even with the override.
    for (below, above) in [("data", "veracrypt1"), ("veracrypt1", "data")] {
        fs.mock_set_mount_table(&stacked(below, above));
        let result = check.run(&fs).unwrap();
        assert!(result.is_fail(), "got {result:?}");
        assert!(
            result.message().contains(
                "two filesystems are mounted at /mnt/data: one of type ext4, then one of type \
                 ext4 over it"
            ),
            "{}",
            result.message()
        );
        assert!(
            !result.message().contains("veracrypt"),
            "{}",
            result.message()
        );
        assert_eq!(
            result.remediation(),
            Some("Unmount the one that is not the volume, then run the command again.")
        );
        assert_eq!(result.allowable(), None);
    }
    assert!(fs.mock_ops().is_empty(), "{:?}", fs.mock_ops());
}

/// A root that is a bind of a folder of `/`: decoy storage.
fn bind_of_a_decoy_folder() -> MockFilesystem {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists(NEUTRAL_ROOT, true);
    fs.mock_set_writable(NEUTRAL_ROOT, true);
    fs.mock_set_mount_table(
        "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
         30 1 8:1 /srv/x /mnt/data rw - ext4 /dev/vda1 rw\n",
    );
    fs
}

#[test]
fn decoy_storage_fails_without_a_write_probe() {
    let fs = bind_of_a_decoy_folder();
    let result = HiddenVolumeCheck::new(PathBuf::from(NEUTRAL_ROOT))
        .run(&fs)
        .unwrap();
    assert!(result.is_fail(), "got {result:?}");
    assert_eq!(
        result.message(),
        "/mnt/data is not a volume of its own: it is a bind mount of a folder of /"
    );
    // The one refusal `--allow-decoy-storage` turns into a warning says so.
    assert_eq!(result.allowable(), Some(Allowable::DecoyStorage));
    assert!(fs.mock_ops().is_empty(), "{:?}", fs.mock_ops());
}

#[test]
fn the_override_turns_decoy_storage_into_a_warning() {
    let fs = bind_of_a_decoy_folder();
    let result = HiddenVolumeCheck::new(PathBuf::from(NEUTRAL_ROOT))
        .allowing(Allow::DecoyStorage)
        .run(&fs)
        .unwrap();
    assert!(result.is_warn(), "got {result:?}");
    assert!(
        result.message().starts_with(
            "--allow-decoy-storage: using /mnt/data although it is a bind mount of a folder of /"
        ),
        "{}",
        result.message()
    );
}

#[test]
fn unjudged_storage_fails_even_with_the_override() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists(NEUTRAL_ROOT, true);
    fs.mock_set_writable(NEUTRAL_ROOT, true);
    fs.mock_set_mount_table(
        "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
         30 1 8:17 / /mnt/data rw - ext4 /dev/sdb1 rw\n",
    );
    // A crypttab that exists but cannot be read.
    fs.mock_set_path_exists("/etc/crypttab", true);
    let result = HiddenVolumeCheck::new(PathBuf::from(NEUTRAL_ROOT))
        .allowing(Allow::DecoyStorage)
        .run(&fs)
        .unwrap();
    assert!(result.is_fail(), "got {result:?}");
    assert!(
        result
            .message()
            .contains("could not read /etc/crypttab to tell where /mnt/data lives"),
        "{}",
        result.message()
    );
    assert_eq!(
        result.remediation(),
        Some("Run the command again with sudo.")
    );
    assert_eq!(result.allowable(), None);
}

/// A root on the whole disk `name`, numbered `dev`. The mock lists every
/// number for a plain driver, so only the name its driver gives a disk tells
/// what it is.
fn on_a_disk(name: &str, dev: &str) -> MockFilesystem {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists(NEUTRAL_ROOT, true);
    fs.mock_set_writable(NEUTRAL_ROOT, true);
    fs.mock_set_mount_table(&format!(
        "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
         30 1 {dev} / /mnt/data rw - ext4 /dev/{name} rw\n"
    ));
    fs
}

#[test]
fn a_served_disk_names_the_override_and_a_zfs_volume_does_not() {
    // What the window offers "Allow for This Activation…" for.
    for (name, dev, what) in [
        ("nbd0", "43:0", "a network block device"),
        ("ublkb0", "259:7", "a userspace block device"),
    ] {
        let fs = on_a_disk(name, dev);
        let refused = HiddenVolumeCheck::new(PathBuf::from(NEUTRAL_ROOT))
            .run(&fs)
            .unwrap();
        assert!(refused.is_fail(), "{name}: {refused:?}");
        assert_eq!(
            refused.message(),
            format!(
                "/mnt/data is not a volume of its own: it is stored on {what}, which a program \
                 can serve from a file on this computer's own disk"
            )
        );
        assert_eq!(refused.allowable(), Some(Allowable::DecoyStorage), "{name}");
        let allowed = HiddenVolumeCheck::new(PathBuf::from(NEUTRAL_ROOT))
            .allowing(Allow::DecoyStorage)
            .run(&fs)
            .unwrap();
        assert!(allowed.is_warn(), "{name}: {allowed:?}");
        assert!(
            allowed.message().starts_with(&format!(
                "--allow-decoy-storage: using /mnt/data although it is stored on {what}"
            )),
            "{}",
            allowed.message()
        );
    }

    let fs = on_a_disk("zd0", "230:0");
    for allow in [Allow::Nothing, Allow::DecoyStorage] {
        let result = HiddenVolumeCheck::new(PathBuf::from(NEUTRAL_ROOT))
            .allowing(allow)
            .run(&fs)
            .unwrap();
        assert!(result.is_fail(), "{allow:?}: {result:?}");
        assert_eq!(
            result.message(),
            "/mnt/data is stored on a ZFS volume, which shows no disk it stores its data on, so \
             where it lives cannot be told"
        );
        assert_eq!(result.allowable(), None, "{allow:?}");
    }
    assert!(fs.mock_ops().is_empty(), "{:?}", fs.mock_ops());
}

#[test]
fn a_zfs_volume_the_decoys_fstab_mounts_names_no_override() {
    // The decoy's own filesystem would be a refusal the override lifts; on a
    // ZFS volume nothing lifts it, so the window offers no "Allow".
    let fs = on_a_disk("zd0", "230:0");
    fs.mock_set_file_content(
        "/etc/fstab",
        "/dev/vda1 / ext4 defaults 0 1\n/dev/zd0 /mnt/data ext4 defaults 0 2\n",
    );
    for allow in [Allow::Nothing, Allow::DecoyStorage] {
        let result = HiddenVolumeCheck::new(PathBuf::from(NEUTRAL_ROOT))
            .allowing(allow)
            .run(&fs)
            .unwrap();
        assert!(result.is_fail(), "{allow:?}: {result:?}");
        assert!(
            result.message().contains("is stored on a ZFS volume"),
            "{}",
            result.message()
        );
        assert_eq!(result.allowable(), None, "{allow:?}");
    }
}

/// [`mount_ok`], with the mount source `data` and `label`.
fn mount_with_label(fs: &MockFilesystem, label: Option<&str>) {
    mount_ok(fs, NEUTRAL_ROOT);
    fs.mock_set_mount_source(
        Path::new(NEUTRAL_ROOT),
        MountSource {
            device: Some("/dev/mapper/data".to_string()),
            dm_name: Some("data".to_string()),
            label: label.map(str::to_string),
        },
    );
}

#[test]
fn passes_when_every_name_is_neutral_and_there_is_no_label() {
    let fs = MockFilesystem::new();
    let check = HiddenVolumeCheck::new(PathBuf::from(NEUTRAL_ROOT));
    mount_with_label(&fs, None);

    let result = check.run(&fs).unwrap();
    assert!(result.is_pass(), "got {result:?}");
    assert_eq!(result.message(), "Hidden volume mounted at /mnt/data");
}

#[test]
fn a_neutral_label_warns_too_and_says_how_to_remove_it() {
    let fs = MockFilesystem::new();
    let check = HiddenVolumeCheck::new(PathBuf::from(NEUTRAL_ROOT));
    mount_with_label(&fs, Some("data"));

    let result = check.run(&fs).unwrap();
    assert!(result.is_warn(), "got {result:?}");
    assert_eq!(
        result.message(),
        "The filesystem at /mnt/data carries the label \"data\". Even a neutral label is a \
         hint: it shows in /dev/disk/by-label, in systemd's device units, in file managers \
         and in lsblk, and a common one such as \"data\" is shared by everyone who followed \
         the same example. Remove the label where setup happens, not on this computer (on \
         ext4: e2label <device> '')."
    );
}

#[test]
fn the_decoys_own_label_is_let_be_on_a_decoy_filesystem_the_operator_accepted() {
    let labelled = |fs: &MockFilesystem| {
        fs.mock_set_mount_source(
            Path::new(NEUTRAL_ROOT),
            MountSource {
                label: Some("fedora".to_string()),
                ..MountSource::default()
            },
        );
    };
    let check = HiddenVolumeCheck::new(PathBuf::from(NEUTRAL_ROOT)).allowing(Allow::DecoyStorage);

    // On a disk of its own, the label warns.
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists(NEUTRAL_ROOT, true);
    fs.mock_set_writable(NEUTRAL_ROOT, true);
    fs.mock_set_mount_table(
        "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
         30 1 8:17 / /mnt/data rw - ext4 /dev/sdb1 rw\n",
    );
    labelled(&fs);
    let result = check.run(&fs).unwrap();
    assert!(
        result.message().contains("carries the label \"fedora\""),
        "{result:?}"
    );

    // On the decoy's own filesystem, the label is the decoy's.
    let fs = bind_of_a_decoy_folder();
    labelled(&fs);
    let result = check.run(&fs).unwrap();
    assert!(result.is_warn(), "got {result:?}");
    assert!(
        result
            .message()
            .starts_with("--allow-decoy-storage: using /mnt/data"),
        "{}",
        result.message()
    );
    assert!(
        !result.message().contains("carries the label"),
        "{}",
        result.message()
    );
}

#[test]
fn only_a_root_on_a_decoy_filesystem_carries_the_decoys_label() {
    use crate::hidden_root::separation::{Claimed, Sharing};
    let refusal = |verdict| {
        Refusal::new(
            RefusalKind::DecoyStorage { verdict },
            Path::new(NEUTRAL_ROOT),
        )
    };
    for how in [Sharing::Bind, Sharing::Subvolume, Sharing::Filesystem] {
        for in_fstab in [true, false] {
            let verdict = Verdict::OnDecoyFilesystem {
                how,
                at: PathBuf::from("/home"),
                in_fstab,
            };
            assert!(on_a_decoy_filesystem(&refusal(verdict)), "{how:?}");
        }
    }
    // On the decoy's storage, but a filesystem of its own, with its own label.
    for verdict in [
        Verdict::ContainerOnDecoy {
            file: PathBuf::from("/home/u/box.img"),
            at: PathBuf::from("/home"),
        },
        Verdict::ImageFileOnDecoy {
            file: PathBuf::from("/home/u/box.img"),
            at: PathBuf::from("/home"),
        },
        Verdict::InsideDecoyStorage {
            device: "dm-0".to_string(),
            holds: Claimed::Mount(PathBuf::from("/")),
            noauto_only: true,
        },
        Verdict::ServedDevice {
            kind: crate::hidden_root::separation::Served::Network,
        },
    ] {
        assert!(
            !on_a_decoy_filesystem(&refusal(verdict.clone())),
            "{verdict:?}"
        );
    }
}

// ------------------------------------------------------------------------
// A volume mounted a second time
// ------------------------------------------------------------------------

/// The decoy's `/` and the volume at `/mnt/data`, writable, plus `extra`
/// mount lines.
fn mounted_with(extra: &str) -> MockFilesystem {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists(NEUTRAL_ROOT, true);
    fs.mock_set_writable(NEUTRAL_ROOT, true);
    fs.mock_set_mount_table(&format!(
        "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
         30 1 253:0 / /mnt/data rw - ext4 /dev/mapper/data rw\n{extra}"
    ));
    fs
}

/// The check's result on `fs`, with `allow`.
fn run_allowing(fs: &MockFilesystem, allow: Allow) -> CheckResult {
    HiddenVolumeCheck::new(PathBuf::from(NEUTRAL_ROOT))
        .allowing(allow)
        .run(fs)
        .unwrap()
}

#[test]
fn a_second_mount_of_the_volume_fails_naming_it_before_any_probe() {
    // A desktop mounted the unlocked volume again under /media.
    let fs = mounted_with("40 1 253:0 / /media/u/X rw,nosuid,nodev - ext4 /dev/mapper/data rw\n");
    for allow in [Allow::Nothing, Allow::DecoyStorage] {
        let result = run_allowing(&fs, allow);
        assert!(result.is_fail(), "{allow:?}: {result:?}");
        assert_eq!(
            result.message(),
            "the volume at /mnt/data is also mounted at /media/u/X: a desktop may have mounted \
             it there by itself when it was unlocked"
        );
        assert_eq!(
            result.remediation(),
            Some(
                "Run `sudo umount /media/u/X`, then run the command again.\n\
                 Long before the next use, turn off the automatic mounting of removable media.\n\
                 Read \"Attaching the drive\" in the decoy requirements on another device."
            )
        );
        // No flag lifts it.
        assert_eq!(result.allowable(), None, "{allow:?}");
        let text = format!("{} {}", result.message(), result.remediation().unwrap());
        assert!(!text.contains("/dev/"), "{text}");
    }
    // Refused before the write probe.
    assert!(fs.mock_ops().is_empty(), "{:?}", fs.mock_ops());
}

#[test]
fn a_bind_of_the_volume_at_the_root_alone_passes() {
    let fs = mounted_with("31 30 253:0 / /mnt/data ro - ext4 /dev/mapper/data rw\n");
    let result = run_allowing(&fs, Allow::Nothing);
    assert!(result.is_pass(), "got {result:?}");
}

#[test]
fn another_device_mounted_elsewhere_passes() {
    let fs = mounted_with(
        "40 1 8:16 / /media/u/STICK rw - vfat /dev/sdb1 rw\n\
         41 1 253:1 / /run/media/u/other rw - ext4 /dev/mapper/other rw\n",
    );
    let result = run_allowing(&fs, Allow::Nothing);
    assert!(result.is_pass(), "got {result:?}");
}

#[test]
fn a_btrfs_subvolume_of_the_volume_mounted_elsewhere_fails() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists(NEUTRAL_ROOT, true);
    fs.mock_set_writable(NEUTRAL_ROOT, true);
    fs.mock_set_mount_table(
        "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
         30 1 0:45 /data /mnt/data rw - btrfs /dev/mapper/data rw,subvol=/data\n\
         40 1 0:45 / /run/media/u/X rw - btrfs /dev/mapper/data rw,subvol=/\n",
    );
    let result = run_allowing(&fs, Allow::Nothing);
    assert!(result.is_fail(), "got {result:?}");
    assert!(
        result.message().contains("also mounted at /run/media/u/X:"),
        "{}",
        result.message()
    );
}

#[test]
fn another_subvolume_of_a_volume_of_its_own_counts_though_it_shows_none_of_the_root() {
    // Only for a root accepted on a filesystem the decoy uses is a mount
    // that shows none of the root's folder left out.
    let result = run_on(
        "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
         30 1 0:45 /data /mnt/data rw - btrfs /dev/mapper/data rw,subvol=/data\n\
         40 1 0:45 /other /run/media/u/X rw - btrfs /dev/mapper/data rw,subvol=/other\n",
    );
    assert!(result.is_fail(), "got {result:?}");
    assert_eq!(
        result.message(),
        "the volume at /mnt/data is also mounted at /run/media/u/X: a desktop may have mounted \
         it there by itself when it was unlocked"
    );
}

#[test]
fn every_other_mount_is_named_and_unmounted_deepest_first_and_quoted() {
    let fs = mounted_with(
        "40 1 253:0 / /media/u/My\\040Drive rw - ext4 /dev/mapper/data rw\n\
         41 40 253:0 /a /media/u/My\\040Drive/b rw - ext4 /dev/mapper/data rw\n\
         42 1 253:0 / /srv/x rw - ext4 /dev/mapper/data rw\n",
    );
    let result = run_allowing(&fs, Allow::Nothing);
    assert!(result.is_fail(), "got {result:?}");
    assert!(
        result.message().contains(
            "also mounted at /media/u/My Drive, /media/u/My Drive/b and /srv/x: a desktop"
        ),
        "{}",
        result.message()
    );
    assert!(
        result.remediation().unwrap().starts_with(
            "Run `sudo umount '/media/u/My Drive/b' '/media/u/My Drive' /srv/x`, then run the \
             command again.\n"
        ),
        "{:?}",
        result.remediation()
    );
}

/// The check's result for the root at `/mnt/data` in `table`.
fn run_on(table: &str) -> CheckResult {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists(NEUTRAL_ROOT, true);
    fs.mock_set_writable(NEUTRAL_ROOT, true);
    fs.mock_set_mount_table(table);
    run_allowing(&fs, Allow::Nothing)
}

/// The two lines every fix for a second mount of a volume of its own ends
/// with.
const ADVICE: &str = "Long before the next use, turn off the automatic mounting of removable \
                      media.\n\
                      Read \"Attaching the drive\" in the decoy requirements on another device.";

/// The last line of every fix for a second mount, and the only one after the
/// unmount lines for a root accepted on a decoy filesystem that is mounted
/// nowhere under /media or /run/media.
const READ: &str = "Read \"Attaching the drive\" in the decoy requirements on another device.";

#[test]
fn a_second_mount_that_holds_the_root_is_unmounted_after_the_root() {
    // The volume at /mnt and again at /mnt/data: /mnt cannot be unmounted
    // while the root is mounted below it, and the root is mounted again
    // alone afterwards.
    let result = run_on(
        "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
         29 1 253:0 / /mnt rw - ext4 /dev/mapper/data rw\n\
         30 29 253:0 / /mnt/data rw - ext4 /dev/mapper/data rw\n",
    );
    assert!(result.is_fail(), "got {result:?}");
    assert_eq!(
        result.message(),
        "the volume at /mnt/data is also mounted at /mnt: a desktop may have mounted it there \
         by itself when it was unlocked"
    );
    assert_eq!(
        result.remediation().unwrap(),
        format!(
            "Run `sudo umount /mnt/data /mnt`, mount the volume at /mnt/data alone, then run \
             the command again.\n{ADVICE}"
        )
    );
}

#[test]
fn a_folder_bound_at_the_root_below_the_volume_is_bound_again_not_replaced_by_the_volume() {
    // The volume at /mnt and its folder /vol bound at /mnt/data: the layout
    // is in /vol, so mounting the volume itself at the root would show its
    // top instead.
    let result = run_on(
        "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
         29 1 253:0 / /mnt rw - ext4 /dev/mapper/data rw\n\
         30 29 253:0 /vol /mnt/data rw - ext4 /dev/mapper/data rw\n",
    );
    assert!(result.is_fail(), "got {result:?}");
    assert_eq!(
        result.remediation().unwrap(),
        format!(
            "Run `sudo umount /mnt/data /mnt`. Then mount the volume at another folder, bind \
             its folder /vol at /mnt/data, unmount that other folder and run the command \
             again.\n{ADVICE}"
        )
    );
    // While the volume's own mount does not hold the root, unmounting it
    // leaves the bind of the folder at the root alone.
    let result = run_on(
        "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
         29 1 253:0 / /mnt/backing rw - ext4 /dev/mapper/data rw\n\
         30 1 253:0 /vol /mnt/data rw - ext4 /dev/mapper/data rw\n",
    );
    assert_eq!(
        result.remediation().unwrap(),
        format!("Run `sudo umount /mnt/backing`, then run the command again.\n{ADVICE}")
    );
}

#[test]
fn a_btrfs_subvolume_at_the_root_below_the_volume_is_mounted_again_by_its_option() {
    // The volume's top at /mnt and its subvolume /data at /mnt/data: mounted
    // without the option, the volume would show its default subvolume.
    let result = run_on(
        "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
         29 1 0:45 / /mnt rw - btrfs /dev/mapper/data rw,subvolid=5,subvol=/\n\
         30 29 0:45 /data /mnt/data rw - btrfs /dev/mapper/data rw,subvolid=256,subvol=/data\n",
    );
    assert!(result.is_fail(), "got {result:?}");
    assert_eq!(
        result.remediation().unwrap(),
        format!(
            "Run `sudo umount /mnt/data /mnt`, mount the btrfs subvolume /data of the volume at \
             /mnt/data alone (mount option subvol=/data), then run the command again.\n{ADVICE}"
        )
    );
}

#[test]
fn a_hidden_second_mount_is_named_with_the_mount_over_it_not_given_to_umount() {
    // A tmpfs over /media hides the desktop's mount: umount given its path
    // would end in the tmpfs. The mount at /srv/x is reached by its path.
    let result = run_on(
        "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
         30 1 253:0 / /mnt/data rw - ext4 /dev/mapper/data rw\n\
         40 1 253:0 / /media/u/X rw - ext4 /dev/mapper/data rw\n\
         41 1 0:50 / /media rw - tmpfs tmpfs rw\n\
         42 1 253:0 / /srv/x rw - ext4 /dev/mapper/data rw\n",
    );
    assert!(result.is_fail(), "got {result:?}");
    assert!(
        result
            .message()
            .contains("also mounted at /media/u/X and /srv/x: a desktop"),
        "{}",
        result.message()
    );
    assert_eq!(
        result.remediation().unwrap(),
        format!(
            "Run `sudo umount /srv/x`, then run the command again.\n\
             The mount at /media/u/X is hidden under another mount at /media, so umount cannot \
             reach it by that path: unmount that one first, then /media/u/X, and mount it again \
             if it is needed.\n{ADVICE}"
        )
    );
    // When every other mount is hidden there is no umount line; one the root's
    // own mount hides, mounted below /mnt/data before the volume was, names
    // the root.
    let result = run_on(
        "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
         29 1 253:0 /a /mnt/data/b rw - ext4 /dev/mapper/data rw\n\
         30 1 253:0 / /mnt/data rw - ext4 /dev/mapper/data rw\n",
    );
    assert_eq!(
        result.remediation().unwrap(),
        format!(
            "The mount at /mnt/data/b is hidden under another mount at /mnt/data, so umount \
             cannot reach it by that path: unmount that one first, then /mnt/data/b, and mount \
             it again if it is needed.\n{ADVICE}"
        )
    );
    let text = format!("{} {}", result.message(), result.remediation().unwrap());
    assert!(!text.contains("/dev/"), "{text}");
}

#[test]
fn the_sessions_own_mounts_of_the_volume_pass() {
    // In the hidden session: the volume bound at its own path twice (again
    // over a decoy filesystem at its parent) and the decoy's /boot carried on
    // it; the plan records the volume's device.
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists(NEUTRAL_ROOT, true);
    fs.mock_set_writable(NEUTRAL_ROOT, true);
    fs.mock_set_mount_table(
        "1 0 0:30 / / rw - overlay overlay rw,lowerdir=/run/overlay-runtime/lower,\
         upperdir=/mnt/data/root/upper,workdir=/mnt/data/root/work\n\
         10 1 253:0 / /mnt/data rw - ext4 /dev/mapper/data rw\n\
         11 1 0:31 / /mnt rw - overlay overlay rw,lowerdir=/run/overlay-runtime/lower-1,\
         upperdir=/mnt/data/root/mounts/mnt/upper,workdir=/mnt/data/root/mounts/mnt/work\n\
         12 11 253:0 / /mnt/data rw - ext4 /dev/mapper/data rw\n\
         13 12 8:3 / /mnt/data/root/decoy/boot ro - ext4 /dev/vda3 rw\n",
    );
    let plan = format!(
        "{{\"version\":{version},\"hidden_root\":\"/mnt/data\",\"hidden_dev\":\"253:0\",\
         \"upper\":\"/mnt/data/root/upper\",\"work\":\"/mnt/data/root/work\",\
         \"decoy_root\":{{\"source\":\"/dev/vda1\",\"fstype\":\"ext4\"}},\
         \"decoy\":{{\"init\":\"/sbin/init\"}},\"hidden\":{{\"init\":\"/sbin/init\"}}}}",
        version = nails_teardown::whole_root::plan::PLAN_VERSION
    );
    let path = nails_teardown::whole_root::plan::default_plan_path();
    fs.mock_set_file_content(path.to_str().unwrap(), &plan);
    let result = run_allowing(&fs, Allow::Nothing);
    assert!(result.is_pass(), "got {result:?}");
}

#[test]
fn a_root_on_a_decoy_filesystem_the_operator_accepted_passes_beside_the_decoys_own_mounts() {
    // A bind of a folder of /, beside NixOS's read-only bind of /nix/store,
    // and a btrfs subvolume beside the /home subvolume the fstab mounts: the
    // decoy's / and /home are where it mounts that filesystem, which the
    // gate's warning names, and neither /nix/store nor /home shows the
    // root's folder.
    let bind = bind_of_a_decoy_folder();
    bind.mock_set_mount_table(
        "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
         5 1 8:1 /nix/store /nix/store ro - ext4 /dev/vda1 rw\n\
         30 1 8:1 /srv/x /mnt/data rw - ext4 /dev/vda1 rw\n",
    );
    let subvolume = MockFilesystem::new();
    subvolume.mock_set_path_exists(NEUTRAL_ROOT, true);
    subvolume.mock_set_writable(NEUTRAL_ROOT, true);
    subvolume.mock_set_mount_table(
        "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
         2 1 0:40 /home /home rw - btrfs /dev/vda2 rw,subvol=/home\n\
         30 1 0:40 /vault /mnt/data rw - btrfs /dev/vda2 rw,subvol=/vault\n",
    );
    subvolume.mock_set_file_content("/etc/fstab", "/dev/vda2 /home btrfs subvol=/home 0 0\n");
    for fs in [bind_of_a_decoy_folder(), bind, subvolume] {
        let result = run_allowing(&fs, Allow::DecoyStorage);
        assert!(result.is_warn(), "got {result:?}");
        assert!(
            result
                .message()
                .starts_with("--allow-decoy-storage: using /mnt/data although it is"),
            "{}",
            result.message()
        );
    }
}

/// The failure of a root the operator accepted on a filesystem the decoy
/// uses, mounted at `places` as well.
fn on_a_decoy_filesystem_also_at(places: &str) -> String {
    format!(
        "the filesystem of /mnt/data, which --allow-decoy-storage accepted, is also mounted at \
         {places}, where neither / nor a line of /etc/fstab mounts it"
    )
}

/// The fix of that failure for one other mount at `place`, which `umount`
/// reaches by its path: first not to unmount a mount this computer makes by
/// itself, then how to unmount one made by hand, and the advice about
/// removable media only for a place under /media or /run/media.
fn on_a_decoy_filesystem_fix(place: &str) -> String {
    let advice = if ["/media", "/run/media"]
        .iter()
        .any(|at| Path::new(place).starts_with(at))
    {
        ADVICE
    } else {
        READ
    };
    format!(
        "If this computer mounts it at {place} by itself, do not unmount it there: use a \
         volume on a disk or partition of its own instead.\n\
         If it was mounted there by hand, unmount it:\n\
         Run `sudo umount {place}`, then run the command again.\n{advice}"
    )
}

#[test]
fn a_separate_drive_also_mounted_at_a_system_folder_is_refused_with_the_flag_too() {
    // The drive at the root is mounted at /srv as well, which no fstab line
    // makes: the gate counts /srv as the decoy's and refuses it as decoy
    // storage, and accepted with the flag it is a second mount.
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists(NEUTRAL_ROOT, true);
    fs.mock_set_writable(NEUTRAL_ROOT, true);
    fs.mock_set_mount_table(
        "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
         30 1 8:17 / /mnt/data rw - ext4 /dev/sdb1 rw\n\
         40 1 8:17 / /srv rw - ext4 /dev/sdb1 rw\n",
    );
    let refused = run_allowing(&fs, Allow::Nothing);
    assert!(refused.is_fail(), "got {refused:?}");
    assert_eq!(
        refused.message(),
        "/mnt/data is not a volume of its own: it is the filesystem this computer has mounted \
         at /srv"
    );
    // No line mounts it there, so the hint says to unmount it, not to remove
    // a line.
    assert!(
        refused.remediation().unwrap().starts_with(
            "If /mnt/data is the volume you prepared and it was mounted at /srv by hand, run \
             `sudo umount /srv`, then run the command again.\n"
        ),
        "{:?}",
        refused.remediation()
    );
    assert_eq!(refused.allowable(), Some(Allowable::DecoyStorage));

    let result = run_allowing(&fs, Allow::DecoyStorage);
    assert!(result.is_fail(), "got {result:?}");
    assert_eq!(result.message(), on_a_decoy_filesystem_also_at("/srv"));
    assert_eq!(
        result.remediation().unwrap(),
        on_a_decoy_filesystem_fix("/srv")
    );
    // No flag lifts it, and nothing was probed.
    assert_eq!(result.allowable(), None);
    assert!(fs.mock_ops().is_empty(), "{:?}", fs.mock_ops());

    // Mounted at /srv by a line of the fstab, it is the decoy's own mount.
    // That line mounts the volume itself, no filesystem the root is part of:
    // backend-entries still fails it with the flag, and says to keep it, as
    // the decoy's own boot needs it.
    fs.mock_set_file_content("/etc/fstab", "/dev/sdb1 /srv ext4 defaults 0 2\n");
    let result = run_allowing(&fs, Allow::DecoyStorage);
    assert!(result.is_warn(), "got {result:?}");
    let entries = crate::preflight::BackendEntriesCheck::new(PathBuf::from(NEUTRAL_ROOT))
        .allowing(Allow::DecoyStorage)
        .run(&fs)
        .unwrap();
    assert!(entries.is_fail(), "got {entries:?}");
    assert_eq!(
        entries.remediation(),
        Some(crate::preflight::checks::backend_entries::STORAGE_OF_ITS_OWN)
    );
}

#[test]
fn a_root_on_a_filesystem_the_decoy_mounts_without_an_fstab_line_is_refused() {
    // A bind of a folder of /home, a partition the decoy mounts with no line
    // (as systemd-gpt-auto-generator does): /home shows the root's folder.
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists(NEUTRAL_ROOT, true);
    fs.mock_set_writable(NEUTRAL_ROOT, true);
    fs.mock_set_mount_table(
        "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
         2 1 8:2 / /home rw - ext4 /dev/vda2 rw\n\
         30 1 8:2 /u/vault /mnt/data rw - ext4 /dev/vda2 rw\n",
    );
    let result = run_allowing(&fs, Allow::DecoyStorage);
    assert!(result.is_fail(), "got {result:?}");
    assert_eq!(result.message(), on_a_decoy_filesystem_also_at("/home"));
    assert_eq!(
        result.remediation().unwrap(),
        on_a_decoy_filesystem_fix("/home")
    );
    assert_eq!(result.allowable(), None);
    // With a line that mounts the partition at /home, it passes with the
    // warning.
    fs.mock_set_file_content("/etc/fstab", "/dev/vda2 /home ext4 defaults 0 2\n");
    let result = run_allowing(&fs, Allow::DecoyStorage);
    assert!(result.is_warn(), "got {result:?}");
    // Without the line and once /home is unmounted, nothing shows that the
    // partition is the decoy's: the root passes with no warning at all, which
    // is why the fix says first to keep that mount.
    let gone = MockFilesystem::new();
    gone.mock_set_path_exists(NEUTRAL_ROOT, true);
    gone.mock_set_writable(NEUTRAL_ROOT, true);
    gone.mock_set_mount_table(
        "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
         30 1 8:2 /u/vault /mnt/data rw - ext4 /dev/vda2 rw\n",
    );
    for allow in [Allow::Nothing, Allow::DecoyStorage] {
        let result = run_allowing(&gone, allow);
        assert!(result.is_pass(), "{allow:?}: {result:?}");
    }
}

#[test]
fn a_second_mount_that_shows_the_folder_of_an_accepted_root_is_refused() {
    // A folder of / bound at the root, and a folder above it bound under
    // /media too: the decoy's files of the root are reached there.
    let fs = bind_of_a_decoy_folder();
    fs.mock_set_mount_table(
        "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
         30 1 8:1 /srv/x /mnt/data rw - ext4 /dev/vda1 rw\n\
         40 1 8:1 /srv /media/u/srv rw - ext4 /dev/vda1 rw\n",
    );
    let result = run_allowing(&fs, Allow::DecoyStorage);
    assert!(result.is_fail(), "got {result:?}");
    assert_eq!(
        result.message(),
        on_a_decoy_filesystem_also_at("/media/u/srv")
    );
    assert_eq!(
        result.remediation().unwrap(),
        on_a_decoy_filesystem_fix("/media/u/srv")
    );
    assert_eq!(result.allowable(), None);
    assert!(fs.mock_ops().is_empty(), "{:?}", fs.mock_ops());
}

/// A mock where the root at `/mnt/data` exists and is writable, with `table`
/// as its mount table and `fstab` as the decoy's fstab.
fn decoy_with(table: &str, fstab: &str) -> MockFilesystem {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists(NEUTRAL_ROOT, true);
    fs.mock_set_writable(NEUTRAL_ROOT, true);
    fs.mock_set_mount_table(table);
    fs.mock_set_file_content("/etc/fstab", fstab);
    fs
}

#[test]
fn an_ostree_layout_is_refused_first_saying_not_to_unmount_what_it_mounts_itself() {
    // ostree binds the deployment at / and its var at /var, and mounts the
    // whole filesystem at /sysroot, with no fstab line for either: a folder
    // of var bound at the root is reached through both.
    let fs = decoy_with(
        "1 0 8:3 /ostree/deploy/fedora/deploy/abc.0 / rw - xfs /dev/vda3 rw\n\
         2 1 8:3 / /sysroot ro - xfs /dev/vda3 rw\n\
         3 1 8:3 /ostree/deploy/fedora/var /var rw - xfs /dev/vda3 rw\n\
         4 1 8:3 /ostree/deploy/fedora/deploy/abc.0/usr /usr ro - xfs /dev/vda3 rw\n\
         5 1 8:2 / /boot rw - ext4 /dev/vda2 rw\n\
         30 1 8:3 /ostree/deploy/fedora/var/data /mnt/data rw - xfs /dev/vda3 rw\n",
        "/dev/vda3 / xfs defaults 0 0\n/dev/vda2 /boot ext4 defaults 1 2\n",
    );
    let result = run_allowing(&fs, Allow::DecoyStorage);
    assert!(result.is_fail(), "got {result:?}");
    assert_eq!(
        result.message(),
        on_a_decoy_filesystem_also_at("/sysroot and /var")
    );
    assert_eq!(
        result.remediation().unwrap(),
        format!(
            "If this computer mounts it at /sysroot and /var by itself, do not unmount it \
             there: use a volume on a disk or partition of its own instead.\n\
             If it was mounted there by hand, unmount it:\n\
             Run `sudo umount /sysroot /var`, then run the command again.\n{READ}"
        )
    );
    assert_eq!(result.allowable(), None);
}

#[test]
fn a_mount_a_bind_line_of_the_fstab_copies_from_the_root_is_refused_with_the_flag_too() {
    // The decoy's fstab binds a folder of the root at /srv: once the hidden
    // drive is mounted at the root, /srv shows its files, and the line names
    // a folder of the drive, not of the decoy's storage.
    let fs = decoy_with(
        "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
         30 1 253:0 / /mnt/data rw - ext4 /dev/mapper/data rw\n\
         40 1 253:0 /srv /srv rw - ext4 /dev/mapper/data rw\n",
        "/dev/vda1 / ext4 defaults 0 1\n/mnt/data/srv /srv none bind,nofail 0 0\n",
    );
    let refused = run_allowing(&fs, Allow::Nothing);
    assert!(refused.is_fail(), "got {refused:?}");
    assert_eq!(refused.allowable(), Some(Allowable::DecoyStorage));
    let result = run_allowing(&fs, Allow::DecoyStorage);
    assert!(result.is_fail(), "got {result:?}");
    assert_eq!(result.message(), on_a_decoy_filesystem_also_at("/srv"));
    assert_eq!(
        result.remediation().unwrap(),
        on_a_decoy_filesystem_fix("/srv")
    );
    assert_eq!(result.allowable(), None);
}

#[test]
fn a_bind_of_a_folder_of_a_zfs_dataset_the_fstab_mounts_passes_with_the_flag() {
    // NixOS mounts a dataset with a legacy mount point by an fstab line that
    // names it; ZFS itself mounts one by its mountpoint property, with none.
    let table = "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
                 2 1 0:51 / /home rw - zfs rpool/home rw,xattr,noacl\n\
                 30 1 0:51 /u/vault /mnt/data rw - zfs rpool/home rw,xattr,noacl\n";
    let fs = decoy_with(table, "rpool/home /home zfs defaults 0 0\n");
    let result = run_allowing(&fs, Allow::DecoyStorage);
    assert!(result.is_warn(), "got {result:?}");
    assert!(
        result.message().starts_with(
            "--allow-decoy-storage: using /mnt/data although it is a bind mount of a folder of \
             /home"
        ),
        "{}",
        result.message()
    );
    let fs = decoy_with(table, "");
    let result = run_allowing(&fs, Allow::DecoyStorage);
    assert!(result.is_fail(), "got {result:?}");
    assert_eq!(result.message(), on_a_decoy_filesystem_also_at("/home"));
    assert_eq!(
        result.remediation().unwrap(),
        on_a_decoy_filesystem_fix("/home")
    );
}
