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
        let verdict = Verdict::OnDecoyFilesystem {
            how,
            at: PathBuf::from("/home"),
        };
        assert!(on_a_decoy_filesystem(&refusal(verdict)), "{how:?}");
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
    ] {
        assert!(
            !on_a_decoy_filesystem(&refusal(verdict.clone())),
            "{verdict:?}"
        );
    }
}
