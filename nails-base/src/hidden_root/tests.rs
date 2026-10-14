// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::MockFilesystem;
use std::path::{Path, PathBuf};

const ROOT_DEVICE: u64 = 1;
const VOLUME_DEVICE: u64 = 42;

/// The decoy's `/` and `/home`, and the hidden volume at `/mnt/data`, plus
/// `extra` mount lines.
fn decoy_table(extra: &str) -> String {
    format!(
        "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
         2 1 8:2 / /home rw - ext4 /dev/vda2 rw\n\
         10 1 253:0 / /mnt/data rw - ext4 /dev/mapper/data rw\n{extra}"
    )
}

/// The hidden session's view: `/` is the overlay whose upper lies on the
/// hidden volume, and `mnt_data` is the mount line at `/mnt/data`, if any.
fn session_table(mnt_data: &str) -> String {
    format!(
        "1 0 0:30 / / rw - overlay overlay rw,lowerdir=/run/overlay-runtime/lower,\
         upperdir=/mnt/data/root/upper,workdir=/mnt/data/root/work\n{mnt_data}"
    )
}

const HIDDEN_MOUNT: &str = "10 1 253:0 / /mnt/data rw - ext4 /dev/mapper/data rw\n";

/// A mock where `/mnt/data` exists, with `table` as its mount table.
fn fs_with(table: &str) -> MockFilesystem {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/mnt/data", true);
    fs.mock_set_mount_table(table);
    fs.mock_set_device_id(Path::new("/"), ROOT_DEVICE);
    fs.mock_set_device_id(Path::new("/mnt/data"), VOLUME_DEVICE);
    fs
}

/// Write a session plan to `/run`, recording `hidden_dev` when given.
fn write_plan(fs: &MockFilesystem, hidden_dev: Option<&str>) {
    let dev = hidden_dev
        .map(|dev| format!(",\"hidden_dev\":\"{dev}\""))
        .unwrap_or_default();
    let text = format!(
        "{{\"version\":{version},\"hidden_root\":\"/mnt/data\"{dev},\
         \"upper\":\"/mnt/data/root/upper\",\"work\":\"/mnt/data/root/work\",\
         \"decoy_root\":{{\"source\":\"/dev/vda1\",\"fstype\":\"ext4\"}},\
         \"decoy\":{{\"init\":\"/sbin/init\"}},\"hidden\":{{\"init\":\"/sbin/init\"}}}}",
        version = nails_teardown::whole_root::plan::PLAN_VERSION
    );
    let path = nails_teardown::whole_root::plan::default_plan_path();
    fs.mock_set_file_content(path.to_str().unwrap(), &text);
}

fn refusal(fs: &MockFilesystem, root: &str) -> Refusal {
    match HiddenRoot::assess(fs, Path::new(root)).unwrap() {
        Assessment::Refused(refusal) => refusal,
        other => panic!("{root} was accepted: {other:?}"),
    }
}

/// A mock where `/mnt/data` is a mounted volume of its own, in the default
/// rendered mount table.
fn attached_fs(root: &Path) -> MockFilesystem {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists(root.to_str().unwrap(), true);
    fs.mock_set_mounted(root, true);
    fs.mock_set_device_id(Path::new("/"), ROOT_DEVICE);
    fs.mock_set_device_id(root, VOLUME_DEVICE);
    fs
}

#[test]
fn the_state_gate_refuses_a_directory_on_the_root_filesystem() {
    let _gate = super::state_attach_probe::enforce();
    let fs = crate::MockFilesystem::new();
    fs.mock_set_path_exists("/", true);
    fs.mock_set_path_exists("/mnt/data", true);
    fs.mock_set_path_type("/mnt/data", crate::filesystem::PathKind::Dir);
    let root = Path::new("/mnt/data");
    assert!(super::ensure_state_dir_attached(&fs, root, root).is_err());
}

#[test]
fn the_state_gate_accepts_a_directory_inside_the_volume() {
    let _gate = super::state_attach_probe::enforce();
    let fs = fs_with(&decoy_table(""));
    let root = Path::new("/mnt/data");
    super::ensure_state_dir_attached(&fs, root, root).unwrap();
    super::ensure_state_dir_attached(&fs, root, &root.join("var/state")).unwrap();
}

#[test]
fn the_state_gate_refuses_a_directory_on_a_mount_inside_the_volume() {
    let _gate = super::state_attach_probe::enforce();
    let fs = fs_with(&decoy_table(
        "11 10 0:50 / /mnt/data/var rw - tmpfs tmpfs rw\n",
    ));
    let root = Path::new("/mnt/data");
    let error = super::ensure_state_dir_attached(&fs, root, &root.join("var/state"))
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("another filesystem (/mnt/data/var)"),
        "{error}"
    );
}

#[test]
fn the_state_gate_refuses_a_directory_outside_the_root() {
    let _gate = super::state_attach_probe::enforce();
    let fs = fs_with(&decoy_table(""));
    let error = super::ensure_state_dir_attached(&fs, Path::new("/mnt/data"), Path::new("/home"))
        .unwrap_err()
        .to_string();
    assert!(error.contains("is not inside the hidden root"), "{error}");
}

#[test]
fn the_state_gate_refuses_what_the_gate_refuses() {
    let _gate = super::state_attach_probe::enforce();
    let fs = fs_with(&decoy_table("11 10 0:50 / /mnt/data rw - tmpfs tmpfs rw\n"));
    let root = Path::new("/mnt/data");
    let error = super::ensure_state_dir_attached(&fs, root, root)
        .unwrap_err()
        .to_string();
    assert!(error.contains("two filesystems are mounted"), "{error}");
}

#[test]
fn a_volume_mounted_at_the_root_is_attached() {
    let fs = fs_with(&decoy_table(""));
    assert_eq!(
        HiddenRoot::assess(&fs, Path::new("/mnt/data")).unwrap(),
        Assessment::Attached
    );
}

#[test]
fn a_plain_directory_names_the_filesystem_it_is_on() {
    // A folder on a separate /home partition has a device of its own, which
    // the old device-only test took for a mounted volume.
    let fs = fs_with(&decoy_table(""));
    fs.mock_set_path_exists("/home/op/vault", true);
    let refused = refusal(&fs, "/home/op/vault");
    assert_eq!(
        refused.kind,
        RefusalKind::NotAMountPoint {
            mount_point: PathBuf::from("/home")
        }
    );
    assert!(
        refused.reason.contains(
            "is not a volume of its own: it is a folder on the filesystem mounted at /home"
        ),
        "{}",
        refused.reason
    );

    fs.mock_set_path_exists("/srv/vault", true);
    assert_eq!(
        refusal(&fs, "/srv/vault").kind,
        RefusalKind::NotAMountPoint {
            mount_point: PathBuf::from("/")
        }
    );
}

#[test]
fn a_root_covered_by_a_mount_on_its_parent_is_no_mount_point() {
    // The volume stays in the table, but a lookup of /mnt/data now ends in
    // the tmpfs mounted on /mnt.
    let fs = fs_with(&decoy_table("11 1 0:50 / /mnt rw - tmpfs tmpfs rw\n"));
    assert_eq!(
        refusal(&fs, "/mnt/data").kind,
        RefusalKind::NotAMountPoint {
            mount_point: PathBuf::from("/mnt")
        }
    );
}

#[test]
fn two_filesystems_at_the_root_are_refused_naming_both() {
    let fs = fs_with(&decoy_table(
        "11 10 8:16 / /mnt/data rw - vfat /dev/sdb1 rw\n",
    ));
    let refused = refusal(&fs, "/mnt/data");
    assert_eq!(
        refused.kind,
        RefusalKind::Covered {
            below: PathBuf::from("/dev/mapper/data"),
            above: PathBuf::from("/dev/sdb1"),
        }
    );
    assert!(
        refused.reason.contains(
            "two filesystems are mounted at /mnt/data: /dev/mapper/data, then /dev/sdb1 over it"
        ),
        "{}",
        refused.reason
    );
}

#[test]
fn a_bind_of_the_same_volume_stacked_on_the_root_is_one_filesystem() {
    let fs = fs_with(&decoy_table(
        "11 10 253:0 / /mnt/data ro - ext4 /dev/mapper/data rw\n",
    ));
    assert!(
        HiddenRoot::assess(&fs, Path::new("/mnt/data"))
            .unwrap()
            .is_attached()
    );
}

#[test]
fn an_unreadable_mount_table_refuses() {
    let fs = fs_with(&decoy_table(""));
    fs.mock_set_mount_table_error("permission denied");
    let refused = refusal(&fs, "/mnt/data");
    assert!(
        matches!(refused.kind, RefusalKind::MountTableUnreadable { .. }),
        "{refused:?}"
    );
    assert!(
        refused.reason.contains("the mount table cannot be read"),
        "{}",
        refused.reason
    );
}

#[test]
fn in_the_session_the_recorded_volume_is_attached() {
    let fs = fs_with(&session_table(HIDDEN_MOUNT));
    write_plan(&fs, Some("253:0"));
    assert_eq!(
        HiddenRoot::assess(&fs, Path::new("/mnt/data")).unwrap(),
        Assessment::Attached
    );
}

#[test]
fn in_the_session_a_disk_over_the_root_is_refused() {
    let covered = format!("{HIDDEN_MOUNT}11 10 8:16 / /mnt/data rw - vfat /dev/sdb1 rw\n");
    let fs = fs_with(&session_table(&covered));
    write_plan(&fs, Some("253:0"));
    assert!(matches!(
        refusal(&fs, "/mnt/data").kind,
        RefusalKind::Covered { .. }
    ));
}

#[test]
fn in_the_session_another_disk_in_place_of_the_volume_is_refused() {
    // The hidden volume went away and a stick was mounted at its mount point.
    let fs = fs_with(&session_table(
        "12 1 8:16 / /mnt/data rw - vfat /dev/sdb1 rw\n",
    ));
    write_plan(&fs, Some("253:0"));
    let refused = refusal(&fs, "/mnt/data");
    assert_eq!(
        refused.kind,
        RefusalKind::NotTheSessionVolume {
            source: PathBuf::from("/dev/sdb1")
        }
    );
    assert!(
        refused
            .reason
            .contains("is not the volume this session started from"),
        "{}",
        refused.reason
    );
}

#[test]
fn in_the_session_an_older_plan_falls_back_to_the_upper() {
    let fs = fs_with(&session_table(HIDDEN_MOUNT));
    write_plan(&fs, None);
    // The upper sits on the root's device: the session's own volume.
    fs.mock_set_device_id(Path::new("/mnt/data/root/upper"), VOLUME_DEVICE);
    assert!(
        HiddenRoot::assess(&fs, Path::new("/mnt/data"))
            .unwrap()
            .is_attached()
    );

    // No upper on the filesystem at the root: not the session's volume.
    let fs = fs_with(&session_table(HIDDEN_MOUNT));
    assert!(matches!(
        refusal(&fs, "/mnt/data").kind,
        RefusalKind::NotTheSessionVolume { .. }
    ));
}

#[test]
fn outside_the_session_no_plan_is_consulted() {
    // A plan in /run that records another device does not matter on the decoy.
    let fs = fs_with(&decoy_table(""));
    write_plan(&fs, Some("8:99"));
    assert!(
        HiddenRoot::assess(&fs, Path::new("/mnt/data"))
            .unwrap()
            .is_attached()
    );
}

#[test]
fn attached_when_root_is_its_own_device() {
    let root = PathBuf::from("/mnt/data");
    let fs = attached_fs(&root);
    let state = HiddenRoot::verify_attached(&fs, &root, false).unwrap();
    assert_eq!(state, AttachState::Attached);
}

#[test]
fn unattached_when_root_shares_device_with_slash() {
    // A mount point whose filesystem is `/`'s own, as a bind of `/` is.
    let root = PathBuf::from("/mnt/data");
    let fs = attached_fs(&root);
    fs.mock_set_device_id(&root, ROOT_DEVICE);

    let state = HiddenRoot::verify_attached(&fs, &root, false).unwrap();
    assert!(!state.is_attached());
    assert!(
        state
            .reason()
            .unwrap()
            .contains("it is on the device that holds /")
    );
    assert_eq!(
        refusal(&fs, "/mnt/data").kind,
        RefusalKind::SameDeviceAsRoot
    );
}

#[test]
fn unattached_when_root_missing() {
    let root = PathBuf::from("/mnt/data");
    let fs = MockFilesystem::new();
    let state = HiddenRoot::verify_attached(&fs, &root, false).unwrap();
    assert!(!state.is_attached());
    assert!(state.reason().unwrap().contains("does not exist"));
    assert_eq!(refusal(&fs, "/mnt/data").kind, RefusalKind::Missing);
}

#[test]
fn unattached_when_marker_required_but_absent() {
    let root = PathBuf::from("/mnt/data");
    let fs = attached_fs(&root);
    let state = HiddenRoot::verify_attached(&fs, &root, true).unwrap();
    assert!(!state.is_attached());
    assert!(state.reason().unwrap().contains("no NAILS marker"));
}

#[test]
fn attached_with_marker_via_state_file() {
    let root = PathBuf::from("/mnt/data");
    let fs = attached_fs(&root);
    fs.mock_set_path_exists("/mnt/data/state.json", true);
    let state = HiddenRoot::verify_attached(&fs, &root, true).unwrap();
    assert_eq!(state, AttachState::Attached);
}

#[test]
fn attached_with_marker_via_config_file() {
    let root = PathBuf::from("/mnt/data");
    let fs = attached_fs(&root);
    fs.mock_set_path_exists("/mnt/data/config/nails.toml", true);
    let state = HiddenRoot::verify_attached(&fs, &root, true).unwrap();
    assert_eq!(state, AttachState::Attached);
}

#[test]
fn init_bypasses_marker_requirement() {
    // `init` runs with require_marker = false so a freshly mounted, empty
    // volume can be initialised.
    let root = PathBuf::from("/mnt/data");
    let fs = attached_fs(&root);
    let state = HiddenRoot::verify_attached(&fs, &root, false).unwrap();
    assert_eq!(state, AttachState::Attached);
}

#[test]
fn a_subdirectory_of_an_attached_volume_is_no_hidden_root() {
    // A folder inside the volume is no mount point; the state gate accepts it
    // as a state directory under the root instead.
    let root = PathBuf::from("/mnt/data");
    let fs = attached_fs(&root);
    fs.mock_set_path_exists("/mnt/data/logs", true);
    let state = HiddenRoot::verify_attached(&fs, &root.join("logs"), false).unwrap();
    assert!(!state.is_attached());
}

#[test]
fn empty_root_is_unattached() {
    let fs = MockFilesystem::new();
    let state = HiddenRoot::verify_attached(&fs, Path::new(""), false).unwrap();
    assert!(!state.is_attached());
    assert_eq!(refusal(&fs, "").kind, RefusalKind::NotConfigured);
}

/// The gate on the real kernel, in an unprivileged user + mount namespace.
mod kernel_tests {
    use super::super::separation::Verdict;
    use super::super::{Assessment, HiddenRoot, RefusalKind};
    use crate::RealFilesystem;
    use crate::test_support::{Rerun, ScratchTmpfs};
    use std::path::Path;

    fn kind(root: &Path) -> Option<RefusalKind> {
        match HiddenRoot::assess(&RealFilesystem, root).unwrap() {
            Assessment::Attached | Assessment::Warned(_) => None,
            Assessment::Refused(refusal) => Some(refusal.kind),
        }
    }

    #[test]
    fn a_tmpfs_is_attached_and_a_second_one_over_it_is_refused() {
        let _ = Rerun::new(crate::test_path!(
            a_tmpfs_is_attached_and_a_second_one_over_it_is_refused
        ))
        .in_user_mount_ns()
        .run(|| {
            let volume = ScratchTmpfs::new("");
            assert_eq!(kind(volume.path()), None);

            nix::mount::mount(
                Some("other"),
                volume.path(),
                Some("tmpfs"),
                nix::mount::MsFlags::empty(),
                Some("mode=0755"),
            )
            .expect("mount a second tmpfs over the first");
            assert!(
                matches!(kind(volume.path()), Some(RefusalKind::Covered { .. })),
                "{:?}",
                kind(volume.path())
            );
        });
    }

    #[test]
    fn a_plain_directory_is_refused() {
        let _ = Rerun::new(crate::test_path!(a_plain_directory_is_refused))
            .in_user_mount_ns()
            .run(|| {
                let volume = ScratchTmpfs::new("");
                let folder = volume.mkdir("folder");
                assert_eq!(
                    kind(&folder),
                    Some(RefusalKind::NotAMountPoint {
                        mount_point: volume.path().canonicalize().unwrap()
                    })
                );
                // A temp directory on whatever backs TMPDIR is no volume either.
                let plain = tempfile::tempdir().unwrap();
                assert!(matches!(
                    kind(plain.path()),
                    Some(RefusalKind::NotAMountPoint { .. })
                ));
            });
    }

    #[test]
    fn a_bind_of_the_root_filesystem_is_refused() {
        let _ = Rerun::new(crate::test_path!(a_bind_of_the_root_filesystem_is_refused))
            .in_user_mount_ns()
            .run(|| {
                let target = tempfile::tempdir().unwrap();
                nix::mount::mount(
                    Some("/"),
                    target.path(),
                    None::<&str>,
                    nix::mount::MsFlags::MS_BIND | nix::mount::MsFlags::MS_REC,
                    None::<&str>,
                )
                .expect("bind / at a scratch path");
                let refused = kind(target.path());
                let _ = nix::mount::umount2(target.path(), nix::mount::MntFlags::MNT_DETACH);
                // On a disk root the decoy-storage judge refuses it as the
                // filesystem at / (or cannot judge it, when crypttab is
                // readable by root only); on a RAM root (a live system) the
                // judge has nothing to say and the device backstop refuses it.
                assert!(
                    matches!(
                        refused,
                        Some(
                            RefusalKind::SameDeviceAsRoot
                                | RefusalKind::DecoyStorage {
                                    verdict: Verdict::OnDecoyFilesystem { .. }
                                }
                                | RefusalKind::StorageUnjudged { .. }
                        )
                    ),
                    "{refused:?}"
                );
            });
    }

    /// Make `/etc/crypttab` exist but fail to read, inside the namespace: a
    /// tmpfs over `/etc` holding a directory of that name.
    fn unreadable_crypttab() {
        nix::mount::mount(
            Some("etc"),
            "/etc",
            Some("tmpfs"),
            nix::mount::MsFlags::empty(),
            Some("mode=0755"),
        )
        .expect("a private /etc");
        std::fs::create_dir("/etc/crypttab").unwrap();
    }

    #[test]
    fn an_unreadable_crypttab_leaves_a_tmpfs_root_attached() {
        let _ = Rerun::new(crate::test_path!(
            an_unreadable_crypttab_leaves_a_tmpfs_root_attached
        ))
        .in_user_mount_ns()
        .run(|| {
            let volume = ScratchTmpfs::new("");
            unreadable_crypttab();
            assert_eq!(kind(volume.path()), None);
        });
    }

    #[test]
    fn an_unreadable_crypttab_refuses_a_root_on_a_disk() {
        let _ = Rerun::new(crate::test_path!(
            an_unreadable_crypttab_refuses_a_root_on_a_disk
        ))
        .in_user_mount_ns()
        .run(|| {
            // A folder of the filesystem behind TMPDIR, bound at a scratch path.
            let backing = tempfile::tempdir().unwrap();
            let target = tempfile::tempdir().unwrap();
            nix::mount::mount(
                Some(backing.path()),
                target.path(),
                None::<&str>,
                nix::mount::MsFlags::MS_BIND,
                None::<&str>,
            )
            .expect("bind a folder at a scratch path");
            let mounts = crate::filesystem::mountinfo::read_mountinfo().unwrap();
            let fstype = super::super::mount_holding(&mounts, target.path())
                .map(|mount| mount.fstype.clone())
                .unwrap_or_default();
            if matches!(fstype.as_str(), "tmpfs" | "ramfs") {
                let _ = nix::mount::umount2(target.path(), nix::mount::MntFlags::MNT_DETACH);
                crate::test_support::skip_host("TMPDIR is on a RAM filesystem");
            }
            unreadable_crypttab();
            let refused = kind(target.path());
            let _ = nix::mount::umount2(target.path(), nix::mount::MntFlags::MNT_DETACH);
            assert_eq!(
                refused,
                Some(RefusalKind::StorageUnjudged {
                    unreadable: vec![std::path::PathBuf::from("/etc/crypttab")]
                })
            );
        });
    }
}

/// A bind of the decoy's `/home/op/vault` at `/mnt/data`: on the decoy's
/// storage, a refusal the override covers.
const BIND_OF_HOME: &str = "13 1 8:2 /op/vault /mnt/data rw - ext4 /dev/vda2 rw\n";

#[test]
fn the_override_attaches_decoy_storage_with_a_warning_but_never_a_folder_or_a_covered_root() {
    let bind = fs_with(&format!(
        "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n2 1 8:2 / /home rw - ext4 /dev/vda2 rw\n{BIND_OF_HOME}"
    ));
    let root = Path::new("/mnt/data");
    assert!(matches!(
        HiddenRoot::assess_allowing(&bind, root, Allow::Nothing).unwrap(),
        Assessment::Refused(_)
    ));
    match HiddenRoot::assess_allowing(&bind, root, Allow::NotSeparate).unwrap() {
        Assessment::Warned(refusal) => assert!(refusal.overridden(), "{refusal:?}"),
        other => panic!("{other:?}"),
    }

    // A folder is no volume of its own, whatever the operator says.
    let fs = fs_with(&decoy_table(""));
    fs.mock_set_path_exists("/home/op/vault", true);
    match HiddenRoot::assess_allowing(&fs, Path::new("/home/op/vault"), Allow::NotSeparate).unwrap()
    {
        Assessment::Refused(refusal) => {
            assert!(
                matches!(refusal.kind, RefusalKind::NotAMountPoint { .. }),
                "{refusal:?}"
            );
            assert!(!refusal.overridden());
        }
        other => panic!("{other:?}"),
    }

    let covered = fs_with(&decoy_table(
        "11 10 8:17 / /mnt/data rw - ext4 /dev/sdb1 rw\n",
    ));
    match HiddenRoot::assess_allowing(&covered, root, Allow::NotSeparate).unwrap() {
        Assessment::Refused(refusal) => {
            assert_eq!(refusal.code(), super::refusal::ROOT_COVERED, "{refusal:?}");
        }
        other => panic!("{other:?}"),
    }

    let missing = MockFilesystem::new();
    assert!(matches!(
        HiddenRoot::assess_allowing(&missing, Path::new("/srv/x"), Allow::NotSeparate).unwrap(),
        Assessment::Refused(Refusal {
            kind: RefusalKind::Missing,
            ..
        })
    ));
}

#[test]
fn in_the_session_a_folder_is_refused_even_when_the_plan_accepted_the_root() {
    // Nothing is mounted at the root, `/` is the overlay with its upper there,
    // and the plan says the activation was run with --allow-unmounted.
    let fs = fs_with(&session_table(""));
    write_plan(&fs, None);
    assert_eq!(super::recorded_acceptance(&fs), None);
    let path = nails_teardown::whole_root::plan::default_plan_path();
    let text = fs.read_file_content(&path).unwrap().replacen(
        "\"hidden_root\"",
        "\"accepted_not_separate\":\"it is a bind mount\",\"hidden_root\"",
        1,
    );
    fs.mock_set_file_content(path.to_str().unwrap(), &text);
    assert_eq!(
        super::recorded_acceptance(&fs).as_deref(),
        Some("it is a bind mount")
    );
    assert!(matches!(
        refusal(&fs, "/mnt/data").kind,
        RefusalKind::NotAMountPoint { .. }
    ));
    let _gate = super::state_attach_probe::enforce();
    assert!(
        super::ensure_state_dir_attached(&fs, Path::new("/mnt/data"), Path::new("/mnt/data"))
            .is_err()
    );
}

#[test]
fn outside_the_session_accepted_decoy_storage_needs_the_override() {
    let table = "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n2 1 8:2 / /home rw - ext4 /dev/vda2 rw\n";
    let fs = fs_with(&format!("{table}{BIND_OF_HOME}"));
    let root = Path::new("/mnt/data");
    let _gate = super::state_attach_probe::enforce();
    assert!(super::ensure_state_dir_attached(&fs, root, root).is_err());
    super::ensure_state_dir_attached_allowing(&fs, root, root, Allow::NotSeparate).unwrap();
    // A directory below the root on another filesystem is still refused.
    let mounted_below = fs_with(&format!(
        "{table}{BIND_OF_HOME}14 13 8:33 / /mnt/data/state rw - ext4 /dev/sdc1 rw\n"
    ));
    assert!(
        super::ensure_state_dir_attached_allowing(
            &mounted_below,
            root,
            &root.join("state"),
            Allow::NotSeparate
        )
        .is_err()
    );
}
