// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for preparing the entry into the hidden root.

use super::*;
use crate::session::fstab::{parse_fstab, parse_in_root};
use nails_teardown::mountinfo::parse_mountinfo;

#[test]
fn the_decoy_root_is_read_from_the_mount_table() {
    let ext4 = parse_mountinfo("1 0 8:2 / / rw - ext4 /dev/vda2 rw\n");
    let root = decoy_root_of(&ext4, Path::new("/")).unwrap();
    assert_eq!(root.source, Path::new("/dev/vda2"));
    assert_eq!(root.fstype, "ext4");
    assert_eq!(root.data, None);
    let btrfs = parse_mountinfo("1 0 0:30 /@ / rw - btrfs /dev/nvme0n1p2 rw,subvol=/@\n");
    assert_eq!(
        decoy_root_of(&btrfs, Path::new("/"))
            .unwrap()
            .data
            .as_deref(),
        Some("subvol=/@")
    );
}

/// A host that only answers the stop-command query.
struct StopHost(&'static str);

impl EntryHost for StopHost {
    fn daemon_reload(&self) -> Result<()> {
        Ok(())
    }
    fn build_hidden_system(&self, _: &NixOSBuilder, _: &Path, _: &Path) -> Result<PathBuf> {
        unreachable!("not used by the stop-guard check")
    }
    fn keep_hidden_closure(&self, _: &Path, _: &Path, _: &Path) -> Result<store::KeepReport> {
        unreachable!("not used by the stop-guard check")
    }
    fn activate_hidden_system(&self, _: &Path, _: &Path) -> Result<()> {
        unreachable!("not used by the stop-guard check")
    }
    fn unit_stop_commands(&self, _: &str) -> Result<String> {
        Ok(self.0.to_string())
    }
}

#[test]
fn a_prefix_guard_is_not_asked_about_by_name() {
    /// Answers with a stop command for anything but blk-availability.
    struct PrefixOnly;
    impl EntryHost for PrefixOnly {
        fn daemon_reload(&self) -> Result<()> {
            Ok(())
        }
        fn build_hidden_system(&self, _: &NixOSBuilder, _: &Path, _: &Path) -> Result<PathBuf> {
            unreachable!()
        }
        fn keep_hidden_closure(&self, _: &Path, _: &Path, _: &Path) -> Result<store::KeepReport> {
            unreachable!()
        }
        fn activate_hidden_system(&self, _: &Path, _: &Path) -> Result<()> {
            unreachable!()
        }
        fn unit_stop_commands(&self, unit: &str) -> Result<String> {
            assert!(
                !unit.ends_with("-.service"),
                "asked about the prefix {unit}"
            );
            Ok(if unit == "blk-availability.service" {
                String::new()
            } else {
                "{ path=/bin/true }".to_string()
            })
        }
    }
    assert!(check_stop_guards(&PrefixOnly).is_ok());
}

#[test]
fn a_stop_command_left_after_the_guard_refuses_the_entry() {
    assert!(check_stop_guards(&StopHost("\n")).is_ok());
    let error = check_stop_guards(&StopHost(
        "{ path=/usr/sbin/blkdeactivate ; argv[]=/usr/sbin/blkdeactivate -u ; }\n",
    ))
    .unwrap_err();
    let text = error.to_string();
    assert!(text.contains("blk-availability.service"), "{text}");
    assert!(text.contains("zz-overlay-runtime.conf"), "{text}");
    assert!(matches!(error, NailsError::PreFlightCheckFailed(_)));
}

#[test]
fn a_build_is_refused_below_the_space_floor() {
    let dir = tempfile::tempdir().unwrap();
    assert!(ensure_build_space(dir.path(), 0).is_ok());
    let error = ensure_build_space(dir.path(), u64::MAX).unwrap_err();
    assert!(error.to_string().contains("rebuild_space_mb"), "{error}");
}

#[test]
fn a_root_that_cannot_be_mounted_again_is_refused() {
    for table in [
        "1 0 0:20 / / rw - tmpfs none rw\n",
        "1 0 0:21 / / rw - overlay overlay rw,lowerdir=/a\n",
        "1 0 0:22 / / rw - zfs /dev/zd0 rw\n",
        "1 0 8:2 /sub / rw - ext4 /dev/vda2 rw\n",
        // A btrfs bind of a plain folder inside the subvolume /@: the mount
        // root (/@/srv) is not the subvolume (subvol=/@), so the way back
        // cannot mount it again by subvol.
        "1 0 0:30 /@/srv / rw - btrfs /dev/nvme0n1p2 rw,subvolid=256,subvol=/@\n",
    ] {
        let entries = parse_mountinfo(table);
        assert!(decoy_root_of(&entries, Path::new("/")).is_err(), "{table}");
    }
}

#[test]
fn a_btrfs_bind_of_a_plain_folder_is_refused_by_path() {
    // The refusal names the folder, never the device-mapper node or device.
    let table = "1 0 0:30 /@/srv / rw - btrfs /dev/nvme0n1p2 rw,subvolid=256,subvol=/@\n";
    let err = decoy_root_of(&parse_mountinfo(table), Path::new("/")).unwrap_err();
    assert!(err.to_string().contains("/@/srv"), "{err}");

    // A genuine subvolume mount, whose root equals its subvol=, is accepted
    // even when the subvolume lives at a deeper path.
    let table =
        "1 0 0:30 /@/snapshots/root / rw - btrfs /dev/nvme0n1p2 rw,subvol=/@/snapshots/root\n";
    assert_eq!(
        decoy_root_of(&parse_mountinfo(table), Path::new("/"))
            .unwrap()
            .data
            .as_deref(),
        Some("subvol=/@/snapshots/root")
    );
}

#[test]
fn a_btrfs_subvolume_whose_path_the_kernel_escapes_is_a_subvolume() {
    // The kernel writes a space, a tab or a backslash of the subvolume's path
    // as an octal escape both in the mount root and in its subvol= option;
    // decoded, the two are the same path.
    for (escaped, path) in [
        ("/@ubuntu\\04026.04", "/@ubuntu 26.04"),
        ("/@root\\011tab", "/@root\ttab"),
        ("/@back\\134slash", "/@back\\slash"),
    ] {
        let table = format!(
            "1 0 0:30 {escaped} / rw - btrfs /dev/nvme0n1p2 rw,subvolid=256,subvol={escaped}\n"
        );
        let root = decoy_root_of(&parse_mountinfo(&table), Path::new("/"))
            .unwrap_or_else(|e| panic!("{table}: {e}"));
        assert_eq!(
            root.data.as_deref(),
            Some(format!("subvol={path}").as_str()),
            "{table}"
        );
    }

    // A bind of a folder with such a path is still refused.
    let table = "1 0 0:30 /@ubuntu\\04026.04/srv / rw - btrfs /dev/nvme0n1p2 \
                 rw,subvol=/@ubuntu\\04026.04\n";
    assert!(decoy_root_of(&parse_mountinfo(table), Path::new("/")).is_err());
}

#[test]
fn a_btrfs_subvolume_with_a_comma_in_its_path_is_refused() {
    // The mount root keeps the comma, the option escapes it. The two match,
    // but the way back passes `subvol=` to mount(2), which splits at commas,
    // so it could not mount the decoy root again.
    let table = "1 0 0:30 /@a,b / rw - btrfs /dev/nvme0n1p2 rw,subvolid=256,subvol=/@a\\054b\n";
    let error = decoy_root_of(&parse_mountinfo(table), Path::new("/")).unwrap_err();
    let text = error.to_string();
    assert!(text.contains("comma"), "{text}");
    assert!(text.contains("/@a,b"), "{text}");
}

/// A minimal `EntryInputs` for the helpers that do not build a system:
/// no builder, no operator, the persona at its default.
fn minimal_inputs<'a>(
    hidden_root: &'a Path,
    binary: &'a Path,
    config_toml: Option<String>,
) -> EntryInputs<'a> {
    EntryInputs {
        hidden_root,
        decoy_root: DecoyRoot {
            source: PathBuf::from("/dev/vda2"),
            fstype: "ext4".into(),
            data: None,
        },
        nixos: false,
        builder: None,
        binary,
        config_toml,
        session_units: Vec::new(),
        backend: Vec::new(),
        persona: Default::default(),
        operator: None,
        rebuild_space_mb: 0,
        read_only_disks: false,
        accepted_decoy_storage: None,
    }
}

#[test]
fn write_runtime_populates_the_runtime_directory() {
    let run = tempfile::tempdir().unwrap();
    let hidden = tempfile::tempdir().unwrap();
    let binary = run.path().join("nails-running-binary");
    std::fs::write(&binary, b"the running binary bytes").unwrap();
    let paths = Paths {
        root: PathBuf::from("/"),
        run: run.path().to_path_buf(),
    };
    // A scratch tree, not the real system, so the runtime lands under it.
    assert!(!paths.is_system());
    let toml = "hidden_volume_root = \"/x\"\n".to_string();
    let inputs = minimal_inputs(hidden.path(), &binary, Some(toml.clone()));
    let snapshot = Snapshot::take(&paths.run);

    write_runtime(&paths, &inputs, &snapshot).unwrap();

    let runtime = paths.runtime();
    // The RAM copy of the binary is the running binary, byte for byte: the
    // whole point of write_runtime, skipped by a body replaced with Ok(()).
    assert_eq!(
        std::fs::read(paths.binary_copy()).unwrap(),
        std::fs::read(&binary).unwrap()
    );
    // The `/run` snapshot and the saved utab the way back reads are written.
    assert!(runtime.join(SNAPSHOT_NAME).exists());
    assert!(runtime.join(UTAB_NAME).exists());
    assert!(runtime.join(UTAB_MOUNTS_NAME).exists());
    // The configuration copy carries the effective TOML verbatim.
    assert_eq!(
        std::fs::read_to_string(runtime.join(CONFIG_COPY_NAME)).unwrap(),
        toml
    );
    // The runtime directory is private (0o700), as write_runtime sets it.
    let mode = std::fs::metadata(&runtime).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);
}

#[test]
fn fresh_home_without_the_operator_is_refused() {
    let run = tempfile::tempdir().unwrap();
    let hidden = tempfile::tempdir().unwrap();
    let binary = run.path().join("nails-running-binary");
    std::fs::write(&binary, b"bin").unwrap();
    let paths = Paths {
        root: run.path().join("root"),
        run: run.path().to_path_buf(),
    };
    let layout = Layout::new(hidden.path());
    // Fresh-home needs the operator (the sudo user) whose home is reset; with
    // none, the entry must refuse rather than silently do nothing. A body
    // replaced with Ok(()) would accept it.
    let inputs = minimal_inputs(hidden.path(), &binary, None);
    assert!(inputs.operator.is_none());

    let error = fresh_home(&paths, &inputs, &layout, &[]).unwrap_err();

    let text = error.to_string();
    assert!(text.contains("fresh-home"), "{text}");
    assert!(text.contains("operator"), "{text}");
    assert!(matches!(error, NailsError::InvalidState(_)));
}

#[test]
fn a_symlinked_fstab_mount_point_is_decided_at_its_real_path() {
    // The decoy keeps /home at var/home (an ostree layout).
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("var/home")).unwrap();
    std::os::unix::fs::symlink("var/home", root.path().join("home")).unwrap();

    // fstab names /home; nothing is mounted there now, so it is masked. The
    // masked unit is the one systemd generates for the real mount point,
    // var-home.mount, not home.mount, so the hidden session really masks it.
    let fstab = parse_in_root(b"/dev/sdb1 /home ext4 defaults 0 2\n", root.path());
    let decisions = decide_fstab(&fstab, &[], Path::new("/mnt/data"), &|_| false).unwrap();
    assert_eq!(policy::masked_units(&decisions), ["var-home.mount"]);
    // With its disk there, local-fs.target's requirement is skipped under the
    // same name.
    let decisions = decide_fstab(&fstab, &[], Path::new("/mnt/data"), &|_| true).unwrap();
    assert_eq!(decisions[0].skip().unwrap().units, ["var-home.mount"]);
}

#[test]
fn the_automount_of_an_overlaid_symlinked_mount_point_is_skipped_by_its_real_path() {
    // The decoy keeps /home at var/home, mounts the filesystem there, and
    // its fstab names /home behind an automount.
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("var/home")).unwrap();
    std::os::unix::fs::symlink("var/home", root.path().join("home")).unwrap();
    let mounts = parse_mountinfo(
        "1 0 8:2 / / rw - ext4 /dev/vda2 rw\n\
         2 1 8:3 / /var/home rw - ext4 /dev/vda3 rw\n",
    );
    let fstab = parse_in_root(
        b"UUID=a /home ext4 defaults,x-systemd.automount 0 2\n",
        root.path(),
    );
    let decisions = decide_fstab(&fstab, &mounts, Path::new("/mnt/data"), &|_| false).unwrap();
    // The filesystem is overlaid where the decoy has it, and the automount
    // the hidden systemd generates for that path is kept off with the same
    // resolved entries: left free, it would find the mount point taken and
    // fail local-fs.target, the emergency mode this prevents. The target
    // requires the automount, so it is skipped, not masked.
    assert_eq!(
        decisions,
        [Decision::Overlay {
            target: PathBuf::from("/var/home")
        }]
    );
    let kept = policy::runtime_units(&fstab, &decisions);
    assert!(kept.masks.is_empty(), "{:?}", kept.masks);
    assert_eq!(kept.skips.len(), 1, "{:?}", kept.skips);
    assert_eq!(kept.skips[0].units, ["var-home.automount"]);
}

#[test]
fn only_the_entries_the_next_root_resolves_elsewhere_are_decided_again() {
    let decoy = parse_fstab(
        "/dev/sdb1 /var/home ext4 defaults 0 2\n\
         /dev/sdc1 /srv ext4 defaults 0 2\n",
    );
    // In the next root the first entry's path is a directory of the hidden
    // session's own (no link to var/home there), the second unchanged.
    let in_nextroot = parse_fstab(
        "/dev/sdb1 /home ext4 defaults 0 2\n\
         /dev/sdc1 /srv ext4 defaults 0 2\n",
    );
    let elsewhere = resolved_elsewhere(&decoy, in_nextroot);
    assert_eq!(elsewhere.len(), 1, "{elsewhere:?}");
    assert_eq!(elsewhere[0].file, Path::new("/home"));
    // Decided there, where the decoy mounts nothing: masked, so the hidden
    // systemd never mounts the decoy's disk read-write at /home.
    let decisions = decide_elsewhere(&elsewhere, &[], Path::new("/mnt/data"), &|_| false).unwrap();
    assert_eq!(policy::masked_units(&decisions), ["home.mount"]);
}

#[test]
fn an_entry_a_link_leads_into_the_hidden_volume_is_masked_there() {
    // The decoy keeps /data and /media for disks it does not mount now. An
    // earlier session moved both onto the hidden volume, replacing each
    // directory with a link into it.
    let decoy = parse_fstab(
        "UUID=X /data ext4 defaults,nofail 0 2\n\
         UUID=Y /media ext4 noauto,x-systemd.automount 0 2\n",
    );
    let in_nextroot = parse_fstab(
        "UUID=X /mnt/data/data ext4 defaults,nofail 0 2\n\
         UUID=Y /mnt/data/media ext4 noauto,x-systemd.automount 0 2\n",
    );
    let elsewhere = resolved_elsewhere(&decoy, in_nextroot);
    assert_eq!(elsewhere.len(), 2, "{elsewhere:?}");
    // The hidden volume's own rule would leave them to the bind of the
    // volume, and the hidden systemd would mount the decoy's disks read-write
    // inside it. They are kept off there: the nofail mount masked, the
    // automount local-fs.target requires skipped, its mount masked.
    let decisions = decide_elsewhere(&elsewhere, &[], Path::new("/mnt/data"), &|_| false).unwrap();
    assert_eq!(
        policy::masked_units(&decisions),
        ["mnt-data-data.mount", "mnt-data-media.mount"]
    );
    let skipped: Vec<&String> = decisions
        .iter()
        .filter_map(Decision::skip)
        .flat_map(|skip| &skip.units)
        .collect();
    assert_eq!(skipped, ["mnt-data-media.automount"]);
}

#[test]
fn the_real_host_finds_no_device_without_its_node() {
    assert!(!RealEntryHost.device_present(Path::new("/dev/disk/by-id/nails-test-no-such-disk")));
}
