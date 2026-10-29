// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the session's pre-flight checks.

use super::*;
use crate::session::fstab::parse_fstab;
use nails_teardown::mountinfo::parse_mountinfo;

/// The host detection finds for `os_release` on a systemd machine.
fn host(os_release: &str) -> HostProfile {
    let fs = crate::filesystem::MockFilesystem::new();
    fs.mock_add_file("/etc/os-release", os_release);
    fs.mock_add_file("/proc/1/comm", "systemd");
    crate::platform::detect(&fs).expect("detection reads through the mock")
}

#[test]
fn a_systemd_new_enough_passes_on_any_host() {
    assert!(judge_version(Some(254), None).is_pass());
    assert!(judge_version(Some(259), Some(&host("ID=arch\n"))).is_pass());
    let unread = judge_version(None, Some(&host("ID=debian\nVERSION_ID=\"13\"\n")));
    assert!(unread.is_fail());
    assert!(unread.remediation().unwrap().contains("systemd host"));
}

/// Each family is told the way its own distribution upgrades, not the Debian
/// and Ubuntu releases.
#[test]
fn an_old_systemd_is_refused_with_how_the_host_upgrades() {
    for (os_release, version, way) in [
        (
            "ID=debian\nVERSION_ID=\"12\"\n",
            252,
            "Debian 13 as its release notes describe",
        ),
        (
            "ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"22.04\"\n",
            249,
            "Ubuntu 24.04 or 26.04 with `do-release-upgrade`",
        ),
        (
            "ID=fedora\nVERSION_ID=38\n",
            253,
            "Fedora 44 with `dnf system-upgrade`",
        ),
        ("ID=arch\n", 253, "`pacman -Syu`"),
        ("ID=endeavouros\nID_LIKE=arch\n", 253, "`pacman -Syu`"),
        (
            "ID=nixos\nVERSION_ID=\"23.05\"\n",
            253,
            "a current NixOS release",
        ),
    ] {
        let profile = host(os_release);
        let old = judge_version(Some(version), Some(&profile));
        assert!(old.is_fail(), "{os_release}: {old:?}");
        assert!(
            old.message()
                .contains(&format!("systemd {version} is too old")),
            "{old:?}"
        );
        let remediation = old.remediation().unwrap();
        assert_eq!(remediation, upgrade_hint(Some(&profile)), "{os_release}");
        assert!(remediation.contains(way), "{os_release}: {remediation}");
    }

    // Without a detected host, the hint names the platforms NAILS runs on.
    let unknown = judge_version(Some(252), None);
    assert!(
        unknown
            .remediation()
            .unwrap()
            .contains("a release NAILS supports (Debian 13, Ubuntu 24.04 and 26.04)"),
        "{unknown:?}"
    );
}

/// `run` judges the version the check was built with on the host it was built
/// on: a Debian 12 host is told the Debian upgrade, a check built without a
/// host names the platforms NAILS runs on, and one without a version fails.
#[test]
fn the_check_judges_its_version_on_its_host() {
    let run = |check: SystemdVersionCheck| {
        check
            .run(&crate::filesystem::MockFilesystem::new())
            .unwrap()
    };
    let debian = || Some(host("ID=debian\nVERSION_ID=\"12\"\n"));

    let old = run(SystemdVersionCheck::new(Some(252), debian()));
    assert!(old.is_fail(), "{old:?}");
    assert_eq!(
        old.remediation(),
        Some("Upgrade to Debian 13 as its release notes describe, then reboot."),
        "{old:?}"
    );

    let without = run(SystemdVersionCheck::new(Some(252), None));
    assert_eq!(
        without.remediation(),
        Some(upgrade_hint(None).as_str()),
        "{without:?}"
    );

    assert!(run(SystemdVersionCheck::new(Some(254), debian())).is_pass());
    let unread = run(SystemdVersionCheck::new(None, debian()));
    assert!(unread.is_fail(), "{unread:?}");
    assert!(
        unread.message().contains("could not read the version"),
        "{unread:?}"
    );
}

#[test]
fn missing_units_on_nixos_come_with_the_module_snippet() {
    let root = tempfile::tempdir().unwrap();
    let result = judge_units(root.path(), true);
    assert!(result.is_fail());
    assert!(
        result
            .remediation()
            .unwrap()
            .contains("SuccessAction=soft-reboot-force")
    );
    assert!(
        !judge_units(root.path(), false)
            .remediation()
            .unwrap()
            .contains("nixpkgs")
    );
}

#[test]
fn an_impermanent_root_is_refused() {
    let ram = parse_mountinfo("1 0 0:20 / / rw - tmpfs none rw\n");
    assert!(judge_decoy_root(&ram, Path::new("/")).is_fail());
    let disk = parse_mountinfo("1 0 8:2 / / rw - ext4 /dev/vda2 rw\n");
    assert!(judge_decoy_root(&disk, Path::new("/")).is_pass());
}

#[test]
fn a_btrfs_subvolume_root_passes_but_a_bind_of_a_folder_is_refused() {
    let subvol = parse_mountinfo("1 0 0:30 /@ / rw - btrfs /dev/nvme0n1p2 rw,subvol=/@\n");
    assert!(judge_decoy_root(&subvol, Path::new("/")).is_pass());
    let bind = parse_mountinfo("1 0 0:30 /@/srv / rw - btrfs /dev/nvme0n1p2 rw,subvol=/@\n");
    assert!(judge_decoy_root(&bind, Path::new("/")).is_fail());
}

#[test]
fn only_the_plain_decoy_may_activate() {
    assert!(judge_session(&SessionView::Decoy).is_pass());
    assert!(judge_session(&SessionView::HiddenWithoutPlan("x".into())).is_fail());
    let interrupted = judge_session(&SessionView::Interrupted {
        plan: None,
        nextroot_mounted: true,
    });
    let remedy = interrupted.remediation().unwrap();
    assert!(
        remedy.contains("sudo ") && remedy.contains("recover"),
        "{remedy}"
    );
}

#[test]
fn filesystems_kept_off_warn_and_a_refusal_fails() {
    let mounts = parse_mountinfo(
        "1 0 8:2 / / rw - ext4 /dev/vda2 rw\n2 1 8:1 / /boot rw - vfat /dev/vda1 rw\n",
    );
    let decide = |text: &str, present: bool| {
        policy::decide_all(&parse_fstab(text), &mounts, Path::new("/mnt/data"), &|_| {
            present
        })
    };
    // Swap is never available, skipped or masked: nothing to warn about while
    // its device is there.
    let boot = judge_fstab(
        &decide(
            "/dev/vda1 /boot vfat defaults 0 2\n/dev/vda3 none swap sw 0 0\n",
            true,
        ),
        &[],
    );
    assert!(boot.is_pass(), "{boot:?}");
    assert!(boot.message().contains("/boot: read-only"));
    assert!(boot.message().contains("/dev/vda3: skipped"), "{boot:?}");
    let data = judge_fstab(&decide("/dev/sdb1 /data ext4 defaults 0 2\n", true), &[]);
    assert!(data.is_warn(), "{data:?}");
    assert!(data.message().contains("/data: skipped"), "{data:?}");
    assert!(
        data.message()
            .contains("not available in the hidden session")
    );
    let refused = judge_fstab(&decide("/dev/sdb1 data ext4 defaults 0 2\n", true), &[]);
    assert!(refused.is_fail());
    assert!(
        refused
            .remediation()
            .is_some_and(|remedy| remedy.contains("fstab entry or the unit directory")),
        "{refused:?}"
    );
    // A skip masked instead, as NAILS cannot tell what it pulls in, warns.
    let unskipped = judge_fstab(
        &decide("/dev/vda1 /boot vfat defaults 0 2\n", true),
        &["srv-x.mount is masked rather than skipped".to_string()],
    );
    assert!(unskipped.is_warn(), "{unskipped:?}");
    assert!(
        unskipped
            .message()
            .contains("srv-x.mount is masked rather than skipped."),
        "{unskipped:?}"
    );
}

#[test]
fn a_mask_that_leaves_a_boot_target_unreached_warns_with_how_to_avoid_it() {
    // The swap partition and the disk are not there: their units are masked,
    // and swap.target and local-fs.target are not reached.
    let mounts = parse_mountinfo("1 0 8:2 / / rw - ext4 /dev/vda2 rw\n");
    let decisions = policy::decide_all(
        &parse_fstab("/dev/vda3 none swap sw 0 0\n/dev/sdb1 /data ext4 defaults 0 2\n"),
        &mounts,
        Path::new("/mnt/data"),
        &|_| false,
    );
    let result = judge_fstab(&decisions, &[]);
    assert!(result.is_warn(), "{result:?}");
    let message = result.message();
    for part in [
        "/dev/vda3: masked",
        "/data: masked",
        "the hidden session will not reach swap.target",
        "the hidden session will not reach local-fs.target",
        "nofail",
    ] {
        assert!(message.contains(part), "{part}: {message}");
    }
}

/// The check decides a symlinked mount point where activation does, at its
/// real path inside the decoy root, so `nails check` names the unit the
/// hidden session keeps off.
#[test]
fn the_policy_check_decides_a_symlinked_mount_point_at_its_real_path() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("etc")).unwrap();
    std::fs::create_dir_all(root.path().join("var/nails-check-home")).unwrap();
    std::os::unix::fs::symlink("var/nails-check-home", root.path().join("home")).unwrap();
    std::fs::write(
        root.path().join("etc/fstab"),
        "/dev/sdb1 /home ext4 defaults,x-systemd.automount 0 2\n",
    )
    .unwrap();
    let check = FstabPolicyCheck::new(root.path().to_path_buf(), PathBuf::from("/mnt/data"));
    let result = check
        .run(&crate::filesystem::MockFilesystem::new())
        .unwrap();
    // local-fs.target requires the automount, which waits for no device: it
    // is skipped, whatever the host's devices.
    assert!(
        result.message().contains("/var/nails-check-home: skipped"),
        "{result:?}"
    );
    assert!(!result.message().contains("/home: skipped"), "{result:?}");
}

/// An fstab that cannot be read fails the check: taken for an empty one, it
/// would leave every decoy filesystem without a decision.
#[test]
fn an_unreadable_fstab_fails_the_policy_check() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("etc/fstab")).unwrap();
    let check = FstabPolicyCheck::new(root.path().to_path_buf(), PathBuf::from("/mnt/data"));
    let result = check
        .run(&crate::filesystem::MockFilesystem::new())
        .unwrap();
    assert!(result.is_fail(), "{result:?}");
    assert!(
        result.message().contains("etc/fstab cannot be read"),
        "{result:?}"
    );

    // A root without an fstab has nothing to decide.
    std::fs::remove_dir(root.path().join("etc/fstab")).unwrap();
    let result = check
        .run(&crate::filesystem::MockFilesystem::new())
        .unwrap();
    assert!(result.is_pass(), "{result:?}");
}

#[test]
fn the_decoy_s_units_outside_its_fstab_are_decided_as_activation_decides_them() {
    let root = tempfile::tempdir().unwrap();
    let run = tempfile::tempdir().unwrap();
    let units = root.path().join("etc/systemd/system");
    std::fs::create_dir_all(units.join("local-fs.target.wants")).unwrap();
    std::fs::write(
        units.join("srv-scratch.mount"),
        "[Mount]\nWhat=/dev/disk/by-id/nails-test-no-such-disk\nWhere=/srv/scratch\nType=ext4\n",
    )
    .unwrap();
    std::os::unix::fs::symlink(
        "../srv-scratch.mount",
        units.join("local-fs.target.wants/srv-scratch.mount"),
    )
    .unwrap();
    let dirs = crate::session::mount_units::UnitDirs {
        root: root.path(),
        run: run.path(),
    };
    let mounts = parse_mountinfo("1 0 8:2 / / rw - ext4 /dev/vda2 rw\n");
    // Its disk is not on this host, and a target only wants it: masked.
    let decisions = decoy_units(dirs, &mounts, Path::new("/mnt/data"));
    assert_eq!(decisions.len(), 1, "{decisions:?}");
    assert_eq!(decisions[0].masked_units(), ["srv-scratch.mount"]);
}
