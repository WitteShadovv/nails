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
fn masked_filesystems_warn_and_a_refusal_fails() {
    let mounts = parse_mountinfo(
        "1 0 8:2 / / rw - ext4 /dev/vda2 rw\n2 1 8:1 / /boot rw - vfat /dev/vda1 rw\n",
    );
    let decide =
        |text: &str| policy::decide_all(&parse_fstab(text), &mounts, Path::new("/mnt/data"));
    let boot = judge_fstab(&decide(
        "/dev/vda1 /boot vfat defaults 0 2\n/dev/vda3 none swap sw 0 0\n",
    ));
    assert!(boot.is_pass(), "{boot:?}");
    assert!(boot.message().contains("/boot: read-only"));
    assert!(judge_fstab(&decide("/dev/sdb1 /data ext4 defaults 0 2\n")).is_warn());
    assert!(judge_fstab(&decide("/dev/sdb1 data ext4 defaults 0 2\n")).is_fail());
}

/// The check decides a symlinked mount point where activation does, at its
/// real path inside the decoy root, so `nails check` names the unit the
/// hidden session masks.
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
    assert!(
        result.message().contains("/var/nails-check-home: masked"),
        "{result:?}"
    );
    assert!(!result.message().contains("/home: masked"), "{result:?}");
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

fn inhibitor(what: &str, mode: &str) -> logind::Inhibitor {
    logind::Inhibitor {
        what: what.to_string(),
        who: "fwupd".to_string(),
        why: "Firmware update in progress".to_string(),
        mode: mode.to_string(),
        pid: 977,
    }
}

/// A program that blocks shutdown outright refuses the entry, named, with what
/// to do, and so does a logind that did not answer; a delay or a weak block
/// does not, nor does a logind that does not run.
#[test]
fn a_program_that_blocks_shutdown_refuses_the_entry() {
    let blocked = judge_blocking(&logind::Blocking::By(inhibitor("sleep:shutdown", "block")));
    assert!(blocked.is_fail());
    assert!(
        blocked
            .message()
            .contains("fwupd blocks shutdown (Firmware update in progress, PID 977)"),
        "{}",
        blocked.message()
    );
    assert_eq!(
        blocked.remediation(),
        Some("Let it finish, then activate again.")
    );
    assert!(judge_blocking(&logind::Blocking::Nothing).is_pass());
    let unknown = judge_blocking(&logind::Blocking::Unknown);
    assert!(unknown.is_fail());
    assert!(
        unknown
            .message()
            .starts_with("logind did not answer whether a program blocks shutdown"),
        "{}",
        unknown.message()
    );
    assert_eq!(
        unknown.remediation(),
        Some("Make sure systemd-logind runs and answers, then activate again.")
    );
    for (what, mode) in [
        ("shutdown", "delay"),
        ("shutdown", "block-weak"),
        ("handle-lid-switch", "block"),
        ("sleep", "block"),
    ] {
        assert!(!inhibitor(what, mode).blocks_shutdown(), "{what} {mode}");
    }
    assert!(inhibitor("sleep:shutdown", "block").blocks_shutdown());
}
