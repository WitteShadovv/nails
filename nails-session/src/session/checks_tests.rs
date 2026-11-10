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
    // An entry below the hidden root, noauto or not: what to do names the
    // root.
    let below = judge_fstab(
        &decide("/dev/sdb1 /mnt/data/backup ext4 noauto 0 2\n", true),
        &[],
    );
    assert!(below.is_fail(), "{below:?}");
    assert!(
        below
            .message()
            .contains("/mnt/data/backup: refused (it lies at or below /mnt/data"),
        "{below:?}"
    );
    assert_eq!(
        below.remediation(),
        Some(
            "Mount the hidden volume where the decoy mounts nothing, or move this mount out \
             from below /mnt/data or remove it, before activating."
        ),
        "{below:?}"
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

/// The mount table line of a direct automount point at `point` that nothing
/// is mounted on yet, as systemd makes one for `x-systemd.automount`.
fn automount_line(point: &Path, id: u32) -> String {
    format!(
        "{id} 1 0:{id} / {} rw,relatime - autofs systemd-1 \
         rw,fd={id},pgrp=1,timeout=0,minproto=5,maxproto=5,direct,pipe_ino={id}\n",
        point.display()
    )
}

/// A snapshot of the decoy's root and an automount point at each of
/// `points` below `root`, nothing mounted on any.
fn automounts_below(root: &Path, points: &[&str]) -> Arc<Snapshot> {
    let mut table = "1 0 8:2 / / rw - ext4 /dev/vda2 rw\n".to_string();
    for (id, point) in (40..).zip(points) {
        table.push_str(&automount_line(&root.join(point), id));
    }
    Snapshot::from_table(parse_mountinfo(&table))
}

/// A unit directory behind an automount point that nothing is mounted on
/// yet is not looked up: the check refuses, naming the point, and gives
/// the fix that mounts it. With the point at mode 0 the refusal still names
/// the point, not a permission error, so no lookup below it was tried.
#[test]
fn a_unit_directory_behind_an_automount_point_refuses_naming_the_point() {
    use crate::filesystem::RealFilesystem;
    use std::os::unix::fs::PermissionsExt;

    if rustix::process::geteuid().is_root() {
        // Root looks into any directory, so a lookup would not show.
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    std::fs::create_dir_all(root.join("etc")).unwrap();
    std::fs::write(root.join("etc/fstab"), "/dev/vda2 / ext4 defaults 0 1\n").unwrap();
    let units = root.join("usr/local/lib/systemd/system/local-fs.target.wants");
    std::fs::create_dir_all(&units).unwrap();
    let usr_local = root.join("usr/local");
    std::fs::set_permissions(&usr_local, std::fs::Permissions::from_mode(0o000)).unwrap();
    let check = FstabPolicyCheck::new(root.clone(), PathBuf::from("/mnt/data"));
    let mounts = parse_mountinfo("1 0 8:2 / / rw - ext4 /dev/vda2 rw\n");

    let result = check.judge(
        &RealFilesystem,
        &automounts_below(&root, &["usr/local"]),
        &mounts,
    );
    std::fs::set_permissions(&usr_local, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(result.is_fail(), "{result:?}");
    assert_eq!(
        result.message(),
        format!(
            "/usr/local/lib/systemd/system/: refused (NAILS cannot list this unit directory: \
             NAILS does not look up {root}/usr/local/lib/systemd/system, since the lookup would \
             mount the automount point {root}/usr/local)",
            root = root.display()
        )
    );
    assert_eq!(
        result.remediation(),
        Some(crate::filesystem::automount::mount_fix(&[usr_local.as_path()]).as_str())
    );
    assert!(!result.message().contains("ermission"), "{result:?}");
    assert_eq!(result.allowable(), None);
}

/// An fstab mount point that is a direct automount point nothing is
/// mounted on yet, as an `x-systemd.automount` ESP is, is resolved from the
/// table without a lookup: it keeps its path and its decision. Looked up,
/// this one would lead elsewhere.
#[test]
fn an_automount_esp_in_the_fstab_keeps_its_decision_and_is_not_looked_up() {
    use crate::filesystem::RealFilesystem;

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    std::fs::create_dir_all(root.join("etc")).unwrap();
    std::fs::write(
        root.join("etc/fstab"),
        "/dev/vda2 / ext4 defaults 0 1\n\
         /dev/vda1 /boot/efi vfat noauto,x-systemd.automount,umask=0077 0 2\n",
    )
    .unwrap();
    std::fs::create_dir_all(root.join("boot")).unwrap();
    std::fs::create_dir_all(root.join("srv/elsewhere")).unwrap();
    std::os::unix::fs::symlink("../srv/elsewhere", root.join("boot/efi")).unwrap();
    let check = FstabPolicyCheck::new(root.clone(), PathBuf::from("/mnt/data"));
    let mounts = parse_mountinfo("1 0 8:2 / / rw - ext4 /dev/vda2 rw\n");

    let guarded = check.judge(
        &RealFilesystem,
        &automounts_below(&root, &["boot/efi"]),
        &mounts,
    );
    assert!(!guarded.is_fail(), "{guarded:?}");
    assert!(
        guarded.message().contains("/boot/efi: ") && !guarded.message().contains("elsewhere"),
        "{guarded:?}"
    );
    // Without the point in the table the lookup is made, and follows the
    // link, as before.
    let unguarded = check.judge(
        &RealFilesystem,
        &Snapshot::read(&RealFilesystem, &root),
        &mounts,
    );
    assert!(
        unguarded.message().contains("/srv/elsewhere: "),
        "{unguarded:?}"
    );
}

/// An fstab the guard does not look up refuses the entry with the guard's
/// reason and the fix that mounts the point, never the fix for a file root
/// cannot read.
#[test]
fn an_fstab_behind_an_automount_point_refuses_with_the_mount_fix() {
    use crate::filesystem::RealFilesystem;

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    std::fs::create_dir_all(root.join("etc")).unwrap();
    std::fs::write(root.join("etc/fstab"), "/dev/vda2 / ext4 defaults 0 1\n").unwrap();
    let check = FstabPolicyCheck::new(root.clone(), PathBuf::from("/mnt/data"));
    let result = check.judge(
        &RealFilesystem,
        &automounts_below(&root, &["etc"]),
        &parse_mountinfo("1 0 8:2 / / rw - ext4 /dev/vda2 rw\n"),
    );
    assert!(result.is_fail(), "{result:?}");
    assert_eq!(
        result.message(),
        format!(
            "{root}/etc/fstab cannot be read: NAILS does not look up {root}/etc/fstab, since the \
             lookup would mount the automount point {root}/etc",
            root = root.display()
        )
    );
    assert_eq!(
        result.remediation(),
        Some(crate::filesystem::automount::mount_fix(&[root.join("etc").as_path()]).as_str())
    );
}

/// An fstab whose way the guard cannot read, here through a loop of links,
/// is not looked up either: it cannot be read, and the check refuses with
/// that error and the fix for a file root cannot read.
#[test]
fn an_fstab_whose_way_cannot_be_read_fails_the_policy_check() {
    use crate::filesystem::RealFilesystem;

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    std::os::unix::fs::symlink("etc", root.join("etc")).unwrap();
    let check = FstabPolicyCheck::new(root.clone(), PathBuf::from("/mnt/data"));
    let result = check.judge(
        &RealFilesystem,
        &automounts_below(&root, &[]),
        &parse_mountinfo("1 0 8:2 / / rw - ext4 /dev/vda2 rw\n"),
    );
    assert!(result.is_fail(), "{result:?}");
    assert!(
        result.message().starts_with(&format!(
            "{root}/etc/fstab cannot be read: {root}/etc/fstab: ",
            root = root.display()
        )) && result.message().contains("(os error 40)"),
        "{result:?}"
    );
    assert!(
        result
            .remediation()
            .is_some_and(|fix| fix.contains("make the decoy's fstab readable by root")),
        "{result:?}"
    );
}

/// Without the mount table nothing is looked up, and the check refuses.
#[test]
fn without_the_mount_table_the_policy_check_looks_up_nothing() {
    let fs = crate::filesystem::MockFilesystem::new();
    fs.mock_set_mount_table_error("permission denied");
    let check = FstabPolicyCheck::new(PathBuf::from("/"), PathBuf::from("/mnt/data"));
    let result = check.run(&fs).unwrap();
    assert!(result.is_fail(), "{result:?}");
    assert!(
        result.message().starts_with(
            "NAILS cannot tell whether every decoy filesystem has a safe decision: NAILS cannot \
             read the mount table ("
        ),
        "{result:?}"
    );
    assert!(fs.mock_lookups().is_empty(), "{:?}", fs.mock_lookups());
}

/// A decoy root with the fstab `fstab` and a direct automount point at
/// `srv/point` that nothing is mounted on: the real folder there holds what
/// a link into the point leads to, so a lookup made through one anyway
/// reads it and changes the check's answer.
fn beside_a_point(fstab: &str) -> (tempfile::TempDir, PathBuf, Arc<Snapshot>) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    std::fs::create_dir_all(root.join("etc/systemd/system")).unwrap();
    std::fs::create_dir_all(root.join("srv/point/wants")).unwrap();
    std::fs::write(root.join("etc/fstab"), fstab).unwrap();
    let snapshot = automounts_below(&root, &["srv/point"]);
    (dir, root, snapshot)
}

/// fstab-policy's answer for the decoy root `root`, judged by `snapshot`.
fn judged(root: &Path, snapshot: &Arc<Snapshot>) -> CheckResult {
    FstabPolicyCheck::new(root.to_path_buf(), PathBuf::from("/mnt/data")).judge(
        &crate::filesystem::RealFilesystem,
        snapshot,
        &parse_mountinfo("1 0 8:2 / / rw - ext4 /dev/vda2 rw\n"),
    )
}

/// Whether `result` refuses with the fix that mounts the point of
/// [`beside_a_point`], naming it.
fn refuses_for_the_point(result: &CheckResult, root: &Path) -> bool {
    let point = root.join("srv/point");
    result.is_fail()
        && result.message().contains(&format!(
            "since the lookup would mount the automount point {}",
            point.display()
        ))
        && result.remediation()
            == Some(crate::filesystem::automount::mount_fix(&[point.as_path()]).as_str())
}

const ROOT_ONLY: &str = "/dev/vda2 / ext4 defaults 0 1\n";

/// A link at the end of a lookup is followed where the lookup follows it:
/// an fstab that links behind an automount point is not read.
#[test]
fn an_fstab_that_links_behind_an_automount_point_is_not_read() {
    let (_dir, root, snapshot) = beside_a_point(ROOT_ONLY);
    std::fs::write(root.join("srv/point/fstab"), ROOT_ONLY).unwrap();
    std::fs::remove_file(root.join("etc/fstab")).unwrap();
    std::os::unix::fs::symlink("../srv/point/fstab", root.join("etc/fstab")).unwrap();
    let result = judged(&root, &snapshot);
    assert!(refuses_for_the_point(&result, &root), "{result:?}");
    assert!(
        result.message().starts_with(&format!(
            "{root}/etc/fstab cannot be read: NAILS does not look up {root}/etc/fstab",
            root = root.display()
        )),
        "{result:?}"
    );
}

/// A directory of links that links behind an automount point is not listed,
/// as a `*.wants` directory made a link is: the check refuses, naming it.
#[test]
fn a_wants_directory_that_links_behind_an_automount_point_is_not_listed() {
    let (_dir, root, snapshot) = beside_a_point(ROOT_ONLY);
    std::os::unix::fs::symlink(
        "../../../srv/point/wants",
        root.join("etc/systemd/system/local-fs.target.wants"),
    )
    .unwrap();
    let result = judged(&root, &snapshot);
    assert!(refuses_for_the_point(&result, &root), "{result:?}");
    assert!(
        result.message().contains(&format!(
            "/etc/systemd/system/local-fs.target.wants: refused (NAILS cannot list this unit \
             directory: NAILS does not look up {}/etc/systemd/system/local-fs.target.wants,",
            root.display()
        )),
        "{result:?}"
    );
}

/// A unit file that links behind an automount point is not resolved: where
/// it leads, here a mask, is not looked up, and the check cannot tell
/// whether it masks the unit, a mount unit `local-fs.target` wants.
#[test]
fn a_unit_that_links_behind_an_automount_point_is_not_resolved() {
    let (_dir, root, snapshot) = beside_a_point(ROOT_ONLY);
    let units = root.join("etc/systemd/system");
    std::fs::create_dir_all(units.join("local-fs.target.wants")).unwrap();
    std::os::unix::fs::symlink(
        "../data.mount",
        units.join("local-fs.target.wants/data.mount"),
    )
    .unwrap();
    std::os::unix::fs::symlink("/dev/null", root.join("srv/point/data.mount")).unwrap();
    std::os::unix::fs::symlink("../../../srv/point/data.mount", units.join("data.mount")).unwrap();
    let result = judged(&root, &snapshot);
    assert!(refuses_for_the_point(&result, &root), "{result:?}");
    assert!(
        result.message().contains(&format!(
            "NAILS does not look up {}/etc/systemd/system/data.mount,",
            root.display()
        )),
        "{result:?}"
    );
}

/// A mount point in the fstab that links behind an automount point is not
/// resolved: it keeps its path as written, and the check refuses it.
#[test]
fn a_mount_point_that_links_behind_an_automount_point_keeps_its_path() {
    let (_dir, root, snapshot) =
        beside_a_point(&format!("{ROOT_ONLY}/dev/vdb1 /data ext4 defaults 0 2\n"));
    std::fs::create_dir_all(root.join("srv/point/data")).unwrap();
    std::os::unix::fs::symlink("srv/point/data", root.join("data")).unwrap();
    let result = judged(&root, &snapshot);
    assert!(refuses_for_the_point(&result, &root), "{result:?}");
    assert!(
        result
            .message()
            .contains(&format!("NAILS does not look up {}/data,", root.display())),
        "{result:?}"
    );
    assert!(!result.message().contains("/srv/point/data"), "{result:?}");
}

/// A decision for a path the guard did not look up asks only for the mount;
/// any other refusal keeps its own fix.
#[test]
fn a_refusal_of_a_path_not_looked_up_leaves_the_fix_to_the_guard() {
    let refused = vec![Decision::Refuse {
        target: PathBuf::from("/usr/local/lib/systemd/system"),
        reason: "NAILS cannot list this unit directory: it is not looked up".to_string(),
        below: None,
    }];
    let skipped = |target: &Path| target == Path::new("/usr/local/lib/systemd/system");
    let result = judge_fstab_not_looked_up(&refused, &[], &skipped);
    assert!(result.is_fail());
    assert_eq!(result.remediation(), None);
    let result = judge_fstab_not_looked_up(&refused, &[], &|_| false);
    assert!(
        result
            .remediation()
            .is_some_and(|fix| fix.starts_with("Fix the fstab entry")),
        "{result:?}"
    );
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
        guard: None,
    };
    let mounts = parse_mountinfo("1 0 8:2 / / rw - ext4 /dev/vda2 rw\n");
    // Its disk is not on this host, and a target only wants it: masked.
    let decisions = decoy_units(dirs, &[], &mounts, Path::new("/mnt/data"));
    assert_eq!(decisions.len(), 1, "{decisions:?}");
    assert_eq!(decisions[0].masked_units(), ["srv-scratch.mount"]);
}
