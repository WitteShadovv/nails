// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the session's pre-flight checks.

use super::*;
use nails_teardown::mountinfo::parse_mountinfo;

#[test]
fn old_systemd_is_refused_naming_the_unsupported_releases() {
    assert!(judge_version(Some(254)).is_pass());
    assert!(judge_version(Some(259)).is_pass());
    let old = judge_version(Some(252));
    assert!(old.is_fail());
    assert!(old.message().contains("252"));
    assert!(old.remediation().unwrap().contains("bookworm"));
    assert!(old.remediation().unwrap().contains("22.04"));
    assert!(judge_version(None).is_fail());
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
fn only_the_plain_decoy_may_activate() {
    assert!(judge_session(&SessionView::Decoy).is_pass());
    assert!(judge_session(&SessionView::HiddenWithoutPlan("x".into())).is_fail());
    let interrupted = judge_session(&SessionView::Interrupted {
        plan: None,
        nextroot_mounted: true,
    });
    assert!(interrupted.remediation().unwrap().contains("nails recover"));
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
