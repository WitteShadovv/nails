// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the mounts a skipped unit pulls in.

use super::*;

/// What the hidden session keeps off for the fstab `fstab`, decided with
/// the decoy's mount table `mounts` and every device there, and the
/// warnings.
fn kept(decoy: &Decoy, fstab: &str, mounts: &str) -> (KeptOff, Vec<String>) {
    let decisions = policy::decide_all(
        &crate::session::fstab::parse_fstab(fstab),
        &parse_mountinfo(mounts),
        Path::new(HIDDEN),
        &|_| true,
    );
    decoy.kept_off(fstab, &decisions)
}

/// The causes `kept` records for its masked units that a target requires.
fn causes(kept: &KeptOff) -> Vec<(String, MaskCause)> {
    kept.required_masks
        .iter()
        .map(|mask| (mask.unit.clone(), mask.cause))
        .collect()
}

#[test]
fn a_skip_that_pulls_in_a_decoy_mount_nothing_keeps_off_is_masked() {
    // /srv/data is skipped, and systemd has its mount require the mount of
    // its parent directory, /srv: a noauto line the policy leaves as it is,
    // which the hidden systemd would mount read-write before the skip's
    // condition is tested. So for a mount its fstab line, its unit files or
    // a path's mount names.
    let child = "/dev/vdc1 /srv/data ext4 defaults 0 2\n";
    for (fstab, files, how) in [
        (
            "/dev/vdb1 /srv ext4 noauto 0 2\n",
            &[][..],
            "the mount of a parent directory",
        ),
        (
            "/dev/vdb2 /srv/b ext4 noauto 0 2\n\
             /dev/vdc1 /srv/data ext4 defaults,x-systemd.requires=/srv/b 0 2\n",
            &[][..],
            "x-systemd.requires= on its fstab line",
        ),
        (
            "/dev/vdb2 /srv/b ext4 noauto 0 2\n\
             /dev/vdc1 /srv/data ext4 defaults,x-systemd.requires-mounts-for=/srv/b/c 0 2\n",
            &[][..],
            "x-systemd.requires-mounts-for= on its fstab line",
        ),
        (
            "/dev/vdb2 /srv/b ext4 noauto 0 2\n",
            &[(
                "/run/systemd/generator/srv-data.mount",
                "[Unit]\nSourcePath=/etc/fstab\nRequiresMountsFor=/srv/b\n\
                 [Mount]\nWhat=/dev/vdc1\nWhere=/srv/data\nType=ext4\n",
            )][..],
            "its RequiresMountsFor=",
        ),
        // A mount unit of the decoy's own that no target links.
        (
            "",
            &[
                (
                    "/etc/systemd/system/srv-c.mount",
                    "[Mount]\nWhat=/dev/vdz1\nWhere=/srv/c\nType=ext4\n",
                ),
                (
                    "/run/systemd/generator/srv-data.mount",
                    "[Unit]\nSourcePath=/etc/fstab\nRequires=srv-c.mount\n\
                     [Mount]\nWhat=/dev/vdc1\nWhere=/srv/data\nType=ext4\n",
                ),
            ][..],
            "its Requires=",
        ),
    ] {
        let decoy = Decoy::new();
        for (path, text) in files {
            decoy.write(path, text);
        }
        let lines = if fstab.contains("/srv/data") {
            fstab.to_string()
        } else {
            format!("{fstab}{child}")
        };
        let (kept, warnings) = kept(&decoy, &lines, ROOT_ONLY);
        assert!(kept.skips.is_empty(), "{how}: {:?}", kept.skips);
        assert!(kept.masks.contains(&"srv-data.mount".to_string()), "{how}");
        assert_eq!(
            causes(&kept),
            [("srv-data.mount".to_string(), MaskCause::PullsInMount)],
            "{how}"
        );
        assert_eq!(warnings.len(), 1, "{how}: {warnings:?}");
        for part in [
            "srv-data.mount is masked rather than skipped",
            how,
            "decoy's disk",
        ] {
            assert!(warnings[0].contains(part), "{part}: {}", warnings[0]);
        }
    }
}

#[test]
fn a_skip_whose_pulls_mount_nothing_of_a_disk_stays_a_skip() {
    let child = "/dev/vdc1 /srv/data ext4 defaults 0 2\n";
    for (fstab, mounts) in [
        // The parent is a tmpfs, or a host share.
        ("tmpfs /srv tmpfs defaults 0 0\n", ROOT_ONLY),
        ("share /srv virtiofs defaults 0 0\n", ROOT_ONLY),
        // The parent is mounted now: the session overlays it.
        (
            "/dev/vdb1 /srv ext4 defaults 0 2\n",
            "1 0 8:2 / / rw - ext4 /dev/vda2 rw\n2 1 8:17 / /srv rw - ext4 /dev/vdb1 rw\n",
        ),
        // The parent is skipped as well: a target requires it too.
        ("/dev/vdb1 /srv ext4 defaults 0 2\n", ROOT_ONLY),
        // No unit file and no line: nothing to start.
        ("", ROOT_ONLY),
    ] {
        let decoy = Decoy::new();
        let (kept, warnings) = kept(&decoy, &format!("{fstab}{child}"), mounts);
        assert!(
            kept.skips
                .iter()
                .any(|skip| skip.units == ["srv-data.mount"]),
            "{fstab}: {:?}",
            kept.skips
        );
        assert!(warnings.is_empty(), "{fstab}: {warnings:?}");
    }
}

#[test]
fn a_unit_of_another_kind_named_by_a_specifier_is_no_pull() {
    // The fstab generator's makefs unit for a skipped mount binds to its
    // device by a specifier: no mount, so the skip holds.
    let decoy = Decoy::new();
    decoy.write(
        "/run/systemd/generator/systemd-makefs@dev-vdc1.service",
        "[Unit]\nBindsTo=%i.device\nAfter=%i.device\nBefore=systemd-fsck@%i.service srv-data.mount\n\
         [Service]\nType=oneshot\n",
    );
    let (skipped, warnings) = kept(
        &decoy,
        "/dev/vdc1 /srv/data ext4 defaults,x-systemd.makefs 0 2\n",
        ROOT_ONLY,
    );
    assert_eq!(skipped.skips.len(), 1, "{:?}", skipped.masks);
    assert!(
        skipped.skips[0]
            .pulled
            .contains(&"systemd-makefs@dev-vdc1.service".to_string())
    );
    assert!(warnings.is_empty(), "{warnings:?}");
    // A mount named by a specifier is one NAILS cannot tell.
    decoy.write(
        "/run/systemd/generator/systemd-makefs@dev-vdc1.service",
        "[Unit]\nRequires=srv-%i.mount\n[Service]\nType=oneshot\n",
    );
    let (masked, warnings) = kept(
        &decoy,
        "/dev/vdc1 /srv/data ext4 defaults,x-systemd.makefs 0 2\n",
        ROOT_ONLY,
    );
    assert!(masked.skips.is_empty(), "{:?}", masked.skips);
    assert_eq!(
        causes(&masked),
        [("srv-data.mount".to_string(), MaskCause::Undetermined)]
    );
    assert_eq!(warnings.len(), 1, "{warnings:?}");
}

#[test]
fn a_skip_that_requires_a_masked_mount_is_warned_of() {
    // The parent has nofail and is not mounted now: masked. The child is
    // skipped, but PID 1 cannot start it with its parent masked, so the
    // boot target that requires it is not reached.
    let decoy = Decoy::new();
    let (kept, warnings) = kept(
        &decoy,
        "/dev/vdb1 /srv ext4 nofail 0 2\n/dev/vdc1 /srv/data ext4 defaults 0 2\n",
        ROOT_ONLY,
    );
    assert_eq!(kept.masks, ["srv.mount"]);
    assert_eq!(kept.skips.len(), 1, "{:?}", kept.skips);
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    for part in [
        "srv-data.mount is skipped, but it requires srv.mount",
        "the mount of a parent directory",
        "not reached",
    ] {
        assert!(warnings[0].contains(part), "{part}: {}", warnings[0]);
    }
}

#[test]
fn the_mounts_a_unit_pulls_in_are_read_from_every_source_each_once() {
    let decoy = Decoy::new();
    decoy.write(
        "/etc/systemd/system/srv-data-sub.mount",
        "[Unit]\nRequires=srv-a.mount systemd-fsck@dev-vdc1.service\nWants=srv-b.mount\n\
         BindsTo=srv-a.mount\nWantsMountsFor=/srv/w\n\
         [Mount]\nWhat=/dev/vdc1\nWhere=/srv/data/sub\nType=ext4\n",
    );
    decoy.link(
        "/etc/systemd/system/srv-data-sub.mount.upholds/srv-u.mount",
        "../srv-u.mount",
    );
    let fstab = crate::session::fstab::parse_fstab(
        "/dev/vdc1 /srv/data/sub ext4 x-systemd.requires=/dev/vdq1,x-systemd.requires=srv-r.swap 0 2\n",
    );
    let pulled = pulls::mount_pulls(decoy.dirs(), "srv-data-sub.mount", &fstab).unwrap();
    let shown: Vec<(&str, bool)> = pulled
        .iter()
        .map(|pull| (pull.unit.as_str(), pull.required))
        .collect();
    assert_eq!(
        shown,
        [
            ("srv-data.mount", true),
            ("srv.mount", true),
            ("srv-a.mount", true),
            ("srv-b.mount", false),
            ("srv-w.mount", false),
            ("srv-u.mount", false),
            ("srv-r.swap", true),
        ]
    );
    // A swap file's directories, and none for a swap on a device.
    assert_eq!(
        pulls::mount_pulls(decoy.dirs(), "srv-swap-file.swap", &[])
            .unwrap()
            .iter()
            .map(|pull| pull.unit.as_str())
            .collect::<Vec<_>>(),
        ["srv-swap.mount", "srv.mount"]
    );
    assert!(
        pulls::mount_pulls(decoy.dirs(), "dev-vda5.swap", &[])
            .unwrap()
            .is_empty()
    );
}
