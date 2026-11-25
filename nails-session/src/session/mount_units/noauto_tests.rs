// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the mask of a `noauto` line of a decoy disk, as the units
//! outside the fstab meet it.

use super::*;

/// The fstab decisions for `fstab` and those of the units outside it, with
/// every device there, and what the hidden session keeps off for them, with
/// the warnings.
fn kept(decoy: &Decoy, fstab: &str) -> (Vec<Decision>, KeptOff, Vec<String>) {
    kept_with(decoy, fstab, true)
}

/// [`kept`] with every device there or none (`present`).
fn kept_with(decoy: &Decoy, fstab: &str, present: bool) -> (Vec<Decision>, KeptOff, Vec<String>) {
    let mut decisions = policy::decide_all(
        &crate::session::fstab::parse_fstab(fstab),
        &parse_mountinfo(ROOT_ONLY),
        Path::new(HIDDEN),
        &|_| present,
    );
    decisions.extend(decoy.decide_with(fstab, ROOT_ONLY, present));
    let (kept, warnings) = decoy.kept_off_with(fstab, &decisions, present);
    (decisions, kept, warnings)
}

/// The fstab line of the decoy disk the tmpfs puller requires.
const PULLED_LINE: &str = "/dev/vdy1 /r/a ext4 noauto 0 2\n";

/// A tmpfs mount unit outside the fstab whose `Requires=` names the mount
/// of the noauto line [`PULLED_LINE`], linked into local-fs.target's
/// `links` directory (`wants` or `requires`).
fn tmpfs_puller(links: &str) -> Decoy {
    let decoy = Decoy::new();
    decoy.write(
        "/etc/systemd/system/r-t9.mount",
        "[Unit]\nRequires=r-a.mount\nAfter=r-a.mount\n[Mount]\nWhat=tmpfs\nWhere=/r/t9\nType=tmpfs\n",
    );
    decoy.link(
        &format!("/etc/systemd/system/local-fs.target.{links}/r-t9.mount"),
        "../r-t9.mount",
    );
    decoy
}

/// A mount unit file outside the fstab, a tmpfs that local-fs.target wants,
/// whose `Requires=` names the mount of a noauto line of a decoy disk. next
/// left the line as never mounted and the tmpfs to the hidden systemd,
/// which started the tmpfs and with it mounted the disk read-write. The
/// line is masked, mount and automount, whatever pulls it in; the tmpfs is
/// left as before, and as no target requires it, nothing is warned of: the
/// hidden systemd cannot start it, and the target is reached.
#[test]
fn a_noauto_line_a_unit_file_pulls_in_is_masked() {
    let decoy = tmpfs_puller("wants");
    let (decisions, kept, warnings) = kept(&decoy, PULLED_LINE);
    assert!(
        decisions.contains(&Decision::Leave {
            target: "/r/t9".into(),
            reason: "RAM or kernel filesystem",
        }),
        "{decisions:?}"
    );
    for unit in ["r-a.mount", "r-a.automount"] {
        assert!(
            kept.masks.iter().any(|mask| mask == unit),
            "{unit}: {kept:?}"
        );
    }
    assert!(kept.skips.is_empty(), "{kept:?}");
    assert!(kept.required_masks.is_empty(), "{kept:?}");
    assert!(warnings.is_empty(), "{warnings:?}");
}

/// The tmpfs of [`a_noauto_line_a_unit_file_pulls_in_is_masked`] linked into
/// local-fs.target.requires: NAILS reads that the target requires it, and
/// its `Requires=`, so the noauto line is kept off as a line the boot
/// mounts. Its disk is there: the mount is skipped with its fsck, and the
/// tmpfs and the target start without it.
#[test]
fn a_noauto_line_a_unit_a_target_requires_needs_is_skipped() {
    let decoy = tmpfs_puller("requires");
    let (_, kept, warnings) = kept(&decoy, PULLED_LINE);
    assert!(
        kept.skips.contains(&Skip {
            units: vec!["r-a.mount".into()],
            pulled: vec!["systemd-fsck@dev-vdy1.service".into()],
            device: Some("/dev/vdy1".into()),
        }),
        "{kept:?}"
    );
    assert!(
        !kept.masks.iter().any(|mask| mask == "r-a.mount"),
        "{kept:?}"
    );
    // The line's automount stays masked: nothing needs it.
    assert!(
        kept.masks.iter().any(|mask| mask == "r-a.automount"),
        "{kept:?}"
    );
    assert_eq!(kept.noauto_masks, ["r-a.automount"], "{kept:?}");
    assert!(kept.required_masks.is_empty(), "{kept:?}");
    assert!(warnings.is_empty(), "{warnings:?}");
}

/// The same without the disk: the mount stays masked, recorded with its
/// device, and the warning names the unit that requires it and its target.
#[test]
fn a_noauto_line_a_unit_a_target_requires_needs_is_warned_of_without_its_disk() {
    let decoy = tmpfs_puller("requires");
    let (_, kept, warnings) = kept_with(&decoy, PULLED_LINE, false);
    assert!(
        kept.masks.iter().any(|mask| mask == "r-a.mount"),
        "{kept:?}"
    );
    assert!(kept.skips.is_empty(), "{kept:?}");
    assert_eq!(
        kept.required_masks,
        [RequiredMask {
            unit: "r-a.mount".into(),
            cause: MaskCause::DeviceAbsent,
            device: Some("/dev/vdy1".into()),
        }]
    );
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    for part in [
        "r-a.mount is masked rather than skipped, as its device /dev/vdy1 is not there",
        "r-t9.mount, which local-fs.target requires, requires r-a.mount (Requires=), the mount \
         of a noauto line of a decoy disk, so the hidden session will not reach local-fs.target",
        "or have local-fs.target want r-t9.mount rather than require it",
    ] {
        assert!(warnings[0].contains(part), "{part}: {warnings:?}");
    }
}

/// A unit file in /etc of the noauto line's name, a tmpfs, outranks the
/// unit the fstab generator makes of the line: the hidden systemd loads the
/// tmpfs, which the unit pass decided. The mask yields to that decision,
/// whether the target requires the tmpfs or wants it.
#[test]
fn a_unit_file_that_outranks_a_noauto_line_s_unit_is_decided_as_a_unit() {
    for links in ["requires", "wants"] {
        let decoy = Decoy::new();
        decoy.write(
            "/etc/systemd/system/r-a.mount",
            "[Mount]\nWhat=tmpfs\nWhere=/r/a\nType=tmpfs\n",
        );
        decoy.link(
            &format!("/etc/systemd/system/local-fs.target.{links}/r-a.mount"),
            "../r-a.mount",
        );
        let (decisions, kept, warnings) = kept(&decoy, PULLED_LINE);
        assert!(
            decisions.contains(&Decision::Leave {
                target: "/r/a".into(),
                reason: "RAM or kernel filesystem",
            }),
            "{links}: {decisions:?}"
        );
        assert!(
            !kept.masks.iter().any(|mask| mask == "r-a.mount"),
            "{links}: {kept:?}"
        );
        assert!(kept.required_masks.is_empty(), "{links}: {kept:?}");
        assert!(warnings.is_empty(), "{links}: {warnings:?}");
    }
}

/// The tmpfs unit file of the noauto line's name in /usr/lib, which the
/// fstab generator's unit of the line outranks: NAILS cannot tell which of
/// them the hidden systemd loads, so the mount stays masked, recorded where
/// the target requires the tmpfs, and warned of.
#[test]
fn a_unit_file_a_noauto_line_s_unit_outranks_is_a_conflict() {
    for (links, required) in [("requires", true), ("wants", false)] {
        let decoy = Decoy::new();
        decoy.write(
            "/usr/lib/systemd/system/r-a.mount",
            "[Mount]\nWhat=tmpfs\nWhere=/r/a\nType=tmpfs\n",
        );
        decoy.link(
            &format!("/usr/lib/systemd/system/local-fs.target.{links}/r-a.mount"),
            "../r-a.mount",
        );
        let (_, kept, warnings) = kept(&decoy, PULLED_LINE);
        assert!(
            kept.masks.iter().any(|mask| mask == "r-a.mount"),
            "{links}: {kept:?}"
        );
        let recorded = RequiredMask {
            unit: "r-a.mount".into(),
            cause: MaskCause::ConflictingLines,
            device: None,
        };
        assert_eq!(
            kept.required_masks.contains(&recorded),
            required,
            "{links}: {kept:?}"
        );
        assert_eq!(warnings.len(), 1, "{links}: {warnings:?}");
        assert!(
            warnings[0].contains(
                "r-a.mount is masked, as a noauto line of a decoy disk names it, and another \
                 fstab line or unit file that the session leaves to the hidden systemd \
                 describes it too"
            ),
            "{links}: {warnings:?}"
        );
        assert_eq!(
            warnings[0].contains("will not reach the boot target that requires it"),
            required,
            "{links}: {warnings:?}"
        );
    }
}

/// A noauto line of the decoy's fstab and a tmpfs line of the hidden
/// session's own fstab for one mount point, and the same two lines in one
/// fstab: NAILS does not read which of them the hidden systemd makes the
/// unit from, so the unit stays masked, recorded where a boot target
/// requires the tmpfs, and warned of.
#[test]
fn a_noauto_line_and_a_ram_line_for_one_mount_point_are_a_conflict() {
    let decoy = Decoy::new();
    let noauto = "/dev/vdb1 /opt/x ext4 noauto 0 2\n";
    for (ram, required) in [
        ("tmpfs /opt/x tmpfs defaults 0 0\n", true),
        ("tmpfs /opt/x tmpfs nofail 0 0\n", false),
    ] {
        let mounts = parse_mountinfo(ROOT_ONLY);
        let mut decisions = policy::decide_all(
            &crate::session::fstab::parse_fstab(noauto),
            &mounts,
            Path::new(HIDDEN),
            &|_| true,
        );
        decisions.extend(policy::decide_all_hidden_fstab(
            &crate::session::fstab::parse_fstab(ram),
            &mounts,
            Path::new(HIDDEN),
            &|_| true,
        ));
        let both = format!("{noauto}{ram}");
        let one = policy::decide_all(
            &crate::session::fstab::parse_fstab(&both),
            &mounts,
            Path::new(HIDDEN),
            &|_| true,
        );
        for decisions in [decisions, one] {
            let (kept, warnings) = decoy.kept_off(&both, &decisions);
            assert!(
                kept.masks.iter().any(|mask| mask == "opt-x.mount"),
                "{kept:?}"
            );
            let recorded = RequiredMask {
                unit: "opt-x.mount".into(),
                cause: MaskCause::ConflictingLines,
                device: None,
            };
            assert_eq!(
                kept.required_masks.contains(&recorded),
                required,
                "{ram}: {kept:?}"
            );
            assert_eq!(warnings.len(), 1, "{ram}: {warnings:?}");
            assert!(
                warnings[0].contains("opt-x.mount is masked, as a noauto line of a decoy disk"),
                "{ram}: {warnings:?}"
            );
        }
    }
}

/// A target that links the unit the fstab generator made for a noauto line
/// requires it through a link NAILS reads: the unit is decided as next
/// decided it, skipped where its disk is there, and the line's mask yields
/// to the skip. Where it lies below another noauto line, its skip would pull
/// that line's mount in: masked, recorded and warned of, as next did.
#[test]
fn a_noauto_line_s_unit_a_target_links_is_decided_as_before() {
    let generated = |name: &str, what: &str, path: &str| {
        let text = format!(
            "[Unit]\nSourcePath=/etc/fstab\n[Mount]\nWhat={what}\nWhere={path}\nType=ext4\n\
             Options=noauto\n"
        );
        (name.to_string(), text)
    };
    let decoy = Decoy::new();
    for (name, text) in [
        generated("srv-pa.mount", "/dev/vdb1", "/srv/pa"),
        generated("srv-pa-child.mount", "/dev/vdc1", "/srv/pa/child"),
        generated("srv-alone.mount", "/dev/vdd1", "/srv/alone"),
    ] {
        decoy.write(&format!("/run/systemd/generator/{name}"), &text);
    }
    for name in ["srv-pa-child.mount", "srv-alone.mount"] {
        decoy.link(
            &format!("/run/systemd/system/nails-pull.target.requires/{name}"),
            &format!("/run/systemd/generator/{name}"),
        );
    }
    let fstab = "/dev/vdb1 /srv/pa ext4 noauto 0 2\n\
                 /dev/vdc1 /srv/pa/child ext4 noauto 0 2\n\
                 /dev/vdd1 /srv/alone ext4 noauto 0 2\n";
    let (_, kept, warnings) = kept(&decoy, fstab);
    // Alone, the unit is skipped, with its fsck: not masked.
    let alone = kept
        .skips
        .iter()
        .find(|skip| skip.units == ["srv-alone.mount"])
        .unwrap_or_else(|| panic!("{kept:?}"));
    assert!(
        alone
            .pulled
            .contains(&"systemd-fsck@dev-vdd1.service".to_string()),
        "{alone:?}"
    );
    assert!(
        !kept.masks.iter().any(|mask| mask == "srv-alone.mount"),
        "{kept:?}"
    );
    // Below the noauto /srv/pa, its skip is masked.
    assert_eq!(
        kept.required_masks,
        [RequiredMask {
            unit: "srv-pa-child.mount".into(),
            cause: MaskCause::PullsInMount,
            device: None,
        }]
    );
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    for part in [
        "srv-pa-child.mount is masked rather than skipped",
        "srv-pa.mount (the mount of a parent directory), the mount of a noauto line of a decoy \
         disk, which the session masks",
    ] {
        assert!(warnings[0].contains(part), "{part}: {warnings:?}");
    }
    assert!(
        kept.masks.iter().any(|mask| mask == "srv-pa.mount"),
        "{kept:?}"
    );
}

/// A tmpfs mount unit outside the fstab, linked into local-fs.target.requires,
/// that requires the mount of the noauto line [`PULLED_LINE`] only as the mount
/// for a path: `RequiresMountsFor=` a path in it, or its mount point below it.
/// systemd 260.5 started such a unit without the masked mount and reached
/// local-fs.target. Its disk there, the mount is skipped as for `Requires=`;
/// without it, the mount stays masked with a warning that the target may not
/// be reached, and nothing is recorded.
#[test]
fn a_noauto_line_a_unit_requires_only_for_a_path_may_leave_its_target_reached() {
    for (name, unit) in [
        (
            "r-t9.mount",
            "[Unit]\nRequiresMountsFor=/r/a/x\n[Mount]\nWhat=tmpfs\nWhere=/r/t9\nType=tmpfs\n",
        ),
        (
            "r-a-t.mount",
            "[Mount]\nWhat=tmpfs\nWhere=/r/a/t\nType=tmpfs\n",
        ),
    ] {
        let decoy = Decoy::new();
        decoy.write(&format!("/etc/systemd/system/{name}"), unit);
        decoy.link(
            &format!("/etc/systemd/system/local-fs.target.requires/{name}"),
            &format!("../{name}"),
        );
        let (_, kept, warnings) = kept(&decoy, PULLED_LINE);
        assert!(
            kept.skips.iter().any(|skip| skip.units == ["r-a.mount"]),
            "{name}: {kept:?}"
        );
        assert!(warnings.is_empty(), "{name}: {warnings:?}");

        let (_, kept, warnings) = kept_with(&decoy, PULLED_LINE, false);
        assert!(
            kept.masks.iter().any(|mask| mask == "r-a.mount"),
            "{name}: {kept:?}"
        );
        assert!(kept.required_masks.is_empty(), "{name}: {kept:?}");
        assert_eq!(warnings.len(), 1, "{name}: {warnings:?}");
        for part in [
            "r-a.mount is masked rather than skipped, as its device /dev/vdy1 is not there",
            &format!("{name}, which local-fs.target requires, requires r-a.mount"),
            "only as the mount for a path, so the hidden session may not reach local-fs.target",
        ] {
            assert!(warnings[0].contains(part), "{name}: {part}: {warnings:?}");
        }
        assert!(!warnings[0].contains("will not"), "{name}: {warnings:?}");
    }
}

/// A drop-in of the decoy's that resets the start conditions of `unit`, which
/// undoes its skip.
fn reset_conditions(decoy: &Decoy, unit: &str) {
    decoy.write(
        &format!("/etc/systemd/system/{unit}.d/zz.conf"),
        "[Unit]\nConditionPathExists=\n",
    );
}

/// A unit linked into local-fs.target.requires needs the mount of the noauto
/// line [`PULLED_LINE`], its disk is there, but a drop-in of the decoy's
/// resets the mount's start conditions: the skip is masked after all. Where
/// the unit names the mount (`Requires=`), the warning says local-fs.target
/// will not be reached, and the mask is recorded. Where it needs it only as
/// the mount for a path (`RequiresMountsFor=`, a mount point below it), the
/// warning said so too, and the mask was recorded, but systemd 260.5 starts
/// such a unit without the mount: the warning says may, and nothing is
/// recorded.
#[test]
fn a_noauto_skip_masked_after_all_says_may_where_a_unit_needs_it_for_a_path() {
    for (name, unit, by_path) in [
        (
            "r-t9.mount",
            "[Unit]\nRequires=r-a.mount\nAfter=r-a.mount\n[Mount]\nWhat=tmpfs\nWhere=/r/t9\n\
             Type=tmpfs\n",
            false,
        ),
        (
            "r-t9.mount",
            "[Unit]\nRequiresMountsFor=/r/a/x\n[Mount]\nWhat=tmpfs\nWhere=/r/t9\nType=tmpfs\n",
            true,
        ),
        (
            "r-a-t.mount",
            "[Mount]\nWhat=tmpfs\nWhere=/r/a/t\nType=tmpfs\n",
            true,
        ),
    ] {
        let decoy = Decoy::new();
        decoy.write(&format!("/etc/systemd/system/{name}"), unit);
        decoy.link(
            &format!("/etc/systemd/system/local-fs.target.requires/{name}"),
            &format!("../{name}"),
        );
        reset_conditions(&decoy, "r-a.mount");
        let (_, kept, warnings) = kept(&decoy, PULLED_LINE);
        assert!(
            kept.masks.iter().any(|mask| mask == "r-a.mount"),
            "{name}: {kept:?}"
        );
        assert!(kept.skips.is_empty(), "{name}: {kept:?}");
        let recorded = RequiredMask {
            unit: "r-a.mount".into(),
            cause: MaskCause::SkipUndone,
            device: None,
        };
        let expected = if by_path { Vec::new() } else { vec![recorded] };
        assert_eq!(kept.required_masks, expected, "{name}: {kept:?}");
        assert_eq!(warnings.len(), 1, "{name}: {warnings:?}");
        assert!(
            warnings[0].contains(
                "r-a.mount is masked rather than skipped, as a drop-in of r-a.mount that sorts \
                 after the skip's resets or hides its start conditions"
            ),
            "{name}: {warnings:?}"
        );
        assert_eq!(
            warnings[0].contains("will not reach"),
            !by_path,
            "{name}: {warnings:?}"
        );
        assert_eq!(
            warnings[0].contains("so the hidden session may not reach that target"),
            by_path,
            "{name}: {warnings:?}"
        );
    }
}

/// next's own path: a noauto line that another fstab line the boot starts
/// needs, its disk there, is skipped as a line the boot mounts, and a
/// drop-in of the decoy's that resets its start conditions masks the skip
/// after all. Where the other line names it (`x-systemd.requires=`), the
/// warning says the target will not be reached, and the mask is recorded.
/// Where it needs it only as the mount for a path (a mount point below it,
/// `x-systemd.requires-mounts-for=`), the warning said so too, and the mask
/// was recorded: it says may, and nothing is recorded.
#[test]
fn a_needed_noauto_skip_masked_after_all_says_may_where_lines_need_it_for_a_path() {
    for (needer, by_path) in [
        ("tmpfs /n/a/t tmpfs defaults 0 0\n", true),
        (
            "tmpfs /srv/t tmpfs x-systemd.requires-mounts-for=/n/a/x 0 0\n",
            true,
        ),
        ("tmpfs /srv/t tmpfs x-systemd.requires=/n/a 0 0\n", false),
    ] {
        let decoy = Decoy::new();
        reset_conditions(&decoy, "n-a.mount");
        let fstab = format!("/dev/vdn1 /n/a ext4 noauto 0 0\n{needer}");
        let (_, kept, warnings) = kept(&decoy, &fstab);
        assert!(
            kept.masks.iter().any(|mask| mask == "n-a.mount"),
            "{needer}: {kept:?}"
        );
        assert!(kept.skips.is_empty(), "{needer}: {kept:?}");
        let recorded = RequiredMask {
            unit: "n-a.mount".into(),
            cause: MaskCause::SkipUndone,
            device: None,
        };
        let expected = if by_path { Vec::new() } else { vec![recorded] };
        assert_eq!(kept.required_masks, expected, "{needer}: {kept:?}");
        assert_eq!(warnings.len(), 1, "{needer}: {warnings:?}");
        assert_eq!(
            warnings[0].contains("will not reach"),
            !by_path,
            "{needer}: {warnings:?}"
        );
        assert_eq!(
            warnings[0].contains("so the hidden session may not reach that target"),
            by_path,
            "{needer}: {warnings:?}"
        );
    }
}
