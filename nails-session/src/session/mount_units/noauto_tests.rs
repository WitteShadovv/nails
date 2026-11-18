// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the mask of a `noauto` line of a decoy disk, as the units
//! outside the fstab meet it.

use super::*;

/// The fstab decisions for `fstab` and those of the units outside it, with
/// every device there, and what the hidden session keeps off for them, with
/// the warnings.
fn kept(decoy: &Decoy, fstab: &str) -> (Vec<Decision>, KeptOff, Vec<String>) {
    let mut decisions = policy::decide_all(
        &crate::session::fstab::parse_fstab(fstab),
        &parse_mountinfo(ROOT_ONLY),
        Path::new(HIDDEN),
        &|_| true,
    );
    decisions.extend(decoy.decide_with(fstab, ROOT_ONLY, true));
    let (kept, warnings) = decoy.kept_off(fstab, &decisions);
    (decisions, kept, warnings)
}

/// A mount unit file outside the fstab, a tmpfs that local-fs.target
/// requires, whose `Requires=` names the mount of a noauto line of a decoy
/// disk. next left the line as never mounted and the tmpfs to the hidden
/// systemd, which started the tmpfs and with it mounted the disk read-write.
/// The line is masked, mount and automount, whatever pulls it in; the tmpfs
/// is left as before, and NAILS reads none of its pulls, so nothing is
/// warned of: the hidden systemd cannot start it.
#[test]
fn a_noauto_line_a_unit_file_pulls_in_is_masked() {
    let decoy = Decoy::new();
    decoy.write(
        "/etc/systemd/system/r-t9.mount",
        "[Unit]\nRequires=r-a.mount\nAfter=r-a.mount\n[Mount]\nWhat=tmpfs\nWhere=/r/t9\nType=tmpfs\n",
    );
    decoy.link(
        "/etc/systemd/system/local-fs.target.requires/r-t9.mount",
        "../r-t9.mount",
    );
    let (decisions, kept, warnings) = kept(&decoy, "/dev/vdy1 /r/a ext4 noauto 0 0\n");
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
