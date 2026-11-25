// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The mask of every `noauto` line of a decoy disk, and what the policy
//! records and warns of for a line kept off that a boot target requires, or
//! may: a line for `/usr`, a chain of lines with a backslash on the way, two
//! lines for one mount point, and a `noauto` line kept off at or below the
//! hidden root.

use super::*;
use crate::session::fstab::parse_fstab;
use nails_teardown::mountinfo::parse_mountinfo;
use nails_teardown::whole_root::plan::{MaskCause, RequiredMask};

const HIDDEN: &str = "/mnt/data";

fn mounts() -> Vec<MountEntry> {
    parse_mountinfo(
        "1 0 8:2 / / rw,relatime - ext4 /dev/vda2 rw\n\
         8 1 253:0 / /mnt/data rw - ext4 /dev/mapper/data rw\n",
    )
}

/// The decisions for the decoy's fstab `fstab`, with every device there or
/// with none.
fn decide_fstab(fstab: &str, there: bool) -> Vec<Decision> {
    decide_all(&parse_fstab(fstab), &mounts(), Path::new(HIDDEN), &|_| {
        there
    })
}

/// The decision for the line with the mount point `target` among
/// `decisions`.
fn at<'a>(decisions: &'a [Decision], target: &str) -> &'a Decision {
    decisions
        .iter()
        .find(|decision| match decision {
            Decision::Mask { target: at, .. }
            | Decision::Skip { target: at, .. }
            | Decision::Leave { target: at, .. } => at == Path::new(target),
            _ => false,
        })
        .unwrap_or_else(|| panic!("no decision for {target}: {decisions:?}"))
}

/// A line for /usr that names a unit to want it: the generator ignored
/// `x-systemd.wanted-by=` and `x-systemd.required-by=` there and linked
/// `usr.mount` into `local-fs.target.requires`. next read the first as one
/// nothing requires and masked it with no warning and no record, and named
/// foo.service for the second with the remedy nofail, which the generator
/// ignores on /usr too. Both are kept off as a line local-fs.target requires:
/// skipped where the device is there, masked with the warning and recorded
/// where it is not, with a remedy that does not name nofail.
#[test]
fn a_usr_line_that_names_a_unit_is_one_local_fs_target_requires() {
    for option in [
        "x-systemd.wanted-by=foo.service",
        "x-systemd.required-by=foo.service",
    ] {
        let line = format!("/dev/vdu1 /usr ext4 {option} 0 0\n");
        let there = decide_fstab(&line, true);
        assert_eq!(
            there[0].skip().map(|skip| skip.units.clone()),
            Some(vec!["usr.mount".to_string()]),
            "{option}: {there:?}"
        );
        let absent = decide_fstab(&line, false);
        let Decision::Mask { unreached, .. } = &absent[0] else {
            panic!("{option}: {absent:?}");
        };
        assert_eq!(
            unreached,
            &Some(Unreached {
                target: "local-fs.target".into(),
                cause: Unskippable::NoDevice("/dev/vdu1".into()),
                origin: Origin::Mandatory,
            }),
            "{option}"
        );
        let warning = absent[0].warning().expect("a warning");
        assert!(
            warning
                .contains("the hidden session will not reach local-fs.target, which requires it"),
            "{warning}"
        );
        assert!(
            warning.ends_with(
                "Attach the device before activating, or remove its fstab entry: the fstab \
                 generator mounts /usr whatever its options say"
            ),
            "{warning}"
        );
        assert!(!warning.contains("nofail"), "{warning}");
        assert!(!warning.contains("foo.service"), "{warning}");
        assert_eq!(
            runtime_units(&parse_fstab(&line), &absent).required_masks,
            [RequiredMask {
                unit: "usr.mount".into(),
                cause: MaskCause::DeviceAbsent,
                device: Some("/dev/vdu1".into()),
            }],
            "{option}"
        );
    }
}

/// A chain: local-fs.target requires the tmpfs at /t1/t2, whose mount
/// requires that of its parent /t1, a tmpfs whose
/// `x-systemd.requires=/data`, before an option with a backslash, requires
/// the noauto /data. The backslash may hide a nofail on /t1, so
/// local-fs.target may not require /t1 itself, but it requires /t1/t2, which
/// requires /t1 all the same. next read every step through /t1 as a may and
/// did not record the mask. It is recorded now; an `x-systemd.requires=`
/// after the backslash, which systemd may join to the option before it, stays
/// a may.
#[test]
fn a_backslash_on_the_way_makes_only_its_own_step_a_may() {
    let sure = "/dev/vdb1 /data ext4 noauto 0 0\n\
                tmpfs /t1 tmpfs x-systemd.requires=/data,comment=a\\,b 0 0\n\
                tmpfs /t1/t2 tmpfs defaults 0 0\n";
    let decisions = decide_fstab(sure, false);
    let Decision::Mask { unreached, .. } = at(&decisions, "/data") else {
        panic!("{decisions:?}");
    };
    let unreached = unreached.as_ref().expect("a target is not reached");
    assert_eq!(unreached.target, "local-fs.target");
    assert_eq!(
        unreached.origin,
        Origin::Needed {
            lines: vec!["/t1/t2".into()],
            may: false,
            by_path: false,
        }
    );
    let warning = at(&decisions, "/data").warning().expect("a warning");
    assert!(
        warning.contains("the hidden session will not reach local-fs.target, which requires it"),
        "{warning}"
    );
    assert_eq!(
        runtime_units(&parse_fstab(sure), &decisions).required_masks,
        [RequiredMask {
            unit: "data.mount".into(),
            cause: MaskCause::DeviceAbsent,
            device: Some("/dev/vdb1".into()),
        }]
    );

    let may = "/dev/vdb1 /data ext4 noauto 0 0\n\
               tmpfs /t1 tmpfs comment=a\\,x-systemd.requires=/data 0 0\n\
               tmpfs /t1/t2 tmpfs defaults 0 0\n";
    let decisions = decide_fstab(may, false);
    let Decision::Mask { unreached, .. } = at(&decisions, "/data") else {
        panic!("{decisions:?}");
    };
    // The option after the backslash may name the mount, so the warning says
    // that where the target requires the line, it is not reached.
    assert!(
        matches!(
            unreached.as_ref().map(|u| &u.origin),
            Some(Origin::Needed {
                may: true,
                by_path: false,
                ..
            })
        ),
        "{unreached:?}"
    );
    assert!(
        runtime_units(&parse_fstab(may), &decisions)
            .required_masks
            .is_empty()
    );
}

/// Two fstabs with a line for /data: in one a noauto line that a tmpfs with a
/// backslash in its options needs, which local-fs.target may require, so it
/// is skipped; in the other a nofail line not mounted now, masked. The mask
/// holds for both. next recorded it as a mask local-fs.target requires
/// (ConflictingLines), though NAILS only reads that it may. It is not
/// recorded now, and still warned of; a skip a target surely requires through
/// a line that names the mount (`x-systemd.requires=`) is recorded as before.
/// A tmpfs below the mount requires it only as the mount for a path, which
/// systemd 260.5 does not hold up for a masked mount: not recorded either.
#[test]
fn a_may_skip_another_line_masks_is_not_recorded_as_required() {
    for (needer, sure) in [
        ("tmpfs /data/tmp tmpfs comment=x\\054nofail 0 0", false),
        ("tmpfs /data/tmp tmpfs defaults 0 0", false),
        ("tmpfs /srv/t tmpfs x-systemd.requires=/data 0 0", true),
    ] {
        let decoy = format!("/dev/vdb1 /data ext4 noauto 0 0\n{needer}\n");
        let mut decisions = decide_fstab(&decoy, true);
        let Decision::Skip { may, .. } = at(&decisions, "/data") else {
            panic!("{decisions:?}");
        };
        assert_eq!(*may, !sure, "{needer}");
        let own = "/dev/vdb1 /data ext4 nofail 0 0\n";
        decisions.extend(decide_fstab(own, true));
        let fstab = parse_fstab(&format!("{decoy}{own}"));
        let kept = runtime_units(&fstab, &decisions);
        assert!(kept.masks.contains(&"data.mount".to_string()), "{kept:?}");
        if sure {
            assert_eq!(
                kept.required_masks,
                [RequiredMask {
                    unit: "data.mount".into(),
                    cause: MaskCause::ConflictingLines,
                    device: None,
                }]
            );
            assert!(kept.may_conflicts.is_empty(), "{kept:?}");
        } else {
            assert!(kept.required_masks.is_empty(), "{kept:?}");
            assert_eq!(kept.may_conflicts, ["data.mount"]);
        }
    }
}

/// A noauto line kept off at or below the hidden root, in the next root's own
/// fstab or led there by a link, whose mount a tmpfs elsewhere requires
/// (`x-systemd.requires-mounts-for=`, or `x-systemd.requires=` by name),
/// which local-fs.target requires. next masked it with no warning and no
/// record. It is skipped where its device is there, and masked with the
/// warning of a needed line where it is not: that the target will not be
/// reached, recorded, where the tmpfs names the mount, and that it may not
/// be, not recorded, where it requires the mount for a path.
#[test]
fn a_noauto_line_kept_off_below_the_hidden_root_that_a_line_needs_is_warned_of() {
    for (option, named) in [
        ("x-systemd.requires-mounts-for=/mnt/data/archive", false),
        ("x-systemd.requires=/mnt/data/archive", true),
    ] {
        kept_below_needed(option, named);
    }
}

/// [`a_noauto_line_kept_off_below_the_hidden_root_that_a_line_needs_is_warned_of`]
/// with a tmpfs that gives `option`, which names the mount where `named`.
fn kept_below_needed(option: &str, named: bool) {
    let fstab =
        format!("/dev/vdb1 /mnt/data/archive ext4 noauto 0 0\ntmpfs /srv/t tmpfs {option} 0 0\n");
    let entries = parse_fstab(&fstab);
    for there in [true, false] {
        let present = |_: &Path| there;
        for (decisions, kept_for) in [
            (
                decide_all_hidden_fstab(&entries, &mounts(), Path::new(HIDDEN), &present),
                KEPT_BELOW,
            ),
            (
                decide_all_redirected(&entries, &mounts(), Path::new(HIDDEN), &present),
                "a link leads it into the hidden volume, where the hidden session would mount a \
                 decoy filesystem read-write",
            ),
        ] {
            let decision = at(&decisions, "/mnt/data/archive");
            let reason = match decision {
                Decision::Mask { reason, .. } | Decision::Skip { reason, .. } => reason,
                other => panic!("{other:?}"),
            };
            assert_eq!(
                reason,
                &format!(
                    "{kept_for}, and the line for /srv/t needs its mount, so the boot mounts it"
                )
            );
            if there {
                assert_eq!(
                    decision.skip().map(|skip| skip.units.clone()),
                    Some(vec!["mnt-data-archive.mount".to_string()]),
                    "{decision:?}"
                );
            } else {
                let warning = decision.warning().expect("a warning");
                let will = if named { "will not" } else { "may not" };
                assert!(
                    warning.contains(&format!(
                        "/mnt/data/archive is masked rather than skipped, as its device \
                         /dev/vdb1 is not there: the hidden session {will} reach \
                         local-fs.target"
                    )),
                    "{warning}"
                );
                assert_eq!(
                    runtime_units(&entries, &decisions).required_masks.len(),
                    usize::from(named),
                    "{decisions:?}"
                );
            }
        }
    }
}

/// A noauto network line, kept off as the hidden session would write to the
/// server, whose mount a tmpfs below it requires, which local-fs.target
/// requires: next masked it with no warning. It is skipped as a needed
/// line, and it waits for no device.
#[test]
fn a_noauto_network_line_a_line_needs_is_skipped() {
    let decisions = decide_fstab(
        "srv:/x /net nfs noauto 0 0
tmpfs /net/tmp tmpfs defaults 0 0
",
        false,
    );
    let decision = at(&decisions, "/net");
    let skip = decision.skip().unwrap_or_else(|| panic!("{decision:?}"));
    assert_eq!(skip.units, ["net.mount"]);
    assert_eq!(skip.device, None);
    let Decision::Skip { reason, .. } = decision else {
        unreachable!()
    };
    assert_eq!(
        reason,
        "the hidden session would write to the server, and the line for /net/tmp needs its \
         mount, so the boot mounts it"
    );
}

/// The mask of a noauto line yields to a skip of its unit that waits for its
/// device, which starts nothing either: the skip pulls in the line's checkers
/// too, and the unit is not masked. A skip that waits for another device is
/// masked, and recorded as one the lines disagree about.
#[test]
fn a_noauto_mask_yields_to_a_skip_of_its_unit_on_its_device() {
    let noauto = decide_fstab("/dev/vdb1 /srv/x ext4 noauto 0 2\n", true);
    assert!(noauto[0].is_noauto_mask(), "{noauto:?}");
    for (device, yields) in [("/dev/vdb1", true), ("/dev/vdc1", false)] {
        let other = format!("{device} /srv/x ext4 defaults 0 0\n");
        let skip = Decision::Skip {
            target: "/srv/x".into(),
            skip: Skip {
                units: vec!["srv-x.mount".into()],
                pulled: Vec::new(),
                device: Some(device.into()),
            },
            masked: Vec::new(),
            reason: "a unit a target links".into(),
            may: false,
        };
        let decisions = [noauto[0].clone(), skip];
        let fstab = parse_fstab(&format!("/dev/vdb1 /srv/x ext4 noauto 0 2\n{other}"));
        let kept = runtime_units(&fstab, &decisions);
        assert!(
            kept.masks.contains(&"srv-x.automount".to_string()),
            "{kept:?}"
        );
        if yields {
            assert!(!kept.masks.contains(&"srv-x.mount".to_string()), "{kept:?}");
            assert_eq!(
                kept.skips[0].pulled,
                ["systemd-fsck@dev-vdb1.service"],
                "{kept:?}"
            );
            assert!(kept.required_masks.is_empty(), "{kept:?}");
        } else {
            assert!(kept.masks.contains(&"srv-x.mount".to_string()), "{kept:?}");
            assert!(kept.skips.is_empty(), "{kept:?}");
            assert_eq!(kept.required_masks[0].cause, MaskCause::ConflictingLines);
        }
        assert_eq!(
            kept.noauto_masks.contains(&"srv-x.mount".to_string()),
            !yields
        );
    }
}

/// A noauto line with an option NAILS does not read whose mount a tmpfs line
/// that local-fs.target requires needs, by name (`x-systemd.requires=`) or
/// as the mount for a path (below it). The mask stands, as the option may
/// have the boot mount the line in other ways too, but a warning now names
/// local-fs.target. Where the tmpfs names the mount, the warning says the
/// target will not be reached, and the mount (not the automount, which
/// nothing pulls in) is recorded as one that target requires; where the
/// tmpfs lies below it, which systemd 260.5 started without a masked mount,
/// the warning says the target may not be reached, and nothing is recorded.
/// next masked it with no warning and no record.
#[test]
fn a_noauto_line_with_an_unread_option_that_a_line_needs_is_warned_of() {
    for (needer, named) in [
        ("tmpfs /r/t tmpfs x-systemd.requires=/r/a 0 0", true),
        ("tmpfs /r/a/t tmpfs defaults 0 0", false),
    ] {
        let fstab = format!("/dev/vdy1 /r/a ext4 noauto,foo 0 0\n{needer}\n");
        let decisions = decide_fstab(&fstab, true);
        let decision = at(&decisions, "/r/a");
        let Decision::Mask {
            units, unreached, ..
        } = decision
        else {
            panic!("{decision:?}");
        };
        assert_eq!(units, &["r-a.mount", "r-a.automount"]);
        assert_eq!(
            unreached.as_ref().map(|u| (u.target.as_str(), &u.cause)),
            Some(("local-fs.target", &Unskippable::Unread)),
            "{decision:?}"
        );
        let line = if named { "/r/t" } else { "/r/a/t" };
        let reached = if named {
            "the hidden session will not reach local-fs.target, which requires it"
        } else {
            "the hidden session may not reach local-fs.target, which requires a line that needs \
             it only as the mount for a path"
        };
        let warning = decision.warning().expect("a warning");
        for part in [
            "/r/a is masked, as noauto, but NAILS does not read its option foo",
            &format!("and the line for {line} needs its mount, so the boot mounts it"),
            reached,
        ] {
            assert!(warning.contains(part), "{part}: {warning}");
        }
        let kept = runtime_units(&parse_fstab(&fstab), &decisions);
        let recorded: &[RequiredMask] = if named {
            &[RequiredMask {
                unit: "r-a.mount".into(),
                cause: MaskCause::Undetermined,
                device: None,
            }]
        } else {
            &[]
        };
        assert_eq!(kept.required_masks, recorded, "{needer}");
    }
    // Nothing needs it: the mask stands as before, with no warning.
    let alone = decide_fstab("/dev/vdy1 /r/a ext4 noauto,foo 0 0\n", true);
    assert_eq!(at(&alone, "/r/a").warning(), None);
}

/// Every way an fstab line the boot starts needs a noauto line's mount, with
/// the noauto line's device not there: masked, with a warning. systemd 260.5
/// started a tmpfs below a masked mount, and one naming it in
/// `x-systemd.requires-mounts-for=`, without that mount, and reached
/// local-fs.target; only `x-systemd.requires=` kept the tmpfs from starting.
/// So the warning says the target will not be reached, and the mask is
/// recorded, only where a line names the mount; where the lines require it
/// only as the mount for a path (below it, a path
/// `x-systemd.requires-mounts-for=` names), the warning says the target may
/// not be reached, and nothing is recorded. A line that names it wins over
/// one below it, and a chain of lines NAILS reads counts by its first step.
#[test]
fn a_needed_noauto_line_warns_will_not_only_where_a_line_names_its_mount() {
    for (needers, named) in [
        ("tmpfs /n/a/t tmpfs defaults 0 0\n", false),
        (
            "tmpfs /srv/t tmpfs x-systemd.requires-mounts-for=/n/a/x 0 0\n",
            false,
        ),
        ("tmpfs /srv/t tmpfs x-systemd.requires=/n/a 0 0\n", true),
        (
            "tmpfs /srv/t tmpfs x-systemd.requires=n-a.mount 0 0\n",
            true,
        ),
        (
            "tmpfs /n/a/t tmpfs defaults 0 0\ntmpfs /srv/t tmpfs x-systemd.requires=/n/a 0 0\n",
            true,
        ),
        // The tmpfs that names it is one only another line requires.
        (
            "tmpfs /srv/t tmpfs nofail,x-systemd.requires=/n/a 0 0\n\
             tmpfs /srv/t/u tmpfs defaults 0 0\n",
            true,
        ),
        // A line below it that another line requires in turn.
        (
            "tmpfs /n/a/t tmpfs nofail 0 0\n\
             tmpfs /srv/u tmpfs x-systemd.requires=/n/a/t 0 0\n",
            false,
        ),
    ] {
        let fstab = format!("/dev/vdn1 /n/a ext4 noauto 0 0\n{needers}");
        let decisions = decide_fstab(&fstab, false);
        let decision = at(&decisions, "/n/a");
        let Decision::Mask {
            unreached: Some(unreached),
            ..
        } = decision
        else {
            panic!("{needers}: {decision:?}");
        };
        assert!(
            matches!(&unreached.origin, Origin::Needed { may: false, by_path, .. } if *by_path != named),
            "{needers}: {unreached:?}"
        );
        let warning = decision.warning().expect("a warning");
        let will = if named { "will not" } else { "may not" };
        assert!(
            warning.contains(&format!(
                "/n/a is masked rather than skipped, as its device /dev/vdn1 is not there: the \
                 hidden session {will} reach local-fs.target"
            )),
            "{needers}: {warning}"
        );
        let kept = runtime_units(&parse_fstab(&fstab), &decisions);
        assert_eq!(
            kept.required_masks.len(),
            usize::from(named),
            "{needers}: {kept:?}"
        );
        // With the device there it is skipped either way.
        let there = decide_fstab(&fstab, true);
        assert_eq!(
            at(&there, "/n/a").skip().map(|skip| skip.units.clone()),
            Some(vec!["n-a.mount".to_string()]),
            "{needers}"
        );
    }
}

/// A noauto line that a line the boot starts needs, here through an option
/// with a backslash or a tmpfs below it: only the mount is kept off as a
/// needed line is, and the rest of the line's own mask, a decoy disk's
/// automount, stays masked, as the mask of every noauto line of a decoy
/// disk has it, so that no autofs goes over the mount point. The needed decision dropped the automount,
/// which the fuzz target found
/// (fuzz/seeds/fstab_crypttab/crash-needed-noauto-automount-*):
/// `var-cache.automount` was neither masked nor skipped. A network share's
/// mask holds its mount alone, and the needed skip of that mount stands in
/// for it (crash-needed-network-noauto-mount-skipped).
#[test]
fn a_needed_noauto_line_keeps_its_automount_masked() {
    let disk = "/dev/vda6 /var/cache ext4 noauto 0 0\n";
    for (line, needer, rest) in [
        (
            disk,
            "store /nix/.ro-store 9p trans=virt\\\\ 0 0\n",
            &["var-cache.automount"][..],
        ),
        (
            disk,
            "tmpfs /var/cache/t tmpfs defaults 0 0\n",
            &["var-cache.automount"][..],
        ),
        (
            "srv:/x /var/cache nfs4 noauto 0 0\n",
            "tmpfs /var/cache/t tmpfs defaults 0 0\n",
            &[][..],
        ),
    ] {
        let fstab = format!("{line}{needer}");
        for there in [true, false] {
            let present = |_: &Path| there;
            let own = decide(
                &parse_fstab(line)[0],
                &mounts(),
                Path::new(HIDDEN),
                &present,
            );
            assert_eq!(own.masked_units()[0], "var-cache.mount", "{line} {there}");
            assert_eq!(&own.masked_units()[1..], rest, "{line} {there}");
            let decisions = decide_fstab(&fstab, there);
            let decision = at(&decisions, "/var/cache");
            let (kept_off, masked): (&[String], &[String]) = match decision {
                Decision::Skip { skip, masked, .. } => (&skip.units, masked),
                Decision::Mask { units, .. } => (&units[..1], &units[1..]),
                _ => panic!("{fstab} {there}: {decision:?}"),
            };
            assert_eq!(kept_off, ["var-cache.mount"], "{fstab} {there}");
            assert_eq!(masked, rest, "{fstab} {there}");
            let kept = runtime_units(&parse_fstab(&fstab), &decisions);
            for unit in rest {
                assert!(
                    kept.masks.iter().any(|mask| mask == unit),
                    "{fstab} {there}: {kept:?}"
                );
                // Never recorded as a unit a target requires.
                assert!(
                    !kept.required_masks.iter().any(|mask| mask.unit == *unit),
                    "{fstab} {there}: {kept:?}"
                );
            }
        }
    }
}
