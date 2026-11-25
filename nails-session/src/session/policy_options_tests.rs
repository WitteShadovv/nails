// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The fstab policy reads each option as systemd 260.5's fstab generator read
//! it on a test root (`SYSTEMD_FSTAB=<file> systemd-fstab-generator <dirs>`):
//! by its name, alone or with a value, the last of a pair winning. A line it
//! takes for one the boot never mounts gives only options NAILS reads, by the
//! lists the `backend-entries` check reads a plain line by; any other line it
//! keeps off is masked, with a reason that names the option.

use super::*;
use crate::session::fstab::parse_fstab;
use nails_teardown::mountinfo::parse_mountinfo;

const HIDDEN: &str = "/mnt/data";

fn mounts() -> Vec<MountEntry> {
    parse_mountinfo(
        "1 0 8:2 / / rw,relatime - ext4 /dev/vda2 rw\n\
         5 1 0:5 / /tmp rw - tmpfs tmpfs rw\n\
         8 1 253:0 / /mnt/data rw - ext4 /dev/mapper/data rw\n",
    )
}

fn present(_: &Path) -> bool {
    true
}

/// The decision for `line` of the decoy's fstab, with every device there.
fn decide_line(line: &str) -> Decision {
    decide(
        &parse_fstab(line)[0],
        &mounts(),
        Path::new(HIDDEN),
        &present,
    )
}

/// The decision for `line` of the next root's own fstab, with every device
/// there.
fn decide_own(line: &str) -> Decision {
    decide_hidden_fstab(
        &parse_fstab(line)[0],
        &mounts(),
        Path::new(HIDDEN),
        &present,
    )
}

fn reason(decision: &Decision) -> &str {
    match decision {
        Decision::Mask { reason, .. } | Decision::Skip { reason, .. } => reason.as_ref(),
        Decision::Leave { reason, .. } => reason,
        other => panic!("no reason: {other:?}"),
    }
}

/// The generator linked `opt.mount` into `local-fs.target.requires` for
/// `noauto,auto=1` and `noauto,auto=0`, and `opt.automount` for
/// `noauto,x-systemd.automount=0`, `=no` and `comment=systemd.automount=1`.
/// next left each alone as "noauto: never mounted", and the hidden systemd
/// mounted the disk read-write.
#[test]
fn a_noauto_taken_back_by_name_is_kept_off_and_never_left() {
    for options in ["noauto,auto=1", "noauto,auto=0", "noauto,auto="] {
        for decision in [
            decide_line(&format!("/dev/vdb1 /opt ext4 {options} 0 0")),
            decide_own(&format!("/dev/vdb1 /opt ext4 {options} 0 0")),
        ] {
            let skip = decision
                .skip()
                .unwrap_or_else(|| panic!("{options}: {decision:?}"));
            assert_eq!(skip.units, ["opt.mount"], "{options}");
            assert_eq!(skip.device.as_deref(), Some(Path::new("/dev/vdb1")));
        }
    }
    for options in [
        "noauto,x-systemd.automount=0",
        "noauto,x-systemd.automount=no",
        "noauto,comment=systemd.automount=1",
    ] {
        let decision = decide_own(&format!("/dev/vdb1 /opt ext4 {options} 0 0"));
        let skip = decision
            .skip()
            .unwrap_or_else(|| panic!("{options}: {decision:?}"));
        assert_eq!(skip.units, ["opt.automount"], "{options}");
        assert_eq!(decision.masked_units(), ["opt.mount"], "{options}");
    }
}

/// The generator wrote noauto=yes for these, and NAILS reads every option of
/// them: nothing NAILS reads pulls them in, and they are masked as noauto
/// lines of a decoy disk, which next left alone.
#[test]
fn a_noauto_line_nails_reads_fully_is_masked_as_a_noauto_line() {
    for line in [
        "/dev/vdb1 /opt ext4 noauto 0 0",
        "/dev/vdb1 /opt ext4 noauto=1 0 0",
        "/dev/vdb1 /opt ext4 auto,noauto= 0 0",
        "/dev/vdb1 /opt ext4 auto=1,noauto,user,nofail 0 0",
        "/dev/sr0 /media/cdrom0 udf,iso9660 user,noauto 0 0",
        "/dev/vdb1 /opt ext4 noauto,x-systemd.requires-mounts-for=/srv/x 0 0",
        "/dev/vdb1 /opt ext4 noauto,x-systemd.device-timeout=5s 0 0",
        "/dev/vdb1 /opt ext4 noauto,journal_path=/dev/vdc1 0 0",
        "/dev/vdb1 /opt btrfs noauto,subvol=@x,compress=zstd:3 0 0",
    ] {
        let decision = decide_line(line);
        assert!(decision.is_noauto_mask(), "{line}: {decision:?}");
    }
}

/// A noauto line with an option NAILS does not read, or one it knows in
/// another form, may be mounted at boot whatever noauto says: masked, mount
/// and automount, with the option named and never its value. Where NAILS
/// does not read what the option pulls in either (a backslash in it, or an
/// option of systemd's own), it may have a boot target require the line,
/// which the mask then keeps from being reached: warned of.
#[test]
fn a_noauto_line_with_an_option_nails_does_not_read_is_masked() {
    for (options, named, may_require) in [
        (
            "noauto,x-systemd.before=multi-user.target",
            "x-systemd.before",
            false,
        ),
        (
            "noauto,x-systemd.after=foo.service",
            "x-systemd.after",
            false,
        ),
        (
            "noauto,x-systemd.requires=foo.service",
            "x-systemd.requires",
            false,
        ),
        ("noauto,X-mount.subdir=sub", "X-mount.subdir", false),
        (
            "noauto,x-systemd.requires-mounts-for=srv",
            "x-systemd.requires-mounts-for",
            false,
        ),
        ("noauto,nofail=1", "nofail", false),
        ("noauto,secret=/dev/vdc", "secret", false),
        ("noauto,x-nails.probe", "x-nails.probe", false),
        ("noauto,loop", "loop", false),
        ("noauto,x-systemd.pcrfs=1", "x-systemd.pcrfs", false),
        // Of systemd's own namespaces, and not read: it may have a target
        // require the line.
        (
            "noauto,x-systemd.nails-probe",
            "x-systemd.nails-probe",
            true,
        ),
        ("noauto,x-initrd.attach", "x-initrd.attach", true),
        // systemd keeps the comma after a backslash in the option, and reads
        // \054 as a comma: the generator mounted these at boot, and set up
        // an automount for the last.
        ("noauto,auto=x\\,noauto", "auto", true),
        ("noauto,auto=\\,noauto", "auto", true),
        ("noauto,comment=x\\054auto", "comment", true),
        ("noauto,x-gvfs-show\\054auto", "x-gvfs-show\\054auto", true),
        ("noauto,comment=x\\054x-systemd.automount", "comment", true),
        // A quote: systemd splits at the comma between the quotes, as NAILS
        // does, but libmount, which `mount` reads the line with, keeps it in
        // the option.
        ("noauto,comment=\"x,auto\"", "comment", false),
        // The option whose pulls NAILS does not read is named first.
        (
            "noauto,X-mount.subdir=a,x-systemd.nails-probe",
            "x-systemd.nails-probe",
            true,
        ),
    ] {
        let line = format!("/dev/vdb1 /opt ext4 {options} 0 0");
        for decision in [decide_line(&line), decide_own(&line)] {
            let Decision::Mask {
                units, unreached, ..
            } = &decision
            else {
                panic!("{options}: {decision:?}");
            };
            assert_eq!(units, &["opt.mount", "opt.automount"], "{options}");
            if may_require {
                assert_eq!(
                    unreached,
                    &Some(Unreached {
                        target: "local-fs.target".into(),
                        cause: Unskippable::MayRequire,
                        origin: Origin::Fstab,
                    }),
                    "{options}"
                );
                let warning = decision.warning().expect("a warning");
                assert!(
                    warning.contains(
                        "where that option has local-fs.target or another unit require it, \
                         the hidden session will not reach that unit"
                    ),
                    "{warning}"
                );
            } else {
                assert_eq!(*unreached, None, "{options}");
                assert_eq!(decision.warning(), None, "{options}");
            }
            let why = reason(&decision);
            assert_eq!(
                why,
                format!(
                    "noauto, but NAILS does not read its option {named} as the line gives \
                     it, so the boot may mount it"
                ),
            );
            assert!(!why.contains("/dev/vdc"), "{why}");
        }
    }
    // NAILS cannot tell that a target requires it: no required mask.
    let decision = decide_line("/dev/vdb1 /opt ext4 noauto,auto=x\\,noauto 0 0");
    assert!(runtime_units(&[], &[decision]).required_masks.is_empty());
}

/// A line named to pull it in by x-systemd.wanted-by= or required-by= and a
/// unit other than local-fs.target, which the generator linked into
/// `foo.service.wants` or `.requires`, is not plain to the lists, but the
/// session reads what those options pull in: masked, and skipped where the
/// unit it names requires it, as next decides it.
#[test]
fn a_line_a_named_unit_pulls_in_is_kept_off_as_before() {
    let wanted = decide_line("/dev/vdb1 /opt ext4 noauto,x-systemd.wanted-by=foo.service 0 0");
    assert_eq!(wanted.masked_units(), ["opt.mount"]);
    let required = decide_line("/dev/vdb1 /opt ext4 noauto,x-systemd.required-by=foo.service 0 0");
    assert_eq!(required.skip().expect("a skip").units, ["opt.mount"]);
}

/// A line the boot mounts with an option of systemd's own that NAILS does not
/// read, or one with a backslash, is masked rather than skipped:
/// the option may pull in units that act on the disk, which a skip would
/// leave free to start. The warning says the target that requires it is not
/// reached, or, for a backslash, which may hide a comma before `noauto` or
/// `nofail`, that the target may require it.
#[test]
fn a_mounted_at_boot_line_with_a_systemd_option_nails_does_not_read_is_masked() {
    for (line, units, named, cause) in [
        (
            "/dev/vdb1 /opt ext4 defaults,x-systemd.nails-probe=1 0 0",
            &["opt.mount", "opt.automount"][..],
            "x-systemd.nails-probe",
            Unskippable::Unread,
        ),
        (
            "/dev/vdb1 /opt ext4 defaults,x-initrd.attach 0 0",
            &["opt.mount", "opt.automount"],
            "x-initrd.attach",
            Unskippable::Unread,
        ),
        (
            "/dev/vdb1 /opt ext4 defaults,x-systemd.requires=a\\054b.service 0 0",
            &["opt.mount", "opt.automount"],
            "x-systemd.requires",
            Unskippable::MayRequire,
        ),
        (
            "/dev/vdb1 /opt ext4 defaults,x-systemd.after=a\\,b.service 0 0",
            &["opt.mount", "opt.automount"],
            "x-systemd.after",
            Unskippable::MayRequire,
        ),
        (
            "/dev/vdb2 none swap sw,x-systemd.nails-probe 0 0",
            &["dev-vdb2.swap"],
            "x-systemd.nails-probe",
            Unskippable::Unread,
        ),
    ] {
        let decision = decide_line(line);
        let Decision::Mask {
            units: masked,
            unreached,
            ..
        } = &decision
        else {
            panic!("{line}: {decision:?}");
        };
        assert_eq!(masked, units, "{line}");
        assert_eq!(unreached.as_ref().map(|u| &u.cause), Some(&cause), "{line}");
        assert!(
            reason(&decision).ends_with(&format!(
                "; NAILS cannot tell what its option {named} pulls in"
            )),
            "{line}: {decision:?}"
        );
        let warning = decision.warning().expect("a warning");
        assert!(warning.contains("will not reach"), "{warning}");
    }
    // nofail=1 is nofail to the generator, which then only wants the unit:
    // masked, and no target left unreached.
    let Decision::Mask { unreached, .. } =
        decide_line("/dev/vdb1 /opt ext4 nofail=1,x-systemd.nails-probe 0 0")
    else {
        panic!("not masked");
    };
    assert_eq!(unreached, None);
}

/// A backslash may hide a comma before `noauto` or `nofail`: systemd 260.5's
/// fstab generator read `comment=x\054noauto` as `noauto` and linked the mount
/// into no target. A line the boot mounts as NAILS reads it, masked for such
/// an option, says that its target may require it, as a `noauto` line masked
/// for one does, and the mask is not recorded as a required one. A line for
/// `/usr`, which the generator mounts whatever its options say, still says
/// that the target is not reached.
#[test]
fn a_mounted_at_boot_line_with_a_backslash_says_its_target_may_require_it() {
    for (line, units, boot) in [
        (
            "/dev/vdj2 /p/j2 ext4 comment=x\\054noauto 0 0",
            &["p-j2.mount", "p-j2.automount"][..],
            "local-fs.target",
        ),
        (
            "/dev/vdj3 /p/j3 ext4 comment=x\\054nofail 0 0",
            &["p-j3.mount", "p-j3.automount"],
            "local-fs.target",
        ),
        (
            "/dev/vdj4 none swap sw,comment=x\\054nofail 0 0",
            &["dev-vdj4.swap"],
            "swap.target",
        ),
    ] {
        for decision in [decide_line(line), decide_own(line)] {
            let Decision::Mask {
                units: masked,
                unreached,
                ..
            } = &decision
            else {
                panic!("{line}: {decision:?}");
            };
            assert_eq!(masked, units, "{line}");
            assert_eq!(
                unreached,
                &Some(Unreached {
                    target: boot.into(),
                    cause: Unskippable::MayRequire,
                    origin: Origin::Fstab,
                }),
                "{line}"
            );
            let warning = decision.warning().expect("a warning");
            assert!(
                warning.contains(&format!(
                    "where that option has {boot} or another unit require it, the hidden \
                     session will not reach that unit"
                )),
                "{warning}"
            );
            assert!(!warning.contains("which requires it"), "{warning}");
            assert!(
                runtime_units(&[], std::slice::from_ref(&decision))
                    .required_masks
                    .is_empty(),
                "{line}"
            );
        }
    }
    let usr = decide_line("/dev/vdj5 /usr ext4 comment=x\\054noauto 0 0");
    let Decision::Mask { unreached, .. } = &usr else {
        panic!("{usr:?}");
    };
    assert_eq!(
        unreached.as_ref().map(|u| &u.cause),
        Some(&Unskippable::Unread)
    );
    let warning = usr.warning().expect("a warning");
    assert!(
        warning.contains("the hidden session will not reach local-fs.target, which requires it"),
        "{warning}"
    );
    // The generator makes no automount for /usr: only its mount is masked
    // and recorded.
    assert_eq!(usr.masked_units(), ["usr.mount"]);
    let kept = runtime_units(&[], &[usr]);
    assert_eq!(kept.required_masks.len(), 1, "{:?}", kept.required_masks);
    assert_eq!(kept.required_masks[0].unit, "usr.mount");
}

/// systemd reads no option outside its own namespaces for what a unit pulls
/// in, other than flags the session reads by their names too: the generator
/// wrote nothing for `hard`, `vers=4.2`, `timeo=30`, `uid=`, `credentials=`,
/// `X-mount.subdir=` or `jqfmt=`, and only an order for `x-systemd.after=`
/// and `x-systemd.before=`. A line the boot mounts with such an option is
/// skipped where its target requires it, as next skips it: an NFS or CIFS
/// share without `nofail` keeps `remote-fs.target` reached.
#[test]
fn a_mounted_at_boot_line_with_an_option_systemd_does_not_read_is_skipped() {
    for (line, units, masked) in [
        (
            "server:/export /net nfs4 rw,hard,vers=4.2 0 0",
            &["net.mount"][..],
            &[][..],
        ),
        (
            "//nas/share /net cifs credentials=/root/.smb,uid=1000,vers=3.0 0 0",
            &["net.mount"],
            &[],
        ),
        (
            "server:/export /net nfs rw,soft,timeo=30,x-systemd.automount 0 0",
            &["net.automount"],
            &["net.mount"],
        ),
        (
            "/dev/vdb1 /opt ext4 defaults,X-mount.subdir=a 0 0",
            &["opt.mount"],
            &[],
        ),
        (
            "/dev/vdb1 /opt ext4 x-systemd.after=foo.service,x-systemd.before=bar.service 0 0",
            &["opt.mount"],
            &[],
        ),
        (
            "/dev/vdb1 /opt ext4 x-systemd.rw-only,x-systemd.device-bound 0 0",
            &["opt.mount"],
            &[],
        ),
        (
            "/dev/vdb1 /opt ext4 usrjquota=aquota.user,jqfmt=vfsv0 0 0",
            &["opt.mount"],
            &[],
        ),
        ("/dev/vdb1 /opt ext4 nofail,fail=1 0 0", &["opt.mount"], &[]),
        (
            "/dev/vdb1 /opt ext4 comment=systemd.nails-probe 0 0",
            &["opt.mount"],
            &[],
        ),
    ] {
        let decision = decide_line(line);
        let skip = decision
            .skip()
            .unwrap_or_else(|| panic!("{line}: {decision:?}"));
        assert_eq!(skip.units, units, "{line}");
        assert_eq!(decision.masked_units(), masked, "{line}");
    }
    // A double quote changes nothing in how systemd splits the options: the
    // generator split each of these at every comma, as NAILS does, and gave
    // the NFS share only Before=remote-fs.target. next skipped them, and so
    // does NAILS, the target reached.
    for (line, units) in [
        (
            "srv:/y /net nfs4 rw,hard,context=\"system_u:object_r:nfs_t:s0\" 0 0",
            "net.mount",
        ),
        (
            "srv:/v /net nfs4 rw,context=\"system_u:object_r:nfs_t:s0:c1,c2\" 0 0",
            "net.mount",
        ),
        (
            "/dev/vdm2 /opt ext4 context=\"system_u:object_r:etc_t:s0\" 0 0",
            "opt.mount",
        ),
        (
            "/dev/vdx1 /opt ext4 noauto,comment=\"x,auto,y\" 0 0",
            "opt.mount",
        ),
        (
            "server:/x /net nfs4 rw,comment=\"a,x-systemd.requires=b.service\" 0 0",
            "net.mount",
        ),
        (
            "/dev/vdb2 none swap sw,comment=\"a,b\" 0 0",
            "dev-vdb2.swap",
        ),
    ] {
        for decision in [decide_line(line), decide_own(line)] {
            let skip = decision
                .skip()
                .unwrap_or_else(|| panic!("{line}: {decision:?}"));
            assert_eq!(skip.units, [units], "{line}");
            assert!(decision.masked_units().is_empty(), "{line}");
            assert_eq!(decision.warning(), None, "{line}");
        }
    }
    // What the generator pulled in for an option between quotes, NAILS reads
    // too: the makefs of `comment="x,x-systemd.makefs,y"` is skipped with
    // the mount.
    let decision = decide_line("/dev/vdx3 /opt ext4 comment=\"x,x-systemd.makefs,y\" 0 0");
    assert!(
        decision
            .skip()
            .expect("a skip")
            .pulled
            .iter()
            .any(|unit| unit == "systemd-makefs@dev-vdx3.service"),
        "{decision:?}"
    );
    let nfs = decide_line("server:/export /net nfs4 rw,hard,vers=4.2 0 0");
    assert!(reason(&nfs).starts_with("the hidden session would write to the server"));
    // The session reads what these pull in: skipped, each with its checkers.
    for (line, pulled) in [
        (
            "/dev/vdb1 /opt ext4 defaults,x-systemd.validatefs=1 0 0",
            "systemd-validatefs@opt.service",
        ),
        (
            "/dev/vdb1 /opt ext4 defaults,usrjquota=aquota.user 0 0",
            "quotaon@opt.service",
        ),
    ] {
        let decision = decide_line(line);
        let skip = decision
            .skip()
            .unwrap_or_else(|| panic!("{line}: {decision:?}"));
        assert!(
            skip.pulled.iter().any(|unit| unit == pulled),
            "{line}: {skip:?}"
        );
    }
}

/// Every unit a line has its mount pull in that acts on the disk is read by
/// its name: the generator linked `systemd-makefs@dev-vdd2.service` into
/// `f1.mount.requires` for `x-systemd.makefs=1`, `systemd-growfs@` for
/// `x-systemd.growfs=1` and `systemd-mkswap@` for a swap line's
/// `x-systemd.makefs=1`. next skipped the mount and left the makefs free,
/// which formats a disk it finds empty.
#[test]
fn the_units_a_skip_pulls_in_are_read_by_their_names() {
    let decision = decide_own("/dev/vdb1 /opt ext4 x-systemd.makefs=1,x-systemd.growfs=yes 0 0");
    let skip = decision.skip().expect("a skip");
    assert_eq!(skip.units, ["opt.mount"]);
    assert_eq!(
        skip.pulled,
        [
            "systemd-fsck@dev-vdb1.service",
            "systemd-makefs@dev-vdb1.service",
            "systemd-growfs@opt.service",
        ]
    );
    let swap = decide_line("/dev/vdb2 none swap sw,x-systemd.makefs=1 0 0");
    assert_eq!(
        swap.skip().expect("a skip").pulled,
        ["systemd-mkswap@dev-vdb2.service"]
    );
}

/// A swap line with noauto,auto=1, which the generator linked into
/// `swap.target.requires`, is skipped rather than masked: next took it for
/// noauto and masked it, leaving swap.target unreached.
#[test]
fn a_swap_line_is_read_by_name_too() {
    let decision = decide_line("/dev/vdb2 none swap noauto,auto=1 0 0");
    assert_eq!(decision.skip().expect("a skip").units, ["dev-vdb2.swap"]);
    let wanted = decide_line("/dev/vdb2 none swap noauto 0 0");
    assert_eq!(wanted.masked_units(), ["dev-vdb2.swap"]);
}

/// The generator mounts a line for /usr whatever noauto says ("Mount '/usr'
/// is mandatory, ignoring 'noauto', 'nofail', and 'x-systemd.automount'
/// options"), and linked `usr.mount` into `local-fs.target.requires` for a
/// line with `nofail,x-systemd.automount`, with no automount: kept off, not
/// left alone, and skipped as the target requires the mount itself.
#[test]
fn a_noauto_line_for_usr_is_kept_off() {
    for options in ["noauto", "nofail,x-systemd.automount", "noauto,nofail"] {
        let decision = decide_line(&format!("/dev/vdb1 /usr ext4 {options} 0 0"));
        let skip = decision
            .skip()
            .unwrap_or_else(|| panic!("{options}: {decision:?}"));
        assert_eq!(skip.units, ["usr.mount"], "{options}");
        assert!(decision.masked_units().is_empty(), "{options}");
    }
}

/// _netdev=1 makes a network line to the generator, which linked it into
/// `remote-fs.target`; NAILS reads it by name and keeps the line off as a
/// network line, skipped as that target requires it. An NFS line's bg=1 is a
/// mount in the background to it, which the target only wants: masked, as
/// next masks a `bg` line.
#[test]
fn a_network_flag_with_a_value_is_read_by_name() {
    let decision = decide_line("/dev/vdb1 /opt ext4 _netdev=1 0 0");
    assert!(reason(&decision).starts_with("the hidden session would write to the server"));
    assert_eq!(decision.skip().expect("a skip").units, ["opt.mount"]);
    let nfs = decide_line("server:/x /net nfs bg=1 0 0");
    let Decision::Mask { unreached, .. } = &nfs else {
        panic!("{nfs:?}");
    };
    assert_eq!(*unreached, None, "bg=1 is bg: the target only wants it");
}

/// An overlay that names its upper directory twice, of which the kernel
/// takes the last, is kept off: NAILS does not tell where its writes go.
#[test]
fn an_overlay_with_two_upper_directories_is_kept_off() {
    let ram = "overlay /o overlay lowerdir=/usr,upperdir=/tmp/u,workdir=/tmp/w 0 0";
    assert!(matches!(decide_line(ram), Decision::Leave { .. }));
    let twice =
        "overlay /o overlay lowerdir=/usr,upperdir=/tmp/u,upperdir=/var/u,workdir=/tmp/w 0 0";
    let decision = decide_line(twice);
    assert_eq!(decision.skip().expect("a skip").units, ["o.mount"]);
    assert!(reason(&decision).contains("more than once"));
    let bare = "overlay /o overlay lowerdir=/usr,upperdir,workdir=/tmp/w 0 0";
    assert!(!matches!(decide_line(bare), Decision::Leave { .. }));
}

/// A unit outside the fstab carries its options in its unit files, and the
/// mask of an option NAILS does not read is for fstab lines alone.
#[test]
fn a_unit_outside_the_fstab_is_decided_by_its_units() {
    let entry = &parse_fstab("/dev/vdb1 /opt ext4 x-nails.probe 0 0")[0];
    let units = Units {
        unit: Some("opt.mount".into()),
        automount: None,
        required_by: Some("local-fs.target".into()),
        checkers: Vec::new(),
        origin: Origin::Installed,
    };
    let decision = decide_units(entry, &units, &mounts(), Path::new(HIDDEN), &present);
    assert_eq!(decision.skip().expect("a skip").units, ["opt.mount"]);
}

/// The decisions for `fstab` of the decoy's, with every device there or with
/// none, ordered by mount-point depth.
fn decide_fstab(fstab: &str, there: bool) -> Vec<Decision> {
    let present = move |_: &Path| there;
    decide_all(&parse_fstab(fstab), &mounts(), Path::new(HIDDEN), &present)
}

/// systemd has a mount require the mounts of its parent directories, of its
/// source and of the paths `x-systemd.requires-mounts-for=` names (`systemctl
/// show` of a mount below another lists that one in `Requires=`). A `noauto`
/// line with a path in it that a line the hidden systemd starts needs is
/// mounted at boot whatever `noauto` says: next left it alone, and the tmpfs
/// below it had the hidden systemd mount the decoy disk read-write. It is
/// skipped where the target requires that line, masked where its device is
/// not there, with a warning, or where the target only wants that line.
#[test]
fn a_noauto_line_another_line_needs_is_kept_off() {
    let fstab = "/dev/vdb1 /data ext4 noauto 0 0\ntmpfs /data/tmp tmpfs defaults 0 0\n";
    let decisions = decide_fstab(fstab, true);
    let Decision::Skip {
        target,
        skip,
        reason,
        ..
    } = &decisions[0]
    else {
        panic!("{decisions:?}");
    };
    assert_eq!(target, Path::new("/data"));
    assert_eq!(skip.units, ["data.mount"]);
    assert_eq!(skip.device.as_deref(), Some(Path::new("/dev/vdb1")));
    assert_eq!(
        reason,
        "noauto, but the line for /data/tmp needs its mount, so the boot mounts it"
    );
    assert!(matches!(decisions[1], Decision::Leave { .. }));

    let absent = decide_fstab(fstab, false);
    let Decision::Mask {
        units, unreached, ..
    } = &absent[0]
    else {
        panic!("{absent:?}");
    };
    // The line's automount stays masked with it.
    assert_eq!(units, &["data.mount", "data.automount"]);
    assert_eq!(
        unreached,
        &Some(Unreached {
            target: "local-fs.target".into(),
            cause: Unskippable::NoDevice("/dev/vdb1".into()),
            origin: Origin::Needed {
                lines: vec!["/data/tmp".into()],
                may: false,
                by_path: true,
            },
        })
    );
    // The tmpfs requires the mount only as that of its parent directory,
    // which systemd 260.5 does not hold up for a masked mount.
    let warning = absent[0].warning().expect("a warning");
    assert_eq!(
        warning,
        "/data is masked rather than skipped, as its device /dev/vdb1 is not there: the hidden \
         session may not reach local-fs.target, which requires a line that needs it only as the \
         mount for a path, and the units only that target pulls in may not start there. Attach \
         the device before activating, or give the fstab entry for /data/tmp the nofail option \
         (x-systemd.wanted-by= in place of an x-systemd.required-by= it gives)"
    );

    for fstab in [
        "/dev/vdb1 /data ext4 noauto 0 0\ntmpfs /data/tmp tmpfs nofail 0 0\n",
        "/dev/vdb1 /data ext4 noauto 0 0\n\
         tmpfs /run/x tmpfs nofail,x-systemd.requires-mounts-for=/data/y 0 0\n",
        "/dev/vdb1 /data ext4 noauto 0 0\n\
         tmpfs /run/x tmpfs nofail,x-systemd.wants-mounts-for=/data 0 0\n",
    ] {
        let decisions = decide_fstab(fstab, true);
        let Decision::Mask {
            units, unreached, ..
        } = &decisions[0]
        else {
            panic!("{fstab}: {decisions:?}");
        };
        assert_eq!(units, &["data.mount", "data.automount"], "{fstab}");
        assert_eq!(*unreached, None, "{fstab}");
    }

    // A line below that is never started itself, or kept off, pulls in
    // nothing; a skip's pulls are walked in the unit pass.
    for fstab in [
        "/dev/vdb1 /data ext4 noauto 0 0\n/dev/vdb2 /data/x ext4 noauto 0 0\n",
        "/dev/vdb1 /data ext4 noauto 0 0\n/dev/vdb2 /data/x ext4 defaults 0 0\n",
        "/dev/vdb1 /data ext4 noauto 0 0\ntmpfs /srv/tmp tmpfs defaults 0 0\n",
        "/dev/vdb1 /data ext4 noauto 0 0\ntmpfs /database tmpfs defaults 0 0\n",
        "/dev/vdb1 /data ext4 noauto 0 0\ntmpfs /data/tmp tmpfs noauto 0 0\n",
    ] {
        let decisions = decide_fstab(fstab, true);
        // Nothing NAILS reads pulls it in: the mask of a noauto line.
        assert!(decisions[0].is_noauto_mask(), "{fstab}: {decisions:?}");
        assert_eq!(
            decisions[0].masked_units(),
            ["data.mount", "data.automount"],
            "{fstab}"
        );
    }

    // The next root's own fstab is read alike.
    let own = decide_all_hidden_fstab(
        &parse_fstab("/dev/vdb1 /data ext4 noauto 0 0\ntmpfs /data/tmp tmpfs defaults 0 0\n"),
        &mounts(),
        Path::new(HIDDEN),
        &present,
    );
    assert_eq!(own[0].skip().expect("a skip").units, ["data.mount"]);
}

/// Every line that needs a noauto line's mount is read, not the first alone:
/// with a `nofail` tmpfs below it first and one a target requires after it,
/// the noauto line is skipped where its device is there, as local-fs.target
/// requires the second tmpfs, and masked with a warning that the target is
/// not reached where its device is not there.
#[test]
fn a_noauto_line_is_judged_by_every_line_that_needs_it() {
    let fstab = "/dev/vdr1 /p/r1 ext4 noauto 0 0\n\
                 tmpfs /p/r1/a tmpfs nofail 0 0\n\
                 tmpfs /p/r1/b tmpfs defaults 0 0\n";
    let decisions = decide_fstab(fstab, true);
    let skip = decisions[0].skip().expect("a skip");
    assert_eq!(skip.units, ["p-r1.mount"]);
    assert_eq!(
        reason(&decisions[0]),
        "noauto, but the line for /p/r1/b needs its mount, so the boot mounts it"
    );
    let absent = decide_fstab(fstab, false);
    let Decision::Mask { unreached, .. } = &absent[0] else {
        panic!("{absent:?}");
    };
    assert_eq!(
        unreached,
        &Some(Unreached {
            target: "local-fs.target".into(),
            cause: Unskippable::NoDevice("/dev/vdr1".into()),
            origin: Origin::Needed {
                lines: vec!["/p/r1/b".into()],
                may: false,
                by_path: true,
            },
        })
    );
    assert!(absent[0].warning().is_some());

    // A line the target requires that requires a nofail line in turn, which
    // needs the noauto mount: the target requires that mount too.
    let chain = "/dev/vdb1 /data ext4 noauto 0 0\n\
                 tmpfs /t1 tmpfs nofail,x-systemd.requires=/data 0 0\n\
                 tmpfs /t2 tmpfs x-systemd.requires=t1.mount 0 0\n";
    let decisions = decide_fstab(chain, true);
    assert_eq!(
        decisions[0].skip().expect("a skip").units,
        ["data.mount"],
        "{decisions:?}"
    );

    // Two targets require it: both are named.
    let both = "/dev/vdb1 /data ext4 noauto 0 0\n\
                tmpfs /data/a tmpfs defaults 0 0\n\
                tmpfs /data/b tmpfs x-systemd.required-by=foo.service 0 0\n";
    let Decision::Mask { unreached, .. } = &decide_fstab(both, false)[0] else {
        panic!("not masked");
    };
    assert_eq!(
        unreached.as_ref().map(|u| u.target.as_str()),
        Some("local-fs.target and foo.service")
    );
}

/// The warning for a noauto line that a chain of lines holds up names the
/// lines the targets require, where `nofail` (or `x-systemd.wanted-by=` in
/// place of `x-systemd.required-by=`, which `nofail` does not change: systemd
/// 260.5's generator linked such a `nofail` tmpfs into `foo.service.requires`)
/// lets the target be reached: not the `nofail` line that needs the mount
/// itself. With several targets it speaks of them all.
#[test]
fn the_warning_for_a_needed_noauto_line_names_the_lines_that_hold_it_up() {
    let chain = "/dev/vdz3 /c/n ext4 noauto 0 0\n\
                 tmpfs /c/n/b tmpfs nofail 0 0\n\
                 tmpfs /c/z tmpfs x-systemd.requires=/c/n/b 0 0\n";
    let absent = decide_fstab(chain, false);
    assert_eq!(
        reason(&absent[0]),
        "noauto, but the line for /c/n/b needs its mount, so the boot mounts it"
    );
    let warning = absent[0].warning().expect("a warning");
    assert!(
        warning.ends_with(
            "give the fstab entry for /c/z the nofail option (x-systemd.wanted-by= in place \
             of an x-systemd.required-by= it gives)"
        ),
        "{warning}"
    );

    let both = "/dev/vdz4 /d/n ext4 noauto 0 0\n\
                tmpfs /d/n/a tmpfs x-systemd.required-by=foo.service 0 0\n\
                tmpfs /d/n/b tmpfs defaults 0 0\n";
    let absent = decide_fstab(both, false);
    assert_eq!(
        absent[0].warning().expect("a warning"),
        "/d/n is masked rather than skipped, as its device /dev/vdz4 is not there: the hidden \
         session may not reach foo.service and local-fs.target, which require a line that needs \
         it only as the mount for a path, and the units only those targets pull in may not start \
         there. Attach the device before activating, or give the fstab entries for /d/n/a and \
         /d/n/b the nofail option (x-systemd.wanted-by= in place of an x-systemd.required-by= \
         they give)"
    );
}

/// A noauto line that only a line with an option NAILS cannot read may pull
/// in (here a backslash) is kept off, but nothing may require it: the tmpfs
/// below gives no dependency on it in systemd 260.5's generator output. The
/// warning says the target may require it, and the mask is not recorded as
/// one a target requires. The option may name the mount, so the warning
/// says that where the target requires the tmpfs, it is not reached.
#[test]
fn a_noauto_line_only_an_unread_option_may_pull_in_may_leave_a_target_unreached() {
    let fstab = "/dev/vdw1 /w/a ext4 noauto 0 0\n\
                 tmpfs /w/t2 tmpfs comment=foo\\040bar 0 0\n";
    assert_eq!(
        decide_fstab(fstab, true)[0].skip().expect("a skip").units,
        ["w-a.mount"]
    );
    let absent = decide_fstab(fstab, false);
    let Decision::Mask { unreached, .. } = &absent[0] else {
        panic!("{absent:?}");
    };
    assert_eq!(
        unreached,
        &Some(Unreached {
            target: "local-fs.target".into(),
            cause: Unskippable::NoDevice("/dev/vdw1".into()),
            origin: Origin::Needed {
                lines: vec!["/w/t2".into()],
                may: true,
                by_path: false,
            },
        })
    );
    assert_eq!(
        absent[0].warning().expect("a warning"),
        "/w/a is masked rather than skipped, as its device /dev/vdw1 is not there: \
         local-fs.target may require it, and where it does, the hidden session will not reach \
         it, and the units only that target pulls in will not start there. Attach the device \
         before activating, or give the fstab entry for /w/t2 the nofail option \
         (x-systemd.wanted-by= in place of an x-systemd.required-by= it gives)"
    );
    let kept = runtime_units(&parse_fstab(fstab), &absent);
    assert!(kept.masks.contains(&"w-a.mount".to_string()), "{kept:?}");
    assert_eq!(kept.required_masks, [], "{kept:?}");

    // Where a line NAILS reads requires it too, by name, the target requires
    // it: the warning says so, names that line alone, and the mask is
    // recorded.
    let sure = "/dev/vdw1 /w/a ext4 noauto 0 0\n\
                tmpfs /w/t2 tmpfs comment=foo\\040bar 0 0\n\
                tmpfs /w/t3 tmpfs x-systemd.requires=/w/a 0 0\n";
    let absent = decide_fstab(sure, false);
    let warning = absent[0].warning().expect("a warning");
    assert!(
        warning.contains("will not reach local-fs.target, which requires it")
            && warning.contains("the fstab entry for /w/t3 the nofail"),
        "{warning}"
    );
    let kept = runtime_units(&parse_fstab(sure), &absent);
    assert_eq!(
        kept.required_masks
            .iter()
            .map(|m| m.unit.as_str())
            .collect::<Vec<_>>(),
        ["w-a.mount"]
    );

    // A line read first through an unread option and then through a chain
    // NAILS reads: the target requires the noauto line all the same, and the
    // reason names the line that surely needs its mount, not the first.
    let twice = "/dev/vdx1 /x ext4 noauto 0 0\n\
                 tmpfs /a tmpfs nofail,comment=p\\040q 0 0\n\
                 tmpfs /m tmpfs nofail,x-systemd.requires=/x,x-systemd.requires=/a 0 0\n\
                 tmpfs /t tmpfs x-systemd.requires=/m 0 0\n";
    let absent = decide_fstab(twice, false);
    assert_eq!(
        reason(&absent[0]),
        "noauto, but the line for /m needs its mount, so the boot mounts it"
    );
    let Decision::Mask { unreached, .. } = &absent[0] else {
        panic!("{absent:?}");
    };
    assert_eq!(
        unreached.as_ref().map(|u| &u.origin),
        Some(&Origin::Needed {
            lines: vec!["/t".into()],
            may: false,
            by_path: false,
        })
    );
}

/// A noauto line below which a noauto RAM line with an option NAILS does not
/// read lies: that line may start, so the boot may mount the noauto line.
#[test]
fn a_noauto_line_a_line_that_may_start_needs_may_be_mounted() {
    let decisions = decide_fstab(
        "/dev/vdl3 /p/l3 ext4 noauto 0 0\ntmpfs /p/l3/tmp tmpfs noauto,x-nails.probe 0 0\n",
        true,
    );
    assert_eq!(
        reason(&decisions[0]),
        "noauto, but the line for /p/l3/tmp needs its mount, so the boot may mount it"
    );
    assert_eq!(
        decisions[0].masked_units(),
        ["p-l3.mount", "p-l3.automount"]
    );
}

/// The fstab generator has a unit require the unit `x-systemd.requires=`
/// names and want the one `x-systemd.wants=` names, a path standing for its
/// mount: systemd 260.5 wrote `Requires=r-a.mount` for
/// `tmpfs /r/t1 tmpfs x-systemd.requires=/r/a` and for
/// `x-systemd.requires=r-a.mount`, and `Wants=r-a.mount` for
/// `x-systemd.wants=r-a.mount`, each tmpfs linked into
/// `local-fs.target.requires`. next left the noauto line for /r/a alone, and
/// the hidden systemd mounted the disk read-write. It is kept off: skipped
/// where a target requires a line that requires it, masked where lines only
/// want it.
#[test]
fn a_noauto_line_a_left_line_pulls_in_is_kept_off() {
    for (pull, skipped) in [
        ("x-systemd.requires=/r/a", true),
        ("x-systemd.requires=/r//a/", true),
        ("x-systemd.requires=r-a.mount", true),
        ("x-systemd.requires=r-a", true),
        ("x-systemd.requires=r/a", true),
        ("x-systemd.wants=r-a.mount", false),
        ("x-systemd.wants=/r/a", false),
    ] {
        let fstab = format!("/dev/vdy1 /r/a ext4 noauto 0 0\ntmpfs /r/t1 tmpfs {pull} 0 0\n");
        for decisions in [
            decide_fstab(&fstab, true),
            decide_all_hidden_fstab(&parse_fstab(&fstab), &mounts(), Path::new(HIDDEN), &present),
        ] {
            assert_eq!(
                reason(&decisions[0]),
                "noauto, but the line for /r/t1 needs its mount, so the boot mounts it",
                "{pull}"
            );
            if skipped {
                assert_eq!(
                    decisions[0].skip().expect("a skip").units,
                    ["r-a.mount"],
                    "{pull}"
                );
            } else {
                let Decision::Mask {
                    units, unreached, ..
                } = &decisions[0]
                else {
                    panic!("{pull}: {decisions:?}");
                };
                assert_eq!(units, &["r-a.mount", "r-a.automount"], "{pull}");
                assert_eq!(*unreached, None, "{pull}");
            }
            assert!(matches!(decisions[1], Decision::Leave { .. }), "{pull}");
        }
    }
    // A RAM overlay and a host share left to the hidden systemd pull it in
    // alike.
    for line in [
        "overlay /r/o overlay lowerdir=/usr,upperdir=/tmp/u,workdir=/tmp/w,x-systemd.requires=/r/a 0 0",
        "share /r/s 9p trans=virtio,x-systemd.requires=r-a.mount 0 0",
    ] {
        let fstab = format!("/dev/vdy1 /r/a ext4 noauto 0 0\n{line}\n");
        let decisions = decide_fstab(&fstab, true);
        assert_eq!(
            decisions[0].skip().expect("a skip").units,
            ["r-a.mount"],
            "{line}"
        );
    }
    // Where NAILS cannot read what the line pulls in, it may be the noauto
    // line: kept off. The unit is taken for one the line requires. systemd
    // 260.5's generator wrote Requires=r-a.mount for the last.
    for pull in [
        "x-systemd.requires=",
        "x-systemd.wants=r\\x2da.mount",
        "comment=x\\054x-systemd.requires=/r/a",
    ] {
        let fstab = format!("/dev/vdy1 /r/a ext4 noauto 0 0\ntmpfs /r/t1 tmpfs {pull} 0 0\n");
        let decisions = decide_fstab(&fstab, true);
        assert_eq!(
            decisions[0].skip().expect("a skip").units,
            ["r-a.mount"],
            "{pull}: {decisions:?}"
        );
        assert_eq!(
            reason(&decisions[0]),
            "noauto, but the line for /r/t1 gives an option NAILS cannot read that may pull \
             in its mount, so the boot may mount it",
            "{pull}"
        );
    }
    // Another unit, a mount below a path it names, a device or a line
    // kept off itself pulls in nothing of it.
    for fstab in [
        "/dev/vdy1 /r/a ext4 noauto 0 0\ntmpfs /r/t1 tmpfs x-systemd.requires=foo.service 0 0\n",
        "/dev/vdy1 /r/a ext4 noauto 0 0\ntmpfs /r/t1 tmpfs x-systemd.requires=/r/a/sub 0 0\n",
        "/dev/vdy1 /r/a ext4 noauto 0 0\ntmpfs /r/t1 tmpfs x-systemd.requires=/dev/vdy1 0 0\n",
        "/dev/vdy1 /r/a ext4 noauto 0 0\ntmpfs /r/t1 tmpfs x-systemd.requires=r-ab.mount 0 0\n",
        "/dev/vdy1 /r/a ext4 noauto 0 0\ntmpfs /r/t1 tmpfs x-systemd.after=r-a.mount 0 0\n",
        // The generator wrote no dependency for a name alone, and escaped
        // these: Requires=\x25i.mount, r\x2ba.mount and -r-..-r-a.mount,
        // and RequiresMountsFor=/r/a%%i, a path below /r alone.
        "/dev/vdy1 /r/a ext4 noauto 0 0\ntmpfs /r/t1 tmpfs x-systemd.requires 0 0\n",
        "/dev/vdy1 /r/a ext4 noauto 0 0\ntmpfs /r/t1 tmpfs x-systemd.requires=%i.mount 0 0\n",
        "/dev/vdy1 /r/a ext4 noauto 0 0\ntmpfs /r/t1 tmpfs x-systemd.requires=r+a.mount 0 0\n",
        "/dev/vdy1 /r/a ext4 noauto 0 0\ntmpfs /r/t1 tmpfs x-systemd.requires=/r/../r/a 0 0\n",
        "/dev/vdy1 /r/a ext4 noauto 0 0\n\
         tmpfs /r/t1 tmpfs x-systemd.requires-mounts-for=/r/a%i 0 0\n",
        "/dev/vdy1 /r/a ext4 noauto 0 0\n/dev/vdz1 /r/b ext4 x-systemd.requires=/r/a 0 0\n",
    ] {
        let decisions = decide_fstab(fstab, true);
        // Nothing NAILS reads pulls it in: the mask of a noauto line.
        assert!(decisions[0].is_noauto_mask(), "{fstab}: {decisions:?}");
        assert_eq!(
            decisions[0].masked_units(),
            ["r-a.mount", "r-a.automount"],
            "{fstab}"
        );
    }
}

/// A backslash anywhere in a line's options keeps NAILS from reading what has
/// a target require the line. systemd 260.5's fstab generator kept the comma
/// after a backslash in the option: it linked the mounts of
/// `comment=x\,nofail` and `comment=x\,x-systemd.wanted-by=foo.service` into
/// `local-fs.target.requires`, and the swaps of `sw,comment=x\,nofail` and
/// `sw,comment=x\,noauto` into `swap.target.requires`. It read `\054` as a
/// comma: `nofail,comment=x\054fail` went into `local-fs.target.requires`,
/// `sw,noauto,comment=x\054auto` into `swap.target.requires`. NAILS read
/// `nofail`, `x-systemd.wanted-by=` or `noauto` on each and masked it with no
/// warning, the target left unreached. Each is masked with the warning that
/// its target may require it, in the decoy's fstab and the hidden session's
/// own, with its device there or not, and the mask is not recorded as a
/// required one.
#[test]
fn a_line_kept_off_with_a_backslash_is_never_masked_without_a_warning() {
    let absent = |_: &Path| false;
    for (line, units, boot) in [
        (
            "/dev/vdq1 /q/a ext4 comment=x\\,nofail 0 0",
            &["q-a.mount", "q-a.automount"][..],
            "local-fs.target",
        ),
        (
            "/dev/vdq2 /q/b ext4 comment=x\\,x-systemd.wanted-by=foo.service 0 0",
            &["q-b.mount", "q-b.automount"],
            "local-fs.target",
        ),
        (
            "/dev/vdq20 /q/u ext4 nofail,comment=x\\054fail 0 0",
            &["q-u.mount", "q-u.automount"],
            "local-fs.target",
        ),
        (
            "/dev/vdq13 none swap sw,comment=x\\,nofail 0 0",
            &["dev-vdq13.swap"],
            "swap.target",
        ),
        (
            "/dev/vdq14 none swap sw,comment=x\\,noauto 0 0",
            &["dev-vdq14.swap"],
            "swap.target",
        ),
        (
            "/dev/vdq21 none swap sw,noauto,comment=x\\054auto 0 0",
            &["dev-vdq21.swap"],
            "swap.target",
        ),
    ] {
        let entry = &parse_fstab(line)[0];
        for decision in [
            decide_line(line),
            decide_own(line),
            decide(entry, &mounts(), Path::new(HIDDEN), &absent),
            decide_hidden_fstab(entry, &mounts(), Path::new(HIDDEN), &absent),
        ] {
            let Decision::Mask {
                units: masked,
                unreached,
                ..
            } = &decision
            else {
                panic!("{line}: {decision:?}");
            };
            assert_eq!(masked, units, "{line}");
            assert_eq!(
                unreached,
                &Some(Unreached {
                    target: boot.into(),
                    cause: Unskippable::MayRequire,
                    origin: Origin::Fstab,
                }),
                "{line}"
            );
            let warning = decision.warning().expect("a warning");
            assert!(
                warning.contains(&format!(
                    "where that option has {boot} or another unit require it, the hidden \
                     session will not reach that unit"
                )),
                "{warning}"
            );
            assert!(
                runtime_units(&[], std::slice::from_ref(&decision))
                    .required_masks
                    .is_empty(),
                "{line}"
            );
        }
    }
    // A line for /usr, which the generator mounts whatever its options say
    // (it ignored x-systemd.wanted-by= there and linked usr.mount into
    // local-fs.target.requires), is masked as one its target requires, with
    // the warning that the target is not reached: NAILS read the
    // x-systemd.wanted-by= after the backslash and gave none.
    let usr = decide_line("/dev/vdu2 /usr ext4 comment=x\\,x-systemd.wanted-by=foo.service 0 0");
    let Decision::Mask { unreached, .. } = &usr else {
        panic!("{usr:?}");
    };
    assert_eq!(
        unreached,
        &Some(Unreached {
            target: "local-fs.target".into(),
            cause: Unskippable::Unread,
            origin: Origin::Mandatory,
        })
    );
    let warning = usr.warning().expect("a warning");
    assert!(
        warning.contains("the hidden session will not reach local-fs.target, which requires it"),
        "{warning}"
    );
    assert_eq!(runtime_units(&[], &[usr]).required_masks.len(), 1);
}

/// A line with a backslash in its options that needs a noauto line's mount
/// may be one a target requires whatever `nofail` or `x-systemd.wanted-by=`
/// NAILS reads on it: systemd 260.5's fstab generator linked the tmpfs of
/// `comment=x\,nofail` and of `comment=x\,x-systemd.wanted-by=foo.service`
/// into `local-fs.target.requires`, and so mounts the noauto line below it at
/// boot. NAILS read the line as one nothing requires and masked the noauto
/// line with no warning, local-fs.target left unreached. It is skipped where
/// its device is there, and masked where it is not, with the warning that
/// the target may require it, which names that line.
#[test]
fn a_noauto_line_a_line_with_a_backslash_needs_is_skipped_or_warned_of() {
    for (dir, device, unit, below) in [
        ("/cdata", "/dev/vdc1", "cdata.mount", "comment=x\\,nofail"),
        (
            "/edata",
            "/dev/vde1",
            "edata.mount",
            "comment=x\\,x-systemd.wanted-by=foo.service",
        ),
    ] {
        let fstab = format!("{device} {dir} ext4 noauto 0 0\ntmpfs {dir}/tmp tmpfs {below} 0 0\n");
        let tmp = format!("{dir}/tmp");
        let there = decide_fstab(&fstab, true);
        let skip = there[0]
            .skip()
            .unwrap_or_else(|| panic!("{fstab}: {there:?}"));
        assert_eq!(skip.units, [unit], "{fstab}");
        assert_eq!(skip.device.as_deref(), Some(Path::new(device)), "{fstab}");
        assert_eq!(
            reason(&there[0]),
            format!("noauto, but the line for {tmp} needs its mount, so the boot may mount it")
        );
        let absent = decide_fstab(&fstab, false);
        let Decision::Mask { unreached, .. } = &absent[0] else {
            panic!("{fstab}: {absent:?}");
        };
        assert_eq!(
            unreached,
            &Some(Unreached {
                target: "local-fs.target".into(),
                cause: Unskippable::NoDevice(device.into()),
                origin: Origin::Needed {
                    lines: vec![tmp.clone().into()],
                    may: true,
                    by_path: true,
                },
            }),
            "{fstab}"
        );
        assert_eq!(
            absent[0].warning().expect("a warning"),
            format!(
                "{dir} is masked rather than skipped, as its device {device} is not there: \
                 local-fs.target may require it, through a line that needs it only as the mount \
                 for a path, so the hidden session may not reach it, and the units only that \
                 target pulls in may not start there. Attach the device before activating, or \
                 give the fstab entry for {tmp} the nofail option (x-systemd.wanted-by= in place \
                 of an x-systemd.required-by= it gives)"
            )
        );
        assert_eq!(
            runtime_units(&parse_fstab(&fstab), &absent).required_masks,
            [],
            "{fstab}"
        );
    }

    // With a line elsewhere whose backslash may hide what it pulls in, the
    // reason names the line below, and the warning names both: NAILS named
    // only the other one, and told to give it the nofail option.
    let both = "/dev/vdb1 /data ext4 noauto 0 0\n\
                tmpfs /data/tmp tmpfs comment=x\\054nofail 0 0\n\
                /dev/vdc1 /cdata ext4 noauto 0 0\n\
                tmpfs /cdata/tmp tmpfs comment=x\\,nofail 0 0\n";
    let absent = decide_fstab(both, false);
    // By depth: /data, /cdata, then the tmpfs lines.
    assert_eq!(
        reason(&absent[1]),
        "noauto, but the line for /cdata/tmp needs its mount, so the boot may mount it"
    );
    let warning = absent[1].warning().expect("a warning");
    assert!(
        warning.contains("local-fs.target may require it")
            && warning.ends_with(
                "give the fstab entries for /data/tmp and /cdata/tmp the nofail option \
                 (x-systemd.wanted-by= in place of an x-systemd.required-by= they give)"
            ),
        "{warning}"
    );
    assert_eq!(
        runtime_units(&parse_fstab(both), &absent).required_masks,
        []
    );
}

/// A line with a backslash in its options that needs a noauto line's mount
/// is no line a target surely requires: systemd 260.5's fstab generator
/// read `comment=x\054nofail` as `nofail` and linked the tmpfs below the
/// noauto line into `local-fs.target.wants` alone, and `comment=x\054noauto`
/// as `noauto`, linking it nowhere. NAILS warned that the hidden session will
/// not reach local-fs.target, which requires the noauto line, and recorded
/// the mask as a required one, which `nails status` listed. Where its
/// device is not there, the warning says the target may require it, and,
/// as the tmpfs needs it only for a path, may not be reached, the mask is
/// not recorded, and the reason says that the boot may mount it.
#[test]
fn a_noauto_line_a_line_with_a_backslash_needs_is_one_a_target_may_require() {
    for below in ["comment=x\\054nofail", "comment=x\\054noauto"] {
        let fstab = format!("/dev/vdb1 /data ext4 noauto 0 0\ntmpfs /data/tmp tmpfs {below} 0 0\n");
        let there = decide_fstab(&fstab, true);
        assert_eq!(
            there[0].skip().expect("a skip").units,
            ["data.mount"],
            "{below}"
        );
        let absent = decide_fstab(&fstab, false);
        assert_eq!(
            reason(&absent[0]),
            "noauto, but the line for /data/tmp needs its mount, so the boot may mount it",
            "{below}"
        );
        let Decision::Mask { unreached, .. } = &absent[0] else {
            panic!("{below}: {absent:?}");
        };
        assert_eq!(
            unreached,
            &Some(Unreached {
                target: "local-fs.target".into(),
                cause: Unskippable::NoDevice("/dev/vdb1".into()),
                origin: Origin::Needed {
                    lines: vec!["/data/tmp".into()],
                    may: true,
                    by_path: true,
                },
            }),
            "{below}"
        );
        let warning = absent[0].warning().expect("a warning");
        assert!(
            warning.contains(
                "local-fs.target may require it, through a line that needs it only as the mount \
                 for a path, so the hidden session may not reach it"
            ) && !warning.contains("will not"),
            "{warning}"
        );
        assert_eq!(
            runtime_units(&parse_fstab(&fstab), &absent).required_masks,
            [],
            "{below}"
        );
    }
}
