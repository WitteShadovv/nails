// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The fstab policy reads each option as systemd 260.5's fstab generator read
//! it on a test root (`SYSTEMD_FSTAB=<file> systemd-fstab-generator <dirs>`):
//! by its name, alone or with a value, the last of a pair winning. A line it
//! leaves alone as never mounted gives only options NAILS reads, by the lists
//! the `backend-entries` check reads a plain line by; any other line it keeps
//! off is masked, with a reason that names the option.

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
/// them: they stay left alone, as next leaves them.
#[test]
fn a_noauto_line_nails_reads_fully_is_left_alone_as_before() {
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
        let target = parse_fstab(line)[0].file.clone();
        assert_eq!(
            decide_line(line),
            Decision::Leave {
                target,
                reason: "noauto: never mounted",
            },
            "{line}"
        );
    }
}

/// A noauto line with an option NAILS does not read, or one it knows in
/// another form, may be mounted at boot whatever noauto says: masked, mount
/// and automount, with the option named and never its value.
#[test]
fn a_noauto_line_with_an_option_nails_does_not_read_is_masked() {
    for (options, named) in [
        (
            "noauto,x-systemd.before=multi-user.target",
            "x-systemd.before",
        ),
        ("noauto,x-systemd.after=foo.service", "x-systemd.after"),
        (
            "noauto,x-systemd.requires=foo.service",
            "x-systemd.requires",
        ),
        ("noauto,X-mount.subdir=sub", "X-mount.subdir"),
        (
            "noauto,x-systemd.requires-mounts-for=srv",
            "x-systemd.requires-mounts-for",
        ),
        ("noauto,nofail=1", "nofail"),
        ("noauto,secret=/dev/vdc", "secret"),
        ("noauto,x-nails.probe", "x-nails.probe"),
        ("noauto,loop", "loop"),
        ("noauto,x-systemd.pcrfs=1", "x-systemd.pcrfs"),
        // systemd keeps the comma after a backslash in the option, and
        // libmount decodes \054 to a comma: the generator mounted these at
        // boot, and set up an automount for the last.
        ("noauto,auto=x\\,noauto", "auto"),
        ("noauto,auto=\\,noauto", "auto"),
        ("noauto,comment=x\\054auto", "comment"),
        ("noauto,x-gvfs-show\\054auto", "x-gvfs-show\\054auto"),
        ("noauto,comment=x\\054x-systemd.automount", "comment"),
        // A comma between quotes stays in the option.
        ("noauto,comment=\"x,auto\"", "comment"),
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
            assert_eq!(*unreached, None, "{options}");
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
/// read, or one with a backslash or a quote, is masked rather than skipped:
/// the option may pull in units that act on the disk, which a skip would
/// leave free to start. The warning says the target that requires it is not
/// reached.
#[test]
fn a_mounted_at_boot_line_with_a_systemd_option_nails_does_not_read_is_masked() {
    for (line, units, named) in [
        (
            "/dev/vdb1 /opt ext4 defaults,x-systemd.nails-probe=1 0 0",
            &["opt.mount", "opt.automount"][..],
            "x-systemd.nails-probe",
        ),
        (
            "/dev/vdb1 /opt ext4 defaults,x-initrd.attach 0 0",
            &["opt.mount", "opt.automount"],
            "x-initrd.attach",
        ),
        (
            "/dev/vdb1 /opt ext4 defaults,x-systemd.requires=a\\054b.service 0 0",
            &["opt.mount", "opt.automount"],
            "x-systemd.requires",
        ),
        (
            "/dev/vdb1 /opt ext4 defaults,x-systemd.after=a\\,b.service 0 0",
            &["opt.mount", "opt.automount"],
            "x-systemd.after",
        ),
        (
            "server:/x /net nfs4 rw,comment=\"a,x-systemd.requires=b.service\" 0 0",
            &["net.mount", "net.automount"],
            "comment",
        ),
        (
            "/dev/vdb2 none swap sw,x-systemd.nails-probe 0 0",
            &["dev-vdb2.swap"],
            "x-systemd.nails-probe",
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
        assert_eq!(
            unreached.as_ref().map(|u| &u.cause),
            Some(&Unskippable::Unread),
            "{line}"
        );
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
        "noauto, but the line for /data/tmp needs a path in it, so the boot mounts it"
    );
    assert!(matches!(decisions[1], Decision::Leave { .. }));

    let absent = decide_fstab(fstab, false);
    let Decision::Mask {
        units, unreached, ..
    } = &absent[0]
    else {
        panic!("{absent:?}");
    };
    assert_eq!(units, &["data.mount"]);
    assert_eq!(
        unreached,
        &Some(Unreached {
            target: "local-fs.target".into(),
            cause: Unskippable::NoDevice("/dev/vdb1".into()),
            origin: Origin::Needed,
        })
    );
    let warning = absent[0].warning().expect("a warning");
    assert!(
        warning.ends_with("give the fstab entry that needs it the nofail option"),
        "{warning}"
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
        assert_eq!(units, &["data.mount"], "{fstab}");
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
        assert_eq!(
            decisions[0],
            Decision::Leave {
                target: "/data".into(),
                reason: NEVER_MOUNTED,
            },
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
