// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The backend-entries check on the options of fstab and crypttab lines:
//! only those on NAILS's lists, in the forms they list, keep a line plain, and
//! an option that names a path or a device is read as a source is. The lines
//! of stock installs keep to the lists.

use super::*;
use crate::hidden_root::separation::Unplain;

/// The failure that names `finding`, a line that names the volume, alone.
fn names_the_volume(finding: &str) -> String {
    format!("The decoy's configuration names the volume at /mnt: {finding}. {STORED}")
}

/// The failure that names `finding`, a line that may name the volume, alone.
fn may_name_the_volume(finding: &str) -> String {
    format!("The decoy's configuration may name the volume at /mnt: {finding}. {STORED}")
}

/// The reason of a line that gives `option`, which no list holds.
fn unknown(option: &str) -> String {
    format!("it gives {option}, an option whose effect NAILS does not read")
}

/// The reason of a line that gives `option` with a value NAILS does not read.
fn unread(option: &str) -> String {
    format!("it gives {option} with a value NAILS does not read")
}

/// The fix for fstab lines that are not plain by the options `options`.
fn unplain_by(options: &[&str]) -> String {
    let options: Vec<String> = options.iter().map(|option| option.to_string()).collect();
    format!("{UNPLAIN}\n{}", unread_options(&options))
}

/// The fstab of a decoy with its line for / and `line` for /home of the
/// btrfs filesystem a subvolume root lies beside (`BESIDE_HOME`).
fn home_line(options: &str) -> MockFilesystem {
    rendered(
        BESIDE_HOME,
        &format!("/dev/vda1 / ext4 defaults 0 1\n/dev/vda2 /home btrfs {options} 0 0\n"),
    )
}

#[test]
fn with_the_flag_a_line_linked_into_another_unit_or_with_a_subdir_fails() {
    // systemd 260.5 linked the line for /home that names a unit by
    // `x-systemd.wanted-by=` or `x-systemd.required-by=` only into that unit,
    // in place of local-fs.target, so the boot mounts it only if that unit
    // starts, with `noauto` too, and `X-mount.subdir=` has libmount mount a
    // folder of the filesystem in place of what the line names. NAILS reads
    // neither, so the line is not plain and fails with the flag too, naming
    // the option, and the check says to write it without it.
    for (options, option, reason) in [
        (
            "subvol=/home,x-systemd.wanted-by=never.service",
            "x-systemd.wanted-by",
            unread("x-systemd.wanted-by"),
        ),
        (
            "subvol=/home,noauto,x-systemd.wanted-by=never.service",
            "x-systemd.wanted-by",
            unread("x-systemd.wanted-by"),
        ),
        (
            "subvol=/home,x-systemd.required-by=never.service",
            "x-systemd.required-by",
            unread("x-systemd.required-by"),
        ),
        (
            "subvol=/home,X-mount.subdir=sub",
            "X-mount.subdir",
            unknown("X-mount.subdir"),
        ),
    ] {
        let fs = home_line(options);
        assert!(hidden_volume_with_the_flag(&fs).is_warn(), "{options}");
        for allow in [Allow::DecoyStorage, Allow::Nothing] {
            let result = run_allowing(&fs, allow);
            assert_eq!(
                result.message(),
                may_name_the_volume(&not_plain("/dev/vda2 /home btrfs", &reason)),
                "{options}"
            );
            assert_eq!(
                result.remediation(),
                Some(unplain_by(&[option]).as_str()),
                "{options}"
            );
        }
    }
    // With local-fs.target, which pulls the line in as without it, the line
    // is the decoy's own, with `noauto` too.
    for options in [
        "subvol=/home,x-systemd.wanted-by=local-fs.target",
        "subvol=/home,x-systemd.required-by=local-fs.target",
        "subvol=/home,noauto,x-systemd.wanted-by=local-fs.target",
    ] {
        let result = run_allowing(&home_line(options), Allow::DecoyStorage);
        assert!(result.is_pass(), "{options}: {result:?}");
        assert_eq!(
            result.message(),
            only_the_decoys_own_line("/home"),
            "{options}"
        );
    }
}

#[test]
fn a_line_with_a_subdir_of_the_roots_filesystem_fails_both_checks() {
    // The top of the root's filesystem at /home, whose line has libmount
    // mount the root's own folder or subvolume there at the next boot. The
    // line is not plain, so it fails backend-entries, and makes no mount of
    // the decoy's own, so the mount at /home, which shows the root's folder,
    // is a second mount. Without `X-mount.subdir=`, the lines are the
    // decoy's own.
    let ext4 = "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
                3 1 8:1 / /home rw - ext4 /dev/vda1 rw\n\
                5 1 8:1 /srv/x /mnt rw - ext4 /dev/vda1 rw\n";
    let btrfs = "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
                 2 1 0:40 / /home rw - btrfs /dev/vda2 rw,subvolid=5,subvol=/\n\
                 5 1 0:40 /vault /mnt rw - btrfs /dev/vda2 rw,subvolid=300,subvol=/vault\n";
    for (table, line, shown) in [
        (
            ext4,
            "/dev/vda1 /home ext4 X-mount.subdir=srv/x 0 2",
            "/dev/vda1 /home ext4",
        ),
        (
            btrfs,
            "/dev/vda2 /home btrfs subvolid=5,X-mount.subdir=vault 0 0",
            "/dev/vda2 /home btrfs",
        ),
    ] {
        let fs = rendered(table, &format!("/dev/vda1 / ext4 defaults 0 1\n{line}\n"));
        let gate = hidden_volume_with_the_flag(&fs);
        assert!(gate.is_fail(), "{line}: {gate:?}");
        assert!(gate.message().contains("/home"), "{line}: {gate:?}");
        let result = run_allowing(&fs, Allow::DecoyStorage);
        assert!(result.is_fail(), "{line}: {result:?}");
        assert!(
            result
                .message()
                .contains(&not_plain(shown, &unknown("X-mount.subdir"))),
            "{line}: {result:?}"
        );
    }
    for (table, line) in [
        (ext4, "/dev/vda1 /home ext4 defaults 0 2"),
        (btrfs, "/dev/vda2 /home btrfs subvolid=5 0 0"),
    ] {
        let fs = rendered(table, &format!("/dev/vda1 / ext4 defaults 0 1\n{line}\n"));
        assert!(hidden_volume_with_the_flag(&fs).is_warn(), "{line}");
        assert!(run_allowing(&fs, Allow::DecoyStorage).is_pass(), "{line}");
    }
}

/// The decoy fixture, with the hidden volume `data` (dm-9) on the whole of
/// sdb, at /mnt, sdc another drive, and `crypttab`.
fn decoy_with_crypttab(crypttab: &str) -> Decoy {
    let decoy = decoy().encrypted().file("/etc/crypttab", crypttab);
    decoy.fs.mock_set_device_node("/dev/dm-9");
    decoy.fs.mock_set_device_node("/dev/sdb");
    decoy
}

/// The hidden-volume check of the root at /mnt of `decoy`, with no flag.
fn gate(decoy: &Decoy) -> CheckResult {
    crate::preflight::HiddenVolumeCheck::new(PathBuf::from("/mnt"))
        .run(&decoy.fs)
        .unwrap()
}

#[test]
fn a_crypttab_token_option_that_names_the_drive_or_a_file_in_the_volume_fails() {
    // systemd 260.5's `systemd-cryptsetup` opened the `tpm2-device=` of a
    // line read-write and wrote TPM commands to it; it opens the
    // `fido2-device=` and reads the `tpm2-signature=` and `tpm2-pcrlock=`
    // files. Of a line for another drive, sdc, a device of the hidden drive
    // fails it, and a file in the volume too, which the attach gate then
    // counts as the decoy's storage.
    for (options, why, gate_refuses) in [
        (
            "luks,tpm2-device=/dev/sdb,nofail",
            "it opens the volume at /mnt or a device it is stored on through its option \
             tpm2-device=",
            false,
        ),
        (
            "luks,fido2-device=/dev/sdb,nofail",
            "it opens the volume at /mnt or a device it is stored on through its option \
             fido2-device=",
            false,
        ),
        (
            "luks,tpm2-device=/dev/mapper/data",
            "it opens the volume at /mnt or a device it is stored on through its option \
             tpm2-device=",
            false,
        ),
        (
            "luks,tpm2-device=auto,tpm2-signature=/mnt/sig.json,nofail",
            "the path its option tpm2-signature= names lies in the volume at /mnt",
            true,
        ),
        (
            "luks,tpm2-device=auto,tpm2-pcrlock=/mnt/pcrlock.json,nofail",
            "the path its option tpm2-pcrlock= names lies in the volume at /mnt",
            true,
        ),
    ] {
        let decoy = decoy_with_crypttab(&format!("vault /dev/sdc none {options}\n"));
        for allow in [Allow::Nothing, Allow::DecoyStorage] {
            let result = run_allowing(&decoy.fs, allow);
            assert_eq!(
                result.message(),
                names_the_volume(&format!("/etc/crypttab: 'vault /dev/sdc' ({why})")),
                "{options}"
            );
            assert_eq!(result.remediation(), Some(REMEDIATION), "{options}");
        }
        assert_eq!(gate(&decoy).is_fail(), gate_refuses, "{options}");
    }
    // A driver:param form, which loads a TPM2 driver and can run a program
    // (`cmd:`), and a path that is not absolute, are not plain.
    for (options, option) in [
        ("luks,tpm2-device=swtpm:path=/run/swtpm.sock", "tpm2-device"),
        ("luks,tpm2-device=cmd:/srv/tpm", "tpm2-device"),
        ("luks,fido2-device=hidraw0", "fido2-device"),
        (
            "luks,tpm2-device=auto,tpm2-signature=sig.json",
            "tpm2-signature",
        ),
    ] {
        let decoy = decoy_with_crypttab(&format!("vault /dev/sdc none {options}\n"));
        let result = decoy.run();
        assert_eq!(
            result.message(),
            may_name_the_volume(&format!(
                "/etc/crypttab: 'vault /dev/sdc' (NAILS reads only plain lines, and {})",
                unread(option)
            )),
            "{options}"
        );
        let options = [option.to_string()];
        assert_eq!(
            result.remediation(),
            Some(format!("{UNPLAIN_CRYPTTAB}\n{}", unread_options(&options)).as_str())
        );
    }
}

#[test]
fn on_an_encrypted_decoy_its_own_line_with_a_token_keeps_to_the_list() {
    // `tpm2-device=auto` and the TPM's own node name no device of the drive,
    // and the stock options of the decoy's own root line of Debian, Ubuntu,
    // Fedora and a TPM2 or FIDO2 token are all read: the flag lets the line
    // be.
    for options in [
        "luks,discard,tpm2-device=auto",
        "luks,discard,tpm2-device=/dev/tpmrm0",
        "luks,fido2-device=auto",
        "luks,discard",
        "luks",
        "discard",
        "luks,discard,x-initrd.attach",
        "luks,tpm2-device=auto,tpm2-pcrs=7+11,headless=true",
        "luks,password-echo=no,x-systemd.device-timeout=0,timeout=180,tries=3",
    ] {
        let decoy = encrypted_decoy_with("/srv/x", options);
        let result = run_allowing(&decoy.fs, Allow::DecoyStorage);
        assert!(result.is_pass(), "{options}: {result:?}");
        assert_eq!(
            result.message(),
            only_the_decoys_own_lines("line for /", "cryptroot /dev/nvme0n1p3"),
            "{options}"
        );
    }
    // The same line with a token option in a form NAILS does not read, or an
    // option no list holds, fails with the flag too.
    for (options, reason) in [
        ("luks,tpm2-device=cmd:/srv/x/tpm", unread("tpm2-device")),
        ("luks,pkcs11-uri=auto", unknown("pkcs11-uri")),
        ("luks,discard=on", unread("discard")),
    ] {
        let decoy = encrypted_decoy_with("/srv/x", options);
        let result = run_allowing(&decoy.fs, Allow::DecoyStorage);
        assert_eq!(
            result.message(),
            may_name_the_volume(&format!(
                "/etc/crypttab: 'cryptroot /dev/nvme0n1p3' (NAILS reads only plain lines, and \
                 {reason})"
            )),
            "{options}"
        );
    }
}

#[test]
fn a_filesystem_option_that_opens_a_device_of_the_drive_fails() {
    // A line for another drive, sdc, whose filesystem opens and writes to a
    // device it names besides its source: ext4's external journal, by its
    // path or its number (2064 is 8:16, sdb; 65033 is 254:9, the mapping),
    // XFS's log and realtime devices, and a btrfs member device. A device of
    // the hidden drive fails the line, with the flag too; one of another
    // drive does not.
    for (line, option) in [
        (
            "/dev/sdc /data ext4 journal_path=/dev/sdb 0 2",
            "journal_path",
        ),
        (
            "/dev/sdc /data ext4 journal_path=/dev/mapper/data 0 2",
            "journal_path",
        ),
        ("/dev/sdc /data ext4 journal_dev=2064 0 2", "journal_dev"),
        ("/dev/sdc /data ext4 journal_dev=65033 0 2", "journal_dev"),
        ("/dev/sdc /data ext4 journal_dev=0x810 0 2", "journal_dev"),
        ("/dev/sdc /data xfs logdev=/dev/sdb 0 0", "logdev"),
        ("/dev/sdc /data xfs rtdev=/dev/mapper/data 0 0", "rtdev"),
        ("/dev/sdc /data btrfs device=/dev/sdb 0 0", "device"),
    ] {
        let decoy = decoy().file(
            "/etc/fstab",
            &format!("/dev/nvme0n1p3 / ext4 defaults 0 1\n{line}\n"),
        );
        let shown: Vec<&str> = line.split_whitespace().take(3).collect();
        for allow in [Allow::Nothing, Allow::DecoyStorage] {
            let result = run_allowing(&decoy.fs, allow);
            assert_eq!(
                result.message(),
                names_the_volume(&format!(
                    "/etc/fstab: '{}' (it opens the volume at /mnt or a device it is stored \
                     on through its option {option}=)",
                    shown.join(" ")
                )),
                "{line}"
            );
        }
    }
    for line in [
        "/dev/sdc /data ext4 journal_path=/dev/sdc 0 2",
        "/dev/sdc /data ext4 journal_dev=2080 0 2",
        "/dev/sdc /data xfs logdev=/dev/nvme0n1p3 0 0",
        "/dev/sdc /data btrfs device=/dev/sdc 0 0",
    ] {
        let decoy = decoy().file(
            "/etc/fstab",
            &format!("/dev/nvme0n1p3 / ext4 defaults 0 1\n{line}\n"),
        );
        let result = decoy.run();
        assert!(result.is_pass(), "{line}: {result:?}");
    }
    // The decoy's own line for /home, which names a device of the root's
    // btrfs filesystem by `device=` as its source does, stays its own.
    let result = run_allowing(
        &home_line("subvol=/home,device=/dev/vda2"),
        Allow::DecoyStorage,
    );
    assert_eq!(result.message(), only_the_decoys_own_line("/home"));
}

#[test]
fn an_option_that_names_a_path_in_the_volume_fails() {
    // A path whose mounts systemd makes first, a credentials file mount.cifs
    // reads and an overlay's folders, read as a bind line's source is, with
    // no link followed: in the volume, the line fails, and the attach gate
    // counts the filesystem that holds the path as the decoy's.
    for (line, option) in [
        (
            "/dev/sdc /data ext4 x-systemd.requires-mounts-for=/mnt/x 0 2",
            "x-systemd.requires-mounts-for",
        ),
        (
            "overlay /data overlay lowerdir=/srv/a,upperdir=/mnt/u,workdir=/srv/w 0 0",
            "upperdir",
        ),
        (
            "overlay /data overlay lowerdir=/srv/a:/mnt/l 0 0",
            "lowerdir",
        ),
        (
            "//server/share /data cifs credentials=/mnt/creds,_netdev 0 0",
            "credentials",
        ),
    ] {
        let decoy = decoy().encrypted().file(
            "/etc/fstab",
            &format!("/dev/nvme0n1p3 / ext4 defaults 0 1\n{line}\n"),
        );
        let shown: Vec<&str> = line.split_whitespace().take(3).collect();
        let result = decoy.run();
        assert_eq!(
            result.message(),
            names_the_volume(&format!(
                "/etc/fstab: '{}' (the path its option {option}= names lies in the volume at \
                 /mnt)",
                shown.join(" ")
            )),
            "{line}"
        );
        let gate = gate(&decoy);
        assert_eq!(
            gate.message(),
            "/mnt is not a volume of its own: it is the filesystem this computer has mounted at \
             /mnt",
            "{line}"
        );
    }
    // With the flag, in the root's folder.
    let fs = rendered(
        BIND_OF_ROOT,
        "/dev/vda1 / ext4 defaults 0 1\n\
         overlay /srv/o overlay lowerdir=/srv/x,upperdir=/var/u,workdir=/var/w 0 0\n",
    );
    let result = run_allowing(&fs, Allow::DecoyStorage);
    assert_eq!(
        result.message(),
        names_the_volume(
            "/etc/fstab: 'overlay /srv/o overlay' (the path its option lowerdir= names lies in \
             the volume at /mnt)"
        )
    );
    // Elsewhere, they name no part of it.
    for line in [
        "/dev/sdc /data ext4 x-systemd.requires-mounts-for=/srv 0 2",
        "overlay /data overlay lowerdir=/srv/a:/srv/b,upperdir=/var/u,workdir=/var/w 0 0",
        "//server/share /data cifs credentials=/etc/creds,_netdev 0 0",
    ] {
        let decoy = decoy().encrypted().file(
            "/etc/fstab",
            &format!("/dev/nvme0n1p3 / ext4 defaults 0 1\n{line}\n"),
        );
        assert!(decoy.run().is_pass(), "{line}");
        assert!(gate(&decoy).is_pass(), "{line}: {:?}", gate(&decoy));
    }
}

#[test]
fn an_option_no_list_holds_fails_with_a_fix_that_names_it() {
    // Of a line of local storage, any option no list holds; of any other
    // line, one whose value may name a path or a device, as a `driver:param`
    // form or a tag does.
    for (line, reasons, options) in [
        (
            "/dev/sdc /data ext4 foo=/dev/sdb 0 2",
            vec![unknown("foo")],
            vec!["foo"],
        ),
        (
            "/dev/sdc /data ext4 x-foo=1,ro=fs 0 2",
            vec![unknown("x-foo"), unread("ro")],
            vec!["x-foo", "ro"],
        ),
        (
            "/dev/sdc /data ext4 ro,verity.hashdevice=/dev/sdb 0 2",
            vec![unknown("verity.hashdevice")],
            vec!["verity.hashdevice"],
        ),
        (
            "tmpfs /data tmpfs size=1G,foo=/mnt/x 0 0",
            vec![unknown("foo")],
            vec!["foo"],
        ),
        (
            "server:/x /data nfs4 bar=cmd:prog 0 0",
            vec![unknown("bar")],
            vec!["bar"],
        ),
    ] {
        let decoy = decoy().file(
            "/etc/fstab",
            &format!("/dev/nvme0n1p3 / ext4 defaults 0 1\n{line}\n"),
        );
        let shown: Vec<&str> = line.split_whitespace().take(3).collect();
        let result = decoy.run();
        assert_eq!(
            result.message(),
            may_name_the_volume(&not_plain(&shown.join(" "), &reasons.join(" and "))),
            "{line}"
        );
        assert_eq!(
            result.remediation(),
            Some(unplain_by(&options).as_str()),
            "{line}"
        );
    }
    // A flag with a value, an option of another filesystem and one that
    // links the line into a unit fail the decoy's own line with the flag.
    for (options, reason) in [
        ("subvol=/home,nofail=1", unread("nofail")),
        ("subvol=/home,errors=remount-ro", unknown("errors")),
        (
            "subvol=/home,x-systemd.requires=never.service",
            unknown("x-systemd.requires"),
        ),
        ("subvol=/home,NOAUTO", unknown("NOAUTO")),
    ] {
        let result = run_allowing(&home_line(options), Allow::DecoyStorage);
        assert_eq!(
            result.message(),
            may_name_the_volume(&not_plain("/dev/vda2 /home btrfs", &reason)),
            "{options}"
        );
    }
}

#[test]
fn the_gate_counts_a_line_with_an_option_nails_does_not_read_as_mounted() {
    // A noauto line for the volume is a mere recipe only when NAILS reads
    // every option it gives: one that may pull it in at boot, such as a unit
    // named by x-systemd.wanted-by= or an option no list holds, makes the
    // gate count the volume as the decoy's storage, failing closed.
    for (options, refused) in [
        ("noauto", false),
        ("noauto,nofail,x-systemd.device-timeout=10s", false),
        ("noauto,x-systemd.wanted-by=backup.service", true),
        ("noauto,x-foo", true),
        ("noauto,nofail=1", true),
    ] {
        let decoy = decoy().encrypted().file(
            "/etc/fstab",
            &format!(
                "/dev/nvme0n1p3 / ext4 defaults 0 1\n/dev/mapper/data /media/x ext4 {options} 0 0\n"
            ),
        );
        assert!(decoy.run().is_fail(), "{options}");
        assert_eq!(
            gate(&decoy).is_fail(),
            refused,
            "{options}: {:?}",
            gate(&decoy)
        );
    }
}

/// The fstab lines of stock installs: Debian's installer and cloud images,
/// Ubuntu's installer and cloud images, Fedora's installer and cloud images,
/// Arch's genfstab and NixOS's, with those of its test machines.
const STOCK_LINES: &[&str] = &[
    "UUID=0a1b /srv/s1 ext4 errors=remount-ro 0 1",
    "UUID=0A1B /srv/s2 vfat umask=0077 0 1",
    "UUID=0a1c none swap sw 0 0",
    "/dev/sr0 /media/cdrom0 iso9660 user,noauto 0 0",
    "PARTUUID=5e0b-01 /srv/s3 ext4 rw,discard,errors=remount-ro,x-systemd.growfs 0 1",
    "/dev/disk/by-uuid/0a1e /srv/s4 ext4 defaults 0 1",
    "/swap.img none swap sw 0 0",
    "LABEL=cloudimg-rootfs /srv/s5 ext4 discard,commit=30,errors=remount-ro 0 1",
    "UUID=f1 /srv/s6 btrfs subvol=root,compress=zstd:1 0 0",
    "UUID=F3 /srv/s7 vfat umask=0077,shortname=winnt 0 2",
    "/dev/mapper/luks-f4 /srv/s8 btrfs subvol=root,compress=zstd:1,x-systemd.device-timeout=0 0 0",
    "/dev/mapper/fedora-root /srv/s9 xfs defaults 0 0",
    "UUID=a1 /srv/s10 ext4 rw,relatime 0 1",
    "UUID=a2 /srv/s11 vfat rw,relatime,fmask=0022,dmask=0022,codepage=437,iocharset=ascii,\
     shortname=mixed,utf8,errors=remount-ro 0 2",
    "UUID=a3 /srv/s12 btrfs rw,relatime,compress=zstd:3,ssd,discard=async,space_cache=v2,\
     subvolid=256,subvol=/@ 0 0",
    "/swapfile none swap defaults 0 0",
    "UUID=a4 /srv/s13 xfs rw,relatime,attr2,inode64,logbufs=8,logbsize=32k,noquota 0 1",
    "/dev/disk/by-uuid/n1 /srv/s14 ext4 x-initrd.mount 0 1",
    "/dev/disk/by-uuid/N2 /srv/s15 vfat fmask=0077,dmask=0077 0 2",
    "nix-store /nix/.ro-store virtiofs x-initrd.mount,x-initrd.mount,ro 0 2",
    "tmpfs /nix/.rw-store tmpfs x-initrd.mount,x-initrd.mount,mode=0755 0 0",
    "overlay /nix/store overlay lowerdir=/sysroot/nix/.ro-store,\
     upperdir=/sysroot/nix/.rw-store/upper,workdir=/sysroot/nix/.rw-store/work,x-initrd.mount,\
     x-systemd.requires-mounts-for=/sysroot/nix/.ro-store 0 0",
    "/dev/disk/by-id/virtio-pool /pool btrfs x-systemd.makefs,x-systemd.makefs 0 0",
];

#[test]
fn the_lines_of_stock_installs_pass() {
    // For a volume of its own, no stock line names it.
    for line in STOCK_LINES {
        let decoy = decoy().file(
            "/etc/fstab",
            &format!("/dev/nvme0n1p3 / ext4 defaults 0 1\n{line}\n"),
        );
        let result = decoy.run();
        assert!(result.is_pass(), "{line}: {result:?}");
    }
    // The decoy's own lines for / and /home in the stock forms, with the flag.
    for options in [
        "errors=remount-ro",
        "rw,discard,errors=remount-ro,x-systemd.growfs",
        "discard,commit=30,errors=remount-ro",
        "rw,relatime",
        "x-initrd.mount,x-initrd.mount",
    ] {
        let fs = rendered(BIND_OF_ROOT, &format!("/dev/vda1 / ext4 {options} 0 1\n"));
        let result = run_allowing(&fs, Allow::DecoyStorage);
        assert_eq!(result.message(), only_the_decoys_own_line("/"), "{options}");
    }
    for options in [
        "subvol=home,compress=zstd:1",
        "subvol=home,compress=zstd:1,x-systemd.device-timeout=0",
        "rw,relatime,compress=zstd:3,ssd,discard=async,space_cache=v2,subvolid=257,subvol=/home",
        "defaults,subvol=/home",
    ] {
        let fs = home_line(&options.replace("subvol=home", "subvol=/home"));
        assert!(hidden_volume_with_the_flag(&fs).is_warn(), "{options}");
        let result = run_allowing(&fs, Allow::DecoyStorage);
        assert_eq!(
            result.message(),
            only_the_decoys_own_line("/home"),
            "{options}"
        );
    }
    // Debian's encrypted swap with a random key beside the root's own line.
    let decoy = encrypted_decoy().file(
        "/etc/crypttab",
        "cryptroot /dev/nvme0n1p3 none luks,discard\n\
         cryptswap /dev/sdc /dev/urandom swap,cipher=aes-xts-plain64,size=256,discard\n",
    );
    let result = run_allowing(&decoy.fs, Allow::DecoyStorage);
    assert!(result.is_pass(), "{result:?}");
}

/// The names of the volume's device and drive that udev, LVM and the kernel
/// make in /dev, each a link to the node it names: by-id, by-uuid,
/// by-partuuid and by-label links, a link in /dev/block by `major:minor`,
/// and an LVM-style link in a folder of /dev, and a path to the node with `.`
/// or a doubled `/` in it.
const DRIVE_NAMES: &[&str] = &[
    "/dev/disk/by-id/usb-hidden",
    "/dev/disk/by-uuid/vol",
    "/dev/disk/by-partuuid/pdrive",
    "/dev/disk/by-label/vault",
    "/dev/block/254:9",
    "/dev/block/8:16",
    "/dev/vg0/data",
    "/dev/./sdb",
    "/dev//sdb",
    "/dev/mapper/./data",
];

/// The decoy fixture, with `line` in its fstab and `crypttab`, and the links
/// of [`DRIVE_NAMES`], with links to sdc and out of /dev beside them.
fn decoy_with_names(line: &str, crypttab: &str) -> Decoy {
    let decoy = decoy_with_crypttab(crypttab).file(
        "/etc/fstab",
        &format!("/dev/nvme0n1p3 / ext4 defaults 0 1\n{line}\n"),
    );
    decoy.fs.mock_set_device_node("/dev/sdc");
    for (link, target) in [
        ("/dev/disk/by-id/usb-hidden", "../../sdb"),
        ("/dev/disk/by-uuid/vol", "../../dm-9"),
        ("/dev/disk/by-partuuid/pdrive", "../../sdb"),
        ("/dev/disk/by-label/vault", "../../dm-9"),
        ("/dev/block/254:9", "../dm-9"),
        ("/dev/block/8:16", "../sdb"),
        ("/dev/vg0/data", "../dm-9"),
        ("/dev/disk/by-id/usb-other", "../../sdc"),
        ("/dev/vlink", "/mnt/img"),
    ] {
        decoy.link(link, target);
    }
    decoy
}

#[test]
fn a_filesystem_option_that_names_the_drive_by_any_of_its_names_fails() {
    // ext4 opened the journal device that `journal_path=` names through a
    // link, through /dev/./ and through a doubled `/` (util-linux 2.42.4,
    // kernel 6.8), and systemd passes the option through unchanged. NAILS
    // resolves the device an option names as it resolves a line's source:
    // through links that stay in /dev, so every name of the volume's device
    // or drive fails the line, for each of the four options that name a
    // device by its path, with the flag too.
    for (fstype, option) in [
        ("ext4", "journal_path"),
        ("xfs", "logdev"),
        ("xfs", "rtdev"),
        ("btrfs", "device"),
    ] {
        for name in DRIVE_NAMES {
            let decoy =
                decoy_with_names(&format!("/dev/sdc /data {fstype} {option}={name} 0 0"), "");
            for allow in [Allow::Nothing, Allow::DecoyStorage] {
                let result = run_allowing(&decoy.fs, allow);
                assert_eq!(
                    result.message(),
                    names_the_volume(&format!(
                        "/etc/fstab: '/dev/sdc /data {fstype}' (it opens the volume at /mnt or a \
                         device it is stored on through its option {option}=)"
                    )),
                    "{option}={name}"
                );
                assert_eq!(result.remediation(), Some(REMEDIATION), "{option}={name}");
            }
        }
        // A link to another drive names none of it, and a link that leads
        // out of /dev is not followed.
        let other = decoy_with_names(
            &format!("/dev/sdc /data {fstype} {option}=/dev/disk/by-id/usb-other 0 0"),
            "",
        );
        assert!(other.run().is_pass(), "{option}: {:?}", other.run());
        let out = decoy_with_names(
            &format!("/dev/sdc /data {fstype} {option}=/dev/vlink 0 0"),
            "",
        );
        assert_eq!(
            out.run().message(),
            may_name_the_volume(&format!(
                "/etc/fstab: '/dev/sdc /data {fstype}' (where the path its option {option}= names \
                 lies cannot be told: /dev/vlink is a symbolic link that leads out of /dev, which \
                 NAILS does not follow)"
            )),
            "{option}"
        );
    }
    // The node itself, and a line's own source by such a link.
    let direct = decoy_with_names("/dev/sdc /data ext4 journal_path=/dev/sdb 0 2", "");
    assert!(direct.run().is_fail());
    let source = decoy_with_names("/dev/disk/by-id/usb-hidden /data ext4 nofail 0 2", "");
    assert_eq!(
        source.run().message(),
        names_the_volume(
            "/etc/fstab: '/dev/disk/by-id/usb-hidden /data ext4' (it mounts a device the volume \
             at /mnt is stored on, and the decoy's own boot needs it)"
        )
    );
    // A crypttab line's tpm2-device= by such a name.
    for name in DRIVE_NAMES {
        let decoy = decoy_with_names(
            "",
            &format!("vault /dev/sdc none luks,tpm2-device={name},nofail\n"),
        );
        assert_eq!(
            decoy.run().message(),
            names_the_volume(
                "/etc/crypttab: 'vault /dev/sdc' (it opens the volume at /mnt or a device it is \
                 stored on through its option tpm2-device=)"
            ),
            "{name}"
        );
    }
}

#[test]
fn loop_on_a_line_for_a_device_fails_and_its_mount_is_a_second_one() {
    // libmount 2.42.4 set up a loop device for `loop` whatever the source
    // was, so the decoy's own line for /home with `loop` mounts the root's
    // filesystem at the next boot through a new loop device, as a second
    // instance of it. The line is not plain, with the flag too, and makes no
    // mount of the decoy's own: with /home now the top of the root's
    // filesystem, the gate counts that mount as a second one.
    let reason = Unplain::Loop.reason();
    let table = format!("{BIND_OF_ROOT}6 1 8:1 / /home rw - ext4 /dev/vda1 rw\n");
    let fstab = |line: &str| format!("/dev/vda1 / ext4 defaults 0 1\n{line}\n");
    let fs = rendered(&table, &fstab("/dev/vda1 /home ext4 loop 0 2"));
    let gate = hidden_volume_with_the_flag(&fs);
    assert!(gate.is_fail(), "{gate:?}");
    assert!(gate.message().contains("/home"), "{gate:?}");
    let finding = not_plain("/dev/vda1 /home ext4", &reason);
    let result = run_allowing(&fs, Allow::DecoyStorage);
    assert_eq!(result.message(), may_name_the_volume(&finding));
    assert_eq!(result.remediation(), Some(unplain_by(&["loop"]).as_str()));
    let result = run_allowing(&fs, Allow::Nothing);
    assert!(result.message().contains(&finding), "{result:?}");
    // Without `loop` the line is the decoy's own.
    let fs = rendered(&table, &fstab("/dev/vda1 /home ext4 defaults 0 2"));
    assert!(hidden_volume_with_the_flag(&fs).is_warn());
    assert!(run_allowing(&fs, Allow::DecoyStorage).is_pass());
    // The btrfs line for the /home subvolume beside the root.
    let fs = home_line("subvol=/home,loop");
    for allow in [Allow::DecoyStorage, Allow::Nothing] {
        assert_eq!(
            run_allowing(&fs, allow).message(),
            may_name_the_volume(&not_plain("/dev/vda2 /home btrfs", &reason))
        );
    }
    // An image file's line, whose file NAILS reads as its source, keeps
    // `loop`: elsewhere it names nothing of the volume, and in the root's
    // folder it mounts a file in the volume.
    let fs = rendered(
        BIND_OF_ROOT,
        &fstab("/srv/disk.img /media/i ext4 loop,nofail 0 0"),
    );
    assert_eq!(
        run_allowing(&fs, Allow::DecoyStorage).message(),
        only_the_decoys_own_line("/")
    );
    let fs = rendered(
        BIND_OF_ROOT,
        &fstab("/srv/x/disk.img /media/i ext4 loop,nofail 0 0"),
    );
    assert_eq!(
        run_allowing(&fs, Allow::DecoyStorage).message(),
        names_the_volume(
            "/etc/fstab: '/srv/x/disk.img /media/i ext4' (the file it names lies in the volume \
             at /mnt)"
        )
    );
}
