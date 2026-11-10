// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The backend-entries check on lines that `libmount`, `mount.fuse` and
//! systemd read otherwise than a plain reader would: a bind option with a
//! value, the source a FUSE line gives its program and the program itself,
//! white space other than a space or a tab before a `#`, an `ID=` tag, and
//! crypttab fields in quotes or with a backslash. Each either names the
//! volume as `libmount` or systemd reads it, or is a line NAILS does not
//! read, which fails, with the flag or without it.

use super::*;
use crate::hidden_root::separation::Unplain;

/// The failure that names `finding`, a line that names the volume, alone.
fn names_the_volume(finding: &str) -> String {
    format!("The decoy's configuration names the volume at /mnt: {finding}. {STORED}")
}

#[test]
fn a_bind_option_with_a_value_fails_with_the_flag_too() {
    // util-linux 2.42's mount binds for `bind=x`, `rbind=` and `bind="a,b"`
    // whatever the type, and so does systemd's mount of such a line, which
    // it requires or wants for local-fs.target. Each of these binds the
    // root's folder, or a folder of it, at every boot: hidden-volume passes
    // the root with the flag's warning, and backend-entries fails the line.
    for (line, why) in [
        (
            "/srv/x /mnt none bind=x 0 0",
            "it mounts the volume at /mnt",
        ),
        (
            "/srv/x /mnt tmpfs bind=x 0 0",
            "it mounts the volume at /mnt",
        ),
        ("/srv/x /mnt nfs bind=x 0 0", "it mounts the volume at /mnt"),
        (
            "/srv/x /mnt overlay rbind= 0 0",
            "it mounts the volume at /mnt",
        ),
        (
            "/srv/x/sub /srv/sub 9p bind=1,nofail 0 0",
            "it mounts a folder of the volume at /mnt",
        ),
        (
            "/srv/x /mnt none bind=\"a,b\" 0 0",
            "it mounts the volume at /mnt",
        ),
        (
            "/srv/x /mnt proc bind=x 0 0",
            "it mounts the volume at /mnt",
        ),
        (
            "/srv/x /mnt tmpfs bind=x,noauto,x-systemd.automount 0 0",
            "it mounts the volume at /mnt",
        ),
    ] {
        let fs = rendered(
            BIND_OF_ROOT,
            &format!("/dev/vda1 / ext4 defaults 0 1\n{line}\n"),
        );
        assert!(hidden_volume_with_the_flag(&fs).is_warn(), "{line}");
        let result = run_allowing(&fs, Allow::DecoyStorage);
        assert!(result.is_fail(), "{line}: {result:?}");
        let shown: Vec<&str> = line.split_whitespace().take(3).collect();
        assert_eq!(
            result.message(),
            names_the_volume(&format!("/etc/fstab: '{}' ({why})", shown.join(" "))),
            "{line}"
        );
        assert_eq!(result.remediation(), Some(REMEDIATION), "{line}");
        assert!(run_allowing(&fs, Allow::Nothing).is_fail(), "{line}");
    }
    // A relative source of such a line is not plain, whatever its type.
    for (line, shown) in [
        ("srv/x /mnt none bind=x 0 0", "srv/x /mnt none"),
        ("srv/x /mnt none bind=\"a,b\" 0 0", "srv/x /mnt none"),
        ("srv/x /mnt zfs bind=x 0 0", "srv/x /mnt zfs"),
        ("srv/x /mnt fuse bind=x 0 0", "srv/x /mnt fuse"),
    ] {
        let fs = rendered(
            BIND_OF_ROOT,
            &format!("/dev/vda1 / ext4 defaults 0 1\n{line}\n"),
        );
        assert!(hidden_volume_with_the_flag(&fs).is_warn(), "{line}");
        fails_as_not_plain(&fs, Allow::DecoyStorage, &not_plain(shown, RELATIVE));
    }
    // Plain bind lines from beside the root's folder name no part of it,
    // with an option with a value too.
    for line in [
        "/srv/y /srv/b none bind 0 0",
        "/srv/y /srv/b none rbind,nofail 0 0",
        "/srv/y /srv/b tmpfs bind=x 0 0",
    ] {
        let fs = rendered(
            BIND_OF_ROOT,
            &format!("/dev/vda1 / ext4 defaults 0 1\n{line}\n"),
        );
        let result = run_allowing(&fs, Allow::DecoyStorage);
        assert!(result.is_pass(), "{line}: {result:?}");
        assert_eq!(result.message(), only_the_decoys_own_line("/"), "{line}");
    }
}

#[test]
fn a_bind_option_with_a_value_from_a_volume_of_its_own_fails() {
    // The volume is the mapping `data` on the whole of sdb, at /mnt.
    for (line, finding) in [
        (
            "/mnt/data /srv/d tmpfs bind=x,nofail 0 0",
            "/etc/fstab: '/mnt/data /srv/d tmpfs' (it mounts a folder of the volume at /mnt)",
        ),
        (
            "/mnt/data /srv/d 9p rbind=,nofail 0 0",
            "/etc/fstab: '/mnt/data /srv/d 9p' (it mounts a folder of the volume at /mnt)",
        ),
        (
            "/mnt/data /srv/d none bind=x,nofail 0 0",
            "/etc/fstab: '/mnt/data /srv/d none' (it mounts a folder of the volume at /mnt)",
        ),
        (
            "/mnt /srv/d nfs bind=x,nofail 0 0",
            "/etc/fstab: '/mnt /srv/d nfs' (it mounts the volume at /mnt)",
        ),
    ] {
        let result = decoy()
            .file(
                "/etc/fstab",
                &format!("/dev/nvme0n1p3 / ext4 defaults 0 1\n{line}\n"),
            )
            .run();
        assert!(result.is_fail(), "{line}: {result:?}");
        assert_eq!(result.message(), names_the_volume(finding), "{line}");
        assert_eq!(result.remediation(), Some(REMEDIATION), "{line}");
    }
    let decoy = decoy().file(
        "/etc/fstab",
        "/dev/nvme0n1p3 / ext4 defaults 0 1\nmnt/data /srv/d none bind=x,nofail 0 0\n",
    );
    fails_as_not_plain(
        &decoy.fs,
        Allow::Nothing,
        &not_plain("mnt/data /srv/d none", RELATIVE),
    );
}

#[test]
fn a_bind_option_with_a_value_makes_the_decoys_own_second_mount() {
    // The root's folder bound at /mnt/again too, by a line with `bind=x`:
    // that mount is the decoy's own, so hidden-volume passes with the flag's
    // warning, and backend-entries fails the line, which binds the volume,
    // as it does for `bind`.
    let table = format!("{BIND_OF_ROOT}6 1 8:1 /srv/x /mnt/again rw - ext4 /dev/vda1 rw\n");
    for line in [
        "/srv/x /mnt/again tmpfs bind=x 0 0",
        "/srv/x /mnt/again none bind=x 0 0",
        "/srv/x /mnt/again none bind 0 0",
    ] {
        let fs = rendered(&table, &format!("/dev/vda1 / ext4 defaults 0 1\n{line}\n"));
        assert!(hidden_volume_with_the_flag(&fs).is_warn(), "{line}");
        let result = run_allowing(&fs, Allow::DecoyStorage);
        let shown: Vec<&str> = line.split_whitespace().take(3).collect();
        assert_eq!(
            result.message(),
            names_the_volume(&format!(
                "/etc/fstab: '{}' (it mounts the volume at /mnt)",
                shown.join(" ")
            )),
            "{line}"
        );
    }
    // With no line for it, the mount at /mnt/again is a second one.
    let fs = rendered(&table, "/dev/vda1 / ext4 defaults 0 1\n");
    assert!(hidden_volume_with_the_flag(&fs).is_fail());
}

#[test]
fn a_fuse_line_fails_by_the_source_it_gives_its_program() {
    // mount.fuse runs the program before the first # of a `fuse` line's
    // first field on the part after it, and hands a `fuse.<program>` line's
    // first field to that program: each of these gives it the root's folder
    // or an image file in it.
    for line in [
        "bindfs#/srv/x /media/b fuse nofail 0 0",
        "fuse2fs#/srv/x/disk.img /media/i fuse nofail 0 0",
        "/srv/x /media/b fuse.bindfs nofail 0 0",
    ] {
        let fs = rendered(
            BIND_OF_ROOT,
            &format!("/dev/vda1 / ext4 defaults 0 1\n{line}\n"),
        );
        assert!(hidden_volume_with_the_flag(&fs).is_warn(), "{line}");
        let result = run_allowing(&fs, Allow::DecoyStorage);
        let shown: Vec<&str> = line.split_whitespace().take(3).collect();
        assert_eq!(
            result.message(),
            names_the_volume(&format!(
                "/etc/fstab: '{}' (the file it names lies in the volume at /mnt)",
                shown.join(" ")
            )),
            "{line}"
        );
    }
    // A source that is no absolute path, for a program not known to take a
    // remote one, or none, or a # read otherwise: not plain, as are rclone's
    // local paths and a `fuse3` or `fuse.<program>` line with a #.
    let source = Unplain::FuseSource.reason();
    let hash = Unplain::FuseHash.reason();
    for (line, shown, reason) in [
        (
            "srv/x /media/b fuse.bindfs nofail 0 0",
            "srv/x /media/b fuse.bindfs",
            source.as_str(),
        ),
        (
            "srv/x /media/r fuse.rclone nofail 0 0",
            "srv/x /media/r fuse.rclone",
            source.as_str(),
        ),
        (
            ":local:/srv/x /media/r fuse.rclone nofail 0 0",
            ":local:/srv/x /media/r fuse.rclone",
            source.as_str(),
        ),
        (
            "/srv/x/a#/tmp /media/b fuse.bindfs nofail 0 0",
            "/srv/x/a#/tmp /media/b fuse.bindfs",
            hash.as_str(),
        ),
        (
            "/usr/bin/fuse2fs#/srv/x/disk.img /media/i fuse3 nofail 0 0",
            "/usr/bin/fuse2fs#/srv/x/disk.img /media/i fuse3",
            hash.as_str(),
        ),
    ] {
        let fs = rendered(
            BIND_OF_ROOT,
            &format!("/dev/vda1 / ext4 defaults 0 1\n{line}\n"),
        );
        fails_as_not_plain(&fs, Allow::DecoyStorage, &not_plain(shown, reason));
    }
    let fs = rendered(
        BIND_OF_ROOT,
        "/dev/vda1 / ext4 defaults 0 1\nbindfs /media/b fuse nofail 0 0\n",
    );
    fails_as_not_plain(
        &fs,
        Allow::DecoyStorage,
        &not_plain("bindfs /media/b fuse", &Unplain::FuseNoSource.reason()),
    );
    // A remote source names no path of this computer.
    for line in [
        "sshfs#op@host:/ /media/s fuse nofail 0 0",
        "op@host:/ /media/s fuse.sshfs nofail 0 0",
        "remote:path /media/r fuse.rclone nofail 0 0",
        "mybucket /media/s3 fuse.s3fs _netdev,allow_other 0 0",
    ] {
        let fs = rendered(
            BIND_OF_ROOT,
            &format!("/dev/vda1 / ext4 defaults 0 1\n{line}\n"),
        );
        let result = run_allowing(&fs, Allow::DecoyStorage);
        assert!(result.is_pass(), "{line}: {result:?}");
        assert_eq!(result.message(), only_the_decoys_own_line("/"), "{line}");
    }
}

#[test]
fn a_fuse_program_in_the_volume_fails_and_the_gate_refuses_the_root() {
    // The volume is the mapping `data` (dm-9) on the whole of sdb, at /mnt.
    // mount.fuse runs the program a `fuse` line names before its #, or a
    // `fuse.<program>` type names, from where its path leads (util-linux
    // 2.42 and fuse 3.17 ran both): here a program stored in the volume.
    // backend-entries fails the line, and hidden-volume refuses the root, as
    // for a swap or image file there, with relative or absolute link
    // targets in /dev/disk.
    for (line, shown) in [
        (
            "/mnt/prog#/tmp/y /media/b fuse nofail 0 0",
            "/mnt/prog#/tmp/y /media/b fuse",
        ),
        (
            "/tmp/y /media/b fuse./mnt/prog nofail 0 0",
            "/tmp/y /media/b fuse./mnt/prog",
        ),
    ] {
        for (mapping, drive) in [("../../dm-9", "../../sdb"), ("/dev/dm-9", "/dev/sdb")] {
            let decoy = decoy().encrypted().file(
                "/etc/fstab",
                &format!("/dev/nvme0n1p3 / ext4 defaults 0 1\n{line}\n"),
            );
            decoy.fs.mock_set_device_node("/dev/dm-9");
            decoy.link("/dev/disk/by-uuid/abcd", mapping);
            decoy.link("/dev/disk/by-id/usb-x", drive);
            let result = decoy.run();
            assert_eq!(
                result.message(),
                names_the_volume(&format!(
                    "/etc/fstab: '{shown}' (the program it runs lies in the volume at /mnt)"
                )),
                "{line}"
            );
            assert_eq!(result.remediation(), Some(REMEDIATION), "{line}");
            let gate = crate::preflight::HiddenVolumeCheck::new(PathBuf::from("/mnt"))
                .run(&decoy.fs)
                .unwrap();
            assert!(gate.is_fail(), "{line}: {gate:?}");
            assert!(
                gate.message().starts_with(
                    "/mnt is not a volume of its own: it is the filesystem this computer has \
                     mounted at /mnt"
                ),
                "{line}: {}",
                gate.message()
            );
        }
    }
    // A program elsewhere, or named alone, names no part of it.
    for line in [
        "/usr/bin/fuse2fs#/srv/disk.img /media/i fuse nofail 0 0",
        "/tmp/y /media/b fuse./usr/bin/prog nofail 0 0",
        "bindfs#/srv/y /media/b fuse nofail 0 0",
    ] {
        let decoy = decoy().encrypted().file(
            "/etc/fstab",
            &format!("/dev/nvme0n1p3 / ext4 defaults 0 1\n{line}\n"),
        );
        let result = decoy.run();
        assert!(result.is_pass(), "{line}: {result:?}");
    }
}

#[test]
fn a_fuse_program_in_the_roots_folder_fails_with_the_flag_too() {
    // A bind of the folder /srv/x of / at the root: mount.fuse runs a
    // program stored in that folder, whatever source it gets, so the line
    // names the volume and the flag does not let it be.
    for (line, findings) in [
        (
            "/srv/x/prog#/tmp/y /media/b fuse nofail 0 0",
            &["the program it runs lies in the volume at /mnt"][..],
        ),
        (
            "/tmp/y /media/b fuse./srv/x/prog nofail 0 0",
            &["the program it runs lies in the volume at /mnt"][..],
        ),
        (
            "/tmp/y /media/b fuseblk./srv/x/sub/prog nofail 0 0",
            &["the program it runs lies in the volume at /mnt"][..],
        ),
        (
            "/srv/x/prog#/srv/x/y /media/b fuse nofail 0 0",
            &[
                "the program it runs lies in the volume at /mnt",
                "the file it names lies in the volume at /mnt",
            ][..],
        ),
    ] {
        let fs = rendered(
            BIND_OF_ROOT,
            &format!("/dev/vda1 / ext4 defaults 0 1\n{line}\n"),
        );
        assert!(hidden_volume_with_the_flag(&fs).is_warn(), "{line}");
        let result = run_allowing(&fs, Allow::DecoyStorage);
        let shown: Vec<&str> = line.split_whitespace().take(3).collect();
        let shown = shown.join(" ");
        let described: Vec<String> = findings
            .iter()
            .map(|why| format!("/etc/fstab: '{shown}' ({why})"))
            .collect();
        assert_eq!(
            result.message(),
            names_the_volume(&described.join("; ")),
            "{line}"
        );
        assert_eq!(result.remediation(), Some(REMEDIATION), "{line}");
        assert!(run_allowing(&fs, Allow::Nothing).is_fail(), "{line}");
    }
    // Through a link its place cannot be told.
    let fs = rendered(
        BIND_OF_ROOT,
        "/dev/vda1 / ext4 defaults 0 1\n/srv/link/prog#/tmp/y /media/b fuse nofail 0 0\n",
    );
    fs.create_symlink(Path::new("/srv/x"), Path::new("/srv/link"))
        .unwrap();
    fails_as_untold(
        &fs,
        Allow::DecoyStorage,
        &untold(
            "/srv/link/prog#/tmp/y /media/b fuse",
            "the program it runs",
            "/srv/link is a symbolic link, which NAILS does not follow",
        ),
    );
    // A program with a / that is not absolute, which /bin/sh runs from /,
    // is not plain, and neither is a `fuse3.<program>` type with a /, which
    // mount.fuse3 runs as it is written.
    for (line, shown) in [
        (
            "srv/x/prog#/tmp/y /media/b fuse nofail 0 0",
            "srv/x/prog#/tmp/y /media/b fuse",
        ),
        (
            "/tmp/y /media/b fuse3./srv/x/prog nofail 0 0",
            "/tmp/y /media/b fuse3./srv/x/prog",
        ),
    ] {
        let fs = rendered(
            BIND_OF_ROOT,
            &format!("/dev/vda1 / ext4 defaults 0 1\n{line}\n"),
        );
        fails_as_not_plain(
            &fs,
            Allow::DecoyStorage,
            &not_plain(shown, &Unplain::FuseProgram.reason()),
        );
    }
    // A program beside the root's folder, or named alone, and a remote
    // source name no part of it.
    for line in [
        "/srv/y/prog#/tmp/y /media/b fuse nofail 0 0",
        "/tmp/y /media/b fuse./srv/y/prog nofail 0 0",
        "/usr/bin/fuse2fs#/srv/y/disk.img /media/i fuse nofail 0 0",
        "bindfs#/srv/y /media/b fuse nofail 0 0",
        "sshfs#op@host:/ /media/s fuse nofail 0 0",
        "sshfs /media/s fuse nofail 0 0",
    ] {
        let fs = rendered(
            BIND_OF_ROOT,
            &format!("/dev/vda1 / ext4 defaults 0 1\n{line}\n"),
        );
        let result = run_allowing(&fs, Allow::DecoyStorage);
        assert!(result.is_pass(), "{line}: {result:?}");
        assert_eq!(result.message(), only_the_decoys_own_line("/"), "{line}");
    }
}

#[test]
fn a_fuse_line_for_the_volumes_device_fails_without_the_flag() {
    // The volume is the mapping `data` (dm-9) on the whole of sdb, at /mnt:
    // fuse2fs mounts it through FUSE, and a relative device is not plain.
    for (line, shown) in [
        (
            "fuse2fs#/dev/mapper/data /media/f fuse nofail 0 0",
            "fuse2fs#/dev/mapper/data /media/f fuse",
        ),
        (
            "fuse2fs#/dev/dm-9 /media/f fuse nofail 0 0",
            "fuse2fs#/dev/dm-9 /media/f fuse",
        ),
    ] {
        let decoy = decoy().encrypted().file(
            "/etc/fstab",
            &format!("/dev/nvme0n1p3 / ext4 defaults 0 1\n{line}\n"),
        );
        decoy.fs.mock_set_device_node("/dev/dm-9");
        let result = decoy.run();
        assert_eq!(
            result.message(),
            names_the_volume(&format!(
                "/etc/fstab: '{shown}' (it mounts the volume at /mnt)"
            )),
            "{line}"
        );
        assert_eq!(result.remediation(), Some(REMEDIATION), "{line}");
    }
    let decoy = decoy().encrypted().file(
        "/etc/fstab",
        "/dev/nvme0n1p3 / ext4 defaults 0 1\ndev/mapper/data /media/f fuse.fuse2fs nofail 0 0\n",
    );
    fails_as_not_plain(
        &decoy.fs,
        Allow::Nothing,
        &not_plain(
            "dev/mapper/data /media/f fuse.fuse2fs",
            &Unplain::FuseSource.reason(),
        ),
    );
}

#[test]
fn a_line_with_other_white_space_before_a_hash_fails_with_the_flag_too() {
    // libmount skips only spaces and tabs before a #, and systemd 260's
    // fstab generator wrote a mount for each of these.
    for (line, shown, c) in [
        (
            "\u{b}#/srv/x /mnt3 none bind 0 0",
            "U+000B#/srv/x /mnt3 none",
            '\u{b}',
        ),
        (
            "\u{a0}#/srv/x /mnt3 none bind 0 0",
            "U+00A0#/srv/x /mnt3 none",
            '\u{a0}',
        ),
    ] {
        let fs = rendered(
            BIND_OF_ROOT,
            &format!("/dev/vda1 / ext4 defaults 0 1\n{line}\n"),
        );
        assert!(hidden_volume_with_the_flag(&fs).is_warn(), "{line:?}");
        fails_as_not_plain(
            &fs,
            Allow::DecoyStorage,
            &not_plain(shown, &Unplain::Character(c).reason()),
        );
    }
}

#[test]
fn an_id_tag_fails_without_the_flag() {
    // libmount looks ID= up in /dev/disk/by-id, which NAILS does not, and
    // systemd 260's fstab generator wrote an automount for this line.
    let decoy = decoy().encrypted().file(
        "/etc/fstab",
        "/dev/nvme0n1p3 / ext4 defaults 0 1\n\
         ID=dm-name-data /media/x ext4 nofail,x-systemd.automount 0 0\n",
    );
    decoy.link("/dev/disk/by-id/dm-name-data", "../../dm-9");
    fails_as_not_plain(
        &decoy.fs,
        Allow::Nothing,
        &not_plain("ID=dm-name-data /media/x ext4", &Unplain::IdTag.reason()),
    );
}

/// The finding for the crypttab line that is not plain whose name and
/// source read `shown`, for `reason`.
fn crypttab_not_plain(shown: &str, reason: &str) -> String {
    format!("/etc/crypttab: '{shown}' (NAILS reads only plain lines, and {reason})")
}

#[test]
fn a_crypttab_line_that_is_not_plain_fails_without_the_flag() {
    // The volume is the mapping `data` on the whole of sdb. systemd's
    // crypttab generator keeps quotes and backslashes, the command it
    // writes reads them, and it opens a relative source from /: each of
    // these may open the volume's drive, and NAILS reads none of them.
    let quote = Unplain::Quote.reason();
    let relative = Unplain::RelativeSource.reason();
    for (crypttab, shown, reason) in [
        (
            "vault2 '/dev/sdb' none luks,nofail\n",
            "vault2 '/dev/sdb'",
            format!("{quote} and {relative}"),
        ),
        (
            "vault2 \"/dev/sdb\" none luks,nofail\n",
            "vault2 \"/dev/sdb\"",
            format!("{quote} and {relative}"),
        ),
        (
            "'data' /dev/sdc none luks,nofail\n",
            "'data' /dev/sdc",
            quote.clone(),
        ),
        (
            "vault3 /dev/sd\\x62 none luks,nofail\n",
            "vault3 /dev/sd\\x62",
            Unplain::Backslash.reason(),
        ),
        (
            "vr1 dev/sdb none luks,nofail\n",
            "vr1 dev/sdb",
            relative.clone(),
        ),
        (
            "vq4\u{a0}x /dev/sdb none luks,nofail\n",
            "vq4U+00A0x /dev/sdb",
            Unplain::Character('\u{a0}').reason(),
        ),
        (
            "vq5 /dev/sdc none luks\rvq6 /dev/sdb none luks\n",
            "vq5 /dev/sdc",
            Unplain::Character('\r').reason(),
        ),
        (
            "\u{a0}#vq7 /dev/sdb none luks,nofail\n",
            "U+00A0#vq7 /dev/sdb",
            Unplain::Character('\u{a0}').reason(),
        ),
        (
            "\u{b}#vq8 /dev/sdb none luks,nofail\n",
            "U+000B#vq8 /dev/sdb",
            Unplain::Character('\u{b}').reason(),
        ),
    ] {
        let result = decoy().file("/etc/crypttab", crypttab).run();
        assert!(result.is_fail(), "{crypttab:?}: {result:?}");
        assert_eq!(
            result.message(),
            format!(
                "The decoy's configuration may name the volume at /mnt: {}. {STORED}",
                crypttab_not_plain(shown, &reason)
            ),
            "{crypttab:?}"
        );
        assert_eq!(result.remediation(), Some(UNPLAIN_CRYPTTAB), "{crypttab:?}");
    }
    // A plain tag for another device, and the plain line for the volume's
    // drive, which names it.
    let result = decoy()
        .file("/etc/crypttab", "other UUID=0a1b none luks,nofail\n")
        .run();
    assert!(result.is_pass(), "{result:?}");
    let result = decoy()
        .file("/etc/crypttab", "vault /dev/sdb none luks,nofail\n")
        .run();
    assert_eq!(
        result.message(),
        names_the_volume(
            "/etc/crypttab: 'vault /dev/sdb' (it opens the volume at /mnt or a device it is \
             stored on)"
        )
    );
}

#[test]
fn a_crypttab_line_that_is_not_plain_fails_with_the_flag_too() {
    // The encrypted decoy's line for the volume its / lies on is its own
    // line, which the flag lets be; written with quotes it is no line NAILS
    // reads, and fails. With an fstab line that is not plain the check says
    // what to do about each.
    let decoy = encrypted_decoy().file("/etc/crypttab", "cryptroot \"/dev/nvme0n1p3\" none luks\n");
    let result = run_allowing(&decoy.fs, Allow::DecoyStorage);
    assert!(result.is_fail(), "{result:?}");
    assert_eq!(
        result.message(),
        format!(
            "The decoy's configuration may name the volume at /mnt: {}. {STORED}",
            crypttab_not_plain(
                "cryptroot \"/dev/nvme0n1p3\"",
                &format!(
                    "{} and {}",
                    Unplain::Quote.reason(),
                    Unplain::RelativeSource.reason()
                )
            )
        )
    );
    assert_eq!(result.remediation(), Some(UNPLAIN_CRYPTTAB));
    let decoy = decoy.file(
        "/etc/fstab",
        "/dev/mapper/cryptroot / ext4 defaults 0 1\nsrv/x /mnt none bind 0 0\n",
    );
    let result = run_allowing(&decoy.fs, Allow::DecoyStorage);
    assert_eq!(
        result.remediation(),
        Some(format!("{UNPLAIN}\n{UNPLAIN_CRYPTTAB}").as_str())
    );
}
