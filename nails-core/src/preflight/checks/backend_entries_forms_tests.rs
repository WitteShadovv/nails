// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The backend-entries check on lines that `libmount`, `mount.fuse` and
//! systemd read otherwise than a plain reader would: a bind option with a
//! value, the source a FUSE line gives its program and the program itself,
//! white space other than a space or a tab before a `#`, an `ID=` tag, a
//! path into `/dev` written otherwise than as a device's path, crypttab fields
//! in quotes or with a backslash, a crypttab source that is a file's path,
//! `noauto` and an automount with a value, and a crypttab line's key file,
//! key device and header.
//! Each either names the volume as `libmount` or systemd reads it, or is a
//! line NAILS does not read, which fails, with the flag or without it.

use super::*;
use crate::hidden_root::separation::Unplain;

/// The failure that names `finding`, a line that names the volume, alone.
fn names_the_volume(finding: &str) -> String {
    format!("The decoy's configuration names the volume at /mnt: {finding}. {STORED}")
}

#[test]
fn a_bind_option_with_a_value_fails_with_the_flag_too() {
    // util-linux 2.42's mount binds for `bind=x` and `rbind=` whatever the
    // type, and so does systemd's mount of such a line, which it requires or
    // wants for local-fs.target. Each of these binds the root's folder, or a
    // folder of it, at every boot: hidden-volume passes the root with the
    // flag's warning, and backend-entries fails the line.
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
    // A relative source of such a line is not plain, whatever its type, and
    // so are options with a quote, inside which libmount keeps a comma in
    // one option (`bind="a,b"`) where NAILS's parser ends it.
    for (line, shown, reason) in [
        ("srv/x /mnt none bind=x 0 0", "srv/x /mnt none", RELATIVE),
        ("srv/x /mnt zfs bind=x 0 0", "srv/x /mnt zfs", RELATIVE),
        ("srv/x /mnt fuse bind=x 0 0", "srv/x /mnt fuse", RELATIVE),
        (
            "/srv/x /mnt none bind=\"a,b\" 0 0",
            "/srv/x /mnt none",
            "its options hold a quote",
        ),
    ] {
        let fs = rendered(
            BIND_OF_ROOT,
            &format!("/dev/vda1 / ext4 defaults 0 1\n{line}\n"),
        );
        assert!(hidden_volume_with_the_flag(&fs).is_warn(), "{line}");
        fails_as_not_plain(&fs, Allow::DecoyStorage, &not_plain(shown, reason));
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

#[test]
fn a_device_path_written_otherwise_or_leading_out_of_dev_fails_without_the_flag() {
    // The volume is the mapping `data` (dm-9) on the whole of sdb, at /mnt.
    // mount opens /dev/sdb for `//dev/sdb`, and a link in /dev to an image
    // file in the volume mounts that file: NAILS reads neither.
    let decoy = decoy().encrypted().file(
        "/etc/fstab",
        "/dev/nvme0n1p3 / ext4 defaults 0 1\n//dev/sdb /media/x ext4 nofail 0 0\n",
    );
    fails_as_not_plain(
        &decoy.fs,
        Allow::Nothing,
        &not_plain("//dev/sdb /media/x ext4", &Unplain::DevOtherwise.reason()),
    );
    let linked = decoy.file(
        "/etc/fstab",
        "/dev/nvme0n1p3 / ext4 defaults 0 1\n/dev/img.link /media/i ext4 loop,nofail 0 0\n",
    );
    linked.link("/dev/img.link", "/mnt/img.raw");
    fails_as_untold(
        &linked.fs,
        Allow::Nothing,
        &untold(
            "/dev/img.link /media/i ext4",
            "the file it names",
            "/dev/img.link is a symbolic link that leads out of /dev, which NAILS does not follow",
        ),
    );
    // A drive that is not plugged in names nothing here.
    let absent = linked.file(
        "/etc/fstab",
        "/dev/nvme0n1p3 / ext4 defaults 0 1\n/dev/sdz1 /media/z ext4 nofail 0 0\n",
    );
    assert!(absent.run().is_pass());
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

/// The failure that names `finding`, a crypttab line whose source cannot be
/// told, alone.
fn may_name_the_volume(finding: &str) -> String {
    format!("The decoy's configuration may name the volume at /mnt: {finding}. {STORED}")
}

#[test]
fn a_crypttab_source_outside_dev_fails_by_the_file_it_opens() {
    // The volume is the mapping `data` on the whole of sdb, at /mnt.
    // systemd 260's crypttab generator wrote BindsTo=dev-sdf.device for
    // `//dev/sdf` and RequiresMountsFor= for a link elsewhere to the drive,
    // and systemd-cryptsetup opens what the source leads to, a regular file
    // through a loop device. NAILS reads a device only by a tag or its path
    // in /dev written plainly: `//dev/sdb` is not plain, a link or a device
    // node outside /dev cannot be told, and a container file is judged where
    // it lies. The gate passes these lines, as it passes the plain line for
    // the drive.
    let slashes = decoy()
        .encrypted()
        .file("/etc/crypttab", "vault //dev/sdb none luks,nofail\n");
    let result = slashes.run();
    assert_eq!(
        result.message(),
        may_name_the_volume(&crypttab_not_plain(
            "vault //dev/sdb",
            &Unplain::DevOtherwise.reason()
        ))
    );
    assert_eq!(result.remediation(), Some(UNPLAIN_CRYPTTAB));
    let gate = crate::preflight::HiddenVolumeCheck::new(PathBuf::from("/mnt"))
        .run(&slashes.fs)
        .unwrap();
    assert!(gate.is_pass(), "{gate:?}");
    for (crypttab, why) in [
        (
            "vault /sdb.link none luks,nofail\n",
            "/sdb.link is a symbolic link, which NAILS does not follow",
        ),
        (
            "vault /srv/sdb.node none luks,nofail\n",
            "/srv/sdb.node is a device node",
        ),
    ] {
        let decoy = decoy().encrypted().file("/etc/crypttab", crypttab);
        decoy.link("/sdb.link", "/dev/sdb");
        decoy.fs.mock_set_device_node("/srv/sdb.node");
        let result = decoy.run();
        let shown: Vec<&str> = crypttab.split_whitespace().take(2).collect();
        assert_eq!(
            result.message(),
            may_name_the_volume(&format!(
                "/etc/crypttab: '{}' (where the file it opens lies cannot be told: {why})",
                shown.join(" ")
            )),
            "{crypttab}"
        );
        assert_eq!(result.remediation(), Some(UNTOLD), "{crypttab}");
        let gate = crate::preflight::HiddenVolumeCheck::new(PathBuf::from("/mnt"))
            .run(&decoy.fs)
            .unwrap();
        assert!(gate.is_pass(), "{crypttab}: {gate:?}");
    }
    // A link in /dev, as a tmpfiles.d line can make at boot, to a container
    // in the volume: no block device answers to its path, which leads out of
    // /dev, so it cannot be told either.
    let linked = decoy()
        .encrypted()
        .file("/etc/crypttab", "box /dev/box.link none luks,nofail\n");
    linked.link("/dev/box.link", "/mnt/box.img");
    assert_eq!(
        linked.run().message(),
        may_name_the_volume(
            "/etc/crypttab: 'box /dev/box.link' (where the file it opens lies cannot be told: \
             /dev/box.link is a symbolic link that leads out of /dev, which NAILS does not follow)"
        )
    );
    // The drive by its own path names it, as before.
    let drive = decoy()
        .encrypted()
        .file("/etc/crypttab", "vault /dev/sdb none luks,nofail\n");
    assert_eq!(
        drive.run().message(),
        names_the_volume(
            "/etc/crypttab: 'vault /dev/sdb' (it opens the volume at /mnt or a device it is \
             stored on)"
        )
    );
    // A container file in the volume: the boot opens it from there, so the
    // line names the volume, and the gate refuses the root, as for an image
    // line there. One elsewhere names no part of it.
    let container = decoy()
        .encrypted()
        .file("/etc/crypttab", "box /mnt/box.img none luks,nofail\n");
    let result = container.run();
    assert_eq!(
        result.message(),
        names_the_volume(
            "/etc/crypttab: 'box /mnt/box.img' (the file it opens lies in the volume at /mnt)"
        )
    );
    assert_eq!(result.remediation(), Some(REMEDIATION));
    let gate = crate::preflight::HiddenVolumeCheck::new(PathBuf::from("/mnt"))
        .run(&container.fs)
        .unwrap();
    assert!(gate.is_fail(), "{gate:?}");
    let result = decoy()
        .encrypted()
        .file("/etc/crypttab", "box /srv/box.img none luks,nofail\n")
        .run();
    assert!(result.is_pass(), "{result:?}");
}

#[test]
fn a_container_in_the_roots_folder_fails_with_the_flag_too() {
    // A bind of the folder /srv/x of / at the root: a crypttab line that
    // opens a container file in that folder names the volume, and the flag
    // does not let it be; one beside it passes.
    let crypttab = |line: &str| {
        let fs = rendered(BIND_OF_ROOT, "/dev/vda1 / ext4 defaults 0 1\n");
        fs.mock_set_file_content("/etc/crypttab", line);
        fs
    };
    let fs = crypttab("box /srv/x/box.img none luks\n");
    assert!(hidden_volume_with_the_flag(&fs).is_warn());
    let result = run_allowing(&fs, Allow::DecoyStorage);
    assert_eq!(
        result.message(),
        names_the_volume(
            "/etc/crypttab: 'box /srv/x/box.img' (the file it opens lies in the volume at /mnt)"
        )
    );
    assert_eq!(result.remediation(), Some(REMEDIATION));
    let result = run_allowing(
        &crypttab("box /srv/y/box.img none luks\n"),
        Allow::DecoyStorage,
    );
    assert!(result.is_pass(), "{result:?}");
    assert_eq!(result.message(), only_the_decoys_own_line("/"));
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

#[test]
fn a_dev_link_out_of_dev_is_untold_at_that_link_and_nothing_past_it_is_read() {
    // Links in /dev, as tmpfiles.d lines can make at boot, to a container in
    // the volume. /dev/out.link leads to /tmp/back, a link on the decoy's
    // disk back to the drive: NAILS stops at the first link that leaves
    // /dev, where a lookup of /tmp fails here, so it reads no link and makes
    // no lookup past /dev. It followed /tmp/back before, and judged the line
    // by the drive. udev's by-uuid link to the drive, relative as udev makes
    // it, stays in /dev and names it.
    for (crypttab, shown) in [
        ("box /dev/box.link none luks,nofail", "box /dev/box.link"),
        (
            "box /dev/shm/box.link none luks,nofail",
            "box /dev/shm/box.link",
        ),
        ("box /dev/out.link none luks,nofail", "box /dev/out.link"),
    ] {
        let decoy = decoy()
            .encrypted()
            .file("/etc/crypttab", &format!("{crypttab}\n"));
        decoy.link("/dev/box.link", "/mnt/box.img");
        decoy.link("/dev/shm/box.link", "../../mnt/box.img");
        decoy.link("/dev/out.link", "/tmp/back");
        decoy.link("/tmp/back", "/dev/sdb");
        for place in ["/mnt", "/tmp"] {
            decoy
                .fs
                .mock_set_mount_root_error(place, std::io::ErrorKind::PermissionDenied);
        }
        let link = shown.split_once(' ').unwrap().1;
        assert_eq!(
            decoy.run().message(),
            may_name_the_volume(&format!(
                "/etc/crypttab: '{shown}' (where the file it opens lies cannot be told: {link} \
                 is a symbolic link that leads out of /dev, which NAILS does not follow)"
            )),
            "{crypttab}"
        );
    }
    let drive = decoy().encrypted().file(
        "/etc/crypttab",
        "vault /dev/disk/by-uuid/abcd none luks,nofail\n",
    );
    drive.link("/dev/disk/by-uuid/abcd", "../../sdb");
    assert_eq!(
        drive.run().message(),
        names_the_volume(
            "/etc/crypttab: 'vault /dev/disk/by-uuid/abcd' (it opens the volume at /mnt or a \
             device it is stored on)"
        )
    );
    // The same link to the other drive names no part of the volume.
    let other = decoy().encrypted().file(
        "/etc/crypttab",
        "vault /dev/disk/by-uuid/abcd none luks,nofail\n",
    );
    other.link("/dev/disk/by-uuid/abcd", "../../sdc");
    assert!(other.run().is_pass(), "{:?}", other.run());
}

#[test]
fn a_tag_whose_udev_link_leads_out_of_dev_is_untold_too() {
    // A tag names the link udev makes for it. by-uuid/out leads to /tmp/back,
    // a link on the decoy's disk back to the drive, which NAILS followed
    // before and judged the line by; by-label/box leads to a container in the
    // volume, which named nothing. Neither link is followed now, a lookup of
    // /tmp fails here, and each line cannot be told, in the fstab as well.
    let untold = |what: &str, link: &str| {
        format!(
            "where {what} lies cannot be told: {link} is a symbolic link that leads out of /dev, \
             which NAILS does not follow"
        )
    };
    for (crypttab, fstab, finding) in [
        (
            "vault UUID=out none luks,nofail\n",
            "",
            format!(
                "/etc/crypttab: 'vault UUID=out' ({})",
                untold("the file it opens", "/dev/disk/by-uuid/out")
            ),
        ),
        (
            "box LABEL=box none luks,nofail\n",
            "",
            format!(
                "/etc/crypttab: 'box LABEL=box' ({})",
                untold("the file it opens", "/dev/disk/by-label/box")
            ),
        ),
        (
            "vault /dev/sdc LABEL=box luks,nofail\n",
            "",
            format!(
                "/etc/crypttab: 'vault /dev/sdc' ({})",
                untold("its key file", "/dev/disk/by-label/box")
            ),
        ),
        (
            "",
            "UUID=out /media/o ext4 nofail 0 0\n",
            format!(
                "/etc/fstab: 'UUID=out /media/o ext4' ({})",
                untold("the file it names", "/dev/disk/by-uuid/out")
            ),
        ),
    ] {
        let decoy = decoy().encrypted().file("/etc/crypttab", crypttab).file(
            "/etc/fstab",
            &format!("/dev/nvme0n1p3 / ext4 defaults 0 1\n{fstab}"),
        );
        decoy.link("/dev/disk/by-uuid/out", "/tmp/back");
        decoy.link("/tmp/back", "/dev/sdb");
        decoy.link("/dev/disk/by-label/box", "/mnt/box.img");
        decoy
            .fs
            .mock_set_mount_root_error("/tmp", std::io::ErrorKind::PermissionDenied);
        let result = decoy.run();
        assert_eq!(result.message(), may_name_the_volume(&finding), "{finding}");
        assert_eq!(result.remediation(), Some(UNTOLD), "{finding}");
    }
}

// ------------------------------------------------------------------------
// Options read by their names, and what a crypttab line reads besides its
// source
// ------------------------------------------------------------------------

#[test]
fn with_the_flag_a_line_that_systemd_reads_as_noauto_still_fails() {
    // Beside the btrfs subvolume at the root, the line for /home with
    // `noauto=1` or `auto,noauto=`, which systemd 260.5's fstab generator
    // read as noauto (`noauto=yes`) and pulled into no target, fails as the
    // plain `noauto` does: it is a line the boot does not mount. So does the
    // encrypted decoy's crypttab line with `noauto=1`, which the crypttab
    // generator left out of cryptsetup.target, as with `noauto`.
    for options in [
        "subvol=/home,noauto=1",
        "subvol=/home,auto,noauto=",
        "subvol=/home,noauto",
        "noauto=yes,subvol=/home",
        "subvol=/home,auto,noauto=no",
    ] {
        let fs = rendered(
            BESIDE_HOME,
            &format!("/dev/vda1 / ext4 defaults 0 1\n/dev/vda2 /home btrfs {options} 0 0\n"),
        );
        assert!(hidden_volume_with_the_flag(&fs).is_warn(), "{options}");
        let result = run_allowing(&fs, Allow::DecoyStorage);
        assert_eq!(
            result.message(),
            names_the_volume(
                "/etc/fstab: '/dev/vda2 /home btrfs' (it mounts the filesystem the volume at \
                 /mnt is part of)"
            ),
            "{options}"
        );
        assert_eq!(result.remediation(), Some(REMEDIATION), "{options}");
    }
    for options in [
        "luks,discard,noauto=1",
        "luks,discard,noauto",
        "luks,auto,noauto=no",
    ] {
        let decoy = encrypted_decoy_with("/srv/x", options);
        let result = run_allowing(&decoy.fs, Allow::DecoyStorage);
        assert_eq!(result.message(), names_the_volume(CRYPTROOT), "{options}");
        assert_eq!(result.remediation(), Some(STORAGE_OF_ITS_OWN), "{options}");
    }
}

#[test]
fn a_line_that_systemd_mounts_by_a_later_auto_or_an_automount_is_the_decoys_own() {
    // The fstab generator pulled `noauto,auto=0` into local-fs.target and
    // made an automount for `x-systemd.automount=0`: such a line for /home
    // is one the boot mounts, as one with `auto` or the automount alone, so
    // the flag lets it be. So for a crypttab line with `noauto,auto=x`.
    for options in [
        "subvol=/home,noauto,auto=1",
        "subvol=/home,noauto,x-systemd.automount=1",
        "subvol=/home,noauto,comment=systemd.automount=x",
    ] {
        let fs = rendered(
            BESIDE_HOME,
            &format!("/dev/vda1 / ext4 defaults 0 1\n/dev/vda2 /home btrfs {options} 0 0\n"),
        );
        let result = run_allowing(&fs, Allow::DecoyStorage);
        assert!(result.is_pass(), "{options}: {result:?}");
        assert_eq!(
            result.message(),
            only_the_decoys_own_line("/home"),
            "{options}"
        );
    }
    let decoy = encrypted_decoy_with("/srv/x", "luks,discard,noauto,auto=x");
    let result = run_allowing(&decoy.fs, Allow::DecoyStorage);
    assert_eq!(
        result.message(),
        only_the_decoys_own_lines("line for /", "cryptroot /dev/nvme0n1p3")
    );
}

#[test]
fn the_gate_counts_a_line_that_systemd_mounts_by_a_later_auto_or_an_automount() {
    // The volume is the mapping `data` on the whole of sdb, at /mnt. A line
    // for it that the boot mounts, by a later `auto=1` or on demand by
    // `x-systemd.automount=1`, makes the decoy use the volume's filesystem,
    // and the attach gate refuses the root, as for a line with neither
    // option. A plain `noauto` line is a mere recipe, which only
    // backend-entries fails.
    for (options, refused) in [
        ("noauto,auto=1", true),
        ("noauto,x-systemd.automount=1", true),
        ("defaults", true),
        ("noauto", false),
    ] {
        let decoy = decoy().encrypted().file(
            "/etc/fstab",
            &format!(
                "/dev/nvme0n1p3 / ext4 defaults 0 1\n/dev/mapper/data /media/x ext4 {options} 0 0\n"
            ),
        );
        assert!(decoy.run().is_fail(), "{options}");
        let gate = crate::preflight::HiddenVolumeCheck::new(PathBuf::from("/mnt"))
            .run(&decoy.fs)
            .unwrap();
        assert_eq!(gate.is_fail(), refused, "{options}: {gate:?}");
        if refused {
            assert!(gate.message().contains("/media/x"), "{options}: {gate:?}");
        }
    }
}

#[test]
fn an_option_with_no_value_where_systemd_reads_one_fails_with_the_flag_too() {
    // The fstab generator linked the line for /home with an empty
    // `x-systemd.wanted-by=` into a unit named by nothing, and not into
    // local-fs.target, so the boot no longer mounts it, and btrfs mounts no
    // `subvol` given with no value: NAILS reads neither, so the line is not
    // plain. `x-systemd.wanted-by` alone is no such option to systemd.
    for (options, option) in [
        ("subvol=/home,x-systemd.wanted-by=", "x-systemd.wanted-by"),
        (
            "subvol=/home,x-systemd.required-by=",
            "x-systemd.required-by",
        ),
        ("subvol,noatime", "subvol"),
        ("subvol=/home,subvolid=", "subvolid"),
    ] {
        let fs = rendered(
            BESIDE_HOME,
            &format!("/dev/vda1 / ext4 defaults 0 1\n/dev/vda2 /home btrfs {options} 0 0\n"),
        );
        let result = run_allowing(&fs, Allow::DecoyStorage);
        assert_eq!(
            result.message(),
            may_name_the_volume(&not_plain(
                "/dev/vda2 /home btrfs",
                &Unplain::NoValue(option).reason()
            )),
            "{options}"
        );
        assert_eq!(
            result.remediation(),
            Some(format!("{UNPLAIN}\n{}", unread_options(&[option.to_string()])).as_str()),
            "{options}"
        );
    }
    let fs = rendered(
        BESIDE_HOME,
        "/dev/vda1 / ext4 defaults 0 1\n\
         /dev/vda2 /home btrfs subvol=/home,x-systemd.wanted-by 0 0\n",
    );
    let result = run_allowing(&fs, Allow::DecoyStorage);
    assert_eq!(result.message(), only_the_decoys_own_line("/home"));
}

/// The volume's finding for the crypttab line `vault /dev/sdc`, a line for
/// another drive, which says `why`.
fn vault(why: &str) -> String {
    format!("/etc/crypttab: 'vault /dev/sdc' ({why})")
}

/// Why a line that mounts the volume or a device below it for `what` fails.
fn mounts_for(what: &str) -> String {
    format!("it mounts the volume at /mnt or a device it is stored on for its {what}")
}

/// Why a line that reads `what` from the volume or a device below it fails.
fn reads_from(what: &str) -> String {
    format!("it reads its {what} from the volume at /mnt or a device it is stored on")
}

#[test]
fn a_crypttab_key_file_key_device_or_header_on_the_volume_fails() {
    // The volume is the mapping `data` on the whole of sdb, at /mnt, and
    // by-uuid/vol names it; vault opens sdc, another drive. systemd 260.5's
    // crypttab generator mounted the device after the last `:` of the key
    // field read-only (`/key:/dev/mapper/data`, `none:/dev/sdd`) and of a
    // `header=` read-write before it opened the line, had the line wait for
    // the device a key file or a header names, and for the mounts of a file's
    // path, which systemd-cryptsetup reads, as it reads a `tcrypt-keyfile=`.
    // A file in the volume makes the gate refuse the root, as a container
    // there does.
    for (crypttab, why, refused) in [
        (
            "vault /dev/sdc /mnt/key luks,nofail",
            "its key file lies in the volume at /mnt".to_string(),
            true,
        ),
        (
            "vault /dev/sdc /key:/dev/mapper/data luks,nofail",
            mounts_for("key file"),
            false,
        ),
        (
            "vault /dev/sdc /key:UUID=vol luks,nofail",
            mounts_for("key file"),
            false,
        ),
        (
            "vault /dev/sdc none luks,header=/mnt/hdr,nofail",
            "its header lies in the volume at /mnt".to_string(),
            true,
        ),
        (
            "vault /dev/sdc none:/dev/mapper/data luks,nofail",
            mounts_for("key file"),
            false,
        ),
        (
            "vault /dev/sdc /key:/dev/sdb luks,nofail",
            mounts_for("key file"),
            false,
        ),
        (
            "vault /dev/sdc none luks,header=/hdr:/dev/mapper/data,nofail",
            mounts_for("header"),
            false,
        ),
        (
            "vault /dev/sdc /dev/sdb luks,keyfile-size=512,nofail",
            reads_from("key file"),
            false,
        ),
        (
            "vault /dev/sdc UUID=vol luks,nofail",
            reads_from("key file"),
            false,
        ),
        (
            "vault /dev/sdc none luks,header=UUID=vol,nofail",
            reads_from("header"),
            false,
        ),
        (
            "vault /dev/sdc none tcrypt,tcrypt-keyfile=/mnt/tk,nofail",
            "its key file lies in the volume at /mnt".to_string(),
            true,
        ),
    ] {
        let decoy = decoy()
            .encrypted()
            .file("/etc/crypttab", &format!("{crypttab}\n"));
        decoy.link("/dev/disk/by-uuid/vol", "/dev/dm-9");
        let result = decoy.run();
        assert_eq!(
            result.message(),
            names_the_volume(&vault(&why)),
            "{crypttab}"
        );
        assert_eq!(result.remediation(), Some(REMEDIATION), "{crypttab}");
        let gate = crate::preflight::HiddenVolumeCheck::new(PathBuf::from("/mnt"))
            .run(&decoy.fs)
            .unwrap();
        assert_eq!(gate.is_fail(), refused, "{crypttab}: {gate:?}");
    }
    // A key file elsewhere, none, /dev/urandom, a key device of another
    // filesystem (the decoy's /), a key file that is no absolute path, which
    // systemd-cryptsetup ignores, a header elsewhere or none, which it
    // refuses, and a TrueCrypt key file elsewhere name no part of it.
    for crypttab in [
        "vault /dev/sdc /etc/keys/v.key luks,nofail",
        "vault /dev/sdc none luks,nofail",
        "vault /dev/sdc - luks,nofail",
        "cswap /dev/sdc /dev/urandom swap,cipher=aes-xts-plain64,size=256",
        "vault /dev/sdc /key:/dev/nvme0n1p3 luks,nofail",
        "vault /dev/sdc keys/v.key luks,nofail",
        "vault /dev/sdc none luks,header=/etc/hdr,nofail",
        "vault /dev/sdc none luks,header,nofail",
        "vault /dev/sdc none tcrypt,tcrypt-keyfile=/etc/tk,nofail",
    ] {
        let decoy = decoy()
            .encrypted()
            .file("/etc/crypttab", &format!("{crypttab}\n"));
        let result = decoy.run();
        assert!(result.is_pass(), "{crypttab}: {result:?}");
    }
}

#[test]
fn a_crypttab_key_file_whose_place_cannot_be_told_or_that_is_not_plain_fails() {
    // A link to the volume, in /dev or elsewhere, is not followed. A key file
    // on a device the boot mounts whose path holds a `..` leads out of that
    // mount (the generator handed systemd-cryptsetup `<mount>/../../../mnt/key`
    // for `../../../mnt/key:/dev/sdg`), `//dev/sdb` names the drive, and
    // Debian's initramfs hands the key field of a line with `keyscript=` to
    // that program: NAILS reads none of these.
    for (crypttab, why) in [
        (
            "vault /dev/sdc /dev/key.link luks,nofail",
            "where its key file lies cannot be told: /dev/key.link is a symbolic link that leads \
             out of /dev, which NAILS does not follow",
        ),
        (
            "vault /dev/sdc /keys/k.link luks,nofail",
            "where its key file lies cannot be told: /keys/k.link is a symbolic link, which NAILS \
             does not follow",
        ),
        (
            "vault /dev/sdc /k:/dev/kd.link luks,nofail",
            "where what it mounts for its key file lies cannot be told: /dev/kd.link is a \
             symbolic link that leads out of /dev, which NAILS does not follow",
        ),
    ] {
        let decoy = decoy()
            .encrypted()
            .file("/etc/crypttab", &format!("{crypttab}\n"));
        decoy.link("/dev/key.link", "/mnt/key");
        decoy.link("/keys/k.link", "/mnt/key");
        decoy.link("/dev/kd.link", "/mnt/kd.img");
        let result = decoy.run();
        assert_eq!(
            result.message(),
            may_name_the_volume(&vault(why)),
            "{crypttab}"
        );
        assert_eq!(result.remediation(), Some(UNTOLD), "{crypttab}");
    }
    for (crypttab, why) in [
        (
            "vault /dev/sdc ../../../../mnt/key:/dev/nvme0n1p3 luks,nofail",
            Unplain::UpOutOfDevice("key file"),
        ),
        (
            "vault /dev/sdc none luks,header=../../hdr:/dev/nvme0n1p3,nofail",
            Unplain::UpOutOfDevice("header"),
        ),
        (
            "vault /dev/sdc //dev/sdb luks,nofail",
            Unplain::DevOtherwise,
        ),
        (
            "vault /dev/sdc /dev/disk/by-uuid/vol:/key luks,keyscript=passdev,nofail",
            Unplain::Keyscript,
        ),
    ] {
        let decoy = decoy()
            .encrypted()
            .file("/etc/crypttab", &format!("{crypttab}\n"));
        let result = decoy.run();
        assert_eq!(
            result.message(),
            may_name_the_volume(&crypttab_not_plain("vault /dev/sdc", &why.reason())),
            "{crypttab}"
        );
        assert_eq!(result.remediation(), Some(UNPLAIN_CRYPTTAB), "{crypttab}");
    }
}

#[test]
fn with_the_flag_a_key_file_or_header_in_the_roots_folder_or_on_its_device_fails() {
    // A folder of / bound at the root, and a key file in the key field: in
    // the root's folder, or on the root's own device, which the boot mounts
    // a second time for it, and a header there. A key file beside the root's
    // folder and a key device of another filesystem name no part of it. A
    // path in the options field after a key field `none`, which
    // systemd-cryptsetup ignores as an option it does not know, is an option
    // no list of NAILS's holds, so the line is not plain.
    for (crypttab, why) in [
        (
            "vault /dev/vdc /srv/x/key luks",
            "its key file lies in the volume at /mnt".to_string(),
        ),
        (
            "vault /dev/vdc /srv/x/key:/dev/vda1 luks",
            mounts_for("key file"),
        ),
        (
            "vault /dev/vdc /etc/k:/dev/vda1 luks",
            mounts_for("key file"),
        ),
        (
            "vault /dev/vdc none luks,header=/srv/x/hdr",
            "its header lies in the volume at /mnt".to_string(),
        ),
        (
            "vault /dev/vdc none luks,header=/hdr:/dev/vda1",
            mounts_for("header"),
        ),
        (
            "vault /dev/vdc /mnt/key luks",
            "its key file lies in the volume at /mnt".to_string(),
        ),
    ] {
        let fs = rendered(BIND_OF_ROOT, "/dev/vda1 / ext4 defaults 0 1\n");
        fs.mock_set_file_content("/etc/crypttab", &format!("{crypttab}\n"));
        assert!(hidden_volume_with_the_flag(&fs).is_warn(), "{crypttab}");
        let result = run_allowing(&fs, Allow::DecoyStorage);
        assert_eq!(
            result.message(),
            names_the_volume(&format!("/etc/crypttab: 'vault /dev/vdc' ({why})")),
            "{crypttab}"
        );
        assert_eq!(result.remediation(), Some(REMEDIATION), "{crypttab}");
    }
    for crypttab in [
        "vault /dev/vdc /srv/y/key luks",
        "vault /dev/vdc /key:/dev/vdc1 luks",
    ] {
        let fs = rendered(BIND_OF_ROOT, "/dev/vda1 / ext4 defaults 0 1\n");
        fs.mock_set_file_content("/etc/crypttab", &format!("{crypttab}\n"));
        let result = run_allowing(&fs, Allow::DecoyStorage);
        assert!(result.is_pass(), "{crypttab}: {result:?}");
        assert_eq!(
            result.message(),
            only_the_decoys_own_line("/"),
            "{crypttab}"
        );
    }
    for (crypttab, option) in [
        ("vault /dev/vdc none /srv/x/key luks", "/srv/x/key"),
        (
            "vault /dev/vdc none /srv/x/key:/dev/vda1 luks",
            "/srv/x/key:/dev/vda1",
        ),
    ] {
        let fs = rendered(BIND_OF_ROOT, "/dev/vda1 / ext4 defaults 0 1\n");
        fs.mock_set_file_content("/etc/crypttab", &format!("{crypttab}\n"));
        let result = run_allowing(&fs, Allow::DecoyStorage);
        assert_eq!(
            result.message(),
            may_name_the_volume(&format!(
                "/etc/crypttab: 'vault /dev/vdc' (NAILS reads only plain lines, and it gives \
                 {option}, an option whose effect NAILS does not read)"
            )),
            "{crypttab}"
        );
    }
}

#[test]
fn on_an_encrypted_decoy_its_own_line_with_a_key_in_the_roots_folder_fails() {
    // The decoy's own crypttab line, which the flag lets be, with its key
    // file in the root's folder, or with its key device the root's own
    // mapping, which the boot mounts a second time, is a finding beside it;
    // its boot needs the line. A key file elsewhere on the root's filesystem
    // is none. With `keyscript=` the line is not plain.
    for (key, why) in [
        (
            "/srv/x/key",
            "its key file lies in the volume at /mnt".to_string(),
        ),
        ("/k:/dev/mapper/cryptroot", mounts_for("key file")),
    ] {
        let decoy = encrypted_decoy().file(
            "/etc/crypttab",
            &format!("cryptroot /dev/nvme0n1p3 {key} luks,discard\n"),
        );
        assert!(hidden_volume_with_the_flag(&decoy.fs).is_warn(), "{key}");
        let result = run_allowing(&decoy.fs, Allow::DecoyStorage);
        assert_eq!(
            result.message(),
            names_the_volume(&format!(
                "/etc/crypttab: 'cryptroot /dev/nvme0n1p3' ({why}, and the decoy's own boot \
                 needs it)"
            )),
            "{key}"
        );
        assert_eq!(result.remediation(), Some(STORAGE_OF_ITS_OWN), "{key}");
    }
    let decoy = encrypted_decoy().file(
        "/etc/crypttab",
        "cryptroot /dev/nvme0n1p3 /etc/keys/root.key luks,discard\n",
    );
    let result = run_allowing(&decoy.fs, Allow::DecoyStorage);
    assert_eq!(
        result.message(),
        only_the_decoys_own_lines("line for /", "cryptroot /dev/nvme0n1p3")
    );
    let decoy = encrypted_decoy().file(
        "/etc/crypttab",
        "cryptroot /dev/nvme0n1p3 none luks,discard,keyscript=decrypt_keyctl\n",
    );
    let result = run_allowing(&decoy.fs, Allow::DecoyStorage);
    assert_eq!(
        result.message(),
        may_name_the_volume(&crypttab_not_plain(
            "cryptroot /dev/nvme0n1p3",
            &Unplain::Keyscript.reason()
        ))
    );
}
