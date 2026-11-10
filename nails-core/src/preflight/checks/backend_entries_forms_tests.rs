// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The backend-entries check on lines that `libmount` and systemd read
//! otherwise than a plain reader would: a bind option with a value, which
//! binds as `bind` does whatever the type of the line.

use super::*;

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
