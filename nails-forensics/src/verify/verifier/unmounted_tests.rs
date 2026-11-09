// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! An offline scan of the system subvolume alone, without the subvolumes the
//! decoy mounts inside it, read as complete: a history in `@home` or a sudo
//! log in `@log` beside it was not read, and nothing said so. Every place the
//! decoy mounts something that holds nothing under the root is now listed as
//! not checked, by the scan and by the examiner's view, each mount point with
//! the mount that writes nothing to the decoy's disk. The decoy's files and
//! places are looked up inside the root: no link in the image leads to the
//! folders of the machine running verify.

use super::Verifier;
use crate::filesystem::PathKind;
use crate::verify::{ExaminerOptions, VerifyResult, VerifyStatus};
use crate::{Filesystem, MockFilesystem, RealFilesystem, Result};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, SystemTime};

const PASSWD: &str = "root:x:0:0:root:/root:/bin/bash\n\
                      daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
                      alice:x:1000:1000:Alice:/home/alice:/bin/bash\n\
                      bob:x:1001:1001:Bob:/srv/bob:/bin/zsh\n\
                      nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n";

/// An archinstall layout: the system in `@`, the rest in subvolumes of
/// their own, mounted inside it, and a bind of a folder of the image.
const FSTAB: &str = "UUID=1 / btrfs rw,subvol=/@ 0 0\n\
                     UUID=1 /home btrfs rw,subvol=/@home 0 0\n\
                     UUID=1 /var/log btrfs rw,subvol=/@log 0 0\n\
                     UUID=1 /.snapshots btrfs rw,subvol=/@.snapshots 0 0\n\
                     UUID=2 /boot vfat rw,umask=0077 0 2\n\
                     /srv/share /data none bind 0 0\n\
                     tmpfs /tmp tmpfs defaults 0 0\n\
                     server:/srv /mnt/share nfs defaults 0 0\n\
                     /swapfile none swap defaults 0 0\n";

/// A decoy root at a temporary folder: `/etc` with `passwd`, the folders
/// `dirs` and the files `files` (path and text).
fn decoy(dirs: &[&str], files: &[(&str, &str)]) -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("etc")).unwrap();
    std::fs::write(root.path().join("etc/passwd"), PASSWD).unwrap();
    for dir in dirs {
        std::fs::create_dir_all(root.path().join(dir)).unwrap();
    }
    for (file, text) in files {
        std::fs::write(root.path().join(file), text).unwrap();
    }
    root
}

fn scan(root: &Path, deep: bool, examiner: bool) -> Result<VerifyResult> {
    let mut verifier = Verifier::new(RealFilesystem).offline_under(root.to_path_buf());
    if examiner {
        verifier = verifier.with_examiner(ExaminerOptions::default());
    }
    verifier.run(deep)
}

/// The lines the scan lists for the decoy's places and files it could not
/// read: each starts with the decoy path it names, as no other line does.
fn unmounted(areas: &[String]) -> Vec<&str> {
    areas
        .iter()
        .map(String::as_str)
        .filter(|area| area.starts_with('/'))
        .collect()
}

/// The decoy places those lines name, in their order.
fn places(areas: &[String]) -> Vec<&str> {
    unmounted(areas)
        .into_iter()
        .map(|area| area.split(", ").next().unwrap())
        .collect()
}

fn home_of(user: &str, home: &str) -> String {
    format!(
        "{home}, the home of {user} in the decoy's /etc/passwd (missing or empty under the root: \
         mount what holds it there without writing to it before the scan)"
    )
}

#[test]
fn a_home_that_is_not_mounted_is_not_checked() {
    // The system subvolume alone: its /home is the empty folder @home is
    // mounted on, and alice's history lies in @home beside it. bob's home is
    // in place; root, daemon and nobody are no login accounts.
    let root = decoy(&["home", "srv/bob"], &[("srv/bob/.bash_history", "ls\n")]);
    for examiner in [false, true] {
        let result = scan(root.path(), true, examiner).unwrap();
        assert_eq!(result.status, VerifyStatus::Secure, "{:?}", result.findings);
        assert_eq!(
            unmounted(&result.areas_not_checked),
            [home_of("alice", "/home/alice")],
            "{:#?}",
            result.areas_not_checked
        );
        // The examiner's view reads the homes too, and says so as well.
        if let Some(report) = &result.examiner {
            assert_eq!(
                unmounted(&report.not_checked),
                [home_of("alice", "/home/alice")]
            );
        }
    }
    // An empty home is not checked either, and one that holds a file is.
    std::fs::create_dir(root.path().join("home/alice")).unwrap();
    let result = scan(root.path(), false, false).unwrap();
    assert_eq!(places(&result.areas_not_checked), ["/home/alice"]);
    std::fs::write(root.path().join("home/alice/.profile"), "").unwrap();
    let result = scan(root.path(), false, false).unwrap();
    assert!(places(&result.areas_not_checked).is_empty());
}

#[test]
fn a_mount_point_of_the_decoys_fstab_that_holds_nothing_is_not_checked() {
    // @home, @log and @.snapshots are not mounted under the root, /boot is,
    // the bind's source lies in the image, and /tmp, the share, the swap file
    // and / itself hold nothing on the disk scanned. alice's home lies under
    // /home, which is listed already.
    let root = decoy(
        &[
            "home",
            "var/log",
            "boot",
            "tmp",
            "srv/bob",
            "data",
            "srv/share",
        ],
        &[
            ("etc/fstab", FSTAB),
            ("boot/grub.cfg", ""),
            ("srv/bob/.profile", ""),
            ("srv/share/notes", ""),
        ],
    );
    let result = scan(root.path(), false, true).unwrap();
    let listed = ["/.snapshots", "/home", "/var/log"];
    assert_eq!(places(&result.areas_not_checked), listed);
    let report = result.examiner.as_ref().expect("the examiner's view ran");
    assert_eq!(places(&report.not_checked), listed);
    // The device is not on this machine, so it is not mounted here: made
    // read-only and mounted without a replay of the btrfs tree log.
    let home = unmounted(&result.areas_not_checked)[1];
    let at = nails_base::next_step::shell_word(root.path().join("home").as_os_str());
    assert_eq!(
        home,
        format!(
            "/home, which the decoy's /etc/fstab mounts (missing or empty under the root. Its \
             device is not mounted here: make it read-only and mount it there without a journal \
             replay before the scan, with `sudo blockdev --setro /dev/disk/by-uuid/1 && sudo mount \
             -o ro,rescue=nologreplay,subvol=/@home /dev/disk/by-uuid/1 {at}`)"
        )
    );

    // With each mounted in place, nothing is listed.
    for place in ["home/alice/.profile", "var/log/wtmp", ".snapshots/1"] {
        let file = root.path().join(place);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, "").unwrap();
    }
    let result = scan(root.path(), false, true).unwrap();
    assert!(places(&result.areas_not_checked).is_empty());
}

#[test]
fn each_mount_point_says_how_to_mount_it_by_how_its_device_is_mounted_now() {
    // A device mounted here read-write (the decoy root's, beneath a hidden
    // session) is mounted again and that mount made read-only; one whose
    // filesystem is mounted read-only already takes `ro`; any other is made
    // read-only first and mounted without a journal replay.
    let fs = MockFilesystem::new();
    fs.mock_set_path_type("/mnt/decoy", PathKind::Dir);
    fs.mock_set_path_type("/mnt/decoy/etc", PathKind::Dir);
    fs.mock_add_file(
        "/mnt/decoy/etc/fstab",
        "UUID=r /home ext4 defaults 0 2\n\
         UUID=o /media/ro xfs defaults 0 2\n\
         UUID=n /media/backup ext4 noauto 0 2\n",
    );
    for empty in ["/mnt/decoy/home", "/mnt/decoy/media/ro"] {
        fs.mock_set_path_type(empty, PathKind::Dir);
        fs.mock_set_directory_contents(Path::new(empty), Vec::new());
    }
    fs.create_symlink(Path::new("/dev/sda2"), Path::new("/dev/disk/by-uuid/r"))
        .unwrap();
    fs.create_symlink(Path::new("/dev/sdb1"), Path::new("/dev/disk/by-uuid/o"))
        .unwrap();
    fs.mock_set_mount_table(
        "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
         30 1 8:2 / /run/overlay-runtime/lower ro - ext4 /dev/sda2 rw,relatime\n\
         31 1 8:17 / /mnt/other ro - xfs /dev/sdb1 ro,relatime\n",
    );

    let result = Verifier::new(fs)
        .offline_under("/mnt/decoy".into())
        .run(false)
        .unwrap();
    let why = |place: &str, how: &str| {
        format!(
            "{place}, which the decoy's /etc/fstab mounts (missing or empty under the root. {how})"
        )
    };
    assert_eq!(
        unmounted(&result.areas_not_checked),
        [
            why(
                "/home",
                "Its device is mounted here already, read-write: mount it there again and make \
                 that mount read-only before the scan, with `sudo mount /dev/disk/by-uuid/r \
                 /mnt/decoy/home && sudo mount -o remount,bind,ro /mnt/decoy/home`"
            ),
            why(
                "/media/backup",
                "Its device is not mounted here: make it read-only and mount it there without a \
                 journal replay before the scan, with `sudo blockdev --setro /dev/disk/by-uuid/n \
                 && sudo mount -o ro,noload /dev/disk/by-uuid/n /mnt/decoy/media/backup`"
            ),
            why(
                "/media/ro",
                "Its device is mounted here already, read-only: mount it there before the scan, \
                 with `sudo mount -o ro /dev/disk/by-uuid/o /mnt/decoy/media/ro`"
            ),
        ]
    );
}

#[test]
fn a_file_or_a_mapping_that_is_not_open_is_opened_read_only_before_its_mount() {
    // A disk image the decoy mounts is attached to a loop device read-only,
    // as its fstab line sets the loop device up. A mapping that is not open
    // here is opened read-only first, from the source and as the decoy's
    // crypttab opens it, a plain volume with its parameters and a detached
    // header from inside the root, and what has no option here is named.
    // The kernel keeps either device read-only, so neither needs blockdev
    // --setro. A mapping that is open here is mounted as any other device
    // is.
    let fs = MockFilesystem::new();
    fs.mock_set_path_type("/mnt/decoy", PathKind::Dir);
    fs.mock_set_path_type("/mnt/decoy/etc", PathKind::Dir);
    fs.mock_add_file(
        "/mnt/decoy/etc/fstab",
        "/home/alice/disk.img /mnt/x ext4 loop 0 0\n\
         /srv/disk.img /mnt/part btrfs loop,offset=1048576,sizelimit=8388608,subvol=@ 0 0\n\
         /dev/mapper/vault /data ext4 defaults 0 2\n\
         /dev/mapper/secret /secret ext4 defaults 0 2\n\
         /dev/mapper/sys /media/sys ext4 defaults 0 2\n\
         /dev/mapper/stick /media/stick vfat defaults 0 2\n\
         /dev/mapper/gone /media/gone xfs defaults 0 2\n\
         /dev/mapper/open /media/open ext4 defaults 0 2\n\
         /dev/mapper/pl /media/pl ext4 defaults 0 2\n\
         /dev/mapper/hd /media/hd ext4 defaults 0 2\n",
    );
    fs.mock_add_file(
        "/mnt/decoy/etc/crypttab",
        "vault UUID=ab none luks\n\
         secret /home/alice/vault.hc none tcrypt-veracrypt,tcrypt-hidden\n\
         sys /dev/sdc none tcrypt-system\n\
         stick PARTUUID=cd none bitlk\n\
         open /dev/sdd none luks\n\
         pl /dev/sdb3 none plain,cipher=aes-xts-plain64,size=512,hash=sha512\n\
         hd UUID=ef /etc/keys/hd.key luks,header=/etc/hd.hdr,tpm2-device=auto\n",
    );
    fs.mock_set_path_type("/dev/mapper/open", PathKind::File);

    let result = Verifier::new(fs)
        .offline_under("/mnt/decoy".into())
        .run(false)
        .unwrap();
    let why = |place: &str, how: &str| {
        format!(
            "{place}, which the decoy's /etc/fstab mounts (missing or empty under the root. {how})"
        )
    };
    let named = |open: &str, mount: &str| {
        format!(
            "Its device is a mapping of the decoy's /etc/crypttab that is not open here: open it \
             read-only and mount it there without a journal replay before the scan, with `sudo \
             cryptsetup open --readonly {open} && sudo mount {mount}`"
        )
    };
    let attached = |losetup: &str, mount: &str| {
        format!(
            "Its device is a file in the image: attach it read-only, with `sudo losetup \
             --read-only --find --show {losetup}`, then mount the loop device that prints there \
             without a journal replay before the scan, with `sudo mount {mount}`"
        )
    };
    assert_eq!(
        unmounted(&result.areas_not_checked),
        [
            why(
                "/data",
                &named(
                    "/dev/disk/by-uuid/ab vault",
                    "-o ro,noload /dev/mapper/vault /mnt/decoy/data"
                )
            ),
            why(
                "/media/gone",
                "Its device is a mapping that is not open here: open it read-only and mount it \
                 there without a journal replay before the scan, with `sudo cryptsetup open \
                 --readonly <source> gone && sudo mount -o ro,norecovery /dev/mapper/gone \
                 /mnt/decoy/media/gone`, where <source> is the encrypted device or file that \
                 holds it"
            ),
            why(
                "/media/hd",
                &format!(
                    "{}. It needs parameters of its own for what its line there also opens it \
                     with, which the command leaves out: the key file /etc/keys/hd.key, \
                     tpm2-device=auto",
                    named(
                        "--header /mnt/decoy/etc/hd.hdr /dev/disk/by-uuid/ef hd",
                        "-o ro,noload /dev/mapper/hd /mnt/decoy/media/hd"
                    )
                )
            ),
            why(
                "/media/open",
                "Its device is not mounted here: make it read-only and mount it there without a \
                 journal replay before the scan, with `sudo blockdev --setro /dev/mapper/open && \
                 sudo mount -o ro,noload /dev/mapper/open /mnt/decoy/media/open`"
            ),
            why(
                "/media/pl",
                &named(
                    "--type plain --cipher aes-xts-plain64 --key-size 512 --hash sha512 /dev/sdb3 pl",
                    "-o ro,noload /dev/mapper/pl /mnt/decoy/media/pl"
                )
            ),
            why(
                "/media/stick",
                &named(
                    "--type bitlk /dev/disk/by-partuuid/cd stick",
                    "-o ro /dev/mapper/stick /mnt/decoy/media/stick"
                )
            ),
            why(
                "/media/sys",
                &named(
                    "--type tcrypt --tcrypt-system /dev/sdc sys",
                    "-o ro,noload /dev/mapper/sys /mnt/decoy/media/sys"
                )
            ),
            why(
                "/mnt/part",
                &attached(
                    "--offset 1048576 --sizelimit 8388608 /mnt/decoy/srv/disk.img",
                    "-o ro,rescue=nologreplay,subvol=@ <loop device> /mnt/decoy/mnt/part"
                )
            ),
            why(
                "/mnt/x",
                &attached(
                    "/mnt/decoy/home/alice/disk.img",
                    "-o ro,noload <loop device> /mnt/decoy/mnt/x"
                )
            ),
            why(
                "/secret",
                &named(
                    "--type tcrypt --tcrypt-hidden /mnt/decoy/home/alice/vault.hc secret",
                    "-o ro,noload /dev/mapper/secret /mnt/decoy/secret"
                )
            ),
        ]
    );
}

#[test]
fn the_file_a_decoy_mounts_and_the_source_of_its_mapping_lie_inside_the_root() {
    // The image's /home is an absolute link to /data/home: the disk image and
    // the container in it are found there, never in the /home of the machine
    // running verify.
    let root = decoy(
        &["data/home/alice", "srv/bob"],
        &[
            (
                "etc/fstab",
                "/home/alice/disk.img /mnt/x ext4 loop 0 0\n\
                 /dev/mapper/nails-test-closed /data/vault ext4 defaults 0 2\n",
            ),
            (
                "etc/crypttab",
                "nails-test-closed /home/alice/vault.hc none luks\n",
            ),
            ("data/home/alice/.profile", ""),
            ("srv/bob/.profile", ""),
        ],
    );
    std::os::unix::fs::symlink("/data/home", root.path().join("home")).unwrap();
    let in_home = |file: &str| {
        nails_base::next_step::shell_word(
            root.path().join("data/home/alice").join(file).as_os_str(),
        )
    };
    let result = scan(root.path(), false, false).unwrap();
    let lines = unmounted(&result.areas_not_checked);
    assert_eq!(places(&result.areas_not_checked), ["/data/vault", "/mnt/x"]);
    assert!(
        lines[0].contains(&format!(
            "`sudo cryptsetup open --readonly {} nails-test-closed && ",
            in_home("vault.hc")
        )),
        "{lines:#?}"
    );
    assert!(
        lines[1].contains(&format!(
            "`sudo losetup --read-only --find --show {}`",
            in_home("disk.img")
        )),
        "{lines:#?}"
    );
}

#[test]
fn the_decoys_links_are_followed_inside_the_root() {
    // NixOS links /etc/fstab into /etc/static, itself a link into the store:
    // both resolve inside the image, never on the machine running verify. A
    // mount point that is an absolute link leads inside the image too.
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("notes"), "").unwrap();
    let root = decoy(
        &["nix/store/abc-etc/etc", "data/home", "srv"],
        &[
            (
                "nix/store/abc-etc/etc/fstab",
                "UUID=1 /home ext4 defaults 0 2\nUUID=1 /var/log ext4 defaults 0 2\n",
            ),
            ("data/home/.keep", ""),
        ],
    );
    let link = |target: &Path, at: &str| {
        std::os::unix::fs::symlink(target, root.path().join(at)).unwrap();
    };
    link(Path::new("/etc/static/fstab"), "etc/fstab");
    link(Path::new("/nix/store/abc-etc/etc"), "etc/static");
    // /home holds the home folder, /var/log leads to nothing in the image,
    // and bob's home leads out of it, where a folder that holds a file is.
    link(Path::new("/data/home"), "home");
    std::fs::create_dir(root.path().join("var")).unwrap();
    link(Path::new("/persist/log"), "var/log");
    link(outside.path(), "srv/bob");

    let result = scan(root.path(), false, false).unwrap();
    assert_eq!(
        places(&result.areas_not_checked),
        ["/var/log", "/home/alice", "/srv/bob"],
        "{:#?}",
        result.areas_not_checked
    );
}

#[test]
fn an_fstab_that_cannot_be_read_inside_the_root_is_not_read() {
    // NixOS's link into a store that is not mounted under the root, which
    // says where it leads there; a file that is no text; and a link to
    // /dev/null, which mounts nothing.
    let root = decoy(&["home/alice", "srv/bob"], &[("home/alice/.profile", "")]);
    std::fs::write(root.path().join("srv/bob/.profile"), "").unwrap();
    let fstab = root.path().join("etc/fstab");
    let not_read = |why: &str| {
        format!(
            "/etc/fstab, the decoy's table of what it mounts ({why}: what it mounts is not known)"
        )
    };
    std::os::unix::fs::symlink("/etc/static/fstab", &fstab).unwrap();
    let result = scan(root.path(), false, false).unwrap();
    assert_eq!(
        unmounted(&result.areas_not_checked),
        [not_read(
            "a link that leads to /etc/static/fstab inside the root, where no file can be read"
        )]
    );
    std::fs::remove_file(&fstab).unwrap();
    std::fs::write(&fstab, b"UUID=1 /home ext4 defaults 0 2 \xff\n").unwrap();
    let result = scan(root.path(), false, false).unwrap();
    assert_eq!(
        unmounted(&result.areas_not_checked),
        [not_read("it could not be read")]
    );
    std::fs::remove_file(&fstab).unwrap();
    std::os::unix::fs::symlink("/dev/null", &fstab).unwrap();
    let result = scan(root.path(), false, false).unwrap();
    assert!(unmounted(&result.areas_not_checked).is_empty());
    // A link that comes back through itself inside the image.
    std::fs::remove_file(&fstab).unwrap();
    std::os::unix::fs::symlink("../etc/fstab", &fstab).unwrap();
    let result = scan(root.path(), false, false).unwrap();
    assert_eq!(
        unmounted(&result.areas_not_checked),
        [not_read("a link that does not resolve inside the root")]
    );
}

/// A temporary folder that holds the decoy root `root`, with the accounts
/// of [`PASSWD`] and bob's home in place, and beside it, out of the image,
/// what `files` names (path from the folder, and text).
fn beside_a_decoy(files: &[(&str, &str)]) -> tempfile::TempDir {
    let tree = tempfile::tempdir().unwrap();
    let root = tree.path().join("root");
    std::fs::create_dir_all(root.join("etc")).unwrap();
    std::fs::write(root.join("etc/passwd"), PASSWD).unwrap();
    std::fs::create_dir_all(root.join("srv/bob")).unwrap();
    std::fs::write(root.join("srv/bob/.profile"), "").unwrap();
    for (file, text) in files {
        let path = tree.path().join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }
    tree
}

/// What the scan says of a decoy place that does not resolve inside the root.
fn not_resolved(place: &str, of: &str) -> String {
    format!("{place}, {of} (it does not resolve inside the root, so nothing there was read)")
}

#[test]
fn a_deep_scan_does_not_follow_a_link_out_of_the_image() {
    // On the machine running verify each link leads beside the image, to a
    // history that names the tool, which was read and reported as a trace on
    // the decoy. Inside the image alice's home as an absolute link and /home
    // climbing out of it lead to nothing, so her home is not checked. /home
    // linked to ../home comes back through itself inside the image, as an
    // absolute link to a folder below the machine's own /home does: it does
    // not resolve there, and nothing is read through it.
    let history = "sudo /mnt/data/nails activate\n";
    let missing = home_of("alice", "/home/alice");
    let looped = not_resolved(
        "/home/alice",
        "the home of alice in the decoy's /etc/passwd",
    );
    for (link, absolute, target, listed) in [
        ("home/alice", true, "outside/alice", &missing),
        ("home", false, "../outside", &missing),
        ("home", false, "../home", &looped),
    ] {
        let tree = beside_a_decoy(&[
            ("outside/alice/.bash_history", history),
            ("home/alice/.bash_history", history),
        ]);
        // The absolute target must not lead back through alice's home.
        assert!(!tree.path().starts_with("/home/alice"));
        let root = tree.path().join("root");
        let target = if absolute {
            tree.path().join(target)
        } else {
            Path::new(target).to_path_buf()
        };
        std::fs::create_dir_all(root.join(link).parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&target, root.join(link)).unwrap();
        let shown = format!("{link} -> {}", target.display());

        let result = scan(&root, true, false).unwrap();
        assert_eq!(
            result.status,
            VerifyStatus::Secure,
            "{shown}: {:?}",
            result.findings
        );
        assert_eq!(
            unmounted(&result.areas_not_checked),
            [listed.as_str()],
            "{shown}"
        );
        let home_not_checked = result.findings.iter().any(|finding| {
            finding.message == "Home not checked (it does not resolve inside the root): /home/alice"
        });
        assert_eq!(
            home_not_checked,
            listed == &looped,
            "{shown}: {:?}",
            result.findings
        );
    }
}

#[test]
fn nothing_is_read_through_a_place_that_does_not_resolve_inside_the_root() {
    // Each link comes back through itself inside the image while it leads
    // beside it on the machine running verify: the deep scan's folders, a
    // mount point, the file a loop device is set up on, the source of a
    // mapping and the fstab itself. None is read, and each is named.
    let tree = beside_a_decoy(&[
        ("var/log/nails.log", ""),
        ("data/notes", ""),
        ("srv/disk.img", ""),
    ]);
    let root = tree.path().join("root");
    let link = |target: &str, at: &str| std::os::unix::fs::symlink(target, root.join(at)).unwrap();
    link("../var", "var");
    link("../data", "data");
    std::fs::create_dir_all(root.join("home/alice")).unwrap();
    std::fs::write(root.join("home/alice/.profile"), "").unwrap();
    std::fs::write(
        root.join("etc/fstab"),
        "UUID=1 /data ext4 defaults 0 2\n\
         /srv/disk.img /mnt/x ext4 loop 0 0\n\
         /dev/mapper/nails-test-looped /mnt/vault ext4 defaults 0 2\n",
    )
    .unwrap();
    std::fs::write(
        root.join("etc/crypttab"),
        "nails-test-looped /srv/vault.hc none luks\n",
    )
    .unwrap();
    std::fs::remove_dir_all(root.join("srv")).unwrap();
    link("../srv", "srv");

    let result = scan(&root, true, false).unwrap();
    assert_eq!(result.status, VerifyStatus::Secure, "{:?}", result.findings);
    for base in ["/var/tmp", "/var/log"] {
        let note = format!("Directory not checked (it does not resolve inside the root): {base}");
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.message == note),
            "{note}: {:?}",
            result.findings
        );
    }
    let mounts = "which the decoy's /etc/fstab mounts";
    let lines = unmounted(&result.areas_not_checked);
    assert_eq!(lines[0], not_resolved("/data", mounts));
    assert!(
        lines[1].starts_with(&format!(
            "/mnt/vault, {mounts} (missing or empty under the root. Its device is a mapping of \
             the decoy's /etc/crypttab that is not open here: open it read-only and mount it \
             there without a journal replay before the scan, with `sudo cryptsetup open \
             --readonly <source> nails-test-looped && "
        )) && lines[1].ends_with(
            ", where <source> is /srv/vault.hc of the image, which does not resolve inside the \
             root)"
        ),
        "{}",
        lines[1]
    );
    assert_eq!(
        lines[2],
        format!(
            "/mnt/x, {mounts} (missing or empty under the root. Its device is the file \
             /srv/disk.img of the image, which does not resolve inside the root, so no command \
             is given)"
        )
    );
    assert_eq!(
        lines[3],
        not_resolved("/srv/bob", "the home of bob in the decoy's /etc/passwd")
    );
    assert_eq!(lines.len(), 4, "{lines:#?}");
}

/// The access time of `path`, to the nanosecond.
fn atime(path: &Path) -> (i64, i64) {
    let meta = std::fs::symlink_metadata(path).unwrap();
    (meta.atime(), meta.atime_nsec())
}

/// Set the access time of `path` well behind its modification time, so that
/// `relatime` updates it on the next plain read.
fn backdate_atime(path: &Path) {
    let old = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
    std::fs::File::open(path)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_accessed(old))
        .unwrap();
}

#[test]
fn looking_for_the_unmounted_places_moves_no_access_time() {
    let root = decoy(
        &["home", "var/log", "boot", "srv/bob"],
        &[("etc/fstab", FSTAB), ("boot/grub.cfg", "")],
    );
    // Unless a plain read moves an access time here, keeping it proves
    // nothing.
    let probe = root.path().join("boot/grub.cfg");
    backdate_atime(&probe);
    let before = atime(&probe);
    let _ = std::fs::read(&probe).unwrap();
    if atime(&probe) == before {
        eprintln!("skipping: the temp filesystem does not record access times");
        return;
    }

    let read = [
        "etc/fstab",
        "etc/passwd",
        "home",
        "var/log",
        "boot",
        "srv/bob",
    ]
    .map(|place| root.path().join(place));
    for path in &read {
        backdate_atime(path);
    }
    let before: Vec<_> = read.iter().map(|path| atime(path)).collect();
    let areas = Verifier::new(RealFilesystem)
        .offline_under(root.path().to_path_buf())
        .unmounted_areas();
    assert!(!areas.is_empty(), "the places were looked at");
    let after: Vec<_> = read.iter().map(|path| atime(path)).collect();
    assert_eq!(after, before, "an access time moved: {read:?}");
}

/// What an offline scan cannot look at, for another reason than that
/// nothing is there, was left out: an fstab it could neither read nor look
/// at, and a mount point or a home it could not look at, which the scan
/// took for scanned. Each is listed as not read, with the error.
#[test]
fn a_place_or_an_fstab_the_scan_cannot_look_at_is_listed_as_not_read() {
    // A decoy at /mnt/decoy whose /home and bob's home cannot be looked at.
    let decoy = || {
        let fs = MockFilesystem::new();
        fs.mock_set_path_type("/mnt/decoy", PathKind::Dir);
        fs.mock_set_path_type("/mnt/decoy/etc", PathKind::Dir);
        fs.mock_add_file("/mnt/decoy/etc/passwd", PASSWD);
        fs.mock_set_lookup_error("/mnt/decoy/home", std::io::ErrorKind::PermissionDenied);
        fs.mock_set_lookup_error("/mnt/decoy/srv/bob", std::io::ErrorKind::Other);
        fs
    };
    let fs = decoy();
    fs.mock_set_lookup_error("/mnt/decoy/etc/fstab", std::io::ErrorKind::PermissionDenied);
    let result = Verifier::new(fs)
        .offline_under("/mnt/decoy".into())
        .run(false)
        .unwrap();
    let unseen = |place: &str| {
        format!(
            "it could not be looked at under the root (/mnt/decoy{place}: Mock: the lookup fails \
             here), so nothing there was read"
        )
    };
    assert_eq!(
        unmounted(&result.areas_not_checked),
        [
            "/etc/fstab, the decoy's table of what it mounts (it could not be looked at \
             (/mnt/decoy/etc/fstab: Mock: the lookup fails here): what it mounts is not known)"
                .to_string(),
            format!(
                "/home/alice, the home of alice in the decoy's /etc/passwd ({})",
                unseen("/home/alice")
            ),
            format!(
                "/srv/bob, the home of bob in the decoy's /etc/passwd ({})",
                unseen("/srv/bob")
            ),
        ],
        "{:#?}",
        result.areas_not_checked
    );

    // A mount point of a readable fstab that cannot be looked at covers
    // what lies below it, as a missing one does.
    let fs = decoy();
    fs.mock_add_file("/mnt/decoy/etc/fstab", "UUID=1 /home ext4 defaults 0 2\n");
    let result = Verifier::new(fs)
        .offline_under("/mnt/decoy".into())
        .run(false)
        .unwrap();
    assert_eq!(
        unmounted(&result.areas_not_checked),
        [
            format!(
                "/home, which the decoy's /etc/fstab mounts ({})",
                unseen("/home")
            ),
            format!(
                "/srv/bob, the home of bob in the decoy's /etc/passwd ({})",
                unseen("/srv/bob")
            ),
        ],
        "{:#?}",
        result.areas_not_checked
    );
}

/// What a place the decoy mounts holds is told by what it is: a link holds
/// something, so the scan read it; a place below a file holds nothing, so
/// it is listed as missing; and one whose inode cannot be read is one the
/// scan could not look at, never one that holds nothing.
#[test]
fn what_a_mount_point_holds_is_told_by_what_it_is() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_type("/mnt/decoy", PathKind::Dir);
    fs.mock_set_path_type("/mnt/decoy/etc", PathKind::Dir);
    fs.mock_add_file("/mnt/decoy/etc/passwd", "root:x:0:0:root:/root:/bin/bash\n");
    fs.mock_add_file(
        "/mnt/decoy/etc/fstab",
        "UUID=1 /srv/a ext4 defaults 0 2\n\
         UUID=1 /srv/b ext4 defaults 0 2\n\
         UUID=1 /srv/c ext4 defaults 0 2\n",
    );
    fs.create_symlink(Path::new("/srv/elsewhere"), Path::new("/mnt/decoy/srv/a"))
        .unwrap();
    fs.mock_set_inode_error(
        Path::new("/mnt/decoy/srv/b"),
        std::io::ErrorKind::NotADirectory,
    );
    fs.mock_set_inode_error(Path::new("/mnt/decoy/srv/c"), std::io::ErrorKind::Other);
    let result = Verifier::new(fs)
        .offline_under("/mnt/decoy".into())
        .run(false)
        .unwrap();
    let listed = unmounted(&result.areas_not_checked);
    assert_eq!(
        places(&result.areas_not_checked),
        ["/srv/b", "/srv/c"],
        "{listed:#?}"
    );
    assert!(
        listed[0].starts_with(
            "/srv/b, which the decoy's /etc/fstab mounts (missing or empty under the root."
        ),
        "{listed:#?}"
    );
    assert_eq!(
        listed[1],
        "/srv/c, which the decoy's /etc/fstab mounts (it could not be looked at under the root \
         (/mnt/decoy/srv/c: other error), so nothing there was read)",
        "{listed:#?}"
    );
}
