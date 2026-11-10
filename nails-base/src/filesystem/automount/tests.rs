// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The automount guard on mock tables: each near miss of a lookup that
//! would mount an automount point, with a lookup next to it that is made,
//! every call of [`Guarded`], its ledger, [`settle`] and [`describe`].

use super::*;
use crate::filesystem::{MockFilesystem, parse_mountinfo};
use crate::next_step::{NextStep, sudo_line};
use crate::target_user::TargetUser;
use std::io::ErrorKind;

/// The decoy's root filesystem.
const ROOT: &str = "1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n";

/// A direct automount point at `/usr/local`, as systemd makes one for
/// `x-systemd.automount`, that nothing is mounted on yet.
const USR_LOCAL: &str = "30 1 0:50 / /usr/local rw,relatime - autofs systemd-1 \
                         rw,fd=50,pgrp=1,timeout=0,minproto=5,maxproto=5,direct,pipe_ino=100\n";

/// A filesystem mounted on that point.
const USR_LOCAL_MOUNTED: &str = "31 30 8:3 / /usr/local rw,relatime - ext4 /dev/sda3 rw\n";

/// The directory of an indirect map at `/net`, as the automounter mounts
/// it: a lookup of a name in it mounts that name.
const NET_MAP: &str = "40 1 0:60 / /net rw,relatime - autofs /etc/auto.net \
                       rw,fd=7,pgrp=900,timeout=300,minproto=5,maxproto=5,indirect,pipe_ino=200\n";

/// What the automounter mounts for the name `srv` of that map.
const NET_SRV: &str = "41 40 0:61 / /net/srv rw,relatime - nfs4 srv:/export rw,vers=4.2\n";

/// An offset mount of a map, below a share it mounted.
const OFFSET: &str = "50 1 0:70 / /srv/export rw,relatime - autofs /etc/auto.srv \
                      rw,fd=9,pgrp=900,timeout=300,minproto=5,maxproto=5,offset,pipe_ino=300\n";

const ENTERS: Lookup = Lookup::Enters { follow: true };
const ENTERS_NOFOLLOW: Lookup = Lookup::Enters { follow: false };
const RESOLVES: Lookup = Lookup::Resolves { follow: true };
const RESOLVES_NOFOLLOW: Lookup = Lookup::Resolves { follow: false };

/// A mock whose mount table is `lines`.
fn mock(lines: &[&str]) -> MockFilesystem {
    let fs = MockFilesystem::new();
    fs.mock_set_mount_table(&lines.concat());
    fs
}

/// What the guard says of a lookup of `path` on `fs`, in short.
fn way(fs: &MockFilesystem, path: &str, lookup: Lookup) -> String {
    let table = fs.mount_table().unwrap();
    match on_the_way(fs, &table, Path::new(path), lookup) {
        Way::Clear => "clear".to_string(),
        Way::Mounts(point) => format!("mounts {}", point.display()),
        Way::AtPoint(point) => format!("at {}", point.display()),
        Way::Failed(error) => format!("failed {:?}", error.kind()),
    }
}

/// A link at `link` to `target`.
fn link(fs: &MockFilesystem, link: &str, target: &str) {
    fs.create_symlink(Path::new(target), Path::new(link))
        .unwrap();
}

/// A guarded view of `fs`, which reads the running system.
fn guarded(fs: &MockFilesystem) -> Guarded<MockFilesystem> {
    Guarded::new(fs.clone(), &Snapshot::read(fs, Path::new("/")))
}

/// Whether `paths` holds `point` or a path below it.
fn reaches(fs: &MockFilesystem, point: &str) -> bool {
    fs.mock_reached(Path::new(point))
}

#[test]
fn a_link_on_the_way_is_followed_where_it_leads() {
    // A relative target, from the directory that holds the link.
    let fs = mock(&[ROOT, NET_MAP]);
    link(&fs, "/usr/local", "../net/srv/local");
    assert_eq!(way(&fs, "/usr/local/bin/nix", ENTERS), "mounts /net/srv");
    let fs = mock(&[ROOT, NET_MAP]);
    link(&fs, "/usr/local", "../opt/local");
    assert_eq!(way(&fs, "/usr/local/bin/nix", ENTERS), "clear");

    // An absolute target.
    let fs = mock(&[ROOT, NET_MAP]);
    link(&fs, "/home/bob", "/net/srv/bob");
    assert_eq!(way(&fs, "/home/bob/.profile", ENTERS), "mounts /net/srv");
    let fs = mock(&[ROOT, NET_MAP]);
    link(&fs, "/home/bob", "/srv/bob");
    assert_eq!(way(&fs, "/home/bob/.profile", ENTERS), "clear");

    // A chain of links.
    let fs = mock(&[ROOT, NET_MAP]);
    link(&fs, "/a", "/b");
    link(&fs, "/b", "c/d");
    link(&fs, "/c/d", "/net/srv/x");
    assert_eq!(way(&fs, "/a/y", ENTERS), "mounts /net/srv");
    let fs = mock(&[ROOT, NET_MAP]);
    link(&fs, "/a", "/b");
    link(&fs, "/b", "c/d");
    link(&fs, "/c/d", "/srv/x");
    assert_eq!(way(&fs, "/a/y", ENTERS), "clear");

    // A target that passes a direct automount point, and one that passes
    // none.
    let fs = mock(&[ROOT, USR_LOCAL]);
    link(&fs, "/opt/tools", "/usr/local/tools");
    assert_eq!(way(&fs, "/opt/tools/bin", ENTERS), "mounts /usr/local");
    let fs = mock(&[ROOT, USR_LOCAL]);
    link(&fs, "/opt/tools", "/usr/lib/tools");
    assert_eq!(way(&fs, "/opt/tools/bin", ENTERS), "clear");
}

#[test]
fn a_link_at_the_end_is_followed_only_by_a_lookup_that_follows_it() {
    let fs = mock(&[ROOT, NET_MAP]);
    link(&fs, "/nix", "/net/srv/nix");
    assert_eq!(way(&fs, "/nix", ENTERS), "mounts /net/srv");
    assert_eq!(way(&fs, "/nix", RESOLVES), "mounts /net/srv");
    assert_eq!(way(&fs, "/nix", ENTERS_NOFOLLOW), "clear");
    assert_eq!(way(&fs, "/nix", RESOLVES_NOFOLLOW), "clear");
    // Below the link it is followed, whatever the lookup does at its end.
    assert_eq!(way(&fs, "/nix/store", ENTERS_NOFOLLOW), "mounts /net/srv");

    // A link to nothing by name ends the lookup.
    let fs = mock(&[ROOT, USR_LOCAL]);
    link(&fs, "/usr/empty", "");
    assert_eq!(way(&fs, "/usr/empty/local/bin", ENTERS), "clear");
}

#[test]
fn dot_dot_is_taken_from_where_the_lookup_is() {
    // Into an automount point and back out of it: the lookup enters it.
    let fs = mock(&[ROOT, USR_LOCAL]);
    assert_eq!(way(&fs, "/usr/local/../lib", ENTERS), "mounts /usr/local");
    assert_eq!(way(&fs, "/usr/lib/../share", ENTERS), "clear");

    // `..` at `/` stays there.
    assert_eq!(way(&fs, "/../usr/local/bin", ENTERS), "mounts /usr/local");
    assert_eq!(way(&fs, "/../../etc/passwd", ENTERS), "clear");

    // After a link, `..` is the parent of where the link led, not of the
    // link.
    let point = "60 1 0:80 / /mnt/disk/usr rw,relatime - autofs systemd-1 rw,direct\n";
    let fs = mock(&[ROOT, point]);
    link(&fs, "/data", "/mnt/disk/data");
    assert_eq!(way(&fs, "/data/../usr/bin", ENTERS), "mounts /mnt/disk/usr");
    let fs = mock(&[ROOT, USR_LOCAL]);
    link(&fs, "/data", "/mnt/disk/data");
    assert_eq!(way(&fs, "/data/../usr/local/bin", ENTERS), "clear");
}

#[test]
fn the_directory_of_an_indirect_map_is_no_automount_point_but_a_name_in_it_is() {
    let fs = mock(&[ROOT, NET_MAP]);
    // The directory itself is looked up and listed.
    assert_eq!(way(&fs, "/net", ENTERS), "clear");
    assert_eq!(way(&fs, "/net", ENTERS_NOFOLLOW), "clear");
    assert_eq!(way(&fs, "/net", RESOLVES), "clear");
    // A name in it, and a path below the name, are not, however the lookup
    // takes its end: looking the name up mounts it.
    for lookup in [ENTERS, ENTERS_NOFOLLOW, RESOLVES, RESOLVES_NOFOLLOW] {
        assert_eq!(
            way(&fs, "/net/srv", lookup),
            "mounts /net/srv",
            "{lookup:?}"
        );
    }
    assert_eq!(way(&fs, "/net/srv/export", ENTERS), "mounts /net/srv");
}

#[test]
fn a_name_mounted_in_an_indirect_map_and_a_point_mounted_over_are_looked_up() {
    let fs = mock(&[ROOT, NET_MAP, NET_SRV]);
    assert_eq!(way(&fs, "/net/srv", ENTERS), "clear");
    assert_eq!(way(&fs, "/net/srv/export/file", ENTERS), "clear");
    // Another name of the same map is not mounted yet.
    assert_eq!(way(&fs, "/net/other/file", ENTERS), "mounts /net/other");

    let fs = mock(&[ROOT, USR_LOCAL, USR_LOCAL_MOUNTED]);
    assert_eq!(way(&fs, "/usr/local", ENTERS), "clear");
    assert_eq!(way(&fs, "/usr/local/bin/nix", ENTERS), "clear");
    let fs = mock(&[ROOT, USR_LOCAL]);
    assert_eq!(way(&fs, "/usr/local/bin/nix", ENTERS), "mounts /usr/local");
}

#[test]
fn an_offset_mount_is_an_automount_point() {
    let fs = mock(&[ROOT, OFFSET]);
    assert_eq!(way(&fs, "/srv/export/data", ENTERS), "mounts /srv/export");
    assert_eq!(way(&fs, "/srv/other/data", ENTERS), "clear");
}

#[test]
fn a_direct_point_at_the_end_is_skipped_or_answered_from_the_table() {
    let fs = mock(&[ROOT, USR_LOCAL]);
    // A lookup that reads what is there mounts it.
    assert_eq!(way(&fs, "/usr/local", ENTERS), "mounts /usr/local");
    assert_eq!(way(&fs, "/usr/local", ENTERS_NOFOLLOW), "mounts /usr/local");
    // One that only resolves the path does not: its answer is the point.
    assert_eq!(way(&fs, "/usr/local", RESOLVES), "at /usr/local");
    assert_eq!(way(&fs, "/usr/local", RESOLVES_NOFOLLOW), "at /usr/local");
    // A path that ends in `/` names a directory, which is looked into.
    assert_eq!(
        way(&fs, "/usr/local/", RESOLVES_NOFOLLOW),
        "mounts /usr/local"
    );
    assert_eq!(way(&fs, "/usr/local/.", RESOLVES), "mounts /usr/local");
    // The point is never read for the answer.
    assert!(!reaches(&fs, "/usr/local"));

    let view = guarded(&fs);
    let point = Path::new("/usr/local");
    assert_eq!(view.canonicalize(point).unwrap(), point);
    assert_eq!(view.mount_root(point).unwrap(), MountRoot::Automount);
    let error = view.read_link(point).unwrap_err();
    assert_eq!(error.io_kind(), Some(ErrorKind::InvalidInput), "{error}");
    assert_eq!(
        view.resolve_in_root(Path::new("/"), point).as_deref(),
        Some(point)
    );
    // Through a link, the answer is where the link leads.
    link(&fs, "/opt/local", "/usr/local");
    assert_eq!(view.canonicalize(Path::new("/opt/local")).unwrap(), point);
    assert!(!reaches(&fs, "/usr/local"));
    assert!(view.skipped().is_empty());
    // A lookup that reads it is not made.
    assert!(view.path_exists(point).is_err());
    assert!(!reaches(&fs, "/usr/local"));
}

/// An automount point the table does not show, as one set up after it was
/// read, is told by what the kernel says of the place (`mount_root`): its
/// attribute for a submount of NFS, CIFS, AFS or FUSE, and an autofs on top
/// for systemd's and the automounters' points.
#[test]
fn an_automount_point_the_table_missed_is_told_by_the_kernel() {
    let fs = mock(&[ROOT]);
    fs.mock_set_automount("/media/usb");
    assert_eq!(way(&fs, "/media/usb/photo", ENTERS), "mounts /media/usb");
    assert_eq!(way(&fs, "/media/usb", ENTERS), "mounts /media/usb");
    assert_eq!(way(&fs, "/media/usb", ENTERS_NOFOLLOW), "mounts /media/usb");
    assert_eq!(way(&fs, "/media/usb", RESOLVES), "at /media/usb");
    assert_eq!(way(&fs, "/media/usb/photo", RESOLVES), "mounts /media/usb");
    assert_eq!(way(&fs, "/media/other/photo", ENTERS), "clear");
}

/// A filesystem the table shows on a direct automount point that expired
/// since the table was read leaves an autofs on top there: the point is
/// not looked up, as if the table had shown it so. Where the table is
/// right, the place is looked into.
#[test]
fn a_point_whose_mount_expired_after_the_table_was_read_is_not_looked_up() {
    let fs = mock(&[ROOT, USR_LOCAL, USR_LOCAL_MOUNTED]);
    assert_eq!(way(&fs, "/usr/local/bin/updatedb", ENTERS), "clear");
    fs.mock_set_automount("/usr/local");
    assert_eq!(
        way(&fs, "/usr/local/bin/updatedb", ENTERS),
        "mounts /usr/local"
    );
    assert_eq!(way(&fs, "/usr/local", RESOLVES), "at /usr/local");
}

/// The directory of an indirect map the table shows is an autofs on top,
/// as the kernel says of it, but no point itself: the walk goes into it,
/// and the name below it is the point.
#[test]
fn the_directory_of_an_indirect_map_is_passed_into() {
    let fs = mock(&[ROOT, NET_MAP]);
    fs.mock_set_automount("/net");
    assert_eq!(way(&fs, "/net", ENTERS), "clear");
    assert_eq!(way(&fs, "/net/srv/export", ENTERS), "mounts /net/srv");
    // A map the table does not show is no directory it knows: the place is
    // taken for a point.
    let fs = mock(&[ROOT]);
    fs.mock_set_automount("/net");
    assert_eq!(way(&fs, "/net/srv/export", ENTERS), "mounts /net");
}

#[test]
fn a_lookup_on_the_way_that_fails_fails_the_lookup_with_its_error() {
    let fs = mock(&[ROOT]);
    fs.mock_set_lookup_error("/home/carol", ErrorKind::PermissionDenied);
    assert_eq!(
        way(&fs, "/home/carol/.profile", ENTERS),
        "failed PermissionDenied"
    );
    fs.mock_clear_lookups();
    let view = guarded(&fs);
    let path = Path::new("/home/carol/.profile");
    let error = view.path_exists(path).unwrap_err();
    assert_eq!(
        error.io_kind(),
        Some(ErrorKind::PermissionDenied),
        "{error}"
    );
    assert!(
        error.to_string().starts_with("/home/carol/.profile: "),
        "{error}"
    );
    // The lookup itself is not made, and it is no skip.
    assert!(!fs.mock_lookups().iter().any(|asked| asked == path));
    assert!(view.skipped().is_empty());

    // A link the guard cannot read fails it too.
    let fs = mock(&[ROOT]);
    fs.mock_set_path_type("/opt/odd", crate::filesystem::PathKind::Symlink);
    assert_eq!(way(&fs, "/opt/odd/file", ENTERS), "failed InvalidInput");

    // A place that is not there ends the walk: the lookup is made, and
    // answers that nothing is there.
    let fs = mock(&[ROOT, USR_LOCAL]);
    fs.mock_set_lookup_error("/gone", ErrorKind::NotFound);
    assert_eq!(way(&fs, "/gone/usr/local", ENTERS), "clear");
    let view = guarded(&fs);
    assert!(!view.path_exists(Path::new("/gone/x")).unwrap());
    assert!(fs.mock_lookups().contains(&PathBuf::from("/gone/x")));
}

#[test]
fn a_lookup_follows_as_many_links_as_the_kernel_and_no_more() {
    // /l1 to /l40: 40 links, the last onto the share.
    let chain = |first: usize| {
        let fs = mock(&[ROOT, NET_MAP]);
        for n in first..40 {
            link(&fs, &format!("/l{n}"), &format!("/l{}", n + 1));
        }
        link(&fs, "/l40", "/net/srv");
        fs
    };
    assert_eq!(way(&chain(1), "/l1/x", ENTERS), "mounts /net/srv");
    // From /l0, 41.
    let fs = chain(0);
    let table = fs.mount_table().unwrap();
    match on_the_way(&fs, &table, Path::new("/l0/x"), ENTERS) {
        Way::Failed(error) => assert_eq!(error.raw_os_error(), Some(nix::libc::ELOOP)),
        other => panic!("{other:?}"),
    }
    let view = guarded(&fs);
    let error = view.path_exists(Path::new("/l0/x")).unwrap_err();
    assert!(error.to_string().starts_with("/l0/x: "), "{error}");
    assert!(!fs.mock_lookups().contains(&PathBuf::from("/l0/x")));

    // A link to itself loops.
    let fs = mock(&[ROOT]);
    link(&fs, "/home/eve", "/home/eve");
    assert_eq!(
        way(&fs, "/home/eve/.profile", ENTERS),
        "failed FilesystemLoop"
    );
}

#[test]
fn a_relative_path_is_walked_from_the_working_directory() {
    let cwd = std::env::current_dir().unwrap();
    let point = cwd.join("automount-guard-probe");
    let fs = mock(&[
        ROOT,
        &format!(
            "70 1 0:90 / {} rw,relatime - autofs systemd-1 rw,direct\n",
            point.display()
        ),
    ]);
    assert_eq!(
        way(&fs, "automount-guard-probe/file", ENTERS),
        format!("mounts {}", point.display())
    );
    assert_eq!(way(&fs, "other/file", ENTERS), "clear");
    assert_eq!(
        way(&fs, "other/../automount-guard-probe", RESOLVES),
        format!("at {}", point.display())
    );
}

#[test]
fn without_the_mount_table_nothing_is_looked_up() {
    let fs = MockFilesystem::new();
    fs.mock_set_mount_table_error("no mountinfo");
    let snapshot = Snapshot::read(&fs, Path::new("/"));
    assert!(snapshot.unreadable().unwrap().contains("no mountinfo"));
    assert!(snapshot.table().is_none());
    let view = Guarded::new(fs.clone(), &snapshot);
    for path in ["/etc/passwd", "/", "/usr/local/bin"] {
        let error = view.path_exists(Path::new(path)).unwrap_err();
        assert!(
            matches!(
                error.not_looked_up(),
                Some((asked, Skip::NoMountTable { error })) if asked == Path::new(path)
                    && error.contains("no mountinfo")
            ),
            "{error:?}"
        );
        assert!(view.canonicalize(Path::new(path)).is_err());
    }
    assert!(fs.mock_lookups().is_empty(), "{:?}", fs.mock_lookups());
    assert_eq!(view.skipped().len(), 6);
    let error = view.mount_table().unwrap_err();
    assert!(error.to_string().contains("no mountinfo"), "{error}");
    assert!(
        snapshot
            .check(&fs, Path::new("/etc/passwd"), ENTERS)
            .is_err()
    );
}

#[test]
fn a_tree_that_is_not_the_running_systems_is_not_guarded() {
    let fs = mock(&[ROOT, USR_LOCAL]);
    let snapshot = Snapshot::read(&fs, Path::new("/srv/image"));
    assert!(snapshot.table().is_none());
    assert!(snapshot.unreadable().is_none());
    let view = Guarded::new(fs.clone(), &snapshot);
    let path = Path::new("/usr/local/bin/nix");
    assert!(!view.path_exists(path).unwrap());
    assert!(fs.mock_lookups().contains(&path.to_path_buf()));
    assert!(view.find_files_with_pattern(path, "x").is_ok());
    assert!(
        view.read_file_in_root(Path::new("/srv/image"), path)
            .is_err()
    );
    assert_eq!(view.skipped(), Vec::new());
    assert_eq!(view.mount_table().unwrap(), fs.mount_table().unwrap());
    assert_eq!(snapshot.check(&fs, path, ENTERS).unwrap(), None);
}

/// A snapshot of a table given whatever the root guards a reader that
/// makes its lookups itself, as the running system's would.
#[test]
fn a_reader_of_its_own_asks_a_snapshot_of_a_given_table() {
    let fs = MockFilesystem::new();
    let snapshot = Snapshot::from_table(parse_mountinfo(&[ROOT, USR_LOCAL, NET_MAP].concat()));
    assert!(snapshot.table().is_some());
    let error = snapshot
        .check(&fs, Path::new("/usr/local/lib/systemd/system"), ENTERS)
        .unwrap_err();
    assert_eq!(
        error.not_looked_up().and_then(|(_, reason)| reason.point()),
        Some(Path::new("/usr/local"))
    );
    assert_eq!(
        snapshot
            .check(&fs, Path::new("/usr/local"), RESOLVES)
            .unwrap(),
        Some(PathBuf::from("/usr/local"))
    );
    assert_eq!(
        snapshot
            .check(&fs, Path::new("/etc/fstab"), ENTERS)
            .unwrap(),
        None
    );
    fs.mock_set_lookup_error("/etc", ErrorKind::PermissionDenied);
    let error = snapshot
        .check(&fs, Path::new("/etc/fstab"), ENTERS)
        .unwrap_err();
    assert_eq!(
        error.io_kind(),
        Some(ErrorKind::PermissionDenied),
        "{error}"
    );
}

/// A call of [`Guarded`] on a path, its value dropped.
type Call = fn(&Guarded<MockFilesystem>, &Path) -> crate::Result<()>;

/// The calls that read what is at their path, or write there.
fn entering_calls() -> Vec<(&'static str, Call)> {
    vec![
        ("path_exists", |fs, p| fs.path_exists(p).map(drop)),
        ("is_directory", |fs, p| fs.is_directory(p).map(drop)),
        ("is_regular_file", |fs, p| fs.is_regular_file(p).map(drop)),
        ("device_id", |fs, p| fs.device_id(p).map(drop)),
        ("inode", |fs, p| fs.inode(p).map(drop)),
        ("record_lock_holder", |fs, p| {
            fs.record_lock_holder(p).map(drop)
        }),
        ("loop_record", |fs, p| fs.loop_record(p).map(drop)),
        ("is_symlink", |fs, p| fs.is_symlink(p).map(drop)),
        ("entry_exists", |fs, p| fs.entry_exists(p).map(drop)),
        ("is_overlay_whiteout", |fs, p| {
            fs.is_overlay_whiteout(p).map(drop)
        }),
        ("disk_usage", |fs, p| fs.disk_usage(p).map(drop)),
        ("get_permissions", |fs, p| fs.get_permissions(p).map(drop)),
        ("is_readable", |fs, p| fs.is_readable(p).map(drop)),
        ("is_writable", |fs, p| fs.is_writable(p).map(drop)),
        ("read_file_content", |fs, p| {
            fs.read_file_content(p).map(drop)
        }),
        ("read_file_bytes", |fs, p| fs.read_file_bytes(p).map(drop)),
        ("read_file_range", |fs, p| {
            fs.read_file_range(p, 0, 1).map(drop)
        }),
        ("read_file_in_root", |fs, p| {
            fs.read_file_in_root(Path::new("/"), p).map(drop)
        }),
        ("list_directory", |fs, p| fs.list_directory(p).map(drop)),
        ("file_size", |fs, p| fs.file_size(p).map(drop)),
        ("modified_time", |fs, p| fs.modified_time(p).map(drop)),
        ("change_time", |fs, p| fs.change_time(p).map(drop)),
        ("supports_symlinks", |fs, p| {
            fs.supports_symlinks(p).map(drop)
        }),
        ("create_symlink", |fs, p| {
            fs.create_symlink(Path::new("/target"), p)
        }),
        ("create_directory", |fs, p| fs.create_directory(p)),
        ("create_hidden_dir_all", |fs, p| {
            fs.create_hidden_dir_all(p, Path::new("x"))
        }),
        ("write_hidden_file_atomic", |fs, p| {
            fs.write_hidden_file_atomic(p, Path::new("x"), "text", 0o600)
        }),
        ("set_permissions", |fs, p| fs.set_permissions(p, 0o600)),
        ("write_file_content", |fs, p| fs.write_file_content(p, "x")),
        ("write_user_file", |fs, p| {
            let user = TargetUser::for_test(1000, 1000, "alice", "/home/alice", "/bin/sh");
            fs.write_user_file(p, "x", &user, 0o600)
        }),
        ("overwrite_file_in_place", |fs, p| {
            fs.overwrite_file_in_place(p, "x")
        }),
        ("rename_file from", |fs, p| {
            fs.rename_file(p, Path::new("/etc/other"))
        }),
        ("rename_file to", |fs, p| {
            fs.rename_file(Path::new("/etc/other"), p)
        }),
        ("remove_file", |fs, p| fs.remove_file(p)),
        ("remove_directory", |fs, p| fs.remove_directory(p)),
        ("remove_dir_all", |fs, p| fs.remove_dir_all(p)),
        ("secure_delete", |fs, p| fs.secure_delete(p)),
        ("secure_delete_dir_all", |fs, p| fs.secure_delete_dir_all(p)),
        ("copy_tree from", |fs, p| {
            fs.copy_tree(p, Path::new("/etc/other"))
        }),
        ("copy_tree to", |fs, p| {
            fs.copy_tree(Path::new("/etc/other"), p)
        }),
        ("copy_file from", |fs, p| {
            fs.copy_file(p, Path::new("/etc/other"))
        }),
        ("copy_file to", |fs, p| {
            fs.copy_file(Path::new("/etc/other"), p)
        }),
    ]
}

/// The calls that only resolve their path.
fn resolving_calls() -> Vec<(&'static str, Call)> {
    vec![
        ("canonicalize", |fs, p| fs.canonicalize(p).map(drop)),
        ("read_link", |fs, p| match fs.read_link(p) {
            // The answer at a point: no link.
            Err(error) if error.io_kind() == Some(ErrorKind::InvalidInput) => Ok(()),
            other => other.map(drop),
        }),
        ("mount_root", |fs, p| fs.mount_root(p).map(drop)),
        ("resolve_in_root", |fs, p| {
            fs.resolve_in_root(Path::new("/"), p)
                .map(drop)
                .ok_or_else(|| NailsError::io(p, std::io::Error::other("unresolved")))
        }),
    ]
}

/// The mount queries, which resolve their path and read the table.
fn querying_calls() -> Vec<(&'static str, Call)> {
    vec![
        ("is_mounted", |fs, p| fs.is_mounted(p).map(drop)),
        ("get_filesystem_type", |fs, p| {
            fs.get_filesystem_type(p).map(drop)
        }),
        ("is_mount_read_only", |fs, p| {
            fs.is_mount_read_only(p).map(drop)
        }),
        ("mount_source", |fs, p| fs.mount_source(p).map(drop)),
    ]
}

/// Whether `result` is a skip of a lookup that would mount `/usr/local`.
fn skipped_at_usr_local(result: &crate::Result<()>) -> bool {
    matches!(
        result.as_ref().map_err(NailsError::not_looked_up),
        Err(Some((_, Skip::Automount { point }))) if point == Path::new("/usr/local")
    )
}

#[test]
fn every_call_that_reads_or_writes_a_path_is_guarded_as_one_that_enters_it() {
    for (name, call) in entering_calls() {
        let fs = mock(&[ROOT, USR_LOCAL]);
        let view = guarded(&fs);
        // A direct point at the end, and a path below it: not made, kept
        // once in the ledger, and nothing looked up there.
        for (n, path) in ["/usr/local", "/usr/local/lib/x"].into_iter().enumerate() {
            let result = call(&view, Path::new(path));
            assert!(skipped_at_usr_local(&result), "{name} {path}: {result:?}");
            assert_eq!(view.skipped().len(), n + 1, "{name} {path}");
            // A call below a root it is given asks about the path it makes.
            assert!(view.skipped()[n].path.starts_with(path), "{name}");
        }
        assert!(!reaches(&fs, "/usr/local"), "{name}");
        assert!(fs.mock_written_paths().is_empty(), "{name}");

        // Elsewhere the call is made.
        let result = call(&view, Path::new("/etc/x"));
        assert!(
            !matches!(&result, Err(error) if error.not_looked_up().is_some()),
            "{name}: {result:?}"
        );
        assert_eq!(view.skipped().len(), 2, "{name}");
    }
}

/// The calls that read what is at their path and read a link there itself:
/// they never follow it.
const READ_THE_LINK: [&str; 5] = [
    "is_symlink",
    "entry_exists",
    "is_overlay_whiteout",
    "record_lock_holder",
    "change_time",
];

/// A mock with a direct automount point at `/usr/local` that nothing is
/// mounted on, a link `/opt/l` to a path below it and a link `/opt/m` to the
/// point itself.
fn links_to_usr_local() -> MockFilesystem {
    let fs = mock(&[ROOT, USR_LOCAL]);
    link(&fs, "/opt/l", "/usr/local/x");
    link(&fs, "/opt/m", "/usr/local");
    fs
}

/// A call that follows a link at the end of its path asks about where the
/// link leads, so it is not made where that is behind an automount point.
/// One that reads the link itself is made. Neither looks anything up behind
/// the point.
#[test]
fn every_call_that_follows_a_link_at_the_end_is_not_made_where_it_leads_behind_a_point() {
    for (name, call) in entering_calls() {
        let fs = links_to_usr_local();
        let view = guarded(&fs);
        for (n, path) in ["/opt/l", "/opt/m"].into_iter().enumerate() {
            let result = call(&view, Path::new(path));
            if READ_THE_LINK.contains(&name) {
                assert!(
                    !matches!(&result, Err(error) if error.not_looked_up().is_some()),
                    "{name} {path}: {result:?}"
                );
                assert!(view.skipped().is_empty(), "{name} {path}");
            } else {
                assert!(skipped_at_usr_local(&result), "{name} {path}: {result:?}");
                assert_eq!(view.skipped().len(), n + 1, "{name} {path}");
            }
        }
        assert!(!reaches(&fs, "/usr/local"), "{name}");
        assert!(fs.mock_written_paths().is_empty(), "{name}");
    }
}

/// A call that resolves a link at the end of its path follows it where it
/// follows one, as `realpath` does: below a point it is not made, at a
/// direct point it is answered with the point. `read_link` and `mount_root`
/// read the link itself and are made. Nothing is looked up behind the point.
#[test]
fn every_call_that_resolves_a_link_at_the_end_follows_it_only_where_it_follows_one() {
    for (name, call) in resolving_calls() {
        let fs = links_to_usr_local();
        let view = guarded(&fs);
        let below = call(&view, Path::new("/opt/l"));
        let at = call(&view, Path::new("/opt/m"));
        match name {
            "read_link" | "mount_root" => {
                assert!(below.is_ok() && at.is_ok(), "{name}: {below:?} {at:?}");
                assert!(view.skipped().is_empty(), "{name}");
            }
            _ => {
                if name == "resolve_in_root" {
                    // It answers none, and the ledger keeps why.
                    assert!(below.is_err(), "{name}: {below:?}");
                } else {
                    assert!(skipped_at_usr_local(&below), "{name}: {below:?}");
                }
                assert!(at.is_ok(), "{name}: {at:?}");
                assert_eq!(
                    view.skipped(),
                    [Skipped {
                        path: PathBuf::from("/opt/l"),
                        reason: Skip::Automount {
                            point: PathBuf::from("/usr/local")
                        }
                    }],
                    "{name}"
                );
            }
        }
        assert!(!reaches(&fs, "/usr/local"), "{name}");
    }
    let fs = links_to_usr_local();
    let view = guarded(&fs);
    let point = PathBuf::from("/usr/local");
    assert_eq!(view.canonicalize(Path::new("/opt/m")).unwrap(), point);
    assert_eq!(
        view.resolve_in_root(Path::new("/"), Path::new("/opt/m")),
        Some(point)
    );
    assert_eq!(
        view.read_link(Path::new("/opt/l")).unwrap(),
        Path::new("/usr/local/x")
    );
    assert_eq!(
        view.mount_root(Path::new("/opt/m")).unwrap(),
        MountRoot::Link
    );
}

/// How often each of `paths` was looked up on `fs`.
fn looked_up(fs: &MockFilesystem, paths: &[&str]) -> Vec<usize> {
    let lookups = fs.mock_lookups();
    paths
        .iter()
        .map(|path| {
            lookups
                .iter()
                .filter(|asked| *asked == Path::new(path))
                .count()
        })
        .collect()
}

/// A remembering view reads each place on the way once, and where a link
/// there leads, and keeps the snapshot and the ledger of the view it was
/// made from: a lookup that would mount a point is still not made. A view
/// made with `new` reads each place each time.
#[test]
fn a_remembering_view_reads_each_place_on_the_way_once() {
    let fs = mock(&[ROOT, USR_LOCAL]);
    link(&fs, "/opt/l", "/usr/local/x");
    let view = guarded(&fs);
    let walk = view.remembering();
    for path in ["/etc/a/x", "/etc/a/y", "/etc/a/z"] {
        assert!(!walk.path_exists(Path::new(path)).unwrap(), "{path}");
    }
    // The guard's read of each path, then the lookup itself.
    assert_eq!(
        looked_up(&fs, &["/etc", "/etc/a", "/etc/a/x"]),
        [1, 1, 2],
        "{:?}",
        fs.mock_lookups()
    );
    for _ in 0..2 {
        let result = walk.path_exists(Path::new("/opt/l/y")).map(drop);
        assert!(skipped_at_usr_local(&result), "{result:?}");
    }
    // What the link is, and where it leads.
    assert_eq!(looked_up(&fs, &["/opt/l"]), [2], "{:?}", fs.mock_lookups());
    assert!(!reaches(&fs, "/usr/local"));
    assert_eq!(view.skipped().len(), 2);

    fs.mock_clear_lookups();
    for path in ["/etc/a/x", "/etc/a/y"] {
        assert!(!view.path_exists(Path::new(path)).unwrap(), "{path}");
    }
    assert_eq!(looked_up(&fs, &["/etc", "/etc/a"]), [2, 2]);
}

#[test]
fn a_call_that_reads_a_path_reaches_the_filesystem_once_it_is_asked() {
    let fs = mock(&[ROOT, USR_LOCAL]);
    fs.mock_add_file("/etc/x", "text");
    let view = guarded(&fs);
    assert!(view.path_exists(Path::new("/etc/x")).unwrap());
    assert_eq!(view.read_file_content(Path::new("/etc/x")).unwrap(), "text");
    view.write_file_content(Path::new("/etc/y"), "new").unwrap();
    assert_eq!(fs.mock_written_paths(), vec![PathBuf::from("/etc/y")]);
    // The guard read the way, and then the lookup was made.
    let lookups = fs.mock_lookups();
    let at = |path: &str| {
        lookups
            .iter()
            .filter(|asked| *asked == Path::new(path))
            .count()
    };
    assert_eq!(at("/etc"), 3, "{lookups:?}");
    assert_eq!(at("/etc/x"), 4, "{lookups:?}");
}

#[test]
fn every_call_that_resolves_a_path_is_answered_at_a_point_and_skipped_below_it() {
    for (name, call) in resolving_calls() {
        let fs = mock(&[ROOT, USR_LOCAL, NET_MAP]);
        let view = guarded(&fs);
        assert!(call(&view, Path::new("/usr/local")).is_ok(), "{name}");
        assert!(view.skipped().is_empty(), "{name}");
        assert!(!reaches(&fs, "/usr/local"), "{name}");
        for path in ["/usr/local/bin", "/net/srv"] {
            let result = call(&view, Path::new(path));
            if name == "resolve_in_root" {
                // It cannot fail: it reads nothing through the path.
                assert!(result.is_err(), "{name} {path}");
            } else {
                assert!(
                    matches!(&result, Err(error) if error.not_looked_up().is_some()),
                    "{name} {path}: {result:?}"
                );
            }
        }
        assert_eq!(view.skipped().len(), 2, "{name}");
        assert!(!reaches(&fs, "/usr/local"), "{name}");
        assert!(!reaches(&fs, "/net/srv"), "{name}");
        // Elsewhere the call is made.
        let _ = call(&view, Path::new("/etc/x"));
        assert!(
            fs.mock_lookups().contains(&PathBuf::from("/etc/x")),
            "{name}"
        );
    }
}

#[test]
fn a_mount_query_is_made_unless_resolving_its_path_would_mount() {
    for (name, call) in querying_calls() {
        let fs = mock(&[ROOT, USR_LOCAL]);
        fs.mock_set_lookup_error("/locked", ErrorKind::PermissionDenied);
        let view = guarded(&fs);
        assert!(call(&view, Path::new("/usr/local")).is_ok(), "{name}");
        // A path it cannot resolve is queried as it is named.
        assert!(call(&view, Path::new("/locked/x")).is_ok(), "{name}");
        assert!(view.skipped().is_empty(), "{name}");
        let result = call(&view, Path::new("/usr/local/bin"));
        assert!(skipped_at_usr_local(&result), "{name}: {result:?}");
        assert_eq!(view.skipped().len(), 1, "{name}");
    }
    // A link at the end is resolved as the query resolves it: where it
    // leads behind a point the query is not made, at a direct point it is.
    for (name, call) in querying_calls() {
        let fs = links_to_usr_local();
        let view = guarded(&fs);
        let result = call(&view, Path::new("/opt/l"));
        assert!(skipped_at_usr_local(&result), "{name}: {result:?}");
        assert!(call(&view, Path::new("/opt/m")).is_ok(), "{name}");
        assert_eq!(view.skipped().len(), 1, "{name}");
        assert!(!reaches(&fs, "/usr/local"), "{name}");
    }
    let fs = mock(&[ROOT, USR_LOCAL]);
    let view = guarded(&fs);
    assert!(view.is_mounted(Path::new("/usr/local")).unwrap());
    assert_eq!(
        view.get_filesystem_type(Path::new("/usr/local")).unwrap(),
        Some("autofs".to_string())
    );
    assert!(view.nails_process_matches().unwrap().is_empty());
}

#[test]
fn a_walk_or_a_read_below_another_root_is_not_made_where_something_is_guarded() {
    let fs = mock(&[ROOT]);
    let view = guarded(&fs);
    for result in [
        view.find_files_with_pattern(Path::new("/var/log"), "nails")
            .map(drop),
        view.scan_files_with_pattern(Path::new("/var/log"), "nails")
            .map(drop),
        view.read_file_in_root(Path::new("/mnt/image"), Path::new("/etc/fstab"))
            .map(drop),
    ] {
        let error = result.unwrap_err();
        assert_eq!(error.io_kind(), Some(ErrorKind::Unsupported), "{error}");
    }
    assert_eq!(
        view.resolve_in_root(Path::new("/mnt/image"), Path::new("/etc/fstab")),
        None
    );
    assert!(fs.mock_lookups().is_empty());
    // Without the table they are not made either, as nothing is.
    let fs = MockFilesystem::new();
    fs.mock_set_mount_table_error("gone");
    let view = guarded(&fs);
    let error = view
        .find_files_with_pattern(Path::new("/var/log"), "nails")
        .unwrap_err();
    assert!(error.not_looked_up().is_some(), "{error}");
    assert_eq!(
        view.resolve_in_root(Path::new("/mnt/image"), Path::new("/etc/fstab")),
        None
    );
    assert!(fs.mock_lookups().is_empty());
}

#[test]
fn the_views_of_one_snapshot_judge_by_it_and_keep_ledgers_of_their_own() {
    let fs = mock(&[ROOT, USR_LOCAL]);
    let snapshot = Snapshot::read(&fs, Path::new("/"));
    let first = Guarded::new(fs.clone(), &snapshot);
    let second = Guarded::new(fs.clone(), &snapshot);
    // Mounted after the snapshot was read: the views still judge by it.
    fs.mock_set_mount_table(&[ROOT, USR_LOCAL, USR_LOCAL_MOUNTED].concat());
    let path = Path::new("/usr/local/bin/nix");
    assert!(first.path_exists(path).is_err());
    assert_eq!(first.skipped().len(), 1);
    assert!(second.skipped().is_empty());
    assert!(second.is_symlink(path).is_err());
    assert_eq!(second.skipped().len(), 1);
    assert_eq!(
        first.mount_table().unwrap(),
        parse_mountinfo(&[ROOT, USR_LOCAL].concat())
    );
    // A clone is the same view, with the same ledger.
    let clone = first.clone();
    assert!(clone.inode(path).is_err());
    assert_eq!(first.skipped().len(), 2);
    assert_eq!(
        first.skipped()[0],
        Skipped {
            path: path.to_path_buf(),
            reason: Skip::Automount {
                point: PathBuf::from("/usr/local")
            }
        }
    );
    // A lookup asked of the view directly is kept as well.
    assert!(first.ask(path, ENTERS).is_err());
    assert_eq!(first.skipped().len(), 3);
    assert_eq!(
        first.ask(Path::new("/usr/local"), RESOLVES).unwrap(),
        Some(PathBuf::from("/usr/local"))
    );
    assert_eq!(first.ask(Path::new("/etc"), ENTERS).unwrap(), None);
    assert_eq!(first.skipped().len(), 3);
}

/// What `fix` says for the points named.
fn fix(points: &[&str]) -> String {
    let paths: Vec<&Path> = points.iter().map(Path::new).collect();
    mount_fix(&paths)
}

/// A skip of `path` behind `point`.
fn skip(path: &str, point: &str) -> Skipped {
    Skipped {
        path: PathBuf::from(path),
        reason: Skip::Automount {
            point: PathBuf::from(point),
        },
    }
}

#[test]
fn the_fix_mounts_each_point_and_runs_the_check_again() {
    let check = sudo_line(NextStep::Check);
    assert_eq!(
        fix(&["/usr/local"]),
        format!("Mount /usr/local (for example `ls /usr/local`) and run `{check}` again.")
    );
    assert_eq!(
        fix(&["/usr/local", "/home/carol", "/srv/my share"]),
        format!(
            "Mount /usr/local, /home/carol and /srv/my share (for example `ls /usr/local \
             /home/carol '/srv/my share'`) and run `{check}` again."
        )
    );
}

#[test]
fn a_check_with_nothing_skipped_or_a_skipped_check_settles_as_it_is() {
    let pass = CheckResult::Pass("no trace".to_string());
    assert_eq!(settle(pass.clone(), &[], OnSkip::Warn), pass);
    let skipped = CheckResult::skipped("inside a hidden session");
    assert_eq!(
        settle(
            skipped.clone(),
            &[skip("/usr/local/x", "/usr/local")],
            OnSkip::Warn
        ),
        skipped
    );
}

#[test]
fn a_pass_with_a_lookup_not_made_warns_or_refuses() {
    let ledger = [
        skip("/usr/local/bin/nix", "/usr/local"),
        skip("/usr/local/etc/nix", "/usr/local"),
        skip("/home/bob/.profile", "/home/bob"),
    ];
    let told = "NAILS cannot tell about everything it checks: NAILS does not look up \
                /usr/local/bin/nix, since the lookup would mount the automount point \
                /usr/local; NAILS does not look up /home/bob/.profile, since the lookup would \
                mount the automount point /home/bob.\nWhere it could look: no trace";
    let pass = CheckResult::Pass("no trace".to_string());
    assert_eq!(
        settle(pass.clone(), &ledger, OnSkip::Warn),
        CheckResult::Warn(format!("{told}\n{}", fix(&["/usr/local", "/home/bob"])))
    );
    assert_eq!(
        settle(
            pass,
            &ledger,
            OnSkip::Refuse(Some(Allowable::PersistentDecoy))
        ),
        CheckResult::Fail {
            message: told.to_string(),
            remediation: Some(fix(&["/usr/local", "/home/bob"])),
            allowable: Some(Allowable::PersistentDecoy),
        }
    );
}

#[test]
fn a_point_the_result_names_is_not_named_twice() {
    let ledger = [skip("/home/bob/.profile", "/home/bob"), skip("/x/y", "/x")];
    // The warning names /home/bob, but neither /home nor /x as a point.
    let warning = "NAILS cannot tell: NAILS does not look into /home/bob, since the lookup \
                   would mount the automount point /home/bob.\nSee the docs.";
    assert_eq!(
        settle(
            CheckResult::Warn(warning.to_string()),
            &ledger,
            OnSkip::Warn
        ),
        CheckResult::Warn(format!(
            "{warning}\nNAILS cannot tell about everything it checks: NAILS does not look up \
             /x/y, since the lookup would mount the automount point /x.\n{}",
            fix(&["/home/bob", "/x"])
        ))
    );
    // A longer path that begins with the point does not name it.
    assert!(!names_point(
        "the automount point /home/bobby",
        Path::new("/home/bob")
    ));
    assert!(!names_point("the automount point /x.d", Path::new("/x")));
    for named in [
        "the automount point /x",
        "the automount point /x.",
        "the automount point /x. Then",
        "the automount point /x; and",
        "(the automount point /x)",
    ] {
        assert!(names_point(named, Path::new("/x")), "{named}");
    }
}

#[test]
fn a_refusing_part_turns_a_warning_into_a_refusal_and_keeps_only_a_shared_override() {
    let ledger = [skip("/usr/local/lib/systemd/journald.conf.d", "/usr/local")];
    let named = "NAILS does not look up /usr/local/lib/systemd/journald.conf.d, since the \
                 lookup would mount the automount point /usr/local";
    assert_eq!(
        settle(
            CheckResult::Warn(format!("{named}.")),
            &ledger,
            OnSkip::Refuse(None)
        ),
        CheckResult::Fail {
            message: format!("{named}."),
            remediation: Some(fix(&["/usr/local"])),
            allowable: None,
        }
    );
    let refusal = |allowable| CheckResult::Fail {
        message: format!("{named}."),
        remediation: Some("Set Storage=volatile.".to_string()),
        allowable,
    };
    let lifts = Some(Allowable::PersistentDecoy);
    for (allowable, on_skip, kept) in [
        (lifts, OnSkip::Refuse(lifts), lifts),
        (lifts, OnSkip::Refuse(None), None),
        (None, OnSkip::Refuse(lifts), None),
        (lifts, OnSkip::Refuse(Some(Allowable::Discards)), None),
        (lifts, OnSkip::Warn, lifts),
    ] {
        assert_eq!(
            settle(refusal(allowable), &ledger, on_skip),
            CheckResult::Fail {
                message: format!("{named}."),
                remediation: Some(format!("Set Storage=volatile.\n{}", fix(&["/usr/local"]))),
                allowable: kept,
            },
            "{allowable:?} {on_skip:?}"
        );
    }
    let unfixed = CheckResult::Fail {
        message: "refused".to_string(),
        remediation: None,
        allowable: None,
    };
    assert_eq!(
        settle(unfixed, &ledger, OnSkip::Refuse(None)).remediation(),
        Some(fix(&["/usr/local"]).as_str())
    );
}

/// A check that words a lookup it did not make itself gives the fix for it:
/// `settle` does not give it a second time, and gives it for the other
/// points only.
#[test]
fn a_fix_the_result_gives_already_is_not_given_again() {
    let ledger = [
        skip("/usr/local/flake", "/usr/local"),
        skip("/srv/other", "/srv"),
    ];
    let own = CheckResult::fail_with(
        "NAILS does not look up /usr/local/flake, since the lookup would mount the automount \
         point /usr/local",
        fix(&["/usr/local"]),
    );
    assert_eq!(
        settle(own, &ledger, OnSkip::Refuse(None)).remediation(),
        Some(format!("{}\n{}", fix(&["/usr/local"]), fix(&["/srv"])).as_str())
    );
    let warned = CheckResult::Warn(format!("one warning\n{}", fix(&["/usr/local"])));
    let settled = settle(warned, &ledger[..1], OnSkip::Warn);
    assert_eq!(
        settled.message().matches("Mount /usr/local").count(),
        1,
        "{settled:?}"
    );
}

/// What a probe that keeps no check result adds for the lookups its view
/// did not make: each point once, by its first path, and none its text
/// names already.
#[test]
fn unnamed_gives_each_point_once_that_the_text_does_not_name() {
    let ledger = [
        skip("/usr/local/lib/systemd", "/usr/local"),
        skip("/usr/local/bin/updatedb", "/usr/local"),
        skip("/srv/data", "/srv"),
    ];
    assert_eq!(
        unnamed("nothing named", &ledger),
        vec![
            "NAILS does not look up /usr/local/lib/systemd, since the lookup would mount the \
             automount point /usr/local"
                .to_string(),
            "NAILS does not look up /srv/data, since the lookup would mount the automount point \
             /srv"
                .to_string(),
        ]
    );
    assert_eq!(
        unnamed("... the automount point /srv: so", &ledger),
        vec![
            "NAILS does not look up /usr/local/lib/systemd, since the lookup would mount the \
             automount point /usr/local"
                .to_string()
        ]
    );
    assert_eq!(unnamed("anything", &[]), Vec::<String>::new());
}

/// What a check that keeps its result says of its ledger: the sentence a
/// pass would get, each point once, and the fix for the points; nothing for
/// an empty ledger, and no mount fix for the mount table alone.
#[test]
fn a_note_names_each_point_once_with_its_fix() {
    assert_eq!(note(&[]), None);
    let ledger = [
        skip("/boot/config-6.8", "/boot"),
        skip("/boot/efi", "/boot"),
        skip("/srv/x", "/srv"),
    ];
    assert_eq!(
        note(&ledger),
        Some(format!(
            "NAILS cannot tell about everything it checks: NAILS does not look up \
             /boot/config-6.8, since the lookup would mount the automount point /boot; NAILS \
             does not look up /srv/x, since the lookup would mount the automount point /srv.\n{}",
            fix(&["/boot", "/srv"])
        ))
    );
    let table = [Skipped {
        path: PathBuf::from("/boot/config-6.8"),
        reason: Skip::NoMountTable {
            error: "gone".to_string(),
        },
    }];
    assert_eq!(
        note(&table),
        Some(
            "NAILS cannot tell about everything it checks: NAILS does not look up \
             /boot/config-6.8, since it cannot read the mount table (gone), which shows where a \
             lookup would mount an automount point."
                .to_string()
        )
    );
}

#[test]
fn an_unreadable_mount_table_is_named_once_and_has_no_mount_fix() {
    let reason = Skip::NoMountTable {
        error: "/proc/self/mountinfo: gone".to_string(),
    };
    let ledger = [
        Skipped {
            path: PathBuf::from("/etc/passwd"),
            reason: reason.clone(),
        },
        Skipped {
            path: PathBuf::from("/etc/group"),
            reason,
        },
    ];
    assert_eq!(
        settle(CheckResult::Pass("fine".to_string()), &ledger, OnSkip::Warn),
        CheckResult::Warn(
            "NAILS cannot tell about everything it checks: NAILS does not look up /etc/passwd, \
             since it cannot read the mount table (/proc/self/mountinfo: gone), which shows \
             where a lookup would mount an automount point.\nWhere it could look: fine"
                .to_string()
        )
    );
    let said = "NAILS cannot read the mount table (gone), so it looks up nothing";
    assert_eq!(
        settle(CheckResult::Warn(said.to_string()), &ledger, OnSkip::Warn),
        CheckResult::Warn(said.to_string())
    );
}

#[test]
fn a_lookup_not_made_is_described_with_its_point_and_its_fix() {
    let skipped = NailsError::NotLookedUp {
        path: PathBuf::from("/usr/local/bin/updatedb"),
        reason: Skip::Automount {
            point: PathBuf::from("/usr/local"),
        },
    };
    assert_eq!(
        describe("/usr/local/bin/updatedb", &skipped),
        Unseen {
            sentence: "NAILS does not look up /usr/local/bin/updatedb, since the lookup would \
                       mount the automount point /usr/local"
                .to_string(),
            fix: Some(fix(&["/usr/local"])),
            automount_point: Some(PathBuf::from("/usr/local")),
        }
    );
    // The check names the path as the decoy names it.
    assert!(
        describe("/bin/updatedb", &skipped)
            .sentence
            .starts_with("NAILS does not look up /bin/updatedb,")
    );
    let unread = NailsError::NotLookedUp {
        path: PathBuf::from("/etc/passwd"),
        reason: Skip::NoMountTable {
            error: "gone".to_string(),
        },
    };
    let described = describe("/etc/passwd", &unread);
    assert_eq!(described.fix, None);
    assert_eq!(described.automount_point, None);
    assert!(
        described
            .sentence
            .contains("cannot read the mount table (gone)")
    );

    let denied = NailsError::io(
        "/home/carol/.profile",
        std::io::Error::from(ErrorKind::PermissionDenied),
    );
    assert_eq!(
        describe("/home/carol/.profile", &denied),
        Unseen {
            sentence: "NAILS cannot look up /home/carol/.profile; run the command again with sudo"
                .to_string(),
            fix: None,
            automount_point: None,
        }
    );
    let failed = NailsError::io("/srv/x", std::io::Error::from_raw_os_error(nix::libc::EIO));
    assert_eq!(
        describe("/srv/x", &failed).sentence,
        format!("NAILS cannot look up /srv/x ({failed})")
    );
}

#[test]
fn a_lookup_not_made_is_an_error_of_its_own_with_the_fix_as_its_hint() {
    let skipped = NailsError::NotLookedUp {
        path: PathBuf::from("/home/bob/.profile"),
        reason: Skip::Automount {
            point: PathBuf::from("/home/bob"),
        },
    };
    assert_eq!(
        skipped.to_string(),
        "NAILS does not look up /home/bob/.profile, since the lookup would mount the automount \
         point /home/bob"
    );
    assert_eq!(skipped.io_kind(), None);
    assert_eq!(skipped.hint(), Some(fix(&["/home/bob"])));
    let unread = NailsError::NotLookedUp {
        path: PathBuf::from("/etc/passwd"),
        reason: Skip::NoMountTable {
            error: "gone".to_string(),
        },
    };
    assert_eq!(unread.hint(), None);
    assert_eq!(
        unread
            .not_looked_up()
            .map(|(path, reason)| (path, reason.point())),
        Some((Path::new("/etc/passwd"), None))
    );
    assert_eq!(NailsError::Cancelled.not_looked_up(), None);
}
