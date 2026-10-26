// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The `package-drift` row against the root overlay the entry mounts: what a
//! hidden session's package manager changes through it lands in the upper,
//! the decoy's later changes show in the next root as the row says, the row
//! tells them from the hidden session's own, and its reads leave the decoy's
//! access times alone.

use nails_core::RealFilesystem;
use nails_core::preflight::PreFlightCheck;
use nails_core::session::package_drift::PackageDriftCheck;
use nails_core::test_path;
use nails_core::test_support::{Rerun, ScratchTmpfs};
use nails_teardown::whole_root::nextroot;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

const STATUS: &str = "var/lib/dpkg/status";
const INFO: &str = "var/lib/dpkg/info";
const LOCAL: &str = "var/lib/pacman/local";

/// A dpkg status file of `packages` (name, version), each installed.
fn status(packages: &[(&str, &str)]) -> String {
    packages
        .iter()
        .map(|(name, version)| {
            format!(
                "Package: {name}\nStatus: install ok installed\nArchitecture: amd64\n\
                 Version: {version}\nDescription: {name}\n a package\n"
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Write dpkg's record as dpkg does: a new file renamed over the old one.
fn write_status(root: &Path, packages: &[(&str, &str)]) {
    let new = root.join(format!("{STATUS}-new"));
    std::fs::write(&new, status(packages)).unwrap();
    std::fs::rename(&new, root.join(STATUS)).unwrap();
}

/// Add pacman's entry `entry` below `root`.
fn add_entry(root: &Path, entry: &str) {
    let dir = root.join(LOCAL).join(entry);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("desc"), format!("%NAME%\n{entry}\n")).unwrap();
}

/// Delete pacman's entry `entry` below `root`.
fn remove_entry(root: &Path, entry: &str) {
    std::fs::remove_dir_all(root.join(LOCAL).join(entry)).unwrap();
}

/// A decoy root on a tmpfs that updates an access time at every read, with
/// dpkg's record and pacman's database.
fn decoy() -> ScratchTmpfs {
    let decoy = ScratchTmpfs::strictatime();
    decoy.mkdir(INFO);
    write_status(
        decoy.path(),
        &[("libc6", "2.41-12"), ("openssh-client", "1:10.0p1-7")],
    );
    for name in ["libc6:amd64.list", "openssh-client.list"] {
        std::fs::write(decoy.path().join(INFO).join(name), "/usr\n").unwrap();
    }
    for entry in ["firefox-131.0-1", "linux-6.17.1.arch1-1"] {
        add_entry(decoy.path(), entry);
    }
    decoy
}

/// A hidden volume with the root overlay's upper and work directories.
fn hidden() -> ScratchTmpfs {
    let hidden = ScratchTmpfs::new("");
    hidden.mkdir("root/upper");
    hidden.mkdir("root/work");
    hidden
}

/// Mount the root overlay over `decoy` with `hidden`'s upper, as the entry
/// does, hand `f` the next root, and detach it again.
fn in_next_root(decoy: &Path, hidden: &Path, f: impl FnOnce(&Path)) {
    let next = hidden.join("next");
    std::fs::create_dir_all(&next).unwrap();
    nextroot::overlay_over(
        decoy,
        &hidden.join("lower"),
        &hidden.join("root/upper"),
        &hidden.join("root/work"),
        &next,
    )
    .expect("the root overlay");
    f(&next);
    nextroot::detach_tree(&next);
}

/// Write the whiteout overlayfs keeps for a deleted `rel` straight into the
/// upper: the kernel deletes no directory through an overlay without the
/// `trusted.*` attributes a namespace lacks.
fn whiteout(upper: &Path, rel: &str) {
    use nix::sys::stat::{Mode, SFlag, mknod};
    mknod(
        &upper.join(rel),
        SFlag::S_IFCHR,
        Mode::from_bits_truncate(0o600),
        0,
    )
    .expect("a whiteout");
}

fn atime(path: &Path) -> (i64, i64) {
    let meta = std::fs::metadata(path).unwrap();
    (meta.atime(), meta.atime_nsec())
}

/// A hidden session installs tor with each package manager and updates
/// firefox and removes linux with pacman; the decoy then updates libc6,
/// firefox and linux. The row names the decoy's changes the hidden session's
/// copies do not follow, and not tor; the next root shows what it names; and
/// reading leaves the decoy's access times as they were.
#[test]
fn the_row_names_the_decoys_changes_the_hidden_copies_do_not_follow() {
    let _ = Rerun::new(test_path!(
        the_row_names_the_decoys_changes_the_hidden_copies_do_not_follow
    ))
    .in_user_mount_ns()
    .run(|| {
        let decoy = decoy();
        let hidden = hidden();
        let upper = hidden.path().join("root/upper");

        in_next_root(decoy.path(), hidden.path(), |next| {
            write_status(
                next,
                &[
                    ("libc6", "2.41-12"),
                    ("openssh-client", "1:10.0p1-7"),
                    ("tor", "0.4.8.17-1"),
                ],
            );
            std::fs::write(next.join(INFO).join("tor.list"), "/usr/bin/tor\n").unwrap();
            add_entry(next, "tor-0.4.8.17-1");
            add_entry(next, "firefox-132.0-1");
        });
        assert!(upper.join(STATUS).is_file(), "the copy of the record");
        whiteout(&upper, &format!("{LOCAL}/firefox-131.0-1"));
        whiteout(&upper, &format!("{LOCAL}/linux-6.17.1.arch1-1"));

        // The decoy updates afterwards, as dpkg and pacman do.
        write_status(
            decoy.path(),
            &[("libc6", "2.41-13"), ("openssh-client", "1:10.0p1-7")],
        );
        std::fs::write(decoy.path().join(INFO).join("libc6:amd64.list"), "/usr\n").unwrap();
        remove_entry(decoy.path(), "firefox-131.0-1");
        add_entry(decoy.path(), "firefox-133.0-1");
        remove_entry(decoy.path(), "linux-6.17.1.arch1-1");
        add_entry(decoy.path(), "linux-6.18.0.arch1-1");

        let read = [decoy.path().join(STATUS), decoy.path().join(LOCAL)];
        let before: Vec<_> = read.iter().map(|path| atime(path)).collect();
        let check = PackageDriftCheck::new(decoy.path().to_path_buf(), hidden.path().to_path_buf())
            .as_privileged(true);
        let result = PreFlightCheck::<RealFilesystem>::run(&check, &RealFilesystem).unwrap();
        let after: Vec<_> = read.iter().map(|path| atime(path)).collect();
        assert_eq!(
            after, before,
            "the row reads without changing an access time"
        );

        assert!(result.is_warn(), "{result:?}");
        let message = result.message();
        for named in [
            "libc6 (2.41-13 on the decoy, 2.41-12 in hidden sessions)",
            "firefox (133.0-1 on the decoy, 132.0-1 in hidden sessions)",
            "linux (6.18.0.arch1-1 on the decoy, not in hidden sessions)",
        ] {
            assert!(message.contains(named), "{named}: {message}");
        }
        assert!(
            !message.contains("tor ("),
            "the hidden session's own: {message}"
        );
        assert!(
            !message.contains("openssh-client ("),
            "unchanged: {message}"
        );

        // The next root is what the row says: the old record, firefox twice,
        // linux listed although the hidden session removed it.
        in_next_root(decoy.path(), hidden.path(), |next| {
            let record = std::fs::read_to_string(next.join(STATUS)).unwrap();
            assert!(record.contains("Version: 2.41-12"), "{record}");
            let mut entries: Vec<String> = std::fs::read_dir(next.join(LOCAL))
                .unwrap()
                .map(|entry| entry.unwrap().file_name().into_string().unwrap())
                .collect();
            entries.sort();
            assert_eq!(
                entries,
                [
                    "firefox-132.0-1",
                    "firefox-133.0-1",
                    "linux-6.18.0.arch1-1",
                    "tor-0.4.8.17-1",
                ]
            );
        });
    });
}

/// Hidden sessions that never changed a package database keep no copy of
/// it, and the row passes without reading the decoy's database, so even a
/// check that is not running as root can tell.
#[test]
fn without_a_copy_the_row_passes_even_without_root() {
    let _ = Rerun::new(test_path!(without_a_copy_the_row_passes_even_without_root))
        .in_user_mount_ns()
        .run(|| {
            let decoy = decoy();
            let hidden = hidden();
            in_next_root(decoy.path(), hidden.path(), |next| {
                std::fs::write(next.join("etc-hostname"), "hidden\n").unwrap();
            });
            let check =
                PackageDriftCheck::new(decoy.path().to_path_buf(), hidden.path().to_path_buf())
                    .as_privileged(false);
            let result = PreFlightCheck::<RealFilesystem>::run(&check, &RealFilesystem).unwrap();
            assert!(result.is_pass(), "{result:?}");
            assert_eq!(
                result.message(),
                "hidden sessions see the decoy's own dpkg package database (/var/lib/dpkg/status); \
             hidden sessions see the decoy's own pacman package database \
             (/var/lib/pacman/local)"
            );
        });
}
