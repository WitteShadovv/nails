// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::RealFilesystem;
use crate::filesystem::{MockFilesystem, PathKind};

fn read_mock(fs: &MockFilesystem, path: &str) -> DecoyFile {
    let hidden = [PathBuf::from("/mnt/data")];
    DecoyFiles::new(fs, Path::new("/"), &hidden).read(Path::new(path))
}

#[test]
fn a_file_of_up_to_one_mib_is_read() {
    let fs = MockFilesystem::new();
    fs.mock_add_file("/etc/x", "x");
    fs.mock_set_file_size("/etc/x", MAX_FILE_BYTES);
    assert_eq!(read_mock(&fs, "/etc/x"), DecoyFile::Text(b"x".to_vec()));
    let larger = DecoyFile::Unread("/etc/x is larger than 1 MiB".to_string());
    fs.mock_set_file_size("/etc/x", MAX_FILE_BYTES + 1);
    assert_eq!(read_mock(&fs, "/etc/x"), larger);
    // One that grew past it between the look and the read is not read
    // either.
    let grown = "x".repeat(usize::try_from(MAX_FILE_BYTES).unwrap() + 1);
    fs.mock_set_file_content("/etc/x", &grown);
    fs.mock_set_file_size("/etc/x", 1);
    assert_eq!(read_mock(&fs, "/etc/x"), larger);
}

#[test]
fn a_file_gone_before_its_read_is_absent() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_type("/etc/x", PathKind::File);
    assert_eq!(read_mock(&fs, "/etc/x"), DecoyFile::Absent);
}

/// Through the automount guard, a file or a directory behind an automount
/// point that nothing is mounted on yet is neither read nor listed, and
/// says so in the guard's words; once something is mounted there, it is.
#[test]
fn what_lies_behind_an_automount_point_is_not_read_and_says_so() {
    use crate::filesystem::automount::{Guarded, Snapshot};
    let root = "1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n";
    let point = "30 1 0:50 / /usr/local rw,relatime - autofs systemd-1 rw,fd=50,direct\n";
    let fs = MockFilesystem::new();
    fs.mock_add_file("/usr/local/etc/updatedb.conf", "PRUNEFS=\"nfs\"\n");
    fs.mock_set_directory_contents(Path::new("/usr/local/etc"), Vec::new());
    fs.mock_set_mount_table(&format!("{root}{point}"));
    let guarded = Guarded::new(fs.clone(), &Snapshot::read(&fs, Path::new("/")));
    let hidden = [PathBuf::from("/mnt/data")];
    let files = DecoyFiles::new(&guarded, Path::new("/"), &hidden);
    assert_eq!(
        files.read(Path::new("/usr/local/etc/updatedb.conf")),
        DecoyFile::Unread(
            "NAILS does not look up /usr/local/etc/updatedb.conf, since the lookup would mount \
             the automount point /usr/local"
                .to_string()
        )
    );
    assert_eq!(
        files.list(Path::new("/usr/local/etc")),
        Err(
            "NAILS does not look up /usr/local/etc, since the lookup would mount the \
             automount point /usr/local"
                .to_string()
        )
    );
    assert!(
        !fs.mock_lookups()
            .iter()
            .any(|path| path.starts_with("/usr/local"))
    );
    assert_eq!(guarded.skipped().len(), 3);

    let mounted = "31 30 8:3 / /usr/local rw,relatime - ext4 /dev/sda3 rw\n";
    fs.mock_set_mount_table(&format!("{root}{point}{mounted}"));
    let guarded = Guarded::new(fs.clone(), &Snapshot::read(&fs, Path::new("/")));
    let files = DecoyFiles::new(&guarded, Path::new("/"), &hidden);
    assert_eq!(
        files.read(Path::new("/usr/local/etc/updatedb.conf")),
        DecoyFile::Text(b"PRUNEFS=\"nfs\"\n".to_vec())
    );
    assert_eq!(files.list(Path::new("/usr/local/etc")), Ok(Vec::new()));
    assert!(guarded.skipped().is_empty());
}

/// A lookup that fails for another reason than that nothing is there is
/// named by its error, and one NAILS may not make asks for sudo; one that
/// finds nothing there is absent.
#[test]
fn a_lookup_that_fails_is_named_by_its_error() {
    use std::io::ErrorKind;
    let failing = |kind| {
        let fs = MockFilesystem::new();
        fs.mock_add_file("/home/bob/.profile", "x");
        fs.mock_set_lookup_error("/home/bob", kind);
        read_mock(&fs, "/home/bob/.profile")
    };
    assert_eq!(
        failing(ErrorKind::PermissionDenied),
        DecoyFile::Unread(
            "NAILS cannot look up /home/bob/.profile; run the command again with sudo".into()
        )
    );
    assert_eq!(
        failing(ErrorKind::Other),
        DecoyFile::Unread(
            "NAILS cannot follow /home/bob/.profile (/home/bob/.profile: Mock: the lookup fails \
             here)"
                .into()
        )
    );
    assert_eq!(failing(ErrorKind::NotFound), DecoyFile::Absent);
}

/// A lookup that fails after one that succeeded is named as well: a read the
/// automount guard does not make, where a point was set up after the file
/// was seen to be one, gives the guard's reason, and a path that is no
/// regular file whose lookup then fails is named by its error.
#[test]
fn a_lookup_that_fails_after_one_that_succeeded_is_named() {
    use crate::filesystem::{MockFailure, MockLookup};
    let fs = MockFilesystem::new();
    let file = Path::new("/usr/local/etc/updatedb.conf");
    fs.mock_add_file(file.to_str().unwrap(), "x");
    fs.mock_fail_only(
        file,
        MockLookup::Read,
        MockFailure::NotLookedUp(PathBuf::from("/usr/local")),
    );
    assert_eq!(
        read_mock(&fs, file.to_str().unwrap()),
        DecoyFile::Unread(
            "NAILS does not look up /usr/local/etc/updatedb.conf, since the lookup would mount \
             the automount point /usr/local"
                .into()
        )
    );

    let dir = Path::new("/etc/cron.d");
    fs.mock_set_path_type(dir.to_str().unwrap(), PathKind::Dir);
    fs.mock_fail_only(
        dir,
        MockLookup::PathExists,
        MockFailure::Io(std::io::ErrorKind::Other),
    );
    assert_eq!(
        read_mock(&fs, "/etc/cron.d"),
        DecoyFile::Unread(
            "NAILS cannot follow /etc/cron.d (/etc/cron.d: Mock: the lookup fails here)".into()
        )
    );
}

#[test]
fn what_the_system_does_not_show_is_named() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let hidden = [root.join("mnt/data")];
    let files = DecoyFiles::new(&RealFilesystem, &root, &hidden);

    // A link that leads to itself.
    let looped = root.join("loop");
    std::os::unix::fs::symlink(&looped, &looped).unwrap();
    let follow = format!("NAILS cannot follow {} (", looped.display());
    assert!(
        matches!(files.read(&looped), DecoyFile::Unread(why) if why.starts_with(&follow)),
        "{:?}",
        files.read(&looped)
    );

    // A file only root may read, and one in a directory only root may enter.
    let file = root.join("secret");
    std::fs::write(&file, "x").unwrap();
    let dir = root.join("locked");
    std::fs::create_dir(&dir).unwrap();
    let inner = dir.join("inner");
    std::fs::write(&inner, "x").unwrap();
    let set_mode = |path: &Path, mode: u32| {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    };
    set_mode(&file, 0o000);
    set_mode(&dir, 0o000);
    // Root reads both all the same, and then there is nothing to name.
    let privileged = std::fs::read(&file).is_ok();
    let read_file = files.read(&file);
    let read_inner = files.read(&inner);
    set_mode(&dir, 0o755);
    set_mode(&file, 0o644);
    if privileged {
        return;
    }
    assert_eq!(
        read_file,
        DecoyFile::Unread(format!(
            "NAILS cannot read {}; run the command again with sudo",
            file.display()
        ))
    );
    assert_eq!(
        read_inner,
        DecoyFile::Unread(format!(
            "NAILS cannot look up {}; run the command again with sudo",
            inner.display()
        ))
    );
}
