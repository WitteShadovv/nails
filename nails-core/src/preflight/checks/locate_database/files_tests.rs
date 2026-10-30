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
