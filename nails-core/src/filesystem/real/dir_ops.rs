// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Directory listing, enumeration, copy, size, and submount operations.

use crate::process::run::COPY_BUDGET;
use crate::process::{ProcessCommand, ProcessRunner, RealProcessRunner};
use crate::{NailsError, Result};
use std::collections::HashSet;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

pub(super) fn list_directory(dir: &Path) -> Result<Vec<PathBuf>> {
    let entries = std::fs::read_dir(dir).map_err(|e| {
        NailsError::IoError(std::io::Error::new(
            e.kind(),
            format!("Failed to read directory {}: {}", dir.display(), e),
        ))
    })?;

    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| {
            NailsError::IoError(std::io::Error::new(
                e.kind(),
                format!("Failed to read directory entry in {}: {}", dir.display(), e),
            ))
        })?;
        paths.push(entry.path());
    }

    Ok(paths)
}

pub(super) fn enumerate_root_directories() -> Result<Vec<PathBuf>> {
    let root = Path::new("/");

    let entries = std::fs::read_dir(root).map_err(|e| {
        NailsError::IoError(std::io::Error::new(
            e.kind(),
            format!("Failed to read /: {}", e),
        ))
    })?;

    let mut directories = Vec::new();

    for entry in entries {
        let entry = entry.map_err(|e| {
            NailsError::IoError(std::io::Error::new(
                e.kind(),
                format!("Failed to read directory entry: {}", e),
            ))
        })?;
        let path = entry.path();

        let metadata = std::fs::symlink_metadata(&path).map_err(|e| {
            NailsError::IoError(std::io::Error::new(
                e.kind(),
                format!("Failed to get metadata for {}: {}", path.display(), e),
            ))
        })?;

        // Skip symlinks (even if they point to directories)
        if metadata.is_symlink() {
            tracing::debug!(
                "Skipping symlink: {} -> {:?}",
                path.display(),
                std::fs::read_link(&path)
            );
            continue;
        }

        if !metadata.is_dir() {
            continue;
        }

        // Skip /run/nails directory
        if path.starts_with("/run/nails") {
            tracing::debug!("Skipping NAILS runtime directory: {}", path.display());
            continue;
        }

        directories.push(path);
    }

    // Sort alphabetically for consistent mount order
    directories.sort();

    Ok(directories)
}

pub(super) fn read_directory(path: &Path) -> Result<Vec<std::fs::DirEntry>> {
    let entries = std::fs::read_dir(path).map_err(|e| {
        NailsError::IoError(std::io::Error::new(
            e.kind(),
            format!("Failed to read directory {}: {}", path.display(), e),
        ))
    })?;

    let mut result = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| {
            NailsError::IoError(std::io::Error::new(
                e.kind(),
                format!(
                    "Failed to read directory entry in {}: {}",
                    path.display(),
                    e
                ),
            ))
        })?;
        result.push(entry);
    }

    Ok(result)
}

pub(super) fn modified_time(path: &Path) -> Result<chrono::DateTime<chrono::Utc>> {
    let metadata = std::fs::metadata(path).map_err(|e| {
        NailsError::IoError(std::io::Error::new(
            e.kind(),
            format!("Failed to get metadata for {}: {}", path.display(), e),
        ))
    })?;

    let modified = metadata.modified().map_err(|e| {
        NailsError::IoError(std::io::Error::new(
            e.kind(),
            format!(
                "Failed to get modification time for {}: {}",
                path.display(),
                e
            ),
        ))
    })?;

    let datetime: chrono::DateTime<chrono::Utc> = modified.into();
    Ok(datetime)
}

pub(super) fn copy_tree(src: &Path, dst: &Path) -> Result<()> {
    copy_tree_with(&RealProcessRunner, src, dst)
}

/// Copies the contents of `src` into `dst` with `cp -a`.
///
/// The pivot snapshot must keep ownership, modes, timestamps, xattrs, ACLs,
/// hard links and special files. `cp -a` preserves all of them; a plain
/// `std::fs` copy does not.
fn copy_tree_with(runner: &dyn ProcessRunner, src: &Path, dst: &Path) -> Result<()> {
    let mut source = src.as_os_str().to_os_string();
    source.push("/.");
    // The copy only touches the paths the caller chose, so it may run in tests.
    // A snapshot of a very large tree can take minutes, so the budget is generous;
    // it exists only so a `cp` wedged on bad storage cannot hang activation
    // forever.
    let command = ProcessCommand::tool("cp")
        .arg("-a")
        .arg("--")
        .arg(&source)
        .arg(dst)
        .deadline(COPY_BUDGET)
        .allow_in_test_runtime();

    let output = runner.run(&command).map_err(|err| match err {
        NailsError::IoError(io) => NailsError::IoError(std::io::Error::new(
            io.kind(),
            format!(
                "Failed to run cp -a {}/. {}: {}",
                src.display(),
                dst.display(),
                io
            ),
        )),
        other => other,
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(NailsError::IoError(std::io::Error::other(format!(
            "cp -a {}/. {} failed: {}",
            src.display(),
            dst.display(),
            stderr.trim()
        ))));
    }

    Ok(())
}

/// Apparent size in bytes of `path` and everything below it, like `du -sb`.
///
/// Sizes come from `lstat`, so a symlink counts as the link itself and is
/// never followed, and a file reached through several hard links counts once.
/// Mount points below `path` are descended, as `cp -a` does: the result sizes
/// a `cp -a` snapshot of the same tree.
pub(super) fn get_directory_size(path: &Path) -> Result<u64> {
    let mut counted_links = HashSet::new();
    let mut pending = vec![path.to_path_buf()];
    let mut total: u64 = 0;

    while let Some(current) = pending.pop() {
        let metadata = std::fs::symlink_metadata(&current).map_err(|e| {
            NailsError::IoError(std::io::Error::new(
                e.kind(),
                format!("Failed to get metadata for {}: {}", current.display(), e),
            ))
        })?;

        if !metadata.is_dir()
            && metadata.nlink() > 1
            && !counted_links.insert((metadata.dev(), metadata.ino()))
        {
            continue;
        }
        total = total.saturating_add(metadata.len());

        if metadata.is_dir() {
            pending.extend(read_directory(&current)?.iter().map(|entry| entry.path()));
        }
    }

    Ok(total)
}

pub(super) fn find_submount_sources(target: &Path) -> Result<Vec<(PathBuf, PathBuf)>> {
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo")?;
    let canonical_target = target
        .canonicalize()
        .unwrap_or_else(|_| target.to_path_buf());
    Ok(super::submount::parse_submount_sources(
        &mountinfo,
        &canonical_target,
    ))
}

pub(super) fn find_submounts(target: &Path) -> Result<Vec<crate::filesystem::Submount>> {
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo")?;
    let canonical_target = target
        .canonicalize()
        .unwrap_or_else(|_| target.to_path_buf());
    Ok(super::classify_submounts(&mountinfo, &canonical_target))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::run::{MockProcessRunner, exited};
    use std::ffi::OsStr;
    use std::fs;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn lstat_len(path: &Path) -> u64 {
        fs::symlink_metadata(path).unwrap().len()
    }

    fn io_error(err: NailsError) -> std::io::Error {
        match err {
            NailsError::IoError(io) => io,
            other => panic!("expected IoError, got {other:?}"),
        }
    }

    #[test]
    fn copy_tree_runs_cp_archive_on_the_source_contents() {
        let runner = MockProcessRunner::new();

        copy_tree_with(&runner, Path::new("/boot"), Path::new("/run/nails/snap")).unwrap();

        assert_eq!(
            runner.calls(),
            vec![
                ProcessCommand::tool("cp")
                    .args(["-a", "--", "/boot/.", "/run/nails/snap"])
                    .deadline(COPY_BUDGET)
                    .allow_in_test_runtime()
            ]
        );
    }

    #[test]
    fn copy_tree_reports_cp_failures_with_stderr() {
        let runner = MockProcessRunner::new().with_response(Ok(exited(1, "", "cp: cannot stat\n")));

        let err =
            io_error(copy_tree_with(&runner, Path::new("/src"), Path::new("/dst")).unwrap_err());

        assert_eq!(err.to_string(), "cp -a /src/. /dst failed: cp: cannot stat");
    }

    #[test]
    fn copy_tree_keeps_the_kind_of_start_failures() {
        let runner = MockProcessRunner::new().with_response(Err(NailsError::IoError(
            std::io::Error::new(std::io::ErrorKind::NotFound, "cp not found"),
        )));

        let err =
            io_error(copy_tree_with(&runner, Path::new("/src"), Path::new("/dst")).unwrap_err());

        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        assert_eq!(
            err.to_string(),
            "Failed to run cp -a /src/. /dst: cp not found"
        );
    }

    #[test]
    fn copy_tree_passes_other_runner_errors_through() {
        let runner = MockProcessRunner::new()
            .with_response(Err(NailsError::InvalidState("refused".to_string())));

        let err = copy_tree_with(&runner, Path::new("/src"), Path::new("/dst")).unwrap_err();

        assert!(matches!(err, NailsError::InvalidState(message) if message == "refused"));
    }

    #[test]
    fn copy_tree_preserves_symlinks_modes_timestamps_and_hard_links() {
        let temp_dir = tempfile::tempdir().unwrap();
        let src = temp_dir.path().join("src");
        let dst = temp_dir.path().join("dst");
        fs::create_dir_all(&src).unwrap();
        fs::create_dir_all(&dst).unwrap();
        let file = src.join("a.txt");
        fs::write(&file, "a").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o640)).unwrap();
        let mtime = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000);
        fs::File::options()
            .write(true)
            .open(&file)
            .unwrap()
            .set_modified(mtime)
            .unwrap();
        fs::hard_link(&file, src.join("b.txt")).unwrap();
        symlink("a.txt", src.join("link")).unwrap();

        copy_tree(&src, &dst).unwrap();

        let copied = fs::symlink_metadata(dst.join("a.txt")).unwrap();
        assert_eq!(copied.permissions().mode() & 0o7777, 0o640);
        assert_eq!(copied.modified().unwrap(), mtime);
        assert_eq!(
            fs::symlink_metadata(dst.join("b.txt")).unwrap().ino(),
            copied.ino()
        );
        assert!(fs::symlink_metadata(dst.join("link")).unwrap().is_symlink());
        assert_eq!(fs::read_link(dst.join("link")).unwrap(), Path::new("a.txt"));
    }

    #[test]
    fn copy_tree_accepts_source_paths_that_are_not_utf8() {
        let temp_dir = tempfile::tempdir().unwrap();
        let src = temp_dir.path().join(OsStr::from_bytes(b"src-\xff"));
        let dst = temp_dir.path().join("dst");
        fs::create_dir_all(&src).unwrap();
        fs::create_dir_all(&dst).unwrap();
        fs::write(src.join("a.txt"), "a").unwrap();

        copy_tree(&src, &dst).unwrap();

        assert_eq!(fs::read_to_string(dst.join("a.txt")).unwrap(), "a");
    }

    #[test]
    fn directory_size_sums_the_apparent_size_of_every_entry() {
        let temp_dir = tempfile::tempdir().unwrap();
        let root = temp_dir.path();
        let nested = root.join("nested");
        fs::create_dir_all(&nested).unwrap();
        fs::write(root.join("a.txt"), vec![0u8; 1234]).unwrap();
        fs::write(nested.join("b.txt"), vec![0u8; 4321]).unwrap();

        let expected = lstat_len(root)
            + lstat_len(&nested)
            + lstat_len(&root.join("a.txt"))
            + lstat_len(&nested.join("b.txt"));

        assert_eq!(get_directory_size(root).unwrap(), expected);
    }

    #[test]
    fn directory_size_counts_symlinks_as_links_without_following_them() {
        let outside = tempfile::tempdir().unwrap();
        let big = outside.path().join("big");
        fs::write(&big, vec![0u8; 1 << 20]).unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let root = temp_dir.path();
        symlink(&big, root.join("file-link")).unwrap();
        symlink(outside.path(), root.join("dir-link")).unwrap();

        let expected = lstat_len(root)
            + lstat_len(&root.join("file-link"))
            + lstat_len(&root.join("dir-link"));

        assert_eq!(get_directory_size(root).unwrap(), expected);
    }

    #[test]
    fn directory_size_counts_hard_linked_files_once() {
        let temp_dir = tempfile::tempdir().unwrap();
        let root = temp_dir.path();
        fs::write(root.join("a"), vec![0u8; 5000]).unwrap();
        fs::hard_link(root.join("a"), root.join("b")).unwrap();

        assert_eq!(get_directory_size(root).unwrap(), lstat_len(root) + 5000);
    }

    #[test]
    fn directory_size_of_a_missing_path_names_it() {
        let temp_dir = tempfile::tempdir().unwrap();
        let missing = temp_dir.path().join("missing");

        let err = io_error(get_directory_size(&missing).unwrap_err());

        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        assert!(err.to_string().contains(&missing.display().to_string()));
    }
}
