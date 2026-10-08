// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Symlink-safe writing of a file into a target user's home.

use super::unique_temp_name;
use crate::target_user::TargetUser;
use crate::{NailsError, Result};
use std::path::Path;

/// Symlink-safe, correctly-owned write of a file in a user-owned home path.
///
/// See [`crate::filesystem::Filesystem::write_user_file`] for the contract. The
/// implementation closes CWE-59 at the point of the open rather than after it:
/// the destination and every component of its parent chain are resolved with
/// symlink resolution disabled, the payload is written to a uniquely named temp
/// created `O_CREAT | O_EXCL | O_NOFOLLOW` relative to the parent's directory fd,
/// and the temp is renamed over the destination. There is no predictable
/// sibling name for an attacker to pre-plant, and the rename replaces a symlink
/// sitting at the destination name instead of following it.
pub(in crate::filesystem::real) fn write_user_file(
    path: &Path,
    content: &str,
    user: &TargetUser,
    default_mode: u32,
) -> Result<()> {
    use nix::fcntl::{AtFlags, OFlag, OpenHow, ResolveFlag, openat2, renameat};
    use nix::sys::stat::{Mode, fchmod, fstatat};
    use nix::unistd::{Gid, Uid, UnlinkatFlags, fchown, unlinkat};
    use std::io::Write;

    let parent = path.parent().ok_or_else(|| {
        NailsError::io(
            path,
            std::io::Error::other(format!(
                "Refusing to write user file with no parent directory: {}",
                path.display()
            )),
        )
    })?;
    let file_name = path.file_name().ok_or_else(|| {
        NailsError::io(
            path,
            std::io::Error::other(format!(
                "Refusing to write user file with no file name: {}",
                path.display()
            )),
        )
    })?;

    // Ensure the parent chain exists and every directory NAILS creates is owned
    // by the target user with private (0700) permissions.
    create_user_dir_all(parent, user)?;

    // Anchor every subsequent operation at a directory fd whose path resolved
    // without traversing any symlink. After this open the parent cannot be
    // swapped out from under the write.
    let dir_fd = open_dir_no_symlinks(parent)?;

    // Preserve an existing file's owner and mode; a new file takes the target
    // user's numeric ids and the caller's default mode.
    let (uid, gid, mode) = match fstatat(&dir_fd, file_name, AtFlags::AT_SYMLINK_NOFOLLOW) {
        Ok(st) => (st.st_uid, st.st_gid, st.st_mode & 0o7777),
        Err(nix::errno::Errno::ENOENT) => (user.uid, user.gid, default_mode & 0o7777),
        Err(e) => {
            return Err(NailsError::io(
                path,
                std::io::Error::other(format!(
                    "Failed to stat {} before writing: {}",
                    path.display(),
                    e
                )),
            ));
        }
    };

    let create_how = OpenHow::new()
        .flags(
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        )
        .mode(Mode::from_bits_truncate(mode))
        .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS | ResolveFlag::RESOLVE_BENEATH);

    // Create the temp under a unique name beneath the parent dir fd.
    let mut temp_name = String::new();
    let mut last_err: Option<nix::errno::Errno> = None;
    let mut temp_fd = None;
    for _ in 0..8 {
        let candidate = unique_temp_name();
        match openat2(&dir_fd, candidate.as_str(), create_how) {
            Ok(fd) => {
                temp_name = candidate;
                temp_fd = Some(fd);
                break;
            }
            Err(nix::errno::Errno::EEXIST) => {
                last_err = Some(nix::errno::Errno::EEXIST);
                continue;
            }
            Err(e) => {
                return Err(NailsError::io(
                    parent,
                    std::io::Error::other(format!(
                        "Failed to create temp file in {}: {}",
                        parent.display(),
                        e
                    )),
                ));
            }
        }
    }
    let temp_fd = temp_fd.ok_or_else(|| {
        NailsError::io(
            parent,
            std::io::Error::other(format!(
                "Failed to create a unique temp file in {} ({:?})",
                parent.display(),
                last_err
            )),
        )
    })?;

    // Everything below must clean up the temp on failure so a half-written file
    // is never left behind in the user's home.
    let outcome = (|| -> Result<()> {
        let mut file = std::fs::File::from(temp_fd);
        file.write_all(content.as_bytes()).map_err(|e| {
            NailsError::io(
                path,
                std::io::Error::new(
                    e.kind(),
                    format!("Failed to write temp file for {}: {}", path.display(), e),
                ),
            )
        })?;
        file.sync_all().map_err(|e| {
            NailsError::io(
                path,
                std::io::Error::new(
                    e.kind(),
                    format!("Failed to sync temp file for {}: {}", path.display(), e),
                ),
            )
        })?;

        // Ownership is skipped in test/test-like runtimes, where the process may
        // lack the privilege to chown to another account. This mirrors the
        // guard the notification writer uses for the same reason.
        if !crate::runtime_safety::should_skip_host_interaction() {
            fchown(&file, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid))).map_err(|e| {
                NailsError::io(
                    path,
                    std::io::Error::other(format!(
                        "Failed to set ownership {uid}:{gid} on {}: {e}",
                        path.display()
                    )),
                )
            })?;
        }

        // Set the mode explicitly so the process umask cannot alter it.
        fchmod(&file, Mode::from_bits_truncate(mode)).map_err(|e| {
            NailsError::io(
                path,
                std::io::Error::other(format!(
                    "Failed to set mode {mode:o} on {}: {e}",
                    path.display()
                )),
            )
        })?;

        renameat(&dir_fd, temp_name.as_str(), &dir_fd, file_name).map_err(|e| {
            NailsError::io(
                path,
                std::io::Error::other(format!(
                    "Failed to move temp file into place at {}: {e}",
                    path.display()
                )),
            )
        })?;
        Ok(())
    })();

    if outcome.is_err() {
        let _ = unlinkat(&dir_fd, temp_name.as_str(), UnlinkatFlags::NoRemoveDir);
    }

    outcome
}

/// Open `dir` as a directory fd whose path contains no symlinked component.
///
/// Uses `openat2` with `RESOLVE_NO_SYMLINKS`, so a symlink anywhere in `dir`'s
/// path (for example a pre-planted `~/.config` pointing elsewhere) is refused
/// with `ELOOP` rather than silently followed. The anchor fd is required by the
/// wrapper but is ignored for the absolute path passed here.
fn open_dir_no_symlinks(dir: &Path) -> Result<std::os::fd::OwnedFd> {
    use nix::fcntl::{OFlag, OpenHow, ResolveFlag, openat2};

    let anchor = std::fs::File::open("/").map_err(|e| {
        NailsError::io(
            "/",
            std::io::Error::new(
                e.kind(),
                format!("Failed to open / to anchor directory resolution: {e}"),
            ),
        )
    })?;
    let how = OpenHow::new()
        .flags(OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC)
        .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS);
    openat2(&anchor, dir, how).map_err(|e| {
        NailsError::io(
            dir,
            std::io::Error::other(format!(
                "Refusing to write into {}: its path is not resolvable without symlinks ({e})",
                dir.display()
            )),
        )
    })
}

/// Create `dir` and any missing ancestors, leaving every directory NAILS creates
/// owned by `user` and mode 0700. Refuses to descend through a symlinked
/// component so a planted symlink cannot redirect directory creation.
fn create_user_dir_all(dir: &Path, user: &TargetUser) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    match std::fs::symlink_metadata(dir) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(NailsError::io(
                dir,
                std::io::Error::other(format!(
                    "Refusing to write under symlinked directory {}",
                    dir.display()
                )),
            ));
        }
        Ok(meta) if meta.is_dir() => return Ok(()),
        Ok(_) => {
            return Err(NailsError::io(
                dir,
                std::io::Error::other(format!(
                    "Parent path {} exists and is not a directory",
                    dir.display()
                )),
            ));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(NailsError::io(
                dir,
                std::io::Error::new(e.kind(), format!("Failed to stat {}: {e}", dir.display())),
            ));
        }
    }

    // Walk up to the first existing ancestor, recording the missing ones.
    let mut missing = Vec::new();
    let mut cursor = dir;
    loop {
        match std::fs::symlink_metadata(cursor) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(NailsError::io(
                    cursor,
                    std::io::Error::other(format!(
                        "Refusing to create directories under symlinked path {}",
                        cursor.display()
                    )),
                ));
            }
            Ok(_) => break,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                missing.push(cursor.to_path_buf());
                match cursor.parent() {
                    Some(parent) => cursor = parent,
                    None => break,
                }
            }
            Err(e) => {
                return Err(NailsError::io(
                    cursor,
                    std::io::Error::new(
                        e.kind(),
                        format!("Failed to stat {}: {e}", cursor.display()),
                    ),
                ));
            }
        }
    }

    for new_dir in missing.iter().rev() {
        match std::fs::create_dir(new_dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(NailsError::io(
                    new_dir,
                    std::io::Error::new(
                        e.kind(),
                        format!("Failed to create directory {}: {e}", new_dir.display()),
                    ),
                ));
            }
        }

        if let Err(e) = std::fs::set_permissions(new_dir, std::fs::Permissions::from_mode(0o700)) {
            tracing::warn!(
                dir = %new_dir.display(),
                error = %e,
                "Failed to set mode on created directory (non-fatal)"
            );
        }

        if !crate::runtime_safety::should_skip_host_interaction() {
            std::os::unix::fs::chown(new_dir, Some(user.uid), Some(user.gid)).map_err(|e| {
                NailsError::io(
                    new_dir,
                    std::io::Error::new(
                        e.kind(),
                        format!(
                            "Failed to set ownership {}:{} on {}: {e}",
                            user.uid,
                            user.gid,
                            new_dir.display()
                        ),
                    ),
                )
            })?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod write_user_file_tests {
    use super::*;
    use crate::target_user::TargetUser;
    use std::os::unix::fs::PermissionsExt;

    fn test_user() -> TargetUser {
        // Ownership is skipped under the test runtime, so the ids never have to
        // match a real passwd entry.
        TargetUser::for_test(1000, 100, "operator", "/home/operator", "/bin/bash")
    }

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
    }

    #[test]
    fn planted_tmp_sibling_symlink_cannot_redirect_the_write() {
        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path();

        // A sensitive file the attacker wants root to clobber, plus the
        // predictable sibling symlink the old implementation would have opened.
        let sentinel = base.join("sentinel");
        std::fs::write(&sentinel, "SECRET").unwrap();
        let target = base.join("foo");
        std::os::unix::fs::symlink(&sentinel, base.join("foo.tmp")).unwrap();

        write_user_file(&target, "payload", &test_user(), 0o600).unwrap();

        // The sentinel the sibling pointed at is untouched.
        assert_eq!(std::fs::read_to_string(&sentinel).unwrap(), "SECRET");
        // The destination is a real file with our content and mode, not a link.
        assert!(
            !std::fs::symlink_metadata(&target)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "payload");
        assert_eq!(mode_of(&target), 0o600);
    }

    #[test]
    fn write_into_symlinked_parent_is_refused() {
        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path();

        let real = base.join("real");
        std::fs::create_dir(&real).unwrap();
        let link = base.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let err = write_user_file(&link.join("file"), "payload", &test_user(), 0o644);
        assert!(
            err.is_err(),
            "expected refusal writing through a symlinked parent"
        );
        // Nothing leaked into the symlink's real target.
        assert!(!real.join("file").exists());
    }

    #[test]
    fn creates_missing_parents_private_and_writes_default_mode() {
        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path();

        let target = base.join("a/b/c.txt");
        write_user_file(&target, "hello", &test_user(), 0o644).unwrap();

        assert_eq!(std::fs::read_to_string(&target).unwrap(), "hello");
        assert_eq!(mode_of(&target), 0o644);
        assert_eq!(mode_of(&base.join("a")), 0o700);
        assert_eq!(mode_of(&base.join("a/b")), 0o700);
    }

    #[test]
    fn existing_file_keeps_its_mode() {
        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path();
        let target = base.join("keep");

        write_user_file(&target, "first", &test_user(), 0o600).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o640)).unwrap();

        // A second write with a different default must not reset the mode.
        write_user_file(&target, "second", &test_user(), 0o600).unwrap();

        assert_eq!(std::fs::read_to_string(&target).unwrap(), "second");
        assert_eq!(mode_of(&target), 0o640);
    }
}
