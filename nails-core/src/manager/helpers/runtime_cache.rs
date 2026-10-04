// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::command_cache::{build_cached_command, nixos_tool_path};
use std::path::{Path, PathBuf};

fn original_nix_store_bind_source_path() -> PathBuf {
    PathBuf::from("/run/nails/original-nix-store")
}

fn cache_original_nix_store_bind_source() -> std::io::Result<PathBuf> {
    if crate::runtime_safety::should_skip_host_interaction() {
        return Ok(PathBuf::from("/nix/store"));
    }

    let cache_path = original_nix_store_bind_source_path();
    std::fs::create_dir_all(&cache_path)?;

    match nix::mount::umount2(&cache_path, nix::mount::MntFlags::MNT_DETACH) {
        Ok(()) | Err(nix::errno::Errno::EINVAL) | Err(nix::errno::Errno::ENOENT) => {}
        Err(err) => {
            return Err(std::io::Error::other(format!(
                "failed to clear cached /nix/store bind source at {}: {err}",
                cache_path.display()
            )));
        }
    }

    nix::mount::mount(
        Some(Path::new("/nix/store")),
        &cache_path,
        None::<&str>,
        nix::mount::MsFlags::MS_BIND,
        None::<&str>,
    )
    .map_err(|err| {
        std::io::Error::other(format!(
            "failed to bind mount /nix/store to cached source {}: {err}",
            cache_path.display()
        ))
    })?;

    nix::mount::mount(
        Some(cache_path.as_path()),
        &cache_path,
        None::<&str>,
        nix::mount::MsFlags::MS_BIND
            | nix::mount::MsFlags::MS_REMOUNT
            | nix::mount::MsFlags::MS_RDONLY,
        None::<&str>,
    )
    .map_err(|err| {
        std::io::Error::other(format!(
            "failed to remount cached /nix/store source {} read-only: {err}",
            cache_path.display()
        ))
    })?;

    Ok(cache_path)
}

/// Resolve the real system-profile path `/run/current-system` should point at
/// after the `/nix` overlay, or `None` when neither candidate resolves.
///
/// Returns the generation the live `/run/current-system` or
/// `/nix/var/nix/profiles/system` symlink points at (an absolute store path), or
/// the `/nix/var/nix/profiles/system` link itself when it exists. It deliberately
/// does **not** fall back to the literal `/run/current-system`: restoring that as
/// the symlink target would create a `/run/current-system -> /run/current-system`
/// self-loop. On a host where nothing resolves the caller skips the symlink
/// restore entirely rather than restore a broken self-reference.
fn resolve_current_system_profile() -> Option<PathBuf> {
    for candidate in ["/run/current-system", "/nix/var/nix/profiles/system"] {
        if let Ok(target) = std::fs::read_link(candidate) {
            let resolved = if target.is_absolute() {
                target
            } else {
                Path::new(candidate)
                    .parent()
                    .map(|parent| parent.join(&target))
                    .unwrap_or(target)
            };

            if resolved.exists() {
                return Some(resolved);
            }
        }
    }

    if std::fs::symlink_metadata("/nix/var/nix/profiles/system").is_ok() {
        Some(PathBuf::from("/nix/var/nix/profiles/system"))
    } else {
        None
    }
}

pub(crate) fn cache_nix_overlay_runtime_commands() -> std::io::Result<PathBuf> {
    // Create the read-only bind of the pre-overlay /nix/store first: the runtime
    // command is resolved against it, so no store bytes are copied.
    let original_nix_store_bind_source = cache_original_nix_store_bind_source()?;
    let systemctl = build_cached_command(
        &nixos_tool_path("systemctl"),
        &original_nix_store_bind_source,
    )?;
    let nix_daemon_path = nixos_tool_path("nix-daemon");
    let nix_daemon = std::fs::canonicalize(&nix_daemon_path).unwrap_or(nix_daemon_path);
    let nix_path = nixos_tool_path("nix");
    let nix = std::fs::canonicalize(&nix_path).unwrap_or(nix_path);

    let display_path = systemctl.display_path().to_path_buf();
    let _ = super::SYSTEMCTL_COMMAND.set(systemctl);
    let _ = super::NIX_DAEMON_PATH.set(nix_daemon);
    let _ = super::NIX_COMMAND_PATH.set(nix);
    // Only cache a current-system profile when one actually resolves; a malformed
    // host leaves it unset, and the restore step then skips the symlink update
    // rather than creating a self-loop.
    if let Some(current_system_profile) = resolve_current_system_profile() {
        let _ = super::CURRENT_SYSTEM_PROFILE.set(current_system_profile);
    }
    Ok(display_path)
}

pub(crate) fn cached_current_system_profile() -> Option<PathBuf> {
    super::CURRENT_SYSTEM_PROFILE.get().cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    fn test_original_nix_store_bind_source_path_is_stable() {
        assert_eq!(
            original_nix_store_bind_source_path(),
            PathBuf::from("/run/nails/original-nix-store")
        );
    }

    #[test]
    #[serial]
    fn test_resolve_current_system_profile_never_self_references() {
        // Whatever resolves, it is a real generation path, never the literal
        // /run/current-system (which would make the restored symlink a self-loop).
        // On a host with no nix profile at all (the sandbox) resolving nothing is
        // the correct answer: the restore step then skips the symlink.
        if let Some(resolved) = resolve_current_system_profile() {
            assert!(resolved.is_absolute(), "resolved={}", resolved.display());
            assert_ne!(
                resolved,
                std::path::Path::new("/run/current-system"),
                "the current-system profile must never resolve to itself"
            );
            assert!(
                resolved == std::path::Path::new("/nix/var/nix/profiles/system")
                    || resolved.starts_with("/nix/store/")
                    || resolved.starts_with("/nix/var/nix/profiles/"),
                "resolved={} should point at a real generation",
                resolved.display()
            );
        }
    }
}
