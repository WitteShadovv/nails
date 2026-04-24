use super::command_cache::build_cached_command;
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

fn resolve_current_system_profile() -> PathBuf {
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
                return resolved;
            }
        }
    }

    if std::fs::symlink_metadata("/nix/var/nix/profiles/system").is_ok() {
        PathBuf::from("/nix/var/nix/profiles/system")
    } else {
        PathBuf::from("/run/current-system")
    }
}

pub(crate) fn cache_nix_overlay_runtime_commands() -> std::io::Result<PathBuf> {
    let systemctl = build_cached_command(Path::new("/run/current-system/sw/bin/systemctl"))?;
    let nix_daemon = std::fs::canonicalize("/run/current-system/sw/bin/nix-daemon")
        .unwrap_or_else(|_| PathBuf::from("/run/current-system/sw/bin/nix-daemon"));
    let nix = std::fs::canonicalize("/run/current-system/sw/bin/nix")
        .unwrap_or_else(|_| PathBuf::from("/run/current-system/sw/bin/nix"));
    let current_system_profile = resolve_current_system_profile();
    let original_nix_store_bind_source = cache_original_nix_store_bind_source()?;

    let display_path = systemctl.display_path().to_path_buf();
    let _ = super::SYSTEMCTL_COMMAND.set(systemctl);
    let _ = super::NIX_DAEMON_PATH.set(nix_daemon);
    let _ = super::NIX_COMMAND_PATH.set(nix);
    let _ = super::CURRENT_SYSTEM_PROFILE.set(current_system_profile);
    let _ = super::ORIGINAL_NIX_STORE_BIND_SOURCE.set(original_nix_store_bind_source);
    Ok(display_path)
}

pub(crate) fn cached_current_system_profile() -> Option<PathBuf> {
    super::CURRENT_SYSTEM_PROFILE.get().cloned()
}

pub(crate) fn cached_original_nix_store_bind_source() -> Option<PathBuf> {
    super::ORIGINAL_NIX_STORE_BIND_SOURCE.get().cloned()
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
    fn test_resolve_current_system_profile_returns_absolute_fallback() {
        let resolved = resolve_current_system_profile();

        assert!(resolved.is_absolute(), "resolved={}", resolved.display());
        assert!(
            resolved == std::path::Path::new("/run/current-system")
                || resolved == std::path::Path::new("/nix/var/nix/profiles/system")
                || resolved.starts_with("/nix/store/"),
            "resolved={} should point at a current-system candidate",
            resolved.display()
        );
    }
}
