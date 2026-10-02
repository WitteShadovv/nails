//! One NixOS build-target discovery, shared by every path that needs it.
//!
//! Historically the cascade was copied into `activate`, into the `check`/`doctor`
//! manager builder, and into the `nixos-build-target` pre-flight check, and the
//! copies drifted. [`discover_host_target`] is the single implementation; the
//! remaining copies are rewired onto it in their owning chunks so all paths
//! derive the same result from one place.

use std::path::{Path, PathBuf};

use crate::Result;
use crate::filesystem::Filesystem;

/// Legacy NixOS configuration, probed when no flake is found.
const LEGACY_CONFIG: &str = "/etc/nixos/configuration.nix";
/// System-wide flake location.
const ETC_FLAKE_DIR: &str = "/etc/nixos";
/// Newest-generation system profile; its mere presence means the host is NixOS.
const SYSTEM_PROFILE: &str = "/nix/var/nix/profiles/system";

/// The NixOS build target activation would select, resolved once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostTarget {
    /// `--overlay-only`: no NixOS build or switch at all.
    OverlayOnly,
    /// An explicit flake reference from `--flake` or config `nixos_flake`.
    ExplicitFlake(String),
    /// A flake directory holding `flake.nix` (hidden volume, or `/etc/nixos`).
    Flake(PathBuf),
    /// A legacy `configuration.nix` build (also the choice when only the system
    /// profile is present, matching activation).
    Legacy(PathBuf),
    /// No NixOS configuration found; activation proceeds overlay-only.
    None,
}

/// Resolve the NixOS build target for this host.
///
/// The cascade, in order, mirrors activation exactly:
///
/// 1. `overlay_only` short-circuits to [`HostTarget::OverlayOnly`].
/// 2. an `explicit_flake` reference wins next.
/// 3. a `flake.nix` in `<hidden_volume_root>/nixos`.
/// 4. a `flake.nix` in `/etc/nixos`.
/// 5. a legacy `/etc/nixos/configuration.nix`, or a present system profile.
/// 6. otherwise [`HostTarget::None`].
///
/// Every probe goes through the [`Filesystem`] trait so the result is
/// deterministic under test.
pub fn discover_host_target<F: Filesystem>(
    fs: &F,
    hidden_volume_root: &Path,
    explicit_flake: Option<&str>,
    overlay_only: bool,
) -> Result<HostTarget> {
    if overlay_only {
        return Ok(HostTarget::OverlayOnly);
    }

    if let Some(flake_ref) = explicit_flake {
        return Ok(HostTarget::ExplicitFlake(flake_ref.to_string()));
    }

    let hidden_flake_dir = hidden_volume_root.join("nixos");
    if fs.path_exists(&hidden_flake_dir.join("flake.nix"))? {
        return Ok(HostTarget::Flake(hidden_flake_dir));
    }

    let etc_flake_dir = PathBuf::from(ETC_FLAKE_DIR);
    if fs.path_exists(&etc_flake_dir.join("flake.nix"))? {
        return Ok(HostTarget::Flake(etc_flake_dir));
    }

    let legacy_config = PathBuf::from(LEGACY_CONFIG);
    if fs.path_exists(&legacy_config)? || fs.path_exists(Path::new(SYSTEM_PROFILE))? {
        return Ok(HostTarget::Legacy(legacy_config));
    }

    Ok(HostTarget::None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::{MockFilesystem, PathKind};

    const HIDDEN_ROOT: &str = "/mnt/hidden";

    fn fs() -> MockFilesystem {
        MockFilesystem::new()
    }

    #[test]
    fn overlay_only_short_circuits() {
        let target =
            discover_host_target(&fs(), Path::new(HIDDEN_ROOT), Some("ignored#ref"), true).unwrap();
        assert_eq!(target, HostTarget::OverlayOnly);
    }

    #[test]
    fn explicit_flake_wins_over_probes() {
        let fs = fs();
        fs.mock_set_path_type("/mnt/hidden/nixos/flake.nix", PathKind::File);
        let target =
            discover_host_target(&fs, Path::new(HIDDEN_ROOT), Some("gh:me/cfg#host"), false)
                .unwrap();
        assert_eq!(
            target,
            HostTarget::ExplicitFlake("gh:me/cfg#host".to_string())
        );
    }

    #[test]
    fn hidden_volume_flake_preferred() {
        let fs = fs();
        fs.mock_set_path_type("/mnt/hidden/nixos/flake.nix", PathKind::File);
        fs.mock_set_path_type("/etc/nixos/flake.nix", PathKind::File);
        let target = discover_host_target(&fs, Path::new(HIDDEN_ROOT), None, false).unwrap();
        assert_eq!(
            target,
            HostTarget::Flake(PathBuf::from("/mnt/hidden/nixos"))
        );
    }

    #[test]
    fn etc_flake_when_no_hidden_flake() {
        let fs = fs();
        fs.mock_set_path_type("/etc/nixos/flake.nix", PathKind::File);
        let target = discover_host_target(&fs, Path::new(HIDDEN_ROOT), None, false).unwrap();
        assert_eq!(target, HostTarget::Flake(PathBuf::from("/etc/nixos")));
    }

    #[test]
    fn legacy_config_when_present() {
        let fs = fs();
        fs.mock_set_path_type("/etc/nixos/configuration.nix", PathKind::File);
        let target = discover_host_target(&fs, Path::new(HIDDEN_ROOT), None, false).unwrap();
        assert_eq!(
            target,
            HostTarget::Legacy(PathBuf::from("/etc/nixos/configuration.nix"))
        );
    }

    /// The agreement case: with only the system profile present, every path must
    /// resolve to the same legacy target activation uses — no drift between
    /// activate, `--dry-run`/`check`, and the `nixos-build-target` pre-flight.
    #[test]
    fn only_system_profile_resolves_to_legacy() {
        let fs = fs();
        fs.mock_set_path_type("/nix/var/nix/profiles/system", PathKind::Dir);
        let target = discover_host_target(&fs, Path::new(HIDDEN_ROOT), None, false).unwrap();
        assert_eq!(
            target,
            HostTarget::Legacy(PathBuf::from("/etc/nixos/configuration.nix"))
        );
    }

    #[test]
    fn nothing_found_is_none() {
        let target = discover_host_target(&fs(), Path::new(HIDDEN_ROOT), None, false).unwrap();
        assert_eq!(target, HostTarget::None);
    }
}
