//! Host detection: read os-release and the kernel's runtime markers once and
//! fold them into a [`HostProfile`].
//!
//! Every host fact is read through the [`Filesystem`] trait so the same code
//! runs against the real root and against os-release fixtures in tests.

use std::path::Path;

use super::{HostProfile, PlatformKind};
use crate::Result;
use crate::filesystem::Filesystem;

/// Where the kernel exposes the running init's command name.
const PID1_COMM: &str = "/proc/1/comm";
/// Marker the ostree stack writes for an image-based boot.
const OSTREE_MARKER: &str = "/run/ostree-booted";
/// Live NixOS generation symlink.
const CURRENT_SYSTEM: &str = "/run/current-system";
/// Standard os-release location.
const OS_RELEASE: &str = "/etc/os-release";

/// Detect the running host.
///
/// Reads `/etc/os-release` (`ID`, `ID_LIKE`, `VERSION_ID`), `/run/ostree-booted`,
/// `/run/current-system` and PID 1's command name, then classifies the host:
///
/// - An ostree / image-based boot, or a PID 1 that is not systemd, resolves to
///   [`PlatformKind::Unsupported`] with an actionable reason. Detection still
///   succeeds — the refusal is carried on the profile and surfaced by
///   [`HostProfile::require_supported`] or the [`UnsupportedPlatform`] backend.
/// - A host whose `ID` is `nixos`, or that has a live `/run/current-system`,
///   resolves to [`PlatformKind::NixOs`].
/// - Any other systemd host resolves to [`PlatformKind::Fhs`].
///
/// [`UnsupportedPlatform`]: super::UnsupportedPlatform
pub fn detect<F: Filesystem>(fs: &F) -> Result<HostProfile> {
    let os_release = read_optional(fs, Path::new(OS_RELEASE));
    let fields = os_release
        .as_deref()
        .map(parse_os_release)
        .unwrap_or_default();

    let is_ostree = fs.path_exists(Path::new(OSTREE_MARKER))?;
    let has_current_system = fs.path_exists(Path::new(CURRENT_SYSTEM))?;
    let pid1 = read_optional(fs, Path::new(PID1_COMM));
    let pid1_comm = pid1.as_deref().map(str::trim).map(str::to_string);
    let is_systemd = pid1_comm.as_deref() == Some("systemd");

    let (kind, unsupported_reason) = classify(
        is_ostree,
        is_systemd,
        pid1_comm.as_deref(),
        &fields,
        has_current_system,
    );

    Ok(HostProfile {
        kind,
        id: fields.id,
        id_like: fields.id_like,
        version_id: fields.version_id,
        is_systemd,
        is_ostree,
        has_current_system,
        unsupported_reason,
    })
}

/// Read a file, treating "absent/unreadable" as `None` rather than an error:
/// os-release and the runtime markers are optional inputs, not failures.
fn read_optional<F: Filesystem>(fs: &F, path: &Path) -> Option<String> {
    fs.read_file_content(path).ok()
}

/// Parsed subset of `/etc/os-release`.
#[derive(Debug, Default)]
struct OsReleaseFields {
    id: Option<String>,
    id_like: Vec<String>,
    version_id: Option<String>,
}

/// Parse the `KEY=VALUE` lines of os-release, lowercasing identifiers and
/// stripping surrounding quotes.
fn parse_os_release(content: &str) -> OsReleaseFields {
    let mut fields = OsReleaseFields::default();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = unquote(value.trim());
        match key.trim() {
            "ID" => fields.id = Some(value.to_ascii_lowercase()),
            "ID_LIKE" => {
                fields.id_like = value
                    .split_whitespace()
                    .map(|token| token.to_ascii_lowercase())
                    .collect();
            }
            "VERSION_ID" => fields.version_id = Some(value.to_string()),
            _ => {}
        }
    }
    fields
}

/// Strip one layer of matching single or double quotes from an os-release value.
fn unquote(value: &str) -> &str {
    let bytes = value.as_bytes();
    if bytes.len() >= 2
        && (bytes[0] == b'"' || bytes[0] == b'\'')
        && bytes[bytes.len() - 1] == bytes[0]
    {
        &value[1..value.len() - 1]
    } else {
        value
    }
}

/// Resolve the host facts to a [`PlatformKind`] and, when unsupported, a reason.
///
/// Refusals come first: an ostree / image-based host and a non-systemd PID 1 are
/// both declined, because NAILS cannot safely lay a hidden overlay over an
/// immutable image or drive teardown without systemd.
fn classify(
    is_ostree: bool,
    is_systemd: bool,
    pid1_comm: Option<&str>,
    fields: &OsReleaseFields,
    has_current_system: bool,
) -> (PlatformKind, Option<String>) {
    if is_ostree {
        return (
            PlatformKind::Unsupported,
            Some(
                "this host is ostree / image-based (found /run/ostree-booted); \
                 NAILS cannot overlay an immutable system. Use a conventional \
                 mutable installation."
                    .to_string(),
            ),
        );
    }

    if !is_systemd {
        let found = pid1_comm
            .filter(|comm| !comm.is_empty())
            .map(|comm| format!("found '{comm}'"))
            .unwrap_or_else(|| "PID 1's command name could not be read".to_string());
        return (
            PlatformKind::Unsupported,
            Some(format!(
                "PID 1 is not systemd ({found}); NAILS requires a systemd host."
            )),
        );
    }

    if fields.id.as_deref() == Some("nixos") || has_current_system {
        return (PlatformKind::NixOs, None);
    }

    (PlatformKind::Fhs, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::MockFilesystem;

    /// Build a mock host: os-release content, PID 1 command, and optional markers.
    fn host(os_release: &str, pid1_comm: &str) -> MockFilesystem {
        let fs = MockFilesystem::new();
        fs.mock_add_file(OS_RELEASE, os_release);
        fs.mock_add_file(PID1_COMM, pid1_comm);
        fs
    }

    const NIXOS: &str = "ID=nixos\nVERSION_ID=\"24.11\"\nPRETTY_NAME=\"NixOS 24.11\"\n";
    const DEBIAN12: &str = "ID=debian\nVERSION_ID=\"12\"\nPRETTY_NAME=\"Debian GNU/Linux 12\"\n";
    const DEBIAN13: &str = "ID=debian\nVERSION_ID=\"13\"\n";
    const UBUNTU: &str =
        "ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04 LTS\"\n";
    const FEDORA: &str = "ID=fedora\nVERSION_ID=40\n";
    const ARCH: &str = "ID=arch\nBUILD_ID=rolling\n";

    #[test]
    fn nixos_by_id() {
        let profile = detect(&host(NIXOS, "systemd")).unwrap();
        assert_eq!(profile.kind, PlatformKind::NixOs);
        assert_eq!(profile.id.as_deref(), Some("nixos"));
        assert!(profile.is_systemd);
        profile.require_supported().unwrap();
    }

    #[test]
    fn nixos_by_current_system_without_os_release() {
        // A host with no readable os-release but a live generation is still NixOS.
        let fs = MockFilesystem::new();
        fs.mock_add_file(PID1_COMM, "systemd");
        fs.mock_set_path_type(CURRENT_SYSTEM, crate::filesystem::PathKind::Symlink);
        let profile = detect(&fs).unwrap();
        assert_eq!(profile.kind, PlatformKind::NixOs);
        assert!(profile.has_current_system);
    }

    #[test]
    fn debian_12_is_fhs() {
        let profile = detect(&host(DEBIAN12, "systemd")).unwrap();
        assert_eq!(profile.kind, PlatformKind::Fhs);
        assert_eq!(profile.id.as_deref(), Some("debian"));
        assert_eq!(profile.version_id.as_deref(), Some("12"));
        assert!(profile.is_debian_like());
    }

    #[test]
    fn debian_13_is_fhs() {
        let profile = detect(&host(DEBIAN13, "systemd")).unwrap();
        assert_eq!(profile.kind, PlatformKind::Fhs);
        assert_eq!(profile.version_id.as_deref(), Some("13"));
    }

    #[test]
    fn ubuntu_2404_is_fhs_and_debian_like() {
        let profile = detect(&host(UBUNTU, "systemd")).unwrap();
        assert_eq!(profile.kind, PlatformKind::Fhs);
        assert_eq!(profile.id.as_deref(), Some("ubuntu"));
        assert_eq!(profile.version_id.as_deref(), Some("24.04"));
        assert!(profile.is_debian_like());
    }

    #[test]
    fn fedora_is_fhs_not_debian_like() {
        let profile = detect(&host(FEDORA, "systemd")).unwrap();
        assert_eq!(profile.kind, PlatformKind::Fhs);
        assert_eq!(profile.version_id.as_deref(), Some("40"));
        assert!(!profile.is_debian_like());
    }

    #[test]
    fn arch_is_fhs() {
        let profile = detect(&host(ARCH, "systemd")).unwrap();
        assert_eq!(profile.kind, PlatformKind::Fhs);
        assert_eq!(profile.id.as_deref(), Some("arch"));
    }

    #[test]
    fn ostree_marker_refuses() {
        let fs = host(FEDORA, "systemd");
        fs.mock_set_path_type(OSTREE_MARKER, crate::filesystem::PathKind::File);
        let profile = detect(&fs).unwrap();
        assert_eq!(profile.kind, PlatformKind::Unsupported);
        assert!(profile.is_ostree);
        let err = profile.require_supported().unwrap_err();
        assert!(matches!(err, crate::NailsError::UnsupportedPlatform { .. }));
        assert!(err.to_string().contains("ostree"));
    }

    #[test]
    fn non_systemd_pid1_refuses() {
        let profile = detect(&host(DEBIAN12, "openrc-init")).unwrap();
        assert_eq!(profile.kind, PlatformKind::Unsupported);
        assert!(!profile.is_systemd);
        let err = profile.require_supported().unwrap_err();
        assert!(err.to_string().contains("systemd"));
        assert!(err.to_string().contains("openrc-init"));
    }

    #[test]
    fn unreadable_pid1_refuses() {
        // No /proc/1/comm at all: cannot confirm systemd, so decline.
        let fs = MockFilesystem::new();
        fs.mock_add_file(OS_RELEASE, DEBIAN12);
        let profile = detect(&fs).unwrap();
        assert_eq!(profile.kind, PlatformKind::Unsupported);
        assert!(profile.require_supported().is_err());
    }

    #[test]
    fn ostree_refusal_precedes_non_systemd() {
        // An ostree host with an odd init is refused as ostree first.
        let fs = host(FEDORA, "init");
        fs.mock_set_path_type(OSTREE_MARKER, crate::filesystem::PathKind::File);
        let profile = detect(&fs).unwrap();
        assert_eq!(profile.kind, PlatformKind::Unsupported);
        assert!(profile.unsupported_reason.unwrap().contains("ostree"));
    }

    #[test]
    fn parses_quoted_and_spaced_id_like() {
        let fields = parse_os_release("ID=ubuntu\nID_LIKE=\"debian gnu\"\n");
        assert_eq!(fields.id.as_deref(), Some("ubuntu"));
        assert_eq!(
            fields.id_like,
            vec!["debian".to_string(), "gnu".to_string()]
        );
    }

    #[test]
    fn unquote_handles_both_quote_styles() {
        assert_eq!(unquote("\"12\""), "12");
        assert_eq!(unquote("'bookworm'"), "bookworm");
        assert_eq!(unquote("plain"), "plain");
    }
}
