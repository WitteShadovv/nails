// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Host detection: read os-release and the kernel's runtime markers once and
//! fold them into a [`HostProfile`].
//!
//! Every host fact is read through the [`Filesystem`] trait so the same code
//! runs against the real root and against os-release fixtures in tests.

use std::path::Path;

use super::family::{self, FamilySupport};
use super::{HostProfile, PlatformKind, composefs, host_facts};
use crate::Result;
use crate::filesystem::Filesystem;
use nails_base::Family;

/// Where the kernel exposes the running init's command name.
const PID1_COMM: &str = "/proc/1/comm";
/// Marker the ostree stack writes for an image-based boot.
const OSTREE_MARKER: &str = "/run/ostree-booted";
/// Live NixOS generation symlink.
const CURRENT_SYSTEM: &str = "/run/current-system";
/// Standard os-release location.
const OS_RELEASE: &str = "/etc/os-release";
/// Core root directories that a usr-merged layout keeps as symlinks into `/usr`.
/// If any is a real directory, the host is not merged and the `/usr` read-only
/// leak guard does not cover it.
const CORE_ROOT_DIRS: &[&str] = &["/bin", "/sbin", "/lib"];

/// Whether a Debian-family host has the merged-usr layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UsrMerge {
    /// `/bin`, `/sbin` and `/lib` are symlinks into `/usr` (or absent, so the
    /// probe cannot contradict a merged layout). Only matched hosts reach the
    /// probe, and every supported release ships them as symlinks.
    Merged,
    /// At least one core root is a real directory outside `/usr`.
    NotMerged,
}

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
/// - Any other systemd host resolves to [`PlatformKind::Fhs`] when the
///   Debian-family table admits it, and to [`PlatformKind::Unsupported`]
///   otherwise. A release the table admits but does not list as tested carries
///   its warning in [`HostProfile::support_warning`].
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
    let usr_merge = probe_usr_merge(fs);
    let composefs_refusal = composefs::composefs_refusal(fs);
    let lsms = host_facts::read_lsms(fs);
    let selinux = host_facts::read_selinux(fs);

    let verdict = classify(
        is_ostree,
        composefs_refusal,
        is_systemd,
        pid1_comm.as_deref(),
        &fields,
        has_current_system,
        usr_merge,
    );

    Ok(HostProfile {
        kind: verdict.kind,
        id: fields.id,
        id_like: fields.id_like,
        version_id: fields.version_id,
        variant_id: fields.variant_id,
        family: verdict.family,
        lsms,
        selinux,
        is_systemd,
        is_ostree,
        has_current_system,
        unsupported_reason: verdict.unsupported_reason,
        support_warning: verdict.support_warning,
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
    variant_id: Option<String>,
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
            "VARIANT_ID" => fields.variant_id = Some(value.to_ascii_lowercase()),
            _ => {}
        }
    }
    fields
}

/// Strip one layer of matching single or double quotes from an os-release value.
///
/// os-release(5) follows shell quoting: inside double quotes a backslash escapes
/// `$`, `"`, `\` and `` ` `` (and stays literal before anything else), while a
/// single-quoted value is taken verbatim.
fn unquote(value: &str) -> std::borrow::Cow<'_, str> {
    let bytes = value.as_bytes();
    if bytes.len() < 2 || bytes[bytes.len() - 1] != bytes[0] {
        return value.into();
    }
    let inner = &value[1..value.len() - 1];
    match bytes[0] {
        b'\'' => inner.into(),
        b'"' => {
            let mut out = String::with_capacity(inner.len());
            let mut chars = inner.chars().peekable();
            while let Some(c) = chars.next() {
                if c == '\\'
                    && let Some(&next) = chars.peek()
                    && matches!(next, '$' | '"' | '\\' | '`')
                {
                    out.push(next);
                    chars.next();
                } else {
                    out.push(c);
                }
            }
            out.into()
        }
        _ => value.into(),
    }
}

/// Probe whether the host uses the merged-usr layout.
///
/// Returns [`UsrMerge::NotMerged`] as soon as a core root (`/bin`, `/sbin`,
/// `/lib`) is present as a real directory rather than a symlink into `/usr`. A
/// core root that is absent or unreadable cannot prove a split layout, so it is
/// skipped — real supported hosts always carry these as symlinks.
fn probe_usr_merge<F: Filesystem>(fs: &F) -> UsrMerge {
    for dir in CORE_ROOT_DIRS {
        let path = Path::new(dir);
        let exists = fs.path_exists(path).unwrap_or(false);
        let is_symlink = fs.is_symlink(path).unwrap_or(false);
        if exists && !is_symlink {
            return UsrMerge::NotMerged;
        }
    }
    UsrMerge::Merged
}

/// What [`classify`] decides about a host.
#[derive(Debug)]
struct Verdict {
    kind: PlatformKind,
    /// Why the host is refused, when [`kind`](Self::kind) is
    /// [`PlatformKind::Unsupported`].
    unsupported_reason: Option<String>,
    /// The warning an admitted host carries: a release NAILS has not been
    /// tested on.
    support_warning: Option<String>,
    /// The FHS family the host resolved to, where one was determined. `None` for
    /// NixOS and for hosts refused before the family table is consulted.
    family: Option<Family>,
}

impl Verdict {
    fn admitted(kind: PlatformKind, support_warning: Option<String>) -> Self {
        Self {
            kind,
            unsupported_reason: None,
            support_warning,
            family: None,
        }
    }

    fn refused(reason: String) -> Self {
        Self {
            kind: PlatformKind::Unsupported,
            unsupported_reason: Some(reason),
            support_warning: None,
            family: None,
        }
    }

    /// Attach the resolved family to this verdict.
    fn with_family(mut self, family: Option<Family>) -> Self {
        self.family = family;
        self
    }
}

/// Resolve the host facts to a [`PlatformKind`] and, when unsupported, a reason.
///
/// Refusals come first: an ostree / image-based host, a composefs-native host
/// and a non-systemd PID 1 are all declined, because NAILS cannot safely lay a
/// hidden overlay over an immutable image or drive teardown without systemd. A
/// systemd host is then resolved to NixOS, a supported Debian-family release
/// (with a warning when NAILS has not been tested on that release), or a
/// documented refusal (unsupported distribution, release below the minimum, or
/// a non-merged layout).
fn classify(
    is_ostree: bool,
    composefs_refusal: Option<String>,
    is_systemd: bool,
    pid1_comm: Option<&str>,
    fields: &OsReleaseFields,
    has_current_system: bool,
    usr_merge: UsrMerge,
) -> Verdict {
    if is_ostree {
        return Verdict::refused(
            "this host is ostree / image-based (found /run/ostree-booted); \
             NAILS cannot overlay an immutable system. Use a conventional \
             mutable installation."
                .to_string(),
        );
    }

    // A sealed composefs image may not write /run/ostree-booted; refuse it here,
    // before the systemd and NixOS tests, for the same reason.
    if let Some(reason) = composefs_refusal {
        return Verdict::refused(reason);
    }

    if !is_systemd {
        let found = pid1_comm
            .filter(|comm| !comm.is_empty())
            .map(|comm| format!("found '{comm}'"))
            .unwrap_or_else(|| "PID 1's command name could not be read".to_string());
        return Verdict::refused(format!(
            "PID 1 is not systemd ({found}); NAILS requires a systemd host."
        ));
    }

    if fields.id.as_deref() == Some("nixos") || has_current_system {
        return Verdict::admitted(PlatformKind::NixOs, None);
    }

    let classification = family::classify(
        fields.id.as_deref(),
        &fields.id_like,
        fields.version_id.as_deref(),
    );
    let family = classification.family;
    let support_warning = match classification.support {
        FamilySupport::Supported => None,
        FamilySupport::Untested(warning) => Some(warning),
        FamilySupport::Refused(reason) => return Verdict::refused(reason).with_family(family),
    };
    if usr_merge == UsrMerge::NotMerged {
        return Verdict::refused(family::USR_MERGE_REFUSAL.to_string()).with_family(family);
    }
    Verdict::admitted(PlatformKind::Fhs, support_warning).with_family(family)
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
    const DEBIAN11: &str = "ID=debian\nVERSION_ID=\"11\"\n";
    const UBUNTU22: &str = "ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"22.04\"\n";
    const UBUNTU2604: &str =
        "ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"26.04\"\nPRETTY_NAME=\"Ubuntu 26.04 LTS\"\n";
    const UBUNTU2610: &str =
        "ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"26.10\"\nPRETTY_NAME=\"Ubuntu 26.10\"\n";

    #[test]
    fn nixos_by_id() {
        let profile = detect(&host(NIXOS, "systemd")).unwrap();
        assert_eq!(profile.kind, PlatformKind::NixOs);
        assert_eq!(profile.id.as_deref(), Some("nixos"));
        assert!(profile.is_systemd);
        assert_eq!(profile.support_warning, None);
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
    fn debian_12_is_refused() {
        // Below the supported minimum: its systemd cannot soft-reboot.
        let profile = detect(&host(DEBIAN12, "systemd")).unwrap();
        assert_eq!(profile.kind, PlatformKind::Unsupported);
        assert_eq!(profile.version_id.as_deref(), Some("12"));
        assert!(profile.require_supported().is_err());
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
        assert_eq!(profile.support_warning, None);
    }

    #[test]
    fn ubuntu_2604_is_a_tested_release() {
        let profile = detect(&host(UBUNTU2604, "systemd")).unwrap();
        assert_eq!(profile.kind, PlatformKind::Fhs);
        assert_eq!(profile.support_warning, None);
        profile.require_supported().unwrap();
    }

    #[test]
    fn ubuntu_2610_runs_with_a_warning_that_it_is_untested() {
        let profile = detect(&host(UBUNTU2610, "systemd")).unwrap();
        assert_eq!(profile.kind, PlatformKind::Fhs);
        assert_eq!(profile.unsupported_reason, None);
        profile.require_supported().unwrap();
        let warning = profile
            .support_warning
            .expect("26.10 is not a tested release");
        assert!(
            warning.starts_with("Ubuntu 26.10 is not a release NAILS has been tested on"),
            "{warning}"
        );
    }

    #[test]
    fn a_host_is_named_as_its_distribution_names_it() {
        let name = |os_release: &str| detect(&host(os_release, "systemd")).unwrap().name();
        assert_eq!(name(NIXOS), "NixOS 24.11");
        assert_eq!(name(UBUNTU), "Ubuntu 24.04");
        assert_eq!(name(DEBIAN13), "Debian 13");
        assert_eq!(
            name("ID=linuxmint\nID_LIKE=\"ubuntu debian\"\nVERSION_ID=\"22\"\n"),
            "linuxmint 22"
        );
        assert_eq!(name("VERSION_ID=\"1\"\n"), "this host");

        // A live generation without os-release is NixOS all the same.
        let fs = MockFilesystem::new();
        fs.mock_add_file(PID1_COMM, "systemd");
        fs.mock_set_path_type(CURRENT_SYSTEM, crate::filesystem::PathKind::Symlink);
        assert_eq!(detect(&fs).unwrap().name(), "NixOS");
    }

    #[test]
    fn a_split_usr_refuses_an_untested_release_without_its_warning() {
        let fs = host(UBUNTU2610, "systemd");
        fs.mock_set_path_type("/bin", crate::filesystem::PathKind::Dir);
        let profile = detect(&fs).unwrap();
        assert_eq!(profile.kind, PlatformKind::Unsupported);
        assert!(profile.unsupported_reason.unwrap().contains("usr-merged"));
        assert_eq!(profile.support_warning, None);
    }

    #[test]
    fn fedora_is_refused_with_documented_reason() {
        let profile = detect(&host(FEDORA, "systemd")).unwrap();
        assert_eq!(profile.kind, PlatformKind::Unsupported);
        assert_eq!(profile.family, Some(Family::Fedora));
        assert!(!profile.is_debian_like());
        let err = profile.require_supported().unwrap_err();
        assert!(
            err.to_string()
                .contains("Fedora is not yet a validated platform")
        );
    }

    #[test]
    fn arch_is_refused_with_documented_reason() {
        let profile = detect(&host(ARCH, "systemd")).unwrap();
        assert_eq!(profile.kind, PlatformKind::Unsupported);
        assert_eq!(profile.id.as_deref(), Some("arch"));
        assert_eq!(profile.family, Some(Family::Arch));
        assert!(profile.require_supported().is_err());
    }

    #[test]
    fn the_resolved_family_is_recorded_on_the_profile() {
        // The family fact is set for every host the family table resolves,
        // whether admitted or refused, and is absent for NixOS and the unknown.
        let family = |os_release: &str| detect(&host(os_release, "systemd")).unwrap().family;
        assert_eq!(family(UBUNTU), Some(Family::Debian));
        assert_eq!(family(DEBIAN13), Some(Family::Debian));
        assert_eq!(family(FEDORA), Some(Family::Fedora));
        assert_eq!(family(ARCH), Some(Family::Arch));
        assert_eq!(family(NIXOS), None);
        assert_eq!(family("ID=voidlinux\nVERSION_ID=\"rolling\"\n"), None);
    }

    #[test]
    fn variant_id_is_parsed_and_lowercased() {
        let profile = detect(&host(
            "ID=fedora\nVARIANT_ID=Workstation\nVERSION_ID=44\n",
            "systemd",
        ))
        .unwrap();
        assert_eq!(profile.variant_id.as_deref(), Some("workstation"));
        // A host that declares none carries no variant.
        assert_eq!(detect(&host(DEBIAN13, "systemd")).unwrap().variant_id, None);
    }

    #[test]
    fn security_facts_are_read_onto_the_profile() {
        use crate::platform::SelinuxMode;

        let fs = host(DEBIAN13, "systemd");
        fs.mock_set_file_content(
            "/sys/kernel/security/lsm",
            "capability,landlock,yama,apparmor",
        );
        let profile = detect(&fs).unwrap();
        assert_eq!(profile.lsms, ["capability", "landlock", "yama", "apparmor"]);
        assert_eq!(profile.selinux, None);

        let fedora = host("ID=fedora\nVERSION_ID=44\n", "systemd");
        fedora.mock_set_path_type("/sys/fs/selinux", crate::filesystem::PathKind::Dir);
        fedora.mock_set_file_content("/sys/fs/selinux/enforce", "1");
        fedora.mock_set_file_content(
            "/etc/selinux/config",
            "SELINUX=enforcing\nSELINUXTYPE=targeted\n",
        );
        let profile = detect(&fedora).unwrap();
        let selinux = profile.selinux.expect("Fedora has SELinux");
        assert_eq!(selinux.enforce, Some(SelinuxMode::Enforcing));
        assert_eq!(selinux.config_policy.as_deref(), Some("targeted"));
    }

    #[test]
    fn unknown_id_is_refused() {
        let profile = detect(&host("ID=voidlinux\nVERSION_ID=\"rolling\"\n", "systemd")).unwrap();
        assert_eq!(profile.kind, PlatformKind::Unsupported);
        assert!(profile.require_supported().is_err());
    }

    #[test]
    fn missing_os_release_id_on_systemd_is_refused() {
        // A systemd host with no identifiable ID is not NixOS and not a known
        // family, so it is declined rather than treated as a generic FHS host.
        let profile = detect(&host("PRETTY_NAME=\"Mystery Linux\"\n", "systemd")).unwrap();
        assert_eq!(profile.kind, PlatformKind::Unsupported);
        assert!(profile.require_supported().is_err());
    }

    #[test]
    fn debian_below_minimum_is_refused() {
        let profile = detect(&host(DEBIAN11, "systemd")).unwrap();
        assert_eq!(profile.kind, PlatformKind::Unsupported);
        let err = profile.require_supported().unwrap_err();
        assert!(err.to_string().contains("minimum"));
    }

    #[test]
    fn ubuntu_below_minimum_is_refused() {
        let profile = detect(&host(UBUNTU22, "systemd")).unwrap();
        assert_eq!(profile.kind, PlatformKind::Unsupported);
        assert!(profile.require_supported().is_err());
    }

    #[test]
    fn non_merged_debian_layout_is_refused() {
        // A supported release whose /bin is a real directory is not usr-merged,
        // a layout NAILS is not tested on: refuse.
        let fs = host(DEBIAN13, "systemd");
        fs.mock_set_path_type("/bin", crate::filesystem::PathKind::Dir);
        let profile = detect(&fs).unwrap();
        assert_eq!(profile.kind, PlatformKind::Unsupported);
        let err = profile.require_supported().unwrap_err();
        assert!(err.to_string().contains("usr-merged"));
    }

    #[test]
    fn merged_debian_layout_passes() {
        // Core roots present as symlinks into /usr are a merged layout.
        let fs = host(DEBIAN13, "systemd");
        for dir in ["/bin", "/sbin", "/lib"] {
            fs.mock_set_path_type(dir, crate::filesystem::PathKind::Symlink);
        }
        let profile = detect(&fs).unwrap();
        assert_eq!(profile.kind, PlatformKind::Fhs);
        profile.require_supported().unwrap();
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
    fn a_composefs_host_without_ostree_booted_is_refused_before_the_family() {
        // A sealed composefs boot writes no /run/ostree-booted; it is still
        // refused as image-based, ahead of the family verdict.
        let fs = host("ID=fedora\nVERSION_ID=44\n", "systemd");
        fs.mock_set_file_content(
            "/proc/cmdline",
            "root=composefs:fedora/x86_64 ostree=/ostree/boot.1/fedora/x/0 rw",
        );
        let profile = detect(&fs).unwrap();
        assert_eq!(profile.kind, PlatformKind::Unsupported);
        assert!(!profile.is_ostree);
        let reason = profile.unsupported_reason.unwrap();
        assert!(reason.contains("composefs"), "{reason}");
        assert!(!reason.contains("not yet a validated platform"), "{reason}");
    }

    #[test]
    fn the_composefs_runtime_directory_refuses() {
        let fs = host(DEBIAN13, "systemd");
        fs.mock_set_path_type("/run/composefs", crate::filesystem::PathKind::Dir);
        let profile = detect(&fs).unwrap();
        assert_eq!(profile.kind, PlatformKind::Unsupported);
        assert!(
            profile
                .require_supported()
                .unwrap_err()
                .to_string()
                .contains("composefs")
        );
    }

    #[test]
    fn non_systemd_pid1_refuses() {
        let profile = detect(&host(DEBIAN13, "openrc-init")).unwrap();
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
        fs.mock_add_file(OS_RELEASE, DEBIAN13);
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
        assert_eq!(unquote(r#""a \"b\" \$c \\ \x""#), r#"a "b" $c \ \x"#);
        assert_eq!(unquote(r"'a \$b'"), r"a \$b");
    }

    /// Render a value the way os-release(5) allows: bare when it holds only
    /// safe characters, otherwise double-quoted with `$ " \\ `` escaped, or
    /// single-quoted when it holds no single quote.
    fn render_os_release_value(value: &str, single: bool) -> String {
        let safe = !value.is_empty()
            && value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
        if safe {
            value.to_string()
        } else if single && !value.contains('\'') {
            format!("'{value}'")
        } else {
            let mut out = String::from("\"");
            for c in value.chars() {
                if matches!(c, '$' | '"' | '\\' | '`') {
                    out.push('\\');
                }
                out.push(c);
            }
            out.push('"');
            out
        }
    }

    proptest::proptest! {
        /// VERSION_ID and ID_LIKE survive os-release quoting and escaping.
        #[test]
        fn fuzz_os_release_values_round_trip(
            version in "[a-zA-Z0-9 .$\"'\\\\`_-]{0,16}",
            like in proptest::collection::vec("[a-z][a-z0-9]{0,6}", 0..3),
            single in proptest::bool::ANY,
        ) {
            let content = format!(
                "# generated\nNAME=\"Some Linux\"\nID=debian\nID_LIKE={}\nVERSION_ID={}\n",
                render_os_release_value(&like.join(" "), single),
                render_os_release_value(&version, single),
            );
            let fields = parse_os_release(&content);
            proptest::prop_assert_eq!(fields.id.as_deref(), Some("debian"));
            proptest::prop_assert_eq!(fields.version_id.as_deref(), Some(version.as_str()), "{}", content);
            proptest::prop_assert_eq!(fields.id_like, like);
        }

        #[test]
        fn fuzz_os_release_never_panics(text in "\\PC{0,300}") {
            let _ = parse_os_release(&text);
        }
    }
}
