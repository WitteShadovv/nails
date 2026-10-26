// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The `platform` pre-flight check: the host NAILS detected, and whether it
//! runs there.
//!
//! The check reports the [`HostProfile`] that detection gathered once for the
//! run, so `check` and activation name the same host. It passes with the
//! host's name (`Ubuntu 24.04`, or `Fedora 44 Cloud` where the edition is
//! gated too), warns on a host NAILS admits but has not been tested on (its
//! release, its edition, or a derivative) or that carries a known issue, and
//! fails on a host NAILS refuses, with the reason activation refuses it with.

use super::super::{CheckResult, PreFlightCheck};
use crate::platform::HostProfile;
use crate::{Filesystem, NailsError, Result};

/// Judge a detected host.
fn judge(profile: &HostProfile) -> CheckResult {
    if let Err(NailsError::UnsupportedPlatform { reason }) = profile.require_supported() {
        return CheckResult::fail(reason);
    }
    match &profile.support_warning {
        Some(warning) => CheckResult::Warn(warning.clone()),
        None => CheckResult::Pass(profile.name()),
    }
}

/// `platform`: the detected host is one NAILS supports, on a release it has
/// been tested on.
#[derive(Debug, Clone)]
pub struct PlatformCheck {
    profile: HostProfile,
}

impl PlatformCheck {
    /// The check over the host `profile` detection found.
    pub fn new(profile: HostProfile) -> Self {
        Self { profile }
    }
}

impl<F: Filesystem> PreFlightCheck<F> for PlatformCheck {
    fn name(&self) -> &'static str {
        "platform"
    }

    fn description(&self) -> &'static str {
        "The host is a platform NAILS supports, on a release it has been tested on"
    }

    fn run(&self, _fs: &F) -> Result<CheckResult> {
        Ok(judge(&self.profile))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MockFilesystem;
    use crate::platform::{FakePlatform, PlatformKind};

    /// What the check says about a host with this os-release.
    fn run_on(os_release: &str) -> CheckResult {
        let fs = MockFilesystem::new();
        fs.mock_set_file_content("/etc/os-release", os_release);
        fs.mock_set_file_content("/proc/1/comm", "systemd\n");
        let profile = crate::platform::detect(&fs).expect("detection reads through the mock");
        PreFlightCheck::<MockFilesystem>::run(&PlatformCheck::new(profile), &fs).unwrap()
    }

    #[test]
    fn a_tested_release_passes_with_its_name() {
        // 26.04 is tested too, but it carries a caveat and so warns rather than
        // passing clean; it is checked on its own below.
        for (os_release, name) in [
            ("ID=ubuntu\nVERSION_ID=\"24.04\"\n", "Ubuntu 24.04"),
            ("ID=debian\nVERSION_ID=\"13\"\n", "Debian 13"),
            ("ID=nixos\nVERSION_ID=\"26.05\"\n", "NixOS 26.05"),
        ] {
            let result = run_on(os_release);
            assert!(result.is_pass(), "{name}: {result:?}");
            assert_eq!(result.message(), name);
        }
    }

    #[test]
    fn a_tested_release_with_a_caveat_warns_naming_the_issue() {
        // Ubuntu 26.04 is a tested release, but a known upstream issue affects
        // it, so the platform row warns (it does not fail) and names the effect.
        let result = run_on("ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"26.04\"\n");
        assert!(result.is_warn(), "{result:?}");
        assert!(!result.is_fail(), "{result:?}");
        assert!(
            result
                .message()
                .starts_with("Ubuntu 26.04 is tested, but a known upstream issue"),
            "{result:?}"
        );
        assert!(
            result.message().contains("AppArmor blocks chrony"),
            "{result:?}"
        );
    }

    #[test]
    fn an_untested_ubuntu_release_warns_and_does_not_fail() {
        // 26.10 among them: no run of NAILS on it has passed yet.
        for release in ["26.10", "28.04"] {
            let result = run_on(&format!(
                "ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"{release}\"\n"
            ));
            assert!(result.is_warn(), "{result:?}");
            assert!(
                result.message().starts_with(&format!(
                    "Ubuntu {release} is not a release NAILS has been tested on \
                     (tested: Ubuntu 24.04 and 26.04)."
                )),
                "{result:?}"
            );
        }
    }

    #[test]
    fn a_refused_host_fails_with_the_reason_activation_gives() {
        let result = run_on("ID=fedora\nVERSION_ID=44\n");
        assert!(result.is_fail(), "{result:?}");
        assert!(
            result
                .message()
                .starts_with("Fedora is not yet a validated platform"),
            "{result:?}"
        );

        let result = run_on("ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"22.04\"\n");
        assert!(result.is_fail(), "{result:?}");
        assert!(result.message().contains("(Ubuntu 24.04)"), "{result:?}");
    }

    #[test]
    fn a_tested_edition_passes_naming_it() {
        // Fedora is refused until it is admitted; this is how its row passes
        // then.
        let mut profile = FakePlatform::fhs().host_profile();
        profile.id = Some("fedora".to_string());
        profile.version_id = Some("44".to_string());
        profile.variant_id = Some("cloud".to_string());
        let result = judge(&profile);
        assert!(result.is_pass(), "{result:?}");
        assert_eq!(result.message(), "Fedora 44 Cloud");
    }

    #[test]
    fn the_row_is_named_platform() {
        let check = PlatformCheck::new(FakePlatform::nixos().host_profile());
        assert_eq!(PreFlightCheck::<MockFilesystem>::name(&check), "platform");
        assert!(PreFlightCheck::<MockFilesystem>::description(&check).contains("tested"));
    }

    #[test]
    fn a_refused_profile_without_a_reason_still_fails() {
        let mut profile = FakePlatform::fhs().host_profile();
        profile.kind = PlatformKind::Unsupported;
        profile.unsupported_reason = None;
        let result = judge(&profile);
        assert!(result.is_fail(), "{result:?}");
        assert_eq!(result.message(), "this host is not supported by NAILS");
    }
}
