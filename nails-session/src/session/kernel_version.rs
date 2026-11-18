// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The `kernel-version` pre-flight check: the running Linux is
//! [`MIN_LINUX`] or newer.
//!
//! NAILS starts every program it runs as root with every mount `noatime`, and
//! makes the decoy's local disk mounts `noatime` while it asks PID 1 for
//! something that makes PID 1 read the decoy ([`nails_teardown::noatime`]). Both change
//! mounts with `mount_setattr(2)`, which Linux 5.12 added. NAILS supports
//! Linux 6.1, a long-term kernel, and newer. The check reads the release as
//! `uname(2)` gives it, starting no program, and refuses a release it cannot
//! read or tell the version of.

use crate::error::Result;
use crate::filesystem::Filesystem;
use crate::preflight::{CheckResult, PreFlightCheck};
pub use nails_teardown::noatime::MIN_LINUX;

/// The major and minor number of the kernel release `release`, as `uname -r`
/// prints it: `6.12.48+deb13-amd64` (Debian), `6.8.0-88-generic` (Ubuntu),
/// `6.17.7-300.fc44.x86_64` (Fedora), `6.12.58` (NixOS), `6.13.0-rc3` or
/// `6.1-rc1` (a release candidate, of the version it leads to). `None` for a
/// release that does not start with two numbers, a dot between them, and
/// after the second one its end or a `.`, `-`, `+` or `_`.
pub fn parse_release(release: &str) -> Option<(u32, u32)> {
    let (major, rest) = release.trim().split_once('.')?;
    let minor_len = rest.bytes().take_while(u8::is_ascii_digit).count();
    let (minor, tail) = rest.split_at(minor_len);
    let digits = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
    let ends = tail.is_empty() || tail.starts_with(['.', '-', '+', '_']);
    if !(digits(major) && digits(minor) && ends) {
        return None;
    }
    Some((major.parse().ok()?, minor.parse().ok()?))
}

/// Judge the running kernel's release `release` (`None`: it could not be
/// read): one older than [`MIN_LINUX`], or one whose version cannot be told,
/// fails, naming the release and the floor.
pub fn judge_release(release: Option<&str>) -> CheckResult {
    let (major, minor) = MIN_LINUX;
    let why = format!(
        "NAILS needs Linux {major}.{minor} or newer: it keeps the programs it starts and \
         PID 1 from changing access times on the decoy with mount_setattr (Linux 5.12)"
    );
    let boot = format!(
        "Boot a kernel of Linux {major}.{minor} or newer, as every release NAILS supports \
         ships by default"
    );
    let Some(release) = release.map(str::trim).filter(|release| !release.is_empty()) else {
        return CheckResult::fail_with(
            "could not read the running kernel's release",
            format!("{why}. {boot}."),
        );
    };
    match parse_release(release) {
        Some(version) if version >= MIN_LINUX => {
            CheckResult::Pass(format!("Linux {release} ({major}.{minor} or newer)"))
        }
        Some(_) => CheckResult::fail_with(
            format!("Linux {release} is older than {major}.{minor}"),
            format!("{why}. This kernel is {release}. {boot}."),
        ),
        None => CheckResult::fail_with(
            format!("cannot tell the version of the running kernel's release {release:?}"),
            format!("{why}. This kernel is {release:?}. {boot}."),
        ),
    }
}

/// The running kernel's release, as `uname(2)` gives it: `None` where it is
/// not UTF-8.
fn running_release() -> Option<String> {
    rustix::system::uname()
        .release()
        .to_str()
        .ok()
        .map(str::to_string)
}

/// `kernel-version`: the running Linux is [`MIN_LINUX`] or newer.
#[derive(Debug, Default)]
pub struct KernelVersionCheck {
    /// The release to judge in place of the running kernel's, for the tests:
    /// `Some(None)` judges a release that could not be read.
    release: Option<Option<String>>,
}

impl KernelVersionCheck {
    /// The check of the running kernel.
    pub fn new() -> Self {
        Self::default()
    }

    /// The check of a kernel whose release reads as `release` (`None`: it
    /// could not be read).
    pub fn of(release: Option<&str>) -> Self {
        Self {
            release: Some(release.map(str::to_string)),
        }
    }
}

impl<F: Filesystem> PreFlightCheck<F> for KernelVersionCheck {
    fn name(&self) -> &'static str {
        "kernel-version"
    }
    fn description(&self) -> &'static str {
        "The running Linux is 6.1 or newer"
    }
    fn run(&self, _fs: &F) -> Result<CheckResult> {
        let release = match &self.release {
            Some(release) => release.clone(),
            None => running_release(),
        };
        Ok(judge_release(release.as_deref()))
    }
}

#[cfg(test)]
#[path = "kernel_version_tests.rs"]
mod tests;
