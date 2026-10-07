// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The FHS backend: systemd hosts laid out on the Filesystem Hierarchy
//! Standard.
//!
//! Debian 13 (trixie) and Ubuntu 24.04 are the validated targets; other FHS,
//! systemd distributions with systemd 254 or newer fall here too. The hidden
//! configuration is whatever the root upper's `/etc` holds, so the backend has
//! no config layer.

use super::{ArtifactScanner, DebianPackageDriftScanner, Platform, PlatformKind};
use crate::filesystem::Filesystem;

/// Directories an FHS host exposes host tools under.
const FHS_COMMAND_DIRS: &[&str] = &["/usr/sbin", "/usr/bin", "/sbin", "/bin"];

/// Backend for systemd FHS hosts (Debian/Ubuntu first).
#[derive(Debug, Clone, Copy, Default)]
pub struct FhsPlatform;

impl<F: Filesystem> Platform<F> for FhsPlatform {
    fn kind(&self) -> PlatformKind {
        PlatformKind::Fhs
    }

    fn host_command_dirs(&self) -> &'static [&'static str] {
        FHS_COMMAND_DIRS
    }

    fn artifact_scanners(&self) -> Vec<Box<dyn ArtifactScanner<F>>>
    where
        F: 'static,
    {
        // Self-gating: on a non-Debian FHS host the apt/dpkg databases do not
        // exist, so the scan finds nothing to compare and reports nothing.
        vec![Box::new(DebianPackageDriftScanner)]
    }
}
