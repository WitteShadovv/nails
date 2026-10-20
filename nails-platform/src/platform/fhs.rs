// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The FHS backend: systemd hosts laid out on the Filesystem Hierarchy
//! Standard.
//!
//! Debian 13 (trixie), Ubuntu 24.04 and Ubuntu 26.04 are the tested targets; a
//! later Debian or Ubuntu release runs here too, with a warning that it is
//! untested, and a derivative whose `ID_LIKE` names `debian` or `ubuntu` is
//! accepted provisionally. Every other family (Fedora, Arch, unknown IDs) is
//! refused at detection and never reaches this backend. The hidden
//! configuration is whatever the root upper's `/etc` holds, so the backend has
//! no config layer.

use super::{Platform, PlatformKind};
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
}
