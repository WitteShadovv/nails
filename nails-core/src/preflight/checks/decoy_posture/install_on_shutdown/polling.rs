// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! A decoy whose shutdown helper of unattended-upgrades starts without
//! python3-gi.
//!
//! The helper waits for logind's shutdown signal through GLib, which
//! python3-gi brings; unattended-upgrades only suggests it, and Debian 13's
//! cloud image does not install it. Without it the helper polls for the
//! signal, and each time it starts it writes two WARNING lines to its log on
//! the decoy disk, `Unable to monitor PrepareForShutdown() signal, polling
//! instead.` and that python3-gi would let it wait. The decoy starts its
//! enabled helper again at every way back to it, so each one adds a pair,
//! dated at the switch. That is warned about, with the fix: install
//! python3-gi.
//!
//! The module the helper imports is looked up where python3-gi installs it;
//! nothing is read or written.

use super::super::{Enabled, unit_enabled};
use super::UNIT;
use crate::Filesystem;
use std::path::Path;

/// Where python3-gi puts the module the helper imports to wait for logind's
/// signal, relative to the root.
const GI_MODULE: &str = "usr/lib/python3/dist-packages/gi/__init__.py";

/// The warning of a decoy whose helper is enabled while python3-gi is
/// missing, `None` otherwise. Without python3-gi the helper cannot wait for
/// logind's signal: each time it starts it writes two WARNING lines to its
/// log on the decoy disk, that it polls instead and that python3-gi would
/// let it wait, so every way back to the decoy, which starts it again, adds
/// a pair dated at the switch. The module is looked up, not read.
pub(super) fn warning<F: Filesystem>(fs: &F, root: &Path) -> Option<String> {
    let untold = match unit_enabled(fs, root, UNIT) {
        Enabled::Yes => None,
        Enabled::No => return None,
        Enabled::Untold(why) => Some(why),
    };
    let lines = "it writes two WARNING lines to /var/log/unattended-upgrades/\
                 unattended-upgrades-shutdown.log on the decoy disk each time it starts, that it \
                 polls for logind's shutdown signal instead of waiting for it, so every way back \
                 to the decoy adds a pair dated at the switch";
    let fix = "apt install python3-gi";
    let gi = fs.is_regular_file(&root.join(GI_MODULE));
    // A helper NAILS cannot tell is enabled warns where python3-gi may be
    // missing.
    if let Some(why) = untold {
        return match gi {
            Ok(true) => None,
            Ok(false) => Some(format!(
                "{why}, and python3-gi is not installed (no /{GI_MODULE}): if {UNIT} is enabled, \
                 {lines} ({fix})"
            )),
            Err(e) => Some(format!(
                "{why}, and whether python3-gi is installed (/{GI_MODULE} cannot be looked up: \
                 {e}): if {UNIT} is enabled without python3-gi, {lines} ({fix})"
            )),
        };
    }
    match gi {
        Ok(true) => None,
        Ok(false) => Some(format!(
            "{UNIT} is enabled on the decoy and python3-gi is not installed (no /{GI_MODULE}): \
             {lines} ({fix})"
        )),
        Err(e) => Some(format!(
            "{UNIT} is enabled on the decoy and NAILS cannot tell whether python3-gi is \
             installed (/{GI_MODULE} cannot be looked up: {e}); without it {lines} ({fix})"
        )),
    }
}

#[cfg(test)]
#[path = "polling_tests.rs"]
pub(super) mod tests;
