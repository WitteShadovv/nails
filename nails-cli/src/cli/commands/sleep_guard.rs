// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Hidden `sleep-guard` command: hold a logind inhibitor for the session.
//!
//! Not an operator-facing command. It runs from the RAM-backed runtime copy as
//! a runtime unit of the hidden session (installed in `/run` by the entry
//! transition) when `sleep_policy.mode` is `block` or `teardown`, and runs for
//! the life of the session. In `teardown` mode an imminent sleep powers the
//! machine off instead: a session kept in RAM behind a lock screen is what the
//! policy exists to prevent. It is marked `hide = true` so it never
//! appears in help, and it reads its configuration from the `/run` copy so it
//! keeps working even after the hidden volume is gone. A copy that is there
//! but cannot be read leaves the mode untold: the guard then does what both
//! modes do ([`sleep_guard::run_untold_guard`]).

use std::path::Path;

use nails_core::config::{Config, SleepPolicyMode};
use nails_core::preflight::checks::sleep_policy::effective_logind_sleep;
use nails_core::sleep_guard::LidSwitch;
use nails_core::{NailsError, RealFilesystem, runtime_copy, sleep_guard};

use crate::cli::output::{ExitStatus, OutputSettings};

/// What the guard guards by.
#[derive(Debug)]
enum Guarding {
    /// The mode the settings name.
    Mode(SleepPolicyMode),
    /// The settings copy is there but cannot be read, for this reason: the
    /// mode the operator chose, `block` or `teardown` (the guard runs for no
    /// other), cannot be told.
    Untold(NailsError),
}

/// What the guard guards by, from what reading the settings copy in `/run`
/// gave: the copy's mode, or without a copy the mode of `fallback`, the
/// configuration file or the defaults; a copy that is there but cannot be
/// read leaves the mode untold.
fn guarding(
    copy: nails_core::Result<Option<Config>>,
    fallback: impl FnOnce() -> Config,
) -> Guarding {
    match copy {
        Ok(Some(config)) => Guarding::Mode(config.sleep_policy.mode),
        Ok(None) => Guarding::Mode(fallback().sleep_policy.mode),
        Err(e) => Guarding::Untold(e),
    }
}

/// Execute the sleep guard.
///
/// Reads the mirrored configuration from the `/run` copy, then holds the logind
/// inhibitors the configured mode calls for: in `block` mode the lid switch's
/// too when the session's logind would sleep on a closed lid. In `teardown`
/// mode the guard runs the bounded emergency teardown and powers the machine
/// off when the host is about to sleep. When the copy is there but cannot be
/// read, it holds `block`'s inhibitors, and powers the machine off if a sleep
/// starts anyway, as `teardown` does.
///
/// Always exits [`ExitStatus::Ok`]: like the backend watcher, this is a
/// best-effort safety net, so a missing copy or an unreachable bus is a logged
/// no-op rather than an error dialog.
pub fn execute(
    _settings: &OutputSettings,
    env: &nails_core::RuntimeEnv,
    config_override: Option<&Path>,
) -> ExitStatus {
    let filesystem = RealFilesystem;

    // Prefer the configuration mirrored into the runtime copy; the real config
    // file lives on the hidden volume, which a teardown may be racing against.
    let guarding = guarding(runtime_copy::read_config_copy(&filesystem), || {
        super::load_config_or_defaults(config_override).into_config()
    });
    match &guarding {
        Guarding::Mode(mode) if !mode.runs_guard() => {
            tracing::debug!("Sleep policy runs no guard; exiting");
            return ExitStatus::Ok;
        }
        Guarding::Mode(_) => {}
        Guarding::Untold(e) => tracing::warn!(
            error = %e,
            "Could not read the session's settings; holding the block inhibitors, and powering \
             off if a sleep starts anyway"
        ),
    }

    // The session's own logind configuration decides whether a closed lid
    // would sleep, and so whether `block` takes the lid switch from logind.
    let lid = if effective_logind_sleep(&filesystem).lid_switch_sleeps() {
        LidSwitch::Take
    } else {
        LidSwitch::Leave
    };

    tracing::info!(?guarding, ?lid, "Sleep guard started");

    let _ = env;
    let on_prepare_for_sleep = || {
        tracing::warn!("The host is about to sleep; powering off instead");
        super::emergency::run_hot_path_with(
            nails_teardown::whole_root::emergency::Finish::Poweroff,
        );
    };

    let guarded = match guarding {
        Guarding::Mode(mode) => sleep_guard::run_guard(mode, lid, on_prepare_for_sleep),
        Guarding::Untold(_) => sleep_guard::run_untold_guard(lid, on_prepare_for_sleep),
    };
    if let Err(e) = guarded {
        tracing::warn!(error = %e, "Sleep guard exiting; the session runs without sleep protection");
    }

    ExitStatus::Ok
}

#[cfg(test)]
mod tests {
    use super::*;

    fn in_mode(mode: SleepPolicyMode) -> Config {
        let mut config = Config::test_default();
        config.sleep_policy.mode = mode;
        config
    }

    /// The copy's mode decides; without a copy the file or the defaults do,
    /// as before.
    #[test]
    fn the_copy_decides_and_without_one_the_fallback_does() {
        for mode in [
            SleepPolicyMode::Warn,
            SleepPolicyMode::Block,
            SleepPolicyMode::Teardown,
        ] {
            let read = guarding(Ok(Some(in_mode(mode))), || {
                panic!("no fallback when the copy is read")
            });
            assert!(matches!(read, Guarding::Mode(m) if m == mode), "{read:?}");
            let none = guarding(Ok(None), || in_mode(mode));
            assert!(matches!(none, Guarding::Mode(m) if m == mode), "{none:?}");
        }
    }

    /// A copy that is there but cannot be read leaves the mode untold, never
    /// the defaults' warn-only mode, which runs no guard at all.
    #[test]
    fn a_copy_that_cannot_be_read_leaves_the_mode_untold() {
        let error = NailsError::io(
            runtime_copy::config_copy_path(),
            std::io::Error::from_raw_os_error(nix::libc::EIO),
        );
        let untold = guarding(Err(error), || panic!("not the defaults"));
        let Guarding::Untold(error) = untold else {
            panic!("{untold:?}");
        };
        assert!(
            error
                .to_string()
                .contains(&runtime_copy::config_copy_path().display().to_string()),
            "{error}"
        );
    }
}
