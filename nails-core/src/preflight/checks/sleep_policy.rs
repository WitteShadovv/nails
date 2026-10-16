// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Suspend/hibernate exposure detection
//!
//! Parses the effective systemd-logind lid-switch and idle settings and warns
//! when the host would put an *active* hidden session to sleep. Suspending (or
//! hibernating) while the hidden environment is up leaves its overlays, dm-crypt
//! mapper and master key resident in RAM behind the hidden session's own lock
//! screen (the decoy is not running), and whoever unlocks that screen on resume
//! is in the live hidden session. It also warns when a closed lid is set to
//! `ignore`: the host stays awake, but the session stays unlocked behind the
//! lid.
//!
//! # Security
//!
//! This check never fails activation — a suspend risk is a standing hazard the
//! operator may have already mitigated at the hardware or desktop level, and the
//! runtime [`sleep_policy`](crate::config::SleepPolicyConfig) modes
//! (`block`/`teardown`) exist precisely to handle it. It only reports the
//! effective lid/idle settings so the operator knows whether closing the lid or
//! walking away will strand a live session. Nothing here writes to the decoy.

use super::systemd_conf::{self, Assignment};
use crate::config::SleepPolicyMode;
use crate::preflight::{CheckResult, PreFlightCheck};
use crate::{Filesystem, Result};
use std::path::Path;

/// logind's configuration name, resolved with its drop-ins by [`systemd_conf`].
const LOGIND_CONF: &str = "logind.conf";
/// The section logind reads these settings from.
const LOGIN_SECTION: &str = "Login";

/// Every value logind accepts for a `Handle*=`/`IdleAction=` setting. Anything
/// else is rejected by logind with a warning and leaves the previous value.
const HANDLE_ACTIONS: &[&str] = &[
    "ignore",
    "poweroff",
    "reboot",
    "halt",
    "kexec",
    "soft-reboot",
    "suspend",
    "hibernate",
    "hybrid-sleep",
    "suspend-then-hibernate",
    "sleep",
    "lock",
    "factory-reset",
    "secure-attention-key",
];

/// The effective logind settings that decide whether an active session is put to
/// sleep.
///
/// Each field is the raw value last assigned across the main file and its
/// drop-ins, or `None` when never set (so logind's built-in default applies). The
/// accessor methods fold in those defaults.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogindSleepSettings {
    /// `HandleLidSwitch`: action on lid close when on battery / not externally
    /// powered. logind default: `suspend`.
    pub handle_lid_switch: Option<String>,
    /// `HandleLidSwitchExternalPower`: action on lid close when on external
    /// power. logind default: unset, so the `HandleLidSwitch` action applies.
    pub handle_lid_switch_external_power: Option<String>,
    /// `HandleLidSwitchDocked`: action on lid close when docked / with an
    /// external monitor. logind default: `ignore`.
    pub handle_lid_switch_docked: Option<String>,
    /// `IdleAction`: action after `IdleActionSec` of inactivity. logind default:
    /// `ignore`.
    pub idle_action: Option<String>,
    /// `IdleActionSec`: idle timeout before `IdleAction` fires. Reported verbatim.
    pub idle_action_sec: Option<String>,
}

impl LogindSleepSettings {
    /// Effective lid-close action on battery (default `suspend`).
    pub fn effective_lid_switch(&self) -> &str {
        self.handle_lid_switch.as_deref().unwrap_or("suspend")
    }

    /// Effective lid-close action on external power.
    ///
    /// logind ignores this setting unless it is assigned: unset, a closed lid on
    /// external power does what [`Self::effective_lid_switch`] says.
    pub fn effective_lid_switch_external_power(&self) -> &str {
        self.handle_lid_switch_external_power
            .as_deref()
            .unwrap_or_else(|| self.effective_lid_switch())
    }

    /// Effective lid-close action when docked (default `ignore`).
    pub fn effective_lid_switch_docked(&self) -> &str {
        self.handle_lid_switch_docked.as_deref().unwrap_or("ignore")
    }

    /// Effective idle action (default `ignore`).
    pub fn effective_idle_action(&self) -> &str {
        self.idle_action.as_deref().unwrap_or("ignore")
    }

    /// Whether a closed lid sends the machine to sleep in any of the three
    /// cases logind tells apart (on battery, on external power, docked or
    /// with an external display). The sleep guard's `block` mode then takes
    /// the lid switch from logind.
    pub fn lid_switch_sleeps(&self) -> bool {
        [
            self.effective_lid_switch(),
            self.effective_lid_switch_external_power(),
            self.effective_lid_switch_docked(),
        ]
        .into_iter()
        .any(action_sleeps)
    }
}

/// Whether a logind `Handle*`/`IdleAction` value sends the machine to sleep.
///
/// These are the actions that keep the session in RAM: ordinary suspend,
/// hibernate, hybrid-sleep, suspend-then-hibernate and `sleep` (whichever sleep
/// mode the host supports). `poweroff`/`halt` clear
/// RAM, and `lock`/`ignore` keep the machine awake, so none of those strand a
/// live session.
pub fn action_sleeps(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "suspend" | "hibernate" | "hybrid-sleep" | "suspend-then-hibernate" | "sleep"
    )
}

/// Apply one `[Login]` assignment to `settings`.
///
/// Keys match case-sensitively, as logind does. A `Handle*=`/`IdleAction=`
/// value logind would reject leaves the previous value in place, and logind
/// rejects an empty one too: unlike most systemd settings these do not reset
/// to the default. `IdleActionSec=` is kept verbatim, and an empty one resets it.
fn apply_logind(settings: &mut LogindSleepSettings, assignment: &Assignment) {
    let field = match assignment.key.as_str() {
        "HandleLidSwitch" => &mut settings.handle_lid_switch,
        "HandleLidSwitchExternalPower" => &mut settings.handle_lid_switch_external_power,
        "HandleLidSwitchDocked" => &mut settings.handle_lid_switch_docked,
        "IdleAction" => &mut settings.idle_action,
        "IdleActionSec" => {
            settings.idle_action_sec =
                Some(assignment.value.clone()).filter(|value| !value.is_empty());
            return;
        }
        _ => return,
    };
    let value = assignment.value.as_str();
    if HANDLE_ACTIONS.contains(&value) {
        *field = Some(value.to_string());
    }
}

/// Merge one logind configuration text into `settings`.
///
/// Only the `[Login]` section counts and the syntax follows systemd (see
/// [`systemd_conf`]). Applying the main file and then each drop-in this way is
/// equivalent to reading them concatenated: the last assignment wins.
pub fn parse_logind_sleep(config_text: &str, settings: &mut LogindSleepSettings) {
    let mut assignments = Vec::new();
    let _ = systemd_conf::parse_section(config_text, LOGIN_SECTION, &mut assignments);
    for assignment in &assignments {
        apply_logind(settings, assignment);
    }
}

/// Read the effective logind sleep settings, resolving the main `logind.conf`
/// and every drop-in the way systemd does (see [`systemd_conf`]). Settings
/// nothing assigns keep logind's built-in defaults, which the accessors supply.
pub fn effective_logind_sleep<F: Filesystem>(fs: &F) -> LogindSleepSettings {
    effective_logind_sleep_at(fs, Path::new("/"))
}

/// [`effective_logind_sleep`] for the system tree rooted at `root`.
pub fn effective_logind_sleep_at<F: Filesystem>(fs: &F, root: &Path) -> LogindSleepSettings {
    let mut settings = LogindSleepSettings::default();
    for assignment in systemd_conf::section_assignments(fs, root, LOGIND_CONF, LOGIN_SECTION) {
        apply_logind(&mut settings, &assignment);
    }
    settings
}

/// Pre-flight check that reports whether the host would suspend an active session.
///
/// Carries the configured [`SleepPolicyMode`] so the warning names the mitigation
/// already in effect (`block`/`teardown`) or recommends one (`warn`).
pub struct SleepPolicyCheck {
    mode: SleepPolicyMode,
}

impl SleepPolicyCheck {
    /// Build the check for the configured sleep-policy mode.
    pub fn new(mode: SleepPolicyMode) -> Self {
        Self { mode }
    }

    /// The ways the effective settings would put an active session to sleep.
    fn sleep_risks(settings: &LogindSleepSettings) -> Vec<String> {
        let mut risks = Vec::new();
        if action_sleeps(settings.effective_lid_switch()) {
            risks.push(format!(
                "closing the lid suspends the host (HandleLidSwitch={})",
                settings.effective_lid_switch()
            ));
        }
        // Unset, the external-power case follows HandleLidSwitch, which the
        // line above already reports.
        if let Some(external) = settings.handle_lid_switch_external_power.as_deref()
            && action_sleeps(external)
        {
            risks.push(format!(
                "closing the lid on external power suspends the host \
                 (HandleLidSwitchExternalPower={external})"
            ));
        }
        // Unset, the docked case ignores the lid, so only an assignment counts.
        if action_sleeps(settings.effective_lid_switch_docked()) {
            risks.push(format!(
                "closing the lid while docked suspends the host (HandleLidSwitchDocked={})",
                settings.effective_lid_switch_docked()
            ));
        }
        if action_sleeps(settings.effective_idle_action()) {
            let idle = match &settings.idle_action_sec {
                Some(sec) => format!(
                    "IdleAction={}, IdleActionSec={sec}",
                    settings.effective_idle_action()
                ),
                None => format!("IdleAction={}", settings.effective_idle_action()),
            };
            risks.push(format!("idle inactivity suspends the host ({idle})"));
        }
        risks
    }

    /// The lid settings that leave an active session running and unlocked
    /// behind a closed lid: `ignore` on battery, or on external power when
    /// assigned there (unset, it follows the battery case, reported already).
    /// The docked case is left out: the session then shows on the external
    /// display.
    fn unlocked_lid(settings: &LogindSleepSettings) -> Vec<String> {
        let mut out = Vec::new();
        if settings.effective_lid_switch() == "ignore" {
            out.push("HandleLidSwitch=ignore".to_string());
        }
        if settings.handle_lid_switch_external_power.as_deref() == Some("ignore") {
            out.push("HandleLidSwitchExternalPower=ignore".to_string());
        }
        out
    }

    /// The warning about the sleep risks, worded for the configured mode.
    fn sleep_warning(&self, settings: &LogindSleepSettings, risks: &[String]) -> String {
        let findings = risks.join("; ");
        match self.mode {
            SleepPolicyMode::Warn => format!(
                "the host would suspend an active session: {findings}. A suspend leaves the \
                 hidden session resident in RAM behind the hidden session's own lock screen. \
                 Set the logind lid switch to lock (see docs/decoy-requirements.md), or set \
                 sleep_policy.mode = \"block\" or \"teardown\" in nails.toml."
            ),
            SleepPolicyMode::Block if settings.lid_switch_sleeps() => format!(
                "the host would suspend an active session: {findings}. sleep_policy.mode = \
                 \"block\" holds sleep and idle inhibitors and takes the lid switch from logind \
                 for the session, so the host stays awake while it is active, but a closed lid \
                 then does nothing, not even lock the screen. Set the logind lid switch to lock \
                 (see docs/decoy-requirements.md)."
            ),
            SleepPolicyMode::Block => format!(
                "the host would suspend an active session: {findings}. sleep_policy.mode = \
                 \"block\" holds sleep and idle inhibitors for the session, so the host stays \
                 awake while it is active."
            ),
            SleepPolicyMode::Teardown => format!(
                "the host would suspend an active session: {findings}. sleep_policy.mode = \
                 \"teardown\" runs the bounded emergency teardown when the host is about to \
                 sleep; a teardown is destructive to the live session, so confirm the logind \
                 delay window (InhibitDelayMaxSec) is long enough (see docs/decoy-requirements.md)."
            ),
        }
    }
}

/// The warning about a closed lid that leaves the session unlocked. No
/// `sleep_policy.mode` changes it: none of them acts on a lid that does not
/// sleep.
fn unlocked_warning(settings: &LogindSleepSettings, unlocked: &[String]) -> String {
    let when = if settings.effective_lid_switch() == "ignore" {
        "a closed lid"
    } else {
        "a closed lid on external power"
    };
    format!(
        "{when} leaves the active session running and unlocked ({}): whoever opens the lid is \
         in the hidden session. Set the logind lid switch to lock (see \
         docs/decoy-requirements.md).",
        unlocked.join(", ")
    )
}

/// `text` with its first letter in upper case, to start a sentence.
fn sentence(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

impl<F: Filesystem> PreFlightCheck<F> for SleepPolicyCheck {
    fn name(&self) -> &'static str {
        "sleep-policy"
    }

    fn description(&self) -> &'static str {
        "Reports whether the host would suspend an active hidden session or leave it unlocked \
         behind a closed lid"
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        let settings = effective_logind_sleep(fs);
        let risks = Self::sleep_risks(&settings);
        let unlocked = Self::unlocked_lid(&settings);

        if risks.is_empty() && unlocked.is_empty() {
            return Ok(CheckResult::Pass(format!(
                "host will not suspend an active session (HandleLidSwitch={}, IdleAction={})",
                settings.effective_lid_switch(),
                settings.effective_idle_action()
            )));
        }

        let mut message = if risks.is_empty() {
            String::new()
        } else {
            self.sleep_warning(&settings, &risks)
        };
        if !unlocked.is_empty() {
            let warning = unlocked_warning(&settings, &unlocked);
            if message.is_empty() {
                message = warning;
            } else {
                message.push(' ');
                message.push_str(&sentence(&warning));
            }
        }
        Ok(CheckResult::Warn(message))
    }
}

#[cfg(test)]
mod tests;
