// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Suspend/hibernate exposure detection
//!
//! Parses the effective systemd-logind lid-switch and idle settings and warns
//! when the host would put an *active* hidden session to sleep. Suspending (or
//! hibernating) while the hidden environment is up leaves its overlays, dm-crypt
//! mapper and master key resident in RAM behind the decoy lock screen; on resume
//! the decoy login unlocks a still-live hidden session.
//!
//! # Security
//!
//! This check never fails activation — a suspend risk is a standing hazard the
//! operator may have already mitigated at the hardware or desktop level, and the
//! runtime [`sleep_policy`](crate::config::SleepPolicyConfig) modes
//! (`block`/`teardown`) exist precisely to handle it. It only reports the
//! effective lid/idle settings so the operator knows whether closing the lid or
//! walking away will strand a live session. Nothing here writes to the decoy.

use crate::config::SleepPolicyMode;
use crate::preflight::{CheckResult, PreFlightCheck};
use crate::{Filesystem, Result};
use std::path::Path;

/// Main logind configuration file.
const LOGIND_CONF: &str = "/etc/systemd/logind.conf";
/// Drop-in directory whose `*.conf` fragments override the main file.
const LOGIND_CONF_D: &str = "/etc/systemd/logind.conf.d";

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
    /// power. logind default: `suspend`.
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

    /// Effective lid-close action on external power (default `suspend`).
    pub fn effective_lid_switch_external_power(&self) -> &str {
        self.handle_lid_switch_external_power
            .as_deref()
            .unwrap_or("suspend")
    }

    /// Effective lid-close action when docked (default `ignore`).
    pub fn effective_lid_switch_docked(&self) -> &str {
        self.handle_lid_switch_docked.as_deref().unwrap_or("ignore")
    }

    /// Effective idle action (default `ignore`).
    pub fn effective_idle_action(&self) -> &str {
        self.idle_action.as_deref().unwrap_or("ignore")
    }
}

/// Whether a logind `Handle*`/`IdleAction` value sends the machine to sleep.
///
/// These are the actions that keep the session in RAM: ordinary suspend,
/// hibernate, hybrid-sleep and suspend-then-hibernate. `poweroff`/`halt` clear
/// RAM, and `lock`/`ignore` keep the machine awake, so none of those strand a
/// live session.
pub fn action_sleeps(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "suspend" | "hibernate" | "hybrid-sleep" | "suspend-then-hibernate"
    )
}

/// Merge one logind configuration fragment into `settings`.
///
/// systemd concatenates the main file and its drop-ins with the last assignment
/// winning, so this overwrites a field every time it sees a recognised key. Keys
/// are matched case-insensitively; full-line `#`/`;` comments and lines without an
/// assignment are ignored. Section headers are ignored: these keys only appear
/// under `[Login]`, and matching the key alone keeps the parser simple without
/// risking a false negative. systemd `.conf` files have no trailing inline
/// comments, so the whole right-hand side is the value.
pub fn parse_logind_sleep(config_text: &str, settings: &mut LogindSleepSettings) {
    for raw in config_text.lines() {
        let line = raw.trim();
        if line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim().to_string();
        let key = key.trim();
        if key.eq_ignore_ascii_case("HandleLidSwitch") {
            settings.handle_lid_switch = Some(value);
        } else if key.eq_ignore_ascii_case("HandleLidSwitchExternalPower") {
            settings.handle_lid_switch_external_power = Some(value);
        } else if key.eq_ignore_ascii_case("HandleLidSwitchDocked") {
            settings.handle_lid_switch_docked = Some(value);
        } else if key.eq_ignore_ascii_case("IdleAction") {
            settings.idle_action = Some(value);
        } else if key.eq_ignore_ascii_case("IdleActionSec") {
            settings.idle_action_sec = Some(value);
        }
    }
}

/// Read the effective logind sleep settings from the main file and its `*.conf`
/// drop-ins.
///
/// The main file is read first, then every `*.conf` under
/// [`LOGIND_CONF_D`] in lexical order (systemd's drop-in order), each applied
/// over the previous so the last assignment wins. A missing or unreadable file
/// leaves logind's built-in defaults, which the accessors supply.
pub fn effective_logind_sleep<F: Filesystem>(fs: &F) -> LogindSleepSettings {
    let mut settings = LogindSleepSettings::default();

    if let Ok(text) = fs.read_file_content(Path::new(LOGIND_CONF)) {
        parse_logind_sleep(&text, &mut settings);
    }

    if let Ok(mut entries) = fs.list_directory(Path::new(LOGIND_CONF_D)) {
        entries.retain(|p| p.extension().is_some_and(|ext| ext == "conf"));
        entries.sort();
        for entry in entries {
            if let Ok(text) = fs.read_file_content(&entry) {
                parse_logind_sleep(&text, &mut settings);
            }
        }
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
        if action_sleeps(settings.effective_lid_switch_external_power()) {
            risks.push(format!(
                "closing the lid on external power suspends the host \
                 (HandleLidSwitchExternalPower={})",
                settings.effective_lid_switch_external_power()
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
}

impl<F: Filesystem> PreFlightCheck<F> for SleepPolicyCheck {
    fn name(&self) -> &'static str {
        "sleep-policy"
    }

    fn description(&self) -> &'static str {
        "Reports whether the host would suspend an active hidden session"
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        let settings = effective_logind_sleep(fs);
        let risks = Self::sleep_risks(&settings);

        if risks.is_empty() {
            return Ok(CheckResult::Pass(format!(
                "host will not suspend an active session (HandleLidSwitch={}, IdleAction={})",
                settings.effective_lid_switch(),
                settings.effective_idle_action()
            )));
        }

        let findings = risks.join("; ");
        let message = match self.mode {
            SleepPolicyMode::Warn => format!(
                "the host would suspend an active session: {findings}. A suspend leaves the \
                 hidden session resident in RAM behind the decoy lock screen. Set the logind lid \
                 switch to ignore/lock (see docs/decoy-requirements.md), or set \
                 sleep_policy.mode = \"block\" or \"teardown\" in nails.toml."
            ),
            SleepPolicyMode::Block => format!(
                "the host would suspend an active session: {findings}. sleep_policy.mode = \
                 \"block\" holds a sleep inhibitor for the session, so this is prevented while \
                 active; the inhibitor is best-effort, so also set the logind lid switch to \
                 ignore/lock (see docs/decoy-requirements.md)."
            ),
            SleepPolicyMode::Teardown => format!(
                "the host would suspend an active session: {findings}. sleep_policy.mode = \
                 \"teardown\" runs the bounded emergency teardown when the host is about to \
                 sleep; a teardown is destructive to the live session, so confirm the logind \
                 delay window (InhibitDelayMaxSec) is long enough (see docs/decoy-requirements.md)."
            ),
        };
        Ok(CheckResult::Warn(message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::MockFilesystem;
    use std::path::PathBuf;

    #[test]
    fn parses_lid_and_idle_keys_case_insensitively() {
        let mut settings = LogindSleepSettings::default();
        parse_logind_sleep(
            "[Login]\nhandlelidswitch=ignore\nIdleAction=suspend\nIdleActionSec=600\n",
            &mut settings,
        );
        assert_eq!(settings.handle_lid_switch.as_deref(), Some("ignore"));
        assert_eq!(settings.idle_action.as_deref(), Some("suspend"));
        assert_eq!(settings.idle_action_sec.as_deref(), Some("600"));
    }

    #[test]
    fn ignores_comments_and_last_assignment_wins() {
        let mut settings = LogindSleepSettings::default();
        parse_logind_sleep(
            "#HandleLidSwitch=ignore\nHandleLidSwitch=suspend\nHandleLidSwitch=lock\n",
            &mut settings,
        );
        assert_eq!(settings.handle_lid_switch.as_deref(), Some("lock"));
    }

    #[test]
    fn effective_defaults_apply_when_unset() {
        let settings = LogindSleepSettings::default();
        assert_eq!(settings.effective_lid_switch(), "suspend");
        assert_eq!(settings.effective_lid_switch_external_power(), "suspend");
        assert_eq!(settings.effective_lid_switch_docked(), "ignore");
        assert_eq!(settings.effective_idle_action(), "ignore");
    }

    #[test]
    fn action_sleeps_matrix() {
        for sleepy in [
            "suspend",
            "hibernate",
            "hybrid-sleep",
            "suspend-then-hibernate",
            "SUSPEND",
        ] {
            assert!(action_sleeps(sleepy), "{sleepy} should count as sleep");
        }
        for awake in ["ignore", "lock", "poweroff", "halt", "reboot", ""] {
            assert!(!action_sleeps(awake), "{awake} should not count as sleep");
        }
    }

    #[test]
    fn drop_in_overrides_main_file_in_lexical_order() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(LOGIND_CONF, "[Login]\nHandleLidSwitch=suspend\n");
        let first = format!("{LOGIND_CONF_D}/10-first.conf");
        let last = format!("{LOGIND_CONF_D}/20-last.conf");
        fs.mock_add_file(&first, "HandleLidSwitch=hibernate\n");
        fs.mock_add_file(&last, "HandleLidSwitch=ignore\n");
        // The mock returns the entries unsorted; the parser sorts them itself.
        fs.mock_set_directory_contents(
            Path::new(LOGIND_CONF_D),
            vec![PathBuf::from(&last), PathBuf::from(&first)],
        );
        let settings = effective_logind_sleep(&fs);
        assert_eq!(settings.effective_lid_switch(), "ignore");
    }

    #[test]
    fn default_host_warns_because_lid_suspends() {
        // No logind.conf at all: logind defaults HandleLidSwitch to suspend.
        let fs = MockFilesystem::new();
        let check = SleepPolicyCheck::new(SleepPolicyMode::Warn);
        let result = check.run(&fs).unwrap();
        assert!(result.is_warn(), "default host suspends on lid close");
        assert!(result.message().contains("HandleLidSwitch=suspend"));
    }

    #[test]
    fn reports_effective_settings_from_fixture() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(
            LOGIND_CONF,
            "[Login]\nHandleLidSwitch=suspend\nIdleAction=ignore\n",
        );
        let settings = effective_logind_sleep(&fs);
        assert_eq!(settings.effective_lid_switch(), "suspend");
        assert_eq!(settings.effective_idle_action(), "ignore");

        let check = SleepPolicyCheck::new(SleepPolicyMode::Warn);
        let result = check.run(&fs).unwrap();
        assert!(result.is_warn());
        assert!(
            result
                .message()
                .contains("closing the lid suspends the host")
        );
    }

    #[test]
    fn idle_suspend_is_reported_with_timeout() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(
            LOGIND_CONF,
            "[Login]\nHandleLidSwitch=ignore\nHandleLidSwitchExternalPower=ignore\n\
             IdleAction=suspend\nIdleActionSec=300\n",
        );
        let check = SleepPolicyCheck::new(SleepPolicyMode::Warn);
        let result = check.run(&fs).unwrap();
        assert!(result.is_warn());
        assert!(result.message().contains("IdleActionSec=300"));
        assert!(!result.message().contains("closing the lid"));
    }

    #[test]
    fn safe_host_passes() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(
            LOGIND_CONF,
            "[Login]\nHandleLidSwitch=lock\nHandleLidSwitchExternalPower=ignore\nIdleAction=lock\n",
        );
        let check = SleepPolicyCheck::new(SleepPolicyMode::Warn);
        let result = check.run(&fs).unwrap();
        assert!(result.is_pass(), "no sleep action configured");
    }

    #[test]
    fn block_mode_notes_the_inhibitor() {
        let fs = MockFilesystem::new();
        let check = SleepPolicyCheck::new(SleepPolicyMode::Block);
        let result = check.run(&fs).unwrap();
        assert!(result.is_warn());
        assert!(result.message().contains("holds a sleep inhibitor"));
    }

    #[test]
    fn check_performs_no_writes() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(LOGIND_CONF, "[Login]\nHandleLidSwitch=suspend\n");
        let drop_in = format!("{LOGIND_CONF_D}/10-lid.conf");
        fs.mock_add_file(&drop_in, "HandleLidSwitch=ignore\n");
        fs.mock_set_directory_contents(Path::new(LOGIND_CONF_D), vec![PathBuf::from(&drop_in)]);

        let before = fs.mock_ops().len();
        let check = SleepPolicyCheck::new(SleepPolicyMode::Warn);
        let _ = check.run(&fs).unwrap();
        let after = fs.mock_ops();
        assert_eq!(
            after.len(),
            before,
            "sleep-policy check must not write: {after:?}"
        );
    }
}
