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
                 switch to lock (see docs/decoy-requirements.md), or set \
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
        };
        Ok(CheckResult::Warn(message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RealFilesystem;
    use crate::filesystem::MockFilesystem;
    use std::path::PathBuf;

    const MAIN: &str = "/etc/systemd/logind.conf";
    const DROP_IN_DIR: &str = "/etc/systemd/logind.conf.d";

    fn write(root: &Path, rel: &str, content: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }

    #[test]
    fn parses_lid_and_idle_keys_like_logind() {
        let mut settings = LogindSleepSettings::default();
        parse_logind_sleep(
            "[Login]\nhandlelidswitch=ignore\nIdleAction=suspend\nIdleActionSec=600\n",
            &mut settings,
        );
        // logind keys are case-sensitive: the lower-case key is not a setting.
        assert_eq!(settings.handle_lid_switch, None);
        assert_eq!(settings.idle_action.as_deref(), Some("suspend"));
        assert_eq!(settings.idle_action_sec.as_deref(), Some("600"));
    }

    #[test]
    fn only_the_login_section_counts() {
        let mut settings = LogindSleepSettings::default();
        parse_logind_sleep(
            "HandleLidSwitch=ignore\n[Other]\nHandleLidSwitch=lock\n",
            &mut settings,
        );
        assert_eq!(settings.handle_lid_switch, None);
    }

    #[test]
    fn ignores_comments_and_last_valid_assignment_wins() {
        let mut settings = LogindSleepSettings::default();
        parse_logind_sleep(
            "[Login]\n#HandleLidSwitch=ignore\nHandleLidSwitch=suspend\nHandleLidSwitch=lock\n\
             HandleLidSwitch=junk\n",
            &mut settings,
        );
        assert_eq!(settings.handle_lid_switch.as_deref(), Some("lock"));
    }

    #[test]
    fn an_empty_action_keeps_the_previous_one_as_logind_does() {
        // logind parses Handle*= and IdleAction= without a reset-to-default
        // case, so it rejects an empty value and keeps what was there.
        let mut settings = LogindSleepSettings::default();
        parse_logind_sleep(
            "[Login]\nHandleLidSwitch=lock\nHandleLidSwitchExternalPower=ignore\n\
             HandleLidSwitchDocked=lock\nIdleAction=lock\nIdleActionSec=300\n",
            &mut settings,
        );
        parse_logind_sleep(
            "[Login]\nHandleLidSwitch=\nHandleLidSwitchExternalPower=\n\
             HandleLidSwitchDocked=\nIdleAction=\nIdleActionSec=\n",
            &mut settings,
        );
        assert_eq!(settings.effective_lid_switch(), "lock");
        assert_eq!(settings.effective_lid_switch_external_power(), "ignore");
        assert_eq!(settings.effective_lid_switch_docked(), "lock");
        assert_eq!(settings.effective_idle_action(), "lock");
        assert!(!settings.lid_switch_sleeps(), "{settings:?}");
        // IdleActionSec= is a time span, and an empty one does reset it.
        assert_eq!(settings.idle_action_sec, None);

        let fs = MockFilesystem::new();
        fs.mock_add_file(MAIN, "[Login]\nHandleLidSwitch=lock\n");
        let drop_in = format!("{DROP_IN_DIR}/10-lid.conf");
        fs.mock_add_file(&drop_in, "[Login]\nHandleLidSwitch=\n");
        fs.mock_set_directory_contents(Path::new(DROP_IN_DIR), vec![PathBuf::from(&drop_in)]);
        let result = SleepPolicyCheck::new(SleepPolicyMode::Block)
            .run(&fs)
            .unwrap();
        assert!(result.is_pass(), "{}", result.message());
        assert!(result.message().contains("HandleLidSwitch=lock"));
    }

    #[test]
    fn a_lid_that_sleeps_only_when_docked_is_reported() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(
            MAIN,
            "[Login]\nHandleLidSwitch=lock\nHandleLidSwitchDocked=suspend\n",
        );
        let result = SleepPolicyCheck::new(SleepPolicyMode::Warn)
            .run(&fs)
            .unwrap();
        assert!(result.is_warn(), "{}", result.message());
        let message = result.message();
        assert!(
            message.contains(
                "closing the lid while docked suspends the host (HandleLidSwitchDocked=suspend)"
            ),
            "{message}"
        );
        assert!(!message.contains("HandleLidSwitch=lock"), "{message}");

        let result = SleepPolicyCheck::new(SleepPolicyMode::Block)
            .run(&fs)
            .unwrap();
        assert!(result.is_warn(), "{}", result.message());
        let message = result.message();
        assert!(
            message.contains("takes the lid switch from logind"),
            "{message}"
        );
        assert!(message.contains("not even lock the screen"), "{message}");
    }

    #[test]
    fn effective_defaults_apply_when_unset() {
        let settings = LogindSleepSettings::default();
        assert_eq!(settings.effective_lid_switch(), "suspend");
        assert_eq!(settings.effective_lid_switch_external_power(), "suspend");
        assert_eq!(settings.effective_lid_switch_docked(), "ignore");
        assert_eq!(settings.effective_idle_action(), "ignore");

        // Unset, the external-power case follows HandleLidSwitch, as in logind.
        let mut settings = LogindSleepSettings::default();
        parse_logind_sleep("[Login]\nHandleLidSwitch=lock\n", &mut settings);
        assert_eq!(settings.effective_lid_switch_external_power(), "lock");
        parse_logind_sleep(
            "[Login]\nHandleLidSwitchExternalPower=suspend\n",
            &mut settings,
        );
        assert_eq!(settings.effective_lid_switch_external_power(), "suspend");
    }

    #[test]
    fn the_lid_switch_sleeps_when_any_of_its_three_cases_does() {
        assert!(LogindSleepSettings::default().lid_switch_sleeps());
        let mut settings = LogindSleepSettings::default();
        parse_logind_sleep(
            "[Login]\nHandleLidSwitch=lock\nHandleLidSwitchExternalPower=ignore\n",
            &mut settings,
        );
        assert!(!settings.lid_switch_sleeps(), "{settings:?}");
        parse_logind_sleep("[Login]\nHandleLidSwitchDocked=suspend\n", &mut settings);
        assert!(settings.lid_switch_sleeps(), "{settings:?}");
        parse_logind_sleep(
            "[Login]\nHandleLidSwitchDocked=poweroff\nIdleAction=suspend\n",
            &mut settings,
        );
        assert!(!settings.lid_switch_sleeps(), "idle is not the lid");
    }

    #[test]
    fn a_lid_that_only_locks_also_locks_on_external_power() {
        let mut settings = LogindSleepSettings::default();
        parse_logind_sleep("[Login]\nHandleLidSwitch=lock\n", &mut settings);
        assert!(!settings.lid_switch_sleeps(), "{settings:?}");

        let fs = MockFilesystem::new();
        fs.mock_add_file(MAIN, "[Login]\nHandleLidSwitch=lock\n");
        for mode in [SleepPolicyMode::Warn, SleepPolicyMode::Block] {
            let result = SleepPolicyCheck::new(mode).run(&fs).unwrap();
            assert!(result.is_pass(), "{}", result.message());
            assert!(!result.message().contains("external power"));
        }
    }

    #[test]
    fn an_unset_external_power_action_is_reported_once_with_the_lid() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(MAIN, "[Login]\nHandleLidSwitch=suspend\n");
        let result = SleepPolicyCheck::new(SleepPolicyMode::Warn)
            .run(&fs)
            .unwrap();
        let message = result.message();
        assert!(message.contains("HandleLidSwitch=suspend"), "{message}");
        assert!(
            !message.contains("HandleLidSwitchExternalPower"),
            "{message}"
        );

        fs.mock_add_file(
            MAIN,
            "[Login]\nHandleLidSwitch=lock\nHandleLidSwitchExternalPower=hibernate\n",
        );
        let result = SleepPolicyCheck::new(SleepPolicyMode::Warn)
            .run(&fs)
            .unwrap();
        let message = result.message();
        assert!(
            message.contains("HandleLidSwitchExternalPower=hibernate"),
            "{message}"
        );
        assert!(!message.contains("HandleLidSwitch=lock"), "{message}");
    }

    #[test]
    fn action_sleeps_matrix() {
        for sleepy in [
            "suspend",
            "hibernate",
            "hybrid-sleep",
            "suspend-then-hibernate",
            "sleep",
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
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(
            root,
            "etc/systemd/logind.conf",
            "[Login]\nHandleLidSwitch=suspend\n",
        );
        write(
            root,
            "etc/systemd/logind.conf.d/10-first.conf",
            "[Login]\nHandleLidSwitch=hibernate\n",
        );
        write(
            root,
            "usr/lib/systemd/logind.conf.d/20-last.conf",
            "[Login]\nHandleLidSwitch=ignore\n",
        );
        let settings = effective_logind_sleep_at(&RealFilesystem, root);
        assert_eq!(settings.effective_lid_switch(), "ignore");
    }

    #[test]
    fn etc_drop_in_shadows_vendor_drop_in() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(
            root,
            "usr/lib/systemd/logind.conf",
            "[Login]\nHandleLidSwitch=ignore\n",
        );
        write(
            root,
            "usr/lib/systemd/logind.conf.d/50-lid.conf",
            "[Login]\nHandleLidSwitch=lock\n",
        );
        write(
            root,
            "etc/systemd/logind.conf.d/50-lid.conf",
            "[Login]\nIdleAction=suspend\n",
        );
        let settings = effective_logind_sleep_at(&RealFilesystem, root);
        assert_eq!(settings.effective_lid_switch(), "ignore");
        assert_eq!(settings.effective_idle_action(), "suspend");
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
            MAIN,
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
            MAIN,
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
            MAIN,
            "[Login]\nHandleLidSwitch=lock\nHandleLidSwitchExternalPower=ignore\nIdleAction=lock\n",
        );
        let check = SleepPolicyCheck::new(SleepPolicyMode::Warn);
        let result = check.run(&fs).unwrap();
        assert!(result.is_pass(), "no sleep action configured");
    }

    #[test]
    fn block_mode_notes_the_inhibitors_and_what_a_closed_lid_then_does() {
        let fs = MockFilesystem::new();
        let check = SleepPolicyCheck::new(SleepPolicyMode::Block);
        let result = check.run(&fs).unwrap();
        assert!(result.is_warn());
        let message = result.message();
        assert!(
            message.contains("holds sleep and idle inhibitors"),
            "{message}"
        );
        assert!(
            message.contains("takes the lid switch from logind"),
            "{message}"
        );
        assert!(message.contains("not even lock the screen"), "{message}");

        // A lid that only locks stays with logind: the warning is about idle.
        fs.mock_add_file(
            MAIN,
            "[Login]\nHandleLidSwitch=lock\nHandleLidSwitchExternalPower=lock\n\
             IdleAction=suspend\n",
        );
        let message = check.run(&fs).unwrap().message().to_string();
        assert!(
            message.contains("idle inactivity suspends the host"),
            "{message}"
        );
        assert!(
            message.contains("holds sleep and idle inhibitors"),
            "{message}"
        );
        assert!(!message.contains("lid switch from logind"), "{message}");
    }

    #[test]
    fn check_performs_no_writes() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(MAIN, "[Login]\nHandleLidSwitch=suspend\n");
        let drop_in = format!("{DROP_IN_DIR}/10-lid.conf");
        fs.mock_add_file(&drop_in, "[Login]\nHandleLidSwitch=ignore\n");
        fs.mock_set_directory_contents(Path::new(DROP_IN_DIR), vec![PathBuf::from(&drop_in)]);

        let before = fs.mock_ops().len();
        let check = SleepPolicyCheck::new(SleepPolicyMode::Warn);
        let _ = check.run(&fs).unwrap();
        assert!(fs.mock_written_paths().is_empty(), "nothing was written");
        assert_eq!(
            fs.read_file_content(Path::new(&drop_in)).unwrap(),
            "[Login]\nHandleLidSwitch=ignore\n",
            "the drop-in is left as it was"
        );
        let after = fs.mock_ops();
        assert_eq!(
            after.len(),
            before,
            "sleep-policy check must not write: {after:?}"
        );
    }
}
