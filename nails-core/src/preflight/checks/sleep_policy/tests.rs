// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

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
        "[Login]\nHandleLidSwitch=lock\nHandleLidSwitchExternalPower=lock\n\
         IdleAction=suspend\nIdleActionSec=300\n",
    );
    let check = SleepPolicyCheck::new(SleepPolicyMode::Warn);
    let result = check.run(&fs).unwrap();
    assert!(result.is_warn());
    assert!(result.message().contains("IdleActionSec=300"));
    assert!(!result.message().contains("closing the lid"));
}

/// A logind configuration NAILS cannot read as logind does leaves the lid and
/// idle actions unknown, however safe the files around it are: the check warns
/// that either may suspend the host, naming the entry, and that a closed lid
/// may leave the session unlocked, and the sleep guard's `block` mode takes
/// the lid switch.
#[test]
fn an_unread_configuration_may_suspend_the_host() {
    let fs = MockFilesystem::new();
    fs.mock_add_file(
        MAIN,
        "[Login]\nHandleLidSwitch=lock\nHandleLidSwitchExternalPower=lock\nIdleAction=lock\n",
    );
    let entry = "/etc/systemd/logind.conf.d/50-x.conf";
    fs.mock_set_directory_contents(Path::new(DROP_IN_DIR), vec![PathBuf::from(entry)]);
    fs.mock_set_path_type(entry, crate::filesystem::PathKind::Dir);

    let settings = effective_logind_sleep(&fs);
    assert_eq!(
        settings.unread.as_ref().map(|unread| unread.path.as_path()),
        Some(Path::new(entry))
    );
    assert!(settings.lid_switch_sleeps());

    let result = SleepPolicyCheck::new(SleepPolicyMode::Warn)
        .run(&fs)
        .unwrap();
    assert!(result.is_warn(), "{result:?}");
    let expected = format!(
        "NAILS cannot tell what logind does on a closed lid or an idle session, so either may \
         suspend the host: {entry} is not a regular file; systemd releases"
    );
    assert!(result.message().contains(&expected), "{}", result.message());
    assert!(
        !result.message().contains("HandleLidSwitch="),
        "{}",
        result.message()
    );
    // The lid may as well be set to ignore, which leaves the session unlocked.
    assert!(
        result.message().contains(
            "A closed lid may leave the active session running and unlocked (logind's lid \
             settings are not known): whoever opens the lid is in the hidden session."
        ),
        "{}",
        result.message()
    );
}

#[test]
fn safe_host_passes() {
    let fs = MockFilesystem::new();
    fs.mock_add_file(
        MAIN,
        "[Login]\nHandleLidSwitch=lock\nHandleLidSwitchExternalPower=lock\n\
         HandleLidSwitchDocked=ignore\nIdleAction=lock\n",
    );
    let check = SleepPolicyCheck::new(SleepPolicyMode::Warn);
    let result = check.run(&fs).unwrap();
    assert!(result.is_pass(), "no sleep action configured");
}

#[test]
fn a_lid_set_to_ignore_warns_that_the_session_stays_unlocked_in_every_mode() {
    let fs = MockFilesystem::new();
    fs.mock_add_file(MAIN, "[Login]\nHandleLidSwitch=ignore\n");
    for mode in [
        SleepPolicyMode::Warn,
        SleepPolicyMode::Block,
        SleepPolicyMode::Teardown,
    ] {
        let result = SleepPolicyCheck::new(mode).run(&fs).unwrap();
        assert!(result.is_warn(), "{mode:?}: {}", result.message());
        let message = result.message();
        assert!(
            message.starts_with(
                "a closed lid leaves the active session running and unlocked \
                 (HandleLidSwitch=ignore)"
            ),
            "{message}"
        );
        assert!(
            message.contains("Set the logind lid switch to lock"),
            "{message}"
        );
        assert!(!message.contains("would suspend"), "{message}");
    }
}

#[test]
fn a_lid_that_ignores_only_on_external_power_is_reported_for_that_case() {
    let fs = MockFilesystem::new();
    fs.mock_add_file(
        MAIN,
        "[Login]\nHandleLidSwitch=lock\nHandleLidSwitchExternalPower=ignore\n",
    );
    let result = SleepPolicyCheck::new(SleepPolicyMode::Warn)
        .run(&fs)
        .unwrap();
    assert!(result.is_warn(), "{}", result.message());
    assert!(
        result.message().starts_with(
            "a closed lid on external power leaves the active session running and unlocked \
             (HandleLidSwitchExternalPower=ignore)"
        ),
        "{}",
        result.message()
    );
}

#[test]
fn a_docked_lid_that_ignores_is_not_reported() {
    // Docked means an external display, where the session stays in view; it
    // is logind's default and what decoy-requirements.md recommends.
    let fs = MockFilesystem::new();
    fs.mock_add_file(
        MAIN,
        "[Login]\nHandleLidSwitch=lock\nHandleLidSwitchExternalPower=lock\n\
         HandleLidSwitchDocked=ignore\n",
    );
    let result = SleepPolicyCheck::new(SleepPolicyMode::Warn)
        .run(&fs)
        .unwrap();
    assert!(result.is_pass(), "{}", result.message());
}

#[test]
fn a_suspending_lid_and_an_unlocked_one_are_reported_together() {
    let fs = MockFilesystem::new();
    fs.mock_add_file(
        MAIN,
        "[Login]\nHandleLidSwitch=suspend\nHandleLidSwitchExternalPower=ignore\n",
    );
    let result = SleepPolicyCheck::new(SleepPolicyMode::Warn)
        .run(&fs)
        .unwrap();
    let message = result.message();
    assert!(result.is_warn(), "{message}");
    assert!(
        message.starts_with("the host would suspend an active session: closing the lid"),
        "{message}"
    );
    assert!(
        message.contains(" A closed lid on external power leaves the active session"),
        "{message}"
    );
}

#[test]
fn the_warning_names_the_hidden_sessions_lock_screen() {
    let fs = MockFilesystem::new();
    let result = SleepPolicyCheck::new(SleepPolicyMode::Warn)
        .run(&fs)
        .unwrap();
    let message = result.message();
    assert!(
        message.contains("behind the hidden session's own lock screen"),
        "{message}"
    );
    assert!(!message.contains("decoy lock screen"), "{message}");
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
