// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The hidden session's own units: the session watcher (the backend, and the
//! disks mounted during the session) and the sleep guard.
//!
//! A transient unit started in the decoy would die with the soft-reboot, so
//! both are written to `/run/systemd/system` by the entry transition and start
//! with the hidden userspace. They run the RAM copy of the binary, so they keep
//! working when the hidden volume fails, and they carry neutral names. The
//! return scrub removes them; the decoy never loads them. Where SELinux runs
//! with a policy loaded, each checks the domain it runs in before it does
//! anything else
//! ([`nails_teardown::whole_root::program_label::enter_domain`]).

use crate::config::Config;
use nails_teardown::whole_root::plan::{BINARY_NAME, RUNTIME_DIR};
use nails_teardown::whole_root::runtime_units::RuntimeUnit;
use std::path::Path;

/// The watcher's unit name.
pub const WATCH_UNIT: &str = "overlay-runtime-monitor.service";

/// The unit that powers off through the emergency's hot path where the
/// watcher fails while it guards the write tripwire.
pub const WATCH_FAILURE_UNIT: &str = "overlay-runtime-monitor-failed.service";

fn unit(name: String, description: &str, argument: &str, unit_lines: &str) -> RuntimeUnit {
    let binary = Path::new(RUNTIME_DIR).join(BINARY_NAME);
    RuntimeUnit {
        name,
        content: format!(
            "[Unit]\nDescription={description}\n{unit_lines}\n[Service]\nExecStart={} \
             {argument}\nRestart=no\nStandardOutput=null\nStandardError=null\nLimitCORE=0\n",
            binary.display()
        ),
        wanted_by: vec!["multi-user.target".to_string()],
    }
}

/// The unit [`WATCH_FAILURE_UNIT`]: the emergency with a power-off, started
/// by nothing but the watcher's failure. Where it fails itself, PID 1 powers
/// off at once, without stopping or syncing anything.
fn failure_unit() -> RuntimeUnit {
    let binary = Path::new(RUNTIME_DIR).join(BINARY_NAME);
    RuntimeUnit {
        name: WATCH_FAILURE_UNIT.to_string(),
        content: format!(
            "[Unit]\nDescription=Overlay runtime monitor fallback\nDefaultDependencies=no\n\
             FailureAction=poweroff-immediate\n\n[Service]\nType=oneshot\nExecStart={} \
             emergency --poweroff\nStandardOutput=null\nStandardError=null\nLimitCORE=0\n",
            binary.display()
        ),
        wanted_by: Vec::new(),
    }
}

/// The units the configuration asks for in the hidden session.
pub fn session_units(config: &Config) -> Vec<RuntimeUnit> {
    let mut units = Vec::new();
    // The watcher also alerts on, and guards, disks mounted during the session.
    if config.backend_watch.enabled || config.session_mounts.needs_watcher() {
        // A watcher that crashes, is killed or never starts leaves the write
        // tripwire off: its failure powers off instead. Its stop at the
        // switch, by SIGTERM, is no failure.
        let tripwire = config.session_mounts.write_tripwire;
        let on_failure = if tripwire {
            format!("OnFailure={WATCH_FAILURE_UNIT}\n")
        } else {
            String::new()
        };
        units.push(unit(
            WATCH_UNIT.to_string(),
            "Overlay runtime monitor",
            "watch",
            &on_failure,
        ));
        if tripwire {
            units.push(failure_unit());
        }
    }
    if config.sleep_policy.mode.runs_guard() {
        units.push(unit(
            format!("{}.service", crate::sleep_guard::SLEEP_GUARD_UNIT_NAME),
            "Overlay runtime power policy",
            "sleep-guard",
            "",
        ));
    }
    units
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SleepPolicyMode;

    #[test]
    fn the_units_follow_the_configuration_and_name_no_product() {
        let mut config = Config::test_default();
        config.backend_watch.enabled = true;
        config.sleep_policy.mode = SleepPolicyMode::Block;
        let units = session_units(&config);
        assert_eq!(units.len(), 2);
        for unit in &units {
            assert!(!unit.name.to_lowercase().contains("nails"), "{}", unit.name);
            assert!(
                !unit.content.to_lowercase().contains("nails"),
                "{}",
                unit.content
            );
            assert!(
                unit.content
                    .contains("ExecStart=/run/overlay-runtime/control ")
            );
            assert_eq!(unit.wanted_by, ["multi-user.target"]);
        }
        config.backend_watch.enabled = false;
        config.sleep_policy.mode = SleepPolicyMode::Warn;
        assert_eq!(
            session_units(&config).len(),
            1,
            "the mount alert keeps the watcher"
        );
        config.session_mounts.alert = false;
        assert!(session_units(&config).is_empty());
        config.session_mounts.read_only = true;
        assert_eq!(session_units(&config)[0].name, WATCH_UNIT);
        assert!(!session_units(&config)[0].content.contains("OnFailure="));
    }

    #[test]
    fn a_watcher_that_guards_the_write_tripwire_powers_off_where_it_fails() {
        let mut config = Config::test_default();
        config.session_mounts.write_tripwire = true;
        let units = session_units(&config);
        let names: Vec<&str> = units.iter().map(|u| u.name.as_str()).collect();
        assert_eq!(names, [WATCH_UNIT, WATCH_FAILURE_UNIT]);
        assert!(
            units[0]
                .content
                .contains(&format!("OnFailure={WATCH_FAILURE_UNIT}\n"))
        );
        let fallback = &units[1];
        assert!(
            fallback
                .content
                .contains("ExecStart=/run/overlay-runtime/control emergency --poweroff\n"),
            "{}",
            fallback.content
        );
        assert!(
            fallback
                .content
                .contains("FailureAction=poweroff-immediate\n")
        );
        assert!(fallback.content.contains("DefaultDependencies=no\n"));
        assert!(
            fallback.wanted_by.is_empty(),
            "started by the failure alone"
        );
        assert!(!fallback.content.to_lowercase().contains("nails"));
    }
}
