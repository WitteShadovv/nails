// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The hidden session's own units: the session watcher (the backend, and the
//! disks mounted during the session) and the sleep guard.
//!
//! A transient unit started in the decoy would die with the soft-reboot, so
//! both are written to `/run/systemd/system` by the entry transition and start
//! with the hidden userspace. They run the RAM copy of the binary, so they keep
//! working when the hidden volume fails, and they carry neutral names. Where
//! the host may run SELinux, PID 1 starts the copy through the exec prefix the
//! activation decided ([`super::exec_prefix`]). The return scrub removes them;
//! the decoy never loads them.

use crate::config::Config;
use nails_teardown::whole_root::exec_prefix;
use nails_teardown::whole_root::plan::{BINARY_NAME, RUNTIME_DIR};
use nails_teardown::whole_root::runtime_units::RuntimeUnit;
use std::path::Path;

/// The watcher's unit name.
pub const WATCH_UNIT: &str = "overlay-runtime-monitor.service";

fn unit(name: String, description: &str, argument: &str, prefix: Option<&Path>) -> RuntimeUnit {
    let binary = Path::new(RUNTIME_DIR).join(BINARY_NAME);
    RuntimeUnit {
        name,
        content: format!(
            "[Unit]\nDescription={description}\n\n[Service]\nExecStart={} {argument}\n\
             Restart=no\nStandardOutput=null\nStandardError=null\nLimitCORE=0\n",
            exec_prefix::command(prefix, &binary)
        ),
        wanted_by: vec!["multi-user.target".to_string()],
    }
}

/// The units the configuration asks for in the hidden session, each starting
/// the RAM copy through `prefix`, the program the activation decided PID 1
/// starts it through ([`super::exec_prefix::ExecPrefix::program`]), where
/// there is one.
pub fn session_units(config: &Config, prefix: Option<&Path>) -> Vec<RuntimeUnit> {
    let mut units = Vec::new();
    // The watcher also alerts on, and guards, disks mounted during the session.
    if config.backend_watch.enabled || config.session_mounts.needs_watcher() {
        units.push(unit(
            WATCH_UNIT.to_string(),
            "Overlay runtime monitor",
            "watch",
            prefix,
        ));
    }
    if config.sleep_policy.mode.runs_guard() {
        units.push(unit(
            format!("{}.service", crate::sleep_guard::SLEEP_GUARD_UNIT_NAME),
            "Overlay runtime power policy",
            "sleep-guard",
            prefix,
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
        let units = session_units(&config, None);
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
            session_units(&config, None).len(),
            1,
            "the mount alert keeps the watcher"
        );
        config.session_mounts.alert = false;
        assert!(session_units(&config, None).is_empty());
        config.session_mounts.read_only = true;
        assert_eq!(session_units(&config, None)[0].name, WATCH_UNIT);
    }

    /// Without an exec prefix, on a host that does not run SELinux, the units
    /// are word for word what they were before there was one.
    #[test]
    fn without_a_prefix_the_units_start_the_copy_themselves() {
        let mut config = Config::test_default();
        config.backend_watch.enabled = true;
        config.sleep_policy.mode = SleepPolicyMode::Block;
        let units = session_units(&config, None);
        assert_eq!(
            units[0].content,
            "[Unit]\nDescription=Overlay runtime monitor\n\n[Service]\n\
             ExecStart=/run/overlay-runtime/control watch\nRestart=no\nStandardOutput=null\n\
             StandardError=null\nLimitCORE=0\n"
        );
        assert_eq!(
            units[1].content,
            "[Unit]\nDescription=Overlay runtime power policy\n\n[Service]\n\
             ExecStart=/run/overlay-runtime/control sleep-guard\nRestart=no\n\
             StandardOutput=null\nStandardError=null\nLimitCORE=0\n"
        );
    }

    /// With the prefix each unit starts the copy through it, with the same
    /// arguments, and is otherwise the same: nothing in it keeps PID 1 from
    /// starting the program in a domain of its own (`NoNewPrivileges=`).
    #[test]
    fn with_a_prefix_the_units_start_the_copy_through_it() {
        let mut config = Config::test_default();
        config.backend_watch.enabled = true;
        config.sleep_policy.mode = SleepPolicyMode::Block;
        let env = Path::new(exec_prefix::TRAMPOLINE);
        let plain = session_units(&config, None);
        let prefixed = session_units(&config, Some(env));
        assert_eq!(prefixed.len(), plain.len());
        for ((with, without), argument) in prefixed.iter().zip(&plain).zip(["watch", "sleep-guard"])
        {
            assert_eq!(with.name, without.name);
            assert_eq!(with.wanted_by, without.wanted_by);
            assert_eq!(
                with.content,
                without.content.replace(
                    &format!("ExecStart=/run/overlay-runtime/control {argument}\n"),
                    &format!("ExecStart=/usr/bin/env /run/overlay-runtime/control {argument}\n")
                )
            );
            assert_ne!(with.content, without.content);
            assert!(
                !with.content.contains("NoNewPrivileges"),
                "{}",
                with.content
            );
            assert!(!with.content.to_lowercase().contains("nails"));
        }
    }
}
