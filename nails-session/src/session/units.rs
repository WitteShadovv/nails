// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The hidden session's own units: the backend watcher and the sleep guard.
//!
//! A transient unit started in the decoy would die with the soft-reboot, so
//! both are written to `/run/systemd/system` by the entry transition and start
//! with the hidden userspace. They run the RAM copy of the binary, so they keep
//! working when the hidden volume fails, and they carry neutral names. The
//! return scrub removes them; the decoy never loads them.

use crate::config::Config;
use nails_teardown::whole_root::plan::{BINARY_NAME, RUNTIME_DIR};
use nails_teardown::whole_root::runtime_units::RuntimeUnit;
use std::path::Path;

/// The watcher's unit name.
pub const WATCH_UNIT: &str = "overlay-runtime-monitor.service";

fn unit(name: String, description: &str, argument: &str) -> RuntimeUnit {
    let binary = Path::new(RUNTIME_DIR).join(BINARY_NAME);
    RuntimeUnit {
        name,
        content: format!(
            "[Unit]\nDescription={description}\n\n[Service]\nExecStart={} {argument}\n\
             Restart=no\nStandardOutput=null\nStandardError=null\nLimitCORE=0\n",
            binary.display()
        ),
        wanted_by: vec!["multi-user.target".to_string()],
    }
}

/// The units the configuration asks for in the hidden session.
pub fn session_units(config: &Config) -> Vec<RuntimeUnit> {
    let mut units = Vec::new();
    if config.backend_watch.enabled {
        units.push(unit(
            WATCH_UNIT.to_string(),
            "Overlay runtime monitor",
            "watch",
        ));
    }
    if config.sleep_policy.mode.runs_guard() {
        units.push(unit(
            format!("{}.service", crate::sleep_guard::SLEEP_GUARD_UNIT_NAME),
            "Overlay runtime power policy",
            "sleep-guard",
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
        assert!(session_units(&config).is_empty());
    }
}
