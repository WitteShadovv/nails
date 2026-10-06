// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Resolving the systemd service unit a process runs in from its cgroup.

/// The system service unit (`<name>.service`) a process's cgroup places it in,
/// for enqueuing a stop job before the emergency kill.
///
/// A unit with `Restart=` that loses its processes to a kill is restarted by
/// systemd after the overlays are gone, and the new instance then writes to the
/// decoy. An enqueued stop job suppresses that restart, so the kill path stops
/// the unit first. Only a `.service` under `system.slice` qualifies, never a unit
/// below `user.slice` (that would be the operator's `user@<uid>.service` or a
/// session scope) and never the display manager: those belong to the graphical
/// session emergency must not end. A process in a delegated sub-cgroup of a
/// service (`system.slice/foo.service/payload`) resolves to that service.
/// `cgroup_content` is the raw `/proc/<pid>/cgroup`; v2 (`0::/…`) and v1
/// (`N:controller:/…`) lines are both read, the first match wins.
pub(crate) fn service_unit_from_cgroup(cgroup_content: &str) -> Option<String> {
    cgroup_content.lines().find_map(|line| {
        let path = line.splitn(3, ':').nth(2)?;
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if segments.contains(&"user.slice") {
            return None;
        }
        let slice = segments.iter().position(|s| *s == "system.slice")?;
        let unit = segments[slice + 1..]
            .iter()
            .find(|segment| segment.ends_with(".service") && segment.len() > ".service".len())?;
        if *unit == "display-manager.service" || unit.starts_with("user@") {
            return None;
        }
        Some((*unit).to_string())
    })
}

/// The service unit this process itself runs in, if any, so a teardown never
/// stops the unit carrying it (the backend watcher's auto-emergency, or a
/// transient unit an operator started it in): stopping it would SIGTERM the
/// teardown itself.
pub(crate) fn own_service_unit() -> Option<String> {
    std::fs::read_to_string("/proc/self/cgroup")
        .ok()
        .and_then(|content| service_unit_from_cgroup(&content))
}

/// Whether a teardown may stop `unit` (named with or without the `.service`
/// suffix) given the unit it runs in itself: never its own.
pub(crate) fn may_stop_unit(own_unit: Option<&str>, unit: &str) -> bool {
    let normalize = |name: &str| name.strip_suffix(".service").unwrap_or(name).to_string();
    own_unit.is_none_or(|own| normalize(own) != normalize(unit))
}

#[cfg(test)]
mod tests {
    use super::{may_stop_unit, service_unit_from_cgroup};

    #[test]
    fn a_system_service_resolves_to_its_unit() {
        assert_eq!(
            service_unit_from_cgroup("0::/system.slice/worker.service\n").as_deref(),
            Some("worker.service")
        );
        // A delegated sub-cgroup still belongs to its service.
        assert_eq!(
            service_unit_from_cgroup("0::/system.slice/worker.service/payload\n").as_deref(),
            Some("worker.service")
        );
        // Nested slices below system.slice.
        assert_eq!(
            service_unit_from_cgroup("0::/system.slice/system-getty.slice/getty@tty1.service\n")
                .as_deref(),
            Some("getty@tty1.service")
        );
        // cgroup v1: one line per controller, the named hierarchy carries the path.
        assert_eq!(
            service_unit_from_cgroup(
                "12:pids:/system.slice/worker.service\n1:name=systemd:/system.slice/worker.service\n"
            )
            .as_deref(),
            Some("worker.service")
        );
    }

    #[test]
    fn the_graphical_session_and_user_units_are_never_stopped() {
        for cgroup in [
            "0::/system.slice/display-manager.service\n",
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app.service\n",
            "0::/user.slice/user-1000.slice/session-2.scope\n",
            "0::/system.slice/user@1000.service\n",
            "0::/init.scope\n",
            "0::/system.slice/foo.scope\n",
            "0::/system.slice/.service\n",
            "",
        ] {
            assert_eq!(service_unit_from_cgroup(cgroup), None, "{cgroup:?}");
        }
    }

    #[test]
    fn the_real_cgroup_of_this_process_parses() {
        // Whatever unit (or none) the test runner lives in, the real file must
        // parse without panicking and never yield a user-session unit.
        let content = std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
        if let Some(unit) = service_unit_from_cgroup(&content) {
            assert!(unit.ends_with(".service"), "{unit}");
            assert!(!content.contains("user.slice"), "{content}");
        }
    }

    #[test]
    fn a_teardown_never_stops_its_own_unit() {
        assert!(!may_stop_unit(
            Some("overlay-runtime-monitor.service"),
            "overlay-runtime-monitor"
        ));
        assert!(!may_stop_unit(Some("worker.service"), "worker.service"));
        assert!(may_stop_unit(
            Some("overlay-runtime-monitor.service"),
            "overlay-runtime-power"
        ));
        assert!(may_stop_unit(None, "overlay-runtime-monitor"));
    }
}
