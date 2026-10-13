// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Inherited decoy persona state pre-flight check.
//!
//! Warns, never fails: it lists how much of the decoy account's autostart
//! entries, enabled user services, lingering and autologin the hidden session
//! would inherit, and highlights the names that look like remote-linked clients.
//! It runs in the shared registry, so both `nails check` and the activation
//! confirmation surface it; the full entry-by-entry listing is shown separately
//! by `nails check`.

use std::path::PathBuf;

use super::super::{CheckResult, PreFlightCheck};
use crate::persona::collect_inherited_persona;
use crate::{Filesystem, Result};

/// Reports the decoy persona state the hidden session would inherit.
#[derive(Debug, Clone, Default)]
pub struct InheritedAutostartCheck {
    /// The operator whose inherited state is inspected. `None` when the target
    /// user could not be resolved, in which case the check reports a Pass that
    /// says the inventory was skipped rather than erroring.
    operator: Option<Operator>,
}

/// The resolved operator context the inventory is collected for.
#[derive(Debug, Clone)]
struct Operator {
    home: PathBuf,
    user: String,
    fresh_home: bool,
}

impl InheritedAutostartCheck {
    /// Create a check for a resolved operator. `fresh_home` reflects the
    /// configured persona mode: in fresh-home mode only system-level inherited
    /// state is reported.
    pub fn new(home: PathBuf, user: String, fresh_home: bool) -> Self {
        Self {
            operator: Some(Operator {
                home,
                user,
                fresh_home,
            }),
        }
    }

    /// Create a check that reports Pass without inspecting anything, used when
    /// the target user could not be resolved.
    pub fn disabled() -> Self {
        Self { operator: None }
    }
}

impl<F: Filesystem> PreFlightCheck<F> for InheritedAutostartCheck {
    fn name(&self) -> &'static str {
        "inherited-autostart"
    }

    fn description(&self) -> &'static str {
        "Reports the decoy autostart, user services and autologin the hidden session would inherit"
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        let Some(operator) = self.operator.as_ref() else {
            return Ok(CheckResult::Pass(
                "Target user could not be resolved; inherited decoy state was not inspected".into(),
            ));
        };

        let inventory =
            collect_inherited_persona(fs, &operator.home, &operator.user, operator.fresh_home);

        if inventory.is_empty() {
            return Ok(CheckResult::Pass(
                "No decoy autostart entries, user services or autologin would be inherited".into(),
            ));
        }

        let remote = inventory.remote_linked_names();
        let mut message = format!(
            "Hidden session would inherit {} decoy item(s) from the decoy account",
            inventory.len()
        );
        if !remote.is_empty() {
            message.push_str(&format!(
                "; {} look like remote-linked client(s): {}",
                remote.len(),
                remote.join(", ")
            ));
        }
        message.push_str(
            ". Review them (they run under the decoy identity) and mask any with [persona] mask_inherited in nails.toml.",
        );

        Ok(CheckResult::Warn(message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::MockFilesystem;
    use std::path::PathBuf;

    fn seed_remote_autostart(fs: &MockFilesystem) {
        let dir = PathBuf::from("/home/alice/.config/autostart");
        let entry = dir.join("dropbox.desktop");
        fs.mock_set_directory_contents(&dir, vec![entry.clone()]);
        fs.mock_set_file_content(entry.to_str().unwrap(), "[Desktop Entry]\n");
    }

    fn check() -> InheritedAutostartCheck {
        InheritedAutostartCheck::new(PathBuf::from("/home/alice"), "alice".to_string(), false)
    }

    #[test]
    fn warns_and_names_remote_linked_entries() {
        let fs = MockFilesystem::new();
        seed_remote_autostart(&fs);

        let result = check().run(&fs).unwrap();
        assert!(result.is_warn());
        let message = result.message();
        assert!(message.contains("inherit 1"));
        assert!(message.contains("dropbox"));
        assert!(message.contains("mask_inherited"));
    }

    #[test]
    fn passes_on_empty_inventory() {
        let fs = MockFilesystem::new();
        let result = check().run(&fs).unwrap();
        assert!(result.is_pass());
        assert!(!result.is_fail());
    }

    #[test]
    fn never_fails_even_with_many_entries() {
        let fs = MockFilesystem::new();
        seed_remote_autostart(&fs);
        fs.mock_set_path_exists("/var/lib/systemd/linger/alice", true);

        let result = check().run(&fs).unwrap();
        assert!(!result.is_fail());
    }

    #[test]
    fn disabled_check_passes_without_inspecting() {
        let fs = MockFilesystem::new();
        seed_remote_autostart(&fs);

        let result = InheritedAutostartCheck::disabled().run(&fs).unwrap();
        assert!(result.is_pass());
        assert!(result.message().contains("could not be resolved"));
    }

    #[test]
    fn warn_message_without_remote_links_omits_the_client_clause() {
        let fs = MockFilesystem::new();
        let dir = PathBuf::from("/home/alice/.config/autostart");
        let entry = dir.join("screenshot.desktop");
        fs.mock_set_directory_contents(&dir, vec![entry.clone()]);
        fs.mock_set_file_content(entry.to_str().unwrap(), "[Desktop Entry]\n");

        let result = check().run(&fs).unwrap();
        assert!(result.is_warn());
        assert!(!result.message().contains("remote-linked"));
    }

    #[test]
    fn metadata_is_stable() {
        let check = InheritedAutostartCheck::disabled();
        assert_eq!(
            <InheritedAutostartCheck as PreFlightCheck<MockFilesystem>>::name(&check),
            "inherited-autostart"
        );
        assert!(
            <InheritedAutostartCheck as PreFlightCheck<MockFilesystem>>::description(&check)
                .contains("inherit")
        );
    }

    #[test]
    fn fresh_home_reports_only_system_level_entries() {
        let fs = MockFilesystem::new();
        // A user-level autostart entry that fresh-home must not report.
        seed_remote_autostart(&fs);

        let check =
            InheritedAutostartCheck::new(PathBuf::from("/home/alice"), "alice".to_string(), true);
        let result = check.run(&fs).unwrap();
        // Nothing system-level is seeded, so fresh-home sees an empty inventory.
        assert!(result.is_pass());
    }
}
