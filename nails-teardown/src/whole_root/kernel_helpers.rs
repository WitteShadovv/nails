// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The kernel's helper paths that a NixOS activation rewrites.
//!
//! A NixOS system's activation points the running kernel at its own store:
//! the program the kernel runs to load a module (`/proc/sys/kernel/modprobe`),
//! the hotplug helper (`/proc/sys/kernel/hotplug`) and the firmware search
//! path (`/sys/module/firmware_class/parameters/path`). The hidden system's
//! activation runs on the decoy's kernel, and so does a `nixos-rebuild test`
//! in a session entered without a hidden build; nothing runs the decoy's
//! activation again on the way back. So every entry records the decoy's values
//! before anything runs ([`read`]), and every way back to the decoy (a
//! rolled-back entry, a disarmed next root, the return transition, an
//! emergency on the decoy) writes them back ([`restore`]). Without that, once the hidden system's store is
//! gone the decoy kernel would load no module and no firmware until power-off,
//! and would name store paths the decoy does not have.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The files a NixOS activation writes, read and restored as they are.
pub const HELPER_PATHS: [&str; 3] = [
    "/proc/sys/kernel/modprobe",
    "/proc/sys/kernel/hotplug",
    "/sys/module/firmware_class/parameters/path",
];

/// One kernel setting as the decoy had it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelSetting {
    /// The file that holds it.
    pub path: PathBuf,
    /// Its value, without the newline the kernel prints after it.
    pub value: String,
}

/// The value of the setting in `path`, `None` when it cannot be read.
fn current(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|text| text.trim_end_matches('\n').to_string())
}

/// The settings in `paths` that can be read now ([`HELPER_PATHS`] on the
/// real system).
pub fn read(paths: &[&str]) -> Vec<KernelSetting> {
    paths
        .iter()
        .filter_map(|path| {
            let path = PathBuf::from(path);
            current(&path).map(|value| KernelSetting { path, value })
        })
        .collect()
}

/// Write back every setting whose value differs now. Best effort: a setting
/// that cannot be written keeps the session's value. The value is written
/// without a newline, as NixOS writes the firmware path (a module parameter
/// keeps the newline it is given); an empty value as one newline, which a
/// sysctl reads as empty.
pub fn restore(settings: &[KernelSetting]) {
    for setting in settings {
        if current(&setting.path).as_deref() == Some(setting.value.as_str()) {
            continue;
        }
        let text = if setting.value.is_empty() {
            "\n"
        } else {
            setting.value.as_str()
        };
        let _ = std::fs::write(&setting.path, text);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_recorded_values_are_written_back_where_they_changed() {
        let dir = tempfile::tempdir().unwrap();
        let modprobe = dir.path().join("modprobe");
        let firmware = dir.path().join("path");
        let hotplug = dir.path().join("hotplug");
        std::fs::write(&modprobe, "/nix/store/decoy-kmod/bin/modprobe\n").unwrap();
        std::fs::write(&firmware, "/nix/store/decoy-firmware/lib/firmware\n").unwrap();
        std::fs::write(&hotplug, "\n").unwrap();
        let paths = [
            modprobe.to_str().unwrap(),
            firmware.to_str().unwrap(),
            hotplug.to_str().unwrap(),
            "/nonexistent/kernel/setting",
        ];
        let recorded = read(&paths);
        assert_eq!(recorded.len(), 3, "an unreadable setting is not recorded");
        assert_eq!(recorded[0].value, "/nix/store/decoy-kmod/bin/modprobe");
        assert_eq!(recorded[2].value, "");

        // The hidden activation points them at its own store.
        std::fs::write(&modprobe, "/nix/store/hidden-kmod/bin/modprobe\n").unwrap();
        std::fs::write(&firmware, "/nix/store/hidden-firmware/lib/firmware").unwrap();
        std::fs::write(&hotplug, "/nix/store/hidden/hotplug\n").unwrap();
        restore(&recorded);
        assert_eq!(
            std::fs::read_to_string(&modprobe).unwrap(),
            "/nix/store/decoy-kmod/bin/modprobe"
        );
        assert_eq!(
            std::fs::read_to_string(&firmware).unwrap(),
            "/nix/store/decoy-firmware/lib/firmware"
        );
        assert_eq!(std::fs::read_to_string(&hotplug).unwrap(), "\n");

        // An unchanged setting is not written at all.
        std::fs::remove_file(&modprobe).unwrap();
        std::os::unix::fs::symlink("/nonexistent/target", &modprobe).unwrap();
        restore(&recorded[1..]);
        assert!(
            std::fs::symlink_metadata(&modprobe)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }
}
