// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Runtime units in `/run/systemd/system`.
//!
//! A soft-reboot carries `/run`, and a fresh PID 1 loads the runtime unit
//! directory `/run/systemd/system` when it starts. At entry the transition
//! installs the hidden session's own units (the backend watcher, the sleep
//! guard) and masks the decoy units the hidden systemd must never start (decoy
//! swap, decoy filesystems it would mount read-write). They live only in `/run`
//! and the return scrub removes them, so the decoy's PID 1 never sees them.
//!
//! Unit names are validated: a plain file name with a known unit suffix, so a
//! plan can never make the transition write outside `/run/systemd/system`
//! and `/run/systemd/system.control`.

use serde::{Deserialize, Serialize};
use std::io;
use std::path::{Path, PathBuf};

/// The runtime unit directory below a `/run` root.
pub const RUNTIME_UNIT_DIR: &str = "systemd/system";

/// The runtime directory that ranks above `/etc/systemd/system`, below a
/// `/run` root. A unit file in a directory listed earlier overrides one of the
/// same name listed later, and `/run/systemd/system` comes after
/// `/etc/systemd/system`, where NixOS links every unit: a mask there only
/// hides a unit installed below `/usr` (or generated from fstab).
pub const RUNTIME_CONTROL_DIR: &str = "systemd/system.control";

/// The unit suffixes a runtime unit may have.
const UNIT_SUFFIXES: &[&str] = &[
    ".service", ".target", ".socket", ".timer", ".path", ".mount", ".swap", ".scope",
];

/// One unit file to install in `/run/systemd/system`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeUnit {
    /// The unit name with its suffix (`overlay-runtime-monitor.service`).
    pub name: String,
    /// The unit file's content.
    pub content: String,
    /// Targets that want the unit (`multi-user.target`): a symlink is placed in
    /// each `<target>.wants/` directory.
    #[serde(default)]
    pub wanted_by: Vec<String>,
}

/// Whether `name` is a plain unit file name with a known suffix.
pub fn valid_unit_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && !name.starts_with('.')
        && !name.contains('/')
        && !name.contains('\0')
        && UNIT_SUFFIXES
            .iter()
            .any(|s| name.len() > s.len() && name.ends_with(s))
}

/// Mask `units` under `run` in [`RUNTIME_CONTROL_DIR`], so the mask wins
/// wherever the unit is installed. Best effort and one at a time: a name that
/// is not a unit name, or a path that already holds anything (a mask or an
/// override of the decoy's own), is skipped. Returns the links written.
pub fn mask_units_best_effort(run: &Path, units: &[String]) -> Vec<PathBuf> {
    let dir = run.join(RUNTIME_CONTROL_DIR);
    let mut written = Vec::new();
    for name in units.iter().filter(|name| valid_unit_name(name)) {
        let link = dir.join(name);
        if std::fs::symlink_metadata(&link).is_ok() {
            continue;
        }
        if std::fs::create_dir_all(&dir).is_ok()
            && std::os::unix::fs::symlink("/dev/null", &link).is_ok()
        {
            written.push(link);
        }
    }
    written
}

fn invalid(name: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("not a unit name: {name:?}"),
    )
}

/// Install `units` under `run` (normally `/run`). Returns the paths written.
pub fn install_units(run: &Path, units: &[RuntimeUnit]) -> io::Result<Vec<PathBuf>> {
    let dir = run.join(RUNTIME_UNIT_DIR);
    let mut written = Vec::new();
    for unit in units {
        if !valid_unit_name(&unit.name) || !unit.wanted_by.iter().all(|t| valid_unit_name(t)) {
            return Err(invalid(&unit.name));
        }
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(&unit.name);
        crate::whole_root::plan::write_atomic_with_mode(
            &path,
            unit.content.as_bytes(),
            crate::whole_root::plan::SERVICE_CONFIG_MODE,
        )?;
        written.push(path);
        for target in &unit.wanted_by {
            let wants = dir.join(format!("{target}.wants"));
            std::fs::create_dir_all(&wants)?;
            let link = wants.join(&unit.name);
            let _ = std::fs::remove_file(&link);
            std::os::unix::fs::symlink(Path::new("..").join(&unit.name), &link)?;
            written.push(link);
        }
    }
    Ok(written)
}

/// Mask `units` under `run`: a `/dev/null` symlink in the runtime unit
/// directory, which ranks above the generator output (fstab units).
pub fn mask_units(run: &Path, units: &[String]) -> io::Result<Vec<PathBuf>> {
    let dir = run.join(RUNTIME_UNIT_DIR);
    let mut written = Vec::new();
    for name in units {
        if !valid_unit_name(name) {
            return Err(invalid(name));
        }
        std::fs::create_dir_all(&dir)?;
        let link = dir.join(name);
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink("/dev/null", &link)?;
        written.push(link);
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unit(name: &str) -> RuntimeUnit {
        RuntimeUnit {
            name: name.to_string(),
            content: "[Service]\nExecStart=/bin/true\n".to_string(),
            wanted_by: vec!["multi-user.target".to_string()],
        }
    }

    #[test]
    fn unit_names_are_plain_file_names_with_a_unit_suffix() {
        assert!(valid_unit_name("overlay-runtime-monitor.service"));
        assert!(valid_unit_name("dev-disk-by\\x2duuid-1234.swap"));
        assert!(valid_unit_name("boot-efi.mount"));
        for bad in [
            "",
            ".service",
            "../etc.service",
            "a/b.service",
            "noext",
            ".hidden.service",
            "x.conf",
        ] {
            assert!(!valid_unit_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn installed_units_are_wanted_by_their_targets() {
        let run = tempfile::tempdir().unwrap();
        let written = install_units(run.path(), &[unit("a.service")]).unwrap();
        assert_eq!(written.len(), 2);
        let dir = run.path().join(RUNTIME_UNIT_DIR);
        assert!(
            std::fs::read_to_string(dir.join("a.service"))
                .unwrap()
                .contains("ExecStart")
        );
        let link = dir.join("multi-user.target.wants/a.service");
        assert_eq!(
            std::fs::read_link(&link).unwrap(),
            Path::new("../a.service")
        );
        assert!(link.exists(), "the wants link resolves");
        // Installing again replaces rather than failing.
        install_units(run.path(), &[unit("a.service")]).unwrap();
    }

    #[test]
    fn a_bad_unit_name_writes_nothing() {
        let run = tempfile::tempdir().unwrap();
        assert!(install_units(run.path(), &[unit("../../escape.service")]).is_err());
        assert!(mask_units(run.path(), &["x/y.swap".to_string()]).is_err());
        assert!(!run.path().join(RUNTIME_UNIT_DIR).exists());
    }

    #[test]
    fn best_effort_masks_rank_above_etc_and_never_replace_what_is_there() {
        let run = tempfile::tempdir().unwrap();
        let dir = run.path().join(RUNTIME_CONTROL_DIR);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("grub-common.service"), "[Unit]\n").unwrap();
        let written = mask_units_best_effort(
            run.path(),
            &[
                "systemd-boot-random-seed.service".to_string(),
                "grub-common.service".to_string(),
                "../escape.service".to_string(),
            ],
        );
        assert_eq!(written, vec![dir.join("systemd-boot-random-seed.service")]);
        assert_eq!(
            std::fs::read_link(&written[0]).unwrap(),
            Path::new("/dev/null")
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("grub-common.service")).unwrap(),
            "[Unit]\n",
            "an override of the decoy's own stays"
        );
        assert!(!run.path().join("systemd/escape.service").exists());
        assert!(mask_units_best_effort(run.path(), &[]).is_empty());
    }

    #[test]
    fn masks_point_at_dev_null() {
        let run = tempfile::tempdir().unwrap();
        mask_units(run.path(), &["dev-vda3.swap".to_string()]).unwrap();
        let link = run.path().join(RUNTIME_UNIT_DIR).join("dev-vda3.swap");
        assert_eq!(std::fs::read_link(link).unwrap(), Path::new("/dev/null"));
    }
}
