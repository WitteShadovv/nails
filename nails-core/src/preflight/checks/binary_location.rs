// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Binary-location pre-flight check.
//!
//! Validates that the running `nails` binary lives on the hidden volume rather
//! than on the decoy disk, and that it is not reached through a symlink planted
//! in a decoy `PATH` directory. A binary (or a pointer to it) sitting in a
//! forensically visible location defeats the point of hiding the environment it
//! manages, so this is surfaced as a warning the operator can act on — most
//! visibly through `nails check`. It reads through the automount guard
//! ([`crate::filesystem::automount`]): a `PATH` directory behind an
//! automount point that nothing is mounted on yet is not looked in, and the
//! warning says it cannot tell, naming the point.

use super::super::{CheckResult, PreFlightCheck};
use crate::filesystem::automount::{Guarded, OnSkip, Snapshot, describe, settle};
use crate::{Filesystem, Result};
use std::path::{Path, PathBuf};

/// Warns when the running binary, or a `PATH` symlink to it, is not on the
/// hidden volume.
///
/// The result is advisory (a warning, never a hard failure): a perfectly valid
/// deployment can install the binary in a standard location that points at a
/// separate vault, so this must not block activation. It still reports the
/// hygiene problem so an operator running `nails check` can move the binary onto
/// the hidden volume.
#[derive(Debug, Clone)]
pub struct BinaryLocationCheck {
    hidden_volume_root: PathBuf,
    /// Overrides the resolved running-binary path. Tests set this; production
    /// leaves it `None` and resolves `std::env::current_exe()` at run time.
    running_binary: Option<PathBuf>,
    /// The `PATH` directories probed for decoy symlinks, taken from the caller's
    /// `PATH` in the startup snapshot ([`Self::with_caller_path`]) or injected by
    /// a test. `None` probes nothing.
    path_dirs: Option<Vec<PathBuf>>,
}

impl BinaryLocationCheck {
    /// Create a check against the configured hidden volume root.
    pub fn new(hidden_volume_root: PathBuf) -> Self {
        Self {
            hidden_volume_root,
            running_binary: None,
            path_dirs: None,
        }
    }

    /// Probe the directories of the caller's `PATH` (from the startup
    /// snapshot) for decoy symlinks to the running binary.
    #[must_use]
    pub fn with_caller_path(mut self, caller_path: Option<&std::ffi::OsStr>) -> Self {
        self.path_dirs = caller_path.map(|path| std::env::split_paths(path).collect());
        self
    }

    /// Create a check with injected probes, for tests that cannot set the real
    /// `current_exe()` or `PATH`.
    #[cfg(test)]
    pub(crate) fn with_probes(
        hidden_volume_root: PathBuf,
        running_binary: PathBuf,
        path_dirs: Vec<PathBuf>,
    ) -> Self {
        Self {
            hidden_volume_root,
            running_binary: Some(running_binary),
            path_dirs: Some(path_dirs),
        }
    }

    /// The running binary path, or `None` inside this crate's test harness where
    /// the test binary lives in a cargo build tree and must not be treated as the
    /// deployed binary.
    fn resolve_binary(&self) -> Option<PathBuf> {
        if let Some(binary) = &self.running_binary {
            return Some(binary.clone());
        }
        if crate::runtime_safety::should_skip_host_interaction() {
            return None;
        }
        std::env::current_exe().ok()
    }

    /// The directories on `PATH` to probe for decoy symlinks.
    fn path_dirs(&self) -> Vec<PathBuf> {
        self.path_dirs.clone().unwrap_or_default()
    }
}

impl<F: Filesystem> PreFlightCheck<F> for BinaryLocationCheck {
    fn name(&self) -> &'static str {
        "binary-location"
    }

    fn description(&self) -> &'static str {
        "Warns when the running binary or a PATH symlink to it is not on the hidden volume"
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        let Some(binary) = self.resolve_binary() else {
            return Ok(CheckResult::Pass(
                "Binary-location check skipped in the test harness".into(),
            ));
        };
        // Without the table a lookup could mount an automount point, so none
        // is made.
        let snapshot = Snapshot::read(fs, Path::new("/"));
        if let Some(error) = snapshot.unreadable() {
            return Ok(CheckResult::Warn(format!(
                "NAILS cannot tell whether the running binary, or a link to it in a PATH \
                 directory, lies on the decoy disk: NAILS cannot read the mount table ({error}), \
                 which shows where a lookup would mount an automount point, so it looks up \
                 nothing"
            )));
        }
        let guarded = Guarded::new(fs.clone(), &snapshot);
        let result = self.judge(&guarded, &binary);
        Ok(settle(result, &guarded.skipped(), OnSkip::Warn))
    }
}

impl BinaryLocationCheck {
    /// The result for the running `binary`, read through `fs`.
    fn judge<F: Filesystem>(&self, fs: &F, binary: &Path) -> CheckResult {
        let binary = binary.to_path_buf();
        // Resolve symlinks where possible so the comparison holds against the
        // real on-disk location, not an intermediate symlink.
        let root = fs
            .canonicalize(&self.hidden_volume_root)
            .unwrap_or_else(|_| self.hidden_volume_root.clone());
        let resolved = fs.canonicalize(&binary).unwrap_or_else(|_| binary.clone());

        let mut warnings: Vec<String> = Vec::new();

        if !resolved.starts_with(&root) {
            warnings.push(format!(
                "the running binary {} is not under the hidden volume root {}; a copy on the decoy disk is a forensic artifact",
                resolved.display(),
                root.display()
            ));
        }

        // A symlink in a PATH directory outside the hidden root that resolves to
        // the running binary is a visible pointer to the hidden tool.
        if let Some(name) = resolved.file_name() {
            for dir in self.path_dirs() {
                if dir.starts_with(&root) {
                    continue;
                }
                let candidate = dir.join(name);
                match fs.is_symlink(&candidate) {
                    Ok(false) => {}
                    Ok(true) => {
                        let target = fs
                            .canonicalize(&candidate)
                            .unwrap_or_else(|_| candidate.clone());
                        if target == resolved {
                            warnings.push(format!(
                                "{} is a decoy PATH symlink pointing at the hidden binary",
                                candidate.display()
                            ));
                        }
                    }
                    // A link there would be a pointer to the hidden tool.
                    Err(error) => {
                        let shown = candidate.display().to_string();
                        warnings.push(format!(
                            "NAILS cannot tell whether {shown} is a link to the hidden binary: {}",
                            describe(&shown, &error).sentence
                        ));
                    }
                }
            }
        }

        if warnings.is_empty() {
            CheckResult::Pass(format!(
                "Running binary lives under the hidden volume root ({})",
                root.display()
            ))
        } else {
            CheckResult::Warn(warnings.join("; "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::MockFilesystem;

    #[test]
    fn passes_when_binary_is_under_the_hidden_root() {
        let fs = MockFilesystem::new();
        let check = BinaryLocationCheck::with_probes(
            PathBuf::from("/mnt/vault"),
            PathBuf::from("/mnt/vault/nails"),
            vec![PathBuf::from("/usr/bin")],
        );

        let result = check.run(&fs).unwrap();
        assert!(result.is_pass(), "{result:?}");
    }

    #[test]
    fn warns_when_binary_lives_on_the_decoy_disk() {
        let fs = MockFilesystem::new();
        let check = BinaryLocationCheck::with_probes(
            PathBuf::from("/mnt/vault"),
            PathBuf::from("/usr/local/bin/nails"),
            vec![],
        );

        let result = check.run(&fs).unwrap();
        assert!(result.is_warn(), "{result:?}");
        assert!(result.message().contains("decoy disk"), "{result:?}");
    }

    #[test]
    fn warns_when_a_decoy_path_symlink_points_at_the_hidden_binary() {
        let fs = MockFilesystem::new();
        let symlink = "/usr/local/bin/nails";
        // `create_symlink` records the link (marking it a symlink) so both
        // `is_symlink` and `canonicalize` resolve it to the hidden binary.
        fs.create_symlink(
            std::path::Path::new("/mnt/vault/nails"),
            std::path::Path::new(symlink),
        )
        .unwrap();

        let check = BinaryLocationCheck::with_probes(
            PathBuf::from("/mnt/vault"),
            PathBuf::from("/mnt/vault/nails"),
            vec![PathBuf::from("/usr/local/bin")],
        );

        let result = check.run(&fs).unwrap();
        assert!(result.is_warn(), "{result:?}");
        assert!(
            result.message().contains("decoy PATH symlink"),
            "{result:?}"
        );
    }

    /// A PATH directory whose lookup fails may hold a link to the hidden
    /// binary: the check warns that it cannot tell, where it passed.
    #[test]
    fn a_path_entry_nails_cannot_look_up_warns() {
        let fs = MockFilesystem::new();
        fs.mock_set_lookup_error("/usr/local/bin", std::io::ErrorKind::PermissionDenied);
        let check = BinaryLocationCheck::with_probes(
            PathBuf::from("/mnt/vault"),
            PathBuf::from("/mnt/vault/nails"),
            vec![PathBuf::from("/usr/bin"), PathBuf::from("/usr/local/bin")],
        );
        let result = check.run(&fs).unwrap();
        assert_eq!(
            result,
            CheckResult::Warn(
                "NAILS cannot tell whether /usr/local/bin/nails is a link to the hidden binary: \
                 NAILS cannot look up /usr/local/bin/nails; run the command again with sudo"
                    .to_string()
            )
        );
    }

    /// A PATH directory behind an automount point that nothing is mounted
    /// on yet is not looked in: the warning names the point and says once
    /// how to mount it. Without a mount table nothing is looked up.
    #[test]
    fn a_path_entry_behind_an_automount_point_warns_without_a_lookup() {
        use crate::filesystem::automount::mount_fix;
        use crate::preflight::checks::automount_fixture::{reached, with_automounts};
        let fs = MockFilesystem::new();
        with_automounts(&fs, &["/usr/local"]);
        let check = BinaryLocationCheck::with_probes(
            PathBuf::from("/mnt/vault"),
            PathBuf::from("/mnt/vault/nails"),
            vec![PathBuf::from("/usr/local/bin")],
        );
        let result = check.run(&fs).unwrap();
        assert!(result.is_warn(), "{result:?}");
        let message = result.message();
        assert!(
            message.starts_with(
                "NAILS cannot tell whether /usr/local/bin/nails is a link to the hidden binary: \
                 NAILS does not look up /usr/local/bin/nails, since the lookup would mount the \
                 automount point /usr/local"
            ),
            "{message}"
        );
        let fix = mount_fix(&[std::path::Path::new("/usr/local")]);
        assert_eq!(message.matches(fix.as_str()).count(), 1, "{message}");
        assert!(!reached(&fs, "/usr/local"), "{:?}", fs.mock_lookups());

        fs.mock_set_mount_table_error("no mountinfo");
        let result = check.run(&fs).unwrap();
        assert!(result.is_warn(), "{result:?}");
        assert!(
            result.message().contains("so it looks up nothing"),
            "{result:?}"
        );
    }

    #[test]
    fn metadata_is_stable() {
        let check = BinaryLocationCheck::new(PathBuf::from("/mnt/vault"));
        assert_eq!(
            <BinaryLocationCheck as PreFlightCheck<MockFilesystem>>::name(&check),
            "binary-location"
        );
    }
}
