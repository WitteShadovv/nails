// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Suspicious NAILS/base-config reference pre-flight check.

use super::{CheckResult, PreFlightCheck};
use crate::filesystem::automount::{Guarded, OnSkip, Snapshot, settle};
use crate::nixos::config::BaseConfigScan;
use crate::{Filesystem, Result, verify_base_config_clean};
use std::path::{Path, PathBuf};

/// The decoy's own configuration directory, which the check reads.
const DECOY_NIXOS_DIR: &str = "/etc/nixos";

/// Refuses activation while the decoy's own `/etc/nixos` names the hidden
/// environment: the hidden volume's device or mount point (or the units
/// systemd names after them), the storage it is on by its device paths, every
/// link udev made for it, its uuids and its labels, its mapping where a line
/// opens it, or NAILS ([`verify_base_config_clean`] lists the forms).
#[derive(Debug, Clone, Default)]
pub struct SuspiciousNailsReferenceCheck {
    hidden_volume_root: PathBuf,
}

impl SuspiciousNailsReferenceCheck {
    /// Creates a check that matches the base config against the configured hidden root.
    pub fn new(hidden_volume_root: PathBuf) -> Self {
        Self { hidden_volume_root }
    }
}

impl<F: Filesystem> PreFlightCheck<F> for SuspiciousNailsReferenceCheck {
    fn name(&self) -> &'static str {
        "suspicious-nails-reference"
    }

    fn description(&self) -> &'static str {
        "Fails before activation if the decoy's /etc/nixos names the hidden volume, its device or mount point, or NAILS"
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        // /etc/nixos, or a link in it, can lead into a home, and a home can
        // lie behind an automount point that nothing is mounted on yet: the
        // walk of the scan would mount the point. Each lookup of the walk is
        // asked of the automount guard first, and where one would mount a
        // point, or the mount table cannot be read, nothing is read and the
        // check refuses, since it cannot tell.
        // The walk is asked about as a whole before the scan makes it, so
        // its answers are as old as the walk either way, and the view reads
        // each place on the way once: a `result` link in /etc/nixos leads
        // the walk through a whole system closure in the store.
        let guarded = Guarded::new(fs.clone(), &Snapshot::read(fs, Path::new("/")));
        ask_the_walk(&guarded.remembering(), Path::new(DECOY_NIXOS_DIR));
        let skipped = guarded.skipped();
        if let Some(first) = skipped.first() {
            let refusal = CheckResult::fail(format!(
                "NAILS cannot tell whether the decoy's /etc/nixos names the hidden environment: {}",
                first.reason.sentence(&first.path)
            ));
            return Ok(settle(refusal, &skipped, OnSkip::Refuse(None)));
        }
        let scan = verify_base_config_clean(fs, &self.hidden_volume_root)?;
        Ok(scan_result(&scan))
    }
}

/// Ask `guarded` about each lookup the scan's walk of `dir` makes
/// ([`Filesystem::find_files_with_pattern`]): whether `dir` is a directory,
/// its listing, and for each entry whether it is a directory to walk, its
/// links followed. A lookup the guard does not make is kept in its ledger;
/// one that fails for another reason is left to the walk, which reads it as
/// before.
fn ask_the_walk<F: Filesystem>(guarded: &Guarded<F>, dir: &Path) {
    if matches!(guarded.is_directory(dir), Ok(true)) {
        ask_the_listing(guarded, dir);
    }
}

/// [`ask_the_walk`] of `dir`, a directory: its listing, and each entry.
fn ask_the_listing<F: Filesystem>(guarded: &Guarded<F>, dir: &Path) {
    let Ok(entries) = guarded.list_directory(dir) else {
        return;
    };
    for entry in entries {
        // Whether an entry is a file is the same lookup as whether it is a
        // directory, so asking that once asks both.
        if matches!(guarded.is_directory(&entry), Ok(true)) {
            ask_the_listing(guarded, &entry);
        }
    }
}

/// The check result for a scan: the first reference with its file, line,
/// text, reason and remedy, or what was read.
fn scan_result(scan: &BaseConfigScan) -> CheckResult {
    let Some(first) = scan.references.first() else {
        return CheckResult::Pass(match scan.files_read {
            0 => "No .nix file under /etc/nixos, so nothing was inspected; a configuration \
                  kept elsewhere is not checked"
                .to_string(),
            1 => "The one .nix file under /etc/nixos names nothing of the hidden environment"
                .to_string(),
            files => {
                format!(
                    "The {files} .nix files under /etc/nixos name nothing of the hidden environment"
                )
            }
        });
    };
    let more = match scan.references.len() - 1 {
        0 => String::new(),
        1 => " One more line does too.".to_string(),
        lines => format!(" {lines} more lines do too."),
    };
    CheckResult::fail_with(
        format!(
            "The decoy's /etc/nixos names the hidden environment: {}, line {}: '{}' ({}). An \
             examination of the decoy reads this file.{more}",
            first.file.display(),
            first.line,
            first.text,
            first.kind.reason()
        ),
        first.kind.remedy(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::MockFilesystem;
    use std::path::Path;

    fn run_on(files: &[(&str, &str)]) -> CheckResult {
        let fs = MockFilesystem::new();
        for (path, content) in files {
            fs.mock_set_file_content(path, content);
        }
        let paths: Vec<&Path> = files.iter().map(|(path, _)| Path::new(*path)).collect();
        fs.mock_set_files_with_pattern("/etc/nixos", ".nix", &paths);
        SuspiciousNailsReferenceCheck::new(PathBuf::from("/mnt/hidden"))
            .run(&fs)
            .unwrap()
    }

    #[test]
    fn a_clean_base_config_passes_and_says_what_was_read() {
        let one = run_on(&[(
            "/etc/nixos/hardware-configuration.nix",
            "{ config, lib, pkgs, ... }: { }",
        )]);
        assert!(one.is_pass());
        assert!(one.message().contains("one .nix file"), "{one:?}");

        let two = run_on(&[
            ("/etc/nixos/configuration.nix", "{ }"),
            ("/etc/nixos/hardware-configuration.nix", "{ }"),
        ]);
        assert!(two.is_pass());
        assert!(two.message().contains("The 2 .nix files"), "{two:?}");
    }

    /// Without a `.nix` file the check passes but says it inspected nothing,
    /// instead of claiming the configuration is clean.
    #[test]
    fn no_nix_file_passes_and_says_nothing_was_inspected() {
        let result = run_on(&[]);
        assert!(result.is_pass());
        assert!(
            result.message().contains("nothing was inspected"),
            "{result:?}"
        );
    }

    #[test]
    fn a_reference_fails_with_its_file_line_text_reason_and_remedy() {
        let result = run_on(&[(
            "/etc/nixos/hardware-configuration.nix",
            "{\n  imports = [ ./nails/configuration.nix ];\n}\n",
        )]);
        assert!(result.is_fail());
        let message = result.message();
        for part in [
            "/etc/nixos/hardware-configuration.nix, line 2",
            "'./nails/configuration.nix'",
            "(text NAILS writes during a session)",
        ] {
            assert!(message.contains(part), "{part} missing: {message}");
        }
        assert!(!message.contains("more line"), "{message}");
        assert!(
            result
                .remediation()
                .is_some_and(|remedy| remedy.starts_with("Remove it from that file")),
            "{result:?}"
        );
    }

    #[test]
    fn further_references_are_counted() {
        let result = run_on(&[
            ("/etc/nixos/a.nix", "{ config.nails.enable = true; }"),
            (
                "/etc/nixos/b.nix",
                "{\n  fileSystems.\"/mnt/hidden\" = { };\n  x = \"mnt-hidden.mount\";\n  y = \"plausible\";\n}",
            ),
        ]);
        assert!(result.is_fail());
        assert!(result.message().contains("/etc/nixos/a.nix, line 1"));
        assert!(
            result.message().ends_with(" 2 more lines do too."),
            "{result:?}"
        );

        let result = run_on(&[(
            "/etc/nixos/a.nix",
            "{ x = /mnt/hidden;\n y = /mnt/hidden; }",
        )]);
        assert!(
            result.message().ends_with(" One more line does too."),
            "{result:?}"
        );
    }

    /// An /etc/nixos that links into a home behind an automount point that
    /// nothing is mounted on yet is not read: the check refuses, naming the
    /// point, and looks up nothing at or below it. Without the mount table it
    /// reads nothing either. Once the point is mounted it reads the files.
    #[test]
    fn an_etc_nixos_behind_an_automount_point_is_not_read() {
        let fs = MockFilesystem::new();
        fs.create_symlink(Path::new("/home/alice/nixos"), Path::new("/etc/nixos"))
            .unwrap();
        let file = Path::new("/etc/nixos/configuration.nix");
        fs.mock_set_file_content(file.to_str().unwrap(), "{ config.nails.enable = true; }");
        fs.mock_set_files_with_pattern("/etc/nixos", ".nix", &[file]);
        let root = "1 0 8:1 / / rw,relatime - ext4 /dev/vda1 rw\n";
        fs.mock_set_mount_table(&format!(
            "{root}30 1 0:50 / /home/alice rw,relatime - autofs systemd-1 \
             rw,fd=50,pgrp=1,timeout=0,minproto=5,maxproto=5,direct,pipe_ino=100\n"
        ));
        fs.mock_clear_lookups();
        let check = SuspiciousNailsReferenceCheck::new(PathBuf::from("/mnt/hidden"));

        let result = check.run(&fs).unwrap();
        assert_eq!(
            result,
            CheckResult::fail_with(
                "NAILS cannot tell whether the decoy's /etc/nixos names the hidden environment: \
                 NAILS does not look up /etc/nixos, since the lookup would mount the automount \
                 point /home/alice",
                crate::filesystem::automount::mount_fix(&[Path::new("/home/alice")]),
            )
        );
        // The guard reads the link itself, and nothing behind it.
        assert!(
            fs.mock_lookups().iter().all(|path| {
                !path.starts_with("/home/alice")
                    && (path == Path::new("/etc/nixos") || !path.starts_with("/etc/nixos"))
            }),
            "{:?}",
            fs.mock_lookups()
        );

        fs.mock_set_mount_table(root);
        let result = check.run(&fs).unwrap();
        assert!(result.is_fail(), "{result:?}");
        assert!(
            result
                .message()
                .starts_with("The decoy's /etc/nixos names the hidden environment"),
            "{result:?}"
        );

        // The error stays set from here on.
        fs.mock_set_mount_table_error("permission denied");
        let result = check.run(&fs).unwrap();
        assert!(result.is_fail(), "{result:?}");
        assert!(
            result.message().contains(
                "NAILS does not look up /etc/nixos, since it cannot read the mount table"
            ),
            "{result:?}"
        );
        assert_eq!(result.remediation(), None);
    }

    /// A link inside /etc/nixos that leads behind an automount point that
    /// nothing is mounted on yet keeps the walk from it: the check refuses
    /// naming the point, and nothing behind the link is looked up.
    #[test]
    fn a_link_in_etc_nixos_behind_an_automount_point_is_not_followed() {
        use crate::filesystem::PathKind;
        let fs = MockFilesystem::new();
        fs.mock_set_path_type("/etc/nixos", PathKind::Dir);
        let file = Path::new("/etc/nixos/configuration.nix");
        let hosts = Path::new("/etc/nixos/hosts");
        fs.mock_set_file_content(file.to_str().unwrap(), "{ }");
        fs.mock_set_directory_contents(
            Path::new("/etc/nixos"),
            vec![file.to_path_buf(), hosts.to_path_buf()],
        );
        fs.create_symlink(Path::new("/home/alice/hosts"), hosts)
            .unwrap();
        fs.mock_set_files_with_pattern("/etc/nixos", ".nix", &[file]);
        fs.mock_set_mount_table(
            "1 0 8:1 / / rw,relatime - ext4 /dev/vda1 rw\n\
             30 1 0:50 / /home/alice rw,relatime - autofs systemd-1 \
             rw,fd=50,pgrp=1,timeout=0,minproto=5,maxproto=5,direct,pipe_ino=100\n",
        );
        fs.mock_clear_lookups();
        let result = SuspiciousNailsReferenceCheck::new(PathBuf::from("/mnt/hidden"))
            .run(&fs)
            .unwrap();
        assert_eq!(
            result,
            CheckResult::fail_with(
                "NAILS cannot tell whether the decoy's /etc/nixos names the hidden environment: \
                 NAILS does not look up /etc/nixos/hosts, since the lookup would mount the \
                 automount point /home/alice",
                crate::filesystem::automount::mount_fix(&[Path::new("/home/alice")]),
            )
        );
        assert!(
            fs.mock_lookups()
                .iter()
                .all(|path| !path.starts_with("/home/alice")),
            "{:?}",
            fs.mock_lookups()
        );
    }

    /// A decoy whose /etc/nixos holds `configuration.nix` and the directory
    /// `hosts`, in which `laptop` links into alice's home, a direct
    /// automount point that nothing is mounted on yet.
    fn a_host_linked_into_an_unmounted_home() -> MockFilesystem {
        use crate::filesystem::PathKind;
        let fs = MockFilesystem::new();
        fs.mock_set_path_type("/etc/nixos", PathKind::Dir);
        fs.mock_set_path_type("/etc/nixos/hosts", PathKind::Dir);
        let file = Path::new("/etc/nixos/configuration.nix");
        let hosts = Path::new("/etc/nixos/hosts");
        let laptop = Path::new("/etc/nixos/hosts/laptop");
        fs.mock_set_file_content(file.to_str().unwrap(), "{ }");
        fs.mock_set_directory_contents(
            Path::new("/etc/nixos"),
            vec![file.to_path_buf(), hosts.to_path_buf()],
        );
        fs.mock_set_directory_contents(hosts, vec![laptop.to_path_buf()]);
        fs.create_symlink(Path::new("/home/alice/laptop"), laptop)
            .unwrap();
        fs.mock_set_files_with_pattern("/etc/nixos", ".nix", &[file]);
        fs.mock_set_mount_table(
            "1 0 8:1 / / rw,relatime - ext4 /dev/vda1 rw\n\
             30 1 0:50 / /home/alice rw,relatime - autofs systemd-1 \
             rw,fd=50,pgrp=1,timeout=0,minproto=5,maxproto=5,direct,pipe_ino=100\n",
        );
        fs.mock_clear_lookups();
        fs
    }

    /// How often `path` was looked up on `fs`.
    fn times(fs: &MockFilesystem, path: &str) -> usize {
        fs.mock_lookups()
            .iter()
            .filter(|asked| *asked == Path::new(path))
            .count()
    }

    /// The walk goes into each directory of /etc/nixos, so a link below its
    /// top that leads behind an automount point keeps it from there too.
    /// Each place on the way is read once, and each directory is asked once
    /// whether it is one.
    #[test]
    fn a_link_deeper_in_etc_nixos_behind_an_automount_point_is_not_followed() {
        let fs = a_host_linked_into_an_unmounted_home();
        let result = SuspiciousNailsReferenceCheck::new(PathBuf::from("/mnt/hidden"))
            .run(&fs)
            .unwrap();
        assert_eq!(
            result,
            CheckResult::fail_with(
                "NAILS cannot tell whether the decoy's /etc/nixos names the hidden environment: \
                 NAILS does not look up /etc/nixos/hosts/laptop, since the lookup would mount \
                 the automount point /home/alice",
                crate::filesystem::automount::mount_fix(&[Path::new("/home/alice")]),
            )
        );
        assert!(
            fs.mock_lookups()
                .iter()
                .all(|path| !path.starts_with("/home/alice")),
            "{:?}",
            fs.mock_lookups()
        );
        // The guard read /etc once; hosts was read by the guard, asked
        // whether it is a directory, and listed.
        assert_eq!(times(&fs, "/etc"), 1, "{:?}", fs.mock_lookups());
        assert_eq!(times(&fs, "/etc/nixos/hosts"), 3, "{:?}", fs.mock_lookups());
    }

    /// A directory of /etc/nixos the walk cannot list is left to the scan,
    /// which reads it as before: the walk asks about nothing below it.
    #[test]
    fn a_directory_of_etc_nixos_the_walk_cannot_list_is_left_to_the_scan() {
        let fs = a_host_linked_into_an_unmounted_home();
        fs.mock_set_unreadable_dir("/etc/nixos/hosts");
        let result = SuspiciousNailsReferenceCheck::new(PathBuf::from("/mnt/hidden"))
            .run(&fs)
            .unwrap();
        assert!(result.is_pass(), "{result:?}");
        assert!(
            fs.mock_lookups()
                .iter()
                .all(|path| !path.starts_with("/etc/nixos/hosts/laptop")
                    && !path.starts_with("/home/alice")),
            "{:?}",
            fs.mock_lookups()
        );
    }

    #[test]
    fn suspicious_reference_check_metadata_is_stable() {
        let check = SuspiciousNailsReferenceCheck::default();
        assert_eq!(
            <SuspiciousNailsReferenceCheck as PreFlightCheck<MockFilesystem>>::name(&check),
            "suspicious-nails-reference"
        );
        assert!(
            <SuspiciousNailsReferenceCheck as PreFlightCheck<MockFilesystem>>::description(&check)
                .contains("decoy's /etc/nixos")
        );
    }
}
