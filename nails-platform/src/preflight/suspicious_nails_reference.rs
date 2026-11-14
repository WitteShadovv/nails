// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Suspicious NAILS/base-config reference pre-flight check.

use super::{CheckResult, PreFlightCheck};
use crate::filesystem::automount::{Guarded, OnSkip, Snapshot, describe, settle};
use crate::nixos::config::BaseConfigScan;
use crate::{Filesystem, NailsError, Result, verify_base_config_clean};
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
        let unseen = ask_the_walk(&guarded.remembering(), Path::new(DECOY_NIXOS_DIR));
        let skipped = guarded.skipped();
        if let Some(first) = skipped.first() {
            let refusal = CheckResult::fail(format!(
                "NAILS cannot tell whether the decoy's /etc/nixos names the hidden environment: {}",
                first.reason.sentence(&first.path)
            ));
            return Ok(settle(refusal, &skipped, OnSkip::Refuse(None)));
        }
        if let Some((path, error)) = unseen {
            return Ok(cannot_tell(
                &describe(&path.display().to_string(), &error).sentence,
            ));
        }
        match verify_base_config_clean(fs, &self.hidden_volume_root) {
            Ok(scan) => Ok(scan_result(&scan)),
            Err(error) => Ok(cannot_tell(&error.to_string())),
        }
    }
}

/// The refusal where NAILS cannot tell whether the decoy's `/etc/nixos`
/// names the hidden environment, for `why`.
fn cannot_tell(why: &str) -> CheckResult {
    CheckResult::fail(format!(
        "NAILS cannot tell whether the decoy's /etc/nixos names the hidden environment: {why}"
    ))
}

/// Ask `guarded` about each lookup the scan's walk of `dir` makes
/// ([`Filesystem::find_files_with_pattern`]): whether `dir` is a directory,
/// its listing, and for each entry whether it is a directory to walk, its
/// links followed. A lookup the guard does not make is kept in its ledger.
/// The first that fails for another reason than that nothing is there comes
/// back with its error: the walk takes such a place for one without a
/// `.nix` file, while it may hold one.
fn ask_the_walk<F: Filesystem>(guarded: &Guarded<F>, dir: &Path) -> Option<(PathBuf, NailsError)> {
    match guarded.is_directory(dir) {
        Ok(true) => ask_the_listing(guarded, dir),
        Ok(false) => None,
        Err(error) => unseen(dir, error),
    }
}

/// [`ask_the_walk`] of `dir`, a directory: its listing, and each entry.
fn ask_the_listing<F: Filesystem>(
    guarded: &Guarded<F>,
    dir: &Path,
) -> Option<(PathBuf, NailsError)> {
    let entries = match guarded.list_directory(dir) {
        Ok(entries) => entries,
        Err(error) => return unseen(dir, error),
    };
    for entry in entries {
        // Whether an entry is a file is the same lookup as whether it is a
        // directory, so asking that once asks both.
        let found = match guarded.is_directory(&entry) {
            Ok(true) => ask_the_listing(guarded, &entry),
            Ok(false) => None,
            Err(error) => unseen(&entry, error),
        };
        if found.is_some() {
            return found;
        }
    }
    None
}

/// `path` with `error`, the failure of its lookup, when it leaves NAILS
/// unable to tell what is there: not where nothing is there, and not for a
/// lookup the guard did not make, which its ledger keeps.
fn unseen(path: &Path, error: NailsError) -> Option<(PathBuf, NailsError)> {
    (!error.nothing_there() && error.not_looked_up().is_none()).then(|| (path.to_path_buf(), error))
}

/// The check result for a scan: the first reference with its file, line,
/// text, reason and remedy, else, where a place that names the hidden
/// volume's storage could not be read, the refusal that NAILS cannot tell,
/// or what was read.
fn scan_result(scan: &BaseConfigScan) -> CheckResult {
    let Some(first) = scan.references.first() else {
        if scan.files_read > 0 && !scan.unread.is_empty() {
            return cannot_tell(&format!(
                "NAILS cannot read {}, which may give a name of the hidden volume's storage that \
                 a file there could use",
                scan.unread.join(", ")
            ));
        }
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

    /// A place of /etc/nixos that cannot be looked up for another reason
    /// than that nothing is there may hold a `.nix` file that names the
    /// hidden environment: the walk took it for one without, and the check
    /// passed. It now refuses, naming the place. An entry that leads to
    /// nothing holds none.
    #[test]
    fn a_place_of_etc_nixos_that_cannot_be_looked_up_refuses() {
        use crate::filesystem::{MockFailure, MockLookup, PathKind};
        let decoy = || {
            let fs = MockFilesystem::new();
            fs.mock_set_path_type("/etc/nixos", PathKind::Dir);
            let file = Path::new("/etc/nixos/configuration.nix");
            fs.mock_set_file_content(file.to_str().unwrap(), "{ }");
            fs.mock_set_directory_contents(
                Path::new("/etc/nixos"),
                vec![file.to_path_buf(), PathBuf::from("/etc/nixos/hosts")],
            );
            fs.mock_set_files_with_pattern("/etc/nixos", ".nix", &[file]);
            fs
        };
        let check = SuspiciousNailsReferenceCheck::new(PathBuf::from("/mnt/hidden"));

        let fs = decoy();
        fs.mock_set_lookup_error("/etc/nixos", std::io::ErrorKind::PermissionDenied);
        assert_eq!(
            check.run(&fs).unwrap(),
            CheckResult::fail(
                "NAILS cannot tell whether the decoy's /etc/nixos names the hidden environment: \
                 NAILS cannot look up /etc/nixos; run the command again with sudo"
            )
        );

        let fs = decoy();
        fs.mock_fail_only(
            Path::new("/etc/nixos/hosts"),
            MockLookup::IsDirectory,
            MockFailure::Io(std::io::ErrorKind::Other),
        );
        let result = check.run(&fs).unwrap();
        assert!(result.is_fail(), "{result:?}");
        assert!(
            result.message().starts_with(
                "NAILS cannot tell whether the decoy's /etc/nixos names the hidden environment: \
                 NAILS cannot look up /etc/nixos/hosts ("
            ),
            "{result:?}"
        );

        let fs = decoy();
        fs.mock_set_lookup_error("/etc/nixos/hosts", std::io::ErrorKind::NotFound);
        assert!(check.run(&fs).unwrap().is_pass());
    }

    /// A place that gives a name of the hidden volume's storage, which the
    /// scan could not read, leaves NAILS unable to tell whether a file names
    /// the storage by it: the check refuses, where it passed on the names it
    /// could read. Without a file to read it passes as before.
    #[test]
    fn a_name_of_the_storage_the_scan_cannot_read_refuses() {
        let scan = BaseConfigScan {
            files_read: 1,
            references: Vec::new(),
            unread: vec!["/run/udev/data/b8:18".to_string()],
        };
        assert_eq!(
            scan_result(&scan),
            CheckResult::fail(
                "NAILS cannot tell whether the decoy's /etc/nixos names the hidden environment: \
                 NAILS cannot read /run/udev/data/b8:18, which may give a name of the hidden \
                 volume's storage that a file there could use"
            )
        );
        let nothing_read = BaseConfigScan {
            files_read: 0,
            ..scan
        };
        assert!(scan_result(&nothing_read).is_pass());
    }

    /// The mount table, read to name the hidden volume's devices, that cannot
    /// be read leaves NAILS unable to tell whether a file names one of them:
    /// the check refuses, where it read no device and passed.
    #[test]
    fn a_mount_table_the_scan_cannot_read_refuses() {
        let fs = MockFilesystem::new();
        let file = Path::new("/etc/nixos/configuration.nix");
        fs.mock_set_file_content(file.to_str().unwrap(), "{ }");
        fs.mock_set_files_with_pattern("/etc/nixos", ".nix", &[file]);
        fs.mock_set_lookup_error("/proc/self/mountinfo", std::io::ErrorKind::Other);
        let result = SuspiciousNailsReferenceCheck::new(PathBuf::from("/mnt/hidden"))
            .run(&fs)
            .unwrap();
        assert!(result.is_fail(), "{result:?}");
        assert!(
            result.message().starts_with(
                "NAILS cannot tell whether the decoy's /etc/nixos names the hidden environment: \
                 /proc/self/mountinfo"
            ),
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

    /// A directory of /etc/nixos the walk cannot list may hold a `.nix`
    /// file: the check refuses, naming it, where the walk left it to the
    /// scan and the scan's mock passed. The walk asks about nothing below it.
    #[test]
    fn a_directory_of_etc_nixos_the_walk_cannot_list_refuses() {
        let fs = a_host_linked_into_an_unmounted_home();
        fs.mock_set_unreadable_dir("/etc/nixos/hosts");
        let result = SuspiciousNailsReferenceCheck::new(PathBuf::from("/mnt/hidden"))
            .run(&fs)
            .unwrap();
        assert_eq!(
            result,
            CheckResult::fail(
                "NAILS cannot tell whether the decoy's /etc/nixos names the hidden environment: \
                 NAILS cannot look up /etc/nixos/hosts; run the command again with sudo"
            )
        );
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
