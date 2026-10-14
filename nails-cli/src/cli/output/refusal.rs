// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! A refused root, reported the same way by every command.
//!
//! The text and the codes come from the attach gate
//! ([`nails_core::hidden_root::refusal`]); this turns them into the error
//! envelope (`--json`) or the human error with one indented line per hint, and
//! exits with [`ExitStatus::PreflightRefused`].

use std::path::Path;

use nails_core::hidden_root::Refusal;

use super::ExitStatus;
use super::envelope::{ErrorBody, report_error};

/// The error body of a refused root. `exe` is the running program, named in
/// the hint when it lies under the root.
pub fn refusal_error(refusal: &Refusal, exe: Option<&Path>) -> ErrorBody {
    ErrorBody::new(refusal.code(), refusal.message()).with_hint(refusal.hint(exe).join("\n"))
}

/// Report a refused root on the terminal (or as one envelope under `--json`)
/// and return [`ExitStatus::PreflightRefused`].
pub fn report_refusal(json: bool, command: &'static str, refusal: &Refusal) -> ExitStatus {
    let exe = std::env::current_exe().ok();
    report_error(
        json,
        command,
        ExitStatus::PreflightRefused,
        refusal_error(refusal, exe.as_deref()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::output::envelope::{error_envelope, write_human_error};
    use nails_core::hidden_root::RefusalKind;
    use nails_core::hidden_root::separation::{Claimed, Sharing, Verdict};
    use std::path::PathBuf;

    fn human(refusal: &Refusal, exe: Option<&Path>) -> String {
        let mut out = Vec::new();
        write_human_error(&mut out, &refusal_error(refusal, exe));
        String::from_utf8(out).unwrap()
    }

    fn refusal(kind: RefusalKind) -> Refusal {
        Refusal::new(kind, Path::new("/mnt"))
    }

    fn on(verdict: Verdict) -> Refusal {
        refusal(RefusalKind::DecoyStorage { verdict })
    }

    #[test]
    fn a_folder_snapshot() {
        let folder = refusal(RefusalKind::NotAMountPoint {
            mount_point: PathBuf::from("/"),
        });
        insta::assert_snapshot!("folder", human(&folder, None));
        insta::assert_snapshot!(
            "folder_with_the_program_on_it",
            human(&folder, Some(Path::new("/mnt/nails")))
        );
    }

    #[test]
    fn decoy_storage_snapshots() {
        let home = || PathBuf::from("/home");
        let cases = [
            (
                "subvolume",
                Verdict::OnDecoyFilesystem {
                    how: Sharing::Subvolume,
                    at: home(),
                },
            ),
            (
                "bind",
                Verdict::OnDecoyFilesystem {
                    how: Sharing::Bind,
                    at: home(),
                },
            ),
            (
                "fstab_filesystem",
                Verdict::OnDecoyFilesystem {
                    how: Sharing::Filesystem,
                    at: PathBuf::from("/srv"),
                },
            ),
            (
                "inside_storage",
                Verdict::InsideDecoyStorage {
                    device: "dm-0".into(),
                    holds: Claimed::Mount(PathBuf::from("/")),
                    noauto_only: false,
                },
            ),
            (
                "swap",
                Verdict::InsideDecoyStorage {
                    device: "sda3".into(),
                    holds: Claimed::Swap("/dev/sda3".into()),
                    noauto_only: false,
                },
            ),
            (
                "image_file",
                Verdict::ImageFileOnDecoy {
                    file: PathBuf::from("/home/u/disk.img"),
                    at: home(),
                },
            ),
            (
                "container_file",
                Verdict::ContainerOnDecoy {
                    file: PathBuf::from("/home/u/files.bin"),
                    at: home(),
                },
            ),
        ];
        for (name, verdict) in cases {
            insta::assert_snapshot!(name, human(&on(verdict), None));
        }
    }

    #[test]
    fn the_other_refusal_snapshots() {
        let cases = [
            ("missing", RefusalKind::Missing),
            (
                "mount_table_unreadable",
                RefusalKind::MountTableUnreadable {
                    error: "permission denied".into(),
                },
            ),
            ("same_device_as_root", RefusalKind::SameDeviceAsRoot),
            (
                "covered",
                RefusalKind::Covered {
                    below: PathBuf::from("/dev/mapper/data"),
                    above: PathBuf::from("/dev/sdc1"),
                },
            ),
            (
                "not_the_session_volume",
                RefusalKind::NotTheSessionVolume {
                    source: PathBuf::from("/dev/sdc1"),
                },
            ),
            (
                "storage_unjudged",
                RefusalKind::StorageUnjudged {
                    unreadable: vec![PathBuf::from("/etc/crypttab")],
                },
            ),
        ];
        for (name, kind) in cases {
            insta::assert_snapshot!(name, human(&refusal(kind), None));
        }
    }

    #[test]
    fn the_envelope_carries_each_code() {
        for (kind, code) in [
            (
                RefusalKind::NotAMountPoint {
                    mount_point: PathBuf::from("/"),
                },
                "not_separate_volume",
            ),
            (
                RefusalKind::Covered {
                    below: PathBuf::from("/dev/a"),
                    above: PathBuf::from("/dev/b"),
                },
                "root_covered",
            ),
            (
                RefusalKind::StorageUnjudged {
                    unreadable: vec![PathBuf::from("/etc/crypttab")],
                },
                "storage_unjudged",
            ),
        ] {
            let line = error_envelope("init", refusal_error(&refusal(kind), None)).to_line();
            let value: serde_json::Value = serde_json::from_str(&line).unwrap();
            assert_eq!(value["error"]["code"], code, "{line}");
            assert!(
                value["error"]["message"]
                    .as_str()
                    .unwrap()
                    .ends_with("Nothing was written.")
            );
            assert!(value["error"]["hint"].is_string(), "{line}");
        }
    }

    #[test]
    fn every_hint_line_is_indented() {
        let text = human(
            &refusal(RefusalKind::NotAMountPoint {
                mount_point: PathBuf::from("/"),
            }),
            None,
        );
        let mut lines = text.lines();
        assert!(lines.next().unwrap().starts_with("error: "));
        let rest: Vec<&str> = lines.collect();
        assert!(rest.len() > 1, "{text}");
        assert!(rest.iter().all(|line| line.starts_with("  ")), "{text}");
    }
}
