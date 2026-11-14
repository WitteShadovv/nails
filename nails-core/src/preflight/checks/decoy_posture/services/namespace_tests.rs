// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::filesystem::MockFilesystem;

/// The `[Service]` assignments of `text`, one `Key=value` a line.
fn section(text: &str) -> Vec<Assignment> {
    text.lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| Assignment {
            key: key.to_string(),
            value: value.to_string(),
        })
        .collect()
}

#[test]
fn a_unit_s_namespace_is_its_last_log_namespace_systemd_takes() {
    for (text, namespace) in [
        ("", None),
        ("LogNamespace=tuned", Some("tuned")),
        ("LogNamespace=a\nLogNamespace=b", Some("b")),
        // An empty value sets none.
        ("LogNamespace=a\nLogNamespace=", None),
        // A name systemd does not take is ignored, which leaves the one
        // before.
        ("LogNamespace=a\nLogNamespace=b/c", Some("a")),
        ("LogNamespace=a\nLogNamespace=..", Some("a")),
        ("LogNamespace=a\nLogNamespace=x y", Some("a")),
        ("LogNamespace=a\nLogNamespace=back\\slash", Some("a")),
        ("LogNamespace=fw.1:x_y-z@q", Some("fw.1:x_y-z@q")),
        // A specifier NAILS does not expand, overridden by a later value.
        ("LogNamespace=%N\nLogNamespace=fw", Some("fw")),
        ("LogNamespace=%N\nLogNamespace=", None),
    ] {
        assert_eq!(
            of_unit(&section(text)),
            Ok(namespace.map(str::to_string)),
            "{text:?}"
        );
    }
    assert_eq!(
        of_unit(&section("LogNamespace=fw\nLogNamespace=%N")),
        Err("NAILS does not expand the specifiers of its LogNamespace=%N".to_string())
    );
}

/// A mount table line that mounts `root` of the `/run` tmpfs at
/// `mount_point`.
fn mount(root: &str, mount_point: &str) -> String {
    format!("612 590 0:25 {root} {mount_point} ro,nosuid,nodev - tmpfs tmpfs rw,mode=755\n")
}

#[test]
fn a_process_s_namespace_is_the_journal_directory_mounted_over_its_own() {
    let fs = MockFilesystem::new();
    let root = Path::new("/");
    let base = "36 35 0:32 / / rw,noatime shared:1 - btrfs /dev/vda3 rw\n\
                40 36 0:25 / /run rw,nosuid,nodev - tmpfs tmpfs rw,mode=755\n";
    fs.mock_add_file("/proc/812/mountinfo", base);
    assert_eq!(of_process(&fs, root, "812"), Ok(None));
    fs.mock_add_file(
        "/proc/812/mountinfo",
        &format!(
            "{base}{}",
            mount("/systemd/journal.tuned", "/run/systemd/journal")
        ),
    );
    assert_eq!(of_process(&fs, root, "812"), Ok(Some("tuned".to_string())));
    // The mount on top counts.
    fs.mock_add_file(
        "/proc/812/mountinfo",
        &format!(
            "{base}{}{}",
            mount("/systemd/journal.a", "/run/systemd/journal"),
            mount("/systemd/journal.b", "/run/systemd/journal")
        ),
    );
    assert_eq!(of_process(&fs, root, "812"), Ok(Some("b".to_string())));
    // Something else mounted there leads NAILS cannot tell where.
    fs.mock_add_file(
        "/proc/812/mountinfo",
        &format!("{base}{}", mount("/elsewhere", "/run/systemd/journal")),
    );
    assert_eq!(
        of_process(&fs, root, "812"),
        Err(
            "process 812 has /elsewhere mounted over /run/systemd/journal, which NAILS does not \
             read as the journal of a namespace"
                .to_string()
        )
    );
    // A process that has ended logs no more.
    assert_eq!(of_process(&fs, root, "900"), Ok(None));
    fs.mock_set_lookup_error("/proc/901/mountinfo", std::io::ErrorKind::PermissionDenied);
    assert_eq!(
        of_process(&fs, root, "901"),
        Err(
            "NAILS cannot read /proc/901/mountinfo, which shows its journal; run the command \
             again with sudo"
                .to_string()
        )
    );
}

#[test]
fn a_log_to_the_decoy_s_own_journal_is_no_file() {
    let fs = MockFilesystem::new();
    assert_eq!(
        journal_log(
            &fs,
            Path::new("/"),
            Ok(None),
            "neither -l nor -d",
            "its log"
        ),
        Log::NoFile
    );
    assert_eq!(
        journal_log(
            &fs,
            Path::new("/"),
            Err("NAILS does not expand the specifiers of its LogNamespace=%N".to_string()),
            "neither -l nor -d",
            "its log"
        ),
        Log::Unknown(
            "it logs to the journal, and NAILS does not expand the specifiers of its \
             LogNamespace=%N"
                .to_string()
        )
    );
}
