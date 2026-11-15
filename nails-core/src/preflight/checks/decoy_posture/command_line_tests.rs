// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::filesystem::MockFilesystem;

#[test]
fn the_command_line_is_split_as_systemd_splits_it() {
    assert_eq!(
        words("BOOT_IMAGE=/vmlinuz root=UUID=1 ro  quiet\n"),
        ["BOOT_IMAGE=/vmlinuz", "root=UUID=1", "ro", "quiet"]
    );
    // Quotes are dropped, and white space within them is kept; a backslash
    // stays as it is; an empty quoted word is a word.
    assert_eq!(
        words("a=\"b c\" 'd' e\\ f \"\" sys\"temd.wants\"=x"),
        ["a=b c", "d", "e\\", "f", "", "systemd.wants=x"]
    );
    // A quote left open runs to the end.
    assert_eq!(words("x \"y z"), ["x", "y z"]);
}

#[test]
fn a_value_names_the_unit_systemd_makes_of_it() {
    for (value, unit) in [
        ("auditd.service", Some("auditd.service")),
        ("auditd", Some("auditd.service")),
        // A slash stands for a dash.
        ("tuned/ppd", Some("tuned-ppd.service")),
        ("tuned-ppd.service", Some("tuned-ppd.service")),
        // An unknown type is part of the name.
        ("auditd.foo", Some("auditd.foo.service")),
        ("auditd.timer", Some("auditd.timer")),
        ("getty@tty1.service", Some("getty@tty1.service")),
        // A path is a mount or a device, and a value systemd escapes names
        // no unit NAILS asks about.
        ("/auditd", None),
        ("audit*", None),
        ("audit d", None),
        ("", None),
    ] {
        assert_eq!(mangled(value).as_deref(), unit, "{value:?}");
    }
}

#[test]
fn a_systemd_wants_on_the_command_line_has_the_manager_start_the_unit() {
    let root = Path::new("/");
    let fs = MockFilesystem::new();
    // No command line, as on a tree that is no running system: none.
    assert_eq!(wants(&fs, root, "auditd.service"), Ok(false));
    for (line, wanted) in [
        (
            "BOOT_IMAGE=/vmlinuz root=/dev/vda3 systemd.wants=auditd.service quiet\n",
            true,
        ),
        ("root=/dev/vda3 systemd.wants=auditd\n", true),
        ("root=/dev/vda3 \"systemd.wants=auditd.service\"\n", true),
        ("root=/dev/vda3 systemd.wants=tuned.service\n", false),
        // Only the initrd reads an rd. word; the key is matched whole.
        ("root=/dev/vda3 rd.systemd.wants=auditd.service\n", false),
        ("root=/dev/vda3 systemd.wants_auditd.service\n", false),
        ("root=/dev/vda3 systemd.mask=auditd.service\n", false),
        ("root=/dev/vda3 systemd.wants\n", false),
    ] {
        fs.mock_add_file("/proc/cmdline", line);
        assert_eq!(wants(&fs, root, "auditd.service"), Ok(wanted), "{line:?}");
    }
    // systemd before 258 reads the first line of the SystemdOptions EFI
    // variable's copy too.
    fs.mock_add_file("/proc/cmdline", "root=/dev/vda3\n");
    fs.mock_add_file(
        "/run/systemd/efivars/SystemdOptions-8cf2644b-4b0b-428f-9387-6d876050dc67",
        "systemd.wants=firewalld.service\nsystemd.wants=auditd.service\n",
    );
    assert_eq!(wants(&fs, root, "firewalld.service"), Ok(true));
    assert_eq!(wants(&fs, root, "auditd.service"), Ok(false));
}

#[test]
fn a_command_line_nails_cannot_read_leaves_it_untold() {
    let fs = MockFilesystem::new();
    fs.mock_set_lookup_error("/proc/cmdline", std::io::ErrorKind::PermissionDenied);
    assert_eq!(
        wants(&fs, Path::new("/"), "auditd.service"),
        Err(
            "NAILS cannot tell whether auditd.service is enabled, which a systemd.wants= there \
             makes it: NAILS cannot read /proc/cmdline; run the command again with sudo"
                .to_string()
        )
    );
    let fs = MockFilesystem::new();
    fs.mock_set_lookup_error(
        "/run/systemd/efivars/SystemdOptions-8cf2644b-4b0b-428f-9387-6d876050dc67",
        std::io::ErrorKind::InvalidData,
    );
    let why = wants(&fs, Path::new("/"), "auditd.service").unwrap_err();
    assert!(
        why.starts_with(
            "NAILS cannot tell whether auditd.service is enabled, which a systemd.wants= there \
             makes it: NAILS cannot read \
             /run/systemd/efivars/SystemdOptions-8cf2644b-4b0b-428f-9387-6d876050dc67 ("
        ),
        "{why}"
    );
}
