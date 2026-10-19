// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! `/etc/os-release` of the host, from which detection decides the backend
//! or refuses the host, under the shell-like quoting os-release(5) allows.
//!
//! The input is the file. The target checks that the identifiers come out
//! lowercased and split as documented, and that the fields, written back as
//! os-release(5) quotes a value (in double quotes, with `$`, `"`, `\` and
//! `` ` `` escaped), are read again unchanged, with the same decision.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nails_base::MockFilesystem;
use nails_platform::platform::{HostProfile, detect};

fuzz_target!(|data: &[u8]| {
    let first = detect_with(&String::from_utf8_lossy(data));
    if let Some(id) = &first.id {
        assert_eq!(id, &id.to_ascii_lowercase());
    }
    for token in &first.id_like {
        assert!(
            !token.is_empty() && !token.contains(char::is_whitespace),
            "{token:?}"
        );
        assert_eq!(token, &token.to_ascii_lowercase());
    }

    let written = write(&first);
    let again = detect_with(&written);
    assert_eq!(
        (&again.id, &again.id_like, &again.version_id),
        (&first.id, &first.id_like, &first.version_id),
        "{written}"
    );
    assert_eq!(again.kind, first.kind);
    assert_eq!(again.unsupported_reason, first.unsupported_reason);
    assert_eq!(again.support_warning, first.support_warning);
});

/// What detection makes of a systemd host with `os_release`.
fn detect_with(os_release: &str) -> HostProfile {
    let fs = MockFilesystem::new();
    fs.mock_set_file_content("/etc/os-release", os_release);
    fs.mock_set_file_content("/proc/1/comm", "systemd\n");
    detect(&fs).expect("detection reads through the mock")
}

/// The fields of `profile` as an os-release file.
fn write(profile: &HostProfile) -> String {
    let mut text = String::new();
    if let Some(id) = &profile.id {
        text.push_str(&format!("ID={}\n", quote(id)));
    }
    if !profile.id_like.is_empty() {
        text.push_str(&format!("ID_LIKE={}\n", quote(&profile.id_like.join(" "))));
    }
    if let Some(version) = &profile.version_id {
        text.push_str(&format!("VERSION_ID={}\n", quote(version)));
    }
    text
}

/// `value` in double quotes, with the characters a shell would expand or end
/// the string at escaped.
fn quote(value: &str) -> String {
    let mut out = String::from("\"");
    for c in value.chars() {
        if matches!(c, '$' | '"' | '\\' | '`') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}
