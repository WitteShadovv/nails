// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What verify reports where a lookup fails for another reason than that
//! nothing is there: a finding that it could not tell, at the severity a hit
//! would have but at most a warning, and the scan goes on. A path verify
//! could not look up never reads as clean, and never as a critical leftover.

use super::Verifier;
use crate::MockFilesystem;
use crate::residue_catalog::ResidueKind;
use crate::verify::{Finding, Severity};
use std::io::ErrorKind;

/// The one finding of `findings` whose message holds `needle`.
fn finding<'a>(findings: &'a [Finding], needle: &str) -> &'a Finding {
    let mut matching = findings.iter().filter(|f| f.message.contains(needle));
    let found = matching
        .next()
        .unwrap_or_else(|| panic!("no finding holds {needle:?}: {findings:#?}"));
    assert!(matching.next().is_none(), "{findings:#?}");
    found
}

/// A catalog path verify cannot look up was taken for one that holds
/// nothing. It is a finding that verify could not tell, at the row's
/// severity: a warning for a row whose hit warns, a note for one whose hit
/// is only noted.
#[test]
fn a_catalog_path_verify_cannot_look_up_is_one_it_cannot_tell() {
    let fs = MockFilesystem::new();
    fs.mock_set_lookup_error("/var/log/sudo-io", ErrorKind::PermissionDenied);
    fs.mock_set_lookup_error("/var/lib/chrony", ErrorKind::Other);
    let findings = Verifier::new(fs).check_catalog_paths(ResidueKind::Session);

    let sudo = finding(&findings, "[sudo-io-log]");
    assert_eq!(sudo.severity, Severity::Warn);
    assert_eq!(sudo.category, "catalog");
    assert_eq!(
        sudo.message,
        "sudo I/O logging not checked: could not tell whether /var/log/sudo-io is live \
         [sudo-io-log]: Mock: the lookup fails here"
    );
    assert_eq!(
        sudo.fix_guidance.as_deref(),
        Some("Find out why /var/log/sudo-io cannot be looked up, then run verify again")
    );
    let chrony = finding(&findings, "[chrony-drift]");
    assert_eq!(chrony.severity, Severity::Info);
    assert!(
        chrony
            .message
            .contains("could not tell whether /var/lib/chrony is live"),
        "{chrony:?}"
    );
}
