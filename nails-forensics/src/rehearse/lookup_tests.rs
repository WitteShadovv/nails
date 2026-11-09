// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! A rehearsal state or a hidden root NAILS cannot look up, for another
//! reason than that nothing is there: the operation fails and names the
//! path, and nothing is written over a state it could not see, or removed.

use super::tests::{TOKEN, state};
use super::*;
use std::io::ErrorKind;

/// A state file whose lookup fails was taken for no state: plant then
/// started a new rehearsal and wrote its state over the old one, losing the
/// record of the copies reset removes. Loading it fails, naming the path.
#[test]
fn a_state_that_cannot_be_looked_up_is_an_error_naming_it() {
    let fs = crate::MockFilesystem::new();
    let root = Path::new("/mnt/data");
    let path = root.join(state_relative_path());
    fs.mock_set_lookup_error(path.to_str().unwrap(), ErrorKind::PermissionDenied);
    let error = load_state(&fs, root).unwrap_err();
    assert_eq!(
        error.io_kind(),
        Some(ErrorKind::PermissionDenied),
        "{error}"
    );
    assert!(
        error.to_string().starts_with(&path.display().to_string()),
        "{error}"
    );
}

/// A hidden root whose lookup fails is refused by the attach gate: no state
/// is saved on it and a reset removes nothing from it.
#[test]
fn a_hidden_root_that_cannot_be_looked_up_gets_no_state_and_keeps_its_copies() {
    let fs = crate::MockFilesystem::new();
    let root = Path::new("/mnt/data");
    fs.mock_set_lookup_error("/mnt/data", ErrorKind::Other);
    let refused = "nothing shows that /mnt/data is a volume of its own: it cannot be looked up";

    let error = save_state(&fs, root, &state(TOKEN)).unwrap_err();
    assert!(
        error
            .to_string()
            .contains(&format!("refusing to write the rehearsal state: {refused}")),
        "{error}"
    );
    let error = reset(&fs, root, &state(TOKEN)).unwrap_err();
    assert!(
        error
            .to_string()
            .contains(&format!("refusing to reset the rehearsal: {refused}")),
        "{error}"
    );
    assert!(fs.mock_ops().is_empty(), "{:?}", fs.mock_ops());
    assert!(fs.mock_written_paths().is_empty());
}
