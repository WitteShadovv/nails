// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! The placeholder binary runs, names its version and says that the graphical
//! interface is not built yet, and nothing else.

use std::process::Command;

#[test]
fn placeholder_names_its_version_and_that_the_interface_is_not_built() {
    let output = Command::new(env!("CARGO_BIN_EXE_nails-gui"))
        .output()
        .expect("the nails-gui binary starts");
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!(
            "nails-gui {}: the graphical interface for running a nails session.\n\
             The graphical interface is not built yet.\n",
            env!("CARGO_PKG_VERSION")
        )
    );
    assert!(output.stderr.is_empty(), "{output:?}");
}
