// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The residue catalog's pre-flight probes against the registry activation
//! and `check` build: the catalog is in `nails-forensics`, the registry here,
//! so the invariant that ties them is tested in this crate.

use crate::residue_catalog::{Probe, catalog};
use std::collections::BTreeSet;

/// The names of every pre-flight check the registry can contain.
fn preflight_check_names() -> BTreeSet<&'static str> {
    use crate::manager::{PreflightOptions, RegistryInputs, build_registry};
    use crate::{Config, MockFilesystem, SystemState};

    let fs = MockFilesystem::new();
    let config = Config::test_default();
    let inputs = RegistryInputs {
        options: PreflightOptions::default(),
        current_state: SystemState::Inactive,
        flake_target_already_validated: false,
        selected_flake_dir: None,
        discovered_target: crate::platform::HostTarget::None,
        operator: None,
        caller_path: None,
        host_profile: None,
    };
    let registry = build_registry(
        &fs,
        &config,
        &inputs,
        Some(&crate::platform::NixOsConfigLayer),
    )
    .expect("registry builds");
    registry.names().into_iter().collect()
}

#[test]
fn preflight_probes_name_registered_checks() {
    let names = preflight_check_names();
    assert!(
        names.contains("residue-catalog"),
        "the catalog check is not registered"
    );
    for row in catalog() {
        if let Probe::Check(name) = row.preflight {
            assert!(
                names.contains(name),
                "{} names pre-flight check {name}, which the registry does not contain: {names:?}",
                row.id
            );
        }
    }
}
