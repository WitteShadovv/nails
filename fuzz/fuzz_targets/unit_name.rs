// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The name of a unit linked in a decoy's unit directory, which the session
//! decodes to the path the unit mounts, swaps or automounts
//! (`mount_units::unit_path`) and decides as an fstab line for that path. A
//! name decoded to another path than the one systemd gives the unit would
//! decide another filesystem: a decoy disk the hidden systemd mounts
//! read-write could pass for a RAM filesystem or for one already in place.
//!
//! The input is a unit name without its suffix. For each of the `.mount`,
//! `.swap` and `.automount` suffixes the target checks that:
//!
//! - a name NAILS decodes is the name systemd's `unit_name_from_path()` gives
//!   the path it decodes to (the model in `nails_fuzz::systemd`), a plain
//!   absolute path: systemd refuses a unit whose name is not that of its
//!   path, and a path with a `..` component or a NUL;
//! - the input read as an absolute path, when the model gives it a name,
//!   decodes back from that name to the path simplified.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nails_fuzz::systemd::{UnitName, path_simplify, unit_name_from_path};
use nails_session::session::mount_units::unit_path;
use nails_teardown::whole_root::runtime_units::valid_unit_name;
use std::path::{Component, PathBuf};

/// The suffixes of the units the session decodes.
const SUFFIXES: [&str; 3] = [".mount", ".swap", ".automount"];

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    for suffix in SUFFIXES {
        let name = format!("{text}{suffix}");
        // The session decodes only the names a directory lists that are unit
        // names.
        if valid_unit_name(&name)
            && let Some(path) = unit_path(&name, suffix)
        {
            assert!(
                path.components()
                    .all(|c| matches!(c, Component::RootDir | Component::Normal(_))),
                "{name:?}: {path:?}"
            );
            let decoded = path.to_str().expect("a decoded path is UTF-8");
            assert_eq!(
                unit_name_from_path(decoded, suffix),
                UnitName::Name(name.clone()),
                "{name:?}: {path:?}"
            );
        }
        if text.starts_with('/')
            && let UnitName::Name(name) = unit_name_from_path(&text, suffix)
        {
            assert_eq!(
                unit_path(&name, suffix),
                Some(PathBuf::from(path_simplify(&text))),
                "{text:?}: {name:?}"
            );
        }
    }
});
