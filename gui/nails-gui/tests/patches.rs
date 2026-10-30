// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! The window builds its patched copy of Slint's winit backend (gui/patches,
//! see gui/Cargo.toml), and the copy keeps its two changes: winit without
//! sctk-adwaita, and settings portal reads that never start the portal. The
//! gui-patches flake check holds the copy to the published crate and its
//! patch; this holds the lock and the patch to what the window needs.

use std::path::Path;

/// A file of the gui/ workspace, by its path from gui/.
fn read(relative: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

/// The `[[package]]` tables of a Cargo.lock, each as its lines.
fn packages(lock: &str) -> Vec<Vec<&str>> {
    lock.split("[[package]]")
        .skip(1)
        .map(|table| {
            table
                .lines()
                .take_while(|line| !line.starts_with("[["))
                .collect()
        })
        .collect()
}

/// The name of a package table.
fn name<'a>(table: &[&'a str]) -> Option<&'a str> {
    table
        .iter()
        .find_map(|line| line.strip_prefix("name = \""))
        .and_then(|rest| rest.strip_suffix('"'))
}

#[test]
fn the_lock_builds_the_patched_backend_and_no_sctk_adwaita() {
    let lock = read("Cargo.lock");
    assert!(
        !lock.contains("[[patch.unused]]"),
        "a patch of gui/Cargo.toml no longer matches what the window depends on"
    );
    let packages = packages(&lock);
    assert!(packages.len() > 100, "no package tables read from the lock");
    let names: Vec<&str> = packages
        .iter()
        .filter_map(|table| name(table.as_slice()))
        .collect();
    assert!(
        !names.contains(&"sctk-adwaita"),
        "sctk-adwaita is back in the window's graph: winit builds its frame again"
    );
    let backend: Vec<&Vec<&str>> = packages
        .iter()
        .filter(|table| name(table.as_slice()) == Some("i-slint-backend-winit"))
        .collect();
    assert_eq!(backend.len(), 1, "{backend:?}");
    assert!(
        backend[0].iter().all(|line| !line.starts_with("source = ")),
        "i-slint-backend-winit comes from a registry, not from gui/patches: {:?}",
        backend[0]
    );
}

#[test]
fn the_patched_backend_keeps_its_two_changes() {
    // winit's wayland-csd-adwaita feature is on no feature list of the copy.
    let manifest = read("patches/i-slint-backend-winit/Cargo.toml");
    let features: Vec<&str> = manifest
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#'))
        .collect();
    assert!(
        features
            .iter()
            .all(|line| !line.contains("winit/wayland-csd-adwaita")),
        "the copy turns winit's sctk-adwaita frame on again"
    );
    // Both portal reads go out with NO_AUTO_START, and no plain call is left.
    let settings = read("patches/i-slint-backend-winit/xdg_desktop_settings.rs");
    assert!(settings.contains("zbus::proxy::MethodFlags::NoAutoStart"));
    for method in ["ReadOne", "Read"] {
        assert!(
            settings.contains(&format!(
                "settings_proxy.call_with_flags(\"{method}\", flags, &args)"
            )),
            "{method} is not read with the flags"
        );
        assert!(
            !settings.contains(&format!("settings_proxy.call(\"{method}\"")),
            "{method} is read without NO_AUTO_START"
        );
    }
}
