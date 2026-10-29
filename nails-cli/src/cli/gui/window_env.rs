// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The window's environment: an allowlist, never the launcher's own.
//!
//! The window starts from an empty environment and gets:
//!
//! - what it needs to reach the operator's desktop: `XDG_RUNTIME_DIR`, the
//!   Wayland display (found in the runtime directory, since sudo drops
//!   `WAYLAND_DISPLAY`), `DISPLAY` and `XAUTHORITY` for X11, the session bus
//!   (its socket in the runtime directory), `XDG_CURRENT_DESKTOP` and
//!   `XDG_SESSION_TYPE`, and the locale (`LANG`, `LC_*`);
//! - its home and every XDG base directory in its own directory in RAM, so a
//!   library that writes a cache or a setting writes it there;
//! - the settings that close the toolkit's other channels: no shader cache,
//!   the system font configuration, a GSettings backend in memory, local file
//!   access only, no portals;
//! - a fixed `PATH`.
//!
//! Everything else is left out, the dynamic loader's variables, the session
//! manager, the log and debug switches and every secret the launcher's own
//! environment may hold included.

use std::ffi::{OsStr, OsString};
use std::os::unix::fs::FileTypeExt;
use std::path::Path;

use nails_core::runtime_env::InheritedVars;

/// The `PATH` the window gets: the system's directories, NixOS's first.
pub(super) const WINDOW_PATH: &str = "/run/current-system/sw/bin:/usr/local/bin:/usr/bin:/bin";

/// Variables the window takes as the launcher got them, when set.
const PASSED: &[&str] = &[
    "DISPLAY",
    "XAUTHORITY",
    "XDG_CURRENT_DESKTOP",
    "XDG_SESSION_TYPE",
    "LANG",
];

/// Variables the window always gets, with their values.
const FIXED: &[(&str, &str)] = &[
    ("MESA_SHADER_CACHE_DISABLE", "true"),
    ("__GL_SHADER_DISK_CACHE", "0"),
    ("FONTCONFIG_FILE", "/etc/fonts/fonts.conf"),
    ("GSETTINGS_BACKEND", "memory"),
    ("GIO_USE_VFS", "local"),
    ("GIO_USE_VOLUME_MONITOR", "unix"),
    ("GDK_DEBUG", "no-portals"),
    ("PATH", WINDOW_PATH),
];

/// The XDG base directories, each a directory of that name in the window's
/// own directory.
const BASE_DIRS: &[(&str, &str)] = &[
    ("XDG_CONFIG_HOME", "config"),
    ("XDG_CACHE_HOME", "cache"),
    ("XDG_DATA_HOME", "data"),
    ("XDG_STATE_HOME", "state"),
];

/// The window's whole environment, sorted by name: `inherited` is the
/// launcher's, `runtime` the operator's runtime directory and `own` the
/// window's own directory in it.
pub(super) fn vars(
    inherited: &InheritedVars,
    runtime: &Path,
    own: &Path,
) -> Vec<(OsString, OsString)> {
    let get = |name: &str| {
        inherited
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value.to_owned())
    };
    let mut out: Vec<(OsString, OsString)> = Vec::new();
    let mut set = |key: &str, value: OsString| out.push((OsString::from(key), value));

    for name in PASSED {
        if let Some(value) = get(name) {
            set(name, value);
        }
    }
    for (key, value) in inherited.iter() {
        if is_locale_category(key) {
            set(&key.to_string_lossy(), value.to_owned());
        }
    }
    for (key, value) in FIXED {
        set(key, OsString::from(value));
    }
    set("XDG_RUNTIME_DIR", runtime.as_os_str().to_owned());
    if let Some(display) = wayland_display(runtime, get("WAYLAND_DISPLAY").as_deref()) {
        set("WAYLAND_DISPLAY", display);
    }
    if let Some(bus) = session_bus(runtime, get("DBUS_SESSION_BUS_ADDRESS")) {
        set("DBUS_SESSION_BUS_ADDRESS", bus);
    }
    set("HOME", own.as_os_str().to_owned());
    for (key, name) in BASE_DIRS {
        set(key, own.join(name).into_os_string());
    }
    out.sort();
    out
}

/// `LC_ALL`, `LC_CTYPE` and the other `LC_*` categories.
fn is_locale_category(key: &OsStr) -> bool {
    key.to_str().is_some_and(|key| {
        key.strip_prefix("LC_").is_some_and(|rest| {
            !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_uppercase() || b == b'_')
        })
    })
}

/// The Wayland display: `named`, when it is a socket in `runtime`, or else
/// the first `wayland-*` socket there.
fn wayland_display(runtime: &Path, named: Option<&OsStr>) -> Option<OsString> {
    let is_socket = |path: &Path| {
        std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_socket())
    };
    if let Some(name) = named
        && !name.is_empty()
        && !name.to_string_lossy().contains('/')
        && is_socket(&runtime.join(name))
    {
        return Some(name.to_owned());
    }
    let mut found: Vec<OsString> = std::fs::read_dir(runtime)
        .ok()?
        .filter_map(Result::ok)
        .map(|entry| entry.file_name())
        .filter(|name| {
            let text = name.to_string_lossy();
            text.starts_with("wayland-") && !text.ends_with(".lock")
        })
        .filter(|name| is_socket(&runtime.join(name)))
        .collect();
    found.sort();
    found.into_iter().next()
}

/// The session bus: its socket in `runtime` when there is one, or else the
/// address the launcher got, if any.
fn session_bus(runtime: &Path, given: Option<OsString>) -> Option<OsString> {
    let socket = runtime.join("bus");
    let present = std::fs::symlink_metadata(&socket).is_ok_and(|meta| meta.file_type().is_socket());
    if present {
        let mut address = OsString::from("unix:path=");
        address.push(socket.as_os_str());
        return Some(address);
    }
    given
}

#[cfg(test)]
#[path = "window_env_tests.rs"]
mod tests;
