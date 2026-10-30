// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The environment a window runs in: an allowlist, never the environment of
//! whoever started it.
//!
//! The launcher (`nails gui`) starts the window from an empty environment and
//! these variables; a window that a hidden session's menu entry started
//! applies the same list to itself before its toolkit starts. Either way the
//! window gets:
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
//!   access only, and no portals for GTK (`GDK_DEBUG`);
//! - a fixed `PATH`.
//!
//! Everything else is left out, the dynamic loader's variables, the session
//! manager, the log and debug switches and every secret the starting
//! environment may hold included.
//!
//! Only GTK reads `GDK_DEBUG`. The window's toolkit is Slint, whose winit
//! backend reads the desktop's appearance from the settings portal on the
//! session bus at every start (`org.freedesktop.portal.Settings`), and no
//! variable here turns that off: the session bus stays, since AccessKit, the
//! screen reader's way in, needs it to find the accessibility bus. Where
//! xdg-desktop-portal is not running, the read starts it through D-Bus
//! activation, which the desktop's trace test has to clear (see the list of
//! admitted desktops in the launcher's gate).
//!
//! The runtime directory is the one logind made for the operator,
//! `/run/user/<uid>`, used only when [`judge`] accepts it: the operator's,
//! private, and in RAM. The window's own directory in it has a fresh name
//! ([`own_dir_name`]).

use std::ffi::{OsStr, OsString};
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};

/// The `PATH` the window gets: the system's directories, NixOS's first.
pub const WINDOW_PATH: &str = "/run/current-system/sw/bin:/usr/local/bin:/usr/bin:/bin";

/// Variables the window takes as they were given, when set.
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

/// Where logind makes each account's runtime directory.
pub const USER_RUNTIME_BASE: &str = "/run/user";

/// The random bytes in the name of the window's own directory.
pub const OWN_DIR_BYTES: usize = 8;

/// The operator `uid`'s runtime directory, `/run/user/<uid>`.
#[must_use]
pub fn runtime_dir_of(uid: u32) -> PathBuf {
    Path::new(USER_RUNTIME_BASE).join(uid.to_string())
}

/// The window's whole environment, sorted by name: `given` is the
/// environment it was started with, `runtime` the operator's runtime
/// directory and `own` the window's own directory in it.
pub fn vars<'a>(
    given: impl IntoIterator<Item = (&'a OsStr, &'a OsStr)>,
    runtime: &Path,
    own: &Path,
) -> Vec<(OsString, OsString)> {
    let given: Vec<(&OsStr, &OsStr)> = given.into_iter().collect();
    let get = |name: &str| {
        given
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| (*value).to_owned())
    };
    let mut out: Vec<(OsString, OsString)> = Vec::new();
    let mut set = |key: &str, value: OsString| out.push((OsString::from(key), value));

    for name in PASSED {
        if let Some(value) = get(name) {
            set(name, value);
        }
    }
    for (key, value) in &given {
        if is_locale_category(key) {
            set(&key.to_string_lossy(), (*value).to_owned());
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
/// address that was given, if any.
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

/// What is checked of a runtime directory before the window's own directory
/// is made in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirFacts {
    /// A directory (a symlink is not one: it is not followed).
    pub is_dir: bool,
    /// The owner's uid.
    pub owner: u32,
    /// The permission bits.
    pub mode: u32,
    /// On a tmpfs.
    pub in_ram: bool,
}

/// Why a runtime directory with `facts` is not one the window of the operator
/// `uid` may use.
///
/// # Errors
///
/// The phrase that says why: not a directory, another account's, reachable
/// by other accounts, or not in RAM.
pub fn judge(facts: &DirFacts, uid: u32) -> Result<(), String> {
    if !facts.is_dir {
        return Err("it is not a directory".to_string());
    }
    if facts.owner != uid {
        return Err(format!("it belongs to uid {}", facts.owner));
    }
    if facts.mode & 0o077 != 0 {
        return Err(format!(
            "other accounts can reach it (mode {:o})",
            facts.mode
        ));
    }
    if !facts.in_ram {
        return Err("it is not in RAM (tmpfs)".to_string());
    }
    Ok(())
}

/// The neutral name of the window's own directory: [`OWN_DIR_BYTES`] random
/// bytes in lowercase hexadecimal.
#[must_use]
pub fn own_dir_name(random: &[u8; OWN_DIR_BYTES]) -> String {
    random.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
#[path = "window_env_tests.rs"]
mod tests;
