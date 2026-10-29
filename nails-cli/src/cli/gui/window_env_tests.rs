// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use std::ffi::OsString;
use std::os::unix::net::UnixListener;
use std::path::Path;

use nails_core::runtime_env::InheritedVars;

use super::*;

fn inherited(pairs: &[(&str, &str)]) -> InheritedVars {
    InheritedVars::new(
        pairs
            .iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v)))
            .collect(),
    )
}

fn names(vars: &[(OsString, OsString)]) -> Vec<String> {
    vars.iter()
        .map(|(k, _)| k.to_string_lossy().into_owned())
        .collect()
}

fn value<'a>(vars: &'a [(OsString, OsString)], key: &str) -> Option<&'a OsStr> {
    vars.iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_os_str())
}

/// The variables the window gets in an empty runtime directory from a
/// launcher that got none: the fixed set and the redirected directories.
const ALWAYS: &[&str] = &[
    "FONTCONFIG_FILE",
    "GDK_DEBUG",
    "GIO_USE_VFS",
    "GIO_USE_VOLUME_MONITOR",
    "GSETTINGS_BACKEND",
    "HOME",
    "MESA_SHADER_CACHE_DISABLE",
    "PATH",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_RUNTIME_DIR",
    "XDG_STATE_HOME",
    "__GL_SHADER_DISK_CACHE",
];

#[test]
fn the_window_gets_only_the_allowlist_whatever_the_launcher_got() {
    let runtime = tempfile::tempdir().unwrap();
    let own = runtime.path().join("own");
    let launcher = inherited(&[
        ("HOME", "/root"),
        ("PATH", "/mnt:/usr/sbin"),
        ("LD_PRELOAD", "/tmp/x.so"),
        ("LD_LIBRARY_PATH", "/tmp"),
        ("SESSION_MANAGER", "local/host:@/tmp/.ICE-unix/1"),
        ("RUST_LOG", "trace"),
        ("SLINT_DEBUG_PERFORMANCE", "refresh_lazy"),
        ("SUDO_UID", "1000"),
        ("SUDO_COMMAND", "/mnt/nails gui"),
        ("SOME_SECRET", "not-for-the-window"),
        ("XDG_CONFIG_HOME", "/home/operator/.config"),
        ("DISPLAY", ":0"),
        ("XAUTHORITY", "/home/operator/.Xauthority"),
        ("XDG_CURRENT_DESKTOP", "ubuntu:GNOME"),
        ("XDG_SESSION_TYPE", "wayland"),
        ("LANG", "de_DE.UTF-8"),
        ("LC_TIME", "en_GB.UTF-8"),
        ("LC_ALL", "C.UTF-8"),
        ("LC_", "x"),
        ("LCX", "x"),
    ]);
    let vars = vars(&launcher, runtime.path(), &own);

    let mut expected: Vec<&str> = ALWAYS.to_vec();
    expected.extend([
        "DISPLAY",
        "LANG",
        "LC_ALL",
        "LC_TIME",
        "XAUTHORITY",
        "XDG_CURRENT_DESKTOP",
        "XDG_SESSION_TYPE",
    ]);
    expected.sort_unstable();
    assert_eq!(names(&vars), expected);

    assert_eq!(value(&vars, "HOME"), Some(own.as_os_str()));
    assert_eq!(
        value(&vars, "XDG_CONFIG_HOME"),
        Some(own.join("config").as_os_str())
    );
    assert_eq!(value(&vars, "PATH"), Some(OsStr::new(WINDOW_PATH)));
    assert_eq!(
        value(&vars, "XDG_RUNTIME_DIR"),
        Some(runtime.path().as_os_str())
    );
    assert_eq!(
        value(&vars, "GSETTINGS_BACKEND"),
        Some(OsStr::new("memory"))
    );
    assert_eq!(value(&vars, "LC_TIME"), Some(OsStr::new("en_GB.UTF-8")));
}

#[test]
fn an_empty_launcher_environment_still_gives_the_window_its_fixed_set() {
    let runtime = tempfile::tempdir().unwrap();
    let vars = vars(
        &inherited(&[]),
        runtime.path(),
        Path::new("/run/user/1000/x"),
    );
    assert_eq!(names(&vars), ALWAYS);
}

#[test]
fn the_wayland_display_and_the_session_bus_are_found_in_the_runtime_directory() {
    let runtime = tempfile::tempdir().unwrap();
    let _bus = UnixListener::bind(runtime.path().join("bus")).unwrap();
    let _one = UnixListener::bind(runtime.path().join("wayland-1")).unwrap();
    let _zero = UnixListener::bind(runtime.path().join("wayland-0")).unwrap();
    std::fs::write(runtime.path().join("wayland-0.lock"), "").unwrap();
    // A file named like a display is not a socket.
    std::fs::write(runtime.path().join("wayland-00"), "").unwrap();

    // sudo dropped WAYLAND_DISPLAY: the first socket is taken.
    let found = vars(&inherited(&[]), runtime.path(), Path::new("/x"));
    assert_eq!(
        value(&found, "WAYLAND_DISPLAY"),
        Some(OsStr::new("wayland-0"))
    );
    let mut bus = OsString::from("unix:path=");
    bus.push(runtime.path().join("bus"));
    assert_eq!(
        value(&found, "DBUS_SESSION_BUS_ADDRESS"),
        Some(bus.as_os_str())
    );

    // A display the launcher was given is kept when it is a socket there.
    let named = vars(
        &inherited(&[("WAYLAND_DISPLAY", "wayland-1")]),
        runtime.path(),
        Path::new("/x"),
    );
    assert_eq!(
        value(&named, "WAYLAND_DISPLAY"),
        Some(OsStr::new("wayland-1"))
    );

    // A name that is no socket there, or a path out of it, is not.
    for given in ["wayland-9", "../wayland-1", "wayland-00"] {
        let other = vars(
            &inherited(&[("WAYLAND_DISPLAY", given)]),
            runtime.path(),
            Path::new("/x"),
        );
        assert_eq!(
            value(&other, "WAYLAND_DISPLAY"),
            Some(OsStr::new("wayland-0")),
            "{given}"
        );
    }
}

#[test]
fn without_a_bus_socket_the_given_address_is_kept_and_no_display_is_invented() {
    let runtime = tempfile::tempdir().unwrap();
    let vars = vars(
        &inherited(&[("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus")]),
        runtime.path(),
        Path::new("/x"),
    );
    assert_eq!(
        value(&vars, "DBUS_SESSION_BUS_ADDRESS"),
        Some(OsStr::new("unix:path=/run/user/1000/bus"))
    );
    assert_eq!(value(&vars, "WAYLAND_DISPLAY"), None);
}
