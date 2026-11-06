// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::RealFilesystem;
use crate::filesystem::MockFilesystem;
use std::path::PathBuf;

/// The files python3-gi installs, as dpkg lists them in
/// `/var/lib/dpkg/info/python3-gi:amd64.list`, generated from the packages of
/// Debian 13 (3.50.0-4+b1), Ubuntu 24.04 (3.48.2-1) and Ubuntu 26.04
/// (3.56.2-1).
pub(in crate::preflight::checks::decoy_posture) const PYTHON3_GI: [&str; 3] = [
    include_str!("../fixtures/debian-13-python3-gi.list"),
    include_str!("../fixtures/ubuntu-24.04-python3-gi.list"),
    include_str!("../fixtures/ubuntu-26.04-python3-gi.list"),
];

/// Install the files of a package's `list` under `root`, empty: a path is
/// a directory where another one lies below it.
pub(in crate::preflight::checks::decoy_posture) fn install(root: &Path, list: &str) {
    let paths: Vec<&str> = list.lines().filter(|path| *path != "/.").collect();
    for path in &paths {
        let at = root.join(path.trim_start_matches('/'));
        if paths
            .iter()
            .any(|other| other.starts_with(&format!("{path}/")))
        {
            std::fs::create_dir_all(at).unwrap();
        } else {
            std::fs::create_dir_all(at.parent().unwrap()).unwrap();
            std::fs::write(at, b"").unwrap();
        }
    }
}

/// A decoy whose helper is enabled, as its package enables it.
fn enabled() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    let wants = tmp
        .path()
        .join("etc/systemd/system/multi-user.target.wants");
    std::fs::create_dir_all(&wants).unwrap();
    std::os::unix::fs::symlink(
        "/usr/lib/systemd/system/unattended-upgrades.service",
        wants.join("unattended-upgrades.service"),
    )
    .unwrap();
    tmp
}

#[test]
fn every_python3_gi_installs_the_module_the_helper_imports() {
    for list in PYTHON3_GI {
        assert!(list.lines().any(|path| path == format!("/{GI_MODULE}")));
        let tmp = enabled();
        install(tmp.path(), list);
        assert_eq!(warning(&RealFilesystem, tmp.path()), None);
    }
}

#[test]
fn an_enabled_helper_without_python3_gi_warns_of_its_lines() {
    let tmp = enabled();
    let warning = warning(&RealFilesystem, tmp.path()).expect("a warning");
    assert!(
        warning.starts_with(
            "unattended-upgrades.service is enabled on the decoy and python3-gi is not installed \
             (no /usr/lib/python3/dist-packages/gi/__init__.py)"
        ),
        "{warning}"
    );
    assert!(
        warning.contains(
            "two WARNING lines to /var/log/unattended-upgrades/unattended-upgrades-shutdown.log \
             on the decoy disk each time it starts"
        ),
        "{warning}"
    );
    assert!(
        warning.contains("every way back to the decoy adds a pair dated at the switch"),
        "{warning}"
    );
    assert!(warning.ends_with("(apt install python3-gi)"), "{warning}");
    // The package's directory without the module is not it.
    std::fs::create_dir_all(tmp.path().join("usr/lib/python3/dist-packages/gi")).unwrap();
    assert!(super::warning(&RealFilesystem, tmp.path()).is_some());
}

#[test]
fn a_helper_that_does_not_start_again_does_not_warn() {
    // Not enabled: the way back does not start it.
    let tmp = tempfile::tempdir().unwrap();
    assert_eq!(warning(&RealFilesystem, tmp.path()), None);
    // Masked: the mask outranks the link that enables it.
    let tmp = enabled();
    std::os::unix::fs::symlink(
        "/dev/null",
        tmp.path()
            .join("etc/systemd/system/unattended-upgrades.service"),
    )
    .unwrap();
    assert_eq!(warning(&RealFilesystem, tmp.path()), None);
}

#[test]
fn the_check_for_python3_gi_writes_nothing() {
    let fs = MockFilesystem::new();
    fs.mock_set_directory_contents(
        Path::new("/etc/systemd/system"),
        vec![PathBuf::from("/etc/systemd/system/multi-user.target.wants")],
    );
    fs.mock_set_is_symlink(
        "/etc/systemd/system/multi-user.target.wants/unattended-upgrades.service",
        true,
    );
    assert!(warning(&fs, Path::new("/")).is_some());
    assert!(fs.mock_written_paths().is_empty());
    assert!(
        fs.mock_ops().is_empty(),
        "nothing is changed: {:?}",
        fs.mock_ops()
    );
}
