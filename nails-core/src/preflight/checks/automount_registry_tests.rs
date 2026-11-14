// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! No check of `check` and activation makes a lookup that would mount an
//! automount point that nothing is mounted on yet. The whole registry, as it
//! is built for an operator on a decoy that is no NixOS, and again with the
//! NixOS layer's checks, runs on a mock decoy with unmounted automount points
//! where the checks read and a hidden volume mounted at `/mnt/data`, so that
//! the checks that need the volume run too: nothing at or below a point is
//! looked up, and each check that reads there names the point. Without a
//! mount table, the checks [`guarded`] lists, which read the decoy through
//! the automount guard, look nothing up on it and say so.
//!
//! Some checks of the registry skip themselves in tests, such as
//! mount-namespace, host-tools and network-tools, and binary-location and
//! locate-database run again with test inputs. fstab-policy reads the decoy
//! with nextroot, not through the mock, so its own tests cover it.
//! kernel-modules reads the running kernel's module tree in `/usr/lib/modules`
//! and the hidden root's upper with the real filesystem, so this test sees
//! none of its lookups.

use super::automount_fixture::{ROOT_MOUNT, direct, reached};
use crate::config::SleepPolicyMode;
use crate::filesystem::MockFilesystem;
use crate::manager::{PreflightOptions, RegistryInputs, build_registry};
use crate::preflight::{
    BinaryLocationCheck, CheckResult, CryptsetupArgon2idCheck, DecoyNixTraceCheck,
    DecoyPersistenceCheck, HiddenVolumeCheck, IncrementalHistoryFlushCheck,
    InheritedAutostartCheck, InspectedShell, LocateDatabaseCheck, MemoryWipeCheck, PreFlightCheck,
    ResidueCatalogCheck, SleepPolicyCheck, UpperFsCapabilityCheck,
};
use crate::{Config, SystemState, TargetUser};
use std::collections::BTreeSet;
use std::path::PathBuf;

/// The direct automount points of the decoy, as systemd makes one for
/// `x-systemd.automount`, nothing mounted on any.
const DIRECT: &[&str] = &["/usr/local", "/var/log/journal", "/boot", "/.snapshots"];

/// The directory of an indirect map at `/home`, as an automounter mounts it:
/// a lookup of a name in it, such as bob's home, mounts that name.
const HOME_MAP: &str = "40 1 0:60 / /home rw,relatime - autofs /etc/auto.home \
                        rw,fd=7,pgrp=900,timeout=300,minproto=5,maxproto=5,indirect,pipe_ino=200\n";

/// Every place no lookup may reach: the direct points and bob's home.
const POINTS: &[&str] = &[
    "/usr/local",
    "/var/log/journal",
    "/boot",
    "/.snapshots",
    "/home/bob",
];

/// The running kernel the mock decoy reports.
const RELEASE: &str = "6.8.0-45-generic";

/// The hidden root of the checks.
const HIDDEN: &str = "/mnt/data";

/// The hidden volume, mounted at [`HIDDEN`], as the mount table lists it.
const HIDDEN_MOUNT: &str = "25 1 8:17 / /mnt/data rw,relatime - ext4 /dev/sdb1 rw\n";

/// The checks of the registry that need the hidden volume, which the runner
/// skips where `hidden-volume` refuses it.
const ON_THE_VOLUME: &[&str] = &[
    "backend-entries",
    "symlink-support",
    "upper-fs-capability",
    "backend-encryption",
    "outer-volume",
    "backend-partition-type",
    "storage-readiness",
    "kernel-modules",
    "package-drift",
    "space",
];

/// bob, the operator, whose home is a name of the indirect map.
fn bob() -> TargetUser {
    TargetUser::for_test(1000, 100, "bob", "/home/bob", "/bin/bash")
}

/// A mock decoy whose mount table holds the direct automount points
/// `points`, the indirect map at `/home` and the hidden volume, with bob in
/// /etc/passwd, the running kernel's release, and journald set to
/// `Storage=auto`, under which `/var/log/journal` decides where the journal
/// goes.
fn decoy_with(points: &[&str]) -> MockFilesystem {
    let fs = MockFilesystem::new();
    let mut table = ROOT_MOUNT.to_string();
    for (id, point) in points.iter().enumerate() {
        table.push_str(&direct(point, id, 1));
    }
    table.push_str(HOME_MAP);
    table.push_str(HIDDEN_MOUNT);
    fs.mock_set_mount_table(&table);
    fs.mock_set_path_type(HIDDEN, crate::filesystem::PathKind::Dir);
    fs.mock_set_writable(HIDDEN, true);
    fs.mock_add_file(
        "/etc/passwd",
        "root:x:0:0:root:/root:/bin/bash\nbob:x:1000:100:Bob:/home/bob:/bin/bash\n",
    );
    fs.mock_add_file("/proc/sys/kernel/osrelease", &format!("{RELEASE}\n"));
    fs.mock_add_file("/etc/systemd/journald.conf", "[Journal]\nStorage=auto\n");
    fs
}

/// The mock decoy with every direct automount point of [`DIRECT`].
fn decoy() -> MockFilesystem {
    decoy_with(DIRECT)
}

/// Assert that nothing at or below any of `points` was looked up on `fs`.
fn none_reached(fs: &MockFilesystem, points: &[&str]) {
    for point in points {
        assert!(
            !reached(fs, point),
            "{point} was looked up: {:#?}",
            fs.mock_lookups()
        );
    }
}

/// The checks of the registry for bob on a decoy that is no NixOS, beside
/// the ones whose registry form skips the host in tests, built with their
/// test inputs: binary-location with /usr/local/bin on its PATH, and
/// locate-database with the units the system manager runs.
fn checks(fs: &MockFilesystem) -> Vec<(String, CheckResult)> {
    let inputs = RegistryInputs {
        options: PreflightOptions::default(),
        current_state: SystemState::Inactive,
        flake_target_already_validated: false,
        selected_flake_dir: None,
        discovered_target: crate::platform::HostTarget::None,
        operator: Some(bob()),
        caller_path: Some("/usr/local/bin:/usr/bin".into()),
        typed_shell: None,
        host_profile: None,
        systemd_version: None,
    };
    let registry = build_registry(fs, &Config::test_default(), &inputs, None).unwrap();
    let (mut results, _) = registry.run_all_detailed(fs);
    results.push((
        "binary-location (test inputs)".to_string(),
        PreFlightCheck::run(
            &BinaryLocationCheck::with_probes(
                PathBuf::from(HIDDEN),
                PathBuf::from(HIDDEN).join("nails"),
                vec![PathBuf::from("/usr/local/bin")],
            ),
            fs,
        )
        .unwrap(),
    ));
    results.push((
        "locate-database (test inputs)".to_string(),
        PreFlightCheck::run(
            &LocateDatabaseCheck::new(PathBuf::from(HIDDEN), false)
                .with_started(Ok(BTreeSet::new())),
            fs,
        )
        .unwrap(),
    ));
    results
}

/// The result of the check `name` among `results`.
fn result<'a>(results: &'a [(String, CheckResult)], name: &str) -> &'a CheckResult {
    results
        .iter()
        .find(|(check, _)| check == name)
        .map(|(_, result)| result)
        .unwrap_or_else(|| panic!("no {name} among {results:#?}"))
}

/// Assert that the hidden volume's gate let the checks of `results` run,
/// each of `needing` among them, which need the volume.
fn the_volume_let_run(results: &[(String, CheckResult)], needing: &[&str]) {
    let gate = result(results, "hidden-volume");
    assert!(!gate.is_fail(), "{gate:?}");
    for name in needing {
        let result = result(results, name);
        assert!(!result.is_skipped(), "{name}: {result:?}");
    }
    let skipped: Vec<&str> = results
        .iter()
        .filter(|(_, result)| result.message() == crate::preflight::SKIPPED_NO_HIDDEN_VOLUME)
        .map(|(name, _)| name.as_str())
        .collect();
    assert!(skipped.is_empty(), "{skipped:?}");
}

/// The whole text of `result`: its message and its remediation.
fn text(result: &CheckResult) -> String {
    format!(
        "{}\n{}",
        result.message(),
        result.remediation().unwrap_or_default()
    )
}

/// Assert that the check `name` among `results` names each of `points` as
/// an automount point, and give its result.
fn names<'a>(results: &'a [(String, CheckResult)], name: &str, points: &[&str]) -> &'a CheckResult {
    let result = result(results, name);
    let text = text(result);
    for point in points {
        assert!(
            text.contains(&format!("the automount point {point}")),
            "{name} does not name {point}: {result:?}"
        );
    }
    result
}

/// With automount points that nothing is mounted on yet where the checks
/// read, no check of the registry looks up a path at or below one, and each
/// check that reads there names the point.
#[test]
fn no_check_looks_up_a_path_behind_an_automount_point() {
    let fs = decoy();
    let results = checks(&fs);
    none_reached(&fs, POINTS);
    the_volume_let_run(&results, ON_THE_VOLUME);

    // The journal's place is asked only where journald's settings say
    // Storage=auto, which a drop-in below /usr/local may change: with
    // /usr/local unmounted, that is what the refusal names.
    let persistence = names(&results, "decoy-persistence", &["/usr/local"]);
    assert!(persistence.is_fail(), "{persistence:?}");
    for (name, points) in [
        ("sleep-policy", &["/usr/local"][..]),
        (
            "locate-database (test inputs)",
            &["/usr/local", "/home/bob"][..],
        ),
        ("decoy-nix-trace", &["/usr/local", "/home/bob"][..]),
        ("binary-location (test inputs)", &["/usr/local"][..]),
        ("inherited-autostart", &["/home/bob"][..]),
        ("incremental-history-flush", &["/home/bob"][..]),
        ("residue-catalog", &["/.snapshots"][..]),
    ] {
        let result = names(&results, name, points);
        assert!(result.is_warn(), "{name}: {result:?}");
    }
    let memory = names(&results, "memory-wipe", &["/boot"]);
    assert!(memory.is_pass(), "{memory:?}");
    // With the volume mounted, the overlay trial would load the overlay
    // module, which reads its settings below /usr/local: no trial is made.
    let capability = names(&results, "upper-fs-capability", &["/usr/local"]);
    assert!(capability.is_fail(), "{capability:?}");

    // With /usr/local mounted, journald's settings say Storage=auto, and the
    // journal's place, an automount point itself, is what the refusal names.
    let fs = decoy_with(&["/var/log/journal", "/boot", "/.snapshots"]);
    let results = checks(&fs);
    none_reached(&fs, &POINTS[1..]);
    let persistence = names(&results, "decoy-persistence", &["/var/log/journal"]);
    assert!(persistence.is_fail(), "{persistence:?}");
}

/// On a NixOS decoy whose /etc/nixos links into bob's home, a name of the
/// indirect map, the checks of the NixOS layer look up nothing behind the
/// point either: suspicious-nails-reference and nixos-config refuse, naming
/// it.
#[test]
fn the_nixos_layer_looks_up_nothing_behind_an_automount_point() {
    use crate::Filesystem;
    let fs = decoy();
    fs.create_symlink(
        std::path::Path::new("/home/bob/nixos"),
        std::path::Path::new("/etc/nixos"),
    )
    .unwrap();
    fs.mock_clear_lookups();
    let inputs = RegistryInputs {
        options: PreflightOptions::default(),
        current_state: SystemState::Inactive,
        flake_target_already_validated: false,
        selected_flake_dir: None,
        discovered_target: crate::platform::HostTarget::None,
        operator: Some(bob()),
        caller_path: None,
        typed_shell: None,
        host_profile: None,
        systemd_version: None,
    };
    let registry = build_registry(
        &fs,
        &Config::test_default(),
        &inputs,
        Some(&crate::platform::NixOsConfigLayer),
    )
    .unwrap();
    let registered = registry.names();
    assert!(
        [
            "suspicious-nails-reference",
            "nixos-config",
            "nixos-build-target"
        ]
        .iter()
        .all(|name| registered.contains(name)),
        "{registered:?}"
    );
    let (results, _) = registry.run_all_detailed(&fs);
    none_reached(&fs, POINTS);
    let mut needing = ON_THE_VOLUME.to_vec();
    needing.push("nixos-config");
    the_volume_let_run(&results, &needing);
    for name in ["suspicious-nails-reference", "nixos-config"] {
        let result = names(&results, name, &["/home/bob"]);
        assert!(result.is_fail(), "{name}: {result:?}");
    }
}

/// The checks that read the decoy through the automount guard, each built
/// as the registry builds it for bob.
fn guarded() -> Vec<(&'static str, Box<dyn PreFlightCheck<MockFilesystem>>)> {
    let hidden = PathBuf::from(HIDDEN);
    vec![
        (
            "decoy-persistence",
            Box::new(DecoyPersistenceCheck::new(false, false)),
        ),
        (
            "sleep-policy",
            Box::new(SleepPolicyCheck::new(SleepPolicyMode::Warn)),
        ),
        (
            "locate-database",
            Box::new(
                LocateDatabaseCheck::new(hidden.clone(), false).with_started(Ok(BTreeSet::new())),
            ),
        ),
        (
            "decoy-nix-trace",
            Box::new(DecoyNixTraceCheck::new(hidden.clone(), false)),
        ),
        (
            "binary-location",
            Box::new(BinaryLocationCheck::with_probes(
                hidden.clone(),
                hidden.join("nails"),
                vec![PathBuf::from("/usr/local/bin")],
            )),
        ),
        (
            "inherited-autostart",
            Box::new(InheritedAutostartCheck::new(
                PathBuf::from("/home/bob"),
                "bob".to_string(),
                Config::test_default().persona,
            )),
        ),
        (
            "incremental-history-flush",
            Box::new(IncrementalHistoryFlushCheck::new(InspectedShell::login(
                &bob(),
            ))),
        ),
        ("residue-catalog", Box::new(ResidueCatalogCheck::new())),
        ("memory-wipe", Box::new(MemoryWipeCheck::new())),
        (
            "cryptsetup-argon2id",
            Box::new(CryptsetupArgon2idCheck::as_root()),
        ),
        (
            "hidden-volume",
            Box::new(HiddenVolumeCheck::new(hidden.clone())),
        ),
        (
            "upper-fs-capability",
            Box::new(UpperFsCapabilityCheck::new(hidden.clone())),
        ),
        (
            "package-drift",
            Box::new(crate::session::package_drift::PackageDriftCheck::new(
                PathBuf::from("/"),
                hidden.clone(),
            )),
        ),
        (
            "unattended-upgrade-run",
            Box::new(crate::preflight::UpgradeRunCheck::new()),
        ),
        (
            "nixos-config",
            Box::new(crate::preflight::NixOSConfigCheck::new(hidden.clone())),
        ),
        (
            "suspicious-nails-reference",
            Box::new(crate::preflight::SuspiciousNailsReferenceCheck::new(hidden)),
        ),
    ]
}

/// Without the mount table, which shows where a lookup would mount an
/// automount point, no check that reads the decoy through the guard looks
/// up anything on it: what is read stays in /proc, which memory-wipe reads
/// for the running kernel. Each says that it cannot read the mount table.
#[test]
fn without_a_mount_table_no_check_looks_up_the_decoy() {
    for (name, check) in guarded() {
        let fs = decoy();
        fs.mock_set_mount_table_error("no mountinfo");
        let result = check.run(&fs).unwrap();
        let lookups = fs.mock_lookups();
        let decoy: Vec<&PathBuf> = lookups
            .iter()
            .filter(|path| !path.starts_with("/proc"))
            .collect();
        assert!(decoy.is_empty(), "{name} looked up {decoy:?}");
        assert!(
            text(&result).contains("mount table"),
            "{name} does not name the mount table: {result:?}"
        );
    }
}
