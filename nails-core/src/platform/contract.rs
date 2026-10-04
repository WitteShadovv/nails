// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! One contract every [`Platform`] backend must satisfy.
//!
//! Each backend runs the same assertions so a new backend cannot quietly skip an
//! invariant: kind and overlay policy stay coherent, only a refused host has no
//! host-command directories, and restoring the base system after a *dispatched*
//! reboot never shells out (so the ESP, bootloader and EFI NVRAM stay untouched).

use super::{
    FakePlatform, FhsPlatform, MountHooks, NixOsPlatform, NixRuntime, Platform, PlatformKind,
    UnsupportedPlatform,
};
use crate::constants::ENV_SYSTEM_PROFILE_PATH;
use crate::filesystem::{Filesystem, MockFilesystem, PathKind};
use crate::process::run::MockProcessRunner;
use crate::test_support::EnvGuard;

/// Assert the invariants that hold for every backend.
fn assert_contract<F: Filesystem + 'static, P: Platform<F>>(platform: &P, fs: &F) {
    // `restore_base_system` resolves the decoy system profile through the
    // process environment (`NAILS_SYSTEM_PROFILE_PATH`), so take the environment
    // lock with that override cleared. Otherwise a deactivation test elsewhere
    // can point the lookup at a stub profile absent from the mock and make the
    // restore fail for a reason that has nothing to do with this contract.
    let mut env = EnvGuard::lock();
    env.remove(ENV_SYSTEM_PROFILE_PATH);

    let kind = platform.kind();

    // Kind and the policy's mount hooks agree.
    let policy = platform.overlay_policy();
    let expected_hooks = match kind {
        PlatformKind::NixOs => MountHooks::NixOs,
        PlatformKind::Fhs => MountHooks::Fhs,
        PlatformKind::Unsupported => MountHooks::None,
    };
    assert_eq!(policy.mount_hooks, expected_hooks);

    // The /nix runtime is resolved from the host, not the target name: nothing
    // to do when /nix is not a target; Native only on NixOS; Foreign (daemon
    // stop/start only, no store bind or current-system restore) everywhere else
    // /nix is overlaid, including a refused/undetected host.
    assert_eq!(platform.nix_runtime(false), NixRuntime::None);
    let expected_runtime = match kind {
        PlatformKind::NixOs => NixRuntime::Native,
        PlatformKind::Fhs | PlatformKind::Unsupported => NixRuntime::Foreign,
    };
    assert_eq!(platform.nix_runtime(true), expected_runtime);

    // A refused host guards and overlays nothing; a supported one never lists a
    // read-only tree it does not also keep out of overlay enumeration.
    if kind == PlatformKind::Unsupported {
        assert!(policy.read_only.is_empty());
        assert!(policy.default_exclusions.is_empty());
    } else {
        for tree in &policy.read_only {
            // The whole decoy root is kept read-only but is not a top-level
            // overlay-enumeration entry, so it is exempt from the subset rule.
            if tree == std::path::Path::new("/") {
                continue;
            }
            assert!(
                policy.default_exclusions.contains(tree),
                "read-only tree {} must also be excluded from overlay",
                tree.display()
            );
        }
    }

    // Only a refused host offers no host-command directories.
    assert_eq!(
        platform.host_command_dirs().is_empty(),
        kind == PlatformKind::Unsupported,
    );

    // Every backend names a non-empty display-manager fallback list with no empty
    // entries, so the session layer always has something to probe after the
    // generic `display-manager.service` alias.
    let display_managers = platform.display_manager_units();
    assert!(
        !display_managers.is_empty(),
        "a backend must list at least one display-manager unit",
    );
    assert!(
        display_managers.iter().all(|unit| !unit.is_empty()),
        "display-manager unit names must be non-empty",
    );

    // Only NixOS carries a declarative config layer; FHS and refused hosts have
    // none, so "overlay-only" is "no layer" rather than a parallel code path.
    assert_eq!(
        platform.config_layer().is_some(),
        kind == PlatformKind::NixOs,
    );

    // Restoring the base system after a dispatched reboot shells out to nothing.
    let runner = MockProcessRunner::new();
    let result = platform.restore_base_system(fs, &runner, true, &|| Ok(()));
    match kind {
        PlatformKind::Unsupported => {
            assert!(result.is_err(), "a refused host must decline restore");
        }
        _ => {
            result.expect("supported backends restore without error");
        }
    }
    assert!(
        runner.calls().is_empty(),
        "a dispatched reboot must not invoke switch-to-configuration",
    );
}

/// A mock NixOS host with a decoy system profile, so the symlink restore works.
fn nixos_host() -> MockFilesystem {
    let fs = MockFilesystem::new();
    fs.mock_set_path_type("/nix/var/nix/profiles/system", PathKind::Dir);
    fs
}

#[test]
fn nixos_backend_honours_contract() {
    assert_contract(&NixOsPlatform, &nixos_host());
}

#[test]
fn fhs_backend_honours_contract() {
    assert_contract(&FhsPlatform, &MockFilesystem::new());
}

#[test]
fn fake_backend_honours_contract() {
    assert_contract(&FakePlatform::nixos(), &MockFilesystem::new());
    assert_contract(&FakePlatform::fhs(), &MockFilesystem::new());
}

#[test]
fn unsupported_backend_honours_contract() {
    assert_contract(
        &UnsupportedPlatform::new("this host is not supported"),
        &MockFilesystem::new(),
    );
}
