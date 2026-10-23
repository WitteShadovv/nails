// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The host-tools check against a temporary bin directory, with the hidden
//! root `/mnt/data` mounted from a mock mount table: from a plain block device,
//! from a device-mapper mapping, or not at all.

use super::*;
use crate::filesystem::MockFilesystem;
use std::fs;
use std::os::unix::fs::PermissionsExt;

const HIDDEN_ROOT: &str = "/mnt/data";

impl HostToolsCheck {
    fn with_probe(dirs: Vec<PathBuf>, kind: PlatformKind, family: Option<Family>) -> Self {
        Self {
            hidden_volume_root: PathBuf::from(HIDDEN_ROOT),
            probe: Some(ProbeOverride { dirs, kind, family }),
        }
    }
}

fn write_executable(path: &Path) {
    fs::write(path, "#!/bin/sh\n").unwrap();
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
}

/// A bin directory below `temp` holding an executable for each of `tools`.
fn bin_with(temp: &tempfile::TempDir, tools: &[&str]) -> PathBuf {
    let dir = temp.path().join("bin");
    fs::create_dir_all(&dir).unwrap();
    for tool in tools {
        write_executable(&dir.join(tool));
    }
    dir
}

/// A host whose hidden root is mounted from `source`.
fn hidden_root_on(source: &str) -> MockFilesystem {
    let fs = MockFilesystem::new();
    fs.mock_add_file(
        "/proc/self/mountinfo",
        &format!("36 35 254:0 / {HIDDEN_ROOT} rw,relatime shared:1 - ext4 {source} rw\n"),
    );
    fs
}

/// A host whose hidden root is mounted from the LUKS mapping `data`
/// (`/dev/dm-0`).
fn hidden_root_on_device_mapper() -> MockFilesystem {
    let fs = hidden_root_on("/dev/dm-0");
    fs.mock_add_file("/sys/block/dm-0/dm/name", "data\n");
    fs
}

#[test]
fn passes_when_every_required_tool_resolves() {
    let temp = tempfile::tempdir().unwrap();
    let dir = bin_with(&temp, &["systemctl", "loginctl", "ip"]);

    let check = HostToolsCheck::with_probe(vec![dir], PlatformKind::Fhs, Some(Family::Debian));
    let result = check.run(&hidden_root_on("/dev/sdb1")).unwrap();
    assert!(result.is_pass(), "{result:?}");
    assert!(result.message().contains("All 3 "), "{}", result.message());
}

#[test]
fn fails_with_a_per_family_install_hint_when_a_tool_is_missing() {
    let temp = tempfile::tempdir().unwrap();
    // `loginctl` is deliberately absent.
    let dir = bin_with(&temp, &["systemctl", "ip"]);

    for (family, hint) in [
        (Family::Debian, "apt install systemd"),
        (Family::Fedora, "dnf install systemd"),
        (Family::Arch, "pacman -S systemd"),
    ] {
        let check = HostToolsCheck::with_probe(vec![dir.clone()], PlatformKind::Fhs, Some(family));
        let result = check.run(&hidden_root_on("/dev/sdb1")).unwrap();
        assert!(result.is_fail(), "{family:?}: {result:?}");
        let message = result.message();
        assert!(message.contains("loginctl"), "{message}");
        assert!(message.contains(hint), "{family:?}: {message}");
        // A present tool is not named in the remediation list.
        assert!(!message.contains("systemctl ("), "{message}");
    }
}

#[test]
fn a_missing_ip_refuses_with_the_package_of_each_family() {
    // Every way back runs `ip`, whatever the backend: without it the links a
    // session made and the addresses it changed would stay on the decoy.
    let temp = tempfile::tempdir().unwrap();
    let dir = bin_with(&temp, &["systemctl", "loginctl"]);

    for (family, hint) in [
        (Some(Family::Debian), "ip (apt install iproute2)"),
        (Some(Family::Fedora), "ip (dnf install iproute)"),
        (Some(Family::Arch), "ip (pacman -S iproute2)"),
        (None, "ip (install the iproute2 package)"),
    ] {
        let check = HostToolsCheck::with_probe(vec![dir.clone()], PlatformKind::Fhs, family);
        let result = check.run(&hidden_root_on("/dev/sdb1")).unwrap();
        assert!(result.is_fail(), "{family:?}: {result:?}");
        assert!(result.message().contains(hint), "{}", result.message());
    }
}

#[test]
fn a_device_mapper_backend_requires_dmsetup() {
    // The way back marks the hidden mapping for deferred removal with
    // `dmsetup`; without it the mapping and its key stay open on the decoy.
    let temp = tempfile::tempdir().unwrap();
    let dir = bin_with(&temp, &["systemctl", "loginctl", "ip"]);

    for (family, hint) in [
        (Family::Debian, "dmsetup (apt install dmsetup)"),
        (Family::Fedora, "dmsetup (dnf install device-mapper)"),
        (Family::Arch, "dmsetup (pacman -S device-mapper)"),
    ] {
        let check = HostToolsCheck::with_probe(vec![dir.clone()], PlatformKind::Fhs, Some(family));
        let result = check.run(&hidden_root_on_device_mapper()).unwrap();
        assert!(result.is_fail(), "{family:?}: {result:?}");
        let message = result.message();
        assert!(message.contains(hint), "{family:?}: {message}");
        assert!(!message.contains("ip ("), "{message}");
    }

    write_executable(&dir.join("dmsetup"));
    let check = HostToolsCheck::with_probe(vec![dir], PlatformKind::Fhs, Some(Family::Debian));
    let result = check.run(&hidden_root_on_device_mapper()).unwrap();
    assert!(result.is_pass(), "{result:?}");
    assert!(result.message().contains("All 4 "), "{}", result.message());
}

#[test]
fn a_plain_block_device_backend_does_not_require_dmsetup() {
    // A partition or a loop device records no device-mapper stack, so the way
    // back never runs `dmsetup` for it.
    let temp = tempfile::tempdir().unwrap();
    let dir = bin_with(&temp, &["systemctl", "loginctl", "ip"]);

    for source in ["/dev/sdb1", "/dev/loop3"] {
        let check =
            HostToolsCheck::with_probe(vec![dir.clone()], PlatformKind::Fhs, Some(Family::Arch));
        let result = check.run(&hidden_root_on(source)).unwrap();
        assert!(result.is_pass(), "{source}: {result:?}");
    }
}

#[test]
fn an_unknown_backend_requires_dmsetup() {
    // No mount table to read, or nothing mounted at the hidden root yet: the
    // backend cannot be told apart from device-mapper, so `dmsetup` is required.
    let temp = tempfile::tempdir().unwrap();
    let dir = bin_with(&temp, &["systemctl", "loginctl", "ip"]);
    let unmounted = MockFilesystem::new();
    unmounted.mock_add_file(
        "/proc/self/mountinfo",
        "1 0 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw\n",
    );

    for host in [MockFilesystem::new(), unmounted] {
        let check =
            HostToolsCheck::with_probe(vec![dir.clone()], PlatformKind::Fhs, Some(Family::Debian));
        let result = check.run(&host).unwrap();
        assert!(result.is_fail(), "{result:?}");
        assert!(
            result.message().contains("dmsetup (apt install dmsetup)"),
            "{}",
            result.message()
        );
    }
}

#[test]
fn a_missing_tool_on_nixos_points_at_the_decoy_configuration() {
    // The check resolves the decoy's system profile, which is also where the
    // way back finds `dmsetup` and `ip`; the hint names nixpkgs packages.
    let temp = tempfile::tempdir().unwrap();
    // Nothing is installed, so every required tool is reported missing.
    let dir = bin_with(&temp, &[]);
    let check = HostToolsCheck::with_probe(vec![dir], PlatformKind::NixOs, None);
    let result = check.run(&hidden_root_on_device_mapper()).unwrap();
    assert!(result.is_fail(), "{result:?}");
    let message = result.message();
    for hint in [
        "nix (add nix to the decoy's environment.systemPackages)",
        "ip (add iproute2 to the decoy's environment.systemPackages)",
        "dmsetup (add lvm2 to the decoy's environment.systemPackages)",
    ] {
        assert!(message.contains(hint), "{message}");
    }
}

#[test]
fn skips_in_test_context_without_a_probe() {
    // Without a probe override the check short-circuits to a skipped Pass in a
    // test runtime, so it never touches the real host from the shared registry.
    let check = HostToolsCheck::new(PathBuf::from(HIDDEN_ROOT));
    let result = check.run(&MockFilesystem::new()).unwrap();
    assert!(result.is_pass(), "{result:?}");
}

#[test]
fn tools_nails_never_spawns_are_not_required() {
    // Audited away: `systemd-run` is never run; `cp`, `chown` and `sync` are
    // syscalls, not binaries; `swapoff` is a masked systemd unit; `kill` goes
    // through the cgroup; `nixos-rebuild` is replaced by `nix`. Opaque handling
    // and directory walks are in-process, so `getfattr`/`du`/`find` are gone
    // too. Requiring any of them would refuse pre-flight on a host without a
    // package it does not need.
    let every: Vec<RequiredTool> = [PlatformKind::Fhs, PlatformKind::NixOs]
        .into_iter()
        .flat_map(|kind| [required_tools(kind, false), required_tools(kind, true)])
        .flatten()
        .collect();
    for absent in [
        "systemd-run",
        "cp",
        "chown",
        "sync",
        "swapoff",
        "kill",
        "nixos-rebuild",
        "getfattr",
        "setfattr",
        "du",
        "find",
    ] {
        assert!(
            !every.iter().any(|t| t.tool == absent),
            "{absent} is no longer spawned and must not be required"
        );
    }
}

#[test]
fn description_names_the_host_tool_contract() {
    // The description is surfaced in the pre-flight listing, so it must be a
    // non-empty, meaningful sentence about this check's job: resolving the host
    // tools NAILS spawns. An empty or placeholder string would still compile.
    let check = HostToolsCheck::new(PathBuf::from(HIDDEN_ROOT));
    let description = PreFlightCheck::<MockFilesystem>::description(&check);
    assert!(!description.is_empty(), "the description must not be empty");
    assert!(
        description.contains("host tools"),
        "the description must name the host-tools contract: {description}"
    );
}

#[test]
fn nixos_requires_nix_on_top_of_the_common_set() {
    let nixos = required_tools(PlatformKind::NixOs, false);
    let fhs = required_tools(PlatformKind::Fhs, false);
    assert!(nixos.iter().any(|t| t.tool == "nix"));
    assert!(!fhs.iter().any(|t| t.tool == "nix"));
    for common in ["systemctl", "loginctl", "ip"] {
        assert!(fhs.iter().any(|t| t.tool == common), "{common}");
        assert!(nixos.iter().any(|t| t.tool == common), "{common}");
    }
}

#[test]
fn dmsetup_is_required_only_for_a_device_mapper_backend() {
    for kind in [PlatformKind::Fhs, PlatformKind::NixOs] {
        assert!(
            required_tools(kind, true)
                .iter()
                .any(|t| t.tool == "dmsetup"),
            "{kind:?}"
        );
        assert!(
            !required_tools(kind, false)
                .iter()
                .any(|t| t.tool == "dmsetup"),
            "{kind:?}"
        );
    }
}

/// Every tool the check requires must have a real spawn site in the product
/// source, so the audited-away tools cannot creep back into the required set.
#[test]
fn every_required_tool_has_a_spawn_site() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the workspace root is above nails-core");
    let mut sources = String::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(read) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in read.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                // The crate sources only: skip build output, VCS and hidden dirs.
                if name == "target" || name.starts_with('.') {
                    continue;
                }
                stack.push(path);
                continue;
            }
            if !path.extension().is_some_and(|ext| ext == "rs") {
                continue;
            }
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            // Skip test code (so a test-only spawn cannot validate a tool) and
            // this module, which holds the required-tool table, not a spawn.
            if name == "tests.rs"
                || name.ends_with("_tests.rs")
                || name == "host_tools.rs"
                || path
                    .components()
                    .any(|c| c.as_os_str().to_str() == Some("tests"))
            {
                continue;
            }
            if let Ok(text) = fs::read_to_string(&path) {
                sources.push_str(&text);
            }
        }
    }
    // Guard against the scan reading nothing (a moved workspace root).
    assert!(
        sources.contains("tool(\"systemctl\")"),
        "the source scan found no spawn sites at all"
    );
    for required in required_tools(PlatformKind::NixOs, true) {
        let tool = required.tool;
        // The way back runs its tools by the absolute path it finds for them:
        // `tools::find(recorded, "dmsetup")`, then `tools::run` on that path.
        let found_for_the_way_back = sources.match_indices("tools::find(").any(|(at, _)| {
            sources[at..]
                .lines()
                .next()
                .is_some_and(|call| call.contains(&format!("\"{tool}\")")))
        });
        let spawned = sources.contains(&format!("tool(\"{tool}\")"))
            || sources.contains(&format!("caller_path(\"{tool}\")"))
            || found_for_the_way_back;
        assert!(
            spawned,
            "{tool} is required but NAILS has no spawn site for it"
        );
    }
}
