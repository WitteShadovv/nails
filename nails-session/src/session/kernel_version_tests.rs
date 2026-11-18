// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the `kernel-version` check.

use super::*;

/// The release forms the distributions NAILS runs on print, and a release
/// candidate, read as the version they are of.
#[test]
fn the_releases_distributions_print_are_read() {
    for (release, version) in [
        ("6.12.48+deb13-amd64", (6, 12)),
        ("6.12.57+deb13-cloud-amd64", (6, 12)),
        ("6.8.0-88-generic", (6, 8)),
        ("7.0.0-14-generic", (7, 0)),
        ("6.17.7-300.fc44.x86_64", (6, 17)),
        ("6.12.58", (6, 12)),
        ("6.1", (6, 1)),
        ("6.13.0-rc3", (6, 13)),
        ("6.1-rc1", (6, 1)),
        ("6.17.8-arch1-1", (6, 17)),
        ("6.6.87.2-microsoft-standard-WSL2", (6, 6)),
        ("5.10.0-35-amd64", (5, 10)),
        ("6.0_custom", (6, 0)),
        ("  6.12.58\n", (6, 12)),
    ] {
        assert_eq!(parse_release(release), Some(version), "{release}");
    }
}

/// A release that does not start with the two numbers is not read.
#[test]
fn a_release_without_its_version_is_not_read() {
    for release in [
        "",
        "6",
        "6.",
        ".1",
        "6.x",
        "x.1",
        "6.1rc1",
        "+6.1",
        "6.+1",
        "6 .1",
        "v6.1",
        "6.1a",
        "99999999999.1",
        "6.99999999999",
    ] {
        assert_eq!(parse_release(release), None, "{release:?}");
    }
}

/// 6.1 and every later release pass with the release named; an earlier one,
/// an unreadable one and one whose version cannot be told fail, naming the
/// release and the floor.
#[test]
fn only_linux_6_1_or_newer_passes() {
    for release in [
        "6.1.0-rc1",
        "6.1.158",
        "6.12.48+deb13-amd64",
        "7.0.0-14-generic",
        "10.0",
    ] {
        let result = judge_release(Some(release));
        assert!(result.is_pass(), "{release}: {result:?}");
        assert_eq!(result.message(), format!("Linux {release} (6.1 or newer)"));
    }
    for release in [
        "6.0.19",
        "5.15.0-140-generic",
        "5.10.0-35-amd64",
        "5.11",
        "4.19.0",
    ] {
        let result = judge_release(Some(release));
        assert!(result.is_fail(), "{release}: {result:?}");
        assert_eq!(
            result.message(),
            format!("Linux {release} is older than 6.1")
        );
        let fix = result.remediation().expect("a fix");
        assert!(fix.contains(&format!("This kernel is {release}.")), "{fix}");
        assert!(fix.contains("NAILS needs Linux 6.1 or newer"), "{fix}");
        assert!(fix.contains("Boot a kernel of Linux 6.1 or newer"), "{fix}");
    }
    let odd = judge_release(Some("6.x-custom"));
    assert!(odd.is_fail(), "{odd:?}");
    assert!(odd.message().contains("\"6.x-custom\""), "{odd:?}");
    let fix = odd.remediation().expect("a fix");
    assert!(fix.contains("\"6.x-custom\""), "{fix}");
    assert!(fix.contains("6.1 or newer"), "{fix}");
    for unread in [None, Some(""), Some(" \n")] {
        let result = judge_release(unread);
        assert!(result.is_fail(), "{unread:?}: {result:?}");
        assert_eq!(
            result.message(),
            "could not read the running kernel's release"
        );
        assert!(
            result
                .remediation()
                .is_some_and(|fix| fix.contains("6.1 or newer")),
            "{result:?}"
        );
    }
}

/// The check judges the release it is given, and the running kernel's
/// otherwise: the one the tests run on is new enough.
#[test]
fn the_check_judges_its_release_or_the_running_kernels() {
    let run = |check: KernelVersionCheck| {
        PreFlightCheck::<crate::filesystem::MockFilesystem>::run(
            &check,
            &crate::filesystem::MockFilesystem::new(),
        )
        .unwrap()
    };
    assert!(run(KernelVersionCheck::of(Some("5.15.0-140-generic"))).is_fail());
    assert!(run(KernelVersionCheck::of(None)).is_fail());
    assert!(run(KernelVersionCheck::of(Some("6.8.0-88-generic"))).is_pass());
    let running = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .expect("read the running kernel's release");
    let result = run(KernelVersionCheck::new());
    assert_eq!(result, judge_release(Some(running.trim())), "{running}");
    assert_eq!(
        PreFlightCheck::<crate::filesystem::MockFilesystem>::name(&KernelVersionCheck::new()),
        "kernel-version"
    );
}
