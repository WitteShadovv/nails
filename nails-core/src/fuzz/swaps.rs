// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! `/proc/swaps` and `/etc/crypttab`, through the swap classifier.

use super::octal_escape;
use crate::filesystem::MockFilesystem;
use crate::preflight::{SwapSeverity, classify_swap};
use proptest::prelude::*;

/// One active swap area.
#[derive(Debug, Clone)]
enum Area {
    /// A swap file at this path.
    File(String),
    /// A dm-crypt swap mapping; `random` says whether crypttab keys it from a
    /// random source, `dm` is its `/dev/dm-N` number.
    Crypt { name: String, random: bool, dm: u32 },
    /// RAM-only zram.
    Zram(u32),
}

/// `/proc/swaps` as the kernel writes it: a header, then the `d_path` of each
/// area (escaped like a mountinfo path) and its type.
fn render_swaps(areas: &[Area]) -> String {
    let mut out = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n".to_string();
    for area in areas {
        let (path, kind) = match area {
            Area::File(path) => (octal_escape(path, " \t\n\\"), "file"),
            // swapon resolves /dev/mapper/<name> to the device node it links to.
            Area::Crypt { dm, .. } => (format!("/dev/dm-{dm}"), "partition"),
            Area::Zram(n) => (format!("/dev/zram{n}"), "partition"),
        };
        out.push_str(&format!("{path}\t{kind}\t\t1048572\t\t0\t\t-2\n"));
    }
    out
}

fn area() -> impl Strategy<Value = Area> {
    prop_oneof![
        super::abs_path().prop_map(Area::File),
        ("[a-z][a-z0-9_-]{0,10}", any::<bool>(), 0u32..64)
            .prop_map(|(name, random, dm)| Area::Crypt { name, random, dm }),
        (0u32..4).prop_map(Area::Zram),
    ]
}

fn host(areas: &[Area]) -> MockFilesystem {
    let fs = MockFilesystem::new();
    fs.mock_add_file("/proc/swaps", &render_swaps(areas));
    fs.mock_add_file("/proc/cmdline", "quiet\n");
    fs.mock_add_file("/sys/power/resume", "0:0\n");
    let mut crypttab = String::from("# <name> <device> <key> <options>\n");
    for area in areas {
        match area {
            Area::Crypt { name, random, dm } => {
                fs.mock_add_file(&format!("/sys/block/dm-{dm}/dm/name"), &format!("{name}\n"));
                let key = if *random {
                    "/dev/urandom"
                } else {
                    "/etc/keys/swap.key"
                };
                crypttab.push_str(&format!(
                    "{name}\t/dev/sda3\t{key}\tcipher=aes-xts-plain64\n"
                ));
            }
            Area::Zram(n) => fs.mock_add_file(&format!("/sys/block/zram{n}/backing_dev"), "none\n"),
            Area::File(_) => {}
        }
    }
    fs.mock_add_file("/etc/crypttab", &crypttab);
    fs
}

proptest! {
    /// The verdict matches the model: a file or a non-random mapping fails, a
    /// randomly keyed mapping warns, zram passes.
    #[test]
    fn fuzz_swap_classification_matches_the_model(
        areas in prop::collection::vec(area(), 0..5)
            .prop_filter("one entry per dm device", |areas| {
                let mut dms: Vec<u32> = areas.iter().filter_map(|a| match a {
                    Area::Crypt { dm, .. } => Some(*dm),
                    _ => None,
                }).collect();
                let names: std::collections::HashSet<&String> = areas.iter().filter_map(|a| match a {
                    Area::Crypt { name, .. } => Some(name),
                    _ => None,
                }).collect();
                let count = dms.len();
                dms.sort();
                dms.dedup();
                dms.len() == count && names.len() == count
            })
    ) {
        let expected = areas.iter().map(|area| match area {
            Area::File(_) | Area::Crypt { random: false, .. } => SwapSeverity::Fail,
            Area::Crypt { random: true, .. } => SwapSeverity::Warn,
            Area::Zram(_) => SwapSeverity::Pass,
        }).max().unwrap_or(SwapSeverity::Pass);
        let posture = classify_swap(&host(&areas));
        prop_assert_eq!(posture.severity, expected, "areas: {:?} findings: {:?}", areas, posture.findings);
        for area in &areas {
            if let Area::File(path) = area {
                prop_assert!(
                    posture.findings.iter().any(|f| f.contains(path.as_str())),
                    "the finding must name the decoded path {:?}: {:?}", path, posture.findings
                );
            }
        }
    }

    #[test]
    fn fuzz_swap_parsers_never_panic(swaps in "\\PC{0,200}", crypttab in "\\PC{0,200}") {
        let fs = MockFilesystem::new();
        fs.mock_add_file("/proc/swaps", &swaps);
        fs.mock_add_file("/etc/crypttab", &crypttab);
        let _ = classify_swap(&fs);
    }
}
