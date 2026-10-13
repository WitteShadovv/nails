// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! `classify_swap` against `/proc/swaps` as the kernel prints it: the header,
//! the column padding and the tab separators of a real capture.

use super::{SwapSeverity, classify_swap};
use crate::filesystem::MockFilesystem;
use crate::kernel_fixtures;

/// The file names in a captured `/proc/swaps`, read the way a person would.
fn swap_files(swaps: &str) -> Vec<String> {
    swaps
        .lines()
        .skip(1)
        .filter_map(|l| l.split_whitespace().next())
        .map(str::to_string)
        .collect()
}

fn classify(swaps: &str) -> super::SwapPosture {
    let fs = MockFilesystem::new();
    fs.mock_add_file("/proc/swaps", swaps);
    classify_swap(&fs)
}

#[test]
fn captured_file_swap_is_named_and_fails() {
    let swaps = kernel_fixtures::userns("proc-swaps.txt");
    let files = swap_files(&swaps);
    let posture = classify(&swaps);
    if files.is_empty() {
        // The capture host had no swap: the header alone is no device.
        assert_eq!(posture.severity, SwapSeverity::Pass);
        return;
    }
    assert_eq!(posture.severity, SwapSeverity::Fail, "{posture:?}");
    assert_eq!(
        posture.disk_swap_devices, files,
        "every device, nothing else"
    );
}

#[test]
fn captured_vm_swaps_parse_without_a_phantom_device() {
    let Some(swaps) = kernel_fixtures::vm("proc-swaps.txt") else {
        return;
    };
    let posture = classify(&swaps);
    for device in &posture.disk_swap_devices {
        assert!(
            swap_files(&swaps).contains(device),
            "{device} is a device of the capture, not a header word"
        );
    }
    assert!(!posture.disk_swap_devices.iter().any(|d| d == "Filename"));
}
