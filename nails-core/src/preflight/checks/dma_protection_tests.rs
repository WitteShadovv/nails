// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the DMA-protection posture report.

use super::*;
use crate::filesystem::MockFilesystem;
use std::path::{Path, PathBuf};

// ----- pure command-line parsing -----

#[test]
fn classifies_the_iommu_command_line() {
    assert_eq!(parse_iommu_cmdline("quiet"), IommuCmdline::Unset);
    assert_eq!(parse_iommu_cmdline(""), IommuCmdline::Unset);
    // A positive flag leaves the answer to /sys: it is intent, not proof.
    assert_eq!(
        parse_iommu_cmdline("BOOT_IMAGE=/vmlinuz intel_iommu=on iommu.passthrough=0 quiet"),
        IommuCmdline::Unset
    );
    assert_eq!(parse_iommu_cmdline("iommu=pt"), IommuCmdline::Passthrough);
    assert_eq!(
        parse_iommu_cmdline("iommu.passthrough=1"),
        IommuCmdline::Passthrough
    );
    assert_eq!(parse_iommu_cmdline("iommu=off"), IommuCmdline::Off);
    assert_eq!(parse_iommu_cmdline("intel_iommu=off"), IommuCmdline::Off);
    assert_eq!(parse_iommu_cmdline("amd_iommu=off"), IommuCmdline::Off);
    // Dashes and underscores are equivalent in a parameter name.
    assert_eq!(parse_iommu_cmdline("intel-iommu=off"), IommuCmdline::Off);
}

#[test]
fn the_last_passthrough_assignment_wins_and_off_dominates() {
    assert_eq!(
        parse_iommu_cmdline("iommu.passthrough=1 iommu.passthrough=0"),
        IommuCmdline::Unset
    );
    assert_eq!(
        parse_iommu_cmdline("iommu.passthrough=0 iommu.passthrough=1"),
        IommuCmdline::Passthrough
    );
    // iommu=off is the most exposed intent and dominates a passthrough flag.
    assert_eq!(parse_iommu_cmdline("iommu=pt iommu=off"), IommuCmdline::Off);
    assert_eq!(
        parse_iommu_cmdline("iommu=off iommu.passthrough=1"),
        IommuCmdline::Off
    );
}

#[test]
fn init_arguments_after_double_dash_are_ignored() {
    assert_eq!(
        parse_iommu_cmdline("quiet -- iommu=pt"),
        IommuCmdline::Unset
    );
}

#[test]
fn kstrtobool_parses_the_kernel_boolean_spellings() {
    // The documented kstrtobool contract, including the two-character `on`
    // and `off` spellings that need a second character to disambiguate.
    for truthy in ["y", "Y", "t", "1", "yes", "true", "on", "ON"] {
        assert_eq!(kstrtobool(truthy), Some(true), "{truthy:?} should be true");
    }
    for falsy in ["n", "N", "f", "0", "no", "false", "off", "OFF"] {
        assert_eq!(kstrtobool(falsy), Some(false), "{falsy:?} should be false");
    }
    // A leading `o` that is neither `on` nor `off` is rejected, as is junk.
    assert_eq!(kstrtobool("ouch"), None);
    assert_eq!(kstrtobool("maybe"), None);
    assert_eq!(kstrtobool(""), None);
}

#[test]
fn iommu_nopt_reverses_an_earlier_passthrough_request() {
    // `iommu=nopt` asks for no passthrough; as the last assignment it cancels
    // a preceding `iommu=pt`, so nothing ends up requesting passthrough.
    assert_eq!(
        parse_iommu_cmdline("iommu=pt iommu=nopt"),
        IommuCmdline::Unset
    );
    // It also cancels an explicit iommu.passthrough=1 that came before it.
    assert_eq!(
        parse_iommu_cmdline("iommu.passthrough=1 iommu=nopt"),
        IommuCmdline::Unset
    );
}

// ----- pure lockdown parsing -----

#[test]
fn parses_the_bracketed_lockdown_state() {
    assert_eq!(
        parse_lockdown("none [integrity] confidentiality\n"),
        Lockdown::Integrity
    );
    assert_eq!(
        parse_lockdown("none integrity [confidentiality]"),
        Lockdown::Confidentiality
    );
    assert_eq!(
        parse_lockdown("[none] integrity confidentiality"),
        Lockdown::None
    );
    // No bracketed token, or empty: read as off rather than panicking.
    assert_eq!(parse_lockdown("garbage"), Lockdown::None);
    assert_eq!(parse_lockdown(""), Lockdown::None);
}

// ----- pure verdict, the decision table -----

#[test]
fn a_thunderbolt_controller_without_protection_warns() {
    // iommu_dma_protection=0, even with the general IOMMU translating.
    let result = verdict(
        TbProtection::Exposed,
        IommuState::Translating,
        Lockdown::Confidentiality,
        true,
    );
    assert!(result.is_warn(), "{}", result.message());
    assert!(result.message().contains("iommu_dma_protection=0"));
    // confidentiality does not save a machine whose hardware DMA path is open.
    assert!(
        result
            .message()
            .contains("does not close this hardware path")
    );
    assert!(result.message().contains("MOR"), "names the MOR boundary");
}

#[test]
fn an_iommu_in_passthrough_warns_even_with_a_protected_controller() {
    // Effective /sys state overrides a stale Thunderbolt attribute.
    let result = verdict(
        TbProtection::Protected,
        IommuState::Exposed,
        Lockdown::None,
        true,
    );
    assert!(result.is_warn(), "{}", result.message());
    assert!(result.message().contains("all of system RAM"));
}

#[test]
fn an_exposed_machine_warns_but_never_blocks() {
    let result = verdict(
        TbProtection::Absent,
        IommuState::Exposed,
        Lockdown::None,
        true,
    );
    assert!(result.is_warn());
    assert!(!result.is_fail(), "the check must never block activation");
    assert!(
        result.message().contains("nails emergency --poweroff"),
        "the fix names the power-off mitigation"
    );
}

#[test]
fn a_protected_machine_with_full_lockdown_passes() {
    let result = verdict(
        TbProtection::Protected,
        IommuState::Translating,
        Lockdown::Confidentiality,
        true,
    );
    assert!(result.is_pass(), "{}", result.message());
    assert!(result.message().contains("iommu_dma_protection=1"));
    assert!(result.message().contains("closed too"));
    assert!(
        result
            .message()
            .contains("power off before handing it over")
    );
}

#[test]
fn a_protected_machine_advises_on_each_weaker_lockdown() {
    for (lockdown, needle) in [
        (Lockdown::Integrity, "lockdown is integrity"),
        (Lockdown::None, "lockdown is off"),
    ] {
        let result = verdict(
            TbProtection::Absent,
            IommuState::Translating,
            lockdown,
            true,
        );
        assert!(result.is_pass(), "{lockdown:?}: {}", result.message());
        assert!(result.message().contains("Advisory"), "{lockdown:?}");
        assert!(result.message().contains(needle), "{lockdown:?}");
    }
}

#[test]
fn a_missing_lockdown_lsm_draws_no_advisory() {
    // CONFIG_SECURITY_LOCKDOWN_LSM=n: judge on the DMA path, do not warn for
    // the missing file.
    let result = verdict(
        TbProtection::Protected,
        IommuState::Translating,
        Lockdown::Unavailable,
        true,
    );
    assert!(result.is_pass(), "{}", result.message());
    assert!(!result.message().contains("Advisory"));
    assert!(!result.message().contains("software memory-read paths"));
}

#[test]
fn an_unconfirmable_iommu_soft_warns() {
    let result = verdict(
        TbProtection::Absent,
        IommuState::Unknown,
        Lockdown::Unavailable,
        true, // the command line was readable, so this is not a skip
    );
    assert!(result.is_warn(), "{}", result.message());
    assert!(result.message().contains("Could not confirm"));
    assert!(
        result
            .message()
            .contains("virtual-machine or container guest")
    );
}

#[test]
fn a_protected_pass_crediting_both_signals_names_both() {
    // Both the active IOMMU and the Thunderbolt controller confirm
    // protection: the basis names the IOMMU remapping AND the controller.
    let result = verdict(
        TbProtection::Protected,
        IommuState::Translating,
        Lockdown::Unavailable,
        true,
    );
    assert!(result.is_pass(), "{}", result.message());
    assert!(
        result
            .message()
            .contains("remapping DMA and the Thunderbolt"),
        "both signals must be cited: {}",
        result.message()
    );
}

#[test]
fn a_protected_pass_on_the_thunderbolt_signal_alone_does_not_claim_remapping() {
    // The controller reports protection but /sys could not confirm remapping
    // (IOMMU Unknown): the basis is the Thunderbolt signal only, and it must
    // not assert the IOMMU is remapping DMA.
    let result = verdict(
        TbProtection::Protected,
        IommuState::Unknown,
        Lockdown::Unavailable,
        true,
    );
    assert!(result.is_pass(), "{}", result.message());
    assert!(
        result
            .message()
            .contains("controller reports IOMMU DMA protection"),
        "{}",
        result.message()
    );
    assert!(
        !result.message().contains("remapping DMA and"),
        "must not claim the IOMMU is remapping: {}",
        result.message()
    );
}

#[test]
fn a_protected_pass_on_the_iommu_alone_credits_only_the_iommu() {
    // No Thunderbolt signal, IOMMU translating: the basis is the active
    // IOMMU alone and cites no Thunderbolt controller.
    let result = verdict(
        TbProtection::Absent,
        IommuState::Translating,
        Lockdown::Unavailable,
        true,
    );
    assert!(result.is_pass(), "{}", result.message());
    assert!(
        result.message().contains("an active IOMMU is present"),
        "{}",
        result.message()
    );
    assert!(
        !result.message().contains("Thunderbolt"),
        "there is no Thunderbolt signal to cite: {}",
        result.message()
    );
}

#[test]
fn nothing_readable_at_all_is_skipped() {
    let result = verdict(
        TbProtection::Absent,
        IommuState::Unknown,
        Lockdown::Unavailable,
        false,
    );
    assert!(result.is_skipped(), "{}", result.message());
    assert!(!result.is_fail());
    assert!(
        result
            .message()
            .contains("virtual-machine or container guest")
    );
}

// ----- integration through run() with a mock filesystem -----

/// Seed one active IOMMU under /sys/class/iommu.
fn with_active_iommu(fs: &MockFilesystem) {
    fs.mock_set_directory_contents(
        Path::new(IOMMU_CLASS),
        vec![PathBuf::from("/sys/class/iommu/dmar0")],
    );
}

/// Seed one Thunderbolt controller reporting `value` for iommu_dma_protection.
fn with_thunderbolt(fs: &MockFilesystem, value: &str) {
    let dir = "/sys/bus/thunderbolt/devices/domain0";
    fs.mock_set_directory_contents(Path::new(THUNDERBOLT_DEVICES), vec![PathBuf::from(dir)]);
    fs.mock_add_file(&format!("{dir}/{TB_DMA_PROTECTION}"), &format!("{value}\n"));
}

/// Seed `count` IOMMU groups, each reporting domain `kind` in its `type`.
fn with_iommu_groups(fs: &MockFilesystem, kind: &str, count: usize) {
    let dirs: Vec<PathBuf> = (0..count)
        .map(|n| PathBuf::from(format!("/sys/kernel/iommu_groups/{n}")))
        .collect();
    for dir in &dirs {
        fs.mock_add_file(
            &format!("{}/{IOMMU_GROUP_TYPE}", dir.display()),
            &format!("{kind}\n"),
        );
    }
    fs.mock_set_directory_contents(Path::new(IOMMU_GROUPS), dirs);
}

#[test]
fn run_warns_when_the_command_line_requests_passthrough() {
    let fs = MockFilesystem::new();
    fs.mock_add_file(
        PROC_CMDLINE,
        "BOOT_IMAGE=/vmlinuz intel_iommu=on iommu=pt quiet\n",
    );
    with_active_iommu(&fs);
    let result = DmaProtectionCheck::new().run(&fs).unwrap();
    assert!(result.is_warn(), "{}", result.message());
    assert!(result.message().contains("all of system RAM"));
    assert!(result.message().contains("nails emergency --poweroff"));
}

#[test]
fn run_warns_when_the_iommu_is_turned_off() {
    let fs = MockFilesystem::new();
    fs.mock_add_file(PROC_CMDLINE, "intel_iommu=off\n");
    // No /sys IOMMU seeded: the off flag alone is decisive.
    let result = DmaProtectionCheck::new().run(&fs).unwrap();
    assert!(result.is_warn(), "{}", result.message());
}

#[test]
fn run_warns_when_a_thunderbolt_controller_is_unprotected() {
    let fs = MockFilesystem::new();
    fs.mock_add_file(PROC_CMDLINE, "intel_iommu=on\n");
    with_active_iommu(&fs);
    with_thunderbolt(&fs, "0");
    let result = DmaProtectionCheck::new().run(&fs).unwrap();
    assert!(result.is_warn(), "{}", result.message());
    assert!(result.message().contains("iommu_dma_protection=0"));
}

#[test]
fn run_passes_a_fully_dma_hardened_machine() {
    let fs = MockFilesystem::new();
    fs.mock_add_file(PROC_CMDLINE, "intel_iommu=on iommu.passthrough=0\n");
    with_active_iommu(&fs);
    with_thunderbolt(&fs, "1");
    fs.mock_add_file(LOCKDOWN, "none integrity [confidentiality]\n");
    let result = DmaProtectionCheck::new().run(&fs).unwrap();
    assert!(result.is_pass(), "{}", result.message());
    assert!(result.message().contains("iommu_dma_protection=1"));
    assert!(result.message().contains("closed too"));
}

#[test]
fn run_passes_an_active_iommu_without_thunderbolt_and_advises_on_lockdown() {
    let fs = MockFilesystem::new();
    fs.mock_add_file(PROC_CMDLINE, "quiet\n");
    with_active_iommu(&fs);
    fs.mock_add_file(LOCKDOWN, "[none] integrity confidentiality\n");
    let result = DmaProtectionCheck::new().run(&fs).unwrap();
    assert!(result.is_pass(), "{}", result.message());
    assert!(result.message().contains("Advisory"));
    assert!(result.message().contains("lockdown is off"));
}

#[test]
fn run_treats_an_empty_sys_iommu_as_exposed() {
    let fs = MockFilesystem::new();
    fs.mock_add_file(PROC_CMDLINE, "quiet\n");
    // /sys is readable but lists no IOMMU: genuinely none active.
    fs.mock_set_directory_contents(Path::new(IOMMU_CLASS), vec![]);
    fs.mock_set_directory_contents(Path::new(IOMMU_GROUPS), vec![]);
    let result = DmaProtectionCheck::new().run(&fs).unwrap();
    assert!(result.is_warn(), "{}", result.message());
}

#[test]
fn run_warns_when_every_iommu_group_is_passthrough() {
    // CONFIG_IOMMU_DEFAULT_PASSTHROUGH=y, or a firmware default: an IOMMU is
    // present (and /sys/class/iommu lists it) but every group is identity-
    // mapped, so DMA is not remapped and no command-line flag says so. The
    // group type is the only signal, and it must override the mere presence.
    let fs = MockFilesystem::new();
    fs.mock_add_file(PROC_CMDLINE, "quiet\n");
    with_active_iommu(&fs);
    with_iommu_groups(&fs, "identity", 3);
    let result = DmaProtectionCheck::new().run(&fs).unwrap();
    assert!(result.is_warn(), "{}", result.message());
    assert!(result.message().contains("all of system RAM"));
}

#[test]
fn run_passes_when_an_iommu_group_is_remapping() {
    // Only the group type reports translation (no /sys/class/iommu seeded):
    // a DMA/DMA-FQ group proves the IOMMU is remapping DMA.
    let fs = MockFilesystem::new();
    fs.mock_add_file(PROC_CMDLINE, "quiet\n");
    with_iommu_groups(&fs, "DMA-FQ", 2);
    let result = DmaProtectionCheck::new().run(&fs).unwrap();
    assert!(result.is_pass(), "{}", result.message());
}

#[test]
fn run_lets_a_remapping_group_outrank_a_passthrough_group() {
    // A mix of domain types: one group remaps DMA (DMA-FQ) while another is
    // identity-mapped (passthrough). A single remapping group proves the
    // IOMMU is translating, so a passthrough group must not downgrade it.
    let fs = MockFilesystem::new();
    fs.mock_add_file(PROC_CMDLINE, "quiet\n");
    let translating = "/sys/kernel/iommu_groups/0";
    let passthrough = "/sys/kernel/iommu_groups/1";
    fs.mock_set_directory_contents(
        Path::new(IOMMU_GROUPS),
        vec![PathBuf::from(translating), PathBuf::from(passthrough)],
    );
    fs.mock_add_file(&format!("{translating}/{IOMMU_GROUP_TYPE}"), "DMA-FQ\n");
    fs.mock_add_file(&format!("{passthrough}/{IOMMU_GROUP_TYPE}"), "identity\n");
    let result = DmaProtectionCheck::new().run(&fs).unwrap();
    assert!(result.is_pass(), "{}", result.message());
    assert!(
        result.message().contains("remapping DMA"),
        "{}",
        result.message()
    );
}

#[test]
fn run_does_not_downgrade_iommu_groups_without_a_type() {
    // A kernel before 5.14 lists groups but exposes no `type`: fall back to
    // presence rather than wrongly reading it as passthrough.
    let fs = MockFilesystem::new();
    fs.mock_add_file(PROC_CMDLINE, "quiet\n");
    fs.mock_set_directory_contents(
        Path::new(IOMMU_GROUPS),
        vec![PathBuf::from("/sys/kernel/iommu_groups/0")],
    );
    let result = DmaProtectionCheck::new().run(&fs).unwrap();
    assert!(result.is_pass(), "{}", result.message());
}

#[test]
fn run_soft_warns_when_only_the_command_line_is_readable() {
    // A command line with no IOMMU flag, and no /sys at all (e.g. a guest):
    // could-not-confirm, a soft warning, not a skip and never a panic.
    let fs = MockFilesystem::new();
    fs.mock_add_file(PROC_CMDLINE, "quiet splash\n");
    let result = DmaProtectionCheck::new().run(&fs).unwrap();
    assert!(result.is_warn(), "{}", result.message());
    assert!(result.message().contains("Could not confirm"));
}

#[test]
fn run_skips_when_nothing_can_be_read() {
    // An empty mock: no /proc, no /sys, no securityfs. Graceful, no panic.
    let fs = MockFilesystem::new();
    let result = DmaProtectionCheck::new().run(&fs).unwrap();
    assert!(result.is_skipped(), "{}", result.message());
}

#[test]
fn run_tolerates_a_thunderbolt_controller_without_the_attribute() {
    // An older kernel: the controller directory exists but exposes no
    // iommu_dma_protection file. No Thunderbolt signal, judged on the IOMMU.
    let fs = MockFilesystem::new();
    fs.mock_add_file(PROC_CMDLINE, "intel_iommu=on\n");
    with_active_iommu(&fs);
    fs.mock_set_directory_contents(
        Path::new(THUNDERBOLT_DEVICES),
        vec![PathBuf::from("/sys/bus/thunderbolt/devices/domain0")],
    );
    let result = DmaProtectionCheck::new().run(&fs).unwrap();
    assert!(result.is_pass(), "{}", result.message());
}

#[test]
fn run_lets_one_unprotected_controller_override_a_protected_one() {
    let fs = MockFilesystem::new();
    fs.mock_add_file(PROC_CMDLINE, "intel_iommu=on\n");
    with_active_iommu(&fs);
    let protected = "/sys/bus/thunderbolt/devices/domain0";
    let exposed = "/sys/bus/thunderbolt/devices/domain1";
    fs.mock_set_directory_contents(
        Path::new(THUNDERBOLT_DEVICES),
        vec![PathBuf::from(protected), PathBuf::from(exposed)],
    );
    fs.mock_add_file(&format!("{protected}/{TB_DMA_PROTECTION}"), "1\n");
    fs.mock_add_file(&format!("{exposed}/{TB_DMA_PROTECTION}"), "0\n");
    let result = DmaProtectionCheck::new().run(&fs).unwrap();
    assert!(result.is_warn(), "{}", result.message());
    assert!(result.message().contains("iommu_dma_protection=0"));
}

#[test]
fn the_check_names_itself_and_never_fails() {
    let check = DmaProtectionCheck::new();
    assert_eq!(
        <DmaProtectionCheck as PreFlightCheck<MockFilesystem>>::name(&check),
        "dma-protection"
    );
    assert!(
        <DmaProtectionCheck as PreFlightCheck<MockFilesystem>>::description(&check).contains("DMA")
    );
}

#[test]
fn the_check_performs_no_writes() {
    let fs = MockFilesystem::new();
    fs.mock_add_file(PROC_CMDLINE, "intel_iommu=on iommu=pt\n");
    with_active_iommu(&fs);
    with_thunderbolt(&fs, "0");
    fs.mock_add_file(LOCKDOWN, "none [integrity] confidentiality\n");

    let before = fs.mock_ops().len();
    let _ = DmaProtectionCheck::new().run(&fs).unwrap();
    assert!(fs.mock_written_paths().is_empty(), "nothing was written");
    assert_eq!(
        fs.mock_ops().len(),
        before,
        "dma-protection check must not write: {:?}",
        fs.mock_ops()
    );
}
