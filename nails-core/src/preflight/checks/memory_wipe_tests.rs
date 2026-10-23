// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the freed-memory posture report.

use super::*;
use crate::RealFilesystem;
use std::path::Path;

#[test]
fn classifies_the_parameter() {
    assert_eq!(parse_init_on_free("quiet"), InitOnFree::Unset);
    assert_eq!(parse_init_on_free(""), InitOnFree::Unset);
    assert_eq!(
        parse_init_on_free("BOOT_IMAGE=/vmlinuz init_on_free=1 quiet\n"),
        InitOnFree::Enabled
    );
    assert_eq!(parse_init_on_free("init_on_free=on"), InitOnFree::Enabled);
    assert_eq!(parse_init_on_free("init-on-free=Y"), InitOnFree::Enabled);
    assert_eq!(parse_init_on_free("init_on_free"), InitOnFree::Unset);
    assert_eq!(parse_init_on_free("init_on_free=maybe"), InitOnFree::Unset);
    assert_eq!(
        parse_init_on_free("init_on_free=1 init_on_free=bogus"),
        InitOnFree::Enabled
    );
    assert_eq!(parse_init_on_free("init_on_free=0"), InitOnFree::Disabled);
    assert_eq!(parse_init_on_free("init_on_free=off"), InitOnFree::Disabled);
}

#[test]
fn the_last_occurrence_wins() {
    assert_eq!(
        parse_init_on_free("init_on_free=1 init_on_free=0"),
        InitOnFree::Disabled
    );
    assert_eq!(
        parse_init_on_free("init_on_free=0 init_on_free=1"),
        InitOnFree::Enabled
    );
}

#[test]
fn init_arguments_after_double_dash_are_ignored() {
    assert_eq!(
        parse_init_on_free("quiet -- init_on_free=1"),
        InitOnFree::Unset
    );
}

#[test]
fn a_similar_parameter_does_not_count() {
    assert_eq!(parse_init_on_free("init_on_alloc=1"), InitOnFree::Unset);
    assert_eq!(parse_init_on_free("xinit_on_free=1"), InitOnFree::Unset);
}

#[test]
fn config_default_is_read_from_the_kernel_config() {
    assert_eq!(
        parse_init_on_free_config("CONFIG_INIT_ON_FREE_DEFAULT_ON=y\n"),
        Some(true)
    );
    assert_eq!(
        parse_init_on_free_config("# CONFIG_INIT_ON_FREE_DEFAULT_ON is not set\n"),
        Some(false)
    );
    assert_eq!(
        parse_init_on_free_config("CONFIG_INIT_ON_FREE_DEFAULT_ON=n\n"),
        Some(false)
    );
    // A different, similarly named symbol does not decide it.
    assert_eq!(
        parse_init_on_free_config("CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y\n"),
        None
    );
    assert_eq!(parse_init_on_free_config("CONFIG_FOO=y\n"), None);
}

fn write(dir: &Path, rel: &str, content: &str) {
    let path = dir.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
}

/// Run the check over a tmpdir, writing the command line, the booted kernel's
/// config (for release `test-kernel`) and a dracut RAM-wipe module as asked.
fn run_with(cmdline: Option<&str>, config: Option<&str>, ram_wipe: bool) -> CheckResult {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    if let Some(cmdline) = cmdline {
        write(root, "cmdline", cmdline);
    }
    if let Some(config) = config {
        write(root, "osrelease", "test-kernel\n");
        write(root, "boot/config-test-kernel", config);
    }
    if ram_wipe {
        std::fs::create_dir_all(root.join("dracut-modules.d/40ram-wipe")).unwrap();
    }
    let check = MemoryWipeCheck {
        cmdline_path: root.join("cmdline"),
        osrelease_path: root.join("osrelease"),
        boot_dir: root.join("boot"),
        dracut_modules_dir: root.join("dracut-modules.d"),
    };
    check.run(&RealFilesystem).unwrap()
}

#[test]
fn the_command_line_enabling_it_passes() {
    let result = run_with(Some("root=/dev/sda1 init_on_free=1\n"), None, false);
    assert!(result.is_pass(), "{}", result.message());
    assert!(
        result.message().contains("zeroes freed memory"),
        "{}",
        result.message()
    );
}

#[test]
fn the_command_line_disabling_it_warns() {
    let result = run_with(Some("init_on_free=0\n"), None, false);
    assert!(result.is_warn(), "{}", result.message());
    assert!(
        result.message().contains("does not zero freed memory"),
        "{}",
        result.message()
    );
    assert!(
        result.message().contains("init_on_free=1"),
        "a fix is named"
    );
}

#[test]
fn the_kernel_config_decides_when_the_command_line_is_silent() {
    let on = run_with(
        Some("quiet\n"),
        Some("CONFIG_INIT_ON_FREE_DEFAULT_ON=y\n"),
        false,
    );
    assert!(on.is_pass(), "{}", on.message());

    let off = run_with(
        Some("quiet\n"),
        Some("# CONFIG_INIT_ON_FREE_DEFAULT_ON is not set\n"),
        false,
    );
    assert!(off.is_warn(), "{}", off.message());
}

#[test]
fn the_command_line_overrides_the_kernel_config() {
    // init_on_free=1 wins over a config default of off.
    let forced_on = run_with(
        Some("init_on_free=1\n"),
        Some("# CONFIG_INIT_ON_FREE_DEFAULT_ON is not set\n"),
        false,
    );
    assert!(forced_on.is_pass(), "{}", forced_on.message());
    // init_on_free=0 wins over a config default of on.
    let forced_off = run_with(
        Some("init_on_free=0\n"),
        Some("CONFIG_INIT_ON_FREE_DEFAULT_ON=y\n"),
        false,
    );
    assert!(forced_off.is_warn(), "{}", forced_off.message());
}

#[test]
fn without_a_readable_source_it_stays_an_informational_pass() {
    // Command line silent and no kernel config: the answer is unknown, so the
    // check stays an informational pass rather than warning on a guess.
    let silent = run_with(Some("quiet\n"), None, false);
    assert!(silent.is_pass(), "{}", silent.message());
    assert!(silent.message().contains("unknown"), "{}", silent.message());

    // Nothing readable at all.
    let nothing = run_with(None, None, false);
    assert!(nothing.is_pass(), "{}", nothing.message());
}

#[test]
fn a_ram_wipe_module_is_noted() {
    let result = run_with(Some("init_on_free=0\n"), None, true);
    assert!(result.is_warn(), "{}", result.message());
    assert!(
        result.message().contains("RAM-wipe mechanism"),
        "{}",
        result.message()
    );
}

#[test]
fn without_a_ram_wipe_module_the_report_adds_no_note() {
    // With no dracut ram-wipe module installed, the report must not claim one
    // is: the present case is covered by `a_ram_wipe_module_is_noted`, and this
    // is its mirror. (A check that always appended the note would falsely
    // reassure the user that RAM is wiped on shutdown.)
    let result = run_with(Some("init_on_free=0\n"), None, false);
    assert!(result.is_warn(), "{}", result.message());
    assert!(
        !result.message().contains("RAM-wipe mechanism"),
        "no RAM-wipe note without the module: {}",
        result.message()
    );
}

#[test]
fn a_comment_that_is_not_the_disabled_form_leaves_it_unknown() {
    // The disabled default is recognised only from the exact form
    // `# CONFIG_INIT_ON_FREE_DEFAULT_ON is not set`, which needs all three of:
    // a leading `#`, *this* symbol's name, and the phrase "is not set". A line
    // satisfying only some of those says nothing about init_on_free and must
    // leave the answer unknown (`None`); otherwise the check would warn on a
    // kernel whose default it has not actually determined.

    // A *different* symbol being "not set" (leading `#` and "is not set", but
    // not this symbol): common in real configs right beside the real line.
    assert_eq!(
        parse_init_on_free_config("# CONFIG_INIT_ON_ALLOC_DEFAULT_ON is not set\n"),
        None
    );
    // This symbol named in a comment that is not the "is not set" form
    // (leading `#` and the symbol, but not "is not set").
    assert_eq!(
        parse_init_on_free_config("# CONFIG_INIT_ON_FREE_DEFAULT_ON: see docs\n"),
        None
    );
    // An ordinary generated-config header comment, mentioning neither.
    assert_eq!(
        parse_init_on_free_config("# Automatically generated file; DO NOT EDIT\n"),
        None
    );
}

#[test]
fn the_description_names_what_it_reports() {
    // The description is surfaced to the user, so it must be present and name
    // its subject rather than be blank or a placeholder.
    let check = MemoryWipeCheck::new();
    let description = PreFlightCheck::<RealFilesystem>::description(&check);
    assert!(!description.is_empty(), "{description:?}");
    assert!(description.contains("freed memory"), "{description:?}");
}
