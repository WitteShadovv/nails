// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::{
    Filesystem,
    filesystem::{MockFilesystem, PathKind},
};
use std::os::unix::fs::PermissionsExt;

#[test]
fn test_prepare_nixos_config_overlay_success() {
    let fs = MockFilesystem::new();
    let hidden_path = std::path::PathBuf::from("/mnt/hidden");

    // Setup filesystem structure using mock
    fs.mock_set_path_exists("/mnt/hidden/etc/nixos", true);
    fs.mock_set_path_type("/mnt/hidden/etc/nixos", PathKind::Dir);
    fs.mock_set_path_exists("/mnt/hidden/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_type(
        "/mnt/hidden/etc/nixos/hardware-configuration.nix",
        PathKind::File,
    );
    fs.mock_set_path_exists("/mnt/hidden/config/nixos/configuration.nix", true);
    fs.mock_set_path_type("/mnt/hidden/config/nixos/configuration.nix", PathKind::File);

    let etc_nixos = hidden_path.join("etc/nixos");
    let hardware_config = etc_nixos.join("hardware-configuration.nix");
    let hidden_config = hidden_path.join("config/nixos/configuration.nix");

    // Create file content with import
    <MockFilesystem as Filesystem>::write_file_content(
        &fs,
        &hardware_config,
        "imports = [ ./nails/configuration.nix ];",
    )
    .unwrap();
    <MockFilesystem as Filesystem>::write_file_content(&fs, &hidden_config, "{ ... }: { }")
        .unwrap();

    // Validate overlay
    let result = prepare_nixos_config_overlay(&fs, &hidden_path).unwrap();

    assert_eq!(result.hardware_config_path, hardware_config);
    assert_eq!(result.hidden_config_path, hidden_config);
    assert_eq!(result.etc_nixos_overlay, etc_nixos);
}

#[test]
fn test_prepare_nixos_config_overlay_missing_etc_nixos_returns_error() {
    let fs = MockFilesystem::new();
    let hidden_path = std::path::PathBuf::from("/mnt/hidden");

    let err = prepare_nixos_config_overlay(&fs, &hidden_path).unwrap_err();
    assert!(err.to_string().contains("missing etc/nixos directory"));
}

#[test]
fn test_prepare_nixos_config_overlay_missing_hardware_config_returns_error() {
    let fs = MockFilesystem::new();
    let hidden_path = std::path::PathBuf::from("/mnt/hidden");

    fs.mock_set_path_exists("/mnt/hidden/etc/nixos", true);
    fs.mock_set_path_type("/mnt/hidden/etc/nixos", PathKind::Dir);

    let err = prepare_nixos_config_overlay(&fs, &hidden_path).unwrap_err();
    assert!(
        err.to_string()
            .contains("Modified hardware-configuration.nix not found")
    );
}

#[test]
fn test_prepare_nixos_config_overlay_missing_hidden_configuration_returns_error() {
    let fs = MockFilesystem::new();
    let hidden_path = std::path::PathBuf::from("/mnt/hidden");
    let hardware_config = hidden_path.join("etc/nixos/hardware-configuration.nix");

    fs.mock_set_path_exists("/mnt/hidden/etc/nixos", true);
    fs.mock_set_path_type("/mnt/hidden/etc/nixos", PathKind::Dir);
    fs.mock_set_path_exists("/mnt/hidden/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_type(
        "/mnt/hidden/etc/nixos/hardware-configuration.nix",
        PathKind::File,
    );
    <MockFilesystem as Filesystem>::write_file_content(
        &fs,
        &hardware_config,
        "imports = [ ./nails/configuration.nix ];",
    )
    .unwrap();

    let err = prepare_nixos_config_overlay(&fs, &hidden_path).unwrap_err();
    assert!(
        err.to_string()
            .contains("Hidden configuration.nix not found")
    );
}

#[test]
fn test_prepare_nixos_config_overlay_rejects_missing_required_import() {
    let fs = MockFilesystem::new();
    let hidden_path = std::path::PathBuf::from("/mnt/hidden");
    let hardware_config = hidden_path.join("etc/nixos/hardware-configuration.nix");
    let hidden_config = hidden_path.join("config/nixos/configuration.nix");

    fs.mock_set_path_exists("/mnt/hidden/etc/nixos", true);
    fs.mock_set_path_type("/mnt/hidden/etc/nixos", PathKind::Dir);
    fs.mock_set_path_exists("/mnt/hidden/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_type(
        "/mnt/hidden/etc/nixos/hardware-configuration.nix",
        PathKind::File,
    );
    fs.mock_set_path_exists("/mnt/hidden/config/nixos/configuration.nix", true);
    fs.mock_set_path_type("/mnt/hidden/config/nixos/configuration.nix", PathKind::File);

    <MockFilesystem as Filesystem>::write_file_content(
        &fs,
        &hardware_config,
        "{ config, pkgs, ... }: { imports = [ ./foo.nix ]; }",
    )
    .unwrap();
    <MockFilesystem as Filesystem>::write_file_content(&fs, &hidden_config, "{ ... }: { }")
        .unwrap();

    let err = prepare_nixos_config_overlay(&fs, &hidden_path).unwrap_err();
    assert!(err.to_string().contains("does not contain required import"));
}

#[test]
fn test_verify_base_config_clean_success() {
    let fs = MockFilesystem::new();
    let base_config = std::path::PathBuf::from("/etc/nixos/hardware-configuration.nix");

    // Create base config with no suspicious patterns
    <MockFilesystem as Filesystem>::write_file_content(
        &fs,
        &base_config,
        "{ config, pkgs, ... }: { }",
    )
    .unwrap();
    fs.mock_set_files_with_pattern("/etc/nixos", ".nix", &[&base_config]);

    let is_clean = verify_base_config_clean(&fs, std::path::Path::new("/mnt/hidden")).unwrap();
    assert!(is_clean, "Base config should be clean");
}

#[test]
fn test_verify_base_config_clean_missing_file_is_treated_as_clean() {
    let fs = MockFilesystem::new();

    let is_clean = verify_base_config_clean(&fs, std::path::Path::new("/mnt/hidden")).unwrap();
    assert!(is_clean, "Missing base config should be treated as clean");
}

#[test]
fn test_verify_base_config_clean_suspicious_hidden_path() {
    let fs = MockFilesystem::new();
    let base_config = std::path::PathBuf::from("/etc/nixos/hardware-configuration.nix");

    // Create base config with suspicious /mnt/hidden reference
    <MockFilesystem as Filesystem>::write_file_content(
        &fs,
        &base_config,
        "{ fileSystems.\"/mnt/hidden\" = { }; }",
    )
    .unwrap();
    fs.mock_set_files_with_pattern("/etc/nixos", ".nix", &[&base_config]);

    let is_clean = verify_base_config_clean(&fs, std::path::Path::new("/mnt/hidden")).unwrap();
    assert!(
        !is_clean,
        "Base config should not be clean with /mnt/hidden"
    );
}

#[test]
fn test_verify_base_config_clean_detects_relative_nails_import() {
    let fs = MockFilesystem::new();
    let base_config = std::path::PathBuf::from("/etc/nixos/hardware-configuration.nix");

    <MockFilesystem as Filesystem>::write_file_content(
        &fs,
        &base_config,
        "{ ... }: { imports = [ ./nails/configuration.nix ]; }",
    )
    .unwrap();
    fs.mock_set_files_with_pattern("/etc/nixos", ".nix", &[&base_config]);

    let is_clean = verify_base_config_clean(&fs, std::path::Path::new("/mnt/hidden")).unwrap();
    assert!(
        !is_clean,
        "Base config should not be clean with relative nails import"
    );
}

#[test]
fn test_verify_base_config_clean_detects_nails_token_without_spaces() {
    let fs = MockFilesystem::new();
    let base_config = std::path::PathBuf::from("/etc/nixos/hardware-configuration.nix");

    <MockFilesystem as Filesystem>::write_file_content(
        &fs,
        &base_config,
        "{ config.nails.enable = true; }",
    )
    .unwrap();
    fs.mock_set_files_with_pattern("/etc/nixos", ".nix", &[&base_config]);

    let is_clean = verify_base_config_clean(&fs, std::path::Path::new("/mnt/hidden")).unwrap();
    assert!(
        !is_clean,
        "Base config should not be clean with dotted nails reference"
    );
}

#[test]
fn test_verify_base_config_clean_ignores_embedded_non_token_nails_text() {
    let fs = MockFilesystem::new();
    let base_config = std::path::PathBuf::from("/etc/nixos/hardware-configuration.nix");

    <MockFilesystem as Filesystem>::write_file_content(
        &fs,
        &base_config,
        "{ networking.hostName = \"snails-box\"; }",
    )
    .unwrap();
    fs.mock_set_files_with_pattern("/etc/nixos", ".nix", &[&base_config]);

    let is_clean = verify_base_config_clean(&fs, std::path::Path::new("/mnt/hidden")).unwrap();
    assert!(
        is_clean,
        "Base config should remain clean when 'nails' only appears inside a larger token"
    );
}

#[test]
fn test_verify_base_config_clean_detects_hidden_keyword_boundary() {
    let fs = MockFilesystem::new();
    let base_config = std::path::PathBuf::from("/etc/nixos/hardware-configuration.nix");

    <MockFilesystem as Filesystem>::write_file_content(
        &fs,
        &base_config,
        "{ boot.kernelParams = [ \"hidden\" ]; }",
    )
    .unwrap();
    fs.mock_set_files_with_pattern("/etc/nixos", ".nix", &[&base_config]);

    let is_clean = verify_base_config_clean(&fs, std::path::Path::new("/mnt/hidden")).unwrap();
    assert!(!is_clean, "Standalone hidden token should be flagged");
}

#[test]
fn test_verify_base_config_clean_detects_plausible_deniability_keywords() {
    let fs = MockFilesystem::new();
    let base_config = std::path::PathBuf::from("/etc/nixos/hardware-configuration.nix");

    <MockFilesystem as Filesystem>::write_file_content(
        &fs,
        &base_config,
        "{ assertions = [ { message = \"plausible deniability\"; } ]; }",
    )
    .unwrap();
    fs.mock_set_files_with_pattern("/etc/nixos", ".nix", &[&base_config]);

    let is_clean = verify_base_config_clean(&fs, std::path::Path::new("/mnt/hidden")).unwrap();
    assert!(
        !is_clean,
        "Plausible deniability keywords should be flagged"
    );
}

#[test]
fn test_verify_base_config_clean_flags_custom_mountpoint_root() {
    let fs = MockFilesystem::new();
    let base_config = std::path::PathBuf::from("/etc/nixos/hardware-configuration.nix");

    // A fileSystems entry for the configured hidden root at a non-/mnt/hidden path.
    <MockFilesystem as Filesystem>::write_file_content(
        &fs,
        &base_config,
        "{ fileSystems.\"/mnt/vault\" = { device = \"/dev/disk/by-uuid/abcd\"; }; }",
    )
    .unwrap();
    fs.mock_set_files_with_pattern("/etc/nixos", ".nix", &[&base_config]);

    let is_clean = verify_base_config_clean(&fs, std::path::Path::new("/mnt/vault")).unwrap();
    assert!(
        !is_clean,
        "A fileSystems entry for the configured hidden root must be flagged regardless of mount point"
    );
}

#[test]
fn test_verify_base_config_clean_flags_mapper_device_from_mountinfo() {
    let fs = MockFilesystem::new();
    let base_config = std::path::PathBuf::from("/etc/nixos/hardware-configuration.nix");

    // The base config references the hidden volume's backing device at an
    // unrelated mount point; only the mount table ties it to the hidden root.
    <MockFilesystem as Filesystem>::write_file_content(
        &fs,
        &base_config,
        "{ swapDevices = [ { device = \"/dev/mapper/vault\"; } ]; }",
    )
    .unwrap();
    fs.mock_set_files_with_pattern("/etc/nixos", ".nix", &[&base_config]);

    // The captured hidden-root scene (fixture README): the kernel's own line
    // for a filesystem from /dev/mapper/vault at "/fixture/mnt/hidden root",
    // printed with the space octal-escaped.
    <MockFilesystem as Filesystem>::write_file_content(
        &fs,
        std::path::Path::new("/proc/self/mountinfo"),
        &crate::kernel_fixtures::userns("mountinfo-hidden-root.txt"),
    )
    .unwrap();

    let is_clean =
        verify_base_config_clean(&fs, std::path::Path::new("/fixture/mnt/hidden root")).unwrap();
    assert!(
        !is_clean,
        "A reference to the hidden root's backing device must be flagged"
    );
}

#[test]
fn test_verify_base_config_clean_scans_imported_module() {
    let fs = MockFilesystem::new();
    let hardware = std::path::PathBuf::from("/etc/nixos/hardware-configuration.nix");
    let module = std::path::PathBuf::from("/etc/nixos/modules/extra.nix");

    // hardware-configuration.nix is clean, but an imported module is dirty.
    <MockFilesystem as Filesystem>::write_file_content(
        &fs,
        &hardware,
        "{ config, pkgs, ... }: { }",
    )
    .unwrap();
    <MockFilesystem as Filesystem>::write_file_content(
        &fs,
        &module,
        "{ imports = [ ./nails/configuration.nix ]; }",
    )
    .unwrap();
    fs.mock_set_files_with_pattern("/etc/nixos", ".nix", &[&hardware, &module]);

    let is_clean = verify_base_config_clean(&fs, std::path::Path::new("/mnt/hidden")).unwrap();
    assert!(
        !is_clean,
        "A dirty imported module under /etc/nixos must be flagged"
    );
}

#[test]
fn test_verify_base_config_clean_skips_malformed_mountinfo_line() {
    let fs = MockFilesystem::new();
    let base_config = std::path::PathBuf::from("/etc/nixos/hardware-configuration.nix");

    <MockFilesystem as Filesystem>::write_file_content(
        &fs,
        &base_config,
        "{ swapDevices = [ { device = \"/dev/mapper/vault\"; } ]; }",
    )
    .unwrap();
    fs.mock_set_files_with_pattern("/etc/nixos", ".nix", &[&base_config]);

    // First line is malformed (no " - " separator); the second resolves the root.
    <MockFilesystem as Filesystem>::write_file_content(
        &fs,
        std::path::Path::new("/proc/self/mountinfo"),
        "garbage line without separator\n36 35 254:0 / /mnt/vault rw - ext4 /dev/mapper/vault rw\n",
    )
    .unwrap();

    let is_clean = verify_base_config_clean(&fs, std::path::Path::new("/mnt/vault")).unwrap();
    assert!(
        !is_clean,
        "A malformed mountinfo line must be skipped while a later valid line still resolves"
    );
}

#[test]
fn test_verify_base_config_clean_ignores_a_device_backing_another_mount() {
    let fs = MockFilesystem::new();
    let base_config = std::path::PathBuf::from("/etc/nixos/hardware-configuration.nix");

    <MockFilesystem as Filesystem>::write_file_content(
        &fs,
        &base_config,
        "{ swapDevices = [ { device = \"/dev/mapper/vault\"; } ]; }",
    )
    .unwrap();
    fs.mock_set_files_with_pattern("/etc/nixos", ".nix", &[&base_config]);
    <MockFilesystem as Filesystem>::write_file_content(
        &fs,
        std::path::Path::new("/proc/self/mountinfo"),
        &crate::kernel_fixtures::userns("mountinfo-hidden-root.txt"),
    )
    .unwrap();

    // In the captured scene /fixture/home is an overlay, not /dev/mapper/vault:
    // the device backs another mount, so it is no trace of this hidden root.
    let is_clean = verify_base_config_clean(&fs, std::path::Path::new("/fixture/home")).unwrap();
    assert!(
        is_clean,
        "A device that does not back the configured hidden root is not flagged"
    );
}

#[test]
fn test_verify_base_config_clean_allows_unrelated_filesystem_entry() {
    let fs = MockFilesystem::new();
    let base_config = std::path::PathBuf::from("/etc/nixos/hardware-configuration.nix");

    // A normal, non-hidden fileSystems entry must not be flagged.
    <MockFilesystem as Filesystem>::write_file_content(
        &fs,
        &base_config,
        "{ fileSystems.\"/\" = { device = \"/dev/sda1\"; fsType = \"ext4\"; }; }",
    )
    .unwrap();
    fs.mock_set_files_with_pattern("/etc/nixos", ".nix", &[&base_config]);

    let is_clean = verify_base_config_clean(&fs, std::path::Path::new("/mnt/vault")).unwrap();
    assert!(is_clean, "An unrelated fileSystems entry must stay clean");
}

const LIVE_HARDWARE: &str = "/etc/nixos/hardware-configuration.nix";
const LIVE_BASE: &str = "/etc/nixos/hardware-configuration.base.nix";

fn seed_live_hardware(fs: &MockFilesystem, content: &str) {
    fs.mock_set_path_exists(LIVE_HARDWARE, true);
    fs.mock_set_path_type(LIVE_HARDWARE, PathKind::File);
    <MockFilesystem as Filesystem>::write_file_content(
        fs,
        std::path::Path::new(LIVE_HARDWARE),
        content,
    )
    .unwrap();
}

fn read_live(fs: &MockFilesystem, path: &str) -> String {
    <MockFilesystem as Filesystem>::read_file_content(fs, std::path::Path::new(path)).unwrap()
}

/// The wrapper is identical regardless of the original's shape, and the original
/// is preserved verbatim in `hardware-configuration.base.nix`.
fn assert_wrapped(fs: &MockFilesystem, original: &str) {
    assert_eq!(
        read_live(fs, LIVE_HARDWARE),
        HARDWARE_WRAPPER,
        "hardware-configuration.nix must become the fixed wrapper"
    );
    assert!(
        contains_nails_import(&read_live(fs, LIVE_HARDWARE)),
        "wrapper must still import ./nails/configuration.nix"
    );
    assert_eq!(
        read_live(fs, LIVE_BASE),
        original,
        "original hardware-configuration.nix must be preserved verbatim as the base"
    );
}

#[test]
fn test_inject_import_block_wraps_config_with_imports() {
    let fs = MockFilesystem::new();
    let original = "{ config, pkgs, ... }: {\n  imports = [\n    ./sub.nix\n  ];\n}\n";
    seed_live_hardware(&fs, original);

    inject_import_block(&fs).unwrap();

    assert_wrapped(&fs, original);
}

#[test]
fn test_inject_import_block_wraps_config_without_imports() {
    let fs = MockFilesystem::new();
    let original = "{ config, pkgs, ... }: {\n  boot.loader.grub.enable = true;\n}\n";
    seed_live_hardware(&fs, original);

    inject_import_block(&fs).unwrap();

    assert_wrapped(&fs, original);
}

#[test]
fn test_inject_import_block_wraps_config_with_lib_optionals() {
    let fs = MockFilesystem::new();
    // A form that the old text-patcher could not handle safely.
    let original =
        "{ config, lib, ... }: {\n  imports = lib.optionals true [ ./foo.nix ] ++ [ ];\n}\n";
    seed_live_hardware(&fs, original);

    inject_import_block(&fs).unwrap();

    assert_wrapped(&fs, original);
}

#[test]
fn test_inject_import_block_second_run_is_noop() {
    let fs = MockFilesystem::new();
    let original = "{ config, pkgs, ... }: {\n  boot.loader.grub.enable = true;\n}\n";
    seed_live_hardware(&fs, original);

    inject_import_block(&fs).unwrap();
    assert_wrapped(&fs, original);

    // Second run must not rewrite the live file or clobber the preserved base.
    inject_import_block(&fs).unwrap();
    assert_wrapped(&fs, original);
}

#[test]
fn test_inject_import_block_skips_when_hardware_config_absent() {
    let fs = MockFilesystem::new();

    // Non-NixOS host: no hardware-configuration.nix at all.
    inject_import_block(&fs).unwrap();

    assert!(
        <MockFilesystem as Filesystem>::read_file_content(&fs, std::path::Path::new(LIVE_BASE))
            .is_err(),
        "no base file should be created when there is no hardware-configuration.nix"
    );
}

#[derive(Debug)]
struct ScriptedNixParser {
    failing: std::collections::HashSet<std::path::PathBuf>,
    parsed: std::sync::Mutex<Vec<std::path::PathBuf>>,
}

impl ScriptedNixParser {
    fn new(failing: &[&str]) -> Self {
        Self {
            failing: failing.iter().map(std::path::PathBuf::from).collect(),
            parsed: std::sync::Mutex::new(Vec::new()),
        }
    }
}

impl NixParser for ScriptedNixParser {
    fn parse_file(&self, path: &std::path::Path) -> std::result::Result<(), String> {
        self.parsed.lock().unwrap().push(path.to_path_buf());
        if self.failing.contains(path) {
            Err("syntax error, unexpected '='".to_string())
        } else {
            Ok(())
        }
    }
}

#[test]
fn test_parse_check_composed_config_skips_missing_files_and_passes() {
    let fs = MockFilesystem::new();
    let etc = std::path::PathBuf::from("/mnt/hidden/etc/nixos");
    let module = std::path::PathBuf::from("/mnt/hidden/config/nixos/configuration.nix");

    // Only the wrapper and the module exist; base.nix is absent.
    fs.mock_set_path_exists("/mnt/hidden/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_exists("/mnt/hidden/config/nixos/configuration.nix", true);

    let parser = ScriptedNixParser::new(&[]);
    let result = parse_check_composed_config(&parser, &fs, &etc, &module).unwrap();
    assert!(result.is_ok(), "no file fails to parse");

    let parsed = parser.parsed.lock().unwrap();
    assert_eq!(
        *parsed,
        vec![
            std::path::PathBuf::from("/mnt/hidden/etc/nixos/hardware-configuration.nix"),
            module,
        ],
        "only existing files are parsed, in composed order, base.nix skipped"
    );
}

#[test]
fn test_parse_check_composed_config_reports_first_syntax_error() {
    let fs = MockFilesystem::new();
    let etc = std::path::PathBuf::from("/mnt/hidden/etc/nixos");
    let module = std::path::PathBuf::from("/mnt/hidden/config/nixos/configuration.nix");

    fs.mock_set_path_exists("/mnt/hidden/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_exists(
        "/mnt/hidden/etc/nixos/hardware-configuration.base.nix",
        true,
    );
    fs.mock_set_path_exists("/mnt/hidden/config/nixos/configuration.nix", true);

    let parser = ScriptedNixParser::new(&["/mnt/hidden/etc/nixos/hardware-configuration.base.nix"]);
    let result = parse_check_composed_config(&parser, &fs, &etc, &module).unwrap();

    let message = result.expect_err("base file has a syntax error");
    assert!(
        message.contains("hardware-configuration.base.nix"),
        "error must name the offending file: {message}"
    );
    assert!(
        message.contains("syntax error"),
        "error must carry the parser message: {message}"
    );
}

#[test]
fn test_contains_nails_import_ignores_comment_only_references() {
    let content = "# ./nails/configuration.nix\n/* ./nails/configuration.nix */\n{ ... }: { }\n";

    assert!(!contains_nails_import(content));
}

#[test]
fn test_contains_nails_import_accepts_active_reference_after_comments() {
    let content = "# comment\n{ ... }: { imports = [ ./nails/configuration.nix ]; }\n";

    assert!(contains_nails_import(content));
}

#[test]
fn test_stage_hidden_config_symlink_creates_dir_and_symlink() {
    let fs = MockFilesystem::new();
    let hidden_path = std::path::PathBuf::from("/mnt/hidden");

    // Setup hidden config
    fs.mock_set_path_exists("/mnt/hidden/etc/nixos", true);
    fs.mock_set_path_type("/mnt/hidden/etc/nixos", PathKind::Dir);
    fs.mock_set_path_exists("/mnt", true);
    fs.mock_set_path_type("/mnt", PathKind::Dir);
    fs.mock_set_writable("/mnt", true);
    fs.mock_set_path_exists("/mnt/hidden", true);
    fs.mock_set_path_type("/mnt/hidden", PathKind::Dir);
    fs.mock_set_writable("/mnt/hidden", true);
    let hidden_config = hidden_path.join("config/nixos/configuration.nix");

    // Stage symlink
    stage_hidden_config_symlink(&fs, &hidden_path).unwrap();

    assert!(
        <MockFilesystem as Filesystem>::path_exists(&fs, &hidden_config).unwrap(),
        "hidden configuration should exist"
    );
    let generated = <MockFilesystem as Filesystem>::read_file_content(&fs, &hidden_config).unwrap();
    assert!(generated.contains("Hidden-session configuration"));
    assert_eq!(fs.mock_get_permissions(&hidden_config), Some(0o600));

    // Verify nails directory was created
    let nails_dir = hidden_path.join("etc/nixos/nails");
    assert!(
        <MockFilesystem as Filesystem>::path_exists(&fs, &nails_dir).unwrap(),
        "nails directory should exist"
    );
    assert_eq!(fs.mock_get_permissions(&nails_dir), Some(0o700));

    // Verify symlink was created
    let symlink_path = nails_dir.join("configuration.nix");
    assert!(
        <MockFilesystem as Filesystem>::path_exists(&fs, &symlink_path).unwrap(),
        "symlink should exist"
    );
}

#[test]
fn test_ensure_hidden_configuration_module_creates_minimal_module() {
    let fs = MockFilesystem::new();
    let hidden_path = std::path::PathBuf::from("/mnt/hidden");
    let hidden_root = hidden_path.clone();

    fs.mock_set_path_exists("/mnt", true);
    fs.mock_set_path_type("/mnt", PathKind::Dir);
    fs.mock_set_writable("/mnt", true);
    fs.mock_set_path_exists(hidden_root.to_str().unwrap(), true);
    fs.mock_set_path_type(hidden_root.to_str().unwrap(), PathKind::Dir);
    fs.mock_set_writable(hidden_root.to_str().unwrap(), true);

    ensure_hidden_configuration_module(&fs, &hidden_path).unwrap();

    let hidden_config = hidden_path.join("config/nixos/configuration.nix");
    let content = <MockFilesystem as Filesystem>::read_file_content(&fs, &hidden_config).unwrap();
    // The seed is a commented template: it documents the hidden-session knobs
    // without turning any of them on.
    assert!(content.contains("Hidden-session configuration"));
    assert!(content.contains("Storage=volatile"));
    assert!(content.starts_with("{ config, lib, pkgs, ... }"));
    assert_eq!(
        fs.mock_get_permissions(&hidden_path.join("config/nixos")),
        Some(0o700)
    );
    assert_eq!(fs.mock_get_permissions(&hidden_config), Some(0o600));
}

#[test]
fn test_ensure_hidden_configuration_module_preserves_existing_file() {
    let fs = MockFilesystem::new();
    let hidden_path = std::path::PathBuf::from("/mnt/hidden");
    let hidden_config = hidden_path.join("config/nixos/configuration.nix");

    fs.mock_set_path_exists("/mnt", true);
    fs.mock_set_path_type("/mnt", PathKind::Dir);
    fs.mock_set_writable("/mnt", true);
    fs.mock_set_path_exists("/mnt/hidden", true);
    fs.mock_set_path_type("/mnt/hidden", PathKind::Dir);
    fs.mock_set_writable("/mnt/hidden", true);
    fs.mock_set_path_exists("/mnt/hidden/config", true);
    fs.mock_set_path_type("/mnt/hidden/config", PathKind::Dir);
    fs.mock_set_writable("/mnt/hidden/config", true);
    fs.mock_set_path_exists("/mnt/hidden/config/nixos", true);
    fs.mock_set_path_type("/mnt/hidden/config/nixos", PathKind::Dir);
    fs.mock_set_writable("/mnt/hidden/config/nixos", true);

    fs.mock_set_path_exists("/mnt/hidden/config/nixos/configuration.nix", true);
    fs.mock_set_path_type("/mnt/hidden/config/nixos/configuration.nix", PathKind::File);
    <MockFilesystem as Filesystem>::write_file_content(
        &fs,
        &hidden_config,
        "{ pkgs, ... }: { environment.systemPackages = [ pkgs.jq ]; }",
    )
    .unwrap();

    ensure_hidden_configuration_module(&fs, &hidden_path).unwrap();

    let content = <MockFilesystem as Filesystem>::read_file_content(&fs, &hidden_config).unwrap();
    assert!(content.contains("pkgs.jq"));
    assert!(!content.contains("pkgs.ripgrep"));
    assert_eq!(fs.mock_get_permissions(&hidden_config), Some(0o600));
}

#[test]
fn test_ensure_hidden_configuration_module_errors_when_directory_creation_fails() {
    let fs = MockFilesystem::new();
    let hidden_path = std::path::PathBuf::from("/mnt/hidden");

    fs.mock_set_path_exists("/mnt", true);
    fs.mock_set_path_type("/mnt", PathKind::Dir);
    fs.mock_set_writable("/mnt", true);
    fs.mock_set_path_exists("/mnt/hidden", true);
    fs.mock_set_path_type("/mnt/hidden", PathKind::Dir);
    fs.mock_set_writable("/mnt/hidden", false);

    let err = ensure_hidden_configuration_module(&fs, &hidden_path).unwrap_err();
    assert!(
        err.to_string()
            .contains("Failed to create hidden config directory")
    );
}

#[test]
fn test_ensure_hidden_configuration_module_errors_when_write_fails() {
    let fs = MockFilesystem::new();
    let hidden_path = std::path::PathBuf::from("/mnt/hidden");
    let hidden_config = hidden_path.join("config/nixos/configuration.nix");

    fs.mock_set_path_exists("/mnt", true);
    fs.mock_set_path_type("/mnt", PathKind::Dir);
    fs.mock_set_writable("/mnt", true);
    fs.mock_set_path_exists("/mnt/hidden", true);
    fs.mock_set_path_type("/mnt/hidden", PathKind::Dir);
    fs.mock_set_writable("/mnt/hidden", true);
    fs.mock_set_path_exists("/mnt/hidden/config", true);
    fs.mock_set_path_type("/mnt/hidden/config", PathKind::Dir);
    fs.mock_set_writable("/mnt/hidden/config", true);
    fs.mock_set_path_exists("/mnt/hidden/config/nixos", true);
    fs.mock_set_path_type("/mnt/hidden/config/nixos", PathKind::Dir);
    fs.mock_set_writable("/mnt/hidden/config/nixos", true);
    fs.mock_set_write_should_fail(hidden_config.to_str().unwrap(), true);

    let err = ensure_hidden_configuration_module(&fs, &hidden_path).unwrap_err();
    assert!(
        err.to_string()
            .contains("Failed to auto-generate hidden configuration.nix")
    );
}

#[test]
fn test_ensure_hidden_configuration_module_errors_when_directory_permission_update_fails() {
    let fs = MockFilesystem::new();
    let hidden_path = std::path::PathBuf::from("/mnt/hidden");
    let config_dir = hidden_path.join("config/nixos");

    fs.mock_set_path_exists("/mnt", true);
    fs.mock_set_path_type("/mnt", PathKind::Dir);
    fs.mock_set_writable("/mnt", true);
    fs.mock_set_path_exists("/mnt/hidden", true);
    fs.mock_set_path_type("/mnt/hidden", PathKind::Dir);
    fs.mock_set_writable("/mnt/hidden", true);
    fs.mock_set_path_exists(config_dir.to_str().unwrap(), true);
    fs.mock_set_path_type(config_dir.to_str().unwrap(), PathKind::Dir);
    fs.mock_set_permissions_should_fail(config_dir.to_str().unwrap(), true);

    let err = ensure_hidden_configuration_module(&fs, &hidden_path).unwrap_err();
    assert!(
        err.to_string()
            .contains("Failed to set permissions on hidden config directory")
    );
}

#[test]
fn test_ensure_hidden_configuration_module_errors_when_existing_file_permission_update_fails() {
    let fs = MockFilesystem::new();
    let hidden_path = std::path::PathBuf::from("/mnt/hidden");
    let hidden_config = hidden_path.join("config/nixos/configuration.nix");

    fs.mock_set_path_exists("/mnt", true);
    fs.mock_set_path_type("/mnt", PathKind::Dir);
    fs.mock_set_writable("/mnt", true);
    fs.mock_set_path_exists("/mnt/hidden", true);
    fs.mock_set_path_type("/mnt/hidden", PathKind::Dir);
    fs.mock_set_writable("/mnt/hidden", true);
    fs.mock_set_path_exists("/mnt/hidden/config", true);
    fs.mock_set_path_type("/mnt/hidden/config", PathKind::Dir);
    fs.mock_set_writable("/mnt/hidden/config", true);
    fs.mock_set_path_exists("/mnt/hidden/config/nixos", true);
    fs.mock_set_path_type("/mnt/hidden/config/nixos", PathKind::Dir);
    fs.mock_set_writable("/mnt/hidden/config/nixos", true);
    fs.mock_set_path_exists(hidden_config.to_str().unwrap(), true);
    fs.mock_set_path_type(hidden_config.to_str().unwrap(), PathKind::File);
    fs.mock_set_file_content(hidden_config.to_str().unwrap(), "{ ... }: { }");
    fs.mock_set_permissions_should_fail(hidden_config.to_str().unwrap(), true);

    let err = ensure_hidden_configuration_module(&fs, &hidden_path).unwrap_err();
    assert!(
        err.to_string()
            .contains("Failed to set permissions on hidden configuration.nix")
    );
}

#[test]
fn test_ensure_hidden_hardware_configuration_bootstraps_from_base_config() {
    let fs = MockFilesystem::new();
    let hidden_path = std::path::PathBuf::from("/mnt/hidden");
    let base_hardware = std::path::PathBuf::from("/etc/nixos/hardware-configuration.nix");
    let hidden_hardware = hidden_path.join("etc/nixos/hardware-configuration.nix");

    fs.mock_set_path_exists("/etc", true);
    fs.mock_set_path_type("/etc", PathKind::Dir);
    fs.mock_set_writable("/etc", true);
    fs.mock_set_path_exists("/etc/nixos", true);
    fs.mock_set_path_type("/etc/nixos", PathKind::Dir);
    fs.mock_set_writable("/etc/nixos", true);
    fs.mock_set_path_exists(base_hardware.to_str().unwrap(), true);
    fs.mock_set_path_type(base_hardware.to_str().unwrap(), PathKind::File);
    fs.mock_set_file_content(
        base_hardware.to_str().unwrap(),
        "{ config, lib, pkgs, modulesPath, ... }:\n{\n  imports = [ (modulesPath + \"/installer/scan/not-detected.nix\") ];\n}\n",
    );

    fs.mock_set_path_exists("/mnt", true);
    fs.mock_set_path_type("/mnt", PathKind::Dir);
    fs.mock_set_writable("/mnt", true);
    fs.mock_set_path_exists(hidden_path.to_str().unwrap(), true);
    fs.mock_set_path_type(hidden_path.to_str().unwrap(), PathKind::Dir);
    fs.mock_set_writable(hidden_path.to_str().unwrap(), true);
    fs.mock_set_path_exists("/mnt/hidden/etc", true);
    fs.mock_set_path_type("/mnt/hidden/etc", PathKind::Dir);
    fs.mock_set_writable("/mnt/hidden/etc", true);
    fs.mock_set_path_exists("/mnt/hidden/etc/nixos", true);
    fs.mock_set_path_type("/mnt/hidden/etc/nixos", PathKind::Dir);
    fs.mock_set_writable("/mnt/hidden/etc/nixos", true);

    ensure_hidden_hardware_configuration(&fs, &hidden_path, &base_hardware).unwrap();

    let hidden_base = hidden_path.join("etc/nixos/hardware-configuration.base.nix");
    let content = <MockFilesystem as Filesystem>::read_file_content(&fs, &hidden_hardware).unwrap();
    assert_eq!(
        content, HARDWARE_WRAPPER,
        "hidden hardware-configuration.nix must be the fixed wrapper"
    );
    let base = <MockFilesystem as Filesystem>::read_file_content(&fs, &hidden_base).unwrap();
    assert!(
        base.contains("modulesPath + \"/installer/scan/not-detected.nix\""),
        "the decoy hardware config must be preserved verbatim as the base"
    );
    assert_eq!(
        fs.mock_get_permissions(&hidden_path.join("etc/nixos")),
        Some(0o700)
    );
    assert_eq!(fs.mock_get_permissions(&hidden_hardware), Some(0o600));
    assert_eq!(fs.mock_get_permissions(&hidden_base), Some(0o600));
}

/// Build a MockFilesystem wired for `ensure_hidden_hardware_configuration` with
/// the given decoy hardware-configuration.nix content, and return the staged
/// base config text.
fn seeded_hidden_base(decoy_hardware: &str) -> String {
    let fs = MockFilesystem::new();
    let hidden_path = std::path::PathBuf::from("/mnt/hidden");
    let base_hardware = std::path::PathBuf::from("/etc/nixos/hardware-configuration.nix");

    fs.mock_set_path_exists("/etc", true);
    fs.mock_set_path_type("/etc", PathKind::Dir);
    fs.mock_set_writable("/etc", true);
    fs.mock_set_path_exists("/etc/nixos", true);
    fs.mock_set_path_type("/etc/nixos", PathKind::Dir);
    fs.mock_set_writable("/etc/nixos", true);
    fs.mock_set_path_exists(base_hardware.to_str().unwrap(), true);
    fs.mock_set_path_type(base_hardware.to_str().unwrap(), PathKind::File);
    fs.mock_set_file_content(base_hardware.to_str().unwrap(), decoy_hardware);

    fs.mock_set_path_exists("/mnt", true);
    fs.mock_set_path_type("/mnt", PathKind::Dir);
    fs.mock_set_writable("/mnt", true);
    fs.mock_set_path_exists(hidden_path.to_str().unwrap(), true);
    fs.mock_set_path_type(hidden_path.to_str().unwrap(), PathKind::Dir);
    fs.mock_set_writable(hidden_path.to_str().unwrap(), true);
    fs.mock_set_path_exists("/mnt/hidden/etc", true);
    fs.mock_set_path_type("/mnt/hidden/etc", PathKind::Dir);
    fs.mock_set_writable("/mnt/hidden/etc", true);
    fs.mock_set_path_exists("/mnt/hidden/etc/nixos", true);
    fs.mock_set_path_type("/mnt/hidden/etc/nixos", PathKind::Dir);
    fs.mock_set_writable("/mnt/hidden/etc/nixos", true);

    ensure_hidden_hardware_configuration(&fs, &hidden_path, &base_hardware).unwrap();

    let hidden_base = hidden_path.join("etc/nixos/hardware-configuration.base.nix");
    <MockFilesystem as Filesystem>::read_file_content(&fs, &hidden_base).unwrap()
}

/// Assert the generated base config contains no active (uncommented) swapDevices
/// assignment with a device in it.
fn assert_no_active_swap(base: &str) {
    for line in base.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("swapDevices") {
            // Only an empty list may remain uncommented.
            let bracket = line.find('[').and_then(|o| line.rfind(']').map(|c| (o, c)));
            if let Some((o, c)) = bracket {
                assert!(
                    c > o && line[o + 1..c].trim().is_empty(),
                    "active swapDevices leaked into the hidden config: {line}"
                );
            } else {
                panic!("active swapDevices leaked into the hidden config: {line}");
            }
        }
        assert!(
            !trimmed.starts_with("device = \"/dev/disk/by-uuid")
                || line.trim_start().starts_with('#'),
            "a swap device path leaked uncommented into the hidden config: {line}"
        );
    }
}

#[test]
fn test_seeded_hidden_config_strips_single_line_swap_devices() {
    let decoy = "{ config, lib, pkgs, modulesPath, ... }:\n{\n  \
                 imports = [ (modulesPath + \"/installer/scan/not-detected.nix\") ];\n  \
                 swapDevices = [ { device = \"/dev/disk/by-uuid/dead-beef\"; } ];\n}\n";
    let base = seeded_hidden_base(decoy);
    assert_no_active_swap(&base);
    assert!(
        base.contains("# ") && base.contains("swapDevices"),
        "swapDevices must be preserved as a comment: {base}"
    );
}

#[test]
fn test_seeded_hidden_config_strips_multi_line_swap_devices() {
    let decoy = "{ config, lib, pkgs, modulesPath, ... }:\n{\n  \
                 imports = [ (modulesPath + \"/installer/scan/not-detected.nix\") ];\n  \
                 swapDevices =\n    [ { device = \"/dev/disk/by-uuid/dead-beef\"; }\n    ];\n}\n";
    let base = seeded_hidden_base(decoy);
    assert_no_active_swap(&base);
    // Every line of the multi-line block must be commented.
    for line in base.lines() {
        if line.contains("/dev/disk/by-uuid/dead-beef") {
            assert!(
                line.trim_start().starts_with('#'),
                "multi-line swap device must be commented: {line}"
            );
        }
    }
}

#[test]
fn test_seeded_hidden_config_keeps_empty_swap_devices() {
    let decoy = "{ config, lib, pkgs, modulesPath, ... }:\n{\n  \
                 imports = [ (modulesPath + \"/installer/scan/not-detected.nix\") ];\n  \
                 swapDevices = [ ];\n}\n";
    let base = seeded_hidden_base(decoy);
    assert_no_active_swap(&base);
    assert!(
        base.contains("swapDevices = [ ];"),
        "an already-empty swapDevices must be preserved verbatim: {base}"
    );
}

#[test]
fn test_seeded_hidden_config_comments_resume_device() {
    let decoy = "{ config, lib, pkgs, modulesPath, ... }:\n{\n  \
                 boot.resumeDevice = \"/dev/disk/by-uuid/dead-beef\";\n}\n";
    let base = seeded_hidden_base(decoy);
    for line in base.lines() {
        if line.contains("resumeDevice") {
            assert!(
                line.trim_start().starts_with('#'),
                "resumeDevice must be commented out: {line}"
            );
        }
    }
}

#[test]
fn test_ensure_hidden_hardware_configuration_updates_existing_hidden_file() {
    let fs = MockFilesystem::new();
    let hidden_path = std::path::PathBuf::from("/mnt/hidden");
    let base_hardware = std::path::PathBuf::from("/etc/nixos/hardware-configuration.nix");
    let hidden_hardware = hidden_path.join("etc/nixos/hardware-configuration.nix");

    fs.mock_set_path_exists("/mnt", true);
    fs.mock_set_path_type("/mnt", PathKind::Dir);
    fs.mock_set_writable("/mnt", true);
    fs.mock_set_path_exists(hidden_path.to_str().unwrap(), true);
    fs.mock_set_path_type(hidden_path.to_str().unwrap(), PathKind::Dir);
    fs.mock_set_writable(hidden_path.to_str().unwrap(), true);
    fs.mock_set_path_exists("/mnt/hidden/etc", true);
    fs.mock_set_path_type("/mnt/hidden/etc", PathKind::Dir);
    fs.mock_set_writable("/mnt/hidden/etc", true);
    fs.mock_set_path_exists("/mnt/hidden/etc/nixos", true);
    fs.mock_set_path_type("/mnt/hidden/etc/nixos", PathKind::Dir);
    fs.mock_set_writable("/mnt/hidden/etc/nixos", true);
    fs.mock_set_path_exists(hidden_hardware.to_str().unwrap(), true);
    fs.mock_set_path_type(hidden_hardware.to_str().unwrap(), PathKind::File);
    fs.mock_set_file_content(
        hidden_hardware.to_str().unwrap(),
        "{ config, lib, pkgs, ... }:\n{\n  networking.hostName = \"hidden\";\n}\n",
    );
    fs.mock_set_path_exists(base_hardware.to_str().unwrap(), true);
    fs.mock_set_path_type(base_hardware.to_str().unwrap(), PathKind::File);
    fs.mock_set_file_content(base_hardware.to_str().unwrap(), "{ }: { }\n");

    ensure_hidden_hardware_configuration(&fs, &hidden_path, &base_hardware).unwrap();

    let hidden_base = hidden_path.join("etc/nixos/hardware-configuration.base.nix");
    let content = <MockFilesystem as Filesystem>::read_file_content(&fs, &hidden_hardware).unwrap();
    assert_eq!(
        content, HARDWARE_WRAPPER,
        "an existing hidden config is migrated to the wrapper"
    );
    let base = <MockFilesystem as Filesystem>::read_file_content(&fs, &hidden_base).unwrap();
    assert!(
        base.contains("networking.hostName = \"hidden\";"),
        "the previous hidden config is preserved verbatim as the base"
    );
    assert_eq!(fs.mock_get_permissions(&hidden_hardware), Some(0o600));
    assert_eq!(fs.mock_get_permissions(&hidden_base), Some(0o600));
}

#[test]
fn test_ensure_hidden_hardware_configuration_errors_when_base_read_fails() {
    let fs = MockFilesystem::new();
    let hidden_path = std::path::PathBuf::from("/mnt/hidden");
    let base_hardware = std::path::PathBuf::from("/etc/nixos/hardware-configuration.nix");

    fs.mock_set_path_exists("/mnt", true);
    fs.mock_set_path_type("/mnt", PathKind::Dir);
    fs.mock_set_writable("/mnt", true);
    fs.mock_set_path_exists(hidden_path.to_str().unwrap(), true);
    fs.mock_set_path_type(hidden_path.to_str().unwrap(), PathKind::Dir);
    fs.mock_set_writable(hidden_path.to_str().unwrap(), true);
    fs.mock_set_path_exists("/mnt/hidden/etc", true);
    fs.mock_set_path_type("/mnt/hidden/etc", PathKind::Dir);
    fs.mock_set_writable("/mnt/hidden/etc", true);
    fs.mock_set_path_exists("/mnt/hidden/etc/nixos", true);
    fs.mock_set_path_type("/mnt/hidden/etc/nixos", PathKind::Dir);
    fs.mock_set_writable("/mnt/hidden/etc/nixos", true);
    fs.mock_set_path_exists(base_hardware.to_str().unwrap(), true);
    fs.mock_set_path_type(base_hardware.to_str().unwrap(), PathKind::File);

    let err = ensure_hidden_hardware_configuration(&fs, &hidden_path, &base_hardware).unwrap_err();
    assert!(
        err.to_string()
            .contains("Failed to bootstrap hidden hardware-configuration.nix")
    );
}

#[test]
fn test_ensure_hidden_hardware_configuration_errors_when_directory_creation_fails() {
    let fs = MockFilesystem::new();
    let hidden_path = std::path::PathBuf::from("/mnt/hidden");
    let base_hardware = std::path::PathBuf::from("/etc/nixos/hardware-configuration.nix");

    fs.mock_set_path_exists("/mnt", true);
    fs.mock_set_path_type("/mnt", PathKind::Dir);
    fs.mock_set_writable("/mnt", true);
    fs.mock_set_path_exists(hidden_path.to_str().unwrap(), true);
    fs.mock_set_path_type(hidden_path.to_str().unwrap(), PathKind::Dir);
    fs.mock_set_writable(hidden_path.to_str().unwrap(), false);

    let err = ensure_hidden_hardware_configuration(&fs, &hidden_path, &base_hardware).unwrap_err();
    assert!(
        err.to_string()
            .contains("Failed to create hidden etc/nixos directory")
    );
}

#[test]
fn test_ensure_hidden_hardware_configuration_errors_when_directory_permission_update_fails() {
    let fs = MockFilesystem::new();
    let hidden_path = std::path::PathBuf::from("/mnt/hidden");
    let base_hardware = std::path::PathBuf::from("/etc/nixos/hardware-configuration.nix");
    let hidden_etc_nixos = hidden_path.join("etc/nixos");

    fs.mock_set_path_exists("/mnt", true);
    fs.mock_set_path_type("/mnt", PathKind::Dir);
    fs.mock_set_writable("/mnt", true);
    fs.mock_set_path_exists(hidden_path.to_str().unwrap(), true);
    fs.mock_set_path_type(hidden_path.to_str().unwrap(), PathKind::Dir);
    fs.mock_set_writable(hidden_path.to_str().unwrap(), true);
    fs.mock_set_path_exists(hidden_etc_nixos.to_str().unwrap(), true);
    fs.mock_set_path_type(hidden_etc_nixos.to_str().unwrap(), PathKind::Dir);
    fs.mock_set_permissions_should_fail(hidden_etc_nixos.to_str().unwrap(), true);

    let err = ensure_hidden_hardware_configuration(&fs, &hidden_path, &base_hardware).unwrap_err();
    assert!(
        err.to_string()
            .contains("Failed to set permissions on hidden etc/nixos directory")
    );
}

#[test]
fn test_ensure_hidden_hardware_configuration_errors_when_existing_file_permission_update_fails() {
    let fs = MockFilesystem::new();
    let hidden_path = std::path::PathBuf::from("/mnt/hidden");
    let base_hardware = std::path::PathBuf::from("/etc/nixos/hardware-configuration.nix");
    let hidden_hardware = hidden_path.join("etc/nixos/hardware-configuration.nix");

    fs.mock_set_path_exists("/mnt", true);
    fs.mock_set_path_type("/mnt", PathKind::Dir);
    fs.mock_set_writable("/mnt", true);
    fs.mock_set_path_exists(hidden_path.to_str().unwrap(), true);
    fs.mock_set_path_type(hidden_path.to_str().unwrap(), PathKind::Dir);
    fs.mock_set_writable(hidden_path.to_str().unwrap(), true);
    fs.mock_set_path_exists("/mnt/hidden/etc", true);
    fs.mock_set_path_type("/mnt/hidden/etc", PathKind::Dir);
    fs.mock_set_writable("/mnt/hidden/etc", true);
    fs.mock_set_path_exists("/mnt/hidden/etc/nixos", true);
    fs.mock_set_path_type("/mnt/hidden/etc/nixos", PathKind::Dir);
    fs.mock_set_writable("/mnt/hidden/etc/nixos", true);
    fs.mock_set_path_exists(hidden_hardware.to_str().unwrap(), true);
    fs.mock_set_path_type(hidden_hardware.to_str().unwrap(), PathKind::File);
    fs.mock_set_file_content(
        hidden_hardware.to_str().unwrap(),
        "{ config, lib, pkgs, ... }:\n{\n  imports = [ ./nails/configuration.nix ];\n}\n",
    );
    fs.mock_set_path_exists(base_hardware.to_str().unwrap(), true);
    fs.mock_set_path_type(base_hardware.to_str().unwrap(), PathKind::File);
    fs.mock_set_file_content(base_hardware.to_str().unwrap(), "{ }: { }\n");
    fs.mock_set_permissions_should_fail(hidden_hardware.to_str().unwrap(), true);

    let err = ensure_hidden_hardware_configuration(&fs, &hidden_path, &base_hardware).unwrap_err();
    assert!(
        err.to_string()
            .contains("Failed to set permissions on hidden hardware-configuration.nix")
    );
}

#[test]
fn test_ensure_hidden_hardware_configuration_errors_when_write_fails() {
    let fs = MockFilesystem::new();
    let hidden_path = std::path::PathBuf::from("/mnt/hidden");
    let base_hardware = std::path::PathBuf::from("/etc/nixos/hardware-configuration.nix");
    let hidden_hardware = hidden_path.join("etc/nixos/hardware-configuration.nix");

    fs.mock_set_path_exists("/mnt", true);
    fs.mock_set_path_type("/mnt", PathKind::Dir);
    fs.mock_set_writable("/mnt", true);
    fs.mock_set_path_exists(hidden_path.to_str().unwrap(), true);
    fs.mock_set_path_type(hidden_path.to_str().unwrap(), PathKind::Dir);
    fs.mock_set_writable(hidden_path.to_str().unwrap(), true);
    fs.mock_set_path_exists("/mnt/hidden/etc", true);
    fs.mock_set_path_type("/mnt/hidden/etc", PathKind::Dir);
    fs.mock_set_writable("/mnt/hidden/etc", true);
    fs.mock_set_path_exists("/mnt/hidden/etc/nixos", true);
    fs.mock_set_path_type("/mnt/hidden/etc/nixos", PathKind::Dir);
    fs.mock_set_writable("/mnt/hidden/etc/nixos", true);
    fs.mock_set_path_exists(hidden_hardware.to_str().unwrap(), true);
    fs.mock_set_path_type(hidden_hardware.to_str().unwrap(), PathKind::File);
    fs.mock_set_file_content(hidden_hardware.to_str().unwrap(), "{ }: { }\n");
    fs.mock_set_write_should_fail(hidden_hardware.to_str().unwrap(), true);

    let err = ensure_hidden_hardware_configuration(&fs, &hidden_path, &base_hardware).unwrap_err();
    assert!(
        err.to_string()
            .contains("Failed to stage hidden hardware-configuration wrapper"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_stage_hidden_config_symlink_is_idempotent_for_existing_correct_symlink() {
    let fs = MockFilesystem::new();
    let hidden_path = std::path::PathBuf::from("/mnt/hidden");
    let nails_dir = hidden_path.join("etc/nixos/nails");
    let hidden_config = hidden_path.join("config/nixos/configuration.nix");
    let symlink_path = nails_dir.join("configuration.nix");

    fs.mock_set_path_exists("/mnt", true);
    fs.mock_set_path_type("/mnt", PathKind::Dir);
    fs.mock_set_writable("/mnt", true);
    fs.mock_set_path_exists("/mnt/hidden", true);
    fs.mock_set_path_type("/mnt/hidden", PathKind::Dir);
    fs.mock_set_writable("/mnt/hidden", true);
    fs.mock_set_path_exists("/mnt/hidden/etc", true);
    fs.mock_set_path_type("/mnt/hidden/etc", PathKind::Dir);
    fs.mock_set_writable("/mnt/hidden/etc", true);
    fs.mock_set_path_exists("/mnt/hidden/etc/nixos", true);
    fs.mock_set_path_type("/mnt/hidden/etc/nixos", PathKind::Dir);
    fs.mock_set_writable("/mnt/hidden/etc/nixos", true);
    fs.mock_set_path_exists("/mnt/hidden/etc/nixos/nails", true);
    fs.mock_set_path_type("/mnt/hidden/etc/nixos/nails", PathKind::Dir);
    fs.mock_set_writable("/mnt/hidden/etc/nixos/nails", true);
    fs.mock_set_path_exists("/mnt/hidden/config", true);
    fs.mock_set_path_type("/mnt/hidden/config", PathKind::Dir);
    fs.mock_set_writable("/mnt/hidden/config", true);
    fs.mock_set_path_exists("/mnt/hidden/config/nixos", true);
    fs.mock_set_path_type("/mnt/hidden/config/nixos", PathKind::Dir);
    fs.mock_set_writable("/mnt/hidden/config/nixos", true);
    fs.mock_set_path_exists(hidden_config.to_str().unwrap(), true);
    fs.mock_set_path_type(hidden_config.to_str().unwrap(), PathKind::File);
    fs.mock_set_file_content(hidden_config.to_str().unwrap(), "{ ... }: { }");
    <MockFilesystem as Filesystem>::create_symlink(&fs, &hidden_config, &symlink_path).unwrap();

    stage_hidden_config_symlink(&fs, &hidden_path).unwrap();

    assert_eq!(
        fs.mock_get_symlink_target(&symlink_path),
        Some(hidden_config)
    );
    assert_eq!(fs.mock_get_permissions(&nails_dir), Some(0o700));
}

#[test]
fn test_stage_hidden_config_symlink_errors_for_conflicting_existing_symlink() {
    let fs = MockFilesystem::new();
    let hidden_path = std::path::PathBuf::from("/mnt/hidden");
    let nails_dir = hidden_path.join("etc/nixos/nails");
    let hidden_config = hidden_path.join("config/nixos/configuration.nix");
    let symlink_path = nails_dir.join("configuration.nix");

    fs.mock_set_path_exists("/mnt", true);
    fs.mock_set_path_type("/mnt", PathKind::Dir);
    fs.mock_set_writable("/mnt", true);
    fs.mock_set_path_exists("/mnt/hidden", true);
    fs.mock_set_path_type("/mnt/hidden", PathKind::Dir);
    fs.mock_set_writable("/mnt/hidden", true);
    fs.mock_set_path_exists("/mnt/hidden/etc", true);
    fs.mock_set_path_type("/mnt/hidden/etc", PathKind::Dir);
    fs.mock_set_writable("/mnt/hidden/etc", true);
    fs.mock_set_path_exists("/mnt/hidden/etc/nixos", true);
    fs.mock_set_path_type("/mnt/hidden/etc/nixos", PathKind::Dir);
    fs.mock_set_writable("/mnt/hidden/etc/nixos", true);
    fs.mock_set_path_exists("/mnt/hidden/etc/nixos/nails", true);
    fs.mock_set_path_type("/mnt/hidden/etc/nixos/nails", PathKind::Dir);
    fs.mock_set_writable("/mnt/hidden/etc/nixos/nails", true);
    fs.mock_set_path_exists("/mnt/hidden/config", true);
    fs.mock_set_path_type("/mnt/hidden/config", PathKind::Dir);
    fs.mock_set_writable("/mnt/hidden/config", true);
    fs.mock_set_path_exists("/mnt/hidden/config/nixos", true);
    fs.mock_set_path_type("/mnt/hidden/config/nixos", PathKind::Dir);
    fs.mock_set_writable("/mnt/hidden/config/nixos", true);
    fs.mock_set_path_exists(hidden_config.to_str().unwrap(), true);
    fs.mock_set_path_type(hidden_config.to_str().unwrap(), PathKind::File);
    fs.mock_set_file_content(hidden_config.to_str().unwrap(), "{ ... }: { }");
    <MockFilesystem as Filesystem>::create_symlink(
        &fs,
        &std::path::PathBuf::from("/wrong/target.nix"),
        &symlink_path,
    )
    .unwrap();

    let err = stage_hidden_config_symlink(&fs, &hidden_path).unwrap_err();
    assert!(err.to_string().contains("Failed to create symlink"));
}

#[test]
fn test_stage_hidden_config_symlink_errors_when_nails_directory_permission_update_fails() {
    let fs = MockFilesystem::new();
    let hidden_path = std::path::PathBuf::from("/mnt/hidden");
    let nails_dir = hidden_path.join("etc/nixos/nails");
    let hidden_config = hidden_path.join("config/nixos/configuration.nix");

    fs.mock_set_path_exists("/mnt", true);
    fs.mock_set_path_type("/mnt", PathKind::Dir);
    fs.mock_set_writable("/mnt", true);
    fs.mock_set_path_exists("/mnt/hidden", true);
    fs.mock_set_path_type("/mnt/hidden", PathKind::Dir);
    fs.mock_set_writable("/mnt/hidden", true);
    fs.mock_set_path_exists("/mnt/hidden/etc", true);
    fs.mock_set_path_type("/mnt/hidden/etc", PathKind::Dir);
    fs.mock_set_writable("/mnt/hidden/etc", true);
    fs.mock_set_path_exists("/mnt/hidden/etc/nixos", true);
    fs.mock_set_path_type("/mnt/hidden/etc/nixos", PathKind::Dir);
    fs.mock_set_writable("/mnt/hidden/etc/nixos", true);
    fs.mock_set_path_exists(nails_dir.to_str().unwrap(), true);
    fs.mock_set_path_type(nails_dir.to_str().unwrap(), PathKind::Dir);
    fs.mock_set_writable(nails_dir.to_str().unwrap(), true);
    fs.mock_set_path_exists("/mnt/hidden/config", true);
    fs.mock_set_path_type("/mnt/hidden/config", PathKind::Dir);
    fs.mock_set_writable("/mnt/hidden/config", true);
    fs.mock_set_path_exists("/mnt/hidden/config/nixos", true);
    fs.mock_set_path_type("/mnt/hidden/config/nixos", PathKind::Dir);
    fs.mock_set_writable("/mnt/hidden/config/nixos", true);
    fs.mock_set_path_exists(hidden_config.to_str().unwrap(), true);
    fs.mock_set_path_type(hidden_config.to_str().unwrap(), PathKind::File);
    fs.mock_set_file_content(hidden_config.to_str().unwrap(), "{ ... }: { }\n");
    fs.mock_set_permissions_should_fail(nails_dir.to_str().unwrap(), true);

    let err = stage_hidden_config_symlink(&fs, &hidden_path).unwrap_err();
    assert!(
        err.to_string()
            .contains("Failed to set permissions on hidden nails config directory")
    );
}

#[test]
fn test_ensure_hidden_configuration_module_real_filesystem_preserves_existing_permissions() {
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_path = temp_dir.path();
    let config_dir = hidden_path.join("config/nixos");
    let hidden_config = config_dir.join("configuration.nix");

    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::write(
        &hidden_config,
        "{ pkgs, ... }: { environment.systemPackages = [ pkgs.jq ]; }",
    )
    .unwrap();
    std::fs::set_permissions(&config_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::set_permissions(&hidden_config, std::fs::Permissions::from_mode(0o644)).unwrap();

    ensure_hidden_configuration_module(&crate::RealFilesystem, hidden_path).unwrap();

    let mode_dir = std::fs::metadata(&config_dir).unwrap().permissions().mode() & 0o777;
    let mode_file = std::fs::metadata(&hidden_config)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    let content = std::fs::read_to_string(&hidden_config).unwrap();

    assert_eq!(mode_dir, 0o700);
    assert_eq!(mode_file, 0o600);
    assert!(content.contains("pkgs.jq"));
    assert!(!content.contains("pkgs.ripgrep"));
}

#[test]
fn test_ensure_hidden_hardware_configuration_real_filesystem_bootstraps_permissions_and_import() {
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_path = temp_dir.path().join("hidden");
    let base_dir = temp_dir.path().join("base");
    let base_hardware = base_dir.join("hardware-configuration.nix");
    let hidden_etc_nixos = hidden_path.join("etc/nixos");
    let hidden_hardware = hidden_etc_nixos.join("hardware-configuration.nix");

    std::fs::create_dir_all(&base_dir).unwrap();
    std::fs::create_dir_all(&hidden_etc_nixos).unwrap();
    std::fs::write(
        &base_hardware,
        "{ config, lib, pkgs, modulesPath, ... }:\n{\n  imports = [ (modulesPath + \"/installer/scan/not-detected.nix\") ];\n}\n",
    )
    .unwrap();
    std::fs::set_permissions(&hidden_etc_nixos, std::fs::Permissions::from_mode(0o755)).unwrap();

    ensure_hidden_hardware_configuration(&crate::RealFilesystem, &hidden_path, &base_hardware)
        .unwrap();

    let hidden_base = hidden_etc_nixos.join("hardware-configuration.base.nix");
    let content = std::fs::read_to_string(&hidden_hardware).unwrap();
    let base_content = std::fs::read_to_string(&hidden_base).unwrap();
    let dir_mode = std::fs::metadata(&hidden_etc_nixos)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    let file_mode = std::fs::metadata(&hidden_hardware)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    let base_mode = std::fs::metadata(&hidden_base)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;

    assert_eq!(content, HARDWARE_WRAPPER);
    assert!(content.contains("./nails/configuration.nix"));
    assert!(base_content.contains("modulesPath + \"/installer/scan/not-detected.nix\""));
    assert_eq!(dir_mode, 0o700);
    assert_eq!(file_mode, 0o600);
    assert_eq!(base_mode, 0o600);
}

#[test]
fn test_stage_hidden_config_symlink_real_filesystem_creates_expected_symlink() {
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_path = temp_dir.path();
    let etc_nixos = hidden_path.join("etc/nixos");
    std::fs::create_dir_all(&etc_nixos).unwrap();

    stage_hidden_config_symlink(&crate::RealFilesystem, hidden_path).unwrap();

    let nails_dir = hidden_path.join("etc/nixos/nails");
    let symlink_path = nails_dir.join("configuration.nix");
    let hidden_config = hidden_path.join("config/nixos/configuration.nix");

    let link_target = std::fs::read_link(&symlink_path).unwrap();
    let nails_mode = std::fs::metadata(&nails_dir).unwrap().permissions().mode() & 0o777;
    let config_mode = std::fs::metadata(&hidden_config)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    let config_content = std::fs::read_to_string(&hidden_config).unwrap();

    assert_eq!(link_target, hidden_config);
    assert_eq!(nails_mode, 0o700);
    assert_eq!(config_mode, 0o600);
    assert!(config_content.contains("Hidden-session configuration"));
}

#[test]
fn generated_hidden_module_force_disables_auto_upgrade() {
    // The hidden module must switch the decoy's automatic upgrade off
    // unconditionally: an unattended rebuild rewrites the decoy profile and can
    // touch EFI NVRAM while the hidden session is active. It is an active
    // setting, not a commented template line.
    assert!(
        AUTO_GENERATED_HIDDEN_CONFIGURATION
            .contains("system.autoUpgrade.enable = lib.mkForce false;"),
        "hidden module must force-disable system.autoUpgrade"
    );
    let active_line = AUTO_GENERATED_HIDDEN_CONFIGURATION
        .lines()
        .find(|line| line.contains("system.autoUpgrade.enable"))
        .expect("autoUpgrade line present");
    assert!(
        !active_line.trim_start().starts_with('#'),
        "the autoUpgrade force-disable must be active, not commented: {active_line:?}"
    );
}

#[test]
fn generated_hidden_module_keeps_shell_history_in_memory_only() {
    // Hidden-session shells keep no history file: an active setting, not a
    // commented template line, for bash/zsh and for fish.
    for needle in ["unset HISTFILE", "set -g fish_history \"\""] {
        let line = AUTO_GENERATED_HIDDEN_CONFIGURATION
            .lines()
            .find(|line| line.contains(needle))
            .unwrap_or_else(|| panic!("{needle} missing from the hidden module"));
        assert!(
            !line.trim_start().starts_with('#'),
            "{line:?} must be active"
        );
    }
    assert!(!AUTO_GENERATED_HIDDEN_CONFIGURATION.contains("HISTSIZE=0"));
}
