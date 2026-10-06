// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests for NixOS builder
//!
//! Unit tests using a mock command executor so no real NixOS system is needed.

use super::*;
use crate::error::Result;
use std::collections::VecDeque;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

type NixCallLog = Arc<Mutex<Vec<Vec<String>>>>;
type ClearNixPathLog = Arc<Mutex<Vec<bool>>>;

/// Mock command executor for testing
struct MockCommandExecutor {
    /// Whether command should succeed
    should_succeed: bool,
    /// Stdout to return
    stdout: String,
    /// Stderr to return
    stderr: String,
}

impl MockCommandExecutor {
    fn success() -> Self {
        Self {
            should_succeed: true,
            stdout: String::from("nixos-rebuild output here"),
            stderr: String::new(),
        }
    }

    #[allow(dead_code)]
    fn failure(stderr: String) -> Self {
        Self {
            should_succeed: false,
            stdout: String::new(),
            stderr,
        }
    }
}

impl CommandExecutorTrait for MockCommandExecutor {
    fn execute_nixos_rebuild(
        &self,
        _args: &[&str],
        _clear_nix_path: bool,
    ) -> Result<(bool, String, String)> {
        Ok((
            self.should_succeed,
            self.stdout.clone(),
            self.stderr.clone(),
        ))
    }

    fn execute_nix(&self, _args: &[&str], _clear_nix_path: bool) -> Result<(bool, String, String)> {
        Ok((
            self.should_succeed,
            self.stdout.clone(),
            self.stderr.clone(),
        ))
    }

    fn execute_switch_to_configuration(
        &self,
        _script_path: &std::path::Path,
        _action: SwitchAction,
    ) -> Result<(bool, String, String)> {
        // For build tests, we don't actually call switch-to-configuration
        // Return success by default
        Ok((true, String::new(), String::new()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RecordedCall {
    NixosRebuild {
        args: Vec<String>,
    },
    SwitchToConfiguration {
        script_path: PathBuf,
        args: Vec<String>,
    },
}

struct RecordingCommandExecutor {
    rebuild_results: Mutex<VecDeque<Result<(bool, String, String)>>>,
    switch_results: Mutex<VecDeque<Result<(bool, String, String)>>>,
    calls: Arc<Mutex<Vec<RecordedCall>>>,
}

impl RecordingCommandExecutor {
    fn new(
        rebuild_results: Vec<Result<(bool, String, String)>>,
        switch_results: Vec<Result<(bool, String, String)>>,
    ) -> Self {
        Self {
            rebuild_results: Mutex::new(rebuild_results.into()),
            switch_results: Mutex::new(switch_results.into()),
            calls: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn with_call_log(
        rebuild_results: Vec<Result<(bool, String, String)>>,
        switch_results: Vec<Result<(bool, String, String)>>,
    ) -> (Self, Arc<Mutex<Vec<RecordedCall>>>) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                rebuild_results: Mutex::new(rebuild_results.into()),
                switch_results: Mutex::new(switch_results.into()),
                calls: Arc::clone(&calls),
            },
            calls,
        )
    }
}

impl CommandExecutorTrait for RecordingCommandExecutor {
    fn execute_nixos_rebuild(
        &self,
        args: &[&str],
        _clear_nix_path: bool,
    ) -> Result<(bool, String, String)> {
        self.calls.lock().unwrap().push(RecordedCall::NixosRebuild {
            args: args.iter().map(|arg| arg.to_string()).collect(),
        });
        self.rebuild_results
            .lock()
            .unwrap()
            .pop_front()
            .expect("missing mocked nixos-rebuild result")
    }

    fn execute_nix(&self, args: &[&str], _clear_nix_path: bool) -> Result<(bool, String, String)> {
        self.calls.lock().unwrap().push(RecordedCall::NixosRebuild {
            args: args.iter().map(|arg| arg.to_string()).collect(),
        });
        self.rebuild_results
            .lock()
            .unwrap()
            .pop_front()
            .expect("missing mocked nix result")
    }

    fn execute_switch_to_configuration(
        &self,
        script_path: &std::path::Path,
        action: SwitchAction,
    ) -> Result<(bool, String, String)> {
        self.calls
            .lock()
            .unwrap()
            .push(RecordedCall::SwitchToConfiguration {
                script_path: script_path.to_path_buf(),
                args: vec![action.as_arg().to_string()],
            });
        self.switch_results
            .lock()
            .unwrap()
            .pop_front()
            .expect("missing mocked switch-to-configuration result")
    }
}

struct PreflightExecutor {
    nix_results: Mutex<VecDeque<Result<(bool, String, String)>>>,
    nix_calls: Arc<Mutex<Vec<Vec<String>>>>,
    nix_clear_flags: Arc<Mutex<Vec<bool>>>,
}

impl PreflightExecutor {
    fn new(
        nix_results: Vec<Result<(bool, String, String)>>,
    ) -> (Self, NixCallLog, ClearNixPathLog) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let clear_flags = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                nix_results: Mutex::new(nix_results.into()),
                nix_calls: Arc::clone(&calls),
                nix_clear_flags: Arc::clone(&clear_flags),
            },
            calls,
            clear_flags,
        )
    }
}

impl CommandExecutorTrait for PreflightExecutor {
    fn execute_nixos_rebuild(
        &self,
        _args: &[&str],
        _clear_nix_path: bool,
    ) -> Result<(bool, String, String)> {
        panic!("execute_nixos_rebuild should not be called in flake preflight tests")
    }

    fn execute_nix(&self, args: &[&str], clear_nix_path: bool) -> Result<(bool, String, String)> {
        self.nix_calls
            .lock()
            .unwrap()
            .push(args.iter().map(|arg| arg.to_string()).collect());
        self.nix_clear_flags.lock().unwrap().push(clear_nix_path);
        self.nix_results
            .lock()
            .unwrap()
            .pop_front()
            .expect("missing mocked nix result")
    }

    fn execute_switch_to_configuration(
        &self,
        _script_path: &Path,
        _action: SwitchAction,
    ) -> Result<(bool, String, String)> {
        panic!("execute_switch_to_configuration should not be called in flake preflight tests")
    }
}

fn write_executable_script(path: &Path, body: &str) {
    fs::write(path, body).unwrap();
    let mut perms = fs::metadata(path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms).unwrap();

    #[cfg(unix)]
    assert!(
        fs::metadata(path).unwrap().permissions().mode() & 0o111 != 0,
        "script should be executable: {}",
        path.display()
    );
}

#[test]
fn test_nixos_builder_construction() {
    let config_path = PathBuf::from("/mnt/hidden/nixos");
    let profile_path = PathBuf::from("/nix/var/nix/profiles/nails-system");

    let builder = NixOSBuilder::new(config_path.clone(), profile_path.clone());

    // Verify struct is constructed with correct values
    assert_eq!(builder.config_path, config_path);
    assert_eq!(builder.profile_path, profile_path);
}

// ========================================================================
// Flake ref tests (--flake /path#attr support)
// ========================================================================

#[test]
fn test_nixos_builder_new_with_flake_ref() {
    let builder = NixOSBuilder::new_with_flake_ref(
        "/srv/example-flake#cfg-alpha".to_string(),
        PathBuf::from("/nix/var/nix/profiles/nails-system"),
    );

    // config_path should be the directory part (before #)
    assert_eq!(builder.config_path, PathBuf::from("/srv/example-flake"));
    // flake_ref should hold the full ref
    assert_eq!(
        builder.flake_ref,
        Some("/srv/example-flake#cfg-alpha".to_string())
    );
}

#[test]
fn test_nixos_builder_new_with_flake_ref_no_fragment() {
    let builder = NixOSBuilder::new_with_flake_ref(
        "/srv/example-flake".to_string(),
        PathBuf::from("/nix/var/nix/profiles/nails-system"),
    );

    // config_path should be the full path (no # to split on)
    assert_eq!(builder.config_path, PathBuf::from("/srv/example-flake"));
    // flake_ref should be None when there's no fragment (no need to override)
    assert_eq!(builder.flake_ref, None);
}

#[test]
fn test_nixos_builder_flake_arg_with_fragment() {
    let builder = NixOSBuilder::new_with_flake_ref(
        "/srv/example-flake#cfg-alpha".to_string(),
        PathBuf::from("/nix/var/nix/profiles/nails-system"),
    );

    assert_eq!(
        builder.effective_flake_arg(),
        "/srv/example-flake#cfg-alpha"
    );
}

#[test]
fn test_nixos_builder_flake_arg_without_fragment() {
    let builder = NixOSBuilder::new(
        PathBuf::from("/mnt/hidden/nixos"),
        PathBuf::from("/nix/var/nix/profiles/nails-system"),
    );

    // Without flake_ref, should fall back to config_path
    assert_eq!(builder.effective_flake_arg(), "/mnt/hidden/nixos");
}

#[test]
fn test_nixos_builder_new_preserves_no_flake_ref() {
    // Existing new() constructor should have flake_ref = None
    let builder = NixOSBuilder::new(
        PathBuf::from("/mnt/hidden/nixos"),
        PathBuf::from("/nix/var/nix/profiles/nails-system"),
    );

    assert_eq!(builder.flake_ref, None);
}

#[test]
fn test_nixos_builder_new_legacy_creates_legacy_builder() {
    let builder = NixOSBuilder::new_legacy(
        PathBuf::from("/etc/nixos/configuration.nix"),
        PathBuf::from("/nix/var/nix/profiles/nails-system"),
    );

    // Legacy builder uses the parent dir as config_path
    assert_eq!(builder.config_path, PathBuf::from("/etc/nixos"));
    assert!(!builder.is_flake());
    assert_eq!(builder.flake_ref, None);
}

#[test]
fn test_nixos_builder_new_legacy_config_at_root_uses_etc_nixos_fallback() {
    // When configuration.nix has no parent, falls back to /etc/nixos
    let builder = NixOSBuilder::new_legacy(
        PathBuf::from("configuration.nix"), // relative path with no parent
        PathBuf::from("/nix/var/nix/profiles/nails-system"),
    );

    // Falls back to /etc/nixos when no parent directory
    assert!(!builder.is_flake());
}

#[test]
fn test_nixos_builder_flake_dir_returns_none_for_legacy_builder() {
    let builder = NixOSBuilder::new_legacy(
        PathBuf::from("/etc/nixos/configuration.nix"),
        PathBuf::from("/nix/var/nix/profiles/nails-system"),
    );

    assert!(builder.flake_dir().is_none());
}

#[test]
fn test_nixos_builder_flake_dir_returns_some_for_flake_builder() {
    let builder = NixOSBuilder::new(
        PathBuf::from("/mnt/hidden/nixos"),
        PathBuf::from("/nix/var/nix/profiles/nails-system"),
    );

    assert_eq!(
        builder.flake_dir(),
        Some(PathBuf::from("/mnt/hidden/nixos").as_path())
    );
}

#[test]
fn test_nixos_builder_is_flake_for_new() {
    let builder = NixOSBuilder::new(
        PathBuf::from("/mnt/hidden/nixos"),
        PathBuf::from("/nix/var/nix/profiles/nails-system"),
    );
    assert!(builder.is_flake());
}

#[test]
fn test_nixos_builder_is_not_flake_for_legacy() {
    let builder = NixOSBuilder::new_legacy(
        PathBuf::from("/etc/nixos/configuration.nix"),
        PathBuf::from("/nix/var/nix/profiles/nails-system"),
    );
    assert!(!builder.is_flake());
}

#[test]
fn test_nixos_builder_effective_flake_arg_for_legacy_uses_config_dir() {
    let builder = NixOSBuilder::new_legacy(
        PathBuf::from("/etc/nixos/configuration.nix"),
        PathBuf::from("/nix/var/nix/profiles/nails-system"),
    );

    // effective_flake_arg returns config_path (parent dir) for legacy
    assert_eq!(builder.effective_flake_arg(), "/etc/nixos");
}

#[test]
fn flake_preflight_runs_read_only_metadata_and_attr_checks() {
    let explicit_name = "cfg-alpha";
    let (executor, calls, clear_flags) = PreflightExecutor::new(vec![
        Ok((true, String::new(), String::new())),
        Ok((
            true,
            "/nix/store/abcd-system.drv".to_string(),
            String::new(),
        )),
    ]);

    let temp_dir = tempfile::tempdir().unwrap();
    std::fs::write(temp_dir.path().join("flake.nix"), "{ outputs = _: {}; }\n").unwrap();

    let builder = NixOSBuilder {
        config_path: temp_dir.path().to_path_buf(),
        profile_path: PathBuf::from("/nix/var/nix/profiles/nails-system"),
        executor: Box::new(executor),
        build_mode: NixOSBuildMode::Flake,
        flake_ref: Some(format!("{}#{}", temp_dir.path().display(), explicit_name)),
    };

    let summary = builder.preflight_flake().unwrap();
    assert_eq!(
        summary,
        FlakePreflightSummary {
            metadata_checked: true,
            attr_checked: true,
        }
    );

    let calls = calls.lock().unwrap().clone();
    let clear_flags = clear_flags.lock().unwrap().clone();

    assert_eq!(clear_flags, vec![true, true]);
    assert_eq!(
        calls,
        vec![
            vec![
                "flake".to_string(),
                "metadata".to_string(),
                "--json".to_string(),
                temp_dir.path().display().to_string(),
                "--no-write-lock-file".to_string(),
                "--impure".to_string(),
            ],
            vec![
                "eval".to_string(),
                "--raw".to_string(),
                "--expr".to_string(),
                format!(
                    "let flake = builtins.getFlake {}; configs = flake.nixosConfigurations or {{}}; in if builtins.hasAttr {} configs then \"1\" else builtins.throw ({} + {})",
                    serde_json::to_string(&temp_dir.path().display().to_string()).unwrap(),
                    serde_json::to_string(explicit_name).unwrap(),
                    serde_json::to_string("__NAILS_MISSING_NIXOS_CONFIGURATION__:").unwrap(),
                    serde_json::to_string(explicit_name).unwrap(),
                ),
                "--no-write-lock-file".to_string(),
                "--impure".to_string(),
            ],
        ]
    );
}

#[test]
fn flake_preflight_infers_same_configuration_attr_for_plain_flake_refs() {
    let inferred_hostname = nix::sys::utsname::uname()
        .unwrap()
        .nodename()
        .to_string_lossy()
        .trim()
        .to_string();
    let (executor, calls, clear_flags) = PreflightExecutor::new(vec![
        Ok((true, String::new(), String::new())),
        Ok((
            true,
            "/nix/store/abcd-system.drv".to_string(),
            String::new(),
        )),
    ]);

    let temp_dir = tempfile::tempdir().unwrap();
    std::fs::write(temp_dir.path().join("flake.nix"), "{ outputs = _: {}; }\n").unwrap();
    let builder = NixOSBuilder {
        config_path: temp_dir.path().to_path_buf(),
        profile_path: PathBuf::from("/nix/var/nix/profiles/nails-system"),
        executor: Box::new(executor),
        build_mode: NixOSBuildMode::Flake,
        flake_ref: None,
    };

    let summary = builder.preflight_flake().unwrap();
    assert_eq!(
        summary,
        FlakePreflightSummary {
            metadata_checked: true,
            attr_checked: true,
        }
    );
    assert_eq!(clear_flags.lock().unwrap().clone(), vec![true, true]);
    let calls = calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 2);
    assert_eq!(
        calls[0][0..2],
        ["flake".to_string(), "metadata".to_string()]
    );
    assert_eq!(
        calls[1][0..3],
        [
            "eval".to_string(),
            "--raw".to_string(),
            "--expr".to_string()
        ]
    );
    assert!(calls[1][3].contains(&serde_json::to_string(&inferred_hostname).unwrap()));
    assert!(calls[1][3].contains("nixosConfigurations"));
    assert!(calls[1][3].contains("builtins.hasAttr"));
}

#[test]
fn flake_preflight_uses_base_ref_for_metadata_when_fragment_is_explicit() {
    let explicit_name = "cfg-beta";
    let (executor, calls, clear_flags) = PreflightExecutor::new(vec![
        Ok((true, String::new(), String::new())),
        Ok((
            true,
            "/nix/store/abcd-system.drv".to_string(),
            String::new(),
        )),
    ]);

    let temp_dir = tempfile::tempdir().unwrap();
    std::fs::write(temp_dir.path().join("flake.nix"), "{ outputs = _: {}; }\n").unwrap();

    let builder = NixOSBuilder {
        config_path: temp_dir.path().to_path_buf(),
        profile_path: PathBuf::from("/nix/var/nix/profiles/nails-system"),
        executor: Box::new(executor),
        build_mode: NixOSBuildMode::Flake,
        flake_ref: Some(format!("{}#{}", temp_dir.path().display(), explicit_name)),
    };

    let summary = builder.preflight_flake().unwrap();
    assert_eq!(
        summary,
        FlakePreflightSummary {
            metadata_checked: true,
            attr_checked: true,
        }
    );

    assert_eq!(clear_flags.lock().unwrap().clone(), vec![true, true]);
    let calls = calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 2);
    assert_eq!(
        calls[0][0..2],
        ["flake".to_string(), "metadata".to_string()]
    );
    assert!(calls[1][3].contains(&serde_json::to_string(explicit_name).unwrap()));
}

#[test]
fn flake_preflight_accepts_explicit_flake_ref_with_slash_before_fragment() {
    let explicit_name = "cfg-gamma";
    let (executor, calls, clear_flags) = PreflightExecutor::new(vec![
        Ok((true, String::new(), String::new())),
        Ok((
            true,
            "/nix/store/abcd-system.drv".to_string(),
            String::new(),
        )),
    ]);

    let temp_dir = tempfile::tempdir().unwrap();
    std::fs::write(temp_dir.path().join("flake.nix"), "{ outputs = _: {}; }\n").unwrap();

    let builder = NixOSBuilder {
        config_path: temp_dir.path().to_path_buf(),
        profile_path: PathBuf::from("/nix/var/nix/profiles/nails-system"),
        executor: Box::new(executor),
        build_mode: NixOSBuildMode::Flake,
        flake_ref: Some(format!("{}/#{}", temp_dir.path().display(), explicit_name)),
    };

    let summary = builder.preflight_flake().unwrap();
    assert_eq!(
        summary,
        FlakePreflightSummary {
            metadata_checked: true,
            attr_checked: true,
        }
    );

    assert_eq!(clear_flags.lock().unwrap().clone(), vec![true, true]);
    let calls = calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 2);
    assert_eq!(
        calls[0][0..2],
        ["flake".to_string(), "metadata".to_string()]
    );
    assert!(calls[1][3].contains(&serde_json::to_string(explicit_name).unwrap()));
}

#[test]
fn flake_preflight_reports_lock_file_failures_without_auto_update() {
    let explicit_name = "cfg-lock";
    let (executor, _, _) = PreflightExecutor::new(vec![Ok((
        false,
        String::new(),
        "flake 'path:/etc/nixos' requires lock file changes".to_string(),
    ))]);
    let temp_dir = tempfile::tempdir().unwrap();
    std::fs::write(temp_dir.path().join("flake.nix"), "{ outputs = _: {}; }\n").unwrap();
    let builder = NixOSBuilder {
        config_path: temp_dir.path().to_path_buf(),
        profile_path: PathBuf::from("/nix/var/nix/profiles/nails-system"),
        executor: Box::new(executor),
        build_mode: NixOSBuildMode::Flake,
        flake_ref: Some(format!("{}#{}", temp_dir.path().display(), explicit_name)),
    };

    let err = builder.preflight_flake().unwrap_err();
    let text = err.to_string();
    assert!(text.contains("flake lock"), "{text}");
    assert!(
        text.contains("does not run 'nix flake update' automatically"),
        "{text}"
    );
}

#[test]
fn flake_preflight_reports_environment_filesystem_failures() {
    let explicit_name = "cfg-fs";
    let (executor, _, _) = PreflightExecutor::new(vec![Ok((
        false,
        String::new(),
        "error: getting status of '/nix/store/foo': Structure needs cleaning".to_string(),
    ))]);
    let temp_dir = tempfile::tempdir().unwrap();
    std::fs::write(temp_dir.path().join("flake.nix"), "{ outputs = _: {}; }\n").unwrap();
    let builder = NixOSBuilder {
        config_path: temp_dir.path().to_path_buf(),
        profile_path: PathBuf::from("/nix/var/nix/profiles/nails-system"),
        executor: Box::new(executor),
        build_mode: NixOSBuildMode::Flake,
        flake_ref: Some(format!("{}#{}", temp_dir.path().display(), explicit_name)),
    };

    let err = builder.preflight_flake().unwrap_err();
    let text = err.to_string();
    assert!(text.contains("environment/filesystem"), "{text}");
    assert!(
        text.contains("did not attempt an automatic repair"),
        "{text}"
    );
}

#[test]
fn enospc_is_classified_as_hidden_volume_full_with_reapply_guidance() {
    // A rebuild that fills the hidden volume must not be bucketed with generic
    // filesystem faults: it gets its own category and points at `nails reapply`.
    let stderr = "error: writing to file: No space left on device";
    assert_eq!(
        classify_nixos_failure_category(stderr, ""),
        "hidden-volume-full"
    );
    let message = format_classified_nixos_failure("NixOS switch", stderr, "");
    assert!(message.contains("hidden-volume-full"), "{message}");
    assert!(message.contains("hidden volume is full"), "{message}");
    assert!(message.contains("nails reapply"), "{message}");
}

#[test]
fn flake_preflight_reports_missing_inferred_attr_before_side_effects() {
    let inferred_hostname = nix::sys::utsname::uname()
        .unwrap()
        .nodename()
        .to_string_lossy()
        .trim()
        .to_string();
    let (executor, calls, clear_flags) = PreflightExecutor::new(vec![
        Ok((
            true,
            "{\"url\":\"path:/tmp/example\"}".to_string(),
            String::new(),
        )),
        Ok((
            false,
            String::new(),
            format!(
                "error: flake does not provide attribute 'nixosConfigurations.{}.config.system.build.toplevel.drvPath'",
                inferred_hostname
            ),
        )),
    ]);
    let temp_dir = tempfile::tempdir().unwrap();
    std::fs::write(temp_dir.path().join("flake.nix"), "{ outputs = _: {}; }\n").unwrap();
    let builder = NixOSBuilder {
        config_path: temp_dir.path().to_path_buf(),
        profile_path: PathBuf::from("/nix/var/nix/profiles/nails-system"),
        executor: Box::new(executor),
        build_mode: NixOSBuildMode::Flake,
        flake_ref: None,
    };

    let err = builder.preflight_flake().unwrap_err();
    let text = err.to_string();
    assert!(
        text.contains("does not provide the inferred nixosConfiguration"),
        "{text}"
    );
    assert!(text.contains(&inferred_hostname), "{text}");
    assert!(text.contains("Use '--flake"), "{text}");
    assert_eq!(clear_flags.lock().unwrap().clone(), vec![true, true]);
    assert_eq!(calls.lock().unwrap().len(), 2);
}

#[test]
fn flake_preflight_reference_fast_uses_metadata_and_attr_check_without_toplevel_eval() {
    let explicit_name = "cfg-metadata";
    let (executor, calls, clear_flags) = PreflightExecutor::new(vec![
        Ok((
            true,
            r#"{"url":"path:/tmp/example"}"#.to_string(),
            String::new(),
        )),
        Ok((true, "1".to_string(), String::new())),
    ]);

    let temp_dir = tempfile::tempdir().unwrap();
    std::fs::write(temp_dir.path().join("flake.nix"), "{ outputs = _: {}; }\n").unwrap();

    let builder = NixOSBuilder {
        config_path: temp_dir.path().to_path_buf(),
        profile_path: PathBuf::from("/nix/var/nix/profiles/nails-system"),
        executor: Box::new(executor),
        build_mode: NixOSBuildMode::Flake,
        flake_ref: Some(format!("{}#{}", temp_dir.path().display(), explicit_name)),
    };

    let summary = builder.preflight_flake_reference_fast().unwrap();
    assert_eq!(
        summary,
        FlakePreflightSummary {
            metadata_checked: true,
            attr_checked: true,
        }
    );
    assert_eq!(clear_flags.lock().unwrap().clone(), vec![true, true]);
    let calls = calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 2);
    assert_eq!(
        calls[0],
        vec![
            "flake".to_string(),
            "metadata".to_string(),
            "--json".to_string(),
            temp_dir.path().display().to_string(),
            "--no-write-lock-file".to_string(),
            "--impure".to_string(),
        ]
    );
    assert_eq!(
        calls[1][0..3],
        [
            "eval".to_string(),
            "--raw".to_string(),
            "--expr".to_string()
        ]
    );
}

#[test]
fn flake_preflight_rejects_relative_plain_flake_ref_before_nix_commands() {
    let (executor, calls, clear_flags) =
        PreflightExecutor::new(vec![Ok((true, String::new(), String::new()))]);
    let builder = NixOSBuilder {
        config_path: PathBuf::from("relative/flake"),
        profile_path: PathBuf::from("/nix/var/nix/profiles/nails-system"),
        executor: Box::new(executor),
        build_mode: NixOSBuildMode::Flake,
        flake_ref: Some("relative/flake#machine".to_string()),
    };

    let err = builder.preflight_flake().unwrap_err();
    let text = err.to_string();
    assert!(text.contains("relative"), "{text}");
    assert!(text.contains("absolute path"), "{text}");
    assert!(calls.lock().unwrap().is_empty());
    assert!(clear_flags.lock().unwrap().is_empty());
}

/// `target` spelled relative to the test process's working directory (which no
/// test changes), as a chain of `../` up to `/` followed by the absolute path.
/// Lets a test exercise relative flake refs without changing the working
/// directory every other test shares.
fn relative_from_cwd(target: &Path) -> String {
    let cwd = std::env::current_dir().unwrap();
    let depth = cwd
        .components()
        .filter(|component| matches!(component, std::path::Component::Normal(_)))
        .count();
    format!(
        "{}{}",
        "../".repeat(depth),
        target.strip_prefix("/").unwrap().display()
    )
}

#[test]
fn flake_preflight_accepts_parent_relative_flake_ref() {
    let (executor, calls, clear_flags) = PreflightExecutor::new(vec![
        Ok((true, String::new(), String::new())),
        Ok((
            true,
            "/nix/store/abcd-system.drv".to_string(),
            String::new(),
        )),
    ]);
    let temp_dir = tempfile::tempdir().unwrap();
    std::fs::write(temp_dir.path().join("flake.nix"), "{ outputs = _: {}; }\n").unwrap();
    let relative = relative_from_cwd(temp_dir.path());

    let builder = NixOSBuilder {
        config_path: PathBuf::from(&relative),
        profile_path: PathBuf::from("/nix/var/nix/profiles/nails-system"),
        executor: Box::new(executor),
        build_mode: NixOSBuildMode::Flake,
        flake_ref: Some(format!("{relative}#machine")),
    };

    let summary = builder.preflight_flake().unwrap();

    assert_eq!(
        summary,
        FlakePreflightSummary {
            metadata_checked: true,
            attr_checked: true,
        }
    );
    assert_eq!(clear_flags.lock().unwrap().clone(), vec![true, true]);
    assert_eq!(calls.lock().unwrap().len(), 2);
}

#[test]
fn flake_preflight_accepts_dot_slash_relative_flake_ref() {
    let (executor, calls, clear_flags) = PreflightExecutor::new(vec![
        Ok((true, String::new(), String::new())),
        Ok((
            true,
            "/nix/store/abcd-system.drv".to_string(),
            String::new(),
        )),
    ]);
    let temp_dir = tempfile::tempdir().unwrap();
    let rel_dir = temp_dir.path().join("relative-flake");
    std::fs::create_dir_all(&rel_dir).unwrap();
    std::fs::write(rel_dir.join("flake.nix"), "{ outputs = _: {}; }\n").unwrap();
    let relative = format!("./{}", relative_from_cwd(&rel_dir));

    let builder = NixOSBuilder {
        config_path: PathBuf::from(&relative),
        profile_path: PathBuf::from("/nix/var/nix/profiles/nails-system"),
        executor: Box::new(executor),
        build_mode: NixOSBuildMode::Flake,
        flake_ref: Some(format!("{relative}#machine")),
    };

    let summary = builder.preflight_flake().unwrap();

    assert_eq!(
        summary,
        FlakePreflightSummary {
            metadata_checked: true,
            attr_checked: true,
        }
    );
    assert_eq!(clear_flags.lock().unwrap().clone(), vec![true, true]);
    assert_eq!(calls.lock().unwrap().len(), 2);
}

#[test]
fn split_flake_ref_separates_base_and_fragment() {
    assert_eq!(
        split_flake_ref("/any/path#cfg-alpha"),
        ("/any/path", Some("cfg-alpha"))
    );
    assert_eq!(
        split_flake_ref("/any/path/#cfg-beta"),
        ("/any/path/", Some("cfg-beta"))
    );
    assert_eq!(split_flake_ref("/any/path"), ("/any/path", None));
    assert_eq!(split_flake_ref("/any/path#"), ("/any/path", None));
    assert_eq!(
        split_flake_ref("path:/some/dir?foo=bar#cfg"),
        ("path:/some/dir?foo=bar", Some("cfg"))
    );
    assert_eq!(
        split_flake_ref("github:owner/repo#cfg"),
        ("github:owner/repo", Some("cfg"))
    );
}

#[test]
fn local_flake_dir_only_returns_paths_for_local_refs() {
    // Relative refs resolve against the working directory, which no test changes.
    assert_eq!(
        local_flake_dir("/some/dir"),
        Some(PathBuf::from("/some/dir"))
    );
    assert_eq!(
        local_flake_dir("path:/some/dir?foo=bar"),
        Some(PathBuf::from("/some/dir"))
    );
    assert_eq!(
        local_flake_dir("."),
        Some(std::env::current_dir().unwrap().join("."))
    );
    assert_eq!(
        local_flake_dir("./relative-flake"),
        Some(std::env::current_dir().unwrap().join("./relative-flake"))
    );
    assert_eq!(local_flake_dir("github:owner/repo"), None);
}

#[test]
fn test_build_and_switch_succeeds_in_legacy_mode() {
    let temp_dir = tempfile::tempdir().unwrap();
    let config_path = temp_dir.path().join("configuration.nix");
    std::fs::write(&config_path, "{}").unwrap();

    let builder = NixOSBuilder::new_legacy_with_executor(
        config_path,
        temp_dir.path().join("profile"),
        Box::new(MockCommandExecutor::success()),
    );

    assert!(builder.build_and_switch().is_ok());
}

#[test]
fn test_build_and_switch_uses_flake_args_and_succeeds() {
    let (executor, calls) = RecordingCommandExecutor::with_call_log(
        vec![Ok((true, String::new(), String::new()))],
        vec![],
    );
    let builder = NixOSBuilder::new_with_executor(
        PathBuf::from("/srv/example-flake"),
        PathBuf::from("/nix/var/nix/profiles/nails-system"),
        Box::new(executor),
    );

    assert!(builder.build_and_switch().is_ok());

    assert_eq!(
        calls.lock().unwrap().clone(),
        vec![RecordedCall::NixosRebuild {
            args: vec![
                "test".to_string(),
                "--flake".to_string(),
                "/srv/example-flake".to_string(),
                "--no-update-lock-file".to_string(),
                "--impure".to_string(),
            ],
        }]
    );
}

#[test]
fn test_build_and_switch_legacy_uses_nixos_config_args() {
    let temp_dir = tempfile::tempdir().unwrap();
    let config_path = temp_dir.path().join("configuration.nix");
    std::fs::write(&config_path, "{}").unwrap();

    let (executor, calls) = RecordingCommandExecutor::with_call_log(
        vec![Ok((true, String::new(), String::new()))],
        vec![],
    );
    let builder = NixOSBuilder::new_legacy_with_executor(
        config_path.clone(),
        temp_dir.path().join("profile"),
        Box::new(executor),
    );

    assert!(builder.build_and_switch().is_ok());

    // Legacy builds pass the configuration path through `-I nixos-config=...`
    // rather than a flake reference, and never clear the Nix search path.
    assert_eq!(
        calls.lock().unwrap().clone(),
        vec![RecordedCall::NixosRebuild {
            args: vec![
                "test".to_string(),
                "-I".to_string(),
                format!("nixos-config={}", config_path.display()),
            ],
        }]
    );
}

#[test]
fn test_build_and_switch_returns_error_when_flake_test_fails() {
    let builder = NixOSBuilder::new_with_executor(
        PathBuf::from("/srv/example-flake"),
        PathBuf::from("/nix/var/nix/profiles/nails-system"),
        Box::new(RecordingCommandExecutor::new(
            vec![Ok((false, String::new(), "flake boom".to_string()))],
            vec![],
        )),
    );

    let err = builder.build_and_switch().unwrap_err();
    assert!(
        err.to_string()
            .contains("nixos-rebuild test failed: flake boom")
    );
}

#[test]
fn test_build_and_switch_prefers_stdout_when_stderr_is_empty() {
    let builder = NixOSBuilder::new_with_executor(
        PathBuf::from("/srv/example-flake"),
        PathBuf::from("/nix/var/nix/profiles/nails-system"),
        Box::new(RecordingCommandExecutor::new(
            vec![Ok((
                false,
                "stdout-only failure".to_string(),
                String::new(),
            ))],
            vec![],
        )),
    );

    let err = builder.build_and_switch().unwrap_err();
    assert!(err.to_string().contains("stdout-only failure"));
}

#[test]
fn test_build_and_switch_treats_unit_restart_failures_as_non_fatal() {
    let builder = NixOSBuilder::new_with_executor(
        PathBuf::from("/srv/example-flake"),
        PathBuf::from("/nix/var/nix/profiles/nails-system"),
        Box::new(RecordingCommandExecutor::new(
            vec![Ok((
                false,
                String::new(),
                "warning: error(s) occurred while switching to the new configuration\nThe following units failed: home-manager-amnesia.service".to_string(),
            ))],
            vec![],
        )),
    );

    assert!(builder.build_and_switch().is_ok());
}

#[test]
fn test_build_and_switch_keeps_real_build_failures_fatal() {
    let builder = NixOSBuilder::new_with_executor(
        PathBuf::from("/srv/example-flake"),
        PathBuf::from("/nix/var/nix/profiles/nails-system"),
        Box::new(RecordingCommandExecutor::new(
            vec![Ok((
                false,
                String::new(),
                "syntax error, unexpected ';'".to_string(),
            ))],
            vec![],
        )),
    );

    let err = builder.build_and_switch().unwrap_err();
    assert!(err.to_string().contains("syntax error"));
}

#[test]
fn test_real_command_executor_execute_nixos_rebuild_uses_path_and_captures_output() {
    // The default executor resolves the toolchain from the caller's PATH, which
    // is how the VM tests substitute stub builds, so this one test scopes a
    // snapshot with a prepended PATH; the others inject a search path instead.
    let temp_dir = tempfile::tempdir().unwrap();
    let script = temp_dir.path().join("nixos-rebuild");
    write_executable_script(
        &script,
        "#!/usr/bin/env bash\nprintf 'rebuilt ok\\n'\nprintf 'warn\\n' 1>&2\nexit 0\n",
    );
    let mut paths = vec![temp_dir.path().to_path_buf()];
    if let Some(existing) = std::env::var_os("PATH") {
        paths.extend(std::env::split_paths(&existing));
    }
    let _env = crate::runtime_env::ScopedRuntimeEnv::new(
        crate::RuntimeEnv::empty().with_path(std::env::join_paths(paths).unwrap()),
    );

    let result = RealCommandExecutor::default()
        .execute_nixos_rebuild(&["test"], false)
        .unwrap();

    assert_eq!(
        result,
        (true, "rebuilt ok\n".to_string(), "warn\n".to_string())
    );
}

#[test]
fn test_real_command_executor_execute_nixos_rebuild_returns_false_on_nonzero_exit() {
    let temp_dir = tempfile::tempdir().unwrap();
    let script = temp_dir.path().join("nixos-rebuild");
    write_executable_script(
        &script,
        "#!/usr/bin/env bash\nprintf 'partial out\\n'\nprintf 'build failed\\n' 1>&2\nexit 17\n",
    );

    let result = RealCommandExecutor::with_search_path(temp_dir.path())
        .execute_nixos_rebuild(&[], false)
        .unwrap();

    assert_eq!(
        result,
        (
            false,
            "partial out\n".to_string(),
            "build failed\n".to_string(),
        )
    );
}

#[test]
fn test_real_command_executor_execute_nixos_rebuild_returns_not_found_when_missing() {
    let temp_dir = tempfile::tempdir().unwrap();

    let err = RealCommandExecutor::with_search_path(temp_dir.path())
        .execute_nixos_rebuild(&[], false)
        .unwrap_err();

    match err {
        crate::NailsError::IoError { source: io, .. } => {
            assert_eq!(io.kind(), std::io::ErrorKind::NotFound)
        }
        other => panic!("expected IoError(NotFound), got {other:?}"),
    }
}

#[test]
fn test_real_command_executor_execute_switch_to_configuration_runs_exact_script_path() {
    let temp_dir = tempfile::tempdir().unwrap();
    let script = temp_dir.path().join("switch-to-configuration");
    write_executable_script(
        &script,
        "#!/usr/bin/env bash\nprintf 'mode=%s\\n' \"$1\"\nprintf 'note\\n' 1>&2\nexit 0\n",
    );

    let result = RealCommandExecutor::default()
        .execute_switch_to_configuration(&script, SwitchAction::Test)
        .unwrap();

    assert_eq!(
        result,
        (true, "mode=test\n".to_string(), "note\n".to_string())
    );
}

#[test]
fn test_real_command_executor_execute_nix_drops_nix_path_only_when_asked() {
    let temp_dir = tempfile::tempdir().unwrap();
    write_executable_script(
        &temp_dir.path().join("nix"),
        "#!/usr/bin/env bash\nprintf '%s' \"${NIX_PATH-unset}\"\n",
    );
    let executor = RealCommandExecutor::with_search_path(temp_dir.path());
    let _env = crate::runtime_env::ScopedRuntimeEnv::new(
        crate::RuntimeEnv::empty()
            .with_inherited(vec![("NIX_PATH".into(), "nixpkgs=/caller/channel".into())]),
    );

    let kept = executor.execute_nix(&["eval"], false);
    let cleared = executor.execute_nix(&["eval"], true);

    assert_eq!(kept.unwrap().1, "nixpkgs=/caller/channel");
    assert_eq!(cleared.unwrap().1, "unset");
}
