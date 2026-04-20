//! Dry-run mode for the activate command

use nails_core::{Config, RealFilesystem, build_overlay_targets};

/// Execute dry-run mode: preview activation steps without making changes
///
/// Loads config, runs preflight checks, computes overlay targets, detects
/// active sessions, and prints what would happen — without modifying the
/// filesystem or creating a NailsManager.
pub(super) fn execute_dry_run(
    config: &Config,
    no_preflight: bool,
    overlay_only: bool,
    no_kill_session: bool,
    plain: bool,
) -> ! {
    use nails_core::preflight::CheckResult;

    let pass = if plain { "[PASS]" } else { "✓" };
    let fail = if plain { "[FAIL]" } else { "✗" };
    let warn = if plain { "[WARN]" } else { "⚠" };
    let info = if plain { "[INFO]" } else { "ℹ" };

    println!("=== NAILS Dry-Run: Activation Preview ===");
    println!();

    // 1. Preflight checks
    println!("--- Pre-flight Checks ---");
    if no_preflight {
        println!("  {} Pre-flight checks skipped (--no-preflight)", warn);
    } else {
        let fs = RealFilesystem;
        let registry = build_preflight_registry(&fs, config, overlay_only);
        let (results, all_passed) = registry.run_all_detailed(&fs);
        for (name, result) in &results {
            let symbol = match result {
                CheckResult::Pass(_) => pass,
                CheckResult::Warn(_) => warn,
                CheckResult::Fail(_) => fail,
            };
            println!("  {} {}: {}", symbol, name, result.message());
        }
        if all_passed {
            println!("  {} All pre-flight checks passed", pass);
        } else {
            println!("  {} Some pre-flight checks failed", fail);
        }
    }
    println!();

    // 2. Overlay targets
    println!("--- Overlay Targets ---");
    let fs = RealFilesystem;
    match build_overlay_targets(&fs, config) {
        Ok(targets) => {
            if targets.is_empty() {
                println!("  {} No overlay targets found", warn);
            } else {
                for target in &targets {
                    println!("  {} Mount overlay on: {}", info, target.display());
                }
                println!(
                    "  {} {} overlay target(s) would be mounted",
                    pass,
                    targets.len()
                );
            }
        }
        Err(e) => {
            println!("  {} Failed to compute overlay targets: {}", fail, e);
        }
    }
    println!();

    // 3. Session detection
    println!("--- Session Management ---");
    let kill_session = !no_kill_session;
    if kill_session {
        match nails_core::detect_session_context() {
            Ok(ctx) => {
                if ctx.kind == nails_core::SessionKind::GraphicalUser {
                    println!(
                        "  {} Graphical session detected — would be killed before activation",
                        warn
                    );
                    if let Some(ref dm) = ctx.display_manager {
                        println!("  {} Display manager: {} (would be restarted)", info, dm);
                    }
                } else {
                    println!(
                        "  {} No graphical session detected — no session kill needed",
                        pass
                    );
                }
            }
            Err(_) => {
                println!("  {} Could not detect session context", warn);
            }
        }
    } else {
        println!("  {} Session kill disabled (--no-kill-session)", info);
    }
    println!();

    // 4. NixOS profile
    println!("--- NixOS Profile ---");
    if overlay_only {
        println!(
            "  {} Overlay-only mode: NixOS profile switch would be skipped",
            info
        );
    } else if config.nixos_flake.is_some() {
        println!(
            "  {} NixOS flake: {} — would build and switch profile",
            info,
            config.nixos_flake.as_ref().unwrap()
        );
    } else {
        let nixos_flake_path = config.hidden_volume_root.join("nixos/flake.nix");
        let etc_flake = std::path::PathBuf::from("/etc/nixos/flake.nix");
        let legacy_config = std::path::PathBuf::from("/etc/nixos/configuration.nix");
        if nixos_flake_path.exists() {
            println!(
                "  {} NixOS flake found in hidden volume — would build and switch",
                info
            );
        } else if etc_flake.exists() {
            println!(
                "  {} NixOS flake found at /etc/nixos — would build and switch",
                info
            );
        } else if legacy_config.exists() {
            println!(
                "  {} Legacy NixOS config found — would build and switch",
                info
            );
        } else {
            println!(
                "  {} No NixOS configuration found — profile switch would be skipped",
                info
            );
        }
    }
    println!();

    println!("=== Dry-run complete. No changes were made. ===");
    std::process::exit(0);
}

/// Build a preflight check registry from config (mirrors NailsManager::run_preflight_checks)
fn build_preflight_registry(
    fs: &RealFilesystem,
    config: &Config,
    overlay_only: bool,
) -> nails_core::preflight::PreFlightRegistry<RealFilesystem> {
    use nails_core::preflight::*;

    let mut registry = PreFlightRegistry::new();

    registry.add_check(Box::new(HiddenVolumeCheck::new(
        config.hidden_volume_root.clone(),
    )));

    registry.add_check(Box::new(SymlinkSupportCheck::new(
        config.hidden_volume_root.clone(),
    )));

    // Compute overlay dirs for storage readiness
    let overlay_dirs: Vec<OverlayDirs> = match config.overlay_mode {
        nails_core::config::OverlayMode::Auto => match build_overlay_targets(fs, config) {
            Ok(targets) => targets
                .iter()
                .map(|target| {
                    let dir_name = target
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string();
                    let upper = config.hidden_volume_root.join(&dir_name);
                    let work = config.hidden_volume_root.join(".work").join(&dir_name);
                    OverlayDirs::new(dir_name, target.clone(), upper, work)
                })
                .collect(),
            Err(_) => Vec::new(),
        },
        nails_core::config::OverlayMode::Explicit => config
            .overlays
            .iter()
            .map(|o| {
                OverlayDirs::new(
                    o.name.clone(),
                    o.lower.clone(),
                    o.upper.clone(),
                    o.work.clone(),
                )
            })
            .collect(),
    };

    registry.add_check(Box::new(StorageReadinessCheck::new(
        config.hidden_volume_root.clone(),
        overlay_dirs,
    )));

    let overlay_target_paths: Vec<std::path::PathBuf> = match config.overlay_mode {
        nails_core::config::OverlayMode::Auto => {
            build_overlay_targets(fs, config).unwrap_or_default()
        }
        nails_core::config::OverlayMode::Explicit => {
            config.overlays.iter().map(|o| o.lower.clone()).collect()
        }
    };

    registry.add_check(Box::new(OverlayCompatibilityCheck::new(
        overlay_target_paths,
        config.hidden_volume_root.clone(),
    )));

    if !overlay_only {
        registry.add_check(Box::new(NixOSConfigCheck::new(
            config.hidden_volume_root.clone(),
        )));

        registry.add_check(Box::new(NixOSBuildTargetCheck::with_selected_flake_dir(
            config.nixos_flake.clone(),
            None, // No builder in dry-run mode
            config.hidden_volume_root.clone(),
        )));
    }

    registry.add_check(Box::new(SwapCheck));

    registry.add_check(Box::new(SpaceCheck::new(
        config.hidden_volume_root.clone(),
        config.minimum_space_mb,
    )));

    registry
}

#[cfg(test)]
mod tests {
    use super::{build_preflight_registry, execute_dry_run};
    use nails_core::{Config, OverlayConfig, OverlayMode, RealFilesystem};
    use std::path::PathBuf;

    const SUBPROCESS_TEST_NAME: &str =
        "cli::commands::activate::dry_run::tests::subprocess_dry_run_entrypoint";

    fn run_dry_run_subprocess(case: &str) -> std::process::Output {
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", SUBPROCESS_TEST_NAME, "--nocapture"])
            .env("NAILS_DRY_RUN_SUBPROCESS_CASE", case)
            .output()
            .expect("failed to run dry-run subprocess test")
    }

    #[test]
    fn subprocess_dry_run_entrypoint() {
        let Ok(case) = std::env::var("NAILS_DRY_RUN_SUBPROCESS_CASE") else {
            return;
        };

        let hidden_root = std::env::temp_dir().join(format!("nails-dry-run-subprocess-{case}"));
        std::fs::create_dir_all(&hidden_root).unwrap();

        let mut config = Config {
            hidden_volume_root: hidden_root,
            minimum_space_mb: 64,
            ..Config::default()
        };

        match case.as_str() {
            "skip-preflight-overlay-only" => {
                execute_dry_run(&config, true, true, true, true);
            }
            "run-preflight" => {
                execute_dry_run(&config, false, false, true, true);
            }
            "flake-session-check" => {
                config.nixos_flake = Some("/etc/nixos#test-host".to_string());
                execute_dry_run(&config, true, false, false, true);
            }
            other => panic!("unknown dry-run subprocess case: {other}"),
        }
    }

    #[test]
    fn execute_dry_run_subprocess_covers_skip_preflight_overlay_only_path() {
        let output = run_dry_run_subprocess("skip-preflight-overlay-only");
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(output.status.success(), "stdout={stdout}");
        assert!(stdout.contains("[WARN] Pre-flight checks skipped (--no-preflight)"));
        assert!(stdout.contains("[INFO] Session kill disabled (--no-kill-session)"));
        assert!(stdout.contains("Overlay-only mode: NixOS profile switch would be skipped"));
    }

    #[test]
    fn execute_dry_run_subprocess_covers_preflight_execution_path() {
        let output = run_dry_run_subprocess("run-preflight");
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(output.status.success(), "stdout={stdout}");
        assert!(stdout.contains("--- Pre-flight Checks ---"));
        assert!(
            stdout.contains("All pre-flight checks passed")
                || stdout.contains("Some pre-flight checks failed")
        );
    }

    #[test]
    fn execute_dry_run_subprocess_covers_flake_and_session_detection_paths() {
        let output = run_dry_run_subprocess("flake-session-check");
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(output.status.success(), "stdout={stdout}");
        assert!(stdout.contains("NixOS flake: /etc/nixos#test-host"));
        assert!(
            stdout.contains("Graphical session detected")
                || stdout.contains("No graphical session detected")
                || stdout.contains("Could not detect session context")
        );
    }

    #[test]
    fn build_preflight_registry_includes_nixos_checks_when_not_overlay_only() {
        let config = Config {
            hidden_volume_root: PathBuf::from("/tmp/nails-dry-run-hidden"),
            minimum_space_mb: 64,
            ..Config::default()
        };

        let registry = build_preflight_registry(&RealFilesystem, &config, false);

        assert_eq!(registry.len(), 8);
    }

    #[test]
    fn build_preflight_registry_skips_nixos_checks_for_overlay_only_mode() {
        let config = Config {
            hidden_volume_root: PathBuf::from("/tmp/nails-dry-run-hidden"),
            minimum_space_mb: 64,
            ..Config::default()
        };

        let registry = build_preflight_registry(&RealFilesystem, &config, true);

        assert_eq!(registry.len(), 6);
    }

    #[test]
    fn build_preflight_registry_supports_explicit_overlay_mode() {
        let hidden_root = PathBuf::from("/tmp/nails-dry-run-hidden-explicit");
        let config = Config {
            hidden_volume_root: hidden_root.clone(),
            minimum_space_mb: 64,
            overlay_mode: OverlayMode::Explicit,
            overlays: vec![OverlayConfig {
                name: "etc".to_string(),
                lower: PathBuf::from("/etc"),
                upper: hidden_root.join("etc"),
                work: hidden_root.join(".work/etc"),
                target: PathBuf::from("/etc"),
            }],
            ..Config::default()
        };

        let registry = build_preflight_registry(&RealFilesystem, &config, false);

        assert_eq!(registry.len(), 8);
    }
}
