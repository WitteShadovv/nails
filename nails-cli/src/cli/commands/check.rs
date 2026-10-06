// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Check (alias `doctor`) command handler.
//!
//! A strictly read-only readiness check: it loads the configuration, builds the
//! same pre-flight registry activation would run (through
//! [`NailsManager::preflight_registry`](nails_core::NailsManager::preflight_registry)),
//! runs it without staging or mutating anything, and reports each result plus the
//! effective configuration, the overlay targets, how the session would be handled
//! and which NixOS profile would be built. `activate --dry-run` is a thin alias
//! for this command, so the two always agree.

use std::io::Write;
use std::path::Path;

use nails_core::{
    CliOverrides, Config, Filesystem, OverlayMode, SessionKind, build_overlay_targets,
};

use crate::cli::args::CheckArgs;
use crate::cli::output::check::{
    CheckReport, CheckRow, ConfigSummary, InheritedSummary, ProfileSummary, SessionSummary,
    print_check_human, print_check_json,
};
use crate::cli::output::envelope::{ErrorBody, report_error};
use crate::cli::output::{ExitStatus, OutputSettings};

/// The command name used in the JSON envelope and error reports.
const COMMAND: &str = "check";

/// Execute the `check`/`doctor` command.
///
/// Returns [`ExitStatus::Ok`] when every check passed (warnings allowed),
/// [`ExitStatus::PreflightRefused`] when any check failed,
/// [`ExitStatus::Config`] when the configuration file could not be loaded, and
/// [`ExitStatus::Failed`] when the checks could not be assembled.
pub fn execute(
    settings: &OutputSettings,
    args: &CheckArgs,
    config_override: Option<&Path>,
) -> ExitStatus {
    let json = settings.is_json();

    let mut loaded = match super::load_config_or_report(config_override, COMMAND, json) {
        Ok(loaded) => loaded,
        Err(status) => return status,
    };
    loaded.apply_cli_overrides(&CliOverrides {
        clear_history: None,
        nixos_flake: args.nixos_flake.clone(),
    });

    let config_path = loaded.path.clone();
    let config = loaded.into_config();
    let overlay_only = args.overlay_only;
    let state_path = config.state_file_path.clone();

    // Build the manager with the NixOS target activation would pick, then build
    // its pre-flight registry. The registry is read-only to run; staging of the
    // hidden NixOS layout only happens on the activation path, never here.
    let manager = super::build_nixos_manager(config, state_path, overlay_only);

    let registry =
        match manager.preflight_registry(overlay_only, true, args.accept_persistent_decoy) {
            Ok(registry) => registry,
            Err(e) => {
                return report_error(
                    json,
                    COMMAND,
                    ExitStatus::Failed,
                    ErrorBody::new("check_error", format!("could not assemble checks: {e}")),
                );
            }
        };

    let (results, _) = registry.run_all_detailed(manager.filesystem());
    let checks: Vec<CheckRow> = results
        .iter()
        .map(|(name, result)| CheckRow::from_result(name.clone(), result))
        .collect();

    let config = manager.config();
    let config_summary = ConfigSummary {
        config_file: config_path
            .exists()
            .then(|| config_path.display().to_string()),
        hidden_volume_root: config.hidden_volume_root.display().to_string(),
        state_file: config.state_file_path.display().to_string(),
        log_path: config.log_path.display().to_string(),
        overlay_mode: match config.overlay_mode {
            OverlayMode::Auto => "auto",
            OverlayMode::Explicit => "explicit",
        },
        persona_mode: config.persona.mode.as_str(),
        minimum_space_mb: config.minimum_space_mb,
    };

    let overlay_targets = build_overlay_targets(manager.filesystem(), config)
        .map(|targets| {
            targets
                .iter()
                .map(|path| path.display().to_string())
                .collect()
        })
        .unwrap_or_default();

    let session = session_summary();
    let profile = profile_summary(
        manager
            .discover_host_target(overlay_only)
            .unwrap_or(nails_core::HostTarget::None),
    );
    let inherited = inherited_summary(config, manager.filesystem());

    let report = CheckReport::finalize(
        checks,
        config_summary,
        overlay_targets,
        session,
        profile,
        inherited,
    );

    if json {
        print_check_json(&report);
    } else {
        print_check_human(&report, settings.stdout_style());
    }
    let _ = std::io::stdout().flush();

    if report.ready {
        ExitStatus::Ok
    } else {
        ExitStatus::PreflightRefused
    }
}

/// Describe how the graphical session would be handled.
///
/// The check runs non-interactively and without privileges, so a session it
/// cannot classify is reported as `unknown` rather than surfaced as an error.
fn session_summary() -> SessionSummary {
    match nails_core::detect_session_context(&nails_core::RealSessionCommandExecutor) {
        Ok(ctx) => {
            let kind = match ctx.kind {
                SessionKind::Tty => "tty",
                SessionKind::GraphicalUser => "graphical-user",
                SessionKind::GraphicalRoot => "graphical-root",
                SessionKind::Ssh => "ssh",
                SessionKind::Unknown => "unknown",
            };
            SessionSummary {
                kind,
                display_manager: ctx.display_manager,
                // Activation's default session policy ends a graphical user
                // session before mounting; other kinds are left running.
                would_terminate: ctx.kind == SessionKind::GraphicalUser,
            }
        }
        Err(_) => SessionSummary {
            kind: "unknown",
            display_manager: None,
            would_terminate: false,
        },
    }
}

/// Describe which NixOS profile activation would build.
///
/// `target` comes from the manager's
/// [`discover_host_target`](nails_core::NailsManager::discover_host_target), the
/// same platform-driven discovery [`super::build_nixos_manager`] and the
/// `nixos-build-target` pre-flight check use, so `--dry-run` can never report a
/// different target than activation would pick. In particular a lone system
/// profile is reported as a legacy build here, matching activation, rather than
/// as "no profile switch".
fn profile_summary(target: nails_core::HostTarget) -> ProfileSummary {
    use nails_core::HostTarget;

    match target {
        HostTarget::OverlayOnly => ProfileSummary {
            mode: "overlay-only",
            detail: Some("overlay-only mode: the NixOS profile switch is skipped".into()),
        },
        HostTarget::ExplicitFlake(flake) => ProfileSummary {
            mode: "flake",
            detail: Some(format!("NixOS flake: {flake}")),
        },
        HostTarget::Flake(dir) => ProfileSummary {
            mode: "flake",
            detail: Some(format!("NixOS flake found at {}", dir.display())),
        },
        HostTarget::Legacy(path) => ProfileSummary {
            mode: "legacy",
            detail: Some(format!("legacy build target: {}", path.display())),
        },
        HostTarget::None => ProfileSummary {
            mode: "none",
            detail: None,
        },
    }
}

/// Collect the decoy persona state the hidden session would inherit.
///
/// The check runs non-interactively and often without privileges, so when the
/// target user cannot be resolved the inventory is reported as "not inspected"
/// rather than surfaced as an error. In fresh-home mode only system-level
/// inherited state is listed, matching what that mode actually carries over.
fn inherited_summary<F: Filesystem>(config: &Config, fs: &F) -> InheritedSummary {
    use nails_core::config::PersonaMode;
    use nails_core::{TargetUser, collect_inherited_persona};

    let Ok(user) = TargetUser::resolve() else {
        return InheritedSummary::not_inspected();
    };

    let fresh_home = config.persona.mode == PersonaMode::FreshHome;
    let inventory = collect_inherited_persona(fs, user.home(), &user.name, fresh_home);
    InheritedSummary::from_inventory(&inventory)
}

#[cfg(test)]
#[path = "check_tests.rs"]
mod tests;
