// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Phase 2 of the overlay mounting strategy: classify the processes using a
//! target, apply the risky-service policy, and refuse to force-terminate
//! interactive user programs.
//!
//! This lives apart from the mounting flow in [`super`] so the restart/guard
//! sequencing can be unit-tested through a scripted command executor.

use crate::overlay::{OverlayStrategyOptions, SurvivingWriter};
use crate::process::{ProcessInfo, RestartStrategy, RiskyServicePolicy};
use crate::{NailsError, Result};
use std::path::{Path, PathBuf};

/// Record a process as a surviving writer (keeps its identity, not just a count).
fn survivor(proc: &ProcessInfo) -> SurvivingWriter {
    SurvivingWriter {
        pid: proc.pid,
        name: proc.name.clone(),
        service: proc.service_name.clone(),
    }
}

/// Whether a process would be force-terminated by signal (it has no systemd
/// service to stop cleanly) while a user is interacting with it.
///
/// These are the processes activation must never SIGKILL silently: a shell, an
/// editor or a `tail -f` the user left running. The caller aborts before mounting
/// when any such process would be terminated without an explicit opt-in.
fn is_protected_interactive(proc: &ProcessInfo) -> bool {
    proc.service_name.is_none() && proc.is_interactive
}

/// Whether Phase 2 would force-terminate an interactive user program: `proc` is
/// protected (see [`is_protected_interactive`]) and its classification on the
/// target means it gets stopped — a safe process while safe restarts are on, or
/// a risky one when risky services are being restarted.
///
/// The single predicate behind both the pre-mount sweep and the per-target
/// guard, so the two can never disagree about which processes are refused.
fn would_force_terminate(
    proc: &ProcessInfo,
    strategy: RestartStrategy,
    options: &OverlayStrategyOptions,
    restart_risky: bool,
) -> bool {
    if !is_protected_interactive(proc) {
        return false;
    }
    match strategy {
        RestartStrategy::Safe => options.auto_restart_safe,
        RestartStrategy::Risky => restart_risky,
        RestartStrategy::NoRestart | RestartStrategy::Skip => false,
    }
}

/// The refusal returned when activation would have to force-terminate
/// interactive programs. `listed` names each process and where it was found.
fn interactive_refusal(scope: &str, listed: &str) -> NailsError {
    NailsError::InvalidState(format!(
        "Refusing to force-terminate interactive process(es) {scope}: {listed}. \
         Close them, or re-run with --terminate-interactive to end them anyway."
    ))
}

/// Refuse up front when mounting `targets` would force-terminate an interactive
/// user program on any of them.
///
/// Runs before the first mount, service stop or signal, so a `tail -f` on
/// `/var` blocks activation with nothing changed rather than after earlier
/// targets were already mounted and their services restarted. Risky services
/// count only under an explicit `restart` policy: when the policy is left to a
/// prompt, the per-target guard in [`run_process_phase`] still applies once the
/// operator has answered.
pub fn refuse_interactive_terminations(
    targets: &[PathBuf],
    options: &OverlayStrategyOptions,
) -> Result<()> {
    if options.terminate_interactive || options.skip_process_detection {
        return Ok(());
    }
    let found = crate::process::detect_interactive_processes_using(targets)?;
    check_interactive_terminations(&found, options)
}

/// The decision behind [`refuse_interactive_terminations`], taking the detected
/// `(target, process)` pairs so it can be tested without a live `/proc`.
pub(super) fn check_interactive_terminations(
    found: &[(PathBuf, ProcessInfo)],
    options: &OverlayStrategyOptions,
) -> Result<()> {
    use crate::process::classify_process;

    if options.terminate_interactive {
        return Ok(());
    }
    let restart_risky = options.risky_services == Some(RiskyServicePolicy::Restart);

    // One entry per process, listing every target it would be terminated for.
    let mut offenders: Vec<(&ProcessInfo, Vec<String>)> = Vec::new();
    for (target, proc) in found {
        if !would_force_terminate(proc, classify_process(proc, target), options, restart_risky) {
            continue;
        }
        let shown = target.display().to_string();
        match offenders.iter_mut().find(|(seen, _)| seen.pid == proc.pid) {
            Some((_, targets)) => targets.push(shown),
            None => offenders.push((proc, vec![shown])),
        }
    }

    if offenders.is_empty() {
        return Ok(());
    }

    let listed = offenders
        .iter()
        .map(|(proc, targets)| {
            format!("{} (PID {}) on {}", proc.name, proc.pid, targets.join(", "))
        })
        .collect::<Vec<_>>()
        .join("; ");
    tracing::error!(
        processes = %listed,
        "  ✗ Refusing to force-terminate interactive process(es) before mounting: {}",
        listed
    );
    Err(interactive_refusal("before mounting", &listed))
}

/// Classify the blocking processes and act on them: restart the safe ones,
/// apply the risky-service policy, and refuse to force-terminate interactive
/// user programs.
///
/// Returns the services stopped (to restart after the mount) and the writers
/// that survived Phase 2 still referencing the target. Returns an error — before
/// any signal is sent — when an interactive, non-service process would be
/// force-terminated and the operator did not opt in via `terminate_interactive`.
///
/// The command executor is a seam so the sequencing can be unit-tested without
/// touching real processes.
pub(super) fn run_process_phase(
    blocking: Vec<ProcessInfo>,
    target: &Path,
    options: &OverlayStrategyOptions,
    executor: &dyn crate::process::restart::CommandExecutor,
) -> Result<(Vec<String>, Vec<SurvivingWriter>)> {
    use crate::process::classify_process;
    use crate::process::restart::restart_processes_with_executor;
    use crate::prompts::prompt_risky_process_restart;

    let mut stopped_services: Vec<String> = Vec::new();
    let mut survivors: Vec<SurvivingWriter> = Vec::new();

    if blocking.is_empty() {
        return Ok((stopped_services, survivors));
    }

    tracing::info!("[Phase 2: Classify] Analyzing restart safety...");

    let mut to_restart_safe = Vec::new();
    let mut to_restart_risky = Vec::new();
    let mut cannot_restart = Vec::new();
    let mut skip_count = 0usize;

    for proc in blocking {
        match classify_process(&proc, target) {
            RestartStrategy::Safe => {
                tracing::info!(name = %proc.name, pid = proc.pid, "  → {} (PID {}) - Safe to restart", proc.name, proc.pid);
                to_restart_safe.push(proc);
            }
            RestartStrategy::Risky => {
                tracing::info!(name = %proc.name, pid = proc.pid, "  → {} (PID {}) - Risky to restart", proc.name, proc.pid);
                to_restart_risky.push(proc);
            }
            RestartStrategy::NoRestart => cannot_restart.push(proc),
            RestartStrategy::Skip => skip_count += 1,
        }
    }

    if !cannot_restart.is_empty() {
        tracing::info!(
            count = cannot_restart.len(),
            "  {} processes cannot be restarted",
            cannot_restart.len()
        );
    }
    if skip_count > 0 {
        tracing::info!(
            count = skip_count,
            "  {} processes skipped (read-only, no action needed)",
            skip_count
        );
    }

    // Resolve what to do with risky services. `None` means "prompt on a
    // terminal"; the prompt helper refuses without one, which leaves the
    // services running (they become reported survivors). Callers resolve `None`
    // to an explicit choice for non-interactive runs before mounting.
    let restart_risky = if to_restart_risky.is_empty() {
        false
    } else {
        match options.risky_services {
            Some(RiskyServicePolicy::Restart) => true,
            Some(RiskyServicePolicy::Skip) => false,
            None => prompt_risky_process_restart(&to_restart_risky)?,
        }
    };

    // Safety gate: never force-terminate an interactive, non-service user process
    // (a shell, editor or `tail -f`). Terminating one by SIGKILL loses the user's
    // work silently, so abort before mounting and before any signal is sent,
    // listing the offenders, unless the operator opted in.
    if !options.terminate_interactive {
        let protected: Vec<&ProcessInfo> = to_restart_safe
            .iter()
            .map(|p| (p, RestartStrategy::Safe))
            .chain(to_restart_risky.iter().map(|p| (p, RestartStrategy::Risky)))
            .filter(|(p, strategy)| would_force_terminate(p, *strategy, options, restart_risky))
            .map(|(p, _)| p)
            .collect();

        if !protected.is_empty() {
            let listed = protected
                .iter()
                .map(|p| format!("{} (PID {})", p.name, p.pid))
                .collect::<Vec<_>>()
                .join(", ");
            tracing::error!(
                target_path = %target.display(),
                processes = %listed,
                "  ✗ Refusing to force-terminate interactive process(es) on {}: {}",
                target.display(),
                listed
            );
            return Err(interactive_refusal(
                &format!("using {}", target.display()),
                &listed,
            ));
        }
    }

    // Restart Safe processes. A safe process that stops cleanly no longer writes
    // to the decoy; one that fails to stop, or is left running because
    // auto-restart is disabled, is a survivor.
    if !to_restart_safe.is_empty() {
        if options.auto_restart_safe {
            tracing::info!(
                count = to_restart_safe.len(),
                "  Restarting {} safe processes...",
                to_restart_safe.len()
            );
            for result in restart_processes_with_executor(&to_restart_safe, executor)? {
                if result.stopped_successfully {
                    if let Some(ref svc) = result.info.service_name {
                        stopped_services.push(svc.clone());
                    }
                } else {
                    survivors.push(survivor(&result.info));
                }
            }
        } else {
            survivors.extend(to_restart_safe.iter().map(survivor));
        }
    }

    // Risky services: restart per the resolved policy, otherwise leave them
    // running — they keep writing to the decoy and are reported as survivors.
    if !to_restart_risky.is_empty() {
        if restart_risky {
            tracing::info!(
                count = to_restart_risky.len(),
                "  Restarting {} risky processes...",
                to_restart_risky.len()
            );
            for result in restart_processes_with_executor(&to_restart_risky, executor)? {
                if result.stopped_successfully {
                    if let Some(ref svc) = result.info.service_name {
                        stopped_services.push(svc.clone());
                    }
                } else {
                    survivors.push(survivor(&result.info));
                }
            }
        } else {
            survivors.extend(to_restart_risky.iter().map(survivor));
            tracing::info!("  Risky processes remain active (not restarted)");
        }
    }

    // Processes that cannot be restarted at all keep writing to the decoy.
    if !cannot_restart.is_empty() {
        survivors.extend(cannot_restart.iter().map(survivor));
        tracing::warn!(
            count = cannot_restart.len(),
            "  ⚠️  {} processes cannot be restarted",
            cannot_restart.len()
        );
        tracing::warn!(
            "  These writers will keep referencing the decoy lower tree after the mount."
        );
    }

    Ok((stopped_services, survivors))
}
