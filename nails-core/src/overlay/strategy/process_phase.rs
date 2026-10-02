//! Phase 2 of the overlay mounting strategy: classify the processes using a
//! target, apply the risky-service policy, and refuse to force-terminate
//! interactive user programs.
//!
//! This lives apart from the mounting flow in [`super`] so the restart/guard
//! sequencing can be unit-tested through a scripted command executor.

use crate::overlay::{OverlayStrategyOptions, SurvivingWriter};
use crate::process::{ProcessInfo, RiskyServicePolicy};
use crate::{NailsError, Result};
use std::path::Path;

/// Record a process as a surviving writer (keeps its identity, not just a count).
fn survivor(proc: &ProcessInfo) -> SurvivingWriter {
    SurvivingWriter {
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
    use crate::process::restart::restart_processes_with_executor;
    use crate::process::{RestartStrategy, classify_process};
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
        let mut protected: Vec<&ProcessInfo> = Vec::new();
        if options.auto_restart_safe {
            protected.extend(
                to_restart_safe
                    .iter()
                    .filter(|p| is_protected_interactive(p)),
            );
        }
        if restart_risky {
            protected.extend(
                to_restart_risky
                    .iter()
                    .filter(|p| is_protected_interactive(p)),
            );
        }

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
            return Err(NailsError::InvalidState(format!(
                "Refusing to force-terminate interactive process(es) using {}: {}. \
                 Close them, or re-run with --terminate-interactive to end them anyway.",
                target.display(),
                listed
            )));
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
