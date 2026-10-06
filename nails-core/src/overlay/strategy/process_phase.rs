// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Phase 2 of the overlay mounting strategy: classify the processes using a
//! target, apply the risky-service policy, and refuse to signal non-service
//! processes without the operator's opt-in.
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

/// Whether a process can only be stopped by signal: it has no systemd unit to
/// stop cleanly.
///
/// Activation never signals such a process without the operator's explicit
/// opt-in (`terminate_processes`): it may be a shell, an editor or a `tail -f`
/// a user is working in, or a detached job whose work a signal would lose.
fn is_signal_only(proc: &ProcessInfo) -> bool {
    proc.service_name.is_none()
}

/// Whether Phase 2 would signal a non-service process: `proc` has no systemd
/// unit (see [`is_signal_only`]) and its classification on the target means it
/// gets stopped — a safe process while safe restarts are on, or a risky one
/// when risky services are being restarted.
///
/// The single predicate behind both the pre-mount sweep and the per-target
/// guard, so the two can never disagree about which processes are refused.
fn would_signal(
    proc: &ProcessInfo,
    strategy: RestartStrategy,
    options: &OverlayStrategyOptions,
    restart_risky: bool,
) -> bool {
    if !is_signal_only(proc) {
        return false;
    }
    match strategy {
        RestartStrategy::Safe => options.auto_restart_safe,
        RestartStrategy::Risky => restart_risky,
        RestartStrategy::NoRestart | RestartStrategy::Skip => false,
    }
}

/// How one refused process is named: `tail (PID 812, interactive)`.
fn refused_label(proc: &ProcessInfo) -> String {
    if proc.is_interactive {
        format!("{} (PID {}, interactive)", proc.name, proc.pid)
    } else {
        format!("{} (PID {})", proc.name, proc.pid)
    }
}

/// The refusal returned when activation would have to signal non-service
/// processes without the opt-in. `listed` names each process and where it was
/// found.
fn signal_refusal(scope: &str, listed: &str) -> NailsError {
    NailsError::InvalidState(format!(
        "Refusing to signal non-service process(es) {scope}: {listed}. \
         Close them, or re-run with --terminate-processes to end them anyway."
    ))
}

/// Refuse up front when mounting `targets` would signal a non-service process
/// on any of them without the operator's opt-in.
///
/// Runs before the first mount, service stop or signal, so a `tail -f` on
/// `/var` blocks activation with nothing changed rather than after earlier
/// targets were already mounted and their services restarted. Risky holders
/// count only under an explicit `restart` policy: when the policy is left to a
/// prompt, the per-target guard in [`run_process_phase`] still applies once the
/// operator has answered.
pub fn refuse_unconsented_signals(
    targets: &[PathBuf],
    options: &OverlayStrategyOptions,
) -> Result<()> {
    if options.terminate_processes || options.skip_process_detection {
        return Ok(());
    }
    let found = crate::process::detect_non_service_processes_using(targets)?;
    check_unconsented_signals(&found, options)
}

/// The decision behind [`refuse_unconsented_signals`], taking the detected
/// `(target, process)` pairs so it can be tested without a live `/proc`.
pub(super) fn check_unconsented_signals(
    found: &[(PathBuf, ProcessInfo)],
    options: &OverlayStrategyOptions,
) -> Result<()> {
    use crate::process::classify_process;

    if options.terminate_processes {
        return Ok(());
    }
    let restart_risky = options.risky_services == Some(RiskyServicePolicy::Restart);

    // One entry per process, listing every target it would be signalled for.
    let mut offenders: Vec<(&ProcessInfo, Vec<String>)> = Vec::new();
    for (target, proc) in found {
        if !would_signal(proc, classify_process(proc, target), options, restart_risky) {
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
        .map(|(proc, targets)| format!("{} on {}", refused_label(proc), targets.join(", ")))
        .collect::<Vec<_>>()
        .join("; ");
    tracing::error!(
        processes = %listed,
        "  ✗ Refusing to signal non-service process(es) before mounting: {}",
        listed
    );
    Err(signal_refusal("before mounting", &listed))
}

/// The fail-closed error when the risky-service policy is `restart` but some
/// risky holders could not be stopped: leaving them running would silently
/// contradict the operator's choice, so activation aborts with the list.
fn risky_restart_failure(target: &Path, failed: &[&ProcessInfo]) -> NailsError {
    let listed = failed
        .iter()
        .map(|p| match &p.service_name {
            Some(service) => format!("{} ({}.service, PID {})", p.name, service, p.pid),
            None => format!("{} (PID {})", p.name, p.pid),
        })
        .collect::<Vec<_>>()
        .join(", ");
    NailsError::InvalidState(format!(
        "Could not restart risky process(es) using {}: {listed}. They would keep writing \
         to the decoy; stop them yourself, or re-run with --risky-services skip to leave \
         them running and have them reported.",
        target.display()
    ))
}

/// Start again the services this phase stopped, before it fails closed, so an
/// aborted activation does not leave them down. Best-effort: a failed start is
/// logged and the original error is still returned.
fn restart_stopped_services(
    services: &[String],
    executor: &dyn crate::process::restart::CommandExecutor,
) {
    for service in services {
        let socket = format!("{service}.socket");
        let _ = executor.execute_systemctl(&["start", &socket]);
        if let Err(err) = executor.execute_systemctl(&["start", service]) {
            tracing::warn!(service = %service, error = %err, "could not restart service after aborted phase");
        }
    }
}

/// Classify the blocking processes and act on them: restart the safe ones,
/// apply the risky-service policy, and refuse to signal non-service processes
/// without the operator's opt-in.
///
/// Returns the services stopped (to restart after the mount) and the writers
/// that survived Phase 2 still referencing the target. Returns an error — before
/// any signal is sent — when a non-service process would be signalled and the
/// operator did not opt in via `terminate_processes`, and fails closed when the
/// risky-service policy is `restart` but a risky holder could not be stopped.
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

    // Safety gate: never signal a non-service process (a shell, editor, `tail
    // -f` or detached job) without the operator's opt-in. A signal can lose
    // their work silently, so abort before mounting and before any signal is
    // sent, listing the offenders.
    if !options.terminate_processes {
        let refused: Vec<&ProcessInfo> = to_restart_safe
            .iter()
            .map(|p| (p, RestartStrategy::Safe))
            .chain(to_restart_risky.iter().map(|p| (p, RestartStrategy::Risky)))
            .filter(|(p, strategy)| would_signal(p, *strategy, options, restart_risky))
            .map(|(p, _)| p)
            .collect();

        if !refused.is_empty() {
            let listed = refused
                .iter()
                .map(|p| refused_label(p))
                .collect::<Vec<_>>()
                .join(", ");
            tracing::error!(
                target_path = %target.display(),
                processes = %listed,
                "  ✗ Refusing to signal non-service process(es) on {}: {}",
                target.display(),
                listed
            );
            return Err(signal_refusal(
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
            let results = restart_processes_with_executor(&to_restart_risky, executor)?;
            let mut failed = Vec::new();
            for result in &results {
                if result.stopped_successfully {
                    if let Some(ref svc) = result.info.service_name {
                        stopped_services.push(svc.clone());
                    }
                } else {
                    failed.push(&result.info);
                }
            }
            // The operator chose to restart risky holders; one that could not be
            // stopped would keep writing to the decoy against that choice, so
            // fail closed (bringing back what this phase stopped) rather than
            // carry it on as a survivor.
            if !failed.is_empty() {
                restart_stopped_services(&stopped_services, executor);
                return Err(risky_restart_failure(target, &failed));
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
