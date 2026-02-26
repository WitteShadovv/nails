//! Activation Logic for NailsManager
//!
//! This module implements the 10-step activation flow that:
//! 1. Validates system state
//! 2. Runs preflight checks
//! 3. Handles session management
//! 4. Builds NixOS configuration (if enabled)
//! 5. Mounts overlays with RAII rollback
//! 6. Switches to active NixOS generation
//! 7. Restarts services
//! 8. Updates state to Active
//!
//! # RAII Rollback Pattern
//!
//! The activation process uses StateGuard and MountTracker for automatic
//! rollback on failure, ensuring the system doesn't get left in a partially
//! activated state.

use super::{
    MountInfo, MountTracker, MountType, NailsManager, build_overlay_targets,
    clean_stale_network_config, create_overlay_config, ensure_run_current_system_symlink,
    select_system_profile, start_service_and_socket,
};
use crate::{
    FailedOverlayInfo, Filesystem, NailsError, OverlayInfo, Result, inject_import_block,
    verify_base_config_clean,
};
use chrono::Utc;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

impl<F: Filesystem> NailsManager<F> {
    pub fn activate(manager_arc: Arc<Mutex<Self>>, no_preflight: bool) -> Result<()> {
        // Use default options for backward compatibility with tests
        let options = crate::ActivateOptions::default();
        Self::activate_with_options(manager_arc, options, no_preflight)
    }

    /// Activate overlays with custom activation options
    ///
    /// Extended version of activate() that accepts ActivateOptions for controlling:
    /// - Session management (--kill-session)
    /// - Process restart behavior (risky process prompts)
    /// - Pivot mount policy (--accept-pivot-risks, --no-pivot)
    /// - User interaction (--yes to skip prompts)
    ///
    /// Story 4.15: User Prompts and CLI Flags for Overlay Strategy
    ///
    /// # Arguments
    ///
    /// * `manager_arc` - Shared reference to NailsManager
    /// * `options` - Activation options controlling behavior
    /// * `no_preflight` - Skip pre-flight checks (expert override)
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::{ActivateOptions, NailsManager, MockFilesystem, Config};
    /// use std::path::PathBuf;
    /// use std::sync::{Arc, Mutex};
    ///
    /// let fs = MockFilesystem::new();
    /// let config = Config::default();
    /// let state_path = PathBuf::from("/mnt/hidden-volume/state.json");
    /// let manager = Arc::new(Mutex::new(NailsManager::new(fs, config, state_path)));
    ///
    /// let options = ActivateOptions {
    ///     no_pivot: true,  // Strict security mode
    ///     ..Default::default()
    /// };
    ///
    /// let result = NailsManager::activate_with_options(Arc::clone(&manager), options, false);
    /// ```
    pub fn activate_with_options(
        manager_arc: Arc<Mutex<Self>>,
        options: crate::ActivateOptions,
        no_preflight: bool,
    ) -> Result<()> {
        use crate::{StateGuard, Stopwatch, Verbosity};

        // RAII guard: if we kill the session but exit early with an error,
        // attempt to restart the user manager and display manager.
        struct SessionRestartGuard {
            plan: crate::process::SessionRestartPlan,
            disarmed: bool,
        }

        impl SessionRestartGuard {
            fn new(plan: crate::process::SessionRestartPlan) -> Self {
                Self {
                    plan,
                    disarmed: false,
                }
            }

            /// Prevent the guard from restarting the session (use after a successful restart).
            fn disarm(&mut self) {
                self.disarmed = true;
            }
        }

        impl Drop for SessionRestartGuard {
            fn drop(&mut self) {
                if self.disarmed {
                    return;
                }

                use crate::process::{restart_display_manager, restart_user_manager};

                if let Some(uid) = self.plan.target_uid
                    && let Err(e) = restart_user_manager(uid)
                {
                    tracing::error!(
                        error = %e,
                        uid = uid,
                        "Failed to restart user manager after activation error"
                    );
                }

                if let Some(dm_name) = self.plan.display_manager.take() {
                    if let Err(e) = restart_display_manager(&dm_name) {
                        tracing::error!(
                            error = %e,
                            dm = %dm_name,
                            "Failed to restart display manager after activation error"
                        );
                    } else {
                        tracing::warn!(
                            dm = %dm_name,
                            "Display manager restarted after activation error"
                        );
                    }
                }
            }
        }

        // RAII guard: if we stop nix-daemon for /nix overlay but exit early,
        // restart both socket and service so the system isn't left degraded.
        struct NixDaemonGuard {
            active: bool,
            disarmed: bool,
        }

        impl NixDaemonGuard {
            fn new(active: bool) -> Self {
                Self {
                    active,
                    disarmed: false,
                }
            }
            fn disarm(&mut self) {
                self.disarmed = true;
            }
        }

        impl Drop for NixDaemonGuard {
            fn drop(&mut self) {
                if !self.active || self.disarmed {
                    return;
                }
                start_service_and_socket("nix-daemon");
            }
        }

        let total_timer = Stopwatch::start();

        // Validate options first
        options.validate()?;

        // Step 1: Capture current state and verbosity for progress logging
        let (previous_state, verbosity) = {
            let manager = manager_arc.lock().unwrap();
            (manager.current_state()?, manager.verbosity)
        };

        // Step 2: Idempotent check - if already active, return early (AC: 7)
        if previous_state.is_active() {
            if verbosity >= Verbosity::Normal {
                tracing::info!(state = ?previous_state, "System already active, nothing to do");
            }
            return Ok(());
        }

        // Story 9.3 AC#1: Log activation started with structured state field
        tracing::info!(state_from = ?previous_state, "Activation started");

        // Step 2.5: Handle --kill-session flag (Story 4.15, AC8)
        // Kill graphical session BEFORE pre-flight checks to ensure optimal activation
        // This enables all direct overlay mounts without pivot mount fallback
        let restart_plan = if options.kill_session {
            use crate::process::{
                SessionKind, detect_session_context, kill_graphical_session,
                prompt_session_kill_confirmation,
            };

            if verbosity >= Verbosity::Normal {
                tracing::info!("Detecting session type for --kill-session...");
            }

            let session = detect_session_context()?;

            match session.kind {
                SessionKind::GraphicalUser => {
                    // Prompt for confirmation unless --yes flag
                    if !options.session_kill_confirmed {
                        prompt_session_kill_confirmation(&session, options.yes)?;
                    }

                    if verbosity >= Verbosity::Normal {
                        let dm = session
                            .display_manager
                            .as_deref()
                            .unwrap_or("display-manager");
                        tracing::info!("Killing graphical session ({})", dm);
                    }

                    let kill_result = kill_graphical_session(&session)?;

                    if verbosity >= Verbosity::Verbose {
                        tracing::info!(
                            "  ✓ Session killed: {} processes terminated, {} force-killed",
                            kill_result.fallback_processes_terminated,
                            kill_result.fallback_processes_force_killed
                        );
                    }

                    // Store restart plan for later
                    kill_result.restart_plan.clone()
                }
                SessionKind::Tty => {
                    if verbosity >= Verbosity::Normal {
                        tracing::warn!("--kill-session requested, but running in TTY - skipping");
                    }
                    crate::process::SessionRestartPlan::default()
                }
                SessionKind::Ssh => {
                    if verbosity >= Verbosity::Normal {
                        tracing::warn!(
                            "--kill-session requested over SSH - skipping session termination"
                        );
                    }
                    crate::process::SessionRestartPlan::default()
                }
                SessionKind::GraphicalRoot => {
                    if verbosity >= Verbosity::Normal {
                        tracing::warn!(
                            "Running as root in graphical session - cannot kill session"
                        );
                    }
                    crate::process::SessionRestartPlan::default()
                }
                SessionKind::Unknown => {
                    if verbosity >= Verbosity::Normal {
                        tracing::warn!("Could not detect session type - skipping session kill");
                    }
                    crate::process::SessionRestartPlan::default()
                }
            }
        } else {
            crate::process::SessionRestartPlan::default()
        };

        // Auto-restart session if we exit early with an error after killing it.
        let mut session_restart_guard = SessionRestartGuard::new(restart_plan.clone());

        // Step 2.75: Stage hidden config symlink before pre-flight checks (Story 15.2).
        // This ensures NixOSConfigCheck can validate the staged link.
        {
            let manager = manager_arc.lock().unwrap();
            if let Err(e) = crate::stage_hidden_config_symlink(
                &manager.filesystem,
                &manager.config.hidden_volume_root,
            ) {
                if no_preflight {
                    tracing::warn!(
                        error = %e,
                        "Skipping staged config failure due to --no-preflight (activation may not use hidden config)"
                    );
                } else {
                    tracing::error!(
                        error = %e,
                        "Failed to stage hidden config symlink before pre-flight checks"
                    );
                    return Err(e);
                }
            }
        }

        // Step 3: Run pre-flight checks (unless skipped)
        if no_preflight {
            if verbosity >= Verbosity::Normal {
                tracing::warn!("DANGER: Skipping pre-flight checks. Activation may fail.");
            }
        } else {
            if verbosity >= Verbosity::Normal {
                tracing::info!("Running pre-flight checks...");
            }
            let step_timer = Stopwatch::start();
            // Run checks before creating StateGuard to avoid rollback overhead
            let manager = manager_arc.lock().unwrap();
            manager.run_preflight_checks()?;
            // Drop lock before proceeding
            drop(manager);
            if verbosity >= Verbosity::Normal {
                // AC #1: Pre-flight checks event with duration_ms field
                tracing::info!(
                    duration_ms = step_timer.elapsed().as_millis() as u64,
                    "Pre-flight checks passed"
                );
            }
        }

        // Step 4: Create StateGuard for automatic rollback on failure/panic
        // If we don't call guard.commit(), drop() will rollback to previous_state
        let guard = StateGuard::new(Arc::clone(&manager_arc), previous_state.clone());

        // Step 5: Validate transition is allowed
        let activating_state = previous_state.begin_activation()?;

        // Step 6: Transition to Activating state
        {
            let mut manager = manager_arc.lock().unwrap();
            manager.update_state(activating_state)?;
        }

        // Step 7: Build NixOS profile (if NixOSBuilder configured)
        //
        // Story 15.4: Use fingerprint-based fast path.  We compute a fingerprint of the
        // two NixOS config files that live in the hidden volume.  If the fingerprint
        // matches the one we persisted after the last successful activation, the cached
        // profile is reused and the expensive `nixos-rebuild` invocation is skipped.
        // `new_fingerprint` is carried through to Step 9 so it can be persisted after a
        // successful `switch-to-configuration`.
        let (generation, new_fingerprint) = {
            let manager = manager_arc.lock().unwrap();
            if let Some(ref builder) = manager.nixos_builder {
                if !builder.is_flake() {
                    if verbosity >= Verbosity::Normal {
                        tracing::info!(
                            "Legacy NixOS config detected — deferring nixos-rebuild switch until after /etc overlay"
                        );
                    }

                    // Still compute fingerprint so we can persist it after switch.
                    let hw_path = manager
                        .config
                        .hidden_volume_root
                        .join("etc/nixos/hardware-configuration.nix");
                    let cfg_path = manager
                        .config
                        .hidden_volume_root
                        .join("config/nixos/configuration.nix");

                    let hw_content = match manager.filesystem.read_file_content(&hw_path) {
                        Ok(content) => content,
                        Err(e) => {
                            tracing::warn!(
                                path = %hw_path.display(),
                                error = %e,
                                "Failed to read hardware-configuration.nix for fingerprint, using empty content"
                            );
                            String::new()
                        }
                    };
                    let cfg_content = match manager.filesystem.read_file_content(&cfg_path) {
                        Ok(content) => content,
                        Err(e) => {
                            tracing::warn!(
                                path = %cfg_path.display(),
                                error = %e,
                                "Failed to read configuration.nix for fingerprint, using empty content"
                            );
                            String::new()
                        }
                    };

                    let current_fp =
                        crate::nixos::compute_config_fingerprint(&hw_content, &cfg_content);

                    let (stored_fp, stored_generation) = {
                        let cached = manager.cached_state.lock().unwrap();
                        (
                            cached.as_ref().and_then(|sf| sf.config_fingerprint.clone()),
                            cached.as_ref().and_then(|sf| sf.nixos_generation.clone()),
                        )
                    };

                    // Debug visibility into fast-path decision (Story 15.4)
                    if verbosity >= Verbosity::Normal {
                        tracing::info!(
                            stored_fingerprint = %stored_fp.as_deref().unwrap_or("none"),
                            current_fingerprint = %current_fp,
                            stored_generation = %stored_generation.as_deref().unwrap_or("none"),
                            "Legacy fast-path check"
                        );
                    }

                    let mut fast_path_generation: Option<String> = None;
                    if stored_fp.as_deref() == Some(current_fp.as_str())
                        && let Some(ref generation_id) = stored_generation
                    {
                        if verbosity >= Verbosity::Normal {
                            tracing::info!(
                                generation = %generation_id,
                                "Legacy fast path: fingerprint matches — attempting generation switch"
                            );
                        }
                        fast_path_generation = Some(generation_id.clone());
                    }

                    (fast_path_generation, Some(current_fp))
                } else {
                    if verbosity >= Verbosity::Normal {
                        tracing::info!("Building NixOS profile...");
                    }

                    // --- Story 15.4, AC1: compute config fingerprint ---
                    let hw_path = manager
                        .config
                        .hidden_volume_root
                        .join("etc/nixos/hardware-configuration.nix");
                    let cfg_path = manager
                        .config
                        .hidden_volume_root
                        .join("config/nixos/configuration.nix");

                    // Read config files for fingerprint computation (Story 15.4, AC1)
                    // Log warnings but continue if files are missing - build will fail later if truly required
                    let hw_content = match manager.filesystem.read_file_content(&hw_path) {
                        Ok(content) => content,
                        Err(e) => {
                            tracing::warn!(
                                path = %hw_path.display(),
                                error = %e,
                                "Failed to read hardware-configuration.nix for fingerprint, using empty content"
                            );
                            String::new()
                        }
                    };
                    let cfg_content = match manager.filesystem.read_file_content(&cfg_path) {
                        Ok(content) => content,
                        Err(e) => {
                            tracing::warn!(
                                path = %cfg_path.display(),
                                error = %e,
                                "Failed to read configuration.nix for fingerprint, using empty content"
                            );
                            String::new()
                        }
                    };

                    let current_fp =
                        crate::nixos::compute_config_fingerprint(&hw_content, &cfg_content);

                    // Load stored fingerprint from persisted state (may be None on first run)
                    let stored_fp: Option<String> = {
                        let cached = manager.cached_state.lock().unwrap();
                        cached.as_ref().and_then(|sf| sf.config_fingerprint.clone())
                    };

                    let step_timer = Stopwatch::start();

                    // --- Story 15.4, AC2/AC3: fast-path decision ---
                    // Story 15.5: when build is required, build_profile_with_fingerprint() delegates
                    // to build_profile_missing_only() which reuses the existing store path when
                    // available, and always passes --no-update-lock-file to avoid package updates.
                    let (generation_id, fp_out, fast_path_used) = builder
                        .build_profile_with_fingerprint(&current_fp, stored_fp.as_deref())
                        .map_err(|e| {
                            // Story 9.3 AC#2: Structured error event for NixOS build failure
                            let error_msg = match &e {
                                NailsError::NixOSError(msg) => {
                                    format!("NixOS build failed: {}", msg)
                                }
                                other => format!("NixOS build failed: {}", other),
                            };

                            tracing::error!(
                                error = %e,
                                phase = "nixos_build",
                                rollback = true,
                                "NixOS profile build failed"
                            );

                            match e {
                                NailsError::NixOSError(_) => NailsError::NixOSError(error_msg),
                                other => other,
                            }
                        })?;

                    if verbosity >= Verbosity::Normal {
                        if fast_path_used {
                            tracing::info!(
                                step = "nixos_build",
                                duration_ms = step_timer.elapsed().as_millis() as u64,
                                generation = generation_id,
                                "NixOS profile ready (fast path): generation {} ({})",
                                generation_id,
                                step_timer
                            );
                        } else {
                            tracing::info!(
                                step = "nixos_build",
                                duration_ms = step_timer.elapsed().as_millis() as u64,
                                generation = generation_id,
                                "✓ NixOS profile ready: generation {} ({})",
                                generation_id,
                                step_timer
                            );
                        }
                    }
                    (Some(generation_id), Some(fp_out))
                }
            } else {
                (None, None)
            }
        };

        // Step 8: Mount persistent overlays with incremental state tracking (Story 4.7, AC1, AC2, Task 4)
        // Mount order is critical: /home first (no dependencies), /etc second (may depend on /home)
        // See MOUNT_ORDER constant for rationale (Story 4.6, AC1)

        // TODO(story-4-5): Integrate prepare_nixos_config_overlay() before mounting /etc overlay
        //
        // Story 4.12, Task 4 (DEFERRED): Before mounting /etc overlay, validate and prepare
        // the NixOS configuration overlay structure by calling:
        //
        //   use crate::prepare_nixos_config_overlay;
        //   let info = prepare_nixos_config_overlay(&fs, &hidden_path)?;
        //
        // This ensures the hidden storage contains the required NixOS config structure:
        // - {hidden}/etc/nixos/hardware-configuration.nix (modified with hidden import)
        // - {hidden}/config/nixos/configuration.nix (hidden environment config)
        //
        // The /etc overlay must include the hidden nixos/ directory to make the modified
        // hardware-configuration.nix visible to the system.
        //
        // See: docs/sprint-artifacts/4-12-implement-nixos-hardware-configuration-nix-overlay-mechanism.md
        //
        // TODO(story-4-5): Write integration tests for full activation/deactivation cycle
        //
        // Story 4.12, Task 9 (DEFERRED): After integration is complete, add tests that verify:
        // - Full activation shows modified config with hidden import
        // - Full deactivation reverts to base config (no hidden import)
        // - Simulated NixOS rebuild reads correct config in both states
        // - No forensic traces remain after deactivation
        //
        // These tests require the NailsManager integration from Task 4 above.

        // Story 15.1, AC1: Verify base hardware-configuration.nix is forensically clean before
        // any overlays are mounted. Fail activation if the base config already contains
        // NAILS or hidden references that would betray the overlay approach.
        {
            let manager = manager_arc.lock().unwrap();
            match verify_base_config_clean(&manager.filesystem) {
                Ok(true) => {
                    tracing::debug!("Base hardware-configuration.nix is clean — proceeding");
                }
                Ok(false) => {
                    tracing::error!(
                        "Base /etc/nixos/hardware-configuration.nix contains suspicious references \
                         (NAILS or hidden paths). Activation aborted to preserve forensic integrity."
                    );
                    return Err(NailsError::NixOSError(
                        "Base hardware-configuration.nix is not forensically clean — \
                         contains NAILS or hidden references before overlay mount"
                            .into(),
                    ));
                }
                Err(e) => {
                    // Treat unreadable base config as a hard failure to avoid unsafe activation.
                    tracing::error!(
                        error = %e,
                        "Could not verify base hardware-configuration.nix; activation aborted"
                    );
                    return Err(e);
                }
            }
        }

        if verbosity >= Verbosity::Normal {
            tracing::info!("Mounting overlays...");
        }
        let mount_timer = Stopwatch::start();

        // Create shared tracker for both persistent and ephemeral overlays (Story 4.11)
        // Tracker will be committed only after full activation succeeds.
        let manager = manager_arc.lock().unwrap();
        let fs = manager.filesystem.clone();
        let mut tracker = MountTracker::new(&fs);

        // Build OverlayStrategyOptions from ActivateOptions (Story 4.15, AC8)
        let strategy_options = crate::overlay::OverlayStrategyOptions {
            auto_restart_safe: true,        // Always restart safe processes automatically
            prompt_for_risky: !options.yes, // Skip risky prompts if --yes flag
            allow_pivot: !options.no_pivot, // Respect --no-pivot flag
            auto_accept_pivot: options.accept_pivot_risks, // Auto-accept if --accept-pivot-risks
            skip_process_detection: options
                .skip_process_detection_override
                .unwrap_or(cfg!(test)), // Allow tests to override
        };

        // Track mount methods for logging
        let mut direct_mounts = 0;
        let mut pivot_mounts = 0;

        // Step 8a: Mount persistent overlays using universal algorithm (Story 4.15)
        // Story 14.10: Use dynamic target list based on overlay_mode
        match manager.config.overlay_mode {
            crate::OverlayMode::Auto => {
                // Auto mode: enumerate root + apply exclusions, create overlays dynamically
                let overlay_targets = build_overlay_targets(&manager.filesystem, &manager.config)?;

                // Pre-overlay: stop nix-daemon if /nix will be overlaid
                // Must happen BEFORE Phase 1 detection so nix-daemon doesn't appear
                // in the blocking process list with its mount namespace references.
                let nix_in_targets = overlay_targets.iter().any(|t| t == Path::new("/nix"));
                let mut nix_guard = NixDaemonGuard::new(nix_in_targets);
                if nix_in_targets {
                    tracing::info!("Stopping nix-daemon before /nix overlay...");
                    // Stop socket first (prevents socket-activation restart)
                    let _ = std::process::Command::new("systemctl")
                        .args(["stop", "nix-daemon.socket"])
                        .output();
                    let _ = std::process::Command::new("systemctl")
                        .args(["stop", "nix-daemon.service"])
                        .output();
                }

                // Track mount failures for best-effort mounting (Story 14.10, Task 8)
                let mut mount_failures: Vec<(PathBuf, NailsError)> = Vec::new();
                let mut nix_overlay_succeeded = false;

                for target in overlay_targets {
                    // Create overlay config on-the-fly (Story 14.10, Task 6)
                    let overlay = match create_overlay_config(
                        &manager.filesystem,
                        &target,
                        &manager.config.hidden_volume_root,
                    ) {
                        Ok(config) => config,
                        Err(e) => {
                            // Best-effort: log warning, track failure, continue with next overlay
                            tracing::warn!(
                                target = %target.display(),
                                error = %e,
                                "⚠ Could not create overlay config for {}: {}",
                                target.display(),
                                e
                            );
                            mount_failures.push((target.clone(), e));
                            continue;
                        }
                    };

                    // Task 6: DNS preservation - clean stale network config before mounting /etc
                    if target == Path::new("/etc")
                        && let Err(e) =
                            clean_stale_network_config(&overlay.upper, &manager.filesystem)
                    {
                        tracing::warn!(
                            error = %e,
                            "Failed to clean stale network config from /etc upper layer: {}",
                            e
                        );
                        // Continue anyway - this is best-effort
                    }

                    // Use universal overlay mounting algorithm (Story 4.15, AC8)
                    match crate::overlay::mount_overlay_with_strategy(
                        &manager.filesystem,
                        &overlay.lower,
                        &overlay.upper,
                        &overlay.work,
                        &overlay.target,
                        &strategy_options,
                    ) {
                        Ok(mount_result) => {
                            use crate::overlay::MountMethod;

                            // Track mount type for logging
                            match mount_result.method {
                                MountMethod::Direct => {
                                    direct_mounts += 1;
                                    if verbosity >= Verbosity::Verbose {
                                        tracing::info!(
                                            "  ✓ {} mounted (direct, optimal security)",
                                            overlay.target.display()
                                        );
                                    }
                                }
                                MountMethod::Pivot => {
                                    pivot_mounts += 1;
                                    if verbosity >= Verbosity::Verbose {
                                        tracing::warn!(
                                            "  ⚠️  {} mounted (pivot, degraded security)",
                                            overlay.target.display()
                                        );
                                    }
                                }
                            }

                            // Post-mount: restart stopped services so they write to overlay
                            for service in &mount_result.stopped_services {
                                start_service_and_socket(service);
                                tracing::info!(
                                    service = %service,
                                    target = %overlay.target.display(),
                                    "Restarted {} (now writing to overlay)", service
                                );
                            }

                            // Track if /nix overlay succeeded for post-mount lifecycle
                            if overlay.target == Path::new("/nix") {
                                nix_overlay_succeeded = true;
                            }

                            // After /var overlay is mounted, unconditionally restart systemd-journald
                            // to ensure all logs are written to the overlay (prevents underlay leakage)
                            if overlay.target == Path::new("/var") {
                                start_service_and_socket("systemd-journald");
                                tracing::info!(
                                    "Restarted systemd-journald after /var overlay mount (prevents log leakage)"
                                );
                            }

                            tracker.push_mount(MountInfo::persistent(overlay.target.clone()));

                            // Story 15.1, AC2/AC4: After /etc overlay is mounted, inject the
                            // NAILS import block into the overlayed hardware-configuration.nix.
                            // Writes land in the upper layer — the base underlay is untouched (AC3).
                            if overlay.target == Path::new("/etc")
                                && let Err(e) = inject_import_block(&manager.filesystem)
                            {
                                tracing::error!(
                                    error = %e,
                                    rollback = true,
                                    "Failed to inject NAILS import block into /etc/nixos/hardware-configuration.nix: {}",
                                    e
                                );
                                if let Err(rollback_err) = tracker.rollback_all() {
                                    tracing::error!(
                                        error = %rollback_err,
                                        context = "inject_import_block_failure",
                                        rollback = true,
                                        "Rollback failed after inject_import_block failure"
                                    );
                                }
                                return Err(e);
                            }

                            // Story 4.7, AC2, Task 4: Update overlay_status incrementally after EACH mount
                            let overlay_info = OverlayInfo {
                                mount_path: overlay.target.clone(),
                                lower_dir: overlay.lower.clone(),
                                upper_dir: overlay.upper.clone(),
                                work_dir: overlay.work.clone(),
                                mounted_at: Utc::now(),
                            };

                            // Update cached state with this mount
                            let mut cached = manager.cached_state.lock().unwrap();
                            if let Some(ref mut state_file) = *cached {
                                state_file
                                    .overlay_status
                                    .insert(overlay.target.clone(), overlay_info);

                                drop(cached); // Release lock before saving
                                if let Err(e) = manager.save_cached_state()
                                    && verbosity >= Verbosity::Debug
                                {
                                    tracing::warn!("Failed to save state after mount: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            // Story 14.10, Task 8: Best-effort mounting
                            tracing::warn!(
                                error = %e,
                                target = %overlay.target.display(),
                                "⚠ Could not overlay {}: {}",
                                overlay.target.display(),
                                e
                            );
                            mount_failures.push((overlay.target.clone(), e));
                            continue;
                        }
                    }
                }

                // If ALL overlays failed, rollback and return error
                if tracker.mounted.is_empty() && !mount_failures.is_empty() {
                    tracing::error!(
                        failure_count = mount_failures.len(),
                        "All overlay mounts failed - activation aborted"
                    );

                    if let Err(rollback_err) = tracker.rollback_all() {
                        tracing::error!(
                            error = %rollback_err,
                            context = "mount_failure_recovery",
                            rollback = true,
                            "Rollback failed during mount failure recovery"
                        );
                    }

                    // Return first failure as representative error
                    return Err(mount_failures.into_iter().next().unwrap().1);
                }

                // Story 14.10, AC9: Record failed overlays in state for status reporting
                if !mount_failures.is_empty() {
                    let failed_infos: Vec<FailedOverlayInfo> = mount_failures
                        .iter()
                        .map(|(path, error)| FailedOverlayInfo {
                            target: path.clone(),
                            error_message: error.to_string(),
                            failed_at: Utc::now(),
                        })
                        .collect();

                    tracing::warn!(
                        failed_count = failed_infos.len(),
                        "Recording {} failed overlay(s) in state for status reporting",
                        failed_infos.len()
                    );

                    let mut cached = manager.cached_state.lock().unwrap();
                    if let Some(ref mut state_file) = *cached {
                        state_file.failed_overlays = failed_infos;
                        drop(cached);
                        if let Err(e) = manager.save_cached_state()
                            && verbosity >= Verbosity::Debug
                        {
                            tracing::warn!("Failed to save failed_overlays to state: {}", e);
                        }
                    }
                }

                // Any failure should abort activation to avoid partially-active state.
                if !mount_failures.is_empty() {
                    return Err(NailsError::InvalidState(format!(
                        "{} overlay(s) failed to mount",
                        mount_failures.len()
                    )));
                }

                // Post-overlay: if /nix was successfully overlaid, restore NixOS security model
                if nix_overlay_succeeded {
                    // Step 1: Recreate read-only bind mount on /nix/store
                    // The overlay on /nix hides the boot-time bind mount; we recreate it
                    // so regular processes see /nix/store as read-only (defense-in-depth)
                    tracing::info!("Restoring read-only bind mount on /nix/store...");
                    let nix_store = Path::new("/nix/store");
                    if let Err(e) = manager.filesystem.bind_mount(nix_store, nix_store) {
                        tracing::warn!(
                            error = %e,
                            "Could not recreate /nix/store bind mount (non-fatal)"
                        );
                    } else {
                        // Remount as read-only (uses Command since Filesystem trait lacks remount_readonly)
                        let remount_result = std::process::Command::new("mount")
                            .args(["-o", "remount,ro,bind", "/nix/store"])
                            .output();
                        match remount_result {
                            Ok(output) if output.status.success() => {
                                tracing::info!("Read-only bind mount on /nix/store restored");
                            }
                            Ok(output) => {
                                tracing::warn!(
                                    stderr = %String::from_utf8_lossy(&output.stderr),
                                    "Remount /nix/store as read-only failed (non-fatal)"
                                );
                            }
                            Err(e) => {
                                tracing::warn!(
                                    error = %e,
                                    "Remount /nix/store command failed (non-fatal)"
                                );
                            }
                        }
                    }

                    // Step 2: Restart nix-daemon (inherits overlay, creates own rw namespace)
                    tracing::info!("Restarting nix-daemon (now writing to overlay)...");
                    start_service_and_socket("nix-daemon");
                    nix_guard.disarm();
                }
            }
            crate::OverlayMode::Explicit => {
                // Explicit mode: use pre-configured overlays (legacy behavior)
                // Security check: fail if no overlays configured (would leave system unprotected)
                if manager.config.overlays.is_empty() {
                    return Err(NailsError::ConfigError(
                        "Explicit mode configured but no overlays defined - system would have NO forensic protection. \
                         Add overlays to config or switch to overlay_mode: auto".to_string()
                    ));
                }

                let critical = [Path::new("/bin"), Path::new("/usr")];
                for overlay in &manager.config.overlays {
                    if critical.contains(&overlay.target.as_path()) {
                        return Err(NailsError::InvalidState(format!(
                            "Overlaying critical system root {} is blocked for safety",
                            overlay.target.display()
                        )));
                    }
                }

                for overlay in &manager.config.overlays {
                    // Task 6: DNS preservation - clean stale network config before mounting /etc
                    if overlay.target == Path::new("/etc")
                        && let Err(e) =
                            clean_stale_network_config(&overlay.upper, &manager.filesystem)
                    {
                        tracing::warn!(
                            error = %e,
                            "Failed to clean stale network config from /etc upper layer: {}",
                            e
                        );
                        // Continue anyway - this is best-effort
                    }

                    // Use universal overlay mounting algorithm (Story 4.15, AC8)
                    match crate::overlay::mount_overlay_with_strategy(
                        &manager.filesystem,
                        &overlay.lower,
                        &overlay.upper,
                        &overlay.work,
                        &overlay.target,
                        &strategy_options,
                    ) {
                        Ok(mount_result) => {
                            use crate::overlay::MountMethod;

                            // Track mount type for logging
                            match mount_result.method {
                                MountMethod::Direct => {
                                    direct_mounts += 1;
                                    if verbosity >= Verbosity::Verbose {
                                        tracing::info!(
                                            "  ✓ {} mounted (direct, optimal security)",
                                            overlay.target.display()
                                        );
                                    }
                                }
                                MountMethod::Pivot => {
                                    pivot_mounts += 1;
                                    if verbosity >= Verbosity::Verbose {
                                        tracing::warn!(
                                            "  ⚠️  {} mounted (pivot, degraded security)",
                                            overlay.target.display()
                                        );
                                    }
                                }
                            }

                            // Post-mount: restart stopped services so they write to overlay
                            for service in &mount_result.stopped_services {
                                start_service_and_socket(service);
                                tracing::info!(
                                    service = %service,
                                    target = %overlay.target.display(),
                                    "Restarted {} (now writing to overlay)", service
                                );
                            }

                            // After /var overlay is mounted, unconditionally restart systemd-journald
                            // to ensure all logs are written to the overlay (prevents underlay leakage)
                            if overlay.target == Path::new("/var") {
                                start_service_and_socket("systemd-journald");
                                tracing::info!(
                                    "Restarted systemd-journald after /var overlay mount (prevents log leakage)"
                                );
                            }

                            tracker.push_mount(MountInfo::persistent(overlay.target.clone()));

                            // Story 15.1, AC2/AC4: After /etc overlay is mounted, inject the
                            // NAILS import block into the overlayed hardware-configuration.nix.
                            // Writes land in the upper layer — the base underlay is untouched (AC3).
                            if overlay.target == Path::new("/etc")
                                && let Err(e) = inject_import_block(&manager.filesystem)
                            {
                                tracing::error!(
                                    error = %e,
                                    rollback = true,
                                    "Failed to inject NAILS import block into /etc/nixos/hardware-configuration.nix: {}",
                                    e
                                );
                                if let Err(rollback_err) = tracker.rollback_all() {
                                    tracing::error!(
                                        error = %rollback_err,
                                        context = "inject_import_block_failure",
                                        rollback = true,
                                        "Rollback failed after inject_import_block failure"
                                    );
                                }
                                return Err(e);
                            }

                            // Story 4.7, AC2, Task 4: Update overlay_status incrementally after EACH mount
                            let overlay_info = OverlayInfo {
                                mount_path: overlay.target.clone(),
                                lower_dir: overlay.lower.clone(),
                                upper_dir: overlay.upper.clone(),
                                work_dir: overlay.work.clone(),
                                mounted_at: Utc::now(),
                            };

                            // Update cached state with this mount
                            let mut cached = manager.cached_state.lock().unwrap();
                            if let Some(ref mut state_file) = *cached {
                                state_file
                                    .overlay_status
                                    .insert(overlay.target.clone(), overlay_info);

                                drop(cached); // Release lock before saving
                                if let Err(e) = manager.save_cached_state()
                                    && verbosity >= Verbosity::Debug
                                {
                                    tracing::warn!("Failed to save state after mount: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            // Explicit mode: fail fast on mount errors (original behavior)
                            tracing::error!(
                                error = %e,
                                target = %overlay.target.display(),
                                rollback = true,
                                "Overlay mount failed"
                            );

                            if let Err(rollback_err) = tracker.rollback_all() {
                                tracing::error!(
                                    error = %rollback_err,
                                    context = "mount_failure_recovery",
                                    rollback = true,
                                    "Rollback failed during mount failure recovery"
                                );
                            }
                            return Err(e);
                        }
                    }
                }
            }
        }

        // Extract persistent overlay paths for state file (before mounting ephemeral)
        let mounted_overlays: Vec<PathBuf> = tracker
            .mounted
            .iter()
            .filter(|info| info.mount_type == MountType::Persistent)
            .map(|info| info.target.clone())
            .collect();

        // Step 8b: Mount ephemeral overlays (/var, /tmp, /srv, /opt) - Story 4.11
        // These are RAM-backed and NOT tracked in state file (ephemeral = destroyed on unmount)
        if manager.config.extended_overlays.enabled {
            if verbosity >= Verbosity::Verbose {
                tracing::info!("Mounting ephemeral overlays...");
            }

            for ephemeral_dir in &manager.config.extended_overlays.directories {
                if verbosity >= Verbosity::Debug {
                    tracing::debug!(
                        "Mounting ephemeral overlay: {} (upper: {}, work: {})",
                        ephemeral_dir.path.display(),
                        ephemeral_dir.tmpfs_upper_size,
                        ephemeral_dir.tmpfs_work_size
                    );
                }

                // Use pivot_ephemeral_mount for active directories (Story 4.11)
                // Direct mount fails with EINVAL on busy directories like /var
                // Pivot strategy: mount to staging → bind mount to target
                match crate::overlay::pivot_ephemeral_mount(
                    &manager.filesystem,
                    ephemeral_dir,
                    &ephemeral_dir.path,
                ) {
                    Ok(mount_info) => {
                        // Track pivot mount with staging + tmpfs paths for rollback
                        // Note: staging path is also needed for proper unmount
                        tracker.push_mount(MountInfo::ephemeral(
                            mount_info.target.clone(),
                            vec![
                                mount_info.staging.clone(), // staging (overlay mount point)
                                mount_info.upper.clone(),   // tmpfs upper
                                mount_info.work.clone(),    // tmpfs work
                            ],
                        ));

                        if verbosity >= Verbosity::Verbose {
                            tracing::info!(
                                "  ✓ {} mounted (ephemeral, RAM-backed)",
                                ephemeral_dir.path.display()
                            );
                        }
                    }
                    Err(e) => {
                        // Story 9.3 AC#2: Structured error event for ephemeral mount failure
                        tracing::error!(
                            error = %e,
                            target = %ephemeral_dir.path.display(),
                            mount_type = "ephemeral",
                            rollback = true,
                            "Ephemeral overlay mount failed"
                        );

                        // Rollback all mounts (persistent + any ephemeral that succeeded)
                        if let Err(rollback_err) = tracker.rollback_all() {
                            tracing::error!(
                                error = %rollback_err,
                                context = "ephemeral_mount_failure_recovery",
                                rollback = true,
                                "Rollback failed during ephemeral mount failure recovery"
                            );
                        }
                        return Err(e);
                    }
                }
            }
        }

        // Story 9.3 AC#1: Log overlays mounted with structured fields
        let mounted_paths: Vec<_> = tracker
            .mounted
            .iter()
            .map(|info| info.target.clone())
            .collect();
        tracing::info!(overlays = ?mounted_paths, "Overlays mounted");

        // Release manager lock before continuing
        drop(manager);

        if verbosity >= Verbosity::Normal {
            let security_status = if pivot_mounts == 0 {
                "OPTIMAL"
            } else {
                "DEGRADED"
            };

            tracing::info!(
                step = "mount_overlays",
                duration_ms = mount_timer.elapsed().as_millis() as u64,
                direct_mounts = direct_mounts,
                pivot_mounts = pivot_mounts,
                "✓ All overlays mounted ({}) - {} direct, {} pivot - Security: {}",
                mount_timer,
                direct_mounts,
                pivot_mounts,
                security_status
            );
        }

        // Step 8.5: Restart display manager BEFORE NixOS switch for better UX
        // This allows the user to log back in immediately while nixos-rebuild runs
        // Note: We skip restarting user manager here - it will start automatically when user logs in
        if restart_plan.display_manager.is_some() {
            use crate::process::restart_display_manager;

            if let Some(ref dm_name) = restart_plan.display_manager {
                if verbosity >= Verbosity::Normal {
                    tracing::info!("Restarting display manager ({})...", dm_name);
                }

                restart_display_manager(dm_name)?;

                if verbosity >= Verbosity::Normal {
                    tracing::info!("  ✓ Display manager restarted - login screen should appear");
                    tracing::info!("  ℹ NixOS rebuild will continue in background...");
                    tracing::info!("  ℹ User manager will start automatically when you log in");
                }
            }

            session_restart_guard.disarm();
        }

        // Step 9: Switch NixOS profile and update nixos_generation (Story 4.7, AC3, Task 3.3)
        {
            let manager = manager_arc.lock().unwrap();
            if let Some(ref builder) = manager.nixos_builder {
                if builder.is_flake() {
                    if let Some(ref generation_id) = generation {
                        if verbosity >= Verbosity::Normal {
                            tracing::info!("Switching to hidden NixOS configuration...");
                        }
                        if let Some(system_profile) = select_system_profile(&manager.filesystem)? {
                            ensure_run_current_system_symlink(
                                &manager.filesystem,
                                &system_profile,
                            )
                            .map_err(|e| {
                                NailsError::NixOSError(format!(
                                    "Failed to prepare /run/current-system for NixOS switch: {}",
                                    e
                                ))
                            })?;
                        }
                        let step_timer = Stopwatch::start();
                        // Use "test" action to avoid updating bootloader (keeps /boot pristine)
                        builder.switch_profile(generation_id, "test").map_err(|e| {
                            // Story 9.3 AC#2: Structured error event for NixOS switch failure
                            let error_msg = match &e {
                                NailsError::NixOSError(msg) => {
                                    format!("NixOS switch failed: {}", msg)
                                }
                                other => format!("NixOS switch failed: {}", other),
                            };

                            tracing::error!(
                                error = %e,
                                generation = generation_id,
                                phase = "nixos_switch",
                                rollback = true,
                                "NixOS profile switch failed"
                            );

                            match e {
                                NailsError::NixOSError(_) => NailsError::NixOSError(error_msg),
                                other => other,
                            }
                        })?;
                        if verbosity >= Verbosity::Normal {
                            tracing::info!(
                                step = "nixos_switch",
                                duration_ms = step_timer.elapsed().as_millis() as u64,
                                "✓ NixOS profile switched ({})",
                                step_timer
                            );
                        }

                        // Story 4.7, AC3: Update nixos_generation in state file after successful switch
                        // Story 15.4, AC4: Persist config_fingerprint so fast path works on next activation
                        let mut cached = manager.cached_state.lock().unwrap();
                        if let Some(ref mut state_file) = *cached {
                            state_file.nixos_generation = Some(generation_id.clone());
                            state_file.config_fingerprint = new_fingerprint.clone();

                            // Save state file to disk (AC1, AC3)
                            // State save failures here are non-critical - the switch succeeded and the system is functional.
                            // The final ACTIVE transition save will persist this data. This incremental save aids crash recovery.
                            drop(cached); // Release lock before saving
                            if let Err(e) = manager.save_cached_state()
                                && verbosity >= Verbosity::Debug
                            {
                                tracing::warn!("Failed to save nixos_generation to state: {}", e);
                            }
                            // Continue - switch succeeded, state save is for tracking/crash recovery only
                        }
                    }
                } else {
                    if verbosity >= Verbosity::Normal {
                        tracing::info!("Switching to hidden NixOS configuration...");
                    }
                    if let Some(system_profile) = select_system_profile(&manager.filesystem)? {
                        ensure_run_current_system_symlink(&manager.filesystem, &system_profile)
                            .map_err(|e| {
                                NailsError::NixOSError(format!(
                                    "Failed to prepare /run/current-system for NixOS switch: {}",
                                    e
                                ))
                            })?;
                    }
                    let step_timer = Stopwatch::start();
                    if let Some(ref generation_id) = generation {
                        // Use "test" action to avoid updating bootloader (keeps /boot pristine)
                        if let Err(e) = builder.switch_system_generation(generation_id, "test") {
                            if verbosity >= Verbosity::Normal {
                                tracing::warn!(
                                    error = %e,
                                    generation = generation_id,
                                    "Legacy fast-path switch failed, falling back to nixos-rebuild"
                                );
                            }

                            // Use "test" action to avoid updating bootloader (keeps /boot pristine)
                            builder.switch_profile("", "test").map_err(|e| {
                                let error_msg = match &e {
                                    NailsError::NixOSError(msg) => {
                                        format!("Legacy NixOS switch failed: {}", msg)
                                    }
                                    other => format!("Legacy NixOS switch failed: {}", other),
                                };

                                tracing::error!(
                                    error = %e,
                                    phase = "nixos_switch",
                                    rollback = true,
                                    "Legacy NixOS switch failed"
                                );

                                match e {
                                    NailsError::NixOSError(_) => NailsError::NixOSError(error_msg),
                                    other => other,
                                }
                            })?;
                        }
                    } else {
                        // Use "test" action to avoid updating bootloader (keeps /boot pristine)
                        builder.switch_profile("", "test").map_err(|e| {
                            let error_msg = match &e {
                                NailsError::NixOSError(msg) => {
                                    format!("Legacy NixOS switch failed: {}", msg)
                                }
                                other => format!("Legacy NixOS switch failed: {}", other),
                            };

                            tracing::error!(
                                error = %e,
                                phase = "nixos_switch",
                                rollback = true,
                                "Legacy NixOS switch failed"
                            );

                            match e {
                                NailsError::NixOSError(_) => NailsError::NixOSError(error_msg),
                                other => other,
                            }
                        })?;
                    }
                    if verbosity >= Verbosity::Normal {
                        tracing::info!(
                            step = "nixos_switch",
                            duration_ms = step_timer.elapsed().as_millis() as u64,
                            "✓ Legacy NixOS switch complete ({})",
                            step_timer
                        );
                    }

                    let mut cached = manager.cached_state.lock().unwrap();
                    if let Some(ref mut state_file) = *cached {
                        if let Some(ref generation_id) = generation {
                            state_file.nixos_generation = Some(generation_id.clone());
                        } else if let Ok(current_gen) = builder.current_system_generation() {
                            state_file.nixos_generation = current_gen;
                        }
                        state_file.config_fingerprint = new_fingerprint.clone();

                        drop(cached);
                        if let Err(e) = manager.save_cached_state()
                            && verbosity >= Verbosity::Debug
                        {
                            tracing::warn!("Failed to save nixos_generation to state: {}", e);
                        }
                    }
                }
            }
        }

        // Step 10: Transition to Active state (Story 4.7, AC1, Task 3.4)
        {
            let mut manager = manager_arc.lock().unwrap();
            let current = manager.current_state()?;
            let active_state = current.complete_activation(mounted_overlays)?;
            // update_state() saves to disk automatically (line 675)
            manager.update_state(active_state)?;
        }

        // Note: User session already restarted in Step 8.5 (before NixOS switch)
        // This allows user to log in while nixos-rebuild runs

        // Commit tracker to prevent automatic rollback on drop now that activation is successful.
        tracker.commit();

        // Step 11: Success - commit guard to prevent rollback
        guard.commit();

        // Story 9.3 AC#1: Log activation complete with state transition and duration
        let final_state = {
            let manager = manager_arc.lock().unwrap();
            manager.current_state().ok()
        };

        // Always show completion message, even in Quiet mode (AC: 3)
        if verbosity >= Verbosity::Quiet {
            tracing::info!(
                step = "activation_complete",
                duration_ms = total_timer.elapsed().as_millis() as u64,
                state_to = ?final_state,
                "✓ Activation complete in {}",
                total_timer
            );
        }
        Ok(())
    }
}
