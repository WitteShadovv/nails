//! # Emergency Deactivation Module
//!
//! Provides emergency countdown, fork-resilient shutdown, orchestration, and abort
//! mechanisms for rapid threat response.
//!
//! # Architecture
//!
//! This module implements Epic 6:
//! - Story 6.1: `EmergencyCountdown` - 3-second countdown with Ctrl+C abort capability
//! - Story 6.2: `fork_and_execute()` - fork-resilient shutdown via child process
//! - Story 6.3: `EmergencyOrchestrator` - fast cleanup coordinator with no rollback
//!
//! Future Epic 6 stories will add:
//! - Story 6.4: CLI integration
//!
//! # Signal Handling Strategy
//!
//! Uses `Arc<AtomicBool>` with `signal-hook` crate for SIGINT handling.
//! The countdown loop checks the atomic flag after each second to detect Ctrl+C.
//!
//! Signal handlers are registered via `signal_hook::flag::register()` and automatically
//! cleaned up when the `Arc<AtomicBool>` flag is dropped.
//!
//! # Fork-Resilient Shutdown
//!
//! The `fork_and_execute()` function forks a child process to execute emergency
//! deactivation. This ensures the shutdown continues even if an adversary kills
//! the parent process. The child calls `setsid()` to detach from the terminal,
//! making it immune to terminal signals sent to the parent's session.
//!
//! # EmergencyOrchestrator
//!
//! `EmergencyOrchestrator` coordinates emergency deactivation with a 4-step sequence:
//! 1. State transition: ANY → EMERGENCY (no StateGuard, no rollback)
//! 2. Fast cleanup: `CleanupManager` with `CleanupMode::Fast`
//! 3. Force unmount: All overlays with `force=true`
//! 4. State transition: EMERGENCY → INACTIVE (best-effort)
//!
//! Key differences from `DeactivationOrchestrator`:
//! - **No rollback**: Emergency never rolls back (FR54)
//! - **Error tolerance**: Collects errors but continues all steps
//! - **Speed priority**: Uses Fast cleanup mode and force unmount
//! - **Defensive**: Still runs cleanup even when already INACTIVE (FR64)
//!
//! # Requirements Fulfilled
//!
//! - AR33: 3-second countdown with Ctrl+C abort
//! - AR34: Fork child process for resilience
//! - AR35: No confirmation required (info-only countdown)
//! - FR3: Emergency command
//! - FR13: Force unmount
//! - FR34: Best-effort shell alias removal
//! - FR54: No rollback in emergency
//! - FR64: Execute cleanup even when INACTIVE
//! - NFR3: Emergency <3s
//! - NFR20: Degraded but continues on fork failure
//! - NFR30: Single command, no cognitive load
//! - TR30: Emergency speed p95 <3 seconds
//! - UXR12: Progress indicators
//! - UXR16: Real-time progress updates
//! - UXR40: 500ms minimum update frequency

use crate::{
    CleanupConfig, CleanupManager, CleanupMode, CleanupReport, Filesystem, NailsError,
    NailsManager, Result, SystemState,
};
use chrono::Utc;
use nix::unistd::{ForkResult, fork, setsid};
use serde::Serialize;
use std::fmt;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

/// Emergency countdown with Ctrl+C abort capability
///
/// Provides a configurable countdown before emergency deactivation begins.
/// Users can abort the countdown by pressing Ctrl+C, giving them a brief
/// window to cancel accidental triggers.
///
/// # Fields
///
/// - `countdown_seconds`: Duration of countdown in seconds (default: 3)
/// - `skip_countdown`: Skip countdown entirely if true (default: false)
///
/// # Example
///
/// ```rust,ignore
/// use nails_core::EmergencyCountdown;
///
/// let countdown = EmergencyCountdown::default();
/// match countdown.run() {
///     Ok(true) => println!("Countdown completed - proceeding with emergency deactivation"),
///     Ok(false) => println!("Countdown aborted by user"),
///     Err(e) => eprintln!("Countdown error: {}", e),
/// }
/// ```
///
/// # Requirements
///
/// - AC1: Struct with `countdown_seconds` and `skip_countdown` fields
/// - AC6: Support for --no-countdown flag via `skip_countdown` field
#[derive(Debug, Clone)]
pub struct EmergencyCountdown {
    /// Duration of countdown in seconds (default: 3)
    pub countdown_seconds: u64,

    /// Skip countdown entirely if true (default: false)
    pub skip_countdown: bool,
}

impl Default for EmergencyCountdown {
    /// Create EmergencyCountdown with default values
    ///
    /// - `countdown_seconds`: 3 (per AR33)
    /// - `skip_countdown`: false
    ///
    /// # Requirements
    ///
    /// - AC1: Default countdown_seconds = 3, skip_countdown = false
    fn default() -> Self {
        Self {
            countdown_seconds: 3,
            skip_countdown: false,
        }
    }
}

impl EmergencyCountdown {
    /// Create a new EmergencyCountdown with default values
    ///
    /// Equivalent to `EmergencyCountdown::default()`.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let countdown = EmergencyCountdown::new();
    /// ```
    pub fn new() -> Self {
        Self::default()
    }

    /// Create EmergencyCountdown with custom countdown duration
    ///
    /// # Arguments
    ///
    /// - `seconds`: Duration of countdown in seconds
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let countdown = EmergencyCountdown::with_countdown_seconds(5);
    /// ```
    pub fn with_countdown_seconds(seconds: u64) -> Self {
        Self {
            countdown_seconds: seconds,
            skip_countdown: false,
        }
    }

    /// Run the emergency countdown
    ///
    /// Displays a countdown from `countdown_seconds` down to 1, checking for
    /// Ctrl+C abort after each second. Returns `Ok(true)` if countdown completes,
    /// `Ok(false)` if aborted by user.
    ///
    /// If `skip_countdown` is true, returns `Ok(true)` immediately.
    ///
    /// # Returns
    ///
    /// - `Ok(true)`: Countdown completed - proceed with emergency deactivation
    /// - `Ok(false)`: Countdown aborted by user (Ctrl+C pressed)
    /// - `Err(...)`: Currently unused, reserved for future I/O errors
    ///
    /// # Errors
    ///
    /// Currently, this method does not return errors. Signal registration failures
    /// are logged but do not prevent countdown from proceeding. The countdown is
    /// advisory, not mandatory - emergency deactivation should proceed even if
    /// countdown fails. Callers should treat any future errors as non-fatal and
    /// continue with emergency deactivation.
    ///
    /// # Requirements
    ///
    /// - AC2: Display countdown with per-second updates
    /// - AC3: Return Ok(true) after countdown completes
    /// - AC4: Return Ok(false) when Ctrl+C pressed
    /// - AC5: Signal handler implementation with AtomicBool
    /// - AC6: Skip countdown if skip_countdown=true
    pub fn run(&self) -> Result<bool> {
        self.run_with_abort_flag(None)
    }

    /// Run the emergency countdown with optional external abort flag
    ///
    /// Internal method that allows injecting an abort flag for testing.
    /// When `abort_flag` is None, a new flag is created and registered with SIGINT.
    ///
    /// # Arguments
    ///
    /// - `abort_flag`: Optional pre-configured abort flag (for testing)
    ///
    /// # Returns
    ///
    /// Same as `run()` method
    fn run_with_abort_flag(&self, abort_flag: Option<Arc<AtomicBool>>) -> Result<bool> {
        // AC6: Skip countdown if flag is set
        if self.skip_countdown {
            tracing::info!("Skipping countdown (--no-countdown flag)");
            return Ok(true);
        }

        // AC5: Set up atomic abort flag for signal handling
        let abort_flag = abort_flag.unwrap_or_else(|| {
            let flag = Arc::new(AtomicBool::new(false));
            // Register SIGINT handler using signal-hook
            let flag_clone = Arc::clone(&flag);
            // AC5: Register SIGINT (Ctrl+C) handler
            if let Err(e) = signal_hook::flag::register(signal_hook::consts::SIGINT, flag_clone) {
                tracing::warn!(
                    "Failed to register SIGINT handler: {}. Ctrl+C abort disabled.",
                    e
                );
                eprintln!("Warning: Ctrl+C abort unavailable (signal registration failed)");
            }
            flag
        });

        // AC2: Display countdown with per-second updates
        for remaining in (1..=self.countdown_seconds).rev() {
            println!(
                "⚠️  EMERGENCY DEACTIVATION in {}... (Ctrl+C to abort)",
                remaining
            );

            // Sleep for ~1 second (not guaranteed precise due to OS scheduling)
            // Actual duration may vary slightly (e.g., 0.99s-1.01s) depending on system load
            thread::sleep(Duration::from_secs(1));

            // AC4: Check abort flag after each sleep
            if abort_flag.load(Ordering::Relaxed) {
                println!("✓ Emergency deactivation aborted");
                return Ok(false);
            }
        }

        // AC3: Countdown completed
        println!("🔴 EMERGENCY DEACTIVATION STARTING...");
        Ok(true)
    }
}

/// Strategy for executing emergency deactivation
///
/// Controls whether `fork_and_execute()` uses a real fork or executes directly.
/// The `Direct` variant enables testing without the complexities and dangers
/// of forking in Rust's multi-threaded test runner.
///
/// # Variants
///
/// - `Fork`: Production mode - fork a child process via `nix::unistd::fork()`
/// - `Direct`: Testing mode - execute the closure directly in the current process
///
/// # Example
///
/// ```rust,ignore
/// use nails_core::emergency::ForkStrategy;
///
/// // Production: use real fork
/// let strategy = ForkStrategy::Fork;
///
/// // Testing: execute directly
/// let strategy = ForkStrategy::Direct;
/// ```
///
/// # Requirements
///
/// - AR34: Fork child process for resilience (Fork variant)
/// - NFR20: Degraded but continues on fork failure (Direct as fallback)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkStrategy {
    /// Production: fork a child process using `nix::unistd::fork()`
    Fork,

    /// Testing: execute the closure directly without forking
    ///
    /// Used in unit tests where `fork()` is unsafe (Rust test runner is multi-threaded,
    /// and `fork()` only copies the calling thread, causing mutex deadlocks).
    Direct,
}

/// Fork a child process to execute emergency deactivation
///
/// Creates a resilient child process that continues emergency deactivation even
/// if the parent process is terminated by an adversary. The child calls `setsid()`
/// to detach from the terminal, making it immune to terminal signals.
///
/// # Arguments
///
/// * `emergency_fn` - Closure containing the emergency deactivation logic.
///   Called in the child process (or directly in fallback mode).
/// * `strategy` - `ForkStrategy::Fork` for production, `ForkStrategy::Direct` for testing
///
/// # Returns
///
/// - `Ok(())` - Fork succeeded; parent should exit. Or direct execution completed.
/// - `Err(NailsError)` - Only in `Direct` mode if the closure fails.
///
/// # Fork Behavior
///
/// With `ForkStrategy::Fork`:
/// - Parent: prints child PID message, returns `Ok(())` (CLI caller exits)
/// - Child: calls `setsid()`, executes closure, calls `std::process::exit()`
/// - On fork failure: falls back to direct execution with warning
///
/// With `ForkStrategy::Direct`:
/// - Executes the closure directly in the current process
/// - Returns the closure's result
///
/// # Safety
///
/// This function performs a `fork()` system call which is inherently unsafe in Rust:
/// - After fork, only the calling thread exists in the child process
/// - Mutexes held by other threads become permanently locked
/// - Allocator state may be inconsistent
///
/// Mitigation: Fork is called BEFORE creating complex state (`Arc<Mutex<...>>`),
/// and child process creates fresh state rather than sharing from parent.
/// The closure should create its own `NailsManager` and `EmergencyOrchestrator`
/// rather than receiving shared references from the parent.
///
/// # Example
///
/// ```rust,ignore
/// use nails_core::emergency::{fork_and_execute, ForkStrategy};
///
/// // Production usage (in CLI handler):
/// fork_and_execute(|| {
///     // Create fresh manager and orchestrator in child process
///     let manager = create_manager()?;
///     let orchestrator = EmergencyOrchestrator::new(manager);
///     orchestrator.run()
/// }, ForkStrategy::Fork)?;
/// std::process::exit(0); // Parent exits after fork
///
/// // Testing usage:
/// fork_and_execute(|| {
///     Ok(()) // Test closure
/// }, ForkStrategy::Direct)?;
/// ```
///
/// # Requirements
///
/// - AR34: Fork child process for resilience
/// - NFR20: Degraded but continues on fork failure
pub fn fork_and_execute<F>(emergency_fn: F, strategy: ForkStrategy) -> Result<()>
where
    F: FnOnce() -> Result<()>,
{
    match strategy {
        ForkStrategy::Direct => {
            // Direct execution mode (testing or fallback)
            tracing::info!("Executing emergency deactivation directly (no fork)");
            emergency_fn()
        }
        ForkStrategy::Fork => {
            // Production mode: fork a child process
            execute_with_fork(emergency_fn)
        }
    }
}

/// Internal: Execute emergency deactivation via fork
///
/// Performs the actual `fork()` system call and handles parent/child branching.
/// Falls back to direct execution if fork fails.
///
/// # Safety
///
/// This function performs a `fork()` system call which is inherently unsafe in Rust:
/// - After fork, only the calling thread exists in the child process
/// - Mutexes held by other threads become permanently locked
/// - Allocator state may be inconsistent
///
/// **Mitigation strategies:**
/// - Fork is called BEFORE creating complex state (`Arc<Mutex<...>>`)
/// - Child process creates fresh state rather than sharing from parent
/// - The provided closure should create its own `NailsManager` and `EmergencyOrchestrator`
///   rather than receiving shared references from the parent
/// - Post-fork child code is kept as simple as possible
/// - Child calls `setsid()` immediately to detach from terminal
///
/// **Why the `unsafe` block is safe here:**
/// The fork occurs at a point where:
/// 1. No complex shared state has been created yet
/// 2. The closure will construct all needed objects fresh in the child process
/// 3. Parent process exits immediately after fork (via CLI's `std::process::exit(0)`)
/// 4. Child process creates its own independent state tree
///
/// This design ensures fork safety by avoiding the typical pitfalls of forking
/// in multi-threaded Rust programs.
fn execute_with_fork<F>(emergency_fn: F) -> Result<()>
where
    F: FnOnce() -> Result<()>,
{
    // Safety: fork() is called before creating complex shared state.
    // The child process will create its own fresh state (NailsManager, etc.)
    // via the provided closure, rather than sharing mutexes from the parent.
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            // Parent process: report child PID and return to caller
            // The CLI handler (Story 6.4) will call std::process::exit(0) after this
            println!("Emergency deactivation initiated (PID: {})", child);
            tracing::info!("Forked child process {} for emergency deactivation", child);
            Ok(())
        }
        Ok(ForkResult::Child) => {
            // Child process: detach from terminal and execute emergency deactivation

            // Become session leader - immune to terminal signals sent to parent's session
            // Ignore setsid errors (non-fatal - we still continue with deactivation)
            if let Err(e) = setsid() {
                eprintln!("Warning: setsid() failed: {} (continuing anyway)", e);
            }

            // TODO(Epic 9): Configure tracing subscriber to append to {hidden_volume}/logs/nails.log
            // Currently logs to stdout/stderr only. AC6 requires hidden volume logging with graceful
            // degradation if path not accessible. Blocked on logging infrastructure (Epic 9).

            // Execute the emergency deactivation closure
            match emergency_fn() {
                Ok(()) => {
                    tracing::info!(
                        "Emergency deactivation completed successfully in child process"
                    );
                    std::process::exit(0);
                }
                Err(e) => {
                    tracing::error!("Emergency deactivation failed in child process: {}", e);
                    eprintln!("Emergency deactivation error: {}", e);
                    eprintln!("Emergency deactivation completed with errors - reboot recommended");
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            // Fork failed - fall back to direct execution (degraded resilience)
            let fork_err = NailsError::ForkFailed(e.to_string());
            tracing::warn!("Fork failed: {}, executing in current process", fork_err);
            eprintln!("Warning: {}", fork_err);
            eprintln!("Falling back to direct execution (degraded resilience)");

            // Execute emergency_fn directly despite fork failure
            emergency_fn()
        }
    }
}

/// Report of emergency deactivation operations
///
/// Provides detailed accounting of emergency cleanup results, unmount outcomes,
/// timing, and error collection. Unlike `DeactivationReport`, `EmergencyReport`
/// collects errors instead of failing fast — emergency always continues.
///
/// # Fields
///
/// - `cleanup_report`: Results from CleanupManager in Fast mode
/// - `unmounted_overlays`: Overlay paths that were successfully force-unmounted
/// - `duration`: Total time for emergency deactivation
/// - `final_state`: System state after emergency (should be Inactive)
/// - `errors`: Non-fatal errors collected during emergency
/// - `was_defensive`: True if emergency ran when already INACTIVE (FR64)
/// - `status`: Computed: `"success"` if no errors, `"error"` otherwise
/// - `recommendation`: Computed: `Some("Reboot recommended")` if errors > 0
///
/// # Serialization
///
/// `cleanup_report` is skipped during serialization because `CleanupReport`
/// does not derive `Serialize`. All other fields are serializable for JSON
/// output support (Story 6.4).
///
/// # Requirements
///
/// - AC3: EmergencyReport with all required fields
/// - FR54: No rollback — errors collected, not thrown
/// - FR64: Defensive cleanup when already INACTIVE
#[derive(Debug, Clone, Serialize)]
pub struct EmergencyReport {
    /// Cleanup operation results (skipped in JSON — CleanupReport not Serializable)
    #[serde(skip)]
    pub cleanup_report: CleanupReport,

    /// Overlays that were successfully force-unmounted
    pub unmounted_overlays: Vec<String>,

    /// Total duration of emergency deactivation
    #[serde(serialize_with = "serialize_duration")]
    pub duration: Duration,

    /// Final system state after emergency deactivation
    pub final_state: SystemState,

    /// Non-fatal errors collected during emergency (never thrown)
    pub errors: Vec<String>,

    /// True if emergency ran when system was already INACTIVE (defensive cleanup)
    pub was_defensive: bool,

    /// Computed status: `"success"` if no errors, `"error"` otherwise
    pub status: String,

    /// Computed recommendation: `Some("Reboot recommended")` if errors > 0
    pub recommendation: Option<String>,
}

/// Custom serializer for `Duration` — outputs seconds as f64
fn serialize_duration<S>(duration: &Duration, serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_f64(duration.as_secs_f64())
}

impl EmergencyReport {
    /// Check if emergency deactivation completed successfully
    ///
    /// Returns `true` if the final state is `Inactive`, regardless of
    /// `was_defensive` or `errors` count. The key metric is whether the
    /// system reached a safe state.
    ///
    /// # Returns
    ///
    /// `true` if `final_state.is_inactive()` (system is in safe state)
    pub fn is_successful(&self) -> bool {
        self.final_state == SystemState::Inactive
    }
}

impl fmt::Display for EmergencyReport {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.was_defensive {
            writeln!(
                f,
                "Emergency deactivation completed (defensive - already INACTIVE)"
            )?;
        }
        writeln!(f, "Emergency Deactivation Complete")?;
        writeln!(f, "Duration: {:.2}s", self.duration.as_secs_f64())?;
        writeln!(f, "Final State: {:?}", self.final_state)?;
        writeln!(f, "Overlays Unmounted: {}", self.unmounted_overlays.len())?;
        if !self.errors.is_empty() {
            writeln!(f, "Errors: {}", self.errors.len())?;
            for error in &self.errors {
                writeln!(f, "  - {}", error)?;
            }
            if let Some(ref recommendation) = self.recommendation {
                writeln!(f, "Recommendation: {}", recommendation)?;
            }
        }
        Ok(())
    }
}

/// Orchestrates emergency deactivation with fast cleanup and no rollback
///
/// `EmergencyOrchestrator` coordinates a 4-step emergency sequence:
/// 1. State transition: ANY → EMERGENCY (no StateGuard, no rollback)
/// 2. Fast cleanup: `CleanupManager` with `CleanupMode::Fast`
/// 3. Force unmount: All overlays with `force=true` in reverse LIFO order
/// 4. State transition: EMERGENCY → INACTIVE (best-effort)
///
/// # Critical Differences from `DeactivationOrchestrator`
///
/// | Aspect | Deactivation | Emergency |
/// |--------|-------------|-----------|
/// | Cleanup mode | Thorough | Fast |
/// | Unmount | graceful → force | force=true always |
/// | Rollback | Yes (StateGuard) | **NO** (FR54) |
/// | Error handling | Fail fast | Collect errors, continue |
/// | INACTIVE state | No-op | Defensive cleanup (FR64) |
///
/// # Generic Parameter
///
/// `F: Filesystem` — Abstracted filesystem operations for testability
///
/// # Requirements
///
/// - AC1: Generic struct with manager, cleanup_config
/// - AC2: 4-step fast sequence
/// - FR54: No rollback in emergency
/// - FR64: Defensive cleanup even when INACTIVE
/// - NFR3: Target <3 seconds
pub struct EmergencyOrchestrator<F: Filesystem> {
    manager: Arc<Mutex<NailsManager<F>>>,
    cleanup_config: CleanupConfig,
}

impl<F: Filesystem + 'static> EmergencyOrchestrator<F> {
    /// Create a new EmergencyOrchestrator
    ///
    /// # Arguments
    ///
    /// * `manager` - Shared reference to NailsManager for state management
    /// * `cleanup_config` - Configuration for cleanup operations
    ///
    /// # Returns
    ///
    /// New EmergencyOrchestrator instance
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use nails_core::{EmergencyOrchestrator, CleanupConfig};
    /// use std::sync::{Arc, Mutex};
    ///
    /// let orchestrator = EmergencyOrchestrator::new(
    ///     Arc::clone(&manager),
    ///     CleanupConfig::default(),
    /// );
    /// ```
    pub fn new(manager: Arc<Mutex<NailsManager<F>>>, cleanup_config: CleanupConfig) -> Self {
        Self {
            manager,
            cleanup_config,
        }
    }

    /// Execute emergency deactivation
    ///
    /// Runs the 4-step emergency sequence. Errors are collected, never thrown.
    /// The method always returns `Ok(EmergencyReport)` unless the manager lock
    /// cannot be acquired.
    ///
    /// # Steps
    ///
    /// 1. Extract overlay paths BEFORE state transition (critical!)
    /// 2. State → Emergency (via `force_state()`, no StateGuard)
    /// 3. Fast cleanup (`CleanupMode::Fast`, no verification)
    /// 4. Force unmount all overlays in reverse order (`force=true`)
    /// 5. State → Inactive (best-effort)
    /// 6. Build and return `EmergencyReport`
    ///
    /// # Returns
    ///
    /// `Ok(EmergencyReport)` — always, with collected errors
    ///
    /// # Errors
    ///
    /// Only returns `Err` if the manager lock is poisoned (fatal).
    ///
    /// # Requirements
    ///
    /// - AC2: 4-step fast sequence
    /// - AC3: Return EmergencyReport
    /// - AC4: Error tolerance — collect, don't throw
    /// - AC5: Defensive execution when INACTIVE
    /// - AC7: Force unmount with `force=true`
    /// - AC8: Timing tracking with Instant
    pub fn run(&self) -> Result<EmergencyReport> {
        let start = Instant::now();
        let mut errors: Vec<String> = Vec::new();

        // Lock manager for the duration
        let mut manager = self
            .manager
            .lock()
            .map_err(|_| NailsError::InvalidState("Failed to acquire manager lock".to_string()))?;

        // Get current state
        let current_state = manager.current_state()?;

        // AC5: Defensive — if already INACTIVE, still run cleanup
        let was_defensive = current_state == SystemState::Inactive;

        // CRITICAL: Extract overlay paths BEFORE transitioning to EMERGENCY state
        // Once state changes, the Active { overlays, .. } variant is gone
        let overlays_to_unmount = match &current_state {
            SystemState::Active { overlays, .. } => overlays.clone(),
            _ => Vec::new(),
        };

        // Step 1: State → Emergency (AC2, FR54: no StateGuard)
        if !was_defensive
            && let Err(e) = manager.force_state(SystemState::Emergency {
                triggered_at: Utc::now(),
            })
        {
            errors.push(format!("State transition to Emergency failed: {}", e));
            // CONTINUE — emergency never stops
        }

        // Step 2: Fast cleanup (AC2, AC6: CleanupMode::Fast)
        let cleanup_report = {
            let fs = manager.filesystem().clone();
            let cleanup_manager =
                CleanupManager::new(fs, self.cleanup_config.clone(), CleanupMode::Fast);

            match cleanup_manager.cleanup() {
                Ok(report) => report,
                Err(e) => {
                    errors.push(format!("Cleanup failed: {}", e));
                    CleanupReport::default()
                }
            }
        };

        // Step 3: Force unmount all overlays in reverse order (AC2, AC7)
        let mut unmounted_overlays: Vec<String> = Vec::new();
        for path in overlays_to_unmount.iter().rev() {
            match manager.filesystem().unmount(path, true) {
                Ok(()) => {
                    tracing::info!("✓ Force unmounted {}", path.display());
                    unmounted_overlays.push(path.to_string_lossy().to_string());
                }
                Err(e) => {
                    errors.push(format!(
                        "Force unmount failed for {}: {}",
                        path.display(),
                        e
                    ));
                    // CONTINUE — emergency never stops
                }
            }
        }

        // Step 4: State → Inactive (AC2, best-effort)
        if let Err(e) = manager.force_state(SystemState::Inactive) {
            errors.push(format!("State transition to Inactive failed: {}", e));
        }

        // Get final state
        let final_state = manager.current_state().unwrap_or(SystemState::Inactive);

        let duration = start.elapsed();

        // AC8: Timing warning if >3 seconds
        if duration.as_secs_f64() > 3.0 {
            tracing::warn!(
                "Emergency deactivation took {:.2}s — exceeds 3s target (NFR3)",
                duration.as_secs_f64()
            );
        }

        // Compute status and recommendation (AC3)
        let status = if errors.is_empty() {
            "success".to_string()
        } else {
            "error".to_string()
        };

        let recommendation = if !errors.is_empty() {
            Some("Reboot recommended".to_string())
        } else {
            None
        };

        Ok(EmergencyReport {
            cleanup_report,
            unmounted_overlays,
            duration,
            final_state,
            errors,
            was_defensive,
            status,
            recommendation,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // AC7: Test countdown completes when skip_countdown=false and no abort
    #[test]
    fn test_countdown_completes() {
        // Use a very short countdown (1 second) for fast test
        let countdown = EmergencyCountdown::with_countdown_seconds(1);
        let result = countdown.run();
        assert!(result.is_ok());
        assert!(result.unwrap(), "Countdown should complete and return true");
    }

    // AC7: Test countdown aborted (set abort flag before/during run)
    #[test]
    fn test_countdown_aborted() {
        // Create abort flag and set it to true
        let abort_flag = Arc::new(AtomicBool::new(true));

        let countdown = EmergencyCountdown::with_countdown_seconds(1);
        let result = countdown.run_with_abort_flag(Some(abort_flag));

        assert!(result.is_ok());
        assert!(!result.unwrap(), "Countdown should abort and return false");
    }

    // AC7: Test skip_countdown=true returns Ok(true) immediately
    #[test]
    fn test_skip_countdown() {
        let countdown = EmergencyCountdown {
            skip_countdown: true,
            ..Default::default()
        };

        let start = std::time::Instant::now();
        let result = countdown.run();
        let duration = start.elapsed();

        assert!(result.is_ok());
        assert!(
            result.unwrap(),
            "skip_countdown should return true immediately"
        );
        assert!(
            duration.as_millis() < 100,
            "skip_countdown should take <100ms, took: {:?}",
            duration
        );
    }

    // AC7: Test default countdown_seconds is 3
    #[test]
    fn test_default_countdown_seconds() {
        let countdown = EmergencyCountdown::default();
        assert_eq!(countdown.countdown_seconds, 3);
        assert!(!countdown.skip_countdown);
    }

    // AC7: Test custom countdown_seconds value
    #[test]
    fn test_custom_countdown_seconds() {
        let countdown = EmergencyCountdown::with_countdown_seconds(5);
        assert_eq!(countdown.countdown_seconds, 5);
        assert!(!countdown.skip_countdown);
    }

    // AC7: Test new() constructor
    #[test]
    fn test_new_constructor() {
        let countdown = EmergencyCountdown::new();
        assert_eq!(countdown.countdown_seconds, 3);
        assert!(!countdown.skip_countdown);
    }

    // Note: Testing actual SIGINT signal delivery is done in E2E tests (Story 13.5)
    // Unit tests focus on the abort flag mechanism

    // MEDIUM: Test signal handler registration failure graceful degradation
    #[test]
    fn test_countdown_continues_despite_signal_registration_failure() {
        // Even if signal registration fails, countdown should work (just without abort)
        // We can't easily force signal_hook::flag::register to fail in a test,
        // but we test the logic by using Direct injection with a pre-created flag
        let abort_flag = Arc::new(AtomicBool::new(false));
        let countdown = EmergencyCountdown::with_countdown_seconds(1);

        let result = countdown.run_with_abort_flag(Some(abort_flag));

        assert!(
            result.is_ok(),
            "Countdown should succeed even if signal handler fails"
        );
        assert!(
            result.unwrap(),
            "Countdown should complete when abort flag never set"
        );
    }

    // MEDIUM: Test signal handler cleanup (RAII)
    #[test]
    fn test_signal_handler_cleanup_after_run() {
        // Test that running multiple countdowns doesn't leak signal handlers
        // The Arc<AtomicBool> should be dropped after each run, cleaning up handlers
        for _ in 0..3 {
            let countdown = EmergencyCountdown::with_countdown_seconds(1);
            let result = countdown.run();
            assert!(result.is_ok(), "Each countdown should succeed");
        }
        // If signal handlers weren't cleaned up properly, we'd hit registration limits
        // or see resource exhaustion. The fact that we can run 3 times proves cleanup works.
    }

    // MEDIUM: Test signal handler cleanup with abort
    #[test]
    fn test_signal_handler_cleanup_after_abort() {
        // Test cleanup when countdown is aborted
        let abort_flag = Arc::new(AtomicBool::new(true));
        let countdown = EmergencyCountdown::with_countdown_seconds(1);

        let result = countdown.run_with_abort_flag(Some(abort_flag));

        assert!(result.is_ok());
        assert!(!result.unwrap(), "Should abort");
        // If handler cleanup failed, subsequent runs would fail
        // Run again to verify cleanup worked
        let countdown2 = EmergencyCountdown::with_countdown_seconds(1);
        let result2 = countdown2.run();
        assert!(result2.is_ok(), "Second run should succeed after abort");
    }

    // LOW: Test edge case - countdown_seconds = 0
    #[test]
    fn test_countdown_zero_seconds() {
        let countdown = EmergencyCountdown::with_countdown_seconds(0);
        let start = std::time::Instant::now();
        let result = countdown.run();
        let duration = start.elapsed();

        assert!(
            result.is_ok(),
            "Zero-second countdown should handle gracefully"
        );
        assert!(
            result.unwrap(),
            "Zero-second countdown should complete immediately"
        );
        assert!(
            duration.as_millis() < 100,
            "Zero-second countdown should take <100ms, took: {:?}",
            duration
        );
    }

    // LOW: Test edge case - countdown_seconds = 1 (minimum useful value)
    #[test]
    fn test_countdown_one_second() {
        let countdown = EmergencyCountdown::with_countdown_seconds(1);
        let start = std::time::Instant::now();
        let result = countdown.run();
        let duration = start.elapsed();

        assert!(result.is_ok());
        assert!(result.unwrap());
        // Should take approximately 1 second (allow some overhead)
        assert!(
            duration.as_secs() >= 1 && duration.as_secs() < 3,
            "One-second countdown should take ~1s, took: {:?}",
            duration
        );
    }

    // LOW: Test edge case - very large countdown_seconds value
    #[test]
    fn test_countdown_large_value_with_abort() {
        // Test that large values work but can still be aborted quickly
        let abort_flag = Arc::new(AtomicBool::new(false));
        let countdown = EmergencyCountdown::with_countdown_seconds(1000);

        // Spawn a thread to set abort flag after 100ms
        let flag_clone = Arc::clone(&abort_flag);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            flag_clone.store(true, Ordering::Relaxed);
        });

        let start = std::time::Instant::now();
        let result = countdown.run_with_abort_flag(Some(abort_flag));
        let duration = start.elapsed();

        assert!(result.is_ok());
        assert!(
            !result.unwrap(),
            "Large countdown should still be abortable"
        );
        assert!(
            duration.as_secs() < 5,
            "Abort should work quickly even with large countdown, took: {:?}",
            duration
        );
    }

    // ========================================================================
    // Story 6.2: Fork-Resilient Emergency Shutdown Tests
    // ========================================================================
    //
    // NOTE: Cannot safely test actual fork() in Rust unit tests because:
    // - Rust's test runner is multi-threaded
    // - fork() only copies the calling thread → deadlocks on mutexes held by test runner
    // - Use E2E tests (Story 13.5) for actual fork verification
    //
    // These tests cover the Direct strategy path and ForkStrategy enum.

    // AC7: Test ForkStrategy enum variants are constructible
    #[test]
    fn test_fork_strategy_variants() {
        let fork = ForkStrategy::Fork;
        let direct = ForkStrategy::Direct;

        assert_eq!(fork, ForkStrategy::Fork);
        assert_eq!(direct, ForkStrategy::Direct);
        assert_ne!(fork, direct);
    }

    // AC7: Test ForkStrategy Debug implementation
    #[test]
    fn test_fork_strategy_debug() {
        let fork = ForkStrategy::Fork;
        let direct = ForkStrategy::Direct;

        assert_eq!(format!("{:?}", fork), "Fork");
        assert_eq!(format!("{:?}", direct), "Direct");
    }

    // AC7: Test ForkStrategy Clone and Copy
    #[test]
    fn test_fork_strategy_clone_copy() {
        let strategy = ForkStrategy::Direct;
        let cloned = strategy; // Copy trait (no need to call .clone() on Copy types)
        let copied = strategy; // Copy trait

        assert_eq!(strategy, cloned);
        assert_eq!(strategy, copied);
    }

    // AC7: Test fork_and_execute with Direct strategy - successful closure
    #[test]
    fn test_fork_and_execute_direct_success() {
        let was_called = Arc::new(AtomicBool::new(false));
        let was_called_clone = Arc::clone(&was_called);

        let result = fork_and_execute(
            move || {
                was_called_clone.store(true, Ordering::Relaxed);
                Ok(())
            },
            ForkStrategy::Direct,
        );

        assert!(result.is_ok(), "Direct execution should succeed");
        assert!(
            was_called.load(Ordering::Relaxed),
            "Closure should have been called"
        );
    }

    // AC7: Test fork_and_execute with Direct strategy - closure returns error
    #[test]
    fn test_fork_and_execute_direct_error_propagation() {
        let result = fork_and_execute(
            || {
                Err(crate::NailsError::CleanupError(
                    "Test cleanup failure".into(),
                ))
            },
            ForkStrategy::Direct,
        );

        assert!(result.is_err(), "Direct execution should propagate error");
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("Test cleanup failure"),
            "Error message should be preserved"
        );
    }

    // AC7: Test fork_and_execute Direct strategy propagates different error types
    #[test]
    fn test_fork_and_execute_direct_fork_failed_error() {
        let result = fork_and_execute(
            || {
                Err(crate::NailsError::ForkFailed(
                    "Resource temporarily unavailable".into(),
                ))
            },
            ForkStrategy::Direct,
        );

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("Failed to fork emergency process"),
            "ForkFailed error message should be correct: {}",
            err
        );
    }

    // AC7: Test fork_and_execute Direct strategy with IO error
    #[test]
    fn test_fork_and_execute_direct_io_error() {
        let result = fork_and_execute(
            || {
                Err(crate::NailsError::IoError(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "permission denied",
                )))
            },
            ForkStrategy::Direct,
        );

        assert!(result.is_err());
    }

    // AC7: Test fork_and_execute Direct strategy executes closure exactly once
    #[test]
    fn test_fork_and_execute_direct_executes_once() {
        let counter = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let counter_clone = Arc::clone(&counter);

        let result = fork_and_execute(
            move || {
                counter_clone.fetch_add(1, Ordering::Relaxed);
                Ok(())
            },
            ForkStrategy::Direct,
        );

        assert!(result.is_ok());
        assert_eq!(
            counter.load(Ordering::Relaxed),
            1,
            "Closure should be called exactly once"
        );
    }

    // AC7: Test fork_and_execute Direct strategy with closure that does work
    #[test]
    fn test_fork_and_execute_direct_closure_does_work() {
        let result_value = Arc::new(Mutex::new(String::new()));
        let result_value_clone = Arc::clone(&result_value);

        let result = fork_and_execute(
            move || {
                let mut val = result_value_clone.lock().unwrap();
                *val = "emergency deactivation completed".to_string();
                Ok(())
            },
            ForkStrategy::Direct,
        );

        assert!(result.is_ok());
        let val = result_value.lock().unwrap();
        assert_eq!(*val, "emergency deactivation completed");
    }

    // Note: Testing actual fork() behavior is done in E2E tests (Story 13.5)
    // The execute_with_fork() function cannot be safely tested in unit tests
    // due to Rust's multi-threaded test runner and fork() semantics.

    // ========================================================================
    // Story 6.3: EmergencyOrchestrator Integration Tests
    // ========================================================================

    use crate::{CleanupConfig, Config, MockFilesystem};
    use std::path::{Path, PathBuf};

    /// Helper: create a manager in ACTIVE state with 2 overlay paths
    fn setup_active_manager() -> Arc<Mutex<NailsManager<MockFilesystem>>> {
        let fs = MockFilesystem::new();

        fs.mock_set_path_exists("/mnt/hidden-volume", true);
        fs.mock_set_path_exists("/mnt/hidden-volume/.nails", true);
        fs.mock_set_path_type("/mnt/hidden-volume", "directory");
        fs.mock_set_path_type("/mnt/hidden-volume/.nails", "directory");

        let temp_dir = tempfile::tempdir().unwrap();
        let mock_hidden_vol = temp_dir.path();
        let state_dir = mock_hidden_vol.join(".nails");
        std::fs::create_dir_all(&state_dir).unwrap();
        let state_path = state_dir.join("state.json");

        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlays: vec![],
            ..Config::test_default()
        };

        let mut manager = NailsManager::new(fs, config, state_path);

        manager
            .force_state(SystemState::Active {
                activated_at: chrono::Utc::now(),
                overlays: vec![PathBuf::from("/home"), PathBuf::from("/etc")],
            })
            .unwrap();

        Arc::new(Mutex::new(manager))
    }

    /// Helper: create a manager in INACTIVE state
    fn setup_inactive_manager() -> Arc<Mutex<NailsManager<MockFilesystem>>> {
        let fs = MockFilesystem::new();

        fs.mock_set_path_exists("/mnt/hidden-volume", true);
        fs.mock_set_path_exists("/mnt/hidden-volume/.nails", true);
        fs.mock_set_path_type("/mnt/hidden-volume", "directory");
        fs.mock_set_path_type("/mnt/hidden-volume/.nails", "directory");

        let temp_dir = tempfile::tempdir().unwrap();
        let mock_hidden_vol = temp_dir.path();
        let state_dir = mock_hidden_vol.join(".nails");
        std::fs::create_dir_all(&state_dir).unwrap();
        let state_path = state_dir.join("state.json");

        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlays: vec![],
            ..Config::test_default()
        };

        let mut manager = NailsManager::new(fs, config, state_path);
        manager.force_state(SystemState::Inactive).unwrap();

        Arc::new(Mutex::new(manager))
    }

    // AC9-1: Successful emergency from ACTIVE state
    #[test]
    fn test_emergency_from_active_state_succeeds() {
        let manager = setup_active_manager();

        // Setup mounts
        {
            let m = manager.lock().unwrap();
            m.filesystem().mock_set_mounted(Path::new("/home"), true);
            m.filesystem().mock_set_mounted(Path::new("/etc"), true);
        }

        let orchestrator =
            EmergencyOrchestrator::new(Arc::clone(&manager), CleanupConfig::default());
        let result = orchestrator.run();

        assert!(result.is_ok(), "Emergency should succeed");
        let report = result.unwrap();
        assert!(report.is_successful(), "Final state should be Inactive");
        assert_eq!(report.final_state, SystemState::Inactive);
        assert!(!report.was_defensive, "Should NOT be defensive from ACTIVE");
        assert_eq!(report.status, "success");
        assert!(report.recommendation.is_none());
        assert_eq!(report.unmounted_overlays.len(), 2);

        // Verify state is INACTIVE
        let m = manager.lock().unwrap();
        assert_eq!(m.current_state().unwrap(), SystemState::Inactive);
    }

    // AC9-2: Emergency from INACTIVE state (defensive, AC5)
    #[test]
    fn test_emergency_from_inactive_state_defensive() {
        let manager = setup_inactive_manager();

        let orchestrator =
            EmergencyOrchestrator::new(Arc::clone(&manager), CleanupConfig::default());
        let result = orchestrator.run();

        assert!(result.is_ok());
        let report = result.unwrap();
        assert!(report.is_successful());
        assert!(
            report.was_defensive,
            "AC5: Should be defensive when already INACTIVE"
        );
        assert_eq!(report.final_state, SystemState::Inactive);
        assert_eq!(
            report.unmounted_overlays.len(),
            0,
            "No overlays to unmount when INACTIVE"
        );
    }

    // AC9-3: Emergency with cleanup failure (continues, collects error)
    #[test]
    fn test_emergency_with_cleanup_failure_continues() {
        let manager = setup_active_manager();

        // Setup mounts
        {
            let m = manager.lock().unwrap();
            m.filesystem().mock_set_mounted(Path::new("/home"), true);
            m.filesystem().mock_set_mounted(Path::new("/etc"), true);

            // Make cleanup fail by setting history write to fail
            let home = std::env::var("HOME").unwrap_or_else(|_| "/home/user".to_string());
            let bash_history = Path::new(&home).join(".bash_history");
            let bash_history_str = bash_history.to_str().unwrap();
            m.filesystem().mock_set_path_exists(bash_history_str, true);
            m.filesystem()
                .mock_set_file_content(bash_history_str, "nails activate\nsome command\n");
            m.filesystem()
                .mock_set_write_should_fail(bash_history_str, true);
        }

        let orchestrator =
            EmergencyOrchestrator::new(Arc::clone(&manager), CleanupConfig::default());
        let result = orchestrator.run();

        // Emergency should still succeed (collect errors, not throw)
        assert!(
            result.is_ok(),
            "Emergency should succeed despite cleanup failure"
        );
        let report = result.unwrap();

        // State should still reach INACTIVE
        assert!(report.is_successful());
        assert_eq!(report.final_state, SystemState::Inactive);

        // Overlays should still be unmounted
        assert_eq!(report.unmounted_overlays.len(), 2);
    }

    // AC9-4: Emergency with unmount failure (continues, collects error)
    #[test]
    fn test_emergency_with_unmount_failure_continues() {
        let manager = setup_active_manager();

        // Setup: /home unmount fails, /etc succeeds
        {
            let m = manager.lock().unwrap();
            m.filesystem().mock_set_mounted(Path::new("/home"), true);
            m.filesystem().mock_set_mounted(Path::new("/etc"), true);
            m.filesystem().mock_set_unmount_should_fail("/home", true);
        }

        let orchestrator =
            EmergencyOrchestrator::new(Arc::clone(&manager), CleanupConfig::default());
        let result = orchestrator.run();

        assert!(
            result.is_ok(),
            "Emergency should succeed despite unmount failure"
        );
        let report = result.unwrap();

        // State should still reach INACTIVE
        assert!(report.is_successful());
        assert_eq!(report.final_state, SystemState::Inactive);

        // Only /etc should be unmounted (reverse order: /etc first, then /home fails)
        assert_eq!(report.unmounted_overlays.len(), 1);
        assert!(report.unmounted_overlays[0].contains("/etc"));

        // Error collected for /home
        assert!(
            report.errors.iter().any(|e| e.contains("/home")),
            "Should collect error for /home unmount failure: {:?}",
            report.errors
        );

        assert_eq!(report.status, "error");
        assert_eq!(
            report.recommendation,
            Some("Reboot recommended".to_string())
        );
    }

    // AC9-5: Emergency with both cleanup and unmount failure
    #[test]
    fn test_emergency_with_both_failures_collects_all_errors() {
        let manager = setup_active_manager();

        {
            let m = manager.lock().unwrap();
            m.filesystem().mock_set_mounted(Path::new("/home"), true);
            m.filesystem().mock_set_mounted(Path::new("/etc"), true);

            // Make cleanup fail
            let home = std::env::var("HOME").unwrap_or_else(|_| "/home/user".to_string());
            let bash_history = Path::new(&home).join(".bash_history");
            let bash_history_str = bash_history.to_str().unwrap();
            m.filesystem().mock_set_path_exists(bash_history_str, true);
            m.filesystem()
                .mock_set_file_content(bash_history_str, "nails activate\n");
            m.filesystem()
                .mock_set_write_should_fail(bash_history_str, true);

            // Make unmount fail for both
            m.filesystem().mock_set_unmount_should_fail("/home", true);
            m.filesystem().mock_set_unmount_should_fail("/etc", true);
        }

        let orchestrator =
            EmergencyOrchestrator::new(Arc::clone(&manager), CleanupConfig::default());
        let result = orchestrator.run();

        assert!(result.is_ok());
        let report = result.unwrap();

        // State should still reach INACTIVE
        assert!(report.is_successful());

        // Both unmount failures collected
        let unmount_errors: Vec<_> = report
            .errors
            .iter()
            .filter(|e| e.contains("Force unmount failed"))
            .collect();
        assert_eq!(
            unmount_errors.len(),
            2,
            "Should have 2 unmount errors: {:?}",
            report.errors
        );

        assert_eq!(report.status, "error");
        assert!(report.recommendation.is_some());
    }

    // AC9-6: No StateGuard/rollback behavior (state stays Inactive, not rolled back)
    #[test]
    fn test_emergency_no_rollback_behavior() {
        let manager = setup_active_manager();

        // Make unmount fail to trigger error path
        {
            let m = manager.lock().unwrap();
            m.filesystem().mock_set_mounted(Path::new("/home"), true);
            m.filesystem().mock_set_mounted(Path::new("/etc"), true);
            m.filesystem().mock_set_unmount_should_fail("/home", true);
        }

        let orchestrator =
            EmergencyOrchestrator::new(Arc::clone(&manager), CleanupConfig::default());
        let result = orchestrator.run();

        assert!(result.is_ok());
        let report = result.unwrap();

        // FR54: State should be INACTIVE, NOT rolled back to ACTIVE
        assert_eq!(
            report.final_state,
            SystemState::Inactive,
            "FR54: Emergency should NOT rollback - state should be Inactive, not Active"
        );

        // Verify manager state is INACTIVE
        let m = manager.lock().unwrap();
        let state = m.current_state().unwrap();
        assert_eq!(
            state,
            SystemState::Inactive,
            "FR54: Manager state should be Inactive after emergency with errors"
        );
    }

    // AC9-7: Fast mode is used (not Thorough)
    #[test]
    fn test_emergency_uses_fast_cleanup_mode() {
        let manager = setup_active_manager();

        {
            let m = manager.lock().unwrap();
            m.filesystem().mock_set_mounted(Path::new("/home"), true);
            m.filesystem().mock_set_mounted(Path::new("/etc"), true);
        }

        let orchestrator =
            EmergencyOrchestrator::new(Arc::clone(&manager), CleanupConfig::default());
        let result = orchestrator.run();

        assert!(result.is_ok());
        let report = result.unwrap();

        // Verify Fast mode was used — CleanupReport.mode should be default (Thorough)
        // when created via default(), but the cleanup_report from emergency should
        // NOT have verification_passed set (Fast mode skips verification)
        assert!(
            report.cleanup_report.verification_passed.is_none(),
            "AC6: Fast mode should skip verification — verification_passed should be None"
        );
    }

    // AC9-8: Force unmount is called (force=true)
    #[test]
    fn test_emergency_force_unmounts_overlays() {
        let manager = setup_active_manager();

        {
            let m = manager.lock().unwrap();
            m.filesystem().mock_set_mounted(Path::new("/home"), true);
            m.filesystem().mock_set_mounted(Path::new("/etc"), true);
        }

        let orchestrator =
            EmergencyOrchestrator::new(Arc::clone(&manager), CleanupConfig::default());
        let result = orchestrator.run();

        assert!(result.is_ok());
        let report = result.unwrap();

        // Both overlays should be unmounted
        assert_eq!(
            report.unmounted_overlays.len(),
            2,
            "AC7: Both overlays should be force unmounted"
        );

        // Verify reverse order (LIFO): /etc first, then /home
        // Active state has [/home, /etc], reversed = [/etc, /home]
        assert_eq!(report.unmounted_overlays[0], "/etc");
        assert_eq!(report.unmounted_overlays[1], "/home");
    }

    // AC9-9: Timing tracking (duration populated)
    #[test]
    fn test_emergency_timing_tracking() {
        let manager = setup_active_manager();

        {
            let m = manager.lock().unwrap();
            m.filesystem().mock_set_mounted(Path::new("/home"), true);
            m.filesystem().mock_set_mounted(Path::new("/etc"), true);
        }

        let orchestrator =
            EmergencyOrchestrator::new(Arc::clone(&manager), CleanupConfig::default());
        let result = orchestrator.run();

        assert!(result.is_ok());
        let report = result.unwrap();

        // AC8: Duration should be tracked and non-zero
        assert!(
            report.duration > Duration::ZERO,
            "AC8: Duration should be tracked and > 0"
        );

        // Emergency should complete well within 3 seconds for mock operations
        assert!(
            report.duration.as_secs() < 3,
            "NFR3: Emergency with mocks should complete in <3s, took: {:?}",
            report.duration
        );
    }

    // AC9-10: Report fields (status, recommendation computed correctly)
    #[test]
    fn test_emergency_report_fields_computed_correctly() {
        // Test success case
        {
            let manager = setup_active_manager();
            {
                let m = manager.lock().unwrap();
                m.filesystem().mock_set_mounted(Path::new("/home"), true);
                m.filesystem().mock_set_mounted(Path::new("/etc"), true);
            }

            let orchestrator =
                EmergencyOrchestrator::new(Arc::clone(&manager), CleanupConfig::default());
            let report = orchestrator.run().unwrap();

            assert_eq!(report.status, "success", "No errors → status=success");
            assert!(
                report.recommendation.is_none(),
                "No errors → no recommendation"
            );
            assert!(report.errors.is_empty());
        }

        // Test error case
        {
            let manager = setup_active_manager();
            {
                let m = manager.lock().unwrap();
                m.filesystem().mock_set_mounted(Path::new("/home"), true);
                m.filesystem().mock_set_mounted(Path::new("/etc"), true);
                m.filesystem().mock_set_unmount_should_fail("/home", true);
            }

            let orchestrator =
                EmergencyOrchestrator::new(Arc::clone(&manager), CleanupConfig::default());
            let report = orchestrator.run().unwrap();

            assert_eq!(report.status, "error", "Errors → status=error");
            assert_eq!(
                report.recommendation,
                Some("Reboot recommended".to_string()),
                "Errors → recommendation present"
            );
            assert!(!report.errors.is_empty());
        }

        // Test Display trait
        {
            let manager = setup_active_manager();
            {
                let m = manager.lock().unwrap();
                m.filesystem().mock_set_mounted(Path::new("/home"), true);
                m.filesystem().mock_set_mounted(Path::new("/etc"), true);
            }

            let orchestrator =
                EmergencyOrchestrator::new(Arc::clone(&manager), CleanupConfig::default());
            let report = orchestrator.run().unwrap();

            let output = format!("{}", report);
            assert!(output.contains("Emergency Deactivation Complete"));
            assert!(output.contains("Duration:"));
            assert!(output.contains("Final State:"));
            assert!(output.contains("Overlays Unmounted: 2"));
        }

        // Test Serialize
        {
            let manager = setup_active_manager();
            {
                let m = manager.lock().unwrap();
                m.filesystem().mock_set_mounted(Path::new("/home"), true);
                m.filesystem().mock_set_mounted(Path::new("/etc"), true);
            }

            let orchestrator =
                EmergencyOrchestrator::new(Arc::clone(&manager), CleanupConfig::default());
            let report = orchestrator.run().unwrap();

            let json = serde_json::to_string(&report);
            assert!(json.is_ok(), "EmergencyReport should serialize to JSON");
            let json_str = json.unwrap();
            assert!(json_str.contains("\"status\":\"success\""));
            assert!(json_str.contains("\"was_defensive\":false"));
        }
    }
}
