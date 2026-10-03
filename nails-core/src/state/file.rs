//! # State File Persistence
//!
//! `StateFile` struct and its save/load/integrity logic for persisting
//! system state to the hidden volume.

#[cfg(not(test))]
use super::is_on_hidden_volume;
#[cfg(test)]
use super::is_on_hidden_volume_internal;
use super::{FailedOverlayInfo, SubmountAttachment, SystemState};
use crate::{NailsError, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use super::OverlayInfo;

/// Path to the kernel's per-boot identifier.
///
/// Read at save time so a state file written before a reboot can be told apart
/// from one written during the current boot. The read is fallible on purpose:
/// restricted environments expose the file but return an empty body.
const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";

/// Minimum age before a leftover `.tmp*` sibling is swept on load.
///
/// A durable save takes milliseconds, so any temp file this old is a leftover
/// from a crashed save, never one a concurrent save is still writing. Keeping a
/// margin means a read (which does not hold the state lock) never deletes the
/// temp file a concurrent, locked save is about to rename into place.
const STALE_TEMP_AGE: std::time::Duration = std::time::Duration::from_secs(120);

/// Describes HOW a state file was loaded, so callers can surface diagnostics
/// without re-inspecting the file themselves.
///
/// There is exactly one load policy: a missing file means the system is
/// inactive, while a file that cannot be read or trusted collapses to the safe
/// default *and* reports the problem so callers can treat the real state as
/// unknown rather than silently assume inactive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadOutcome {
    /// File existed, parsed, and passed the integrity check.
    Loaded,
    /// No file existed — returned `StateFile::default()` (effectively inactive).
    Missing,
    /// File existed but could not be read (I/O error) — returned the safe
    /// default; the real state is unknown.
    Unreadable,
    /// File existed but was malformed, failed its integrity check, carried no
    /// integrity digest, or was written by an incompatible version — returned
    /// the safe default; the real state is unknown.
    Corrupt,
}

impl LoadOutcome {
    /// Whether this outcome means the on-disk state could not be trusted, so
    /// the returned [`StateFile`] is a safe default rather than the real state.
    ///
    /// `Missing` is *not* unknown: no file legitimately means inactive.
    pub fn is_unknown(&self) -> bool {
        matches!(self, LoadOutcome::Unreadable | LoadOutcome::Corrupt)
    }
}

/// Result of `StateFile::load_with_outcome()`.
#[derive(Debug, Clone, PartialEq)]
pub struct LoadResult {
    pub state_file: StateFile,
    pub outcome: LoadOutcome,
}

/// State file for persistence to hidden volume
///
/// The StateFile contains the current system state and all metadata needed
/// to reconstruct the system state after a reboot or emergency shutdown.
///
/// # Security Critical
///
/// **INVARIANT**: State file MUST only exist at {hidden_volume}/state.json
/// **NEVER** at: /home/user/state.json, /etc/nails/state.json, or ANY path
/// outside the hidden volume.
///
/// Writing state to the decoy system would leak evidence of hidden
/// environment usage, defeating NAILS' plausible deniability.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StateFile {
    /// Schema version for the on-disk format (uses semver from Cargo.toml).
    /// Format: "major.minor.patch" (e.g., "0.2.0").
    pub version: String,

    /// Current system state (Inactive, Activating, Active, Deactivating, Degraded)
    pub state: SystemState,

    /// Store path of the hidden NixOS system toplevel built and switched to on
    /// the last successful activation (e.g. `/nix/store/…-nixos-system-host-…`).
    ///
    /// The fast path reuses this directly: when the config fingerprint still
    /// matches and this path still exists on disk, activation re-runs
    /// `switch-to-configuration test` against it instead of rebuilding. `None`
    /// until the first successful activation that switched the hidden config, and
    /// cleared on deactivation. Deactivation keys the decoy restore on this being
    /// set, so it is the record that a hidden configuration is in force.
    pub hidden_toplevel: Option<String>,

    /// Config fingerprint after last successful activation.
    ///
    /// 16-char hex FNV-1a hash of hardware-configuration.nix + configuration.nix content.
    /// Used by the fast-path activation logic to skip rebuilds when the config has not changed.
    /// `None` until the first successful activation with fingerprint tracking.
    #[serde(default)]
    pub config_fingerprint: Option<String>,

    /// Currently mounted overlays with their configuration
    pub overlay_status: HashMap<PathBuf, OverlayInfo>,

    /// Overlays that failed to mount during last activation
    ///
    /// Used for status reporting and debugging. Cleared on successful deactivation.
    #[serde(default)]
    pub failed_overlays: Vec<FailedOverlayInfo>,

    /// Whether a read-only `/nix/store` self-bind was created in PID 1's mount
    /// namespace during activation.
    ///
    /// This only happens when the manager and init mount namespaces differ (an
    /// invocation preflight normally refuses). When set, that extra bind lives in
    /// the init namespace, so the manager-namespace `/nix/store` unmount does not
    /// reach it and teardown must undo it separately. Recording the fact here lets
    /// deactivation remove exactly the bind it created — never the system's own
    /// boot-time `/nix/store` bind. Cleared on deactivation.
    #[serde(default)]
    pub nix_store_init_namespace_bound: bool,

    /// Decoy OS trees bind-remounted read-only for the session.
    ///
    /// On an FHS host the activation keeps the decoy root (`/`) and `/usr` (plus
    /// any non-usr-merged core binary roots) read-only while hidden is active, so
    /// hidden-session writes cannot reach the decoy disk. Each entry is a
    /// read-only self-bind that deactivation and emergency teardown must undo to
    /// return write access to the host. Empty on platforms whose protection comes
    /// from overlays alone (NixOS). Cleared on deactivation.
    #[serde(default)]
    pub read_only_guards: Vec<PathBuf>,

    /// Mounts created to keep submounts visible under overlaid targets, in
    /// creation order.
    ///
    /// When a parent overlay would hide a filesystem the host mounted beneath it
    /// (a snap squashfs, a separate `/var/log` partition, a tmpfs), activation
    /// stages and re-attaches or nests it. Each resulting mount is recorded here
    /// so deactivation and emergency teardown undo exactly those mounts, in
    /// reverse, before the parent overlays come down. Empty when no target had a
    /// hidden submount. Cleared on deactivation.
    #[serde(default)]
    pub submount_attachments: Vec<SubmountAttachment>,

    /// Timestamp of last state modification
    pub last_modified: DateTime<Utc>,

    /// Kernel boot identifier captured at write time.
    ///
    /// Read from `/proc/sys/kernel/random/boot_id`. `None` when the kernel does
    /// not expose it (for example in a restricted container). Lets a reader tell
    /// a state file written during the current boot from a stale one left behind
    /// by a crash before a reboot.
    #[serde(default)]
    pub boot_id: Option<String>,

    /// PID of the process that last wrote this file.
    ///
    /// Together with the inter-process lock this distinguishes a live operation
    /// from a crashed one. Set from `std::process::id()` at write time.
    #[serde(default)]
    pub owner_pid: u32,

    /// SHA-256 integrity digest over the rest of the file.
    ///
    /// This detects *corruption* (truncation, partial writes, bit rot), not
    /// malicious modification: it is an unkeyed hash, so anyone who can write the
    /// file can recompute it. A file that arrives without this digest is treated
    /// as corrupt rather than trusted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub integrity_sha256: Option<String>,
}

impl Default for StateFile {
    /// Create default StateFile with Inactive state.
    ///
    /// Used when the state file is missing, unreadable, or corrupt. The safe
    /// default assumes the system is INACTIVE (no hidden environment).
    fn default() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            state: SystemState::Inactive,
            hidden_toplevel: None,
            config_fingerprint: None,
            overlay_status: HashMap::new(),
            failed_overlays: Vec::new(),
            nix_store_init_namespace_bound: false,
            read_only_guards: Vec::new(),
            submount_attachments: Vec::new(),
            last_modified: Utc::now(),
            boot_id: None,
            owner_pid: 0,
            integrity_sha256: None,
        }
    }
}

impl StateFile {
    /// Save state file to disk with a durable atomic write.
    ///
    /// # Durability & Atomicity
    ///
    /// Writes to a temp file in the same directory, `fsync`s it, renames it over
    /// the target (a single atomic syscall on POSIX), then `fsync`s the parent
    /// directory so the rename itself survives a crash. Either the old file or
    /// the complete new file exists, never a partial one.
    ///
    /// # Hidden Volume Validation
    ///
    /// **CRITICAL**: the state file MUST be on the hidden volume. This method
    /// returns an error if the path is outside the configured hidden_volume_root.
    ///
    /// # Security
    ///
    /// - File permissions set to 0600 (owner read/write only)
    /// - Parent directories created if needed
    ///
    /// # Example
    ///
    /// ```no_run
    /// use nails_core::StateFile;
    /// use nails_core::config::Config;
    /// use std::path::Path;
    ///
    /// let config = Config::default();
    /// let state = StateFile::default();
    /// let root = config.hidden_volume_root.to_string_lossy();
    /// state.save(Path::new("/mnt/hidden-volume/state.json"), &root)?;
    /// # Ok::<(), nails_core::NailsError>(())
    /// ```
    pub fn save(&self, path: &Path, hidden_volume_root: &str) -> Result<()> {
        self.save_with_root(path, hidden_volume_root)
    }

    /// Save state file with a custom hidden volume root path.
    ///
    /// Used by NailsManager to validate paths against the configured hidden
    /// volume root.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use nails_core::StateFile;
    /// use std::path::{Path, PathBuf};
    ///
    /// let state = StateFile::default();
    /// let custom_root = PathBuf::from("/tmp");
    /// state.save_with_custom_root(Path::new("/tmp/state.json"), &custom_root)?;
    /// # Ok::<(), nails_core::NailsError>(())
    /// ```
    pub fn save_with_custom_root(&self, path: &Path, hidden_volume_root: &Path) -> Result<()> {
        self.save_with_root(
            path,
            hidden_volume_root
                .to_str()
                .unwrap_or(crate::config::DEFAULT_HIDDEN_VOLUME_ROOT),
        )
    }

    /// Save state file with custom hidden volume root (for testing)
    #[cfg(test)]
    pub(crate) fn save_with_root(&self, path: &Path, hidden_volume_root: &str) -> Result<()> {
        if !is_on_hidden_volume_internal(path, hidden_volume_root) {
            return Err(NailsError::InvalidState(format!(
                "State file must be on hidden volume ({}), but attempted to write to: {}",
                hidden_volume_root,
                path.display()
            )));
        }

        self.save_internal(path, hidden_volume_root)
    }

    /// Save state file with default hidden volume root (production)
    #[cfg(not(test))]
    fn save_with_root(&self, path: &Path, hidden_volume_root: &str) -> Result<()> {
        if !is_on_hidden_volume(path, hidden_volume_root) {
            return Err(NailsError::InvalidState(format!(
                "State file must be on hidden volume ({}), but attempted to write to: {}",
                hidden_volume_root,
                path.display()
            )));
        }

        self.save_internal(path, hidden_volume_root)
    }

    /// Internal save implementation (shared by test and production).
    ///
    /// The write is routed through [`crate::filesystem::SafeRoot`] anchored on the
    /// hidden volume root, so a symlink or `..` planted at any component between
    /// the root and `state.json` cannot redirect this privileged write onto the
    /// decoy filesystem. `SafeRoot` performs the temp-then-rename atomic write
    /// (unique `O_EXCL` temp under the parent dir fd, `fsync`, `renameat`, parent
    /// `fsync`) that the previous `tempfile`-based path did, with containment added.
    fn save_internal(&self, path: &Path, hidden_volume_root: &str) -> Result<()> {
        // Test-only: let a regression test force this save to fail at a precise
        // target state, standing in for an ENOSPC/EROFS write failure without a
        // read-only filesystem. Compiled out of the production path entirely.
        #[cfg(test)]
        save_probe::check(&self.state)?;

        // 1. Stamp write-time provenance onto a working copy.
        let mut final_state = self.clone();
        final_state.boot_id = read_boot_id();
        final_state.owner_pid = std::process::id();

        // 2. Compute the integrity digest over the state with the digest field
        //    cleared, so the hash is deterministic and self-verifying on load.
        final_state.integrity_sha256 = None;
        let digest = compute_integrity(&final_state)?;
        final_state.integrity_sha256 = Some(digest);

        let json = serde_json::to_string_pretty(&final_state)
            .map_err(|e| NailsError::ConfigError(format!("Failed to serialize state: {}", e)))?;

        // 3. Resolve the state path relative to the hidden root. Validation above
        //    already proved the path lies beneath the root; the relative remainder
        //    is what SafeRoot resolves, contained, beneath its pinned root fd.
        let root = Path::new(hidden_volume_root);
        let relative = path.strip_prefix(root).map_err(|_| {
            NailsError::InvalidState(format!(
                "State file path {} is not beneath the hidden volume root {}",
                path.display(),
                hidden_volume_root
            ))
        })?;

        // 4. Contained atomic write at mode 0600: SafeRoot creates any missing
        //    parent (0700), writes to a unique O_EXCL temp under the parent dir fd,
        //    fsyncs it, renames it into place and fsyncs the parent directory.
        let safe_root = crate::filesystem::SafeRoot::open(root)?;
        safe_root.write_atomic(relative, json.as_bytes(), 0o600)?;

        // The durability fsyncs (file before rename, directory after) both run
        // inside write_atomic; record them for the durability regression test.
        #[cfg(test)]
        {
            sync_probe::record_file_sync();
            sync_probe::record_dir_sync();
        }

        Ok(())
    }

    /// Load state file from disk, discarding the load outcome metadata.
    ///
    /// Never returns a corruption error: a missing, unreadable, or corrupt file
    /// collapses to the safe inactive default. Only a hard permission error
    /// propagates, because that is an operator problem, not a state problem.
    pub fn load(path: &Path) -> Result<StateFile> {
        Ok(Self::load_with_outcome(path)?.state_file)
    }

    /// Load state file from disk with structured outcome metadata.
    ///
    /// One load policy:
    /// - **Missing file** → `Ok(LoadResult { outcome: Missing, .. })`, inactive.
    /// - **Unreadable (I/O error)** → `Ok(LoadResult { outcome: Unreadable, .. })`.
    /// - **Malformed / failed integrity / no digest / incompatible version** →
    ///   `Ok(LoadResult { outcome: Corrupt, .. })`.
    /// - **Loaded and verified** → `Ok(LoadResult { outcome: Loaded, .. })`.
    ///
    /// Only a permission error returns `Err`; every other problem is reported
    /// through the outcome so no command (including emergency) is broken by a
    /// damaged state file.
    pub fn load_with_outcome(path: &Path) -> Result<LoadResult> {
        // Opportunistically sweep stale temp files left by an interrupted save.
        //
        // Skip this when the state file itself is a `.tmp*` path: that is never
        // the real layout (the production state file is `state.json`), and a
        // `.tmp*` target would otherwise match the sweep and delete itself.
        let target_is_temp = path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with(".tmp"));
        if !target_is_temp && let Some(dir) = path.parent() {
            remove_stale_temp_files(dir);
        }

        // Missing file is a legitimate "inactive" signal, not corruption.
        if !path.exists() {
            tracing::warn!(
                "State file not found at {}, assuming INACTIVE",
                path.display()
            );
            return Ok(LoadResult {
                state_file: StateFile::default(),
                outcome: LoadOutcome::Missing,
            });
        }

        // Read file contents.
        let contents = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    return Err(NailsError::PermissionDenied(format!(
                        "Cannot read state file {}: {}",
                        path.display(),
                        e
                    )));
                }

                tracing::warn!(
                    "State file unreadable at {}: {}, treating state as unknown",
                    path.display(),
                    e
                );
                return Ok(LoadResult {
                    state_file: StateFile::default(),
                    outcome: LoadOutcome::Unreadable,
                });
            }
        };

        // Parse JSON.
        let state_file = match serde_json::from_str::<StateFile>(&contents) {
            Ok(sf) => sf,
            Err(e) => {
                tracing::warn!(
                    "State file malformed at {}: {}, treating state as unknown",
                    path.display(),
                    e
                );
                return Ok(corrupt_result());
            }
        };

        // Integrity: a trustworthy file carries a digest that matches its body.
        // A file with no digest is treated as corrupt, never silently accepted.
        match &state_file.integrity_sha256 {
            Some(stored) => {
                let mut for_hash = state_file.clone();
                for_hash.integrity_sha256 = None;
                let computed = compute_integrity(&for_hash)?;
                if &computed != stored {
                    tracing::warn!(
                        path = %path.display(),
                        "State file integrity digest mismatch, treating state as unknown"
                    );
                    return Ok(corrupt_result());
                }
            }
            None => {
                tracing::warn!(
                    path = %path.display(),
                    "State file has no integrity digest, treating state as unknown"
                );
                return Ok(corrupt_result());
            }
        }

        // Reject files from an incompatible (newer major) schema version. With
        // no backwards-compatibility guarantee we do not migrate; an unreadable
        // schema is reported as corrupt (effectively unknown), not a hard error.
        let current_major = major_version(env!("CARGO_PKG_VERSION"));
        let stored_major = major_version(&state_file.version);
        if stored_major > current_major {
            tracing::warn!(
                current_version = %env!("CARGO_PKG_VERSION"),
                stored_version = %state_file.version,
                path = %path.display(),
                "State file was written by a newer major version, treating state as unknown"
            );
            return Ok(corrupt_result());
        }

        Ok(LoadResult {
            state_file,
            outcome: LoadOutcome::Loaded,
        })
    }
}

/// Build the safe-default result used for every corruption case.
fn corrupt_result() -> LoadResult {
    LoadResult {
        state_file: StateFile::default(),
        outcome: LoadOutcome::Corrupt,
    }
}

/// Compute the SHA-256 integrity digest over a state file.
///
/// The caller is responsible for clearing `integrity_sha256` first so the digest
/// is computed over a deterministic body.
fn compute_integrity(state: &StateFile) -> Result<String> {
    use sha2::Digest;
    let value = serde_json::to_value(state).map_err(|e| {
        NailsError::ConfigError(format!(
            "Failed to serialize state for integrity digest: {}",
            e
        ))
    })?;
    let json = value.to_string();
    Ok(hex::encode(sha2::Sha256::digest(json.as_bytes())))
}

/// Parse the major component of a semver string, defaulting to 0.
fn major_version(version: &str) -> u32 {
    version
        .split('.')
        .next()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(0)
}

/// Read the kernel boot id, returning `None` when it is unavailable or empty.
///
/// Exposed to the crate so state reconciliation can compare a persisted boot id
/// against the current one. Both the save-time stamp and the reconcile-time read
/// go through here, so a test can drive both sides with [`test_boot_id`].
pub(crate) fn read_boot_id() -> Option<String> {
    #[cfg(test)]
    if let Some(value) = test_boot_id::get() {
        return value;
    }
    match std::fs::read_to_string(BOOT_ID_PATH) {
        Ok(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
        Err(_) => None,
    }
}

/// Test-only override for the kernel boot id.
///
/// Reconciliation decides a state file is stale when its stamped boot id differs
/// from the current one. Both values come from [`read_boot_id`], so a test arms
/// one boot id, saves an `Active` state (stamped with it), then arms a different
/// boot id before reconciling to drive the stale-reset path hermetically. The
/// override is thread-local and the guard clears it on drop so it never leaks
/// into another test sharing the worker thread.
#[cfg(test)]
pub(crate) mod test_boot_id {
    use std::cell::RefCell;

    thread_local! {
        static OVERRIDE: RefCell<Option<Option<String>>> = const { RefCell::new(None) };
    }

    /// The armed override, if any: `Some(value)` means `read_boot_id` returns
    /// `value`; the outer `None` means no override is active.
    pub(crate) fn get() -> Option<Option<String>> {
        OVERRIDE.with(|cell| cell.borrow().clone())
    }

    /// Arm the override so `read_boot_id` returns `value` until the guard drops.
    pub(crate) fn arm(value: Option<&str>) -> Guard {
        OVERRIDE.with(|cell| *cell.borrow_mut() = Some(value.map(str::to_string)));
        Guard
    }

    /// Clears the override when dropped.
    pub(crate) struct Guard;

    impl Drop for Guard {
        fn drop(&mut self) {
            OVERRIDE.with(|cell| *cell.borrow_mut() = None);
        }
    }
}

/// Remove stale temp siblings left by an interrupted atomic write.
///
/// The hidden-root atomic write (`SafeRoot::write_atomic`) names its temps with a
/// `.nails-tmp.` prefix; older `tempfile`-based writes used a `.tmp` prefix. If a
/// save crashed between creating the temp file and the rename, the leftover would
/// otherwise accumulate on the hidden volume forever, so both prefixes are swept.
fn remove_stale_temp_files(dir: &Path) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    let now = std::time::SystemTime::now();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let is_temp = name
            .to_str()
            .is_some_and(|name| name.starts_with(".tmp") || name.starts_with(".nails-tmp"));
        if !is_temp {
            continue;
        }
        // Only sweep temps old enough to be leftovers from a crashed save, never
        // one a concurrent (lock-holding) save is still writing.
        let stale = entry
            .metadata()
            .and_then(|meta| meta.modified())
            .ok()
            .and_then(|mtime| now.duration_since(mtime).ok())
            .is_some_and(|age| age >= STALE_TEMP_AGE);
        if stale {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// Test-only observation seam for the durability fsyncs.
///
/// Compiled only under `cfg(test)`, so the production save path always performs
/// the real `fsync` and records nothing; the counters merely let tests assert
/// that the file and directory syncs actually ran.
#[cfg(test)]
pub(crate) mod sync_probe {
    use std::sync::atomic::{AtomicUsize, Ordering};

    static FILE_SYNCS: AtomicUsize = AtomicUsize::new(0);
    static DIR_SYNCS: AtomicUsize = AtomicUsize::new(0);

    pub(crate) fn record_file_sync() {
        FILE_SYNCS.fetch_add(1, Ordering::SeqCst);
    }

    pub(crate) fn record_dir_sync() {
        DIR_SYNCS.fetch_add(1, Ordering::SeqCst);
    }

    pub(crate) fn file_syncs() -> usize {
        FILE_SYNCS.load(Ordering::SeqCst)
    }

    pub(crate) fn dir_syncs() -> usize {
        DIR_SYNCS.load(Ordering::SeqCst)
    }
}

/// Test-only seam to force a state save to fail at a chosen target state.
///
/// Mirrors [`sync_probe`]: compiled only under `cfg(test)`, so the production
/// save path never consults it. It lets the deactivation regression tests make
/// [`StateFile::save_internal`] fail at a precise `?` site — the save of a given
/// target state — reproducing an ENOSPC/EROFS write failure without needing a
/// real read-only filesystem, and so without perturbing the earlier saves that
/// must succeed to reach that site.
///
/// The arming flag is thread-local: a test arms it on the same worker thread
/// that runs the deactivation (and therefore the save), so concurrent `serial`
/// tests and the harness's own saves on other threads are never affected.
#[cfg(test)]
pub(crate) mod save_probe {
    use crate::{NailsError, Result, SystemState};
    use std::cell::Cell;

    /// A target state whose save should fail on the current thread. Several may be
    /// armed at once so a single run can fail an early write *and* the rollback
    /// write that `StateGuard::drop` then attempts — the exact shape of the
    /// original self-deadlock.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub(crate) enum FailOn {
        /// Fail the `ACTIVE -> DEACTIVATING` write (the first guarded `?` site).
        Deactivating,
        /// Fail the `DEACTIVATING -> INACTIVE` write (after unmount).
        Inactive,
        /// Fail the rollback write back to `ACTIVE` performed by `StateGuard::drop`.
        Active,
    }

    const BIT_DEACTIVATING: u8 = 1 << 0;
    const BIT_INACTIVE: u8 = 1 << 1;
    const BIT_ACTIVE: u8 = 1 << 2;

    thread_local! {
        static FAIL_BITS: Cell<u8> = const { Cell::new(0) };
    }

    fn bit(target: FailOn) -> u8 {
        match target {
            FailOn::Deactivating => BIT_DEACTIVATING,
            FailOn::Inactive => BIT_INACTIVE,
            FailOn::Active => BIT_ACTIVE,
        }
    }

    /// Arm the seam so every save whose state matches one of `targets` returns
    /// `Err`. Replaces any previously armed set on this thread.
    pub(crate) fn arm(targets: &[FailOn]) {
        let bits = targets.iter().fold(0u8, |acc, &t| acc | bit(t));
        FAIL_BITS.with(|cell| cell.set(bits));
    }

    /// Disarm the seam on the current thread.
    pub(crate) fn disarm() {
        FAIL_BITS.with(|cell| cell.set(0));
    }

    /// Return `Err` when the state being written matches an armed target.
    pub(crate) fn check(state: &SystemState) -> Result<()> {
        let bits = FAIL_BITS.with(|cell| cell.get());
        let hit = match state {
            SystemState::Deactivating { .. } => bits & BIT_DEACTIVATING != 0,
            SystemState::Inactive => bits & BIT_INACTIVE != 0,
            SystemState::Active { .. } => bits & BIT_ACTIVE != 0,
            _ => false,
        };
        if hit {
            return Err(NailsError::IoError(std::io::Error::other(
                "injected state-save failure (test seam)",
            )));
        }
        Ok(())
    }
}
