// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! # State File Persistence
//!
//! `StateFile` struct and its save/load/integrity logic for persisting
//! system state to the hidden volume.

use super::SystemState;
#[cfg(not(test))]
use super::is_on_hidden_volume;
#[cfg(test)]
use super::is_on_hidden_volume_internal;
use crate::{Family, NailsError, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;

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

/// The platform-specific half of a saved activation, tagged by platform.
///
/// A typed section replaces the former flat `hidden_toplevel`/`last_switch_warning`
/// fields: only NixOS applies a declarative configuration layer, so only its
/// variant records a generation and a switch warning. FHS / Debian-family hosts
/// have no such layer, so their variant is empty. This keeps NixOS-only data off
/// every non-NixOS state file and lets the status surface render the hidden-system
/// generation on NixOS alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "platform", rename_all = "snake_case")]
pub enum PlatformState {
    /// A NixOS host: the hidden system generation in force, plus any warning from
    /// the last switch.
    NixOs {
        /// Store path of the hidden NixOS system toplevel switched to on the last
        /// successful activation (e.g. `/nix/store/…-nixos-system-host-…`). The
        /// fast path reuses it when the config fingerprint still matches and the
        /// path still exists. `None` until the first switch that produced one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        generation: Option<String>,
        /// Reason the hidden configuration was not applied on the last activation,
        /// when the switch failed but the overlays and session were kept
        /// (`nixos_switch_required = false`). `None` when the switch applied
        /// cleanly. The detached GUI worker exits before the operator sees console
        /// output, so this is the durable record `nails status` reports.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        last_switch_warning: Option<String>,
    },
    /// A Debian/Ubuntu or other FHS host: no declarative configuration layer.
    ///
    /// `family` names the host's FHS family, but only when it is one NAILS
    /// records (Fedora or Arch). A Debian-family or unresolved host leaves it
    /// absent, and it is skipped on the wire, so the section serialises to
    /// exactly `{"platform":"debian_family"}` — byte for byte what every release
    /// before families were recorded wrote. That keeps the state file's
    /// integrity digest unchanged across the upgrade for the common case.
    DebianFamily {
        /// The FHS family, recorded only for Fedora and Arch; absent (and
        /// omitted from the serialised form) for a Debian-family or unresolved
        /// host.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        family: Option<Family>,
    },
}

impl PlatformState {
    /// A NixOS section carrying `generation` and no switch warning.
    pub fn nixos(generation: Option<String>) -> Self {
        PlatformState::NixOs {
            generation,
            last_switch_warning: None,
        }
    }
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
/// How long the most recent successful activation took, and when it finished.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LastActivation {
    /// Wall-clock duration of the activation, from its start to the commit to
    /// Active, in milliseconds.
    pub duration_ms: u64,
    /// When the activation committed to Active.
    pub finished_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StateFile {
    /// Schema version for the on-disk format (uses semver from Cargo.toml).
    /// Format: "major.minor.patch" (e.g., "0.2.0").
    pub version: String,

    /// Current system state (Inactive, Activating, Active, Deactivating, Degraded)
    pub state: SystemState,

    /// Platform-specific activation record, or `None` before the first
    /// activation and after a rollback to Inactive.
    ///
    /// Only NixOS has a declarative layer, so only its variant carries a
    /// generation (the hidden system toplevel) and a switch warning. FHS /
    /// Debian-family hosts protect the decoy with overlays and read-only guards
    /// alone, so [`PlatformState::DebianFamily`] carries no layer state. Status
    /// reads this to surface the hidden-system generation on NixOS only, and
    /// deactivation keys the decoy restore on a NixOS generation being present.
    #[serde(default)]
    pub platform: Option<PlatformState>,

    /// Config fingerprint after last successful activation.
    ///
    /// 16-char hex FNV-1a hash of hardware-configuration.nix + configuration.nix content.
    /// Used by the fast-path activation logic to skip rebuilds when the config has not changed.
    /// `None` until the first successful activation with fingerprint tracking. This
    /// is an internal cache key, not operator-facing platform state, so it stays a
    /// flat field rather than moving into [`PlatformState`].
    #[serde(default)]
    pub config_fingerprint: Option<String>,

    /// Canonicalized store path of the decoy's running system, captured at
    /// activation before the hidden switch repoints `/run/current-system`.
    ///
    /// Recorded from `readlink -f /run/current-system` (the booted system's
    /// `/nix/store/…-nixos-system-*` toplevel) the moment activation begins, so
    /// deactivation can restore the exact system that was running rather than
    /// guessing from the system profile. The profile may be absent (an
    /// impermanent or freshly imaged host never populates
    /// `/nix/var/nix/profiles/system`) or point at a newer generation that was
    /// built but never switched to, so this recorded target is the authoritative
    /// restore point; the profile is only a fallback. `None` on a non-NixOS host
    /// or when `/run/current-system` could not be resolved at activation. It lives
    /// on the hidden volume and is read by the teardown that restores the decoy, so
    /// it is only meaningful while a session is active. This is an internal restore
    /// key, not operator-facing platform state, so it stays a flat field like
    /// `config_fingerprint`.
    #[serde(default)]
    pub decoy_system: Option<String>,

    /// Timing of the most recent successful activation.
    ///
    /// Written as activation commits to Active and kept across deactivation, so
    /// `nails status` can tell the operator how long the last activation took
    /// (useful to judge whether a slow rebuild is unusual). `None` until the first
    /// successful activation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_activation: Option<LastActivation>,

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

    /// Start time of [`owner_pid`](Self::owner_pid), in clock ticks since boot
    /// (field 22 of `/proc/<pid>/stat`), captured at write time.
    ///
    /// A pid alone can be reused; the pid and its start time (within the same
    /// boot) identify one process, so a teardown signals the recorded owner only
    /// when both still match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_start_time: Option<u64>,

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
            platform: None,
            config_fingerprint: None,
            decoy_system: None,
            last_activation: None,
            last_modified: Utc::now(),
            boot_id: None,
            owner_pid: 0,
            owner_start_time: None,
            integrity_sha256: None,
        }
    }
}

impl StateFile {
    /// Whether the last activation ran on NixOS (the only platform with a layer).
    pub fn is_nixos(&self) -> bool {
        matches!(self.platform, Some(PlatformState::NixOs { .. }))
    }

    /// Store path of the hidden NixOS system generation in force, if any.
    ///
    /// `Some` only on NixOS after a switch produced a toplevel; `None` on every
    /// other platform. Deactivation keys the decoy restore on this.
    pub fn hidden_toplevel(&self) -> Option<&str> {
        match &self.platform {
            Some(PlatformState::NixOs { generation, .. }) => generation.as_deref(),
            _ => None,
        }
    }

    /// Reason the hidden NixOS configuration was not applied on the last
    /// activation, if the switch failed but the activation was kept.
    pub fn last_switch_warning(&self) -> Option<&str> {
        match &self.platform {
            Some(PlatformState::NixOs {
                last_switch_warning,
                ..
            }) => last_switch_warning.as_deref(),
            _ => None,
        }
    }

    /// Record the NixOS generation, marking the platform NixOS and preserving any
    /// stored switch warning. A `None` generation keeps a previously stored one
    /// (a switch that applied without yielding a fresh toplevel does not erase the
    /// generation already in force).
    pub fn set_nixos_generation(&mut self, generation: Option<String>) {
        let generation = generation.or_else(|| self.hidden_toplevel().map(str::to_string));
        let last_switch_warning = self.last_switch_warning().map(str::to_string);
        self.platform = Some(PlatformState::NixOs {
            generation,
            last_switch_warning,
        });
    }

    /// Record (or clear) the last NixOS switch warning, marking the platform NixOS
    /// and preserving the stored generation.
    pub fn set_switch_warning(&mut self, warning: Option<String>) {
        let generation = self.hidden_toplevel().map(str::to_string);
        self.platform = Some(PlatformState::NixOs {
            generation,
            last_switch_warning: warning,
        });
    }

    /// Mark the platform as FHS / Debian-family with no recorded family, unless
    /// a NixOS section is already present. Equivalent to
    /// [`mark_fhs_family(None)`](Self::mark_fhs_family).
    pub fn mark_debian_family(&mut self) {
        self.mark_fhs_family(None);
    }

    /// Mark the platform as FHS / Debian-family, recording the FHS family only
    /// when it is one NAILS keeps on the wire (Fedora or Arch).
    ///
    /// A Debian-family or unresolved host records no family, so its section
    /// stays `{"platform":"debian_family"}` — byte identical to what earlier
    /// releases wrote — and the state file's integrity digest is unchanged
    /// across the upgrade. No-op when a NixOS section is already recorded, since
    /// that host has a declarative layer this would erase.
    pub fn mark_fhs_family(&mut self, family: Option<Family>) {
        if !self.is_nixos() {
            self.platform = Some(PlatformState::DebianFamily {
                family: recorded_family(family),
            });
        }
    }

    /// The FHS family recorded for the last activation, if any.
    ///
    /// `Some` only when a Fedora or Arch activation recorded one; `None` on a
    /// Debian-family host, on NixOS, and before the first activation.
    pub fn family(&self) -> Option<Family> {
        match &self.platform {
            Some(PlatformState::DebianFamily { family }) => *family,
            _ => None,
        }
    }

    /// Drop the platform section (rollback to Inactive clears stale activation
    /// metadata).
    pub fn clear_platform(&mut self) {
        self.platform = None;
    }

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
    /// use nails_base::StateFile;
    /// use nails_base::config::Config;
    /// use std::path::Path;
    ///
    /// let config = Config::default();
    /// let state = StateFile::default();
    /// let root = config.hidden_volume_root.to_string_lossy();
    /// state.save(Path::new("/mnt/hidden-volume/state.json"), &root)?;
    /// # Ok::<(), nails_base::NailsError>(())
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
    /// use nails_base::StateFile;
    /// use std::path::{Path, PathBuf};
    ///
    /// let state = StateFile::default();
    /// let custom_root = PathBuf::from("/tmp");
    /// state.save_with_custom_root(Path::new("/tmp/state.json"), &custom_root)?;
    /// # Ok::<(), nails_base::NailsError>(())
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
        // 1. Stamp write-time provenance onto a working copy.
        let mut final_state = self.clone();
        final_state.boot_id = read_boot_id();
        final_state.owner_pid = std::process::id();
        final_state.owner_start_time = crate::process::proc_start_time(final_state.owner_pid);

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
            tracing::debug!(
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

/// Which FHS family is kept on the wire of the state file.
///
/// Only Fedora and Arch are recorded. A Debian-family host (or one whose family
/// could not be resolved) records nothing, so its section serialises to exactly
/// `{"platform":"debian_family"}` — byte identical to what every release before
/// families were recorded wrote. This keeps the integrity digest of the common
/// Debian-family install unchanged across the upgrade.
fn recorded_family(family: Option<Family>) -> Option<Family> {
    match family {
        Some(Family::Fedora) => Some(Family::Fedora),
        Some(Family::Arch) => Some(Family::Arch),
        Some(Family::Debian) | None => None,
    }
}

/// Compute the SHA-256 integrity digest over a state file.
///
/// The caller is responsible for clearing `integrity_sha256` first so the digest
/// is computed over a deterministic body. Exposed to the crate so the golden
/// state-file generator stamps a digest the same way [`StateFile::save`] does.
pub(crate) fn compute_integrity(state: &StateFile) -> Result<String> {
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
pub fn read_boot_id() -> Option<String> {
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
