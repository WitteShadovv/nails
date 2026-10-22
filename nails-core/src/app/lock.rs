// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The exclusive state lock, taken before a mutating operation touches the
//! mounts and the state file.
//!
//! A concurrent `nails` operation holds this lock, so a second one fails fast
//! rather than racing it. The lock lies next to the state file and is created
//! only on the volume mounted at `hidden_root` (or on the root the operator
//! accepted). A front end renders the refusal and the lock error; the gate and
//! the acquisition are here.

use std::path::Path;

use crate::hidden_root::{Allow, Assessment, Refusal, ensure_state_dir_attached_allowing};
use crate::{
    EMERGENCY_LOCK_TIMEOUT, HiddenRoot, NailsError, RealFilesystem, StateLock,
    ensure_state_dir_attached,
};

/// Directory holding the state file (and its `.lock`) on the hidden volume.
pub fn state_lock_dir(state_file_path: &Path) -> &Path {
    state_file_path.parent().unwrap_or_else(|| Path::new("."))
}

/// The outcome of taking the exclusive state lock for an ordinary mutating
/// command.
pub enum LockOutcome {
    /// The lock was taken; keep the guard alive for the whole operation.
    Acquired(StateLock),
    /// The attach gate refused the root: nothing was written. The front end
    /// renders the refusal (exit `PreflightRefused`).
    Refused(Refusal),
    /// The directory could not be attached or the lock could not be taken (a
    /// concurrent operation holds it). The front end reports it (exit `Failed`).
    Error(NailsError),
}

/// Take the exclusive state lock for an ordinary mutating command.
///
/// The lock is created only on the volume mounted at `hidden_root`, or on the
/// root the operator accepted with `allow`. A root the attach gate refuses is
/// returned as [`LockOutcome::Refused`] with the gate's text and code; the
/// returned guard (on success) must be kept alive for the whole operation.
pub fn acquire_mutating(hidden_root: &Path, allow: Allow, state_file_path: &Path) -> LockOutcome {
    if let Ok(Assessment::Refused(refusal)) =
        HiddenRoot::assess_allowing(&RealFilesystem, hidden_root, allow)
    {
        return LockOutcome::Refused(refusal);
    }
    let dir = state_lock_dir(state_file_path);
    match ensure_state_dir_attached_allowing(&RealFilesystem, hidden_root, dir, allow)
        .and_then(|()| StateLock::try_acquire(dir))
    {
        Ok(lock) => LockOutcome::Acquired(lock),
        Err(error) => LockOutcome::Error(error),
    }
}

/// Take the state lock for emergency teardown, proceeding without it on timeout.
///
/// Emergency must never be blocked by a crashed or unresponsive holder, so after
/// a short wait it continues without the lock. The returned guard (when present)
/// must be kept alive for the duration of the teardown. Never creates `.lock` in
/// a bare mount-point directory on the decoy, nor on a disk mounted over the
/// hidden volume: then emergency proceeds without the lock.
pub fn acquire_for_emergency(hidden_root: &Path, state_file_path: &Path) -> Option<StateLock> {
    let dir = state_lock_dir(state_file_path);
    if let Err(error) = ensure_state_dir_attached(&RealFilesystem, hidden_root, dir) {
        tracing::warn!(%error, "Hidden volume not attached; proceeding with emergency teardown without the state lock");
        return None;
    }
    match StateLock::acquire_with_timeout(dir, EMERGENCY_LOCK_TIMEOUT) {
        Ok(Some(lock)) => Some(lock),
        Ok(None) => {
            tracing::warn!(
                "Proceeding with emergency teardown without the state lock (acquire timed out)"
            );
            None
        }
        Err(error) => {
            tracing::warn!(%error, "Could not open the state lock; proceeding with emergency teardown");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_for_emergency_takes_the_lock_when_the_volume_is_attached_and_free() {
        // The hidden volume is attached (a library unit-test build skips the
        // attach gate) and no other process holds the lock, so emergency
        // teardown must take the lock rather than fall through to unlocked
        // teardown. The returned guard names the `.lock` beside the state file,
        // proving the real lock on the derived state directory was acquired.
        let dir = tempfile::tempdir().unwrap();
        let state_file_path = dir.path().join("state.json");

        let lock = acquire_for_emergency(dir.path(), &state_file_path)
            .expect("a free, attached state lock must be acquired, not skipped");

        assert_eq!(lock.path(), StateLock::lock_path(dir.path()));
        assert!(lock.path().exists());
    }
}
