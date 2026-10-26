// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The exclusive state lock, taken before a mutating operation touches the
//! mounts and the state file.
//!
//! A concurrent `nails` operation holds this lock, so a second one fails fast
//! rather than racing it. The lock lies next to the state file and is created
//! only on the volume mounted at `hidden_root` (or on the root the operator
//! accepted). The operations that write under it take it in their own lock
//! step, which hands out the only handle that runs their writing steps
//! ([`activate`](super::activate), [`deactivate`](super::deactivate),
//! [`discard_upper`](super::discard_upper)); a front end renders a
//! [`LockError`]. The gate and the acquisition are here.

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

/// Why an operation's lock step handed out no handle.
#[derive(Debug)]
pub enum LockError {
    /// The attach gate refused the root: nothing was written. The front end
    /// renders the refusal (exit `PreflightRefused`).
    Refused(Box<Refusal>),
    /// The directory could not be attached, or the lock could not be taken: a
    /// concurrent operation holds it. The front end reports it (exit `Failed`).
    Unavailable(NailsError),
    /// Taken under the lock: the state file is corrupt or unreadable, so the
    /// current state is unknown. Only an activation checks it; the front end
    /// reports it (exit `InvalidState`). The lock is released again.
    UntrustedState,
}

/// Take the exclusive state lock for an ordinary mutating command.
///
/// The lock is created only on the volume mounted at `hidden_root`, or on the
/// root the operator accepted with `allow`. A root the attach gate refuses is
/// returned as [`LockError::Refused`] with the gate's text and code; the
/// returned guard (on success) must be kept alive for the whole operation.
pub(crate) fn acquire_mutating(
    hidden_root: &Path,
    allow: Allow,
    state_file_path: &Path,
) -> Result<StateLock, LockError> {
    if let Ok(Assessment::Refused(refusal)) =
        HiddenRoot::assess_allowing(&RealFilesystem, hidden_root, allow)
    {
        return Err(LockError::Refused(Box::new(refusal)));
    }
    let dir = state_lock_dir(state_file_path);
    ensure_state_dir_attached_allowing(&RealFilesystem, hidden_root, dir, allow)
        .and_then(|()| StateLock::try_acquire(dir))
        .map_err(LockError::Unavailable)
}

/// For the lock steps' tests: take the lock beside `state_file_path` as
/// [`acquire_mutating`] does, without the attach gate, which refuses the
/// test's scratch directory (it is not a mount point).
#[cfg(test)]
pub(crate) fn acquire_unattached(
    _hidden_root: &Path,
    _allow: Allow,
    state_file_path: &Path,
) -> Result<StateLock, LockError> {
    StateLock::try_acquire(state_lock_dir(state_file_path)).map_err(LockError::Unavailable)
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

    /// A root the attach gate refuses (a scratch directory is no mount point)
    /// is the gate's refusal, before any lock file is created.
    #[test]
    fn a_root_the_attach_gate_refuses_takes_no_lock() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state.json");
        match acquire_mutating(dir.path(), Allow::Nothing, &state) {
            Err(LockError::Refused(_)) => {}
            Err(other) => panic!("expected the gate's refusal, got {other:?}"),
            Ok(_) => panic!("took the lock on a root the gate refuses"),
        }
        assert!(!StateLock::lock_path(dir.path()).exists());
    }

    /// A lock another operation holds is reported as unavailable, never
    /// taken twice.
    #[test]
    fn a_held_lock_is_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state.json");
        let _held = StateLock::try_acquire(dir.path()).unwrap();
        assert!(matches!(
            acquire_unattached(dir.path(), Allow::Nothing, &state),
            Err(LockError::Unavailable(
                NailsError::OperationInProgress { .. }
            ))
        ));
    }

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
