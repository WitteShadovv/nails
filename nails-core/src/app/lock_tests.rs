// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for taking the exclusive state lock.

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
