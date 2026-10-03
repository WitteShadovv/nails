//! # Inter-process State Lock
//!
//! A single-writer lock guarding every state-mutating operation.
//!
//! Mounting overlays, tearing them down, and rewriting the state file must not
//! interleave between two `nails` invocations. [`StateLock`] takes an exclusive
//! `flock(2)` on `<state dir>/.lock` on the hidden volume, so a second mutating
//! command fails fast instead of racing the first.
//!
//! The lock is advisory and tied to the open file description, so the kernel
//! releases it automatically when the holding process exits or crashes — there
//! is no stale PID file to reap. The lock file lives on the hidden volume, never
//! on the decoy system, so holding it leaves no decoy-side artifact.

use crate::filesystem::SafeRoot;
use crate::{NailsError, Result};
use nix::fcntl::{Flock, FlockArg};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// How long emergency teardown waits for the lock before proceeding without it.
pub const EMERGENCY_LOCK_TIMEOUT: Duration = Duration::from_secs(2);

/// An exclusive, process-held lock over the state directory.
///
/// Dropping the value releases the lock. The guard must therefore be kept alive
/// for the whole duration of the operation it protects.
pub struct StateLock {
    /// Held purely for its `Drop`, which releases the advisory lock.
    _flock: Flock<File>,
    path: PathBuf,
}

impl StateLock {
    /// Name of the lock file within the state directory.
    pub const LOCK_FILE_NAME: &'static str = ".lock";

    /// Path of the lock file for a given state directory.
    pub fn lock_path(state_dir: &Path) -> PathBuf {
        state_dir.join(Self::LOCK_FILE_NAME)
    }

    /// Open (creating if needed) the lock file with owner-only permissions.
    ///
    /// The state directory is the hidden-volume path the lock lives in, so the
    /// open is anchored there through [`SafeRoot`]: the lock file is resolved
    /// with `O_NOFOLLOW` beneath the pinned directory fd, so a symlink swapped in
    /// at `.lock` is refused instead of redirecting the create onto the decoy.
    fn open_lock_file(state_dir: &Path) -> Result<File> {
        let safe_root = SafeRoot::open(state_dir)?;
        safe_root.open_rw_create(Path::new(Self::LOCK_FILE_NAME), 0o600)
    }

    /// Take the lock without blocking.
    ///
    /// Returns [`NailsError::OperationInProgress`] naming the holding PID when
    /// another process already holds the lock. This is the path every ordinary
    /// mutating command (activate, deactivate, init, recover) takes.
    pub fn try_acquire(state_dir: &Path) -> Result<Self> {
        let path = Self::lock_path(state_dir);
        let file = Self::open_lock_file(state_dir)?;
        match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
            Ok(flock) => Ok(Self::finish(flock, path)),
            Err((file, _errno)) => {
                let pid = read_holder_pid(&file);
                Err(NailsError::OperationInProgress { pid })
            }
        }
    }

    /// Take the lock, retrying until a deadline before giving up.
    ///
    /// Returns `Ok(None)` on timeout so the caller (emergency teardown) can
    /// proceed without the lock rather than block indefinitely on an
    /// unresponsive or crashed holder.
    pub fn acquire_with_timeout(state_dir: &Path, timeout: Duration) -> Result<Option<Self>> {
        let path = Self::lock_path(state_dir);
        let deadline = Instant::now() + timeout;
        let mut file = Self::open_lock_file(state_dir)?;
        loop {
            match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
                Ok(flock) => return Ok(Some(Self::finish(flock, path))),
                Err((returned, _errno)) => {
                    if Instant::now() >= deadline {
                        return Ok(None);
                    }
                    file = returned;
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }
    }

    /// Record the holding PID in the lock file so a contending process can
    /// report who holds it, then wrap the locked handle in the guard.
    fn finish(mut flock: Flock<File>, path: PathBuf) -> Self {
        let pid = std::process::id();
        let _ = write_holder_pid(&mut flock, pid);
        Self {
            _flock: flock,
            path,
        }
    }

    /// Path of the lock file this guard holds.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl std::fmt::Debug for StateLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateLock")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

/// Overwrite the lock file with the holder's PID.
fn write_holder_pid(flock: &mut Flock<File>, pid: u32) -> std::io::Result<()> {
    let file: &mut File = flock;
    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(pid.to_string().as_bytes())?;
    file.flush()?;
    Ok(())
}

/// Read the PID the current holder wrote, or 0 when it cannot be determined.
fn read_holder_pid(mut file: &File) -> u32 {
    let _ = file.seek(SeekFrom::Start(0));
    let mut buf = String::new();
    if file.read_to_string(&mut buf).is_ok() {
        buf.trim().parse::<u32>().unwrap_or(0)
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_acquire_succeeds_on_a_fresh_directory() {
        let dir = tempfile::tempdir().unwrap();
        let lock = StateLock::try_acquire(dir.path()).unwrap();
        assert_eq!(lock.path(), StateLock::lock_path(dir.path()));
        assert!(lock.path().exists());
    }

    #[test]
    fn acquire_refuses_a_symlinked_lock_file() {
        // A symlink planted at `.lock` must not be followed: the open is anchored
        // through SafeRoot with O_NOFOLLOW, so the lock cannot be redirected onto
        // another file (which flock would then pin and the PID write would clobber).
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let victim = outside.path().join("victim");
        std::fs::write(&victim, "original").unwrap();
        std::os::unix::fs::symlink(&victim, StateLock::lock_path(dir.path())).unwrap();

        assert!(StateLock::try_acquire(dir.path()).is_err());
        // The link's target is untouched.
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "original");
    }

    #[test]
    fn second_acquire_fails_fast_naming_the_holder_pid() {
        let dir = tempfile::tempdir().unwrap();
        let _held = StateLock::try_acquire(dir.path()).unwrap();

        match StateLock::try_acquire(dir.path()) {
            Err(NailsError::OperationInProgress { pid }) => {
                assert_eq!(pid, std::process::id());
            }
            other => panic!("expected OperationInProgress, got {other:?}"),
        }
    }

    #[test]
    fn lock_message_matches_the_user_facing_wording() {
        let dir = tempfile::tempdir().unwrap();
        let _held = StateLock::try_acquire(dir.path()).unwrap();
        let err = StateLock::try_acquire(dir.path()).unwrap_err();
        let pid = std::process::id();
        assert_eq!(
            err.to_string(),
            format!("another nails operation is running (pid {pid})")
        );
    }

    #[test]
    fn release_on_drop_lets_the_next_caller_acquire() {
        let dir = tempfile::tempdir().unwrap();
        {
            let _held = StateLock::try_acquire(dir.path()).unwrap();
        }
        // Previous guard dropped: the lock must be free again.
        let _again = StateLock::try_acquire(dir.path()).unwrap();
    }

    #[test]
    fn acquire_with_timeout_returns_none_when_held() {
        let dir = tempfile::tempdir().unwrap();
        let _held = StateLock::try_acquire(dir.path()).unwrap();
        let start = Instant::now();
        let outcome =
            StateLock::acquire_with_timeout(dir.path(), Duration::from_millis(200)).unwrap();
        assert!(outcome.is_none(), "timed-out acquire should yield None");
        assert!(start.elapsed() >= Duration::from_millis(150));
    }

    #[test]
    fn acquire_with_timeout_succeeds_when_free() {
        let dir = tempfile::tempdir().unwrap();
        let outcome =
            StateLock::acquire_with_timeout(dir.path(), Duration::from_millis(200)).unwrap();
        assert!(
            outcome.is_some(),
            "free lock should be acquired immediately"
        );
    }
}
