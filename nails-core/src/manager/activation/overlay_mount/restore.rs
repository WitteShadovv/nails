use crate::manager::activation::guards::NixDaemonGuard;
use crate::{Filesystem, NailsError, NailsManager, Result};
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{ForkResult, fork};
use std::ffi::CString;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs as unix_fs;
use std::path::Path;

/// Exit codes used by the raw-syscall fork helpers. The child must stay
/// async-signal-safe, so it reports failures as distinct exit codes and the
/// parent (which may allocate) turns them into messages.
mod child_exit {
    pub(super) const UNSHARE_FS: i32 = 11;
    pub(super) const SETNS: i32 = 12;
    pub(super) const BIND: i32 = 13;
    pub(super) const REMOUNT_RO: i32 = 14;
    pub(super) const SYMLINK: i32 = 22;
}

fn describe_child_exit(code: i32) -> &'static str {
    match code {
        child_exit::UNSHARE_FS => "unshare(CLONE_FS)",
        child_exit::SETNS => "setns(CLONE_NEWNS)",
        child_exit::BIND => "bind mount",
        child_exit::REMOUNT_RO => "read-only remount",
        child_exit::SYMLINK => "symlinkat",
        _ => "unknown step",
    }
}

fn cstring_for(path: &Path) -> Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(|e| {
        NailsError::OverlayError(format!(
            "Path {} cannot be passed to a syscall: {e}",
            path.display()
        ))
    })
}

#[cfg(debug_assertions)]
fn assert_single_threaded_before_fork() {
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if let Some(count) = line.strip_prefix("Threads:") {
                let threads: usize = count.trim().parse().unwrap_or(0);
                debug_assert_eq!(
                    threads, 1,
                    "init-namespace fork helper must run before any threads are spawned (Threads: {threads})"
                );
            }
        }
    }
}

/// Child body for the read-only self-bind, entered after `fork`.
///
/// Async-signal-safe: raw syscalls only, no allocation, no formatting, no
/// buffered I/O. Every string was built in the parent before the fork.
///
/// # Safety
/// Must be called only in the forked child with `target` pointing at a NUL
/// terminated string that outlives the call, and `ns_fd` referring to an open
/// mount-namespace file.
#[allow(unsafe_code)]
unsafe fn self_bind_ro_child(ns_fd: RawFd, target: *const nix::libc::c_char) -> i32 {
    use nix::libc;
    // SAFETY: the caller guarantees `ns_fd` is an open namespace file and
    // `target` a live NUL-terminated path; the kernel only reads them. A bind
    // mount ignores the filesystem type and data, so null is valid for both.
    unsafe {
        if libc::unshare(libc::CLONE_FS) != 0 {
            return child_exit::UNSHARE_FS;
        }
        if libc::setns(ns_fd, libc::CLONE_NEWNS) != 0 {
            return child_exit::SETNS;
        }
        let no_data = std::ptr::null();
        let no_fstype = std::ptr::null();
        if libc::mount(target, target, no_fstype, libc::MS_BIND, no_data) != 0 {
            return child_exit::BIND;
        }
        if libc::mount(
            target,
            target,
            no_fstype,
            libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY,
            no_data,
        ) != 0
        {
            return child_exit::REMOUNT_RO;
        }
    }
    0
}

/// Child body for replacing a symlink, entered after `fork`.
///
/// Async-signal-safe: raw syscalls only.
///
/// # Safety
/// Must be called only in the forked child with `link`/`target` pointing at NUL
/// terminated strings that outlive the call, and `ns_fd` referring to an open
/// mount-namespace file.
#[allow(unsafe_code)]
unsafe fn replace_symlink_child(
    ns_fd: RawFd,
    link: *const nix::libc::c_char,
    target: *const nix::libc::c_char,
) -> i32 {
    use nix::libc;
    // SAFETY: the caller guarantees `ns_fd` is an open namespace file and
    // `link`/`target` live NUL-terminated paths; the kernel only reads them.
    unsafe {
        if libc::unshare(libc::CLONE_FS) != 0 {
            return child_exit::UNSHARE_FS;
        }
        if libc::setns(ns_fd, libc::CLONE_NEWNS) != 0 {
            return child_exit::SETNS;
        }
        // Best-effort removal of any existing symlink; a failure here surfaces as
        // an EEXIST from symlinkat below.
        let _ = libc::unlink(link);
        if libc::symlinkat(target, libc::AT_FDCWD, link) != 0 {
            return child_exit::SYMLINK;
        }
    }
    0
}

impl<F: Filesystem> NailsManager<F> {
    /// Whether this process runs in a different mount namespace than PID 1.
    ///
    /// When they are identical (the normal sudo-from-terminal / transient-unit
    /// case) a bind created here already applies to the init namespace, so the
    /// fork/`setns` helper is skipped — avoiding a second, stacked bind.
    fn init_namespace_differs() -> Result<bool> {
        let self_ns = Self::namespace_identity(Path::new("/proc/self/ns/mnt"))?;
        let init_ns = Self::namespace_identity(Path::new("/proc/1/ns/mnt"))?;
        Ok(self_ns != init_ns)
    }

    fn namespace_identity(path: &Path) -> Result<(u64, u64)> {
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::metadata(path).map_err(|e| {
            NailsError::OverlayError(format!(
                "Failed to stat mount namespace {}: {e}",
                path.display()
            ))
        })?;
        Ok((metadata.dev(), metadata.ino()))
    }

    fn restore_nix_store_bind_mount() -> Result<()> {
        let nix_store = Path::new("/nix/store");

        // Self-bind the already-overlaid /nix/store read-only. A writable remount
        // by nix-daemon (LocalStore::makeStoreWritable) then resolves into the
        // overlay upper instead of the decoy backing store, so hidden-session
        // writes never land on the decoy.
        Self::restore_read_only_bind_mount(nix_store, nix_store)?;
        tracing::info!("Read-only self-bind on /nix/store restored in manager namespace");

        if Self::init_namespace_differs()? {
            Self::restore_read_only_self_bind_in_init_namespace(nix_store)?;
            tracing::info!("Read-only self-bind on /nix/store restored in init mount namespace");
        } else {
            tracing::debug!(
                "Manager and init mount namespaces are identical; one /nix/store bind suffices"
            );
        }

        Ok(())
    }

    fn restore_read_only_bind_mount(source: &Path, target: &Path) -> Result<()> {
        nix::mount::mount(
            Some(source),
            target,
            None::<&str>,
            nix::mount::MsFlags::MS_BIND,
            None::<&str>,
        )
        .map_err(|e| {
            NailsError::OverlayError(format!(
                "Failed to bind mount {} to {}: {}",
                source.display(),
                target.display(),
                e
            ))
        })?;

        nix::mount::mount(
            Some(target),
            target,
            None::<&str>,
            nix::mount::MsFlags::MS_BIND
                | nix::mount::MsFlags::MS_REMOUNT
                | nix::mount::MsFlags::MS_RDONLY,
            None::<&str>,
        )
        .map_err(|e| {
            NailsError::OverlayError(format!(
                "Failed to remount {} read-only: {}",
                target.display(),
                e
            ))
        })
    }

    #[allow(unsafe_code)]
    fn restore_read_only_self_bind_in_init_namespace(target: &Path) -> Result<()> {
        // Build everything in the parent so the child allocates nothing.
        let init_namespace = std::fs::File::open("/proc/1/ns/mnt").map_err(|e| {
            NailsError::OverlayError(format!("Failed to open init mount namespace: {e}"))
        })?;
        let ns_fd = init_namespace.as_raw_fd();
        let target_c = cstring_for(target)?;

        #[cfg(debug_assertions)]
        assert_single_threaded_before_fork();

        // SAFETY: the child runs only async-signal-safe code (raw syscalls in
        // `self_bind_ro_child`, then `_exit`), so it never touches a lock or an
        // allocator that another thread held at fork time.
        let child = unsafe { fork() }.map_err(|e| {
            NailsError::OverlayError(format!("Failed to fork init namespace helper: {e}"))
        })?;

        match child {
            ForkResult::Child => {
                // SAFETY: this is the forked child; `ns_fd` stays open and
                // `target_c` alive until `_exit`, since both were made before
                // the fork and nothing in the child drops them.
                let code = unsafe { self_bind_ro_child(ns_fd, target_c.as_ptr()) };
                // SAFETY: `_exit` skips destructors and atexit handlers, which
                // must not run on the parent's state copied into the child.
                unsafe { nix::libc::_exit(code) }
            }
            ForkResult::Parent { child } => {
                Self::wait_for_init_namespace_helper(child, "/nix/store bind")
            }
        }
    }

    fn replace_symlink(link: &Path, target: &Path) -> Result<()> {
        match std::fs::symlink_metadata(link) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                std::fs::remove_file(link).map_err(|err| {
                    NailsError::OverlayError(format!(
                        "Failed to remove existing symlink {}: {}",
                        link.display(),
                        err
                    ))
                })?;
            }
            Ok(_) => {
                return Err(NailsError::OverlayError(format!(
                    "{} exists but is not a symlink",
                    link.display()
                )));
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(NailsError::OverlayError(format!(
                    "Failed to inspect {}: {}",
                    link.display(),
                    err
                )));
            }
        }

        unix_fs::symlink(target, link).map_err(|err| {
            NailsError::OverlayError(format!(
                "Failed to create symlink {} -> {}: {}",
                link.display(),
                target.display(),
                err
            ))
        })?;

        let restored_target = std::fs::read_link(link).map_err(|err| {
            NailsError::OverlayError(format!(
                "Failed to verify symlink {}: {}",
                link.display(),
                err
            ))
        })?;
        if restored_target != target {
            return Err(NailsError::OverlayError(format!(
                "Symlink {} points to {} instead of {}",
                link.display(),
                restored_target.display(),
                target.display()
            )));
        }

        if !link.exists() {
            return Err(NailsError::OverlayError(format!(
                "Symlink {} is still not reachable after restoration",
                link.display()
            )));
        }

        Ok(())
    }

    fn restore_run_current_system_symlink(target: &Path) -> Result<()> {
        let run_current = Path::new("/run/current-system");
        Self::replace_symlink(run_current, target)?;
        tracing::info!(
            target = %target.display(),
            "Restored /run/current-system symlink in manager namespace"
        );

        if Self::init_namespace_differs()? {
            Self::restore_run_current_system_symlink_in_init_namespace(run_current, target)?;
            tracing::info!(
                target = %target.display(),
                "Restored /run/current-system symlink in init mount namespace"
            );
        } else {
            tracing::debug!(
                "Manager and init mount namespaces are identical; one symlink update suffices"
            );
        }

        Ok(())
    }

    #[allow(unsafe_code)]
    fn restore_run_current_system_symlink_in_init_namespace(
        link: &Path,
        target: &Path,
    ) -> Result<()> {
        let init_namespace = std::fs::File::open("/proc/1/ns/mnt").map_err(|e| {
            NailsError::OverlayError(format!("Failed to open init mount namespace: {e}"))
        })?;
        let ns_fd = init_namespace.as_raw_fd();
        let link_c = cstring_for(link)?;
        let target_c = cstring_for(target)?;

        #[cfg(debug_assertions)]
        assert_single_threaded_before_fork();

        // SAFETY: as for the /nix/store helper, the child runs only raw
        // syscalls (`replace_symlink_child`) and `_exit`.
        let child = unsafe { fork() }.map_err(|e| {
            NailsError::OverlayError(format!("Failed to fork init namespace symlink helper: {e}"))
        })?;

        match child {
            ForkResult::Child => {
                // SAFETY: this is the forked child; `ns_fd`, `link_c` and
                // `target_c` were made before the fork and outlive the call.
                let code =
                    unsafe { replace_symlink_child(ns_fd, link_c.as_ptr(), target_c.as_ptr()) };
                // SAFETY: as above, `_exit` skips the parent's destructors.
                unsafe { nix::libc::_exit(code) }
            }
            ForkResult::Parent { child } => {
                Self::wait_for_init_namespace_helper(child, "/run/current-system symlink")
            }
        }
    }

    fn wait_for_init_namespace_helper(child: nix::unistd::Pid, context: &str) -> Result<()> {
        match waitpid(child, None).map_err(|e| {
            NailsError::OverlayError(format!(
                "Failed waiting for init namespace helper ({context}): {e}"
            ))
        })? {
            WaitStatus::Exited(_, 0) => Ok(()),
            WaitStatus::Exited(_, status) => Err(NailsError::OverlayError(format!(
                "Init namespace helper ({context}) failed at {}",
                describe_child_exit(status)
            ))),
            WaitStatus::Signaled(_, signal, _) => Err(NailsError::OverlayError(format!(
                "Init namespace helper ({context}) terminated by signal {signal}"
            ))),
            status => Err(NailsError::OverlayError(format!(
                "Init namespace helper ({context}) ended unexpectedly: {status:?}"
            ))),
        }
    }

    /// Restore NixOS security model after /nix overlay
    pub(super) fn restore_nix_security_model(&self, nix_guard: &mut NixDaemonGuard) -> Result<()> {
        // Step 1: Recreate read-only bind mount on /nix/store
        // The overlay on /nix hides the boot-time bind mount; we recreate it as a
        // read-only *self*-bind so regular processes see /nix/store as read-only
        // (defense-in-depth) and daemon writes resolve into the overlay upper.
        tracing::info!("Restoring read-only self-bind on /nix/store...");
        if crate::runtime_safety::should_skip_host_interaction() {
            self.filesystem
                .bind_mount(Path::new("/nix/store"), Path::new("/nix/store"))?;
        } else {
            Self::restore_nix_store_bind_mount()?;
        }

        // Step 2: Restart nix-daemon (inherits overlay, creates own rw namespace)
        tracing::info!("Restarting nix-daemon (now writing to overlay)...");
        if let Some(system_profile) = crate::manager::helpers::cached_current_system_profile() {
            tracing::info!(system_profile = %system_profile.display(), "Restoring /run/current-system symlink before nix-daemon restart");
            if crate::runtime_safety::should_skip_host_interaction() {
                crate::manager::helpers::ensure_run_current_system_symlink(
                    &self.filesystem,
                    &system_profile,
                )
                .map_err(|e| {
                    NailsError::NixOSError(format!(
                        "Failed to restore /run/current-system before restarting nix-daemon: {}",
                        e
                    ))
                })?;
            } else {
                Self::restore_run_current_system_symlink(&system_profile).map_err(|e| {
                    NailsError::NixOSError(format!(
                        "Failed to restore /run/current-system before restarting nix-daemon: {}",
                        e
                    ))
                })?;
            }
        } else {
            tracing::warn!(
                "No cached current system profile was available before nix-daemon restart"
            );
        }
        for probe in [
            "/run/current-system",
            "/run/current-system/systemd/lib/systemd/systemd-executor",
            "/proc/1/root/run/current-system/systemd/lib/systemd/systemd-executor",
            "/run/current-system/sw/bin/nix-daemon",
            "/proc/1/root/run/current-system/sw/bin/nix-daemon",
            "/nix/store",
            "/proc/1/root/nix/store",
        ] {
            tracing::info!(
                probe,
                exists = Path::new(probe).exists(),
                "Pre-restart path probe"
            );
        }
        crate::manager::helpers::ServiceController::start_nix_daemon_and_wait().map_err(|e| {
            NailsError::NixOSError(format!(
                "Failed to restart nix-daemon after /nix overlay activation: {}",
                e
            ))
        })?;
        nix_guard.disarm();

        Ok(())
    }
}

#[cfg(test)]
#[path = "tests_restore.rs"]
mod tests_restore;
