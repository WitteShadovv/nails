use crate::manager::activation::guards::NixDaemonGuard;
use crate::{Filesystem, NailsError, NailsManager, Result};
use nix::sched::{CloneFlags, unshare};
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{ForkResult, fork};
use std::os::unix::fs as unix_fs;
use std::path::{Path, PathBuf};

impl<F: Filesystem> NailsManager<F> {
    fn live_submount_sources(target: &Path) -> Vec<(PathBuf, PathBuf)> {
        match std::fs::read_to_string("/proc/self/mountinfo") {
            Ok(mountinfo) => crate::filesystem::real::parse_submount_sources(&mountinfo, target),
            Err(err) => {
                tracing::warn!(
                    target = %target.display(),
                    error = %err,
                    "Failed reading live mountinfo for submount detection"
                );
                Vec::new()
            }
        }
    }

    fn restore_nix_store_bind_mount() -> Result<()> {
        let target = Path::new("/nix");
        let submount_sources = Self::live_submount_sources(target);

        let nix_store_source = crate::manager::helpers::cached_original_nix_store_bind_source()
            .or_else(|| {
                submount_sources
                    .into_iter()
                    .find_map(|(mount_point, source_path)| {
                        (mount_point == Path::new("/nix/store")).then_some(source_path)
                    })
            })
            .unwrap_or_else(|| PathBuf::from("/proc/1/root/nix/store"));

        let nix_store = Path::new("/nix/store");
        Self::restore_read_only_bind_mount(&nix_store_source, nix_store)?;
        tracing::info!(source = %nix_store_source.display(), "Read-only bind mount on /nix/store restored in manager namespace");

        Self::restore_read_only_bind_mount_in_init_namespace(nix_store)?;
        tracing::info!(source = %nix_store_source.display(), "Read-only bind mount on /nix/store restored in init mount namespace");

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

    fn restore_read_only_bind_mount_in_init_namespace(target: &Path) -> Result<()> {
        let caller_pid = std::process::id();
        let target = target.to_path_buf();

        let child = unsafe { fork() }.map_err(|e| {
            NailsError::OverlayError(format!("Failed to fork init namespace helper: {e}"))
        })?;

        match child {
            ForkResult::Child => {
                use std::fs::File;

                let source = PathBuf::from(format!("/proc/{caller_pid}/root{}", target.display()));

                let exit_code = match File::open("/proc/1/ns/mnt")
                    .map_err(|e| {
                        NailsError::OverlayError(format!(
                            "Failed to open init mount namespace: {e}"
                        ))
                    })
                    .and_then(|init_namespace| {
                        unshare(CloneFlags::CLONE_FS).map_err(|e| {
                            NailsError::OverlayError(format!(
                                "Failed to unshare filesystem attributes before entering init mount namespace: {e}"
                            ))
                        })?;

                        nix::sched::setns(&init_namespace, CloneFlags::CLONE_NEWNS).map_err(|e| {
                            NailsError::OverlayError(format!(
                                "Failed to enter init mount namespace: {e}"
                            ))
                        })?;

                        Self::restore_read_only_bind_mount(&source, &target)
                    }) {
                    Ok(()) => 0,
                    Err(err) => {
                        eprintln!("{err}");
                        1
                    }
                };

                unsafe { nix::libc::_exit(exit_code) }
            }
            ForkResult::Parent { child } => match waitpid(child, None).map_err(|e| {
                NailsError::OverlayError(format!("Failed waiting for init namespace helper: {e}"))
            })? {
                WaitStatus::Exited(_, 0) => Ok(()),
                WaitStatus::Exited(_, status) => Err(NailsError::OverlayError(format!(
                    "Init namespace helper exited with status {status}"
                ))),
                WaitStatus::Signaled(_, signal, _) => Err(NailsError::OverlayError(format!(
                    "Init namespace helper terminated by signal {signal}"
                ))),
                status => Err(NailsError::OverlayError(format!(
                    "Init namespace helper ended unexpectedly: {status:?}"
                ))),
            },
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

        Self::restore_run_current_system_symlink_in_init_namespace(target)?;
        tracing::info!(
            target = %target.display(),
            "Restored /run/current-system symlink in init mount namespace"
        );

        Ok(())
    }

    fn restore_run_current_system_symlink_in_init_namespace(target: &Path) -> Result<()> {
        let target = target.to_path_buf();

        let child = unsafe { fork() }.map_err(|e| {
            NailsError::OverlayError(format!("Failed to fork init namespace symlink helper: {e}"))
        })?;

        match child {
            ForkResult::Child => {
                use std::fs::File;

                let exit_code = match File::open("/proc/1/ns/mnt")
                    .map_err(|e| {
                        NailsError::OverlayError(format!(
                            "Failed to open init mount namespace: {e}"
                        ))
                    })
                    .and_then(|init_namespace| {
                        unshare(CloneFlags::CLONE_FS).map_err(|e| {
                            NailsError::OverlayError(format!(
                                "Failed to unshare filesystem attributes before entering init mount namespace: {e}"
                            ))
                        })?;

                        nix::sched::setns(&init_namespace, CloneFlags::CLONE_NEWNS).map_err(|e| {
                            NailsError::OverlayError(format!(
                                "Failed to enter init mount namespace: {e}"
                            ))
                        })?;

                        Self::replace_symlink(Path::new("/run/current-system"), &target)
                    }) {
                    Ok(()) => 0,
                    Err(err) => {
                        eprintln!("{err}");
                        1
                    }
                };

                unsafe { nix::libc::_exit(exit_code) }
            }
            ForkResult::Parent { child } => match waitpid(child, None).map_err(|e| {
                NailsError::OverlayError(format!(
                    "Failed waiting for init namespace symlink helper: {e}"
                ))
            })? {
                WaitStatus::Exited(_, 0) => Ok(()),
                WaitStatus::Exited(_, status) => Err(NailsError::OverlayError(format!(
                    "Init namespace symlink helper exited with status {status}"
                ))),
                WaitStatus::Signaled(_, signal, _) => Err(NailsError::OverlayError(format!(
                    "Init namespace symlink helper terminated by signal {signal}"
                ))),
                status => Err(NailsError::OverlayError(format!(
                    "Init namespace symlink helper ended unexpectedly: {status:?}"
                ))),
            },
        }
    }

    /// Restore NixOS security model after /nix overlay
    pub(super) fn restore_nix_security_model(&self, nix_guard: &mut NixDaemonGuard) -> Result<()> {
        // Step 1: Recreate read-only bind mount on /nix/store
        // The overlay on /nix hides the boot-time bind mount; we recreate it
        // so regular processes see /nix/store as read-only (defense-in-depth)
        tracing::info!("Restoring read-only bind mount on /nix/store...");
        if crate::runtime_safety::should_skip_host_interaction() {
            let nix_store_source = self
                .filesystem
                .find_submount_sources(Path::new("/nix"))?
                .into_iter()
                .find_map(|(mount_point, source_path)| {
                    (mount_point == Path::new("/nix/store")).then_some(source_path)
                })
                .or_else(crate::manager::helpers::cached_original_nix_store_bind_source)
                .unwrap_or_else(|| PathBuf::from("/nix/store"));
            self.filesystem
                .bind_mount(&nix_store_source, Path::new("/nix/store"))?;
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
