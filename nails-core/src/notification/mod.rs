//! Desktop notification signal files for post-activation user feedback
//!
//! The activation process runs as root and may restart the display manager
//! after the NixOS switch/rebuild step completes. This module provides a file-based signaling
//! mechanism so the logged-in user receives desktop notifications about:
//!
//! - Overlay mount status (OPTIMAL / DEGRADED / failed)
//! - NixOS rebuild completion (success / failure)
//!
//! # Flow
//!
//! 1. Root activation writes JSON signal files to `{hidden_volume}/notifications/`
//! 2. An XDG autostart entry runs `nails notify-dispatch` on user login
//! 3. The dispatch command reads pending files, calls `notify-send`, and deletes them

use crate::Result;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Build the environment overrides handed to `notify-send` so it reaches the
/// operator's session bus. Split from [`notification_runtime_environment`] as a
/// pure function of the operator's uid and the current display variables, so it
/// can be unit-tested without a real passwd or privilege-escalation environment.
fn build_runtime_environment(
    uid: Option<u32>,
    display: Option<String>,
    wayland_display: Option<String>,
) -> Vec<(&'static str, String)> {
    let mut env = Vec::new();

    if let Some(uid) = uid {
        let runtime_dir = format!("/run/user/{}", uid);
        env.push(("XDG_RUNTIME_DIR", runtime_dir.clone()));
        env.push((
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path={}/bus", runtime_dir),
        ));
    }

    if let Some(display) = display {
        env.push(("DISPLAY", display));
    }

    if let Some(wayland_display) = wayland_display {
        env.push(("WAYLAND_DISPLAY", wayland_display));
    }

    env
}

/// Environment overrides for the detached `notify-send` invocation.
///
/// `XDG_RUNTIME_DIR` (and the derived bus address) are built from the uid of the
/// operator resolved through [`crate::TargetUser`], so this agrees with every
/// other subsystem on who the operator is instead of re-reading the escalation
/// environment directly. The display variables are forwarded from the current
/// environment so the notification reaches the right display server.
#[cfg(not(test))]
pub fn notification_runtime_environment() -> Vec<(&'static str, String)> {
    let uid = crate::TargetUser::resolve().ok().map(|user| user.uid);
    build_runtime_environment(
        uid,
        std::env::var("DISPLAY").ok(),
        std::env::var("WAYLAND_DISPLAY").ok(),
    )
}

/// A desktop notification payload stored as a JSON signal file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Notification {
    /// Short title (shown as notification heading)
    pub title: String,
    /// Body text (shown as notification content)
    pub body: String,
    /// Urgency level for `notify-send`: "low", "normal", or "critical"
    #[serde(default = "default_urgency")]
    pub urgency: String,
    /// Freedesktop icon name (e.g., "security-high", "dialog-error")
    #[serde(default)]
    pub icon: Option<String>,
    /// ISO 8601 timestamp when the notification was created
    pub created_at: String,
}

fn default_urgency() -> String {
    "normal".to_string()
}

/// Return the notifications directory inside the hidden volume.
pub fn notifications_dir(hidden_volume_root: &Path) -> PathBuf {
    hidden_volume_root.join("notifications")
}

/// Write a notification signal file to the pending directory.
///
/// Creates the notifications directory if it doesn't exist.
///
/// Files are named `{YYYYMMDDTHHMMSSmmm}_{sanitized_title}.json`: a
/// millisecond-precision UTC timestamp followed by the sanitized title, so they
/// sort chronologically. The file is created exclusively; if a file of that
/// name already exists (same title written in the same millisecond), an
/// incrementing numeric suffix is appended so no notification is overwritten.
pub fn write_notification(hidden_volume_root: &Path, notification: &Notification) -> Result<()> {
    let dir = notifications_dir(hidden_volume_root);
    std::fs::create_dir_all(&dir).map_err(|e| {
        crate::NailsError::IoError(std::io::Error::new(
            e.kind(),
            format!(
                "Failed to create notifications dir {}: {}",
                dir.display(),
                e
            ),
        ))
    })?;

    // Set the notifications directory to 0o700 (owner rwx only).
    // The directory is chown'd to the target user below so they can manage files.
    if let Err(e) = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)) {
        tracing::warn!(
            dir = %dir.display(),
            error = %e,
            "Failed to set permissions on notifications directory (non-fatal)"
        );
    }

    // Resolve the operator once so both the directory and the signal file can be
    // handed to their numeric uid and gid. The gid matters: on NixOS an ordinary
    // account's primary group is `users`, not a per-user group, so the previous
    // `chown user:user` left the files owned by a group the operator was not in
    // and the user-run dispatcher could not read them. Skipped in test/test-like
    // runtimes, where the process may lack the privilege to chown to another
    // account.
    let target_user = if crate::runtime_safety::should_skip_host_interaction() {
        tracing::debug!(
            dir = %dir.display(),
            "Skipping notification ownership in test/test-like context"
        );
        None
    } else {
        match crate::TargetUser::resolve() {
            Ok(user) => Some(user),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "Could not resolve the target user to own notification files (non-fatal)"
                );
                None
            }
        }
    };

    // Hand the directory to the operator so the user-run dispatcher can delete
    // the files it processes.
    if let Some(user) = target_user.as_ref()
        && let Err(e) = chown_to_user(&dir, user)
    {
        tracing::warn!(
            dir = %dir.display(),
            error = %e,
            "Failed to set ownership on notifications directory (non-fatal)"
        );
    }

    // Generate a filename that sorts chronologically
    let timestamp = chrono::Utc::now().format("%Y%m%dT%H%M%S%3f");
    let safe_title: String = notification
        .title
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .take(40)
        .collect();
    let json = serde_json::to_string_pretty(notification).map_err(|e| {
        crate::NailsError::IoError(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Failed to serialize notification: {}", e),
        ))
    })?;

    // Create the file exclusively so two notifications written in the same
    // millisecond with the same title cannot silently overwrite one another; on
    // a name collision, append an incrementing numeric suffix.
    const MAX_COLLISION_SUFFIXES: u32 = 10_000;
    let base = format!("{}_{}", timestamp, safe_title);
    let mut path = dir.join(format!("{}.json", base));
    let mut attempt: u32 = 0;
    let mut file = loop {
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => break file,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                attempt += 1;
                if attempt > MAX_COLLISION_SUFFIXES {
                    return Err(crate::NailsError::IoError(std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        format!(
                            "Failed to find a free notification filename for {} after {} attempts",
                            base, MAX_COLLISION_SUFFIXES
                        ),
                    )));
                }
                path = dir.join(format!("{}_{}.json", base, attempt));
            }
            Err(e) => {
                return Err(crate::NailsError::IoError(std::io::Error::new(
                    e.kind(),
                    format!(
                        "Failed to create notification file {}: {}",
                        path.display(),
                        e
                    ),
                )));
            }
        }
    };

    file.write_all(json.as_bytes()).map_err(|e| {
        crate::NailsError::IoError(std::io::Error::new(
            e.kind(),
            format!(
                "Failed to write notification file {}: {}",
                path.display(),
                e
            ),
        ))
    })?;

    // Set the notification file to 0o600 (owner rw only).
    // The file is chown'd to the target user below so dispatch_all can delete it.
    if let Err(e) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)) {
        tracing::warn!(
            path = %path.display(),
            error = %e,
            "Failed to set permissions on notification file (non-fatal)"
        );
    }

    // Hand the signal file to the operator for the same reason. Operating on the
    // open file descriptor avoids any symlink race on the path.
    if let Some(user) = target_user.as_ref()
        && let Err(e) = fchown_to_user(&file, user)
    {
        tracing::warn!(
            path = %path.display(),
            error = %e,
            "Failed to set ownership on notification file (non-fatal)"
        );
    }

    tracing::debug!(path = %path.display(), title = %notification.title, "Wrote notification signal file");
    Ok(())
}

/// Change `path`'s ownership to the operator's numeric uid and gid.
fn chown_to_user(path: &Path, user: &crate::TargetUser) -> std::io::Result<()> {
    std::os::unix::fs::chown(path, Some(user.uid), Some(user.gid))
}

/// Change the ownership of an open file descriptor to the operator. Using the fd
/// rather than the path closes the window where the path could be swapped for a
/// symlink between creation and chown.
fn fchown_to_user<Fd: std::os::fd::AsFd>(fd: Fd, user: &crate::TargetUser) -> nix::Result<()> {
    nix::unistd::fchown(
        fd,
        Some(nix::unistd::Uid::from_raw(user.uid)),
        Some(nix::unistd::Gid::from_raw(user.gid)),
    )
}

/// Read all pending notification signal files, sorted chronologically.
///
/// Returns `(file_path, notification)` pairs so callers can delete after dispatch.
pub fn read_pending(hidden_volume_root: &Path) -> Result<Vec<(PathBuf, Notification)>> {
    let dir = notifications_dir(hidden_volume_root);
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .map_err(|e| {
            crate::NailsError::IoError(std::io::Error::new(
                e.kind(),
                format!("Failed to read notifications dir {}: {}", dir.display(), e),
            ))
        })?
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "json"))
        .collect();

    // Sort by filename (which starts with timestamp) for chronological order
    entries.sort_by_key(|e| e.file_name());

    let mut results = Vec::new();
    for entry in entries {
        let path = entry.path();
        match std::fs::read_to_string(&path) {
            Ok(content) => match serde_json::from_str::<Notification>(&content) {
                Ok(notification) => results.push((path, notification)),
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "Skipping malformed notification file"
                    );
                }
            },
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "Failed to read notification file"
                );
            }
        }
    }

    Ok(results)
}

/// Delete a notification signal file after successful dispatch.
pub fn clear_notification(path: &Path) -> Result<()> {
    std::fs::remove_file(path).map_err(|e| {
        crate::NailsError::IoError(std::io::Error::new(
            e.kind(),
            format!(
                "Failed to remove notification file {}: {}",
                path.display(),
                e
            ),
        ))
    })?;
    Ok(())
}

/// Delete all pending notification signal files.
pub fn clear_all(hidden_volume_root: &Path) -> Result<()> {
    let dir = notifications_dir(hidden_volume_root);
    if !dir.exists() {
        return Ok(());
    }
    for entry in std::fs::read_dir(&dir)
        .map_err(|e| {
            crate::NailsError::IoError(std::io::Error::new(
                e.kind(),
                format!("Failed to read notifications dir {}: {}", dir.display(), e),
            ))
        })?
        .flatten()
    {
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "json") {
            let _ = std::fs::remove_file(&path);
        }
    }
    Ok(())
}

/// Dispatch all pending notifications via `notify-send`.
///
/// Reads all pending signal files, invokes `notify-send` for each,
/// and deletes successfully dispatched files. Returns the count of
/// notifications sent.
///
/// Silently skips notifications if `notify-send` is not available.
///
/// # Test Safety
///
/// This function is disabled during testing to prevent real desktop notifications:
/// - Set `NAILS_DISABLE_NOTIFICATIONS=1` environment variable, OR
/// - Compile with `#[cfg(test)]` (notification dispatch is always skipped in test builds)
pub fn dispatch_all(hidden_volume_root: &Path) -> Result<usize> {
    // LAYER 1: Compile-time test guard - NEVER dispatch in test builds
    #[cfg(test)]
    {
        tracing::debug!("Notification dispatch disabled in test build");
        let _ = hidden_volume_root; // suppress unused warning
        Ok(0)
    }

    // LAYER 2: Runtime test guard - skip host dispatch from test binaries
    #[cfg(not(test))]
    if crate::runtime_safety::should_skip_host_interaction() {
        tracing::debug!("Notification dispatch disabled in test/test-like runtime context");
        return Ok(0);
    }

    // LAYER 3: Runtime environment guard - check NAILS_DISABLE_NOTIFICATIONS early
    // This is the FIRST explicit env-var check, before we even read pending notifications
    #[cfg(not(test))]
    if is_notifications_disabled() {
        tracing::debug!("Notification dispatch disabled via NAILS_DISABLE_NOTIFICATIONS");
        return Ok(0);
    }

    #[cfg(not(test))]
    {
        let pending = read_pending(hidden_volume_root)?;
        if pending.is_empty() {
            return Ok(0);
        }

        // Check if notify-send is available (also checks NAILS_DISABLE_NOTIFICATIONS)
        let notify_send = which_notify_send();
        if notify_send.is_none() {
            tracing::warn!("notify-send not found in PATH; skipping desktop notifications");
            return Ok(0);
        }
        let notify_send = notify_send.unwrap();

        let mut dispatched = 0;
        for (path, notification) in &pending {
            match send_notification(&notify_send, notification) {
                Ok(()) => {
                    let _ = clear_notification(path);
                    dispatched += 1;
                }
                Err(e) => {
                    tracing::warn!(
                        title = %notification.title,
                        error = %e,
                        "Failed to dispatch notification"
                    );
                }
            }
        }

        Ok(dispatched)
    }
}

/// Check if notifications are disabled via environment variable.
///
/// This is the runtime check used to prevent real notifications in tests
/// and other environments where desktop notifications are not desired.
#[cfg(not(test))]
fn is_notifications_disabled() -> bool {
    std::env::var(crate::constants::ENV_DISABLE_NOTIFICATIONS).is_ok()
}

/// Find `notify-send` in PATH.
///
/// Returns `None` if `NAILS_DISABLE_NOTIFICATIONS` is set (used in tests to prevent
/// real notifications from being sent).
#[cfg(not(test))]
fn which_notify_send() -> Option<PathBuf> {
    // Allow tests to disable notification dispatch
    if is_notifications_disabled() {
        return None;
    }

    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths).find_map(|dir| {
            let candidate = dir.join("notify-send");
            if candidate.is_file() {
                Some(candidate)
            } else {
                None
            }
        })
    })
}

/// Invoke `notify-send` with the given notification payload.
#[cfg(not(test))]
fn send_notification(notify_send: &Path, notification: &Notification) -> Result<()> {
    let mut cmd = std::process::Command::new(notify_send);
    cmd.arg("--urgency").arg(&notification.urgency);
    cmd.arg("--app-name").arg("NAILS");

    for (key, value) in notification_runtime_environment() {
        cmd.env(key, value);
    }

    if let Some(ref icon) = notification.icon {
        cmd.arg("--icon").arg(icon);
    }

    cmd.arg(&notification.title);
    cmd.arg(&notification.body);

    let output = cmd.output().map_err(|e| {
        crate::NailsError::IoError(std::io::Error::new(
            e.kind(),
            format!("Failed to run notify-send: {}", e),
        ))
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(crate::NailsError::IoError(std::io::Error::other(format!(
            "notify-send exited with {}: {}",
            output.status,
            stderr.trim()
        ))));
    }

    Ok(())
}

#[cfg(test)]
mod tests;
