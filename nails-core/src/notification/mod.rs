//! Desktop notification signal files for post-activation user feedback
//!
//! The activation process runs as root and restarts the display manager before
//! the NixOS rebuild completes. This module provides a file-based signaling
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

use crate::{Result, obfuscate};
use serde::{Deserialize, Serialize};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

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
/// Files are named `{timestamp_millis}_{sanitized_title}.json` for ordering.
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

    // Set the notifications directory to 0o755 (owner rwx, group/other rx).
    // The directory is chown'd to the target user below so they can manage files.
    if let Err(e) = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)) {
        tracing::warn!(
            dir = %dir.display(),
            error = %e,
            "Failed to set permissions on notifications directory (non-fatal)"
        );
    }

    // Best-effort chown directory to target user so dispatch_all can delete files
    if let Ok(user) =
        std::env::var(obfuscate::env_target_user()).or_else(|_| std::env::var("SUDO_USER"))
    {
        let _ = std::process::Command::new("chown")
            .arg(format!("{}:{}", user, user))
            .arg(&dir)
            .output();
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
    let filename = format!("{}_{}.json", timestamp, safe_title);
    let path = dir.join(filename);

    let json = serde_json::to_string_pretty(notification).map_err(|e| {
        crate::NailsError::IoError(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Failed to serialize notification: {}", e),
        ))
    })?;

    std::fs::write(&path, json).map_err(|e| {
        crate::NailsError::IoError(std::io::Error::new(
            e.kind(),
            format!(
                "Failed to write notification file {}: {}",
                path.display(),
                e
            ),
        ))
    })?;

    // Set the notification file to 0o644 (owner rw, group/other read-only).
    // The file is chown'd to the target user below so dispatch_all can delete it.
    if let Err(e) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)) {
        tracing::warn!(
            path = %path.display(),
            error = %e,
            "Failed to set permissions on notification file (non-fatal)"
        );
    }

    // Best-effort chown to target user so dispatch_all can delete the file
    if let Ok(user) =
        std::env::var(obfuscate::env_target_user()).or_else(|_| std::env::var("SUDO_USER"))
    {
        let _ = std::process::Command::new("chown")
            .arg(format!("{}:{}", user, user))
            .arg(&path)
            .output();
    }

    tracing::debug!(path = %path.display(), title = %notification.title, "Wrote notification signal file");
    Ok(())
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

    // LAYER 2: Runtime test guard - check NAILS_DISABLE_NOTIFICATIONS early
    // This is the FIRST check, before we even read pending notifications
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
    std::env::var(obfuscate::env_disable_notifications()).is_ok()
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
