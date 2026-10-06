// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

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

pub mod deliver;

use crate::Result;
use crate::filesystem::SafeRoot;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::os::fd::AsFd;
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
    let (safe_root, target_user) = prepare_notifications_dir(hidden_volume_root)?;
    let rel_dir = Path::new("notifications");

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

    let base = format!("{}_{}", timestamp, safe_title);
    let (relative, mut file) = create_signal_file(&safe_root, rel_dir, &base)?;
    let path = hidden_volume_root.join(&relative);

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

    // Pin the mode to 0o600 (owner rw only) regardless of the umask. This acts
    // on the open descriptor, not the path: the directory already belongs to
    // the operator, so a path-based chmod could be redirected through a symlink
    // swapped in after the create. The file is chown'd to the target user below
    // so dispatch_all can read and delete it.
    if let Err(e) = nix::sys::stat::fchmod(
        file.as_fd(),
        nix::sys::stat::Mode::from_bits_truncate(0o600),
    ) {
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

/// Open the hidden root and make sure `notifications/` exists, is `0700` and
/// belongs to the operator (who runs the login-time dispatcher), returning the
/// anchored root and the resolved operator.
///
/// Every create under the hidden root goes through [`SafeRoot`], so a symlink
/// or `..` planted at the `notifications` component cannot redirect a
/// root-privileged write onto the decoy filesystem.
fn prepare_notifications_dir(
    hidden_volume_root: &Path,
) -> Result<(SafeRoot, Option<crate::TargetUser>)> {
    // Anchor every create under the hidden root through SafeRoot, so a symlink or
    // `..` planted at the `notifications` component cannot redirect this
    // root-privileged write onto the decoy filesystem.
    let safe_root = SafeRoot::open(hidden_volume_root).map_err(|e| {
        crate::NailsError::IoError(std::io::Error::other(format!(
            "Failed to open hidden root {} for notifications: {e}",
            hidden_volume_root.display()
        )))
    })?;
    let rel_dir = Path::new("notifications");
    // `dir` is used for diagnostics only; all operations go through `safe_root`.
    let dir = notifications_dir(hidden_volume_root);
    safe_root.create_dir_all(rel_dir).map_err(|e| {
        crate::NailsError::IoError(std::io::Error::other(format!(
            "Failed to create notifications dir {}: {e}",
            dir.display()
        )))
    })?;

    // Open the directory as a descriptor so permissions and ownership are set on
    // the directory itself, never through a path that a symlink could redirect.
    let dir_fd = safe_root.open_dir(rel_dir).map_err(|e| {
        crate::NailsError::IoError(std::io::Error::other(format!(
            "Failed to open notifications dir {}: {e}",
            dir.display()
        )))
    })?;

    // Set the notifications directory to 0o700 (owner rwx only).
    // The directory is chown'd to the target user below so they can manage files.
    if let Err(e) = nix::sys::stat::fchmod(
        dir_fd.as_fd(),
        nix::sys::stat::Mode::from_bits_truncate(0o700),
    ) {
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
    // the files it processes. Operate on the open descriptor so a symlink race on
    // the path cannot redirect the chown.
    if let Some(user) = target_user.as_ref()
        && let Err(e) = fchown_to_user(&dir_fd, user)
    {
        tracing::warn!(
            dir = %dir.display(),
            error = %e,
            "Failed to set ownership on notifications directory (non-fatal)"
        );
    }

    Ok((safe_root, target_user))
}

/// Create a new signal file named `{base}.json` under `rel_dir` (relative to the
/// hidden root `safe_root` anchors), or `{base}_{n}.json` when that name is taken,
/// returning the created path *relative to the hidden root* and the open handle.
///
/// The create is exclusive so two notifications written in the same millisecond
/// with the same title cannot silently overwrite one another. It matters for
/// safety too: once the operator owns the directory they can plant entries in it,
/// and [`SafeRoot::create_new`] treats a symlink at the name as taken (and
/// refuses to traverse any symlinked component) instead of following it to a file
/// a root-privileged write would then overwrite. The file is born 0600, so it is
/// never readable by anyone else while it is written.
fn create_signal_file(
    safe_root: &SafeRoot,
    rel_dir: &Path,
    base: &str,
) -> Result<(PathBuf, std::fs::File)> {
    const MAX_COLLISION_SUFFIXES: u32 = 10_000;
    let mut relative = rel_dir.join(format!("{}.json", base));
    let mut attempt: u32 = 0;
    loop {
        match safe_root.create_new(&relative, 0o600) {
            Ok(file) => return Ok((relative, file)),
            Err(crate::NailsError::IoError(e)) if e.kind() == std::io::ErrorKind::AlreadyExists => {
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
                relative = rel_dir.join(format!("{}_{}.json", base, attempt));
            }
            Err(e) => {
                return Err(crate::NailsError::IoError(std::io::Error::other(format!(
                    "Failed to create notification file {}: {e}",
                    relative.display()
                ))));
            }
        }
    }
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

    // This dispatcher runs as root at login, so every file it opens is anchored
    // under the hidden root through SafeRoot: a symlink planted at a `*.json`
    // entry (or at the `notifications` component) is rejected by
    // RESOLVE_NO_SYMLINKS/RESOLVE_BENEATH and O_NOFOLLOW rather than followed off
    // the hidden volume. The directory listing only yields entry names and never
    // opens them, so it stays a plain `read_dir`; the symlink-sensitive open of
    // each file goes through `safe_root`.
    let safe_root = SafeRoot::open(hidden_volume_root).map_err(|e| {
        crate::NailsError::IoError(std::io::Error::other(format!(
            "Failed to open hidden root {} for notifications: {e}",
            hidden_volume_root.display()
        )))
    })?;
    let rel_dir = Path::new("notifications");

    let mut names: Vec<std::ffi::OsString> = std::fs::read_dir(&dir)
        .map_err(|e| {
            crate::NailsError::IoError(std::io::Error::new(
                e.kind(),
                format!("Failed to read notifications dir {}: {}", dir.display(), e),
            ))
        })?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name())
        .filter(|name| Path::new(name).extension().is_some_and(|ext| ext == "json"))
        .collect();

    // Sort by filename (which starts with timestamp) for chronological order
    names.sort();

    let mut results = Vec::new();
    for name in names {
        let path = dir.join(&name);
        match safe_root.read_to_string(&rel_dir.join(&name)) {
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
///
/// `path` is a `<hidden-root>/notifications/<name>` entry returned by
/// [`read_pending`]. The removal is anchored under the hidden root through
/// `SafeRoot`, so a symlink planted at the `notifications` component cannot
/// redirect the unlink off the volume; it stays symmetrical with the contained
/// read path.
pub fn clear_notification(hidden_volume_root: &Path, path: &Path) -> Result<()> {
    let name = path.file_name().ok_or_else(|| {
        crate::NailsError::IoError(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("notification path has no file name: {}", path.display()),
        ))
    })?;
    let safe_root = SafeRoot::open(hidden_volume_root).map_err(|e| {
        crate::NailsError::IoError(std::io::Error::other(format!(
            "Failed to open hidden root {} for notifications: {e}",
            hidden_volume_root.display()
        )))
    })?;
    safe_root.remove_file(&Path::new("notifications").join(name))
}

/// Delete all pending notification signal files.
pub fn clear_all(hidden_volume_root: &Path) -> Result<()> {
    let dir = notifications_dir(hidden_volume_root);
    if !dir.exists() {
        return Ok(());
    }
    // The directory listing only yields entry names and never opens them, so it
    // stays a plain `read_dir`; each removal is anchored under the hidden root
    // through SafeRoot so a planted symlink at the `notifications` component
    // cannot redirect the unlink.
    let safe_root = SafeRoot::open(hidden_volume_root).map_err(|e| {
        crate::NailsError::IoError(std::io::Error::other(format!(
            "Failed to open hidden root {} for notifications: {e}",
            hidden_volume_root.display()
        )))
    })?;
    let rel_dir = Path::new("notifications");
    for entry in std::fs::read_dir(&dir)
        .map_err(|e| {
            crate::NailsError::IoError(std::io::Error::new(
                e.kind(),
                format!("Failed to read notifications dir {}: {}", dir.display(), e),
            ))
        })?
        .flatten()
    {
        let name = entry.file_name();
        if Path::new(&name)
            .extension()
            .is_some_and(|ext| ext == "json")
        {
            let _ = safe_root.remove_file(&rel_dir.join(&name));
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

        // `notify-send` is resolved from the fixed system tool directories, never
        // the caller's PATH; if none of them holds it there is nothing to do.
        if !notify_send_available() {
            // Recorded once on the hidden volume, so `nails status` can explain
            // why results stay undelivered, without a warning at every login.
            match deliver::record_notify_send_missing(hidden_volume_root) {
                Ok(true) => tracing::warn!(
                    "notify-send not found on PATH; desktop notifications stay queued and \
                     `nails status` lists them"
                ),
                Ok(false) => {
                    tracing::debug!("notify-send still missing; notifications stay queued")
                }
                Err(e) => tracing::warn!(error = %e, "notify-send not found; could not record it"),
            }
            return Ok(0);
        }

        let mut dispatched = 0;
        for (path, notification) in &pending {
            match send_notification(notification) {
                Ok(()) => {
                    let _ = clear_notification(hidden_volume_root, path);
                    deliver::clear_notify_send_missing(hidden_volume_root);
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

/// Whether an executable `notify-send` exists on the caller's `PATH`.
///
/// Mirrors the resolution [`ProcessCommand::caller_path`](crate::process::ProcessCommand::caller_path)
/// performs — absolute `PATH` entries, an executable file — so a probe here
/// agrees with where the dispatch below will actually look. Notification dispatch
/// runs from the operator's own login session (an XDG autostart entry), so
/// resolving `notify-send` from their `PATH` is correct and is not a root spawn.
#[cfg(not(test))]
fn notify_send_available() -> bool {
    use crate::platform::host_commands::is_executable_file;
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path)
        .filter(|dir| dir.is_absolute())
        .any(|dir| is_executable_file(&dir.join("notify-send")))
}

/// Invoke `notify-send` with the given notification payload.
///
/// Runs through the shared [`ProcessRunner`](crate::process::ProcessRunner): the
/// child starts from a cleared environment, `notify-send` resolves from the
/// operator's `PATH` (dispatch runs in their login session), and their session
/// variables (`XDG_RUNTIME_DIR`, `DBUS_SESSION_BUS_ADDRESS`, the display
/// variables) are set explicitly with
/// [`set_env`](crate::process::ProcessCommand::set_env) so the notification
/// reaches their bus rather than root's.
#[cfg(not(test))]
fn send_notification(notification: &Notification) -> Result<()> {
    run_notify_send(&queued_notification_command(
        notification,
        &notification_runtime_environment(),
    ))
}

/// Application name the login-time queue dispatches under.
const QUEUE_APP_NAME: &str = "NAILS";

/// Neutral application name for immediate watcher alerts.
///
/// The login-time queue identifies itself as the product, but an alert the
/// in-session watcher raises when the backend fails must reveal nothing on screen
/// to a shoulder-surfer, so it is attributed to a generic source instead.
const NEUTRAL_APP_NAME: &str = "System";

/// Send a desktop notification immediately, bypassing the login-time file queue.
///
/// The queue lives on the hidden root, so it is useless for reporting a failure of
/// that very root: this sends straight to the operator's session bus. Attributed
/// to a neutral application name so the alert does not name the tool on screen.
#[cfg(not(test))]
pub fn send_immediate(notification: &Notification) -> Result<()> {
    run_notify_send(&immediate_alert_command(
        notification,
        &notification_runtime_environment(),
    ))
}

/// Test build: immediate alerts never reach a real session bus.
#[cfg(test)]
pub fn send_immediate(_notification: &Notification) -> Result<()> {
    Ok(())
}

/// The `notify-send` command for a queued notification dispatched at login.
///
/// Dispatch runs as the operator from their own login session, so `notify-send`
/// resolves from their `PATH` ([`Program::CallerPath`](crate::process::Program::CallerPath)).
fn queued_notification_command(
    notification: &Notification,
    session_env: &[(&'static str, String)],
) -> crate::process::ProcessCommand {
    notify_send_command(
        crate::process::ProcessCommand::caller_path("notify-send"),
        notification,
        QUEUE_APP_NAME,
        session_env,
    )
}

/// The `notify-send` command for an immediate backend-failure alert.
///
/// The backend watcher raises this as root from a transient system unit whose
/// `PATH` is minimal and not the operator's, so a caller-`PATH` lookup finds
/// nothing there; `notify-send` is a host tool resolved from the fixed system
/// directories ([`Program::Tool`](crate::process::Program::Tool)) instead.
fn immediate_alert_command(
    notification: &Notification,
    session_env: &[(&'static str, String)],
) -> crate::process::ProcessCommand {
    notify_send_command(
        crate::process::ProcessCommand::tool("notify-send"),
        notification,
        NEUTRAL_APP_NAME,
        session_env,
    )
}

/// Add the notification payload, application name and the operator's session
/// variables to a bare `notify-send` command.
fn notify_send_command(
    base: crate::process::ProcessCommand,
    notification: &Notification,
    app_name: &str,
    session_env: &[(&'static str, String)],
) -> crate::process::ProcessCommand {
    let mut command = base
        .arg("--urgency")
        .arg(&notification.urgency)
        .arg("--app-name")
        .arg(app_name);

    for (key, value) in session_env {
        command = command.set_env(key, value);
    }

    if let Some(ref icon) = notification.icon {
        command = command.arg("--icon").arg(icon);
    }

    command.arg(&notification.title).arg(&notification.body)
}

/// Run a prepared `notify-send` command and turn a non-zero exit into an error.
#[cfg(not(test))]
fn run_notify_send(command: &crate::process::ProcessCommand) -> Result<()> {
    use crate::process::{ProcessRunner, RealProcessRunner};

    let output = RealProcessRunner.run(command)?;

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
