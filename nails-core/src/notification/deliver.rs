// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Reliable delivery of activation results to the operator.
//!
//! Results are queued as signal files on the hidden volume (see the parent
//! module). Three mechanisms get them in front of the operator:
//!
//! 1. **Push.** When an activation commits, it delivers the queue straight into
//!    the operator's graphical session ([`push_pending`]): through
//!    `systemd-run --user --machine=<user>@.host`, falling back to `runuser`,
//!    each running `notify-send` against the operator's session bus. A pushed
//!    notification is removed from the queue, which is what marks it delivered.
//!    Without a session bus (nobody logged in yet, or a text console) nothing is
//!    pushed and the queue stays for the next mechanism. Only a committed
//!    activation pushes: after a rollback the operator is back on the decoy
//!    session, which must never show a hidden-environment notification.
//! 2. **Login dispatch.** `nails notify-dispatch`, started by an autostart entry
//!    in the hidden session, dispatches the queue and keeps polling while an
//!    activation is still in progress ([`dispatch_until_settled`]), so a result
//!    raised after the session restart is not missed. It cannot read the
//!    root-only state file, so the activation signals "in progress" with a
//!    marker in the operator-owned notifications directory
//!    ([`ResultPendingMarker`]). Polling stops when the marker goes, or after
//!    [`DISPATCH_POLL_CAP`].
//! 3. **Status.** Whatever is still queued is undelivered; `nails status` lists
//!    it, and reports when `notify-send` was missing in the session (recorded
//!    once, see [`record_notify_send_missing`]).

use std::path::Path;
use std::time::{Duration, SystemTime};

use super::{Notification, read_pending};
use crate::Result;
use crate::filesystem::SafeRoot;

/// Marker present in `notifications/` while an activation is in progress.
pub const RESULT_PENDING_MARKER: &str = ".result-pending";

/// Marker recording that `notify-send` was missing when a dispatch was due.
pub const NOTIFY_SEND_MISSING_MARKER: &str = ".notify-send-missing";

/// How often the login dispatcher re-checks the queue while an activation runs.
pub const DISPATCH_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// The longest the login dispatcher waits for an activation to settle. A
/// marker older than this is treated as left behind by a crashed activation.
pub const DISPATCH_POLL_CAP: Duration = Duration::from_secs(15 * 60);

fn rel(name: &str) -> std::path::PathBuf {
    Path::new("notifications").join(name)
}

fn open_root(hidden_volume_root: &Path) -> Result<SafeRoot> {
    SafeRoot::open(hidden_volume_root).map_err(|e| {
        crate::NailsError::IoError(std::io::Error::other(format!(
            "Failed to open hidden root {} for notifications: {e}",
            hidden_volume_root.display()
        )))
    })
}

/// Create (or replace) a small marker file under `notifications/` holding the
/// current time, owned by the operator so their dispatcher can see it.
fn write_marker(hidden_volume_root: &Path, name: &str) -> Result<()> {
    use std::io::Write;

    let (safe_root, target_user) = super::prepare_notifications_dir(hidden_volume_root)?;
    let relative = rel(name);
    // The directory belongs to the operator, who could plant an entry at the
    // marker's name; `create_new` never follows one, so drop whatever is there
    // and create the marker afresh.
    let _ = safe_root.remove_file(&relative);
    let mut file = safe_root.create_new(&relative, 0o600)?;
    file.write_all(chrono::Utc::now().to_rfc3339().as_bytes())?;
    if let Some(user) = target_user.as_ref() {
        let _ = super::fchown_to_user(&file, user);
    }
    Ok(())
}

fn remove_marker(hidden_volume_root: &Path, name: &str) {
    if let Ok(safe_root) = open_root(hidden_volume_root) {
        let _ = safe_root.remove_file(&rel(name));
    }
}

/// When the marker `name` was written: its recorded timestamp, else its
/// modification time. `None` when the marker is absent.
fn marker_time(hidden_volume_root: &Path, name: &str) -> Option<SystemTime> {
    let path = hidden_volume_root.join(rel(name));
    let metadata = std::fs::symlink_metadata(&path).ok()?;
    if !metadata.is_file() {
        return None;
    }
    let recorded = open_root(hidden_volume_root)
        .ok()
        .and_then(|root| root.read_to_string(&rel(name)).ok())
        .and_then(|text| chrono::DateTime::parse_from_rfc3339(text.trim()).ok())
        .map(|time| SystemTime::from(time.with_timezone(&chrono::Utc)));
    recorded.or_else(|| metadata.modified().ok())
}

// ---------------------------------------------------------------------------
// Activation in progress
// ---------------------------------------------------------------------------

/// Signals "an activation is in progress" to the login dispatcher for as long
/// as it is alive. Arm it once the hidden volume is known to be mounted.
#[derive(Debug)]
pub struct ResultPendingMarker {
    hidden_volume_root: std::path::PathBuf,
}

impl ResultPendingMarker {
    /// Write the marker. A failure is logged and the activation carries on: the
    /// dispatcher then simply does not wait for late results.
    pub fn arm(hidden_volume_root: &Path) -> Self {
        if let Err(e) = write_marker(hidden_volume_root, RESULT_PENDING_MARKER) {
            tracing::debug!(error = %e, "Could not write the activation-in-progress marker");
        }
        Self {
            hidden_volume_root: hidden_volume_root.to_path_buf(),
        }
    }
}

impl Drop for ResultPendingMarker {
    fn drop(&mut self) {
        remove_marker(&self.hidden_volume_root, RESULT_PENDING_MARKER);
    }
}

/// Whether an activation is in progress, as the login dispatcher sees it: the
/// marker exists and is younger than [`DISPATCH_POLL_CAP`] at `now`.
pub fn result_pending(hidden_volume_root: &Path, now: SystemTime) -> bool {
    marker_time(hidden_volume_root, RESULT_PENDING_MARKER).is_some_and(|written| {
        now.duration_since(written)
            .map_or(true, |age| age < DISPATCH_POLL_CAP)
    })
}

// ---------------------------------------------------------------------------
// Missing notify-send
// ---------------------------------------------------------------------------

/// Record that `notify-send` was missing when notifications were due.
///
/// Recorded once: returns `Ok(true)` when this call wrote the record and
/// `Ok(false)` when it already existed, so the caller logs the condition a
/// single time rather than at every dispatch.
pub fn record_notify_send_missing(hidden_volume_root: &Path) -> Result<bool> {
    if notify_send_missing(hidden_volume_root) {
        return Ok(false);
    }
    write_marker(hidden_volume_root, NOTIFY_SEND_MISSING_MARKER)?;
    Ok(true)
}

/// Forget a recorded missing `notify-send` (a notification was delivered).
pub fn clear_notify_send_missing(hidden_volume_root: &Path) {
    remove_marker(hidden_volume_root, NOTIFY_SEND_MISSING_MARKER);
}

/// Whether a missing `notify-send` is on record.
pub fn notify_send_missing(hidden_volume_root: &Path) -> bool {
    marker_time(hidden_volume_root, NOTIFY_SEND_MISSING_MARKER).is_some()
}

// ---------------------------------------------------------------------------
// Push to the operator's session
// ---------------------------------------------------------------------------

/// The operator whose graphical session receives pushed results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionUser {
    /// Numeric user id.
    pub uid: u32,
    /// Login name.
    pub name: String,
}

/// Delivers notifications into a user's session. The real implementation runs
/// `notify-send` inside the session; tests inject a recording one.
pub trait SessionNotifier {
    /// Whether the user's session bus is up, so a push can reach them.
    fn session_bus_available(&self, user: &SessionUser) -> bool;
    /// Deliver `notification` into the user's session.
    fn send(&self, user: &SessionUser, notification: &Notification) -> Result<()>;
}

/// What a push achieved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushOutcome {
    /// Every queued notification was delivered (the count may be zero).
    Delivered(usize),
    /// No operator or no session bus to push to; the queue is left for the
    /// login dispatcher.
    NoSession,
    /// A send failed after `delivered` succeeded; the rest stay queued.
    Failed {
        /// Notifications delivered before the failure.
        delivered: usize,
        /// Why the send failed.
        error: String,
    },
}

/// Push every queued notification into `user`'s session, removing each one
/// once delivered. Stops at the first failed send, leaving the rest queued for
/// the login dispatcher, which is also what happens when there is no session.
pub fn push_pending<N: SessionNotifier>(
    hidden_volume_root: &Path,
    user: Option<&SessionUser>,
    notifier: &N,
) -> Result<PushOutcome> {
    let Some(user) = user else {
        return Ok(PushOutcome::NoSession);
    };
    if !notifier.session_bus_available(user) {
        return Ok(PushOutcome::NoSession);
    }
    let mut delivered = 0;
    for (path, notification) in read_pending(hidden_volume_root)? {
        match notifier.send(user, &notification) {
            Ok(()) => {
                let _ = super::clear_notification(hidden_volume_root, &path);
                delivered += 1;
            }
            Err(e) => {
                return Ok(PushOutcome::Failed {
                    delivered,
                    error: e.to_string(),
                });
            }
        }
    }
    Ok(PushOutcome::Delivered(delivered))
}

/// Runs `notify-send` inside the operator's session as root: through the
/// user's service manager (`systemd-run --user --machine=<user>@.host`), or
/// with `runuser` and the session bus address when that fails.
#[derive(Debug, Default)]
pub struct RealSessionNotifier;

impl RealSessionNotifier {
    /// The `notify-send` command line (program and arguments) for `notification`,
    /// attributed to the product as the login-time queue is.
    fn notify_send_args(notify_send: &Path, notification: &Notification) -> Vec<String> {
        let mut args = vec![
            notify_send.display().to_string(),
            "--urgency".to_string(),
            notification.urgency.clone(),
            "--app-name".to_string(),
            super::QUEUE_APP_NAME.to_string(),
        ];
        if let Some(icon) = &notification.icon {
            args.push("--icon".to_string());
            args.push(icon.clone());
        }
        args.push(notification.title.clone());
        args.push(notification.body.clone());
        args
    }

    /// `systemd-run` into the user's manager. A neutral description keeps the
    /// notification text out of the unit's start message.
    fn systemd_run_command(
        user: &SessionUser,
        notify_send_args: &[String],
    ) -> crate::process::ProcessCommand {
        crate::process::ProcessCommand::tool("systemd-run")
            .arg("--user")
            .arg(format!("--machine={}@.host", user.name))
            .args([
                "--quiet",
                "--wait",
                "--collect",
                "--description=notification",
                "--",
            ])
            .args(notify_send_args)
            .deadline(crate::process::run::SYSTEMCTL_ACTION_BUDGET)
    }

    /// `runuser` as the user with their session bus in the environment.
    fn runuser_command(
        user: &SessionUser,
        notify_send_args: &[String],
    ) -> crate::process::ProcessCommand {
        let runtime_dir = format!("/run/user/{}", user.uid);
        crate::process::ProcessCommand::tool("runuser")
            .args(["-u", user.name.as_str(), "--"])
            .args(notify_send_args)
            .set_env("XDG_RUNTIME_DIR", &runtime_dir)
            .set_env(
                "DBUS_SESSION_BUS_ADDRESS",
                format!("unix:path={runtime_dir}/bus"),
            )
            .deadline(crate::process::run::SYSTEMCTL_ACTION_BUDGET)
    }

    fn run(command: &crate::process::ProcessCommand) -> Result<()> {
        use crate::process::{ProcessRunner, RealProcessRunner};
        let output = RealProcessRunner.run(command)?;
        if output.status.success() {
            Ok(())
        } else {
            Err(crate::NailsError::IoError(std::io::Error::other(format!(
                "exited with {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            ))))
        }
    }
}

impl SessionNotifier for RealSessionNotifier {
    fn session_bus_available(&self, user: &SessionUser) -> bool {
        Path::new(&format!("/run/user/{}/bus", user.uid)).exists()
    }

    fn send(&self, user: &SessionUser, notification: &Notification) -> Result<()> {
        let notify_send =
            crate::platform::host_commands::HostCommands::new(crate::process::SYSTEM_TOOL_DIRS)
                .resolve("notify-send")?;
        let args = Self::notify_send_args(&notify_send, notification);
        match Self::run(&Self::systemd_run_command(user, &args)) {
            Ok(()) => Ok(()),
            Err(first) => Self::run(&Self::runuser_command(user, &args)).map_err(|second| {
                crate::NailsError::IoError(std::io::Error::other(format!(
                    "systemd-run: {first}; runuser: {second}"
                )))
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Login dispatch loop
// ---------------------------------------------------------------------------

/// What the login dispatch loop needs from its surroundings, so the loop can be
/// tested with a fake queue and clock.
pub trait DispatchEnv {
    /// Dispatch whatever is queued now, returning how many were delivered.
    fn dispatch(&mut self) -> Result<usize>;
    /// Whether an activation is still in progress.
    fn activation_in_progress(&mut self) -> bool;
    /// Time since the loop started.
    fn elapsed(&self) -> Duration;
    /// Wait `duration` before the next check.
    fn sleep(&mut self, duration: Duration);
}

/// Dispatch the queue, then keep dispatching every `interval` while an
/// activation is in progress, for at most `cap`. Once the activation has
/// settled one final sweep collects its last results. Returns the number of
/// notifications delivered.
///
/// A dispatch error ends the loop and is returned only when nothing was
/// delivered at all; a partial success is reported as such.
pub fn dispatch_until_settled<E: DispatchEnv>(
    env: &mut E,
    interval: Duration,
    cap: Duration,
) -> Result<usize> {
    let mut total = env.dispatch()?;
    let mut waited = false;
    while env.activation_in_progress() && env.elapsed() < cap {
        env.sleep(interval);
        waited = true;
        match env.dispatch() {
            Ok(count) => total += count,
            Err(e) if total == 0 => return Err(e),
            Err(_) => return Ok(total),
        }
    }
    if waited {
        // The activation settled (or the cap ran out): collect what it raised
        // last.
        match env.dispatch() {
            Ok(count) => total += count,
            Err(e) if total == 0 => return Err(e),
            Err(_) => {}
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests;
