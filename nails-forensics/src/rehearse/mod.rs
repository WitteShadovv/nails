// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! `nails rehearse`: a canary self-test of this machine, decoy and backend.
//!
//! The disk-image checks in CI prove the leak claims on CI's VMs. A rehearsal
//! proves them on the operator's own machine, in three steps:
//!
//! 1. **Plant** ([`plant`]), inside an active hidden session: a random token
//!    goes into the channels a session most often leaks through: file contents
//!    and names in the hidden root (the root upper and every overlaid decoy
//!    filesystem) and in the operator's home, a line in the system log, a
//!    process command line, a `recently-used.xbel` entry and a desktop
//!    notification. Every file write is checked first to land in an overlay
//!    upper or on the hidden volume; nothing is written to the decoy.
//! 2. **Deactivate** as usual: it soft-reboots back to the decoy.
//! 3. **Scan** ([`scan`]), back on the decoy or in a later session, or offline
//!    against an image: the raw, decrypted decoy block devices are read
//!    `O_RDONLY | O_NOATIME`, never mounted, and searched for the token in
//!    ASCII and UTF-16LE, allocated and unallocated space alike. A scan in the
//!    planting session itself is refused
//!    ([`RehearsalState::planted_in_this_session`]).
//!
//! The token and the progress live in `rehearse/state.json` on the hidden
//! volume. The token is never printed or logged whole (only a short
//! fingerprint), so the rehearsal's own output cannot plant it in a log.

mod plant;
mod scan;

#[cfg(test)]
mod tests;

pub use plant::{PlantContext, plant};
pub use scan::{DeviceScan, NOT_VISIBLE, ScanReport, default_scan_targets, scan};

use crate::{Filesystem, NailsError, Result};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::{Path, PathBuf};

/// Directory on the hidden root that holds the rehearsal state.
pub const REHEARSE_DIR: &str = "rehearse";
/// State file name inside [`REHEARSE_DIR`].
pub const STATE_FILE: &str = "state.json";
/// Prefix of every planted file name, followed by the token.
pub const FILE_PREFIX: &str = "rehearse-";
/// Schema version of the state file.
pub const STATE_SCHEMA_VERSION: u32 = 1;

/// Where a rehearsal stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Phase {
    /// The canary is planted; the next step is a deactivation, then a scan.
    Planted,
    /// At least one scan has run.
    Scanned,
}

/// A channel the canary was planted in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChannelKind {
    /// A file named after the token, holding the token, in an overlaid tree.
    OverlayFile,
    /// The same, in the operator's home.
    HomeFile,
    /// A bookmark in the operator's `recently-used.xbel`.
    RecentFiles,
    /// A line sent to the system log socket (`/dev/log`).
    SystemLog,
    /// A short-lived process whose command line holds the token.
    ProcessCmdline,
    /// A desktop notification whose body holds the token.
    Notification,
}

/// What happened to one channel at plant time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelRecord {
    /// The channel.
    pub kind: ChannelKind,
    /// Where (a path as the session saw it, or a description).
    pub location: String,
    /// For a planted file: its copy in the overlay upper on the hidden volume,
    /// which `reset` removes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upper_copy: Option<PathBuf>,
    /// `None` when planted, else why it was skipped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skipped: Option<String>,
}

impl ChannelRecord {
    /// Whether the canary went into this channel.
    pub fn planted(&self) -> bool {
        self.skipped.is_none()
    }

    /// A copy safe to print: every occurrence of `token` (planted file names
    /// carry it) is replaced by `<canary>`.
    pub fn redacted(&self, token: &str) -> ChannelRecord {
        let hide = |text: &str| text.replace(token, "<canary>");
        ChannelRecord {
            kind: self.kind,
            location: hide(&self.location),
            upper_copy: self
                .upper_copy
                .as_ref()
                .map(|path| PathBuf::from(hide(&path.to_string_lossy()))),
            skipped: self.skipped.as_deref().map(hide),
        }
    }
}

/// A finished scan, without the token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanSummary {
    /// When it ran.
    pub at: String,
    /// The boot it ran in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_id: Option<String>,
    /// The devices scanned.
    pub devices: Vec<String>,
    /// Total hits.
    pub hits: usize,
}

/// The rehearsal state kept on the hidden volume.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RehearsalState {
    /// Schema version.
    pub schema_version: u32,
    /// The canary token (lowercase hex).
    pub token: String,
    /// Where the rehearsal stands.
    pub phase: Phase,
    /// When the canary was planted.
    pub planted_at: String,
    /// The boot the canary was planted in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub planted_boot_id: Option<String>,
    /// When the hidden session the canary was planted in was entered: its
    /// plan's entry time, in seconds since the epoch. A soft-reboot keeps the
    /// boot ID, but every activation enters a session with an entry time of
    /// its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub planted_entered_at: Option<u64>,
    /// systemd's soft-reboot count when the canary was planted, where systemd
    /// reports one (256 and newer).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub planted_soft_reboots: Option<u64>,
    /// The channels, planted or skipped.
    pub channels: Vec<ChannelRecord>,
    /// Scans run so far.
    #[serde(default)]
    pub scans: Vec<ScanSummary>,
}

/// A live hidden session.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LiveSession {
    /// When it was entered (its plan's entry time, in seconds since the
    /// epoch), when its plan is readable.
    pub entered_at: Option<u64>,
}

/// Where a rehearsal step runs: the facts that tell the session the canary was
/// planted in from any other.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Here {
    /// The live hidden session this runs in, `None` outside one.
    pub session: Option<LiveSession>,
    /// The running boot's ID.
    pub boot_id: Option<String>,
    /// systemd's soft-reboot count in this boot. `None` where systemd does not
    /// report one (255 and older), and outside a hidden session, where it is
    /// not needed.
    pub soft_reboots: Option<u64>,
}

impl Here {
    /// The facts of the running system, in or outside `session`.
    pub fn read(session: Option<LiveSession>) -> Self {
        Self {
            session,
            boot_id: current_boot_id(),
            soft_reboots: session.and_then(|_| current_soft_reboots()),
        }
    }
}

impl RehearsalState {
    /// Whether `here` is the hidden session the canary was planted in, where a
    /// scan could read the disks before the session's writes reach them.
    ///
    /// The canary is planted only in a live hidden session, so outside one (on
    /// the decoy after the way back, or after a power-off) the planting session
    /// has ended. Inside one, a different boot is a later session. Then the
    /// session's entry time decides, on every systemd version; then systemd's
    /// soft-reboot count, which only 256 and newer report. When neither is
    /// known on both sides, the answer is yes: a refused scan can run later,
    /// while a scan in the planting session proves little.
    pub fn planted_in_this_session(&self, here: &Here) -> bool {
        let Some(session) = here.session else {
            return false;
        };
        if let (Some(planted), Some(now)) = (&self.planted_boot_id, &here.boot_id)
            && planted != now
        {
            return false;
        }
        if let (Some(planted), Some(now)) = (self.planted_entered_at, session.entered_at) {
            return planted == now;
        }
        match (self.planted_soft_reboots, here.soft_reboots) {
            (Some(planted), Some(now)) => planted == now,
            _ => true,
        }
    }

    /// A short, safe-to-print stand-in for the token.
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.token)
    }

    /// The channels with the token redacted, for output.
    pub fn redacted_channels(&self) -> Vec<ChannelRecord> {
        self.channels
            .iter()
            .map(|record| record.redacted(&self.token))
            .collect()
    }
}

/// The first six characters of `token` and an ellipsis.
pub fn fingerprint(token: &str) -> String {
    let head: String = token.chars().take(6).collect();
    format!("{head}…")
}

/// A fresh 128-bit token from the kernel's random source, as 32 hex digits.
///
/// # Errors
///
/// Fails when `/dev/urandom` cannot be read.
pub fn generate_token() -> Result<String> {
    let path = Path::new("/dev/urandom");
    let mut bytes = [0u8; 16];
    std::fs::File::open(path)
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|e| NailsError::io(path, e))?;
    Ok(hex::encode(bytes))
}

/// Whether `token` is a well-formed rehearsal token (16 to 64 hex digits).
pub fn valid_token(token: &str) -> bool {
    (16..=64).contains(&token.len()) && token.chars().all(|c| c.is_ascii_hexdigit())
}

/// The state file's path relative to the hidden root.
pub fn state_relative_path() -> PathBuf {
    Path::new(REHEARSE_DIR).join(STATE_FILE)
}

/// Load the rehearsal state from the hidden root, `None` when there is none.
///
/// # Errors
///
/// Fails when the file exists but cannot be read or parsed.
pub fn load_state<F: Filesystem>(fs: &F, hidden_root: &Path) -> Result<Option<RehearsalState>> {
    let path = hidden_root.join(state_relative_path());
    if !fs.path_exists(&path)? {
        return Ok(None);
    }
    let text = fs.read_file_content(&path)?;
    let state: RehearsalState = serde_json::from_str(&text).map_err(|e| {
        NailsError::ConfigError(format!(
            "rehearsal state {} is unreadable: {e}",
            path.display()
        ))
    })?;
    if !valid_token(&state.token) {
        return Err(NailsError::ConfigError(format!(
            "rehearsal state {} holds no valid token",
            path.display()
        )));
    }
    Ok(Some(state))
}

/// Save the rehearsal state on the hidden root, refusing unless the hidden
/// volume is really mounted there.
///
/// # Errors
///
/// Fails when the hidden root is not attached or the write fails.
pub fn save_state<F: Filesystem>(fs: &F, hidden_root: &Path, state: &RehearsalState) -> Result<()> {
    let attach = crate::HiddenRoot::verify_attached(fs, hidden_root, true)?;
    if let Some(reason) = attach.reason() {
        return Err(NailsError::InvalidState(format!(
            "refusing to write the rehearsal state: {reason}"
        )));
    }
    fs.create_hidden_dir_all(hidden_root, Path::new(REHEARSE_DIR))?;
    let json = serde_json::to_string_pretty(state)
        .map_err(|e| NailsError::io(hidden_root, std::io::Error::other(e)))?;
    fs.write_hidden_file_atomic(hidden_root, &state_relative_path(), &json, 0o600)
}

/// Remove a rehearsal: the planted files' copies in the overlay uppers (only
/// paths under the hidden root whose name carries the token), the token's
/// bookmark lines in an upper `recently-used.xbel`, and the state file.
/// Returns the paths removed or rewritten.
///
/// The attach gate decides first: on a root it refuses (an unmounted mount
/// point, a disk mounted over the volume) nothing is removed or rewritten.
///
/// # Errors
///
/// Fails when the gate refuses the root or the state file cannot be removed.
pub fn reset<F: Filesystem>(
    fs: &F,
    hidden_root: &Path,
    state: &RehearsalState,
) -> Result<Vec<PathBuf>> {
    if let crate::hidden_root::Assessment::Refused(refusal) =
        crate::HiddenRoot::assess(fs, hidden_root)?
    {
        return Err(NailsError::InvalidState(format!(
            "refusing to reset the rehearsal: {}",
            refusal.reason
        )));
    }
    let mut touched = Vec::new();
    for record in &state.channels {
        let Some(upper) = &record.upper_copy else {
            continue;
        };
        if !upper.starts_with(hidden_root) {
            continue;
        }
        match record.kind {
            ChannelKind::RecentFiles => {
                if let Ok(text) = std::fs::read_to_string(upper) {
                    let kept: Vec<&str> = text
                        .lines()
                        .filter(|line| !line.contains(&state.token))
                        .collect();
                    if std::fs::write(upper, kept.join("\n") + "\n").is_ok() {
                        touched.push(upper.clone());
                    }
                }
            }
            _ => {
                let named = upper
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().contains(&state.token));
                if named && std::fs::remove_file(upper).is_ok() {
                    touched.push(upper.clone());
                }
            }
        }
    }
    let path = hidden_root.join(state_relative_path());
    std::fs::remove_file(&path).map_err(|e| NailsError::io(&path, e))?;
    touched.push(path);
    Ok(touched)
}

/// The current UTC time, RFC 3339.
pub(crate) fn now() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// The running boot's id. A soft-reboot keeps it.
pub fn current_boot_id() -> Option<String> {
    crate::state::read_boot_id()
}

/// systemd's count of soft-reboots in this boot (`SoftRebootsCount`). `None`
/// when the service manager does not report it: systemd 255 and older print
/// nothing for a property they do not have, and the probe may fail.
pub fn current_soft_reboots() -> Option<u64> {
    use crate::process::{ProcessCommand, ProcessRunner, RealProcessRunner};
    let command = ProcessCommand::tool("systemctl")
        .args(["show", "-p", "SoftRebootsCount", "--value"])
        .deadline(crate::process::run::SYSTEMCTL_PROBE_BUDGET);
    RealProcessRunner
        .run_text(&command)
        .ok()
        .and_then(|(ok, out, _)| ok.then(|| out.trim().parse().ok()).flatten())
}
