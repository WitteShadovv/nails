// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The `config set` and `config unset` operation: change settings in the
//! `nails.toml` on the hidden volume the engine runs from.
//!
//! The configuration lives on the hidden volume beside the binary, so a change
//! to it lands there and nowhere else. Before it reads the file, an edit
//! refuses:
//!
//! - a volume the attach gate refuses ([`HiddenRoot::assess`]): the directory
//!   the running `nails` lies in must be a volume of its own, and in a hidden
//!   session the volume the session entered with;
//! - a volume without a NAILS layout: neither its state file nor its
//!   configuration is there;
//! - a file anywhere but beneath that directory: a `--config` path elsewhere,
//!   a link at the file or on the way to it, or another filesystem mounted on
//!   the way, which the kernel refuses as it resolves the path from a root that
//!   must still be the mount the gate judged ([`PinnedDir`]).
//!
//! The file is then edited as a document ([`crate::config::edit`]), so its
//! comments, its order and every key the edit does not name stay as they were,
//! and the result is checked by the loader `config validate` runs before
//! anything is written. While a hidden session runs, is entering or was left
//! behind by an interrupted entry ([`SessionView`], from `/run` and the mount
//! table), the hidden volume root and the state file must stay where the
//! session recorded them at entry (its plan and its copy of the
//! configuration): the way back and `recover` find the session's state there.
//! An edit that points them back there is written, so a file that went wrong
//! can be put right. The new text replaces the file at once
//! ([`PinnedDir::replace`]: a new file in the same directory with the old one's
//! owner and mode, flushed and renamed over it), under an exclusive lock on the
//! directory, so two edits at the same time never lose one another. A cancel
//! (SIGINT or SIGTERM under the handlers the CLI installs) is honoured until
//! the rename and never after it.
//!
//! [`edit`] reads, checks and writes under one lock, for the CLI. A window asks
//! between the two halves: [`plan`] reads and checks, and [`apply`] writes that
//! plan only while the file is still what the plan read.

use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use nails_api::{ErrorBody, ExitStatus};
use serde::Serialize;

use crate::config::edit::{self, Change, EditError};
use crate::filesystem::mountinfo::top_mount_at;
use crate::filesystem::pinned_dir::{DirLock, Owner, PinError, PinnedDir};
use crate::hidden_root::{
    Assessment, HiddenRoot, MARKER_CONFIG_DIR, MARKER_CONFIG_FILE, MARKER_STATE_FILE, Refusal,
};
use crate::session::entry::CONFIG_COPY_NAME;
use crate::session::{Paths, SessionView};
use crate::{Config, Filesystem, LoadedConfig, NailsError, RealFilesystem};

pub use crate::config::edit::{Edit, Kind, SETTINGS, Setting, Value, setting, unknown_key};

/// The largest `nails.toml` an edit reads.
pub const MAX_FILE_BYTES: usize = 1 << 20;

/// How long an edit waits for another edit of the same file.
pub const LOCK_WAIT: Duration = Duration::from_secs(10);

/// Why an edit was refused or failed. Nothing was written in any case.
#[derive(Debug)]
pub enum Failure {
    /// A key, a value or a list of edits that the file does not take.
    Usage(String),
    /// The attach gate refused the volume the engine runs from.
    Refused(Box<Refusal>),
    /// The file is not a plain file on the volume the engine runs from.
    OffVolume(String),
    /// The volume holds neither a state file nor a configuration.
    NoLayout(PathBuf),
    /// While a hidden session runs, is entering or was left behind, the edit
    /// moves the hidden volume root or the state file away from where the
    /// session recorded them.
    SessionPaths(&'static str),
    /// The file could not be read.
    Read(NailsError),
    /// The file with the edits made is not a configuration nails accepts.
    Invalid(NailsError),
    /// The file changed after the plan was made.
    Stale(PathBuf),
    /// Another edit kept the file for longer than [`LOCK_WAIT`].
    Busy(PathBuf),
    /// The new file could not be written.
    Write(NailsError),
    /// A cancel arrived before the file was replaced.
    Cancelled,
}

impl Failure {
    /// The stable code a caller branches on.
    pub fn code(&self) -> &'static str {
        match self {
            Failure::Usage(_) => "usage",
            Failure::Refused(refusal) => refusal.code(),
            Failure::OffVolume(_) => "config_off_volume",
            Failure::NoLayout(_) => "no_layout",
            Failure::SessionPaths(_) => "session_paths",
            Failure::Read(_) | Failure::Invalid(_) => "config",
            Failure::Stale(_) => "plan_stale",
            Failure::Busy(_) => "config_busy",
            Failure::Write(_) => "write_failed",
            Failure::Cancelled => "cancelled",
        }
    }

    /// The exit status a front end reports it with.
    pub fn exit_status(&self) -> ExitStatus {
        match self {
            Failure::Usage(_) => ExitStatus::Usage,
            Failure::Refused(_)
            | Failure::OffVolume(_)
            | Failure::NoLayout(_)
            | Failure::SessionPaths(_) => ExitStatus::PreflightRefused,
            Failure::Read(_) | Failure::Invalid(_) => ExitStatus::Config,
            Failure::Stale(_) | Failure::Busy(_) | Failure::Write(_) => ExitStatus::Failed,
            Failure::Cancelled => ExitStatus::Cancelled,
        }
    }

    /// The I/O error behind a failed read or write, for a front end that adds
    /// the `sudo` line to a refused one.
    pub fn error(&self) -> Option<&NailsError> {
        match self {
            Failure::Read(error) | Failure::Invalid(error) | Failure::Write(error) => Some(error),
            _ => None,
        }
    }

    /// The machine-readable body. `exe` is the running program, which a
    /// refused volume's hint names when it lies on it.
    pub fn body(&self, exe: Option<&Path>) -> ErrorBody {
        if let Failure::Refused(refusal) = self {
            return super::refusal::refusal_body(refusal, exe);
        }
        ErrorBody::new(self.code(), self.message())
    }

    /// The sentence for a person.
    pub fn message(&self) -> String {
        match self {
            Failure::Usage(message) => message.clone(),
            Failure::Refused(refusal) => refusal.message(),
            Failure::OffVolume(reason) => format!(
                "{reason}: a setting is written only to the configuration beside nails on its \
                 volume. Nothing was written."
            ),
            Failure::NoLayout(root) => format!(
                "{} holds no NAILS layout (no {MARKER_STATE_FILE} and no \
                 {MARKER_CONFIG_DIR}/{MARKER_CONFIG_FILE}); run `{}` on it first. Nothing was \
                 written.",
                root.display(),
                crate::next_step::sudo_line(crate::next_step::NextStep::Init)
            ),
            Failure::SessionPaths(key) => format!(
                "`{key}` cannot change while a hidden session runs, is entering or was left \
                 behind by an interrupted entry: the way back to the decoy finds the session's \
                 state where the session recorded it. Make this change on another machine, with \
                 the hidden volume mounted there. Nothing was written."
            ),
            Failure::Read(error) | Failure::Invalid(error) => format!(
                "{}. Nothing was written.",
                super::config::config_error_line(error)
            ),
            Failure::Stale(path) => format!(
                "{} changed after the change was planned; plan it again. Nothing was written.",
                path.display()
            ),
            Failure::Busy(path) => format!(
                "another change of {} did not finish within {} seconds. Nothing was written.",
                path.display(),
                LOCK_WAIT.as_secs()
            ),
            Failure::Write(error) => format!("{error}. The file is as it was."),
            Failure::Cancelled => crate::catalog::CANCEL_CONFIG.text.to_string(),
        }
    }
}

/// Where an edit writes, as the gate admitted it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Target {
    /// The directory the engine runs from: the volume's root.
    root: PathBuf,
    /// The file's directory beneath it.
    dir: PathBuf,
    /// The file's name.
    name: OsString,
    /// The mount the gate judged, which the opened root must be on.
    mount_id: Option<u64>,
    /// The hidden session on this machine, if one runs, is entering or was
    /// left behind.
    session: Option<Session>,
}

impl Target {
    /// The file, as the gate judged it: absolute, beneath the root.
    fn path(&self) -> PathBuf {
        self.root.join(&self.dir).join(&self.name)
    }
}

/// A hidden session that runs, is entering or was left behind by an
/// interrupted entry, with the paths it recorded at entry where they can be
/// read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Session {
    /// Whether this is the hidden session itself, not an entry on the decoy.
    running: bool,
    /// The hidden volume root its plan names.
    hidden_root: Option<PathBuf>,
    /// The state file its copy of the configuration names.
    state_file: Option<PathBuf>,
}

impl Session {
    /// The session `view` shows, if any, with what the runtime directory of
    /// `paths` recorded for it.
    fn of(view: &SessionView, paths: &Paths) -> Option<Self> {
        let plan = match view {
            SessionView::Decoy => return None,
            SessionView::Hidden(plan) | SessionView::Entering(plan) => Some(plan.as_ref()),
            SessionView::Interrupted { plan, .. } => plan.as_deref(),
            SessionView::HiddenWithoutPlan(_) => None,
        };
        let copy: Option<Config> = std::fs::read_to_string(paths.runtime().join(CONFIG_COPY_NAME))
            .ok()
            .and_then(|text| toml::from_str(&text).ok());
        let hidden_root = plan
            .map(|plan| plan.hidden_root.clone())
            .or_else(|| copy.as_ref().map(|copy| copy.hidden_volume_root.clone()));
        Some(Self {
            running: view.is_hidden(),
            hidden_root,
            state_file: copy.map(|copy| copy.state_file_path),
        })
    }
}

/// Decides where an edit may write.
pub(crate) trait Gate {
    /// Admit the file at `path`, or say why not.
    fn admit(&self, path: &Path) -> Result<Target, Failure>;
}

/// The gate of a running engine: the volume of the directory the running
/// `nails` lies in, as the attach gate judges it.
struct EngineGate;

impl Gate for EngineGate {
    fn admit(&self, path: &Path) -> Result<Target, Failure> {
        let root = engine_root()?;
        admit(&RealFilesystem, &Paths::system(), &root, path)
    }
}

/// The directory the running `nails` lies in, its links resolved.
fn engine_root() -> Result<PathBuf, Failure> {
    let unplaced = |error: std::io::Error| {
        Failure::OffVolume(format!(
            "cannot tell which volume nails runs from ({error})"
        ))
    };
    let exe = std::env::current_exe()
        .and_then(|exe| exe.canonicalize())
        .map_err(unplaced)?;
    exe.parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| Failure::OffVolume(format!("nails runs from {}", exe.display())))
}

/// Admit `path` beneath `root` when the attach gate passes `root` and it
/// holds a NAILS layout, and tell the hidden session `paths` (`/` and `/run`)
/// show, if there is one.
pub(crate) fn admit<F: Filesystem>(
    fs: &F,
    paths: &Paths,
    root: &Path,
    path: &Path,
) -> Result<Target, Failure> {
    let (dir, name) = beneath(root, path)?;
    match HiddenRoot::assess(fs, root) {
        Ok(Assessment::Refused(refusal)) => return Err(Failure::Refused(Box::new(refusal))),
        Ok(Assessment::Attached | Assessment::Warned(_)) => {}
        Err(error) => return Err(Failure::Read(error)),
    }
    let marked = |relative: &Path| fs.path_exists(&root.join(relative)).unwrap_or(false);
    let config = Path::new(MARKER_CONFIG_DIR).join(MARKER_CONFIG_FILE);
    if !marked(Path::new(MARKER_STATE_FILE)) && !marked(&config) {
        return Err(Failure::NoLayout(root.to_path_buf()));
    }
    let table = fs.mount_table().map_err(Failure::Read)?;
    let mount_id = top_mount_at(&table, root).and_then(|mount| u64::try_from(mount.mount_id).ok());
    if mount_id.is_none() {
        return Err(Failure::OffVolume(format!(
            "{} is no longer a mounted volume",
            root.display()
        )));
    }
    let view = crate::session::probe::probe_with(paths, root, &table);
    Ok(Target {
        root: root.to_path_buf(),
        dir,
        name,
        mount_id,
        session: Session::of(&view, paths),
    })
}

/// `path` as a directory beneath `root` and a file name, when it lies beneath
/// it with no `..` on the way.
fn beneath(root: &Path, path: &Path) -> Result<(PathBuf, OsString), Failure> {
    let absolute = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    let elsewhere = || {
        Failure::OffVolume(format!(
            "{} is not on the volume nails runs from, {}",
            absolute.display(),
            root.display()
        ))
    };
    let relative = absolute.strip_prefix(root).map_err(|_| elsewhere())?;
    if relative
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(elsewhere());
    }
    let name = relative.file_name().ok_or_else(elsewhere)?.to_os_string();
    let dir = relative.parent().unwrap_or(Path::new("")).to_path_buf();
    Ok((dir, name))
}

/// A planned edit: the file as it was read, the text it becomes and what
/// changes, checked and ready for [`apply`].
#[derive(Debug, Clone)]
pub struct Plan {
    target: Target,
    path: PathBuf,
    edits: Vec<Edit>,
    before: Option<Vec<u8>>,
    owner: Option<Owner>,
    after: Option<String>,
    changes: Vec<Change>,
}

impl Plan {
    /// The file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// What each edit changes.
    pub fn changes(&self) -> &[Change] {
        &self.changes
    }

    /// Whether applying it writes the file: false when every value is already
    /// what the edits ask for.
    pub fn writes(&self) -> bool {
        self.after.is_some()
    }

    /// The changes as the machine-readable contract carries them.
    pub fn change_data(&self) -> Vec<ChangeData> {
        self.changes.iter().map(ChangeData::from_change).collect()
    }

    /// The machine-readable result of the plan as it stands, nothing written.
    pub fn data(&self) -> EditData {
        EditData {
            path: self.path.display().to_string(),
            written: false,
            changes: self.change_data(),
        }
    }
}

/// What an edit did.
#[derive(Debug, Clone, PartialEq)]
pub struct Applied {
    /// The file.
    pub path: PathBuf,
    /// What each edit changed.
    pub changes: Vec<Change>,
    /// Whether the file was written.
    pub written: bool,
    /// Whether this ran in a hidden session. Its watcher and its sleep guard
    /// keep the copy of the settings activation made.
    pub in_session: bool,
}

impl Applied {
    /// The machine-readable result.
    pub fn data(&self) -> EditData {
        EditData {
            path: self.path.display().to_string(),
            written: self.written,
            changes: self.changes.iter().map(ChangeData::from_change).collect(),
        }
    }
}

/// The machine-readable result of `config set` and `config unset`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EditData {
    /// The file.
    pub path: String,
    /// Whether the file was written: false when every value already was what
    /// the edits asked for.
    pub written: bool,
    /// What each edit changed, in the order given.
    pub changes: Vec<ChangeData>,
}

/// One key's value as the file wrote it before and after an edit.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ChangeData {
    /// The key.
    pub key: &'static str,
    /// The value the file held; `null` where it did not set the key.
    pub before: Option<serde_json::Value>,
    /// The value the file holds; `null` where it does not set the key.
    pub after: Option<serde_json::Value>,
}

impl ChangeData {
    fn from_change(change: &Change) -> Self {
        let json = |value: &toml::Value| serde_json::to_value(value).ok();
        Self {
            key: change.key,
            before: change.before.as_ref().and_then(json),
            after: change.after.as_ref().and_then(json),
        }
    }
}

/// Make `edits` on the configuration `config_override` names, the
/// binary-relative file without one: read, check and write under one lock.
///
/// # Errors
///
/// A [`Failure`]; nothing was written then.
pub fn edit(config_override: Option<&Path>, edits: &[Edit]) -> Result<Applied, Failure> {
    edit_with(&EngineGate, config_override, edits)
}

/// Read and check `edits` without writing: what [`apply`] writes.
///
/// # Errors
///
/// As [`edit`].
pub fn plan(config_override: Option<&Path>, edits: &[Edit]) -> Result<Plan, Failure> {
    plan_with(&EngineGate, config_override, edits)
}

/// Write `plan`, when the file is still what the plan read and the edits
/// still check.
///
/// # Errors
///
/// As [`edit`], and [`Failure::Stale`] when the file or its volume changed
/// after the plan.
pub fn apply(plan: &Plan) -> Result<Applied, Failure> {
    apply_with(&EngineGate, plan)
}

pub(crate) fn edit_with(
    gate: &dyn Gate,
    config_override: Option<&Path>,
    edits: &[Edit],
) -> Result<Applied, Failure> {
    cancelled()?;
    let target = gate.admit(&crate::config::discover_config_path(config_override))?;
    let path = target.path();
    let dir = open(&target)?;
    let _lock = lock(&dir, &path)?;
    let plan = plan_in(target, &dir, path, edits)?;
    write(&dir, &plan)
}

pub(crate) fn plan_with(
    gate: &dyn Gate,
    config_override: Option<&Path>,
    edits: &[Edit],
) -> Result<Plan, Failure> {
    let target = gate.admit(&crate::config::discover_config_path(config_override))?;
    let path = target.path();
    let dir = open(&target)?;
    plan_in(target, &dir, path, edits)
}

/// Stop before anything is done when a cancel already arrived.
fn cancelled() -> Result<(), Failure> {
    crate::cancel::checkpoint().map_err(|_| Failure::Cancelled)
}

pub(crate) fn apply_with(gate: &dyn Gate, plan: &Plan) -> Result<Applied, Failure> {
    cancelled()?;
    let target = gate.admit(&plan.path)?;
    if target != plan.target {
        return Err(Failure::Stale(plan.path.clone()));
    }
    let dir = open(&target)?;
    let _lock = lock(&dir, &plan.path)?;
    let now = plan_in(target, &dir, plan.path.clone(), &plan.edits)?;
    if now.before != plan.before || now.after != plan.after {
        return Err(Failure::Stale(plan.path.clone()));
    }
    write(&dir, &now)
}

fn open(target: &Target) -> Result<PinnedDir, Failure> {
    PinnedDir::open(&target.root, &target.dir, target.mount_id).map_err(pin_failure(Failure::Read))
}

fn lock(dir: &PinnedDir, path: &Path) -> Result<DirLock, Failure> {
    match dir.lock(LOCK_WAIT) {
        Ok(Some(lock)) => Ok(lock),
        Ok(None) => Err(Failure::Busy(path.to_path_buf())),
        Err(error) => Err(pin_failure(Failure::Write)(error)),
    }
}

/// The failure for a refusal of the pinned directory, or `io` for an I/O
/// error.
fn pin_failure(io: fn(NailsError) -> Failure) -> impl Fn(PinError) -> Failure {
    move |error| match error {
        PinError::Io(error) => io(error),
        PinError::Cancelled(_) => Failure::Cancelled,
        PinError::TooLarge(path, limit) => Failure::Invalid(NailsError::ConfigError(format!(
            "invalid config {}: larger than {limit} bytes",
            path.display()
        ))),
        refused => Failure::OffVolume(refused.to_string()),
    }
}

/// Read the file, make the edits and check the result.
fn plan_in(
    target: Target,
    dir: &PinnedDir,
    path: PathBuf,
    edits: &[Edit],
) -> Result<Plan, Failure> {
    let read = dir
        .read(&target.name, MAX_FILE_BYTES)
        .map_err(pin_failure(Failure::Read))?;
    let (before, owner) = match read {
        Some(file) => (Some(file.bytes), Some(file.owner)),
        None => (None, None),
    };
    let text = match &before {
        Some(bytes) => std::str::from_utf8(bytes).map_err(|_| {
            Failure::Invalid(NailsError::ConfigError(format!(
                "invalid config {}: not UTF-8 text",
                path.display()
            )))
        })?,
        None => "",
    };
    let edited = edit::apply(text, edits).map_err(|error| edit_failure(&path, text, error))?;
    let checked = LoadedConfig::parse(&path, &edited.text).map_err(Failure::Invalid)?;
    if let Some(session) = &target.session {
        session_paths(
            &path,
            before.as_ref().map(|_| text),
            &checked.config,
            session,
        )?;
    }
    let after = (edited.text != text).then_some(edited.text);
    Ok(Plan {
        target,
        path,
        edits: edits.to_vec(),
        before,
        owner,
        after,
        changes: edited.changes,
    })
}

fn edit_failure(path: &Path, text: &str, error: EditError) -> Failure {
    match error {
        EditError::Value(message) => Failure::Usage(message),
        EditError::Repeated(_) => Failure::Usage(error.to_string()),
        // The loader says what is wrong with a file that is not TOML, in the
        // words `config validate` uses.
        EditError::Syntax(message) => {
            Failure::Invalid(LoadedConfig::parse(path, text).err().unwrap_or_else(|| {
                NailsError::ConfigError(format!("invalid config {}: {message}", path.display()))
            }))
        }
        EditError::Blocked { .. } => Failure::Invalid(NailsError::ConfigError(format!(
            "invalid config {}: {error}",
            path.display()
        ))),
    }
}

/// While `session` runs, is entering or was left behind, refuse an edit that
/// moves the hidden volume root or the state file anywhere but where the
/// session recorded them: the way back and `recover` find its state there.
/// An edit that leaves a path as the file has it now is not refused for it,
/// and one that moves it back to the recorded place is the repair of a file
/// that went wrong. A path the session did not record (no plan or copy to
/// read) stays where the way back reads it now: the file as it is, or the
/// defaults where it is missing or broken, as `deactivate` reads it.
fn session_paths(
    path: &Path,
    before: Option<&str>,
    after: &Config,
    session: &Session,
) -> Result<(), Failure> {
    let now = before
        .and_then(|text| LoadedConfig::parse(path, text).ok())
        .map_or_else(Config::default, LoadedConfig::into_config);
    let kept = |key, now: &PathBuf, after: &PathBuf, recorded: Option<&PathBuf>| {
        if after == now || recorded == Some(after) {
            Ok(())
        } else {
            Err(Failure::SessionPaths(key))
        }
    };
    kept(
        "hidden_volume_root",
        &now.hidden_volume_root,
        &after.hidden_volume_root,
        session.hidden_root.as_ref(),
    )?;
    kept(
        "state_file_path",
        &now.state_file_path,
        &after.state_file_path,
        session.state_file.as_ref(),
    )
}

fn write(dir: &PinnedDir, plan: &Plan) -> Result<Applied, Failure> {
    if let Some(text) = &plan.after {
        dir.replace(&plan.target.name, text.as_bytes(), plan.owner)
            .map_err(pin_failure(Failure::Write))?;
    }
    Ok(Applied {
        path: plan.path.clone(),
        changes: plan.changes.clone(),
        written: plan.after.is_some(),
        in_session: plan
            .target
            .session
            .as_ref()
            .is_some_and(|session| session.running),
    })
}

#[cfg(test)]
#[path = "config_edit_tests.rs"]
mod tests;
