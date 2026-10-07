// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The teardown plan in `nails-core`: recording it at activation, running it
//! through the [`Filesystem`] abstraction, and rebuilding it when no plan file
//! exists.
//!
//! Activation is a list of steps, each with a fixed undo (T-136). Every mount
//! goes through the [`MountTracker`](crate::MountTracker), which appends the
//! step's undo to the [`PlanRecorder`]; the other steps (the `/nix/store`
//! self-bind, the read-only guards, the units the hidden configuration added,
//! an overlay re-mounted after the NixOS switch) append theirs where they
//! happen. The recorder rewrites the plan file on the decoy's `/run` atomically
//! after each step (ADR 0007).
//!
//! Rollback, deactivation, recovery and emergency then all undo that one plan
//! with [`nails_teardown::undo::run_plan`], through [`FsMountOps`] here (so the
//! unit tests run the same executor against the mock filesystem) or through
//! [`nails_teardown::KernelMountOps`] on the emergency hot path. Adding an
//! activation step therefore needs no teardown code anywhere else: its undo is
//! recorded with it.

use crate::filesystem::Filesystem;
use crate::manager::mount_tracker::{MountInfo, MountType};
use nails_teardown::plan::{MountKind, Plan, Tools, Undo};
use nails_teardown::undo::{Outcome, UndoReport};
use nails_teardown::{MountOps, Presence};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// The private mode of the runtime directory that holds the plan.
const RUNTIME_DIR_MODE: u32 = 0o700;

struct Inner {
    plan: Plan,
    /// Where the plan is persisted; `None` keeps it in memory only (unit tests,
    /// the runtime-safety mode, a tracker built without an activation).
    path: Option<PathBuf>,
}

/// The plan an activation records, shared by the mount tracker, the rollback
/// guard and the activation steps. Cloning shares the same plan.
#[derive(Clone)]
pub struct PlanRecorder {
    inner: Arc<Mutex<Inner>>,
}

impl std::fmt::Debug for PlanRecorder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlanRecorder")
            .field("steps", &self.snapshot().steps.len())
            .finish()
    }
}

impl PlanRecorder {
    /// A recorder for an activation using `hidden_root`, persisting to `path`.
    pub fn new(hidden_root: PathBuf, path: Option<PathBuf>) -> Self {
        let mut plan = Plan::new(hidden_root);
        plan.mount_namespace = nails_teardown::derive::own_mount_namespace();
        let recorder = Self {
            inner: Arc::new(Mutex::new(Inner { plan, path })),
        };
        recorder.persist();
        recorder
    }

    /// A recorder that never touches the disk.
    pub fn memory(hidden_root: PathBuf) -> Self {
        Self::new(hidden_root, None)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// A copy of the plan as recorded so far.
    pub fn snapshot(&self) -> Plan {
        self.lock().plan.clone()
    }

    /// Where the plan is persisted.
    pub fn path(&self) -> Option<PathBuf> {
        self.lock().path.clone()
    }

    /// Change the plan with `edit` and persist it.
    pub fn update(&self, edit: impl FnOnce(&mut Plan)) {
        edit(&mut self.lock().plan);
        self.persist();
    }

    /// Append one step.
    pub fn record(&self, undo: Undo) {
        self.update(|plan| plan.push(undo));
    }

    /// Append the steps of a tracked mount, with the mount id `fs` reports for
    /// it right now.
    pub fn record_mount<F: Filesystem>(&self, fs: &F, info: &MountInfo) {
        let undos = undos_for_mount(info, |target| fs.top_mount_id(target));
        self.update(|plan| {
            if info.mount_type == MountType::Tmpfs {
                plan.runtime_root = Some(info.target.clone());
            }
            for undo in undos {
                plan.push(undo);
            }
        });
    }

    /// Keep only the steps whose undo in `report` failed, after a rollback, so
    /// the plan names exactly what is still live. An empty plan's file is
    /// removed: there is nothing left to tear down.
    pub fn retain_failed(&self, report: &UndoReport) {
        let failed: Vec<PathBuf> = report.failures().into_iter().map(|(p, _)| p).collect();
        let empty = {
            let mut inner = self.lock();
            inner.plan.steps.retain(|step| match &step.undo {
                Undo::StopUnit { .. } => false,
                undo => undo.target().is_some_and(|t| failed.iter().any(|f| f == t)),
            });
            inner.plan.steps.is_empty()
        };
        if empty {
            self.remove_file();
        } else {
            self.persist();
        }
    }

    /// Delete the plan file (after a complete teardown or rollback).
    pub fn remove_file(&self) {
        if let Some(path) = self.path() {
            let _ = std::fs::remove_file(path);
        }
    }

    fn persist(&self) {
        let inner = self.lock();
        let Some(path) = &inner.path else {
            return;
        };
        if let Some(dir) = path.parent()
            && !dir.exists()
        {
            use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
            let created = std::fs::DirBuilder::new()
                .recursive(true)
                .mode(RUNTIME_DIR_MODE)
                .create(dir);
            if created.is_ok() {
                let _ = std::fs::set_permissions(
                    dir,
                    std::fs::Permissions::from_mode(RUNTIME_DIR_MODE),
                );
            }
        }
        if let Err(e) = inner.plan.write_atomic(path) {
            tracing::warn!(
                error = %e,
                path = %path.display(),
                "Could not write the teardown plan; emergency will rebuild it from the mount table"
            );
        }
    }
}

/// The undo steps of one tracked mount, in the order they were mounted. An
/// ephemeral overlay's tmpfs layers were mounted before the overlay, so they
/// are recorded first and taken down after it.
pub(crate) fn undos_for_mount(
    info: &MountInfo,
    mount_id: impl Fn(&Path) -> Option<i32>,
) -> Vec<Undo> {
    let unmount = |target: &Path, kind| Undo::Unmount {
        target: target.to_path_buf(),
        kind,
        mount_id: mount_id(target),
    };
    match info.mount_type {
        MountType::Persistent => vec![unmount(&info.target, MountKind::Overlay)],
        MountType::Ephemeral => info
            .tmpfs_paths
            .iter()
            .map(|p| unmount(p, MountKind::Tmpfs))
            .chain(std::iter::once(unmount(&info.target, MountKind::Overlay)))
            .collect(),
        MountType::Bind => vec![unmount(&info.target, MountKind::Attachment)],
        MountType::NestedOverlay => vec![unmount(&info.target, MountKind::NestedOverlay)],
        MountType::Tmpfs => vec![unmount(&info.target, MountKind::RuntimeRoot)],
    }
}

/// The tools the teardown runs, resolved now against the decoy system. A
/// `systemctl` cached to run through the pre-overlay store's loader is recorded
/// that way, so the panic path never executes from an overlaid `/nix/store`.
pub(crate) fn teardown_tools() -> Tools {
    crate::manager::helpers::teardown_tools()
}

/// [`MountOps`] over a [`Filesystem`], so rollback and deactivation run the
/// plan executor through the same abstraction (and the same mock) as the rest
/// of the manager.
pub struct FsMountOps<'a, F: Filesystem> {
    fs: &'a F,
    hidden_root: PathBuf,
    compare_ids: bool,
}

impl<'a, F: Filesystem> FsMountOps<'a, F> {
    /// Operations on `fs` for a plan recorded with `hidden_root` in the mount
    /// namespace `recorded_namespace`.
    pub fn new(fs: &'a F, hidden_root: &Path, recorded_namespace: Option<u64>) -> Self {
        let compare_ids = recorded_namespace.is_some()
            && recorded_namespace == nails_teardown::derive::own_mount_namespace();
        Self {
            fs,
            hidden_root: hidden_root.to_path_buf(),
            compare_ids,
        }
    }

    /// Operations for `plan`.
    pub fn for_plan(fs: &'a F, plan: &Plan) -> Self {
        Self::new(fs, &plan.hidden_root, plan.mount_namespace)
    }
}

fn io_error(e: crate::NailsError) -> io::Error {
    io::Error::other(e.to_string())
}

impl<F: Filesystem> MountOps for FsMountOps<'_, F> {
    fn presence(
        &self,
        target: &Path,
        kind: MountKind,
        recorded_id: Option<i32>,
    ) -> io::Result<Presence> {
        if !self.fs.is_mounted(target).map_err(io_error)? {
            return Ok(Presence::Absent);
        }
        if self.compare_ids
            && let (Some(recorded), Some(live)) = (recorded_id, self.fs.top_mount_id(target))
        {
            return Ok(if recorded == live {
                Presence::Owned
            } else {
                Presence::Foreign
            });
        }
        match kind {
            MountKind::Tmpfs | MountKind::RuntimeRoot | MountKind::Attachment => {
                Ok(Presence::Owned)
            }
            MountKind::Overlay | MountKind::NestedOverlay | MountKind::StoreBind => {
                Ok(if self.fs.is_nails_owned(target).map_err(io_error)? {
                    Presence::Owned
                } else {
                    Presence::Foreign
                })
            }
        }
    }

    fn nails_mounts(&self) -> io::Result<crate::filesystem::NailsMounts> {
        let mut mounts = self
            .fs
            .discover_nails_mounts(Some(&self.hidden_root))
            .map_err(io_error)?;
        // Keep only what the backend also reports mounted, so a mount point the
        // classifier lists and an unmount already took away is not retried.
        let mounted = |p: &PathBuf| self.fs.is_mounted(p).unwrap_or(true);
        mounts.persistent_overlays.retain(mounted);
        mounts.ephemeral_overlays.retain(mounted);
        mounts.pivot_binds.retain(mounted);
        mounts.persona_binds.retain(mounted);
        if mounts.runtime_tmpfs.as_ref().is_some_and(|p| !mounted(p)) {
            mounts.runtime_tmpfs = None;
        }
        if mounts.nix_store_bind.as_ref().is_some_and(|p| !mounted(p)) {
            mounts.nix_store_bind = None;
        }
        Ok(mounts)
    }

    fn unmount(&self, target: &Path, kind: MountKind, lazy: bool) -> io::Result<()> {
        match kind {
            MountKind::Attachment => self.fs.unmount_bind(target),
            MountKind::Tmpfs | MountKind::RuntimeRoot => self.fs.unmount_tmpfs(target),
            MountKind::Overlay | MountKind::NestedOverlay | MountKind::StoreBind => {
                self.fs.unmount(target, lazy)
            }
        }
        .map_err(io_error)
    }

    fn guard_present(&self, tree: &Path) -> io::Result<bool> {
        self.fs.is_read_only_guard(tree).map_err(io_error)
    }

    fn remove_guard(&self, tree: &Path) -> io::Result<()> {
        self.fs.remove_read_only_guard(tree).map_err(io_error)
    }

    fn unmount_in_init_namespace(&self, target: &Path) -> io::Result<bool> {
        if crate::runtime_safety::should_skip_host_interaction() {
            return Ok(false);
        }
        nails_teardown::initns::unmount_in_init_namespace(target)
    }

    fn remove_dir(&self, path: &Path) -> io::Result<()> {
        self.fs.remove_directory(path).map_err(io_error)
    }
}

/// Log what an executed undo did, one line per action, with the messages the
/// teardown has always printed (the VM suite reads `Overlay unmounted path=…`).
pub(crate) fn log_undo(report: &UndoReport) {
    for action in &report.actions {
        let path = action.target.display();
        match (&action.outcome, action.kind) {
            (Outcome::Detached { lazy }, Some(MountKind::Overlay | MountKind::NestedOverlay)) => {
                let method = if *lazy { "force" } else { "graceful" };
                tracing::info!(path = %path, method, "Overlay unmounted");
            }
            (Outcome::Detached { .. }, Some(MountKind::Attachment)) => {
                tracing::info!(path = %path, "Removed submount attachment");
            }
            (Outcome::Detached { .. }, Some(MountKind::StoreBind)) => {
                tracing::info!(path = %path, "Removed the read-only /nix/store bind");
            }
            (Outcome::Detached { .. }, _) => {
                tracing::info!(path = %path, "Runtime tmpfs unmounted");
            }
            (Outcome::GuardRemoved, _) => {
                tracing::info!(tree = %path, "Removed read-only guard from decoy OS tree");
            }
            (Outcome::Failed(error), _) => {
                tracing::error!(
                    path = %path,
                    error = %error,
                    phase = "unmount",
                    "Unmount failed; continuing with the remaining targets"
                );
            }
            (Outcome::NotOurs, _) => {
                tracing::debug!(path = %path, "Left a mount NAILS did not make in place");
            }
            (Outcome::AlreadyGone, _) => {}
        }
    }
}

/// The overlay-family targets an undo took down, in order, and those that only
/// came down lazily: what a teardown report lists as detached overlays.
pub(crate) fn detached_overlays(report: &UndoReport) -> (Vec<String>, Vec<String>) {
    let detached = report.detached(&[MountKind::Overlay, MountKind::NestedOverlay]);
    let names = detached
        .iter()
        .map(|(p, _)| p.display().to_string())
        .collect();
    let forced = detached
        .iter()
        .filter(|(_, lazy)| *lazy)
        .map(|(p, _)| p.display().to_string())
        .collect();
    (names, forced)
}

impl<F: Filesystem> crate::NailsManager<F> {
    /// Keep the teardown plan at `path` (`None`: in memory only).
    #[must_use]
    pub fn with_plan_path(mut self, path: Option<PathBuf>) -> Self {
        self.plan_path = path;
        self
    }

    /// Where the teardown plan is kept, if on disk.
    pub fn plan_path(&self) -> Option<&Path> {
        self.plan_path.as_deref()
    }

    /// Start recording a fresh plan for this activation, replacing any plan
    /// left from an earlier one. The operator (resolved from the startup
    /// environment, else `session_uid`, the uid of the session the activation
    /// took over) is the one whose user manager the emergency kill spares.
    pub(crate) fn begin_teardown_plan(&self, session_uid: Option<u32>) -> PlanRecorder {
        let operator_uid = crate::TargetUser::resolve_with(self.runtime_env())
            .ok()
            .map(|user| user.uid)
            .filter(|uid| *uid != 0)
            .or(session_uid);
        let recorder = PlanRecorder::new(
            self.config.hidden_volume_root.clone(),
            self.plan_path.clone(),
        );
        recorder.update(|plan| {
            plan.tools = teardown_tools();
            plan.session.operator_uid = operator_uid;
            plan.session.spare_fragments =
                std::iter::once(nails_teardown::session::DISPLAY_MANAGER_FRAGMENT.to_string())
                    .chain(operator_uid.map(nails_teardown::session::user_manager_fragment))
                    .collect();
        });
        *self.teardown_plan.borrow_mut() = Some(recorder.clone());
        recorder
    }

    /// The plan the running activation records, if one is being recorded.
    pub(crate) fn plan_recorder(&self) -> Option<PlanRecorder> {
        self.teardown_plan.borrow().clone()
    }

    /// Record one activation step's undo in the running plan (a no-op outside
    /// an activation).
    pub(crate) fn record_plan_step(&self, undo: Undo) {
        if let Some(recorder) = self.plan_recorder() {
            recorder.record(undo);
        }
    }

    /// Re-resolve the recorded tools: the mount phase caches `systemctl`
    /// against the pre-overlay store once `/nix` is about to be overlaid.
    pub(crate) fn refresh_plan_tools(&self) {
        if let Some(recorder) = self.plan_recorder() {
            recorder.update(|plan| plan.tools = teardown_tools());
        }
    }

    /// The plan a teardown runs, and where it came from.
    ///
    /// In order: the plan this process is recording, the plan file, then a plan
    /// rebuilt from the state file when it is `trusted`, else one rebuilt from
    /// the live mount table.
    pub(crate) fn plan_for_teardown(&self, trusted: bool) -> (Plan, nails_teardown::PlanSource) {
        use nails_teardown::PlanSource;
        if let Some(recorder) = self.plan_recorder() {
            return (recorder.snapshot(), PlanSource::Recorded);
        }
        let why = match &self.plan_path {
            Some(path) => match Plan::load(path) {
                Ok(plan) => return (plan, PlanSource::Recorded),
                Err(e) => e.to_string(),
            },
            None => "no teardown plan file in this run".to_string(),
        };
        if trusted && let Some(plan) = self.plan_from_state() {
            return (
                plan,
                PlanSource::Derived(format!("{why}; rebuilt from the state file")),
            );
        }
        (
            self.plan_from_mounts(),
            PlanSource::Derived(format!("{why}; rebuilt from the mount table")),
        )
    }

    /// The plan the state file implies: what a trusted teardown undid before
    /// plans existed (the recorded overlays in mount order, the runtime root,
    /// the `/nix/store` binds, the submount attachments, the read-only guards
    /// and the units the hidden configuration added).
    fn plan_from_state(&self) -> Option<Plan> {
        use crate::state::SubmountAttachment;
        self.current_state().ok()?;
        let mut overlays = self.tracked_overlay_paths_by_mount_order().ok()?;
        let cached = self.cached_state.borrow();
        let state = cached.as_ref()?;
        if let crate::SystemState::Active {
            overlays: active, ..
        } = &state.state
        {
            for path in active {
                if !overlays.contains(path) {
                    overlays.push(path.clone());
                }
            }
        }
        let mut plan = Plan::new(self.config.hidden_volume_root.clone());
        plan.runtime_root = state.runtime_root.clone();
        let unmount = |target: &Path, kind| Undo::Unmount {
            target: target.to_path_buf(),
            kind,
            mount_id: None,
        };
        if let Some(root) = &state.runtime_root {
            plan.push(unmount(root, MountKind::RuntimeRoot));
        }
        for target in &overlays {
            plan.push(unmount(target, MountKind::Overlay));
        }
        if state.overlay_status.contains_key(Path::new("/nix")) {
            plan.push(unmount(Path::new("/nix/store"), MountKind::StoreBind));
            if state.nix_store_init_namespace_bound {
                plan.push(Undo::UnmountInInitNamespace {
                    target: PathBuf::from("/nix/store"),
                });
            }
        }
        for attachment in &state.submount_attachments {
            plan.push(match attachment {
                SubmountAttachment::Bind { path } => unmount(path, MountKind::Attachment),
                SubmountAttachment::Overlay { path } => unmount(path, MountKind::NestedOverlay),
            });
        }
        for tree in &state.read_only_guards {
            plan.push(Undo::RemoveReadOnlyGuard { tree: tree.clone() });
        }
        for unit in &state.hidden_added_units {
            plan.push(Undo::StopUnit { unit: unit.clone() });
        }
        plan.tools = teardown_tools();
        Some(plan)
    }

    /// The plan the live mount table implies, plus the read-only guards the
    /// platform's policy would have set and that are still in place.
    fn plan_from_mounts(&self) -> Plan {
        let hidden_root = self.config.hidden_volume_root.clone();
        let mounts = self
            .filesystem
            .discover_nails_mounts(Some(&hidden_root))
            .unwrap_or_default();
        let mut plan = nails_teardown::derive::plan_from_nails_mounts(&mounts, &hidden_root);
        // Only a tree that carries a guard now is undone: a policy tree without
        // one is the decoy's own mount (a separate /usr, or / itself).
        let guards = crate::platform::detect_platform(&self.filesystem)
            .ok()
            .map(|platform| platform.overlay_policy())
            .and_then(|policy| policy.resolve_read_only(&self.filesystem).ok())
            .unwrap_or_default();
        for tree in guards {
            if self.filesystem.is_read_only_guard(&tree).unwrap_or(false) {
                plan.push(Undo::RemoveReadOnlyGuard { tree });
            }
        }
        plan.tools = teardown_tools();
        plan
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ephemeral_overlay_records_its_tmpfs_layers_before_itself() {
        let info = MountInfo::ephemeral(
            PathBuf::from("/var"),
            vec![
                PathBuf::from("/run/r/var/upper"),
                PathBuf::from("/run/r/var/work"),
            ],
        );
        let undos = undos_for_mount(&info, |_| None);
        let kinds: Vec<_> = undos
            .iter()
            .map(|u| match u {
                Undo::Unmount { target, kind, .. } => (target.clone(), *kind),
                other => panic!("unexpected {other:?}"),
            })
            .collect();
        assert_eq!(
            kinds,
            vec![
                (PathBuf::from("/run/r/var/upper"), MountKind::Tmpfs),
                (PathBuf::from("/run/r/var/work"), MountKind::Tmpfs),
                (PathBuf::from("/var"), MountKind::Overlay),
            ]
        );
    }

    #[test]
    fn a_recorder_persists_every_step_and_removes_an_emptied_plan() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("runtime").join("plan.json");
        let recorder = PlanRecorder::new(PathBuf::from("/mnt/h"), Some(path.clone()));
        recorder.record(Undo::RemoveReadOnlyGuard {
            tree: PathBuf::from("/usr"),
        });
        let on_disk = Plan::load(&path).unwrap();
        assert_eq!(on_disk, recorder.snapshot());
        assert_eq!(on_disk.steps.len(), 1);

        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, RUNTIME_DIR_MODE);

        recorder.retain_failed(&UndoReport::default());
        assert!(!path.exists());
    }
}
