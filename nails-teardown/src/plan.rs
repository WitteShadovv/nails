// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The RAM teardown plan: every completed activation step with its fixed undo.
//!
//! Activation appends one [`Step`] per thing it did (a mount, a bind, a guard, a
//! unit the hidden configuration added) and rewrites the file atomically after
//! each, so the file always matches what is live. Rollback undoes the steps
//! recorded so far, deactivation and emergency undo all of them, each in reverse.
//! The undo of a step is a function of the step alone, which is why the plan
//! needs no separate journal: running it twice, or after a partial run, is safe
//! because every operation first checks the live mount table (see
//! [`crate::undo`]).
//!
//! The set of operations is closed and none of them writes to a decoy
//! filesystem: they unmount, clear a read-only flag, or stop a unit.
//!
//! The file lives on the decoy's `/run` tmpfs under a neutral name, never on the
//! hidden volume, so the panic path can read it when the hidden volume is dead.
//! A version field guards the format: a plan of another version is refused and
//! the caller falls back to the live mount table, never to a guess.

use serde::{Deserialize, Serialize};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// The plan format this build reads and writes.
pub const PLAN_VERSION: u32 = 1;

/// The neutral runtime directory on the decoy's `/run` tmpfs that holds the plan
/// (and the RAM-backed copy of the binary and configuration next to it).
pub const RUNTIME_DIR: &str = "/run/overlay-runtime";

/// The plan's file name inside [`RUNTIME_DIR`]. Neutral, like the directory.
pub const PLAN_NAME: &str = "plan.json";

/// The plan's default location.
pub fn default_plan_path() -> PathBuf {
    Path::new(RUNTIME_DIR).join(PLAN_NAME)
}

/// What one activation step mounted, so its undo knows how to take it down and
/// how to tell that the mount at the target is still the one it made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MountKind {
    /// An overlay on a target, a pivot bind of a staged overlay onto its target,
    /// or the fresh-home persona bind: the mounts the live-table classifier
    /// recognises as NAILS-created.
    Overlay,
    /// A plain bind made to keep a host submount visible under an overlaid
    /// target: the staging bind under the hidden root, or the re-attach over the
    /// parent overlay.
    Attachment,
    /// A nested overlay that gives a writable decoy-backed submount its own
    /// upper on the hidden volume.
    NestedOverlay,
    /// The read-only `/nix/store` self-bind made after the `/nix` overlay.
    StoreBind,
    /// A tmpfs backing an ephemeral overlay's upper or work directory.
    Tmpfs,
    /// The per-activation runtime scaffolding tmpfs under `/run`; its directory
    /// is removed after the unmount.
    RuntimeRoot,
}

/// The undo of one activation step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
pub enum Undo {
    /// Unmount what the step mounted at `target`.
    Unmount {
        /// The mount point.
        target: PathBuf,
        /// What was mounted there.
        kind: MountKind,
        /// The mount id the kernel gave the mount, read right after it was made
        /// (`None` when it could not be read). It proves the mount still at the
        /// target is the step's own and not a decoy mount that lay beneath it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mount_id: Option<i32>,
    },
    /// Unmount the `/nix/store` self-bind activation had to make in PID 1's mount
    /// namespace because it ran in another one.
    UnmountInInitNamespace {
        /// The mount point in PID 1's namespace.
        target: PathBuf,
    },
    /// Return write access to a decoy OS tree kept read-only for the session.
    RemoveReadOnlyGuard {
        /// The guarded tree.
        tree: PathBuf,
    },
    /// Stop a unit the hidden configuration added. Only the emergency path runs
    /// this; a standard deactivation reboots instead.
    StopUnit {
        /// The unit name, with its type suffix.
        unit: String,
    },
}

/// When a teardown takes a step down, relative to the rest of the plan.
///
/// The emergency path undoes every phase at once, in reverse order. A standard
/// deactivation keeps its thorough order and runs the phases at different
/// points: the store bind before the shell kill, the dependents after it, the
/// main phase once the artifact cleanup has run through the still-mounted
/// overlays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// The `/nix/store` binds.
    Store,
    /// The read-only guards and the submount attachments, which sit on top of
    /// the overlays and must come off before them.
    Dependents,
    /// The overlays, persona binds, ephemeral tmpfs and the runtime root.
    Main,
    /// Units the hidden configuration added (emergency only).
    Units,
}

impl Undo {
    /// The phase this undo belongs to.
    pub fn phase(&self) -> Phase {
        match self {
            Undo::Unmount {
                kind: MountKind::StoreBind,
                ..
            }
            | Undo::UnmountInInitNamespace { .. } => Phase::Store,
            Undo::Unmount {
                kind: MountKind::Attachment | MountKind::NestedOverlay,
                ..
            }
            | Undo::RemoveReadOnlyGuard { .. } => Phase::Dependents,
            Undo::Unmount { .. } => Phase::Main,
            Undo::StopUnit { .. } => Phase::Units,
        }
    }

    /// The path this undo acts on, if it acts on one.
    pub fn target(&self) -> Option<&Path> {
        match self {
            Undo::Unmount { target, .. } | Undo::UnmountInInitNamespace { target } => Some(target),
            Undo::RemoveReadOnlyGuard { tree } => Some(tree),
            Undo::StopUnit { .. } => None,
        }
    }
}

/// One completed activation step, recorded as its undo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Step {
    /// How to undo the step.
    pub undo: Undo,
}

/// How to run one tool: its absolute path, or the pre-overlay store's dynamic
/// loader with an explicit library path when the tool lives in a `/nix/store`
/// that will be overlaid (the loader then runs `program` from the pre-overlay
/// bind, never through the overlay).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tool {
    /// The program to run.
    pub program: PathBuf,
    /// The dynamic loader to run it through, when one is needed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loader: Option<PathBuf>,
    /// The loader's `--library-path`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub library_path: Option<String>,
}

impl Tool {
    /// A tool run directly from `program`.
    pub fn direct(program: PathBuf) -> Self {
        Self {
            program,
            loader: None,
            library_path: None,
        }
    }
}

/// Absolute paths of the tools the teardown runs, resolved at activation against
/// the decoy system (never through an overlay), so the panic path executes
/// exactly these files and never searches a `PATH`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tools {
    /// `systemctl`, for the stop jobs that keep `Restart=` from reviving a unit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub systemctl: Option<Tool>,
    /// `journalctl`, to hand the journal back to `/run` before `/var` comes down.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub journalctl: Option<Tool>,
}

/// What activation decided about the operator's graphical session, so the panic
/// path never asks logind (see [`crate::session`]).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRecord {
    /// cgroup-path fragments whose processes the kill always spares: the display
    /// manager and the operator's user manager.
    #[serde(default)]
    pub spare_fragments: Vec<String>,
    /// The operator's uid, when activation knew it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_uid: Option<u32>,
}

/// The teardown plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plan {
    /// The format version; see [`PLAN_VERSION`].
    pub version: u32,
    /// The hidden volume root the overlays' upper layers live under.
    pub hidden_root: PathBuf,
    /// The per-activation runtime scaffolding root, once created.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_root: Option<PathBuf>,
    /// The inode of the mount namespace activation ran in. Recorded mount ids
    /// are only compared in that namespace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mount_namespace: Option<u64>,
    /// The tools the teardown runs.
    #[serde(default)]
    pub tools: Tools,
    /// The graphical-session decision made at activation.
    #[serde(default)]
    pub session: SessionRecord,
    /// The completed steps, in the order activation did them.
    #[serde(default)]
    pub steps: Vec<Step>,
}

/// Why a plan could not be used.
#[derive(Debug)]
pub enum PlanError {
    /// No plan file exists.
    Missing,
    /// The file exists but could not be read.
    Unreadable(std::io::Error),
    /// The file is not a valid plan.
    Corrupt(String),
    /// The plan was written in a format version this build does not read.
    Version(u32),
}

impl std::fmt::Display for PlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlanError::Missing => write!(f, "no teardown plan"),
            PlanError::Unreadable(e) => write!(f, "teardown plan unreadable: {e}"),
            PlanError::Corrupt(e) => write!(f, "teardown plan corrupt: {e}"),
            PlanError::Version(v) => write!(
                f,
                "teardown plan has format version {v}, this build reads {PLAN_VERSION}"
            ),
        }
    }
}

impl std::error::Error for PlanError {}

/// Just the version field, read first so a future format is refused by its
/// version rather than by whatever field fails to parse.
#[derive(Deserialize)]
struct VersionProbe {
    version: u32,
}

impl Plan {
    /// An empty plan for an activation using `hidden_root`.
    pub fn new(hidden_root: PathBuf) -> Self {
        Self {
            version: PLAN_VERSION,
            hidden_root,
            runtime_root: None,
            mount_namespace: None,
            tools: Tools::default(),
            session: SessionRecord::default(),
            steps: Vec::new(),
        }
    }

    /// Append a step.
    pub fn push(&mut self, undo: Undo) {
        self.steps.push(Step { undo });
    }

    /// Every undo in teardown order: the reverse of the order activation did
    /// the steps.
    pub fn undo_order(&self) -> impl Iterator<Item = &Undo> {
        self.steps.iter().rev().map(|step| &step.undo)
    }

    /// Whether some step mounted an overlay on exactly `target`.
    pub fn overlays(&self, target: &Path) -> bool {
        self.steps.iter().any(|step| {
            matches!(&step.undo, Undo::Unmount { target: t, kind: MountKind::Overlay, .. } if t == target)
        })
    }

    /// The units the hidden configuration added.
    pub fn hidden_units(&self) -> Vec<String> {
        self.steps
            .iter()
            .filter_map(|step| match &step.undo {
                Undo::StopUnit { unit } => Some(unit.clone()),
                _ => None,
            })
            .collect()
    }

    /// Parse a plan, refusing another format version.
    pub fn from_json(text: &str) -> Result<Self, PlanError> {
        let probe: VersionProbe =
            serde_json::from_str(text).map_err(|e| PlanError::Corrupt(e.to_string()))?;
        if probe.version != PLAN_VERSION {
            return Err(PlanError::Version(probe.version));
        }
        serde_json::from_str(text).map_err(|e| PlanError::Corrupt(e.to_string()))
    }

    /// The plan as compact JSON.
    pub fn to_json(&self) -> String {
        // Serialising plain data with string keys cannot fail.
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Read the plan at `path`.
    pub fn load(path: &Path) -> Result<Self, PlanError> {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::from_json(&text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(PlanError::Missing),
            Err(e) => Err(PlanError::Unreadable(e)),
        }
    }

    /// Write the plan to `path` atomically: a private (`0600`) temporary file in
    /// the same directory, renamed over the old plan, so a reader sees either
    /// the old plan or the new one and never a torn write. The directory must
    /// exist.
    pub fn write_atomic(&self, path: &Path) -> std::io::Result<()> {
        let dir = path.parent().unwrap_or(Path::new("/"));
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let temp = dir.join(format!(".{name}.{}", std::process::id()));
        let result = (|| {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&temp)?;
            file.write_all(self.to_json().as_bytes())?;
            drop(file);
            std::fs::rename(&temp, path)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temp);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Plan {
        let mut plan = Plan::new(PathBuf::from("/mnt/hidden"));
        plan.runtime_root = Some(PathBuf::from("/run/0123456789abcdef"));
        plan.push(Undo::Unmount {
            target: PathBuf::from("/run/0123456789abcdef"),
            kind: MountKind::RuntimeRoot,
            mount_id: Some(40),
        });
        plan.push(Undo::Unmount {
            target: PathBuf::from("/home"),
            kind: MountKind::Overlay,
            mount_id: None,
        });
        plan.push(Undo::RemoveReadOnlyGuard {
            tree: PathBuf::from("/usr"),
        });
        plan.push(Undo::StopUnit {
            unit: "hidden.service".to_string(),
        });
        plan
    }

    #[test]
    fn a_plan_round_trips_through_its_file_format() {
        let plan = sample();
        assert_eq!(Plan::from_json(&plan.to_json()).unwrap(), plan);
    }

    #[test]
    fn the_undo_order_is_the_reverse_of_the_step_order() {
        let order: Vec<_> = sample().undo_order().map(Undo::phase).collect();
        assert_eq!(
            order,
            vec![Phase::Units, Phase::Dependents, Phase::Main, Phase::Main]
        );
    }

    #[test]
    fn another_format_version_is_refused_not_guessed_at() {
        let text = sample().to_json().replace("\"version\":1", "\"version\":2");
        assert!(matches!(Plan::from_json(&text), Err(PlanError::Version(2))));
    }

    #[test]
    fn a_corrupt_plan_is_reported_as_corrupt() {
        assert!(matches!(
            Plan::from_json("not json"),
            Err(PlanError::Corrupt(_))
        ));
        assert!(matches!(
            Plan::from_json("{\"version\":1}"),
            Err(PlanError::Corrupt(_))
        ));
    }

    #[test]
    fn write_atomic_leaves_a_private_file_and_no_temporary() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(PLAN_NAME);
        let mut plan = sample();
        plan.write_atomic(&path).unwrap();
        plan.push(Undo::StopUnit {
            unit: "second.service".to_string(),
        });
        plan.write_atomic(&path).unwrap();

        assert_eq!(Plan::load(&path).unwrap(), plan);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from(PLAN_NAME)]);
    }

    #[test]
    fn a_missing_plan_is_told_apart_from_an_unreadable_one() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            Plan::load(&dir.path().join("absent.json")),
            Err(PlanError::Missing)
        ));
        assert!(matches!(
            Plan::load(dir.path()),
            Err(PlanError::Unreadable(_))
        ));
    }

    #[test]
    fn the_file_names_no_product() {
        let text = sample().to_json().to_lowercase();
        assert!(!text.contains("nails"), "{text}");
        assert!(!default_plan_path().to_string_lossy().contains("nails"));
    }
}
