// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The session plan of a whole-root session.
//!
//! Activation writes it on the decoy's `/run` tmpfs before the soft-reboot into
//! the hidden root. `/run` is carried across every soft-reboot, so the same file
//! is read in the hidden session by `deactivate` and `emergency`, and by the
//! transition step that runs last before each switch (see
//! [`crate::whole_root::transition`]). It records everything needed to get back
//! to the plain decoy root without the configuration or the hidden volume: the
//! decoy root's device, the init paths to check, the device-mapper stack to
//! close, and the tools to run.
//!
//! The file lives under a neutral name and never on the hidden volume. A version
//! field guards the format: a plan of another version is refused, never guessed
//! at.

use crate::whole_root::runtime_units::RuntimeUnit;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// The plan format this build reads and writes.
pub const PLAN_VERSION: u32 = 2;

/// The neutral runtime directory on the decoy's `/run` tmpfs. It holds the plan,
/// the `/run` snapshot, the saved `utab` with the mounts it names and the RAM
/// copy of the binary. The return scrub removes it as a whole.
pub const RUNTIME_DIR: &str = "/run/overlay-runtime";

/// The plan's file name inside [`RUNTIME_DIR`].
pub const PLAN_NAME: &str = "plan.json";

/// The `/run` snapshot's file name inside [`RUNTIME_DIR`].
pub const SNAPSHOT_NAME: &str = "run-entries";

/// The saved `/run/mount/utab` inside [`RUNTIME_DIR`].
pub const UTAB_NAME: &str = "mount-table";

/// The decoy's mount table lines for the mounts the saved `utab` names by ID,
/// read with it, inside [`RUNTIME_DIR`]
/// ([`crate::whole_root::utab::named_mounts`]).
pub const UTAB_MOUNTS_NAME: &str = "mount-ids";

/// The copy of the decoy's records ([`crate::whole_root::run_records`])
/// inside [`RUNTIME_DIR`].
pub const RECORDS_NAME: &str = "run-records";

/// The RAM copy of the binary inside [`RUNTIME_DIR`] (neutral name).
pub const BINARY_NAME: &str = "control";

/// How long an armed transition stays valid. A soft-reboot runs the orderly
/// shutdown first, and `soft-reboot.target` itself times out after 30 minutes,
/// so an arming older than that never belongs to the transition running now.
pub const ARM_VALIDITY_SECS: u64 = 30 * 60;

/// The plan's default location.
pub fn default_plan_path() -> PathBuf {
    Path::new(RUNTIME_DIR).join(PLAN_NAME)
}

/// The activation process that wrote the plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Owner {
    /// The pid.
    pub pid: u32,
    /// Its start time, in clock ticks since boot.
    pub start_time: u64,
}

/// The decoy root, as needed to mount it again at `/run/nextroot` from inside
/// the hidden session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecoyRoot {
    /// The block device the decoy root is mounted from.
    pub source: PathBuf,
    /// Its filesystem type.
    pub fstype: String,
    /// Mount data needed to reach the same tree (a btrfs `subvol=`), if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
}

/// One root a transition switches into: its init and, on NixOS, the system
/// toplevel `/run/current-system` must point at when PID 1 re-executes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootSide {
    /// The init PID 1 will execute, as a path inside that root. Checked before
    /// every switch: systemd >= 258 freezes on a root without a usable init.
    pub init: PathBuf,
    /// The NixOS system toplevel of that root (`/nix/store/…-nixos-system-…`),
    /// which `/run/current-system` is repointed to right before the switch.
    /// `None` on a host whose init is a plain path (FHS).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system: Option<PathBuf>,
}

/// A mount the fstab policy placed inside the next root, for status and tests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyMount {
    /// The mount point, as a path inside the hidden root.
    pub target: PathBuf,
    /// What was put there.
    pub kind: PolicyMountKind,
}

/// What the fstab policy put on a decoy filesystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyMountKind {
    /// A read-only bind (the ESP and other boot filesystems).
    ReadOnlyBind,
    /// An overlay with its upper on the hidden volume.
    Overlay,
    /// The hidden volume itself, bound at its own path.
    HiddenVolume,
}

/// A decoy filesystem carried into the hidden session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CarriedMount {
    /// Its mount point in the decoy root.
    pub target: PathBuf,
    /// Where the hidden session holds it: a read-only bind on the hidden volume.
    pub at: PathBuf,
    /// Whether the decoy had it read-only.
    pub read_only: bool,
    /// The carried mount's filesystem (`major:minor`, as the mount table
    /// shows it) and the directory of it that the mount shows. The way back
    /// takes a mount from it only while the mount at [`at`](Self::at) is still
    /// that one. Absent from a plan written before they were recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dev: Option<String>,
    /// See [`dev`](Self::dev).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<PathBuf>,
}

/// Where the way back takes a decoy mount from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MountSource {
    /// The decoy root, mounted again from its device.
    Root,
    /// The carried decoy filesystem with this index in [`Plan::carried`].
    Carried(usize),
}

/// A mount of the decoy that the way back makes again (see
/// [`crate::whole_root::decoy_mounts`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecoyMount {
    /// Its mount ID in the decoy at entry: libmount's `utab` lines name it by
    /// this ID.
    pub id: i32,
    /// Its mount point in the decoy root.
    pub target: PathBuf,
    /// The filesystem it shows.
    pub source: MountSource,
    /// The directory of that filesystem it shows, relative to the one the
    /// source shows (empty for the same).
    pub path: PathBuf,
    /// Its per-mount options, as the mount table shows them
    /// (`ro,nosuid,nodev,relatime`).
    pub options: String,
    /// The mount ID the way back gave it, which the transition gives its
    /// `utab` lines. Absent until the way back is prepared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restored: Option<i32>,
}

/// Absolute paths of the tools a transition-side step runs, resolved at
/// activation so nothing searches a `PATH` later.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tools {
    /// `systemctl`, to enqueue the soft-reboot or the power action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub systemctl: Option<PathBuf>,
    /// `dmsetup`, to mark the hidden backend for deferred removal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dmsetup: Option<PathBuf>,
}

/// Which way the armed transition goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Direction {
    /// From the decoy into the hidden root.
    Enter,
    /// From the hidden root back to the plain decoy root.
    Leave,
}

/// A transition the next soft-reboot is allowed to perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Arm {
    /// The direction.
    pub direction: Direction,
    /// When it was armed, in seconds since the epoch.
    pub at: u64,
}

impl Arm {
    /// An arming for `direction` made now.
    pub fn now(direction: Direction) -> Self {
        Self {
            direction,
            at: unix_now(),
        }
    }

    /// Whether this arming is still valid at `now` (seconds since the epoch).
    pub fn valid_at(&self, now: u64) -> bool {
        now >= self.at && now - self.at <= ARM_VALIDITY_SECS
    }
}

/// Seconds since the epoch.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The session plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plan {
    /// The format version; see [`PLAN_VERSION`].
    pub version: u32,
    /// The hidden volume root.
    pub hidden_root: PathBuf,
    /// The device (`major:minor`, as the mount table shows it) of the mount at
    /// the hidden root when the entry began. In the session the attach gate
    /// accepts the root only while this device is mounted there, so a disk
    /// mounted over the hidden root receives no write. Absent from a plan
    /// written before it was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hidden_dev: Option<String>,
    /// Why the hidden root is not a volume of its own, when the operator
    /// accepted that with `activate --allow-decoy-storage`. In the session the
    /// attach gate then accepts a root that is no mount point; `status` shows
    /// it and `rehearse plant` refuses. Absent when nothing was overridden.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_decoy_storage: Option<String>,
    /// The root overlay's upper directory on the hidden volume.
    pub upper: PathBuf,
    /// The root overlay's work directory on the hidden volume.
    pub work: PathBuf,
    /// The activation process that wrote the plan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<Owner>,
    /// The decoy root device, to mount at `/run/nextroot` on the way back.
    pub decoy_root: DecoyRoot,
    /// The decoy side of the transition.
    pub decoy: RootSide,
    /// The hidden side of the transition.
    pub hidden: RootSide,
    /// The mounts the fstab policy made inside the hidden root.
    #[serde(default)]
    pub policy_mounts: Vec<PolicyMount>,
    /// Units masked in `/run` at entry, so the hidden systemd never starts them
    /// (decoy swap, decoy filesystems that would be mounted read-write).
    #[serde(default)]
    pub masks: Vec<String>,
    /// Units masked in the hidden root alone, best effort: units of the decoy
    /// that would only fail there and whose job the hidden root does not
    /// need, the boot-loader units that write to the read-only boot
    /// filesystems at every start among them. Kept apart from
    /// [`masks`](Self::masks), without which the entry must not happen.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub boot_masks: Vec<String>,
    /// Runtime units installed in `/run` at entry, for the hidden session.
    #[serde(default)]
    pub session_units: Vec<RuntimeUnit>,
    /// Device-mapper names of the hidden backend, top of the stack first,
    /// marked for deferred removal before the way back.
    #[serde(default)]
    pub backend: Vec<String>,
    /// The tools.
    #[serde(default)]
    pub tools: Tools,
    /// The transition the next soft-reboot may perform.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub armed: Option<Arm>,
    /// When the hidden root was entered, in seconds since the epoch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entered_at: Option<u64>,
    /// Whether the entry cleared `noexec` on `/run` (Debian and Ubuntu mount
    /// it so) to run the binary copy there; the way back sets it again.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub run_noexec: bool,
    /// Decoy filesystems carried into the hidden session, so the way back can
    /// put them in place in the decoy root again (see
    /// [`crate::whole_root::carry`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub carried: Vec<CarriedMount>,
    /// The decoy's mounts the way back makes again, the decoy root first and
    /// the others in the order the decoy mounted them (see
    /// [`crate::whole_root::decoy_mounts`]). Absent from a plan written before
    /// they were recorded: the way back then puts back the decoy root and the
    /// carried filesystems alone.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub decoy_mounts: Vec<DecoyMount>,
    /// Whether the disks the session does not use are read-only for the
    /// session (`[session_mounts] read_only`): the entry transition installs
    /// the udev rule, the way back makes them writable again (see
    /// [`crate::whole_root::disk_guard`]).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub read_only_disks: bool,
    /// The units already failed when the session was prepared. The way back
    /// resets every other failed unit, so a failure the session caused (an
    /// emergency's kill, a unit that would not stop) never reaches the decoy,
    /// while the decoy's own earlier failures stay.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failed_at_entry: Vec<String>,
    /// The kernel's helper paths as the decoy had them before a hidden NixOS
    /// activation rewrote them; every way back to the decoy writes them back
    /// (see [`crate::whole_root::kernel_helpers`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kernel_settings: Vec<crate::whole_root::kernel_helpers::KernelSetting>,
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
            PlanError::Missing => write!(f, "no session plan"),
            PlanError::Unreadable(e) => write!(f, "session plan unreadable: {e}"),
            PlanError::Corrupt(e) => write!(f, "session plan corrupt: {e}"),
            PlanError::Version(v) => write!(
                f,
                "session plan has format version {v}, this build reads {PLAN_VERSION}"
            ),
        }
    }
}

impl std::error::Error for PlanError {}

#[derive(Deserialize)]
struct VersionProbe {
    version: u32,
}

impl Plan {
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

    /// Write the plan to `path` atomically, private (`0600`). The directory
    /// must exist.
    pub fn write_atomic(&self, path: &Path) -> std::io::Result<()> {
        write_private_atomic(path, self.to_json().as_bytes())
    }

    /// Whether the plan is armed for `direction` and the arming is still valid
    /// at `now`.
    pub fn armed_for(&self, direction: Direction, now: u64) -> bool {
        self.armed
            .is_some_and(|arm| arm.direction == direction && arm.valid_at(now))
    }
}

/// The mode of the files the session writes for the service manager and udev
/// (drop-ins, runtime units, the read-only rule). Both read them as root, but
/// PID 1 warns about a configuration file that is not readable by everyone and
/// names it in the log: at the start of the other root, before its journald
/// runs, that is the kernel log, which outlives the session in RAM.
pub const SERVICE_CONFIG_MODE: u32 = 0o644;

/// Write `bytes` to `path` through a private temporary file in the same
/// directory, renamed over the target, so a reader never sees a torn write.
pub fn write_private_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    write_atomic_with_mode(path, bytes, 0o600)
}

/// [`write_private_atomic`], with the file's final `mode` set on the open
/// temporary file before the rename: the name never shows another mode, and
/// a restrictive umask cannot take bits away.
pub fn write_atomic_with_mode(path: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
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
        file.write_all(bytes)?;
        file.set_permissions(std::fs::Permissions::from_mode(mode))?;
        drop(file);
        std::fs::rename(&temp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

#[cfg(test)]
pub(crate) fn sample() -> Plan {
    Plan {
        version: PLAN_VERSION,
        hidden_root: PathBuf::from("/mnt/data"),
        hidden_dev: None,
        accepted_decoy_storage: None,
        upper: PathBuf::from("/mnt/data/root/upper"),
        work: PathBuf::from("/mnt/data/root/work"),
        owner: Some(Owner {
            pid: 42,
            start_time: 7,
        }),
        decoy_root: DecoyRoot {
            source: PathBuf::from("/dev/vda2"),
            fstype: "ext4".to_string(),
            data: None,
        },
        decoy: RootSide {
            init: PathBuf::from("/nix/store/aaa-nixos-system/systemd/lib/systemd/systemd"),
            system: Some(PathBuf::from("/nix/store/aaa-nixos-system")),
        },
        hidden: RootSide {
            init: PathBuf::from("/nix/store/bbb-nixos-system/systemd/lib/systemd/systemd"),
            system: Some(PathBuf::from("/nix/store/bbb-nixos-system")),
        },
        policy_mounts: vec![PolicyMount {
            target: PathBuf::from("/boot"),
            kind: PolicyMountKind::ReadOnlyBind,
        }],
        masks: vec!["dev-vda3.swap".to_string()],
        boot_masks: Vec::new(),
        session_units: Vec::new(),
        backend: vec!["sample-backend-unmapped".to_string()],
        tools: Tools::default(),
        armed: Some(Arm {
            direction: Direction::Enter,
            at: 1_000,
        }),
        entered_at: None,
        run_noexec: false,
        carried: Vec::new(),
        decoy_mounts: Vec::new(),
        read_only_disks: false,
        failed_at_entry: Vec::new(),
        kernel_settings: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plan_round_trips_through_its_file_format() {
        let plan = sample();
        assert_eq!(Plan::from_json(&plan.to_json()).unwrap(), plan);
    }

    #[test]
    fn the_hidden_device_is_kept_and_a_plan_without_it_still_loads() {
        let recorded = Plan {
            hidden_dev: Some("253:0".to_string()),
            ..sample()
        };
        let text = recorded.to_json();
        assert!(text.contains("\"hidden_dev\":\"253:0\""), "{text}");
        assert_eq!(Plan::from_json(&text).unwrap(), recorded);

        // A plan written before the field existed has no key at all.
        let older = sample().to_json();
        assert!(!older.contains("hidden_dev"), "{older}");
        assert_eq!(Plan::from_json(&older).unwrap().hidden_dev, None);
    }

    #[test]
    fn an_accepted_override_is_kept_and_a_plan_without_it_still_loads() {
        let accepted = Plan {
            accepted_decoy_storage: Some("it is a folder on the filesystem mounted at /".into()),
            ..sample()
        };
        let text = accepted.to_json();
        assert!(text.contains("\"accepted_decoy_storage\":"), "{text}");
        assert_eq!(Plan::from_json(&text).unwrap(), accepted);

        let plain = sample().to_json();
        assert!(!plain.contains("accepted_decoy_storage"), "{plain}");
        assert_eq!(
            Plan::from_json(&plain).unwrap().accepted_decoy_storage,
            None
        );
    }

    #[test]
    fn another_format_version_is_refused_not_guessed_at() {
        let text = sample().to_json().replace("\"version\":2", "\"version\":1");
        assert!(matches!(Plan::from_json(&text), Err(PlanError::Version(1))));
        assert!(matches!(
            Plan::from_json("not json"),
            Err(PlanError::Corrupt(_))
        ));
    }

    #[test]
    fn an_arming_is_valid_only_for_its_direction_and_window() {
        let plan = sample();
        assert!(plan.armed_for(Direction::Enter, 1_000));
        assert!(plan.armed_for(Direction::Enter, 1_000 + ARM_VALIDITY_SECS));
        assert!(!plan.armed_for(Direction::Enter, 1_001 + ARM_VALIDITY_SECS));
        assert!(!plan.armed_for(Direction::Leave, 1_000));
        // A clock that went backwards never validates an arming.
        assert!(!plan.armed_for(Direction::Enter, 999));
    }

    #[test]
    fn write_atomic_leaves_a_private_file_and_no_temporary() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(PLAN_NAME);
        sample().write_atomic(&path).unwrap();
        assert_eq!(Plan::load(&path).unwrap(), sample());
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        assert!(matches!(
            Plan::load(&dir.path().join("absent")),
            Err(PlanError::Missing)
        ));
    }

    #[test]
    fn a_file_written_with_a_mode_has_it_and_replaces_the_old_one_whole() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("unit.conf");
        std::fs::write(&path, "old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        write_atomic_with_mode(&path, b"[Service]\n", SERVICE_CONFIG_MODE).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "[Service]\n");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o644);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn the_runtime_names_carry_no_product_name() {
        for name in [
            RUNTIME_DIR,
            PLAN_NAME,
            SNAPSHOT_NAME,
            UTAB_NAME,
            UTAB_MOUNTS_NAME,
            RECORDS_NAME,
            BINARY_NAME,
        ] {
            assert!(!name.to_lowercase().contains("nails"), "{name}");
        }
        assert!(!sample().to_json().to_lowercase().contains("nails"));
    }
}
