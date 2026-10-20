// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Storage-backend detection pre-flight check
//!
//! Identifies the block-device stack under the hidden root (dm-crypt type,
//! loop-backed file container, discard policy) and warns about the hazards
//! that are specific to that backend. `docs/backends.md` explains each one.

use super::super::{CheckResult, PreFlightCheck};
use crate::blockdev::{self, DmKind, LoopFollow};
use crate::config::get_default_hidden_volume_root;
use crate::filesystem::mountinfo::{MountEntry, parse_mountinfo};
use crate::{Filesystem, Result};
use std::path::{Path, PathBuf};

mod argon2;
mod hazards;
mod luks2;
pub use argon2::CryptsetupArgon2idCheck;
use hazards::hazards;
use luks2::{Luks2Metadata, read_luks2_header};

/// Where the device nodes the LUKS2 header is read from live.
const DEV_DIR: &str = "/dev";

/// The mount table, which maps the hidden root to its backing device.
const MOUNTINFO: &str = "/proc/self/mountinfo";
/// Where the per-backend guidance lives, named in every warning.
const BACKENDS_DOC: &str = "docs/backends.md";

/// The dm-crypt mapping type, from the `CRYPT-<TYPE>-` prefix that cryptsetup
/// writes into the device-mapper uuid.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CryptType {
    /// A TrueCrypt/VeraCrypt header (`cryptsetup open --type tcrypt`).
    Tcrypt,
    /// LUKS1 or LUKS2.
    Luks,
    /// Headerless plain dm-crypt.
    Plain,
    /// Any other cryptsetup type (BITLK, FVAULT2, an integrity sub-device, ...).
    Other(String),
}

impl CryptType {
    /// The cryptsetup type of a device-mapper device, `None` for a mapping
    /// cryptsetup did not make. The inner layers of a cipher chain and the
    /// integrity and verity mappings keep their own type names here.
    fn of(kind: &DmKind) -> Option<Self> {
        match kind {
            DmKind::Crypt(kind) => Some(match kind.as_str() {
                "TCRYPT" => CryptType::Tcrypt,
                "LUKS1" | "LUKS2" => CryptType::Luks,
                "PLAIN" => CryptType::Plain,
                other => CryptType::Other(other.to_string()),
            }),
            DmKind::CryptSubdev => Some(CryptType::Other("SUBDEV".into())),
            DmKind::Integrity => Some(CryptType::Other("INTEGRITY".into())),
            DmKind::Verity => Some(CryptType::Other("VERITY".into())),
            DmKind::VeraCrypt | DmKind::Lvm | DmKind::Other => None,
        }
    }

    fn label(&self) -> String {
        match self {
            CryptType::Tcrypt => "VeraCrypt/TrueCrypt (tcrypt)".into(),
            CryptType::Luks => "LUKS".into(),
            CryptType::Plain => "plain dm-crypt".into(),
            CryptType::Other(kind) => format!("dm-crypt ({kind})"),
        }
    }

    /// Whether the mapping's deniability rests on its blocks being
    /// indistinguishable from random data, which discards destroy.
    fn relies_on_random_looking_blocks(&self) -> bool {
        matches!(self, CryptType::Tcrypt | CryptType::Plain)
    }
}

/// One block device in the stack under the hidden root, as sysfs reports it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Layer {
    /// Kernel name (`dm-3`, `loop0`, `sdb1`); used only in messages.
    name: String,
    /// Whether this is a device-mapper device.
    is_dm: bool,
    /// The dm-crypt type, when this is a cryptsetup mapping.
    crypt: Option<CryptType>,
    /// The file behind a loop device.
    backing_file: Option<PathBuf>,
    /// `queue/discard_max_bytes`; non-zero means discards reach this device.
    discard_max_bytes: u64,
    /// The device-mapper name (`dm/name`), for a device-mapper device.
    dm_name: Option<String>,
    /// Kernel names of the devices below this one (`slaves/`).
    slaves: Vec<String>,
    /// The LUKS2 header metadata, for a LUKS mapping whose header is on the
    /// device below it (absent for a detached header or an unreadable device).
    luks2: Option<Luks2Metadata>,
}

impl Layer {
    /// The check's view of one device of the stack `nails_base::blockdev`
    /// read.
    fn from_device(device: &blockdev::Layer) -> Self {
        Layer {
            name: device.name.clone(),
            is_dm: device.dm.is_some(),
            crypt: device.dm.as_ref().and_then(|dm| CryptType::of(&dm.kind)),
            backing_file: device
                .loop_device
                .as_ref()
                .map(|loop_device| loop_device.backing.path().to_path_buf()),
            discard_max_bytes: device.discard_max_bytes,
            dm_name: device.dm.as_ref().map(|dm| dm.name.clone()),
            slaves: device.slaves.clone(),
            luks2: None,
        }
    }

    /// Whether this is a Shufflecake (`dm-sflc`) volume, which the tool names
    /// `sflc_<device>_<volume>` in `/dev/mapper`.
    fn is_shufflecake(&self) -> bool {
        self.dm_name.as_deref().is_some_and(|name| {
            name.strip_prefix("sflc_")
                .and_then(|rest| rest.split_once('_'))
                .is_some_and(|(dev, vol)| {
                    !dev.is_empty()
                        && !vol.is_empty()
                        && dev.bytes().all(|b| b.is_ascii_digit())
                        && vol.bytes().all(|b| b.is_ascii_digit())
                })
        })
    }
}

/// Pre-flight check that names deniability hazards specific to the storage
/// backend under the hidden root.
///
/// # Security
///
/// The backend choice changes what an adversary with one or more disk images
/// can learn, and preflight otherwise treats every backend the same. This
/// check walks the device stack under the hidden root and warns about:
///
/// - **Discards on a tcrypt or plain mapping.** TRIM through a hidden volume
///   leaves a readable used/free map where the outer volume should look like
///   random data, hole-punches a loop-backed container, and an outer volume
///   opened with `--allow-discards` can destroy the hidden volume.
/// - **File containers.** Every read-write session updates the container's
///   mtime and ctime, and ctime cannot be restored.
/// - **File containers on a copy-on-write decoy** (btrfs, zfs, bcachefs),
///   which can keep old container blocks in free space or snapshots.
/// - **Loop devices backed by a FUSE file**, whose mount depends on a
///   userspace process the session kill can terminate.
///
/// # Never fails
///
/// The hazards are deniability trade-offs the operator may have accepted, not
/// conditions that make activation unsafe to attempt, so the check only ever
/// returns `Pass` or `Warn`. Anything it cannot read is treated as "no backend
/// information" rather than an error. There is deliberately no configuration
/// knob: detection is automatic and read-only.
///
/// # How it detects
///
/// All reads go through the [`Filesystem`] abstraction, so the logic runs
/// unchanged against `MockFilesystem` fixtures. The hidden root's mount
/// (longest prefix in `/proc/self/mountinfo`) gives a device number, which
/// resolves to `/sys/dev/block/<major:minor>`; btrfs reports an anonymous
/// device there, so the mount source (`/dev/mapper/<name>`, `/dev/dm-N`,
/// `/dev/loopN`) is the fallback. From that device the walk of
/// `nails_base::blockdev` follows `slaves/` and reads `dm/uuid`,
/// `loop/backing_file` and `queue/discard_max_bytes` on every layer.
#[derive(Debug, Clone)]
pub struct BackendDetectCheck {
    hidden_volume_root: PathBuf,
}

impl BackendDetectCheck {
    /// Create a new `BackendDetectCheck` with a custom hidden-root path.
    pub fn new(hidden_volume_root: PathBuf) -> Self {
        Self { hidden_volume_root }
    }
}

impl Default for BackendDetectCheck {
    /// Create the check with the default hidden-volume path.
    fn default() -> Self {
        Self {
            hidden_volume_root: PathBuf::from(get_default_hidden_volume_root()),
        }
    }
}

impl<F: Filesystem> PreFlightCheck<F> for BackendDetectCheck {
    fn name(&self) -> &'static str {
        "backend-detect"
    }

    fn description(&self) -> &'static str {
        "Detects the hidden root's storage backend and warns about backend-specific hazards"
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        // Mount points in mountinfo are canonical paths, so compare against the
        // resolved root, exactly as the real filesystem's mount queries do.
        let root = self
            .hidden_volume_root
            .canonicalize()
            .unwrap_or_else(|_| self.hidden_volume_root.clone());
        Ok(assess(fs, &root))
    }
}

/// Detect the backend under `root` and turn it into a `Pass` or `Warn`.
fn assess<F: Filesystem>(fs: &F, root: &Path) -> CheckResult {
    assess_with_dev_dir(fs, root, Path::new(DEV_DIR))
}

/// [`assess`], reading LUKS2 headers from the device nodes in `dev_dir`.
fn assess_with_dev_dir<F: Filesystem>(fs: &F, root: &Path, dev_dir: &Path) -> CheckResult {
    let Ok(content) = fs.read_file_content(Path::new(MOUNTINFO)) else {
        return CheckResult::Pass(format!(
            "Backend detection skipped: cannot read {MOUNTINFO}"
        ));
    };
    let entries = parse_mountinfo(&content);

    // The hidden-volume check already fails a hidden root that is not itself a
    // mount point; describing the decoy filesystem it would then sit on (and
    // warning about that filesystem's backend) would only mislead.
    let Some(mount) = mount_containing(&entries, root).filter(|m| m.mount_point == root) else {
        return CheckResult::Pass(
            "Backend detection skipped: the hidden root is not a mount point".into(),
        );
    };

    let mut layers = blockdev::device_of_mount(fs, mount)
        .map(|top| device_layers(fs, &top))
        .unwrap_or_default();
    for layer in layers
        .iter_mut()
        .filter(|layer| layer.crypt == Some(CryptType::Luks))
    {
        layer.luks2 = layer
            .slaves
            .first()
            .and_then(|slave| read_luks2_header(&dev_dir.join(slave)));
    }
    let summary = describe(&mount.fstype, &layers);
    let found = hazards(&layers, &entries);

    if found.is_empty() {
        CheckResult::Pass(format!(
            "Hidden root backend: {summary}; no backend-specific hazards detected"
        ))
    } else {
        CheckResult::Warn(format!(
            "Hidden root backend: {summary}. {} See {BACKENDS_DOC}.",
            found.join(" ")
        ))
    }
}

// ============================================================================
// Device-stack discovery and pure assessment seams
// ============================================================================

/// The stack below the device whose sysfs directory is `top`, as the check
/// sees it. The check describes a loop device as a file container, so the
/// walk stops at every loop device ([`LoopFollow::Never`]).
fn device_layers<F: Filesystem>(fs: &F, top: &Path) -> Vec<Layer> {
    blockdev::stack(fs, top, LoopFollow::Never)
        .iter()
        .map(Layer::from_device)
        .collect()
}

/// Pure seam: the mount that contains `path` (longest mount-point prefix).
///
/// When several mounts share that mount point the last one in table order
/// wins, because it is the one stacked on top and therefore visible.
pub(crate) fn mount_containing<'a>(
    entries: &'a [MountEntry],
    path: &Path,
) -> Option<&'a MountEntry> {
    entries
        .iter()
        .filter(|entry| path.starts_with(&entry.mount_point))
        .max_by_key(|entry| entry.mount_point.components().count())
}

/// Pure seam: a one-line description of the backend, top layer first.
fn describe(fstype: &str, layers: &[Layer]) -> String {
    if layers.is_empty() {
        return format!("{fstype} with no identifiable block device");
    }
    let stack: Vec<String> = layers
        .iter()
        .map(|layer| match (&layer.crypt, &layer.backing_file) {
            (Some(crypt), _) => format!("{} mapping {}", crypt.label(), layer.name),
            (None, Some(_)) => format!("loop device {} (file container)", layer.name),
            (None, None) if layer.is_shufflecake() => format!(
                "Shufflecake volume {} ({})",
                layer.dm_name.as_deref().unwrap_or_default(),
                layer.name
            ),
            (None, None) if layer.is_dm => format!("device-mapper device {}", layer.name),
            (None, None) => format!("block device {}", layer.name),
        })
        .collect();
    format!("{fstype} on {}", stack.join(" on "))
}

#[cfg(test)]
mod tests;
