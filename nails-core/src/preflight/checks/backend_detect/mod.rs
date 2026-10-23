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

    /// A RAM-only zram block device (`zram0`, `zram1`, …), whose discards never
    /// reach persistent storage. The discard refusal does not apply to a stack
    /// that rests on such devices alone ([`rests_on_ram_only`]).
    fn is_ram_backed(&self) -> bool {
        self.name
            .strip_prefix("zram")
            .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
    }

    /// Whether this cryptsetup mapping forwards TRIM to the device below it,
    /// either at runtime (`discard_max_bytes`) or through a stored LUKS2
    /// `allow-discards` flag. A non-cryptsetup device is never counted.
    fn forwards_discards(&self) -> bool {
        self.crypt.is_some() && (self.discard_max_bytes > 0 || self.has_persistent_discards())
    }

    /// Whether this layer's LUKS2 header stores the persistent `allow-discards`
    /// flag, which turns discards on at every open.
    fn has_persistent_discards(&self) -> bool {
        self.luks2
            .as_ref()
            .is_some_and(|meta| meta.flags.iter().any(|flag| flag == "allow-discards"))
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
/// check walks the device stack under the hidden root and reports:
///
/// - **Discards over the hidden volume** (a cryptsetup mapping that forwards
///   TRIM, at runtime or through a stored LUKS2 flag). TRIM leaves a readable
///   used/free map where the volume should look like uniform random data,
///   hole-punches a loop-backed container, and an outer volume opened with
///   discards can destroy a hidden volume inside it. This fails closed; only a
///   stack that rests on RAM-only zram devices alone is excepted, and the
///   operator accepts the risk for one run with `--allow-discards`, which
///   turns the refusal into a warning.
/// - **File containers.** Every read-write session updates the container's
///   mtime and ctime, and ctime cannot be restored.
/// - **File containers on a copy-on-write decoy** (btrfs, zfs, bcachefs),
///   which can keep old container blocks in free space or snapshots.
/// - **Loop devices backed by a FUSE file**, whose mount depends on a
///   userspace process the session kill can terminate.
///
/// # Pass, warn or fail
///
/// Discards over the hidden volume fail closed (unless accepted for the run);
/// the other findings are deniability trade-offs the operator may have
/// accepted, so they only warn. Anything the check cannot read is treated as
/// "no backend information" rather than an error, and detection is automatic
/// and read-only.
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
    /// Whether the operator accepted discards over the hidden volume for this
    /// run (the per-run `--allow-discards` override). Off by default, so
    /// discards fail closed.
    allow_discards: bool,
}

impl BackendDetectCheck {
    /// Create a new `BackendDetectCheck` with a custom hidden-root path.
    ///
    /// Discards over the hidden volume fail closed; call
    /// [`allowing_discards`](Self::allowing_discards) to accept them for a run.
    pub fn new(hidden_volume_root: PathBuf) -> Self {
        Self {
            hidden_volume_root,
            allow_discards: false,
        }
    }

    /// Accept discards over the hidden volume for this run (the per-run
    /// `--allow-discards` override): the discard refusal becomes a warning.
    #[must_use]
    pub fn allowing_discards(mut self, allow: bool) -> Self {
        self.allow_discards = allow;
        self
    }
}

impl Default for BackendDetectCheck {
    /// Create the check with the default hidden-volume path.
    fn default() -> Self {
        Self {
            hidden_volume_root: PathBuf::from(get_default_hidden_volume_root()),
            allow_discards: false,
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
        Ok(assess(fs, &root, self.allow_discards))
    }
}

/// Detect the backend under `root` and turn it into a `Pass`, `Warn` or, when
/// discards are enabled and `allow_discards` is false, a `Fail`.
fn assess<F: Filesystem>(fs: &F, root: &Path, allow_discards: bool) -> CheckResult {
    assess_with_dev_dir(fs, root, Path::new(DEV_DIR), allow_discards)
}

/// [`assess`], reading LUKS2 headers from the device nodes in `dev_dir`.
fn assess_with_dev_dir<F: Filesystem>(
    fs: &F,
    root: &Path,
    dev_dir: &Path,
    allow_discards: bool,
) -> CheckResult {
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
    let discards = discards_over_hidden(&layers);

    // Discards over the hidden volume fail closed: forwarding TRIM makes the
    // used/free block map readable on the physical device, where a deniable
    // volume should look like uniform random data. Accepted for the run with
    // `--allow-discards`, they become a warning instead. The refusal names no
    // device-mapper node.
    if discards && !allow_discards {
        return CheckResult::fail_with(DISCARD_REFUSAL, DISCARD_REMEDIATION);
    }

    let mut found = hazards(&layers, &entries);
    if discards {
        found.insert(0, DISCARD_ACCEPTED.to_string());
    }

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

/// The deniability concerns of discards over the hidden volume, as the refusal
/// states them and `docs/backends.md` explains them. The refusal and its
/// remediation name no device-mapper node.
const DISCARD_REFUSAL: &str = "Discards are enabled over the hidden volume. Forwarding TRIM to the \
     physical device leaves a readable map of used and free blocks there, so a volume that should \
     look like uniform random data no longer does, and writing an outer volume with discards on \
     can destroy a hidden volume inside it.";
const DISCARD_REMEDIATION: &str = "Re-open the hidden volume with discards off. A LUKS2 header \
     that stores the flag keeps enabling them: run `cryptsetup refresh --persistent` without \
     `--allow-discards`, then check that `cryptsetup luksDump` reports `(no flags)`. See \
     docs/backends.md.";
const DISCARD_ACCEPTED: &str = "Discards are enabled over the hidden volume, accepted for this \
     run: TRIM leaves a readable map of used and free blocks on the physical device, where a \
     deniable volume should look like uniform random data.";

/// Whether discards reach the physical device under the hidden volume: a
/// cryptsetup mapping forwards TRIM (at runtime or through a stored LUKS2 flag)
/// and the stack does not rest on RAM-only zram devices alone.
fn discards_over_hidden(layers: &[Layer]) -> bool {
    layers.iter().any(Layer::forwards_discards) && !rests_on_ram_only(layers)
}

/// Whether every device at the bottom of the stack (one without devices below
/// it) is a RAM-only zram device, so TRIM reaches no persistent storage. A
/// zram device anywhere in a stack that also rests on a disk (the cache of a
/// cached logical volume, say) excepts nothing, and neither does a layer whose
/// devices below could not be read.
fn rests_on_ram_only(layers: &[Layer]) -> bool {
    let mut bottom = layers
        .iter()
        .filter(|layer| layer.slaves.is_empty())
        .peekable();
    bottom.peek().is_some() && bottom.all(Layer::is_ram_backed)
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
