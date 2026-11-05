// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Storage-backend detection pre-flight check
//!
//! Identifies the block-device stack under the hidden root (dm-crypt type,
//! loop-backed file container, discard policy, what the device below a LUKS
//! mapping starts with) and warns about the hazards that are specific to that
//! backend. `docs/backends.md` explains each one.

use super::super::{CheckResult, PreFlightCheck};
use crate::blockdev::{self, DmKind, LoopBacking, LoopFollow};
use crate::config::get_default_hidden_volume_root;
use crate::filesystem::mountinfo::{MountEntry, parse_mountinfo};
use crate::hidden_root::separation::{self, Verdict};
use crate::{Filesystem, Result};
use nails_api::Allowable;
use std::path::{Path, PathBuf};

mod argon2;
mod encryption;
mod graph;
mod hazards;
mod luks2;
mod outer_volume;
mod partition_type;
pub use argon2::{
    CryptsetupArgon2idCheck, CryptsetupVersion, installed_cryptsetup_version,
    parse_cryptsetup_version,
};
pub use encryption::BackendEncryptionCheck;
use hazards::hazards;
use luks2::{HeaderProbe, Luks2Metadata, probe_header, same_volume};
pub use outer_volume::OuterVolumeCheck;
pub use partition_type::BackendPartitionTypeCheck;

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
    /// A mapping the VeraCrypt application made through the kernel
    /// (`veracrypt<N>`, with no uuid up to VeraCrypt 1.26.29 and the uuid
    /// `VERACRYPT-<serial>-<name>` from 1.26.30 on).
    VeraCrypt,
    /// Any other cryptsetup type (BITLK, FVAULT2, an integrity sub-device, ...).
    Other(String),
}

impl CryptType {
    /// The cryptsetup type of a device-mapper device, or the VeraCrypt
    /// application's own mapping; `None` for a mapping neither made. The
    /// inner layers of a cipher chain and the integrity and verity mappings
    /// keep their own type names here.
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
            DmKind::VeraCrypt => Some(CryptType::VeraCrypt),
            DmKind::Lvm | DmKind::Other => None,
        }
    }

    fn label(&self) -> String {
        match self {
            CryptType::Tcrypt => "VeraCrypt/TrueCrypt (tcrypt)".into(),
            CryptType::Luks => "LUKS".into(),
            CryptType::Plain => "plain dm-crypt".into(),
            CryptType::VeraCrypt => "VeraCrypt application".into(),
            CryptType::Other(kind) => format!("dm-crypt ({kind})"),
        }
    }
}

/// One block device in the stack under the hidden root, as sysfs reports it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Layer {
    /// Kernel name (`dm-3`, `loop0`, `sdb1`): in messages, and to tell
    /// whether the walk read every device a layer names in its `slaves`.
    name: String,
    /// Whether this is a device-mapper device.
    is_dm: bool,
    /// The dm-crypt type, when this is a cryptsetup mapping.
    crypt: Option<CryptType>,
    /// The regular file behind a loop device: a file container.
    backing_file: Option<PathBuf>,
    /// The block device behind a loop device, by kernel name.
    loop_over: Option<String>,
    /// Whether a loop device detaches when its last user closes it.
    autoclear: bool,
    /// `queue/discard_max_bytes`; non-zero means discards reach this device.
    discard_max_bytes: u64,
    /// The device-mapper name (`dm/name`), for a device-mapper device.
    dm_name: Option<String>,
    /// The device-mapper uuid (`dm/uuid`), for a device-mapper device.
    dm_uuid: Option<String>,
    /// Kernel names of the devices below this one (`slaves/`).
    slaves: Vec<String>,
    /// Kernel names of the devices the walk went on into below this one: its
    /// `slaves`, or the device behind a loop over a block device.
    below: Vec<String>,
    /// The LUKS2 header metadata, for a LUKS mapping whose own header is on
    /// the device below it (absent for a detached header, an unreadable
    /// device, and a header of another volume).
    luks2: Option<Luks2Metadata>,
    /// What the start of the device below a LUKS mapping holds, once read.
    header: Option<Header>,
}

/// The start of the device a LUKS mapping's header is on, as read.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Header {
    /// The device read, by kernel name: the one below the mapping, or the
    /// one below the sub-devices cryptsetup builds below a LUKS2 volume, such
    /// as its integrity layer.
    device: String,
    /// What its start holds.
    probe: HeaderProbe,
}

impl Layer {
    /// The check's view of one device of the stack `nails_base::blockdev`
    /// read.
    fn from_device(device: &blockdev::Layer) -> Self {
        Layer {
            name: device.name.clone(),
            is_dm: device.dm.is_some(),
            crypt: device.dm.as_ref().and_then(|dm| CryptType::of(&dm.kind)),
            backing_file: device.loop_device.as_ref().and_then(|loop_device| {
                match &loop_device.backing {
                    LoopBacking::File(path) => Some(path.clone()),
                    LoopBacking::Block { .. } => None,
                }
            }),
            loop_over: device.loop_device.as_ref().and_then(|loop_device| {
                match &loop_device.backing {
                    LoopBacking::Block { name, .. } => Some(name.clone()),
                    LoopBacking::File(_) => None,
                }
            }),
            autoclear: device
                .loop_device
                .as_ref()
                .is_some_and(|loop_device| loop_device.autoclear),
            discard_max_bytes: device.discard_max_bytes,
            dm_name: device.dm.as_ref().map(|dm| dm.name.clone()),
            dm_uuid: device.dm.as_ref().map(|dm| dm.uuid.clone()),
            slaves: device.slaves.clone(),
            below: device.below.clone(),
            luks2: None,
            header: None,
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

    /// Whether this cryptsetup or VeraCrypt mapping forwards TRIM to the
    /// device below it, either at runtime (`discard_max_bytes`) or through a
    /// stored LUKS2 `allow-discards` flag. Any other device is never counted.
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

    /// Whether this is a dm-integrity mapping: one integritysetup made, or
    /// the integrity layer cryptsetup puts below a LUKS2 volume with
    /// authenticated encryption, `<name>_dif`, to which cryptsetup 2.8 and
    /// later give the type `SUBDEV` (as they do the further cipher layers of
    /// a cascade) and the volume's uuid.
    fn is_integrity_layer(&self) -> bool {
        let integrity = matches!(&self.crypt, Some(CryptType::Other(kind)) if kind == "INTEGRITY");
        integrity
            || (self.is_luks2_subdevice()
                && self
                    .dm_name
                    .as_deref()
                    .is_some_and(luks2::is_integrity_layer_name))
    }

    /// Whether this is a `SUBDEV` mapping that names a volume uuid: one of
    /// the sub-devices cryptsetup builds below a LUKS2 volume, such as its
    /// integrity layer, or the overlay and the hotzone of an online
    /// reencryption ([`luks2::names_a_volume`]).
    fn is_luks2_subdevice(&self) -> bool {
        matches!(&self.crypt, Some(CryptType::Other(kind)) if kind == "SUBDEV")
            && luks2::names_a_volume(self.dm_uuid.as_deref().unwrap_or_default())
    }

    /// Whether this is a sub-device cryptsetup built below the LUKS volume
    /// whose uuid, without its dashes, is `volume`: a `SUBDEV` mapping, or
    /// the `INTEGRITY` layer of cryptsetup before 2.8, with that uuid.
    fn is_subdevice_of(&self, volume: &str) -> bool {
        let Some(CryptType::Other(kind)) = &self.crypt else {
            return false;
        };
        matches!(kind.as_str(), "SUBDEV" | "INTEGRITY")
            && luks2::volume_uuid_of(self.dm_uuid.as_deref().unwrap_or_default()) == Some(volume)
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
/// - **A LUKS header the mapping was not opened with**: a header of another
///   volume at the start of the device below it, or a LUKS2 secondary header
///   a device opened with a detached header kept, which blkid and an
///   examiner identify. The mapping's own header is named in the pass line.
/// - **A loop device over a block device without autoclear**, which stays
///   bound after the volume is closed.
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
/// `nails_base::blockdev` follows `slaves/` and a loop over a block device,
/// and reads `dm/uuid`, `loop/backing_file` and `queue/discard_max_bytes` on
/// every layer. The start of the device below a LUKS mapping is read
/// read-only, without changing its access time. A root on a filesystem the
/// decoy uses is skipped: its stack is the decoy's, which the attach gate
/// reports. Discards over that stack, which keeps the root's data, are
/// still refused.
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
    let header_devices: Vec<Option<String>> = layers
        .iter()
        .map(|layer| header_device(&layers, layer).map(str::to_string))
        .collect();
    for (layer, device) in layers.iter_mut().zip(header_devices) {
        let Some(device) = device else {
            continue;
        };
        let probe = probe_header(&dev_dir.join(&device));
        if let HeaderProbe::Attached { uuid, meta, .. } = &probe
            && same_volume(uuid, layer.dm_uuid.as_deref().unwrap_or_default())
        {
            layer.luks2 = meta.clone();
        }
        layer.header = Some(Header { device, probe });
    }
    let discards = discards_over_hidden(&layers);

    // Discards over the hidden volume fail closed: forwarding TRIM makes the
    // used/free block map readable on the physical device, where a deniable
    // volume should look like uniform random data. Accepted for the run with
    // `--allow-discards`, they become a warning instead. The refusal names no
    // device-mapper node. It holds for a root on a filesystem the decoy uses
    // too, whose data that stack keeps.
    if discards && !allow_discards {
        return CheckResult::fail_with(DISCARD_REFUSAL, DISCARD_REMEDIATION)
            .accepted_by(Allowable::Discards);
    }

    // A root on a filesystem the decoy uses (a bind, a subvolume, the
    // filesystem itself), which the attach gate refuses unless the run
    // accepts the decoy's storage: its stack is the decoy's own, and
    // describing it as the hidden root's backend would only mislead.
    if let Verdict::OnDecoyFilesystem { .. } =
        separation::judge_storage(fs, &entries, mount, Path::new("/")).verdict
    {
        return if discards {
            CheckResult::Warn(format!(
                "{ON_DECOY_FILESYSTEM}. {DISCARD_ACCEPTED} See {BACKENDS_DOC}."
            ))
        } else {
            CheckResult::Pass(ON_DECOY_FILESYSTEM.into())
        };
    }

    let summary = describe(&mount.fstype, &layers);
    let mut found = hazards(&layers, &entries);
    if discards {
        found.insert(0, DISCARD_ACCEPTED.to_string());
    }
    let notes: String = hazards::notes(&layers)
        .iter()
        .map(|note| format!(" {note}"))
        .collect();

    if found.is_empty() {
        let notes = if notes.is_empty() {
            String::new()
        } else {
            format!(".{notes}")
        };
        CheckResult::Pass(format!(
            "Hidden root backend: {summary}; no backend-specific hazards detected{notes}"
        ))
    } else {
        CheckResult::Warn(format!(
            "Hidden root backend: {summary}. {}{notes} See {BACKENDS_DOC}.",
            found.join(" ")
        ))
    }
}

/// What the check says of a root on a filesystem the decoy uses.
const ON_DECOY_FILESYSTEM: &str = "Backend detection skipped: the hidden root is on a filesystem \
     the decoy uses, which the hidden-volume check reports";

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
/// it, a loop over a block device counting that device as below it) is a
/// RAM-only zram device, so TRIM reaches no persistent storage. A zram
/// device anywhere in a stack that also rests on a disk (the cache of a
/// cached logical volume, say) excepts nothing, and neither does a layer whose
/// devices below could not be read, nor a walk that did not read every device
/// a layer names below it: the walk stops after
/// [`MAX_STACK_DEVICES`](blockdev::MAX_STACK_DEVICES) devices, and the disks
/// it did not reach would take the discards.
fn rests_on_ram_only(layers: &[Layer]) -> bool {
    let walked = |name: &String| layers.iter().any(|layer| layer.name == *name);
    let complete = layers.iter().all(|layer| layer.below.iter().all(walked));
    let mut bottom = layers
        .iter()
        .filter(|layer| layer.below.is_empty())
        .peekable();
    complete && bottom.peek().is_some() && bottom.all(Layer::is_ram_backed)
}

/// The device whose start holds the header of `layer`, a LUKS mapping of the
/// stack `layers`: the device below it, or, where that is one of the
/// volume's own sub-devices, the device below them, which holds the volume's
/// data, and its header unless that is detached. cryptsetup builds the
/// integrity layer of a LUKS2 volume with authenticated encryption on that
/// device, and while `cryptsetup reencrypt` runs on the open volume, the
/// overlay that holds its segments on that device and on the hotzone, a
/// linear map of that device. `None` for any other layer, and for a LUKS
/// mapping whose device below is not known.
fn header_device<'a>(layers: &'a [Layer], layer: &'a Layer) -> Option<&'a str> {
    if layer.crypt != Some(CryptType::Luks) {
        return None;
    }
    let volume = luks2::volume_uuid_of(layer.dm_uuid.as_deref().unwrap_or_default());
    let subdevice = |name: &str| {
        layers
            .iter()
            .find(|other| other.name == name)
            .filter(|other| volume.is_some_and(|volume| other.is_subdevice_of(volume)))
    };
    // Down through the sub-devices, below each to the device that is none
    // where there is one. A stack read from sysfs has no loops, so no way
    // down from `layer` passes more devices than the others of the stack.
    let down = |below: &&'a String| {
        let sub = subdevice(below.as_str())?;
        sub.slaves
            .iter()
            .find(|slave| subdevice(slave.as_str()).is_none())
            .or_else(|| sub.slaves.first())
    };
    std::iter::successors(layer.slaves.first(), down)
        .take(layers.len())
        .find(|below| subdevice(below.as_str()).is_none())
        .map(String::as_str)
}

// ============================================================================
// Device-stack discovery and pure assessment seams
// ============================================================================

/// The stack below the device whose sysfs directory is `top`, as the check
/// sees it: into the device behind a loop over a block device, which holds
/// the hidden volume's data, and no further than a loop over a file, a file
/// container, whose filesystem is not the hidden volume's
/// ([`LoopFollow::BlockDevices`]).
fn device_layers<F: Filesystem>(fs: &F, top: &Path) -> Vec<Layer> {
    blockdev::stack(fs, top, LoopFollow::BlockDevices)
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
            (Some(CryptType::Luks), _)
                if matches!(
                    layer.header.as_ref().map(|header| &header.probe),
                    Some(HeaderProbe::Detached { .. })
                ) =>
            {
                format!("LUKS mapping {} (detached header)", layer.name)
            }
            (Some(_), _) if layer.is_integrity_layer() => {
                format!("dm-integrity mapping {} (encrypts nothing)", layer.name)
            }
            (Some(_), _) if layer.is_luks2_subdevice() => {
                format!("LUKS2 sub-device {} (SUBDEV)", layer.name)
            }
            (Some(CryptType::Other(kind)), _) if kind == "SUBDEV" => {
                format!("dm-crypt cascade layer {} (SUBDEV)", layer.name)
            }
            (Some(CryptType::Other(kind)), _) if kind == "VERITY" => {
                format!("dm-verity mapping {} (encrypts nothing)", layer.name)
            }
            (Some(crypt), _) => format!("{} mapping {}", crypt.label(), layer.name),
            (None, Some(_)) => format!("loop device {} (file container)", layer.name),
            (None, None) if layer.loop_over.is_some() => format!("loop device {}", layer.name),
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
#[cfg(test)]
mod tests_host;
