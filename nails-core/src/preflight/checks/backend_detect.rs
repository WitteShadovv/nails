// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Storage-backend detection pre-flight check
//!
//! Identifies the block-device stack under the hidden root (dm-crypt type,
//! loop-backed file container, discard policy) and warns about the hazards
//! that are specific to that backend. `docs/backends.md` explains each one.

use super::super::{CheckResult, PreFlightCheck};
use crate::config::get_default_hidden_volume_root;
use crate::filesystem::mountinfo::{MountEntry, parse_mountinfo};
use crate::{Filesystem, Result};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};

mod luks2;
use luks2::{Luks2Metadata, read_luks2_header};

/// Where the device nodes the LUKS2 header is read from live.
const DEV_DIR: &str = "/dev";
/// LUKS2 token types that name the unlock method and tie it to hardware.
const HARDWARE_TOKENS: &[&str] = &["systemd-tpm2", "systemd-fido2", "systemd-pkcs11"];

/// The mount table, which maps the hidden root to its backing device.
const MOUNTINFO: &str = "/proc/self/mountinfo";
/// Block devices by `major:minor`.
const SYS_DEV_BLOCK: &str = "/sys/dev/block";
/// Block devices (disks and partitions) by kernel name.
const SYS_CLASS_BLOCK: &str = "/sys/class/block";
/// Whole block devices by kernel name; device-mapper devices live here.
const SYS_BLOCK: &str = "/sys/block";
/// Upper bound on the devices visited in one stack. Real stacks are two or
/// three deep (filesystem on dm-crypt on a loop device or partition); the
/// bound only keeps a pathological sysfs from turning the walk into a loop.
const MAX_STACK_DEVICES: usize = 16;
/// Filesystems that write changed blocks to new locations instead of in place.
const COW_FILESYSTEMS: &[&str] = &["btrfs", "zfs", "bcachefs"];
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
/// `/dev/loopN`) is the fallback. From that device the walk follows `slaves/`
/// and reads `dm/uuid`, `loop/backing_file` and `queue/discard_max_bytes` on
/// every layer.
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

    let mut layers = device_dir_for_mount(fs, mount)
        .map(|top| device_stack(fs, top))
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

/// The files behind any loop device in the stack under the hidden root mounted
/// at `root` (a file container's path), empty when the root is not a mount point
/// or not file-backed. `entries` is the parsed mount table.
pub(crate) fn hidden_root_backing_files<F: Filesystem>(
    fs: &F,
    entries: &[MountEntry],
    root: &Path,
) -> Vec<PathBuf> {
    let Some(mount) = mount_containing(entries, root).filter(|m| m.mount_point == root) else {
        return Vec::new();
    };
    device_dir_for_mount(fs, mount)
        .map(|top| device_stack(fs, top))
        .unwrap_or_default()
        .into_iter()
        .filter_map(|layer| layer.backing_file)
        .collect()
}

// ============================================================================
// Device-stack discovery (Filesystem reads only)
// ============================================================================

/// The sysfs directory of the block device the mount sits on, if any.
fn device_dir_for_mount<F: Filesystem>(fs: &F, mount: &MountEntry) -> Option<PathBuf> {
    // ext4, xfs and f2fs report the real block device's number.
    let by_dev = Path::new(SYS_DEV_BLOCK).join(&mount.dev);
    if is_block_device_dir(fs, &by_dev) {
        return Some(by_dev);
    }

    // btrfs reports an anonymous `0:N` device, so fall back to the source.
    let source_name = mount.source.file_name()?.to_str()?;
    if mount.source.starts_with("/dev/mapper") {
        return find_dm_by_name(fs, source_name);
    }
    if mount.source.starts_with("/dev") {
        let by_name = Path::new(SYS_CLASS_BLOCK).join(source_name);
        if is_block_device_dir(fs, &by_name) {
            return Some(by_name);
        }
    }
    None
}

/// Every block device's sysfs directory carries a `dev` attribute.
fn is_block_device_dir<F: Filesystem>(fs: &F, dir: &Path) -> bool {
    fs.read_file_content(&dir.join("dev")).is_ok()
}

/// Find the device-mapper device whose `dm/name` is `name`.
fn find_dm_by_name<F: Filesystem>(fs: &F, name: &str) -> Option<PathBuf> {
    let mut devices = fs.list_directory(Path::new(SYS_BLOCK)).ok()?;
    devices.sort();
    devices.into_iter().find(|dir| {
        fs.read_file_content(&dir.join("dm/name"))
            .is_ok_and(|dm_name| dm_name.trim() == name)
    })
}

/// Walk from `top` down through `slaves/`, reading each layer once.
fn device_stack<F: Filesystem>(fs: &F, top: PathBuf) -> Vec<Layer> {
    let mut layers = Vec::new();
    let mut pending = VecDeque::from([top]);
    while let Some(dir) = pending.pop_front() {
        if layers.len() >= MAX_STACK_DEVICES {
            break;
        }
        let mut layer = read_layer(fs, &dir);
        if let Ok(mut slaves) = fs.list_directory(&dir.join("slaves")) {
            slaves.sort();
            layer.slaves = slaves
                .iter()
                .filter_map(|slave| slave.file_name())
                .map(|name| name.to_string_lossy().into_owned())
                .collect();
            pending.extend(slaves);
        }
        layers.push(layer);
    }
    layers
}

/// Read the attributes of one block device; every attribute is optional.
fn read_layer<F: Filesystem>(fs: &F, dir: &Path) -> Layer {
    let read = |attribute: &str| fs.read_file_content(&dir.join(attribute)).ok();

    let dm_uuid = read("dm/uuid");
    let dm_name = read("dm/name").map(|name| name.trim().to_string());
    let name = read("uevent")
        .as_deref()
        .and_then(parse_devname)
        .or_else(|| {
            dir.file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })
        .unwrap_or_default();

    Layer {
        name,
        is_dm: dm_uuid.is_some() || dm_name.is_some(),
        crypt: dm_uuid.as_deref().and_then(classify_dm_uuid),
        backing_file: read("loop/backing_file")
            .as_deref()
            .and_then(parse_backing_file),
        discard_max_bytes: read("queue/discard_max_bytes")
            .as_deref()
            .and_then(parse_discard_max_bytes)
            .unwrap_or(0),
        dm_name,
        slaves: Vec::new(),
        luks2: None,
    }
}

// ============================================================================
// Pure parsing and assessment seams
// ============================================================================

/// Pure seam: the dm-crypt type encoded in a device-mapper uuid.
///
/// cryptsetup names its mappings `CRYPT-<TYPE>-[<uuid>-]<name>`, e.g.
/// `CRYPT-LUKS2-<hex>-hidden` or `CRYPT-TCRYPT-hidden`. Anything without the
/// `CRYPT-` prefix (LVM, multipath, a hand-made `dmsetup` table) is not a
/// cryptsetup mapping.
fn classify_dm_uuid(uuid: &str) -> Option<CryptType> {
    let rest = uuid.trim().strip_prefix("CRYPT-")?;
    let kind = rest.split('-').next().unwrap_or_default();
    match kind {
        "" => None,
        "TCRYPT" => Some(CryptType::Tcrypt),
        "LUKS1" | "LUKS2" => Some(CryptType::Luks),
        "PLAIN" => Some(CryptType::Plain),
        other => Some(CryptType::Other(other.to_string())),
    }
}

/// Pure seam: the file behind a loop device, from `loop/backing_file`.
///
/// The attribute is absent for an unbound loop device and holds the path plus
/// a newline otherwise.
fn parse_backing_file(content: &str) -> Option<PathBuf> {
    let path = content.trim_end_matches('\n');
    (!path.is_empty()).then(|| PathBuf::from(path))
}

/// Pure seam: the value of `queue/discard_max_bytes`.
fn parse_discard_max_bytes(content: &str) -> Option<u64> {
    content.trim().parse().ok()
}

/// Pure seam: the kernel device name (`DEVNAME=`) from a sysfs `uevent`.
fn parse_devname(uevent: &str) -> Option<String> {
    uevent
        .lines()
        .find_map(|line| line.strip_prefix("DEVNAME="))
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
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

/// Pure seam: one sentence-group per hazard found in the device stack.
///
/// `entries` is the mount table, used to find the filesystem a container file
/// lives on.
fn hazards(layers: &[Layer], entries: &[MountEntry]) -> Vec<String> {
    let mut found = Vec::new();

    for layer in layers {
        if let Some(crypt) = &layer.crypt
            && crypt.relies_on_random_looking_blocks()
            && layer.discard_max_bytes > 0
        {
            found.push(discard_hazard(crypt, layer));
        }
        if let Some(meta) = &layer.luks2 {
            found.extend(luks2_hazards(layer, meta));
        }

        let Some(backing_file) = &layer.backing_file else {
            continue;
        };
        let host_fstype = mount_containing(entries, backing_file).map(|m| m.fstype.as_str());

        // A FUSE-provided file (for example VeraCrypt's aux mount without
        // kernel crypto) is not the container itself, so the container
        // timestamp and COW findings would name the wrong file.
        if let Some(fstype) = host_fstype.filter(|fs| fs.starts_with("fuse")) {
            found.push(format!(
                "Loop device {} is backed by a file on a {fstype} mount, so the hidden \
                 root depends on a userspace process that terminating the session can \
                 kill. Open the volume with cryptsetup so the kernel manages the mapping.",
                layer.name
            ));
            continue;
        }

        found.push(container_timestamp_hazard(layer, host_fstype));
        if let Some(fstype) = host_fstype.filter(|fs| COW_FILESYSTEMS.contains(fs)) {
            found.push(format!(
                "The container sits on a copy-on-write {fstype} filesystem, which writes \
                 changed container blocks to new locations and can keep old versions in \
                 free space or snapshots, so even one disk image can hold several versions \
                 of the container to compare. Prefer a whole-device hidden volume, and \
                 disable automatic snapshots of that filesystem."
            ));
        }
    }

    found
}

/// Hazards recorded in a LUKS2 header: the checks `docs/backends.md` otherwise
/// asks for by hand with `cryptsetup luksDump`.
fn luks2_hazards(layer: &Layer, meta: &Luks2Metadata) -> Vec<String> {
    let mut found = Vec::new();
    if meta.flags.iter().any(|flag| flag == "allow-discards") {
        found.push(format!(
            "The LUKS2 header of mapping {} stores the persistent allow-discards flag, so \
             every open forwards TRIM and the device shows which blocks are in use. Clear \
             it with cryptsetup refresh --persistent (without --allow-discards) and check \
             that cryptsetup luksDump shows (no flags).",
            layer.name
        ));
    }
    let hardware: Vec<&str> = meta
        .token_types
        .iter()
        .map(String::as_str)
        .filter(|kind| HARDWARE_TOKENS.contains(kind))
        .collect();
    if !hardware.is_empty() {
        found.push(format!(
            "The LUKS2 header of mapping {} carries {} token(s), which name the unlock \
             method in plain text; a systemd-tpm2 token also seals the key to this \
             machine's TPM, binding the volume to the host. Remove the token with \
             systemd-cryptenroll --wipe-slot or cryptsetup token remove --token-id if the volume \
             must not point at this machine.",
            layer.name,
            hardware.join(", ")
        ));
    }
    found
}

fn discard_hazard(crypt: &CryptType, layer: &Layer) -> String {
    let consequence = match crypt {
        CryptType::Tcrypt => {
            "TRIM through a hidden volume leaves a readable used/free map where the outer \
             volume should look like random data, and hole-punches a loop-backed \
             container; an outer volume opened with --allow-discards can destroy the \
             hidden volume. Re-open the mapping without --allow-discards, never open the \
             outer volume with it, and never run fstrim on a volume that contains a \
             hidden volume."
        }
        _ => {
            "TRIM leaves a readable used/free map on a device that should look like \
             uniform random data. Re-open the mapping without --allow-discards."
        }
    };
    format!(
        "Discards are enabled on the {} mapping {} (discard_max_bytes={}). {consequence}",
        crypt.label(),
        layer.name,
        layer.discard_max_bytes
    )
}

fn container_timestamp_hazard(layer: &Layer, host_fstype: Option<&str>) -> String {
    let host = match host_fstype {
        Some(fstype) => format!(" on a {fstype} filesystem"),
        None => String::new(),
    };
    format!(
        "The hidden root lives in a file container attached through loop device {}{host}. \
         Every read-write session updates the container's mtime and ctime, and ctime \
         cannot be restored, so the container shows when it was last used; a \
         whole-device hidden volume has no such timestamps.",
        layer.name
    )
}

#[cfg(test)]
mod tests;
