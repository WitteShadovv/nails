// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The decoy disk read-only in the kernel for the whole hidden session.
//!
//! The entry transition puts up a fence around every disk the decoy mounted
//! at entry ([`spec`], [`targets`]) before PID 1 switches root, so that a
//! program of the hidden session that writes there, one NAILS knows of or
//! not, gets an error instead of leaving a trace. A hidden session never goes
//! back to the decoy's kernel ([`crate::whole_root::session_end`]): the fence
//! stays up until the power-off ends it, and nothing here takes it down.
//!
//! The read-only flag of the block layer alone is no fence: the kernel only
//! warns about a write bio to a read-only device and lets it through
//! (`bio_check_ro`), so a mounted filesystem, device-mapper, md and swap
//! write on. The fence is five layers, each closing what the others leave
//! open ([`apply`]):
//!
//! 1. every decoy filesystem still alive at the switch is reconfigured
//!    read-only, after a `sync`: what refuses file writes (`EROFS`) and keeps
//!    the filesystem itself from writing (journal, metadata, access times);
//!    efivarfs and pstore as well;
//! 2. `BLKROSET` on every decoy disk, each partition of it and every device
//!    stacked on them (the decoy's LUKS, LVM, md), but the hidden volume's own
//!    top device: writes through a device node, read-write mounts and
//!    remounts (but a btrfs's, which skips the check), and the journal or log
//!    replay of a new mount are refused. The hidden volume's writes to a
//!    fenced device below it pass, as the kernel only warns about them;
//! 3. discard turned off on those devices (`queue/discard_max_bytes` 0): the
//!    kernel then fails every discard to them, which a read-only ext4 or
//!    btrfs would still send for `fstrim`;
//! 4. a device-cgroup program on the root cgroup ([`crate::whole_root::fence_bpf`])
//!    that denies every open of those devices and of the character devices
//!    that reach the same hardware (sg, bsg, the NVMe controllers and their
//!    generic nodes): no process can open them, so none can send SCSI or NVMe
//!    commands past the block layer;
//! 5. the kernel's crash log kept from the firmware: pstore's EFI backend
//!    writes every oops and panic of the session into an EFI variable itself,
//!    past efivarfs, and the decoy's next boot copies the record onto its
//!    disk (`systemd-pstore`). The fence turns the backend off
//!    (`efi_pstore.pstore_disable`, which unregisters it from Linux 6.12 on,
//!    else unloads the module).
//!
//! The entry refuses at activation what the fence cannot cover ([`check`]):
//! no decoy disk found, a hidden root that shares a filesystem with the decoy
//! (a folder or subvolume of a decoy filesystem, a container file on one),
//! a crash-log backend that keeps records past a power-off and cannot be
//! turned off, and a kernel that does not load the device program. A step
//! that fails at the switch ends the session there ([`FenceError`]); the
//! caller powers off with what is up of the fence, which nothing undoes.
//! Everything here is kernel state in RAM: nothing of the fence reaches a
//! disk, and a power-off ends it.
//!
//! **Not closed**, and said so in the threat model: a root user of the hidden
//! session who sets out to undo it (detach the program, clear the flag,
//! remount), a read-write remount of a decoy btrfs through a mount the
//! session sees, disks the decoy did not mount at entry, and stores that are
//! not block devices (the TPM, firmware logs, a RAM crash log across a warm
//! reboot).

use crate::mountinfo::MountEntry;
use crate::whole_root::disk_guard::{DevNum, Sysfs, block_device, mount_device, node_of};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// The directory in the runtime directory where a superblock no mount shows
/// is mounted for a moment to be reconfigured.
pub const SCRATCH_NAME: &str = "ro";
/// The major number of the SCSI generic driver (`/dev/sg*`).
pub const SG_MAJOR: u32 = 21;

/// What the entry records for the fence, before the decoy's shutdown
/// unmounts what the fstab policy masked.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FenceSpec {
    /// The decoy's disks: the whole hardware disks below every block-backed
    /// mount of its tree at entry but the hidden storage's, below its swap
    /// areas, and below the other devices its filesystems keep data on (a
    /// multi-device btrfs, an external journal or log).
    pub disks: Vec<DevNum>,
    /// The hidden volume's own top device (its device-mapper mapping, md or
    /// loop device), which keeps writing: never set read-only, never denied,
    /// nor anything stacked on it. Empty where that device is the decoy's
    /// own too.
    #[serde(default)]
    pub kept_devices: Vec<DevNum>,
    /// The superblocks (`major:minor` as the mount table shows it) that hold
    /// the hidden storage: the filesystem at the hidden root, and the one that
    /// holds the backing file of a loop device in its stack. They stay
    /// read-write.
    #[serde(default)]
    pub kept_superblocks: Vec<String>,
    /// The superblocks that hold the hidden storage and that the decoy mounts
    /// too, which the fence cannot make read-only: the entry refuses them
    /// ([`check`]).
    #[serde(default)]
    pub shared_superblocks: Vec<String>,
}

/// A block device of the fence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    /// Its number.
    pub dev: DevNum,
    /// The node it is reached through.
    pub node: PathBuf,
}

/// A superblock of the fence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Superblock {
    /// Its device number, as the mount table shows it.
    pub sb_dev: String,
    /// Its filesystem type.
    pub fstype: String,
    /// The block device it is on, `None` for efivarfs and pstore.
    pub device: Option<Device>,
    /// Whether it was read-write when the fence found it.
    pub read_write: bool,
}

/// What the device program denies.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rules {
    /// Block devices, every access.
    pub block: Vec<DevNum>,
    /// Character devices, every access.
    pub chars: Vec<DevNum>,
    /// Every SCSI generic node ([`SG_MAJOR`]): a fenced disk is a SCSI device,
    /// and its node may appear later under a minor no one can know now.
    pub sg: bool,
}

/// What the fence covers at the switch.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Targets {
    /// The superblocks to make read-only.
    pub superblocks: Vec<Superblock>,
    /// The block devices to set read-only.
    pub devices: Vec<Device>,
    /// The `discard_max_bytes` files to set to 0.
    pub queues: Vec<PathBuf>,
    /// What the device program denies.
    pub rules: Rules,
}

/// The program the fence attached.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Program {
    /// Its ID.
    pub id: u32,
    /// Its tag, in hex.
    pub tag: String,
}

/// pstore's EFI backend, by the name it registers.
pub const EFI_CRASH_LOG: &str = "efi_pstore";
/// The one backend that keeps its records in RAM, which a power-off clears.
pub const RAM_CRASH_LOG: &str = "ramoops";

/// An active swap area, as `/proc/swaps` lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Swap {
    /// A block device.
    Device(DevNum),
    /// A file, on the superblock `major:minor`.
    File(String),
}

/// The kernel operations of the fence; tests replace them.
pub trait FenceKernel: std::fmt::Debug + Send + Sync {
    /// Flush every filesystem.
    fn sync(&self);
    /// The active swap areas.
    fn swaps(&self) -> Vec<Swap>;
    /// Reconfigure `sb` read-only, through a mount of it the mount table
    /// shows, else one made below `scratch` for the moment.
    fn reconfigure(&self, sb: &Superblock, scratch: &Path) -> io::Result<()>;
    /// Whether the mount table shows `sb` read-only, `None` when it shows no
    /// mount of it.
    fn superblock_read_only(&self, sb: &Superblock) -> Option<bool>;
    /// Whether the kernel reports the device read-only.
    fn device_read_only(&self, device: &Device) -> bool;
    /// `BLKROSET` on the device.
    fn set_read_only(&self, device: &Device) -> io::Result<()>;
    /// The value of a `discard_max_bytes` file.
    fn discard_max(&self, queue: &Path) -> io::Result<u64>;
    /// Set a `discard_max_bytes` file to 0.
    fn discard_off(&self, queue: &Path) -> io::Result<()>;
    /// Load the device program for `rules` and attach it to the root cgroup.
    fn attach(&self, rules: &Rules) -> io::Result<Program>;
    /// The pstore backend registered now, `None` when there is none.
    fn crash_log_backend(&self) -> Option<String>;
    /// Whether pstore's EFI backend can be turned off now: a module, which
    /// can be unloaded, or a kernel (6.12 and newer) whose `pstore_disable`
    /// unregisters it at once.
    fn efi_crash_log_stoppable(&self) -> bool;
    /// Stop pstore's EFI backend, as far as the kernel lets it.
    fn stop_efi_crash_log(&self) -> io::Result<()>;
    /// Load the device program for `rules` and let it go again, attaching
    /// nothing: the entry's early check that the fence can be put up.
    fn probe(&self, rules: &Rules) -> io::Result<()>;
}

/// Why the fence could not be put up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FenceError {
    /// The step that failed.
    pub step: &'static str,
    /// What the kernel said.
    pub detail: String,
}

impl std::fmt::Display for FenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the decoy disk could not be made read-only ({}): {}",
            self.step, self.detail
        )
    }
}

impl std::error::Error for FenceError {}

fn fail(step: &'static str, detail: impl std::fmt::Display) -> FenceError {
    FenceError {
        step,
        detail: detail.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Which devices and superblocks

impl Sysfs {
    /// The devices stacked on this one (`holders/`).
    pub(crate) fn holders(&self, dev: DevNum) -> Vec<DevNum> {
        let Some(dir) = self.dir(dev) else {
            return Vec::new();
        };
        let mut found: Vec<DevNum> = std::fs::read_dir(dir.join("holders"))
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| Self::dev_in(&e.path()))
            .collect();
        found.sort();
        found
    }

    /// The partitions of a whole disk.
    pub(crate) fn partitions(&self, disk: DevNum) -> Vec<DevNum> {
        let Some(dir) = self.dir(disk) else {
            return Vec::new();
        };
        let mut found: Vec<DevNum> = std::fs::read_dir(&dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.path().join("partition").is_file())
            .filter_map(|e| Self::dev_in(&e.path()))
            .collect();
        found.sort();
        found
    }

    /// The kernel name of a device (`sda1`, `dm-0`).
    pub(crate) fn name(&self, dev: DevNum) -> Option<String> {
        Some(self.dir(dev)?.file_name()?.to_string_lossy().into_owned())
    }

    /// The device of a kernel name (`sda1`).
    fn by_name(&self, name: &str) -> Option<DevNum> {
        Self::dev_in(&self.root.join("class/block").join(name))
    }

    /// The file a loop device is bound to.
    fn loop_backing(&self, dev: DevNum) -> Option<PathBuf> {
        let text = std::fs::read_to_string(self.dir(dev)?.join("loop/backing_file")).ok()?;
        let path = text.trim_end_matches('\n');
        (!path.is_empty()).then(|| PathBuf::from(path))
    }

    /// Every device of the btrfs that `dev` is one device of
    /// (`/sys/fs/btrfs/<fsid>/devices`), `dev` included; just `dev` for any
    /// other device.
    fn btrfs_devices(&self, dev: DevNum) -> Vec<DevNum> {
        let Some(name) = self.name(dev) else {
            return vec![dev];
        };
        for fs in std::fs::read_dir(self.root.join("fs/btrfs"))
            .into_iter()
            .flatten()
            .flatten()
        {
            let devices = fs.path().join("devices");
            if !devices.join(&name).exists() {
                continue;
            }
            let mut found: Vec<DevNum> = std::fs::read_dir(&devices)
                .into_iter()
                .flatten()
                .flatten()
                .filter_map(|e| self.by_name(&e.file_name().to_string_lossy()))
                .collect();
            found.sort();
            found.dedup();
            if !found.is_empty() {
                return found;
            }
        }
        vec![dev]
    }

    /// The `discard_max_bytes` file of a device that has a queue of its own
    /// (a whole disk, device-mapper, md); `None` for a partition.
    fn discard_queue(&self, dev: DevNum) -> Option<PathBuf> {
        let file = self.dir(dev)?.join("queue/discard_max_bytes");
        file.is_file().then_some(file)
    }

    /// The character devices below the hardware a disk sits on (sg, bsg, an
    /// NVMe controller and its generic nodes), and whether the disk is a SCSI
    /// device. For an NVMe multipath head, whose `device` is its virtual
    /// subsystem, the controllers come from the paths it lists under
    /// `multipath/`. The walk follows no link and goes at most three levels
    /// down.
    fn hardware_nodes(&self, disk: DevNum) -> (Vec<DevNum>, bool) {
        let Some(dir) = self.dir(disk) else {
            return (Vec::new(), false);
        };
        let mut starts: Vec<PathBuf> = std::fs::canonicalize(dir.join("device"))
            .into_iter()
            .collect();
        for path in std::fs::read_dir(dir.join("multipath"))
            .into_iter()
            .flatten()
            .flatten()
        {
            starts.extend(std::fs::canonicalize(path.path().join("device")));
        }
        let scsi = starts.iter().any(|s| s.join("scsi_device").is_dir());
        let mut found = Vec::new();
        let mut stack: Vec<(PathBuf, usize)> = starts.into_iter().map(|s| (s, 0)).collect();
        while let Some((dir, depth)) = stack.pop() {
            let is_block = std::fs::read_link(dir.join("subsystem"))
                .ok()
                .and_then(|l| l.file_name().map(|n| n == "block"))
                .unwrap_or(false);
            if !is_block && let Some(dev) = Self::dev_in(&dir) {
                found.push(dev);
            }
            if depth == 3 {
                continue;
            }
            for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
                if entry.file_type().is_ok_and(|t| t.is_dir()) {
                    stack.push((entry.path(), depth + 1));
                }
            }
        }
        found.sort();
        found.dedup();
        (found, scsi)
    }

    /// Whether hardware sits below the device, as [`Sysfs::is_hardware`]
    /// tells, or it is an NVMe multipath head with paths.
    fn is_disk_hardware(&self, dev: DevNum) -> bool {
        self.is_hardware(dev) || self.dir(dev).is_some_and(|d| d.join("multipath").is_dir())
    }
}

/// The whole hardware disks a device is on: itself for a disk, the disk of a
/// partition, and those below every device it is stacked on.
fn disks_below(sys: &Sysfs, dev: DevNum) -> BTreeSet<DevNum> {
    let mut disks = BTreeSet::new();
    let mut seen = BTreeSet::new();
    let mut todo = vec![dev];
    while let Some(dev) = todo.pop() {
        if !seen.insert(dev) {
            continue;
        }
        let slaves = sys.slaves(dev);
        if !slaves.is_empty() {
            todo.extend(slaves);
        } else if let Some(disk) = sys.parent(dev) {
            disks.insert(disk);
        } else if sys.is_disk_hardware(dev) {
            disks.insert(dev);
        }
    }
    disks
}

/// The devices other than its source a filesystem keeps data on, named in its
/// options: an XFS log or realtime device, an ext4 journal by path, a btrfs
/// `device=`.
fn option_devices(mount: &MountEntry) -> Vec<DevNum> {
    mount
        .super_opts
        .split(',')
        .chain(mount.mount_opts.split(','))
        .filter_map(|opt| {
            let (key, value) = opt.split_once('=')?;
            ["logdev", "rtdev", "journal_path", "device"]
                .contains(&key)
                .then(|| block_device(Path::new(value)))?
        })
        .collect()
}

/// The fence's record of the decoy at entry. `mounts` is the decoy's mount
/// table, `swaps` the active swap areas, `root` the decoy root (`/`) and
/// `hidden_root` the hidden volume's root; only mounts at or below `root`
/// count, and the disks below a swap area on a device count as the decoy's
/// too.
pub fn spec(
    mounts: &[MountEntry],
    swaps: &[Swap],
    root: &Path,
    hidden_root: &Path,
    sys: &Sysfs,
) -> FenceSpec {
    let canonical = std::fs::canonicalize(hidden_root).unwrap_or_else(|_| hidden_root.into());
    // The mount a lookup of the hidden root ends on: its own, or for a root
    // that is a folder, the mount of the filesystem it is a folder of.
    let hidden = canonical
        .ancestors()
        .find_map(|at| crate::mountinfo::top_mount_at(mounts, at));
    let decoy_mounts: Vec<&MountEntry> = mounts
        .iter()
        .filter(|m| {
            let point = &m.mount_point;
            point.starts_with(root)
                && !point.starts_with(&canonical)
                && !point.starts_with(hidden_root)
        })
        .collect();
    let mut kept_devices = BTreeSet::new();
    let mut kept_superblocks = BTreeSet::new();
    if let Some(mount) = hidden {
        kept_superblocks.insert(mount.dev.clone());
        if let Some(top) = mount_device(mount) {
            // The hidden volume's own top device stays writable, unless the
            // decoy mounts it too (a folder of a decoy filesystem).
            let decoy_uses = decoy_mounts.iter().any(|m| mount_device(m) == Some(top));
            if !sys.is_hardware(top) && !decoy_uses {
                kept_devices.insert(top);
            }
            // A container file: the filesystem it lies on holds the storage.
            let mut todo = vec![top];
            let mut seen = BTreeSet::new();
            while let Some(dev) = todo.pop() {
                if !seen.insert(dev) || sys.is_hardware(dev) {
                    continue;
                }
                if let Some(file) = sys.loop_backing(dev)
                    && let Ok(meta) = std::fs::metadata(&file)
                {
                    kept_superblocks.insert(DevNum::from_raw(meta.dev()).text());
                }
                todo.extend(sys.slaves(dev));
            }
        }
    }
    let mut disks = BTreeSet::new();
    for mount in &decoy_mounts {
        let mut devices: Vec<DevNum> = mount_device(mount).into_iter().collect();
        if mount.fstype == "btrfs" {
            // A btrfs mount shows an anonymous device number; its source names
            // one member, which sysfs also knows by its kernel name.
            let named = mount
                .source
                .file_name()
                .and_then(|name| sys.by_name(&name.to_string_lossy()));
            if let Some(dev) = devices.first().copied().or(named) {
                devices = sys.btrfs_devices(dev);
            }
        }
        devices.extend(option_devices(mount));
        for dev in devices {
            if !kept_devices.contains(&dev) {
                disks.extend(disks_below(sys, dev));
            }
        }
    }
    for swap in swaps {
        if let Swap::Device(dev) = swap
            && !kept_devices.contains(dev)
        {
            disks.extend(disks_below(sys, *dev));
        }
    }
    let shared_superblocks = decoy_mounts
        .iter()
        .filter(|m| kept_superblocks.contains(&m.dev) && mount_device(m).is_some())
        .map(|m| m.dev.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    FenceSpec {
        disks: disks.into_iter().collect(),
        kept_devices: kept_devices.into_iter().collect(),
        kept_superblocks: kept_superblocks.into_iter().collect(),
        shared_superblocks,
    }
}

/// The superblocks that are no block device but keep firmware state: EFI
/// variables, and the kernel's crash records (whose removal by
/// `systemd-pstore` erases them from the firmware).
const FIRMWARE_FILESYSTEMS: [&str; 2] = ["efivarfs", "pstore"];

/// The character devices that reach the firmware past efivarfs, which the
/// device program denies where they exist.
const FIRMWARE_NODES: [&str; 2] = ["efi_test", "efi_capsule_loader"];

/// What the fence covers now, from the entry's record, the live mount table
/// and sysfs.
pub fn targets(spec: &FenceSpec, mounts: &[MountEntry], sys: &Sysfs) -> Targets {
    let kept: BTreeSet<DevNum> = spec.kept_devices.iter().copied().collect();
    let mut fenced = BTreeSet::new();
    let mut todo: Vec<DevNum> = Vec::new();
    for &disk in &spec.disks {
        todo.push(disk);
        todo.extend(sys.partitions(disk));
    }
    while let Some(dev) = todo.pop() {
        if kept.contains(&dev) || !fenced.insert(dev) {
            continue;
        }
        todo.extend(sys.holders(dev));
    }
    let devices: Vec<Device> = fenced
        .iter()
        .filter_map(|&dev| {
            let node = node_of(sys, &sys.name(dev)?);
            Some(Device { dev, node })
        })
        .collect();
    let queues = fenced
        .iter()
        .filter_map(|&dev| sys.discard_queue(dev))
        .collect();
    let mut superblocks: Vec<Superblock> = Vec::new();
    for mount in mounts {
        if superblocks.iter().any(|sb| sb.sb_dev == mount.dev)
            || spec.kept_superblocks.contains(&mount.dev)
        {
            continue;
        }
        let read_write = mount.super_opts.split(',').next() == Some("rw");
        let device = if FIRMWARE_FILESYSTEMS.contains(&mount.fstype.as_str()) {
            None
        } else {
            match mount_device(mount) {
                Some(dev) if fenced.contains(&dev) => Some(
                    devices
                        .iter()
                        .find(|d| d.dev == dev)
                        .cloned()
                        .unwrap_or(Device {
                            dev,
                            node: mount.source.clone(),
                        }),
                ),
                _ => continue,
            }
        };
        superblocks.push(Superblock {
            sb_dev: mount.dev.clone(),
            fstype: mount.fstype.clone(),
            device,
            read_write,
        });
    }
    let mut chars = BTreeSet::new();
    let mut sg = false;
    for &disk in &spec.disks {
        let (nodes, scsi) = sys.hardware_nodes(disk);
        chars.extend(nodes);
        sg |= scsi;
    }
    // The firmware's own doors past efivarfs: EFI runtime calls, a
    // SetVariable among them (`efi_test`), and capsule updates.
    for misc in FIRMWARE_NODES {
        chars.extend(Sysfs::dev_in(&sys.root.join("class/misc").join(misc)));
    }
    Targets {
        superblocks,
        rules: Rules {
            block: fenced.into_iter().collect(),
            chars: chars.into_iter().collect(),
            sg,
        },
        devices,
        queues,
    }
}

// ---------------------------------------------------------------------------
// Putting it up

/// The swap area that writes past the fence, if one is active: on a fenced
/// device, or a file on a fenced superblock.
fn swap_past(targets: &Targets, swaps: &[Swap]) -> Option<String> {
    swaps.iter().find_map(|swap| match swap {
        Swap::Device(dev) if targets.rules.block.contains(dev) => {
            Some(format!("swap is on {}", dev.text()))
        }
        Swap::File(sb) if targets.superblocks.iter().any(|s| &s.sb_dev == sb) => {
            Some(format!("a swap file is on the filesystem {sb}"))
        }
        _ => None,
    })
}

/// Why a crash-log backend keeps the fence from going up, if it does: one
/// that keeps its records past a power-off and cannot be turned off.
fn crash_log_refusal(kernel: &dyn FenceKernel) -> Option<String> {
    match kernel.crash_log_backend() {
        None => None,
        Some(ram) if ram == RAM_CRASH_LOG => None,
        Some(efi) if efi == EFI_CRASH_LOG && kernel.efi_crash_log_stoppable() => None,
        Some(other) => Some(format!(
            "the kernel keeps its crash records in {other}, which survives a power-off and \
             cannot be turned off for the session"
        )),
    }
}

/// Put the fence up. On failure the error says which step failed. Nothing is
/// undone: the caller ends the session with what is up of the fence.
pub fn apply(
    targets: &Targets,
    kernel: &dyn FenceKernel,
    scratch: &Path,
) -> Result<(), FenceError> {
    kernel.sync();
    if let Some(why) = swap_past(targets, &kernel.swaps()) {
        return Err(fail("swap", why));
    }
    for sb in targets.superblocks.iter().filter(|sb| sb.read_write) {
        kernel.reconfigure(sb, scratch).map_err(|e| {
            let why = if e.kind() == io::ErrorKind::ResourceBusy {
                ": a program still holds a file of it open for writing, or a deleted file \
                 open, as one does after a package update until the next boot; reboot the \
                 decoy and activate again"
            } else {
                ""
            };
            fail(
                "read-only filesystem",
                format!("{} ({}): {e}{why}", sb.sb_dev, sb.fstype),
            )
        })?;
        // At the switch every fenced superblock has a mount the table shows;
        // where none does, the reconfigure's own answer stands.
        if kernel.superblock_read_only(sb) == Some(false) {
            return Err(fail(
                "read-only filesystem",
                format!("{} ({}) still reads read-write", sb.sb_dev, sb.fstype),
            ));
        }
    }
    if let Some(why) = crash_log_refusal(kernel) {
        return Err(fail("crash log", why));
    }
    if kernel.crash_log_backend().as_deref() == Some(EFI_CRASH_LOG) {
        kernel
            .stop_efi_crash_log()
            .map_err(|e| fail("crash log", e))?;
        if let Some(left) = kernel.crash_log_backend().filter(|b| b != RAM_CRASH_LOG) {
            return Err(fail(
                "crash log",
                format!("the kernel still keeps its crash records in {left}"),
            ));
        }
    }
    for device in &targets.devices {
        if kernel.device_read_only(device) {
            continue;
        }
        kernel.set_read_only(device).map_err(|e| {
            fail(
                "read-only device",
                format!("{}: {e}", device.node.display()),
            )
        })?;
    }
    for queue in &targets.queues {
        let bytes = kernel
            .discard_max(queue)
            .map_err(|e| fail("discard", format!("{}: {e}", queue.display())))?;
        if bytes != 0 {
            kernel
                .discard_off(queue)
                .map_err(|e| fail("discard", format!("{}: {e}", queue.display())))?;
        }
    }
    kernel
        .attach(&targets.rules)
        .map_err(|e| fail("device access", e))?;
    Ok(())
}

/// Put the fence up at the switch from the entry's record. `runtime_dir`
/// holds the scratch directory.
pub fn put_up(
    spec: &FenceSpec,
    mounts: &[MountEntry],
    sys: &Sysfs,
    kernel: &dyn FenceKernel,
    runtime_dir: &Path,
) -> Result<(), FenceError> {
    if spec.disks.is_empty() {
        return Err(fail(
            "decoy disks",
            "the entry found no disk the decoy mounts",
        ));
    }
    if !spec.shared_superblocks.is_empty() {
        return Err(fail(
            "hidden storage",
            "the hidden root shares a filesystem with the decoy",
        ));
    }
    let targets = targets(spec, mounts, sys);
    apply(&targets, kernel, &runtime_dir.join(SCRATCH_NAME))
}

/// The entry's check, at activation, that the fence can go up at the switch:
/// a decoy disk was found, the hidden root shares no filesystem with the
/// decoy, no crash-log backend keeps records past a power-off that cannot be
/// turned off, and the kernel loads the device program for the devices it
/// would deny (a cgroup2 hierarchy, `CONFIG_CGROUP_BPF`, no policy that
/// denies it). What only the switch can find (a filesystem still busy) the
/// transition refuses there.
pub fn check(
    spec: FenceSpec,
    mounts: &[MountEntry],
    sys: &Sysfs,
    kernel: &dyn FenceKernel,
) -> Result<FenceSpec, String> {
    if spec.disks.is_empty() {
        return Err(
            "no disk the decoy mounts was found, so the decoy disk cannot be made \
             read-only for the session"
                .to_string(),
        );
    }
    if !spec.shared_superblocks.is_empty() {
        return Err(format!(
            "the hidden root shares a filesystem with the decoy ({}): a folder or subvolume \
             of a decoy filesystem, or a container file on one, which the session would \
             have to keep writable on the decoy disk; put the hidden root on storage of its \
             own",
            spec.shared_superblocks.join(", ")
        ));
    }
    if let Some(why) = crash_log_refusal(kernel) {
        return Err(format!(
            "the decoy disk cannot be made read-only for the session: {why}"
        ));
    }
    kernel
        .probe(&targets(&spec, mounts, sys).rules)
        .map_err(|e| {
            format!(
                "the decoy disk cannot be made read-only for the session: the kernel does not \
                 load the device program that keeps its devices closed ({e})"
            )
        })?;
    Ok(spec)
}

#[cfg(test)]
#[path = "fence_tests.rs"]
mod tests;
