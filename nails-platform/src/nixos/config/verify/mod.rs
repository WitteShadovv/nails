// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The decoy's own NixOS configuration, checked for traces of the hidden
//! environment.
//!
//! Every `*.nix` file under `/etc/nixos` (the flake, `configuration.nix`,
//! `hardware-configuration.nix` and any module they import) belongs to the
//! decoy, so an examination reads it. [`verify_base_config_clean`] reports
//! each line that names the hidden volume (its device, its mount point, the
//! units systemd names after them, its mapping where a line opens it, or the
//! storage it lives on, by its device paths, its kernel names, every link
//! udev made for it, its uuids and its labels) or NAILS, with the file, the
//! line, the matched text and why it counts. Only `.nix` files are read:
//! other files in `/etc/nixos` and the history of a git repository there are
//! not.

mod nix_text;
mod scan;
mod storage;

use crate::artifacts::{ARTIFACTS, ArtifactKind};
use crate::error::Result;
use crate::filesystem::Filesystem;
use nails_base::filesystem::parse_mountinfo;
use nails_base::fstab::escape_path;
use nails_base::hidden_root::separation::{OwnFilesystem, counts_as_system_folder};
use nix_text::{Context, Pattern, Shell};
use scan::{Place, Scanner};
use std::path::{Path, PathBuf};

/// Base `/etc/nixos` directory scanned for hidden-environment traces.
const BASE_NIXOS_DIR: &str = "/etc/nixos";

/// Kernel mount table exposing the backing source of each mount point.
const SELF_MOUNTINFO: &str = "/proc/self/mountinfo";

/// What `--allow-decoy-storage` lets be of the names of a device, for the
/// fix of a line that names one.
macro_rules! own_device_names {
    () => {
        " With --allow-decoy-storage, for a hidden root that is a folder or a btrfs subvolume \
         of a filesystem the decoy itself mounts at / or at a system folder, a name of a device \
         that filesystem lies on passes as the device or label of a fileSystems entry for / or \
         a system folder, or as the name or device of a boot.initrd.luks.devices entry. It \
         fails anywhere else, and so do the root's mount point, its folder and subvolume, and \
         the names of any other device."
    };
}

/// What a line of the decoy's configuration names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferenceKind {
    /// Text NAILS writes into a file during a session, such as the import of
    /// the hidden module (from the artifact registry).
    StagedText,
    /// The device the hidden volume is mounted from (`/dev/mapper/<name>`, or
    /// `/dev/disk/by-id/dm-name-<name>`).
    Device,
    /// The unit systemd names after that device (`dev-mapper-data.device`).
    DeviceUnit,
    /// What the hidden volume is stored on, as the system names it below its
    /// mount: the partition or disk (`/dev/sdb2`) and the image file behind a
    /// loop device; the kernel's name of each of them and of the hidden
    /// volume's own device, alone (`KERNEL=="sdb2"`) or as a device node
    /// (`/dev/dm-0`), and its `/dev/block/<major>:<minor>` link; every link
    /// udev made for one of them or for the hidden volume's own device
    /// (`/dev/disk/by-id/…`, `by-path`, `by-partlabel`, `by-uuid`,
    /// `by-label`, the LVM path `/dev/<vg>/<lv>`); their uuids (the
    /// partition's, the LUKS header's, the filesystem's: `UUID=<uuid>`); and
    /// their labels as tags (`LABEL=`, `PARTLABEL=`, a `fileSystems` entry's
    /// `label`).
    Storage,
    /// The hidden volume's mount point.
    MountPoint,
    /// The unit systemd names after the mount point (`mnt-data.mount`,
    /// `mnt-data.automount`).
    MountUnit,
    /// For a root that `--allow-decoy-storage` accepted as a folder or a
    /// btrfs subvolume of a filesystem the decoy uses: that folder as another
    /// mount of the filesystem shows it (`/srv/x` for a bind of a folder of
    /// `/`), the folder's or subvolume's own name as a part of any path, a
    /// whole string or an attribute name (`@vault`, `vault`), the
    /// subvolume's id as `subvolid=` gives it in any base, and a `subvol=`
    /// or `subvolid=` value that cannot be read.
    RootPlace,
    /// The hidden volume's device-mapper name where it names the mapping: a
    /// `luks.devices` entry, crypttab text or a `cryptsetup` line.
    MapperName,
    /// The word `nails`.
    ToolName,
}

impl ReferenceKind {
    /// What the matched text is, in the words of a check result.
    pub fn reason(self) -> &'static str {
        match self {
            ReferenceKind::StagedText => "text NAILS writes during a session",
            ReferenceKind::Device => "the hidden volume's device",
            ReferenceKind::DeviceUnit => "the unit systemd names after the hidden volume's device",
            ReferenceKind::Storage => {
                "a name of the device or file the hidden volume is stored on (a device node, a \
                 kernel name, a link, a uuid or a label)"
            }
            ReferenceKind::MountPoint => "the hidden volume's mount point",
            ReferenceKind::MountUnit => {
                "the unit systemd names after the hidden volume's mount point"
            }
            ReferenceKind::RootPlace => {
                "the folder or btrfs subvolume of the decoy's filesystem that the hidden volume is"
            }
            ReferenceKind::MapperName => "the hidden volume's device-mapper name",
            ReferenceKind::ToolName => "the name of this tool",
        }
    }

    /// What the operator does about it. For a name of a device, it says
    /// what `--allow-decoy-storage` lets be and what it does not.
    pub fn remedy(self) -> &'static str {
        match self {
            ReferenceKind::MapperName => concat!(
                "Remove it from that file long before the next use and rebuild the decoy. If \
                 the name is there for another reason, open the hidden volume under a name \
                 that appears nowhere in /etc/nixos instead.",
                own_device_names!()
            ),
            ReferenceKind::MountPoint | ReferenceKind::MountUnit => {
                "Remove it from that file long before the next use and rebuild the decoy. If \
                 the decoy uses that path for something else, mount the hidden volume at a \
                 path that appears nowhere in /etc/nixos instead."
            }
            ReferenceKind::RootPlace => {
                "Remove it from that file long before the next use and rebuild the decoy. If \
                 the decoy uses that folder or subvolume for something else, or the name only \
                 happens to be the same, keep the hidden root in a folder or subvolume whose \
                 name appears in no path, string or attribute name in /etc/nixos instead. \
                 Write a subvol= or subvolid= value out in full. --allow-decoy-storage never \
                 lets it be."
            }
            ReferenceKind::Storage => concat!(
                "Remove it from that file long before the next use and rebuild the decoy. If \
                 it is a label the decoy's own device carries too, give the hidden volume \
                 another label instead. If it is a kernel name such as /dev/dm-1 that the \
                 decoy's own device holds at other times, name that device by its uuid \
                 instead.",
                own_device_names!()
            ),
            ReferenceKind::Device | ReferenceKind::DeviceUnit => concat!(
                "Remove it from that file long before the next use and rebuild the decoy.",
                own_device_names!()
            ),
            ReferenceKind::StagedText | ReferenceKind::ToolName => {
                "Remove it from that file long before the next use and rebuild the decoy."
            }
        }
    }
}

/// One line of the decoy's configuration that names the hidden environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseConfigReference {
    /// The file.
    pub file: PathBuf,
    /// The line, counted from 1.
    pub line: usize,
    /// The matched text as the file spells it.
    pub text: String,
    /// What the text names.
    pub kind: ReferenceKind,
}

/// What the scan of the decoy's `/etc/nixos` found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BaseConfigScan {
    /// How many `*.nix` files were read; none means nothing was inspected.
    pub files_read: usize,
    /// Every line that names the hidden environment, by file and then line.
    pub references: Vec<BaseConfigReference>,
    /// Every other line that names a device of the filesystem that
    /// `--allow-decoy-storage` accepted the hidden root on as a folder or a
    /// subvolume of it, which the decoy mounts itself
    /// ([`verify_base_config_clean_allowing`]), by file and then line: the
    /// decoy's own names for its own filesystem, let be.
    pub let_be: Vec<BaseConfigReference>,
    /// The places that may give a name of the hidden volume's storage that
    /// are there but could not be read: a line that names the storage by
    /// one of those names would not be found.
    pub unread: Vec<String>,
}

impl BaseConfigScan {
    /// Whether no line names the hidden environment.
    pub fn is_clean(&self) -> bool {
        self.references.is_empty()
    }
}

/// One thing to look for, and what a match names.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Marker {
    pattern: Pattern,
    kind: ReferenceKind,
}

/// Scans the decoy's `/etc/nixos` for traces of the hidden environment.
///
/// Every `*.nix` file under `/etc/nixos` is read, and each line is matched
/// against these markers, in this order (a line counts once, for the first
/// marker it matches). Every marker counts in comments as well, since an
/// examiner reads them:
///
/// - text NAILS writes during a session (the artifact registry's content
///   markers);
/// - the device `/proc/self/mountinfo` reports for `hidden_volume_root`
///   (`/dev/mapper/<name>`), the device of every device-mapper layer below it
///   (the LUKS mapping under a logical volume), `/dev/disk/by-id/dm-name-<name>`
///   and cryptsetup's `/dev/disk/by-id/dm-uuid-CRYPT-<TYPE>-[<uuid>-]<name>`,
///   each as a whole path, and the units systemd names after them
///   (`dev-mapper-data.device`);
/// - what the volume is stored on, read from the system below its mount as
///   long as nothing else is built on it ([`storage`]): the partition or
///   disk, the image file behind a loop device, the device node of each of
///   these layers and of the volume's own device (`/dev/sdb2`, `/dev/dm-0`)
///   and its `/dev/block/<major>:<minor>` link, every link udev made for
///   them or for the volume's own device (`/dev/disk/by-id/…`, `by-path`,
///   `by-partlabel`, `by-uuid`, `by-label`, `/dev/<vg>/<lv>`), their uuids
///   (partition, LUKS, filesystem) and their labels as tags (`LABEL=`,
///   `PARTLABEL=`, a `fileSystems` or `swapDevices` entry's `label`);
/// - `hidden_volume_root` itself, as a whole path (`/mnt/data` and
///   `/mnt/data/nixos` count, `/mnt/data2` does not), and its `.mount` and
///   `.automount` units (`mnt-data.mount`);
/// - the device-mapper names where they name the mapping: a `luks.devices` or
///   `clevis.devices` entry in nested blocks too (`luks.devices.data`,
///   `luks.devices."data"`, `luks = { devices.data = … }`, `inherit data;` in
///   a `luks.devices` block, inside `with`, `let … in`, `lib.mkForce` or
///   `lib.mkMerge`), also in a block commented out line by line whose lines
///   are indented at least as deep as its first, the `name` of such an entry
///   or of one in the old list form, `encrypted.label`, a word after
///   `cryptsetup` or `systemd-cryptsetup` and a verb that opens, closes or
///   asks about a mapping (`open`, `create`, `close`, `status`, …) up to the
///   end of the command, continued lines, comments and prose included, the
///   instance of `systemd-cryptsetup@data.service`, or the first field of a
///   crypttab line at the start of a line or a string (`data UUID=… none
///   luks`, `data /var/lib/vault.img none luks`);
/// - the kernel's name of each layer of that storage as a whole word, as a
///   udev rule writes it (`KERNEL=="sdb2"`; `sdb20` does not count), after
///   the markers above, so a line that names the storage by a path reports
///   the path;
/// - the word `nails`.
///
/// A path counts however many slashes separate its parts (`/mnt//data`,
/// `/dev/mapper//data`); `/srv//mnt/data` is `/srv/mnt/data` and does not
/// count. A path counts behind the prefixes systemd allows before one where
/// they start a value (`EnvironmentFile=-/mnt/data/app.env`), but not inside
/// another path (`/srv/-/mnt/data`). A unit name with a character systemd
/// escapes (`mnt-my\x2ddata.mount`) counts in both spellings: with one
/// backslash, as a comment or an indented `''…''` string holds it, and with
/// two, as a double-quoted string writes it. Matching ignores ASCII case.
/// Ordinary configuration passes: the mapping name as an ordinary word
/// (`description = "Back up user data"` with the mapping `data`,
/// `cryptsetup` beside it in a package list, or in prose that puts none of
/// those verbs between `cryptsetup` and the name, such as
/// `# cryptsetup keeps the data safe`) or a directory
/// (`/var/lib/postgresql/data`), the decoy's own mapping whose name ends like
/// the hidden one (`user-data`), another device's kernel name (`sdb20` beside
/// `sdb2`, `/dev/dm-1` beside `/dev/dm-0`), the word `hidden` (GRUB's
/// `timeoutStyle = "hidden"`), or an option such as `services.plausible`.
///
/// The scan reads text and evaluates no Nix. A mapping defined through a
/// `let` binding, `lib.listToAttrs` or an interpolated name
/// (`luks.devices.${"data"}`) is not followed; its device still counts when
/// it is written as above. A path written with a `.` or `..` component or
/// relative to the file (`/mnt/./data`, `../../mnt/data`) is not matched,
/// and neither are the units systemd names after the storage's devices
/// (`dev-sdb2.device`) nor the storage's `<major>:<minor>` outside
/// `/dev/block/` (`8:18` in a device-mapper table). A kernel name counts as
/// the kernel gives it while the scan runs: `/dev/dm-1` is refused while the
/// hidden volume's mapping holds that number, also where the decoy means a
/// device of its own that holds it at other times.
///
/// This is a best-effort trace scan, not a proof: a clean result means none of
/// the known markers were found, which is weaker than the base being
/// byte-for-byte identical to a stock install. Only `.nix` files are read.
///
/// # Errors
///
/// A `.nix` file that cannot be read.
///
/// # Example
///
/// ```no_run
/// use std::path::Path;
/// use nails_base::RealFilesystem;
/// use nails_platform::nixos::verify_base_config_clean;
///
/// let scan = verify_base_config_clean(&RealFilesystem, Path::new("/mnt/data"))?;
/// for found in &scan.references {
///     eprintln!("{}:{}: '{}' ({})", found.file.display(), found.line, found.text, found.kind.reason());
/// }
/// # Ok::<(), nails_base::NailsError>(())
/// ```
pub fn verify_base_config_clean<F: Filesystem>(
    fs: &F,
    hidden_volume_root: &Path,
) -> Result<BaseConfigScan> {
    verify_base_config_clean_allowing(fs, hidden_volume_root, None)
}

/// [`verify_base_config_clean`], where `own` is the filesystem that
/// `--allow-decoy-storage` accepted the hidden root on as a folder or a btrfs
/// subvolume of it, while the decoy itself mounts another part of it at `/`
/// or at a system folder ([`HiddenRoot::own_filesystem`]).
///
/// The names of the devices that filesystem lies on are then the decoy's own
/// where the decoy's configuration names its own mounts with them, as its
/// `hardware-configuration.nix` writes them for `/` and `/home`. A name of
/// such a device, by any of the forms above (its device node, its kernel
/// name, a `/dev/disk/by-*` link, its uuid, `PARTUUID`, label or partition
/// label, its device-mapper name), is let be where it stands in a string
/// that is the `device` or `label` of a `fileSystems` entry for `/` or a
/// system folder (as `backend-entries` counts them, the folders below `/var`
/// and `/.snapshots` among them), in the name of a
/// `boot.initrd.luks.devices` entry, or in a string that is the `device` of
/// one ([`BaseConfigScan::let_be`]). Anywhere else it counts, as before: in a
/// `fileSystems` entry for another folder, in a `let` binding, in a comment
/// outside such an entry, in a service's settings. A layer of the storage
/// counts as one of those devices only where sysfs gives it now the same
/// kernel name and the same device number as `own` holds, which the attach
/// gate's judge read; every other layer's names count as before, and so does
/// every place that could not be read.
///
/// The root's own place counts as well ([`ReferenceKind::RootPlace`]),
/// beside its mount point: its folder as the other mounts of the filesystem
/// show it (`/srv/x`), the last part of its path inside the filesystem
/// (`@vault`, `vault`) wherever it stands as a whole part of a path, as a
/// whole string or as an attribute name the file defines, and on btrfs a
/// `subvolid=` that names its id in any base the kernel reads, or a
/// `subvol=` or `subvolid=` value the scan cannot read.
///
/// # Errors
///
/// As [`verify_base_config_clean`].
///
/// [`HiddenRoot::own_filesystem`]: nails_base::hidden_root::HiddenRoot::own_filesystem
pub fn verify_base_config_clean_allowing<F: Filesystem>(
    fs: &F,
    hidden_volume_root: &Path,
    own: Option<&OwnFilesystem>,
) -> Result<BaseConfigScan> {
    let mut files = fs.find_files_with_pattern(Path::new(BASE_NIXOS_DIR), ".nix")?;
    files.sort();

    let mut scan = BaseConfigScan::default();
    if files.is_empty() {
        tracing::debug!("no .nix file under {BASE_NIXOS_DIR}; nothing to inspect");
        return Ok(scan);
    }

    let markers = markers(fs, hidden_volume_root, own, &mut scan.unread)?;
    for file in &files {
        // Nix reads a source file as bytes, so one with a byte that is no
        // UTF-8 (a comment in Latin-1, say) still evaluates. The markers are
        // UTF-8 text, and labels and dm names need not be ASCII, but
        // `from_utf8_lossy` replaces only the bytes that are no UTF-8 and
        // keeps every valid sequence, so every marker the file holds.
        let content = String::from_utf8_lossy(&fs.read_file_bytes(file)?).into_owned();
        scan.files_read += 1;
        let (references, let_be) = references_in(file, &content, &markers);
        scan.references.extend(references);
        scan.let_be.extend(let_be);
    }
    tracing::debug!(
        files = scan.files_read,
        references = scan.references.len(),
        let_be = scan.let_be.len(),
        "scanned the decoy's /etc/nixos"
    );
    Ok(scan)
}

/// What a line is matched against: the markers that count, in order, and
/// the names of the devices of the filesystem that `--allow-decoy-storage`
/// accepted the root on, which are let be in the decoy's own places for
/// them ([`decoys_own_place`]) and count elsewhere.
#[derive(Debug, Default)]
struct Markers {
    counted: Vec<Marker>,
    let_be: Vec<Marker>,
    /// The hidden root's mount point, which the system folders are told
    /// apart from, where names are let be.
    root: PathBuf,
}

/// The markers for `hidden_volume_root`, in the order a line is matched,
/// and with `own` the names it lets be. The places of the storage's names
/// that could not be read land in `unread`.
///
/// # Errors
///
/// The mount table is there but cannot be read: without it the device
/// names of the hidden volume are not known, and a line that names them
/// would pass. Where it is not there, as on a test's tree, no mount shows a
/// device.
fn markers<F: Filesystem>(
    fs: &F,
    hidden_volume_root: &Path,
    own: Option<&OwnFilesystem>,
    unread: &mut Vec<String>,
) -> Result<Markers> {
    let marker = |pattern, kind| Marker { pattern, kind };
    let mut markers: Vec<Marker> = ARTIFACTS
        .iter()
        .filter(|artifact| artifact.kind == ArtifactKind::ContentMarker)
        .map(|artifact| {
            marker(
                Pattern::Text(artifact.value.to_ascii_lowercase()),
                ReferenceKind::StagedText,
            )
        })
        .collect();

    // Only an absolute device path is a device marker: a pseudo source such as
    // `tmpfs` names no device.
    let mountinfo = match fs.read_file_content(Path::new(SELF_MOUNTINFO)) {
        Ok(mountinfo) => mountinfo,
        Err(error) if error.nothing_there() => String::new(),
        Err(error) => return Err(error),
    };
    let sources = resolve_backing_sources(&mountinfo, hidden_volume_root);
    let own_devices = own.map_or(&[][..], |own| own.devices.as_slice());
    let (below, own_below) = storage::below_letting_be(
        fs,
        &parse_mountinfo(&mountinfo),
        hidden_volume_root,
        own_devices,
    );
    unread.extend(below.unread.iter().cloned());
    // A source is a name of a device the root's filesystem lies on where the
    // names of that device hold it.
    let (own_sources, sources): (Vec<String>, Vec<String>) = sources
        .into_iter()
        .partition(|source| names_own(source, &own_below));
    let counted = DeviceMarkers::of(&sources, &below);
    let let_be = DeviceMarkers::of(&own_sources, &own_below);
    markers.extend(counted.paths);

    // Normalised, so a configured `/mnt/data/` still matches `/mnt/data`; a
    // degenerate root (`/`) would match every path.
    let root: PathBuf = hidden_volume_root.components().collect();
    let root = root.to_string_lossy().to_ascii_lowercase();
    if root.len() > 1 {
        markers.push(marker(
            Pattern::Path(root.clone()),
            ReferenceKind::MountPoint,
        ));
        for suffix in ["mount", "automount"] {
            for spelling in spellings(&unit(&root, suffix)) {
                markers.push(marker(Pattern::Path(spelling), ReferenceKind::MountUnit));
            }
        }
    }
    if let Some(own) = own {
        markers.extend(root_place(own).into_iter().map(|pattern| Marker {
            pattern,
            kind: ReferenceKind::RootPlace,
        }));
    }

    markers.extend(counted.words);
    markers.push(marker(
        Pattern::Word("nails".into()),
        ReferenceKind::ToolName,
    ));
    Ok(Markers {
        counted: markers,
        let_be: let_be.paths.into_iter().chain(let_be.words).collect(),
        root: own.map(|own| own.root.clone()).unwrap_or_default(),
    })
}

/// Whether the mount source `source` is a name of a device in `own`, the
/// names of the devices the accepted root's filesystem lies on: one of its
/// paths, or its mapping's.
fn names_own(source: &str, own: &storage::Storage) -> bool {
    own.markers.contains(&Pattern::Path(source.to_string()))
        || source
            .strip_prefix("/dev/mapper/")
            .is_some_and(|name| own.names.iter().any(|own| own == name))
}

/// The markers of the devices the mount table's `sources` and the storage
/// below them name.
struct DeviceMarkers {
    /// Those matched before the mount point: the devices, their dm-uuid
    /// links, the storage's names, the units systemd names after the
    /// devices.
    paths: Vec<Marker>,
    /// Those matched after it: the device-mapper names and the kernel names,
    /// short words that a line that names a path names too.
    words: Vec<Marker>,
}

impl DeviceMarkers {
    fn of(sources: &[String], storage: &storage::Storage) -> Self {
        let marker = |pattern, kind| Marker { pattern, kind };
        let mut names: Vec<String> = Vec::new();
        let from_sources = sources
            .iter()
            .filter_map(|source| source.strip_prefix("/dev/mapper/"))
            .filter(|name| !name.is_empty() && !name.contains('/'))
            .map(str::to_string);
        for name in from_sources.chain(storage.names.iter().cloned()) {
            push_new(&mut names, name);
        }
        let mut devices: Vec<String> = Vec::new();
        for source in sources.iter().filter(|source| source.starts_with('/')) {
            push_new(&mut devices, source.clone());
        }
        for name in &names {
            push_new(&mut devices, format!("/dev/mapper/{name}"));
            push_new(&mut devices, format!("/dev/disk/by-id/dm-name-{name}"));
        }
        let mut paths = Vec::new();
        for device in &devices {
            paths.push(marker(Pattern::Path(device.clone()), ReferenceKind::Device));
        }
        for name in &names {
            paths.push(marker(Pattern::DmUuid(name.clone()), ReferenceKind::Device));
        }
        for pattern in &storage.markers {
            paths.push(marker(pattern.clone(), ReferenceKind::Storage));
        }
        for device in &devices {
            for spelling in spellings(&unit(device, "device")) {
                paths.push(marker(Pattern::Path(spelling), ReferenceKind::DeviceUnit));
            }
        }
        let mut words = Vec::new();
        for name in names {
            words.push(marker(
                Pattern::Name {
                    escaped: spellings(&escape_path(Path::new(&name)).to_ascii_lowercase()),
                    name,
                },
                ReferenceKind::MapperName,
            ));
        }
        // A kernel name is a short word (`sdb2`): it comes after every other
        // marker, so a line that names the storage by a path reports the path.
        for name in &storage.kernel_names {
            words.push(marker(Pattern::Word(name.clone()), ReferenceKind::Storage));
        }
        Self { paths, words }
    }
}

/// The names of the root's own place in the filesystem `own`: each folder
/// another mount of it shows the root at, the last part of its path inside
/// the filesystem wherever it stands whole, and on btrfs a `subvolid=` that
/// names its id or cannot be read, and a `subvol=` that cannot be read.
fn root_place(own: &OwnFilesystem) -> Vec<Pattern> {
    let mut patterns = Vec::new();
    for folder in &own.folders {
        patterns.push(Pattern::Path(folder.to_string_lossy().to_ascii_lowercase()));
    }
    patterns.push(Pattern::Component(own.name().to_ascii_lowercase()));
    if own.btrfs {
        patterns.push(Pattern::SubvolId(own.subvolid));
        patterns.push(Pattern::SubvolUnread);
    }
    patterns
}

/// Whether `place` is one where the decoy's configuration names the devices
/// of its own mounts, so a name of a device of the filesystem the root lies
/// on is let be there: a string that is the `device` or `label` of a
/// `fileSystems` entry for `/` or a system folder, other than the hidden
/// root at `root` and anything above it ([`counts_as_system_folder`]), the
/// name of a `boot.initrd.luks.devices` entry, or a string that is the
/// `device` of one. The attribute names are read as Nix reads them, with
/// their case.
fn decoys_own_place(place: &Place, root: &Path) -> bool {
    let path: Vec<&str> = place.path.iter().map(String::as_str).collect();
    if place.attribute {
        return matches!(path.as_slice(), [.., "initrd", "luks", "devices", _]);
    }
    match path.as_slice() {
        [.., "fileSystems", at, "device" | "label"] => counts_as_system_folder(Path::new(at), root),
        [.., "initrd", "luks", "devices", _, "device"] => true,
        _ => false,
    }
}

/// Add `item` to `items` unless it is there already.
fn push_new(items: &mut Vec<String>, item: String) {
    if !items.contains(&item) {
        items.push(item);
    }
}

/// The ways a `.nix` file spells the systemd name `name`: as it is, which a
/// comment or an indented `''…''` string holds, and, when it has an escape in
/// it (`mnt-my\x2ddata.mount`), with each backslash doubled, as a
/// double-quoted string must write it.
fn spellings(name: &str) -> Vec<String> {
    if name.contains('\\') {
        vec![name.to_string(), name.replace('\\', "\\\\")]
    } else {
        vec![name.to_string()]
    }
}

/// The name of the `suffix` unit systemd makes for `path`, lowercased like
/// the text it is matched against.
fn unit(path: &str, suffix: &str) -> String {
    format!("{}.{suffix}", escape_path(Path::new(path))).to_ascii_lowercase()
}

/// Each line of `content` that matches a marker that counts, for the first
/// one it matches, or a name let be outside the decoy's own places for it,
/// for the first such name, and each other line that matches one of the
/// names let be, for the first of those.
fn references_in(
    file: &Path,
    content: &str,
    markers: &Markers,
) -> (Vec<BaseConfigReference>, Vec<BaseConfigReference>) {
    let original = content.as_bytes();
    let text = original.to_ascii_lowercase();
    let mut scanner = Scanner::default();
    let mut shell = Shell::default();

    let mut found = Vec::new();
    let mut let_be = Vec::new();
    let mut start = 0;
    for (index, line) in text.split(|&byte| byte == b'\n').enumerate() {
        let end = start + line.len();
        // The scanner reads the line as the file spells it, so the attribute
        // names of the places keep their case.
        let context = Context {
            names: scanner.line(&original[start..end]),
            arguments: shell.line(line),
            places: scanner.places(),
        };
        let first = |markers: &[Marker]| {
            markers.iter().find_map(|marker| {
                marker
                    .pattern
                    .find(line, &context)
                    .map(|range| (marker.kind, range))
            })
        };
        let reference =
            |(kind, range): (ReferenceKind, std::ops::Range<usize>)| BaseConfigReference {
                file: file.to_path_buf(),
                line: index + 1,
                text: String::from_utf8_lossy(&original[start + range.start..start + range.end])
                    .into_owned(),
                kind,
            };
        if let Some(hit) = first(&markers.counted) {
            found.push(reference(hit));
        } else if let Some(hit) = first(&markers.let_be) {
            // The line with the decoy's own places blanked out: a name of
            // the filesystem's devices that it still holds stands elsewhere.
            let mut elsewhere = line.to_vec();
            for place in &context.places {
                if decoys_own_place(place, &markers.root) {
                    elsewhere[place.range.clone()].fill(b' ');
                }
            }
            let outside = markers.let_be.iter().find_map(|marker| {
                marker
                    .pattern
                    .find(&elsewhere, &context)
                    .map(|range| (marker.kind, range))
            });
            match outside {
                Some(outside) => found.push(reference(outside)),
                None => let_be.push(reference(hit)),
            }
        }
        start = end + 1;
    }
    (found, let_be)
}

/// Resolves the backing source(s) that the mount table `mountinfo` (the text
/// of `/proc/self/mountinfo`) reports for `hidden_volume_root`,
/// ASCII-lowercased. Returns an empty list when the mount table is unavailable
/// or has no matching entry (path-only matching then applies).
fn resolve_backing_sources(mountinfo: &str, hidden_volume_root: &Path) -> Vec<String> {
    let mut sources = Vec::new();
    for line in mountinfo.lines() {
        // mountinfo: <pre> " - " <fstype> <source> <super_opts>
        // <pre> fields: mount_id parent_id major:minor root mount_point opts [optional...]
        let Some((pre, post)) = line.split_once(" - ") else {
            continue;
        };

        let mut pre_fields = pre.split(' ');
        // Field 5 (index 4) is the mount point; it may carry octal escapes.
        let Some(mount_point) = pre_fields.nth(4) else {
            continue;
        };
        if Path::new(&octal_unescape(mount_point)) != hidden_volume_root {
            continue;
        }

        // Post-separator fields: fstype, source, super_opts.
        let mut post_fields = post.split(' ');
        let Some(source) = post_fields.nth(1) else {
            continue;
        };
        sources.push(octal_unescape(source).to_ascii_lowercase());
    }

    sources
}

/// Decodes the octal escapes (`\040` space, `\011` tab, `\012` newline,
/// `\134` backslash, and any `\ooo`) that the kernel writes into mountinfo
/// fields. Non-escape bytes pass through unchanged.
fn octal_unescape(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0usize;

    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 3 < bytes.len()
            && matches!(bytes[i + 1], b'0'..=b'7')
            && matches!(bytes[i + 2], b'0'..=b'7')
            && matches!(bytes[i + 3], b'0'..=b'7')
        {
            // Compute in a wider type: a leading octal digit of 4-7 would
            // overflow `u8` (7 * 64 = 448) and panic in debug builds.
            let code = (u16::from(bytes[i + 1] - b'0') << 6)
                | (u16::from(bytes[i + 2] - b'0') << 3)
                | u16::from(bytes[i + 3] - b'0');
            out.push(code as u8);
            i += 4;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }

    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod octal_decode_tests {
    use super::octal_unescape;

    #[test]
    fn decodes_kernel_escapes_and_passes_through_plain_bytes() {
        assert_eq!(
            octal_unescape("/mnt/hidden\\040volume"),
            "/mnt/hidden volume"
        );
        assert_eq!(octal_unescape("a\\011b"), "a\tb");
        assert_eq!(octal_unescape("a\\134b"), "a\\b");
        assert_eq!(octal_unescape("/dev/mapper/vault"), "/dev/mapper/vault");
    }

    #[test]
    fn decodes_high_octal_value_without_overflow() {
        // A leading octal digit of 4-7 exceeds a single-byte product; the
        // decoder must widen the arithmetic instead of overflowing.
        assert_eq!(octal_unescape("\\101"), "A");
        assert_eq!(octal_unescape("\\176"), "~");
    }

    #[test]
    fn leaves_incomplete_escapes_untouched() {
        assert_eq!(octal_unescape("\\04"), "\\04");
        assert_eq!(octal_unescape("\\09x"), "\\09x");
    }
}

#[cfg(test)]
mod tests;
