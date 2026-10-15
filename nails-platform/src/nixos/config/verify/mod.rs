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
//! storage it lives on) or NAILS, with the file, the line, the matched text and
//! why it counts. Only `.nix` files are read: other files in `/etc/nixos` and
//! the history of a git repository there are not.

mod nix_text;
mod scan;
mod storage;

use crate::artifacts::{ARTIFACTS, ArtifactKind};
use crate::error::Result;
use crate::filesystem::Filesystem;
use nails_base::filesystem::parse_mountinfo;
use nails_base::fstab::escape_path;
use nix_text::{Context, Pattern, Shell};
use scan::Scanner;
use std::path::{Path, PathBuf};

/// Base `/etc/nixos` directory scanned for hidden-environment traces.
const BASE_NIXOS_DIR: &str = "/etc/nixos";

/// Kernel mount table exposing the backing source of each mount point.
const SELF_MOUNTINFO: &str = "/proc/self/mountinfo";

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
    /// What the hidden volume is stored on, as sysfs shows it below its
    /// mount: the partition or disk (`/dev/sdb2`), its partition uuid, the
    /// LUKS uuid (`/dev/disk/by-uuid/<uuid>`, `UUID=<uuid>`), the
    /// `/dev/disk/by-id/dm-uuid-…` link, or an image file behind a loop device.
    Storage,
    /// The hidden volume's mount point.
    MountPoint,
    /// The unit systemd names after the mount point (`mnt-data.mount`,
    /// `mnt-data.automount`).
    MountUnit,
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
                "the device or file the hidden volume is stored on, or one of its identifiers"
            }
            ReferenceKind::MountPoint => "the hidden volume's mount point",
            ReferenceKind::MountUnit => {
                "the unit systemd names after the hidden volume's mount point"
            }
            ReferenceKind::MapperName => "the hidden volume's device-mapper name",
            ReferenceKind::ToolName => "the name of this tool",
        }
    }

    /// What the operator does about it.
    pub fn remedy(self) -> &'static str {
        match self {
            ReferenceKind::MapperName => {
                "Remove it from that file long before the next use and rebuild the decoy. If \
                 the name is there for another reason, open the hidden volume under a name \
                 that appears nowhere in /etc/nixos instead."
            }
            ReferenceKind::MountPoint | ReferenceKind::MountUnit => {
                "Remove it from that file long before the next use and rebuild the decoy. If \
                 the decoy uses that path for something else, mount the hidden volume at a \
                 path that appears nowhere in /etc/nixos instead."
            }
            _ => "Remove it from that file long before the next use and rebuild the decoy.",
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
///   and any `/dev/disk/by-id/dm-uuid-…-<name>`, each as a whole path, and
///   the units systemd names after them (`dev-mapper-data.device`);
/// - what the volume is stored on, read from sysfs below its mount as long as
///   nothing else is built on it ([`storage`]): the partition or disk, its
///   partition uuid, the LUKS uuid, the `dm-uuid` link, or the image file
///   behind a loop device;
/// - `hidden_volume_root` itself, as a whole path (`/mnt/data` and
///   `/mnt/data/nixos` count, `/mnt/data2` does not), and its `.mount` and
///   `.automount` units (`mnt-data.mount`);
/// - the device-mapper names where they name the mapping: a `luks.devices` or
///   `clevis.devices` entry however its blocks nest (`luks.devices.data`,
///   `luks.devices."data"`, `luks = { devices.data = … }`, `inherit data;` in
///   a `luks.devices` block, inside `with`, `let … in`, `lib.mkForce` or
///   `lib.mkMerge`), the `name` of such an entry or of one in the old list
///   form, `encrypted.label`, an argument of a `cryptsetup` command that
///   opens, closes or asks about a mapping (continued lines included) or the
///   instance of `systemd-cryptsetup@data.service`, or the first field of a
///   crypttab line at the start of a line or a string (`data UUID=… none
///   luks`, `data /var/lib/vault.img none luks`);
/// - the word `nails`.
///
/// A unit name with a character systemd escapes (`mnt-my\x2ddata.mount`)
/// counts in both spellings: with one backslash, as a comment or an indented
/// `''…''` string holds it, and with two, as a double-quoted string writes it.
/// Matching ignores ASCII case. Ordinary configuration never counts: the
/// mapping name as an ordinary word (`description = "Back up user data"` with
/// the mapping `data`, `cryptsetup` beside it in a package list or in prose)
/// or a directory (`/var/lib/postgresql/data`), the decoy's own mapping whose
/// name ends like the hidden one (`user-data`), the word `hidden` (GRUB's
/// `timeoutStyle = "hidden"`), or an option such as `services.plausible`. A
/// mapping defined through a `let` binding or `lib.listToAttrs` is not
/// followed; its device still counts where the line names it.
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
    let mut files = fs.find_files_with_pattern(Path::new(BASE_NIXOS_DIR), ".nix")?;
    files.sort();

    let mut scan = BaseConfigScan::default();
    if files.is_empty() {
        tracing::debug!("no .nix file under {BASE_NIXOS_DIR}; nothing to inspect");
        return Ok(scan);
    }

    let markers = markers(fs, hidden_volume_root);
    for file in &files {
        let content = fs.read_file_content(file)?;
        scan.files_read += 1;
        scan.references
            .extend(references_in(file, &content, &markers));
    }
    tracing::debug!(
        files = scan.files_read,
        references = scan.references.len(),
        "scanned the decoy's /etc/nixos"
    );
    Ok(scan)
}

/// The markers for `hidden_volume_root`, in the order a line is matched.
fn markers<F: Filesystem>(fs: &F, hidden_volume_root: &Path) -> Vec<Marker> {
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
    let mountinfo = fs
        .read_file_content(Path::new(SELF_MOUNTINFO))
        .unwrap_or_default();
    let sources = resolve_backing_sources(&mountinfo, hidden_volume_root);
    let below = storage::below(fs, &parse_mountinfo(&mountinfo), hidden_volume_root);
    let mut names: Vec<String> = Vec::new();
    let from_sources = sources
        .iter()
        .filter_map(|source| source.strip_prefix("/dev/mapper/"))
        .filter(|name| !name.is_empty() && !name.contains('/'))
        .map(str::to_string);
    for name in from_sources.chain(below.names.iter().cloned()) {
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
    for device in &devices {
        markers.push(marker(Pattern::Path(device.clone()), ReferenceKind::Device));
    }
    for name in &names {
        markers.push(marker(Pattern::DmUuid(name.clone()), ReferenceKind::Device));
    }
    for pattern in below.markers {
        markers.push(marker(pattern, ReferenceKind::Storage));
    }
    for device in &devices {
        for spelling in spellings(&unit(device, "device")) {
            markers.push(marker(Pattern::Path(spelling), ReferenceKind::DeviceUnit));
        }
    }

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

    for name in names {
        markers.push(marker(
            Pattern::Name {
                escaped: spellings(&escape_path(Path::new(&name)).to_ascii_lowercase()),
                name,
            },
            ReferenceKind::MapperName,
        ));
    }

    markers.push(marker(
        Pattern::Word("nails".into()),
        ReferenceKind::ToolName,
    ));
    markers
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

/// Each line of `content` that matches a marker, for the first marker it
/// matches.
fn references_in(file: &Path, content: &str, markers: &[Marker]) -> Vec<BaseConfigReference> {
    let original = content.as_bytes();
    let text = original.to_ascii_lowercase();
    let mut scanner = Scanner::default();
    let mut shell = Shell::default();

    let mut found = Vec::new();
    let mut start = 0;
    for (index, line) in text.split(|&byte| byte == b'\n').enumerate() {
        let end = start + line.len();
        let context = Context {
            names: scanner.line(line),
            arguments: shell.line(line),
        };
        let hit = markers.iter().find_map(|marker| {
            marker
                .pattern
                .find(line, &context)
                .map(|range| (marker.kind, range))
        });
        if let Some((kind, range)) = hit {
            found.push(BaseConfigReference {
                file: file.to_path_buf(),
                line: index + 1,
                text: String::from_utf8_lossy(&original[start + range.start..start + range.end])
                    .into_owned(),
                kind,
            });
        }
        start = end + 1;
    }
    found
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
