// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Hidden volume pre-flight check
//!
//! Validates that the hidden volume is mounted and writable before activation.

use super::super::{CheckResult, PreFlightCheck};
use crate::filesystem::MountSource;
use crate::hidden_root::separation::{Sharing, Verdict};
use crate::hidden_root::{Allow, Assessment, HiddenRoot, MountedElsewhere, Refusal, RefusalKind};
use crate::naming::suspicious_token;
use crate::{Filesystem, Result, config::get_default_hidden_volume_root};
use nails_api::Allowable;
use std::path::{Component, Path, PathBuf};

/// Pre-flight check that validates the hidden volume is mounted and accessible
///
/// This check validates in three steps and then audits the names in two:
/// 1. **Path Existence**: Hidden volume path must exist
/// 2. **The attach gate**: a volume of its own must be mounted at the path
///    ([`HiddenRoot::assess`]): not a folder, not a root covered by a second
///    filesystem, not storage the decoy uses, and storage that can be judged.
///    On the decoy its filesystem must be mounted nowhere else in the mount
///    table ([`HiddenRoot::mounted_elsewhere`]): a desktop that mounts a drive
///    by itself mounts the unlocked volume again under `/media` or
///    `/run/media`, where the decoy's desktop reaches its files. No flag lifts
///    that. For a root on a filesystem the decoy uses, accepted with
///    `--allow-decoy-storage`, the decoy's own mounts of that filesystem, at
///    `/` and by its fstab, and mounts that show none of the root's folder do
///    not count ([`HiddenRoot::mounted_elsewhere_on_a_decoy_filesystem`]).
///    Nothing is probed before both pass, so `check` writes no probe file
///    onto the decoy's storage.
/// 3. **Write Permission**: Path must be writable to store overlay directories
/// 4. **Neutral naming**: once mounted and writable, the mount path, the
///    device-mapper name and the filesystem label are scanned for words that
///    betray hidden storage, and a match is reported as a non-blocking warning
/// 5. **No label**: any other filesystem label warns as well, since even a
///    neutral one shows in `/dev/disk/by-label` and the tools that list
///    disks. A root on a filesystem the decoy uses, which the operator
///    accepted, carries the decoy's own label and is let be.
///
/// A root the gate only warns about (a container file on a decoy filesystem),
/// or decoy storage the operator accepted with `--allow-decoy-storage`, passes
/// with that warning. A refusal is reported in the gate's own words.
///
/// # Failure Guidance
///
/// Each failure mode provides actionable guidance with fix steps:
/// - **Missing, or refused by the gate**: the gate's own hint (mount the
///   volume, prepare it where nothing reaches this disk, unmount the second
///   filesystem, run with sudo)
/// - **Mounted elsewhere too**: the `sudo umount` line for the other mounts,
///   what hides one that `umount` cannot reach by its path, and turning the
///   desktop's automatic mounting of removable media off long before the next
///   use. For a root the operator accepted on a filesystem the decoy uses, the
///   failure says that no line of the fstab that NAILS can tell made the other
///   mounts from the computer's own storage, and the fix first says not to
///   unmount one the computer makes by itself but to use a volume of its own,
///   then how to unmount one made by hand
/// - **Not writable**: Suggests checking permissions
///
/// # Example
///
/// ```rust
/// use nails_core::preflight::{HiddenVolumeCheck, PreFlightCheck};
/// use nails_core::filesystem::MockFilesystem;
/// use std::path::PathBuf;
///
/// let fs = MockFilesystem::new();
/// let check = HiddenVolumeCheck::new(PathBuf::from("/mnt/data"));
///
/// // Set up mock state
/// fs.mock_set_path_exists("/mnt/data", true);
/// fs.mock_set_mounted(std::path::Path::new("/mnt/data"), true);
/// fs.mock_set_writable("/mnt/data", true);
///
/// let result = check.run(&fs).unwrap();
/// assert!(result.is_pass());
/// ```
#[derive(Debug, Clone)]
pub struct HiddenVolumeCheck {
    hidden_volume_root: PathBuf,
    allow: Allow,
}

impl HiddenVolumeCheck {
    /// Create a new HiddenVolumeCheck with a custom path
    ///
    /// # Arguments
    ///
    /// * `hidden_volume_root` - Path to the hidden volume mount point
    pub fn new(hidden_volume_root: PathBuf) -> Self {
        Self {
            hidden_volume_root,
            allow: Allow::Nothing,
        }
    }

    /// Accept the gate refusals `allow` covers (`--allow-decoy-storage`) with a
    /// warning.
    #[must_use]
    pub fn allowing(mut self, allow: Allow) -> Self {
        self.allow = allow;
        self
    }
}

impl Default for HiddenVolumeCheck {
    /// Create check with default hidden volume path
    fn default() -> Self {
        Self::new(PathBuf::from(get_default_hidden_volume_root()))
    }
}

/// The failure of a root the attach gate refused: the gate's own sentence, as
/// `init`, `activate` and `rehearse` print it, with its hint as the
/// remediation. A refusal `--allow-decoy-storage` would turn into a warning
/// names that override; no other does.
fn gate_failure(refusal: &Refusal) -> CheckResult {
    let exe = std::env::current_exe().ok();
    let failure = CheckResult::fail_with(
        refusal.reason.clone(),
        refusal.hint(exe.as_deref()).join("\n"),
    );
    if Allow::DecoyStorage.covers(&refusal.kind) {
        failure.accepted_by(Allowable::DecoyStorage)
    } else {
        failure
    }
}

impl<F: Filesystem> PreFlightCheck<F> for HiddenVolumeCheck {
    fn name(&self) -> &'static str {
        "hidden-volume"
    }

    fn description(&self) -> &'static str {
        "Validates hidden volume is mounted and writable"
    }

    fn is_hidden_volume_gate(&self) -> bool {
        true
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        // Steps 1 and 2: the attach gate, which also finds a missing root,
        // before anything is probed.
        let mut warnings = Vec::new();
        let mut decoy_filesystem = false;
        match HiddenRoot::assess_allowing(fs, &self.hidden_volume_root, self.allow)? {
            Assessment::Attached => {}
            Assessment::Warned(refusal) => {
                decoy_filesystem = on_a_decoy_filesystem(&refusal);
                warnings.push(refusal.warning());
            }
            Assessment::Refused(refusal) => return Ok(gate_failure(&refusal)),
        }

        // Step 2b: mounted nowhere else, before anything is probed. A root on
        // a filesystem the decoy uses, which the operator accepted, is also
        // mounted where the decoy mounts that filesystem, at / or by a line of
        // its fstab, which the gate's warning is about: only those mounts, and
        // those that show none of the root's folder, are left out.
        let elsewhere = if decoy_filesystem {
            HiddenRoot::mounted_elsewhere_on_a_decoy_filesystem(fs, &self.hidden_volume_root)?
        } else {
            HiddenRoot::mounted_elsewhere(fs, &self.hidden_volume_root)?
        };
        if let Some(elsewhere) = elsewhere {
            return Ok(mounted_twice(
                fs,
                &self.hidden_volume_root,
                &elsewhere,
                decoy_filesystem,
            ));
        }

        // Step 3: Check path is writable
        if !fs.is_writable(&self.hidden_volume_root)? {
            return Ok(CheckResult::fail(format!(
                "Hidden volume at {} is not writable. Check permissions.",
                self.hidden_volume_root.display()
            )));
        }

        // Step 4: Audit names for words that betray hidden storage. This never
        // blocks activation — the volume is usable — it only warns so the
        // operator can rename before the name leaks off the box. A source
        // that cannot be read contributes no hints rather than failing the
        // check, exactly as the backend detector treats an unreadable mount
        // table.
        let source = fs
            .mount_source(&self.hidden_volume_root)
            .ok()
            .flatten()
            .unwrap_or_default();
        let hints = self.naming_hints(&source);
        if !hints.is_empty() {
            warnings.push(format!(
                "Hidden volume mounted at {}, but a name here hints at hidden storage: {}. \
                 Such a name survives in the leftover mount-point directory, in generated \
                 mount unit names, in /dev/disk/by-label and in kernel and sudo journal \
                 lines. Use neutral names that reveal nothing (for example a \"data\" \
                 mapper and a /mnt/data mountpoint) and no filesystem label. These names \
                 also leak before NAILS runs; see the pre-activation residue section of \
                 docs/operator-guide.md.",
                self.hidden_volume_root.display(),
                hints.join("; ")
            ));
        }

        // Step 5: any other label. A root on a filesystem the decoy uses
        // carries the decoy's label, which says nothing of hidden storage.
        if let Some(label) = source.label.as_deref()
            && suspicious_token(label).is_none()
            && !decoy_filesystem
        {
            warnings.push(label_warning(&self.hidden_volume_root, label));
        }
        if !warnings.is_empty() {
            return Ok(CheckResult::Warn(warnings.join(" ")));
        }

        Ok(CheckResult::Pass(format!(
            "Hidden volume mounted at {}",
            self.hidden_volume_root.display()
        )))
    }
}

/// The failure of a root whose filesystem is mounted at other places too
/// ([`HiddenRoot::mounted_elsewhere`]): it names every other mount point, then
/// says how to unmount them. No flag lifts it.
///
/// The `umount` line names the mounts a lookup of their path reaches (see
/// [`unmount_line`]). One that another mount hides gets a line of its own,
/// which names the mount over it: `umount` given its path would reach that
/// one, or none. The advice to turn off the automatic mounting of removable
/// media and the section to read come last.
///
/// For a root on a filesystem the decoy uses, which the operator accepted
/// (`decoy_filesystem`), the computer's own mounts of it, at `/` and by a line
/// of the fstab from its own storage, are left out, and the failure says that
/// no such line that NAILS can tell made the other mounts: a bind line whose
/// source has a link in it makes none it can tell (the judge,
/// [`separation`](crate::hidden_root::separation), follows no link), and
/// neither does a line that is not plain, which NAILS does not read as
/// `libmount` and systemd do. It names no mount at `/` or by the fstab, as
/// there may be none: a drive of its own also mounted at `/srv` by hand counts
/// as the computer's storage. Its fix starts by saying that one the computer
/// makes by itself is not to be unmounted, as the root then needs a volume of
/// its own: once a partition the
/// computer mounts with no fstab line is unmounted, the check can no longer
/// tell that a root on it lies on the computer's storage. Only then come the
/// unmount lines, for a mount made by hand, and the advice about removable
/// media only when one of the mounts lies under `/media` or `/run/media`.
fn mounted_twice<F: Filesystem>(
    fs: &F,
    root: &Path,
    elsewhere: &MountedElsewhere,
    decoy_filesystem: bool,
) -> CheckResult {
    use crate::catalog::{
        CHECK_MOUNTED_TWICE, CHECK_MOUNTED_TWICE_ADVICE, CHECK_MOUNTED_TWICE_DECOY_FILESYSTEM,
        CHECK_MOUNTED_TWICE_DECOY_FILESYSTEM_FIX, CHECK_MOUNTED_TWICE_HIDDEN,
        CHECK_MOUNTED_TWICE_READ,
    };
    let shown_root = root.display().to_string();
    let others: Vec<&Path> = elsewhere
        .mounts
        .iter()
        .map(|mount| mount.mount_point.as_path())
        .collect();
    let others = places(&others);
    let failure = if decoy_filesystem {
        CHECK_MOUNTED_TWICE_DECOY_FILESYSTEM
    } else {
        CHECK_MOUNTED_TWICE
    };
    let message = failure.render(&[("root", &shown_root), ("places", &others)]);

    let mut fix = Vec::new();
    if decoy_filesystem {
        fix.push(CHECK_MOUNTED_TWICE_DECOY_FILESYSTEM_FIX.render(&[("places", &others)]));
    }
    let reachable: Vec<&Path> = elsewhere
        .mounts
        .iter()
        .filter(|mount| mount.hidden_under.is_none())
        .map(|mount| mount.mount_point.as_path())
        .collect();
    if !reachable.is_empty() {
        fix.push(unmount_line(fs, root, &reachable, elsewhere));
    }
    for mount in &elsewhere.mounts {
        if let Some(cover) = &mount.hidden_under {
            fix.push(CHECK_MOUNTED_TWICE_HIDDEN.render(&[
                ("place", &mount.mount_point.display().to_string()),
                ("cover", &cover.display().to_string()),
            ]));
        }
    }
    let removable_media = elsewhere.mounts.iter().any(|mount| {
        REMOVABLE_MEDIA
            .iter()
            .any(|at| mount.mount_point.starts_with(at))
    });
    if !decoy_filesystem || removable_media {
        fix.push(CHECK_MOUNTED_TWICE_ADVICE.render(&[]));
    }
    fix.push(CHECK_MOUNTED_TWICE_READ.render(&[]));
    CheckResult::fail_with(message, fix.join("\n"))
}

/// Where a desktop that mounts drives by itself mounts them: `/media/<user>`
/// on Debian and Ubuntu, `/run/media/<user>` on most other distributions.
const REMOVABLE_MEDIA: &[&str] = &["/media", "/run/media"];

/// The `sudo umount` line for the other mounts at `reachable`, the deepest
/// first, so a mount inside another goes before it, each quoted for the shell.
/// One that holds the root can only go once the root is unmounted too, so the
/// root joins them, and the line says how to mount it again alone, as its
/// mount showed the volume: all of it, a folder of it bound there, or a btrfs
/// subvolume.
fn unmount_line<F: Filesystem>(
    fs: &F,
    root: &Path,
    reachable: &[&Path],
    elsewhere: &MountedElsewhere,
) -> String {
    use crate::catalog::{
        CHECK_MOUNTED_TWICE_FIX, CHECK_MOUNTED_TWICE_FIX_HOLDING_FOLDER,
        CHECK_MOUNTED_TWICE_FIX_HOLDING_ROOT, CHECK_MOUNTED_TWICE_FIX_HOLDING_SUBVOLUME,
    };
    let canonical = fs.canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let holding_root = reachable.iter().any(|place| canonical.starts_with(place));
    let mut unmount = reachable.to_vec();
    if holding_root {
        unmount.push(&canonical);
    }
    unmount.sort_by_key(|place| std::cmp::Reverse(place.components().count()));
    let mount_points = unmount
        .iter()
        .map(|place| crate::next_step::shell_word(place.as_os_str()))
        .collect::<Vec<_>>()
        .join(" ");
    if !holding_root {
        return CHECK_MOUNTED_TWICE_FIX.render(&[("mount_points", &mount_points)]);
    }
    let shown_root = root.display().to_string();
    let folder = elsewhere.root_folder.display().to_string();
    match elsewhere.root_shows {
        Sharing::Filesystem => CHECK_MOUNTED_TWICE_FIX_HOLDING_ROOT
            .render(&[("mount_points", &mount_points), ("root", &shown_root)]),
        Sharing::Bind => CHECK_MOUNTED_TWICE_FIX_HOLDING_FOLDER.render(&[
            ("mount_points", &mount_points),
            ("folder", &folder),
            ("root", &shown_root),
        ]),
        Sharing::Subvolume => CHECK_MOUNTED_TWICE_FIX_HOLDING_SUBVOLUME.render(&[
            ("mount_points", &mount_points),
            ("subvolume", &folder),
            ("root", &shown_root),
        ]),
    }
}

/// `places` for a sentence: `a`, `a and b`, `a, b and c`.
fn places(places: &[&Path]) -> String {
    let shown: Vec<String> = places.iter().map(|p| p.display().to_string()).collect();
    match shown.split_last() {
        Some((last, rest)) if !rest.is_empty() => format!("{} and {last}", rest.join(", ")),
        _ => shown.join(""),
    }
}

/// Whether the gate placed the root on a filesystem the decoy uses: a bind,
/// a btrfs subvolume, or that filesystem itself.
fn on_a_decoy_filesystem(refusal: &Refusal) -> bool {
    matches!(
        refusal.kind,
        RefusalKind::DecoyStorage {
            verdict: Verdict::OnDecoyFilesystem { .. }
        }
    )
}

/// The warning about a filesystem label with no telling word in it.
fn label_warning(root: &Path, label: &str) -> String {
    format!(
        "The filesystem at {} carries the label \"{label}\". Even a neutral label is a hint: \
         it shows in /dev/disk/by-label, in systemd's device units, in file managers and in \
         lsblk, and a common one such as \"data\" is shared by everyone who followed the same \
         example. Remove the label where setup happens, not on this computer (on ext4: \
         e2label <device> '').",
        root.display()
    )
}

impl HiddenVolumeCheck {
    /// Collect every way the mounted volume's names hint at hidden storage.
    ///
    /// Scans the mount path's own components, the device-mapper name behind the
    /// mount source and the filesystem label, from the `source` that
    /// [`Filesystem::mount_source`] read.
    fn naming_hints(&self, source: &MountSource) -> Vec<String> {
        let mut hints = Vec::new();

        // (a) The mount path itself. One mention is enough, so stop at the first
        // component that matches.
        for component in self.hidden_volume_root.components() {
            if let Component::Normal(part) = component {
                let part = part.to_string_lossy();
                if let Some(token) = suspicious_token(&part) {
                    hints.push(format!(
                        "the mount path component \"{part}\" contains \"{token}\""
                    ));
                    break;
                }
            }
        }

        // (b) and (c) The device-mapper name and filesystem label behind the
        // mount source.
        if let Some(name) = source.dm_name.as_deref()
            && let Some(token) = suspicious_token(name)
        {
            hints.push(format!(
                "the device-mapper name \"{name}\" contains \"{token}\""
            ));
        }
        if let Some(label) = source.label.as_deref()
            && let Some(token) = suspicious_token(label)
        {
            hints.push(format!(
                "the filesystem label \"{label}\" contains \"{token}\""
            ));
        }

        hints
    }
}

#[cfg(test)]
#[path = "hidden_volume_tests.rs"]
mod tests;
