// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Runtime units in `/run/systemd/system`, and runtime masks of units and
//! generators.
//!
//! A soft-reboot carries `/run`, and a fresh PID 1 loads the runtime unit
//! directory `/run/systemd/system` and runs the generators when it starts. At
//! entry the transition installs the hidden session's own units (the backend
//! watcher, the sleep guard), masks the decoy units the hidden systemd must
//! never start (decoy swap, decoy filesystems it would mount read-write) and
//! the generators it must never run. They live only in `/run` and the way
//! back removes them, so the decoy's PID 1 never sees them.
//!
//! Unit and generator names are validated: a plain file name with a known
//! unit suffix, or one ending in `-generator`, so a plan can never make the
//! transition write outside `/run/systemd/system`,
//! `/run/systemd/system.control` and `/run/systemd/system-generators`.

use crate::whole_root::run_scrub::Snapshot;
use serde::{Deserialize, Serialize};
use std::io;
use std::path::{Path, PathBuf};

/// The runtime unit directory below a `/run` root.
pub const RUNTIME_UNIT_DIR: &str = "systemd/system";

/// The runtime directory that ranks above `/etc/systemd/system`, below a
/// `/run` root. A unit file in a directory listed earlier overrides one of the
/// same name listed later, and `/run/systemd/system` comes after
/// `/etc/systemd/system`, where NixOS links every unit: a mask there only
/// hides a unit installed below `/usr` (or generated from fstab).
pub const RUNTIME_CONTROL_DIR: &str = "systemd/system.control";

/// The runtime generator directory below a `/run` root. PID 1 runs a
/// generator from the first directory that has one of its name, and this one
/// comes first, before `/etc/systemd/system-generators`: a link to
/// `/dev/null` here masks the generator wherever it is installed.
pub const GENERATOR_DIR: &str = "systemd/system-generators";

/// The suffix every systemd generator's name ends in.
const GENERATOR_SUFFIX: &str = "-generator";

/// The unit suffixes a runtime unit or mask may have. The fstab policy masks
/// an automount with its mount.
const UNIT_SUFFIXES: &[&str] = &[
    ".service",
    ".target",
    ".socket",
    ".timer",
    ".path",
    ".mount",
    ".automount",
    ".swap",
    ".scope",
];

/// One unit file to install in `/run/systemd/system`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeUnit {
    /// The unit name with its suffix (`overlay-runtime-monitor.service`).
    pub name: String,
    /// The unit file's content.
    pub content: String,
    /// Targets that want the unit (`multi-user.target`): a symlink is placed in
    /// each `<target>.wants/` directory.
    #[serde(default)]
    pub wanted_by: Vec<String>,
}

/// Whether `name` is a plain unit file name with a known suffix.
pub fn valid_unit_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && !name.starts_with('.')
        && !name.contains('/')
        && !name.contains('\0')
        && UNIT_SUFFIXES
            .iter()
            .any(|s| name.len() > s.len() && name.ends_with(s))
}

/// Whether `name` is a plain file name that ends in `-generator`, as every
/// systemd generator's does.
pub fn valid_generator_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && !name.starts_with('.')
        && !name.contains('/')
        && !name.contains('\0')
        && name.len() > GENERATOR_SUFFIX.len()
        && name.ends_with(GENERATOR_SUFFIX)
}

/// Mask `units` under `run` in [`RUNTIME_CONTROL_DIR`], so the mask wins
/// wherever the unit is installed. Best effort and one at a time: a name that
/// is not a unit name, or a path that already holds anything (a mask or an
/// override of the decoy's own), is skipped. Returns the links written.
pub fn mask_units_best_effort(run: &Path, units: &[String]) -> Vec<PathBuf> {
    let dir = run.join(RUNTIME_CONTROL_DIR);
    let mut written = Vec::new();
    for name in units.iter().filter(|name| valid_unit_name(name)) {
        let link = dir.join(name);
        if std::fs::symlink_metadata(&link).is_ok() {
            continue;
        }
        if std::fs::create_dir_all(&dir).is_ok()
            && std::os::unix::fs::symlink("/dev/null", &link).is_ok()
        {
            written.push(link);
        }
    }
    written
}

/// Remove the masks a session wrote below `run`: `masks` from the runtime
/// unit directory, `boot_masks` from the control directory and
/// `generator_masks` from the generator directory, each only where it is
/// still a link to `/dev/null` and `kept` (the `/run` snapshot the entry
/// took, empty when it is gone) does not hold it, so a mask the decoy had
/// before stays. The control and generator directories go too when the decoy
/// had none and they are empty now.
///
/// The way back calls this before its scrub, which keeps them all when the
/// snapshot is gone, and so does the decoy side: an entry rolled back, a next
/// root disarmed, or an emergency on the decoy after a switch that never
/// happened. Without it the decoy would keep its swap, its other disks, its
/// boot-loader units or its generators masked until the next boot. Returns
/// whether a mask went: PID 1 keeps a unit masked, and the units a masked
/// generator would make missing, until its next reload.
pub fn remove_masks(
    run: &Path,
    masks: &[String],
    boot_masks: &[String],
    generator_masks: &[String],
    kept: &Snapshot,
) -> bool {
    let mut removed = remove_links(run, RUNTIME_UNIT_DIR, masks, valid_unit_name, kept);
    removed |= remove_links(run, RUNTIME_CONTROL_DIR, boot_masks, valid_unit_name, kept);
    removed |= remove_links(
        run,
        GENERATOR_DIR,
        generator_masks,
        valid_generator_name,
        kept,
    );
    for dir in [RUNTIME_CONTROL_DIR, GENERATOR_DIR] {
        if !kept.contains(std::ffi::OsStr::new(dir)) {
            let _ = std::fs::remove_dir(run.join(dir));
        }
    }
    removed
}

/// Remove from `dir` below `run` each of `names` that `valid` accepts, where
/// it is still a link to `/dev/null` and `kept` does not hold it. Returns
/// whether one went.
fn remove_links(
    run: &Path,
    dir: &str,
    names: &[String],
    valid: fn(&str) -> bool,
    kept: &Snapshot,
) -> bool {
    let mut removed = false;
    for name in names.iter().filter(|name| valid(name)) {
        let relative = Path::new(dir).join(name);
        let link = run.join(&relative);
        if !kept.contains(relative.as_os_str())
            && std::fs::read_link(&link).is_ok_and(|target| target == Path::new("/dev/null"))
        {
            removed |= std::fs::remove_file(&link).is_ok();
        }
    }
    removed
}

fn invalid(name: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("not a unit name: {name:?}"),
    )
}

/// Install `units` under `run` (normally `/run`). Returns the paths written.
pub fn install_units(run: &Path, units: &[RuntimeUnit]) -> io::Result<Vec<PathBuf>> {
    let dir = run.join(RUNTIME_UNIT_DIR);
    let mut written = Vec::new();
    for unit in units {
        if !valid_unit_name(&unit.name) || !unit.wanted_by.iter().all(|t| valid_unit_name(t)) {
            return Err(invalid(&unit.name));
        }
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(&unit.name);
        crate::whole_root::plan::write_atomic_with_mode(
            &path,
            unit.content.as_bytes(),
            crate::whole_root::plan::SERVICE_CONFIG_MODE,
        )?;
        written.push(path);
        for target in &unit.wanted_by {
            let wants = dir.join(format!("{target}.wants"));
            std::fs::create_dir_all(&wants)?;
            let link = wants.join(&unit.name);
            let _ = std::fs::remove_file(&link);
            std::os::unix::fs::symlink(Path::new("..").join(&unit.name), &link)?;
            written.push(link);
        }
    }
    Ok(written)
}

/// Mask `units` under `run`: a `/dev/null` symlink in the runtime unit
/// directory, which ranks above the generator output (fstab units).
pub fn mask_units(run: &Path, units: &[String]) -> io::Result<Vec<PathBuf>> {
    let dir = run.join(RUNTIME_UNIT_DIR);
    let mut written = Vec::new();
    for name in units {
        if !valid_unit_name(name) {
            return Err(invalid(name));
        }
        std::fs::create_dir_all(&dir)?;
        let link = dir.join(name);
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink("/dev/null", &link)?;
        written.push(link);
    }
    Ok(written)
}

/// Mask the generators `names` under `run`: a `/dev/null` symlink in
/// [`GENERATOR_DIR`], so PID 1 runs none of them, from any directory. A name
/// that is not a generator name fails the call before anything is written,
/// and so does a generator directory reached through a link or on a
/// filesystem of its own: the scrub on the way back follows no link and stays
/// on the filesystem of `/run`, so a mask written there would outlive the
/// session. A path that already holds a mask, the decoy's own, is left as it
/// is. A path that holds anything else fails the call before anything is
/// written: PID 1 would run the decoy's program of that name, or skip an entry
/// it cannot run (a dangling link, a directory, a file not marked executable)
/// and run the generator from the next directory. Returns the links written.
pub fn mask_generators(run: &Path, names: &[String]) -> io::Result<Vec<PathBuf>> {
    use std::os::unix::fs::MetadataExt;
    if let Some(name) = names.iter().find(|name| !valid_generator_name(name)) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("not a generator name: {name:?}"),
        ));
    }
    let mut written = Vec::new();
    if names.is_empty() {
        return Ok(written);
    }
    let dir = run.join(GENERATOR_DIR);
    std::fs::create_dir_all(&dir)?;
    if std::fs::canonicalize(&dir)? != std::fs::canonicalize(run)?.join(GENERATOR_DIR)
        || std::fs::metadata(&dir)?.dev() != std::fs::metadata(run)?.dev()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{} is reached through a link or is a filesystem of its own",
                dir.display()
            ),
        ));
    }
    if let Some(taken) = names
        .iter()
        .map(|name| dir.join(name))
        .find(|path| std::fs::symlink_metadata(path).is_ok() && !masks_generator(path))
    {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("{} is there and does not mask it", taken.display()),
        ));
    }
    for name in names {
        let link = dir.join(name);
        if std::fs::symlink_metadata(&link).is_ok() {
            continue;
        }
        std::os::unix::fs::symlink("/dev/null", &link)?;
        written.push(link);
    }
    Ok(written)
}

/// Whether the entry at `path` masks a generator the way PID 1 reads a mask
/// there: it resolves to a character device (a link to `/dev/null`) or to an
/// empty regular file.
fn masks_generator(path: &Path) -> bool {
    use std::os::unix::fs::FileTypeExt;
    std::fs::metadata(path)
        .is_ok_and(|meta| meta.file_type().is_char_device() || (meta.is_file() && meta.len() == 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unit(name: &str) -> RuntimeUnit {
        RuntimeUnit {
            name: name.to_string(),
            content: "[Service]\nExecStart=/bin/true\n".to_string(),
            wanted_by: vec!["multi-user.target".to_string()],
        }
    }

    #[test]
    fn unit_names_are_plain_file_names_with_a_unit_suffix() {
        assert!(valid_unit_name("overlay-runtime-monitor.service"));
        assert!(valid_unit_name("dev-disk-by\\x2duuid-1234.swap"));
        assert!(valid_unit_name("boot-efi.mount"));
        for bad in [
            "",
            ".service",
            "../etc.service",
            "a/b.service",
            "noext",
            ".hidden.service",
            "x.conf",
        ] {
            assert!(!valid_unit_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn generator_names_are_plain_file_names_ending_in_generator() {
        assert!(valid_generator_name("systemd-gpt-auto-generator"));
        assert!(valid_generator_name("zram-generator"));
        for bad in [
            "",
            "-generator",
            "../x-generator",
            "a/b-generator",
            ".x-generator",
            "x-generator\0",
            "systemd-gpt-auto",
            "systemd-gpt-auto-generator.service",
            "x-generator/",
        ] {
            assert!(!valid_generator_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn installed_units_are_wanted_by_their_targets() {
        let run = tempfile::tempdir().unwrap();
        let written = install_units(run.path(), &[unit("a.service")]).unwrap();
        assert_eq!(written.len(), 2);
        let dir = run.path().join(RUNTIME_UNIT_DIR);
        assert!(
            std::fs::read_to_string(dir.join("a.service"))
                .unwrap()
                .contains("ExecStart")
        );
        let link = dir.join("multi-user.target.wants/a.service");
        assert_eq!(
            std::fs::read_link(&link).unwrap(),
            Path::new("../a.service")
        );
        assert!(link.exists(), "the wants link resolves");
        // Installing again replaces rather than failing.
        install_units(run.path(), &[unit("a.service")]).unwrap();
    }

    #[test]
    fn a_bad_unit_name_writes_nothing() {
        let run = tempfile::tempdir().unwrap();
        assert!(install_units(run.path(), &[unit("../../escape.service")]).is_err());
        assert!(mask_units(run.path(), &["x/y.swap".to_string()]).is_err());
        assert!(!run.path().join(RUNTIME_UNIT_DIR).exists());
    }

    #[test]
    fn best_effort_masks_rank_above_etc_and_never_replace_what_is_there() {
        let run = tempfile::tempdir().unwrap();
        let dir = run.path().join(RUNTIME_CONTROL_DIR);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("grub-common.service"), "[Unit]\n").unwrap();
        let written = mask_units_best_effort(
            run.path(),
            &[
                "systemd-boot-random-seed.service".to_string(),
                "grub-common.service".to_string(),
                "../escape.service".to_string(),
            ],
        );
        assert_eq!(written, vec![dir.join("systemd-boot-random-seed.service")]);
        assert_eq!(
            std::fs::read_link(&written[0]).unwrap(),
            Path::new("/dev/null")
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("grub-common.service")).unwrap(),
            "[Unit]\n",
            "an override of the decoy's own stays"
        );
        assert!(!run.path().join("systemd/escape.service").exists());
        assert!(mask_units_best_effort(run.path(), &[]).is_empty());
    }

    #[test]
    fn generator_masks_rank_first_and_never_replace_a_mask_that_is_there() {
        let run = tempfile::tempdir().unwrap();
        let dir = run.path().join(GENERATOR_DIR);
        std::fs::create_dir_all(&dir).unwrap();
        // The decoy masks two generators itself, with the two masks PID 1
        // reads: a link to /dev/null and an empty file.
        std::os::unix::fs::symlink("/dev/null", dir.join("zram-generator")).unwrap();
        std::fs::write(dir.join("local-generator"), "").unwrap();
        let names = [
            "systemd-gpt-auto-generator",
            "zram-generator",
            "local-generator",
        ]
        .map(String::from);
        let written = mask_generators(run.path(), &names).unwrap();
        assert_eq!(written, vec![dir.join("systemd-gpt-auto-generator")]);
        assert_eq!(
            std::fs::read_link(&written[0]).unwrap(),
            Path::new("/dev/null")
        );
        assert!(
            std::fs::read(dir.join("local-generator"))
                .unwrap()
                .is_empty(),
            "the decoy's own mask stays"
        );
        // Masking again finds the masks there and writes nothing.
        assert!(mask_generators(run.path(), &names).unwrap().is_empty());
        assert!(mask_generators(run.path(), &[]).unwrap().is_empty());
    }

    #[test]
    fn an_entry_there_that_does_not_mask_the_generator_writes_nothing() {
        use crate::test_support::write_executable;
        /// Makes an entry at its second path; the first is a directory
        /// outside the generator directory.
        type Make = fn(&Path, &Path);
        // PID 1 skips the first three and runs the generator from the next
        // directory, and runs the last two in its place.
        let entries: [(&str, Make); 5] = [
            ("a dangling link", |_, path| {
                std::os::unix::fs::symlink("/nonexistent", path).unwrap()
            }),
            ("a directory", |_, path| std::fs::create_dir(path).unwrap()),
            ("a file not marked executable", |_, path| {
                std::fs::write(path, "#!/bin/sh\n").unwrap()
            }),
            ("an executable", |_, path| {
                write_executable(path, "#!/bin/sh\n", 0o755)
            }),
            ("a link to an executable", |elsewhere, path| {
                let target = elsewhere.join("real-generator");
                write_executable(&target, "#!/bin/sh\n", 0o755);
                std::os::unix::fs::symlink(&target, path).unwrap()
            }),
        ];
        for (what, make) in entries {
            let run = tempfile::tempdir().unwrap();
            let dir = run.path().join(GENERATOR_DIR);
            std::fs::create_dir_all(&dir).unwrap();
            let gpt = dir.join("systemd-gpt-auto-generator");
            make(run.path(), &gpt);
            let names = ["zram-generator", "systemd-gpt-auto-generator"].map(String::from);
            let err = mask_generators(run.path(), &names).unwrap_err();
            assert!(
                err.to_string().contains("does not mask it"),
                "{what}: {err}"
            );
            assert!(
                std::fs::symlink_metadata(dir.join("zram-generator")).is_err(),
                "{what}: a mask is written"
            );
            assert!(std::fs::symlink_metadata(&gpt).is_ok(), "{what} stays");
        }
    }

    #[test]
    fn a_bad_generator_name_or_a_linked_generator_directory_writes_nothing() {
        let run = tempfile::tempdir().unwrap();
        let names = ["systemd-gpt-auto-generator", "../escape-generator"].map(String::from);
        assert!(mask_generators(run.path(), &names).is_err());
        assert!(!run.path().join("systemd").exists());

        // A generator directory that is a link into a directory the scrub
        // never enters: a mask written there would outlive the session.
        let elsewhere = run.path().join("udev/elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::fs::create_dir_all(run.path().join("systemd")).unwrap();
        std::os::unix::fs::symlink(&elsewhere, run.path().join(GENERATOR_DIR)).unwrap();
        let gpt = ["systemd-gpt-auto-generator".to_string()];
        assert!(mask_generators(run.path(), &gpt).is_err());
        assert!(std::fs::read_dir(&elsewhere).unwrap().next().is_none());
    }

    #[test]
    fn the_generator_masks_go_and_the_decoy_s_own_stay() {
        let gpt = ["systemd-gpt-auto-generator".to_string()];
        // A /run without a generator directory: the mask and the directory go.
        let run = tempfile::tempdir().unwrap();
        let written = mask_generators(run.path(), &gpt).unwrap();
        assert!(remove_masks(
            run.path(),
            &[],
            &[],
            &gpt,
            &Snapshot::default()
        ));
        assert!(std::fs::symlink_metadata(&written[0]).is_err());
        assert!(!run.path().join(GENERATOR_DIR).exists());

        // The decoy masks a generator itself: its mask and the directory stay.
        let run = tempfile::tempdir().unwrap();
        let dir = run.path().join(GENERATOR_DIR);
        std::fs::create_dir_all(&dir).unwrap();
        std::os::unix::fs::symlink("/dev/null", dir.join("zram-generator")).unwrap();
        let kept = Snapshot::take(run.path());
        let both = ["zram-generator", "systemd-gpt-auto-generator"].map(String::from);
        mask_generators(run.path(), &both).unwrap();
        assert!(remove_masks(run.path(), &[], &[], &both, &kept));
        assert!(std::fs::symlink_metadata(dir.join("systemd-gpt-auto-generator")).is_err());
        assert_eq!(
            std::fs::read_link(dir.join("zram-generator")).unwrap(),
            Path::new("/dev/null")
        );
    }

    #[test]
    fn masks_point_at_dev_null() {
        let run = tempfile::tempdir().unwrap();
        // A swap, and a filesystem the policy masks with its automount.
        let units = ["dev-vda3.swap", "data.mount", "data.automount"].map(String::from);
        mask_units(run.path(), &units).unwrap();
        for unit in &units {
            let link = run.path().join(RUNTIME_UNIT_DIR).join(unit);
            assert_eq!(std::fs::read_link(link).unwrap(), Path::new("/dev/null"));
        }
        assert!(remove_masks(
            run.path(),
            &units,
            &[],
            &[],
            &Snapshot::default()
        ));
        assert!(
            std::fs::read_dir(run.path().join(RUNTIME_UNIT_DIR))
                .unwrap()
                .next()
                .is_none()
        );
    }
}
