// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Runtime drop-ins that make the hidden systemd skip a unit.
//!
//! A boot target requires some of the units the session must keep from
//! starting: the mount (or automount) of a decoy filesystem without
//! `nofail`, that of a network filesystem, a swap line. A runtime mask
//! ([`runtime_units::mask_units`]) keeps a unit from starting, but PID 1
//! cannot pull a masked unit into a transaction: it drops the job of the
//! target that requires it, silently, and with the target every unit only
//! the target pulls in (`systemd-remount-fs.service`, a mount the target only
//! wants). The hidden session then runs without `local-fs.target`,
//! `remote-fs.target` or `swap.target`, and nothing reports it.
//!
//! [`skip_units`] gives such a unit a drop-in whose start condition never
//! holds (`ConditionPathExists=!/`) instead: PID 1 gives it a job, tests the
//! condition, ends the job with the unit skipped, and the target is reached.
//! What a skipped unit requires or wants still starts, before its condition
//! is tested: its fsck and makefs would run on the decoy disk, so they get
//! the same drop-in ([`Skip::pulled`]). And a skipped mount or swap still
//! waits for its device: one that is not there holds the hidden session up
//! until the device timeout and then starts emergency mode, so the switch
//! masks the units of a skip whose device is gone by then
//! ([`Skip::device`]).
//!
//! The drop-ins live in `/run` alone, written at the switch with the masks.
//! The way back removes them by name, and so does the decoy side when a
//! switch never happened ([`remove_skips`]).

use crate::whole_root::plan::{self, Skip};
use crate::whole_root::run_scrub::Snapshot;
use crate::whole_root::runtime_units::{self, RUNTIME_UNIT_DIR, valid_unit_name};
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// The skip drop-in's file name, the neutral name of the session's other
/// runtime drop-ins. systemd applies a unit's drop-ins in the order of their
/// names, and `zz-` sorts after the ones a decoy has: an empty
/// `ConditionPathExists=` in a drop-in applied later would clear the
/// condition.
pub const SKIP_DROPIN_NAME: &str = "zz-overlay-runtime.conf";

/// The skip drop-in's text: `/` always exists, so the unit's start
/// condition never holds.
pub const SKIP_TEXT: &str = "[Unit]\nConditionPathExists=!/\n";

/// The drop-in directory of `unit`, below a `/run` root.
pub fn dropin_dir(unit: &str) -> PathBuf {
    Path::new(RUNTIME_UNIT_DIR).join(format!("{unit}.d"))
}

fn invalid(name: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("not a unit name: {name:?}"),
    )
}

/// Write `skips` under `run`: the skip drop-in for every unit of a skip and
/// every unit it pulls in, readable by all
/// ([`plan::SERVICE_CONFIG_MODE`]), or, for a skip whose device is not there
/// now, a mask of its units ([`runtime_units::mask_units`]) and nothing for
/// the units it pulls in, which a masked unit never starts. A name that is
/// not a unit name fails the call before anything is written, and so does a
/// drop-in directory reached through a link or on a filesystem of its own:
/// the scrub on the way back follows no link and stays on the filesystem of
/// `/run`, so a drop-in written there would outlive the session. Returns the
/// paths written.
pub fn skip_units(run: &Path, skips: &[Skip]) -> io::Result<Vec<PathBuf>> {
    if let Some(name) = skips
        .iter()
        .flat_map(|skip| skip.units.iter().chain(&skip.pulled))
        .find(|name| !valid_unit_name(name))
    {
        return Err(invalid(name));
    }
    let mut written = Vec::new();
    for skip in skips {
        if skip
            .device
            .as_deref()
            .is_some_and(|device| !device.exists())
        {
            written.extend(runtime_units::mask_units(run, &skip.units)?);
            continue;
        }
        for unit in skip.units.iter().chain(&skip.pulled) {
            written.push(write_dropin(run, unit)?);
        }
    }
    Ok(written)
}

/// Write the skip drop-in of `unit` under `run` (see [`skip_units`]).
fn write_dropin(run: &Path, unit: &str) -> io::Result<PathBuf> {
    let relative = dropin_dir(unit);
    let dir = run.join(&relative);
    std::fs::create_dir_all(&dir)?;
    if std::fs::canonicalize(&dir)? != std::fs::canonicalize(run)?.join(&relative)
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
    let path = dir.join(SKIP_DROPIN_NAME);
    plan::write_atomic_with_mode(&path, SKIP_TEXT.as_bytes(), plan::SERVICE_CONFIG_MODE)?;
    Ok(path)
}

/// Remove what [`skip_units`] wrote for `skips` under `run`: each skip
/// drop-in that `kept` (the `/run` snapshot the entry took, empty when it is
/// gone) does not hold and that still holds [`SKIP_TEXT`], each drop-in
/// directory left empty that `kept` does not hold, and the masks written in
/// place of a skip whose device was gone ([`runtime_units::remove_unit_masks`]).
/// A drop-in directory the decoy had keeps its own files.
///
/// The way back calls this before its scrub, which keeps everything when the
/// snapshot is gone, and so does the decoy side: an entry rolled back, a next
/// root disarmed, or an emergency on the decoy after a switch that never
/// happened. Without it the decoy would skip its own units until its next
/// boot. Returns whether a drop-in or a mask went: PID 1 keeps them loaded
/// until its next reload.
pub fn remove_skips(run: &Path, skips: &[Skip], kept: &Snapshot) -> bool {
    let mut removed = false;
    for skip in skips {
        for unit in skip
            .units
            .iter()
            .chain(&skip.pulled)
            .filter(|unit| valid_unit_name(unit))
        {
            let dir = dropin_dir(unit);
            let file = dir.join(SKIP_DROPIN_NAME);
            if !kept.contains(file.as_os_str())
                && std::fs::read(run.join(&file)).is_ok_and(|text| text == SKIP_TEXT.as_bytes())
            {
                removed |= std::fs::remove_file(run.join(&file)).is_ok();
            }
            if !kept.contains(dir.as_os_str()) {
                let _ = std::fs::remove_dir(run.join(&dir));
            }
        }
        removed |= runtime_units::remove_unit_masks(run, &skip.units, kept);
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn skip(units: &[&str], pulled: &[&str], device: Option<&Path>) -> Skip {
        Skip {
            units: units.iter().map(|u| (*u).to_string()).collect(),
            pulled: pulled.iter().map(|u| (*u).to_string()).collect(),
            device: device.map(Path::to_path_buf),
        }
    }

    fn dropin(run: &Path, unit: &str) -> PathBuf {
        run.join(dropin_dir(unit)).join(SKIP_DROPIN_NAME)
    }

    #[test]
    fn a_skip_writes_a_dropin_whose_condition_never_holds_for_every_unit() {
        use std::os::unix::fs::PermissionsExt;
        let run = tempfile::tempdir().unwrap();
        let device = run.path().join("disk");
        fs::write(&device, "").unwrap();
        let skips = [
            skip(
                &["srv-data.mount"],
                &[
                    "systemd-fsck@dev-vdb1.service",
                    "systemd-makefs@dev-vdb1.service",
                ],
                Some(&device),
            ),
            skip(&["boot.automount"], &[], None),
        ];
        let written = skip_units(run.path(), &skips).unwrap();
        assert_eq!(written.len(), 4);
        for unit in [
            "srv-data.mount",
            "systemd-fsck@dev-vdb1.service",
            "systemd-makefs@dev-vdb1.service",
            "boot.automount",
        ] {
            let path = dropin(run.path(), unit);
            assert_eq!(fs::read_to_string(&path).unwrap(), SKIP_TEXT, "{unit}");
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o7777;
            assert_eq!(mode, 0o644, "{unit}: PID 1 would name a private one");
            assert!(
                fs::symlink_metadata(run.path().join(RUNTIME_UNIT_DIR).join(unit)).is_err(),
                "{unit} is not masked"
            );
        }
        // Writing again replaces them with the same text.
        assert_eq!(skip_units(run.path(), &skips).unwrap().len(), 4);

        assert!(remove_skips(run.path(), &skips, &Snapshot::default()));
        assert!(
            fs::read_dir(run.path().join(RUNTIME_UNIT_DIR))
                .unwrap()
                .next()
                .is_none(),
            "every drop-in and its directory went"
        );
        assert!(!remove_skips(run.path(), &skips, &Snapshot::default()));
    }

    #[test]
    fn the_units_of_a_skip_whose_device_is_gone_are_masked_instead() {
        // A skipped mount would wait for its device until the timeout and
        // start emergency mode; the mask keeps it and what it pulls in from
        // starting at all.
        let run = tempfile::tempdir().unwrap();
        let gone = run.path().join("gone");
        let skips = [skip(
            &["srv-data.mount"],
            &["systemd-fsck@dev-vdb1.service"],
            Some(&gone),
        )];
        let written = skip_units(run.path(), &skips).unwrap();
        let mask = run.path().join(RUNTIME_UNIT_DIR).join("srv-data.mount");
        let control = run
            .path()
            .join(runtime_units::RUNTIME_CONTROL_DIR)
            .join("srv-data.mount");
        assert_eq!(written, vec![mask.clone(), control.clone()]);
        assert_eq!(fs::read_link(&mask).unwrap(), Path::new("/dev/null"));
        assert!(fs::symlink_metadata(dropin(run.path(), "srv-data.mount")).is_err());
        assert!(
            fs::symlink_metadata(run.path().join(dropin_dir("systemd-fsck@dev-vdb1.service")))
                .is_err(),
            "nothing for the units it pulls in"
        );

        assert!(remove_skips(run.path(), &skips, &Snapshot::default()));
        assert!(fs::symlink_metadata(&mask).is_err());
        assert!(fs::symlink_metadata(&control).is_err());
    }

    #[test]
    fn a_bad_name_or_a_linked_dropin_directory_writes_nothing() {
        let run = tempfile::tempdir().unwrap();
        let bad = [
            skip(&["srv-data.mount"], &[], None),
            skip(&["boot.automount"], &["../escape.service"], None),
        ];
        assert!(skip_units(run.path(), &bad).is_err());
        assert!(!run.path().join("systemd").exists());

        // A drop-in directory that is a link into a directory the scrub never
        // enters: a drop-in written there would outlive the session.
        let elsewhere = run.path().join("udev/elsewhere");
        fs::create_dir_all(&elsewhere).unwrap();
        fs::create_dir_all(run.path().join(RUNTIME_UNIT_DIR)).unwrap();
        std::os::unix::fs::symlink(&elsewhere, run.path().join(dropin_dir("srv-data.mount")))
            .unwrap();
        assert!(skip_units(run.path(), &[skip(&["srv-data.mount"], &[], None)]).is_err());
        assert!(fs::read_dir(&elsewhere).unwrap().next().is_none());
    }

    #[test]
    fn the_decoy_s_own_dropins_stay() {
        // The decoy has drop-ins of its own for the mount: its directory and
        // files stay, and only the skip goes.
        let run = tempfile::tempdir().unwrap();
        let dir = run.path().join(dropin_dir("srv-data.mount"));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("50-local.conf"), "[Mount]\nTimeoutSec=5\n").unwrap();
        let kept = Snapshot::take(run.path());
        let skips = [skip(&["srv-data.mount"], &[], None)];
        skip_units(run.path(), &skips).unwrap();
        assert!(remove_skips(run.path(), &skips, &kept));
        assert!(fs::symlink_metadata(dir.join(SKIP_DROPIN_NAME)).is_err());
        assert_eq!(
            fs::read_to_string(dir.join("50-local.conf")).unwrap(),
            "[Mount]\nTimeoutSec=5\n"
        );

        // A file of that name the decoy had, or one that does not skip, stays
        // even without a snapshot.
        fs::write(dir.join(SKIP_DROPIN_NAME), "[Unit]\nDescription=own\n").unwrap();
        assert!(!remove_skips(run.path(), &skips, &Snapshot::default()));
        assert!(dir.join(SKIP_DROPIN_NAME).exists());
    }
}
