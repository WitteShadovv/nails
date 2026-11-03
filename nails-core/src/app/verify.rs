// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The `verify` operation: scan for the artifacts a NAILS session can leave.
//!
//! It reads the recorded state for the report, builds the verifier with the
//! resolved configuration and the chosen scan (live, or offline under a mounted
//! decoy image with the examiner's view) and runs it. The result is a
//! [`VerifyResult`] a front end renders; this never prints.

use std::path::{Path, PathBuf};

use crate::{
    Config, ExaminerOptions, RealFilesystem, Result, RuntimeEnv, StateFile, StateFileStatus,
    Verifier, VerifyResult,
};

/// What `verify` should scan.
#[derive(Debug, Default, Clone)]
pub struct VerifyOptions {
    /// Deep scan (slower, more thorough).
    pub deep: bool,
    /// Scan a read-only mounted decoy image under `root` instead of the live host.
    pub offline: bool,
    /// The mounted decoy image root for `offline`.
    pub root: Option<PathBuf>,
    /// Run the examiner's view over the offline image.
    pub examiner: bool,
    /// The raw disk or image behind the mounted root, for the examiner's
    /// partition-level checks.
    pub disk: Option<PathBuf>,
}

/// Run a verification for the resolved configuration and options.
///
/// For a live scan it reads the state file status for the report (missing,
/// present with its recorded state, or an error); an offline scan leaves the
/// state file out ([`StateFileStatus::NotChecked`]). Then it builds the
/// verifier and runs it. An error means the verification itself could not
/// run. Options that do not go together are refused, never dropped: an
/// offline scan without the root of its image, which would run as a scan of
/// the live host, and an image root or the examiner's view without an offline
/// scan, or the examiner's disk without the examiner's view, which would be
/// ignored. The verifier refuses an image root that holds nothing to scan
/// ([`NailsError::RefusedOfflineRoot`](crate::NailsError::RefusedOfflineRoot)),
/// which would read as a clean image.
pub fn verify(env: &RuntimeEnv, config: Config, options: &VerifyOptions) -> Result<VerifyResult> {
    if let Some(reason) = refused_combination(options) {
        return Err(crate::NailsError::InvalidArgument(reason.to_string()));
    }
    // The state file is the record of this computer's sessions on the hidden
    // volume, not part of a decoy image: an offline scan, run from a hidden
    // session as often as not, would report the live session's record in a
    // report about the image.
    let (state, state_file_status) = if options.offline {
        (None, StateFileStatus::NotChecked)
    } else {
        read_state(&config.state_file_path)
    };

    let mut verifier = Verifier::with_config(RealFilesystem, config, state, state_file_status)
        .with_runtime_env(env);
    if options.offline
        && let Some(ref root) = options.root
    {
        verifier = verifier.offline_under(root.clone());
        if options.examiner {
            verifier = verifier.with_examiner(ExaminerOptions {
                disk: options.disk.clone(),
                ..ExaminerOptions::default()
            });
        }
    }
    verifier.run(options.deep)
}

/// The state file at `state_path` for the report of a live scan: missing,
/// present with its recorded state, or an error, with the state itself when
/// it loaded.
fn read_state(state_path: &Path) -> (Option<StateFile>, StateFileStatus) {
    if !state_path.exists() {
        return (
            None,
            StateFileStatus::Missing {
                path: state_path.to_path_buf(),
            },
        );
    }
    match StateFile::load(state_path) {
        Ok(loaded_state) => {
            let state_name = loaded_state.state.label().to_string();
            (
                Some(loaded_state),
                StateFileStatus::Present {
                    path: state_path.to_path_buf(),
                    state: state_name,
                },
            )
        }
        Err(error) => (
            None,
            StateFileStatus::Error {
                path: state_path.to_path_buf(),
                message: error.to_string(),
            },
        ),
    }
}

/// Why `options` cannot run as given, if they cannot.
fn refused_combination(options: &VerifyOptions) -> Option<&'static str> {
    if options.offline && options.root.is_none() {
        Some("an offline scan needs the root of the mounted decoy image")
    } else if !options.offline && options.root.is_some() {
        Some("the root of a mounted decoy image is scanned only offline")
    } else if !options.offline && options.examiner {
        Some("the examiner's view runs only over an offline scan")
    } else if !options.examiner && options.disk.is_some() {
        Some("the disk behind the image is read only for the examiner's view")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A config whose state file and logs live under `root`, so `verify` reads
    /// and writes only inside the temp dir.
    fn config_rooted_at(root: &std::path::Path) -> Config {
        Config {
            hidden_volume_root: root.to_path_buf(),
            state_file_path: root.join("state.json"),
            log_path: root.join("logs"),
            ..Config::test_default()
        }
    }

    /// Give the image at `root` the `etc` folder of a decoy root, without which
    /// an offline scan refuses it.
    fn decoy_root(root: &std::path::Path) {
        std::fs::create_dir_all(root.join("etc")).unwrap();
    }

    /// An offline scan under `root`, which skips every live-host check so the
    /// run stays inside the temp tree.
    fn offline_options(root: &std::path::Path) -> VerifyOptions {
        VerifyOptions {
            offline: true,
            root: Some(root.to_path_buf()),
            ..VerifyOptions::default()
        }
    }

    #[test]
    fn a_missing_state_file_is_reported_as_missing_not_loaded() {
        // The state file does not exist. A live scan must report it Missing by
        // the `!state_path.exists()` guard, before ever calling
        // `StateFile::load`. Deleting the `!` sends a missing path down the
        // load branch instead, where `StateFile::load` collapses an absent
        // file to the inactive default and the status comes back `Present`
        // rather than `Missing`.
        let root = tempfile::tempdir().unwrap();
        let expected_path = config_rooted_at(root.path()).state_file_path;

        let (state, status) = read_state(&expected_path);

        assert!(state.is_none());
        match status {
            StateFileStatus::Missing { path } => assert_eq!(path, expected_path),
            other => panic!("a missing state file must be reported Missing, got {other:?}"),
        }
    }

    #[test]
    fn a_present_state_file_is_reported_present_with_its_state() {
        // A valid state file exists, so a live scan takes the load branch and
        // reports it Present with its recorded state label. Deleting the `!`
        // inverts the guard, sending an existing file down the Missing branch.
        let root = tempfile::tempdir().unwrap();
        let state_path = config_rooted_at(root.path()).state_file_path;
        StateFile::default()
            .save_with_custom_root(&state_path, root.path())
            .unwrap();
        let expected_label = StateFile::default().state.label().to_string();

        let (state, status) = read_state(&state_path);

        assert!(state.is_some());
        match status {
            StateFileStatus::Present { path, state } => {
                assert_eq!(path, state_path);
                assert_eq!(state, expected_label);
            }
            other => panic!("an existing state file must be reported Present, got {other:?}"),
        }
    }

    /// An offline scan reports on a decoy image, and the state file on the
    /// hidden volume is the record of this computer's own session, active
    /// when the scan runs from a hidden session: it is neither read nor
    /// reported, whether it is there, damaged or missing.
    #[test]
    fn an_offline_scan_leaves_the_live_state_file_out() {
        for case in ["active", "damaged", "missing"] {
            let root = tempfile::tempdir().unwrap();
            decoy_root(root.path());
            let config = config_rooted_at(root.path());
            let state_path = &config.state_file_path;
            match case {
                "active" => StateFile {
                    state: crate::SystemState::Active {
                        activated_at: chrono::Utc::now(),
                    },
                    ..StateFile::default()
                }
                .save_with_custom_root(state_path, root.path())
                .unwrap(),
                "damaged" => std::fs::write(state_path, b"{ not a state file").unwrap(),
                _ => {}
            }

            let result = verify(
                &RuntimeEnv::default(),
                config,
                &offline_options(root.path()),
            )
            .unwrap();

            assert_eq!(
                result.state_file_status,
                StateFileStatus::NotChecked,
                "{case}"
            );
        }
    }

    #[test]
    fn an_offline_scan_without_its_image_root_is_refused() {
        // Offline with no root would fall through to a scan of the live host,
        // whose verdict a front end would show as the image's.
        let root = tempfile::tempdir().unwrap();
        let options = VerifyOptions {
            offline: true,
            root: None,
            ..VerifyOptions::default()
        };
        let error = verify(
            &RuntimeEnv::default(),
            config_rooted_at(root.path()),
            &options,
        )
        .unwrap_err();
        assert!(
            matches!(&error, crate::NailsError::InvalidArgument(message)
                if message.contains("root of the mounted decoy image")),
            "{error:?}"
        );
    }

    #[test]
    fn an_image_root_with_nothing_to_scan_is_refused() {
        // A root that does not exist read as a secure image, the examiner's
        // view with no trace, and so did an empty folder, the mount point of
        // an image that was never mounted, and the top level of a btrfs
        // filesystem mounted whole, whose system is in the subvolume @.
        use crate::error::OfflineRootProblem;
        let dir = tempfile::tempdir().unwrap();
        let mount_point = dir.path().join("decoy");
        std::fs::create_dir(&mount_point).unwrap();
        let top = dir.path().join("top");
        std::fs::create_dir_all(top.join("@/etc")).unwrap();
        std::fs::create_dir(top.join("@home")).unwrap();
        for (root, problem) in [
            (dir.path().join("absent"), OfflineRootProblem::Missing),
            (mount_point, OfflineRootProblem::Empty),
            (
                top,
                OfflineRootProblem::NoEtcFolder {
                    subvolumes: Vec::new(),
                },
            ),
        ] {
            let options = VerifyOptions {
                examiner: true,
                ..offline_options(&root)
            };
            let error = verify(
                &RuntimeEnv::default(),
                config_rooted_at(dir.path()),
                &options,
            )
            .unwrap_err();
            assert!(
                matches!(&error, crate::NailsError::RefusedOfflineRoot { root: refused, problem: named }
                    if *refused == root && *named == problem),
                "{error:?}"
            );
        }
    }

    /// An image root, the examiner's view or its disk outside the scan they
    /// belong to is refused, never dropped: the live host's verdict would be
    /// shown as the image's.
    #[test]
    fn options_that_belong_to_an_offline_scan_are_refused_without_it() {
        let root = tempfile::tempdir().unwrap();
        let image = Some(root.path().to_path_buf());
        let disk = Some(root.path().join("decoy.img"));
        for (options, reason) in [
            (
                VerifyOptions {
                    root: image.clone(),
                    ..VerifyOptions::default()
                },
                "scanned only offline",
            ),
            (
                VerifyOptions {
                    examiner: true,
                    ..VerifyOptions::default()
                },
                "runs only over an offline scan",
            ),
            (
                VerifyOptions {
                    disk: disk.clone(),
                    ..offline_options(root.path())
                },
                "only for the examiner's view",
            ),
        ] {
            let error = verify(
                &RuntimeEnv::default(),
                config_rooted_at(root.path()),
                &options,
            )
            .unwrap_err();
            assert!(
                matches!(&error, crate::NailsError::InvalidArgument(message)
                    if message.contains(reason)),
                "{options:?}: {error:?}"
            );
        }
        // The combinations that go together run.
        assert_eq!(refused_combination(&VerifyOptions::default()), None);
        assert_eq!(refused_combination(&offline_options(root.path())), None);
        let examined = VerifyOptions {
            examiner: true,
            disk,
            ..offline_options(root.path())
        };
        assert_eq!(refused_combination(&examined), None);
    }

    #[test]
    fn the_examiner_disk_option_is_wired_through_to_the_audit() {
        // With `examiner` and a `disk` set, the offline run must hand the disk
        // to the examiner, which records the `examiner-disk` check. Dropping the
        // `disk` field from the `ExaminerOptions` literal falls back to the
        // default (`None`), so the disk audit never runs and the check is absent.
        let root = tempfile::tempdir().unwrap();
        decoy_root(root.path());
        let disk_path = root.path().join("decoy.img");
        // A 1 MiB all-zero image: a readable raw source with no partition table
        // and no high-entropy regions, so the audit runs and finds nothing.
        std::fs::write(&disk_path, vec![0u8; 1 << 20]).unwrap();

        let options = VerifyOptions {
            examiner: true,
            disk: Some(disk_path),
            ..offline_options(root.path())
        };

        let result = verify(
            &RuntimeEnv::default(),
            config_rooted_at(root.path()),
            &options,
        )
        .unwrap();

        let report = result
            .examiner
            .expect("an examiner run must produce a report");
        assert!(
            report.checks_run.contains(&"examiner-disk"),
            "the disk audit must run when a disk is given: {:?}",
            report.checks_run
        );
    }
}
