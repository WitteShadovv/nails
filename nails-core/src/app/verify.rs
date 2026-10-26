// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The `verify` operation: scan for the artifacts a NAILS session can leave.
//!
//! It reads the recorded state for the report, builds the verifier with the
//! resolved configuration and the chosen scan (live, or offline under a mounted
//! decoy image with the examiner's view) and runs it. The result is a
//! [`VerifyResult`] a front end renders; this never prints.

use std::path::PathBuf;

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
/// Reads the state file status for the report (missing, present with its
/// recorded state, or an error), builds the verifier and runs it. An error
/// means the verification itself could not run. Options that do not go
/// together are refused, never dropped: an offline scan without the root of
/// its image, which would run as a scan of the live host, and an image root
/// or the examiner's view without an offline scan, or the examiner's disk
/// without the examiner's view, which would be ignored.
pub fn verify(env: &RuntimeEnv, config: Config, options: &VerifyOptions) -> Result<VerifyResult> {
    if let Some(reason) = refused_combination(options) {
        return Err(crate::NailsError::InvalidArgument(reason.to_string()));
    }
    let state_path = config.state_file_path.clone();
    let (state, state_file_status) = if !state_path.exists() {
        (
            None,
            StateFileStatus::Missing {
                path: state_path.clone(),
            },
        )
    } else {
        match StateFile::load(&state_path) {
            Ok(loaded_state) => {
                let state_name = loaded_state.state.label().to_string();
                (
                    Some(loaded_state),
                    StateFileStatus::Present {
                        path: state_path.clone(),
                        state: state_name,
                    },
                )
            }
            Err(error) => (
                None,
                StateFileStatus::Error {
                    path: state_path.clone(),
                    message: error.to_string(),
                },
            ),
        }
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
        // The state file does not exist. `verify` must report it Missing by the
        // `!state_path.exists()` guard, before ever calling `StateFile::load`.
        // Deleting the `!` sends a missing path down the load branch instead,
        // where `StateFile::load` collapses an absent file to the inactive
        // default and the status comes back `Present` rather than `Missing`.
        let root = tempfile::tempdir().unwrap();
        let config = config_rooted_at(root.path());
        let expected_path = config.state_file_path.clone();

        let result = verify(
            &RuntimeEnv::default(),
            config,
            &offline_options(root.path()),
        )
        .unwrap();

        match result.state_file_status {
            StateFileStatus::Missing { path } => assert_eq!(path, expected_path),
            other => panic!("a missing state file must be reported Missing, got {other:?}"),
        }
    }

    #[test]
    fn a_present_state_file_is_reported_present_with_its_state() {
        // A valid state file exists, so `verify` takes the load branch and
        // reports it Present with its recorded state label. Deleting the `!`
        // inverts the guard, sending an existing file down the Missing branch.
        let root = tempfile::tempdir().unwrap();
        let config = config_rooted_at(root.path());
        let state_path = config.state_file_path.clone();
        StateFile::default()
            .save_with_custom_root(&state_path, root.path())
            .unwrap();
        let expected_label = StateFile::default().state.label().to_string();

        let result = verify(
            &RuntimeEnv::default(),
            config,
            &offline_options(root.path()),
        )
        .unwrap();

        match result.state_file_status {
            StateFileStatus::Present { path, state } => {
                assert_eq!(path, state_path);
                assert_eq!(state, expected_label);
            }
            other => panic!("an existing state file must be reported Present, got {other:?}"),
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
