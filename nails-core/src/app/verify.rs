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
/// means the verification itself could not run.
pub fn verify(env: &RuntimeEnv, config: Config, options: &VerifyOptions) -> Result<VerifyResult> {
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

#[cfg(test)]
#[path = "verify_tests.rs"]
mod tests;
