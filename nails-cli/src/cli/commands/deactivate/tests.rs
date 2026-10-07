// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::execute;
use crate::cli::args::DeactivateArgs;
use crate::cli::output::{ExitStatus, OutputMode, OutputSettings};

fn json() -> OutputSettings {
    OutputSettings {
        mode: OutputMode::Json,
        ..OutputSettings::default()
    }
}

#[test]
fn outside_a_hidden_session_deactivate_refuses_with_invalid_state() {
    // The test process runs on its host's own root, never in a hidden root.
    let config = tempfile::tempdir().unwrap();
    let missing = config.path().join("absent.toml");
    for args in [
        DeactivateArgs::default(),
        DeactivateArgs {
            yes: true,
            poweroff: true,
        },
    ] {
        let status = execute(
            &json(),
            &nails_core::RuntimeEnv::default(),
            &args,
            Some(&missing),
        );
        assert_eq!(status, ExitStatus::InvalidState, "{args:?}");
    }
}
