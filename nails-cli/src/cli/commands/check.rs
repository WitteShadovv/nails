// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Check command handler.
//!
//! A readiness check that leaves nothing behind. It loads the configuration,
//! then calls the [`readiness`](nails_core::app::readiness) operation, which
//! builds the same pre-flight registry activation would run, runs it without
//! staging anything (its only writes are the probes on the hidden volume, which
//! remove what they write), and gathers the effective configuration, the
//! overlay targets, how the session would be handled and which NixOS profile
//! would be built. `activate --dry-run` is a thin alias for this command, so
//! the two always agree.
//!
//! A root the attach gate refuses is reported first, on stderr and in the words
//! `init` and `activate` use, before any check runs and also when the checks
//! cannot be assembled; then the readiness report follows. Under `--json` the
//! refusal is the report's `refusal`.

use std::io::Write;
use std::path::Path;

use nails_core::app::readiness::ReadinessReport;
use nails_core::{CliOverrides, PreflightOptions};

use crate::cli::args::CheckArgs;
use crate::cli::output::check::{print_check_human, print_check_json};
use crate::cli::output::envelope::{ErrorBody, report_error, write_human_error};
use crate::cli::output::{ExitStatus, OutputSettings};

/// The command name used in the JSON envelope and error reports.
const COMMAND: &str = "check";

/// Execute the `check` command.
///
/// Returns [`ExitStatus::Ok`] when every check passed (warnings allowed),
/// [`ExitStatus::PreflightRefused`] when any check failed,
/// [`ExitStatus::Config`] when the configuration file could not be loaded, and
/// [`ExitStatus::Failed`] when the checks could not be assembled.
pub fn execute(
    settings: &OutputSettings,
    env: &nails_core::RuntimeEnv,
    args: &CheckArgs,
    config_override: Option<&Path>,
) -> ExitStatus {
    let json = settings.is_json();

    // The human surface prints the attach-gate refusal first, on stderr and in
    // the words `init` and `activate` use: before the checks run (and log), and
    // also when they cannot be assembled. Under `--json` it is the report's
    // `refusal` field.
    let refusal_first = |error: &ErrorBody| {
        if !json {
            write_human_error(&mut std::io::stderr().lock(), error);
        }
    };
    let report = match readiness_report(env, args, config_override, refusal_first) {
        Ok(report) => report,
        Err((status, error)) => return report_error(json, COMMAND, status, error),
    };

    if json {
        print_check_json(&report);
    } else {
        print_check_human(&report, settings.stdout_style());
    }
    let _ = std::io::stdout().flush();
    exit_status(&report)
}

/// The exit status of a readiness report: [`ExitStatus::Ok`] when every check
/// passed (warnings allowed), [`ExitStatus::PreflightRefused`] when any failed.
pub(crate) fn exit_status(report: &ReadinessReport) -> ExitStatus {
    if report.ready {
        ExitStatus::Ok
    } else {
        ExitStatus::PreflightRefused
    }
}

/// Load the configuration and run the readiness checks of `check`, handing
/// `refusal` the attach gate's refusal (if any) before the checks run.
///
/// The error is the exit status and body to report: [`ExitStatus::Config`]
/// when the configuration file could not be loaded, [`ExitStatus::Failed`]
/// when the checks could not be assembled. The CLI and the window's helper
/// both run `check` through here, so they cannot judge a host differently.
pub(crate) fn readiness_report(
    env: &nails_core::RuntimeEnv,
    args: &CheckArgs,
    config_override: Option<&Path>,
    refusal: impl FnOnce(&ErrorBody),
) -> Result<ReadinessReport, (ExitStatus, ErrorBody)> {
    let mut loaded = super::resolve_config(config_override).map_err(|error| {
        (
            ExitStatus::Config,
            super::config_error_body(&error, COMMAND),
        )
    })?;
    loaded.apply_cli_overrides(&CliOverrides {
        nixos_flake: args.nixos_flake.clone(),
    });

    let config_path = loaded.path.clone();
    let config = loaded.into_config();
    let options = preflight_options(args);

    let readiness = nails_core::app::readiness::prepare(env, &config_path, config, &options);
    if let Some(error) = readiness.refusal() {
        refusal(error);
    }
    readiness
        .run()
        .map_err(|e| (ExitStatus::Failed, assembly_error(&e)))
}

/// The error body of checks that could not be assembled, with the error's
/// next step where it has one: for a lookup the automount guard did not
/// make, the line that says to mount the point and run `check` again.
fn assembly_error(error: &nails_core::NailsError) -> ErrorBody {
    ErrorBody::new("check_error", format!("could not assemble checks: {error}"))
        .with_hint(error.hint().unwrap_or_default())
}

/// The pre-flight options of `check`: what activation builds from the same
/// flags (`EnterOptions::preflight`), so both run the same checks.
pub(super) fn preflight_options(args: &CheckArgs) -> PreflightOptions {
    PreflightOptions {
        overlay_only: args.overlay_only,
        allow_persistent_decoy: args.allow_persistent_decoy,
        allow_decoy_storage: args.allow_decoy_storage,
        allow_discards: args.allow_discards,
        ..PreflightOptions::default()
    }
}

#[cfg(test)]
mod tests {
    use super::assembly_error;
    use crate::cli::output::envelope::{error_envelope, write_human_error};
    use nails_core::NailsError;
    use nails_core::error::Skip;
    use std::path::PathBuf;

    /// Checks that cannot be assembled because the automount guard did not
    /// look up a path, such as an explicit flake behind an automount point
    /// that nothing is mounted on yet, name the path and the point, and say
    /// to mount the point and run `check` again: for a person and in JSON.
    #[test]
    fn a_lookup_the_guard_did_not_make_says_to_mount_the_point() {
        let point = PathBuf::from("/srv/flake");
        let error = NailsError::NotLookedUp {
            path: PathBuf::from("/srv/flake/flake.nix"),
            reason: Skip::Automount {
                point: point.clone(),
            },
        };
        let fix = nails_core::filesystem::automount::mount_fix(&[point.as_path()]);
        let body = assembly_error(&error);
        assert_eq!(body.code, "check_error");
        assert_eq!(
            body.message,
            format!(
                "could not assemble checks: NAILS does not look up /srv/flake/flake.nix, since \
                 the lookup would mount the automount point /srv/flake\n{fix}"
            )
        );

        let mut human = Vec::new();
        write_human_error(&mut human, &body);
        assert_eq!(
            String::from_utf8(human).unwrap(),
            format!(
                "error: could not assemble checks: NAILS does not look up /srv/flake/flake.nix, \
                 since the lookup would mount the automount point /srv/flake\n  {fix}\n"
            )
        );
        let json = serde_json::to_value(error_envelope("check", body)).unwrap();
        assert_eq!(json["ok"], false, "{json}");
        assert_eq!(json["error"]["code"], "check_error", "{json}");
        assert!(
            json["error"]["message"]
                .as_str()
                .is_some_and(|message| message.ends_with(&format!("\n{fix}"))),
            "{json}"
        );
    }

    /// An error with no next step is reported as it was, with nothing added.
    #[test]
    fn an_error_without_a_next_step_gets_no_hint() {
        let error = NailsError::InvalidState("the state file is corrupt".into());
        assert_eq!(error.hint(), None);
        let body = assembly_error(&error);
        assert_eq!(body.message, format!("could not assemble checks: {error}"));
    }
}
