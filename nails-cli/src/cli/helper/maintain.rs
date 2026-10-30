// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The operations that look at or lay out the hidden volume: verify, each step
//! of the rehearsal, and init (a plan and an apply).
//!
//! Each runs the CLI's own handler under `--json`, so the window gets the
//! CLI's envelope and exit code. The paths they take come from the window and
//! reach the engine as the CLI's arguments would; the decoder has checked that
//! each is absolute and holds no control character.

use std::path::{Path, PathBuf};

use nails_api::protocol::{
    InitArgs, InitPlanData, RehearsePlantArgs, RehearseScanArgs, VerifyArgs,
};
use nails_core::RuntimeEnv;
use nails_core::app::init::HardwareBootstrap;

use super::ops::{Engine, Planned, captured, json_settings};
use super::session::Answer;
use crate::cli::args::RehearseStep;
use crate::cli::args::{RehearseArgs, RehearsePlantArgs as CliPlant, RehearseScanArgs as CliScan};
use crate::cli::commands;

/// `nails verify`.
pub(super) fn verify(env: &RuntimeEnv, args: &VerifyArgs, config: Option<&Path>) -> Answer {
    let settings = json_settings();
    let args = crate::cli::args::VerifyArgs {
        deep: args.deep,
        offline: args.offline,
        root: args.root.as_ref().map(PathBuf::from),
        examiner: args.examiner,
        disk: args.disk.as_ref().map(PathBuf::from),
    };
    captured("verify", || {
        commands::verify::execute(&settings, env, &args, config)
    })
}

/// The CLI's `rehearse plant` step for `args`.
pub(super) fn plant_step(args: &RehearsePlantArgs) -> RehearseStep {
    RehearseStep::Plant(CliPlant {
        user: args.user.clone(),
    })
}

/// The CLI's `rehearse scan` step for `args`.
pub(super) fn scan_step(args: &RehearseScanArgs) -> RehearseStep {
    let paths = |paths: &[String]| paths.iter().map(PathBuf::from).collect();
    RehearseStep::Scan(CliScan {
        devices: paths(&args.devices),
        offline: args.offline,
        images: paths(&args.images),
        token_file: args.token_file.as_ref().map(PathBuf::from),
        allow_same_boot: args.allow_same_boot,
        max_bytes: args.max_bytes,
    })
}

/// One step of `nails rehearse`.
pub(super) fn rehearse(env: &RuntimeEnv, step: RehearseStep, config: Option<&Path>) -> Answer {
    let settings = json_settings();
    let args = RehearseArgs { step: Some(step) };
    captured("rehearse", || {
        commands::rehearse::execute(&settings, env, &args, config)
    })
}

/// The CLI's `init` arguments for `args`.
fn init_args(args: &InitArgs) -> crate::cli::args::InitArgs {
    crate::cli::args::InitArgs {
        path: PathBuf::from(&args.path),
        allow_decoy_storage: args.allow_decoy_storage,
        hardware_config: args.hardware_config.as_ref().map(PathBuf::from),
        no_hardware_config: args.no_hardware_config,
    }
}

impl Engine<'_> {
    /// The plan half of `nails init`: every precondition that can be read,
    /// with nothing written. A failing one answers as the CLI does and keeps
    /// nothing. Init takes the hidden volume from its arguments, never from
    /// the helper's configuration.
    pub(super) fn init_plan(&mut self, args: &InitArgs) -> Answer {
        let args = init_args(args);
        let plan = match commands::init::plan(&nails_core::RealFilesystem, &args) {
            Ok(plan) => plan,
            Err(failure) => {
                return captured("init", || commands::init::report_failure(true, failure));
            }
        };
        let (hardware_config, skipped) = match plan.bootstrap {
            HardwareBootstrap::From(path) => (Some(path.display().to_string()), None),
            HardwareBootstrap::Skip(why) => (None, Some(why)),
        };
        let path = args.path.display().to_string();
        let warnings = plan.warnings;
        self.hold("init", Planned::Init(args), |token| InitPlanData {
            path,
            hardware_config,
            skipped,
            warnings,
            token,
        })
    }
}

/// The apply half of `nails init`, as the CLI runs it: the preconditions are
/// checked again, and only then is the layout written.
pub(super) fn init_apply(args: &crate::cli::args::InitArgs) -> Answer {
    let settings = json_settings();
    captured("init", || {
        commands::init::run(&settings, &nails_core::RealFilesystem, args)
    })
}

#[cfg(test)]
#[path = "maintain_tests.rs"]
mod tests;
