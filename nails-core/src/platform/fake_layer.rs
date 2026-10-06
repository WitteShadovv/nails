// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! A recording [`ConfigLayer`] for core tests.
//!
//! Lets manager tests drive the declarative half of activation (staging, the
//! base-config gate, the post-`/etc` import, the build and switch, the restore)
//! without any NixOS files on the mock host: each call is recorded, and each
//! step's outcome is set by the test. Clones share one record, so a test keeps a
//! handle while the manager owns another through a
//! [`FakePlatform`](super::FakePlatform).

use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use super::{ConfigLayer, ConfigPlan, RestoreOutcome};
use crate::filesystem::Filesystem;
use crate::preflight::{CheckResult, PreFlightCheck};
use crate::process::ProcessRunner;
use crate::{NailsError, Result, Verbosity};

/// Name of the fake base-config gate in check results.
pub const FAKE_BASE_REFERENCE_CHECK: &str = "fake-base-reference";
/// Name of the fake hidden-config check in check results.
pub const FAKE_CONFIG_CHECK: &str = "fake-config-layer";

/// One call the manager made into the layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LayerCall {
    /// [`ConfigLayer::stage`], with its `overlay_only` argument.
    Stage {
        /// The `overlay_only` argument.
        overlay_only: bool,
    },
    /// [`ConfigLayer::stage_symlink`].
    StageSymlink,
    /// [`ConfigLayer::inject_import`], noting whether `/etc` was mounted at the
    /// time, so ordering against the overlay mounts is observable.
    InjectImport {
        /// Whether `/etc` was mounted when the import ran.
        etc_mounted: bool,
    },
    /// [`ConfigLayer::plan`].
    Plan,
    /// [`ConfigLayer::apply`], with the fast-path toplevel it was handed.
    Apply {
        /// The fast-path toplevel argument.
        fast_path_toplevel: Option<String>,
    },
    /// [`ConfigLayer::restore`], with its `reboot_follows` argument.
    Restore {
        /// The `reboot_follows` argument.
        reboot_follows: bool,
    },
}

/// The verdict a fake check reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FakeVerdict {
    /// `Ok(CheckResult::Pass)`.
    Pass,
    /// `Ok(CheckResult::Fail)` with this message.
    Fail(String),
    /// `Err(NailsError::IoError)` with this message: the check could not run (an
    /// unreadable base configuration, say).
    Error(String),
}

#[derive(Debug)]
struct State {
    calls: Vec<LayerCall>,
    base_reference: FakeVerdict,
    config_check: FakeVerdict,
    stage_error: Option<String>,
    inject_error: Option<String>,
    apply_error: Option<String>,
    applied_toplevel: Option<String>,
    fast_path_toplevel: Option<String>,
}

/// A config layer whose every step is recorded and scripted by the test.
#[derive(Debug, Clone)]
pub struct FakeConfigLayer {
    state: Arc<Mutex<State>>,
}

impl Default for FakeConfigLayer {
    fn default() -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                calls: Vec::new(),
                base_reference: FakeVerdict::Pass,
                config_check: FakeVerdict::Pass,
                stage_error: None,
                inject_error: None,
                apply_error: None,
                applied_toplevel: None,
                fast_path_toplevel: None,
            })),
        }
    }
}

impl FakeConfigLayer {
    /// A layer whose every step succeeds and whose checks pass.
    pub fn new() -> Self {
        Self::default()
    }

    fn state(&self) -> MutexGuard<'_, State> {
        // A test that panicked while holding the lock leaves the record usable.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Set the base-config gate's verdict.
    pub fn with_base_reference(self, verdict: FakeVerdict) -> Self {
        self.state().base_reference = verdict;
        self
    }

    /// Set the hidden-config check's verdict.
    pub fn with_config_check(self, verdict: FakeVerdict) -> Self {
        self.state().config_check = verdict;
        self
    }

    /// Make [`ConfigLayer::stage`] fail with this message.
    pub fn with_stage_error(self, message: impl Into<String>) -> Self {
        self.state().stage_error = Some(message.into());
        self
    }

    /// Make [`ConfigLayer::inject_import`] fail with this message.
    pub fn with_inject_error(self, message: impl Into<String>) -> Self {
        self.state().inject_error = Some(message.into());
        self
    }

    /// Make [`ConfigLayer::apply`] fail with this message (as a NixOS error).
    pub fn with_apply_error(self, message: impl Into<String>) -> Self {
        self.state().apply_error = Some(message.into());
        self
    }

    /// The toplevel a successful [`ConfigLayer::apply`] reports.
    pub fn with_applied_toplevel(self, toplevel: impl Into<String>) -> Self {
        self.state().applied_toplevel = Some(toplevel.into());
        self
    }

    /// The fast-path toplevel [`ConfigLayer::plan`] carries forward.
    pub fn with_fast_path(self, toplevel: impl Into<String>) -> Self {
        self.state().fast_path_toplevel = Some(toplevel.into());
        self
    }

    /// Every call recorded so far, in order.
    pub fn calls(&self) -> Vec<LayerCall> {
        self.state().calls.clone()
    }

    fn record(&self, call: LayerCall) {
        self.state().calls.push(call);
    }
}

/// A pre-flight check reporting a fixed verdict.
#[derive(Debug)]
struct FakeCheck {
    name: &'static str,
    verdict: FakeVerdict,
}

impl<F: Filesystem> PreFlightCheck<F> for FakeCheck {
    fn name(&self) -> &'static str {
        self.name
    }

    fn description(&self) -> &'static str {
        "Scripted config-layer check"
    }

    fn run(&self, _fs: &F) -> Result<CheckResult> {
        match &self.verdict {
            FakeVerdict::Pass => Ok(CheckResult::Pass(format!("{} passed", self.name))),
            FakeVerdict::Fail(message) => Ok(CheckResult::fail(message.clone())),
            FakeVerdict::Error(message) => {
                Err(NailsError::io("", std::io::Error::other(message.clone())))
            }
        }
    }
}

fn scripted(error: &Option<String>) -> Result<()> {
    match error {
        Some(message) => Err(NailsError::NixOSError(message.clone())),
        None => Ok(()),
    }
}

impl<F: Filesystem> ConfigLayer<F> for FakeConfigLayer {
    fn base_reference_check(&self, _hidden_volume_root: &Path) -> Box<dyn PreFlightCheck<F>> {
        Box::new(FakeCheck {
            name: FAKE_BASE_REFERENCE_CHECK,
            verdict: self.state().base_reference.clone(),
        })
    }

    fn preflight_checks(&self, _hidden_volume_root: &Path) -> Vec<Box<dyn PreFlightCheck<F>>> {
        vec![Box::new(FakeCheck {
            name: FAKE_CONFIG_CHECK,
            verdict: self.state().config_check.clone(),
        })]
    }

    fn stage(&self, _fs: &F, _hidden_volume_root: &Path, overlay_only: bool) -> Result<()> {
        self.record(LayerCall::Stage { overlay_only });
        scripted(&self.state().stage_error)
    }

    fn stage_symlink(&self, _fs: &F, _hidden_volume_root: &Path) -> Result<()> {
        self.record(LayerCall::StageSymlink);
        scripted(&self.state().stage_error)
    }

    fn inject_import(&self, fs: &F) -> Result<()> {
        let etc_mounted = fs.is_mounted(Path::new("/etc")).unwrap_or(false);
        self.record(LayerCall::InjectImport { etc_mounted });
        scripted(&self.state().inject_error)
    }

    fn plan(
        &self,
        _fs: &F,
        _hidden_volume_root: &Path,
        _stored_fingerprint: Option<&str>,
        _stored_toplevel: Option<&str>,
        _flake_ref: Option<&str>,
        _config_name: Option<&str>,
        _flake_source: Option<&Path>,
        _verbosity: Verbosity,
    ) -> Result<ConfigPlan> {
        self.record(LayerCall::Plan);
        Ok(ConfigPlan {
            fast_path_toplevel: self.state().fast_path_toplevel.clone(),
            fingerprint: "fake-fingerprint".to_string(),
        })
    }

    fn apply(
        &self,
        _fs: &F,
        _builder: &crate::nixos::NixOSBuilder,
        fast_path_toplevel: Option<&str>,
        _verbosity: Verbosity,
    ) -> Result<Option<String>> {
        self.record(LayerCall::Apply {
            fast_path_toplevel: fast_path_toplevel.map(str::to_string),
        });
        let state = self.state();
        scripted(&state.apply_error)?;
        Ok(state.applied_toplevel.clone())
    }

    fn restore(
        &self,
        _fs: &F,
        _runner: &dyn ProcessRunner,
        reboot_follows: bool,
        _dispatch_reboot: &dyn Fn() -> Result<()>,
        _env: &crate::RuntimeEnv,
    ) -> Result<RestoreOutcome> {
        self.record(LayerCall::Restore { reboot_follows });
        Ok(RestoreOutcome::SymlinkRestored)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::MockFilesystem;

    #[test]
    fn clones_share_one_record_and_script() {
        let layer = FakeConfigLayer::new().with_inject_error("boom");
        let handle = layer.clone();
        let fs = MockFilesystem::new();

        ConfigLayer::<MockFilesystem>::stage(&layer, &fs, Path::new("/h"), false).unwrap();
        let err = ConfigLayer::<MockFilesystem>::inject_import(&layer, &fs).unwrap_err();
        assert!(err.to_string().contains("boom"));
        assert_eq!(
            handle.calls(),
            vec![
                LayerCall::Stage {
                    overlay_only: false
                },
                LayerCall::InjectImport { etc_mounted: false },
            ]
        );
    }

    #[test]
    fn checks_report_their_scripted_verdicts() {
        let fs = MockFilesystem::new();
        let layer = FakeConfigLayer::new()
            .with_base_reference(FakeVerdict::Fail("dirty".into()))
            .with_config_check(FakeVerdict::Error("unreadable".into()));

        let gate = ConfigLayer::<MockFilesystem>::base_reference_check(&layer, Path::new("/h"));
        assert_eq!(gate.name(), FAKE_BASE_REFERENCE_CHECK);
        assert!(gate.run(&fs).unwrap().is_fail());

        let checks = ConfigLayer::<MockFilesystem>::preflight_checks(&layer, Path::new("/h"));
        assert_eq!(checks.len(), 1);
        assert!(checks[0].run(&fs).is_err());
    }
}
