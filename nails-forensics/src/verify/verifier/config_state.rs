// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Config-aware and state-file-aware checks.

use super::*;

impl<F: Filesystem> Verifier<F> {
    /// Check config-specific paths for residual artifacts
    ///
    /// Checks the log directory, hidden volume path and state file location for
    /// any residual NAILS artifacts.
    pub(super) fn check_config_paths(
        &self,
        config: &Config,
        in_session: bool,
    ) -> Result<(Vec<Finding>, usize)> {
        let mut findings = Vec::new();
        let mut paths_checked: usize = 0;

        // When verify runs from the hidden environment with nothing activated
        // (state reads Inactive), the hidden volume being mounted and the state
        // file existing are the *expected* situation, not residue. Flagging them
        // would make every clean run warn about itself, so they are suppressed
        // and an Inactive assertion is recorded instead.
        let host_context_inactive = self
            .state
            .as_ref()
            .is_some_and(|state| matches!(state.state, crate::state::SystemState::Inactive));

        // A decoy-scoped baseline runs while the hidden volume is deliberately
        // attached, and a run inside the hidden session runs on the volume the
        // session uses, so — exactly as for the Inactive host context — its path
        // being accessible and its state file existing are expected, not residue.
        let suppress_hidden_volume = host_context_inactive || self.scope_to_decoy || in_session;

        // 2. Check hidden volume path for accessibility.
        let hidden_vol = &config.hidden_volume_root;
        paths_checked += 1;
        if !suppress_hidden_volume {
            findings.extend(self.hidden_volume_exposure(hidden_vol));
        }

        // 3. Check log directory for remaining logs.
        //
        // A log directory that sits on the hidden volume is the intended,
        // on-volume log location, not decoy-disk residue: those logs live where
        // they belong and are only reachable while the volume is mounted, which
        // the hidden-volume-path finding above already reports. Flagging them
        // here would turn the active log dir into a permanent false positive
        // every time `verify` runs from the hidden environment. Logs whose
        // directory sits outside the hidden root are a real leak onto the decoy
        // disk and are still flagged.
        let log_path = &config.log_path;
        paths_checked += 1;
        let log_is_on_hidden_volume =
            !hidden_vol.as_os_str().is_empty() && log_path.starts_with(hidden_vol);
        let log_dir = if log_is_on_hidden_volume {
            Ok(false)
        } else {
            self.filesystem.path_exists(log_path).and_then(|exists| {
                if exists {
                    self.filesystem.is_directory(log_path)
                } else {
                    Ok(false)
                }
            })
        };
        if let Err(error) = &log_dir {
            findings.push(untold(
                Severity::Warn,
                "config",
                &format!(
                    "Could not tell whether log files are left in the configured log directory {}",
                    log_path.display()
                ),
                log_path,
                error,
            ));
        }
        if matches!(log_dir, Ok(true)) {
            let log_files = self.filesystem.find_files_with_pattern(log_path, "nails")?;
            for log_file in log_files {
                findings.push(
                    Finding::new(
                        Severity::Warn,
                        "config",
                        format!(
                            "Log file found in config log directory: {}",
                            log_file.display()
                        ),
                    )
                    .with_fix_guidance(format!("Delete log file: rm {}", log_file.display())),
                );
            }
        }

        // 4. Check state file location
        let state_path = &config.state_file_path;
        paths_checked += 1;
        let state_file = if suppress_hidden_volume {
            Ok(false)
        } else {
            self.filesystem.path_exists(state_path)
        };
        match state_file {
            Ok(true) => findings.push(
                Finding::new(
                    Severity::Warn,
                    "config",
                    format!(
                        "State file exists at configured path: {}",
                        state_path.display()
                    ),
                )
                .with_fix_guidance("State file should only exist on hidden volume when active"),
            ),
            Ok(false) => {}
            Err(error) => findings.push(untold(
                Severity::Warn,
                "config",
                &format!(
                    "Could not tell whether a state file exists at the configured path {}",
                    state_path.display()
                ),
                state_path,
                &error,
            )),
        }

        if self.scope_to_decoy {
            findings.push(Finding::new(
                Severity::Info,
                "context",
                "Decoy-scoped baseline; findings about the hidden volume itself are suppressed \
                 (it is deliberately attached for the activation in progress)",
            ));
        } else if host_context_inactive {
            findings.push(Finding::new(
                Severity::Info,
                "context",
                "State reads Inactive; findings about the hidden volume itself are suppressed \
                 (its presence is expected while mounted)",
            ));
        }

        Ok((findings, paths_checked))
    }

    /// The finding for the hidden volume path `root`, when a genuine
    /// hidden-volume location is accessible there.
    ///
    /// Only a *genuine* hidden-volume location is an exposure. A genuine
    /// location is one of:
    ///   * an **explicitly configured** root (from a config file or a CLI
    ///     override) — something the operator pointed NAILS at; or
    ///   * a root that is a **genuinely attached** hidden volume: mounted on
    ///     its own device and carrying a NAILS marker (`state.json` or
    ///     `config/nails.toml`), the attach gate the rest of NAILS already
    ///     uses for write safety.
    ///
    /// When NAILS runs with no config (and no `--hidden-volume-root`), the
    /// root *defaults* to the binary's own install directory
    /// (`derive_hidden_volume_root`). For a read-only nix-store install that
    /// is a store path like `/nix/store/…-nails-…/bin`, which exists and —
    /// with a dedicated store image — even sits on its own device, yet is the
    /// program's install location, not a mounted hidden volume. Flagging it
    /// reported the install dir as an accessible hidden volume, a false
    /// positive that made a clean post-deactivation `verify --deep` exit
    /// non-zero. The marker requirement is what separates that read-only
    /// store dir (no marker) from a real hidden volume the binary lives on
    /// (which carries a marker), so a defaulted root is reported only when it
    /// is a genuinely attached, marked volume.
    ///
    /// A defaulted root the gate cannot tell about counts as genuine, with
    /// why in the finding, and a root that cannot be looked up is one verify
    /// cannot tell is accessible ([`untold`]).
    fn hidden_volume_exposure(&self, root: &Path) -> Option<Finding> {
        let genuine = if *root == crate::config::derive_hidden_volume_root() {
            self.attached_and_marked(root)
        } else {
            Ok(true)
        };
        if genuine == Ok(false) {
            return None;
        }
        match self.filesystem.path_exists(root) {
            Ok(true) => {}
            Ok(false) => return None,
            Err(error) => {
                return Some(untold(
                    Severity::Warn,
                    "config",
                    &format!(
                        "Could not tell whether the hidden volume path {} is accessible",
                        root.display()
                    ),
                    root,
                    &error,
                ));
            }
        }
        let message = match genuine {
            Ok(_) => format!("Hidden volume path is accessible: {}", root.display()),
            Err(reason) => format!(
                "Hidden volume path is accessible: {}, and verify could not tell whether it is a \
                 mounted hidden volume or only the folder the program runs from: {reason}",
                root.display()
            ),
        };
        Some(
            Finding::new(Severity::Warn, "config", message)
                .with_fix_guidance("Ensure hidden volume is unmounted when not in use"),
        )
    }

    /// Whether `root` is a hidden volume the attach gate takes for attached,
    /// and that carries a NAILS marker, as
    /// [`HiddenRoot::verify_attached`](crate::hidden_root::HiddenRoot::verify_attached)
    /// decides. `Err` with the reason where the gate cannot tell: the root,
    /// the mount table or what tells where the root lives cannot be read, or
    /// neither marker can be looked up.
    fn attached_and_marked(&self, root: &Path) -> std::result::Result<bool, String> {
        use crate::hidden_root::{Assessment, HiddenRoot, RefusalKind};
        match HiddenRoot::assess(&self.filesystem, root) {
            Err(error) => Err(error.to_string()),
            Ok(Assessment::Refused(refusal)) => match refusal.kind {
                RefusalKind::LookupFailed { .. }
                | RefusalKind::NotLookedUp { .. }
                | RefusalKind::MountTableUnreadable { .. }
                | RefusalKind::StorageUnjudged { .. } => Err(refusal.reason),
                _ => Ok(false),
            },
            Ok(Assessment::Attached | Assessment::Warned(_)) => {
                HiddenRoot::has_marker(&self.filesystem, root).map_err(|error| error.to_string())
            }
        }
    }

    /// Check state file for indicators of incomplete deactivation
    pub(super) fn check_state(&self, state: &StateFile, in_session: bool) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // The live facts (the session-leftovers check) say where the machine
        // is; the record only adds that a session ended without `deactivate`.
        // Inside the hidden session an active record describes the session
        // verify runs in.
        match &state.state {
            crate::SystemState::Active { .. } if in_session => {}
            crate::SystemState::Active { .. } => {
                findings.push(
                    Finding::new(
                        Severity::Warn,
                        "state",
                        "The state file records an active session: a session ended without a \
                         deactivation (a hard reset, a power-off or an emergency that could not \
                         record it)",
                    )
                    .with_fix_guidance(format!(
                        "The next activation records a new session; check `{}` first",
                        nails_base::next_step::sudo_line(nails_base::next_step::NextStep::Status)
                    )),
                );
            }
            crate::SystemState::Degraded { reason, .. } => {
                findings.push(
                    Finding::new(
                        Severity::Warn,
                        "state",
                        format!("The state file records a degraded session: {reason}"),
                    )
                    .with_fix_guidance({
                        use nails_base::next_step::{NextStep, sudo_line};
                        format!(
                            "Run `{}`, then `{} --deep`",
                            sudo_line(NextStep::Recover),
                            sudo_line(NextStep::Verify)
                        )
                    }),
                );
            }
            crate::SystemState::Inactive => {}
        }

        Ok(findings)
    }
}
