// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Forensic validation verifier implementation

use super::types::{Finding, ScanDepth, Severity, StateFileStatus, VerifyResult, VerifyStatus};
use crate::artifacts::{self, ArtifactKind, ArtifactScope, ArtifactSeverity};
use crate::config::Config;
use crate::filesystem::ProcessMatch;
use crate::preflight::SwapSeverity;
use crate::state::StateFile;
use crate::{Filesystem, Result};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// `/sys/block`, enumerated for open dm-crypt mappers and loop devices.
const SYS_BLOCK_DIR: &str = "/sys/block";

/// Kernel mount table, read to find the device backing the hidden volume and to
/// enumerate overlay mounts.
const SELF_MOUNTINFO: &str = "/proc/self/mountinfo";

/// The system account database, parsed to discover every real user's home so the
/// history scan covers each one rather than a hardcoded `/root` and a
/// non-existent `/home` file.
const PASSWD_FILE: &str = "/etc/passwd";

/// Smallest uid treated as a real (non-system) login account on the hosts NAILS
/// targets. Combined with a login shell, this selects the humans whose homes the
/// deep scan should cover.
const FIRST_LOGIN_UID: u32 = 1000;

/// Base-OS trees whose writable, non-overlay presence on the decoy block device
/// leaks a hidden session's package and `/usr` writes. `/` is checked separately.
const OS_TREE_MOUNTS: &[&str] = &["/usr", "/bin", "/sbin", "/lib", "/lib64"];

/// Per-home relative paths whose contents are searched for a reference to the
/// configured hidden volume root.
const DESKTOP_RECENT_FILES: &[&str] = &[
    ".local/share/recently-used.xbel",
    ".config/VeraCrypt/History.xml",
    ".config/VeraCrypt/Favorite Volumes.xml",
];

/// Shell history files, relative to a home, searched for NAILS commands.
const HISTORY_FILES: &[&str] = &[".bash_history", ".zsh_history"];

/// Overlay targets an active hidden session is expected to present. Leftover
/// NAILS overlays or staging binds anywhere else mean teardown left scaffolding
/// behind; [`check_overlay_mounts`](Verifier::check_overlay_mounts) already
/// reports these expected targets, so the mount-table scan skips them.
const STANDARD_OVERLAY_TARGETS: &[&str] = &["/home", "/etc", "/root"];

/// Where a verification run is pointed: the live host, or an offline image.
#[derive(Debug, Clone)]
enum VerifyContext {
    /// Scanning the running host. Live checks (processes, mounts, block devices,
    /// platform scanners) apply.
    Host,
    /// Scanning a read-only mounted decoy image or partition rooted at this path.
    /// Every filesystem path is rebased under it, and live checks are skipped.
    Offline { root: PathBuf },
}

/// Forensic validation verifier
///
/// Performs systematic checks to validate that no NAILS artifacts remain
/// on the system after deactivation.
pub struct Verifier<F: Filesystem> {
    filesystem: F,
    config: Option<Config>,
    state: Option<StateFile>,
    state_file_status: StateFileStatus,
    context: VerifyContext,
    scope_to_decoy: bool,
}

impl<F: Filesystem> Verifier<F> {
    /// Create a new verifier with the given filesystem
    pub fn new(filesystem: F) -> Self {
        Self {
            filesystem,
            config: None,
            state: None,
            state_file_status: StateFileStatus::NotChecked,
            context: VerifyContext::Host,
            scope_to_decoy: false,
        }
    }

    /// Create a new verifier with config and optional state
    pub fn with_config(
        filesystem: F,
        config: Config,
        state: Option<StateFile>,
        state_file_status: StateFileStatus,
    ) -> Self {
        Self {
            filesystem,
            config: Some(config),
            state,
            state_file_status,
            context: VerifyContext::Host,
            scope_to_decoy: false,
        }
    }

    /// Scope this live-host scan to the decoy, treating the configured hidden
    /// volume and its backing device as out of scope.
    ///
    /// The pre-activation residue baseline runs *while the hidden volume is
    /// deliberately attached* for the activation that is about to happen, so a
    /// plain host scan would report the hidden volume's own mount, its on-volume
    /// files (`config/nails.toml`, `state.json`, logs, reports) and its backing
    /// crypt mapper as findings — self-inflicted noise that is not decoy residue.
    /// In this mode those are suppressed: the hidden root being mounted is not
    /// flagged, hidden-root artifact paths are skipped, the hidden-volume path and
    /// its state file are not reported, and the hidden volume's own backing device
    /// is not listed. A *second*, unexpected crypt mapper or loop device is still a
    /// warning, and every decoy-side and runtime check runs unchanged, so a real
    /// leak on the decoy is still caught.
    pub fn scoped_to_decoy(mut self) -> Self {
        self.scope_to_decoy = true;
        self
    }

    /// Point this verifier at an offline image mounted read-only at `root`.
    ///
    /// Every filesystem path the verifier resolves is rebased under `root`, and
    /// the live-only checks (running processes, the kernel mount table, open
    /// block devices and the host platform scanners) are skipped, because they
    /// describe the machine running `verify`, not the image under inspection.
    pub fn offline_under(mut self, root: PathBuf) -> Self {
        self.context = VerifyContext::Offline { root };
        self
    }

    /// Whether this run is scanning an offline image rather than the live host.
    fn is_offline(&self) -> bool {
        matches!(self.context, VerifyContext::Offline { .. })
    }

    /// Whether findings about the hidden volume itself are out of scope for this
    /// run: an offline image scan (the hidden volume is not part of the decoy
    /// image) or a decoy-scoped baseline (the hidden volume is deliberately
    /// attached for the activation in progress).
    fn excludes_hidden_root(&self) -> bool {
        self.is_offline() || self.scope_to_decoy
    }

    /// Rebase an absolute path under the offline root, if any.
    ///
    /// On the live host this returns `path` unchanged. For an offline image at
    /// `/mnt/decoy`, `/etc/passwd` becomes `/mnt/decoy/etc/passwd`, so the same
    /// checks read the image instead of the running system.
    fn rebase(&self, path: &Path) -> PathBuf {
        match &self.context {
            VerifyContext::Host => path.to_path_buf(),
            VerifyContext::Offline { root } => {
                let relative = path.strip_prefix("/").unwrap_or(path);
                root.join(relative)
            }
        }
    }

    /// The hidden volume root from config, when configured and non-empty.
    fn hidden_root(&self) -> Option<&Path> {
        self.config
            .as_ref()
            .map(|config| config.hidden_volume_root.as_path())
            .filter(|root| !root.as_os_str().is_empty())
    }

    /// Run the verification process
    ///
    /// # Arguments
    ///
    /// * `deep` - If true, perform comprehensive deep scan
    ///
    /// # Returns
    ///
    /// `VerifyResult` containing all findings and overall status
    pub fn run(&self, deep: bool) -> Result<VerifyResult> {
        let mut findings = Vec::new();
        let mut config_paths_checked: usize = 0;
        let mut checks_run: usize = 0;
        let mut scanner_not_checked: Vec<String> = Vec::new();

        let offline = self.is_offline();

        // Live-only checks: these describe the running machine, not an image.
        if !offline {
            // 1. Leftover overlays whose upper layer sits under the hidden root.
            findings.extend(self.check_overlay_upperdirs()?);
            checks_run += 1;

            // 1b. While active, flag a writable non-overlay decoy OS tree.
            findings.extend(self.check_writable_decoy_mounts()?);
            checks_run += 1;

            // 1c. Flag leftover NAILS overlays and staging binds at non-standard
            // targets, classified from the live mount table.
            findings.extend(self.check_nails_owned_mounts()?);
            checks_run += 1;

            // 1d. Flag a hidden root still mounted while no hidden session is
            // active — the signature of an emergency teardown that did not close
            // the backend.
            findings.extend(self.check_hidden_root_mounted()?);
            checks_run += 1;
        }

        // 2. Check for artifact files from the shared registry.
        findings.extend(self.check_artifact_files()?);
        checks_run += 1;

        if !offline {
            // 3. Check for nails processes (honest, identity-based match).
            findings.extend(self.check_nails_processes()?);
            checks_run += 1;

            // 4. Check memory status (swap warnings).
            findings.extend(self.check_memory_status()?);
            checks_run += 1;

            // 4b. Name-independent open crypt mapper / loop device detection.
            findings.extend(self.check_block_devices()?);
            checks_run += 1;

            // 4c. Platform-specific, read-only drift scanners (apt/dpkg on
            //     Debian, the /var/lib/nixos note on NixOS).
            let (scan_findings, scan_not_checked) = self.run_platform_scanners();
            findings.extend(scan_findings);
            scanner_not_checked = scan_not_checked;
            checks_run += 1;
        }

        // 5. Config-aware checks run against live locations only.
        if !offline && let Some(ref config) = self.config {
            let (config_findings, paths_checked) = self.check_config_paths(config)?;
            findings.extend(config_findings);
            config_paths_checked = paths_checked;
            checks_run += 1;
        }

        // 6. State-aware checks (if state is available).
        if !offline && let Some(ref state) = self.state {
            findings.extend(self.check_state(state)?);
            checks_run += 1;
        }

        // 7. Deep scan if requested (homes, histories, temp directories).
        if deep {
            findings.extend(self.deep_scan()?);
            checks_run += 1;
        }

        // Determine overall status
        let status = if findings.iter().any(|f| f.severity == Severity::Critical) {
            VerifyStatus::Critical
        } else if findings.iter().any(|f| f.severity == Severity::Warn) {
            VerifyStatus::Warning
        } else {
            VerifyStatus::Secure
        };

        let scan_depth = if deep {
            ScanDepth::Deep
        } else {
            ScanDepth::Standard
        };

        let mut areas_not_checked = self.areas_not_checked(deep);
        areas_not_checked.extend(scanner_not_checked);

        let mut result = if self.config.is_some() {
            VerifyResult::new_config_aware(
                status,
                findings,
                scan_depth,
                config_paths_checked,
                self.state_file_status.clone(),
            )
        } else {
            VerifyResult::new(status, findings, scan_depth)
        };
        result.checks_run = checks_run;
        result.areas_not_checked = areas_not_checked;
        Ok(result)
    }

    /// The honest list of areas this run did not inspect, so the headline can say
    /// what a clean result does *not* prove.
    fn areas_not_checked(&self, deep: bool) -> Vec<String> {
        let mut areas = Vec::new();
        areas.push("the systemd journal (not searched by verify)".to_string());
        if !deep {
            areas.push(
                "shell histories and temp directories (/tmp, /var/tmp); re-run with --deep"
                    .to_string(),
            );
        }
        if self.is_offline() {
            areas.push(
                "live processes, mounts and open block devices (offline image scan)".to_string(),
            );
        }
        areas.push("renamed or unknown artifacts not in the registry".to_string());
        areas.push("a byte-for-byte comparison of the decoy disk against a baseline".to_string());
        areas
    }

    /// Run the detected platform's read-only drift scanners, returning their
    /// findings and the areas they could not inspect.
    ///
    /// The host is detected from the live filesystem; a detection failure (an
    /// unreadable `/etc/os-release`, say) is not fatal — it simply means no
    /// platform scanner runs. Scanners are dispatched by platform kind rather
    /// than through a boxed trait object so this stays free of a `'static` bound
    /// on the verifier.
    fn run_platform_scanners(&self) -> (Vec<Finding>, Vec<String>) {
        use crate::platform::{
            ArtifactScanner, DebianPackageDriftScanner, NixOsStateNoteScanner, PlatformKind,
        };

        let Ok(profile) = crate::platform::detect(&self.filesystem) else {
            return (Vec::new(), Vec::new());
        };

        let rebase = |path: &Path| self.rebase(path);
        let hidden = self.hidden_root();
        let mut findings = Vec::new();
        let mut not_checked = Vec::new();

        let scan =
            |scanner: &dyn ArtifactScanner<F>| scanner.scan(&self.filesystem, &rebase, hidden);
        let result = match profile.kind {
            PlatformKind::NixOs => scan(&NixOsStateNoteScanner),
            PlatformKind::Fhs => scan(&DebianPackageDriftScanner),
            PlatformKind::Unsupported => return (findings, not_checked),
        };
        if let Ok(outcome) = result {
            findings.extend(outcome.findings);
            not_checked.extend(outcome.not_checked);
        }

        (findings, not_checked)
    }
}

mod config_state;
mod deep_scan;
mod mounts;
mod system;
