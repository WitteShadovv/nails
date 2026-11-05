// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Forensic validation verifier implementation

use super::types::{Finding, ScanDepth, Severity, StateFileStatus, VerifyResult, VerifyStatus};
use crate::artifacts::{self, ArtifactKind, ArtifactScope, ArtifactSeverity};
use crate::config::Config;
use crate::filesystem::ProcessMatch;
use crate::state::StateFile;
use crate::{Filesystem, Result};
use nails_base::preflight::SwapSeverity;
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

/// Per-home relative paths whose contents are searched for a reference to the
/// configured hidden volume root.
const DESKTOP_RECENT_FILES: &[&str] = &[
    ".local/share/recently-used.xbel",
    ".config/VeraCrypt/History.xml",
    ".config/VeraCrypt/Favorite Volumes.xml",
];

/// Shell history files, relative to a home, searched for NAILS commands.
const HISTORY_FILES: &[&str] = &[".bash_history", ".zsh_history"];

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
    /// Reads the systemd journal for the deep-scan leak search. Defaults to the
    /// live `journalctl` reader; tests inject a deterministic fake.
    journal: Box<dyn super::journal::JournalReader>,
    /// The invoking operator's login name (`SUDO_USER` from the startup
    /// snapshot), whose real home a live scan also covers. `None` when the scan
    /// was not given a snapshot or ran without `sudo`.
    invoking_user: Option<String>,
    /// Run the examiner audit of setup traces as well (offline scans only).
    examiner: Option<super::ExaminerOptions>,
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
            journal: Box::new(super::journal::JournalctlReader),
            invoking_user: None,
            examiner: None,
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
            journal: Box::new(super::journal::JournalctlReader),
            invoking_user: None,
            examiner: None,
        }
    }

    /// Take the invoking operator from the startup environment snapshot, so a
    /// live scan also covers the real home of the user who ran `sudo`.
    #[must_use]
    pub fn with_runtime_env(mut self, env: &crate::RuntimeEnv) -> Self {
        self.invoking_user = env.sudo_user.clone();
        self
    }

    /// Replace the journal reader (tests inject a deterministic fake).
    #[cfg(test)]
    pub(crate) fn with_journal_reader(
        mut self,
        reader: Box<dyn super::journal::JournalReader>,
    ) -> Self {
        self.journal = reader;
        self
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
    /// `root` is the root of the decoy system: one that does not exist, is not
    /// a folder or holds no `etc` folder holds nothing to scan, and
    /// [`run`](Self::run) refuses it with
    /// [`NailsError::RefusedOfflineRoot`](crate::NailsError::RefusedOfflineRoot).
    pub fn offline_under(mut self, root: PathBuf) -> Self {
        self.context = VerifyContext::Offline { root };
        self
    }

    /// Also run the examiner audit of setup traces (see
    /// [`super::examiner`]). It needs an offline root and is ignored on a live
    /// scan, whose root is the running host rather than a decoy image.
    #[must_use]
    pub fn with_examiner(mut self, options: super::ExaminerOptions) -> Self {
        self.examiner = Some(options);
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

    /// Where the decoy's `path` lies under the offline root, its links followed
    /// inside the root as the decoy itself follows them: an absolute link in
    /// the image resolves in the image, never on the machine that runs
    /// verify ([`Filesystem::resolve_in_root`]). `None` where `path` does not
    /// resolve inside the root, through a loop of links or where the kernel
    /// refuses the lookup: the root joined with `path` would follow the
    /// image's links out of it on this machine, so nothing is read there. On
    /// the live host, `path` itself. Following a link updates the link's own
    /// access time on a read-write mount, which the advised read-only mounts
    /// are not.
    fn place(&self, path: &Path) -> Option<PathBuf> {
        match &self.context {
            VerifyContext::Host => Some(path.to_path_buf()),
            VerifyContext::Offline { root } => {
                let inside = self.filesystem.resolve_in_root(root, path)?;
                Some(root.join(inside.strip_prefix("/").unwrap_or(&inside)))
            }
        }
    }

    /// The text of the decoy's file `path`: under the offline root its links
    /// followed inside the root, as [`place`](Self::place) follows them, and
    /// read without updating its access time; on the live host `path` itself.
    fn read_in_image(&self, path: &Path) -> Result<String> {
        match &self.context {
            VerifyContext::Host => self.filesystem.read_file_content(path),
            VerifyContext::Offline { root } => self.filesystem.read_file_in_root(root, path),
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
    ///
    /// # Errors
    ///
    /// Fails when the offline root holds nothing to scan, which is refused
    /// before any check runs ([`offline_under`](Self::offline_under)), and
    /// when a check returns an error.
    pub fn run(&self, deep: bool) -> Result<VerifyResult> {
        if let VerifyContext::Offline { root } = &self.context {
            self.refuse_a_root_with_nothing_to_scan(root)?;
        }

        let mut findings = Vec::new();
        let mut config_paths_checked: usize = 0;
        let mut ran: BTreeSet<&'static str> = BTreeSet::new();
        let mut scanner_not_checked: Vec<String> = Vec::new();

        let offline = self.is_offline();

        // Inside the hidden session the live root is the session's overlay, so
        // its own files, its state and its journal show in the live view. Worked
        // out once, for every check that must tell them from the decoy's.
        let session = if offline { None } else { self.hidden_session() };
        let in_session = session.is_some();

        // Live-only checks: these describe the running machine, not an image.
        if !offline {
            // 1. What an entry or a hidden session leaves in /run on the decoy.
            findings.extend(self.check_session_leftovers(session.as_ref())?);
            ran.insert("session-leftovers");
        }

        // 2. Check for artifact files from the shared registry.
        findings.extend(self.check_artifact_files(session.as_ref())?);
        ran.insert("artifact-files");

        // 2b. The residue catalog's path probes for session residue.
        findings.extend(self.check_catalog_paths(crate::residue_catalog::ResidueKind::Session));
        ran.insert("catalog-paths");

        if !offline {
            // 3. Check for nails processes (honest, identity-based match).
            findings.extend(self.check_nails_processes()?);
            ran.insert("processes");

            // 4. Check memory status (swap warnings).
            findings.extend(self.check_memory_status()?);
            ran.insert("memory-swap");

            // 4b. Name-independent open crypt mapper / loop device detection.
            findings.extend(self.check_block_devices()?);
            ran.insert("block-devices");

            // 4c. Platform-specific, read-only drift scanners (apt/dpkg on
            //     Debian, the /var/lib/nixos note on NixOS).
            let (scan_findings, scan_not_checked) = self.run_platform_scanners();
            findings.extend(scan_findings);
            scanner_not_checked = scan_not_checked;
            ran.insert("platform-scanners");
        }

        // 5. Config-aware checks run against live locations only.
        if !offline && let Some(ref config) = self.config {
            let (config_findings, paths_checked) = self.check_config_paths(config, in_session)?;
            findings.extend(config_findings);
            config_paths_checked = paths_checked;
            ran.insert("config-paths");
        }

        // 6. State-aware checks (if state is available).
        if !offline && let Some(ref state) = self.state {
            findings.extend(self.check_state(state, in_session)?);
            ran.insert("state");
        }

        // 7. Deep scan if requested (homes, histories, temp directories).
        let mut journal_searched = false;
        if deep {
            findings.extend(self.deep_scan()?);
            ran.extend([
                "deep-scan-files",
                "deep-scan-history",
                "deep-scan-recent-files",
            ]);

            // 7b. Grep the live journal for the tokens a leaked hidden session
            //     would leave there. Live-host only: an offline image scan has no
            //     journald to query, so it is left to the host-side disk-image
            //     forensics instead.
            if !offline {
                let (journal_findings, searched) = self.scan_journal(in_session);
                findings.extend(journal_findings);
                journal_searched = searched;
                if searched {
                    ran.insert("journal-scan");
                }
            }
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

        // What the decoy mounts at a place that holds nothing under the image
        // root was not read, by this scan nor by the examiner's view.
        let unmounted = if offline {
            self.unmounted_areas()
        } else {
            Vec::new()
        };

        // 8. The examiner audit of setup traces, offline only. Its findings are
        //    reported apart and never change the status computed above.
        let examiner = match (&self.context, &self.examiner) {
            (VerifyContext::Offline { root }, Some(options)) => {
                let mut report = super::examiner::examine(root, options);
                ran.extend(report.checks_run.iter().copied());
                report.not_checked.extend(unmounted.iter().cloned());
                Some(report)
            }
            _ => None,
        };

        let mut areas_not_checked = self.areas_not_checked(deep, journal_searched);
        areas_not_checked.extend(scanner_not_checked);
        areas_not_checked.extend(self.catalog_areas_not_checked(&ran, examiner.is_some()));
        match &examiner {
            Some(report) => areas_not_checked.extend(report.not_checked.iter().cloned()),
            None => areas_not_checked.extend(unmounted),
        }

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
        result.checks_run = ran.len();
        result.areas_not_checked = areas_not_checked;
        result.examiner = examiner;
        Ok(result)
    }

    /// The honest list of areas this run did not inspect, so the headline can say
    /// what a clean result does *not* prove.
    fn areas_not_checked(&self, deep: bool, journal_searched: bool) -> Vec<String> {
        let mut areas = Vec::new();
        if journal_searched {
            // A deep live scan greps the journal, but only for the known leak
            // tokens (tool name, hidden volume path, backend command names), so a
            // clean result is not proof the journal holds nothing else.
            areas.push(
                "the systemd journal beyond the known leak tokens (tool name, hidden volume path, \
                 backend command names)"
                    .to_string(),
            );
        } else {
            areas.push("the systemd journal (not searched by verify)".to_string());
        }
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
    /// The host is detected from the live filesystem. A detection that fails,
    /// a host detection refuses (one whose markers NAILS cannot look up among
    /// them) and a scanner that fails run no scanner, or none to its end, and
    /// each says so in the areas not checked, so a clean result never hides
    /// a drift scan that did not run. Scanners are dispatched by platform kind
    /// rather than through a boxed trait object so this stays free of a
    /// `'static` bound on the verifier.
    fn run_platform_scanners(&self) -> (Vec<Finding>, Vec<String>) {
        use super::scanners::{ArtifactScanner, DebianPackageDriftScanner, NixOsStateNoteScanner};
        use crate::platform::PlatformKind;

        let not_run = |why: String| (Vec::new(), vec![format!("platform drift scanners ({why})")]);
        let profile = match crate::platform::detect(&self.filesystem) {
            Ok(profile) => profile,
            Err(error) => {
                return not_run(format!("not run: the host could not be detected: {error}"));
            }
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
            PlatformKind::Unsupported => {
                let why = profile
                    .unsupported_reason
                    .unwrap_or_else(|| "the host is not one NAILS supports".to_string());
                return not_run(format!("not run on a host NAILS refuses: {why}"));
            }
        };
        match result {
            Ok(outcome) => {
                findings.extend(outcome.findings);
                not_checked.extend(outcome.not_checked);
            }
            Err(error) => not_checked.push(format!("platform drift scanners (failed: {error})")),
        }

        (findings, not_checked)
    }
}

mod catalog;
pub use catalog::VERIFY_CHECK_IDS;
mod config_state;
mod crypt_open;
#[cfg(test)]
mod crypt_open_tests;
mod deep_scan;
mod journal_scan;
#[cfg(test)]
mod journal_scan_tests;
mod offline_root;
#[cfg(test)]
mod offline_root_tests;
mod session;
#[cfg(test)]
mod session_tests;
mod system;
mod unmounted;
#[cfg(test)]
mod unmounted_tests;
