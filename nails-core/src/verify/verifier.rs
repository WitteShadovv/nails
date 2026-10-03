//! Forensic validation verifier implementation

use super::types::{Finding, ScanDepth, Severity, StateFileStatus, VerifyResult, VerifyStatus};
use crate::artifacts::{self, ArtifactKind, ArtifactScope, ArtifactSeverity};
use crate::config::Config;
use crate::filesystem::ProcessMatch;
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
        }
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

    /// Flag every overlay mount whose `upperdir` sits under the configured hidden
    /// volume root, at any mount point.
    ///
    /// Reads `/proc/self/mountinfo` rather than probing a fixed list of mount
    /// points, so a leftover overlay at `/var`, `/nix`, `/srv` or anywhere else
    /// is caught, not only `/home`, `/etc` and `/root`. Attribution is by the
    /// overlay's upper layer: an overlay whose writable layer lives on the hidden
    /// volume is unambiguously one NAILS mounted, regardless of the mount point's
    /// name. Without a configured hidden root there is nothing to attribute, so
    /// this reports nothing (the config-path check still covers configured
    /// targets).
    fn check_overlay_upperdirs(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        let Some(hidden_root) = self.hidden_root() else {
            return Ok(findings);
        };

        let Ok(mountinfo) = self.filesystem.read_file_content(Path::new(SELF_MOUNTINFO)) else {
            return Ok(findings);
        };

        for line in mountinfo.lines() {
            let Some((pre, post)) = line.split_once(" - ") else {
                continue;
            };
            // Pre-separator fields: id parent maj:min root mountpoint options ...
            let Some(mount_point) = pre.split(' ').nth(4) else {
                continue;
            };
            // Post-separator fields: fstype source super_opts.
            let post_fields: Vec<&str> = post.split(' ').collect();
            let Some(fstype) = post_fields.first() else {
                continue;
            };
            if *fstype != "overlay" {
                continue;
            }
            let Some(super_opts) = post_fields.get(2) else {
                continue;
            };
            let Some(upperdir) = super_opts
                .split(',')
                .find_map(|opt| opt.strip_prefix("upperdir="))
            else {
                continue;
            };
            if !Path::new(upperdir).starts_with(hidden_root) {
                continue;
            }
            findings.push(
                Finding::new(
                    Severity::Critical,
                    "mount",
                    format!(
                        "Leftover overlay at {mount_point} (upper layer {upperdir} on the hidden volume)"
                    ),
                )
                .with_fix_guidance("Run 'nails deactivate' to unmount overlays"),
            );
        }

        Ok(findings)
    }

    /// While a hidden session is active, flag any base-OS tree on the decoy that
    /// is mounted writable and is not an overlay.
    ///
    /// The read-only invariant ([`crate::platform::ro_guard`]) says the decoy's
    /// base-OS trees are either overlaid or kept read-only for the session. A
    /// writable, non-overlay mount of `/` or `/usr` (and the other core binary
    /// roots) backed by a real block device means hidden-session writes are
    /// reaching the decoy disk — the exact leak the invariant exists to prevent —
    /// so it is reported Critical. The walk reads `/proc/self/mountinfo` directly
    /// rather than trusting recorded state; it runs only in the active state,
    /// since a writable decoy root is expected when nothing is hidden.
    fn check_writable_decoy_mounts(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        let active = self
            .state
            .as_ref()
            .is_some_and(|state| matches!(state.state, crate::state::SystemState::Active { .. }));
        if !active {
            return Ok(findings);
        }

        let Ok(mountinfo) = self.filesystem.read_file_content(Path::new(SELF_MOUNTINFO)) else {
            return Ok(findings);
        };

        let hidden_root = self.hidden_root();

        for line in mountinfo.lines() {
            let Some((pre, post)) = line.split_once(" - ") else {
                continue;
            };
            let pre_fields: Vec<&str> = pre.split(' ').collect();
            // mountinfo pre fields: id parent maj:min root mountpoint options ...
            let (Some(mount_point), Some(options)) = (pre_fields.get(4), pre_fields.get(5)) else {
                continue;
            };
            let post_fields: Vec<&str> = post.split(' ').collect();
            // mountinfo post fields: fstype source superopts.
            let (Some(fstype), Some(source)) = (post_fields.first(), post_fields.get(1)) else {
                continue;
            };

            let mount_point = Path::new(mount_point);
            let is_os_tree = mount_point == Path::new("/")
                || OS_TREE_MOUNTS
                    .iter()
                    .any(|tree| mount_point == Path::new(tree));
            if !is_os_tree {
                continue;
            }
            // A tree that lives under the hidden volume is supposed to be writable.
            if let Some(root) = hidden_root
                && mount_point.starts_with(root)
            {
                continue;
            }
            let writable = options.split(',').any(|opt| opt == "rw");
            let is_overlay = *fstype == "overlay";
            let block_backed = source.starts_with("/dev/");
            if writable && !is_overlay && block_backed {
                findings.push(
                    Finding::new(
                        Severity::Critical,
                        "mount",
                        format!(
                            "Writable non-overlay decoy mount at {} ({fstype} on {source}); \
                             hidden-session writes are reaching the decoy disk",
                            mount_point.display()
                        ),
                    )
                    .with_fix_guidance(
                        "The decoy OS tree must be overlaid or kept read-only while hidden is \
                         active; run 'nails deactivate' and re-activate",
                    ),
                );
            }
        }

        Ok(findings)
    }

    /// Scan the live mount table for NAILS overlays and staging binds left at a
    /// non-standard target.
    ///
    /// [`check_overlay_mounts`](Self::check_overlay_mounts) covers the expected
    /// `/home`, `/etc` and `/root` overlays. This catches everything else an
    /// incomplete teardown can leave behind: an ephemeral `/var`, `/tmp`,
    /// `/srv`, `/opt` or `/nix` overlay whose upper or work dir resolves under
    /// the runtime directory, a pivot staging bind, or — when a config pins the
    /// hidden volume — an overlay whose upper or work dir resolves under the
    /// hidden root. Such a mount at an unexpected target means scaffolding is
    /// still mounted, so it is reported Critical.
    ///
    /// The table is parsed from `/proc/self/mountinfo` through the shared parser
    /// ([`parse_mountinfo`](crate::filesystem::parse_mountinfo)) and classified
    /// by [`NailsMounts`](crate::filesystem::NailsMounts), so a fake table can be
    /// injected in tests. Only mounts positively attributable to NAILS are
    /// flagged: staging binds and runtime-backed ephemeral overlays are always
    /// NAILS, while a generic overlay is attributed only when a configured
    /// hidden root places its upper or work dir inside the hidden volume. This
    /// keeps a foreign overlay (a container or build sandbox) from being
    /// mistaken for a leftover when verify runs without a config.
    fn check_nails_owned_mounts(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        let Ok(content) = self.filesystem.read_file_content(Path::new(SELF_MOUNTINFO)) else {
            return Ok(findings);
        };

        let hidden_root = self
            .config
            .as_ref()
            .map(|config| config.hidden_volume_root.clone())
            .filter(|root| !root.as_os_str().is_empty());

        let entries = crate::filesystem::parse_mountinfo(&content);
        let owned = crate::filesystem::NailsMounts::from_entries(&entries, hidden_root.as_deref());

        // Staging binds and runtime-backed ephemeral overlays are unambiguously
        // NAILS and are not reported anywhere else, so this scan owns them. A
        // persistent overlay (upper/work under the configured hidden root) is
        // already reported by `check_overlay_upperdirs`, which runs first and
        // catches it at every mount point, so it is intentionally not repeated
        // here to avoid double-reporting the same mount.
        let mut suspects: Vec<std::path::PathBuf> = Vec::new();
        suspects.extend(owned.pivot_binds.iter().cloned());
        suspects.extend(owned.ephemeral_overlays.iter().cloned());

        let is_standard = |p: &Path| STANDARD_OVERLAY_TARGETS.iter().any(|t| p == Path::new(t));

        let mut seen: Vec<std::path::PathBuf> = Vec::new();
        for target in suspects {
            if is_standard(&target) || seen.contains(&target) {
                continue;
            }
            seen.push(target.clone());
            findings.push(
                Finding::new(
                    Severity::Critical,
                    "mount",
                    format!(
                        "NAILS overlay or staging mount left at non-standard target {}; \
                         teardown did not remove all scaffolding",
                        target.display()
                    ),
                )
                .with_fix_guidance(
                    "Run 'nails deactivate' (or 'nails emergency') to tear down leftover \
                     overlays, staging binds and the runtime directory",
                ),
            );
        }

        Ok(findings)
    }

    /// Check for leftover NAILS artifacts drawn from the shared registry.
    ///
    /// Iterates [`artifacts::ARTIFACTS`] and flags every entry that resolves to a
    /// single filesystem path and still exists. Absolute paths (runtime and
    /// decoy traces) are always checked; hidden-root paths are checked against
    /// the configured hidden volume root when a config is available. In an
    /// offline image scan the hidden-root paths are skipped — the hidden volume
    /// is not part of the decoy image, and finding its own files there is not the
    /// point — while decoy and runtime paths are rebased under the image root.
    /// Content markers and bare basenames do not map to one path; they are
    /// covered by the base-config pre-flight check and the disk-image harness.
    fn check_artifact_files(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let hidden_root = self.hidden_root();
        let offline = self.is_offline();

        for artifact in artifacts::ARTIFACTS {
            let resolved = match artifact.kind {
                ArtifactKind::HiddenRootPath => {
                    if offline {
                        None
                    } else {
                        hidden_root.and_then(|root| artifact.resolve_path(root))
                    }
                }
                _ => artifact.resolve_path(Path::new("")),
            };
            let Some(path) = resolved else {
                continue;
            };
            let probe = self.rebase(&path);

            if self.filesystem.path_exists(&probe)? {
                findings.push(
                    Finding::new(
                        map_artifact_severity(artifact.severity),
                        "file",
                        format!("Artifact file found: {}", path.display()),
                    )
                    .with_fix_guidance(artifact_fix_guidance(artifact.scope, &path)),
                );
            }
        }

        Ok(findings)
    }

    /// Name-independent detection of open dm-crypt mappers and loop devices.
    ///
    /// Reads `/sys/block`: a `dm-*` device whose `dm/uuid` begins with `CRYPT-`
    /// is a dm-crypt mapper, and a `loop*` device with a non-empty
    /// `loop/backing_file` is an attached loop device. The device that backs the
    /// hidden volume (and therefore the running binary) is reported at Info level
    /// — "close it before handing over the machine" — while any *other* open
    /// crypt mapper or loop device is a warning, because it can expose a second
    /// hidden volume regardless of the neutral name it was given.
    ///
    /// When `/sys/block` cannot be read (an offline scan, a container, or a mock
    /// without the fixture) this reports nothing rather than erroring.
    fn check_block_devices(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        let entries = match self.filesystem.list_directory(Path::new(SYS_BLOCK_DIR)) {
            Ok(entries) => entries,
            Err(_) => return Ok(findings),
        };

        let own_sources = self.hidden_volume_backing_sources();

        for entry in entries {
            let Some(name) = entry.file_name().and_then(|name| name.to_str()) else {
                continue;
            };

            if name.starts_with("dm-") {
                let uuid = match self.filesystem.read_file_content(&entry.join("dm/uuid")) {
                    Ok(uuid) => uuid,
                    Err(_) => continue,
                };
                if !uuid.trim().starts_with("CRYPT-") {
                    continue;
                }
                let mapper_name = self
                    .filesystem
                    .read_file_content(&entry.join("dm/name"))
                    .map(|name| name.trim().to_string())
                    .unwrap_or_else(|_| name.to_string());
                let node = format!("/dev/mapper/{mapper_name}");
                let is_own = own_sources
                    .iter()
                    .any(|source| source == &node || source.ends_with(&format!("/{mapper_name}")));
                findings.push(block_device_finding(
                    is_own,
                    "dm-crypt mapper",
                    &mapper_name,
                    &node,
                ));
            } else if name.starts_with("loop") {
                let backing = match self
                    .filesystem
                    .read_file_content(&entry.join("loop/backing_file"))
                {
                    Ok(backing) => backing.trim().to_string(),
                    Err(_) => continue,
                };
                if backing.is_empty() {
                    continue;
                }
                let node = format!("/dev/{name}");
                let is_own = own_sources
                    .iter()
                    .any(|source| source == &node || source == &backing);
                findings.push(block_device_finding(is_own, "loop device", &backing, &node));
            }
        }

        Ok(findings)
    }

    /// The source device(s) that `/proc/self/mountinfo` reports for the
    /// configured hidden volume root, used to tell the hidden volume's own
    /// backing device apart from any other open crypt mapper or loop device.
    fn hidden_volume_backing_sources(&self) -> Vec<String> {
        let Some(root) = self.hidden_root() else {
            return Vec::new();
        };

        let Ok(mountinfo) = self.filesystem.read_file_content(Path::new(SELF_MOUNTINFO)) else {
            return Vec::new();
        };

        let mut sources = Vec::new();
        for line in mountinfo.lines() {
            let Some((pre, post)) = line.split_once(" - ") else {
                continue;
            };
            // mountinfo pre-separator field 5 (index 4) is the mount point.
            let Some(mount_point) = pre.split(' ').nth(4) else {
                continue;
            };
            if Path::new(mount_point) != root {
                continue;
            }
            // Post-separator fields: fstype, source, super_opts.
            if let Some(source) = post.split(' ').nth(1) {
                sources.push(source.to_string());
            }
        }

        sources
    }

    /// Check for nails-related processes, distinguishing the real binary from an
    /// unrelated command that merely mentions "nails".
    ///
    /// A strong match (the process runs the NAILS binary, or was invoked as
    /// `nails`) is Critical: a hidden session's worker is still live. A weak
    /// match (any other command line that contains "nails", such as an editor on
    /// a config file, `grep`, `sed` or `tee`) is only Info, so routine use of the
    /// tool's name never produces a critical false positive.
    fn check_nails_processes(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for ProcessMatch { strong, detail, .. } in self.filesystem.nails_process_matches()? {
            if strong {
                findings.push(
                    Finding::new(
                        Severity::Critical,
                        "process",
                        format!("NAILS process is running: {detail}"),
                    )
                    .with_fix_guidance("Stop all nails processes before deactivation"),
                );
            } else {
                findings.push(Finding::new(
                    Severity::Info,
                    "process",
                    format!("A process references NAILS on its command line: {detail}"),
                ));
            }
        }

        Ok(findings)
    }

    /// Check memory status (swap warnings)
    fn check_memory_status(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check if swap is enabled
        if self.filesystem.swap_is_enabled()? {
            findings.push(
                Finding::new(
                    Severity::Info,
                    "memory",
                    "Swap is enabled - sensitive data may persist in swap space",
                )
                .with_fix_guidance("Consider disabling swap: swapoff -a"),
            );
        }

        // Always add RAM persistence warning as Info
        findings.push(Finding::new(
            Severity::Info,
            "memory",
            "RAM may retain data briefly after shutdown - consider cold boot for maximum security",
        ));

        Ok(findings)
    }

    /// Perform deep scan of temporary directories, user homes and shell history.
    fn deep_scan(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // 1. Temporary and log directories: recursively scan for nails-named
        //    files, tolerating directories we cannot enter.
        let deep_scan_paths = ["/tmp", "/var/tmp", "/var/log"];
        for base_path in deep_scan_paths {
            let path_buf = self.rebase(Path::new(base_path));
            if self.filesystem.path_exists(&path_buf)? && self.filesystem.is_directory(&path_buf)? {
                let scan = self
                    .filesystem
                    .scan_files_with_pattern(&path_buf, "nails")?;
                for file in scan.matches {
                    findings.push(
                        Finding::new(
                            Severity::Warn,
                            "file",
                            format!("NAILS-related file found: {}", file.display()),
                        )
                        .with_fix_guidance(format!("Delete file: rm {}", file.display())),
                    );
                }
                for unreadable in scan.unreadable {
                    findings.push(Finding::new(
                        Severity::Info,
                        "file",
                        format!(
                            "Directory not checked (permission denied): {}",
                            unreadable.display()
                        ),
                    ));
                }
            }
        }

        // 2. Per-home history and desktop recency files.
        for home in self.user_homes() {
            findings.extend(self.scan_home(&home)?);
        }

        Ok(findings)
    }

    /// Scan one user's home for shell history containing nails commands and for
    /// desktop recency files that name the configured hidden root.
    fn scan_home(&self, home: &Path) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for history in HISTORY_FILES {
            let path = home.join(history);
            let probe = self.rebase(&path);
            if !self.filesystem.path_exists(&probe)? {
                continue;
            }
            match self.filesystem.read_file_content(&probe) {
                Ok(content) if content.to_lowercase().contains("nails") => {
                    findings.push(
                        Finding::new(
                            Severity::Warn,
                            "file",
                            format!("Shell history contains nails commands: {}", path.display()),
                        )
                        .with_fix_guidance(format!(
                            "Edit history to remove nails commands: nano {}",
                            path.display()
                        )),
                    );
                }
                Ok(_) => {}
                Err(_) => {
                    findings.push(
                        Finding::new(
                            Severity::Info,
                            "file",
                            format!(
                                "History file exists (cannot read contents): {}",
                                path.display()
                            ),
                        )
                        .with_fix_guidance("Review history manually if needed"),
                    );
                }
            }
        }

        // Desktop recency files only matter when they name the hidden root, so
        // there is nothing to look for without a configured hidden root.
        if let Some(hidden_root) = self.hidden_root() {
            let needle = hidden_root.to_string_lossy().to_string();
            for recent in DESKTOP_RECENT_FILES {
                let path = home.join(recent);
                let probe = self.rebase(&path);
                if !self.filesystem.path_exists(&probe)? {
                    continue;
                }
                if let Ok(content) = self.filesystem.read_file_content(&probe)
                    && content.contains(&needle)
                {
                    findings.push(
                        Finding::new(
                            Severity::Warn,
                            "file",
                            format!(
                                "Desktop recency file references the hidden volume root: {}",
                                path.display()
                            ),
                        )
                        .with_fix_guidance(format!(
                            "Remove the entry that names {} from {}",
                            needle,
                            path.display()
                        )),
                    );
                }
            }
        }

        Ok(findings)
    }

    /// The home directories to scan: root, every real login account from
    /// `/etc/passwd`, and `$SUDO_USER` when verify was run under sudo.
    ///
    /// Parsing `/etc/passwd` directly (rather than resolving a single user) is
    /// what makes the scan cover *every* user's history instead of the old
    /// hardcoded `/root` plus a bare `/home` history file that never exists. In an
    /// offline image scan the file is read from under the image root.
    fn user_homes(&self) -> Vec<PathBuf> {
        let mut homes: BTreeSet<PathBuf> = BTreeSet::new();
        // Root's home is always present and always worth scanning.
        homes.insert(PathBuf::from("/root"));

        let passwd_path = self.rebase(Path::new(PASSWD_FILE));
        if let Ok(content) = self.filesystem.read_file_content(&passwd_path) {
            for line in content.lines() {
                let fields: Vec<&str> = line.split(':').collect();
                if fields.len() < 7 {
                    continue;
                }
                let uid: u32 = match fields[2].parse() {
                    Ok(uid) => uid,
                    Err(_) => continue,
                };
                let home = fields[5];
                let shell = fields[6];
                let has_login_shell =
                    !shell.is_empty() && !shell.ends_with("/nologin") && !shell.ends_with("/false");
                let is_real_user = uid == 0 || (uid >= FIRST_LOGIN_UID && has_login_shell);
                if is_real_user && !home.is_empty() {
                    homes.insert(PathBuf::from(home));
                }
            }
        }

        // Prefer the invoking user's real home when running under sudo on the
        // live host; an offline scan has no meaningful live environment.
        if !self.is_offline()
            && let Ok(sudo_user) = std::env::var("SUDO_USER")
            && !sudo_user.is_empty()
            && let Ok(content) = self.filesystem.read_file_content(Path::new(PASSWD_FILE))
        {
            for line in content.lines() {
                let fields: Vec<&str> = line.split(':').collect();
                if fields.len() >= 7 && fields[0] == sudo_user && !fields[5].is_empty() {
                    homes.insert(PathBuf::from(fields[5]));
                }
            }
        }

        homes.into_iter().collect()
    }

    /// Check config-specific paths for residual artifacts
    ///
    /// Checks overlay mount points from config, log directory, hidden volume path,
    /// and state file location for any residual NAILS artifacts.
    fn check_config_paths(&self, config: &Config) -> Result<(Vec<Finding>, usize)> {
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

        // 1. Check config overlay mount points for residual mounts
        for overlay in &config.overlays {
            let mount_path = &overlay.target;
            paths_checked += 1;
            if self.filesystem.is_overlay_mounted(mount_path)? {
                findings.push(
                    Finding::new(
                        Severity::Critical,
                        "config",
                        format!(
                            "Config overlay mount point still mounted: {}",
                            mount_path.display()
                        ),
                    )
                    .with_fix_guidance("Run 'nails deactivate' to unmount overlays"),
                );
            }
        }

        // 2. Check hidden volume path for accessibility
        let hidden_vol = &config.hidden_volume_root;
        paths_checked += 1;
        if !host_context_inactive && self.filesystem.path_exists(hidden_vol)? {
            findings.push(
                Finding::new(
                    Severity::Warn,
                    "config",
                    format!("Hidden volume path is accessible: {}", hidden_vol.display()),
                )
                .with_fix_guidance("Ensure hidden volume is unmounted when not in use"),
            );
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
        if !log_is_on_hidden_volume
            && self.filesystem.path_exists(log_path)?
            && self.filesystem.is_directory(log_path)?
        {
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
        if !host_context_inactive && self.filesystem.path_exists(state_path)? {
            findings.push(
                Finding::new(
                    Severity::Warn,
                    "config",
                    format!(
                        "State file exists at configured path: {}",
                        state_path.display()
                    ),
                )
                .with_fix_guidance("State file should only exist on hidden volume when active"),
            );
        }

        if host_context_inactive {
            findings.push(Finding::new(
                Severity::Info,
                "context",
                "State reads Inactive; findings about the hidden volume itself are suppressed \
                 (its presence is expected while mounted)",
            ));
        }

        Ok((findings, paths_checked))
    }

    /// Check state file for indicators of incomplete deactivation
    fn check_state(&self, state: &StateFile) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check if state indicates system is still active or in transition
        match &state.state {
            crate::SystemState::Active { overlays, .. } => {
                findings.push(
                    Finding::new(
                        Severity::Critical,
                        "state",
                        format!(
                            "State file indicates system is ACTIVE with {} overlays",
                            overlays.len()
                        ),
                    )
                    .with_fix_guidance("Run 'nails deactivate' to properly shut down"),
                );
            }
            crate::SystemState::Activating { .. } => {
                findings.push(
                    Finding::new(
                        Severity::Critical,
                        "state",
                        "State file indicates system is stuck in ACTIVATING state",
                    )
                    .with_fix_guidance(
                        "Run 'nails deactivate --force' to clean up partial activation",
                    ),
                );
            }
            crate::SystemState::Deactivating { .. } => {
                findings.push(
                    Finding::new(
                        Severity::Critical,
                        "state",
                        "State file indicates system is stuck in DEACTIVATING state",
                    )
                    .with_fix_guidance("Run 'nails deactivate --force' to complete deactivation"),
                );
            }
            crate::SystemState::Degraded {
                remaining_mounts, ..
            } => {
                findings.push(
                    Finding::new(
                        Severity::Critical,
                        "state",
                        format!(
                            "State file indicates DEGRADED state — {} mount(s) may still be live",
                            remaining_mounts.len()
                        ),
                    )
                    .with_fix_guidance(
                        "Run 'nails recover' to finish teardown, then 'nails verify --deep'",
                    ),
                );
            }
            crate::SystemState::Inactive => {
                // Good — system is inactive, no state-level concerns
            }
        }

        // Check for failed overlays from previous activation
        if !state.failed_overlays.is_empty() {
            findings.push(Finding::new(
                Severity::Info,
                "state",
                format!(
                    "State records {} failed overlay(s) from previous activation",
                    state.failed_overlays.len()
                ),
            ));
        }

        Ok(findings)
    }
}

/// Map a registry severity hint onto a verification severity.
fn map_artifact_severity(severity: ArtifactSeverity) -> Severity {
    match severity {
        ArtifactSeverity::Info => Severity::Info,
        ArtifactSeverity::Warn => Severity::Warn,
        ArtifactSeverity::Critical => Severity::Critical,
    }
}

/// Fix guidance for a leftover artifact, tailored to where it lives.
fn artifact_fix_guidance(scope: ArtifactScope, path: &Path) -> String {
    match scope {
        ArtifactScope::Runtime => format!(
            "Runtime leftover from an incomplete teardown; run 'nails deactivate' (then confirm {} is gone)",
            path.display()
        ),
        ArtifactScope::Decoy => {
            format!(
                "Trace on the decoy filesystem; remove it: rm -rf {}",
                path.display()
            )
        }
        ArtifactScope::HiddenRoot => format!(
            "Expected on the hidden volume while mounted; unmount it before handing over the machine ({})",
            path.display()
        ),
    }
}

/// Build a finding for an open crypt mapper or loop device.
fn block_device_finding(is_own: bool, kind: &str, label: &str, node: &str) -> Finding {
    if is_own {
        Finding::new(
            Severity::Info,
            "block-device",
            format!("Open {kind} backing the hidden volume: {label} ({node})"),
        )
        .with_fix_guidance(
            "Close it before handing over the machine (cryptsetup close / losetup -d)",
        )
    } else {
        Finding::new(
            Severity::Warn,
            "block-device",
            format!("Open {kind} not backing the hidden volume: {label} ({node})"),
        )
        .with_fix_guidance(format!(
            "An unexpected {kind} is open; close it if it is not in use ({node})"
        ))
    }
}
