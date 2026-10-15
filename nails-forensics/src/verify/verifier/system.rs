// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Artifact-file, block-device, process and memory checks, with the finding/severity helpers they share.

use super::session::{CHECK_DECOY_OFFLINE, HiddenSession};
use super::*;

impl<F: Filesystem> Verifier<F> {
    /// Check for leftover NAILS artifacts drawn from the shared registry.
    ///
    /// Iterates [`artifacts::ARTIFACTS`] and flags every entry that resolves to a
    /// single filesystem path and still exists. Absolute paths (runtime and
    /// decoy traces) are always checked; hidden-root paths are checked against
    /// the configured hidden volume root when a config is available. In an
    /// offline image scan or a decoy-scoped baseline the hidden-root paths are
    /// skipped — the hidden volume is not part of the decoy (it is either absent
    /// from the image or deliberately attached for the activation in progress),
    /// and finding its own files is not the point — while decoy and runtime paths
    /// are still checked (rebased under the image root when offline).
    /// Content markers and bare basenames do not map to one path; they are
    /// covered by the base-config pre-flight check and the disk-image harness.
    ///
    /// Inside the hidden session the live root is the session's overlay: its
    /// own runtime files are skipped (the session note covers them), and a
    /// decoy path is attributed to the layer that holds it.
    pub(super) fn check_artifact_files(
        &self,
        session: Option<&HiddenSession>,
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let hidden_root = self.hidden_root();
        let skip_hidden_root = self.excludes_hidden_root();

        for artifact in artifacts::ARTIFACTS {
            let resolved = match artifact.kind {
                ArtifactKind::HiddenRootPath => {
                    if skip_hidden_root {
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
            if artifact.scope == ArtifactScope::Runtime
                && session.is_some_and(|session| session.owns_runtime_path(&path))
            {
                continue;
            }
            // On the live decoy the session-leftovers check reports the
            // runtime directory, as critical: one finding per leftover.
            if session.is_none()
                && !self.is_offline()
                && path == Path::new(nails_teardown::whole_root::plan::RUNTIME_DIR)
            {
                continue;
            }
            if !self.entry_exists(&self.rebase(&path))? {
                continue;
            }
            findings.push(match session {
                Some(session) if artifact.scope == ArtifactScope::Decoy => {
                    self.decoy_artifact_in_session(artifact.severity, &path, session)?
                }
                _ => Finding::new(
                    map_artifact_severity(artifact.severity),
                    "file",
                    format!("Artifact file found: {}", path.display()),
                )
                .with_fix_guidance(artifact_fix_guidance(artifact.scope, &path)),
            });
        }

        Ok(findings)
    }

    /// Whether anything is at `path`, a dangling symbolic link included. The
    /// probe is `lstat`, not `stat`: a leaked link whose target does not
    /// resolve where verify runs (an offline image, say) is still a trace.
    fn entry_exists(&self, path: &Path) -> Result<bool> {
        Ok(self.filesystem.is_symlink(path)? || self.filesystem.path_exists(path)?)
    }

    /// A decoy path found from inside the hidden session. The live root is
    /// the session's overlay, so the entry is the session's own when the
    /// upper holds it, and only an entry from the decoy root beneath keeps
    /// the registry's severity. Deleting either through the overlay leaves the
    /// decoy as it is, so the guidance never suggests it.
    fn decoy_artifact_in_session(
        &self,
        severity: ArtifactSeverity,
        path: &Path,
        session: &HiddenSession,
    ) -> Result<Finding> {
        let found = format!("Artifact file found: {}", path.display());
        let upper = session.upper_path(path);
        if self.entry_exists(&upper)? {
            return Ok(
                Finding::new(Severity::Info, "file", found).with_fix_guidance(format!(
                    "The hidden session's own copy, in its hidden layer ({}); the decoy is not \
                 written. The session cannot see the decoy beneath it: to check the decoy, \
                 {CHECK_DECOY_OFFLINE}",
                    upper.display()
                )),
            );
        }
        Ok(
            Finding::new(map_artifact_severity(severity), "file", found).with_fix_guidance(
                format!(
                    "Trace on the decoy filesystem, seen through the hidden session. Deleting it \
                 here only hides it in the hidden layer: remove it on the decoy after the \
                 return, or first confirm it ({CHECK_DECOY_OFFLINE})"
                ),
            ),
        )
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
    pub(super) fn check_block_devices(&self) -> Result<Vec<Finding>> {
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
                // A decoy-scoped baseline excludes the hidden volume's own backing
                // device: it is attached on purpose for the activation in progress.
                if is_own && self.scope_to_decoy {
                    continue;
                }
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
                if is_own && self.scope_to_decoy {
                    continue;
                }
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

        // The shared parser decodes the kernel's octal escapes, so a hidden root
        // whose path holds a space or a backslash still finds its own entry.
        crate::filesystem::parse_mountinfo(&mountinfo)
            .into_iter()
            .filter(|entry| entry.mount_point == root)
            .map(|entry| entry.source.to_string_lossy().into_owned())
            .collect()
    }

    /// Check for nails-related processes, distinguishing the real binary from an
    /// unrelated command that merely mentions "nails".
    ///
    /// A strong match (the process runs the NAILS binary, or was invoked as
    /// `nails`) is Critical: a hidden session's worker is still live. A weak
    /// match (any other command line that contains "nails", such as an editor on
    /// a config file, `grep`, `sed` or `tee`) is only Info, so routine use of the
    /// tool's name never produces a critical false positive.
    pub(super) fn check_nails_processes(&self) -> Result<Vec<Finding>> {
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
    pub(super) fn check_memory_status(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Classify swap per device, matching the pre-flight check exactly: a disk
        // or file swap (or hibernation) can leak memory to persistent storage and
        // is critical; ephemeral encrypted swap warns; RAM-only zram passes.
        let posture = nails_base::preflight::classify_swap(&self.filesystem);
        match posture.severity {
            SwapSeverity::Pass => {}
            SwapSeverity::Warn => findings.push(
                Finding::new(
                    Severity::Warn,
                    "memory",
                    format!("Swap posture warning: {}", posture.findings.join("; ")),
                )
                .with_fix_guidance("Confirm the encrypted swap key is never persisted"),
            ),
            SwapSeverity::Fail => findings.push(
                Finding::new(
                    Severity::Critical,
                    "memory",
                    format!(
                        "Swap can leak memory to persistent storage: {}",
                        posture.findings.join("; ")
                    ),
                )
                .with_fix_guidance(
                    "Disable disk and file swap (swapoff -a) and hibernation; keep only RAM-only zram",
                ),
            ),
        }

        // Always add the RAM note as Info. A cold boot is the attack on RAM
        // the note guards against, never advice.
        findings.push(
            Finding::new(
                Severity::Info,
                "memory",
                "RAM keeps the session's data until power-off, and briefly after it",
            )
            .with_fix_guidance(
                "End the session with --poweroff and leave the machine off for a few minutes \
                 before handing it over",
            ),
        );

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
            "Leftover of an interrupted activation, in RAM; run 'nails recover' on the decoy, \
             or power off (then confirm {} is gone)",
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
