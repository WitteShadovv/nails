// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The single registry of traces an activation can leave on a host.
//!
//! Every file name, directory, content marker and runtime path that NAILS
//! writes is described here once. `verify`, the base-config pre-flight check and
//! the end-to-end disk-image harness all read this registry instead of keeping
//! their own, drifting copies of "what to look for". The registry is exported
//! verbatim to `nix/e2e-tests/fixtures/indicators.json` (guarded by a drift
//! test), so the host-side image scan looks for exactly the strings the tool
//! actually produces — not an invented list that can neither detect a leak nor
//! fail honestly.
//!
//! The registry is a *description*, not a promise of coverage. A clean `verify`
//! means none of these known markers were found, which is weaker than proof that
//! the decoy is byte-for-byte untouched.

use serde::Serialize;
use std::path::{Path, PathBuf};

/// The tool's own name as it appears on a command line.
///
/// A hidden session that logs to a persistent decoy journal before the overlays
/// are mounted (sudo command lines, transient unit names) leaves this token
/// behind, so both the deep-scan history search and the journal leak search grep
/// for it. The single definition of the literal.
pub const TOOL_NAME: &str = "nails";

/// Directory on the hidden root that holds the configuration file.
///
/// This is the single definition of the name; [`crate::config`] and
/// [`crate::hidden_root`] re-export it rather than repeating the literal.
pub const CONFIG_DIR_NAME: &str = "config";

/// File name of the configuration file, under [`CONFIG_DIR_NAME`] on the hidden
/// root. The single definition of the literal; every other reference resolves
/// here.
pub const CONFIG_FILE_NAME: &str = "nails.toml";

/// Activation state file name, on the hidden root. The single definition.
pub const STATE_FILE_NAME: &str = "state.json";

/// The relative import that the staged `hardware-configuration.nix` wrapper adds
/// to pull in the hidden NixOS module. The detector (base-config pre-flight) and
/// the stager reference this one definition.
pub const NIXOS_IMPORT_MARKER: &str = "./nails/configuration.nix";

/// How to interpret an artifact's [`Artifact::value`] when looking for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactKind {
    /// A fixed absolute path on the decoy root (e.g. `/run/nails`).
    AbsolutePath,
    /// A path relative to the hidden volume root (e.g. `config/nails.toml`).
    HiddenRootPath,
    /// A bare file name that may appear in more than one directory.
    Basename,
    /// A substring that appears inside another file's contents.
    ContentMarker,
}

/// Where an artifact lives, which decides whether finding it is a leak.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactScope {
    /// On the decoy root or a shared location. Finding it after deactivation is
    /// a real leak onto the persistent decoy disk.
    Decoy,
    /// On the hidden volume. Expected while the volume is mounted, but must be
    /// absent from an image of the decoy disk.
    HiddenRoot,
    /// Ephemeral runtime state. Must be gone after deactivation.
    Runtime,
}

/// Severity hint carried by a registry entry, mapped by each consumer onto its
/// own finding severity. Kept local to the registry so `artifacts` depends on
/// nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactSeverity {
    /// Informational: expected in some contexts; note, do not alarm.
    Info,
    /// A potential leak that should be investigated.
    Warn,
    /// A trace that reveals the hidden environment; requires action.
    Critical,
}

/// One kind of trace NAILS can leave behind.
#[derive(Debug, Clone, Copy)]
pub struct Artifact {
    /// Stable identifier, used in reports and tests.
    pub id: &'static str,
    /// How to interpret [`Artifact::value`].
    pub kind: ArtifactKind,
    /// Where the artifact lives.
    pub scope: ArtifactScope,
    /// Severity hint for consumers.
    pub severity: ArtifactSeverity,
    /// The path, relative path, file name or content substring, per [`kind`].
    ///
    /// [`kind`]: Artifact::kind
    pub value: &'static str,
    /// Human-readable description of the trace.
    pub description: &'static str,
}

impl Artifact {
    /// The distinctive string a raw disk-image scan should grep for.
    ///
    /// For path kinds this is the final path component, because a filesystem
    /// image stores directory entries by basename, not by full path, so a search
    /// for `config/nails.toml` would never match while `nails.toml` will.
    pub fn image_token(&self) -> &str {
        match self.kind {
            ArtifactKind::AbsolutePath | ArtifactKind::HiddenRootPath => Path::new(self.value)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or(self.value),
            ArtifactKind::Basename | ArtifactKind::ContentMarker => self.value,
        }
    }

    /// Resolve to an absolute filesystem path for the kinds that occupy exactly
    /// one, given the hidden volume root. Content markers and bare basenames can
    /// appear in many places and return `None`.
    pub fn resolve_path(&self, hidden_root: &Path) -> Option<PathBuf> {
        match self.kind {
            ArtifactKind::AbsolutePath => Some(PathBuf::from(self.value)),
            ArtifactKind::HiddenRootPath => Some(hidden_root.join(self.value)),
            ArtifactKind::Basename | ArtifactKind::ContentMarker => None,
        }
    }
}

/// The registry: every trace an activation can leave behind, in one place.
pub const ARTIFACTS: &[Artifact] = &[
    Artifact {
        id: "config-file",
        kind: ArtifactKind::HiddenRootPath,
        scope: ArtifactScope::HiddenRoot,
        severity: ArtifactSeverity::Info,
        value: "config/nails.toml",
        description: "Per-volume configuration file on the hidden root.",
    },
    Artifact {
        id: "state-file",
        kind: ArtifactKind::HiddenRootPath,
        scope: ArtifactScope::HiddenRoot,
        severity: ArtifactSeverity::Info,
        value: "state.json",
        description: "Activation state file on the hidden root.",
    },
    Artifact {
        id: "log-file",
        kind: ArtifactKind::HiddenRootPath,
        scope: ArtifactScope::HiddenRoot,
        severity: ArtifactSeverity::Info,
        value: "logs/nails.log",
        description: "Operation log on the hidden root.",
    },
    Artifact {
        id: "deactivation-reports",
        kind: ArtifactKind::HiddenRootPath,
        scope: ArtifactScope::HiddenRoot,
        severity: ArtifactSeverity::Info,
        value: "reports",
        description: "Deactivation self-check reports directory on the hidden root.",
    },
    Artifact {
        id: "nixos-module-source",
        kind: ArtifactKind::HiddenRootPath,
        scope: ArtifactScope::HiddenRoot,
        severity: ArtifactSeverity::Info,
        value: "etc/nixos/nails/configuration.nix",
        description: "Staged hidden NixOS module source on the hidden root.",
    },
    Artifact {
        id: "runtime-dir-legacy",
        kind: ArtifactKind::AbsolutePath,
        scope: ArtifactScope::Runtime,
        severity: ArtifactSeverity::Warn,
        value: "/run/nails",
        description: "Fixed runtime directory used by earlier builds. Current builds use a random per-activation tmpfs, so a leftover at this fixed path is a prior version's teardown failure.",
    },
    Artifact {
        id: "runtime-copy-dir",
        kind: ArtifactKind::AbsolutePath,
        scope: ArtifactScope::Runtime,
        severity: ArtifactSeverity::Warn,
        value: nails_teardown::whole_root::plan::RUNTIME_DIR,
        description: "RAM-backed copy of the binary, config and mount manifest on the decoy /run; removed on deactivation and emergency.",
    },
    Artifact {
        id: "pivot-staging-run-legacy",
        kind: ArtifactKind::AbsolutePath,
        scope: ArtifactScope::Runtime,
        severity: ArtifactSeverity::Warn,
        value: "/run/nails-pivot",
        description: "Fixed overlay pivot staging base used by earlier builds. Current builds stage inside a random per-activation tmpfs, so a leftover here is a prior version's teardown failure.",
    },
    Artifact {
        id: "pivot-staging-legacy",
        kind: ArtifactKind::AbsolutePath,
        scope: ArtifactScope::Decoy,
        severity: ArtifactSeverity::Critical,
        value: "/mnt/nails-pivot",
        description: "Decoy-root pivot staging base used by earlier builds; must be absent from the decoy disk. A leftover here is a persistent trace a prior version failed to remove.",
    },
    Artifact {
        id: "nixos-staged-link",
        kind: ArtifactKind::AbsolutePath,
        scope: ArtifactScope::Decoy,
        severity: ArtifactSeverity::Critical,
        value: "/etc/nixos/nails/configuration.nix",
        description: "Symlink into the hidden NixOS module; must be absent from the decoy /etc/nixos after deactivation.",
    },
    Artifact {
        id: "nixos-import-marker",
        kind: ArtifactKind::ContentMarker,
        scope: ArtifactScope::Decoy,
        severity: ArtifactSeverity::Critical,
        value: NIXOS_IMPORT_MARKER,
        description: "Import line added to hardware-configuration.nix; must be absent from the decoy base config after deactivation.",
    },
    Artifact {
        id: "autostart-notify",
        kind: ArtifactKind::Basename,
        scope: ArtifactScope::Decoy,
        severity: ArtifactSeverity::Warn,
        value: LEGACY_NOTIFY_AUTOSTART_FILE,
        description: "XDG autostart entry written into the overlaid home.",
    },
    Artifact {
        id: "shell-rc-marker",
        kind: ArtifactKind::ContentMarker,
        scope: ArtifactScope::Decoy,
        severity: ArtifactSeverity::Warn,
        value: LEGACY_RC_BEGIN,
        description: "Managed shell-integration block marker appended to a login shell rc file.",
    },
];

/// The autostart entry name earlier, live-overlay releases wrote; still
/// scanned for, because a decoy may carry one from such a release.
pub const LEGACY_NOTIFY_AUTOSTART_FILE: &str = "nails-notify.desktop";

/// The shell-integration block marker earlier releases wrote; still scanned for.
const LEGACY_RC_BEGIN: &str = "# >>> managed shell integration (auto-removed on deactivation) >>>";

/// The full registry.
pub fn artifacts() -> &'static [Artifact] {
    ARTIFACTS
}

/// The registry entry with the given id, if any. Lets a consumer reference a
/// single artifact (e.g. the import marker) without re-hardcoding its value.
pub fn artifact(id: &str) -> Option<&'static Artifact> {
    ARTIFACTS.iter().find(|entry| entry.id == id)
}

/// Serializable view of one artifact, including the derived image token.
#[derive(Debug, Clone, Serialize)]
struct IndicatorEntry {
    id: &'static str,
    kind: ArtifactKind,
    scope: ArtifactScope,
    severity: ArtifactSeverity,
    value: &'static str,
    image_token: String,
    description: &'static str,
}

/// Serializable document exported to `nix/e2e-tests/fixtures/indicators.json`.
#[derive(Debug, Clone, Serialize)]
struct IndicatorDocument {
    schema: &'static str,
    note: &'static str,
    artifacts: Vec<IndicatorEntry>,
}

/// Schema tag for the exported indicators document.
const INDICATORS_SCHEMA: &str = "nails-artifact-indicators/v1";

/// Render the registry as the pretty-printed JSON committed to
/// `nix/e2e-tests/fixtures/indicators.json`. The output ends with a trailing
/// newline so it round-trips cleanly through editors and the drift test.
pub fn indicators_json() -> String {
    let document = IndicatorDocument {
        schema: INDICATORS_SCHEMA,
        note: "Generated from nails-base/src/artifacts.rs. Do not edit by hand; run \
               `cargo test -p nails-base artifacts -- --ignored regenerate_indicators_json`.",
        artifacts: ARTIFACTS
            .iter()
            .map(|entry| IndicatorEntry {
                id: entry.id,
                kind: entry.kind,
                scope: entry.scope,
                severity: entry.severity,
                value: entry.value,
                image_token: entry.image_token().to_string(),
                description: entry.description,
            })
            .collect(),
    };

    let mut json =
        serde_json::to_string_pretty(&document).expect("artifact registry is always serializable");
    json.push('\n');
    json
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Path to the committed export, relative to this crate's manifest.
    fn indicators_fixture_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("nix/e2e-tests/fixtures/indicators.json")
    }

    #[test]
    fn registry_is_non_empty_and_well_formed() {
        assert!(!ARTIFACTS.is_empty());
        for entry in ARTIFACTS {
            assert!(!entry.id.is_empty(), "artifact id must not be empty");
            assert!(
                !entry.value.is_empty(),
                "artifact {} has an empty value",
                entry.id
            );
            assert!(
                !entry.description.is_empty(),
                "artifact {} has an empty description",
                entry.id
            );
            assert!(
                !entry.image_token().is_empty(),
                "artifact {} has an empty image token",
                entry.id
            );
        }
    }

    #[test]
    fn artifact_ids_are_unique() {
        let mut ids: Vec<&str> = ARTIFACTS.iter().map(|entry| entry.id).collect();
        ids.sort_unstable();
        let unique = ids.len();
        ids.dedup();
        assert_eq!(unique, ids.len(), "duplicate artifact id in the registry");
    }

    #[test]
    fn config_and_state_names_are_the_canonical_literals() {
        assert_eq!(CONFIG_DIR_NAME, "config");
        assert_eq!(CONFIG_FILE_NAME, "nails.toml");
        assert_eq!(STATE_FILE_NAME, "state.json");
    }

    #[test]
    fn hidden_root_filename_entries_match_their_owning_constants() {
        // The hidden-root path entries must stay in step with the constants that
        // actually produce those files, so the registry never drifts from the
        // write paths it describes.
        let config = artifact("config-file").unwrap();
        assert_eq!(
            config.value,
            format!("{CONFIG_DIR_NAME}/{CONFIG_FILE_NAME}")
        );

        let state = artifact("state-file").unwrap();
        assert_eq!(state.value, STATE_FILE_NAME);

        let log = artifact("log-file").unwrap();
        assert!(
            log.value.ends_with(crate::logging::LOG_FILE_NAME),
            "log entry {} must end with the log file name",
            log.value
        );

        let import = artifact("nixos-import-marker").unwrap();
        assert_eq!(import.value, NIXOS_IMPORT_MARKER);
    }

    #[test]
    fn image_token_is_the_basename_for_path_kinds() {
        assert_eq!(artifact("config-file").unwrap().image_token(), "nails.toml");
        assert_eq!(artifact("state-file").unwrap().image_token(), "state.json");
        assert_eq!(
            artifact("runtime-dir-legacy").unwrap().image_token(),
            "nails"
        );
        assert_eq!(
            artifact("nixos-import-marker").unwrap().image_token(),
            NIXOS_IMPORT_MARKER
        );
    }

    #[test]
    fn resolve_path_joins_hidden_root_only_for_path_kinds() {
        let root = Path::new("/mnt/data");
        assert_eq!(
            artifact("config-file").unwrap().resolve_path(root),
            Some(PathBuf::from("/mnt/data/config/nails.toml"))
        );
        assert_eq!(
            artifact("runtime-dir-legacy").unwrap().resolve_path(root),
            Some(PathBuf::from("/run/nails"))
        );
        assert_eq!(
            artifact("autostart-notify").unwrap().resolve_path(root),
            None
        );
        assert_eq!(
            artifact("nixos-import-marker").unwrap().resolve_path(root),
            None
        );
    }

    #[test]
    fn indicators_json_is_valid_and_lists_every_artifact() {
        let json = indicators_json();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["schema"], INDICATORS_SCHEMA);
        let listed = parsed["artifacts"].as_array().unwrap();
        assert_eq!(listed.len(), ARTIFACTS.len());
        assert!(json.ends_with('\n'));
    }

    /// Regenerate the committed export. Ignored by default; run with
    /// `cargo test -p nails-base artifacts -- --ignored regenerate_indicators_json`
    /// after changing the registry, then commit the updated fixture.
    #[test]
    #[ignore = "writes the committed indicators.json; run explicitly to regenerate"]
    fn regenerate_indicators_json() {
        let path = indicators_fixture_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, indicators_json()).unwrap();
    }

    #[test]
    fn committed_indicators_json_matches_the_registry() {
        let path = indicators_fixture_path();
        let committed = std::fs::read_to_string(&path).unwrap_or_else(|err| {
            panic!(
                "cannot read {}: {err}. Regenerate it with \
                 `cargo test -p nails-base artifacts -- --ignored regenerate_indicators_json`",
                path.display()
            )
        });
        assert_eq!(
            committed,
            indicators_json(),
            "indicators.json has drifted from the artifact registry. Regenerate it with \
             `cargo test -p nails-base artifacts -- --ignored regenerate_indicators_json`"
        );
    }
}
