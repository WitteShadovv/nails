// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The `init` operation: bootstrap the NAILS directory structure on a hidden
//! volume.
//!
//! The attach gate decides first: the target must be a volume of its own,
//! mounted there and not stored on this computer's own storage, so the layout
//! never lands on the decoy disk where the real volume later hides it. Only then
//! is anything probed. Every other precondition is checked before the first
//! write, so a refusal leaves the target untouched. The operation is split into
//! [`plan`] (check everything, resolve the bootstrap source, write nothing) and
//! [`apply`] (write the layout, reporting each item), so a front end can show
//! what it would do before it does it.

use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::config::CONFIG_FILE_NAME;
use crate::hidden_root::{Allow, Assessment, Refusal};
use crate::{
    Config, Filesystem, HiddenRoot, HostProfile, NailsError, Result, StateFile, StateLock, detect,
    ensure_hidden_hardware_configuration, stage_hidden_config_symlink,
};

/// Platform-agnostic subdirectories to create, each with 0700 permissions.
///
/// These back the whole-root layout on every supported host and are created
/// regardless of the detected platform. The root overlay's upper
/// (`root/upper`) is created at the first activation with the decoy root's
/// own mode and owner, because an overlay's root directory takes its
/// attributes from the upper.
pub const COMMON_SUBDIRS: &[&str] = &["logs", "config", "root", "root/work"];

/// Subdirectories the NixOS declarative config layer needs.
///
/// Created only when the hidden NixOS layout is bootstrapped (a NixOS host, or an
/// explicit `--hardware-config`). On a host without a config layer (FHS / Debian)
/// these are never written, so init leaves no NixOS paths on such a host. The
/// hidden `/etc/nixos` inside the root upper is created with the hardware
/// configuration below.
pub const NIXOS_SUBDIRS: &[&str] = &["config/nixos"];

/// Default base hardware configuration consulted on a NixOS host.
pub const DEFAULT_HARDWARE_CONFIG: &str = "/etc/nixos/hardware-configuration.nix";

/// What `init` should bootstrap.
#[derive(Debug, Clone, Default)]
pub struct InitOptions {
    /// The hidden volume root to bootstrap.
    pub path: PathBuf,
    /// Proceed on storage the decoy uses, accepting the risk.
    pub allow_decoy_storage: bool,
    /// Skip the hidden NixOS layout.
    pub no_hardware_config: bool,
    /// Seed the NixOS layout from this base hardware configuration.
    pub hardware_config: Option<PathBuf>,
}

/// Whether an item was freshly created or already present.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemStatus {
    /// The item did not exist and was created.
    Created,
    /// The item was already present and left as it was.
    AlreadyPresent,
}

impl ItemStatus {
    fn of(existed: bool) -> Self {
        if existed {
            ItemStatus::AlreadyPresent
        } else {
            ItemStatus::Created
        }
    }

    /// The human label for the item's status.
    pub fn label(self) -> &'static str {
        match self {
            ItemStatus::Created => "created",
            ItemStatus::AlreadyPresent => "already present",
        }
    }
}

/// One reported layout item and what happened to it.
#[derive(Debug, Clone, Serialize)]
pub struct InitItem {
    /// The item's path.
    pub path: String,
    /// Whether it was created or already present.
    pub status: ItemStatus,
}

impl InitItem {
    /// A reported item at `path` with `status`.
    pub fn new(path: &Path, status: ItemStatus) -> Self {
        Self {
            path: path.display().to_string(),
            status,
        }
    }
}

/// The machine-readable result of a successful init.
#[derive(Debug, Clone, Serialize)]
pub struct InitReport {
    /// The hidden volume root the layout was written to.
    pub root: String,
    /// Each layout item and what happened to it.
    pub items: Vec<InitItem>,
    /// Warnings to surface (an untested release, accepted decoy storage).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    /// Informational lines, such as why the hidden NixOS layout was skipped.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    /// The numbered next steps the operator takes to activate.
    pub next_steps: Vec<String>,
}

/// How the hidden NixOS layout's hardware configuration is bootstrapped.
pub enum HardwareBootstrap {
    /// Seed the layout from this base hardware configuration.
    From(PathBuf),
    /// Skip the NixOS layout; the string explains why (shown as an info line).
    Skip(String),
}

/// Why init refused, so a front end can map it to an exit status and a message.
#[derive(Debug)]
pub enum InitFailure {
    /// The attach gate refused the target; nothing was probed or written.
    NotSeparate(Refusal),
    /// One or more preconditions were not met; nothing was written.
    Preconditions(Vec<String>),
    /// A filesystem query or write failed.
    Io(NailsError),
}

impl From<NailsError> for InitFailure {
    fn from(error: NailsError) -> Self {
        InitFailure::Io(error)
    }
}

/// A validated plan: what to bootstrap and the warnings to surface.
pub struct InitPlan {
    /// How the hidden NixOS layout is bootstrapped (or why it is skipped).
    pub bootstrap: HardwareBootstrap,
    /// Warnings to surface once the layout is written.
    pub warnings: Vec<String>,
}

/// Check every precondition and resolve the hardware bootstrap source.
///
/// The attach gate runs first and alone: a refused target returns
/// [`InitFailure::NotSeparate`] before any probe touches it. On any other
/// precondition failure this returns [`InitFailure::Preconditions`] with every
/// failing reason and performs no write, so a refusal leaves the target
/// untouched.
pub fn plan<F: Filesystem>(
    fs: &F,
    options: &InitOptions,
) -> std::result::Result<InitPlan, InitFailure> {
    let base = &options.path;
    let allow = if options.allow_decoy_storage {
        Allow::DecoyStorage
    } else {
        Allow::Nothing
    };
    let mut warnings = Vec::new();
    match HiddenRoot::assess_allowing(fs, base, allow)? {
        Assessment::Attached => {}
        Assessment::Warned(refusal) => warnings.push(refusal.warning()),
        Assessment::Refused(refusal) => return Err(InitFailure::NotSeparate(refusal)),
    }

    let mut failures = Vec::new();
    if !fs.is_directory(base)? {
        failures.push(format!("target {} is not a directory", base.display()));
    }

    if !fs.is_writable(base)? {
        failures.push(format!("target {} is not writable", base.display()));
    }

    if !fs.supports_symlinks(base)? {
        failures.push(format!(
            "the filesystem at {} does not support symlinks, which the overlay layout needs",
            base.display()
        ));
    }

    // Resolving the bootstrap source consults the platform seam on the auto path
    // and refuses an unsupported host before any write, so the layout is only ever
    // written on a host NAILS can operate on, and the NixOS-only subdirectories are
    // skipped on a host without a config layer. A release NAILS has not been
    // tested on adds its warning.
    let bootstrap = resolve_bootstrap(fs, options, &mut warnings)?;
    let nixos_layout = matches!(bootstrap, HardwareBootstrap::From(_));

    failures.extend(obstructions(fs, base, nixos_layout)?);

    if let HardwareBootstrap::From(hardware) = &bootstrap
        && !(fs.path_exists(hardware)? && fs.is_readable(hardware)?)
    {
        failures.push(format!(
            "base hardware configuration {} is missing or unreadable \
             (pass --hardware-config <PATH>, or --no-hardware-config to skip the NixOS layout)",
            hardware.display()
        ));
    }

    if failures.is_empty() {
        Ok(InitPlan {
            bootstrap,
            warnings,
        })
    } else {
        Err(InitFailure::Preconditions(failures))
    }
}

/// The subdirectories init creates for this run.
///
/// Always the [`COMMON_SUBDIRS`]; the [`NIXOS_SUBDIRS`] are added only when the
/// hidden NixOS layout is being bootstrapped, so a host without a config layer
/// (FHS / Debian) never gets any NixOS paths.
fn layout_subdirs(nixos_layout: bool) -> Vec<&'static str> {
    let mut dirs: Vec<&'static str> = COMMON_SUBDIRS.to_vec();
    if nixos_layout {
        dirs.extend_from_slice(NIXOS_SUBDIRS);
    }
    dirs
}

/// Existing entries of the wrong kind where the layout needs a directory or a
/// file.
///
/// Found before the first write, so init neither creates part of the layout nor
/// changes the permissions of something it would then fail to replace.
fn obstructions<F: Filesystem>(fs: &F, base: &Path, nixos_layout: bool) -> Result<Vec<String>> {
    let mut found = Vec::new();
    for dir_name in layout_subdirs(nixos_layout) {
        let dir = base.join(dir_name);
        if fs.path_exists(&dir)? && !fs.is_directory(&dir)? {
            found.push(format!(
                "{} exists but is not a directory; move it aside first",
                dir.display()
            ));
        }
    }
    for file in [
        base.join("config").join(CONFIG_FILE_NAME),
        base.join("state.json"),
    ] {
        if fs.path_exists(&file)? && fs.is_directory(&file)? {
            found.push(format!(
                "{} exists but is a directory; move it aside first",
                file.display()
            ));
        }
    }
    Ok(found)
}

/// Decide where the hidden NixOS layout's base hardware config comes from.
///
/// `--no-hardware-config` skips the layout; `--hardware-config` names the base
/// explicitly (and asserts NixOS intent, so the platform seam is not consulted);
/// otherwise the host is resolved through the platform seam ([`detect`]). Only a
/// host with a declarative config layer (NixOS) is bootstrapped with the hidden
/// NixOS layout; every other supported host (FHS / Debian) is overlay-only and
/// the layout is skipped, so init writes no NixOS paths there. An unsupported
/// host (ostree / image-based, or non-systemd) is refused before any write, and
/// a release NAILS has not been tested on is admitted with its warning added to
/// `warnings`.
fn resolve_bootstrap<F: Filesystem>(
    fs: &F,
    options: &InitOptions,
    warnings: &mut Vec<String>,
) -> std::result::Result<HardwareBootstrap, InitFailure> {
    if options.no_hardware_config {
        return Ok(HardwareBootstrap::Skip(
            "--no-hardware-config: skipping the hidden NixOS layout".to_string(),
        ));
    }

    if let Some(path) = &options.hardware_config {
        return Ok(HardwareBootstrap::From(path.clone()));
    }

    let profile = detect(fs)?;
    profile
        .require_supported()
        .map_err(|error| InitFailure::Preconditions(vec![error.to_string()]))?;
    warnings.extend(profile.support_warning.clone());

    if profile.has_config_layer() {
        Ok(HardwareBootstrap::From(PathBuf::from(
            DEFAULT_HARDWARE_CONFIG,
        )))
    } else {
        Ok(HardwareBootstrap::Skip(format!(
            "{} has no NixOS config layer (overlay-only); skipping the hidden NixOS layout",
            platform_label(&profile)
        )))
    }
}

/// A short, human-readable name for the detected host, for the skip note.
fn platform_label(profile: &HostProfile) -> String {
    match profile.id.as_deref() {
        Some(id) => format!("host '{id}'"),
        None => "this host".to_string(),
    }
}

/// Write the layout, reporting each item's status. Called only after [`plan`].
pub fn apply<F: Filesystem>(fs: &F, base: &Path, plan: InitPlan) -> Result<InitReport> {
    let mut items = Vec::new();
    let mut notes = Vec::new();

    let nixos_layout = matches!(plan.bootstrap, HardwareBootstrap::From(_));
    for dir_name in layout_subdirs(nixos_layout) {
        let dir = base.join(dir_name);
        let existed = fs.path_exists(&dir)?;
        if !existed {
            fs.create_directory(&dir)?;
        }
        fs.set_permissions(&dir, 0o700)?;
        items.push(InitItem::new(&dir, ItemStatus::of(existed)));
    }

    let config_path = base.join("config").join(CONFIG_FILE_NAME);
    let config_existed = fs.path_exists(&config_path)?;
    if !config_existed {
        fs.write_file_content(&config_path, &Config::init_template(base))?;
        fs.set_permissions(&config_path, 0o600)?;
    }
    items.push(InitItem::new(&config_path, ItemStatus::of(config_existed)));

    items.push(write_state_file(base)?);

    match plan.bootstrap {
        HardwareBootstrap::From(hardware) => {
            let hidden_config = base.join("config/nixos/configuration.nix");
            let etc_nixos = crate::nixos::config::hidden_etc_nixos(base);
            let hidden_hardware = etc_nixos.join("hardware-configuration.nix");
            let staged_symlink = etc_nixos.join("nails/configuration.nix");
            let config_existed = fs.path_exists(&hidden_config)?;
            let hardware_existed = fs.path_exists(&hidden_hardware)?;
            let symlink_existed = fs.path_exists(&staged_symlink)?;

            stage_hidden_config_symlink(fs, base)?;
            ensure_hidden_hardware_configuration(fs, base, &hardware)?;

            items.push(InitItem::new(
                &hidden_config,
                ItemStatus::of(config_existed),
            ));
            items.push(InitItem::new(
                &hidden_hardware,
                ItemStatus::of(hardware_existed),
            ));
            items.push(InitItem::new(
                &staged_symlink,
                ItemStatus::of(symlink_existed),
            ));
        }
        HardwareBootstrap::Skip(reason) => notes.push(reason),
    }

    Ok(InitReport {
        root: base.display().to_string(),
        items,
        warnings: plan.warnings,
        notes,
        next_steps: next_steps(base),
    })
}

/// Create the initial state file under the exclusive state lock.
///
/// The lock is held only while the state file is touched, so init cannot race a
/// concurrent activate/deactivate over the same hidden volume.
fn write_state_file(base: &Path) -> Result<InitItem> {
    let state_path = base.join("state.json");
    let _state_lock = StateLock::try_acquire(base)?;

    if state_path.exists() {
        if !state_path.is_file() {
            return Err(NailsError::InvalidState(format!(
                "state path exists but is not a file: {}",
                state_path.display()
            )));
        }
        return Ok(InitItem::new(&state_path, ItemStatus::AlreadyPresent));
    }

    StateFile::default().save_with_custom_root(&state_path, base)?;
    Ok(InitItem::new(&state_path, ItemStatus::Created))
}

/// The numbered steps the operator takes after init to reach activation.
///
/// Init runs on the decoy, so none of them edits a file there: an editor
/// leaves its own traces (swap and backup files, `~/.viminfo`, recent-file
/// lists). The binary is not mentioned: the documented setup runs init from
/// `<root>/nails` already, and the `binary-location` check warns at `check`
/// and `activate` when it runs from anywhere else.
pub fn next_steps(base: &Path) -> Vec<String> {
    let root = base.display();
    let config = base.join("config").join(CONFIG_FILE_NAME);
    vec![
        format!(
            "optionally change the configuration, but not on the decoy: prepare {config} on \
             another machine, or write {config}.new inside a hidden session and move it into \
             place afterwards",
            config = config.display()
        ),
        format!("check readiness without changing anything: sudo {root}/nails check"),
        format!("activate the hidden environment: sudo {root}/nails activate"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::FakePlatform;
    use crate::{MockFilesystem, PathKind};
    use tempfile::TempDir;

    /// A mock whose `root` reads as a mounted, writable, symlink-capable volume
    /// of its own, so the attach gate admits it and planning reaches the
    /// preconditions. Mirrors the CLI suite's helper of the same name.
    fn attached_mock(root: &Path) -> MockFilesystem {
        let fs = MockFilesystem::new();
        let root_str = root.to_str().unwrap();
        fs.mock_set_path_exists(root_str, true);
        fs.mock_set_path_type(root_str, PathKind::Dir);
        fs.mock_set_writable(root_str, true);
        fs.mock_set_supports_symlinks(root, true);
        // The default mock device id for an unmapped path differs from `/`'s, so
        // a mount here reads as a filesystem of its own and the gate admits it.
        fs.mock_set_mounted(root, true);
        fs
    }

    /// Options that bootstrap `root` from an explicit base hardware config, which
    /// pins the NixOS layout without consulting the host detector.
    fn options_from(root: &Path, hardware_config: &str) -> InitOptions {
        InitOptions {
            path: root.to_path_buf(),
            hardware_config: Some(PathBuf::from(hardware_config)),
            ..Default::default()
        }
    }

    #[test]
    fn plan_validates_a_mounted_writable_symlink_capable_volume() {
        let root = Path::new("/mnt/data");
        let fs = attached_mock(root);
        let hardware = "/seed/hardware-configuration.nix";
        fs.mock_set_path_exists(hardware, true);
        fs.mock_set_readable(hardware, true);

        let plan = plan(&fs, &options_from(root, hardware)).expect(
            "a mounted, writable, symlink-capable volume with a readable base config validates",
        );

        // The explicit base config pins the NixOS layout, and nothing warns.
        assert!(matches!(plan.bootstrap, HardwareBootstrap::From(_)));
        assert!(plan.warnings.is_empty(), "{:?}", plan.warnings);
    }

    #[test]
    fn plan_rejects_a_hardware_config_that_exists_but_is_unreadable() {
        let root = Path::new("/mnt/data");
        let fs = attached_mock(root);
        let hardware = "/seed/hardware-configuration.nix";
        // Present on disk, but not readable: planning must still refuse it, since
        // the layout cannot be seeded from a base config it cannot read.
        fs.mock_set_path_exists(hardware, true);
        fs.mock_set_readable(hardware, false);

        match plan(&fs, &options_from(root, hardware)) {
            Err(InitFailure::Preconditions(failures)) => assert!(
                failures
                    .iter()
                    .any(|reason| reason.contains("missing or unreadable")),
                "{failures:?}"
            ),
            other => panic!("expected a precondition failure, got {:?}", other.is_ok()),
        }
    }

    #[test]
    fn layout_subdirs_adds_the_nixos_paths_only_when_requested() {
        // Overlay-only: exactly the platform-agnostic subdirectories, no more.
        assert_eq!(layout_subdirs(false), COMMON_SUBDIRS.to_vec());
        assert!(!layout_subdirs(false).contains(&"config/nixos"));

        // With the NixOS layout: the common subdirectories plus the NixOS ones.
        let expected: Vec<&str> = COMMON_SUBDIRS
            .iter()
            .chain(NIXOS_SUBDIRS)
            .copied()
            .collect();
        assert_eq!(layout_subdirs(true), expected);
        assert!(layout_subdirs(true).contains(&"config/nixos"));
    }

    #[test]
    fn obstructions_are_empty_when_the_layout_is_clear() {
        let base = Path::new("/mnt/data");

        // A pristine volume has nothing in the way.
        let clear = MockFilesystem::new();
        assert!(obstructions(&clear, base, true).unwrap().is_empty());

        // Layout directories that already exist as proper directories are not
        // obstructions, so a re-run does not flag its own prior layout.
        let present = MockFilesystem::new();
        present.mock_set_path_type(base.join("logs").to_str().unwrap(), PathKind::Dir);
        present.mock_set_path_type(base.join("root").to_str().unwrap(), PathKind::Dir);
        assert!(obstructions(&present, base, false).unwrap().is_empty());

        // An already-present config file and state file of the right kind are
        // likewise fine (they are the markers a re-run expects to find).
        let files = MockFilesystem::new();
        files.mock_set_path_type(
            base.join("config").join(CONFIG_FILE_NAME).to_str().unwrap(),
            PathKind::File,
        );
        files.mock_set_path_type(base.join("state.json").to_str().unwrap(), PathKind::File);
        assert!(obstructions(&files, base, false).unwrap().is_empty());
    }

    #[test]
    fn obstructions_flag_entries_of_the_wrong_kind() {
        let base = Path::new("/mnt/data");

        // A file where the layout needs a directory is reported, naming the path.
        let file_in_the_way = MockFilesystem::new();
        file_in_the_way.mock_set_path_type(base.join("logs").to_str().unwrap(), PathKind::File);
        let found = obstructions(&file_in_the_way, base, false).unwrap();
        assert!(
            found
                .iter()
                .any(|reason| reason.contains("/mnt/data/logs exists but is not a directory")),
            "{found:?}"
        );

        // A directory where the layout needs the state file is reported too.
        let dir_in_the_way = MockFilesystem::new();
        dir_in_the_way.mock_set_path_type(base.join("state.json").to_str().unwrap(), PathKind::Dir);
        let found = obstructions(&dir_in_the_way, base, false).unwrap();
        assert!(
            found
                .iter()
                .any(|reason| reason.contains("/mnt/data/state.json exists but is a directory")),
            "{found:?}"
        );
    }

    #[test]
    fn platform_label_names_the_host_or_falls_back() {
        let mut profile = FakePlatform::fhs().host_profile();
        profile.id = Some("debian".to_string());
        assert_eq!(platform_label(&profile), "host 'debian'");

        profile.id = Some("ubuntu".to_string());
        assert_eq!(platform_label(&profile), "host 'ubuntu'");

        // Without an os-release ID the label falls back to a generic phrase.
        profile.id = None;
        assert_eq!(platform_label(&profile), "this host");
    }

    #[test]
    fn apply_creates_the_layout_on_disk_and_writes_the_config() {
        // A real temp dir backs the state file and its lock (written through the
        // core's own atomic path); the mock backs the layout directory writes.
        let tmp = TempDir::new().unwrap();
        let base = tmp.path();
        let fs = attached_mock(base);

        let overlay_plan = InitPlan {
            bootstrap: HardwareBootstrap::Skip(
                "overlay-only: skipping the hidden NixOS layout".to_string(),
            ),
            warnings: Vec::new(),
        };
        let report = apply(&fs, base, overlay_plan).expect("apply writes the layout");

        // Each common subdirectory is actually created (not merely reported) and
        // locked down to 0700.
        for rel in COMMON_SUBDIRS {
            let dir = base.join(rel);
            assert!(
                fs.path_exists(&dir).unwrap(),
                "{rel} must be created on the filesystem, not only reported"
            );
            assert_eq!(fs.mock_get_permissions(&dir), Some(0o700), "{rel} mode");
        }
        // The skip keeps every NixOS path off the volume.
        for rel in NIXOS_SUBDIRS {
            assert!(
                !fs.path_exists(&base.join(rel)).unwrap(),
                "{rel} must not be created when the NixOS layout is skipped"
            );
        }

        // The config template is written when none is present.
        let config_path = base.join("config").join(CONFIG_FILE_NAME);
        let expected = Config::init_template(base);
        assert_eq!(
            fs.get_written_content(&config_path).as_deref(),
            Some(expected.as_str()),
            "the init config template must be written when none exists"
        );

        // A fresh run reports everything as freshly created, and the skip is a note.
        assert!(
            report
                .items
                .iter()
                .all(|item| item.status == ItemStatus::Created),
            "{:?}",
            report.items
        );
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("overlay-only")),
            "{:?}",
            report.notes
        );
    }

    #[test]
    fn write_state_file_keeps_an_existing_regular_state_file() {
        let tmp = TempDir::new().unwrap();
        let base = tmp.path();
        let state_path = base.join("state.json");
        std::fs::write(&state_path, "{}").unwrap();

        // An existing *regular* state file is left in place and reported present,
        // never mistaken for a wrong-kind entry that would abort init.
        let item = write_state_file(base).expect("an existing regular state.json is accepted");
        assert_eq!(item.status, ItemStatus::AlreadyPresent);
        assert_eq!(item.path, state_path.display().to_string());
    }

    #[test]
    fn next_steps_lists_the_three_activation_steps() {
        let steps = next_steps(Path::new("/mnt/data"));

        assert_eq!(steps.len(), 3, "{steps:?}");
        assert!(steps[0].contains("another machine"), "{steps:?}");
        assert!(steps[1].contains("sudo /mnt/data/nails check"), "{steps:?}");
        assert!(
            steps[2].contains("sudo /mnt/data/nails activate"),
            "{steps:?}"
        );
    }
}
