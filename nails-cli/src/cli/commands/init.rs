// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Init command handler
//!
//! Bootstraps the NAILS directory structure on a hidden volume.
//!
//! The attach gate decides first: the target must be a volume of its own,
//! mounted there and not stored on this computer's own storage, so the layout
//! never lands on the decoy disk where the real volume later hides it. Only
//! then is anything probed. The probes for a writable target and for symlink
//! support create and delete a file, which would change a refused directory's
//! timestamps. Every other precondition is checked *before* the first write:
//! the target must be a directory, writable, able to hold symlinks, and free
//! of a file where the layout needs a directory or the reverse; the base
//! hardware configuration must be readable whenever the hidden NixOS layout
//! will be bootstrapped. A refusal therefore leaves the target untouched. Writes then go through the [`Filesystem`] trait, except the
//! state file, which the core state module writes atomically under its lock.
//! Each item is reported as created or already present, and the run ends with
//! the numbered next steps the operator takes to activate.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::cli::args::InitArgs;
use crate::cli::output::envelope::{Envelope, ErrorBody, report_error};
use crate::cli::output::refusal::report_refusal;
use crate::cli::output::{ExitStatus, OutputSettings};
use nails_core::config::CONFIG_FILE_NAME;
use nails_core::hidden_root::{Allow, Assessment, Refusal};
use nails_core::{
    Config, Filesystem, HiddenRoot, HostProfile, NailsError, RealFilesystem, Result, StateFile,
    StateLock, detect, ensure_hidden_hardware_configuration, stage_hidden_config_symlink,
};

/// Platform-agnostic subdirectories to create, each with 0700 permissions.
///
/// These back the whole-root layout on every supported host and are created
/// regardless of the detected platform. The root overlay's upper
/// (`root/upper`) is created at the first activation with the decoy root's
/// own mode and owner, because an overlay's root directory takes its
/// attributes from the upper.
const COMMON_SUBDIRS: &[&str] = &["logs", "config", "root", "root/work"];

/// Subdirectories the NixOS declarative config layer needs.
///
/// Created only when the hidden NixOS layout is bootstrapped (a NixOS host, or an
/// explicit `--hardware-config`). On a host without a config layer (FHS / Debian)
/// these are never written, so init leaves no NixOS paths on such a host. The
/// hidden `/etc/nixos` inside the root upper is created with the hardware
/// configuration below.
const NIXOS_SUBDIRS: &[&str] = &["config/nixos"];

/// Default base hardware configuration consulted on a NixOS host.
const DEFAULT_HARDWARE_CONFIG: &str = "/etc/nixos/hardware-configuration.nix";

/// Whether an item was freshly created or already present.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ItemStatus {
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

    fn label(self) -> &'static str {
        match self {
            ItemStatus::Created => "created",
            ItemStatus::AlreadyPresent => "already present",
        }
    }
}

/// One reported layout item and what happened to it.
#[derive(Debug, Clone, Serialize)]
struct InitItem {
    path: String,
    status: ItemStatus,
}

impl InitItem {
    fn new(path: &Path, status: ItemStatus) -> Self {
        Self {
            path: path.display().to_string(),
            status,
        }
    }
}

/// The machine-readable result of a successful init.
#[derive(Debug, Clone, Serialize)]
struct InitReport {
    root: String,
    items: Vec<InitItem>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
    /// Informational lines, such as why the hidden NixOS layout was skipped.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    notes: Vec<String>,
    next_steps: Vec<String>,
}

/// How the hidden NixOS layout's hardware configuration is bootstrapped.
enum HardwareBootstrap {
    /// Seed the layout from this base hardware configuration.
    From(PathBuf),
    /// Skip the NixOS layout; the string explains why (shown as an info line).
    Skip(String),
}

/// Why init refused, so the caller can map it to an exit status and a message.
#[derive(Debug)]
enum InitFailure {
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

/// Execute the init command.
///
/// # Arguments
///
/// * `settings` - Output settings resolved once from the global flags
/// * `args` - The `init` arguments (target path and bootstrap flags)
/// * `config_override` - The global `--config`, which init does not use
///
/// # Returns
///
/// - [`ExitStatus::Ok`] once the layout exists
/// - [`ExitStatus::Config`] when the global `--config` was passed
/// - [`ExitStatus::PreflightRefused`] when the attach gate refuses the target
///   or a precondition is not met
/// - [`ExitStatus::Failed`] when a filesystem operation fails
pub fn execute(
    settings: &OutputSettings,
    args: &InitArgs,
    config_override: Option<&Path>,
) -> ExitStatus {
    let json = settings.is_json();

    // init takes its target positionally and writes a fixed layout; the global
    // --config (which points at an existing config file) has no meaning here, so
    // accepting it silently would hide an operator mistake.
    if config_override.is_some() {
        return report_error(
            json,
            "init",
            ExitStatus::Config,
            ErrorBody::new(
                "config",
                "nails init takes the hidden volume path as its positional argument; \
                 the global --config flag is not used by init",
            )
            .with_hint("run `nails init <hidden-volume-root>`"),
        );
    }

    run(settings, &RealFilesystem, args)
}

/// Drive init against a filesystem: validate, apply, report.
fn run<F: Filesystem>(settings: &OutputSettings, fs: &F, args: &InitArgs) -> ExitStatus {
    let json = settings.is_json();

    let plan = match plan(fs, args) {
        Ok(plan) => plan,
        Err(InitFailure::NotSeparate(refusal)) => {
            return report_refusal(json, "init", &refusal);
        }
        Err(InitFailure::Preconditions(failures)) => {
            return report_error(
                json,
                "init",
                ExitStatus::PreflightRefused,
                ErrorBody::new("preconditions", failures.join("; ")),
            );
        }
        Err(InitFailure::Io(error)) => {
            return report_error(
                json,
                "init",
                ExitStatus::Failed,
                ErrorBody::new("io", error.to_string()),
            );
        }
    };

    let report = match apply(fs, &args.path, plan) {
        Ok(report) => report,
        Err(error) => {
            return report_error(
                json,
                "init",
                ExitStatus::Failed,
                ErrorBody::new("io", error.to_string()),
            );
        }
    };

    render_report(settings, &report);
    ExitStatus::Ok
}

/// Check every precondition and resolve the hardware bootstrap source.
///
/// The attach gate runs first and alone: a refused target returns
/// [`InitFailure::NotSeparate`] before any probe touches it. On any other
/// precondition failure this returns [`InitFailure::Preconditions`] with every
/// failing reason and performs no write, so a refusal leaves the target
/// untouched.
fn plan<F: Filesystem>(fs: &F, args: &InitArgs) -> std::result::Result<InitPlan, InitFailure> {
    let base = &args.path;
    let allow = if args.allow_decoy_storage {
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
    // skipped on a host without a config layer.
    let bootstrap = resolve_bootstrap(fs, args)?;
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

/// A validated plan: what to bootstrap and the warnings to surface.
struct InitPlan {
    bootstrap: HardwareBootstrap,
    warnings: Vec<String>,
}

/// Decide where the hidden NixOS layout's base hardware config comes from.
///
/// `--no-hardware-config` skips the layout; `--hardware-config` names the base
/// explicitly (and asserts NixOS intent, so the platform seam is not consulted);
/// otherwise the host is resolved through the platform seam ([`detect`]). Only a
/// host with a declarative config layer (NixOS) is bootstrapped with the hidden
/// NixOS layout; every other supported host (FHS / Debian) is overlay-only and
/// the layout is skipped, so init writes no NixOS paths there. An unsupported
/// host (ostree / image-based, or non-systemd) is refused before any write.
fn resolve_bootstrap<F: Filesystem>(
    fs: &F,
    args: &InitArgs,
) -> std::result::Result<HardwareBootstrap, InitFailure> {
    if args.no_hardware_config {
        return Ok(HardwareBootstrap::Skip(
            "--no-hardware-config: skipping the hidden NixOS layout".to_string(),
        ));
    }

    if let Some(path) = &args.hardware_config {
        return Ok(HardwareBootstrap::From(path.clone()));
    }

    let profile = detect(fs)?;
    profile
        .require_supported()
        .map_err(|error| InitFailure::Preconditions(vec![error.to_string()]))?;

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
fn apply<F: Filesystem>(fs: &F, base: &Path, plan: InitPlan) -> Result<InitReport> {
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
            let etc_nixos = nails_core::nixos::config::hidden_etc_nixos(base);
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
fn next_steps(base: &Path) -> Vec<String> {
    let root = base.display();
    vec![
        format!(
            "copy the nails binary onto the hidden volume: install -m0755 <source>/nails {root}/nails"
        ),
        format!(
            "optionally review the generated config: $EDITOR {}",
            base.join("config").join(CONFIG_FILE_NAME).display()
        ),
        format!("preview activation read-only: sudo {root}/nails activate --dry-run"),
        format!("activate the hidden environment: sudo {root}/nails activate"),
    ]
}

/// Render the report: one JSON envelope under `--json`, otherwise any warnings
/// on stderr (kept under `-q`) and [`render_text`] on stdout.
fn render_report(settings: &OutputSettings, report: &InitReport) {
    if settings.is_json() {
        Envelope::success("init", report).print();
        return;
    }

    for warning in &report.warnings {
        eprintln!("warning: {warning}");
    }

    if settings.is_quiet() {
        return;
    }

    print!("{}", render_text(report));
}

/// The human-readable report: the item lines, any informational notes, and the
/// numbered next steps, which always come last.
fn render_text(report: &InitReport) -> String {
    let mut out = String::new();
    for item in &report.items {
        let _ = writeln!(out, "  {}: {}", item.status.label(), item.path);
    }
    for note in &report.notes {
        let _ = writeln!(out, "info: {note}");
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "NAILS layout initialized at {}", report.root);
    let _ = writeln!(out);
    let _ = writeln!(out, "Next steps:");
    for (index, step) in report.next_steps.iter().enumerate() {
        let _ = writeln!(out, "  {}. {step}", index + 1);
    }
    out
}

#[cfg(test)]
mod tests;
