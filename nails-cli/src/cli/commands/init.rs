//! Init command handler
//!
//! Bootstraps the NAILS directory structure on a hidden volume.
//!
//! Every precondition is checked *before* the first write: the target must be a
//! directory, a mounted volume of its own (so the layout never lands on the
//! decoy disk where the real volume later hides it), writable, and able to hold
//! symlinks; the base hardware configuration must be readable whenever the
//! hidden NixOS layout will be bootstrapped. A refusal therefore leaves the
//! target untouched. Writes then go through the [`Filesystem`] trait, except the
//! state file, which the core state module writes atomically under its lock.
//! Each item is reported as created or already present, and the run ends with
//! the numbered next steps the operator takes to activate.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::cli::args::InitArgs;
use crate::cli::output::envelope::{Envelope, ErrorBody, report_error};
use crate::cli::output::{ExitStatus, OutputSettings};
use nails_core::config::CONFIG_FILE_NAME;
use nails_core::{
    AttachState, Config, Filesystem, HiddenRoot, NailsError, RealFilesystem, Result, StateFile,
    StateLock, ensure_hidden_hardware_configuration, stage_hidden_config_symlink,
};

/// Required subdirectories to create, each with 0700 permissions.
const SUBDIRS: &[&str] = &[
    "logs",
    "config",
    "config/nixos",
    "etc",
    "etc/nixos",
    "home",
    "nix",
    ".work",
    ".work/etc",
    ".work/home",
    ".work/nix",
];

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
/// - [`ExitStatus::PreflightRefused`] when a precondition is not met
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
/// On any precondition failure this returns [`InitFailure::Preconditions`] with
/// every failing reason and performs no write, so a refusal leaves the target
/// untouched.
fn plan<F: Filesystem>(fs: &F, args: &InitArgs) -> std::result::Result<InitPlan, InitFailure> {
    let base = &args.path;
    let mut failures = Vec::new();

    if !fs.path_exists(base)? {
        return Err(InitFailure::Preconditions(vec![format!(
            "target {} does not exist (mount the hidden volume there first)",
            base.display()
        )]));
    }

    if !fs.is_directory(base)? {
        failures.push(format!("target {} is not a directory", base.display()));
    }

    let mut warnings = Vec::new();
    if args.allow_unmounted {
        warnings.push(format!(
            "--allow-unmounted: initialising {} without verifying it is a mounted volume; \
             use this only for a directory-style backend",
            base.display()
        ));
    } else {
        match HiddenRoot::verify_attached(fs, base, false)? {
            AttachState::Attached => {}
            AttachState::Unattached(reason) => failures.push(format!(
                "{reason}; mount the hidden volume first, \
                 or pass --allow-unmounted for a directory-style backend"
            )),
        }
    }

    if !fs.is_writable(base)? {
        failures.push(format!("target {} is not writable", base.display()));
    }

    if !fs.supports_symlinks(base)? {
        failures.push(format!(
            "the filesystem at {} does not support symlinks, which the hidden NixOS layout needs",
            base.display()
        ));
    }

    let bootstrap = resolve_bootstrap(fs, args)?;
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

/// A validated plan: what to bootstrap and the warnings to surface.
struct InitPlan {
    bootstrap: HardwareBootstrap,
    warnings: Vec<String>,
}

/// Decide where the hidden NixOS layout's base hardware config comes from.
///
/// `--no-hardware-config` skips the layout; `--hardware-config` names the base
/// explicitly; otherwise the host is probed for NixOS. The probe is a local
/// stand-in: it treats the presence of `/etc/NIXOS` as "this host is NixOS".
/// Replace it with the platform detection seam (`HostProfile`/`Platform::detect`)
/// once that module exists, so other platforms can bootstrap their own layout.
fn resolve_bootstrap<F: Filesystem>(fs: &F, args: &InitArgs) -> Result<HardwareBootstrap> {
    if args.no_hardware_config {
        return Ok(HardwareBootstrap::Skip(
            "--no-hardware-config: skipping the hidden NixOS layout".to_string(),
        ));
    }

    if let Some(path) = &args.hardware_config {
        return Ok(HardwareBootstrap::From(path.clone()));
    }

    if fs.path_exists(Path::new("/etc/NIXOS"))? {
        Ok(HardwareBootstrap::From(PathBuf::from(
            DEFAULT_HARDWARE_CONFIG,
        )))
    } else {
        Ok(HardwareBootstrap::Skip(
            "host is not NixOS (no /etc/NIXOS); skipping the hidden NixOS layout".to_string(),
        ))
    }
}

/// Write the layout, reporting each item's status. Called only after [`plan`].
fn apply<F: Filesystem>(fs: &F, base: &Path, plan: InitPlan) -> Result<InitReport> {
    let mut items = Vec::new();
    let mut notes = Vec::new();

    for dir_name in SUBDIRS {
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
            let hidden_hardware = base.join("etc/nixos/hardware-configuration.nix");
            let staged_symlink = base.join("etc/nixos/nails/configuration.nix");
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
