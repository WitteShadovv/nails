//! Command Execution Abstraction
//!
//! Provides a testable abstraction for executing external commands during
//! NixOS profile building and activation.
//!
//! The `CommandExecutor` trait abstracts command execution to allow:
//! - Real command execution in production (`RealCommandExecutor`)
//! - Mock command execution in tests (`MockCommandExecutor`)
//!
//! This design pattern enables unit testing of the NixOS builder without
//! requiring actual nixos-rebuild or switch-to-configuration execution.

use super::NixOSBuilder;
use crate::error::Result;
use crate::process::{ProcessCommand, ProcessRunner, RealProcessRunner};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// `nix` or `nixos-rebuild` with `args`, taken from the caller's `PATH` (see
/// [`RealCommandExecutor`] for the search-path override).
///
/// Allowed in test runtimes because the builder tests drive both through stub
/// binaries. The child starts from a cleared environment, so `NIX_PATH` is
/// absent by default: a flake build (`clear_nix_path`) leaves it that way so the
/// caller's channel search path cannot influence evaluation, while a
/// channel-based build passes it through explicitly.
fn nix_toolchain_command(
    program: &'static str,
    args: &[&str],
    clear_nix_path: bool,
) -> ProcessCommand {
    let command = ProcessCommand::caller_path(program)
        .args(args)
        .allow_in_test_runtime();
    if clear_nix_path {
        command
    } else {
        command.allow_env("NIX_PATH")
    }
}

/// Non-installing action for `switch-to-configuration` / `nixos-rebuild`.
///
/// Activating or restoring a generation must never reinstall the bootloader or
/// write EFI NVRAM: a boot entry, ESP file or NVRAM variable that enables the
/// hidden mode is itself evidence. This type can only express `test`, so no
/// caller can smuggle a `switch` or `boot` action through
/// [`CommandExecutor::execute_switch_to_configuration`] or into `nixos-rebuild`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwitchAction {
    /// `switch-to-configuration test`: activate the generation for the running
    /// session only, leaving the bootloader, ESP and EFI NVRAM untouched.
    Test,
}

impl SwitchAction {
    /// The literal argument this action passes to `switch-to-configuration`.
    pub fn as_arg(self) -> &'static str {
        match self {
            SwitchAction::Test => "test",
        }
    }
}

/// Trait for executing commands (for testability)
///
/// Abstracts command execution to allow mocking in tests.
/// Production code uses real Command execution, tests use mock.
pub trait CommandExecutor {
    /// Execute nixos-rebuild command
    ///
    /// # Arguments
    ///
    /// - `args`: Command arguments
    ///
    /// # Returns
    ///
    /// - `Ok((success, stdout, stderr))` with command output
    fn execute_nixos_rebuild(
        &self,
        args: &[&str],
        clear_nix_path: bool,
    ) -> Result<(bool, String, String)>;

    /// Execute `nix` command
    fn execute_nix(&self, args: &[&str], clear_nix_path: bool) -> Result<(bool, String, String)>;

    /// Execute switch-to-configuration script
    ///
    /// # Arguments
    ///
    /// - `script_path`: Full path to switch-to-configuration script
    /// - `action`: the non-installing action to run; only `test` is expressible,
    ///   so this can never reinstall the bootloader or write EFI NVRAM
    ///
    /// # Returns
    ///
    /// - `Ok((success, stdout, stderr))` with command output
    fn execute_switch_to_configuration(
        &self,
        script_path: &Path,
        action: SwitchAction,
    ) -> Result<(bool, String, String)>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FlakePreflightSummary {
    pub metadata_checked: bool,
    pub attr_checked: bool,
}

/// Real command executor for production use
///
/// A thin wrapper over [`RealProcessRunner`]. `nix` and `nixos-rebuild` come
/// from the caller's `PATH` unless the executor was given a search path.
#[derive(Debug, Clone, Default)]
pub struct RealCommandExecutor {
    search_path: Option<OsString>,
}

impl RealCommandExecutor {
    /// An executor that looks up `nix` and `nixos-rebuild` only in `dirs`, a
    /// `PATH`-style list, so a test can point it at stub builds without
    /// changing the process environment that every other test thread shares.
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_search_path(dirs: impl Into<OsString>) -> Self {
        Self {
            search_path: Some(dirs.into()),
        }
    }

    fn toolchain_command(
        &self,
        program: &'static str,
        args: &[&str],
        clear_nix_path: bool,
    ) -> ProcessCommand {
        let command = nix_toolchain_command(program, args, clear_nix_path);
        match &self.search_path {
            Some(dirs) => command.search_path(dirs.clone()),
            None => command,
        }
    }
}

impl CommandExecutor for RealCommandExecutor {
    /// Runs the build to completion with a progress heartbeat and no deadline: a
    /// build may legitimately take many minutes, and killing it part-way serves
    /// no one.
    fn execute_nixos_rebuild(
        &self,
        args: &[&str],
        clear_nix_path: bool,
    ) -> Result<(bool, String, String)> {
        run_long_step(
            &self.toolchain_command("nixos-rebuild", args, clear_nix_path),
            "building",
        )
    }

    fn execute_nix(&self, args: &[&str], clear_nix_path: bool) -> Result<(bool, String, String)> {
        RealProcessRunner.run_text(&self.toolchain_command("nix", args, clear_nix_path))
    }

    /// Runs the generation's own script; allowed in test runtimes because the
    /// switch tests point it at stub scripts. Streamed with a heartbeat and never
    /// a deadline — interrupting `switch-to-configuration` would leave the system
    /// in an undefined state.
    fn execute_switch_to_configuration(
        &self,
        script_path: &Path,
        action: SwitchAction,
    ) -> Result<(bool, String, String)> {
        run_long_step(
            &ProcessCommand::exact(script_path)
                .args([action.as_arg()])
                .allow_in_test_runtime(),
            "activating the configuration",
        )
    }
}

/// Runs a long, uninterruptible step through the streaming runner, logging
/// "still {activity}, 2m10s" at a steady interval so the operator can see a slow
/// build or switch is still alive. Never applies a deadline.
fn run_long_step(command: &ProcessCommand, activity: &str) -> Result<(bool, String, String)> {
    RealProcessRunner.run_streaming_text(
        command,
        crate::process::run::BUILD_PROGRESS_INTERVAL,
        &mut |elapsed| {
            tracing::info!(
                "still {activity}, {}",
                crate::process::run::format_elapsed(elapsed)
            );
        },
    )
}

impl NixOSBuilder {
    pub(crate) fn preflight_flake_reference_fast(&self) -> crate::Result<FlakePreflightSummary> {
        self.preflight_flake_reference_read_only()
    }

    /// Static, side-effect-free flake validation safe to run before `/nix` and
    /// `/root` are overlaid.
    ///
    /// It only reads the flake layout from disk — for a local flake, `flake.nix`
    /// and `flake.lock` must exist and the selected `nixosConfigurations`
    /// attribute name must be resolvable — and never invokes `nix`. Running
    /// `nix flake metadata`/`getFlake` here would copy the plaintext hidden
    /// configuration into the decoy `/nix/store` and Nix DB and seed root's
    /// fetcher cache, all on the persistent decoy disk before the overlays hide
    /// it. The real metadata/eval validation is deferred to
    /// [`preflight_flake_reference_fast`], which activation runs only after the
    /// overlays are in place.
    pub(crate) fn preflight_flake_static(&self) -> crate::Result<()> {
        if !self.is_flake() {
            return Ok(());
        }

        let (metadata_flake_ref, selected_fragment) = self.preflight_flake_refs();

        // `flake.nix` (and the flake directory) must exist for a local ref.
        validate_local_flake_reference(&metadata_flake_ref)?;

        // A local flake must carry a committed `flake.lock`: activation never
        // runs `nix flake update`, and the deferred metadata check would fail
        // without one, so catch it here with a clear message and no nix call.
        if let Some(local_flake_dir) = resolve_local_flake_dir(&metadata_flake_ref)? {
            let lock_file = local_flake_dir.join("flake.lock");
            if !lock_file.exists() {
                return Err(crate::NailsError::NixOSPreflightError {
                    category: "flake lock",
                    message: format!(
                        "flake.lock not found in '{}'. Activation does not run 'nix flake update' automatically; commit a flake.lock and retry activation.",
                        local_flake_dir.display()
                    ),
                });
            }
        }

        // The selected `nixosConfigurations` attribute name must resolve (an
        // explicit `#fragment` or the inferred hostname). This parses only; it
        // does not evaluate the flake.
        let _ = selected_nixos_configuration_fragment(selected_fragment.as_deref())?;

        Ok(())
    }

    fn preflight_flake_reference_read_only(&self) -> crate::Result<FlakePreflightSummary> {
        if !self.is_flake() {
            return Ok(FlakePreflightSummary {
                metadata_checked: false,
                attr_checked: false,
            });
        }

        let (metadata_flake_ref, selected_fragment) = self.preflight_flake_refs();
        validate_local_flake_reference(&metadata_flake_ref)?;

        let (metadata_ok, metadata_stdout, metadata_stderr) = self.executor.execute_nix(
            &[
                "flake",
                "metadata",
                "--json",
                &metadata_flake_ref,
                "--no-write-lock-file",
                "--impure",
            ],
            self.should_clear_nix_path(),
        )?;

        if !metadata_ok {
            return Err(crate::NailsError::NixOSPreflightError {
                category: classify_nixos_failure_category(&metadata_stderr, &metadata_stdout),
                message: format_classified_nixos_failure(
                    "flake metadata validation failed",
                    &metadata_stderr,
                    &metadata_stdout,
                ),
            });
        }

        let (selected_fragment, fragment_is_explicit) =
            selected_nixos_configuration_fragment(selected_fragment.as_deref())?;
        let attr_check_expr =
            flake_nixos_configuration_attr_check_expr(&metadata_flake_ref, &selected_fragment)?;
        let clear_nix_path = self.should_clear_nix_path();

        let (attr_ok, attr_stdout, attr_stderr) = self.executor.execute_nix(
            &[
                "eval",
                "--raw",
                "--expr",
                &attr_check_expr,
                "--no-write-lock-file",
                "--impure",
            ],
            clear_nix_path,
        )?;

        if !attr_ok {
            let message = if is_missing_nixos_configuration_attr(&attr_stderr, &attr_stdout) {
                if fragment_is_explicit {
                    format_missing_explicit_configuration_error(
                        &metadata_flake_ref,
                        &selected_fragment,
                        &attr_stderr,
                        &attr_stdout,
                    )
                } else {
                    format_missing_inferred_configuration_error(
                        &metadata_flake_ref,
                        &selected_fragment,
                        &attr_stderr,
                        &attr_stdout,
                    )
                }
            } else {
                format_classified_nixos_failure(
                    "flake nixosConfiguration validation failed",
                    &attr_stderr,
                    &attr_stdout,
                )
            };

            return Err(crate::NailsError::NixOSPreflightError {
                category: classify_nixos_failure_category(&attr_stderr, &attr_stdout),
                message,
            });
        }

        Ok(FlakePreflightSummary {
            metadata_checked: true,
            attr_checked: true,
        })
    }

    #[cfg(test)]
    pub(crate) fn preflight_flake(&self) -> crate::Result<FlakePreflightSummary> {
        self.preflight_flake_reference_read_only()
    }
}

fn validate_local_flake_reference(base_ref: &str) -> crate::Result<()> {
    if let Some(local_flake_dir) = resolve_local_flake_dir(base_ref)? {
        if !local_flake_dir.exists() {
            return Err(crate::NailsError::NixOSPreflightError {
                category: "configuration",
                message: format!(
                    "flake directory '{}' not found. Fix the flake/configuration problem and retry activation.",
                    local_flake_dir.display()
                ),
            });
        }

        let flake_file = local_flake_dir.join("flake.nix");
        if !flake_file.exists() {
            return Err(crate::NailsError::NixOSPreflightError {
                category: "configuration",
                message: format!(
                    "flake.nix not found in '{}'. Fix the flake/configuration problem and retry activation.",
                    local_flake_dir.display()
                ),
            });
        }
    }

    Ok(())
}

fn flake_nixos_configuration_attr_check_expr(
    base_ref: &str,
    selected_fragment: &str,
) -> crate::Result<String> {
    let quoted_ref = nix_string_literal(base_ref)?;
    let quoted_fragment = nix_string_literal(selected_fragment)?;
    let missing_marker = nix_string_literal(&missing_nixos_configuration_attr_marker())?;

    Ok(format!(
        "let flake = builtins.getFlake {quoted_ref}; configs = flake.nixosConfigurations or {{}}; in if builtins.hasAttr {quoted_fragment} configs then \"1\" else builtins.throw ({missing_marker} + {quoted_fragment})"
    ))
}

pub(crate) fn split_flake_ref(flake_ref: &str) -> (&str, Option<&str>) {
    match flake_ref.split_once('#') {
        Some((base_ref, fragment)) if !fragment.is_empty() => (base_ref, Some(fragment)),
        Some((base_ref, _)) => (base_ref, None),
        None => (flake_ref, None),
    }
}

#[cfg(test)]
pub(crate) fn local_flake_dir(base_ref: &str) -> Option<PathBuf> {
    resolve_local_flake_dir(base_ref).ok().flatten()
}

pub(crate) fn resolve_local_flake_dir(base_ref: &str) -> crate::Result<Option<PathBuf>> {
    if base_ref.starts_with('/') {
        return Ok(Some(PathBuf::from(base_ref)));
    }

    if let Some(path_ref) = base_ref.strip_prefix("path:") {
        let (path_ref, _) = path_ref.split_once('?').unwrap_or((path_ref, ""));
        return resolved_local_path(path_ref).map(Some);
    }

    if looks_like_explicit_relative_flake_ref(base_ref) {
        return resolved_local_path(base_ref).map(Some);
    }

    if looks_like_generic_flake_ref(base_ref) {
        return Ok(None);
    }

    Err(crate::NailsError::NixOSPreflightError {
        category: "configuration",
        message: format!(
            "flake path '{}' is relative. Use './path', '../path', '.', an absolute path, 'path:/absolute/path', or a generic flake ref such as 'github:owner/repo#name'. Fix the flake/configuration problem and retry activation.",
            base_ref
        ),
    })
}

fn resolved_local_path(path_ref: &str) -> crate::Result<PathBuf> {
    if path_ref.starts_with('/') {
        return Ok(PathBuf::from(path_ref));
    }

    let cwd = std::env::current_dir().map_err(|err| crate::NailsError::NixOSPreflightError {
        category: "configuration",
        message: format!(
            "could not resolve current working directory for relative flake ref '{}': {}",
            path_ref, err
        ),
    })?;

    Ok(cwd.join(path_ref))
}

fn looks_like_generic_flake_ref(base_ref: &str) -> bool {
    !matches!(base_ref, "." | "..")
        && !base_ref.starts_with("./")
        && !base_ref.starts_with("../")
        && base_ref.contains(':')
}

fn looks_like_explicit_relative_flake_ref(base_ref: &str) -> bool {
    matches!(base_ref, "." | "..") || base_ref.starts_with("./") || base_ref.starts_with("../")
}

fn selected_nixos_configuration_fragment(
    explicit_fragment: Option<&str>,
) -> crate::Result<(String, bool)> {
    if let Some(fragment) = explicit_fragment.filter(|fragment| !fragment.is_empty()) {
        return Ok((fragment.to_string(), true));
    }

    let utsname = nix::sys::utsname::uname().map_err(|err| crate::NailsError::NixOSPreflightError {
        category: "configuration",
        message: format!(
            "could not determine the local hostname needed to infer the default nixosConfiguration attribute: {}",
            err
        ),
    })?;

    let hostname = utsname.nodename().to_string_lossy().trim().to_string();
    if hostname.is_empty() {
        return Err(crate::NailsError::NixOSPreflightError {
            category: "configuration",
            message: "could not determine the local hostname needed to infer the default nixosConfiguration attribute"
                .to_string(),
        });
    }

    Ok((hostname, false))
}

fn is_missing_nixos_configuration_attr(stderr: &str, stdout: &str) -> bool {
    let combined = combine_output(stderr, stdout);
    let lower = combined.to_lowercase();

    combined.contains(&missing_nixos_configuration_attr_marker())
        || lower.contains("does not provide attribute")
        || (lower.contains("attribute") && lower.contains("nixosconfigurations"))
}

fn format_missing_inferred_configuration_error(
    base_ref: &str,
    inferred_fragment: &str,
    stderr: &str,
    stdout: &str,
) -> String {
    let combined = combine_output(stderr, stdout);
    format!(
        "flake '{}' does not provide the inferred nixosConfiguration '{}'. Nails would later pass '--flake {}', which resolves to 'nixosConfigurations.{}'. Use '--flake {}#<name>' or add that configuration. Nix said: {}",
        base_ref, inferred_fragment, base_ref, inferred_fragment, base_ref, combined
    )
}

fn format_missing_explicit_configuration_error(
    base_ref: &str,
    explicit_fragment: &str,
    stderr: &str,
    stdout: &str,
) -> String {
    let combined = combine_output(stderr, stdout);
    format!(
        "flake '{}' does not provide nixosConfiguration '{}'. Nails would later pass '--flake {}#{}'. Use '--flake {}#<name>' with an existing configuration or add that attribute. Nix said: {}",
        base_ref, explicit_fragment, base_ref, explicit_fragment, base_ref, combined
    )
}

fn missing_nixos_configuration_attr_marker() -> String {
    "__NAILS_MISSING_NIXOS_CONFIGURATION__:".to_string()
}

fn nix_string_literal(value: &str) -> crate::Result<String> {
    serde_json::to_string(value).map_err(|err| crate::NailsError::NixOSPreflightError {
        category: "configuration",
        message: format!("failed to quote flake preflight expression input: {}", err),
    })
}

pub(crate) fn classify_nixos_failure_category(stderr: &str, stdout: &str) -> &'static str {
    let combined = combine_output(stderr, stdout);
    let lower = combined.to_lowercase();

    if lower.contains("failed to download")
        || lower.contains("unable to download")
        || lower.contains("could not resolve host")
        || lower.contains("name or service not known")
        || lower.contains("network is unreachable")
        || lower.contains("timed out")
        || lower.contains("connection reset")
        || lower.contains("connection refused")
        || lower.contains("http error")
        || lower.contains("substituter")
        || lower.contains("unable to start any build")
    {
        "network/substituter"
    } else if lower.contains("lock file")
        || lower.contains("cannot write modified lock file")
        || lower.contains("requires lock file changes")
        || lower.contains("needs to be updated")
        || lower.contains("is out of date")
    {
        "flake lock"
    } else if lower.contains("does not provide attribute")
        || lower.contains("attribute '")
        || lower.contains("attribute ")
        || lower.contains("nixosconfigurations")
        || lower.contains("syntax error")
        || lower.contains("error: undefined variable")
        || lower.contains("option ")
        || lower.contains("while evaluating")
    {
        "configuration"
    } else if lower.contains("structure needs cleaning")
        || lower.contains("read-only file system")
        || lower.contains("input/output error")
        || lower.contains("no space left on device")
        || lower.contains("permission denied")
        || lower.contains("stale file handle")
    {
        "environment/filesystem"
    } else {
        "nix"
    }
}

pub(crate) fn format_classified_nixos_failure(context: &str, stderr: &str, stdout: &str) -> String {
    let combined = combine_output(stderr, stdout);
    let category = classify_nixos_failure_category(stderr, stdout);

    let guidance = match category {
        "flake lock" => {
            "Activation does not run 'nix flake update' automatically. Update or repair the lock file yourself before retrying."
        }
        "network/substituter" => {
            "Check network access, substituters/caches, or retry later. This is not caused by overlay activation itself."
        }
        "environment/filesystem" => {
            "This looks like a host or filesystem problem; Nails did not attempt an automatic repair. Fix the environment and retry."
        }
        _ => "Fix the flake/configuration problem and retry activation.",
    };

    format!("{} [{}]: {}. {}", context, category, combined, guidance)
}

pub(crate) fn is_non_fatal_switch_failure(stderr: &str, stdout: &str) -> bool {
    let combined = combine_output(stderr, stdout);
    let lower = combined.to_lowercase();

    lower.contains("error(s) occurred while switching to the new configuration")
        || lower.contains("the following units failed")
        || lower.contains("failed units:")
        || (lower.contains("job for ")
            && lower.contains("failed because the control process exited with error code"))
}

fn combine_output(stderr: &str, stdout: &str) -> String {
    let stderr = stderr.trim();
    if !stderr.is_empty() {
        return stderr.to_string();
    }

    let stdout = stdout.trim();
    if !stdout.is_empty() {
        return stdout.to_string();
    }

    "command returned a non-zero exit status without diagnostic output".to_string()
}
