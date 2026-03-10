//! Output formatting for the activate command

/// JSON output structure for activate command
#[derive(serde::Serialize)]
struct ActivateResult {
    status: String,
    duration: f64,
    state: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    failed_checks: Option<Vec<FailedCheckJson>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    shell_instructions: Option<ShellInstructionsJson>,
}

#[derive(serde::Serialize)]
pub struct ShellInstructionsJson {
    pub shell_type: String,
    pub prompt_script: String,
    pub alias_script: String,
    pub instructions: Vec<String>,
}

#[derive(serde::Serialize)]
struct FailedCheckJson {
    name: String,
    reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    fix: Option<String>,
}

/// Print activation result in JSON format
pub fn print_activate_json<F: nails_core::Filesystem>(
    result: &Result<(), nails_core::NailsError>,
    duration: f64,
    manager: &std::sync::Arc<std::sync::Mutex<nails_core::NailsManager<F>>>,
    shell_setup: Option<&nails_core::ShellSetupResult>,
) {
    use nails_core::NailsError;

    let state = manager
        .lock()
        .unwrap()
        .current_state()
        .map(|s| format!("{:?}", s))
        .unwrap_or_else(|_| "UNKNOWN".to_string());

    // Convert shell setup result to JSON structure
    let shell_instructions_json = shell_setup.map(|setup| ShellInstructionsJson {
        shell_type: format!("{:?}", setup.shell_type).to_lowercase(),
        prompt_script: setup.prompt_script_path.display().to_string(),
        alias_script: setup.alias_script_path.display().to_string(),
        instructions: setup.instructions.clone(),
    });

    let output = match result {
        Ok(_) => ActivateResult {
            status: "success".to_string(),
            duration,
            state,
            message: format!("Activation complete in {:.1}s", duration),
            failed_checks: None,
            shell_instructions: shell_instructions_json,
        },
        Err(e) => match e {
            NailsError::PreFlightCheckFailed(failures) => ActivateResult {
                status: "error".to_string(),
                duration,
                state: state.clone(),
                message: "Pre-flight checks failed".to_string(),
                failed_checks: Some(
                    failures
                        .iter()
                        .map(|(name, reason)| FailedCheckJson {
                            name: name.clone(),
                            reason: reason.clone(),
                            fix: Some(
                                "Review system state and ensure hidden volume is mounted"
                                    .to_string(),
                            ),
                        })
                        .collect(),
                ),
                shell_instructions: None,
            },
            _ => ActivateResult {
                status: "error".to_string(),
                duration,
                state,
                message: format!("Activation failed: {}", e),
                failed_checks: None,
                shell_instructions: None,
            },
        },
    };

    println!(
        "{}",
        serde_json::to_string_pretty(&output).expect("Failed to serialize JSON")
    );
}

/// Print activation result in human-readable format
pub fn print_activate_human<F: nails_core::Filesystem>(
    result: &Result<(), nails_core::NailsError>,
    duration: f64,
    manager: &std::sync::Arc<std::sync::Mutex<nails_core::NailsManager<F>>>,
    shell_setup: Option<&nails_core::ShellSetupResult>,
    quiet: bool,
) {
    use colored::Colorize;
    use nails_core::NailsError;

    match result {
        Ok(_) => {
            println!(
                "{}",
                format!("✓ Activation complete in {:.1}s", duration)
                    .green()
                    .bold()
            );

            // Print shell integration instructions (unless quiet mode)
            if !quiet {
                if let Some(setup) = shell_setup {
                    if let Some(ref warn) = setup.warning {
                        // Script generation failed, show warning with reason
                        println!();
                        println!("{}", format!("Shell prompt not updated: {}", warn).yellow());
                        println!(
                            "{}",
                            "You can manually source scripts from the hidden volume if needed"
                                .dimmed()
                        );
                    } else if setup.rc_modified {
                        // RC file was modified - new terminals auto-configured
                        println!();
                        println!("{}", "Shell Integration:".cyan().bold());
                        println!(
                            "{}",
                            "✓ New terminals will automatically have prompt, alias, and color scheme."
                                .green()
                        );
                        println!();
                        println!("{}", "To apply to this terminal now, run:".dimmed());
                        for cmd in &setup.instructions {
                            println!("  {}", cmd.bright_white());
                        }
                    } else {
                        // RC file not modified - show fallback instructions
                        println!();
                        println!("{}", "Shell Integration:".cyan().bold());
                        println!(
                            "{}",
                            "To update your prompt and add the 'nails' alias, run:".dimmed()
                        );
                        for cmd in &setup.instructions {
                            println!("  {}", cmd.bright_white());
                        }
                    }
                } else {
                    // No shell detected or unsupported shell
                    println!();
                    println!(
                        "{}",
                        "Shell prompt not updated - no supported shell detected".yellow()
                    );
                    println!(
                        "{}",
                        "You can manually source scripts from the hidden volume if needed".dimmed()
                    );
                }
            }
        }
        Err(e) => match e {
            NailsError::PreFlightCheckFailed(failures) => {
                eprintln!("{}", "✗ Pre-flight checks failed:".red().bold());
                for (name, reason) in failures {
                    eprintln!("  • {}: {}", name.yellow(), reason);
                }
                eprintln!(
                    "\n  {}",
                    "Fix: Review system state and ensure hidden volume is mounted".yellow()
                );
            }
            _ => {
                eprintln!("{}", format!("✗ Activation failed: {}", e).red().bold());
                eprintln!("  {}", "Automatic rollback completed.".dimmed());
                if let Ok(state) = manager.lock().unwrap().current_state() {
                    eprintln!("  {}: {:?}", "Current state".dimmed(), state);
                }
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nails_core::{Config, MockFilesystem, NailsError, NailsManager, ShellSetupResult};
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    fn make_manager() -> Arc<Mutex<NailsManager<MockFilesystem>>> {
        let fs = MockFilesystem::new();
        let config = Config::default();
        let manager = NailsManager::new(fs, config, PathBuf::from("/tmp/test-state.json"));
        Arc::new(Mutex::new(manager))
    }

    fn make_shell_setup_rc_modified() -> ShellSetupResult {
        use nails_core::shell::ShellType;
        ShellSetupResult {
            shell_type: ShellType::Bash,
            prompt_script_path: PathBuf::from("/mnt/hidden/scripts/nails_prompt.bash"),
            alias_script_path: PathBuf::from("/mnt/hidden/scripts/nails_alias.sh"),
            instructions: vec!["source /mnt/hidden/scripts/nails_prompt.bash".to_string()],
            warning: None,
            rc_modified: true,
        }
    }

    fn make_shell_setup_no_rc() -> ShellSetupResult {
        use nails_core::shell::ShellType;
        ShellSetupResult {
            shell_type: ShellType::Bash,
            prompt_script_path: PathBuf::from("/mnt/hidden/scripts/nails_prompt.bash"),
            alias_script_path: PathBuf::from("/mnt/hidden/scripts/nails_alias.sh"),
            instructions: vec!["source /mnt/hidden/scripts/nails_prompt.bash".to_string()],
            warning: None,
            rc_modified: false,
        }
    }

    fn make_shell_setup_with_warning() -> ShellSetupResult {
        use nails_core::shell::ShellType;
        ShellSetupResult {
            shell_type: ShellType::Bash,
            prompt_script_path: PathBuf::from("/mnt/hidden/scripts/nails_prompt.bash"),
            alias_script_path: PathBuf::from("/mnt/hidden/scripts/nails_alias.sh"),
            instructions: vec![],
            warning: Some("Could not detect shell config".to_string()),
            rc_modified: false,
        }
    }

    // ── print_activate_json ────────────────────────────────────────────────────

    #[test]
    fn test_json_success_no_shell() {
        let manager = make_manager();
        print_activate_json(&Ok(()), 1.5, &manager, None);
    }

    #[test]
    fn test_json_success_with_shell() {
        let manager = make_manager();
        let setup = make_shell_setup_rc_modified();
        print_activate_json(&Ok(()), 2.3, &manager, Some(&setup));
    }

    #[test]
    fn test_json_preflight_failure() {
        let manager = make_manager();
        let err = NailsError::PreFlightCheckFailed(vec![
            ("hidden_volume".to_string(), "not mounted".to_string()),
            ("swap".to_string(), "swap enabled".to_string()),
        ]);
        print_activate_json(&Err(err), 0.1, &manager, None);
    }

    #[test]
    fn test_json_other_error() {
        let manager = make_manager();
        let err = NailsError::InvalidState("unexpected state".to_string());
        print_activate_json(&Err(err), 0.5, &manager, None);
    }

    // ── print_activate_human ───────────────────────────────────────────────────

    #[test]
    fn test_human_success_no_shell() {
        let manager = make_manager();
        print_activate_human(&Ok(()), 1.5, &manager, None, false);
    }

    #[test]
    fn test_human_success_quiet() {
        let manager = make_manager();
        print_activate_human(&Ok(()), 1.5, &manager, None, true);
    }

    #[test]
    fn test_human_success_shell_rc_modified() {
        let manager = make_manager();
        let setup = make_shell_setup_rc_modified();
        print_activate_human(&Ok(()), 1.0, &manager, Some(&setup), false);
    }

    #[test]
    fn test_human_success_shell_no_rc() {
        let manager = make_manager();
        let setup = make_shell_setup_no_rc();
        print_activate_human(&Ok(()), 1.0, &manager, Some(&setup), false);
    }

    #[test]
    fn test_human_success_shell_with_warning() {
        let manager = make_manager();
        let setup = make_shell_setup_with_warning();
        print_activate_human(&Ok(()), 1.0, &manager, Some(&setup), false);
    }

    #[test]
    fn test_human_success_shell_quiet_suppresses_instructions() {
        let manager = make_manager();
        let setup = make_shell_setup_rc_modified();
        print_activate_human(&Ok(()), 1.0, &manager, Some(&setup), true);
    }

    #[test]
    fn test_human_preflight_failure() {
        let manager = make_manager();
        let err = NailsError::PreFlightCheckFailed(vec![(
            "hidden_volume".to_string(),
            "not mounted".to_string(),
        )]);
        print_activate_human(&Err(err), 0.1, &manager, None, false);
    }

    #[test]
    fn test_human_other_error() {
        let manager = make_manager();
        let err = NailsError::InvalidState("bad state".to_string());
        print_activate_human(&Err(err), 0.3, &manager, None, false);
    }
}
