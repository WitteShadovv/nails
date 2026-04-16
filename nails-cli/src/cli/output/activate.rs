//! Output formatting for the activate command

/// JSON output structure for activate command
#[derive(Debug, serde::Serialize)]
struct ActivateResult {
    event: &'static str,
    status: String,
    duration: f64,
    state: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    failed_checks: Option<Vec<FailedCheckJson>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    shell_instructions: Option<ShellInstructionsJson>,
}

#[derive(Debug, serde::Serialize)]
pub struct ShellInstructionsJson {
    pub shell_type: String,
    pub prompt_script: String,
    pub alias_script: String,
    pub instructions: Vec<String>,
}

#[derive(Debug, serde::Serialize)]
struct FailedCheckJson {
    name: String,
    reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    fix: Option<String>,
}

fn manager_state_debug<F: nails_core::Filesystem>(
    manager: &std::sync::Arc<std::sync::Mutex<nails_core::NailsManager<F>>>,
) -> Option<String> {
    match manager.lock() {
        Ok(manager) => manager
            .current_state()
            .ok()
            .map(|state| format!("{:?}", state)),
        Err(_) => None,
    }
}

/// Print activation result in JSON format
pub fn print_activate_json<F: nails_core::Filesystem>(
    result: &Result<(), nails_core::NailsError>,
    duration: f64,
    manager: &std::sync::Arc<std::sync::Mutex<nails_core::NailsManager<F>>>,
    shell_setup: Option<&nails_core::ShellSetupResult>,
) {
    let output = build_activate_json_output(result, duration, manager, shell_setup);

    println!(
        "{}",
        serde_json::to_string(&output).expect("Failed to serialize JSON")
    );
}

fn build_activate_json_output<F: nails_core::Filesystem>(
    result: &Result<(), nails_core::NailsError>,
    duration: f64,
    manager: &std::sync::Arc<std::sync::Mutex<nails_core::NailsManager<F>>>,
    shell_setup: Option<&nails_core::ShellSetupResult>,
) -> ActivateResult {
    use nails_core::NailsError;

    let state = manager_state_debug(manager).unwrap_or_else(|| "UNKNOWN".to_string());

    // Convert shell setup result to JSON structure
    let shell_instructions_json = shell_setup.map(|setup| ShellInstructionsJson {
        shell_type: format!("{:?}", setup.shell_type).to_lowercase(),
        prompt_script: setup.prompt_script_path.display().to_string(),
        alias_script: setup.alias_script_path.display().to_string(),
        instructions: setup.instructions.clone(),
    });

    match result {
        Ok(_) => ActivateResult {
            event: "result",
            status: "success".to_string(),
            duration,
            state,
            message: format!("Activation complete in {:.1}s", duration),
            failed_checks: None,
            shell_instructions: shell_instructions_json,
        },
        Err(e) => match e {
            NailsError::PreFlightCheckFailed(failures) => ActivateResult {
                event: "result",
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
                event: "result",
                status: "error".to_string(),
                duration,
                state,
                message: format!("Activation failed: {}", e),
                failed_checks: None,
                shell_instructions: None,
            },
        },
    }
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
                if let Some(state) = manager_state_debug(manager) {
                    eprintln!("  {}: {}", "Current state".dimmed(), state);
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
        let output = build_activate_json_output(&Ok(()), 1.5, &manager, None);
        let json = serde_json::to_value(&output).unwrap();
        assert_eq!(output.event, "result");
        assert_eq!(output.status, "success");
        assert_eq!(output.message, "Activation complete in 1.5s");
        assert_eq!(json.get("event").and_then(|v| v.as_str()), Some("result"));
    }

    #[test]
    fn test_json_success_with_shell() {
        let manager = make_manager();
        let setup = make_shell_setup_rc_modified();
        let output = build_activate_json_output(&Ok(()), 2.3, &manager, Some(&setup));
        assert_eq!(output.event, "result");
        assert_eq!(output.status, "success");
        assert!(output.shell_instructions.is_some());
    }

    #[test]
    fn test_json_preflight_failure() {
        let manager = make_manager();
        let err = NailsError::PreFlightCheckFailed(vec![
            ("hidden_volume".to_string(), "not mounted".to_string()),
            ("swap".to_string(), "swap enabled".to_string()),
        ]);
        let output = build_activate_json_output(&Err(err), 0.1, &manager, None);
        let json = serde_json::to_value(&output).unwrap();
        assert_eq!(output.event, "result");
        assert_eq!(output.status, "error");
        assert_eq!(output.message, "Pre-flight checks failed");
        assert_eq!(output.failed_checks.as_ref().map(Vec::len), Some(2));
        assert_eq!(json.get("event").and_then(|v| v.as_str()), Some("result"));
    }

    #[test]
    fn test_json_other_error() {
        let manager = make_manager();
        let err = NailsError::InvalidState("unexpected state".to_string());
        let output = build_activate_json_output(&Err(err), 0.5, &manager, None);
        assert_eq!(output.event, "result");
        assert_eq!(output.status, "error");
        assert_eq!(
            output.message,
            "Activation failed: Invalid state: unexpected state"
        );
    }

    #[test]
    fn test_json_poisoned_manager_falls_back_to_unknown_state() {
        let manager = make_manager();
        let poison_target = Arc::clone(&manager);
        let _ = std::thread::spawn(move || {
            let _guard = poison_target.lock().unwrap();
            panic!("poison manager lock for test");
        })
        .join();

        let output = build_activate_json_output(&Ok(()), 0.2, &manager, None);
        assert_eq!(output.state, "UNKNOWN");
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

    #[test]
    fn test_human_error_with_poisoned_manager_does_not_panic() {
        let manager = make_manager();
        let poison_target = Arc::clone(&manager);
        let _ = std::thread::spawn(move || {
            let _guard = poison_target.lock().unwrap();
            panic!("poison manager lock for test");
        })
        .join();

        let err = NailsError::InvalidState("bad state".to_string());
        print_activate_human(&Err(err), 0.3, &manager, None, false);
    }
}
