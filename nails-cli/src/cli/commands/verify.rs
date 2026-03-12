//! Verify command handler

use crate::cli::output;
use std::io::Write;

/// Execute the verify command
///
/// Verifies that the system is clean of NAILS artifacts.
///
/// # Arguments
///
/// * `deep` - Perform deep scan (slower, more thorough)
/// * `json` - Output results as JSON
///
/// # Returns
///
/// Never returns - exits with appropriate exit code:
/// - 0: System is secure
/// - 1: Warning or critical issues found
/// - 2: Error running verification
pub fn execute(deep: bool, json: bool) -> ! {
    use nails_core::{RealFilesystem, Verifier};

    // Create verifier with real filesystem
    let filesystem = RealFilesystem;
    let verifier = Verifier::new(filesystem);

    // Run verification
    let result = match verifier.run(deep) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("Error running verification: {}", e);
            std::process::exit(2); // Exit code 2 for verify command errors
        }
    };

    // Output results
    if json {
        // JSON output
        let json_output =
            serde_json::to_string_pretty(&result).expect("Failed to serialize verification result");
        println!("{}", json_output);
    } else {
        // Human-readable output
        output::print_verify_result(&result);
    }

    // Set exit code based on status
    let _ = std::io::stdout().flush();
    match result.status {
        nails_core::VerifyStatus::Secure => std::process::exit(0),
        nails_core::VerifyStatus::Warning | nails_core::VerifyStatus::Critical => {
            std::process::exit(1)
        }
    }
}
