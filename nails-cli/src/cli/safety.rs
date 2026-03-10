//! Safety guards for test execution
//!
//! This module provides defense-in-depth measures to prevent integration tests
//! from accidentally executing dangerous operations on the development system.

/// TEST SAFETY GUARD (Layer 1): Check if real system operations are allowed
///
/// This is a defense-in-depth measure to prevent integration tests from
/// accidentally executing dangerous operations on the development system.
///
/// # How It Works
///
/// 1. Checks if `NAILS_UNSAFE_REAL_OPS=1` environment variable is set
/// 2. If NOT set, checks if the hidden volume root appears to be a build directory
/// 3. If it's a build directory and env var not set, refuses to proceed
///
/// # When This Triggers
///
/// - Integration tests running from `cargo test` without opt-in
/// - Binary executed from `target/debug/` or `target/release/` without explicit permission
///
/// # How to Bypass (Intentionally)
///
/// Set the environment variable:
/// ```bash
/// NAILS_UNSAFE_REAL_OPS=1 cargo test
/// ```
///
/// # Returns
///
/// - `Ok(())` if operations are allowed
/// - `Err(message)` if operations are blocked for safety
pub fn check_real_operations_allowed(hidden_volume_root: &std::path::Path) -> Result<(), String> {
    // Check for explicit opt-in via environment variable
    if std::env::var("NAILS_UNSAFE_REAL_OPS").unwrap_or_default() == "1" {
        return Ok(());
    }

    // Check if hidden volume root appears to be a build directory
    let path_str = hidden_volume_root.to_string_lossy();
    let is_build_dir = path_str.contains("/target/debug")
        || path_str.contains("/target/release")
        || path_str.contains("/target/llvm-cov-target");

    if is_build_dir {
        return Err(format!(
            "🛡️  TEST SAFETY GUARD: Refusing to execute real system operations\n\
             \n\
             Hidden volume root appears to be a build directory:\n\
             {}\n\
             \n\
             This usually means you're running integration tests without proper safeguards.\n\
             Real system operations (mount, unmount, systemctl, process killing) are BLOCKED.\n\
             \n\
             To run tests that execute real operations, set:\n\
             \n\
             NAILS_UNSAFE_REAL_OPS=1 cargo test\n\
             \n\
             ⚠️  WARNING: This will execute REAL system commands. Only use this if you know\n\
             what you're doing and are prepared for potential system disruption.\n\
             \n\
             For safe testing, use the unit tests or MockFilesystem-based tests instead.",
            hidden_volume_root.display()
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn allows_when_unsafe_env_is_set_even_for_build_dir() {
        let _guard = env_lock().lock().unwrap();
        unsafe {
            std::env::set_var("NAILS_UNSAFE_REAL_OPS", "1");
        }

        let result =
            check_real_operations_allowed(Path::new("/tmp/project/target/debug/fake-hidden"));

        unsafe {
            std::env::remove_var("NAILS_UNSAFE_REAL_OPS");
        }
        assert!(result.is_ok());
    }

    #[test]
    fn blocks_target_debug_path_without_opt_in() {
        let _guard = env_lock().lock().unwrap();
        unsafe {
            std::env::remove_var("NAILS_UNSAFE_REAL_OPS");
        }

        let err = check_real_operations_allowed(Path::new("/tmp/project/target/debug/fake-hidden"))
            .unwrap_err();

        assert!(err.contains("TEST SAFETY GUARD"));
        assert!(err.contains("/target/debug"));
    }

    #[test]
    fn blocks_target_release_path_without_opt_in() {
        let _guard = env_lock().lock().unwrap();
        unsafe {
            std::env::remove_var("NAILS_UNSAFE_REAL_OPS");
        }

        let err =
            check_real_operations_allowed(Path::new("/tmp/project/target/release/fake-hidden"))
                .unwrap_err();

        assert!(err.contains("TEST SAFETY GUARD"));
        assert!(err.contains("/target/release"));
    }

    #[test]
    fn blocks_llvm_cov_path_without_opt_in() {
        let _guard = env_lock().lock().unwrap();
        unsafe {
            std::env::remove_var("NAILS_UNSAFE_REAL_OPS");
        }

        let err = check_real_operations_allowed(Path::new(
            "/tmp/project/target/llvm-cov-target/fake-hidden",
        ))
        .unwrap_err();

        assert!(err.contains("TEST SAFETY GUARD"));
        assert!(err.contains("/target/llvm-cov-target"));
    }

    #[test]
    fn allows_non_build_path_without_opt_in() {
        let _guard = env_lock().lock().unwrap();
        unsafe {
            std::env::remove_var("NAILS_UNSAFE_REAL_OPS");
        }

        let result = check_real_operations_allowed(Path::new("/mnt/hidden-volume"));

        assert!(result.is_ok());
    }
}
