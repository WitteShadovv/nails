//! Test utilities for cleanup module tests
//!
//! This module provides safe test environment setup to prevent tests from
//! accidentally operating on real user files.
//!
//! # CRITICAL SAFETY NOTICE
//!
//! Tests MUST NEVER use `std::env::var("HOME")` directly, as this returns the
//! REAL home directory of the user running the tests. Instead, tests should:
//!
//! 1. Use `TEST_HOME` constant which is a safe fake path
//! 2. Call `set_safe_test_home()` at the start of any test that involves history files
//! 3. Use `assert_path_is_safe()` to validate paths before filesystem operations
//!
//! # Example
//!
//! ```rust,ignore
//! use nails_core::cleanup::test_utils::{TEST_HOME, set_safe_test_home};
//!
//! #[test]
//! fn test_history_cleanup() {
//!     set_safe_test_home();
//!
//!     // Now std::env::var("HOME") returns TEST_HOME ("/home/testuser")
//!     let bash_history = format!("{}/.bash_history", TEST_HOME);
//!     // ... rest of test
//! }
//! ```

/// Safe fake home directory for tests.
///
/// This path does NOT exist on the real filesystem and is safe to use in tests.
/// All tests involving history files should use this constant instead of reading
/// the real HOME environment variable.
pub const TEST_HOME: &str = "/home/testuser";

/// Paths that are NEVER safe to access in tests.
///
/// If a test attempts to operate on any path starting with these prefixes
/// (after resolving the real HOME), it indicates a test safety bug.
pub const UNSAFE_PATH_PREFIXES: &[&str] = &[
    // Common home directories - if HOME is set to a real user's home,
    // these would be the real paths
    "/root",
    // XDG directories that could leak to real filesystem
    "/home/", // Note: trailing slash means we allow /home/testuser but not /home/realuser
];

/// Sets the HOME environment variable to a safe test value.
///
/// # Safety
///
/// This function modifies a global environment variable, which can cause race
/// conditions if multiple tests run in parallel. Use `#[serial]` attribute on
/// tests that call this function.
///
/// # Example
///
/// ```rust,ignore
/// use serial_test::serial;
/// use nails_core::cleanup::test_utils::set_safe_test_home;
///
/// #[test]
/// #[serial]
/// fn test_with_safe_home() {
///     set_safe_test_home();
///     // ... test code
/// }
/// ```
pub fn set_safe_test_home() {
    // SAFETY: This is only called from tests and we use #[serial] to prevent races
    unsafe {
        std::env::set_var("HOME", TEST_HOME);
    }
}

/// Asserts that a path is safe for test operations.
///
/// This function validates that a path does not point to a real user directory.
/// It should be called before any filesystem operation in tests to catch
/// accidental real path usage early.
///
/// # Panics
///
/// Panics if the path appears to be a real user directory (not the test directory).
///
/// # Example
///
/// ```rust,ignore
/// use nails_core::cleanup::test_utils::assert_path_is_safe;
///
/// let path = "/home/testuser/.bash_history";
/// assert_path_is_safe(&path); // OK
///
/// let real_path = "/home/realuser/.bash_history";
/// assert_path_is_safe(&real_path); // PANICS!
/// ```
pub fn assert_path_is_safe(path: &str) {
    // Check if path starts with our safe test home
    if path.starts_with(TEST_HOME) {
        return; // Safe
    }

    // Check if path is absolute and starts with an unsafe prefix
    if path.starts_with('/') {
        // Get the real HOME to detect if someone accidentally used it
        if let Ok(real_home) = std::env::var("HOME") {
            // If the test path starts with the REAL home directory (and real_home != TEST_HOME),
            // this is a test bug
            if real_home != TEST_HOME && path.starts_with(&real_home) {
                panic!(
                    "\n\n🚨 TEST SAFETY VIOLATION 🚨\n\n\
                    Test attempted to access REAL user path: {}\n\
                    Real HOME: {}\n\n\
                    FIX: Use test_utils::set_safe_test_home() at the start of the test,\n\
                    or use TEST_HOME constant instead of std::env::var(\"HOME\")\n\n",
                    path, real_home
                );
            }
        }

        // Additional check for common real paths
        for unsafe_prefix in UNSAFE_PATH_PREFIXES {
            if path.starts_with(unsafe_prefix) && !path.starts_with(TEST_HOME) {
                // Special case: /home/testuser is OK, /home/anything_else is not
                if *unsafe_prefix == "/home/" {
                    // Extract what comes after /home/
                    let after_home = &path[6..]; // Skip "/home/"
                    if let Some(first_component) = after_home.split('/').next()
                        && first_component != "testuser"
                    {
                        panic!(
                            "\n\n🚨 TEST SAFETY VIOLATION 🚨\n\n\
                            Test attempted to access suspicious path: {}\n\
                            This path might point to a real user directory.\n\n\
                            FIX: Use test_utils::TEST_HOME (\"/home/testuser\") for all test paths.\n\n",
                            path
                        );
                    }
                } else {
                    panic!(
                        "\n\n🚨 TEST SAFETY VIOLATION 🚨\n\n\
                        Test attempted to access unsafe path: {}\n\
                        Matches unsafe prefix: {}\n\n\
                        FIX: Use test_utils::TEST_HOME for all test paths.\n\n",
                        path, unsafe_prefix
                    );
                }
            }
        }
    }
}

/// Returns the safe test home path for bash history.
///
/// Convenience function that returns the standard test path for .bash_history.
pub fn test_bash_history_path() -> String {
    format!("{}/.bash_history", TEST_HOME)
}

/// Returns the safe test home path for zsh history.
///
/// Convenience function that returns the standard test path for .zsh_history.
pub fn test_zsh_history_path() -> String {
    format!("{}/.zsh_history", TEST_HOME)
}

/// Returns the safe test home path for fish history.
///
/// Convenience function that returns the standard test path for fish history.
pub fn test_fish_history_path() -> String {
    format!("{}/.local/share/fish/fish_history", TEST_HOME)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assert_path_is_safe_allows_test_home() {
        // These should not panic
        assert_path_is_safe("/home/testuser/.bash_history");
        assert_path_is_safe("/home/testuser/.zsh_history");
        assert_path_is_safe("/home/testuser/some/deep/path");
    }

    #[test]
    fn test_assert_path_is_safe_allows_non_home_paths() {
        // These should not panic - they're not under /home
        assert_path_is_safe("/tmp/test");
        assert_path_is_safe("/mnt/hidden-volume/test");
        assert_path_is_safe("/var/log/test");
    }

    #[test]
    #[should_panic(expected = "TEST SAFETY VIOLATION")]
    fn test_assert_path_is_safe_rejects_root_path() {
        assert_path_is_safe("/root/.bash_history");
    }

    #[test]
    #[should_panic(expected = "TEST SAFETY VIOLATION")]
    fn test_assert_path_is_safe_rejects_other_user() {
        assert_path_is_safe("/home/otheruser/.bash_history");
    }

    #[test]
    fn test_helper_paths() {
        assert_eq!(test_bash_history_path(), "/home/testuser/.bash_history");
        assert_eq!(test_zsh_history_path(), "/home/testuser/.zsh_history");
        assert_eq!(
            test_fish_history_path(),
            "/home/testuser/.local/share/fish/fish_history"
        );
    }
}
