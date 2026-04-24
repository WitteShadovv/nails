//! Runtime safeguards to avoid host interaction from test binaries.

use std::path::Path;

const TEST_RUNTIME_ENV: &str = "NAILS_TEST_RUNTIME";

/// Return true when running under a Rust test harness/integration-test binary.
///
/// `cfg!(test)` only protects unit-test builds of the current crate. Integration
/// tests compile the library as a normal dependency, so we also detect the
/// standard Cargo test binary layout (`target/.../deps/<name>-<hash>`).
pub(crate) fn should_skip_host_interaction() -> bool {
    if cfg!(test) {
        return true;
    }

    if std::env::var_os(TEST_RUNTIME_ENV).is_some() {
        return true;
    }

    std::env::current_exe().ok().is_some_and(|exe| {
        exe.components()
            .any(|component| component.as_os_str() == Path::new("deps").as_os_str())
    })
}
