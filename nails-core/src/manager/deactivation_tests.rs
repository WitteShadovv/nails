use super::{
    REBOOT_BINARY_OVERRIDE_ENV, SYSTEMCTL_REBOOT_OVERRIDE_ENV, dispatch_reboot_candidates,
    reboot_candidates, request_reboot,
};
use serial_test::serial;
use std::fs;
use std::os::unix::fs::PermissionsExt;

fn write_executable_script(path: &std::path::Path, body: &str) {
    fs::write(path, body).expect("write test script");
    let mut permissions = fs::metadata(path).expect("stat test script").permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).expect("chmod test script");
}

struct EnvGuard {
    key: &'static str,
    original: Option<std::ffi::OsString>,
}

impl EnvGuard {
    fn set(key: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
        let original = std::env::var_os(key);
        unsafe {
            std::env::set_var(key, value);
        }
        Self { key, original }
    }

    fn remove(key: &'static str) -> Self {
        let original = std::env::var_os(key);
        unsafe {
            std::env::remove_var(key);
        }
        Self { key, original }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        if let Some(value) = &self.original {
            unsafe {
                std::env::set_var(self.key, value);
            }
        } else {
            unsafe {
                std::env::remove_var(self.key);
            }
        }
    }
}

#[test]
#[serial]
fn request_reboot_uses_configured_systemctl_override() {
    let temp_dir = tempfile::tempdir().unwrap();
    let marker = temp_dir.path().join("systemctl-arg.txt");
    let systemctl = temp_dir.path().join("systemctl");

    write_executable_script(
        &systemctl,
        &format!(
            "#!/usr/bin/env bash\nprintf '%s' \"$1\" > '{}'\nexit 0\n",
            marker.display()
        ),
    );

    let _systemctl_override = EnvGuard::set(SYSTEMCTL_REBOOT_OVERRIDE_ENV, &systemctl);
    let _reboot_override = EnvGuard::remove(REBOOT_BINARY_OVERRIDE_ENV);

    dispatch_reboot_candidates(reboot_candidates()).expect("override systemctl should be used");

    assert_eq!(fs::read_to_string(marker).unwrap(), "reboot");
}

#[test]
#[serial]
fn request_reboot_falls_back_to_override_reboot_binary_when_systemctl_fails() {
    let temp_dir = tempfile::tempdir().unwrap();
    let systemctl = temp_dir.path().join("systemctl");
    let reboot = temp_dir.path().join("reboot");
    let marker = temp_dir.path().join("reboot-called.txt");

    write_executable_script(
        &systemctl,
        "#!/usr/bin/env bash\nprintf 'denied\n' >&2\nexit 1\n",
    );
    write_executable_script(
        &reboot,
        &format!("#!/usr/bin/env bash\n: > '{}'\nexit 0\n", marker.display()),
    );

    let _systemctl_override = EnvGuard::set(SYSTEMCTL_REBOOT_OVERRIDE_ENV, &systemctl);
    let _reboot_override = EnvGuard::set(REBOOT_BINARY_OVERRIDE_ENV, &reboot);

    dispatch_reboot_candidates(reboot_candidates()).expect("reboot fallback should succeed");

    assert!(marker.exists(), "reboot fallback should have been invoked");
}

#[test]
#[serial]
fn request_reboot_fails_closed_in_test_runtime() {
    let err = request_reboot().expect_err("request_reboot must be blocked in tests");
    assert!(err.to_string().contains("Refusing to trigger reboot"));
}

#[test]
#[serial]
fn reboot_override_never_falls_back_to_real_host_commands() {
    let temp_dir = tempfile::tempdir().unwrap();
    let broken_systemctl = temp_dir.path().join("systemctl");

    write_executable_script(
        &broken_systemctl,
        "#!/usr/bin/env bash\nprintf 'override failed\n' >&2\nexit 1\n",
    );

    let _systemctl_override = EnvGuard::set(SYSTEMCTL_REBOOT_OVERRIDE_ENV, &broken_systemctl);
    let _reboot_override = EnvGuard::remove(REBOOT_BINARY_OVERRIDE_ENV);

    let err = dispatch_reboot_candidates(reboot_candidates())
        .expect_err("broken override must not fall back to host binaries");
    assert!(err.to_string().contains("override failed"));
}
